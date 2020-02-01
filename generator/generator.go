package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"k8s.io/client-go/kubernetes/scheme"

	"github.com/ghodss/yaml"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"github.com/sysdiglabs/kube-psp-advisor/utils"

	appsv1 "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"

	"reflect"
	"strings"
	"time"
)

const (
	volumeTypeSecret = "secret"
)

type Generator struct {
}

func NewGenerator() (*Generator, error) {

	return &Generator{}, nil
}

func getVolumeTypes(spec corev1.PodSpec, sa *corev1.ServiceAccount) (volumeTypes []string) {
	volumeTypeMap := map[string]bool{}
	for _, v := range spec.Volumes {
		if volumeType := getVolumeType(v); volumeType != "" {
			volumeTypeMap[getVolumeType(v)] = true
		}
	}

	// If don't opt out of automounting API credentials for a service account
	// or a particular pod, "secret" needs to be into PSP allowed volume types.
	if sa == nil || mountServiceAccountToken(spec, *sa) {
		volumeTypeMap[volumeTypeSecret] = true
	}

	volumeTypes = utils.MapToArray(volumeTypeMap)
	return
}

func getVolumeHostPaths(spec corev1.PodSpec) map[string]bool {
	hostPathMap := map[string]bool{}

	containerMountMap := map[string]bool{}

	for _, c := range spec.Containers {
		for _, vm := range c.VolumeMounts {
			if _, exists := containerMountMap[vm.Name]; !exists {
				containerMountMap[vm.Name] = vm.ReadOnly
			} else {
				containerMountMap[vm.Name] = containerMountMap[vm.Name] && vm.ReadOnly
			}
		}
	}

	for _, c := range spec.InitContainers {
		for _, vm := range c.VolumeMounts {
			if _, exists := containerMountMap[vm.Name]; !exists {
				containerMountMap[vm.Name] = vm.ReadOnly
			} else {
				containerMountMap[vm.Name] = containerMountMap[vm.Name] && vm.ReadOnly
			}
		}
	}

	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			if _, exists := containerMountMap[v.Name]; exists {
				hostPathMap[v.HostPath.Path] = containerMountMap[v.Name]
			}
		}
	}

	return hostPathMap
}

func getVolumeType(v corev1.Volume) string {
	val := reflect.ValueOf(v.VolumeSource)
	for i := 0; i < val.Type().NumField(); i++ {
		if !val.Field(i).IsNil() {
			protos := strings.Split(val.Type().Field(i).Tag.Get("protobuf"), ",")
			for _, p := range protos {
				if strings.HasPrefix(p, "name=") {
					return p[5:]
				}
			}
		}
	}
	return ""
}

func getRunAsUser(sc *corev1.SecurityContext, psc *corev1.PodSecurityContext) *int64 {
	if sc == nil {
		if psc != nil {
			return psc.RunAsUser
		}
		return nil
	}

	return sc.RunAsUser
}

func getRunAsGroup(sc *corev1.SecurityContext, psc *corev1.PodSecurityContext) *int64 {
	if sc == nil {
		if psc != nil {
			return psc.RunAsGroup
		}
		return nil
	}

	return sc.RunAsGroup
}

func getHostPorts(containerPorts []corev1.ContainerPort) (hostPorts []int32) {
	for _, p := range containerPorts {
		hostPorts = append(hostPorts, p.HostPort)
	}
	return
}

func getEffectiveCapablities(add, drop []string) (effectiveCaps []string) {
	dropCapMap := utils.ArrayToMap(drop)
	defaultCaps := types.DefaultCaps

	for _, cap := range defaultCaps {
		if _, exists := dropCapMap[cap]; !exists {
			effectiveCaps = append(effectiveCaps, cap)
		}
	}

	effectiveCaps = append(effectiveCaps, add...)

	return
}

func getPrivileged(sc *corev1.SecurityContext) bool {
	if sc == nil {
		return false
	}

	if sc.Privileged == nil {
		return false
	}

	return *sc.Privileged
}

func getRunAsNonRootUser(sc *corev1.SecurityContext, psc *corev1.PodSecurityContext) *bool {
	if sc == nil {
		if psc != nil {
			return psc.RunAsNonRoot
		}
		return nil
	}

	return sc.RunAsNonRoot
}

func getAllowedPrivilegeEscalation(sc *corev1.SecurityContext) *bool {
	if sc == nil {
		return nil
	}

	return sc.AllowPrivilegeEscalation
}

func getIDs(podStatus corev1.PodStatus, containerName string) (containerID, imageID string) {
	containers := podStatus.ContainerStatuses
	for _, c := range containers {
		if c.Name == containerName {
			if len(c.ContainerID) > 0 {
				idx := strings.Index(c.ContainerID, "docker://") + 9
				if idx > len(c.ContainerID) {
					idx = 0
				}
				containerID = c.ContainerID[idx:]
			}

			if len(c.ImageID) > 0 {
				imageID = c.ImageID[strings.Index(c.ImageID, "sha256"):]
			}

			return
		}
	}
	return
}

func getReadOnlyRootFileSystem(sc *corev1.SecurityContext) bool {
	if sc == nil {
		return false
	}

	if sc.ReadOnlyRootFilesystem == nil {
		return false
	}

	return *sc.ReadOnlyRootFilesystem
}

func getCapabilities(sc *corev1.SecurityContext) (addList []string, dropList []string) {
	if sc == nil {
		return
	}

	if sc.Capabilities == nil {
		return
	}

	addCaps := sc.Capabilities.Add
	dropCaps := sc.Capabilities.Drop

	for _, cap := range addCaps {
		addList = append(addList, string(cap))
	}

	for _, cap := range dropCaps {
		dropList = append(dropList, string(cap))
	}
	return
}

func mountServiceAccountToken(spec corev1.PodSpec, sa corev1.ServiceAccount) bool {
	// First Pod's preference is checked
	if spec.AutomountServiceAccountToken != nil {
		return *spec.AutomountServiceAccountToken
	}

	// Then service account's
	if sa.AutomountServiceAccountToken != nil {
		return *sa.AutomountServiceAccountToken
	}

	return true
}

func (pg *Generator) GetSecuritySpecFromPodSpec(metadata types.Metadata, namespace string, spec corev1.PodSpec, sa *corev1.ServiceAccount) ([]types.ContainerSecuritySpec, types.PodSecuritySpec) {
	cssList := []types.ContainerSecuritySpec{}
	podSecuritySpec := types.PodSecuritySpec{
		Metadata:       metadata,
		Namespace:      namespace,
		HostPID:        spec.HostPID,
		HostNetwork:    spec.HostNetwork,
		HostIPC:        spec.HostIPC,
		VolumeTypes:    getVolumeTypes(spec, sa),
		MountHostPaths: getVolumeHostPaths(spec),
		ServiceAccount: getServiceAccountName(spec),
	}

	for _, container := range spec.InitContainers {
		addCapList, dropCapList := getCapabilities(container.SecurityContext)
		csc := types.ContainerSecuritySpec{
			Metadata:                 metadata,
			ContainerName:            container.Name,
			ImageName:                container.Image,
			PodName:                  metadata.Name,
			Namespace:                namespace,
			HostName:                 spec.NodeName,
			Capabilities:             getEffectiveCapablities(addCapList, dropCapList),
			AddedCap:                 addCapList,
			DroppedCap:               dropCapList,
			ReadOnlyRootFS:           getReadOnlyRootFileSystem(container.SecurityContext),
			RunAsNonRoot:             getRunAsNonRootUser(container.SecurityContext, spec.SecurityContext),
			AllowPrivilegeEscalation: getAllowedPrivilegeEscalation(container.SecurityContext),
			Privileged:               getPrivileged(container.SecurityContext),
			RunAsGroup:               getRunAsGroup(container.SecurityContext, spec.SecurityContext),
			RunAsUser:                getRunAsUser(container.SecurityContext, spec.SecurityContext),
			HostPorts:                getHostPorts(container.Ports),
			ServiceAccount:           getServiceAccountName(spec),
		}
		cssList = append(cssList, csc)
	}

	for _, container := range spec.Containers {
		addCapList, dropCapList := getCapabilities(container.SecurityContext)
		csc := types.ContainerSecuritySpec{
			Metadata:                 metadata,
			ContainerName:            container.Name,
			ImageName:                container.Image,
			PodName:                  metadata.Name,
			Namespace:                namespace,
			HostName:                 spec.NodeName,
			Capabilities:             getEffectiveCapablities(addCapList, dropCapList),
			AddedCap:                 addCapList,
			DroppedCap:               dropCapList,
			ReadOnlyRootFS:           getReadOnlyRootFileSystem(container.SecurityContext),
			RunAsNonRoot:             getRunAsNonRootUser(container.SecurityContext, spec.SecurityContext),
			AllowPrivilegeEscalation: getAllowedPrivilegeEscalation(container.SecurityContext),
			Privileged:               getPrivileged(container.SecurityContext),
			RunAsGroup:               getRunAsGroup(container.SecurityContext, spec.SecurityContext),
			RunAsUser:                getRunAsUser(container.SecurityContext, spec.SecurityContext),
			HostPorts:                getHostPorts(container.Ports),
			ServiceAccount:           getServiceAccountName(spec),
		}
		cssList = append(cssList, csc)
	}
	return cssList, podSecuritySpec
}

func (pg *Generator) GeneratePSP(cssList []types.ContainerSecuritySpec,
	pssList []types.PodSecuritySpec,
	namespace, serverGitVersion string) *policyv1beta1.PodSecurityPolicy {

	return pg.GeneratePSPWithName(cssList, pssList, namespace, serverGitVersion, "")
}

// GeneratePSP generate Pod Security Policy
func (pg *Generator) GeneratePSPWithName(
	cssList []types.ContainerSecuritySpec,
	pssList []types.PodSecuritySpec,
	namespace, serverGitVersion, pspName string) *policyv1beta1.PodSecurityPolicy {
	var ns string
	// no PSP will be generated if no security spec is provided
	if len(cssList) == 0 && len(pssList) == 0 {
		return nil
	}

	psp := &policyv1beta1.PodSecurityPolicy{}

	psp.APIVersion = "policy/v1beta1"
	psp.Kind = "PodSecurityPolicy"

	addedCap := map[string]int{}
	droppedCap := map[string]int{}

	effectiveCap := map[string]bool{}

	runAsUser := map[int64]bool{}

	runAsGroup := map[int64]bool{}

	volumeTypes := map[string]bool{}

	hostPaths := map[string]bool{}

	runAsUserCount := 0

	runAsGroupCount := 0

	runAsNonRootCount := 0

	notAllowPrivilegeEscationCount := 0

	ns = namespace

	if ns == "" {
		ns = "all"
	}

	if pspName == "" {
		psp.Name = fmt.Sprintf("%s-%s-%s", "pod-security-policy", ns, time.Now().Format("20060102150405"))
	} else {
		psp.Name = pspName
	}

	for _, sc := range pssList {
		psp.Spec.HostPID = psp.Spec.HostPID || sc.HostPID
		psp.Spec.HostIPC = psp.Spec.HostIPC || sc.HostIPC
		psp.Spec.HostNetwork = psp.Spec.HostNetwork || sc.HostNetwork

		for _, t := range sc.VolumeTypes {
			volumeTypes[t] = true
		}

		for path, readOnly := range sc.MountHostPaths {
			if _, exists := hostPaths[path]; !exists {
				hostPaths[path] = readOnly
			} else {
				hostPaths[path] = readOnly && hostPaths[path]
			}
		}
	}

	for _, sc := range cssList {
		for _, cap := range sc.Capabilities {
			effectiveCap[cap] = true
		}

		for _, cap := range sc.AddedCap {
			addedCap[cap]++
		}

		for _, cap := range sc.DroppedCap {
			droppedCap[cap]++
		}

		psp.Spec.Privileged = psp.Spec.Privileged || sc.Privileged

		psp.Spec.ReadOnlyRootFilesystem = psp.Spec.ReadOnlyRootFilesystem || sc.ReadOnlyRootFS

		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			runAsNonRootCount++
		}

		// runAsUser is set and not to root
		if sc.RunAsUser != nil && *sc.RunAsUser != 0 {
			runAsUser[*sc.RunAsUser] = true
			runAsUserCount++
		}

		// runAsGroup is set
		if sc.RunAsGroup != nil && *sc.RunAsGroup != 0 {
			runAsGroup[*sc.RunAsGroup] = true
			runAsGroupCount++
		}

		if sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation {
			notAllowPrivilegeEscationCount++
		}

		// set host ports
		//TODO: need to integrate with listening port during the runtime, might cause false positive.
		//for _, port := range sc.HostPorts {
		//	psp.Spec.HostPorts = append(psp.Spec.HostPorts, policyv1beta1.HostPortRange{Min: port, Max: port})
		//}
	}

	// set allowedPrivilegeEscalation
	if notAllowPrivilegeEscationCount == len(cssList) {
		notAllowed := false
		psp.Spec.AllowPrivilegeEscalation = &notAllowed
	}

	// set runAsUser strategy
	if runAsNonRootCount == len(cssList) {
		psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyMustRunAsNonRoot
	}

	// set runAsGroup strategy
	if runAsGroupCount == len(cssList) {
		psp.Spec.RunAsGroup = &policyv1beta1.RunAsGroupStrategyOptions{}
		psp.Spec.RunAsGroup.Rule = policyv1beta1.RunAsGroupStrategyMustRunAs
		for gid := range runAsGroup {
			psp.Spec.RunAsGroup.Ranges = append(psp.Spec.RunAsGroup.Ranges, policyv1beta1.IDRange{
				Min: gid,
				Max: gid,
			})
		}
	}

	// set runAsUser strategy
	if runAsUserCount == len(cssList) {
		psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyMustRunAs
		for uid := range runAsUser {
			psp.Spec.RunAsUser.Ranges = append(psp.Spec.RunAsUser.Ranges, policyv1beta1.IDRange{
				Min: uid,
				Max: uid,
			})
		}
	}

	// set allowed host path
	enforceReadOnly, _ := utils.CompareVersion(serverGitVersion, types.Version1_11)

	for path, readOnly := range hostPaths {
		psp.Spec.AllowedHostPaths = append(psp.Spec.AllowedHostPaths, policyv1beta1.AllowedHostPath{
			PathPrefix: path,
			ReadOnly:   readOnly || enforceReadOnly,
		})
	}

	// set limit volumes
	volumeTypeList := utils.MapToArray(volumeTypes)

	for _, v := range volumeTypeList {
		psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.FSType(v))
	}

	// set allowedCapabilities
	defaultCap := utils.ArrayToMap(types.DefaultCaps)
	for cap := range defaultCap {
		if _, exists := effectiveCap[cap]; exists {
			delete(effectiveCap, cap)
		}
	}

	// set allowedAddCapabilities
	for cap := range effectiveCap {
		psp.Spec.AllowedCapabilities = append(psp.Spec.AllowedCapabilities, corev1.Capability(cap))
	}

	// set defaultAddCapabilities
	for k, v := range addedCap {
		if v == len(cssList) {
			psp.Spec.DefaultAddCapabilities = append(psp.Spec.DefaultAddCapabilities, corev1.Capability(k))
		}
	}

	// set requiredDroppedCapabilities
	for k, v := range droppedCap {
		if v == len(cssList) {
			psp.Spec.RequiredDropCapabilities = append(psp.Spec.RequiredDropCapabilities, corev1.Capability(k))
		}
	}

	// set to default values
	if string(psp.Spec.RunAsUser.Rule) == "" {
		psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	}

	if psp.Spec.RunAsGroup != nil && string(psp.Spec.RunAsGroup.Rule) == "" {
		psp.Spec.RunAsGroup.Rule = policyv1beta1.RunAsGroupStrategyRunAsAny
	}

	if string(psp.Spec.FSGroup.Rule) == "" {
		psp.Spec.FSGroup.Rule = policyv1beta1.FSGroupStrategyRunAsAny
	}

	if string(psp.Spec.SELinux.Rule) == "" {
		psp.Spec.SELinux.Rule = policyv1beta1.SELinuxStrategyRunAsAny
	}

	if string(psp.Spec.SupplementalGroups.Rule) == "" {
		psp.Spec.SupplementalGroups.Rule = policyv1beta1.SupplementalGroupsStrategyRunAsAny
	}

	return psp
}

func (pg *Generator) fromPodObj(metadata types.Metadata, spec corev1.PodSpec) (string, error) {

	cssList, pss := pg.GetSecuritySpecFromPodSpec(metadata, "default", spec, nil)

	pssList := []types.PodSecuritySpec{pss}

	// We assume a namespace "default", which is only used for the
	// name of the resulting PSP, and assume a k8s version of
	// 1.11, which allows enforcing ReadOnly.
	psp := pg.GeneratePSP(cssList, pssList, "default", types.Version1_11)

	pspJson, err := json.Marshal(psp)
	if err != nil {
		return "", fmt.Errorf("Could not marshal resulting PSP: %v", err)
	}

	pspYaml, err := yaml.JSONToYAML(pspJson)
	if err != nil {
		return "", fmt.Errorf("Could not convert resulting PSP to Json: %v", err)
	}

	return string(pspYaml), nil
}

func (pg *Generator) fromDaemonSet(ds *appsv1.DaemonSet) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: ds.Name,
		Kind: ds.Kind,
	}, ds.Spec.Template.Spec)
}

func (pg *Generator) fromDeployment(dep *appsv1.Deployment) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: dep.Name,
		Kind: dep.Kind,
	}, dep.Spec.Template.Spec)
}

func (pg *Generator) fromReplicaSet(rs *appsv1.ReplicaSet) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: rs.Name,
		Kind: rs.Kind,
	}, rs.Spec.Template.Spec)
}

func (pg *Generator) fromStatefulSet(ss *appsv1.StatefulSet) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: ss.Name,
		Kind: ss.Kind,
	}, ss.Spec.Template.Spec)
}

func (pg *Generator) fromReplicationController(rc *corev1.ReplicationController) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: rc.Name,
		Kind: rc.Kind,
	}, rc.Spec.Template.Spec)
}

func (pg *Generator) fromCronJob(cj *batchv1beta1.CronJob) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: cj.Name,
		Kind: cj.Kind,
	}, cj.Spec.JobTemplate.Spec.Template.Spec)
}

func (pg *Generator) fromJob(job *batch.Job) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: job.Name,
		Kind: job.Kind,
	}, job.Spec.Template.Spec)
}

func (pg *Generator) fromPod(pod *corev1.Pod) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: pod.Name,
		Kind: pod.Kind,
	}, pod.Spec)
}

func (pg *Generator) FromPodObjString(podObjString string) (string, error) {

	podObjJson, err := yaml.YAMLToJSON([]byte(podObjString))
	if err != nil {
		return "", fmt.Errorf("Could not parse pod Object: %v", err)
	}

	var anyJson map[string]interface{}

	err = json.Unmarshal(podObjJson, &anyJson)

	if err != nil {
		return "", fmt.Errorf("Could not unmarshal json document: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(podObjJson))
	decoder.DisallowUnknownFields()

	switch kind := anyJson["kind"]; kind {
	case "DaemonSet":
		var ds appsv1.DaemonSet
		if err = decoder.Decode(&ds); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as DaemonSet: %v", err)
		}
		return pg.fromDaemonSet(&ds)
	case "Deployment":
		var dep appsv1.Deployment
		if err = decoder.Decode(&dep); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Deployment: %v", err)
		}
		return pg.fromDeployment(&dep)
	case "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err = decoder.Decode(&rs); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as ReplicaSet: %v", err)
		}
		return pg.fromReplicaSet(&rs)
	case "StatefulSet":
		var ss appsv1.StatefulSet
		if err = decoder.Decode(&ss); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as StatefulSet: %v", err)
		}
		return pg.fromStatefulSet(&ss)
	case "ReplicationController":
		var rc corev1.ReplicationController
		if err = decoder.Decode(&rc); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as ReplicationController: %v", err)
		}
		return pg.fromReplicationController(&rc)
	case "CronJob":
		var cj batchv1beta1.CronJob
		if err = decoder.Decode(&cj); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as CronJob: %v", err)
		}
		return pg.fromCronJob(&cj)
	case "Job":
		var job batch.Job
		if err = decoder.Decode(&job); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Job: %v", err)
		}
		return pg.fromJob(&job)
	case "Pod":
		var pod corev1.Pod
		if err = decoder.Decode(&pod); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Pod: %v", err)
		}
		return pg.fromPod(&pod)
	}

	return "", fmt.Errorf("K8s Object not one of supported types")
}

func (pg *Generator) GeneratePSPFormYamls(yamls []string) (*policyv1beta1.PodSecurityPolicy, error) {
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}
	for _, yamlFile := range yamls {
		csl, psl, err := pg.loadYaml(yamlFile)
		if err != nil {
			return nil, err
		}

		if len(csl) > 0 {
			cssList = append(cssList, csl...)
			pssList = append(pssList, psl...)
		}
	}

	psp := pg.GeneratePSP(cssList, pssList, "", types.Version1_11)

	return psp, nil
}

func (pg *Generator) loadYaml(yamlFile string) ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	file, err := os.Open(yamlFile)
	if err != nil {
		return cssList, pssList, fmt.Errorf("failed to open yaml file %s for reading: %v", yamlFile, err)
	}
	defer file.Close()

	fileBytes, err := ioutil.ReadAll(file)

	sepYamlFiles := strings.Split(string(fileBytes), "---")

	for _, f := range sepYamlFiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}

		// remove comments: line starts with #
		lines := strings.Split(f, "\n")
		newLines := []string{}
		for _, line := range lines {
			if line != "" && line != "\n" && !strings.HasPrefix(line, "#") {
				newLines = append(newLines, line)
			}
		}

		if len(newLines) == 0 {
			continue
		}

		newFile := strings.Join(newLines, "\n")

		csl := []types.ContainerSecuritySpec{}
		pss := types.PodSecuritySpec{}

		decode := scheme.Codecs.UniversalDeserializer().Decode
		obj, _, err := decode([]byte(newFile), nil, nil)

		if err != nil {
			log.Println(fmt.Sprintf("Error while decoding YAML object: %s. Error was: %s", newFile, err))
			continue
		}

		switch o := obj.(type) {
		case *corev1.Pod:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec, nil)
		case *appsv1.StatefulSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.DaemonSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.Deployment:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.ReplicaSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *corev1.ReplicationController:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *batchv1beta1.CronJob:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.JobTemplate.Spec.Template.Spec, nil)
		case *batch.Job:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name: o.Name,
				Kind: o.Kind,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		}

		if len(csl) > 0 {
			cssList = append(cssList, csl...)
			pssList = append(pssList, pss)
		}
	}

	return cssList, pssList, nil
}

func getServiceAccountName(spec corev1.PodSpec) string {
	if spec.ServiceAccountName == "" {
		return "default"
	}

	return spec.ServiceAccountName
}

func getNamespace(ns string) string {
	if ns != "" {
		return ns
	}

	return "default"
}
