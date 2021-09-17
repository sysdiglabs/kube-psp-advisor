package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

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

//NEW OPA
func getVolumeMounts(spec corev1.PodSpec) map[string]bool {
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

	return containerMountMap
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
	addCapMap := utils.ArrayToMap(add)
	defaultCaps := types.DefaultCaps
	effectiveCapMap := map[string]bool{}

	for _, cap := range defaultCaps {
		if _, exists := dropCapMap[cap]; !exists {
			effectiveCapMap[cap] = true
		}
	}

	for cap := range addCapMap {
		if _, exists := dropCapMap[cap]; !exists {
			effectiveCapMap[cap] = true
		}
	}

	effectiveCaps = utils.MapToArray(effectiveCapMap)

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

	addCapMap := map[string]bool{}
	dropCapMap := map[string]bool{}

	for _, cap := range addCaps {
		addCapMap[string(cap)] = true
	}

	for _, cap := range dropCaps {
		dropCapMap[string(cap)] = true
	}

	// delete cap if exists both in the drop list and add list
	for cap := range addCapMap {
		if _, exists := dropCapMap[cap]; exists {
			delete(addCapMap, cap)
			delete(dropCapMap, cap)
		}
	}
	return utils.MapToArray(addCapMap), utils.MapToArray(dropCapMap)
}

func getSysctls(psc *corev1.PodSecurityContext) (sysctls []string) {
	if psc == nil {
		return
	}

	for _, s := range psc.Sysctls {
		sysctls = append(sysctls, s.Name)
	}

	return sysctls
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
		VolumeMounts:   getVolumeMounts(spec),
		MountHostPaths: getVolumeHostPaths(spec),
		ServiceAccount: getServiceAccountName(spec),
		Sysctls:        getSysctls(spec.SecurityContext),
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
			VolumeMounts:             getVolumeMounts(container.VolumeMounts),
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

func (pg *Generator) GenerateOPA(cssList []types.ContainerSecuritySpec,
	pssList []types.PodSecuritySpec,
	namespace, serverGitVersion string, OPAdefaultRule bool) *ast.Module {

	return pg.GenerateOPAWithName(cssList, pssList, namespace, serverGitVersion, "", OPAdefaultRule)
}

func (pg *Generator) GenerateOPAPod(cssList []types.ContainerSecuritySpec,
	pssList []types.PodSecuritySpec,
	namespace, serverGitVersion string, OPAdefaultRule bool) *ast.Module {

	return pg.GenerateOPAWithName(cssList, pssList, namespace, serverGitVersion, "", OPAdefaultRule)
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
	psp.Spec.ReadOnlyRootFilesystem = true

	addedCap := map[string]int{}
	droppedCap := map[string]int{}

	effectiveCap := map[string]bool{}

	runAsUser := map[int64]bool{}

	runAsGroup := map[int64]bool{}

	volumeTypes := map[string]bool{}

	hostPaths := map[string]bool{}

	hostPorts := map[int32]bool{}

	sysctls := map[string]bool{}

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

		for _, s := range sc.Sysctls {
			sysctls[s] = true
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

		psp.Spec.ReadOnlyRootFilesystem = psp.Spec.ReadOnlyRootFilesystem && sc.ReadOnlyRootFS

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

		for _, port := range sc.HostPorts {
			hostPorts[port] = true
		}
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

	// set host ports
	portRangeList := types.PortRangeList{}
	for hostPort := range hostPorts {
		portRange := types.NewPortRange(hostPort, hostPort)
		portRangeList = append(portRangeList, portRange)
	}

	// set allowedUnsafeSysctls
	for s := range sysctls {
		psp.Spec.AllowedUnsafeSysctls = append(psp.Spec.AllowedUnsafeSysctls, s)
	}

	for _, portRange := range portRangeList.Consolidate() {
		psp.Spec.HostPorts = append(psp.Spec.HostPorts, policyv1beta1.HostPortRange{Min: portRange.Min, Max: portRange.Max})
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

// GenerateOPA generate OPA Policy
func (pg *Generator) GenerateOPAWithName(
	cssList []types.ContainerSecuritySpec,
	pssList []types.PodSecuritySpec,
	namespace, serverGitVersion, pspName string, OPAdefaultRule bool) *ast.Module {

	var ns string
	// no OPA will be generated if no security spec is provided
	if len(cssList) == 0 && len(pssList) == 0 {
		return nil
	}

	var mod ast.Module
	pack := ast.MustParsePackage("package kubernetes.admission")

	a := ast.Head{
		Name: "deny",
		Key: &ast.Term{
			ast.VarTerm("message").Value,
			nil,
		},
	}
	rule := ast.Rule{
		nil,
		false,
		&a,
		nil,
		nil,
		nil,
	}

	hostPaths := []string{}
	volumeMounts := map[string]bool{}
	volumeMountValues := []string{}
	hostPid := false
	HostIPC := false
	HostNet := false
	sysctls := []string{}
	Privileged := false
	ReadOnlyRootFS := 0
	runAsUserCount := 0

	runAsGroupCount := 0
	RunAsNonRoot := 0
	AllowPrivilegeEscalation := 0
	addedCap := []string{}
	droppedCap := []string{}
	runAsUser := []string{}
	runAsGroup := []string{}

	effectiveCap := map[string]bool{}
	hostPorts := []string{}
	basepath := ""

	ns = namespace

	if ns == "" {
		ns = "all"
	}
	rule.Body.Append(ast.MustParseExpr("workload := input.request.object"))
	rule.Body.Append(ast.NewExpr(ast.VarTerm(checkOPADefault(OPAdefaultRule) + "valueWorkLoadSecContext(workload)")))
	valueWorkLoadSecContext := addOPARule("valueWorkLoadSecContext", "workload")

	for _, wsc := range pssList {

		hostPid = hostPid || wsc.HostPID
		HostIPC = HostIPC || wsc.HostIPC
		HostNet = HostNet || wsc.HostNetwork

		for path, _ := range wsc.MountHostPaths {
			hostPaths = append(hostPaths, "\""+path+"\"")
		}

		for name, readOnly := range wsc.MountHostPaths {
			if _, exists := volumeMounts[name]; !exists {
				if readOnly {
					volumeMounts[name] = readOnly
					volumeMountValues = append(volumeMountValues, "\""+name+"\"")
				}
			} else {
				volumeMounts[name] = readOnly && volumeMounts[name]
			}
		}

		// Sysctls is set
		for _, s := range wsc.Sysctls {
			sysctls = append(sysctls, "\""+s+"\"")
		}

		// Check if workload or pod
		if wsc.Metadata.Kind == "Deployment" || wsc.Metadata.Kind == "Job" || wsc.Metadata.Kind == "ReplicaSet" || wsc.Metadata.Kind == "DaemonSet" || wsc.Metadata.Kind == "ReplicationController" {
			basepath = "input.request.object.spec.template.spec"
		} else {
			basepath = "input.request.object.spec"
		}

	}

	valueWorkLoadSecContext.Body.Append(ast.MustParseExpr("container := " + basepath + ".containers[_]"))

	// Add rule hostPaths
	if len(hostPaths) > 0 {
		valueWorkLoadSecContext.Body.Append(ast.MustParseExpr("volumeHostPaths(workload)"))
		valueHostPathRule := addOPARule("volumeHostPaths", "workload")
		valueHostPathRule.Body.Append(ast.MustParseExpr("hostPaths = {" + strings.Join(hostPaths, ",") + "}"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("diff_fields := {label | label := " + basepath + ".volumes[_].hostPath.path} -  hostPaths"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("names := {name | path1 := {p | volumes := " + basepath + ".volumes[_];checkHostPort(volumes); p := volumes};name := path1[_].name}"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("namesNotRO := {name | path1 := {p | volumeMounts := " + basepath + ".containers[_].volumeMounts[_]; not volumeMounts.readOnly == true; p := volumeMounts}; name := path1[_].name}"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("intersect := namesNotRO & names"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("not namesNotRO == names"))
		valueHostPathRule.Body.Append(ast.MustParseExpr("count(intersect) == 0"))

		for volume := range volumeMounts {
			valueHostPathRule := addOPARule("checkHostPort", "volumes")
			valueHostPathRule.Body.Append(ast.MustParseExpr("volumes.hostPath.path == \"" + volume + "\""))
			mod.Rules = append(mod.Rules, valueHostPathRule)
		}

		mod.Rules = append(mod.Rules, valueHostPathRule)
	}

	// Add rule sysctls
	if len(sysctls) > 0 {
		valueWorkLoadSecContext.Body.Append(ast.MustParseExpr("valueSysctls(workload)"))
		valueSysctlsRule := addOPARule("valueSysctls", "sysctls")
		valueSysctlsRule.Body.Append(ast.MustParseExpr("sysctls = {" + strings.Join(sysctls, ",") + "}"))
		valueSysctlsRule.Body.Append(ast.MustParseExpr("setSysctls := {" + basepath + ".securityContext.sysctls[_] | " + basepath + ".securityContext.sysctls[_] != null}"))
		valueSysctlsRule.Body.Append(ast.MustParseExpr("count(setSysctls) > 0"))
		valueSysctlsRule.Body.Append(ast.MustParseExpr("diff_fields := {label | label := " + basepath + ".securityContext.sysctls[_]} -  sysctls"))
		valueSysctlsRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueSysctlsRule)
	}

	// Add rule hostPid
	if hostPid {
		valueWorkLoadSecContext.Body.Append(ast.MustParseExpr(basepath + ".hostPID"))
	}

	// Add rule HostIPC
	if HostIPC {
		valueWorkLoadSecContext.Body.Append(ast.MustParseExpr(basepath + ".hostIPC"))
	}

	// Add rule HostNet
	if HostNet {
		valueWorkLoadSecContext.Body.Append(ast.MustParseExpr(basepath + ".hostNetwork"))
	}
	mod.Rules = append(mod.Rules, valueWorkLoadSecContext)

	valueWorkLoadSecContext.Body.Append(ast.NewExpr(ast.VarTerm("valueSecContext(container)")))

	for _, sc := range cssList {
		for _, cap := range sc.Capabilities {
			effectiveCap[cap] = true
		}

		for _, cap := range sc.AddedCap {
			addedCap = append(addedCap, "\""+cap+"\"")
		}

		for _, cap := range sc.DroppedCap {
			droppedCap = append(droppedCap, "\""+cap+"\"")
		}

		Privileged = Privileged || sc.Privileged

		// runAsUser is set and not to root
		if sc.RunAsUser != nil && *sc.RunAsUser != 0 {
			runAsUser = append(runAsUser, strconv.FormatInt(*sc.RunAsUser, 10))
			runAsUserCount++
		}

		// runAsGroup is set
		if sc.RunAsGroup != nil && *sc.RunAsGroup != 0 {
			runAsGroup = append(runAsGroup, strconv.FormatInt(*sc.RunAsGroup, 10))
			runAsGroupCount++
		}

		// port is set
		for _, port := range sc.HostPorts {
			hostPorts = append(hostPorts, fmt.Sprint(port))
		}

		if sc.ReadOnlyRootFS {
			ReadOnlyRootFS++
		}

		if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
			RunAsNonRoot++
		}

		if sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation {
			AllowPrivilegeEscalation++
		}
	}

	valueSecContextRule := addOPARule("valueSecContext", "container")

	// Add rule addedCap
	if len(addedCap) > 0 {
		valueSecContextRule.Body.Append(ast.NewExpr(ast.VarTerm("valueAddedCap(container)")))
		valueAddedCapRule := addOPARule("valueAddedCap", "addedCap")
		valueAddedCapRule.Body.Append(ast.MustParseExpr("caps = {" + strings.Join(addedCap, ",") + "}"))
		valueAddedCapRule.Body.Append(ast.MustParseExpr("diff_fields := {label | label := " + basepath + ".containers[_].securityContext.capabilities.add[_]} -  caps"))
		valueAddedCapRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueAddedCapRule)
	}

	// Add rule droppedCap
	if len(droppedCap) > 0 {
		valueSecContextRule.Body.Append(ast.NewExpr(ast.VarTerm("valueDroppedCap(container)")))
		valueDroppedCapRule := addOPARule("valueDroppedCap", "droppedCap")
		valueDroppedCapRule.Body.Append(ast.MustParseExpr("caps = {" + strings.Join(droppedCap, ",") + "}"))
		valueDroppedCapRule.Body.Append(ast.MustParseExpr("diff_fields := {label | label := " + basepath + ".containers[_].securityContext.capabilities.drop[_]} -  caps"))
		valueDroppedCapRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueDroppedCapRule)
	}

	// Add rule runAsUser
	if len(runAsUser) > 0 {
		valueSecContextRule.Body.Append(ast.NewExpr(ast.VarTerm("valueRunAsUserID(container)")))
		valueHostRunAsUserRule := addOPARule("valueRunAsUserID", "uid")
		valueHostRunAsUserRule.Body.Append(ast.MustParseExpr("uids = {" + strings.Join(runAsUser, ",") + "}"))
		valueHostRunAsUserRule.Body.Append(ast.MustParseExpr("setRunAsUser := {" + basepath + ".containers[_].securityContext.runAsUser | " + basepath + ".containers[_].securityContext.runAsUser != null}"))
		valueHostRunAsUserRule.Body.Append(ast.MustParseExpr("count(setRunAsUser) > 0"))
		valueHostRunAsUserRule.Body.Append(ast.MustParseExpr("diff_fields := setRunAsUser - uids"))
		valueHostRunAsUserRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueHostRunAsUserRule)
	}

	// Add rule runAsGroup
	if len(runAsGroup) > 0 {
		valueSecContextRule.Body.Append(ast.NewExpr(ast.VarTerm("valueRunAsGroupID(container)")))
		valueHostRunAsGroupRule := addOPARule("valueRunAsGroupID", "gid")
		valueHostRunAsGroupRule.Body.Append(ast.MustParseExpr("gids = {" + strings.Join(runAsGroup, ",") + "}"))
		valueHostRunAsGroupRule.Body.Append(ast.MustParseExpr("setRunAsGroup := {" + basepath + ".containers[_].securityContext.runAsGroup | " + basepath + ".containers[_].securityContext.runAsGroup != null}"))
		valueHostRunAsGroupRule.Body.Append(ast.MustParseExpr("count(setRunAsGroup) > 0"))
		valueHostRunAsGroupRule.Body.Append(ast.MustParseExpr("diff_fields := setRunAsGroup - gids"))
		valueHostRunAsGroupRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueHostRunAsGroupRule)
	}

	// Add rule hostPorts
	if len(hostPorts) > 0 {
		valueSecContextRule.Body.Append(ast.NewExpr(ast.VarTerm("valueHostPort(container)")))
		valueHostPortRule := addOPARule("valueHostPort", "container")
		valueHostPortRule.Body.Append(ast.MustParseExpr("ports = {" + strings.Join(hostPorts, ",") + "}"))
		valueHostPortRule.Body.Append(ast.MustParseExpr("setHostPort := {" + basepath + ".containers[_].ports[_].hostPort | " + basepath + ".containers[_].ports[_].hostPort != null}"))
		valueHostPortRule.Body.Append(ast.MustParseExpr("count(setHostPort) > 0"))
		valueHostPortRule.Body.Append(ast.MustParseExpr("diff_fields := setHostPort - ports"))
		valueHostPortRule.Body.Append(ast.MustParseExpr("count(diff_fields) <= 0"))
		mod.Rules = append(mod.Rules, valueHostPortRule)
	}

	// Add rule Privileged
	if Privileged {
		valueSecContextRule.Body.Append(ast.MustParseExpr("container.securityContext.privileged"))
	}

	// Add rule ReadOnlyRootFS
	if ReadOnlyRootFS == len(cssList) {
		valueSecContextRule.Body.Append(ast.MustParseExpr("container.securityContext.readOnlyRootFilesystem"))
	}

	// Add rule RunAsNonRoot
	if RunAsNonRoot == len(cssList) {
		valueSecContextRule.Body.Append(ast.MustParseExpr("container.securityContext.runAsNonRoot"))
	}

	// Add rule AllowPrivilegeEscalation
	if AllowPrivilegeEscalation == len(cssList) {
		valueSecContextRule.Body.Append(ast.MustParseExpr("container.securityContext.allowPrivilegeEscalation == false"))
	}

	mod.Rules = append(mod.Rules, valueSecContextRule)

	rule.Body.Append(ast.MustParseExpr("message := sprintf(\"Workflow or pod compliant with the policy.\", [workload.metadata.name])"))
	mod.Package = pack
	mod.Rules = append(mod.Rules, &rule)

	return &mod

}

// deny-by-default option check
func checkOPADefault(OPAdefaultRule bool) string {
	if !OPAdefaultRule {
		return "not "
	} else {
		return ""
	}
}

func addOPARule(nameRuleHead string, arg string) *ast.Rule {
	RuleHead := ast.Head{
		Name: ast.Var(nameRuleHead),
		Args: []*ast.Term{
			ast.VarTerm(arg),
		},
	}
	Rule := ast.Rule{
		nil,
		false,
		&RuleHead,
		nil,
		nil,
		nil,
	}
	return &Rule
}

func (pg *Generator) fromPodObj(metadata types.Metadata, spec corev1.PodSpec, OPAformat string, OPAdefaultRule bool) (string, error) {

	cssList, pss := pg.GetSecuritySpecFromPodSpec(metadata, "default", spec, nil)

	pssList := []types.PodSecuritySpec{pss}

	// We assume a namespace "default", which is only used for the
	// name of the resulting PSP, and assume a k8s version of
	// 1.11, which allows enforcing ReadOnly.
	var psp *policyv1beta1.PodSecurityPolicy
	var mod *ast.Module
	var out string

	if OPAformat == "psp" {
		psp = pg.GeneratePSP(cssList, pssList, "default", types.Version1_11)
		pspJson, err := json.Marshal(psp)
		if err != nil {
			return "", fmt.Errorf("Could not marshal resulting PSP: %v", err)
		}
		pspYaml, err := yaml.JSONToYAML(pspJson)
		if err != nil {
			return "", fmt.Errorf("Could not convert resulting PSP to Json: %v", err)
		}
		out = string(pspYaml)
	} else if OPAformat == "opa" {
		mod = pg.GenerateOPAPod(cssList, pssList, "default", types.Version1_11, OPAdefaultRule)
		out = mod.String()
	}

	return string(out), nil
}

func (pg *Generator) fromDaemonSet(ds *appsv1.DaemonSet, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: ds.Name,
		Kind: ds.Kind,
	}, ds.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromDeployment(dep *appsv1.Deployment, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: dep.Name,
		Kind: dep.Kind,
	}, dep.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromReplicaSet(rs *appsv1.ReplicaSet, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: rs.Name,
		Kind: rs.Kind,
	}, rs.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromStatefulSet(ss *appsv1.StatefulSet, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: ss.Name,
		Kind: ss.Kind,
	}, ss.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromReplicationController(rc *corev1.ReplicationController, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: rc.Name,
		Kind: rc.Kind,
	}, rc.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromCronJob(cj *batchv1beta1.CronJob, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: cj.Name,
		Kind: cj.Kind,
	}, cj.Spec.JobTemplate.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromJob(job *batch.Job, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: job.Name,
		Kind: job.Kind,
	}, job.Spec.Template.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) fromPod(pod *corev1.Pod, OPAformat string, OPAdefaultRule bool) (string, error) {
	return pg.fromPodObj(types.Metadata{
		Name: pod.Name,
		Kind: pod.Kind,
	}, pod.Spec, OPAformat, OPAdefaultRule)
}

func (pg *Generator) FromPodObjString(podObjString string, OPAformat string, OPAdefaultRule bool) (string, error) {

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
		return pg.fromDaemonSet(&ds, OPAformat, OPAdefaultRule)
	case "Deployment":
		var dep appsv1.Deployment
		if err = decoder.Decode(&dep); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Deployment: %v", err)
		}
		return pg.fromDeployment(&dep, OPAformat, OPAdefaultRule)
	case "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err = decoder.Decode(&rs); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as ReplicaSet: %v", err)
		}
		return pg.fromReplicaSet(&rs, OPAformat, OPAdefaultRule)
	case "StatefulSet":
		var ss appsv1.StatefulSet
		if err = decoder.Decode(&ss); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as StatefulSet: %v", err)
		}
		return pg.fromStatefulSet(&ss, OPAformat, OPAdefaultRule)
	case "ReplicationController":
		var rc corev1.ReplicationController
		if err = decoder.Decode(&rc); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as ReplicationController: %v", err)
		}
		return pg.fromReplicationController(&rc, OPAformat, OPAdefaultRule)
	case "CronJob":
		var cj batchv1beta1.CronJob
		if err = decoder.Decode(&cj); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as CronJob: %v", err)
		}
		return pg.fromCronJob(&cj, OPAformat, OPAdefaultRule)
	case "Job":
		var job batch.Job
		if err = decoder.Decode(&job); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Job: %v", err)
		}
		return pg.fromJob(&job, OPAformat, OPAdefaultRule)
	case "Pod":
		var pod corev1.Pod
		if err = decoder.Decode(&pod); err != nil {
			return "", fmt.Errorf("Could not unmarshal json document as Pod: %v", err)
		}
		return pg.fromPod(&pod, OPAformat, OPAdefaultRule)
	}

	return "", fmt.Errorf("K8s Object not one of supported types")
}

func (pg *Generator) GeneratePSPFormYamls(yamls []string) (*policyv1beta1.PodSecurityPolicy, error) {
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}
	for _, yamlFile := range yamls {
		csl, psl, err := pg.LoadYaml(yamlFile)
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

func (pg *Generator) LoadYaml(yamlFile string) ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
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

		fileName := filepath.Base(yamlFile)
		switch o := obj.(type) {
		case *corev1.Pod:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec, nil)
		case *appsv1.StatefulSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.DaemonSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.Deployment:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *appsv1.ReplicaSet:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  yamlFile,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *corev1.ReplicationController:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec.Template.Spec, nil)
		case *batchv1beta1.CronJob:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
			}, getNamespace(o.Namespace), o.Spec.JobTemplate.Spec.Template.Spec, nil)
		case *batch.Job:
			csl, pss = pg.GetSecuritySpecFromPodSpec(types.Metadata{
				Name:      o.Name,
				Kind:      o.Kind,
				Namespace: getNamespace(o.Namespace),
				YamlFile:  fileName,
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

func getVolumeMounts(mounts []corev1.VolumeMount) []types.VolumeMount {
	list := []types.VolumeMount{}

	for _, vm := range mounts {
		list = append(list, types.VolumeMount{
			Name:        vm.Name,
			MountPath:   vm.MountPath,
			ReadOnly:    vm.ReadOnly,
			SubPath:     vm.SubPath,
			SubPathExpr: vm.SubPathExpr,
		})
	}

	return list
}
