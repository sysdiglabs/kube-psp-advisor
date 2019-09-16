package processor

import (
	"reflect"
	"strings"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"github.com/sysdiglabs/kube-psp-advisor/utils"

	"k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DaemonSet             = "DaemonSet"
	Deployment            = "Deployment"
	Pod                   = "Pod"
	StatefulSet           = "StatefulSet"
	ReplicaSet            = "ReplicaSet"
	ReplicationController = "ReplicationController"
	Job                   = "Job"
	CronJob               = "CronJob"

	volumeTypeSecret = "secret"
)

func getSecuritySpec(metadata types.Metadata, namespace string, spec v1.PodSpec, sa v1.ServiceAccount) ([]types.ContainerSecuritySpec, types.PodSecuritySpec) {
	cssList := []types.ContainerSecuritySpec{}
	podSecuritySpec := types.PodSecuritySpec{
		Metadata:       metadata,
		Namespace:      namespace,
		HostPID:        spec.HostPID,
		HostNetwork:    spec.HostNetwork,
		HostIPC:        spec.HostIPC,
		VolumeTypes:    getVolumeTypes(spec, sa),
		MountHostPaths: getVolumeHostPaths(spec),
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
		}
		cssList = append(cssList, csc)
	}
	return cssList, podSecuritySpec
}

func (p *Processor) getSecuritySpecFromDaemonSets() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cspList := []types.ContainerSecuritySpec{}
	pspList := []types.PodSecuritySpec{}

	daemonSetList, err := clientset.AppsV1().DaemonSets(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cspList, pspList, err
	}

	for _, ds := range daemonSetList.Items {
		p.resourceNamePrefix[ds.Name] = true
		sa := p.serviceAccountMap[ds.Spec.Template.Spec.ServiceAccountName]
		cspList2, podSecurityPosture := getSecuritySpec(types.Metadata{
			Name: ds.Name,
			Kind: DaemonSet,
		}, ds.Namespace, ds.Spec.Template.Spec, sa)

		pspList = append(pspList, podSecurityPosture)
		cspList = append(cspList, cspList2...)
	}

	return cspList, pspList, nil
}

func (p *Processor) getSecuritySpecFromReplicaSets() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	replicaSetList, err := clientset.AppsV1().ReplicaSets(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, rs := range replicaSetList.Items {
		if p.hasSpecRecorded(rs.Name) {
			continue
		}

		p.resourceNamePrefix[rs.Name] = true
		sa := p.serviceAccountMap[rs.Spec.Template.Spec.ServiceAccountName]
		cspList2, psc := getSecuritySpec(types.Metadata{
			Name: rs.Name,
			Kind: ReplicaSet,
		}, rs.Namespace, rs.Spec.Template.Spec, sa)

		pssList = append(pssList, psc)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromStatefulSets() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	statefulSetList, err := clientset.AppsV1().StatefulSets(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, sts := range statefulSetList.Items {
		p.resourceNamePrefix[sts.Name] = true
		sa := p.serviceAccountMap[sts.Spec.Template.Spec.ServiceAccountName]
		cspList2, pss := getSecuritySpec(types.Metadata{
			Name: sts.Name,
			Kind: StatefulSet,
		}, sts.Namespace, sts.Spec.Template.Spec, sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromReplicationController() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	replicationControllerList, err := clientset.CoreV1().ReplicationControllers(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, rc := range replicationControllerList.Items {
		p.resourceNamePrefix[rc.Name] = true
		sa := p.serviceAccountMap[rc.Spec.Template.Spec.ServiceAccountName]
		cspList2, pss := getSecuritySpec(types.Metadata{
			Name: rc.Name,
			Kind: ReplicationController,
		}, rc.Namespace, rc.Spec.Template.Spec, sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromCronJobs() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	jobList, err := clientset.BatchV1beta1().CronJobs(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, cronJob := range jobList.Items {
		p.resourceNamePrefix[cronJob.Name] = true
		sa := p.serviceAccountMap[cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName]
		cspList2, pss := getSecuritySpec(types.Metadata{
			Name: cronJob.Name,
			Kind: CronJob,
		}, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec, sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromJobs() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	jobList, err := clientset.BatchV1().Jobs(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, job := range jobList.Items {
		if p.hasSpecRecorded(job.Name) {
			continue
		}

		p.resourceNamePrefix[job.Name] = true
		sa := p.serviceAccountMap[job.Spec.Template.Spec.ServiceAccountName]
		cspList2, pss := getSecuritySpec(types.Metadata{
			Name: job.Name,
			Kind: Job,
		}, job.Namespace, job.Spec.Template.Spec, sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromDeployments() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	deployments, err := clientset.AppsV1().Deployments(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, deploy := range deployments.Items {
		p.resourceNamePrefix[deploy.Name] = true
		sa := p.serviceAccountMap[deploy.Spec.Template.Spec.ServiceAccountName]
		cspList2, pss := getSecuritySpec(types.Metadata{
			Name: deploy.Name,
			Kind: Deployment,
		}, deploy.Namespace, deploy.Spec.Template.Spec, sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) hasSpecRecorded(resourceName string) bool {
	for prefix := range p.resourceNamePrefix {
		if strings.HasPrefix(resourceName, prefix) {
			return true
		}
	}
	return false
}

func (p *Processor) getSecuritySpecFromPods() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	pods, err := clientset.CoreV1().Pods(p.namespace).List(v12.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, pod := range pods.Items {
		if p.hasSpecRecorded(pod.Name) {
			continue
		}

		sa := p.serviceAccountMap[pod.Spec.ServiceAccountName]
		cspList2, podSecurityPosture := getSecuritySpec(types.Metadata{
			Name: pod.Name,
			Kind: Pod,
		}, pod.Namespace, pod.Spec, sa)

		pssList = append(pssList, podSecurityPosture)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getServiceAccountMap() (map[string]v1.ServiceAccount, error) {
	serviceAccountMap := map[string]v1.ServiceAccount{}

	serviceAccounts, err := p.k8sClient.CoreV1().ServiceAccounts(p.namespace).List(v12.ListOptions{})
	if err != nil {
		return serviceAccountMap, err
	}

	for _, sa := range serviceAccounts.Items {
		serviceAccountMap[sa.Name] = sa
	}

	return serviceAccountMap, nil
}

func getVolumeTypes(spec v1.PodSpec, sa v1.ServiceAccount) (volumeTypes []string) {
	volumeTypeMap := map[string]bool{}
	for _, v := range spec.Volumes {
		if volumeType := getVolumeType(v); volumeType != "" {
			volumeTypeMap[getVolumeType(v)] = true
		}
	}

	// If don't opt out of automounting API credentils for a service account
	// or a particular pod, "secret" needs to be into PSP allowed volume types.
	if mountServiceAccountToken(spec, sa) {
		volumeTypeMap[volumeTypeSecret] = true
	}

	volumeTypes = utils.MapToArray(volumeTypeMap)
	return
}

func getVolumeHostPaths(spec v1.PodSpec) map[string]bool {
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

	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			if _, exists := containerMountMap[v.Name]; exists {
				hostPathMap[v.HostPath.Path] = containerMountMap[v.Name]
			}
		}
	}

	return hostPathMap
}

func getVolumeType(v v1.Volume) string {
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

func getRunAsUser(sc *v1.SecurityContext, psc *v1.PodSecurityContext) *int64 {
	if sc == nil {
		if psc != nil {
			return psc.RunAsUser
		}
		return nil
	}

	return sc.RunAsUser
}

func getRunAsGroup(sc *v1.SecurityContext, psc *v1.PodSecurityContext) *int64 {
	if sc == nil {
		if psc != nil {
			return psc.RunAsGroup
		}
		return nil
	}

	return sc.RunAsGroup
}

func getHostPorts(containerPorts []v1.ContainerPort) (hostPorts []int32) {
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

func getPrivileged(sc *v1.SecurityContext) bool {
	if sc == nil {
		return false
	}

	if sc.Privileged == nil {
		return false
	}

	return *sc.Privileged
}

func getRunAsNonRootUser(sc *v1.SecurityContext, psc *v1.PodSecurityContext) *bool {
	if sc == nil {
		if psc != nil {
			return psc.RunAsNonRoot
		}
		return nil
	}

	return sc.RunAsNonRoot
}

func getAllowedPrivilegeEscalation(sc *v1.SecurityContext) *bool {
	if sc == nil {
		return nil
	}

	return sc.AllowPrivilegeEscalation
}

func getIDs(podStatus v1.PodStatus, containerName string) (containerID, imageID string) {
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

func getReadOnlyRootFileSystem(sc *v1.SecurityContext) bool {
	if sc == nil {
		return false
	}

	if sc.ReadOnlyRootFilesystem == nil {
		return false
	}

	return *sc.ReadOnlyRootFilesystem
}

func getCapabilities(sc *v1.SecurityContext) (addList []string, dropList []string) {
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

func mountServiceAccountToken(spec v1.PodSpec, sa v1.ServiceAccount) bool {
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
