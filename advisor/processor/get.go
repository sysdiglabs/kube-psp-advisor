package processor

import (
	"strings"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"

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
)

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
		cspList2, podSecurityPosture := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: ds.Name,
			Kind: DaemonSet,
		}, ds.Namespace, ds.Spec.Template.Spec, &sa)

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
		cspList2, psc := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: rs.Name,
			Kind: ReplicaSet,
		}, rs.Namespace, rs.Spec.Template.Spec, &sa)

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
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: sts.Name,
			Kind: StatefulSet,
		}, sts.Namespace, sts.Spec.Template.Spec, &sa)

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
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: rc.Name,
			Kind: ReplicationController,
		}, rc.Namespace, rc.Spec.Template.Spec, &sa)

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
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: cronJob.Name,
			Kind: CronJob,
		}, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec, &sa)

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
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: job.Name,
			Kind: Job,
		}, job.Namespace, job.Spec.Template.Spec, &sa)

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
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: deploy.Name,
			Kind: Deployment,
		}, deploy.Namespace, deploy.Spec.Template.Spec, &sa)

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
		cspList2, podSecurityPosture := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: pod.Name,
			Kind: Pod,
		}, pod.Namespace, pod.Spec, &sa)

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

