package processor

import (
	"fmt"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"

	"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	daemonSetList, err := clientset.AppsV1().DaemonSets(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cspList, pspList, err
	}

	for _, ds := range daemonSetList.Items {
		sa := p.GetServiceAccount(ds.Namespace, ds.Spec.Template.Spec.ServiceAccountName)

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

	replicaSetList, err := clientset.AppsV1().ReplicaSets(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, rs := range replicaSetList.Items {
		if len(rs.OwnerReferences) > 0 {
			continue
		}

		sa := p.GetServiceAccount(rs.Namespace, rs.Spec.Template.Spec.ServiceAccountName)
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

	statefulSetList, err := clientset.AppsV1().StatefulSets(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, sts := range statefulSetList.Items {
		sa := p.GetServiceAccount(sts.Namespace, sts.Spec.Template.Spec.ServiceAccountName)
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

	replicationControllerList, err := clientset.CoreV1().ReplicationControllers(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, rc := range replicationControllerList.Items {
		sa := p.GetServiceAccount(rc.Namespace, rc.Spec.Template.Spec.ServiceAccountName)
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

	jobList, err := clientset.BatchV1beta1().CronJobs(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, cronJob := range jobList.Items {
		sa := p.GetServiceAccount(cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName)
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

	jobList, err := clientset.BatchV1().Jobs(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, job := range jobList.Items {
		if len(job.OwnerReferences) > 0 {
			continue
		}
		sa := p.GetServiceAccount(job.Namespace, job.Spec.Template.Spec.ServiceAccountName)
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

	deployments, err := clientset.AppsV1().Deployments(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, deploy := range deployments.Items {
		sa := p.GetServiceAccount(deploy.Namespace, deploy.Spec.Template.Spec.ServiceAccountName)
		cspList2, pss := p.gen.GetSecuritySpecFromPodSpec(types.Metadata{
			Name: deploy.Name,
			Kind: Deployment,
		}, deploy.Namespace, deploy.Spec.Template.Spec, &sa)

		pssList = append(pssList, pss)
		cssList = append(cssList, cspList2...)
	}

	return cssList, pssList, nil
}

func (p *Processor) getSecuritySpecFromPods() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	clientset := p.k8sClient
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	pods, err := clientset.CoreV1().Pods(p.namespace).List(v1meta.ListOptions{})

	if err != nil {
		return cssList, pssList, err
	}

	for _, pod := range pods.Items {
		if len(pod.OwnerReferences) > 0 {
			continue
		}

		sa := p.GetServiceAccount(pod.Namespace, pod.Spec.ServiceAccountName)
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

	serviceAccounts, err := p.k8sClient.CoreV1().ServiceAccounts(p.namespace).List(v1meta.ListOptions{})
	if err != nil {
		return serviceAccountMap, err
	}

	// service account is an namespaced object
	for _, sa := range serviceAccounts.Items {
		key := fmt.Sprintf("%s:%s", sa.Namespace, sa.Name)
		serviceAccountMap[key] = sa
	}

	return serviceAccountMap, nil
}

func (p *Processor) GetServiceAccount(ns, saName string) v1.ServiceAccount {
	if saName == "" {
		saName = "default"
	}

	key := fmt.Sprintf("%s:%s", ns, saName)

	sa, exists := p.serviceAccountMap[key]

	if !exists {
		return v1.ServiceAccount{}
	}

	return sa
}
