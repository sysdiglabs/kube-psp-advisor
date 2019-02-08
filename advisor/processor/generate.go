package processor

import (
	"fmt"
	"time"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/report"
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"github.com/sysdiglabs/kube-psp-advisor/utils"

	v1 "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Processor struct {
	k8sClient          *kubernetes.Clientset
	resourceNamePrefix map[string]bool
	namespace          string
}

func NewProcessor(kubeconfig string) (*Processor, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Processor{
		k8sClient:          clientset,
		resourceNamePrefix: map[string]bool{},
	}, nil
}

func (p *Processor) SetNamespace(ns string) {
	p.namespace = ns
}

// GeneratePSP generate Pod Security Policy
func (p *Processor) GeneratePSP(cssList []types.ContainerSecuritySpec, pssList []types.PodSecuritySpec) *v1beta1.PodSecurityPolicy {
	// no PSP will be generated if no security spec is provided
	if len(cssList) == 0 && len(pssList) == 0 {
		return nil
	}

	psp := &v1beta1.PodSecurityPolicy{}

	psp.APIVersion = "policy/v1beta1"
	psp.Kind = "PodSecurityPolicy"

	addedCap := map[string]int{}
	droppedCap := map[string]int{}

	effectiveCap := map[string]bool{}

	runAsUser := map[int64]bool{}

	volumeTypes := map[string]bool{}

	hostPaths := map[string]bool{}

	runAsUserCount := 0

	runAsNonRootCount := 0

	notAllowPrivilegeEscationCount := 0

	psp.Name = fmt.Sprintf("%s-%s", "pod-security-policy", time.Now().Format("20060102150405"))

	for _, sc := range pssList {
		psp.Spec.HostPID = psp.Spec.HostPID || sc.HostPID
		psp.Spec.HostIPC = psp.Spec.HostIPC || sc.HostIPC
		psp.Spec.HostNetwork = psp.Spec.HostNetwork || sc.HostNetwork

		for _, t := range sc.VolumeTypes {
			volumeTypes[t] = true
		}

		for _, path := range sc.MountHostPaths {
			hostPaths[path] = true
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

		if sc.RunAsUser != nil {
			runAsUser[*sc.RunAsUser] = true
			runAsUserCount++
		}

		if sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation {
			notAllowPrivilegeEscationCount++
		}

		// set host ports
		for _, port := range sc.HostPorts {
			psp.Spec.HostPorts = append(psp.Spec.HostPorts, v1beta1.HostPortRange{Min: port, Max: port})
		}
	}

	// set allowedPrivilegeEscalation
	if notAllowPrivilegeEscationCount == len(cssList) {
		notAllowed := false
		psp.Spec.AllowPrivilegeEscalation = &notAllowed
	}

	// set runAsUser strategy
	if runAsNonRootCount == len(cssList) {
		psp.Spec.RunAsUser.Rule = v1beta1.RunAsUserStrategyMustRunAsNonRoot
	}

	if runAsUserCount == len(cssList) {
		psp.Spec.RunAsUser.Rule = v1beta1.RunAsUserStrategyMustRunAs
		for uid := range runAsUser {
			if psp.Spec.RunAsUser.Rule == v1beta1.RunAsUserStrategyMustRunAsNonRoot && uid != 0 {
				psp.Spec.RunAsUser.Ranges = append(psp.Spec.RunAsUser.Ranges, v1beta1.IDRange{
					Min: uid,
					Max: uid,
				})
			}
		}
	}

	// set allowed host path
	hostPathList := utils.MapToArray(hostPaths)

	for _, path := range hostPathList {
		psp.Spec.AllowedHostPaths = append(psp.Spec.AllowedHostPaths, v1beta1.AllowedHostPath{
			PathPrefix: path,
		})
	}

	// set limit volumes
	volumeTypeList := utils.MapToArray(volumeTypes)

	for _, v := range volumeTypeList {
		psp.Spec.Volumes = append(psp.Spec.Volumes, v1beta1.FSType(v))
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
		psp.Spec.AllowedCapabilities = append(psp.Spec.AllowedCapabilities, v1.Capability(cap))
	}

	// set defaultAddCapabilities
	for k, v := range addedCap {
		if v == len(cssList) {
			psp.Spec.DefaultAddCapabilities = append(psp.Spec.DefaultAddCapabilities, v1.Capability(k))
		}
	}

	// set requiredDroppedCapabilities
	for k, v := range droppedCap {
		if v == len(cssList) {
			psp.Spec.RequiredDropCapabilities = append(psp.Spec.RequiredDropCapabilities, v1.Capability(k))
		}
	}

	// set to default values
	if string(psp.Spec.RunAsUser.Rule) == "" {
		psp.Spec.RunAsUser.Rule = v1beta1.RunAsUserStrategyRunAsAny
	}

	if psp.Spec.RunAsGroup != nil && string(psp.Spec.RunAsGroup.Rule) == "" {
		psp.Spec.RunAsGroup.Rule = v1beta1.RunAsGroupStrategyRunAsAny
	}

	if string(psp.Spec.FSGroup.Rule) == "" {
		psp.Spec.FSGroup.Rule = v1beta1.FSGroupStrategyRunAsAny
	}

	if string(psp.Spec.SELinux.Rule) == "" {
		psp.Spec.SELinux.Rule = v1beta1.SELinuxStrategyRunAsAny
	}

	if string(psp.Spec.SupplementalGroups.Rule) == "" {
		psp.Spec.SupplementalGroups.Rule = v1beta1.SupplementalGroupsStrategyRunAsAny
	}

	return psp
}

func (p *Processor) GenerateReport(cssList []types.ContainerSecuritySpec, pssList []types.PodSecuritySpec) *report.Report {
	r := report.NewReport()

	for _, c := range cssList {
		r.AddContainer(c)
	}

	for _, p := range pssList {
		r.AddPod(p)
	}

	return r
}

// GetSecuritySpec security posture
func (p *Processor) GetSecuritySpec() ([]types.ContainerSecuritySpec, []types.PodSecuritySpec, error) {
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}

	// get security spec from daemonsets
	cspList0, pspList0, err := p.getSecuritySpecFromDaemonSets()

	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cspList0...)
	pssList = append(pssList, pspList0...)

	// get security spec from deployments
	cssList1, pssList1, err := p.getSecuritySpecFromDeployments()

	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList1...)
	pssList = append(pssList, pssList1...)

	// get security spec from replicasets
	cssList2, pssList2, err := p.getSecuritySpecFromReplicaSets()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList2...)
	pssList = append(pssList, pssList2...)

	// get security spec from statefulsets
	cssList3, pssList3, err := p.getSecuritySpecFromStatefulSets()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList3...)
	pssList = append(pssList, pssList3...)

	// get security spec from replication controller
	cssList4, pssList4, err := p.getSecuritySpecFromReplicationController()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList4...)
	pssList = append(pssList, pssList4...)

	// get security spec from cron job
	cssList5, pssList5, err := p.getSecuritySpecFromCronJobs()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList5...)
	pssList = append(pssList, pssList5...)

	// get security spec from job
	cssList6, pssList6, err := p.getSecuritySpecFromJobs()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList6...)
	pssList = append(pssList, pssList6...)

	// get security spec from pods
	cssList7, pssList7, err := p.getSecuritySpecFromPods()
	if err != nil {
		return cssList, pssList, err
	}

	cssList = append(cssList, cssList7...)
	pssList = append(pssList, pssList7...)

	return cssList, pssList, nil
}
