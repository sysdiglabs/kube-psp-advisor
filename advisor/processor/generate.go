package processor

import (
	"fmt"
	"sort"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/report"
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"github.com/sysdiglabs/kube-psp-advisor/generator"

	v1 "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Processor struct {
	k8sClient         *kubernetes.Clientset
	namespace         string
	serviceAccountMap map[string]v1.ServiceAccount
	serverGitVersion  string
	gen               *generator.Generator
}

// NewProcessor returns a new processor
func NewProcessor(kubeconfig string) (*Processor, error) {

	gen, err := generator.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("Could not create generator: %v", err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	info, err := clientset.ServerVersion()

	if err != nil {
		return nil, err
	}

	return &Processor{
		k8sClient:        clientset,
		serverGitVersion: info.GitVersion,
		gen:              gen,
	}, nil
}

func (p *Processor) SetNamespace(ns string) {
	p.namespace = ns
}

// GeneratePSP generates Pod Security Policy
func (p *Processor) GeneratePSP(cssList []types.ContainerSecuritySpec, pssList []types.PodSecuritySpec) *v1beta1.PodSecurityPolicy {
	return p.gen.GeneratePSP(cssList, pssList, p.namespace, p.serverGitVersion)
}

// GeneratePSPGrant generates Pod Security Policies, Roles, RoleBindings for service accounts to use PSP
func (p *Processor) GeneratePSPGrant(cssList []types.ContainerSecuritySpec, pssList []types.PodSecuritySpec) (types.PSPGrantList, string) {
	saSecuritySpecMap := map[string]*types.SASecuritySpec{}
	pspGrantList := []types.PSPGrant{}
	grantWarnings := ""

	for _, css := range cssList {
		key := fmt.Sprintf("%s:%s", css.Namespace, css.ServiceAccount)
		if _, exists := saSecuritySpecMap[key]; !exists {
			saSecuritySpecMap[key] = types.NewSASecuritySpec(css.Namespace, css.ServiceAccount)
		}
		saSecuritySpecMap[key].AddContainerSecuritySpec(css)
	}

	for _, pss := range pssList {
		key := fmt.Sprintf("%s:%s", pss.Namespace, pss.ServiceAccount)
		if _, exists := saSecuritySpecMap[key]; !exists {
			saSecuritySpecMap[key] = types.NewSASecuritySpec(pss.Namespace, pss.ServiceAccount)
		}
		saSecuritySpecMap[key].AddPodSecuritySpec(pss)
	}

	saSecuritySpecList := types.SASecuritySpecList{}

	// convert saSecuritySpecMap into list and then sort
	for _, saSecuritySpec := range saSecuritySpecMap {
		saSecuritySpecList = append(saSecuritySpecList, saSecuritySpec)
	}

	sort.Sort(saSecuritySpecList)

	for _, s := range saSecuritySpecList {
		if !s.IsDefaultServiceAccount() {
			pspGrant := types.PSPGrant{
				Comment:           s.GenerateComment(),
				ServiceAccount:    s.ServiceAccount,
				Namespace:         s.Namespace,
				Role:              s.GenerateRole(),
				RoleBinding:       s.GenerateRoleBinding(),
				PodSecurityPolicy: p.gen.GeneratePSPWithName(s.ContainerSecuritySpecList, s.PodSecuritySpecList, s.Namespace, p.serverGitVersion, s.GeneratePSPName()),
			}

			pspGrantList = append(pspGrantList, pspGrant)
		} else {
			grantWarnings += s.GenerateComment()
		}
	}

	return pspGrantList, grantWarnings
}

// GenerateReport generate a JSON report
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

	// get and cache service account list in the specified namespace
	var err error
	p.serviceAccountMap, err = p.getServiceAccountMap()
	if err != nil {
		return cssList, pssList, err
	}

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
