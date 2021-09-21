package advisor

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/ast"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/processor"
	"github.com/sysdiglabs/kube-psp-advisor/advisor/report"

	"k8s.io/api/policy/v1beta1"
	k8sJSON "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type Advisor struct {
	podSecurityPolicy *v1beta1.PodSecurityPolicy
	OPAModulePolicy   *ast.Module
	k8sClient         *kubernetes.Clientset
	processor         *processor.Processor
	report            *report.Report
	grants            []types.PSPGrant
	grantWarnings     string
}

// Create an podSecurityPolicy advisor instance
func NewAdvisor(kubeconfig string) (*Advisor, error) {
	p, err := processor.NewProcessor(kubeconfig)

	if err != nil {
		return nil, err
	}

	return &Advisor{
		podSecurityPolicy: nil,
		processor:         p,
		report:            nil,
		grants:            []types.PSPGrant{},
	}, nil
}

func (advisor *Advisor) Process(namespace string, excludeNamespaces []string, OPAformat string, OPAdefaultRule bool) error {
	advisor.processor.SetNamespace(namespace)
	advisor.processor.SetExcludeNamespaces(excludeNamespaces)

	cssList, pssList, err := advisor.processor.GetSecuritySpec()

	if err != nil {
		return err
	}

	if OPAformat == "opa" {
		advisor.OPAModulePolicy = advisor.processor.GenerateOPA(cssList, pssList, OPAdefaultRule)
	} else if OPAformat == "psp" {
		advisor.podSecurityPolicy = advisor.processor.GeneratePSP(cssList, pssList)
	}

	advisor.report = advisor.processor.GenerateReport(cssList, pssList)

	advisor.grants, advisor.grantWarnings = advisor.processor.GeneratePSPGrant(cssList, pssList)

	return nil
}

func (advisor *Advisor) PrintReport() {
	jsonOutput, err := json.Marshal(advisor.report)

	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonOutput))
}

func (advisor *Advisor) PrintPodSecurityPolicy() error {
	e := k8sJSON.NewYAMLSerializer(k8sJSON.DefaultMetaFactory, nil, nil)

	err := e.Encode(advisor.podSecurityPolicy, os.Stdout)

	return err
}

func (advisor *Advisor) PrintOPAPolicy() string {
	if advisor.OPAModulePolicy != nil {
		err := advisor.OPAModulePolicy.String()
		fmt.Printf(err)
		return err
	} else {
		return ""
	}
}
func (advisor *Advisor) GetPodSecurityPolicy() *v1beta1.PodSecurityPolicy {
	return advisor.podSecurityPolicy
}

func (advisor *Advisor) PrintPodSecurityPolicyWithGrants() error {
	var err error
	e := k8sJSON.NewYAMLSerializer(k8sJSON.DefaultMetaFactory, nil, nil)

	if advisor.grantWarnings != "" {
		fmt.Println(advisor.grantWarnings)
		printYamlSeparator()
	}

	for _, pspGrant := range advisor.grants {
		fmt.Println(pspGrant.Comment)

		if err = e.Encode(pspGrant.PodSecurityPolicy, os.Stdout); err != nil {
			return err
		}

		printYamlSeparator()

		if err = e.Encode(pspGrant.Role, os.Stdout); err != nil {
			return err
		}

		printYamlSeparator()

		if err = e.Encode(pspGrant.RoleBinding, os.Stdout); err != nil {
			return err
		}

		printYamlSeparator()
	}

	return nil
}

func printYamlSeparator() {
	fmt.Println("---")
}
