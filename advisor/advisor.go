package advisor

import (
	"encoding/json"
	"fmt"
	"os"
	"sysdig-labs/kube-psp-advisor/advisor/processor"
	"sysdig-labs/kube-psp-advisor/advisor/report"

	"k8s.io/api/policy/v1beta1"
	k8sJSON "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type Advisor struct {
	podSecurityPolicy *v1beta1.PodSecurityPolicy
	k8sClient         *kubernetes.Clientset
	processor         *processor.Processor
	report            *report.Report
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
	}, nil
}

func (advisor *Advisor) Process(namespace string) error {
	advisor.processor.SetNamespace(namespace)

	cssList, pssList, err := advisor.processor.GetSecuritySpec()

	if err != nil {
		return err
	}

	advisor.podSecurityPolicy = advisor.processor.GeneratePSP(cssList, pssList)

	advisor.report = advisor.processor.GenerateReport(cssList, pssList)

	return nil
}

func (advisor *Advisor) PrintReport() {
	jsonOutput, err := json.Marshal(advisor.report)

	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonOutput))
}

func (advisor *Advisor) PrintPodSecurityPolicy() {
	e := k8sJSON.NewYAMLSerializer(k8sJSON.DefaultMetaFactory, nil, nil)

	e.Encode(advisor.podSecurityPolicy, os.Stdout)
}
