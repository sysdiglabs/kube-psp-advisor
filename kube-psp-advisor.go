package main

import (
	"flag"
	"path/filepath"

	"github.com/sysdiglabs/kube-psp-advisor/advisor"

	"k8s.io/client-go/util/homedir"
	// Initialize all known client auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	var kubeconfig string
	var withReport bool
	var namespace string

	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}

	flag.BoolVar(&withReport, "report", false, "(optional) return with detail report")

	flag.StringVar(&namespace, "namespace", "", "(optional) namespace")

	flag.Parse()

	advisor, err := advisor.NewAdvisor(kubeconfig)

	if err != nil {
		panic(err)
	}

	err = advisor.Process(namespace)

	if err != nil {
		panic(err)
	}

	if withReport {
		advisor.PrintReport()
		return
	}

	advisor.PrintPodSecurityPolicy()
}
