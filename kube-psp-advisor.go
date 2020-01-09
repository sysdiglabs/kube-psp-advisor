package main

import (
	"fmt"

	"io/ioutil"

	"os"

	log "github.com/sirupsen/logrus"

	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sysdiglabs/kube-psp-advisor/advisor"
	"github.com/sysdiglabs/kube-psp-advisor/generator"

	"k8s.io/client-go/util/homedir"
	// Initialize all known client auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func inspectPsp(kubeconfig string, namespace string, withReport, withGrant bool) error {
	advisor, err := advisor.NewAdvisor(kubeconfig)

	if err != nil {
		return fmt.Errorf("Could not create advisor object: %v", err)
	}

	err = advisor.Process(namespace)

	if err != nil {
		return fmt.Errorf("Could not run advisor to inspect cluster and generate PSP: %v", err)
	}

	if withReport {
		advisor.PrintReport()
		return nil
	}

	if withGrant {
		return advisor.PrintPodSecurityPolicyWithGrants()
	}
	err = advisor.PrintPodSecurityPolicy()

	if err != nil {
		return fmt.Errorf("Could not print PSP: %v", err)
	}

	return nil
}

func convertPsp(podObjFilename string, pspFilename string) error {
	podObjFile, err := os.Open(podObjFilename)
	if err != nil {
		return fmt.Errorf("Could not open pod object file %s for reading: %v", podObjFilename, err)
	}
	defer podObjFile.Close()

	log.Debugf("Reading pod Obj File from %s", podObjFilename)

	podObjString, err := ioutil.ReadAll(podObjFile)

	if err != nil {
		return fmt.Errorf("Could not read contents of pod object file %s: %v", podObjFilename, err)
	}

	log.Debugf("Contents of Obj File: %s", podObjString)

	psp_gen, err := generator.NewGenerator()
	if err != nil {
		return fmt.Errorf("Could not create Psp Generator: %v", err)
	}

	pspString, err := psp_gen.FromPodObjString(string(podObjString))
	if err != nil {
		return fmt.Errorf("Could not generate PSP from pod Object: %v", err)
	}

	err = ioutil.WriteFile(pspFilename, []byte(pspString), 0644)

	log.Infof("Wrote generated psp to %s", pspFilename)

	return nil
}

func main() {

	var kubeconfig string
	var withReport bool
	var withGrant bool
	var namespace string
	var podObjFilename string
	var pspFilename string
	var logLevel string

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	var rootCmd = &cobra.Command{
		Use:   "kube-psp-advisor",
		Short: "kube-psp-advisor generates K8s PodSecurityPolicies",
		Long:  "A way to generate K8s PodSecurityPolicy objects from a live K8s environment or individual K8s objects containing pod specifications",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			lvl, err := log.ParseLevel(logLevel)
			if err != nil {
				log.Fatal(err)
			}

			log.SetLevel(lvl)
		},
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "level", "info", "Log level")

	var inspectCmd = &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a live K8s Environment to generate a PodSecurityPolicy",
		Long:  "Fetch all objects in the provided namespace to generate a Pod Security Policy",
		Run: func(cmd *cobra.Command, args []string) {
			err := inspectPsp(kubeconfig, namespace, withReport, withGrant)
			if err != nil {
				log.Fatalf("Could not run inspect command: %v", err)
			}
		},
	}

	var convertCmd = &cobra.Command{
		Use:   "convert",
		Short: "Generate a PodSecurityPolicy from a single K8s Yaml file",
		Long:  "Generate a PodSecurityPolicy from a single K8s Yaml file containing a pod Spec e.g. DaemonSet, Deployment, ReplicaSet, StatefulSet, ReplicationController, CronJob, Job, or Pod",
		PreRun: func(cmd *cobra.Command, args []string) {
			if podObjFilename == "" {
				log.Fatalf("--podFile must be provided")
			}

			if pspFilename == "" {
				log.Fatalf("--pspFile must be provided")
			}
		},

		Run: func(cmd *cobra.Command, args []string) {
			err := convertPsp(podObjFilename, pspFilename)
			if err != nil {
				log.Fatalf("Could not run convert command: %v", err)
			}
		},
	}

	if home := homedir.HomeDir(); home != "" {
		inspectCmd.Flags().StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		inspectCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}
	inspectCmd.Flags().BoolVar(&withReport, "report", false, "(optional) return with detail report")
	inspectCmd.Flags().BoolVar(&withGrant, "grant", false, "(optional) return with pod security policies, roles and rolebindings")
	inspectCmd.Flags().StringVar(&namespace, "namespace", "", "(optional) namespace")

	convertCmd.Flags().StringVar(&podObjFilename, "podFile", "", "Path to a yaml file containing an object with a pod Spec")
	convertCmd.Flags().StringVar(&pspFilename, "pspFile", "", "Write the resulting PSP to this file")

	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(convertCmd)

	rootCmd.Execute()
}
