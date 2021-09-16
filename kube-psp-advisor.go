package main

import (
	"fmt"
	"strings"

	"github.com/sysdiglabs/kube-psp-advisor/comparator"

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

func inspect(kubeconfig string, namespace string, excludeNamespaces []string, withReport, withGrant bool, OPAformat bool, OPAdefaultRule bool) error {
	advisor, err := advisor.NewAdvisor(kubeconfig)

	if err != nil {
		return fmt.Errorf("Could not create advisor object: %v", err)
	}

	err = advisor.Process(namespace, excludeNamespaces, OPAformat, OPAdefaultRule)

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

	if !OPAformat {
		err = advisor.PrintPodSecurityPolicy()
		if err != nil {
			return fmt.Errorf("Could not print PSP: %v", err)
		}
	} else {
		opaRuleOutput := advisor.PrintOPAPolicy()
		if opaRuleOutput == "" {
			return fmt.Errorf("Could not print OPA rule: %v", err)
		}
	}
	return nil
}

func convert(podObjFilename string, pspFilename string, OPAformat bool, OPAdefaultRule bool) error {
	podObjFile, err := os.Open(podObjFilename)
	if err != nil {
		return fmt.Errorf("Could not open pod object file %s for reading: %v", podObjFilename, err)
	}
	defer podObjFile.Close()

	log.Debugf("Reading pod Obj File from %s", podObjFilename)

	podObjString, err := ioutil.ReadAll(podObjFile)

	if err != nil {
		return fmt.Errorf("failed to read contents of pod object file %s: %v", podObjFilename, err)
	}

	log.Debugf("Contents of Obj File: %s", podObjString)

	psp_gen, err := generator.NewGenerator()
	if err != nil {
		return fmt.Errorf("failed to create PSP Generator: %v", err)
	}

	pspString, err := psp_gen.FromPodObjString(string(podObjString), OPAformat, OPAdefaultRule)
	if err != nil {
		return fmt.Errorf("failed to generate PSP from pod Object: %v", err)
	}

	err = ioutil.WriteFile(pspFilename, []byte(pspString), 0644)

	log.Infof("Wrote generated psp to %s", pspFilename)

	return nil
}

func comparePsp(srcDir, targetDir string) error {
	srcYamls, err := getWorkLoadYamls(srcDir)

	if err != nil {
		return fmt.Errorf("failed to read source workload directory %s: %s", srcDir, err)
	}

	targetYamls, err := getWorkLoadYamls(targetDir)

	if err != nil {
		return fmt.Errorf("failed to read target workload directory %s: %s", targetDir, err)
	}

	c, err := comparator.NewComparator()

	if err != nil {
		return fmt.Errorf("failed to create PSP comparator")
	}

	err = c.LoadYamls(srcYamls, comparator.Source)

	if err != nil {
		return fmt.Errorf("failed to create PSP comparator")
	}

	err = c.LoadYamls(targetYamls, comparator.Target)

	if err != nil {
		return fmt.Errorf("failed to create PSP comparator")
	}

	c.Compare()

	c.PrintEscalationReport()

	return nil
}

func main() {

	var kubeconfig string
	var withReport bool
	var withGrant bool
	var namespace string
	var excludeNamespaces []string
	var podObjFilename string
	var pspFilename string
	var OPAformat bool
	var OPAdefaultRule bool
	var logLevel string
	var srcYamlDir string
	var targetYamlDir string

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

			err := inspect(kubeconfig, namespace, excludeNamespaces, withReport, withGrant, OPAformat, OPAdefaultRule)

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
			err := convert(podObjFilename, pspFilename, OPAformat, OPAdefaultRule)
			if err != nil {
				log.Fatalf("Could not run convert command: %v", err)
			}
		},
	}

	var compareCmd = &cobra.Command{
		Use:   "compare",
		Short: "Compare k8s workload YAML files",
		Long:  "Compare k8s workload YAML files and generate privilege escalation report",
		PreRun: func(cmd *cobra.Command, args []string) {
			if srcYamlDir == "" {
				log.Fatalf("--srcDir must be provided")
			}

			if targetYamlDir == "" {
				log.Fatalf("--targetDir must be provided")
			}
		},

		Run: func(cmd *cobra.Command, args []string) {
			err := comparePsp(srcYamlDir, targetYamlDir)
			if err != nil {
				log.Fatalf("Could not run compare command: %v", err)
			}
		},
	}

	if home := homedir.HomeDir(); home != "" {
		inspectCmd.Flags().StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		inspectCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}
	inspectCmd.Flags().BoolVarP(&withReport, "report", "r", false, "(optional) return with detail report")
	inspectCmd.Flags().BoolVarP(&withGrant, "grant", "g", false, "(optional) return with pod security policies, roles and rolebindings")
	inspectCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "(optional) namespace")
	inspectCmd.Flags().StringSliceVarP(&excludeNamespaces, "exclude-namespaces", "e", []string{}, "(optional) comma separated list of namespaces to exclude")
	inspectCmd.Flags().BoolVarP(&OPAformat, "opa", "", false, "(optional) OPA option for output in OPA format")
	inspectCmd.Flags().BoolVarP(&OPAdefaultRule, "OPADefaultRule", "", false, "(optional) OPA Default Rule: use this option iF OPA Default Rule is Deny ALL")

	convertCmd.Flags().StringVar(&podObjFilename, "podFile", "", "Path to a yaml file containing an object with a pod Spec")
	convertCmd.Flags().StringVar(&pspFilename, "pspFile", "", "Write the resulting output to this file")
	convertCmd.Flags().BoolVarP(&OPAformat, "opa", "", false, "(optional) OPA option for output in OPA format")
	convertCmd.Flags().BoolVarP(&OPAdefaultRule, "deny-by-default", "", false, "(optional) OPA Default Rule: use this option if OPA Default Rule is Deny ALL")

	compareCmd.Flags().StringVar(&srcYamlDir, "sourceDir", "", "Source YAML directory to load YAMLs")
	compareCmd.Flags().StringVar(&targetYamlDir, "targetDir", "", "Target YAML directory to load YAMLs")

	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(compareCmd)

	rootCmd.Execute()
}

func getWorkLoadYamls(dir string) ([]string, error) {
	yamls := []string{}

	err := filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
				yamls = append(yamls, path)
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}

	return yamls, nil
}
