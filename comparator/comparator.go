package comparator

import (
	"encoding/json"
	"fmt"

	"github.com/sysdiglabs/kube-psp-advisor/generator"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
)

const (
	Source = "Source"
	Target = "Target"
)

type Comparator struct {
	escalationReport *types.LintReport
	gen              *generator.Generator
	srcCssList       []types.ContainerSecuritySpec
	srcPssList       []types.PodSecuritySpec
	targetCssList    []types.ContainerSecuritySpec
	targetPssList    []types.PodSecuritySpec
}

// NewComparator returns a new comparator object
func NewComparator() (*Comparator, error) {
	gen, err := generator.NewGenerator()

	if err != nil {
		return nil, err
	}

	return &Comparator{
		gen:              gen,
		escalationReport: types.NewEscalationReport(),
		srcCssList:       []types.ContainerSecuritySpec{},
		srcPssList:       []types.PodSecuritySpec{},
		targetCssList:    []types.ContainerSecuritySpec{},
		targetPssList:    []types.PodSecuritySpec{},
	}, nil
}

// LoadYamls loads yamls from files
func (c *Comparator) LoadYamls(yamls []string, dirType string) error {
	if dirType != Source && dirType != Target {
		return fmt.Errorf("invalid directory type: %s (expected 'Source' or 'Target')", dirType)
	}
	cssList := []types.ContainerSecuritySpec{}
	pssList := []types.PodSecuritySpec{}
	for _, yamlFile := range yamls {
		csl, psl, err := c.gen.LoadYaml(yamlFile)
		if err != nil {
			return err
		}

		if len(csl) > 0 {
			cssList = append(cssList, csl...)
			pssList = append(pssList, psl...)
		}
	}

	if dirType == Source {
		c.srcCssList = cssList
		c.srcPssList = pssList
	} else {
		c.targetCssList = cssList
		c.targetPssList = pssList
	}

	return nil
}

// Compare compares security contexts between the source YAMLs and target YAMLs
func (c *Comparator) Compare() {
	c.escalationReport.GenerateEscalationReportFromSecurityContext(c.srcCssList, c.targetCssList, c.srcPssList, c.targetPssList)
}

// Clear clears everything in the comparator
func (c *Comparator) Clear() {
	c.srcCssList = []types.ContainerSecuritySpec{}
	c.targetCssList = []types.ContainerSecuritySpec{}
	c.srcPssList = []types.PodSecuritySpec{}
	c.targetPssList = []types.PodSecuritySpec{}

	c.escalationReport = types.NewEscalationReport()
}

// PrintEscalationReport prints escalation report to STDOUT
func (c *Comparator) PrintEscalationReport() {
	data, _ := json.Marshal(c.escalationReport)

	fmt.Println(string(data))

}
