package comparator

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/sysdiglabs/kube-psp-advisor/generator"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
)

const (
	Source = "Source"
	Target = "Target"
)

type Comparator struct {
	escalationReport *types.EscalationReport
	gen              *generator.Generator
	srcCssList       []types.ContainerSecuritySpec
	srcPssList       []types.PodSecuritySpec
	targetCssList    []types.ContainerSecuritySpec
	targetPssList    []types.PodSecuritySpec
}

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

func (c *Comparator) LoadYamls(yamls []string, dir string) error {
	if dir != Source && dir != Target {
		return fmt.Errorf("invalid directory type: %s (expected 'Source' or 'Target')", dir)
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

	if dir == Source {
		c.srcCssList = cssList
		c.srcPssList = pssList
	} else {
		c.targetCssList = cssList
		c.targetPssList = pssList
	}

	return nil
}

func (c *Comparator) Compare() bool {
	c.escalationReport.GenerateEscalationReportFromSecurityContext(c.srcCssList, c.targetCssList, c.srcPssList, c.targetPssList)
	log.Printf("%+v\n", c.srcCssList)
	log.Printf("%+v\n", c.targetCssList)

	return c.escalationReport.NoChanges()
}

func (c *Comparator) Clear() {
	c.srcCssList = []types.ContainerSecuritySpec{}
	c.targetCssList = []types.ContainerSecuritySpec{}
	c.srcPssList = []types.PodSecuritySpec{}
	c.targetPssList = []types.PodSecuritySpec{}

	c.escalationReport = types.NewEscalationReport()
}

func (c *Comparator) PrintEscalationReport() {
	data, _ := json.Marshal(c.escalationReport)

	fmt.Println(string(data))

}
