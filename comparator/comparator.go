package comparator

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sysdiglabs/kube-psp-advisor/generator"

	"github.com/olekukonko/tablewriter"
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"k8s.io/api/policy/v1beta1"
)

const (
	NotAvailable = "N/A"
	Source       = "Source"
	Target       = "Target"
)

type Comparator struct {
	srcPSP           *v1beta1.PodSecurityPolicy
	targetPSP        *v1beta1.PodSecurityPolicy
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
	c.srcPSP = c.gen.GeneratePSP(c.srcCssList, c.srcPssList, "", types.Version1_11)
	c.targetPSP = c.gen.GeneratePSP(c.targetCssList, c.targetPssList, "", types.Version1_11)

	err := c.escalationReport.GenerateEscalationReport(c.srcPSP, c.targetPSP)

	if err != nil {
		log.Printf("failed to generate escalation report: %s", err)
	}

	c.escalationReport.EnrichEscalationReport(c.srcCssList, c.targetCssList, c.srcPssList, c.targetPssList)

	return c.escalationReport.NoChanges()
}

func (c *Comparator) ComparePSP(psp1, psp2 *v1beta1.PodSecurityPolicy) bool {
	c.clear()

	c.srcPSP = psp1
	c.targetPSP = psp2
	err := c.escalationReport.GenerateEscalationReport(psp1, psp2)

	if err != nil {
		fmt.Println(err)
	}

	return c.escalationReport.NoChanges()
}

func (c *Comparator) clear() {
	c.srcPSP = nil
	c.targetPSP = nil
	c.escalationReport = types.NewEscalationReport()
}

func metaListToString(metaList []types.Metadata) string {
	ret := []string{}
	for _, meta := range metaList {
		ret = append(ret, fmt.Sprintf("%s/%s/%s in %s", meta.Kind, meta.Namespace, meta.Name, meta.YamlFile))
	}

	return strings.Join(ret, "\n")
}

func (c *Comparator) FindPrivilegedChangedWorkload(status int) string {
	srcCssMap := map[types.Metadata]types.ContainerSecuritySpec{}
	targetCssMap := map[types.Metadata]types.ContainerSecuritySpec{}

	metaList := []types.Metadata{}

	for _, css := range c.srcCssList {
		srcCssMap[css.Metadata] = css
	}

	for _, css := range c.targetCssList {
		targetCssMap[css.Metadata] = css
	}

	if status == types.Escalated {
		for meta, targetCss := range targetCssMap {
			srcCss, exits := srcCssMap[meta]
			if targetCss.Privileged && (!exits || !srcCss.Privileged) {
				metaList = append(metaList, meta)
			}
		}
	} else if status == types.Reduced {
		for meta, srcCss := range srcCssMap {
			targetCss, exists := targetCssMap[meta]

			if !targetCss.Privileged && (!exists || srcCss.Privileged) {
				metaList = append(metaList, meta)
			}
		}
	}

	return metaListToString(metaList)
}

func (c *Comparator) PrintEscalationReport(jsonFormat bool) {
	if c.targetPSP == nil || c.srcPSP == nil {
		return
	}

	if !jsonFormat {
		table1 := tablewriter.NewWriter(os.Stdout)
		table1.SetHeader([]string{"Security Attributes", "Previous", "Current", "Changed", "Detail"})

		data := [][]string{
			{"Privileged", getBool(c.srcPSP.Spec.Privileged), getBool(c.targetPSP.Spec.Privileged), types.GetEscalatedStatus(c.escalationReport.Privileged.Status), c.FindPrivilegedChangedWorkload(c.escalationReport.Privileged.Status)},
			{"hostIPC", getBool(c.srcPSP.Spec.HostPID), getBool(c.targetPSP.Spec.HostPID), types.GetEscalatedStatus(c.escalationReport.HostPID.Status), ""},
			{"hostNetwork", getBool(c.srcPSP.Spec.HostNetwork), getBool(c.targetPSP.Spec.HostNetwork), types.GetEscalatedStatus(c.escalationReport.HostNetwork.Status), ""},
			{"HostPID", getBool(c.srcPSP.Spec.HostPID), getBool(c.targetPSP.Spec.HostPID), types.GetEscalatedStatus(c.escalationReport.HostPID.Status), ""},
			{"ReadOnlyRootFileSystem", getBool(c.srcPSP.Spec.ReadOnlyRootFilesystem), getBool(c.targetPSP.Spec.ReadOnlyRootFilesystem), types.GetEscalatedStatus(c.escalationReport.ReadOnlyRootFS.Status), ""},
			{"RunAsUserStrategy", string(c.srcPSP.Spec.RunAsUser.Rule), string(c.targetPSP.Spec.RunAsUser.Rule), types.GetEscalatedStatus(c.escalationReport.RunAsUserStrategy), ""},
		}

		srcRunAsGroup := ""
		targetRunAsGroup := ""

		if c.srcPSP.Spec.RunAsGroup == nil {
			srcRunAsGroup = string(v1beta1.RunAsGroupStrategyRunAsAny)
		} else {
			srcRunAsGroup = string(c.srcPSP.Spec.RunAsGroup.Rule)
		}

		if c.targetPSP.Spec.RunAsGroup == nil {
			targetRunAsGroup = string(v1beta1.RunAsGroupStrategyRunAsAny)
		} else {
			srcRunAsGroup = string(c.targetPSP.Spec.RunAsGroup.Rule)
		}

		data = append(data,
			[]string{"RunAsGroupStrategy", srcRunAsGroup, targetRunAsGroup, types.GetEscalatedStatus(c.escalationReport.RunAsGroupStrategy)})

		table1.AppendBulk(data)

		table1.Render()

		table2 := tablewriter.NewWriter(os.Stdout)
		// print capabilities, volumes
		table2.SetHeader([]string{"Security Attributes", "Changed"})

		addedCaps := ""
		removedCaps := ""
		addedVols := ""
		removedVols := ""

		if c.escalationReport.AddedCapabilities() {
			addedCaps = strings.Join(c.escalationReport.NewCapabilities, ",")
		} else {
			addedCaps = NotAvailable
		}

		if c.escalationReport.DroppedCapabilities() {
			removedCaps = strings.Join(c.escalationReport.RemovedCapabilities, ",")
		} else {
			removedCaps = NotAvailable
		}

		if c.escalationReport.AddedVolumes() {
			addedVols = strings.Join(c.escalationReport.NewVolumeTypes, ",")
		} else {
			addedVols = NotAvailable
		}

		if c.escalationReport.RemovedVolumes() {
			removedVols = strings.Join(c.escalationReport.RemovedVolumeTypes, ",")
		} else {
			removedVols = NotAvailable
		}
		data2 := [][]string{
			{"Added Linux Capabilities", addedCaps},
			{"Removed Linux Capabilities", removedCaps},
			{"Added Volumes", addedVols},
			{"Removed Volumes", removedVols},
		}

		table2.AppendBulk(data2)

		table2.Render()
	} else {
		data, _ := json.Marshal(c.escalationReport)

		fmt.Println(string(data))
	}
}

func getBool(value bool) string {
	return fmt.Sprintf("%t", value)
}
