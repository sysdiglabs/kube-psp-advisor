package comparator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
	"k8s.io/api/policy/v1beta1"
)

const (
	NotAvailable = "N/A"
)

type Comparator struct {
	srcPSP           *v1beta1.PodSecurityPolicy
	targetPSP        *v1beta1.PodSecurityPolicy
	escalationReport *types.EscalationReport
}

func NewComparator() (*Comparator, error) {
	return &Comparator{
		escalationReport: types.NewEscalationReport(),
	}, nil
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

func (c *Comparator) PrintEscalationReport(jsonFormat bool) {
	if c.targetPSP == nil || c.srcPSP == nil {
		return
	}

	if !jsonFormat {
		table1 := tablewriter.NewWriter(os.Stdout)
		table1.SetHeader([]string{"Security Attributes", "Previous", "Current", "Changed"})

		data := [][]string{
			{"Privileged", getBool(c.srcPSP.Spec.Privileged), getBool(c.targetPSP.Spec.Privileged), types.GetEscalatedStatus(c.escalationReport.Privileged)},
			{"hostIPC", getBool(c.srcPSP.Spec.HostPID), getBool(c.targetPSP.Spec.HostPID), types.GetEscalatedStatus(c.escalationReport.HostPID)},
			{"hostNetwork", getBool(c.srcPSP.Spec.HostNetwork), getBool(c.targetPSP.Spec.HostNetwork), types.GetEscalatedStatus(c.escalationReport.HostNetwork)},
			{"HostPID", getBool(c.srcPSP.Spec.HostPID), getBool(c.targetPSP.Spec.HostPID), types.GetEscalatedStatus(c.escalationReport.HostPID)},
			{"ReadOnlyRootFileSystem", getBool(c.srcPSP.Spec.ReadOnlyRootFilesystem), getBool(c.targetPSP.Spec.ReadOnlyRootFilesystem), types.GetEscalatedStatus(c.escalationReport.ReadOnlyRootFS)},
			{"RunAsUserStrategy", string(c.srcPSP.Spec.RunAsUser.Rule), string(c.targetPSP.Spec.RunAsUser.Rule), types.GetEscalatedStatus(c.escalationReport.RunAsUserStrategy)},
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
		data, _ := json.MarshalIndent(c.escalationReport, "", "    ")

		fmt.Println(string(data))
	}
}

func getBool(value bool) string {
	return fmt.Sprintf("%t", value)
}
