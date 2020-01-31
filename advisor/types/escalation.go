package types

import (
	"fmt"

	"github.com/sysdiglabs/kube-psp-advisor/utils"
	"k8s.io/api/policy/v1beta1"
)

const (
	Reduced   = -1
	NoChange  = 0
	Escalated = 1
)

var (
	m = map[int]string{
		Reduced:   "Reduced",
		NoChange:  "No Change",
		Escalated: "Escalated",
	}
)

type EscalationReport struct {
	OverallEscalation   bool            `json:"escalation"`
	OverallReduction    bool            `json:"reduction"`
	Privileged          int             `json:"privileged"`
	HostIPC             int             `json:"hostIPC"`
	HostNetwork         int             `json:"hostNetwork"`
	HostPID             int             `json:"hostPID"`
	NewHostPaths        map[string]bool `json:"new_hostpaths"`
	RemovedHostPaths    map[string]bool `json:"removed_hostpaths"`
	NewVolumeTypes      []string        `json:"new_volume_types"`
	RemovedVolumeTypes  []string        `json:"removed_volume_types"`
	NewCapabilities     []string        `json:"new_capabilities"`
	RemovedCapabilities []string        `json:"reduced_capabilities"`
	RunAsUserStrategy   int             `json:"run_as_user_strategy"`
	RunAsGroupStrategy  int             `json:"un_as_group_strategy"`
	ReadOnlyRootFS      int             `json:"read_only_root_fs"`
}

func NewEscalationReport() *EscalationReport {
	return &EscalationReport{
		Privileged:          NoChange,
		HostNetwork:         NoChange,
		HostIPC:             NoChange,
		HostPID:             NoChange,
		NewHostPaths:        map[string]bool{},
		NewCapabilities:     []string{},
		NewVolumeTypes:      []string{},
		RemovedCapabilities: []string{},
		RemovedHostPaths:    map[string]bool{},
		RemovedVolumeTypes:  []string{},
		RunAsGroupStrategy:  NoChange,
		RunAsUserStrategy:   NoChange,
		ReadOnlyRootFS:      NoChange,
	}
}

func (e *EscalationReport) PrivilegeEscalated() bool {
	return e.Privileged == Escalated
}

func (e *EscalationReport) PrivilegeReduced() bool {
	return e.Privileged == Reduced
}

func (e *EscalationReport) PrivilegeNoChange() bool {
	return e.Privileged == NoChange
}

func (e *EscalationReport) HostIPCEscalated() bool {
	return e.HostIPC == Escalated
}

func (e *EscalationReport) HostIPCReduced() bool {
	return e.HostIPC == Reduced
}

func (e *EscalationReport) HostIPCNoChange() bool {
	return e.HostIPC == NoChange
}

func (e *EscalationReport) HostNetworkEscalated() bool {
	return e.HostNetwork == Escalated
}

func (e *EscalationReport) HostNetworkReduced() bool {
	return e.HostNetwork == Reduced
}

func (e *EscalationReport) HostNetworkNoChange() bool {
	return e.HostNetwork == NoChange
}

func (e *EscalationReport) HostPIDEscalated() bool {
	return e.HostPID == Escalated
}

func (e *EscalationReport) HostPIDReduced() bool {
	return e.HostPID == Reduced
}

func (e *EscalationReport) HostPIDNoChange() bool {
	return e.HostPID == NoChange
}

func (e *EscalationReport) ReadOnlyRootFSEscalated() bool {
	return e.ReadOnlyRootFS == Escalated
}

func (e *EscalationReport) ReadOnlyRootFSReduced() bool {
	return e.ReadOnlyRootFS == Reduced
}

func (e *EscalationReport) ReadOnlyRootFSNoChange() bool {
	return e.ReadOnlyRootFS == NoChange
}

func (e *EscalationReport) RunAsUserStrategyEscalated() bool {
	return e.RunAsUserStrategy == Escalated
}

func (e *EscalationReport) RunAsUserStrategyReduced() bool {
	return e.RunAsUserStrategy == Reduced
}

func (e *EscalationReport) RunAsUserStrategyNoChange() bool {
	return e.RunAsUserStrategy == NoChange
}

func (e *EscalationReport) RunAsGroupStrategyEscalated() bool {
	return e.RunAsGroupStrategy == Escalated
}

func (e *EscalationReport) RunAsGroupStrategyReduced() bool {
	return e.RunAsGroupStrategy == Reduced
}

func (e *EscalationReport) RunAsGroupStrategyNoChange() bool {
	return e.RunAsGroupStrategy == NoChange
}

func (e *EscalationReport) AddedVolumes() bool {
	return len(e.NewVolumeTypes) > 0
}

func (e *EscalationReport) RemovedVolumes() bool {
	return len(e.RemovedVolumeTypes) > 0
}

func (e *EscalationReport) AddedCapabilities() bool {
	return len(e.NewCapabilities) > 0
}

func (e *EscalationReport) DroppedCapabilities() bool {
	return len(e.RemovedCapabilities) > 0
}

func (e *EscalationReport) Escalated() bool {
	if e.PrivilegeEscalated() || e.HostNetworkEscalated() || e.HostPIDEscalated() || e.HostIPCEscalated() || e.AddedVolumes() ||
		e.AddedCapabilities() || e.ReadOnlyRootFSEscalated() || e.RunAsGroupStrategyEscalated() || e.RunAsUserStrategyEscalated() {
		return true
	}

	return false
}

func (e *EscalationReport) Reduced() bool {
	if e.PrivilegeReduced() || e.HostNetworkReduced() || e.HostPIDReduced() || e.HostIPCReduced() || e.RemovedVolumes() ||
		e.DroppedCapabilities() || e.ReadOnlyRootFSReduced() || e.RunAsGroupStrategyReduced() || e.RunAsUserStrategyReduced() {
		return true
	}

	return false
}

func (e *EscalationReport) NoChanges() bool {
	if e.Privileged != NoChange {
		return false
	}

	if e.HostIPC != NoChange {
		return false
	}

	if e.HostPID != NoChange {
		return false
	}

	if e.HostNetwork != NoChange {
		return false
	}

	if e.RunAsGroupStrategy != NoChange {
		return false
	}

	if e.RunAsUserStrategy != NoChange {
		return false
	}

	if e.ReadOnlyRootFS != NoChange {
		return false
	}

	if len(e.RemovedCapabilities) > 0 {
		return false
	}

	if len(e.NewCapabilities) > 0 {
		return false
	}

	if len(e.RemovedVolumeTypes) > 0 {
		return false
	}

	if len(e.NewVolumeTypes) > 0 {
		return false
	}

	return true
}

func (e *EscalationReport) GenerateEscalationReport(psp1, psp2 *v1beta1.PodSecurityPolicy) error {
	if psp1 == nil || psp2 == nil {
		return fmt.Errorf("psp is empty")
	}

	spec1 := psp1.Spec
	spec2 := psp2.Spec

	// privileged mode
	if !spec1.Privileged && spec2.Privileged {
		e.Privileged = Escalated
	} else if spec1.Privileged && !spec2.Privileged {
		e.Privileged = Reduced
	}

	// hostNetwork
	if !spec1.HostNetwork && spec2.HostNetwork {
		e.HostNetwork = Escalated
	} else if spec1.HostNetwork && !spec2.HostNetwork {
		e.HostNetwork = Reduced
	}

	// hostPID
	if !spec1.HostPID && spec2.HostPID {
		e.HostPID = Escalated
	} else if spec1.HostPID && !spec2.HostPID {
		e.HostPID = Reduced
	}

	// hostIPC
	if !spec1.HostIPC && spec2.HostIPC {
		e.HostIPC = Escalated
	} else if spec1.HostIPC && !spec2.HostIPC {
		e.HostIPC = Reduced
	}

	//TODO: host paths

	// mounted volumes
	volMap1 := map[string]bool{}
	volMap2 := map[string]bool{}

	for _, v := range spec1.Volumes {
		volMap1[string(v)] = true
	}

	for _, v := range spec2.Volumes {
		volMap2[string(v)] = true
	}

	_, anyVolExists1 := volMap1["*"]
	_, anyVolExists2 := volMap2["*"]

	if anyVolExists1 && !anyVolExists2 {
		e.RemovedVolumeTypes = append(e.RemovedVolumeTypes, "*")
	}

	if !anyVolExists1 && anyVolExists2 {
		e.NewVolumeTypes = append(e.NewVolumeTypes, "*")
	}

	if !anyVolExists1 && !anyVolExists2 {
		for v1 := range volMap1 {
			if _, exists := volMap2[v1]; !exists {
				e.RemovedVolumeTypes = append(e.RemovedVolumeTypes, v1)
			}
		}

		for v2 := range volMap2 {
			if _, exists := volMap1[v2]; !exists {
				e.NewVolumeTypes = append(e.NewVolumeTypes, v2)
			}
		}
	}

	// capabilities
	addCapMap1 := map[string]bool{}
	addCapMap2 := map[string]bool{}
	allowCapMap1 := map[string]bool{}
	allowCapMap2 := map[string]bool{}
	dropCapMap1 := map[string]bool{}
	dropCapMap2 := map[string]bool{}

	newCapMap := map[string]bool{}
	removedCapMap := map[string]bool{}

	for _, cap := range spec1.DefaultAddCapabilities {
		addCapMap1[string(cap)] = true
	}

	for _, cap := range spec1.RequiredDropCapabilities {
		dropCapMap1[string(cap)] = true
	}

	for _, cap := range spec1.AllowedCapabilities {
		allowCapMap1[string(cap)] = true
	}

	for _, cap := range spec2.DefaultAddCapabilities {
		addCapMap2[string(cap)] = true
	}

	for _, cap := range spec2.RequiredDropCapabilities {
		dropCapMap2[string(cap)] = true
	}

	for _, cap := range spec2.AllowedCapabilities {
		allowCapMap2[string(cap)] = true
	}

	_, anyAddCapExists1 := addCapMap1["*"]
	_, anyAddCapExists2 := addCapMap1["*"]

	if anyAddCapExists1 && !anyAddCapExists2 {
		removedCapMap["*"] = true
	}

	if !anyAddCapExists1 && anyAddCapExists2 {
		newCapMap["*"] = true
	}

	_, anyAllowCapExists1 := allowCapMap1["*"]
	_, anyAllowCapExists2 := allowCapMap2["*"]

	if anyAllowCapExists1 && !anyAllowCapExists2 {
		removedCapMap["*"] = true
	}

	if !anyAllowCapExists1 && anyAllowCapExists2 {
		newCapMap["*"] = true
	}

	// drop * cap doesnt make sense here

	if !anyAddCapExists1 && !anyAddCapExists2 {
		for cap1 := range addCapMap1 {
			if _, exists := addCapMap2[cap1]; !exists {
				removedCapMap[cap1] = true
			}
		}

		for cap2 := range addCapMap2 {
			if _, exists := addCapMap1[cap2]; !exists {
				newCapMap[cap2] = true
			}
		}
	}

	if !anyAllowCapExists1 && !anyAllowCapExists2 {
		for cap1 := range allowCapMap1 {
			if _, exists := allowCapMap2[cap1]; !exists {
				removedCapMap[cap1] = true
			}
		}

		for cap2 := range allowCapMap2 {
			if _, exists := allowCapMap1[cap2]; !exists {
				newCapMap[cap2] = true
			}
		}
	}

	for cap1 := range dropCapMap1 {
		if _, exists := dropCapMap2[cap1]; !exists {
			newCapMap[cap1] = true
		}
	}

	for cap2 := range dropCapMap2 {
		if _, exists := dropCapMap1[cap2]; !exists {
			removedCapMap[cap2] = true
		}
	}

	e.NewCapabilities = utils.MapToArray(newCapMap)
	e.RemovedCapabilities = utils.MapToArray(removedCapMap)

	// runAsUser
	if spec1.RunAsUser.Rule != v1beta1.RunAsUserStrategyRunAsAny && spec2.RunAsUser.Rule == v1beta1.RunAsUserStrategyRunAsAny {
		e.RunAsUserStrategy = Escalated
	} else if spec1.RunAsUser.Rule == v1beta1.RunAsUserStrategyRunAsAny && spec2.RunAsUser.Rule != v1beta1.RunAsUserStrategyRunAsAny {
		e.RunAsUserStrategy = Reduced
	}

	// runAsGroup
	if (spec1.RunAsGroup != nil && spec1.RunAsGroup.Rule != v1beta1.RunAsGroupStrategyRunAsAny) && (spec2.RunAsGroup == nil || spec2.RunAsGroup.Rule == v1beta1.RunAsGroupStrategyRunAsAny) {
		e.RunAsGroupStrategy = Escalated
	} else if (spec1.RunAsGroup == nil || spec1.RunAsGroup.Rule == v1beta1.RunAsGroupStrategyRunAsAny) && (spec2.RunAsGroup != nil && spec2.RunAsGroup.Rule != v1beta1.RunAsGroupStrategyRunAsAny) {
		e.RunAsGroupStrategy = Reduced
	}

	// readOnlyFS
	if spec1.ReadOnlyRootFilesystem && !spec2.ReadOnlyRootFilesystem {
		e.ReadOnlyRootFS = Escalated
	} else if !spec1.ReadOnlyRootFilesystem && spec2.ReadOnlyRootFilesystem {
		e.ReadOnlyRootFS = Reduced
	}

	if e.Escalated() {
		e.OverallEscalation = true
	}

	if e.Reduced() {
		e.OverallReduction = true
	}

	return nil
}

func GetEscalatedStatus(status int) string {
	return m[status]
}
