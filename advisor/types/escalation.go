package types

import (
	"github.com/sysdiglabs/kube-psp-advisor/utils"
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

const (
	root    = "root"
	nonRoot = "non-root"
)

type EscalationReport struct {
	TotalSourceWorkloads  int                    `json:"total_source_workloads"`
	TotalTargetWorkloads  int                    `json:"total_target_workloads"`
	TotalEscalation       int                    `json:"escalation_count"`
	TotalReduction        int                    `json:"reduction_count"`
	Escalations           []Metadata             `json:"escalations"`
	Reductions            []Metadata             `json:"reductions"`
	NewPrivileged         *Escalation            `json:"new_privileged"`
	RemovedPrivileged     *Escalation            `json:"removed_privileged"`
	NewHostIPC            *Escalation            `json:"new_hostIPC"`
	RemovedHostIPC        *Escalation            `json:"removed_hostIPC"`
	NewHostNetwork        *Escalation            `json:"new_hostNetwork"`
	RemovedHostNetwork    *Escalation            `json:"removed_hostNetwork"`
	NewHostPID            *Escalation            `json:"new_hostPID"`
	RemovedHostPID        *Escalation            `json:"removed_hostPID"`
	NewHostPaths          map[string]bool        `json:"-"`
	RemovedHostPaths      map[string]bool        `json:"-"`
	NewVolumeTypes        map[string]*Escalation `json:"new_volume_types"`
	RemovedVolumeTypes    map[string]*Escalation `json:"removed_volume_types"`
	NewCapabilities       map[string]*Escalation `json:"new_capabilities"`
	RemovedCapabilities   map[string]*Escalation `json:"reduced_capabilities"`
	NewRunUserAsRoot      *Escalation            `json:"new_run_user_as_root"`
	RemovedRunUserAsRoot  *Escalation            `json:"removed_run_user_as_root"`
	NewRunGroupAsRoot     *Escalation            `json:"new_run_group_as_root"`
	RemovedRunGroupAsRoot *Escalation            `json:"removed_run_group_as_root"`
	NewReadOnlyRootFS     *Escalation            `json:"new_read_only_root_fs"`
	RemovedReadOnlyRootFS *Escalation            `json:"removed_read_only_root_fs"`
}

type Escalation struct {
	Status        int               `json:"-"`
	StatusMessage string            `json:"status"`
	Previous      string            `json:"previous"`
	Current       string            `json:"current"`
	Workloads     []Metadata        `json:"workloads"`
	WorkloadCount int               `json:"workloads_count"`
	workloadMap   map[Metadata]bool `json:"-"`
}

func InitEscalation(status int, prev, cur string) *Escalation {
	return &Escalation{
		Status:        status,
		StatusMessage: getEscalatedStatus(status),
		Previous:      prev,
		Current:       cur,
		Workloads:     []Metadata{},
		workloadMap:   map[Metadata]bool{},
	}
}

func (e *Escalation) SetEscalation(status int, prev, cur string) {
	e.Status = status
	e.StatusMessage = getEscalatedStatus(status)
	e.Previous = prev
	e.Current = cur
}

func (e *Escalation) UseSecurityContext() bool {
	return len(e.Workloads) > 0
}

func (e *Escalation) AddWorkload(w Metadata) {
	e.workloadMap[w] = true
}

func (e *Escalation) ConsolidateWorkload() {
	for w := range e.workloadMap {
		e.Workloads = append(e.Workloads, w)
	}

	e.WorkloadCount = len(e.Workloads)
}

func (e *Escalation) NoChanges() bool {
	return !e.UseSecurityContext()
}

func (e *Escalation) IsEscalated() bool {
	return e.Status == Escalated && e.UseSecurityContext()
}

func (e *Escalation) IsReduced() bool {
	return e.Status == Reduced && e.UseSecurityContext()
}

func NewEscalationReport() *EscalationReport {
	return &EscalationReport{
		TotalSourceWorkloads:  0,
		TotalTargetWorkloads:  0,
		TotalEscalation:       0,
		TotalReduction:        0,
		Escalations:           []Metadata{},
		Reductions:            []Metadata{},
		NewPrivileged:         InitEscalation(Escalated, "false", "true"),
		RemovedPrivileged:     InitEscalation(Reduced, "true", "false"),
		NewHostNetwork:        InitEscalation(Escalated, "false", "true"),
		RemovedHostNetwork:    InitEscalation(Reduced, "true", "false"),
		NewHostIPC:            InitEscalation(Escalated, "false", "true"),
		RemovedHostIPC:        InitEscalation(Reduced, "true", "false"),
		NewHostPID:            InitEscalation(Escalated, "false", "true"),
		RemovedHostPID:        InitEscalation(Reduced, "true", "false"),
		NewHostPaths:          map[string]bool{},
		RemovedHostPaths:      map[string]bool{},
		NewCapabilities:       map[string]*Escalation{},
		RemovedCapabilities:   map[string]*Escalation{},
		NewVolumeTypes:        map[string]*Escalation{},
		RemovedVolumeTypes:    map[string]*Escalation{},
		NewRunGroupAsRoot:     InitEscalation(Escalated, nonRoot, root),
		RemovedRunGroupAsRoot: InitEscalation(Reduced, root, nonRoot),
		NewRunUserAsRoot:      InitEscalation(Escalated, nonRoot, root),
		RemovedRunUserAsRoot:  InitEscalation(Reduced, root, nonRoot),
		NewReadOnlyRootFS:     InitEscalation(Reduced, "false", "true"),
		RemovedReadOnlyRootFS: InitEscalation(Escalated, "true", "false"),
	}
}

func (er *EscalationReport) PrivilegeEscalated() bool {
	return er.NewPrivileged.IsEscalated()
}

func (er *EscalationReport) PrivilegeReduced() bool {
	return er.RemovedPrivileged.IsReduced()
}

func (er *EscalationReport) PrivilegeNoChange() bool {
	return !er.PrivilegeReduced() && !er.PrivilegeReduced()
}

func (er *EscalationReport) HostIPCEscalated() bool {
	return er.NewHostIPC.IsEscalated()
}

func (er *EscalationReport) HostIPCReduced() bool {
	return er.RemovedHostIPC.IsReduced()
}

func (er *EscalationReport) HostIPCNoChange() bool {
	return !er.HostIPCEscalated() && !er.HostIPCReduced()
}

func (er *EscalationReport) HostNetworkEscalated() bool {
	return er.NewHostNetwork.IsEscalated()
}

func (er *EscalationReport) HostNetworkReduced() bool {
	return er.RemovedHostNetwork.IsReduced()
}

func (er *EscalationReport) HostNetworkNoChange() bool {
	return !er.HostNetworkEscalated() && !er.HostNetworkReduced()
}

func (er *EscalationReport) HostPIDEscalated() bool {
	return er.NewHostPID.IsEscalated()
}

func (er *EscalationReport) HostPIDReduced() bool {
	return er.RemovedHostPID.IsReduced()
}

func (er *EscalationReport) HostPIDNoChange() bool {
	return !er.HostPIDEscalated() && !er.HostPIDReduced()
}

func (er *EscalationReport) ReadOnlyRootFSEscalated() bool {
	return er.RemovedReadOnlyRootFS.IsEscalated()
}

func (er *EscalationReport) ReadOnlyRootFSReduced() bool {
	return er.NewReadOnlyRootFS.IsReduced()
}

func (er *EscalationReport) ReadOnlyRootFSNoChange() bool {
	return !er.ReadOnlyRootFSEscalated() && !er.ReadOnlyRootFSReduced()
}

func (er *EscalationReport) RunUserAsRootEscalated() bool {
	return er.NewRunUserAsRoot.IsEscalated()
}

func (er *EscalationReport) RunUserAsRootReduced() bool {
	return er.RemovedRunUserAsRoot.IsReduced()
}

func (er *EscalationReport) RunUserAsRootNoChange() bool {
	return !er.RunUserAsRootEscalated() && !er.RunUserAsRootReduced()
}

func (er *EscalationReport) RunGroupAsRootEscalated() bool {
	return er.NewRunGroupAsRoot.IsEscalated()
}

func (er *EscalationReport) RunGroupAsRootReduced() bool {
	return er.RemovedRunGroupAsRoot.IsReduced()
}

func (er *EscalationReport) RunGroupAsRootNoChange() bool {
	return er.NewRunGroupAsRoot.NoChanges()
}

func (er *EscalationReport) AddedVolumes() bool {
	return len(er.NewVolumeTypes) > 0
}

func (er *EscalationReport) RemovedVolumes() bool {
	return len(er.RemovedVolumeTypes) > 0
}

func (er *EscalationReport) AddedCapabilities() bool {
	return len(er.NewCapabilities) > 0
}

func (er *EscalationReport) DroppedCapabilities() bool {
	return len(er.RemovedCapabilities) > 0
}

func (er *EscalationReport) Escalated() bool {
	if er.PrivilegeEscalated() || er.HostNetworkEscalated() || er.HostPIDEscalated() || er.HostIPCEscalated() || er.AddedVolumes() ||
		er.AddedCapabilities() || er.ReadOnlyRootFSEscalated() || er.RunGroupAsRootEscalated() || er.RunUserAsRootEscalated() {
		return true
	}

	return false
}

func (er *EscalationReport) Reduced() bool {
	if er.PrivilegeReduced() || er.HostNetworkReduced() || er.HostPIDReduced() || er.HostIPCReduced() || er.RemovedVolumes() ||
		er.DroppedCapabilities() || er.ReadOnlyRootFSReduced() || er.RunGroupAsRootReduced() || er.RunUserAsRootReduced() {
		return true
	}

	return false
}

func (er *EscalationReport) NoChanges() bool {
	if !er.NewPrivileged.NoChanges() {
		return false
	}

	if !er.NewHostIPC.NoChanges() {
		return false
	}

	if !er.NewHostPID.NoChanges() {
		return false
	}

	if !er.NewHostNetwork.NoChanges() {
		return false
	}

	if !er.NewRunGroupAsRoot.NoChanges() {
		return false
	}

	if !er.NewRunUserAsRoot.NoChanges() {
		return false
	}

	if !er.NewReadOnlyRootFS.NoChanges() {
		return false
	}

	if len(er.RemovedCapabilities) > 0 {
		return false
	}

	if len(er.NewCapabilities) > 0 {
		return false
	}

	if len(er.RemovedVolumeTypes) > 0 {
		return false
	}

	if len(er.NewVolumeTypes) > 0 {
		return false
	}

	return true
}

func (er *EscalationReport) GenerateEscalationReportFromSecurityContext(srcCssList, targetCssList []ContainerSecuritySpec, srcPssList, targetPssList []PodSecuritySpec) {
	srcCssMap := map[Metadata]ContainerSecuritySpec{}
	targetCssMap := map[Metadata]ContainerSecuritySpec{}

	srcPssMap := map[Metadata]PodSecuritySpec{}
	targetPssMap := map[Metadata]PodSecuritySpec{}

	escalations := InitEscalation(Escalated, "", "")
	reductions := InitEscalation(Reduced, "", "")

	for _, css := range srcCssList {
		srcCssMap[css.Metadata] = css
	}

	for _, css := range targetCssList {
		targetCssMap[css.Metadata] = css
	}

	for _, pss := range srcPssList {
		srcPssMap[pss.Metadata] = pss
	}

	for _, pss := range targetPssList {
		targetPssMap[pss.Metadata] = pss
	}

	// privileged - false to true (escalated)
	for meta, targetCss := range targetCssMap {
		srcCss, exits := srcCssMap[meta]
		if targetCss.Privileged && (!exits || !srcCss.Privileged) {
			er.NewPrivileged.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewPrivileged.ConsolidateWorkload()

	// privileged - true to false (reduced)
	for meta, srcCss := range srcCssMap {
		targetCss, exists := targetCssMap[meta]

		if srcCss.Privileged && (!exists || !targetCss.Privileged) {
			er.RemovedPrivileged.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedPrivileged.ConsolidateWorkload()

	// hostNetwork - false to true (escalated)
	for meta, targetPss := range targetPssMap {
		srcPss, exits := srcPssMap[meta]
		if targetPss.HostNetwork && (!exits || !srcPss.HostNetwork) {
			er.NewHostNetwork.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewHostNetwork.ConsolidateWorkload()

	// hostNetwork - true to false (reduced)
	for meta, srcPss := range srcPssMap {
		targetPss, exists := targetPssMap[meta]

		if srcPss.HostNetwork && (!exists || !targetPss.HostNetwork) {
			er.RemovedHostNetwork.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedHostNetwork.ConsolidateWorkload()

	// hostIPC - false to true (escalated)
	for meta, targetPss := range targetPssMap {
		srcPss, exits := srcPssMap[meta]
		if targetPss.HostIPC && (!exits || !srcPss.HostIPC) {
			er.NewHostIPC.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewHostIPC.ConsolidateWorkload()

	// hostIPC - true to false (reduced)
	for meta, srcPss := range srcPssMap {
		targetPss, exists := targetPssMap[meta]

		if srcPss.HostIPC && (!exists || !targetPss.HostIPC) {
			er.RemovedHostIPC.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedHostIPC.ConsolidateWorkload()

	// hostPID - false to true (escalated)
	for meta, targetPss := range targetPssMap {
		srcPss, exits := srcPssMap[meta]
		if targetPss.HostPID && (!exits || !srcPss.HostPID) {
			er.NewHostPID.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewHostPID.ConsolidateWorkload()

	// hostPID - true to false (reduced)
	for meta, srcPss := range srcPssMap {
		targetPss, exists := targetPssMap[meta]

		if srcPss.HostPID && (!exists || !targetPss.HostPID) {
			er.RemovedHostPID.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedHostPID.ConsolidateWorkload()

	// readOnlyRootFS - true to false (escalated)
	for meta, targetCss := range targetCssMap {
		srcCss, exists := srcCssMap[meta]
		if !targetCss.ReadOnlyRootFS && (!exists || srcCss.ReadOnlyRootFS) {
			er.RemovedReadOnlyRootFS.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.RemovedReadOnlyRootFS.ConsolidateWorkload()

	// readOnlyRootFS - false to true (reduced)
	for meta, srcCss := range srcCssMap {
		targetCss, exists := targetCssMap[meta]

		if !srcCss.ReadOnlyRootFS && (!exists || targetCss.ReadOnlyRootFS) {
			er.NewReadOnlyRootFS.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.NewReadOnlyRootFS.ConsolidateWorkload()

	// runAsUer - non root to root (escalated)
	for meta, targetCss := range targetCssMap {
		srcCss, exists := srcCssMap[meta]
		if (targetCss.RunAsUser == nil || *targetCss.RunAsUser == 0) && (!exists || (srcCss.RunAsUser != nil && *srcCss.RunAsUser > 0)) {
			er.NewRunUserAsRoot.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewRunUserAsRoot.ConsolidateWorkload()

	// runAsUer - root to non root (reduced)
	for meta, srcCss := range srcCssMap {
		targetCss, exists := targetCssMap[meta]

		if (srcCss.RunAsUser == nil || *srcCss.RunAsUser == 0) && (!exists || (targetCss.RunAsUser != nil && *targetCss.RunAsUser > 0)) {
			er.RemovedRunUserAsRoot.workloadMap[meta] = true
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedRunUserAsRoot.ConsolidateWorkload()

	// runAsGroup - non root to root (escalated)
	for meta, targetCss := range targetCssMap {
		srcCss, exists := srcCssMap[meta]
		if (targetCss.RunAsGroup == nil || *targetCss.RunAsGroup == 0) && (!exists || (srcCss.RunAsGroup != nil && *srcCss.RunAsGroup > 0)) {
			er.NewRunGroupAsRoot.AddWorkload(meta)
			escalations.AddWorkload(meta)
		}
	}
	er.NewRunGroupAsRoot.ConsolidateWorkload()

	// runAsGroup - root to non root (reduced)
	for meta, srcCss := range srcCssMap {
		targetCss, exists := targetCssMap[meta]

		if (srcCss.RunAsGroup == nil || *srcCss.RunAsGroup == 0) && (!exists || (targetCss.RunAsGroup != nil && *targetCss.RunAsGroup > 0)) {
			er.RemovedRunGroupAsRoot.AddWorkload(meta)
			reductions.AddWorkload(meta)
		}
	}
	er.RemovedRunGroupAsRoot.ConsolidateWorkload()

	// caps
	for meta, targetCss := range targetCssMap {
		srcCss, exists := srcCssMap[meta]

		if exists {
			leftDiff, rightDiff := diff(srcCss.Capabilities, targetCss.Capabilities)

			for _, cap := range rightDiff {
				if _, capExists := er.NewCapabilities[cap]; !capExists {
					er.NewCapabilities[cap] = InitEscalation(Escalated, "", cap)
				}
				er.NewCapabilities[cap].AddWorkload(meta)
				escalations.AddWorkload(meta)
			}

			for _, cap := range leftDiff {
				if _, capExists := er.RemovedCapabilities[cap]; !capExists {
					er.RemovedCapabilities[cap] = InitEscalation(Reduced, cap, "")
				}

				er.RemovedCapabilities[cap].AddWorkload(meta)
				reductions.AddWorkload(meta)
			}
		}
	}

	for _, e := range er.NewCapabilities {
		e.ConsolidateWorkload()
	}

	for _, e := range er.RemovedCapabilities {
		e.ConsolidateWorkload()
	}

	// volume types (configMap, secret, emptryDir etc.)
	for meta, targetPss := range targetPssMap {
		srcPss, exists := srcPssMap[meta]

		if exists {
			leftDiff, rightDiff := diff(srcPss.VolumeTypes, targetPss.VolumeTypes)

			for _, vol := range rightDiff {
				if _, volExists := er.NewVolumeTypes[vol]; !volExists {
					er.NewVolumeTypes[vol] = InitEscalation(Escalated, "", vol)
				}
				er.NewVolumeTypes[vol].AddWorkload(meta)
				escalations.AddWorkload(meta)
			}

			for _, vol := range leftDiff {
				if _, volExists := er.RemovedVolumeTypes[vol]; !volExists {
					er.RemovedVolumeTypes[vol] = InitEscalation(Reduced, vol, "")
				}
				er.RemovedVolumeTypes[vol].AddWorkload(meta)
				reductions.AddWorkload(meta)
			}
		}
	}

	for _, e := range er.NewVolumeTypes {
		e.ConsolidateWorkload()
	}

	for _, e := range er.RemovedVolumeTypes {
		e.ConsolidateWorkload()
	}

	escalations.ConsolidateWorkload()
	reductions.ConsolidateWorkload()

	er.Escalations = append(er.Escalations, escalations.Workloads...)
	er.Reductions = append(er.Reductions, reductions.Workloads...)

	er.TotalEscalation = len(er.Escalations)
	er.TotalReduction = len(er.Reductions)
	er.TotalSourceWorkloads = len(srcPssMap)
	er.TotalTargetWorkloads = len(targetPssMap)
}

func getEscalatedStatus(status int) string {
	return m[status]
}

func diff(left, right []string) (leftDiff, rightDiff []string) {
	leftMap := utils.ArrayToMap(left)
	rightMap := utils.ArrayToMap(right)
	for cap := range leftMap {
		if _, exists := rightMap[cap]; exists {
			delete(leftMap, cap)
			delete(rightMap, cap)
		}
	}

	return utils.MapToArray(leftMap), utils.MapToArray(rightMap)
}
