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

type LintReport struct {
	TotalSourceWorkloads  int                    `json:"total_source_workloads"`
	TotalTargetWorkloads  int                    `json:"total_target_workloads"`
	TotalSourceImages     int                    `json:"total_source_images"`
	TotalTargetImages     int                    `json:"total_target_images"`
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

// InitEscalation returns an initialized escalation object
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

// SetEscalation set escalation status
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

func (e *Escalation) ConsolidateWorkloadImage() {
	m := map[Metadata]bool{}

	for w := range e.workloadMap {
		w.Image = ""
		m[w] = true
	}

	for w := range m {
		e.Workloads = append(e.Workloads, w)
	}

	e.WorkloadCount = len(e.Workloads)
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

// NewEscalationReport returns an escalation report object
func NewEscalationReport() *LintReport {
	return &LintReport{
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

// privileged mode
func (er *LintReport) PrivilegedEscalated() bool {
	return er.NewPrivileged.IsEscalated()
}

// privileged mode
func (er *LintReport) PrivilegedReduced() bool {
	return er.RemovedPrivileged.IsReduced()
}

// privileged mode
func (er *LintReport) PrivilegedNoChange() bool {
	return !er.PrivilegedReduced() && !er.PrivilegedReduced()
}

// HostIPC
func (er *LintReport) HostIPCEscalated() bool {
	return er.NewHostIPC.IsEscalated()
}

// HostIPC
func (er *LintReport) HostIPCReduced() bool {
	return er.RemovedHostIPC.IsReduced()
}

// HostIPC
func (er *LintReport) HostIPCNoChange() bool {
	return !er.HostIPCEscalated() && !er.HostIPCReduced()
}

// HostNetwork
func (er *LintReport) HostNetworkEscalated() bool {
	return er.NewHostNetwork.IsEscalated()
}

// HostNetwork
func (er *LintReport) HostNetworkReduced() bool {
	return er.RemovedHostNetwork.IsReduced()
}

// HostNetwork
func (er *LintReport) HostNetworkNoChange() bool {
	return !er.HostNetworkEscalated() && !er.HostNetworkReduced()
}

// HostPID
func (er *LintReport) HostPIDEscalated() bool {
	return er.NewHostPID.IsEscalated()
}

// HostPID
func (er *LintReport) HostPIDReduced() bool {
	return er.RemovedHostPID.IsReduced()
}

// HostPID
func (er *LintReport) HostPIDNoChange() bool {
	return !er.HostPIDEscalated() && !er.HostPIDReduced()
}

// ReadOnlyRootFileSystem
func (er *LintReport) ReadOnlyRootFSEscalated() bool {
	return er.RemovedReadOnlyRootFS.IsEscalated()
}

// ReadOnlyRootFileSystem
func (er *LintReport) ReadOnlyRootFSReduced() bool {
	return er.NewReadOnlyRootFS.IsReduced()
}

// ReadOnlyRootFileSystem
func (er *LintReport) ReadOnlyRootFSNoChange() bool {
	return !er.ReadOnlyRootFSEscalated() && !er.ReadOnlyRootFSReduced()
}

// runAsUser (non root -> root)
func (er *LintReport) RunUserAsRootEscalated() bool {
	return er.NewRunUserAsRoot.IsEscalated()
}

// runAsUser (root -> non root)
func (er *LintReport) RunUserAsRootReduced() bool {
	return er.RemovedRunUserAsRoot.IsReduced()
}

// runAsUser
func (er *LintReport) RunUserAsRootNoChange() bool {
	return !er.RunUserAsRootEscalated() && !er.RunUserAsRootReduced()
}

// runAsGroup (non root -> root)
func (er *LintReport) RunGroupAsRootEscalated() bool {
	return er.NewRunGroupAsRoot.IsEscalated()
}

// runAsGroup (root -> non root)
func (er *LintReport) RunGroupAsRootReduced() bool {
	return er.RemovedRunGroupAsRoot.IsReduced()
}

// runAsGroup
func (er *LintReport) RunGroupAsRootNoChange() bool {
	return er.NewRunGroupAsRoot.NoChanges()
}

// newly added volume types
func (er *LintReport) AddedVolumes() bool {
	return len(er.NewVolumeTypes) > 0
}

// removed volume types
func (er *LintReport) RemovedVolumes() bool {
	return len(er.RemovedVolumeTypes) > 0
}

// added capabilities
func (er *LintReport) AddedCapabilities() bool {
	return len(er.NewCapabilities) > 0
}

// dropped capabilities
func (er *LintReport) DroppedCapabilities() bool {
	return len(er.RemovedCapabilities) > 0
}

func (er *LintReport) Escalated() bool {
	if er.PrivilegedEscalated() || er.HostNetworkEscalated() || er.HostPIDEscalated() || er.HostIPCEscalated() || er.AddedVolumes() ||
		er.AddedCapabilities() || er.ReadOnlyRootFSEscalated() || er.RunGroupAsRootEscalated() || er.RunUserAsRootEscalated() {
		return true
	}

	return false
}

func (er *LintReport) Reduced() bool {
	if er.PrivilegedReduced() || er.HostNetworkReduced() || er.HostPIDReduced() || er.HostIPCReduced() || er.RemovedVolumes() ||
		er.DroppedCapabilities() || er.ReadOnlyRootFSReduced() || er.RunGroupAsRootReduced() || er.RunUserAsRootReduced() {
		return true
	}

	return false
}

// GenerateEscalationReportFromSecurityContext returns a escalation report after comparing the source and target YAML files
func (er *LintReport) GenerateEscalationReportFromSecurityContext(srcCssList, targetCssList []ContainerSecuritySpec, srcPssList, targetPssList []PodSecuritySpec) {
	srcCssMap := NewContainerSecuritySpecMap(srcCssList)
	targetCssMap := NewContainerSecuritySpecMap(targetCssList)

	srcPssMap := NewPodSecuritySpecMap(srcPssList)
	targetPssMap := NewPodSecuritySpecMap(targetPssList)

	escalations := InitEscalation(Escalated, "", "")
	reductions := InitEscalation(Reduced, "", "")

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

	escalations.ConsolidateWorkloadImage()
	reductions.ConsolidateWorkloadImage()

	er.Escalations = append(er.Escalations, escalations.Workloads...)
	er.Reductions = append(er.Reductions, reductions.Workloads...)

	er.TotalEscalation = len(er.Escalations)
	er.TotalReduction = len(er.Reductions)
	er.TotalSourceWorkloads = len(srcPssMap)
	er.TotalTargetWorkloads = len(targetPssMap)
	er.TotalSourceImages = len(srcCssMap)
	er.TotalTargetImages = len(targetCssMap)
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
