package report

import (
	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
)

const (
	allPrivilegEscalation  = "allowPrivilegeEscalation"
	runAsUser              = "runAsUser"
	runAsGroup             = "runAsGroup"
	runAsNonRoot           = "runAsNonRoot"
	dropCapabilities       = "dropCapabilities"
	addCapabilities        = "addCapabilities"
	privileged             = "privileged"
	readOnlyRootFileSystem = "readOnlyRootFileSystem"
	hostPID                = "hostPID"
	hostIPC                = "hostIPC"
	hostNetwork            = "hostNetwork"
)

type Report struct {
	PodSecuritySpecs map[string][]types.PodSecuritySpec       `json:"podSecuritySpecs"`
	PodVolumes       map[string][]types.PodSecuritySpec       `json:"podVolumeTypes"`
	Containers       map[string][]types.ContainerSecuritySpec `json:"containerSecuritySpec"`
}

func NewReport() *Report {
	r := &Report{
		Containers:       map[string][]types.ContainerSecuritySpec{},
		PodSecuritySpecs: map[string][]types.PodSecuritySpec{},
		PodVolumes:       map[string][]types.PodSecuritySpec{},
	}

	// container related security posture report
	r.Containers[allPrivilegEscalation] = []types.ContainerSecuritySpec{}
	r.Containers[runAsUser] = []types.ContainerSecuritySpec{}
	r.Containers[runAsNonRoot] = []types.ContainerSecuritySpec{}
	r.Containers[dropCapabilities] = []types.ContainerSecuritySpec{}
	r.Containers[addCapabilities] = []types.ContainerSecuritySpec{}
	r.Containers[runAsGroup] = []types.ContainerSecuritySpec{}
	r.Containers[privileged] = []types.ContainerSecuritySpec{}
	r.Containers[readOnlyRootFileSystem] = []types.ContainerSecuritySpec{}

	// pod related security posture report
	r.PodSecuritySpecs[hostPID] = []types.PodSecuritySpec{}
	r.PodSecuritySpecs[hostNetwork] = []types.PodSecuritySpec{}
	r.PodSecuritySpecs[hostIPC] = []types.PodSecuritySpec{}

	return r
}

func (r *Report) AddPod(p types.PodSecuritySpec) {
	if p.HostPID {
		r.PodSecuritySpecs[hostPID] = append(r.PodSecuritySpecs[hostPID], p)
	}

	if p.HostNetwork {
		r.PodSecuritySpecs[hostNetwork] = append(r.PodSecuritySpecs[hostNetwork], p)
	}

	if p.HostIPC {
		r.PodSecuritySpecs[hostIPC] = append(r.PodSecuritySpecs[hostIPC], p)
	}

	for _, v := range p.VolumeTypes {
		if _, exists := r.PodVolumes[v]; !exists {
			r.PodVolumes[v] = []types.PodSecuritySpec{}
		}

		r.PodVolumes[v] = append(r.PodVolumes[v], p)
	}
}

func (r *Report) AddContainer(c types.ContainerSecuritySpec) {
	if c.AllowPrivilegeEscalation != nil && *c.AllowPrivilegeEscalation {
		r.Containers[allPrivilegEscalation] = append(r.Containers[allPrivilegEscalation], c)
	}

	if c.RunAsUser != nil {
		r.Containers[runAsUser] = append(r.Containers[runAsUser], c)
	}

	if c.RunAsNonRoot != nil {
		r.Containers[runAsNonRoot] = append(r.Containers[runAsNonRoot], c)
	}

	if len(c.DroppedCap) > 0 {
		r.Containers[dropCapabilities] = append(r.Containers[dropCapabilities], c)
	}

	if len(c.AddedCap) > 0 {
		r.Containers[addCapabilities] = append(r.Containers[addCapabilities], c)
	}

	if c.RunAsGroup != nil {
		r.Containers[runAsGroup] = append(r.Containers[runAsGroup], c)
	}

	if c.Privileged {
		r.Containers[privileged] = append(r.Containers[privileged], c)
	}

	if c.ReadOnlyRootFS {
		r.Containers[readOnlyRootFileSystem] = append(r.Containers[readOnlyRootFileSystem], c)
	}
}
