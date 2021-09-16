package types

var (
	DefaultCaps = []string{
		"SETPCAP",
		"MKNOD",
		"AUDIT_WRITE",
		"CHOWN",
		"NET_RAW",
		"DAC_OVERRIDE",
		"FOWNER",
		"FSETID",
		"KILL",
		"SETGID",
		"SETUID",
		"NET_BIND_SERVICE",
		"SYS_CHROOT",
		"SETFCAP",
	}
)

const (
	Version1_11 = "v1.11"
)

//PodSecurityPolicy Recommendation System help in the following attributes:
//	1. allowPrivilegeEscalation - done
//	2. allowedCapabilities - done
//	3. allowedHostPaths - done
//	4. hostIPC - done
//	5. hostNetwork - done
//	6. hostPID - done
//	7. hostPorts - done
//	8. privileged - done
//	9. readOnlyRootFilesystem - done
//  10. runAsUser - done
//  11. runAsGroup - done
//  12. Volume - done
//	13. seLinux and others - need further investigation
//  14. allowedUnsafeSysctls - done

type VolumeMount struct {
	MountPath   string `json:"mountPath"`
	Name        string `json:"name"`
	SubPath     string `json:"subPath,omitempty"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	SubPathExpr string `json:"subPathExpr,omitempty"`
}

type ContainerSecuritySpec struct {
	Metadata                 Metadata      `json:"parentMetadata"`
	ContainerID              string        `json:"containerID"`
	ContainerName            string        `json:"containerName"`
	PodName                  string        `json:"podName"`
	Namespace                string        `json:"namespace"`
	ImageName                string        `json:"imageName"`
	ImageSHA                 string        `json:"imageSHA"`
	HostName                 string        `json:"hostName"`
	Capabilities             []string      `json:"effectiveCapabilities,omitempty"`
	DroppedCap               []string      `json:"droppedCapabilities,omitempty"`
	AddedCap                 []string      `json:"addedCapabilities,omitempty"`
	Privileged               bool          `json:"privileged,omitempty"`
	ReadOnlyRootFS           bool          `json:"readOnlyRootFileSystem,omitempty"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot,omitempty"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation,omitempty"`
	RunAsUser                *int64        `json:"runAsUser,omitempty"`
	RunAsGroup               *int64        `json:"runAsGroup,omitempty"`
	HostPorts                []int32       `json:"hostPorts,omitempty"`
	ServiceAccount           string        `json:"serviceAccount,omitempty"`
	VolumeMounts             []VolumeMount `json:"volumeMounts"`
}

type PodSecuritySpec struct {
	Metadata       Metadata        `json:"metadata"`
	Namespace      string          `json:"namespace"`
	HostPID        bool            `json:"hostPID,omitempty"`
	HostNetwork    bool            `json:"hostNetwork,omitempty"`
	HostIPC        bool            `json:"hostIPC,omitempty"`
	VolumeTypes    []string        `json:"volumeTypes,omitempty"`
	MountHostPaths map[string]bool `json:"mountedHostPath,omitempty"`
	ServiceAccount string          `json:"serviceAccount,omitempty"`
	Sysctls        []string        `json:"sysctls,omitempty"`
}

type Metadata struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	YamlFile  string `json:"file,omitempty"`
	Image     string `json:"image,omitempty"`
}

type PodSecuritySpecMap map[Metadata]PodSecuritySpec

func NewPodSecuritySpecMap(pssList []PodSecuritySpec) PodSecuritySpecMap {
	pssMap := PodSecuritySpecMap{}

	for _, pss := range pssList {
		pssMap[pss.Metadata] = pss
	}

	return pssMap
}

type ContainerSecuritySpecMap map[Metadata]ContainerSecuritySpec

func NewContainerSecuritySpecMap(cssList []ContainerSecuritySpec) ContainerSecuritySpecMap {
	cssMap := ContainerSecuritySpecMap{}
	for _, css := range cssList {
		css.Metadata.Image = css.ImageName
		cssMap[css.Metadata] = css
	}

	return cssMap
}
