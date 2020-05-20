package generator

import (
	"testing"

	"github.com/sysdiglabs/kube-psp-advisor/advisor/types"
)

var (
	allowPrivilegeEscalation       = true
	notRunAsNonRoot                = false
	runAsNonRoot                   = true
	namespaceTest                  = "test"
	runAsUser                int64 = 100
	runAsGroup               int64 = 1000

	emptyCSSList = []types.ContainerSecuritySpec{}

	cssList = []types.ContainerSecuritySpec{
		{Metadata: types.Metadata{
			Kind: "Deployment",
			Name: "testDeploy",
		},
			ContainerName:            "containerA",
			ImageName:                "imageA",
			Capabilities:             []string{"SYS_ADMIN"},
			Privileged:               true,
			ReadOnlyRootFS:           false,
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			RunAsNonRoot:             &notRunAsNonRoot,
			ServiceAccount:           "acctA",
			Namespace:                namespaceTest,
			RunAsUser:                &runAsUser,
			RunAsGroup:               &runAsGroup,
			HostPorts:                []int32{80, 8080},
		},
		{Metadata: types.Metadata{
			Kind: "Deployment",
			Name: "testDeploy",
		},
			ContainerName:  "containerB",
			ImageName:      "imageA",
			Capabilities:   []string{"SYS_ADMIN"},
			Privileged:     false,
			ReadOnlyRootFS: true,
			RunAsNonRoot:   &runAsNonRoot,
			ServiceAccount: "acctB",
			Namespace:      namespaceTest,
			RunAsUser:      &runAsUser,
			RunAsGroup:     &runAsGroup,
			HostPorts:      []int32{80, 8081},
		},
	}

	emptyPSSList = []types.PodSecuritySpec{}

	pssList = []types.PodSecuritySpec{
		{Metadata: types.Metadata{
			Kind: "Deployment",
			Name: "testDeploy",
		},
			Namespace:   namespaceTest,
			HostIPC:     true,
			HostNetwork: true,
			HostPID:     true,
			VolumeTypes: []string{"secret", "configMap"},
			MountHostPaths: map[string]bool{
				"/proc": true,
			},
		},
		{Metadata: types.Metadata{
			Kind: "Deployment",
			Name: "testDeploy",
		},
			Namespace:   namespaceTest,
			HostIPC:     false,
			HostNetwork: false,
			HostPID:     false,
			VolumeTypes: []string{"secret", "emptyDir"},
			MountHostPaths: map[string]bool{
				"/etc": true,
			},
		},
	}
)

func TestCSS(t *testing.T) {
	gen, _ := NewGenerator()

	psp := gen.GeneratePSP(cssList, emptyPSSList, namespaceTest, "v1.12.1")

	if !psp.Spec.Privileged {
		t.Fatal("psp should be privileged")
	}

	hasSYSADMIN := false
	for _, cap := range psp.Spec.AllowedCapabilities {
		if string(cap) == "SYS_ADMIN" {
			hasSYSADMIN = true
			break
		}
	}

	if !hasSYSADMIN {
		t.Fatal("psp should have SYS_ADMIN in capabilities")
	}

	if psp.Spec.ReadOnlyRootFilesystem {
		t.Fatal("psp should have readonlyrootsystem to false")
	}

	if psp.Spec.AllowPrivilegeEscalation != nil && !*psp.Spec.AllowPrivilegeEscalation {
		t.Fatal("psp should have allowPrivilegeEscalation to true")
	}

	if psp.Spec.RunAsUser.Ranges[0].Min != runAsUser && psp.Spec.RunAsUser.Ranges[0].Max != runAsUser {
		t.Fatal("psp should have set run as user to 100")
	}

	if psp.Spec.RunAsGroup.Ranges[0].Min != runAsGroup && psp.Spec.RunAsGroup.Ranges[0].Max != runAsGroup {
		t.Fatal("psp should have set run as group to 1000")
	}

	if len(psp.Spec.HostPorts) != 2 {
		t.Fatalf("there should be 2 port ranges, actual: %d", len(psp.Spec.HostPorts))
	}

	if psp.Spec.HostPorts[0].Min != 80 || psp.Spec.HostPorts[0].Max != 80 {
		t.Fatalf("Expect port range [80, 80], actual: %v", psp.Spec.HostPorts[0])
	}

	if psp.Spec.HostPorts[1].Min != 8080 || psp.Spec.HostPorts[1].Max != 8081 {
		t.Fatalf("Expect port range [8080, 8081], actual: %v", psp.Spec.HostPorts[1])
	}
}

func TestPSS(t *testing.T) {
	gen, _ := NewGenerator()

	psp := gen.GeneratePSP(emptyCSSList, pssList, namespaceTest, "v1.12.1")

	if !psp.Spec.HostPID {
		t.Fatal("psp should allow hostPID")
	}

	if !psp.Spec.HostNetwork {
		t.Fatal("psp should allow hostNetwork")
	}

	if !psp.Spec.HostIPC {
		t.Fatal("psp should allow hostIPC")
	}

	volMap := map[string]bool{}

	for _, fs := range psp.Spec.Volumes {
		volMap[string(fs)] = true
	}

	if _, exists := volMap["secret"]; !exists {
		t.Fatal("psp should allow mount secret")
	}

	if _, exists := volMap["configMap"]; !exists {
		t.Fatal("psp should allow mount configMap")
	}

	if _, exists := volMap["emptyDir"]; !exists {
		t.Fatal("psp should allow mount emptyDir")
	}

	if len(volMap) > 3 {
		t.Fatal("psp allow more volume types than needed")
	}

	hpMap := map[string]bool{}
	for _, hp := range psp.Spec.AllowedHostPaths {
		hpMap[hp.PathPrefix] = true
	}

	if _, exists := hpMap["/proc"]; !exists {
		t.Fatal("psp shoud allow mount on hostpath /proc")
	}

	if _, exists := hpMap["/etc"]; !exists {
		t.Fatal("psp shoud allow mount on hostpath /etc")
	}

	if len(hpMap) > 2 {
		t.Fatal("psp allow more host path mount than needed")
	}
}
