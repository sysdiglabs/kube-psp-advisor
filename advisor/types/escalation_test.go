package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"k8s.io/api/policy/v1beta1"

	"github.com/ghodss/yaml"
)

var (
	pspRestrictedStr = `
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false  # Don't allow privileged pods!
  # The rest fills in some required fields.
  runAsUser:
    rule: MustRunAsNonRoot
  runAsGroup:
    rule: MustRunAsNonRoot
  volumes:
  - 'secret'
  - 'configMap'
  - 'emptyDir'
  readOnlyRootFilesystem: true
`
	pspPrivilegedStr = `
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
`
)

func TestNoChanges(t *testing.T) {
	r := NewEscalationReport()

	if !r.NoChanges() {
		t.Fatal("new report should not contain an changes.")
	}
}

func TestEscalationReportEscalated(t *testing.T) {
	pspRestricted, err := readPSPYaml(pspRestrictedStr)

	if err != nil {
		t.Fatal(err)
	}

	pspPrivileged, err := readPSPYaml(pspPrivilegedStr)

	if err != nil {
		t.Fatal(err)
	}

	r := NewEscalationReport()

	r.GenerateEscalationReport(pspRestricted, pspPrivileged)

	if !r.PrivilegeEscalated() {
		t.Fatal("privilege should be escalated")
	}

	if !r.HostIPCEscalated() {
		t.Fatal("hostIPC should be escalated")
	}

	if !r.HostNetworkEscalated() {
		t.Fatal("hostNetwork should be escalated")
	}

	if !r.HostPIDEscalated() {
		t.Fatal("hostPID should be escalated")
	}

	if !r.RunAsUserStrategyEscalated() {
		t.Fatal("runAsUser should be escalated")
	}

	if !r.RunAsGroupStrategyEscalated() {
		t.Fatal("runAsGroup should be escalated")
	}

	if !r.ReadOnlyRootFSEscalated() {
		t.Fatal("readOnlyFS should be escalated")
	}

	if !r.AddedCapabilities() {
		t.Fatal("new capabilities should be added")
	}

	if !r.AddedVolumes() {
		t.Fatal("new volumes should be added")
	}
}

func TestEscalationReportReduced(t *testing.T) {
	pspRestricted, err := readPSPYaml(pspRestrictedStr)

	if err != nil {
		t.Fatal(err)
	}

	pspPrivileged, err := readPSPYaml(pspPrivilegedStr)

	if err != nil {
		t.Fatal(err)
	}

	r := NewEscalationReport()

	err = r.GenerateEscalationReport(pspPrivileged, pspRestricted)

	if err != nil {
		t.Fatal(err)
	}

	if !r.PrivilegeReduced() {
		t.Fatal("privilege should be reduced")
	}

	if !r.HostIPCReduced() {
		t.Fatal("hostIPC should be reduced")
	}

	if !r.HostNetworkReduced() {
		t.Fatal("hostNetwork should be reduced")
	}

	if !r.HostPIDReduced() {
		t.Fatal("hostPID should be reduced")
	}

	if !r.RunAsUserStrategyReduced() {
		t.Fatal("runAsUser should be reduced")
	}

	if !r.RunAsGroupStrategyReduced() {
		t.Fatal("runAsGroup should be reduced")
	}

	if !r.ReadOnlyRootFSReduced() {
		t.Fatal("readOnlyFS should be reduced")
	}

	if !r.DroppedCapabilities() {
		t.Fatal("some capabilities should be dropped")
	}

	if !r.RemovedVolumes() {
		t.Fatal("some volumes should be removed")
	}
}

func readPSPYaml(pspInput string) (*v1beta1.PodSecurityPolicy, error) {
	var psp v1beta1.PodSecurityPolicy

	pspRestrictedJSON, err := yaml.YAMLToJSON([]byte(pspInput))
	if err != nil {
		return nil, err
	}

	var anyJson map[string]interface{}

	err = json.Unmarshal(pspRestrictedJSON, &anyJson)

	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(pspRestrictedJSON))
	decoder.DisallowUnknownFields()

	switch kind := anyJson["kind"]; kind {
	case "PodSecurityPolicy":
		if err := decoder.Decode(&psp); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("not a valid psp file")
	}

	return &psp, nil
}
