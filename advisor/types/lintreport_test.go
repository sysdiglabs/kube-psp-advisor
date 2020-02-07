package types

import (
	"bytes"
	"encoding/json"
	"fmt"

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
