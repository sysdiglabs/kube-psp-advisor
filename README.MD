# Kube PodSecurityPolicy Advisor

## Build and Run locally
1. ```make build```
2. ```./kube-psp-advisor``` to generate Pod Security Policy based on running cluster configuration
3. ```./kube-psp-advisor --report``` to print the details reports (why this PSP is recommended for the cluster)

## Build and Run as Container
1. ```docker build -t <Image Name> container/Dockerfile .```
2. ```docker run -v ~/.kube:/root/.kube -v ~/.aws:/root/.aws <Image Name>``` (the `.aws` folder mount is optional and totally depends on your clould provider)

## Use Cases
1. Help verify the deployment, daemonset settings in cluster and plan to reduce unnecessary privileges/resources
2. Apply Pod Security Policy to the target cluster
3. flag `--namespace=<namespace>` is introduced to debug and narrow down the security context per namespace

## Attributes Aggregated for Pod Security Policy
- allowPrivilegeEscalation
- allowedCapabilities
- allowedHostPaths
- hostIPC
- hostNetwork
- hostPID
- privileged
- readOnlyRootFilesystem
- runAsUser
- Volume
- hostPorts


## Sample Pod Security Policy
Command: `./kube-psp-advisor --namespace=psp-test`
```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  creationTimestamp: null
  name: pod-security-policy-20181130114734
spec:
  allowedCapabilities:
  - SYS_ADMIN
  - NET_ADMIN
  allowedHostPaths:
  - pathPrefix: /bin
  - pathPrefix: /tmp
  - pathPrefix: /usr/sbin
  - pathPrefix: /usr/bin
  fsGroup:
    rule: RunAsAny
  hostIPC: false
  hostNetwork: false
  hostPID: false
  privileged: true
  runAsUser:
    rule: RunAsAny
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  volumes:
  - hostPath
  - configMap
  - secret
  ```

## Sample Report 
Command: `./kube-psp-advisor --namespace=psp-test --report | jq .podSecuritySpecs`
```
{
  "hostIPC": [
    {
      "metadata": {
        "name": "busy-rs",
        "kind": "ReplicaSet"
      },
      "namespace": "psp-test",
      "hostPID": true,
      "hostMetwork": true,
      "hostIPC": true,
      "volumeTypes": [
        "configMap"
      ]
    },
    {
      "metadata": {
        "name": "busy-job",
        "kind": "Job"
      },
      "namespace": "psp-test",
      "hostIPC": true,
      "volumeTypes": [
        "hostPath"
      ],
      "mountedHostPath": [
        "/usr/bin"
      ]
    }
  ],
  "hostNetwork": [
    {
      "metadata": {
        "name": "busy-rs",
        "kind": "ReplicaSet"
      },
      "namespace": "psp-test",
      "hostPID": true,
      "hostMetwork": true,
      "hostIPC": true,
      "volumeTypes": [
        "configMap"
      ]
    },
    {
      "metadata": {
        "name": "busy-pod",
        "kind": "Pod"
      },
      "namespace": "psp-test",
      "hostMetwork": true,
      "volumeTypes": [
        "hostPath",
        "secret"
      ],
      "mountedHostPath": [
        "/usr/bin"
      ]
    }
  ],
  "hostPID": [
    {
      "metadata": {
        "name": "busy-deploy",
        "kind": "Deployment"
      },
      "namespace": "psp-test",
      "hostPID": true,
      "volumeTypes": [
        "hostPath"
      ],
      "mountedHostPath": [
        "/tmp"
      ]
    },
    {
      "metadata": {
        "name": "busy-rs",
        "kind": "ReplicaSet"
      },
      "namespace": "psp-test",
      "hostPID": true,
      "hostMetwork": true,
      "hostIPC": true,
      "volumeTypes": [
        "configMap"
      ]
    }
  ]
}
```
