# Kube PodSecurityPolicy Advisor

kube-psp-advisor is a tool that makes it easier to create K8s Pod Security Policies (PSPs) from either a live K8s environment or from a single .yaml file containing a pod specification (Deployment, DaemonSet, Pod, etc).

It has 2 subcommands, `kube-psp-advisor inspect` and `kube-psp-advisor convert`. `inspect` connects to a K8s API server, downloads all Pod-related objects in a given namespace, and generates a PSP based on the properties of those objects. `convert` works without connecting to an API Server, reading a single .yaml file containing a object with a pod spec and generating a PSP based on the file.

## Installation as a Krew Plugin

Follow the [instructions](https://github.com/kubernetes-sigs/krew#installation) to install `krew`. Then run the following command:

```
kubectl krew install advise-psp
```

The plugin will be available as `kubectl advise-psp`.

## Build and Run locally
1. ```make build```
2. ```./kube-psp-advisor inspect``` to generate Pod Security Policy based on running cluster configuration
   - 2.1 ```./kube-psp-advisor inspect --report``` to print the details reports (why this PSP is recommended for the cluster)
   - 2.2 ```./kube-psp-advisor inspect --grant``` to print PSPs, roles and rolebindings for service accounts (refer to [psp-grant.yaml](./test-yaml/psp-grant.yaml))
   - 2.3 ```./kube-psp-advisor inspect --namespace=<ns>``` to print report or PSP(s) within a given namespace (default to all) 
4. ```./kube-psp-advisor convert --podFile <path> --pspFile <path>``` to generate a PSP from a single .yaml file.

## Build and Run as Container
1. ```docker build -t <Image Name> -f container/Dockerfile .```
2. ```docker run -v ~/.kube:/root/.kube -v ~/.aws:/root/.aws <Image Name>``` (the `.aws` folder mount is optional and totally depends on your clould provider)

## Use Cases
1. Help verify the deployment, daemonset settings in cluster and plan to reduce unnecessary privileges/resources
2. Apply Pod Security Policy to the target cluster
3. flag `--namespace=<namespace>` is introduced to debug and narrow down the security context per namespace

## Attributes Aggregated for Pod Security Policy
- allowPrivilegeEscalation
- allowedCapabilities
- allowedHostPaths
  - readOnly
- hostIPC
- hostNetwork
- hostPID
- privileged
- readOnlyRootFilesystem
- runAsUser
- Volume

## Limitations
Some attributes(capabilities, host ports etc.) required gathering runtime information in order to provide the followings:
- Least privilege (capabilities captured from runtime)
- Accuracy (host ports listening on `0.0.0.0`)

## High-level todo list

- [x] Basic functionalities;
- [ ] Create PSP's for common charts
- [ ] Kubectl plugin
`
## Sample Pod Security Policy
Command: `./kube-psp-advisor inspect --namespace=psp-test`
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
Command: `./kube-psp-advisor inspect --namespace=psp-test --report | jq .podSecuritySpecs`
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
      "hostNetwork": true,
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
      "hostNetwork": true,
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
      "hostNetwork": true,
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
