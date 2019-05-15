# Examples

## Environment
**Namespace** | **Service Account** | **Role** | **Pod Security Policy**
--- | --- | --- | ---
privileged | privileged-sa | psp-privileged-role | psp-privielged
restricted | restricted-sa | psp-restricted-role | psp-restricted

In order to enforce the pod security policies, the service accounts need to be authorized to use the pod security policy.

**Role** | **Rule Verb** | **Rule API Group** | **Rule Resources** | **Rule Resource Name** 
--- | --- | --- | --- | ---
psp-privileged-role | use | policy | podsecuritypolicies | psp-privileged
psp-restricted-role | use | policy | podsecuritypolicies | psp-restricted

## Try out examples
1. setup k8s cluster
2. run `make build` to build the `kube-psp-advisor` binary
3. run `make example` to setup the example environment and show the test scenarios

## Explanation of examples
1. deploy `restrcited` and `privileged` namespaces with services account, roles, rolebindings and pods to k8s cluster
2. `kube-psp-advisor` generates pod security policies seperately for namespaces `restricted` and `privileged` based on the running pods, and then apply the pod security policies to cluster
3. test pod security policies with pods that comply with pod security policies (pods-allows.yaml)
4. test pod security policies with pods that violate pod security policies (pods-deny.yaml)
