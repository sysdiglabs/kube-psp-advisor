#!/bin/bash

export PATH=$PATH:../

set -eu

# create namespaces
kubectl apply -f ns.yaml || true

# create service accounts
kubectl apply -f sa.yaml || true

# create roles and rolebindings for service accounts to use pod security policies
kubectl apply -f roles.yaml || true

# create pods
kubectl apply -f pods.yaml || true

# generate psp and update the pod security policy name
kube-psp-advisor --namespace privileged | sed -e 's/pod-security.*/psp-privileged/g' | kubectl apply -f -

kube-psp-advisor --namespace restricted | sed -e 's/pod-security.*/psp-restricted/g' | kubectl apply -f -

# test creating pods that pass the pod security policies
kubectl apply -f pods-allow.yaml || true

kubectl get pods -n privileged

kubectl get pods -n restricted

# test creating pod that violate pod security policies
kubectl apply -f pods-deny.yaml || true

kubectl get pods -n privileged

kubectl get pods -n restricted

