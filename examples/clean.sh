#!/bin/bash

set -eu

kubectl delete -f ns.yaml || true

kubectl delete psp psp-privileged psp-restricted || true
