#!/bin/bash

source ./helper.sh
NAMESPACE=$(__readini global NAMESPACE)

kubectl delete ns $NAMESPACE
kubectl delete pv pv-ebpf-influxdb