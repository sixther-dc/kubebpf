#!/bin/bash

source ./helper.sh
NAMESPACE=$(__readini global NAMESPACE)
INFLUXDB_HOST=$(__readini influxdb INFLUXDB_HOST)
INFLUXDB_PV_PATH=$(__readini influxdb INFLUXDB_PV_PATH)
GRAFANA_HOST=$(__readini grafana GRAFANA_HOST)
GRAFANA_PV_PATH=$(__readini grafana GRAFANA_PV_PATH)

kubectl delete ns $NAMESPACE
kubectl delete pv pv-kubebpf-influxdb
kubectl delete pv pv-kubebpf-grafana

echo "kubebpf uninstalled..."
echo "please delete directory of influxdb, node: $INFLUXDB_HOST, dir: $INFLUXDB_PV_PATH ."
echo "please delete directory of grafana, node: $GRAFANA_HOST, dir: $GRAFANA_PV_PATH ."