#!/bin/bash
source ./helper.sh

NAMESPACE=$(__readini global NAMESPACE)
INFLUXDB_HOST=$(__readini influxdb INFLUXDB_HOST)
INFLUXDB_PV_PATH=$(__readini influxdb INFLUXDB_PV_PATH)
export NAMESPACE
export INFLUXDB_PV_PATH
export INFLUXDB_HOST

# install influxdb
function __install_fluxdb {
    INFLUX_ADDR=influxdb.$NAMESPACE.svc.cluster.local
    INFLUX_USERNAME=admin
    INFLUX_ORG=ebpf
    INFLUX_PASSWORD=$(__generate_password)
    INFLUX_BUCKET=ebpf
    echo "install influxdb..."
    cat influxdb/pv.yaml  | envsubst | kubectl apply -f -
    cat influxdb/statefulset.yml| envsubst | kubectl apply -f -
    __wait_sts default influxdb
    #初始化influxdb的用户信息
    kubectl exec -it  influxdb-0 -n dc-ebpf -- influx setup \
        --username $INFLUX_USERNAME \
        --password $INFLUX_PASSWORD \
        --bucket default \
        --org $INFLUX_ORG \
        --force
    
    #创建默认bucket
    bucketid=$(kubectl exec -it  influxdb-0 -n dc-ebpf -- influx bucket create \
        --org=$INFLUX_ORG \
        --name=$INFLUX_BUCKET \
        --retention 1h \
        | tail -n 1 | awk '{print $1}')
    #创建token
    INFLUX_TOKEN=$(kubectl exec -it  influxdb-0 -n dc-ebpf -- influx auth create \
        --org=$INFLUX_ORG \
        --read-bucket $bucketid \
        --write-bucket $bucketid \
        --description "for-ebpf" \
       | tail -n 1  | awk '{print $3}')
    

    echo influx addr:     $INFLUX_ADDR 
    echo influx username: $INFLUX_USERNAME
    echo influx password: $INFLUX_PASSWORD
    echo influx org:      $INFLUX_ORG
    echo influx bucket:   $INFLUX_BUCKET
    echo influx token:    $INFLUX_TOKEN

# influx addr:  influxdb.dc-ebpf.svc.cluster.local
# influx username: admin
# influx password: K3m2KHSk0SA7fjm_TQTq2gPV
# influx org: ebpf
# influx bucket: ebpf
# influx token: skqHl5ks_UZVwTgW9ycxh8jAmDh_NhkuHcs6VLP9s6brKBngM8TAmpOKqWZp5l5QMQ3OzdJCDZct4jCmkwIAQA==
}

# install grafana
function __install_grafana {
}

# install ebpf agent
function __install_agent {

}
# install
__install_fluxdb
__install_grafana
__install_agent

echo "ending..."
