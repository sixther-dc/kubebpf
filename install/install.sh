#!/bin/bash

export NAMESPACE="dc-ebpf"

# install influxdb
# 判断influxdb是否已经安装
echo "Install influxdb"
echo "A PersistentVolumeClaim is also created to store data written to InfluxDB."
echo -n  "Witch path do you want influxdb installed? [eg: /data/pv-ebpf-influxdb]"
read INFLUXDB_PV_PATH
echo -n "Witch node do you want influxdb installed? [eg: cn-hangzhou-1]"
read INFLUXDB_HOST
export INFLUXDB_PV_PATH
export INFLUXDB_HOST

cat influxdb/pv.yaml  | envsubst | kubectl apply -f -
cat influxdb/statefulset.yml| envsubst | kubectl apply -f -

# 初始化influxdb的密码使用登录容器执行influx命令行的方式
# https://docs.influxdata.com/influxdb/v2/install/?t=Set+up+with+the+CLI
# install grafana

# install agent