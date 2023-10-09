package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"

	"main/metric"
	"main/output/influxdb"
	plugins "main/plugins"
	_ "main/plugins/all"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:8777", nil))
	}()
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	influxAddr := os.Getenv("INFLUX_ADDR")
	influxOrg := os.Getenv("INFLUX_ORG")
	influxBucket := os.Getenv("INFLUX_BUCKET")
	influxToken := os.Getenv("INFLUX_TOKEN")
	influxdb := influxdb.NewInfluxdb(influxAddr, influxOrg, influxBucket, influxToken).Run()

	//初始化metric管道
	ch := make(chan metric.Metric, 1000)

	//启动所有插件
	for k, v := range plugins.Plugins {
		log.Printf("start run plugin [%s]\n", k)
		go v.Gather(ch)
	}
	for m := range ch {
		//处理metric, print / influxdb / prometheus / erda   等
		// log.Printf("[%d] metric is wating to write\n", len(ch))
		// log.Println(m.String())
		influxdb.Write(m)
	}

}
