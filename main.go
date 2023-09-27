package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"

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
	influxdb := influxdb.NewInfluxdb("http://influxdb.default.svc.cluster.local:8086", "erda", "ebpf", "kWwVy7IfF05yWPdMIlP4k6VPfPV8Uy0rdr583W-0FZ0XYZ93isCyEXc4cKD9xUWVa9bNO2OLp6EakddB-lpbfw==")
	fmt.Printf("%v\n", influxdb)

	ch := make(chan metric.Metric)

	for k, v := range plugins.Plugins {
		log.Printf("start run plugin [%s]\n", k)
		go v.Gather(ch)
	}
	for m := range ch {
		//处理http metric, simple print /  influxdb / prometheus / erda   等
		// fmt.Println(m.String())
		influxdb.Write(m)
	}

}
