package main

import (
	"fmt"
	"log"
	"main/internal/controller"
	"main/internal/ebpf"
	"net/http"
	_ "net/http/pprof"

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
	ch := make(chan ebpf.Metric)
	controller := controller.NewController(ch)
	controller.Run()
	for m := range ch {
		fmt.Println(m.String())
	}
}
