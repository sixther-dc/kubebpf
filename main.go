package main

import (
	"bytes"
	"encoding/binary"
	// "errors"
	"log"
	"net/http"
	_ "net/http/pprof"
	"time"
	// "os"
	"syscall"
	"unsafe"

	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:8777", nil))
	}()
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	eBPFprogram := GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		klog.Errorln("Error loading eBPF collectionSpec: ", err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		klog.Errorln("Error getting the eBPF program collection: ", err)
	}
	defer coll.Close()
	httpRequestProgram := coll.DetachProgram("socket__filter_package")
	if httpRequestProgram == nil {
		klog.Errorf("Error: no program named %s found !", "socket__filter_package")
	}

	socketHttpRequestFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketHttpRequestFd)

	if err := syscall.SetsockoptInt(socketHttpRequestFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, httpRequestProgram.FD()); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketHttpRequestFd, syscall.SOL_SOCKET, SO_DETACH_BPF, httpRequestProgram.FD())

	var (
		key uint32
		val []byte
	)
	requestMap := coll.DetachMap("response_map")

	for {
		for requestMap.Iterate().Next(&key, &val) {
			m := DecodeMapItem(val)
			log.Printf("%s\n", m)
			if err := requestMap.Delete(key); err != nil {
				panic(err)
			}
		}
		time.Sleep(1 * time.Second)
	}
}
