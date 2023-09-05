package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"syscall"
	"unsafe"

	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
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

	requestMap := coll.DetachMap("package_map")

	rd, err := perf.NewReader(requestMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	reqmap := make(map[uint32]RequestPackage)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		// log.Printf("raw data: %+v\n", record.RawSample)
		m := DecodeMapItem(record.RawSample)
		if m.Type == 1 {
			method, url, host := DecodeHTTPRequest(m.PayLoad)
			request := RequestPackage{
				DstIP:   m.DstIP,
				DstPort: m.DstPort,
				SrcIP:   m.SrcIP,
				SrcPort: m.SrcPort,
				Host:    host,
				Method:  method,
				URL:     url,
				Ack:     m.Ack,
				TS:      m.TS,
			}
			reqmap[m.Ack] = request
		}

		if m.Type == 2 {
			code := DecodeHTTPResponse(m.PayLoad)
			response := ResponsePackage{
				DstIP:   m.DstIP,
				DstPort: m.DstPort,
				SrcIP:   m.SrcIP,
				SrcPort: m.SrcPort,
				Code:    code,
				Seq:     m.Seq,
				TS:      m.TS,
			}
			value, ok := reqmap[m.Seq]
			duration := (response.TS - value.TS) / (1000 * 1000) //ms
			if ok {
				httppackage := FullHTTPPackage{
					DstIP:    value.DstIP,
					DstPort:  value.DstPort,
					SrcIP:    value.SrcIP,
					SrcPort:  value.SrcPort,
					Host:     value.Host,
					Method:   value.Method,
					URL:      value.URL,
					Code:     response.Code,
					Duration: duration,
				}
				fmt.Println(httppackage.String())
			}
		}
	}
}
