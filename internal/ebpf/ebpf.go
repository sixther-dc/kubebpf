package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	_ "net/http/pprof"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

type Ebpf struct {
	IfIndex     int
	PodName     string
	NodeName    string
	NameSpace   string
	ServiceName string
	Ch          chan MapPackage
}

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func NewEbpf(ifindex int, nodename string, podname string, namespace string, servicename string, ch chan MapPackage) *Ebpf {
	return &Ebpf{
		IfIndex:     ifindex,
		PodName:     podname,
		NodeName:    nodename,
		NameSpace:   namespace,
		ServiceName: servicename,
		Ch:          ch,
	}
}
func (e *Ebpf) Load() error {
	eBPFprogram := GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	// defer coll.Close()
	prog := coll.DetachProgram("socket__filter_package")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "socket__filter_package")
		return errors.New(msg)
	}

	// sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	// if err != nil {
	// 	panic(err)
	// }
	sock, err := OpenRawSock(e.IfIndex)
	if err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}
	// defer syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_DETACH_BPF, prog.FD())

	m := coll.DetachMap("response_map")
	go e.FanInMetric(m)
	return nil
}

func (e *Ebpf) FanInMetric(m *ebpf.Map) {
	var (
		key uint32
		val []byte
	)
	for {
		for m.Iterate().Next(&key, &val) {
			value := DecodeMapItem(val)
			value.IfIndex = e.IfIndex
			value.NodeName = e.NodeName
			value.NameSpace = e.NameSpace
			value.PodName = e.PodName
			value.ServiceName = e.ServiceName
			fmt.Printf("%+v\n", value)
			if err := m.Delete(key); err != nil {
				panic(err)
			}
			e.Ch <- *value
		}
		time.Sleep(1 * time.Second)
	}
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("main.bpf.o")
	if err != nil {
		fmt.Println("Could not read BPF object file", err.Error())
	}
	return b
}
