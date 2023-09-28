package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	_ "net/http/pprof"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

type Ebpf struct {
	IfIndex   int
	IPaddress string
	NodeName  string
	//hostnetwork类型的pod,使用pod来区分k8s的元数据
	PortMap map[int32]K8SMeta
	Ch      chan Metric
}

type K8SMeta struct {
	PodName     string
	NameSpace   string
	ServiceName string
}

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func NewEbpf(ifindex int, ip string, ports []int32, nodename string, podname string,
	namespace string, servicename string, ch chan Metric) *Ebpf {
	portMap := make(map[int32]K8SMeta)
	for _, v := range ports {
		portMap[v] = K8SMeta{
			PodName:     podname,
			NameSpace:   namespace,
			ServiceName: servicename,
		}
	}
	return &Ebpf{
		IfIndex:   ifindex,
		IPaddress: ip,
		NodeName:  nodename,
		PortMap:   portMap,
		Ch:        ch,
	}
}

func (e *Ebpf) AppendPod(ports []int32, podname string,
	namespace string, servicename string) {
	for _, v := range ports {
		e.PortMap[v] = K8SMeta{
			PodName:     podname,
			NameSpace:   namespace,
			ServiceName: servicename,
		}
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
	// log.Printf("=======ip, %v\n", e.IPaddress)
	// log.Printf("=====FFFF==ip, %v\n", uint64(Htonl(IP4toDec(e.IPaddress))))
	const keyIPAddr uint32 = 1
	if err := coll.DetachMap("filter_map").Put(keyIPAddr, uint64(Htonl(IP4toDec(e.IPaddress)))); err != nil {
		return err
	}
	m := coll.DetachMap("response_map")
	go e.FanInMetric(m)
	return nil
}

func (e *Ebpf) Converet(p *MapPackage) *Metric {
	m := new(Metric)
	m.Type = p.Type
	m.DstIP = p.DstIP
	m.DstPort = p.DstPort
	m.SrcIP = p.SrcIP
	m.SrcPort = p.SrcPort
	m.Duration = p.Duration
	m.Host = p.Host
	m.Method = p.Method
	m.Protocol = p.Protocol
	m.URL = p.URL
	m.Code = p.Code
	m.NodeName = e.NodeName
	m.IfIndex = e.IfIndex
	if m.DstIP == e.IPaddress {
		m.Flow = 0
	} else {
		m.Flow = 1
	}
	if e.IfIndex != 2 {
		m.PodName = e.PortMap[0].PodName
		m.NameSpace = e.PortMap[0].NameSpace
		m.ServiceName = e.PortMap[0].ServiceName
	} else {
		//针对hostnetwork的pod, 不记录OUT方向的请求,因为这种请求没有任何标记它是属于哪一个pod
		_, ok := e.PortMap[int32(m.DstPort)]
		if !ok {
			return nil
		}
		m.PodName = e.PortMap[int32(m.DstPort)].PodName
		m.NameSpace = e.PortMap[int32(m.DstPort)].NameSpace
		m.ServiceName = e.PortMap[int32(m.DstPort)].ServiceName
	}
	return m
}

func (e *Ebpf) FanInMetric(m *ebpf.Map) {
	var (
		key uint32
		val []byte
	)
	for {
		for m.Iterate().Next(&key, &val) {
			value := DecodeMapItem(val)
			metric := e.Converet(value)
			if err := m.Delete(key); err != nil {
				panic(err)
			}
			if metric == nil {
				break
			}
			e.Ch <- *metric
		}
		time.Sleep(1 * time.Second)
	}
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/traffic.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
