package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	// "golang.org/x/net/icmp"
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

type RequestPackage struct {
	DstIP    string
	DstPort  uint16
	SrcIp    string
	SrcPort  uint16
	Host     string
	Method   string
	Protocol string
	URL      string
	ACK      uint32
	TS       time.Time
	PID      int32
}

type ResponsePackage struct {
	DstIP   string
	DstPort uint16
	SrcIp   string
	SrcPort uint16
	Code    string
	SEQ     uint32
	TS      time.Time
	PID     int32
}

type FullHTTPPackage struct {
	DstIP    string
	DstPort  uint16
	SrcIp    string
	SrcPort  uint16
	Host     string
	Method   string
	Protocol string
	URL      string
	Code     string
	Duration int64
	PID      int32
}

func (f *FullHTTPPackage) String() string {
	return fmt.Sprintf("[%d] [%s][%d] --> [%s][%d][%s %s %s %s] ====> %s  [%dms]", f.PID, f.SrcIp, f.SrcPort, f.DstIP, f.DstPort, f.Protocol, f.Method, f.Host, f.URL, f.Code, f.Duration)
}
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {
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

	detachedEbpfProgram := coll.DetachProgram("socket__filter")
	if detachedEbpfProgram == nil {
		klog.Errorf("Error: no program named %s found !", "socket__filter")
	}

	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketFd)

	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, detachedEbpfProgram.FD()); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, detachedEbpfProgram.FD())

	var pid int32
	debug := false

	reqmap := make(map[uint32]RequestPackage)
	for {
		buf := make([]byte, 1500)
		numRead, _, err := syscall.Recvfrom(socketFd, buf, 0)
		if err != nil {
			log.Println(err)
			continue
		}
		rawData := buf[:numRead]

		//ETH的头部是14, IP的头部是20, TCP的头部是20(不包含option)
		//根据包头长度来过滤掉非TCP的包
		if numRead < 14+20+20 {
			// log.Print("invalid tcp packet")
			continue
		}
		packet := gopacket.NewPacket(rawData, layers.LayerTypeEthernet, gopacket.Default)
		// 获得IP层的对象
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		// 获得TCP层的对象
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		for _, i := range tcp.Options {
			if i.OptionType == 253 {
				pid = int32(binary.BigEndian.Uint32(i.OptionData[2:6]))
				// fmt.Printf("%v\n", pid)
			}
		}
		if debug {
			log.Printf("===============================================================================================")
			log.Printf("length: %d\n", numRead)
			// for _, i := range tcp.Options {
			// 	fmt.Printf("[TCP Option]: %+v\n", i.String())

			// }
			// fmt.Printf("[TCP Option]: %+v\n", tcp.Options.String())
			log.Printf("[%s]:[%d] -> [%s]:[%d], pid: %d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, pid)
			if packet.ApplicationLayer() != nil {
				fmt.Printf("application layer: %+v\n", packet.ApplicationLayer().LayerType())
			}
			// contents包含了tcp报文头以及数据部分
			// log.Printf("contend: %+v", string(tcp.Contents))
			// payload仅包含了数据部分
			// log.Printf("[SYN]: %v,[ACK]: %v,[FIN]: %v,[PSH]: %v,[RST]: %v,[URG]: %v\n", tcp.SYN, tcp.ACK, tcp.FIN, tcp.PSH, tcp.RST, tcp.URG)
			log.Printf("[SYN]: %v\n", tcp.SYN)
			log.Printf("[ACK]: %v\n", tcp.ACK)
			log.Printf("[FIN]: %v\n", tcp.FIN)
			log.Printf("[PSH]: %v\n", tcp.PSH)
			log.Printf("[RST]: %v\n", tcp.RST)
			log.Printf("[URG]: %v\n", tcp.URG)
			log.Printf("[Window Size]: %v, [Seq Number]: %v, [Ack Number]: %v, [CheckSum]: %v, [UrgentPoint]: %v\n", tcp.Window, tcp.Seq, tcp.Ack, tcp.Checksum, tcp.Urgent)
			// log.Printf("contend: %+v", string(tcp.Contents))
			log.Printf("payload: %s", string(tcp.Payload))
		}
		//如何区分http还是https
		// if (tcp.SrcPort == 80 || tcp.DstPort == 80) && len(tcp.Payload) > 0 {
		if len(tcp.Payload) > 0 {

			// if os.Getenv("DEBUG") = true {
			// 	Debug()
			// }

			if IsHTTPRequest(tcp.Payload) {
				method, url, protocol, host := DecodeHTTPRequest(tcp.Payload)
				request := RequestPackage{
					DstIP:    ip.DstIP.String(),
					DstPort:  uint16(tcp.DstPort),
					SrcIp:    ip.SrcIP.String(),
					SrcPort:  uint16(tcp.SrcPort),
					Host:     host,
					Method:   method,
					Protocol: protocol,
					URL:      url,
					ACK:      tcp.Ack,
					TS:       time.Now(),
					PID:      pid,
				}
				reqmap[tcp.Ack] = request
			}

			if IsHTTPResponse(tcp.Payload) {
				code := DecodeHTTPResponse(tcp.Payload)
				response := ResponsePackage{
					DstIP:   ip.DstIP.String(),
					DstPort: uint16(tcp.DstPort),
					SrcIp:   ip.SrcIP.String(),
					SrcPort: uint16(tcp.SrcPort),
					Code:    code,
					SEQ:     tcp.Seq,
					TS:      time.Now(),
					PID:     pid,
				}
				value, ok := reqmap[response.SEQ]
				duration := response.TS.Sub(value.TS).Milliseconds()
				if ok {
					if pid == 0 {
						response.PID = value.PID
					}
					httppackage := FullHTTPPackage{
						DstIP:    value.DstIP,
						DstPort:  value.DstPort,
						SrcIp:    value.SrcIp,
						SrcPort:  value.SrcPort,
						Host:     value.Host,
						Method:   value.Method,
						Protocol: value.Protocol,
						URL:      value.URL,
						Code:     response.Code,
						Duration: duration,
						PID:      response.PID,
					}
					fmt.Println(httppackage.String())
				}
			}
		}
	}
}

func IsHTTPRequest(p []byte) bool {
	if len(p) < 6 {
		return false
	}
	if string(p[0:3]) == "GET" {
		return true
	}
	if string(p[0:4]) == "POST" {
		return true
	}
	if string(p[0:3]) == "PUT" {
		return true
	}
	if string(p[0:6]) == "DELETE" {
		return true
	}
	if string(p[0:4]) == "HEAD" {
		return true
	}
	return false
}

func IsHTTPResponse(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	if string(p[0:4]) == "HTTP" {
		return true
	}
	return false
}

func DecodeHTTPRequest(p []byte) (string, string, string, string) {
	s := strings.Split(string(p), "\n")
	l0 := strings.Fields(s[0])
	// log.Printf("ssssss, %+v\n", s[0])
	// log.Printf("llll, %+v\n", l0[0])
	l1 := strings.Fields(s[1])
	return l0[0], l0[1], l0[2], l1[1]
}

func DecodeHTTPResponse(p []byte) string {
	s := strings.Split(string(p), "\n")
	l0 := strings.Fields(s[0])
	return l0[1]
}

func GetEBPFProg() []byte {

	b, err := ioutil.ReadFile("main.bpf.o")
	if err != nil {
		fmt.Println("Could not read BPF object file", err.Error())
	}
	return b
}

// From cilium :)
func binaryString(buf []byte) string {
	var builder strings.Builder
	for _, b := range buf {
		builder.WriteString(`\x`)
		builder.WriteString(fmt.Sprintf("%02x", b))
	}
	return builder.String()
}
