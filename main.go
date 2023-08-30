package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	// "regexp"
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

type TcpPackage struct {
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
	PayLoad []byte
	Ack     uint32
	Seq     uint32
}
type RequestPackage struct {
	DstIP    string
	DstPort  uint16
	SrcIP    string
	SrcPort  uint16
	Host     string
	Method   string
	Protocol string
	URL      string
	Ack      uint32
	TS       time.Time
	PID      int32
}

type ResponsePackage struct {
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
	Code    string
	Seq     uint32
	TS      time.Time
	PID     int32
}

type FullHTTPPackage struct {
	DstIP    string
	DstPort  uint16
	SrcIP    string
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
	return fmt.Sprintf("[%s][%d] --> [%s][%d][%s %s %s] ====> %s  [%dus]", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Method, f.Host, f.URL, f.Code, f.Duration)
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

	httpRequestProgram := coll.DetachProgram("socket__filter_http_request")
	if httpRequestProgram == nil {
		klog.Errorf("Error: no program named %s found !", "socket__filter_http_request")
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
	//----------------------------------------------
	httpResponseProgram := coll.DetachProgram("socket__filter_http_response")
	if httpResponseProgram == nil {
		klog.Errorf("Error: no program named %s found !", "socket__filter_http_response")
	}

	socketHttpResponseFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketHttpResponseFd)

	if err := syscall.SetsockoptInt(socketHttpResponseFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, httpResponseProgram.FD()); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketHttpResponseFd, syscall.SOL_SOCKET, SO_DETACH_BPF, httpResponseProgram.FD())

	reqmap := make(map[uint32]RequestPackage)

	for {
		req := GetPayload(socketHttpRequestFd)
		rsp := GetPayload(socketHttpResponseFd)
		if len(req.PayLoad) > 0 {
			method, url, host := DecodeHTTPRequest(req.PayLoad)
			request := RequestPackage{
				DstIP:   req.DstIP,
				DstPort: req.DstPort,
				SrcIP:   req.SrcIP,
				SrcPort: req.SrcPort,
				Host:    host,
				Method:  method,
				URL:     url,
				Ack:     req.Ack,
				TS:      time.Now(),
			}
			reqmap[req.Ack] = request
		}

		if len(rsp.PayLoad) > 0 {
			code := DecodeHTTPResponse(rsp.PayLoad)
			response := ResponsePackage{
				DstIP:   rsp.DstIP,
				DstPort: rsp.DstPort,
				SrcIP:   rsp.SrcIP,
				SrcPort: rsp.SrcPort,
				Code:    code,
				Seq:     rsp.Seq,
				TS:      time.Now(),
			}
			value, ok := reqmap[response.Seq]
			duration := response.TS.Sub(value.TS).Microseconds()
			if ok {
				// if pid == 0 {
				// 	response.PID = value.PID
				// }
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

func GetPayload(fd int) *TcpPackage {
	debug := true
	buf := make([]byte, 1500)
	numRead, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil
	}
	rawData := buf[:numRead]

	//ETH的头部是14, IP的头部是20, TCP的头部是20(不包含option)
	//根据包头长度来过滤掉非TCP的包
	if numRead < 14+20+20 {
		// log.Print("invalid tcp packet")
		return nil
	}
	packet := gopacket.NewPacket(rawData, layers.LayerTypeEthernet, gopacket.Default)
	// 获得IP层的对象
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	// 获得TCP层的对象
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	//从TCP option中获取pid，依赖deepflow的tot内核模块
	// for _, i := range tcp.Options {
	// 	if i.OptionType == 253 {
	// 		pid = int32(binary.BigEndian.Uint32(i.OptionData[2:6]))
	// 	}
	// }
	if debug {
		log.Printf("===============================================================================================")
		log.Printf("length: %d\n", numRead)
		log.Printf("[%s]:[%d] -> [%s]:[%d]", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
		if packet.ApplicationLayer() != nil {
			fmt.Printf("application layer: %+v\n", packet.ApplicationLayer().LayerType())
		}
		// contents包含了tcp报文头以及数据部分
		// payload仅包含了数据部分
		log.Printf("[SYN]: %v\n", tcp.SYN)
		log.Printf("[ACK]: %v\n", tcp.ACK)
		log.Printf("[FIN]: %v\n", tcp.FIN)
		log.Printf("[PSH]: %v\n", tcp.PSH)
		log.Printf("[RST]: %v\n", tcp.RST)
		log.Printf("[URG]: %v\n", tcp.URG)
		log.Printf("[Window Size]: %v, [Seq Number]: %v, [Ack Number]: %v, [CheckSum]: %v, [UrgentPoint]: %v\n", tcp.Window, tcp.Seq, tcp.Ack, tcp.Checksum, tcp.Urgent)
		log.Printf("payload: %s", string(tcp.Payload))
	}
	p := new(TcpPackage)
	p.DstIP = ip.DstIP.String()
	p.SrcIP = ip.SrcIP.String()
	p.DstPort = uint16(tcp.DstPort)
	p.SrcPort = uint16(tcp.SrcPort)
	p.PayLoad = tcp.Payload
	p.Ack = tcp.Ack
	p.Seq = tcp.Seq
	return p
}

// method, url, host
func DecodeHTTPRequest(p []byte) (string, string, string) {
	// var host string
	s := string(p)
	// pattern := `Host:\s+(\S+)`
	// re := regexp.MustCompile(pattern)
	// match := re.FindStringSubmatch(s)

	// if len(match) > 1 {
	// 	// 输出匹配到的 Host
	// 	host = match[1]
	// }

	lines := strings.Split(s, "\n")
	items := strings.Fields(lines[0])
	return items[0], items[1], ""
}

// httpcode
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
