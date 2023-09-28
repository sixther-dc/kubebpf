package ebpf

import (
	"encoding/binary"
	"fmt"
	"main/metric"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type MapPackage struct {
	//HTTP, RPC, MySQL etc.
	Type     uint32
	DstIP    string
	DstPort  uint16
	SrcIP    string
	SrcPort  uint16
	Ack      uint32
	Seq      uint32
	Duration uint32
	Host     string
	Method   string
	Protocol string
	URL      string
	Code     string
}

type Metric struct {
	//HTTP, RPC, MySQL etc.
	Type uint32
	//从本pod来看是被请求(0)还是请求(1)
	Flow        int
	DstIP       string
	DstPort     uint16
	SrcIP       string
	SrcPort     uint16
	Duration    uint32
	Host        string
	Method      string
	Protocol    string
	URL         string
	Code        string
	IfIndex     int
	PodName     string
	NodeName    string
	NameSpace   string
	ServiceName string
}

func (m *Metric) CovertMetric() metric.Metric {
	var metric metric.Metric
	metric.Measurement = "traffic"
	metric.AddTags("podname", m.PodName)
	metric.AddTags("nodename", m.NodeName)
	metric.AddTags("namespace", m.NameSpace)
	metric.AddTags("servicename", m.ServiceName)
	metric.AddTags("type", strconv.Itoa(int(m.Type)))
	metric.AddTags("flow", strconv.Itoa(m.Flow))
	metric.AddTags("dstip", m.DstIP)
	metric.AddTags("dstport", strconv.Itoa(int(m.DstPort)))
	metric.AddTags("srcip", m.SrcIP)
	metric.AddTags("srcport", strconv.Itoa(int(m.SrcPort)))
	metric.AddTags("method", m.Method)
	metric.AddTags("protocol", m.Protocol)
	metric.AddTags("url", m.URL)
	metric.AddTags("code", m.Code)
	metric.AddTags("ifinfex", strconv.Itoa(m.IfIndex))
	metric.AddField("duration", m.Duration)
	return metric
}
func (m *Metric) String() string {
	return fmt.Sprintf("%s %d %d [%s][%d] --> [%s][%d][%s %s] ====> %s [%dms] \n%s %s %s %s %d\n",
		time.Now().Format("2006-01-02 15:04:05"), m.Type, m.Flow, m.SrcIP, m.SrcPort, m.DstIP, m.DstPort, m.Method, m.URL, m.Code, m.Duration,
		m.NodeName, m.NameSpace, m.PodName, m.ServiceName, m.IfIndex,
	)
}

func DecodeMapItem(e []byte) *MapPackage {
	m := new(MapPackage)
	m.DstIP = net.IP(e[4:8]).String()
	m.DstPort = binary.BigEndian.Uint16(e[8:10])
	m.SrcIP = net.IP(e[12:16]).String()
	m.SrcPort = binary.BigEndian.Uint16(e[16:20])
	m.Ack = binary.BigEndian.Uint32(e[20:24])
	m.Seq = binary.BigEndian.Uint32(e[24:28])
	m.Duration = binary.LittleEndian.Uint32(e[28:32]) / (1000 * 1000)
	method, url, host := DecodeHTTPRequest(string(e[32:212]))
	m.Method = method
	m.URL = url
	m.Host = host
	code := DecodeHTTPResponse(e[212:392])
	m.Code = code
	m.Type = binary.LittleEndian.Uint32(e[392:396])
	return m
}

// method, url, host
func DecodeHTTPRequest(s string) (string, string, string) {
	// var host string
	//使用正则会有较多的开销，尽量使用byte的位置截取
	// pattern := `Host:\s+(\S+)`
	// re := regexp.MustCompile(pattern)
	// match := re.FindStringSubmatch(s)

	// if len(match) > 1 {
	// 	// 输出匹配到的 Host
	// 	host = match[1]
	// }
	lines := strings.Split(s, "\n")
	items := strings.Fields(lines[0])
	if len(items) < 2 {
		return "", "", ""
	}
	return items[0], items[1], ""
}

// httpcode
func DecodeHTTPResponse(p []byte) string {
	//response, HTTP/1.1 200 OK
	if len(p) < 11 {
		return ""
	}
	return string(p[9:12])
}

// Htons converts to network byte order short uint16.
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// Htonl converts to network byte order long uint32.
func Htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

// IP4toDec transforms and IPv4 to decimal
func IP4toDec(IPv4Addr string) uint32 {
	bits := strings.Split(IPv4Addr, ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	// left shifting 24,16,8,0 and bitwise OR

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}

// OpenRawSock 创建一个原始的socket套接字
func OpenRawSock(index int) (int, error) {
	// ETH_P_IP: Internet Protocol version 4 (IPv4)
	// ETH_P_ARP: Address Resolution Protocol (ARP)
	// ETH_P_IPV6: Internet Protocol version 6 (IPv6)
	// ETH_P_RARP: Reverse ARP
	// ETH_P_LOOP: Loopback protocol
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(Htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = Htons(ETH_P_ALL)
	//设置套接字的网卡序号
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
