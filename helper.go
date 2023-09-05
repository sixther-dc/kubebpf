package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
)

type MapPackage struct {
	Type    uint32
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
	Ack     uint32
	Seq     uint32
	TS      uint32
	PayLoad string
}

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
	TS       uint32
}

type ResponsePackage struct {
	DstIP   string
	DstPort uint16
	SrcIP   string
	SrcPort uint16
	Code    string
	Seq     uint32
	TS      uint32
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
	Duration uint32
}

func (f *FullHTTPPackage) String() string {
	return fmt.Sprintf("[%s][%d] --> [%s][%d][%s %s] ====> %s  [%dms]", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Method, f.URL, f.Code, f.Duration)
}

func uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func DecodeMapItem(e []byte) *MapPackage {
	m := new(MapPackage)
	m.Type = binary.LittleEndian.Uint32(e[0:4])
	m.DstIP = net.IP(e[4:8]).String()
	m.DstPort = binary.BigEndian.Uint16(e[8:10])
	m.SrcIP = net.IP(e[12:16]).String()
	m.SrcPort = binary.BigEndian.Uint16(e[16:20])
	m.Ack = binary.BigEndian.Uint32(e[20:24])
	m.Seq = binary.BigEndian.Uint32(e[24:28])
	m.TS = binary.LittleEndian.Uint32(e[28:32])
	//TODO: fix it
	m.PayLoad = string(e[32:])
	// fmt.Printf("ssssss: %+v\n", m)
	return m
}

// method, url, host
func DecodeHTTPRequest(s string) (string, string, string) {
	var host string
	pattern := `Host:\s+(\S+)`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(s)

	if len(match) > 1 {
		// 输出匹配到的 Host
		host = match[1]
	}

	lines := strings.Split(s, "\n")
	items := strings.Fields(lines[0])
	return items[0], items[1], host
}

// httpcode
func DecodeHTTPResponse(p string) string {
	s := strings.Split(p, "\n")
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
func BinaryString(buf []byte) string {
	var builder strings.Builder
	for _, b := range buf {
		builder.WriteString(`\x`)
		builder.WriteString(fmt.Sprintf("%02x", b))
	}
	return builder.String()
}
