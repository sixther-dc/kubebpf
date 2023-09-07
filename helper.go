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
	Status   uint32
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
	// ReqPayLoad string
	// RspPayLoad string
}

func (m *MapPackage) String() string {
	return fmt.Sprintf("[%s][%d] --> [%s][%d][%s %s] ====> %s  [%dms]", m.SrcIP, m.SrcPort, m.DstIP, m.DstPort, m.Method, m.URL, m.Code, m.Duration)
}

func uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func DecodeMapItem(e []byte) *MapPackage {
	m := new(MapPackage)
	m.Status = binary.LittleEndian.Uint32(e[0:4])
	m.DstIP = net.IP(e[4:8]).String()
	m.DstPort = binary.BigEndian.Uint16(e[8:10])
	m.SrcIP = net.IP(e[12:16]).String()
	m.SrcPort = binary.BigEndian.Uint16(e[16:20])
	m.Ack = binary.BigEndian.Uint32(e[20:24])
	m.Seq = binary.BigEndian.Uint32(e[24:28])
	m.Duration = binary.LittleEndian.Uint32(e[28:32]) / (1000 * 1000)
	//TODO: fix it
	method, url, host := DecodeHTTPRequest(string(e[32:212]))
	m.Method = method
	m.URL = url
	m.Host = host
	code := DecodeHTTPResponse(string(e[212:392]))
	m.Code = code
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
	if len(items) < 2 {
		return "", "", ""
	}
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
