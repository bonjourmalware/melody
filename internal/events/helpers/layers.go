package helpers

import "github.com/google/gopacket/layers"

type IPv4Layer struct {
	Header *layers.IPv4
}

type IPv6Layer struct {
	Header *layers.IPv6
}

func (lay IPv4Layer) GetIPv4Header() *layers.IPv4 {
	return lay.Header
}

func (lay IPv6Layer) GetIPv6Header() *layers.IPv6 {
	return lay.Header
}

type UDPLayer struct {
	Header *layers.UDP
}

func (lay UDPLayer) GetUDPHeader() *layers.UDP {
	return lay.Header
}

type TCPLayer struct {
	Header *layers.TCP
}

func (lay TCPLayer) GetTCPHeader() *layers.TCP {
	return lay.Header
}

type ICMPv4Layer struct {
	Header *layers.ICMPv4
}

func (lay ICMPv4Layer) GetICMPv4Header() *layers.ICMPv4 {
	return lay.Header
}

type ICMPv6Layer struct {
	Header *layers.ICMPv6
}

func (lay ICMPv6Layer) GetICMPv6Header() *layers.ICMPv6 {
	return lay.Header
}
