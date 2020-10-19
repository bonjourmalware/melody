package events

import "github.com/google/gopacket/layers"

type IPLayer struct{
	Header     *layers.IPv4
}

func (lay IPLayer) GetIPHeader() *layers.IPv4 {
	return lay.Header
}

type UDPLayer struct{
	Header     *layers.UDP
}

func (lay UDPLayer) GetUDPHeader() *layers.UDP {
	return lay.Header
}

type TCPLayer struct{
	Header     *layers.TCP
}

func (lay TCPLayer) GetTCPHeader() *layers.TCP {
	return lay.Header
}

type ICMPv4Layer struct{
	Header     *layers.ICMPv4
}

func (lay ICMPv4Layer) GetICMPv4Header() *layers.ICMPv4 {
	return lay.Header
}

