package helpers

import "github.com/google/gopacket/layers"

// IPv4Layer is a custom layer on top of the layers.IPv4 object from gopacket
type IPv4Layer struct {
	Header *layers.IPv4
}

// IPv6Layer is a custom layer on top of the layers.IPv6 object from gopacket
type IPv6Layer struct {
	Header *layers.IPv6
}

// GetIPv4Header returns the gopacket's layers.IPv4 layer from the custom IPv4Layer abstraction
func (lay IPv4Layer) GetIPv4Header() *layers.IPv4 {
	return lay.Header
}

// GetIPv6Header returns the gopacket's layers.IPv6 layer from the custom IPv6Layer abstraction
func (lay IPv6Layer) GetIPv6Header() *layers.IPv6 {
	return lay.Header
}

// UDPLayer is a custom layer on top of the layers.UDP object from gopacket
type UDPLayer struct {
	Header *layers.UDP
}

// GetUDPHeader returns the gopacket's layers.UDP layer from the custom UDPLayer abstraction
func (lay UDPLayer) GetUDPHeader() *layers.UDP {
	return lay.Header
}

// TCPLayer is a custom layer on top of the layers.TCP object from gopacket
type TCPLayer struct {
	Header *layers.TCP
}

// GetTCPHeader returns the gopacket's layers.TCP layer from the custom TCPLayer abstraction
func (lay TCPLayer) GetTCPHeader() *layers.TCP {
	return lay.Header
}

// ICMPv4Layer is a custom layer on top of the layers.ICMPv4 object from gopacket
type ICMPv4Layer struct {
	Header *layers.ICMPv4
}

// GetICMPv4Header returns the gopacket's layers.ICMPv4 layer from the custom ICMPv4Layer abstraction
func (lay ICMPv4Layer) GetICMPv4Header() *layers.ICMPv4 {
	return lay.Header
}

// ICMPv6Layer is a custom layer on top of the layers.ICMPv6 object from gopacket
type ICMPv6Layer struct {
	Header *layers.ICMPv6
}

// GetICMPv6Header returns the gopacket's layers.ICMPv6 layer from the custom ICMPv6Layer abstraction
func (lay ICMPv6Layer) GetICMPv6Header() *layers.ICMPv6 {
	return lay.Header
}
