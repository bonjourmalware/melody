package events

import "github.com/google/gopacket/layers"

type Event interface {
	//Match(rule rules.Rule) bool
	ToLog() EventLog
	GetKind() string
	GetSourceIP() string
	GetDestPort() uint16
	GetIPHeader() *layers.IPv4
	GetICMPv6Header() *layers.ICMPv6
	GetICMPv4Header() *layers.ICMPv4
	GetUDPHeader() *layers.UDP
	GetTCPHeader() *layers.TCP
	GetHTTPData() HTTPEvent

	AddTags(tags []string)
	AddAdditional(add map[string]string)
}

type EventLog interface {
	String() (string, error)
}
