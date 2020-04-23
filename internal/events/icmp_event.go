package events

import (
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ICMPv4Event struct {
	ICMPv4Header *layers.ICMPv4
	IPHeader     *layers.IPv4
	LogData      ICMPv4EventLog
	Event
}


func NewICMPv4Event(packet gopacket.Packet) (*ICMPv4Event, error) {
	var ev = &ICMPv4Event{}
	ev.Kind = ICMPv4Kind

	ev.Session = "n/a"

	ICMPv4Header, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	ev.ICMPv4Header = ICMPv4Header
	IPHeader, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ev.IPHeader = IPHeader
	ev.SourceIP = IPHeader.SrcIP.String()
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

func (ev ICMPv4Event) ToLog() ICMPv4EventLog {
	var ipFlagsStr []string

	ev.LogData = ICMPv4EventLog{}
	ev.LogData.Timestamp = time.Now().Format(time.RFC3339)
	ev.LogData.Type = ev.Kind
	ev.LogData.SourceIP = ev.SourceIP
	ev.LogData.DestPort = ev.DestPort
	ev.LogData.Session = ev.Session

	// Deduplicate tags
	if len(ev.Tags) == 0 {
		ev.LogData.Tags = []string{}
	} else {
		var set = make(map[string]struct{})
		for _, tag := range ev.Tags {
			if _, ok := set[tag]; !ok {
				set[tag] = struct{}{}
			}
		}

		for tag, _ := range set {
			ev.LogData.Tags = append(ev.LogData.Tags, tag)
		}
	}

	ev.LogData.ICMPv4 = ICMPv4LogData{
		TypeCode: ev.ICMPv4Header.TypeCode,
		Checksum: ev.ICMPv4Header.Checksum,
		Id:       ev.ICMPv4Header.Id,
		Seq:      ev.ICMPv4Header.Seq,
	}

	ev.LogData.IP = IPLogData{
		Version:    ev.IPHeader.Version,
		IHL:        ev.IPHeader.IHL,
		TOS:        ev.IPHeader.TOS,
		Length:     ev.IPHeader.Length,
		Id:         ev.IPHeader.Id,
		FragOffset: ev.IPHeader.FragOffset,
		TTL:        ev.IPHeader.TTL,
		Protocol:   ev.IPHeader.Protocol,
	}

	if ev.IPHeader.Flags&layers.IPv4EvilBit != 0 {
		ipFlagsStr = append(ipFlagsStr, "EV")
	}
	if ev.IPHeader.Flags&layers.IPv4DontFragment != 0 {
		ipFlagsStr = append(ipFlagsStr, "DF")
	}
	if ev.IPHeader.Flags&layers.IPv4MoreFragments != 0 {
		ipFlagsStr = append(ipFlagsStr, "MF")
	}

	ev.LogData.IP.Fragbits = strings.Join(ipFlagsStr, "")

	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}
