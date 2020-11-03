package events

import (
	"github.com/bonjourmalware/pinknoise/internal/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"time"
)

type ICMPv6Event struct {
	LogData ICMPv6EventLog
	BaseEvent
	IPv6Layer
	ICMPv6Layer
}

func NewICMPv6Event(packet gopacket.Packet) (*ICMPv6Event, error) {
	var ev = &ICMPv6Event{}
	ev.Kind = config.ICMPv6Kind

	ev.Session = "n/a"
	ev.Timestamp = packet.Metadata().Timestamp

	ICMPv6Header, _ := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	ev.ICMPv6Layer = ICMPv6Layer{Header: ICMPv6Header}

	IPHeader, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	ev.IPv6Layer = IPv6Layer{Header: IPHeader}
	ev.SourceIP = ev.IPv6Layer.Header.SrcIP.String()
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

//func (ev ICMPv6Event) GetIPv4Header() *layers.IPv6 {
//	return ev.IPHeader
//}

//func (ev ICMPv6Event) Match(rule rules.Rule) bool {
//	return false
//}

func (ev ICMPv6Event) ToLog() EventLog {
	ev.LogData = ICMPv6EventLog{}
	//ev.LogData.Timestamp = time.Now().Format(time.RFC3339)
	//ev.LogData.NsTimestamp = strconv.FormatInt(time.Now().UnixNano(), 10)
	ev.LogData.Timestamp = ev.Timestamp.Format(time.RFC3339Nano)

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

		for tag := range set {
			ev.LogData.Tags = append(ev.LogData.Tags, tag)
		}
	}

	ev.LogData.ICMPv6 = ICMPv6LogData{
		TypeCode:     ev.ICMPv6Layer.Header.TypeCode,
		TypeCodeName: ev.ICMPv6Layer.Header.TypeCode.String(),
		Checksum:     ev.ICMPv6Layer.Header.Checksum,
	}

	ev.LogData.IP = IPv6LogData{
		Version:        ev.IPv6Layer.Header.Version,
		Length:         ev.IPv6Layer.Header.Length,
		NextHeader:     ev.IPv6Layer.Header.NextHeader,
		NextHeaderName: ev.IPv6Layer.Header.NextHeader.String(),
		TrafficClass:   ev.IPv6Layer.Header.TrafficClass,
		FlowLabel:      ev.IPv6Layer.Header.FlowLabel,
		HopLimit:       ev.IPv6Layer.Header.HopLimit,
	}

	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}
