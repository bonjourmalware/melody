package events

import (
	"time"

	"github.com/bonjourmalware/melody/internal/config"
	"github.com/bonjourmalware/melody/internal/events/helpers"
	"github.com/bonjourmalware/melody/internal/events/logdata"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ICMPv6Event struct {
	LogData logdata.ICMPv6EventLog
	BaseEvent
	helpers.IPv6Layer
	helpers.ICMPv6Layer
}

func NewICMPv6Event(packet gopacket.Packet) (*ICMPv6Event, error) {
	var ev = &ICMPv6Event{}
	ev.Kind = config.ICMPv6Kind

	ev.Session = "n/a"
	ev.Timestamp = packet.Metadata().Timestamp

	ICMPv6Header, _ := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	ev.ICMPv6Layer = helpers.ICMPv6Layer{Header: ICMPv6Header}

	IPHeader, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	ev.IPv6Layer = helpers.IPv6Layer{Header: IPHeader}
	ev.SourceIP = ev.IPv6Layer.Header.SrcIP.String()
	ev.Additional = make(map[string]string)
	ev.Tags = make(Tags)

	return ev, nil
}

//func (ev ICMPv6Event) GetIPv4Header() *layers.IPv6 {
//	return ev.IPHeader
//}

//func (ev ICMPv6Event) Match(rule rules.Rule) bool {
//	return false
//}

func (ev ICMPv6Event) ToLog() EventLog {
	ev.LogData = logdata.ICMPv6EventLog{}
	//ev.LogData.Timestamp = time.Now().Format(time.RFC3339)
	//ev.LogData.NsTimestamp = strconv.FormatInt(time.Now().UnixNano(), 10)
	ev.LogData.Timestamp = ev.Timestamp.Format(time.RFC3339Nano)

	ev.LogData.Type = ev.Kind
	ev.LogData.SourceIP = ev.SourceIP
	ev.LogData.DestPort = ev.DestPort
	ev.LogData.Session = ev.Session

	if len(ev.Tags) == 0 {
		ev.LogData.Tags = []string{}
	} else {
		ev.LogData.Tags = ev.Tags.ToArray()
	}

	ev.LogData.ICMPv6 = logdata.ICMPv6LogData{
		TypeCode:     ev.ICMPv6Layer.Header.TypeCode,
		TypeCodeName: ev.ICMPv6Layer.Header.TypeCode.String(),
		Checksum:     ev.ICMPv6Layer.Header.Checksum,
	}

	ev.LogData.IP = logdata.IPv6LogData{
		Version:        ev.IPv6Layer.Header.Version,
		Length:         ev.IPv6Layer.Header.Length,
		NextHeader:     ev.IPv6Layer.Header.NextHeader,
		NextHeaderName: ev.IPv6Layer.Header.NextHeader.String(),
		TrafficClass:   ev.IPv6Layer.Header.TrafficClass,
		FlowLabel:      ev.IPv6Layer.Header.FlowLabel,
		HopLimit:       ev.IPv6Layer.Header.HopLimit,
	}

	ev.LogData.Additional = ev.Additional

	return ev.LogData
}
