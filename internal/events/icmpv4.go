package events

import (
	"github.com/bonjourmalware/pinknoise/internal/config"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ICMPv4Event struct {
	//ICMPv4Header *layers.ICMPv4
	LogData      ICMPv4EventLog
	BaseEvent
	IPv4Layer
	ICMPv4Layer
}

func NewICMPv4Event(packet gopacket.Packet) (*ICMPv4Event, error) {
	var ev = &ICMPv4Event{}
	ev.Kind = config.ICMPv4Kind

	ev.Session = "n/a"

	ICMPv4Header, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	ev.ICMPv4Layer = ICMPv4Layer{Header: ICMPv4Header}

	IPHeader, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ev.IPv4Layer = IPv4Layer{Header: IPHeader}
	ev.SourceIP = ev.IPv4Layer.Header.SrcIP.String()
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

//func (ev ICMPv4Event) GetIPHeader() *layers.IPv4 {
//	return ev.IPHeader
//}

//func (ev ICMPv4Event) Match(rule rules.Rule) bool {
//	return false
//}

func (ev ICMPv4Event) ToLog() EventLog {
	var ipFlagsStr []string

	ev.LogData = ICMPv4EventLog{}
	ev.LogData.Timestamp = time.Now().Format(time.RFC3339)
	ev.LogData.NsTimestamp = strconv.FormatInt(time.Now().UnixNano(), 10)
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
		TypeCode: ev.ICMPv4Layer.Header.TypeCode,
		TypeCodeName: ev.ICMPv4Layer.Header.TypeCode.String(),
		Checksum: ev.ICMPv4Layer.Header.Checksum,
		Id:       ev.ICMPv4Layer.Header.Id,
		Seq:      ev.ICMPv4Layer.Header.Seq,
	}

	ev.LogData.IP = IPv4LogData{
		IHL:        ev.IPv4Layer.Header.IHL,
		TOS:        ev.IPv4Layer.Header.TOS,
		Length:     ev.IPv4Layer.Header.Length,
		Id:         ev.IPv4Layer.Header.Id,
		FragOffset: ev.IPv4Layer.Header.FragOffset,
		TTL:        ev.IPv4Layer.Header.TTL,
		Protocol:   ev.IPv4Layer.Header.Protocol,
	}

	if ev.IPv4Layer.Header.Flags&layers.IPv4EvilBit != 0 {
		ipFlagsStr = append(ipFlagsStr, "EV")
	}
	if ev.IPv4Layer.Header.Flags&layers.IPv4DontFragment != 0 {
		ipFlagsStr = append(ipFlagsStr, "DF")
	}
	if ev.IPv4Layer.Header.Flags&layers.IPv4MoreFragments != 0 {
		ipFlagsStr = append(ipFlagsStr, "MF")
	}

	ev.LogData.IP.Fragbits = strings.Join(ipFlagsStr, "")

	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}
