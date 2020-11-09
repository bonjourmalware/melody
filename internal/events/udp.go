package events

import (
	"strings"
	"time"

	"github.com/bonjourmalware/melody/internal/config"

	"github.com/bonjourmalware/melody/internal/sessions"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type UDPEvent struct {
	//IPHeader  *layers.IPv4
	//UDPHeader *layers.UDP
	LogData UDPEventLog
	BaseEvent
	UDPLayer
	IPv4Layer
	IPv6Layer
}

func NewUDPEvent(packet gopacket.Packet, IPVersion uint) (*UDPEvent, error) {
	var ev = &UDPEvent{}
	ev.Kind = config.UDPKind
	ev.IPVersion = IPVersion

	ev.Timestamp = packet.Metadata().Timestamp
	ev.Session = sessions.Map.GetUID(packet.TransportLayer().TransportFlow().String())

	switch IPVersion {
	case 4:
		IPHeader, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ev.IPv4Layer = IPv4Layer{Header: IPHeader}
		ev.SourceIP = IPHeader.SrcIP.String()
	case 6:
		IPHeader, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ev.IPv6Layer = IPv6Layer{Header: IPHeader}
		ev.SourceIP = IPHeader.SrcIP.String()
	}

	UDPHeader, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ev.UDPLayer = UDPLayer{Header: UDPHeader}
	ev.DestPort = uint16(UDPHeader.DstPort)

	ev.Additional = make(map[string]string)

	return ev, nil
}

func (ev UDPEvent) ToLog() EventLog {
	var ipFlagsStr []string

	ev.LogData = UDPEventLog{}
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

	switch ev.IPVersion {
	case 4:
		if ev.IPv4Layer.Header.Flags&layers.IPv4EvilBit != 0 {
			ipFlagsStr = append(ipFlagsStr, "EV")
		}
		if ev.IPv4Layer.Header.Flags&layers.IPv4DontFragment != 0 {
			ipFlagsStr = append(ipFlagsStr, "DF")
		}
		if ev.IPv4Layer.Header.Flags&layers.IPv4MoreFragments != 0 {
			ipFlagsStr = append(ipFlagsStr, "MF")
		}

		ev.LogData.IP = IPv4LogData{
			Version:    ev.IPv4Layer.Header.Version,
			IHL:        ev.IPv4Layer.Header.IHL,
			TOS:        ev.IPv4Layer.Header.TOS,
			Length:     ev.IPv4Layer.Header.Length,
			Id:         ev.IPv4Layer.Header.Id,
			FragOffset: ev.IPv4Layer.Header.FragOffset,
			TTL:        ev.IPv4Layer.Header.TTL,
			Protocol:   ev.IPv4Layer.Header.Protocol,
			Fragbits:   strings.Join(ipFlagsStr, ""),
		}

	case 6:
		ev.LogData.IP = IPv6LogData{
			Version:        ev.IPv6Layer.Header.Version,
			Length:         ev.IPv6Layer.Header.Length,
			NextHeader:     ev.IPv6Layer.Header.NextHeader,
			NextHeaderName: ev.IPv6Layer.Header.NextHeader.String(),
			TrafficClass:   ev.IPv6Layer.Header.TrafficClass,
			FlowLabel:      ev.IPv6Layer.Header.FlowLabel,
			HopLimit:       ev.IPv6Layer.Header.HopLimit,
		}
	}

	ev.LogData.UDP = UDPLogData{
		Payload:  NewPayload(ev.UDPLayer.Header.Payload, config.Cfg.MaxUDPDataSize),
		Length:   ev.UDPLayer.Header.Length,
		Checksum: ev.UDPLayer.Header.Checksum,
	}

	ev.LogData.Additional = ev.Additional

	return ev.LogData
}
