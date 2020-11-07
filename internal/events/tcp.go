package events

import (
	"strings"
	"time"

	"github.com/bonjourmalware/pinknoise/internal/sessions"

	"github.com/bonjourmalware/pinknoise/internal/config"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPEvent struct {
	LogData TCPEventLog
	BaseEvent
	TCPLayer
	IPv4Layer
	IPv6Layer
}

func NewTCPEvent(packet gopacket.Packet, IPVersion uint) (*TCPEvent, error) {
	var ev = &TCPEvent{}
	ev.Kind = config.TCPKind
	ev.IPVersion = IPVersion

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

	TCPHeader, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	ev.Timestamp = packet.Metadata().Timestamp
	ev.TCPLayer = TCPLayer{Header: TCPHeader}
	ev.DestPort = uint16(TCPHeader.DstPort)

	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)

	return ev, nil
}

func (ev TCPEvent) ToLog() EventLog {
	var tcpFlagsStr []string
	var ipFlagsStr []string

	ev.LogData = TCPEventLog{}
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

	ev.LogData.TCP = TCPLogData{
		Window:     ev.TCPLayer.Header.Window,
		Seq:        ev.TCPLayer.Header.Seq,
		Ack:        ev.TCPLayer.Header.Ack,
		DataOffset: ev.TCPLayer.Header.DataOffset,
		Urgent:     ev.TCPLayer.Header.Urgent,
		Payload:    NewPayload(ev.TCPLayer.Header.Payload, config.Cfg.MaxTCPDataSize),
	}

	if ev.TCPLayer.Header.FIN {
		tcpFlagsStr = append(tcpFlagsStr, "F")
	}
	if ev.TCPLayer.Header.SYN {
		tcpFlagsStr = append(tcpFlagsStr, "S")
	}
	if ev.TCPLayer.Header.RST {
		tcpFlagsStr = append(tcpFlagsStr, "R")
	}
	if ev.TCPLayer.Header.PSH {
		tcpFlagsStr = append(tcpFlagsStr, "P")
	}
	if ev.TCPLayer.Header.ACK {
		tcpFlagsStr = append(tcpFlagsStr, "A")
	}
	if ev.TCPLayer.Header.URG {
		tcpFlagsStr = append(tcpFlagsStr, "U")
	}
	if ev.TCPLayer.Header.ECE {
		tcpFlagsStr = append(tcpFlagsStr, "E")
	}
	if ev.TCPLayer.Header.CWR {
		tcpFlagsStr = append(tcpFlagsStr, "C")
	}
	if ev.TCPLayer.Header.NS {
		tcpFlagsStr = append(tcpFlagsStr, "N")
	}

	ev.LogData.TCP.Flags = strings.Join(tcpFlagsStr, "")
	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References

	return ev.LogData
}
