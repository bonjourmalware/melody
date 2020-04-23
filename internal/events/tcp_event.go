package events

import (
	"strings"
	"time"

	"gitlab.com/Alvoras/pinknoise/internal/sessions"

	"gitlab.com/Alvoras/pinknoise/internal/config"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPEvent struct {
	IPHeader  *layers.IPv4
	TCPHeader *layers.TCP
	LogData   TCPEventLog
	Event
	//BaseEvent
}

func NewTCPEvent(packet gopacket.Packet) (*TCPEvent, error) {
	var ev = &TCPEvent{}
	ev.Kind = TCPKind

	ev.Session = sessions.Map.GetUID(packet.TransportLayer().TransportFlow().String())

	IPHeader, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ev.IPHeader = IPHeader
	ev.SourceIP = IPHeader.SrcIP.String()

	TCPHeader, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	ev.TCPHeader = TCPHeader
	ev.DestPort = uint(TCPHeader.DstPort)
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

func (ev TCPEvent) ToLog() TCPEventLog {
	var tcpFlagsStr []string
	var ipFlagsStr []string

	ev.LogData = TCPEventLog{}
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

	ev.LogData.TCP = TCPLogData{
		Window:     ev.TCPHeader.Window,
		Seq:        ev.TCPHeader.Seq,
		Ack:        ev.TCPHeader.Ack,
		DataOffset: ev.TCPHeader.DataOffset,
		Urgent:     ev.TCPHeader.Urgent,
		Payload:    NewPayload(ev.TCPHeader.Payload, config.Cfg.MaxTCPDataSize),
	}

	if ev.TCPHeader.FIN {
		tcpFlagsStr = append(tcpFlagsStr, "F")
	}
	if ev.TCPHeader.SYN {
		tcpFlagsStr = append(tcpFlagsStr, "S")
	}
	if ev.TCPHeader.RST {
		tcpFlagsStr = append(tcpFlagsStr, "R")
	}
	if ev.TCPHeader.PSH {
		tcpFlagsStr = append(tcpFlagsStr, "P")
	}
	if ev.TCPHeader.ACK {
		tcpFlagsStr = append(tcpFlagsStr, "A")
	}
	if ev.TCPHeader.URG {
		tcpFlagsStr = append(tcpFlagsStr, "U")
	}
	if ev.TCPHeader.ECE {
		tcpFlagsStr = append(tcpFlagsStr, "E")
	}
	if ev.TCPHeader.CWR {
		tcpFlagsStr = append(tcpFlagsStr, "C")
	}
	if ev.TCPHeader.NS {
		tcpFlagsStr = append(tcpFlagsStr, "N")
	}

	ev.LogData.TCP.Flags = strings.Join(tcpFlagsStr, "")
	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}
