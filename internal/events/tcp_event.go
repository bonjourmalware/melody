package events

import (
	"strconv"
	"strings"
	"time"

	"github.com/bonjourmalware/pinknoise/internal/sessions"

	"github.com/bonjourmalware/pinknoise/internal/config"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPEvent struct {
	//IPHeader  *layers.IPv4
	//TCPHeader *layers.TCP
	LogData   TCPEventLog
	BaseEvent
	TCPLayer
	IPLayer
}

func NewTCPEvent(packet gopacket.Packet) (*TCPEvent, error) {
	var ev = &TCPEvent{}
	ev.Kind = TCPKind

	ev.Session = sessions.Map.GetUID(packet.TransportLayer().TransportFlow().String())

	IPHeader, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ev.IPLayer = IPLayer{Header: IPHeader}
	ev.SourceIP = IPHeader.SrcIP.String()

	TCPHeader, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	ev.TCPLayer = TCPLayer{Header: TCPHeader}
	ev.DestPort = uint(TCPHeader.DstPort)

	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

func (ev TCPEvent) ToLog() EventLog {
	var tcpFlagsStr []string
	var ipFlagsStr []string

	ev.LogData = TCPEventLog{}
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

	ev.LogData.IP = IPLogData{
		Version:    ev.IPLayer.Header.Version,
		IHL:        ev.IPLayer.Header.IHL,
		TOS:        ev.IPLayer.Header.TOS,
		Length:     ev.IPLayer.Header.Length,
		Id:         ev.IPLayer.Header.Id,
		FragOffset: ev.IPLayer.Header.FragOffset,
		TTL:        ev.IPLayer.Header.TTL,
		Protocol:   ev.IPLayer.Header.Protocol,
	}

	if ev.IPLayer.Header.Flags&layers.IPv4EvilBit != 0 {
		ipFlagsStr = append(ipFlagsStr, "EV")
	}
	if ev.IPLayer.Header.Flags&layers.IPv4DontFragment != 0 {
		ipFlagsStr = append(ipFlagsStr, "DF")
	}
	if ev.IPLayer.Header.Flags&layers.IPv4MoreFragments != 0 {
		ipFlagsStr = append(ipFlagsStr, "MF")
	}

	ev.LogData.IP.Fragbits = strings.Join(ipFlagsStr, "")

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
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}
