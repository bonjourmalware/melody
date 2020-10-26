package events

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/google/gopacket/layers"

	"github.com/bonjourmalware/pinknoise/internal/sessions"

	"github.com/bonjourmalware/pinknoise/internal/config"

	"github.com/bonjourmalware/pinknoise/internal/parsing"
	"github.com/google/gopacket"
)

type HTTPEvent struct {
	Verb          string            `json:"verb"`
	Proto         string            `json:"proto"`
	RequestURI    string            `json:"URI"`
	SourcePort    uint16            `json:"src_port"`
	DestHost      string            `json:"dst_host"`
	DestPort      uint16            `json:"dst_port"`
	Headers       map[string]string `json:"headers"`
	InlineHeaders []string
	Errors        []string `json:"errors"`
	Body          Payload  `json:"body"`
	IsTLS         bool     `json:"is_tls"`
	Req           *http.Request
	LogData       HTTPEventLog
	BaseEvent
}

func (ev HTTPEvent) GetIPHeader() *layers.IPv4 {
	return nil
}

func (ev HTTPEvent) GetHTTPData() HTTPEvent {
	return ev
}

func (ev HTTPEvent) ToLog() EventLog {
	ev.LogData = HTTPEventLog{}
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

	ev.LogData.Session = ev.Session
	ev.LogData.HTTP.Verb = ev.Verb
	ev.LogData.HTTP.Proto = ev.Proto
	ev.LogData.HTTP.RequestURI = ev.RequestURI
	//ev.BaseLogData.RemoteAddr = ev.RemoteAddr
	ev.LogData.HTTP.SourcePort = ev.SourcePort
	ev.LogData.HTTP.DestHost = ev.DestHost
	ev.LogData.DestPort = ev.DestPort
	ev.LogData.SourceIP = ev.SourceIP
	ev.LogData.HTTP.Headers = ev.Headers
	ev.LogData.HTTP.Body = ev.Body
	ev.LogData.HTTP.IsTLS = ev.IsTLS
	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}

func NewHTTPEvent(r *http.Request, network gopacket.Flow, transport gopacket.Flow) (*HTTPEvent, error) {
	headers := make(map[string]string)
	var inlineHeaders []string
	var errs []string
	var params []byte
	var err error

	for header := range r.Header {
		headers[header] = r.Header.Get(header)
		inlineHeaders = append(inlineHeaders, header+": "+r.Header.Get(header))
	}

	dstPort, _ := strconv.ParseUint(transport.Dst().String(), 10, 16)
	srcPort, _ := strconv.ParseUint(transport.Src().String(), 10, 16)

	params, err = parsing.GetBodyPayload(r)
	if err != nil {
		errs = append(errs, err.Error())
	}

	ev := &HTTPEvent{
		Verb:       r.Method,
		Proto:      r.Proto,
		RequestURI: r.URL.RequestURI(),
		SourcePort: uint16(srcPort),
		DestPort:   uint16(dstPort),
		DestHost:   network.Dst().String(),
		Body:       NewPayload(params, config.Cfg.MaxPOSTDataSize),
		//IsTLS:         r.TLS != nil,
		IsTLS:         false,
		Headers:       headers,
		InlineHeaders: inlineHeaders,
		Errors:        errs,
	}

	// Cannot use promoted (inherited) fields in struct literal
	ev.Session = sessions.Map.GetUID(transport.String())
	ev.Kind = config.HTTPKind
	ev.SourceIP = network.Src().String()
	ev.Tags = []string{}
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}

func NewHTTPEventFromRequest(r *http.Request) (*HTTPEvent, error) {
	headers := make(map[string]string)
	var inlineHeaders []string
	var errs []string
	var params []byte
	var srcIP string
	var rawDstPort string
	var rawSrcPort string
	var err error

	for header := range r.Header {
		headers[header] = r.Header.Get(header)
		inlineHeaders = append(inlineHeaders, header+": "+r.Header.Get(header))
	}

	hostChunks := strings.Split(r.Host, ":")
	dstHost := hostChunks[0]
	rawDstPort = hostChunks[1]
	remoteAddrChunks := strings.Split(r.RemoteAddr, ":")
	fmt.Println(remoteAddrChunks)
	srcIP, rawSrcPort = remoteAddrChunks[0], remoteAddrChunks[1]

	params, err = parsing.GetBodyPayload(r)
	if err != nil {
		errs = append(errs, err.Error())
	}

	srcPort, _ := strconv.ParseUint(rawSrcPort, 10, 16)
	dstPort, _ := strconv.ParseUint(rawDstPort, 10, 16)

	ev := &HTTPEvent{
		Verb:       r.Method,
		Proto:      r.Proto,
		RequestURI: r.URL.RequestURI(),
		SourcePort: uint16(srcPort),
		DestPort:   uint16(dstPort),
		DestHost:   dstHost,
		Body:       NewPayload(params, config.Cfg.MaxPOSTDataSize),
		//IsTLS:         r.TLS != nil,
		IsTLS:         true,
		Headers:       headers,
		InlineHeaders: inlineHeaders,
		Errors:        errs,
	}

	// Cannot use promoted (inherited) fields in struct literal
	ev.Session = xid.New().String()
	ev.Kind = config.HTTPKind
	ev.SourceIP = srcIP
	ev.Tags = []string{}
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev, nil
}
