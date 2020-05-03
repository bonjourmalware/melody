package events

import (
	"net/http"
	"strconv"
	"time"

	"github.com/bonjourmalware/pinknoise/internal/sessions"

	"github.com/bonjourmalware/pinknoise/internal/config"

	"github.com/google/gopacket"
	"github.com/bonjourmalware/pinknoise/internal/parsing"
)

type HTTPEvent struct {
	Verb       string `json:"verb"`
	Proto      string `json:"proto"`
	RequestURI string `json:"URI"`
	SourcePort uint64 `json:"src_port"`
	DestHost   string `json:"dst_host"`
	DestPort   uint   `json:"dst_port"`
	Headers       map[string]string `json:"headers"`
	InlineHeaders []string
	Errors        []string `json:"errors"`
	Body          Payload  `json:"body"`
	IsTLS         bool     `json:"is_tls"`
	Req           *http.Request
	LogData       HTTPEventLog
	Event
}

func (ev HTTPEvent) ToLog() HTTPEventLog {
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
	ev.LogData.Verb = ev.Verb
	ev.LogData.Proto = ev.Proto
	ev.LogData.RequestURI = ev.RequestURI
	//ev.LogData.RemoteAddr = ev.RemoteAddr
	ev.LogData.SourcePort = ev.SourcePort
	ev.LogData.DestHost = ev.DestHost
	ev.LogData.DestPort = ev.DestPort
	ev.LogData.SourceIP = ev.SourceIP
	ev.LogData.Headers = ev.Headers
	ev.LogData.Body = ev.Body
	ev.LogData.IsTLS = ev.IsTLS
	ev.LogData.Metadata = ev.Metadata
	ev.LogData.References = ev.References
	ev.LogData.Statements = ev.Statements

	return ev.LogData
}

func NewHTTPEvent(r *http.Request, network gopacket.Flow, transport gopacket.Flow) *HTTPEvent {
	headers := make(map[string]string)
	var inlineHeaders []string
	var errs []string
	var params []byte
	var isTLS bool
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

	if r.TLS != nil {
		isTLS = true
	} else {
		isTLS = false
	}

	ev := &HTTPEvent{
		Verb:       r.Method,
		Proto:      r.Proto,
		RequestURI: r.URL.RequestURI(),
		SourcePort: srcPort,
		DestPort:   uint(dstPort),
		DestHost:   network.Dst().String(),
		Body:       NewPayload(params, config.Cfg.MaxPOSTDataSize),
		IsTLS:      isTLS,
		Headers:       headers,
		InlineHeaders: inlineHeaders,
		Errors:        errs,
	}

	// Cannot use promoted (inherited) fields in struct literal
	ev.Session = sessions.Map.GetUID(transport.String())
	ev.Kind = HTTPKind
	ev.SourceIP = network.Src().String()
	ev.DestPort = uint(dstPort)
	ev.Tags = []string{}
	ev.Metadata = make(map[string]string)
	ev.References = make(map[string][]string)
	ev.Statements = []string{}

	return ev
}