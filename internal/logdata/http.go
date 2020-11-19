package logdata

import "encoding/json"

// HTTPLogData is the struct describing the logged data for reassembled HTTP packets
type HTTPLogData struct {
	Verb          string            `json:"verb"`
	Proto         string            `json:"proto"`
	RequestURI    string            `json:"uri"`
	SourcePort    uint16            `json:"src_port"`
	DestHost      string            `json:"dst_host"`
	UserAgent     string            `json:"user_agent"`
	Headers       map[string]string `json:"headers"`
	HeadersKeys   []string          `json:"headers_keys"`
	HeadersValues []string          `json:"headers_values"`
	Errors        []string          `json:"errors"`
	Body          Payload           `json:"body"`
	IsTLS         bool              `json:"is_tls"`
}

// HTTPEventLog is the event log struct for reassembled HTTP packets
type HTTPEventLog struct {
	HTTP HTTPLogData `json:"http"`
	IP   IPLogData   `json:"ip"`
	BaseLogData
}

func (eventLog HTTPEventLog) String() (string, error) {
	data, err := json.Marshal(eventLog)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
