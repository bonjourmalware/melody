package logdata

// IPLogData is the interface used by packet structs supporting an IP layer
type IPLogData interface{}

// BaseLogData is used as the base packet log and contains common data, such as the timestamp
type BaseLogData struct {
	Timestamp  string            `json:"timestamp"`
	Session    string            `json:"session"`
	Type       string            `json:"type"`
	SourceIP   string            `json:"src_ip"`
	DestPort   uint16            `json:"dst_port"`
	Tags       []string          `json:"matches"`
	Additional map[string]string `json:"embedded"`
}
