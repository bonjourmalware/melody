package logdata

type IPLogData interface{}

type BaseLogData struct {
	Timestamp  string            `json:"timestamp"`
	Session    string            `json:"session"`
	Type       string            `json:"type"`
	SourceIP   string            `json:"src_ip"`
	DestPort   uint16            `json:"dst_port"`
	Tags       []string              `json:"matches"`
	Additional map[string]string `json:"embedded"`
}
//
//type Tags []string
//
//func (t *Tags) FromEvent(ev ) {
//	var parsed = Tags{}
//	var set = make(map[string]struct{})
//	for _, tag := range ev.Tags {
//		if _, ok := set[tag]; !ok {
//			set[tag] = struct{}{}
//		}
//	}
//
//	for tag := range set {
//		parsed = append(*t, tag)
//	}
//
//	*t = parsed
//}
