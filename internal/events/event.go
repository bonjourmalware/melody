package events

const (
	UDPKind     = "udp"
	TCPKind     = "tcp"
	ICMPv4Kind  = "icmpv4"
	HTTPKind    = "http"
	DefaultKind = "default"
)


//TODO Add common properties such as dst_host, src_port to base event
type Event struct {
	Tags       []string
	Kind       string
	SourceIP   string
	DestPort   uint
	Session    string
	Metadata   map[string]string
	Statements []string
	References map[string][]string
}

func (ev *Event) AddTags(tags []string) {
	ev.Tags = append(ev.Tags, tags...)
}

func (ev *Event) AddStatements(statements []string) {
	ev.Statements = append(ev.Statements, statements...)
}

func (ev *Event) AddMeta(metadata map[string]string) {
	for key, value := range metadata {
		ev.Metadata[key] = value
	}
}

func (ev *Event) AddRefs(refs map[string][]string) {
	for key, values := range refs {
		for _, value := range values {
			ev.References[key] = append(ev.References[key], value)
		}
	}
}
