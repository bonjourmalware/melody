package events

//TODO Add common properties such as dst_host, src_port to base event
type BaseEvent struct {
	Tags       []string
	Kind       string
	SourceIP   string
	DestPort   uint16
	Session    string
	Metadata   map[string]string
	Statements []string
	References map[string][]string
	Event
}

func (ev BaseEvent) GetKind() string {
	return ev.Kind
}

func (ev BaseEvent) GetSourceIP() string {
	return ev.SourceIP
}

func (ev BaseEvent) GetDestPort() uint16 {
	return ev.DestPort
}

func (ev *BaseEvent) AddTags(tags []string) {
	ev.Tags = append(ev.Tags, tags...)
}

func (ev *BaseEvent) AddStatements(statements []string) {
	ev.Statements = append(ev.Statements, statements...)
}

func (ev *BaseEvent) AddMeta(metadata map[string]string) {
	for key, value := range metadata {
		ev.Metadata[key] = value
	}
}

func (ev *BaseEvent) AddRefs(refs map[string][]string) {
	for key, values := range refs {
		for _, value := range values {
			ev.References[key] = append(ev.References[key], value)
		}
	}
}
