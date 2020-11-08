package events

import (
	"time"
)

type BaseEvent struct {
	IPVersion  uint
	Tags       []string
	Kind       string
	SourceIP   string
	DestPort   uint16
	Session    string
	Timestamp  time.Time
	Additional map[string]string
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

func (ev *BaseEvent) AddAdditional(add map[string]string) {
	for key, values := range add {
		ev.Additional[key] = values
	}
}
