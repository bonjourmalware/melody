package events

import (
	"time"
)

type BaseEvent struct {
	IPVersion  uint
	Tags       Tags
	Kind       string
	SourceIP   string
	DestPort   uint16
	Session    string
	Timestamp  time.Time
	Additional map[string]string
	Event
}

type Tags map[string]interface{}

func (ev BaseEvent) GetKind() string {
	return ev.Kind
}

func (ev BaseEvent) GetSourceIP() string {
	return ev.SourceIP
}

func (ev BaseEvent) GetDestPort() uint16 {
	return ev.DestPort
}

func (ev *BaseEvent) AddAdditional(add map[string]string) {
	for key, values := range add {
		ev.Additional[key] = values
	}
}

func (ev *BaseEvent) AddTags(tags []string) {
	for _, tag := range tags {
		ev.Tags[tag] = struct{}{}
	}
}

func (t *Tags) ToArray() []string {
	var ret []string
	for tag := range *t {
		ret = append(ret, tag)
	}

	return ret
}
