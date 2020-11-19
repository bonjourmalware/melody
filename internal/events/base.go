package events

import (
	"github.com/bonjourmalware/melody/internal/loggable"
	"time"
)

// BaseEvent described the common structure to all the events generated by the received packets
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
	loggable.Loggable
}

// Tags is an abstraction of map[string]interface{} allowing for the use of a set-like structure and a more graceful
// conversion to array
type Tags map[string][]string

// GetKind fetches the Kind of an event
func (ev BaseEvent) GetKind() string {
	return ev.Kind
}

// GetSourceIP fetches the SourceIP of an event
func (ev BaseEvent) GetSourceIP() string {
	return ev.SourceIP
}

// GetDestPort fetches the DestPort of an event
func (ev BaseEvent) GetDestPort() uint16 {
	return ev.DestPort
}

// GetSession fetches the Session of an event
func (ev BaseEvent) GetSession() string {
	return ev.Session
}

// GetTags fetches the Tags of an event
func (ev BaseEvent) GetTags() map[string][]string {
	return ev.Tags
}

// AddAdditional fetches the Additional values of an event
func (ev *BaseEvent) AddAdditional(add map[string]string) {
	for key, values := range add {
		ev.Additional[key] = values
	}
}

// AddTags add the given tag array to the event's tags
//func (ev *BaseEvent) AddTags(tags []string) {
//	for _, tag := range tags {
//		ev.Tags[tag] = struct{}{}
//	}
//}

// AddTags add the given tag array to the event's tags
func (ev *BaseEvent) AddTags(tags map[string]string) {
	// If the tag does not already exist in its category, add it
	for cat, tag := range tags {
		if _, ok := ev.Tags[cat]; !ok {
			ev.Tags[cat] = []string{tag}
			continue
		}

		for _, val := range ev.Tags[cat] {
			if val == tag {
				break
			}
		}

		ev.Tags[cat] = append(ev.Tags[cat], tag)
	}
}

////ToInlineArray converts a Tags map to an array of its values with the keys and values merged with a '.'
//func (t *Tags) ToInlineArray() []string {
//	var inlineTags []string
//
//	for key, values := range *t {
//		for _, val := range values {
//			inlineTags = append(inlineTags, fmt.Sprintf("%s.%s", key, val))
//		}
//	}
//
//	return inlineTags
//}
