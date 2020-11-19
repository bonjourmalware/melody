package loggable

// Loggable is an interface to allow mutual use of events.BaseEvent for logdata.BaseLogData
type Loggable interface {
	GetSession() string
	GetTags() map[string][]string
	GetKind() string
	GetSourceIP() string
	GetDestPort() uint16
}
