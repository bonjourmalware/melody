package sessions

import (
	"time"

	"github.com/rs/xid"
)

// Session abstracts a session made of a last seen record and an uid
type Session struct {
	lastSeen time.Time
	uid      string
}

// sessionMap abstracts a hash table of multiple Session sorted by their flow data
type sessionMap map[string]*Session

var (
	// SessionMap is the global sessions hash table
	SessionMap = make(sessionMap)
)

func (m sessionMap) GetUID(flow string) string {
	if session, ok := m[flow]; ok {
		return session.uid
	}

	return m.add(flow)
}

func (m *sessionMap) add(flow string) string {
	//var ts = strconv.FormatInt(time.Now().UnixNano(), 10)
	var ts = xid.New().String()

	(*m)[flow] = &Session{
		uid:      ts,
		lastSeen: time.Now(),
	}
	return ts
}

// FlushOlderThan cleans the session mapping of sessions not seen since the given deadline
func (m *sessionMap) FlushOlderThan(deadline time.Time) {
	for flow, session := range *m {
		if session.lastSeen.Before(deadline) {
			delete(*m, flow)
		}
	}
}

// FlushAll removes all sessions from the session mapping
func (m *sessionMap) FlushAll() {
	for flow := range *m {
		delete(*m, flow)
	}
}
