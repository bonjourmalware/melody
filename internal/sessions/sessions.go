package sessions

import (
	"strconv"
	"time"
)

type Session struct {
	lastSeen time.Time
	uid      string
}

type SessionMap map[string]*Session

var (
	Map = make(SessionMap)
)

func (sessions SessionMap) GetUID(flow string) string {
	if session, ok := sessions[flow]; ok {
		return session.uid
	}

	return sessions.add(flow)
}

func (sessions *SessionMap) add(flow string) string {
	var ts = strconv.FormatInt(time.Now().UnixNano(), 10)
	(*sessions)[flow] = &Session{
		uid:      ts,
		lastSeen: time.Now(),
	}
	return ts
}

func (sessions *SessionMap) FlushOlderThan(deadline time.Time) {
	for flow, session := range *sessions {
		if session.lastSeen.Before(deadline) {
			delete(*sessions, flow)
		}
	}
}

func (sessions *SessionMap) FlushAll() {
	for flow := range *sessions {
		delete(*sessions, flow)
	}
}
