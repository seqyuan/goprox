// Package eventlog keeps a small, in-memory history of what happened to each
// user's sessions and cards: logins, card accesses with their outcome, and
// connectivity probes.
//
// It exists so the person hitting "跳转异常 / 打不开" can look at the logs page
// and see which hop failed, instead of guessing. History is per user (nobody
// sees another account's activity) and lives in memory only: a restart clears
// it, while the full gateway log stays available on stdout/journalctl.
package eventlog

import (
	"sync"
	"time"
)

// Kinds of events.
const (
	KindLogin  = "login"  // sign-in attempt (success or failure)
	KindAccess = "access" // a card was opened (page/API through the gateway)
	KindProbe  = "probe"  // "测一下" connectivity probe
)

// Event is one entry in a user's history.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	OK      bool      `json:"ok"`
	Service string    `json:"service,omitempty"` // card name, when applicable
	Detail  string    `json:"detail,omitempty"`  // error reason / target
	Millis  int64     `json:"ms,omitempty"`      // duration for access/probe
}

// Log is a fixed-capacity per-user history. It is safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	events map[string][]Event
	cap    int
}

// DefaultPerUser is how many events are kept per account.
const DefaultPerUser = 500

// New creates a history keeping at most perUser events per account.
func New(perUser int) *Log {
	if perUser <= 0 {
		perUser = DefaultPerUser
	}
	return &Log{cap: perUser}
}

// Add appends an event for a user, dropping the oldest when the cap is reached.
// An empty username is ignored (unauthenticated probes have no place in a
// per-user history).
func (l *Log) Add(username string, e Event) {
	if l == nil || username == "" {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.events == nil {
		l.events = make(map[string][]Event)
	}
	buf := l.events[username]
	buf = append(buf, e)
	if len(buf) > l.cap {
		// Copy into a fresh slice so the old backing array can be collected.
		buf = append([]Event(nil), buf[len(buf)-l.cap:]...)
	}
	l.events[username] = buf
}

// List returns up to limit events for a user, newest first.
func (l *Log) List(username string, limit int) []Event {
	if l == nil || username == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buf := l.events[username]
	if limit <= 0 || limit > len(buf) {
		limit = len(buf)
	}
	out := make([]Event, 0, limit)
	for i := len(buf) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, buf[i])
	}
	return out
}

// CountFailures returns how many events of the given kinds failed since a
// duration ago. Used for the dashboard summary line.
func (l *Log) CountFailures(username string, since time.Duration, kinds ...string) int {
	if l == nil || username == "" {
		return 0
	}
	cutoff := time.Now().Add(-since)
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.events[username] {
		if e.OK || e.Time.Before(cutoff) {
			continue
		}
		for _, k := range kinds {
			if e.Kind == k {
				n++
				break
			}
		}
	}
	return n
}

// Reset drops every user's history. Only tests use it.
func (l *Log) Reset() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.events = nil
	l.mu.Unlock()
}
