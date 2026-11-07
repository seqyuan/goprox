package eventlog

import (
	"fmt"
	"testing"
	"time"
)

func TestAddListNewestFirst(t *testing.T) {
	l := New(10)
	base := time.Now()
	for i := 0; i < 3; i++ {
		l.Add("alice", Event{Time: base.Add(time.Duration(i) * time.Second), Kind: KindAccess, OK: true, Detail: fmt.Sprintf("e%d", i)})
	}
	got := l.List("alice", 0)
	if len(got) != 3 {
		t.Fatalf("got %d events", len(got))
	}
	if got[0].Detail != "e2" || got[2].Detail != "e0" {
		t.Fatalf("not newest-first: %+v", got)
	}
	if got := l.List("bob", 0); len(got) != 0 {
		t.Fatalf("bob must not see alice's events, got %d", len(got))
	}
}

func TestCapacityDropsOldest(t *testing.T) {
	l := New(3)
	for i := 0; i < 6; i++ {
		l.Add("alice", Event{Detail: fmt.Sprintf("e%d", i)})
	}
	got := l.List("alice", 0)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	if got[0].Detail != "e5" || got[2].Detail != "e3" {
		t.Fatalf("wrong window: %+v", got)
	}
}

func TestLimitAndEmptyUser(t *testing.T) {
	l := New(10)
	l.Add("", Event{Kind: KindAccess}) // ignored
	for i := 0; i < 5; i++ {
		l.Add("alice", Event{})
	}
	if got := l.List("alice", 2); len(got) != 2 {
		t.Fatalf("limit not applied: %d", len(got))
	}
	if l.List("alice", 0)[0].Time.IsZero() {
		t.Fatal("time must be filled in")
	}
}

func TestCountFailuresWindow(t *testing.T) {
	l := New(10)
	l.Add("alice", Event{Time: time.Now().Add(-2 * time.Hour), Kind: KindAccess, OK: false})
	l.Add("alice", Event{Time: time.Now(), Kind: KindAccess, OK: false})
	l.Add("alice", Event{Time: time.Now(), Kind: KindAccess, OK: true})
	l.Add("alice", Event{Time: time.Now(), Kind: KindLogin, OK: false})

	if n := l.CountFailures("alice", time.Hour, KindAccess); n != 1 {
		t.Fatalf("CountFailures(access, 1h) = %d, want 1", n)
	}
	if n := l.CountFailures("alice", 24*time.Hour, KindAccess, KindLogin); n != 3 {
		t.Fatalf("CountFailures(access+login, 24h) = %d, want 3", n)
	}
	if n := l.CountFailures("bob", 24*time.Hour, KindAccess); n != 0 {
		t.Fatalf("bob has no events, got %d", n)
	}
}

func TestNilLogIsSafe(t *testing.T) {
	var l *Log
	l.Add("alice", Event{})
	if l.List("alice", 0) != nil || l.CountFailures("alice", time.Hour, KindAccess) != 0 {
		t.Fatal("nil log must be a no-op")
	}
}
