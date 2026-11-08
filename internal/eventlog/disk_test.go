package eventlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiskHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	l, err := NewWithDisk(filepath.Join(dir, "logs"), 10, 7)
	if err != nil {
		t.Fatal(err)
	}
	if l.LogDir() == "" || l.RetentionDays() != 7 {
		t.Fatalf("log dir/retention = %q/%d", l.LogDir(), l.RetentionDays())
	}
	l.Add("alice", Event{Kind: KindLogin, OK: true, Detail: "密码登录"})
	l.Add("bob", Event{Kind: KindAccess, OK: false, Service: "App", Detail: "connection refused"})

	// A fresh instance (think: gateway restart) must see the same history.
	l2, err := NewWithDisk(filepath.Join(dir, "logs"), 10, 7)
	if err != nil {
		t.Fatal(err)
	}
	alice := l2.List("alice", 0)
	if len(alice) != 1 || alice[0].Detail != "密码登录" || !alice[0].OK {
		t.Fatalf("alice history after restart = %+v", alice)
	}
	if got := l2.List("bob", 0); len(got) != 1 || got[0].Service != "App" {
		t.Fatalf("bob history after restart = %+v", got)
	}
	if got := l2.List("carol", 0); len(got) != 0 {
		t.Fatalf("carol must not see other users' events: %+v", got)
	}

	// File permissions: the history contains usernames and paths.
	files, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.HasSuffix(files[0].Name(), ".jsonl") {
		t.Fatalf("unexpected log files: %v", files)
	}
	info, err := files[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("log file too open: %v", info.Mode())
	}
}

func TestDiskHistoryNewestFirstAndLimit(t *testing.T) {
	dir := t.TempDir()
	l, err := NewWithDisk(dir, 100, 7)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		l.Add("alice", Event{Time: base.Add(time.Duration(i) * time.Minute), Detail: string(rune('a' + i))})
	}
	got := l.List("alice", 2)
	if len(got) != 2 || got[0].Detail != "e" || got[1].Detail != "d" {
		t.Fatalf("got %+v", got)
	}
}

func TestDiskHistorySpansDays(t *testing.T) {
	dir := t.TempDir()
	l, err := NewWithDisk(dir, 100, 7)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Add("alice", Event{Time: now.AddDate(0, 0, -1), Detail: "yesterday"})
	l.Add("alice", Event{Time: now, Detail: "today"})

	got := l.List("alice", 10)
	if len(got) != 2 || got[0].Detail != "today" || got[1].Detail != "yesterday" {
		t.Fatalf("cross-day order = %+v", got)
	}
}

func TestDiskRetentionPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	// Hand-craft files: one older than the window, one inside it.
	old := filepath.Join(dir, filePrefix+time.Now().AddDate(0, 0, -30).Format("2006-01-02")+fileSuffix)
	keep := filepath.Join(dir, filePrefix+time.Now().Format("2006-01-02")+fileSuffix)
	for _, p := range []string{old, keep} {
		if err := os.WriteFile(p, []byte(`{"user":"alice","kind":"access","ok":true}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewWithDisk(dir, 10, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("file older than the retention window was not pruned")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("file inside the window was removed: %v", err)
	}
}

func TestDiskDisabledWhenRetentionZero(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	l, err := NewWithDisk(dir, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	l.Add("alice", Event{Kind: KindLogin, OK: true})
	if l.LogDir() != "" {
		t.Fatal("retention 0 must not write files")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("retention 0 must not create the directory")
	}
	if got := l.List("alice", 0); len(got) != 1 {
		t.Fatalf("memory fallback broken: %+v", got)
	}
}

func TestDiskUnusableFallsBackToMemory(t *testing.T) {
	// A file where the log dir should be: MkdirAll fails.
	path := filepath.Join(t.TempDir(), "logs")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := NewWithDisk(path, 10, 7)
	if err == nil {
		t.Fatal("expected an error for an unusable log dir")
	}
	if l == nil {
		t.Fatal("log must still be usable")
	}
	l.Add("alice", Event{Kind: KindLogin, OK: true})
	if got := l.List("alice", 0); len(got) != 1 {
		t.Fatalf("memory fallback broken: %+v", got)
	}
}

func TestDiskTornLineIsSkipped(t *testing.T) {
	dir := t.TempDir()
	l, err := NewWithDisk(dir, 10, 7)
	if err != nil {
		t.Fatal(err)
	}
	l.Add("alice", Event{Kind: KindLogin, OK: true, Detail: "good"})
	// Simulate a crash mid-write.
	path := filepath.Join(dir, filePrefix+time.Now().Format("2006-01-02")+fileSuffix)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"user":"alice","kind":"acc`)
	f.Close()

	got := l.List("alice", 0)
	if len(got) != 1 || got[0].Detail != "good" {
		t.Fatalf("torn line handling = %+v", got)
	}
}
