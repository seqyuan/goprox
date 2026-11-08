package eventlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Retention defaults and bounds for the on-disk history.
const (
	DefaultRetentionDays = 7
	maxRetentionDays     = 3650
	// maxFileBytes bounds how much of one day's file is parsed for a single
	// List call. A lab gateway produces a few KB/day; this only guards against
	// a pathological file (or a hand-edited one) eating memory.
	maxFileBytes = 8 << 20
)

const filePrefix = "events-"
const fileSuffix = ".jsonl"

// record is one JSON line on disk. The user is stored inside the line rather
// than in the file name so a single day file can hold every account.
type record struct {
	User string `json:"user"`
	Event
}

// diskStore appends events to <dir>/events-YYYY-MM-DD.jsonl and prunes files
// older than retentionDays. It is safe for concurrent use.
type diskStore struct {
	dir           string
	retentionDays int

	mu  sync.Mutex
	f   *os.File
	day string // date of the currently open file, YYYY-MM-DD
}

// NewWithDisk returns a history that also persists to dir, keeping the last
// retentionDays days (0 disables disk logging). An unusable directory is
// reported, but the returned Log is still usable (memory only).
func NewWithDisk(dir string, perUser, retentionDays int) (*Log, error) {
	log := New(perUser)
	if retentionDays <= 0 {
		return log, nil
	}
	if retentionDays > maxRetentionDays {
		retentionDays = maxRetentionDays
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return log, fmt.Errorf("create log dir: %w", err)
	}
	// Probe writability now: failing later on every request would be silent.
	probe := filepath.Join(dir, ".write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return log, fmt.Errorf("log dir %s is not writable: %w", dir, err)
	}
	f.Close()
	os.Remove(probe)

	d := &diskStore{dir: dir, retentionDays: retentionDays}
	d.prune(time.Now())
	log.disk = d
	return log, nil
}

// LogDir returns the directory backing a disk-enabled log ("" when memory only).
func (l *Log) LogDir() string {
	if l == nil || l.disk == nil {
		return ""
	}
	return l.disk.dir
}

// RetentionDays returns the configured retention (0 = memory only).
func (l *Log) RetentionDays() int {
	if l == nil || l.disk == nil {
		return 0
	}
	return l.disk.retentionDays
}

func (d *diskStore) append(username string, e Event) error {
	line, err := json.Marshal(record{User: username, Event: e})
	if err != nil {
		return err
	}
	day := e.Time.Local().Format("2006-01-02")

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.f == nil || d.day != day {
		if d.f != nil {
			d.f.Close()
			d.f = nil
		}
		// A date change is also the natural moment to drop old files.
		d.pruneLocked(e.Time)
		f, err := os.OpenFile(filepath.Join(d.dir, filePrefix+day+fileSuffix),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		d.f = f
		d.day = day
	}
	_, err = d.f.Write(append(line, '\n'))
	return err
}

// list returns up to limit events for one user, newest first, scanning the
// newest day files first.
func (d *diskStore) list(username string, limit int) ([]Event, error) {
	files, err := d.dayFiles()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = DefaultPerUser
	}
	out := make([]Event, 0, limit)
	// dayFiles is sorted oldest→newest; walk it backwards.
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		events, err := readDayFile(files[i].path, username)
		if err != nil {
			continue // an unreadable day must not hide the others
		}
		for j := len(events) - 1; j >= 0 && len(out) < limit; j-- {
			out = append(out, events[j])
		}
	}
	return out, nil
}

type dayFile struct {
	day  string
	path string
}

func (d *diskStore) dayFiles() ([]dayFile, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	files := make([]dayFile, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileSuffix) {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileSuffix)
		if _, err := time.Parse("2006-01-02", day); err != nil {
			continue
		}
		files = append(files, dayFile{day: day, path: filepath.Join(d.dir, name)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].day < files[j].day })
	return files, nil
}

// prune deletes day files older than the retention window.
func (d *diskStore) prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
}

func (d *diskStore) pruneLocked(now time.Time) {
	cutoff := now.AddDate(0, 0, -d.retentionDays).Format("2006-01-02")
	files, err := d.dayFiles()
	if err != nil {
		return
	}
	for _, f := range files {
		if f.day < cutoff {
			// Keep the currently open file even if its date looks stale (clock
			// jumps): closing it here would break appends.
			if d.f != nil && f.day == d.day {
				continue
			}
			os.Remove(f.path)
		}
	}
}

func readDayFile(path, username string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var read int64
	for scanner.Scan() {
		line := scanner.Bytes()
		read += int64(len(line)) + 1
		if read > maxFileBytes {
			break
		}
		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // a torn last line (crash) must not break the history
		}
		if rec.User != username {
			continue
		}
		out = append(out, rec.Event)
	}
	return out, scanner.Err()
}
