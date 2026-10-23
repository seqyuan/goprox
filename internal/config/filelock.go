package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	lockWaitTimeout  = 30 * time.Second
	lockStaleAfter   = 2 * time.Minute
	lockPollInterval = 25 * time.Millisecond
)

// lockConfigFile takes an exclusive lock by atomically creating path with
// O_CREATE|O_EXCL. Unlike flock this works on filesystems (including many NFS
// mounts) that do not support advisory locks, and the lock file is removed on
// release, so normal operation leaves no .lock clutter.
//
// A crashed process leaves the file behind. The lock records the host and PID:
// on the same host a dead PID is reclaimed immediately; cross-host (NFS) or
// unparsable files are reclaimed after lockStaleAfter.
func lockConfigFile(path string) (func(), error) {
	return lockConfigFileWith(path, lockWaitTimeout, lockStaleAfter, lockPollInterval)
}

func lockConfigFileWith(path string, wait, staleAfter, poll time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			host, _ := os.Hostname()
			fmt.Fprintf(f, "%s %d %d\n", host, os.Getpid(), time.Now().Unix())
			info, statErr := f.Stat()
			f.Close()
			if statErr != nil {
				os.Remove(path)
				return nil, statErr
			}
			return func() {
				// Only remove the file we created: a stale-lock reclaim by
				// another process could have replaced it.
				if cur, err := os.Stat(path); err == nil && os.SameFile(cur, info) {
					os.Remove(path)
				}
			}, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if staleLock(path, staleAfter) {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for lock %s", path)
		}
		time.Sleep(poll)
	}
}

func staleLock(path string, staleAfter time.Duration) bool {
	if data, err := os.ReadFile(path); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			myHost, _ := os.Hostname()
			if fields[0] == myHost {
				if pid, err := strconv.Atoi(fields[1]); err == nil && pid > 0 && !processAlive(pid) {
					return true
				}
			}
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > staleAfter
}
