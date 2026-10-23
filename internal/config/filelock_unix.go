//go:build !windows
// +build !windows

package config

import "syscall"

// processAlive reports whether pid is a live process on this host. Used to
// reclaim a lock left by a crashed gateway/CLI without waiting for the mtime
// stale threshold.
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
