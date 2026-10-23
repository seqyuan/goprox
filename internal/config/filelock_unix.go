//go:build !windows
// +build !windows

package config

import (
	"os"
	"syscall"
)

// lockConfigFile takes an exclusive advisory lock on path. It is used in
// addition to the in-process mutex so the gateway and CLI commands (separate
// processes) cannot interleave a read-modify-write of the same config file.
// The lock is released automatically when the process dies.
func lockConfigFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
