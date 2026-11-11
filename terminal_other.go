//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import "errors"

// terminalState is the placeholder state type on platforms without POSIX
// termios. It keeps cmd_user.go (which only passes the value back to restore)
// building on every target.
type terminalState struct{}

// errNoRawMode reports that password echo cannot be disabled here.
var errNoRawMode = errors.New("terminal raw mode is not supported on this platform")

// makeRaw always fails on these platforms. readPassword treats a failed
// makeRaw as "no terminal control available" and keeps reading the password,
// which simply echoes what is typed (e.g. on Windows) instead of refusing to
// create the account.
func makeRaw(int) (*terminalState, error) { return nil, errNoRawMode }

// restore is a no-op because makeRaw never changed anything.
func restore(int, *terminalState) error { return nil }
