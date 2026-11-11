//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package main

import "syscall"

// BSD / macOS termios ioctls (the historical 4.4BSD spelling). Using these is
// what makes `goprox user <name>` work on a macOS or BSD login node, where the
// Linux TCGETS/TCSETS constants do not exist.
const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)
