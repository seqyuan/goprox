//go:build linux

package main

import "syscall"

// Linux termios ioctls (the Linux/System V spelling).
const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)
