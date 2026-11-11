//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"syscall"
	"unsafe"
)

// makeRaw disables echo and line buffering on fd so a password prompt does not
// print what is typed. The ioctl request numbers differ between the Linux
// (TCGETS/TCSETS) and BSD/macOS (TIOCGETA/TIOCSETA) families, so they live in
// terminal_ioctl_*.go; everything else is shared.
func makeRaw(fd int) (*syscall.Termios, error) {
	var oldState syscall.Termios
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		ioctlGetTermios, uintptr(unsafe.Pointer(&oldState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	newState := oldState
	newState.Lflag &^= syscall.ECHO | syscall.ICANON
	newState.Cc[syscall.VMIN] = 1
	newState.Cc[syscall.VTIME] = 0

	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		ioctlSetTermios, uintptr(unsafe.Pointer(&newState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	return &oldState, nil
}

func restore(fd int, state *syscall.Termios) error {
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		ioctlSetTermios, uintptr(unsafe.Pointer(state)), 0, 0, 0)
	return err
}
