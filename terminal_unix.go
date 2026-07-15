//go:build !windows
// +build !windows

package main

import (
	"syscall"
	"unsafe"
)

func makeRaw(fd int) (*syscall.Termios, error) {
	var oldState syscall.Termios
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCGETS, uintptr(unsafe.Pointer(&oldState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	newState := oldState
	newState.Lflag &^= syscall.ECHO | syscall.ICANON
	newState.Cc[syscall.VMIN] = 1
	newState.Cc[syscall.VTIME] = 0

	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(&newState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	return &oldState, nil
}

func restore(fd int, state *syscall.Termios) error {
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(state)), 0, 0, 0)
	return err
}
