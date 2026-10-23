//go:build windows
// +build windows

package config

// processAlive cannot check PIDs portably on Windows here; returning true
// means stale locks are reclaimed by the mtime threshold instead of PID
// liveness. (GoProx itself targets Linux/Unix; this keeps the package
// buildable for tooling.)
func processAlive(int) bool { return true }
