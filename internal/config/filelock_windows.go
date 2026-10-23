//go:build windows
// +build windows

package config

// lockConfigFile is a no-op on Windows. GoProx targets Linux/Unix (the CLI's
// terminal handling is Unix-only), but keeping the symbol lets the package
// still compile on Windows for tooling.
func lockConfigFile(string) (func(), error) {
	return func() {}, nil
}
