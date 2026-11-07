package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// filesRootAllowlist restricts kind:"files" roots to the directories listed in
// state.yaml (server.files_roots). It is empty on single-admin installs, where
// any readable directory is allowed — except the gateway config directory,
// which is always refused regardless of this list (see ValidateFileRoot).
var (
	filesRootMu        sync.RWMutex
	filesRootAllowlist []string
)

// SetFilesRootAllowlist installs the allowlist (server.files_roots). Entries are
// cleaned and symlink-resolved; an empty list disables the restriction. Invalid
// entries are dropped with a message so a typo cannot silently lock everyone out
// of their file cards... except that dropping a typo *would* widen access, so
// LoadState validates the list first and refuses to start on invalid input.
func SetFilesRootAllowlist(roots []string) {
	normalized := make([]string, 0, len(roots))
	for _, raw := range roots {
		raw = strings.TrimSpace(raw)
		if raw == "" || !filepath.IsAbs(raw) {
			continue
		}
		normalized = append(normalized, resolveSymlinks(filepath.Clean(raw)))
	}
	filesRootMu.Lock()
	filesRootAllowlist = normalized
	filesRootMu.Unlock()
}

// FilesRootAllowlist returns a copy of the current allowlist (for messages).
func FilesRootAllowlist() []string {
	filesRootMu.RLock()
	defer filesRootMu.RUnlock()
	out := make([]string, len(filesRootAllowlist))
	copy(out, filesRootAllowlist)
	return out
}

// NormalizeFilesRoots validates and normalizes server.files_roots.
func NormalizeFilesRoots(roots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(roots))
	seen := make(map[string]bool, len(roots))
	for _, raw := range roots {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !filepath.IsAbs(raw) {
			return nil, fmt.Errorf("server.files_roots entry %q must be an absolute path", raw)
		}
		clean := filepath.Clean(raw)
		st, err := os.Stat(clean)
		if err != nil {
			return nil, fmt.Errorf("server.files_roots entry %q: %w", raw, err)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("server.files_roots entry %q is not a directory", raw)
		}
		key := resolveSymlinks(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out, nil
}

// assertWithinFilesRoots rejects a files root outside the configured allowlist.
func assertWithinFilesRoots(root string) error {
	filesRootMu.RLock()
	allowed := filesRootAllowlist
	filesRootMu.RUnlock()
	if len(allowed) == 0 {
		return nil
	}
	resolved := resolveSymlinks(root)
	for _, dir := range allowed {
		if within(resolved, dir) {
			return nil
		}
	}
	return fmt.Errorf("目录 %s 不在允许挂载的白名单内（state.yaml 的 server.files_roots）：%s",
		root, strings.Join(allowed, ", "))
}
