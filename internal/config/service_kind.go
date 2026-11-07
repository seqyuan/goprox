package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func NormalizeServiceKind(kind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", ServiceKindProxy:
		return ServiceKindProxy, true
	case ServiceKindFiles:
		return ServiceKindFiles, true
	}
	return "", false
}

// ValidateFileRoot normalizes and checks the directory of a files service: it
// must be an absolute path to an existing, readable directory that does not
// overlap the gateway's own config directory.
//
// The overlap check is a privilege boundary, not tidiness. A files service is
// configured by any logged-in user, and the gateway serves whatever its own
// account can read; without this rule a normal user could mount
// <config dir>/ as a card and download state.yaml (session_secret) and
// users/*.yaml (password hashes, TOTP secrets), then forge a session for any
// account. The check runs on the symlink-resolved paths, so a link cannot be
// used to reach the config directory either.

func ValidateFileRoot(root, configPath string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("目录路径不能为空（填写服务端绝对路径，例如 /data/share）")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("目录必须是绝对路径，例如 /data/share")
	}
	clean := filepath.Clean(root)
	st, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("目录不可用：%v", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s 不是目录", clean)
	}
	if err := assertNotConfigDir(clean, configPath); err != nil {
		return "", err
	}
	if err := assertWithinFilesRoots(clean); err != nil {
		return "", err
	}
	f, err := os.Open(clean)
	if err != nil {
		return "", fmt.Errorf("目录无法读取：%v", err)
	}
	// Probe an actual directory read: permission bits alone do not prove the
	// gateway account can list it.
	if _, err := f.ReadDir(1); err != nil && err != io.EOF {
		f.Close()
		return "", fmt.Errorf("目录无法读取：%v", err)
	}
	f.Close()
	return clean, nil
}

// assertNotConfigDir rejects a files root that is, contains, or sits inside the
// gateway config directory (<configDir>/users/<user>.yaml → <configDir>).

func assertNotConfigDir(root, configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		return nil
	}
	configDir := filepath.Dir(filepath.Dir(configPath)) // <configDir>/users/
	if configDir == "" || configDir == "." {
		return nil
	}
	rootPath, cfgDir := resolveSymlinks(root), resolveSymlinks(configDir)
	if within(rootPath, cfgDir) || within(cfgDir, rootPath) {
		return fmt.Errorf("目录 %s 与网关配置目录重叠，禁止挂载：请指定要共享的具体子目录（如 /data/share），不要使用包含网关配置的上级目录", root)
	}
	return nil
}

// resolveSymlinks returns the canonical path, falling back to the input when it
// cannot be resolved (a missing path is reported by the caller's own checks).

func resolveSymlinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// within reports whether child is parent or lives under it.

func within(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// ServiceConfig represents a single backend service.
