package main

// 配置预检子命令（check）。

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

func runConfigCheck(opts options) {
	configDir := opts.configDir
	if _, err := os.Stat(configDir); err != nil {
		log.Fatalf("config dir %s: %v", configDir, err)
	}
	statePath := config.StatePath(configDir)
	if _, err := os.Stat(statePath); err != nil {
		log.Fatalf("state.yaml not found in %s; run goprox serve once first", configDir)
	}
	state, err := config.LoadState(statePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	srv := server.New(state, configDir)
	if err := srv.ValidateVHosts(); err != nil {
		log.Fatalf("config check failed: %v", err)
	}

	fmt.Printf("[goprox] config: %s\n", configDir)
	fmt.Printf("[goprox] public_host: %q\n", state.Server.PublicHost)
	fmt.Printf("[goprox] public_scheme: %q\n", state.Server.PublicScheme)
	fmt.Printf("[goprox] cookie_domain: %q\n", state.Server.CookieDomain)
	if roots := config.FilesRootAllowlist(); len(roots) > 0 {
		fmt.Printf("[goprox] files_roots: %v\n", roots)
	}
	if state.Auth.CookieSuffix != "" {
		fmt.Printf("[goprox] cookie_suffix: %q (instance-isolated cookie names)\n", state.Auth.CookieSuffix)
	}
	if days := state.Server.LogRetention(); days == 0 {
		fmt.Println("[goprox] event log: memory only (server.log_retention_days = 0)")
	} else {
		fmt.Printf("[goprox] event log: %s (retention %d days)\n", filepath.Join(configDir, "logs"), days)
	}
	hosts := srv.HostEntries()
	fmt.Printf("[goprox] users: %d, services: %d, virtual hosts: %d\n", srv.UserCount(), srv.ServiceCount(), len(hosts))
	if len(hosts) == 0 {
		fmt.Println("[goprox] no virtual hosts configured")
	}
	for _, h := range hosts {
		fmt.Printf("  %s -> %s/%s\n", h.Host, h.Username, h.ServiceID)
	}
	fmt.Println("[goprox] config check OK")
}

// passwordReader is shared across readPassword calls: a fresh bufio.Reader per
// call would eagerly buffer all of stdin on the first read, starving the second
// (confirmation) prompt when input comes from a pipe.
