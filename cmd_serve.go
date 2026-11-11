package main

// serve 子命令：启动网关、TLS、扫描循环与优雅退出。

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

// gateway is a fully prepared, already-listening server that has not started
// serving yet. Splitting "prepare" from "serve" keeps the startup path testable
// (config load, CLI overrides, TLS, vhost validation, bind, persistence) instead
// of hiding it behind a blocking function that exits on error.
type gateway struct {
	configDir string
	statePath string
	state     *config.StateConfig
	srv       *server.Server
	http      *http.Server
	listener  net.Listener
	tls       bool
}

func runServer(opts options) {
	g, err := startGateway(opts)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := g.run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// startGateway performs every startup step up to and including the bind. It
// returns an error (never exits) so tests can assert the same behavior.
func startGateway(opts options) (*gateway, error) {
	configDir := opts.configDir

	// Ensure the config dir exists and is writable before doing anything else.
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir %s: %w", configDir, err)
	}
	if err := checkWritableDir(configDir); err != nil {
		return nil, fmt.Errorf("config dir %s is not writable: %v\nhint: copy the goprox binary to a writable directory (do NOT use a symlink)", configDir, err)
	}
	// Create config/users up front. A fresh install has no user configs yet;
	// without this directory every registry scan fails (and logs) until the
	// first `goprox user` command runs.
	if err := os.MkdirAll(config.UsersDir(configDir), 0700); err != nil {
		return nil, fmt.Errorf("create users dir %s: %w", config.UsersDir(configDir), err)
	}

	statePath := config.StatePath(configDir)

	state, err := config.LoadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	// Apply CLI overrides. Host/port are persisted in state.yaml, so only an
	// explicitly-passed flag may override them; parser defaults must not.
	applyListenOverrides(state, opts)
	if opts.trustedProxy != "" {
		state.Server.TrustedProxy = opts.trustedProxy
	}
	if !config.IsValidTrustedProxy(state.Server.TrustedProxy) {
		return nil, fmt.Errorf("invalid --trusted-proxy %q (must be an IP or CIDR)", state.Server.TrustedProxy)
	}
	if opts.title != "" {
		state.Server.Title = opts.title
	}
	if opts.tlsCert != "" || opts.tlsKey != "" {
		state.Server.TLSCert = mustAbsPath(opts.tlsCert)
		state.Server.TLSKey = mustAbsPath(opts.tlsKey)
	}
	if opts.tlsSelfSigned {
		cert, key, err := ensureSelfSignedCert(filepath.Join(configDir, "tls"))
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		state.Server.TLSCert = mustAbsPath(cert)
		state.Server.TLSKey = mustAbsPath(key)
	}
	if opts.publicHost != "" {
		v, err := config.NormalizePublicHost(opts.publicHost)
		if err != nil {
			return nil, fmt.Errorf("invalid --public-host: %w", err)
		}
		state.Server.PublicHost = v
	}
	if opts.publicScheme != "" {
		v, err := config.NormalizePublicScheme(opts.publicScheme)
		if err != nil {
			return nil, fmt.Errorf("invalid --public-scheme: %w", err)
		}
		state.Server.PublicScheme = v
	}
	if opts.cookieDomain != "" {
		v, err := config.NormalizeCookieDomain(opts.cookieDomain)
		if err != nil {
			return nil, fmt.Errorf("invalid --cookie-domain: %w", err)
		}
		state.Server.CookieDomain = v
	}
	tlsEnabled := state.Server.TLSCert != "" && state.Server.TLSKey != ""
	if tlsEnabled {
		if _, err := os.Stat(state.Server.TLSCert); err != nil {
			return nil, fmt.Errorf("tls cert %s: %w", state.Server.TLSCert, err)
		}
		if _, err := os.Stat(state.Server.TLSKey); err != nil {
			return nil, fmt.Errorf("tls key %s: %w", state.Server.TLSKey, err)
		}
	}

	srv := server.New(state, configDir)
	if err := srv.ValidateVHosts(); err != nil {
		return nil, fmt.Errorf("invalid virtual-host config: %w", err)
	}

	httpServer := &http.Server{
		Addr:              net.JoinHostPort(state.Server.Host, strconv.Itoa(state.Server.Port)),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, // slow header (slowloris) protection
		ReadTimeout:       60 * time.Second, // cap form posts; proxied bodies are extended to an idle timeout per read (see forwardToBackend)
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: it would cut off long-lived streaming responses
		// (SSE, log tails) from proxied services. WebSocket upgrades are safe
		// from both timeouts because http.Server clears the connection
		// deadlines when the handler hijacks the connection for the upgrade.
	}

	// A gateway bound to all interfaces without TLS is the "just works on the
	// LAN" default; on anything reachable from a public network it exposes
	// sessions and backends in plaintext. Say so once, loudly, at startup.
	if warn := listenExposureWarning(state.Server.Host, tlsEnabled, state.Server.TrustedProxy); warn != "" {
		log.Printf("WARNING: %s", warn)
	}

	// Bind before persisting: a failed bind (port already in use) must abort
	// here instead of overwriting state.yaml with a port we never bound.
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", httpServer.Addr, err)
	}

	// Persist server config only after the listener is up. Persisting before
	// the already-running check / bind would let a failed start overwrite
	// state.yaml with a port we never bound, corrupting the running gateway's
	// recorded port for `status` and future default starts.
	if err := config.PersistServerConfig(statePath, state.Server.Host, state.Server.Port,
		opts.trustedProxy, opts.title,
		state.Server.TLSCert, state.Server.TLSKey,
		state.Server.PublicHost, state.Server.PublicScheme, state.Server.CookieDomain); err != nil {
		log.Printf("[goprox] WARNING: failed to persist server config to %s: %v", statePath, err)
	}

	return &gateway{
		configDir: configDir,
		statePath: statePath,
		state:     state,
		srv:       srv,
		http:      httpServer,
		listener:  listener,
		tls:       tlsEnabled,
	}, nil
}

// run serves until a termination signal, then shuts down gracefully.
func (g *gateway) run() error {
	g.logStartup()

	stopScan := make(chan struct{})
	go g.srv.ScanLoop(10*time.Second, stopScan)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		close(stopScan)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := g.http.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown: %v; forcing close", err)
			g.http.Close()
		}
	}()

	if err := g.serve(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// serve blocks in the HTTP server (plain HTTP or TLS).
func (g *gateway) serve() error {
	if g.tls {
		return g.http.ServeTLS(g.listener, g.state.Server.TLSCert, g.state.Server.TLSKey)
	}
	return g.http.Serve(g.listener)
}

func (g *gateway) logStartup() {
	scheme := "http"
	if g.tls {
		scheme = "https"
	}
	log.Printf("listening on %s://%s:%d", scheme, g.state.Server.Host, g.state.Server.Port)
	log.Printf("config: %s", g.configDir)
	log.Printf("users: %s", config.UsersDir(g.configDir))
	log.Printf("%d user(s) loaded", g.srv.UserCount())
	if g.tls {
		log.Printf("tls: %s (cert), %s (key)", g.state.Server.TLSCert, g.state.Server.TLSKey)
	}
	if g.state.Server.TrustedProxy != "" {
		if config.IsTrustedProxyTooBroad(g.state.Server.TrustedProxy) {
			log.Printf("WARNING: trusted proxy %q covers the whole address space; any client can spoof X-Forwarded-* headers and defeat login rate limiting", g.state.Server.TrustedProxy)
		}
		log.Printf("trusted proxy: %s (X-Forwarded-For/Proto trusted only from this CIDR)", g.state.Server.TrustedProxy)
	} else {
		log.Printf("trusted proxy: none (X-Forwarded-* headers ignored)")
	}

	// With a parent cookie domain every session cookie is Domain-scoped, so only
	// hosts inside it can hold a login. A browser on an IP address or another
	// zone would otherwise appear to log in and immediately bounce back.
	if g.state.Server.CookieDomain != "" {
		who := g.state.Server.CookieDomain
		if g.state.Server.PublicHost != "" {
			who += "（主入口：" + g.state.Server.PublicHost + "）"
		}
		log.Printf("WARNING: session cookie domain is %s: only hostnames inside that domain can stay logged in; IP-address and other-host access is refused at login", who)
	}

	// kind:"files" cards are served from the local filesystem by the gateway
	// account, so without an allowlist a logged-in user can browse anything that
	// account can read — including other users' home directories.
	if n := g.srv.FilesServiceCount(); n > 0 && len(config.FilesRootAllowlist()) == 0 {
		log.Printf("WARNING: %d file-browsing card(s) and no server.files_roots allowlist: any logged-in user can mount any directory this account can read; set server.files_roots for a shared gateway", n)
	}

	if g.state.SSO.UserHeader != "" {
		mode := "unsigned (backend must be network-isolated)"
		if g.state.SSO.HMACSecret != "" {
			mode = "HMAC-signed"
		}
		log.Printf("sso: %s = <username> (%s)", g.state.SSO.UserHeader, mode)
	}
}

// ---- helpers ----

// listenExposureWarning returns a startup warning for the common insecure
// exposure (all interfaces, plain HTTP, no trusted proxy in front), or "" when
// the configuration is already safe.
func listenExposureWarning(host string, tlsEnabled bool, trustedProxy string) string {
	bare := strings.Trim(host, "[]")
	ip := net.ParseIP(bare)
	allInterfaces := host == "" || bare == "" || (ip != nil && ip.IsUnspecified())
	if !allInterfaces || tlsEnabled || trustedProxy != "" {
		return ""
	}
	return "listening on all interfaces over plain HTTP: anyone who can reach this port can read " +
		"sessions and proxied traffic. For anything beyond a trusted LAN, terminate TLS in front " +
		"(docs/reverse-proxy-tls.md) and set --trusted-proxy, or use --tls-selfsigned"
}

// mustAbsPath resolves a persisted file path (TLS cert/key) to an absolute one,
// so a later restart from a different working directory still finds it.
func mustAbsPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// checkWritableDir verifies the gateway can create files in dir (a copy of the
// binary in a read-only location would break every config write).
func checkWritableDir(dir string) error {
	probe := filepath.Join(dir, ".goprox-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	f.Close()
	os.Remove(probe)
	return nil
}
