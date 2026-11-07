package main

// serve 子命令：启动网关、TLS、扫描循环与优雅退出。

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

func runServer(opts options) {
	configDir := opts.configDir

	// Ensure the config dir exists and is writable before doing anything else.
	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatalf("create config dir %s: %v", configDir, err)
	}
	if err := checkWritableDir(configDir); err != nil {
		log.Fatalf("config dir %s is not writable: %v\nhint: copy the goprox binary to a writable directory (do NOT use a symlink)", configDir, err)
	}
	// Create config/users up front. A fresh install has no user configs yet;
	// without this directory every registry scan fails (and logs) until the
	// first `goprox user` command runs.
	if err := os.MkdirAll(config.UsersDir(configDir), 0700); err != nil {
		log.Fatalf("create users dir %s: %v", config.UsersDir(configDir), err)
	}

	statePath := config.StatePath(configDir)

	state, err := config.LoadState(statePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	// Apply CLI overrides. Host/port are persisted in state.yaml, so only an
	// explicitly-passed flag may override them; parser defaults must not.
	applyListenOverrides(state, opts)
	if opts.trustedProxy != "" {
		state.Server.TrustedProxy = opts.trustedProxy
	}
	if !config.IsValidTrustedProxy(state.Server.TrustedProxy) {
		log.Fatalf("invalid --trusted-proxy %q (must be an IP or CIDR)", state.Server.TrustedProxy)
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
			log.Fatalf("generate self-signed cert: %v", err)
		}
		state.Server.TLSCert = mustAbsPath(cert)
		state.Server.TLSKey = mustAbsPath(key)
	}
	if opts.publicHost != "" {
		v, err := config.NormalizePublicHost(opts.publicHost)
		if err != nil {
			log.Fatalf("invalid --public-host: %v", err)
		}
		state.Server.PublicHost = v
	}
	if opts.publicScheme != "" {
		v, err := config.NormalizePublicScheme(opts.publicScheme)
		if err != nil {
			log.Fatalf("invalid --public-scheme: %v", err)
		}
		state.Server.PublicScheme = v
	}
	if opts.cookieDomain != "" {
		v, err := config.NormalizeCookieDomain(opts.cookieDomain)
		if err != nil {
			log.Fatalf("invalid --cookie-domain: %v", err)
		}
		state.Server.CookieDomain = v
	}
	tlsEnabled := state.Server.TLSCert != "" && state.Server.TLSKey != ""
	if tlsEnabled {
		if _, err := os.Stat(state.Server.TLSCert); err != nil {
			log.Fatalf("tls cert %s: %v", state.Server.TLSCert, err)
		}
		if _, err := os.Stat(state.Server.TLSKey); err != nil {
			log.Fatalf("tls key %s: %v", state.Server.TLSKey, err)
		}
	}

	srv := server.New(state, configDir)
	if err := srv.ValidateVHosts(); err != nil {
		log.Fatalf("invalid virtual-host config: %v", err)
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

	// Bind the listener before writing the pidfile so that a failed bind
	// (e.g. port already in use) aborts here instead of leaving a stale pidfile.
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", httpServer.Addr, err)
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

	// Start config scanner
	stopScan := make(chan struct{})
	go srv.ScanLoop(10*time.Second, stopScan)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		close(stopScan)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown: %v; forcing close", err)
			httpServer.Close()
		}
	}()

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	log.Printf("listening on %s://%s:%d", scheme, state.Server.Host, state.Server.Port)
	log.Printf("config: %s", configDir)
	log.Printf("users: %s", config.UsersDir(configDir))
	log.Printf("%d user(s) loaded", srv.UserCount())
	if tlsEnabled {
		log.Printf("tls: %s (cert), %s (key)", state.Server.TLSCert, state.Server.TLSKey)
	}
	if state.Server.TrustedProxy != "" {
		if config.IsTrustedProxyTooBroad(state.Server.TrustedProxy) {
			log.Printf("WARNING: trusted proxy %q covers the whole address space; any client can spoof X-Forwarded-* headers and defeat login rate limiting", state.Server.TrustedProxy)
		}
		log.Printf("trusted proxy: %s (X-Forwarded-For/Proto trusted only from this CIDR)", state.Server.TrustedProxy)
	} else {
		log.Printf("trusted proxy: none (X-Forwarded-* headers ignored)")
	}

	if state.SSO.UserHeader != "" {
		mode := "unsigned (backend must be network-isolated)"
		if state.SSO.HMACSecret != "" {
			mode = "HMAC-signed"
		}
		log.Printf("sso: %s = <username> (%s)", state.SSO.UserHeader, mode)
	}

	if tlsEnabled {
		if err := httpServer.ServeTLS(listener, state.Server.TLSCert, state.Server.TLSKey); err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	} else if err := httpServer.Serve(listener); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// ---- helpers ----

// mustAbsPath resolves a persisted file path (TLS cert/key) to an absolute one,
// so a later restart from a different working directory still finds it.
