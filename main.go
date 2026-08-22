package main

import (
	"bufio"
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

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

// version is injected at build time so it matches the git tag, e.g.:
//
//	go build -ldflags "-X main.version=$(git describe --tags --abbrev=0)"
//
// Local builds (go run / go install without ldflags) report "dev".
var version = "dev"

const usage = `Usage:
  goprox serve [options]        Start the gateway server (foreground)
  goprox user <name>            Create a user account (prompts for password)
  goprox passwd <name>          Reset a user's password
  goprox del <name>             Delete a user account
  goprox 2fa-reset <name>       Disable a user's two-factor authentication
  goprox sso [options]          Show or configure lightweight SSO (identity
                                header forwarded to backends; see below)

Options:
  -d, --config-dir <dir>  Config directory (default: <program dir>/config)
  --host <host>           Listen address (default: 0.0.0.0)
  --port <port>           Gateway listen port (default: 1908)
  --trusted-proxy <cidr>  Trusted reverse-proxy CIDR (e.g. 127.0.0.1/32);
                          enables X-Forwarded-For/Proto trust (default: none)
  --tls-cert <file>       TLS certificate (PEM); with --tls-key serves HTTPS
  --tls-key <file>        TLS private key (PEM)
  --tls-selfsigned        Generate a self-signed cert into the config dir and
                          serve HTTPS (covers localhost + LAN IPs; browsers
                          show a one-time warning you must accept)
  --title <text>          Site title shown in the top-left corner of the
                          dashboard and login page (default: GoProx)
  -V, --version           Show version
  -h, --help              Show this help

SSO options (with goprox sso):
  --user-header <name>    Request header carrying the logged-in username on
                          every proxied request (e.g. X-Authenticated-User);
                          backends that opt in trust it as the user identity
  --hmac-secret <key>     Optional shared secret: additionally signs the
                          header (HMAC-SHA256, base64url) so backends can
                          verify the identity without network isolation alone
  --off                   Disable SSO (clears user_header and hmac_secret)

With no options, goprox sso prints the current configuration.
The backend must be reachable only through the gateway (loopback/firewall),
otherwise anyone who can reach it directly can forge the identity header.

HTTPS turns the whole site into a secure context, which unlocks every
secure-context Web API (crypto.randomUUID, crypto.subtle, navigator.storage,
clipboard, ...) for proxied apps over plain LAN HTTP. TLS settings persist in
state.yaml; to disable, delete the tls_cert/tls_key lines and restart.

Run in the foreground (Ctrl+C to stop). For a persistent session, run it in
tmux/screen or with nohup:
    nohup ./goprox serve --port 1908 > goprox.log 2>&1 &

All config (state, users/) lives in the config directory next to the binary,
so the whole directory is portable. Copy the binary to a writable directory -
do NOT use a symlink (symlinks are resolved to the real path).

Manage services via the web dashboard at http://host:port/
`

func printUsage() {
	fmt.Printf("GoProx %s - Multi-service authenticated reverse proxy hub\n\n%s", version, usage)
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[goprox] ")

	args := os.Args[1:]

	// Parse for help / version flags
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printUsage()
			return
		}
		if a == "-V" || a == "--version" {
			fmt.Printf("GoProx %s\n", version)
			return
		}
	}

	// Determine subcommand
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	// user/passwd/del/2fa-reset take a positional username.
	var username string
	switch cmd {
	case "user", "passwd", "del", "2fa-reset":
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "error: %s requires a username\n", cmd)
			printUsage()
			os.Exit(1)
		}
		username = args[0]
		args = args[1:]
		if !config.IsValidUsername(username) {
			fmt.Fprintf(os.Stderr, "error: invalid username %q\n", username)
			os.Exit(1)
		}
	}

	// sso has its own option set, so it is handled before the shared parse.
	if cmd == "sso" {
		runSSO(parseSSOArgs(args))
		return
	}

	// Parse options
	opts, err := parseOptions(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		printUsage()
		os.Exit(1)
	}

	switch cmd {
	case "serve":
		runServer(opts)
	case "user":
		runUserAdd(opts, username)
	case "passwd":
		runUserPasswd(opts, username)
	case "del":
		runUserDel(opts, username)
	case "2fa-reset":
		runTOTPReset(opts, username)
	default:
		if cmd == "start" || cmd == "stop" || cmd == "status" {
			fmt.Fprintf(os.Stderr, "error: goprox %s 已移除；goprox 现为前台运行（goprox serve），停止用 Ctrl+C，后台可用 tmux/nohup\n", cmd)
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		}
		printUsage()
		os.Exit(1)
	}
}

type options struct {
	configDir     string
	host          string
	port          int
	trustedProxy  string
	title         string
	tlsCert       string
	tlsKey        string
	tlsSelfSigned bool
}

func parseOptions(args []string) (options, error) {
	opts := options{
		configDir: config.DefaultConfigDir(),
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		// next returns the following argument as the option value.
		next := func() (string, bool) {
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch a {
		case "-d", "--config-dir":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.configDir = v
		case "--host":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.host = v
		case "--port":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return opts, fmt.Errorf("invalid port %q (must be 1-65535)", v)
			}
			opts.port = p
		case "--trusted-proxy":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.trustedProxy = v
		case "--tls-cert":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.tlsCert = v
		case "--tls-key":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.tlsKey = v
		case "--tls-selfsigned":
			opts.tlsSelfSigned = true
		case "--title":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.title = v
		default:
			return opts, fmt.Errorf("unknown option: %s", a)
		}
	}

	if opts.host == "" {
		opts.host = config.DefaultHost
	}
	if opts.port == 0 {
		opts.port = config.DefaultPort
	}

	if opts.tlsCert != "" || opts.tlsKey != "" {
		if opts.tlsCert == "" || opts.tlsKey == "" {
			return opts, fmt.Errorf("tls requires both --tls-cert and --tls-key")
		}
	}

	return opts, nil
}

// ---- user management (admin CLI) ----

func runUserAdd(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err == nil {
		log.Fatalf("user %s already exists (%s)", username, configPath)
	}

	if err := config.EnsureUserConfig(configPath); err != nil {
		log.Fatalf("create config: %v", err)
	}

	password, err := promptNewPassword()
	if err != nil {
		// Clean up the empty config on failure.
		os.Remove(configPath)
		log.Fatalf("%v", err)
	}
	if err := config.UpdatePasswordHash(configPath, auth.HashPassword(password)); err != nil {
		log.Fatalf("update password: %v", err)
	}
	fmt.Printf("[goprox] user %s created (%s)\n", username, configPath)
}

func runUserPasswd(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}

	password, err := promptNewPassword()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := config.UpdatePasswordHash(configPath, auth.HashPassword(password)); err != nil {
		log.Fatalf("update password: %v", err)
	}
	fmt.Printf("[goprox] password updated for %s\n", username)
}

func runUserDel(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}
	if err := os.Remove(configPath); err != nil {
		log.Fatalf("remove config: %v", err)
	}
	fmt.Printf("[goprox] user %s deleted\n", username)
}

func runTOTPReset(opts options, username string) {
	configPath := config.UserConfigPath(opts.configDir, username)
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("user %s does not exist (%s)", username, configPath)
	}
	if err := config.UpdateTOTPSecret(configPath, ""); err != nil {
		log.Fatalf("reset 2FA: %v", err)
	}
	fmt.Printf("[goprox] 2FA disabled for %s\n", username)
}

// ---- lightweight SSO (admin CLI) ----

// ssoArgs holds the parsed `goprox sso` options.
type ssoArgs struct {
	configDir  string
	userHeader string
	hmacSecret string
	haveHeader bool
	haveHMAC   bool
	off        bool
}

// parseSSOArgs parses `goprox sso` options (its own set, distinct from the
// serve options).
func parseSSOArgs(args []string) ssoArgs {
	sa := ssoArgs{configDir: config.DefaultConfigDir()}
	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch args[i] {
		case "-d", "--config-dir":
			v, ok := next()
			if !ok {
				log.Fatalf("option %s requires a value", args[i])
			}
			sa.configDir = v
		case "--user-header":
			v, ok := next()
			if !ok {
				log.Fatalf("option --user-header requires a value")
			}
			sa.userHeader, sa.haveHeader = v, true
		case "--hmac-secret":
			v, ok := next()
			if !ok {
				log.Fatalf("option --hmac-secret requires a value")
			}
			sa.hmacSecret, sa.haveHMAC = v, true
		case "--off":
			sa.off = true
		default:
			log.Fatalf("unknown sso option: %s", args[i])
		}
	}
	return sa
}

// runSSO shows or updates the lightweight SSO configuration in state.yaml.
func runSSO(sa ssoArgs) {
	statePath := config.StatePath(sa.configDir)
	state, err := config.LoadState(statePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	if sa.off {
		if err := config.PersistSSOConfig(statePath, "", ""); err != nil {
			log.Fatalf("update state: %v", err)
		}
		fmt.Println("[goprox] sso disabled")
		fmt.Println("[goprox] restart the gateway for changes to take effect")
		return
	}

	if !sa.haveHeader {
		// No changes requested: show the current configuration.
		if state.SSO.UserHeader == "" {
			fmt.Println("[goprox] sso: disabled")
			return
		}
		mode := "unsigned (backend must be network-isolated)"
		if state.SSO.HMACSecret != "" {
			mode = "HMAC-signed"
		}
		fmt.Printf("[goprox] sso: user_header=%s hmac_secret=%s (%s)\n",
			state.SSO.UserHeader, maskSecret(state.SSO.HMACSecret), mode)
		return
	}

	if sa.userHeader == "" {
		log.Fatalf("--user-header requires a non-empty header name (use --off to disable)")
	}
	if !config.IsValidHeaderName(sa.userHeader) {
		log.Fatalf("invalid header name %q (must be a valid HTTP header name)", sa.userHeader)
	}
	if sa.haveHMAC && sa.hmacSecret == "" {
		log.Fatalf("--hmac-secret requires a non-empty key (omit it to keep the current one)")
	}

	hmacSecret := state.SSO.HMACSecret // keep the current secret unless replaced
	if sa.haveHMAC {
		hmacSecret = sa.hmacSecret
	}
	if err := config.PersistSSOConfig(statePath, sa.userHeader, hmacSecret); err != nil {
		log.Fatalf("update state: %v", err)
	}

	mode := "unsigned (backend must be network-isolated)"
	if hmacSecret != "" {
		mode = "HMAC-signed"
	}
	fmt.Printf("[goprox] sso: user_header=%s (%s)\n", sa.userHeader, mode)
	fmt.Println("[goprox] restart the gateway for changes to take effect")
}

// maskSecret hides a configured secret in status output.
func maskSecret(s string) string {
	if s == "" {
		return "<unset>"
	}
	return "<set>"
}

// ---- server ----

func runServer(opts options) {
	configDir := opts.configDir

	// Ensure the config dir exists and is writable before doing anything else.
	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatalf("create config dir %s: %v", configDir, err)
	}
	if err := checkWritableDir(configDir); err != nil {
		log.Fatalf("config dir %s is not writable: %v\nhint: copy the goprox binary to a writable directory (do NOT use a symlink)", configDir, err)
	}

	statePath := config.StatePath(configDir)

	state, err := config.LoadState(statePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	// Apply CLI overrides
	if opts.host != "" {
		state.Server.Host = opts.host
	}
	if opts.port > 0 {
		state.Server.Port = opts.port
	}
	if opts.trustedProxy != "" {
		state.Server.TrustedProxy = opts.trustedProxy
	}
	if opts.title != "" {
		state.Server.Title = opts.title
	}
	if opts.tlsCert != "" || opts.tlsKey != "" {
		state.Server.TLSCert = opts.tlsCert
		state.Server.TLSKey = opts.tlsKey
	}
	if opts.tlsSelfSigned {
		cert, key, err := generateSelfSignedCert(filepath.Join(configDir, "tls"))
		if err != nil {
			log.Fatalf("generate self-signed cert: %v", err)
		}
		state.Server.TLSCert = cert
		state.Server.TLSKey = key
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

	httpServer := &http.Server{
		Addr:              net.JoinHostPort(state.Server.Host, strconv.Itoa(state.Server.Port)),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, // slow header (slowloris) protection
		ReadTimeout:       60 * time.Second, // bound slow request bodies (slowloris variant)
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
	config.PersistServerConfig(statePath, opts.host, opts.port, opts.trustedProxy, opts.title,
		state.Server.TLSCert, state.Server.TLSKey)

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

// passwordReader is shared across readPassword calls: a fresh bufio.Reader per
// call would eagerly buffer all of stdin on the first read, starving the second
// (confirmation) prompt when input comes from a pipe.
var passwordReader = bufio.NewReader(os.Stdin)

func promptNewPassword() (string, error) {
	fmt.Print("Enter password: ")
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Print("Confirm password: ")
	confirm, err := readPassword()
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}

func readPassword() (string, error) {
	// Disable echo
	termios, err := makeRaw(0)
	if err == nil {
		defer restore(0, termios)
	}

	password, err := passwordReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after password input
	// Strip the line ending only, preserving any intentional whitespace.
	return strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r"), nil
}

func checkWritableDir(dir string) error {
	f, err := os.CreateTemp(dir, ".goprox-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
