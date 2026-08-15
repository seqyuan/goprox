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

Options:
  -d, --config-dir <dir>  Config directory (default: <program dir>/config)
  --host <host>           Listen address (default: 0.0.0.0)
  --port <port>           Gateway listen port (default: 1908)
  --trusted-proxy <cidr>  Trusted reverse-proxy CIDR (e.g. 127.0.0.1/32);
                          enables X-Forwarded-For/Proto trust (default: none)
  -h, --help              Show this help

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

	// Parse for help flag
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printUsage()
			return
		}
	}

	// Determine subcommand
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	// user/passwd/del take a positional username.
	var username string
	switch cmd {
	case "user", "passwd", "del":
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
	configDir    string
	host         string
	port         int
	trustedProxy string
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
	config.PersistServerConfig(statePath, opts.host, opts.port, opts.trustedProxy)

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

	log.Printf("listening on http://%s:%d", state.Server.Host, state.Server.Port)
	log.Printf("config: %s", configDir)
	log.Printf("users: %s", config.UsersDir(configDir))
	log.Printf("%d user(s) loaded", srv.UserCount())
	if state.Server.TrustedProxy != "" {
		if config.IsTrustedProxyTooBroad(state.Server.TrustedProxy) {
			log.Printf("WARNING: trusted proxy %q covers the whole address space; any client can spoof X-Forwarded-* headers and defeat login rate limiting", state.Server.TrustedProxy)
		}
		log.Printf("trusted proxy: %s (X-Forwarded-For/Proto trusted only from this CIDR)", state.Server.TrustedProxy)
	} else {
		log.Printf("trusted proxy: none (X-Forwarded-* headers ignored)")
	}

	if err := httpServer.Serve(listener); err != http.ErrServerClosed {
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
