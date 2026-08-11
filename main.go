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
  goprox start [options]        Start in background
  goprox stop [options]         Stop the running gateway
  goprox status [options]       Show gateway status
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

All config (state, pid, log, users/) lives in the config directory next to
the binary, so the whole directory is portable. Copy the binary to a writable
directory - do NOT use a symlink (symlinks are resolved to the real path).

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
	case "serve", "start":
		if cmd == "start" {
			daemonize(opts)
			return
		}
		runServer(opts)
	case "stop":
		runStop(opts)
	case "status":
		runStatus(opts)
	case "user":
		runUserAdd(opts, username)
	case "passwd":
		runUserPasswd(opts, username)
	case "del":
		runUserDel(opts, username)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
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

	// Persist server config
	config.PersistServerConfig(statePath, opts.host, opts.port, opts.trustedProxy)

	// Check if already running
	pidPath := config.PidPath(configDir)
	if pid, err := readPidFile(pidPath); err == nil && pid > 0 {
		if processRunning(pid) {
			log.Fatalf("goprox is already running (pid %d); stop it first: goprox stop", pid)
		}
	}

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
		ReadHeaderTimeout: 10 * time.Second, // slowloris protection
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout/WriteTimeout: they would kill long-lived WebSocket
		// connections to proxied services.
	}

	// Bind the listener before writing the pidfile so that a failed bind
	// (e.g. port already in use) aborts here instead of leaving a stale pidfile.
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", httpServer.Addr, err)
	}

	// Write PID file only after the listener is up (the `start` command waits
	// for this file to consider the daemon ready).
	writePidFile(pidPath, os.Getpid())
	defer os.Remove(pidPath)

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
		os.Remove(pidPath)
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
		log.Printf("trusted proxy: %s (X-Forwarded-For/Proto trusted only from this CIDR)", state.Server.TrustedProxy)
	} else {
		log.Printf("trusted proxy: none (X-Forwarded-* headers ignored)")
	}

	if err := httpServer.Serve(listener); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// ---- daemonize ----

func daemonize(opts options) {
	// Get the executable path
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable: %v", err)
	}

	// Build args for the child process (serve mode)
	childArgs := []string{exe, "serve"}
	if opts.configDir != config.DefaultConfigDir() {
		childArgs = append(childArgs, "--config-dir", opts.configDir)
	}
	if opts.host != config.DefaultHost {
		childArgs = append(childArgs, "--host", opts.host)
	}
	if opts.port != config.DefaultPort {
		childArgs = append(childArgs, "--port", strconv.Itoa(opts.port))
	}
	if opts.trustedProxy != "" {
		childArgs = append(childArgs, "--trusted-proxy", opts.trustedProxy)
	}

	// Open log file
	logPath := config.LogPath(opts.configDir)
	os.MkdirAll(filepath.Dir(logPath), 0700)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}

	pidPath := config.PidPath(opts.configDir)
	// Refuse to start while another instance is running.
	if pid, err := readPidFile(pidPath); err == nil && pid > 0 {
		if processRunning(pid) {
			log.Fatalf("goprox is already running (pid %d); stop it first: goprox stop", pid)
		}
	}

	// Start child process
	procAttr := &os.ProcAttr{
		Dir:   "/",
		Env:   os.Environ(),
		Files: []*os.File{nil, logFile, logFile},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	}

	process, err := os.StartProcess(exe, childArgs, procAttr)
	if err != nil {
		log.Fatalf("start process: %v", err)
	}
	logFile.Close()

	// Wait for the child to become ready (it writes its own pidfile once the
	// listener is up) or to exit with an error. The parent must NOT write the
	// pidfile: the child owns it, otherwise it sees itself as "already running".
	done := make(chan error, 1)
	go func() { _, werr := process.Wait(); done <- werr }()

	deadline := time.After(10 * time.Second)
	for {
		if pid, err := readPidFile(pidPath); err == nil && pid == process.Pid && processRunning(pid) {
			process.Release()
			displayHost := opts.host
			if displayHost == "0.0.0.0" || displayHost == "::" {
				displayHost = getLocalIP()
			}
			log.Printf("started (pid %d)", process.Pid)
			log.Printf("listening on http://%s:%d", displayHost, opts.port)
			log.Printf("log: %s", logPath)
			return
		}
		select {
		case werr := <-done:
			log.Printf("goprox failed to start: %v (see %s)", werr, logPath)
			os.Remove(pidPath)
			return
		case <-deadline:
			log.Printf("timed out waiting for goprox to start (see %s)", logPath)
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ---- stop ----

func runStop(opts options) {
	pidPath := config.PidPath(opts.configDir)
	pid, err := readPidFile(pidPath)
	if err != nil || pid <= 0 {
		log.Println("not running")
		return
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidPath)
		log.Println("not running")
		return
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		os.Remove(pidPath)
		log.Println("not running")
		return
	}

	// Wait for process to stop
	for i := 0; i < 50; i++ {
		if !processRunning(pid) {
			os.Remove(pidPath)
			log.Printf("stopped (pid %d)", pid)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill
	process.Signal(syscall.SIGKILL)
	os.Remove(pidPath)
	log.Printf("force stopped (pid %d)", pid)
}

// ---- status ----

func runStatus(opts options) {
	pidPath := config.PidPath(opts.configDir)
	pid, err := readPidFile(pidPath)

	if err != nil || pid <= 0 || !processRunning(pid) {
		fmt.Println("[goprox] not running")
	} else {
		fmt.Printf("[goprox] running (pid %d)\n", pid)
	}

	logPath := config.LogPath(opts.configDir)
	fmt.Printf("[goprox] log: %s\n", logPath)

	if pid > 0 && processRunning(pid) {
		state, err := config.LoadState(config.StatePath(opts.configDir))
		if err == nil {
			displayHost := state.Server.Host
			if displayHost == "0.0.0.0" || displayHost == "::" {
				displayHost = getLocalIP()
			}
			fmt.Printf("[goprox] listening on http://%s:%d\n", displayHost, state.Server.Port)
		}
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

func processRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func writePidFile(path string, pid int) error {
	os.MkdirAll(filepath.Dir(path), 0700)
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0600)
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

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}
