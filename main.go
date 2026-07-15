package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/server"
)

const usage = `GoProx - Multi-service authenticated reverse proxy hub

Usage:
  goprox [options]              Start the gateway server
  goprox stop [options]         Stop the running gateway
  goprox status [options]       Show gateway status
  goprox passwd [options]       Set login password
  goprox add [options]          Add a backend service (interactive)
  goprox list [options]         List configured services
  goprox remove <name> [options] Remove a backend service
  
Options:
  -s, --state <path>     State file path (default: ~/.local/state/goprox/state.yaml)
  -c, --config <path>    User config path (default: ~/.config/goprox/config.yaml)
  --host <host>          Listen address (default: 0.0.0.0)
  --port <port>          Gateway listen port (default: 1907)
  -h, --help             Show this help
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("[goprox] ")

	args := os.Args[1:]

	// Parse for help flag
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Print(usage)
			return
		}
	}

	// Determine subcommand
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	// Parse options
	opts := parseOptions(args)

	switch cmd {
	case "serve", "start":
		if cmd == "start" {
			// Daemonize by forking
			daemonize(opts)
			return
		}
		runServer(opts)
	case "stop":
		runStop(opts)
	case "status":
		runStatus(opts)
	case "passwd":
		runPasswd(opts)
	case "add":
		runAdd(opts)
	case "list":
		runList(opts)
	case "remove":
		runRemove(args, opts)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		fmt.Print(usage)
		os.Exit(1)
	}
}

type options struct {
	statePath  string
	configPath string
	host       string
	port       int
}

func parseOptions(args []string) options {
	opts := options{
		statePath: config.DefaultStatePath(),
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-s", "--state":
			if i+1 < len(args) {
				opts.statePath = args[i+1]
				i++
			}
		case "-c", "--config":
			if i+1 < len(args) {
				opts.configPath = args[i+1]
				i++
			}
		case "--host":
			if i+1 < len(args) {
				opts.host = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				opts.port, _ = strconv.Atoi(args[i+1])
				i++
			}
		}
	}

	if opts.configPath == "" {
		opts.configPath = config.DefaultUserConfigPath()
	}
	if opts.host == "" {
		opts.host = config.DefaultHost
	}
	if opts.port == 0 {
		opts.port = config.DefaultPort
	}

	return opts
}

// ---- server ----

func runServer(opts options) {
	statePath := opts.statePath

	// Persist server config
	config.PersistServerConfig(statePath, opts.host, opts.port)

	// Check if already running
	if pid, err := readPidFile(config.GetPidPath(statePath)); err == nil && pid > 0 {
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

	srv := server.New(state)

	httpServer := &http.Server{
		Addr:    net.JoinHostPort(state.Server.Host, strconv.Itoa(state.Server.Port)),
		Handler: srv.Handler(),
	}

	// Write PID file
	pidPath := config.GetPidPath(statePath)
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
		httpServer.Close()
	}()

	log.Printf("listening on http://%s:%d", state.Server.Host, state.Server.Port)
	log.Printf("state: %s", statePath)
	log.Printf("scanning %s/*/.config/goprox/config.yaml", state.Users.HomePrefix)
	log.Printf("%d user(s) loaded", srv.UserCount())

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// ---- daemonize ----

func daemonize(opts options) {
	// Fork and run in background
	// Get the executable path
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable: %v", err)
	}

	// Build args for the child process (serve mode)
	childArgs := []string{exe, "serve"}
	if opts.statePath != config.DefaultStatePath() {
		childArgs = append(childArgs, "-s", opts.statePath)
	}
	if opts.host != config.DefaultHost {
		childArgs = append(childArgs, "--host", opts.host)
	}
	if opts.port != config.DefaultPort {
		childArgs = append(childArgs, "--port", strconv.Itoa(opts.port))
	}

	// Open log file
	logPath := config.GetLogPath(opts.statePath)
	os.MkdirAll(filepath.Dir(logPath), 0755)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
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

	// Write PID file
	pidPath := config.GetPidPath(opts.statePath)
	writePidFile(pidPath, process.Pid)

	displayHost := opts.host
	if displayHost == "0.0.0.0" || displayHost == "::" {
		displayHost = getLocalIP()
	}
	log.Printf("started (pid %d)", process.Pid)
	log.Printf("listening on http://%s:%d", displayHost, opts.port)
	log.Printf("log: %s", logPath)

	process.Release()
}

// ---- stop ----

func runStop(opts options) {
	pidPath := config.GetPidPath(opts.statePath)
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
	pidPath := config.GetPidPath(opts.statePath)
	pid, err := readPidFile(pidPath)

	if err != nil || pid <= 0 || !processRunning(pid) {
		fmt.Println("[goprox] not running")
	} else {
		fmt.Printf("[goprox] running (pid %d)\n", pid)
	}

	logPath := config.GetLogPath(opts.statePath)
	fmt.Printf("[goprox] log: %s\n", logPath)

	if pid > 0 && processRunning(pid) {
		state, err := config.LoadState(opts.statePath)
		if err == nil {
			displayHost := state.Server.Host
			if displayHost == "0.0.0.0" || displayHost == "::" {
				displayHost = getLocalIP()
			}
			fmt.Printf("[goprox] listening on http://%s:%d\n", displayHost, state.Server.Port)
		}
	}
}

// ---- passwd ----

func runPasswd(opts options) {
	configPath := opts.configPath

	if err := config.EnsureUserConfig(configPath); err != nil {
		log.Fatalf("create config: %v", err)
	}

	fmt.Print("Enter password: ")
	password, err := readPassword()
	if err != nil {
		log.Fatalf("read password: %v", err)
	}

	hash := auth.HashPassword(password)
	if err := config.UpdatePasswordHash(configPath, hash); err != nil {
		log.Fatalf("update password: %v", err)
	}

	// Check if running under shared gateway and fix permissions
	fixSharedPermissions(configPath)

	fmt.Printf("[goprox] password updated in %s\n", configPath)
}

// ---- add ----

func runAdd(opts options) {
	configPath := opts.configPath
	if err := config.EnsureUserConfig(configPath); err != nil {
		log.Fatalf("ensure config: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)

	name := prompt(reader, "服务名称", "")
	description := prompt(reader, "说明 (可选)", "")
	host := prompt(reader, "后端地址", "127.0.0.1")
	portStr := prompt(reader, "端口", "")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		log.Fatal("无效端口")
	}

	wsInput := prompt(reader, "WebSocket 代理 (y/n)", "y")
	websocket := strings.ToLower(wsInput) == "y" || wsInput == ""

	category := prompt(reader, "分类 (可选)", "")

	svc := config.ServiceConfig{
		ID:          config.SlugifyName(name),
		Name:        name,
		Description: description,
		Host:        host,
		Port:        port,
		Path:        config.ServicePathFromName(name),
		WebSocket:   websocket,
		Category:    category,
	}

	if err := config.AddService(configPath, svc); err != nil {
		log.Fatalf("add service: %v", err)
	}

	fmt.Printf("[goprox] added service: %s -> %s:%d%s\n", svc.Name, svc.Host, svc.Port, svc.Path)
}

// ---- list ----

func runList(opts options) {
	configPath := opts.configPath

	cfg, err := config.LoadUserConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if len(cfg.Services) == 0 {
		fmt.Println("(no services configured)")
		return
	}

	for _, s := range cfg.Services {
		wsTag := ""
		if s.WebSocket {
			wsTag = " [ws]"
		}
		fmt.Printf("  %-15s %s:%d%s%s\n", s.Name, s.Host, s.Port, s.Path, wsTag)
	}
}

// ---- remove ----

func runRemove(args []string, opts options) {
	configPath := opts.configPath

	if len(args) == 0 {
		log.Fatal("usage: goprox remove <name>")
	}

	name := args[0]
	if err := config.RemoveService(configPath, name); err != nil {
		log.Fatalf("remove service: %v", err)
	}

	fmt.Printf("[goprox] removed service: %s\n", name)
}

// ---- helpers ----

func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" && defaultVal != "" {
		return defaultVal
	}
	return input
}

func readPassword() (string, error) {
	// Disable echo
	termios, err := makeRaw(0)
	if err == nil {
		defer restore(0, termios)
	}

	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after password input
	return strings.TrimSpace(password), nil
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
	os.MkdirAll(filepath.Dir(path), 0755)
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644)
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

func fixSharedPermissions(configPath string) {
	statePath := config.DefaultStatePath()
	pidPath := config.GetPidPath(statePath)

	currentUser, err := user.Current()
	if err != nil || currentUser == nil {
		return
	}

	// Check if running under shared gateway (daemon operator != current user)
	isShared := false

	// Method 1: check running daemon process owner
	pid, _ := readPidFile(pidPath)
	if pid > 0 && processRunning(pid) {
		procOwner := getProcessOwner(pid)
		if procOwner != "" && procOwner != currentUser.Username {
			isShared = true
		}
	}

	// Method 2: check state file owner (daemon not running)
	if !isShared {
		if info, err := os.Stat(statePath); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				stateOwner := fmt.Sprintf("%d", stat.Uid)
				if stateOwner != currentUser.Uid {
					isShared = true
				}
			}
		}
	}

	if !isShared {
		fmt.Println("[goprox] gateway operator is current user; home/config permissions unchanged")
		return
	}

	// Resolve real paths (防符号链接绕过)
	configReal, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		// Config file might not exist yet; use resolved path
		configReal = configPath
		if p, err := filepath.Abs(configPath); err == nil {
			configReal = p
		}
	}

	homeReal, err := filepath.EvalSymlinks(currentUser.HomeDir)
	if err != nil {
		fmt.Println("[goprox] cannot resolve home directory; skipping permissions")
		return
	}

	// 如果 config 不在当前用户的 home 内，跳过权限修复
	if !isUnderDir(configReal, homeReal) {
		fmt.Printf("[goprox] config is outside home (%s); shared-gateway permissions not modified\n", configReal)
		return
	}

	// Build target list: home → .config → goprox → config.yaml
	seen := make(map[string]bool)
	var targets []struct {
		path     string
		wantMode os.FileMode
	}

	addTarget := func(p string, mode os.FileMode) {
		if seen[p] {
			return
		}
		seen[p] = true
		targets = append(targets, struct {
			path     string
			wantMode os.FileMode
		}{p, mode})
	}

	addTarget(homeReal, 0711)

	configDir := filepath.Dir(configReal)          // ~/.config/goprox
	dotConfig := filepath.Dir(configDir)           // ~/.config

	// 只修复确实在 home 下的目录
	if isUnderDir(dotConfig, homeReal) && dotConfig != homeReal {
		if info, err := os.Stat(dotConfig); err == nil && info.IsDir() {
			addTarget(dotConfig, 0711)
		}
	}
	if isUnderDir(configDir, homeReal) && configDir != homeReal {
		if info, err := os.Stat(configDir); err == nil && info.IsDir() {
			addTarget(configDir, 0711)
		}
	}

	addTarget(configReal, 0666)

	changed := false
	var permLines []string
	for _, t := range targets {
		info, err := os.Stat(t.path)
		if err != nil {
			continue
		}
		currentMode := info.Mode().Perm()
		needFix := false
		if info.IsDir() {
			// others 没有 --x 权限 → 需要修复
			needFix = currentMode&0001 != 0001
		} else {
			needFix = currentMode != 0666
		}
		if needFix {
			os.Chmod(t.path, t.wantMode)
			permLines = append(permLines, fmt.Sprintf("  %s -> %04o", t.path, t.wantMode))
			changed = true
		}
	}

	if changed {
		fmt.Println("[goprox] updated shared-gateway permissions:")
		for _, line := range permLines {
			fmt.Println(line)
		}
	} else {
		fmt.Println("[goprox] home/config permissions already sufficient for shared gateway")
	}
}

// isUnderDir checks if child path is under (or equal to) parent.
func isUnderDir(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || !strings.HasPrefix(rel, "..")
}

func getProcessOwner(pid int) string {
	// Read /proc/<pid>/status to find Uid
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid := fields[1]
				if u, err := user.LookupId(uid); err == nil {
					return u.Username
				}
				return uid
			}
		}
	}
	return ""
}


