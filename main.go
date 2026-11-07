package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/seqyuan/goprox/internal/config"
)

var version = "dev"

const usage = `Usage:
  goprox serve [options]        Start the gateway server (foreground)
  goprox user <name>            Create a user account (prompts for password)
  goprox passwd <name>          Reset a user's password
  goprox del <name>             Delete a user account
  goprox 2fa-reset <name>       Disable a user's two-factor authentication
  goprox sso [options]          Show or configure lightweight SSO (identity
                                header forwarded to backends; see below)
  goprox check [options]        Validate state/users/virtual hosts, don't start

Options:
  -d, --config-dir <dir>  Config directory (default: <program dir>/config)
  --host <host>           Listen address (default: 0.0.0.0)
  --port <port>           Gateway listen port (default: 30152)
  --trusted-proxy <cidr>  Trusted reverse-proxy CIDR (e.g. 127.0.0.1/32);
                          enables X-Forwarded-For/Proto trust (default: none)
  --tls-cert <file>       TLS certificate (PEM); with --tls-key serves HTTPS
  --tls-key <file>        TLS private key (PEM)
  --tls-selfsigned        Generate a self-signed cert into the config dir and
                          serve HTTPS (covers localhost + LAN IPs; browsers
                          show a one-time warning you must accept)
  --title <text>          Site title shown in the top-left corner of the
                          dashboard and login page (default: GoProx)
  --public-host <host[:port]>  Public gateway authority for vhost login redirects
  --public-scheme <http|https> Public scheme for vhost login redirects
  --cookie-domain <.domain>    Parent cookie domain for vhost sessions
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
    nohup ./goprox serve --port 30152 > goprox.log 2>&1 &

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
	case "check":
		runConfigCheck(opts)
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
	hostSet       bool // --host was passed explicitly (do not override persisted state otherwise)
	port          int
	portSet       bool // --port was passed explicitly
	trustedProxy  string
	title         string
	tlsCert       string
	tlsKey        string
	tlsSelfSigned bool
	publicHost    string
	publicScheme  string
	cookieDomain  string
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
			opts.host, opts.hostSet = v, true
		case "--port":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return opts, fmt.Errorf("invalid port %q (must be 1-65535)", v)
			}
			opts.port, opts.portSet = p, true
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
		case "--public-host":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.publicHost = v
		case "--public-scheme":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.publicScheme = v
		case "--cookie-domain":
			v, ok := next()
			if !ok {
				return opts, fmt.Errorf("option %s requires a value", a)
			}
			opts.cookieDomain = v
		default:
			return opts, fmt.Errorf("unknown option: %s", a)
		}
	}

	if opts.tlsCert != "" || opts.tlsKey != "" {
		if opts.tlsCert == "" || opts.tlsKey == "" {
			return opts, fmt.Errorf("tls requires both --tls-cert and --tls-key")
		}
	}

	return opts, nil
}

// applyListenOverrides applies only the listen options the user passed on the
// command line. host/port live in state.yaml; treating parser defaults as
// explicit overrides would silently reset them on every restart (and could
// expose a loopback-only gateway on all interfaces).

func applyListenOverrides(state *config.StateConfig, opts options) {
	if opts.hostSet {
		state.Server.Host = opts.host
	}
	if opts.portSet {
		state.Server.Port = opts.port
	}
}

// ---- user management (admin CLI) ----
