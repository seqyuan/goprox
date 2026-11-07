package main

// 轻量单点登录子命令（sso）与相关参数解析。

import (
	"fmt"
	"log"

	"github.com/seqyuan/goprox/internal/config"
)

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

	if !sa.haveHeader && !sa.haveHMAC {
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

	if sa.haveHMAC && sa.hmacSecret == "" {
		log.Fatalf("--hmac-secret requires a non-empty key (omit it to keep the current one)")
	}

	// A header update replaces the name; an HMAC-only update keeps the existing
	// name. Both must never silently turn a requested change into a no-op.
	userHeader := state.SSO.UserHeader
	if sa.haveHeader {
		if sa.userHeader == "" {
			log.Fatalf("--user-header requires a non-empty header name (use --off to disable)")
		}
		if !config.IsValidHeaderName(sa.userHeader) {
			log.Fatalf("invalid header name %q (must be a valid HTTP header name)", sa.userHeader)
		}
		userHeader = sa.userHeader
	}
	if userHeader == "" {
		log.Fatalf("--hmac-secret requires a configured user header; pass --user-header too")
	}

	hmacSecret := state.SSO.HMACSecret // keep the current secret unless replaced
	if sa.haveHMAC {
		hmacSecret = sa.hmacSecret
	}
	if err := config.PersistSSOConfig(statePath, userHeader, hmacSecret); err != nil {
		log.Fatalf("update state: %v", err)
	}

	mode := "unsigned (backend must be network-isolated)"
	if hmacSecret != "" {
		mode = "HMAC-signed"
	}
	fmt.Printf("[goprox] sso: user_header=%s (%s)\n", userHeader, mode)
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

// runConfigCheck validates state, users, host index and virtual-host
// requirements without binding a port or starting the server.
