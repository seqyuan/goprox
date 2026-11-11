package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seqyuan/goprox/internal/config"
)

func TestParseOptionsTLS(t *testing.T) {
	opts, err := parseOptions([]string{"--tls-cert", "c.pem", "--tls-key", "k.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.tlsCert != "c.pem" || opts.tlsKey != "k.pem" || opts.tlsSelfSigned {
		t.Fatalf("unexpected tls options: %+v", opts)
	}

	opts, err = parseOptions([]string{"--tls-selfsigned"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.tlsSelfSigned {
		t.Fatal("--tls-selfsigned not parsed")
	}

	if _, err := parseOptions([]string{"--tls-cert", "c.pem"}); err == nil {
		t.Fatal("--tls-cert without --tls-key must be rejected")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := generateSelfSignedCert(filepath.Join(dir, "tls"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("key file permissions too open: %v", info.Mode())
	}

	// The pair must load and the certificate must carry the expected SANs.
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	foundLoopback := false
	foundDNS := false
	for _, ip := range leaf.IPAddresses {
		if ip.IsLoopback() {
			foundLoopback = true
		}
	}
	for _, dns := range leaf.DNSNames {
		if dns == "localhost" {
			foundDNS = true
		}
	}
	if !foundLoopback || !foundDNS {
		t.Fatalf("cert SANs missing loopback IP / localhost DNS: ip=%v dns=%v", leaf.IPAddresses, leaf.DNSNames)
	}
	if !leaf.NotAfter.After(leaf.NotBefore.AddDate(5, 0, 0)) {
		t.Fatalf("cert validity too short: %v -> %v", leaf.NotBefore, leaf.NotAfter)
	}
}

// Persisted host/port must not be overwritten by parser defaults. Only flags
// the operator actually passed may change the effective listen address.
func TestApplyListenOverridesPreservesStateUnlessExplicit(t *testing.T) {
	state := &config.StateConfig{
		Server: config.ServerState{Host: "127.0.0.1", Port: 39001},
	}

	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.hostSet || opts.portSet {
		t.Fatalf("hostSet/portSet must be false without flags: %+v", opts)
	}
	applyListenOverrides(state, opts)
	if state.Server.Host != "127.0.0.1" || state.Server.Port != 39001 {
		t.Fatalf("state was overwritten by defaults: %+v", state.Server)
	}

	opts, err = parseOptions([]string{"--host", "0.0.0.0", "--port", "40000"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.hostSet || !opts.portSet {
		t.Fatalf("explicit flags not recorded: %+v", opts)
	}
	applyListenOverrides(state, opts)
	if state.Server.Host != "0.0.0.0" || state.Server.Port != 40000 {
		t.Fatalf("explicit flags not applied: %+v", state.Server)
	}
}

// `goprox sso --hmac-secret ...` without --user-header must update the secret
// while keeping the existing header, not silently act as "show config".
func TestRunSSOHMACOnlyKeepsExistingHeader(t *testing.T) {
	dir := t.TempDir()
	path := config.StatePath(dir)
	if err := config.PersistSSOConfig(path, "X-Authenticated-User", "old-secret"); err != nil {
		t.Fatal(err)
	}
	runSSO(ssoArgs{configDir: dir, hmacSecret: "new-secret", haveHMAC: true})
	st, err := config.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.SSO.UserHeader != "X-Authenticated-User" {
		t.Fatalf("user_header = %q, want preserved X-Authenticated-User", st.SSO.UserHeader)
	}
	if st.SSO.HMACSecret != "new-secret" {
		t.Fatalf("hmac_secret = %q, want new-secret", st.SSO.HMACSecret)
	}
}

// --tls-selfsigned must reuse an existing pair so the browser does not see a
// new untrusted certificate on every restart. Deleting the files rotates it.
func TestEnsureSelfSignedCertReusesExisting(t *testing.T) {
	dir := t.TempDir()
	cert1, key1, err := ensureSelfSignedCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	certBytes1, err := os.ReadFile(cert1)
	if err != nil {
		t.Fatal(err)
	}
	cert2, key2, err := ensureSelfSignedCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	certBytes2, err := os.ReadFile(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 != cert2 || key1 != key2 || string(certBytes1) != string(certBytes2) {
		t.Fatal("ensureSelfSignedCert regenerated an existing certificate")
	}
}

// ---- 启动暴露面提示（M-2） ----

func TestListenExposureWarning(t *testing.T) {
	cases := []struct {
		name         string
		host         string
		tls          bool
		trustedProxy string
		wantNonEmpty bool
	}{
		{"wildcard-v4-http", "0.0.0.0", false, "", true},
		{"wildcard-v6-http", "::", false, "", true},
		{"empty-host", "", false, "", true},
		{"loopback-http", "127.0.0.1", false, "", false},
		{"lan-ip-http", "192.168.0.106", false, "", false},
		{"wildcard-with-tls", "0.0.0.0", true, "", false},
		{"wildcard-behind-proxy", "0.0.0.0", false, "127.0.0.1/32", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := listenExposureWarning(c.host, c.tls, c.trustedProxy)
			if (got != "") != c.wantNonEmpty {
				t.Fatalf("listenExposureWarning(%q,tls=%v,proxy=%q) = %q", c.host, c.tls, c.trustedProxy, got)
			}
		})
	}
}

// ---- 选项解析 ----

func TestParseOptionsFull(t *testing.T) {
	opts, err := parseOptions([]string{
		"-d", "/tmp/cfg",
		"--host", "127.0.0.1",
		"--port", "39999",
		"--trusted-proxy", "10.0.0.0/8",
		"--title", "生信平台",
		"--public-host", "gw.example.com",
		"--public-scheme", "https",
		"--cookie-domain", ".example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.configDir != "/tmp/cfg" || opts.host != "127.0.0.1" || !opts.hostSet ||
		opts.port != 39999 || !opts.portSet || opts.trustedProxy != "10.0.0.0/8" ||
		opts.title != "生信平台" || opts.publicHost != "gw.example.com" ||
		opts.publicScheme != "https" || opts.cookieDomain != ".example.com" {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

func TestParseOptionsErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--host"},
		{"--port"},
		{"--port", "not-a-number"},
		{"--port", "0"},
		{"--port", "70000"},
		{"-d"},
		{"--trusted-proxy"},
		{"--unknown-flag"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("parseOptions(%v) accepted an invalid invocation", args)
		}
	}
}

// Parser defaults must never be written back over persisted state: only an
// explicitly passed --host/--port may override it.
func TestApplyListenOverrides(t *testing.T) {
	state := &config.StateConfig{Server: config.ServerState{Host: "192.168.0.5", Port: 31000}}

	applyListenOverrides(state, options{}) // no flags
	if state.Server.Host != "192.168.0.5" || state.Server.Port != 31000 {
		t.Fatalf("defaults overwrote persisted state: %+v", state.Server)
	}

	applyListenOverrides(state, options{host: "127.0.0.1", hostSet: true, port: 32000, portSet: true})
	if state.Server.Host != "127.0.0.1" || state.Server.Port != 32000 {
		t.Fatalf("explicit flags not applied: %+v", state.Server)
	}
}

func TestMustAbsPath(t *testing.T) {
	dir := t.TempDir()
	abs := mustAbsPath(filepath.Join(dir, "x.pem"))
	if !filepath.IsAbs(abs) {
		t.Fatalf("mustAbsPath returned %q", abs)
	}
}

func TestCheckWritableDir(t *testing.T) {
	dir := t.TempDir()
	if err := checkWritableDir(dir); err != nil {
		t.Fatalf("writable dir rejected: %v", err)
	}
	if err := checkWritableDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
}

// ---- 配置预检（goprox check 的核心路径） ----

func TestRunConfigCheckOK(t *testing.T) {
	dir := t.TempDir()
	if _, err := config.LoadState(config.StatePath(dir)); err != nil { // creates state + secret
		t.Fatal(err)
	}
	usersDir := config.UsersDir(dir)
	if err := os.MkdirAll(usersDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfgPath := config.UserConfigPath(dir, "alice")
	body := "auth:\n  password_hash: \"" + strings.Repeat("1", 64) + "\"\nservices:\n  - id: data\n    name: d\n    kind: files\n    path: /data\n    root: " + dir + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	// The files root overlaps the config dir, so the card is dropped; the check
	// itself must still succeed and report zero services.
	runConfigCheck(options{configDir: dir})
}

func TestMaskSecret(t *testing.T) {
	if maskSecret("") != "<unset>" || maskSecret("s3cret") != "<set>" {
		t.Fatalf("maskSecret = %q / %q", maskSecret(""), maskSecret("s3cret"))
	}
}

func TestParseSSOArgs(t *testing.T) {
	sa := parseSSOArgs([]string{"-d", "/tmp/c", "--user-header", "X-Authenticated-User", "--hmac-secret", "k", "--off"})
	if sa.configDir != "/tmp/c" || sa.userHeader != "X-Authenticated-User" || !sa.haveHeader ||
		sa.hmacSecret != "k" || !sa.haveHMAC || !sa.off {
		t.Fatalf("unexpected sso args: %+v", sa)
	}
}

// The subcommand may appear before or after the global options; both spellings
// must resolve to the same command and leave every option for the parser.
func TestSplitSubcommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCmd  string
		wantRest []string
	}{
		{"no args", nil, "serve", nil},
		{"serve explicit", []string{"serve", "--port", "8080"}, "serve", []string{"--port", "8080"}},
		{"flags first", []string{"-d", "/opt/gw", "user", "alice"}, "user", []string{"-d", "/opt/gw", "alice"}},
		{"flags last", []string{"user", "alice", "-d", "/opt/gw"}, "user", []string{"alice", "-d", "/opt/gw"}},
		{"flags both sides", []string{"--port", "8080", "check", "-d", "/opt/gw"}, "check", []string{"--port", "8080", "-d", "/opt/gw"}},
		{"value looks like a command", []string{"-d", "user", "check"}, "check", []string{"-d", "user"}},
		{"bare flags only", []string{"--port", "8080"}, "serve", []string{"--port", "8080"}},
		{"sso with its own options", []string{"-d", "/opt/gw", "sso", "--user-header", "X-User"}, "sso", []string{"-d", "/opt/gw", "--user-header", "X-User"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, rest := splitSubcommand(tc.args)
			if cmd != tc.wantCmd {
				t.Fatalf("cmd = %q, want %q", cmd, tc.wantCmd)
			}
			if strings.Join(rest, " ") != strings.Join(tc.wantRest, " ") {
				t.Fatalf("rest = %v, want %v", rest, tc.wantRest)
			}
		})
	}
}

func TestTakePositional(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantValue string
		wantOK    bool
		wantRest  []string
	}{
		{"plain", []string{"alice"}, "alice", true, nil},
		{"after option", []string{"-d", "/opt/gw", "alice"}, "alice", true, []string{"-d", "/opt/gw"}},
		{"before option", []string{"alice", "-d", "/opt/gw"}, "alice", true, []string{"-d", "/opt/gw"}},
		{"missing", []string{"-d", "/opt/gw"}, "", false, []string{"-d", "/opt/gw"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, rest, ok := takePositional(tc.args)
			if value != tc.wantValue || ok != tc.wantOK {
				t.Fatalf("value = %q ok=%v, want %q/%v", value, ok, tc.wantValue, tc.wantOK)
			}
			if strings.Join(rest, " ") != strings.Join(tc.wantRest, " ") {
				t.Fatalf("rest = %v, want %v", rest, tc.wantRest)
			}
		})
	}
}
