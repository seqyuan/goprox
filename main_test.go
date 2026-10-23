package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
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
