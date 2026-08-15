package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
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
