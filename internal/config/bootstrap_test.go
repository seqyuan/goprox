package config

import "testing"

func TestValidateAuthBootstrap(t *testing.T) {
	cases := []struct {
		name    string
		in      *AuthBootstrapConfig
		wantOK  bool
		wantMod string
	}{
		{"nil", nil, false, ""},
		{"static", &AuthBootstrapConfig{Mode: "STATIC", TokenValue: "abc"}, true, BootstrapModeStatic},
		{"static missing value", &AuthBootstrapConfig{Mode: "static"}, false, ""},
		{"file", &AuthBootstrapConfig{Mode: "file", TokenFile: "/tmp/tok"}, true, BootstrapModeFile},
		{"file missing path", &AuthBootstrapConfig{Mode: "file"}, false, ""},
		{"log", &AuthBootstrapConfig{Mode: "log", TokenLog: "/tmp/dsh.log"}, true, BootstrapModeLog},
		{"log missing path", &AuthBootstrapConfig{Mode: "log"}, false, ""},
		{"unknown mode", &AuthBootstrapConfig{Mode: "carrier-pigeon"}, false, ""},
		{"bad regex", &AuthBootstrapConfig{Mode: "log", TokenLog: "/tmp/l", TokenRegex: "("}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := validateAuthBootstrap(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && got.Mode != tc.wantMod {
				t.Fatalf("mode = %q, want %q", got.Mode, tc.wantMod)
			}
		})
	}
}

// serializeServices is used by every config write (add/edit/layout), so it must
// carry auth_bootstrap through or a card reorder would silently wipe it.
func TestSerializeServicesPreservesAuthBootstrap(t *testing.T) {
	bs := &AuthBootstrapConfig{Mode: BootstrapModeLog, TokenLog: "/tmp/dsh.log", TokenRegex: `\?token=(\w+)`}
	out := serializeServices([]ServiceConfig{{
		ID: "dsh", Name: "dsh", Host: "127.0.0.1", Port: 3080, Path: "/dsh",
		AuthBootstrap: bs,
	}})
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	got, ok := out[0]["auth_bootstrap"].(*AuthBootstrapConfig)
	if !ok || got != bs {
		t.Fatalf("auth_bootstrap not serialized: %#v", out[0]["auth_bootstrap"])
	}
}
