package config

import "testing"

func TestIsValidHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"", false},
		{"X-Authenticated-User", true},
		{"Remote_User", true},
		{"X-Custom-User", true},
		{"a.b-c_d", true},     // token chars: . - _ all legal
		{"Bad Header", false}, // space is not a token char
		{"Header\nInjection", false},
		{"头", false},   // non-ASCII
		{"X:Y", false}, // colon is not a token char
	}
	for _, tc := range cases {
		if got := IsValidHeaderName(tc.name); got != tc.want {
			t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
