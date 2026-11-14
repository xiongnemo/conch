package daemon

import (
	"encoding/base64"
	"slices"
	"testing"
)

func TestSplitLinks(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"vless://a@h:1#HK 01\r\nss://b@h:2#JP\n\n", []string{"vless://a@h:1#HK 01", "ss://b@h:2#JP"}},
		// Lines a single-line input joined with spaces.
		{"vless://a@h:1#HK 01 trojan://c@h:3#US 02", []string{"vless://a@h:1#HK 01", "trojan://c@h:3#US 02"}},
		{"# a comment\nhysteria2://d@h:4", []string{"hysteria2://d@h:4"}},
		{base64.StdEncoding.EncodeToString([]byte("ss://b@h:2#JP\nsocks://h:5")), []string{"ss://b@h:2#JP", "socks://h:5"}},
		{"  \n ", nil},
		{"\ufeffsocks://h:5", []string{"socks://h:5"}},
	} {
		if got := SplitLinks(c.in); !slices.Equal(got, c.want) {
			t.Errorf("SplitLinks(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
