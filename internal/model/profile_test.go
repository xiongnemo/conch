package model

import (
	"strings"
	"testing"
)

func TestUnknownFieldsAreReported(t *testing.T) {
	for _, src := range []string{
		"rotues: {}",                            // top-level typo
		"inbound: { mixed_port: 7890 }",         // nested typo
		"routes: { default: DIRECT, list: [] }", // routes typo
		"groups: [{ name: g, type: select, member: [a] }]",
		"routes: { entries: { a.com: { via: DIRECT, reslove: true } } }",
	} {
		_, err := Parse([]byte(src), "profile.yaml")
		if err == nil || !strings.Contains(err.Error(), "没有字段") || !strings.Contains(err.Error(), "profile.yaml") {
			t.Errorf("%s: want unknown-field error with file name, got %v", src, err)
		}
	}
}

func TestExtensionKeysAndMerge(t *testing.T) {
	p, err := Parse([]byte(`
x-common: &common { type: ss, cipher: aes-128-gcm, password: x, UDP: "true" }
nodes:
  - { <<: *common, name: a, server: 192.0.2.1, port: "8388" }
  - { <<: *common, name: b, type: trojan, server: 192.0.2.2, port: 443 }
routes:
  default: a
  entries:
    lan: false
`), "profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a, b := p.Nodes[0], p.Nodes[1]
	if a.View.Type != "ss" || a.View.Port != 8388 || a.View.UDP == nil || !*a.View.UDP {
		t.Errorf("node a view = %+v (merged keys, weak typing and key case should behave like mihomo)", a.View)
	}
	if b.View.Type != "trojan" {
		t.Errorf("explicit keys must override merged ones, got type %q", b.View.Type)
	}
	if got := Lookup(a.Raw, "cipher"); got == nil || got.Value != "aes-128-gcm" {
		t.Errorf("merged key missing from raw node")
	}
	if !p.Routes.Entries[0].Off {
		t.Errorf("lan: false should turn the built-in lan entry off")
	}
	if p.Routes.DefaultPos.Line != 7 {
		t.Errorf("default position = %v, want line 7", p.Routes.DefaultPos)
	}
}
