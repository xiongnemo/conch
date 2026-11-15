package nodeform

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for text, want := range map[string]int{
		`{ name: a, type: ss, server: 1.2.3.4, port: 1 }`:                    1,
		"- { name: a, type: ss }\n- { name: b, type: ss }":                   2,
		"nodes:\n  - { name: a, type: ss }\n  - { name: b, type: ss }\n":     2,
		"name: a\ntype: trojan\nserver: t.example\nport: 443\npassword: p\n": 1,
	} {
		nodes, err := Parse(text)
		if err != nil || len(nodes) != want {
			t.Errorf("%q: %d nodes, %v", text, len(nodes), err)
		}
	}
	for _, text := range []string{"", "a", "[1, 2]", "{ name: a", "nodes: x"} {
		if _, err := Parse(text); err == nil {
			t.Errorf("%q: no error", text)
		}
	}
}

// What the form sends is written the way managed.yaml keeps nodes: the
// form's order, no empty values, quotes only where needed; keys the form
// does not know stay, and strings stay as they were typed.
func TestTidyLine(t *testing.T) {
	n, err := FromJSON([]byte(`{"udp": true, "password": "123456", "port": 8388, "server": " 1.2.3.4 ", "type": "ss", "name": "香港 01",
		"plugin": "obfs", "cipher": "aes-128-gcm", "ws-opts": {"path": "", "headers": {"Host": ""}}, "sni": "", "alpn": []}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Line(Tidy(n))
	want := `{name: 香港 01, type: ss, server: " 1.2.3.4 ", port: 8388, cipher: aes-128-gcm, password: "123456", udp: true, plugin: obfs}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	back, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ToMap(back[0])
	if m["password"] != "123456" || m["port"] != 8388 || Name(back[0]) != "香港 01" {
		t.Errorf("read back: %v", m)
	}
}

func TestVisibleAndMissing(t *testing.T) {
	m := New("vless")
	shown := func() []string {
		var keys []string
		for _, f := range Fields {
			if Visible(f, m) && !f.More {
				keys = append(keys, f.Key)
			}
		}
		return keys
	}
	if got := strings.Join(shown(), " "); got != "name type server port uuid flow tls network udp" {
		t.Errorf("vless without TLS shows %s", got)
	}
	Set(m, "tls", true)
	Set(m, "network", "ws")
	if got := strings.Join(shown(), " "); !strings.Contains(got, "servername reality-opts.public-key") || !strings.Contains(got, "ws-opts.path ws-opts.headers.Host") {
		t.Errorf("vless with TLS over ws shows %s", got)
	}
	Set(m, "ws-opts.headers.Host", "cdn.example")
	if Get(m, "ws-opts.headers.Host") != "cdn.example" {
		t.Error("nested set")
	}
	Set(m, "ws-opts.headers.Host", nil)
	if Get(m, "ws-opts.headers.Host") != nil {
		t.Error("nested delete")
	}
	n, _ := FromJSON([]byte(`{"type": "vless", "name": "v", "server": "a.example"}`))
	if got := Missing(n); !reflect.DeepEqual(got, []string{"端口", "UUID"}) {
		t.Errorf("missing %v", got)
	}
	if New("ss")["cipher"] != "aes-128-gcm" || New("vmess")["cipher"] != "auto" || New("hysteria2")["udp"] != nil {
		t.Errorf("defaults: %v %v %v", New("ss"), New("vmess"), New("hysteria2"))
	}
}

func TestValueText(t *testing.T) {
	field := func(key string) Field {
		for _, f := range Fields {
			if f.Key == key {
				return f
			}
		}
		t.Fatalf("no field %s", key)
		return Field{}
	}
	for _, c := range []struct {
		key, text string
		want      any
	}{
		{"port", "443", 443},
		{"reserved", "1, 2，3", []any{1, 2, 3}},
		{"alpn", "h2, http/1.1", []any{"h2", "http/1.1"}},
		{"tls", "true", true},
		{"sni", "  ", nil},
	} {
		got := Value(field(c.key), c.text)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q = %#v, want %#v", c.key, c.text, got, c.want)
		}
		if c.want != nil && Text(got) != strings.ReplaceAll(c.text, "，", ", ") {
			t.Errorf("%s: text of %#v = %q", c.key, got, Text(got))
		}
	}
}
