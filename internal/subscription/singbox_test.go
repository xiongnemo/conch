package subscription

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/backend/singbox"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/model"
)

// A sing-box config read as a subscription and written for sing-box again
// is the config it was: conch's own sing-box goldens, node by node.
func TestSingBoxRoundTrip(t *testing.T) {
	for _, golden := range []string{"transports", "options", "sing-protocols", "hysteria2", "plugins"} {
		body, err := os.ReadFile("../backend/singbox/testdata/" + golden + ".golden.json")
		if err != nil {
			t.Fatal(err)
		}
		snap, err := Parse(body, nil)
		if err != nil {
			t.Fatalf("%s: %v", golden, err)
		}
		nodes := &yaml.Node{Kind: yaml.SequenceNode, Content: snap.Nodes}
		doc := &yaml.Node{Kind: yaml.MappingNode}
		model.SetKey(doc, "nodes", nodes)
		text, _ := yaml.Marshal(doc)
		p, err := model.Parse(append(text, []byte("routes: { default: DIRECT }\n")...), "profile.yaml")
		if err != nil {
			t.Fatalf("%s: %v\n%s", golden, err, text)
		}
		res := compile.Compile(p)
		art, d := singbox.Backend{}.Encode(res, backend.Options{})
		if art == nil {
			t.Fatalf("%s: %v", golden, d)
		}
		before, after := outbounds(t, body), outbounds(t, art.Config)
		for tag, want := range before {
			if strings.Contains(tag, "›") {
				continue // a chain copy or a helper outbound
			}
			got := after[tag]
			// A public-key pin or trusted roots cannot go back to mihomo's
			// certificate hash; the rest of TLS comes back.
			for _, o := range []map[string]any{want, got} {
				if t, ok := o["tls"].(map[string]any); ok {
					delete(t, "certificate_public_key_sha256")
					delete(t, "certificate")
				}
			}
			if !reflect.DeepEqual(got, want) {
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				t.Errorf("%s: %s\n got  %s\n want %s", golden, tag, g, w)
			}
		}
		t.Logf("%s: %d nodes; %q", golden, len(snap.Nodes), snap.Warnings)
	}
}

func outbounds(t *testing.T, config []byte) map[string]map[string]any {
	var c struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, o := range append(c.Outbounds, c.Endpoints...) {
		switch o["type"] {
		case "selector", "urltest", "direct", "block":
			continue
		}
		out[o["tag"].(string)] = o
	}
	return out
}

func TestSIP008(t *testing.T) {
	snap, err := Parse([]byte(`{"version": 1, "servers": [
  {"id": "1", "remarks": "香港", "server": "hk.example.com", "server_port": 8388, "password": "p", "method": "aes-128-gcm",
   "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=cdn.example.com"},
  {"id": "2", "remarks": "坏的", "server": "x.example.com", "server_port": 8388, "password": "p", "method": "aes-128-gcm", "plugin": "kcptun"},
  {"id": "3", "server": "jp.example.com", "server_port": 443, "password": "p", "method": "chacha20-ietf-poly1305"}
], "bytes_used": 1}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Nodes) != 2 || len(snap.Warnings) != 1 || !strings.Contains(snap.Warnings[0], "kcptun") {
		t.Fatalf("%d nodes, warnings %q", len(snap.Nodes), snap.Warnings)
	}
	n := snap.Nodes[0]
	for key, want := range map[string]string{"name": "香港", "type": "ss", "cipher": "aes-128-gcm", "plugin": "obfs"} {
		if got := model.WeakString(model.Lookup(n, key)); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := model.WeakString(model.Lookup(model.Lookup(n, "plugin-opts"), "host")); got != "cdn.example.com" {
		t.Errorf("obfs host %q", got)
	}
	if got := model.WeakString(model.Lookup(snap.Nodes[1], "name")); got != "jp.example.com:443" {
		t.Errorf("unnamed server named %q", got)
	}
}
