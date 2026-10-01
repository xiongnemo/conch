// Package sidecar runs protocol helpers beside the kernel for nodes the
// kernel cannot speak; today that is trojan-go. Each sidecar is a local
// SOCKS5 proxy that the kernel uses in place of the node. A sidecar in the
// middle of a chain dials through the hop before via a loopback inbound
// of the kernel that sends everything to that hop.
package sidecar

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/model"
)

// Kernel is the helper binary sidecars run.
const Kernel = "trojan-go"

// Ports are a sidecar's local ports, kept stable so the kernel config
// does not change on every reload.
type Ports struct {
	Local   int `json:"local"`             // the SOCKS5 proxy the kernel uses
	Forward int `json:"forward,omitempty"` // the kernel's inbound towards the previous hop
}

// Sidecar is one helper process.
type Sidecar struct {
	Proxy  string // the compiled proxy it stands in for
	Ports  Ports
	Config []byte
}

// Needs reports whether a proxy is served by a sidecar.
func Needs(p *compile.Proxy) bool {
	return strings.EqualFold(p.Node.View.Type, "trojan-go")
}

// Plan replaces every proxy that needs a sidecar with a SOCKS5 node at its
// local port, in a copy of res for the backend, and returns the sidecars
// and the loopback inbounds the kernel must provide. ports must have an
// entry for every such proxy.
func Plan(res *compile.Result, ports map[string]Ports) (*compile.Result, []Sidecar, []backend.Forward, error) {
	out := *res
	out.Proxies = make([]*compile.Proxy, len(res.Proxies))
	var cars []Sidecar
	var forwards []backend.Forward
	for i, p := range res.Proxies {
		out.Proxies[i] = p
		if !Needs(p) {
			continue
		}
		pp, ok := ports[p.Name]
		if !ok || pp.Local == 0 || p.Upstream != "" && pp.Forward == 0 {
			return nil, nil, nil, fmt.Errorf("没有给 %q 分配边车端口", p.Name)
		}
		if p.Upstream == "" {
			pp.Forward = 0
		} else {
			forwards = append(forwards, backend.Forward{Name: compile.HopSep + "sidecar" + compile.HopSep + p.Name, Port: pp.Forward, Via: p.Upstream})
		}
		cfg, err := TrojanGoConfig(p.Node, pp)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("节点 %q：%w", p.Node.Name, err)
		}
		cars = append(cars, Sidecar{Proxy: p.Name, Ports: pp, Config: cfg})
		local := *p
		local.Upstream = "" // the sidecar dials through the previous hop itself
		local.Node = socksNode(p.Node, pp.Local)
		out.Proxies[i] = &local
	}
	return &out, cars, forwards, nil
}

func socksNode(n *model.Node, port int) *model.Node {
	m := &yaml.Node{Kind: yaml.MappingNode}
	for _, kv := range [][2]string{{"name", n.Name}, {"type", "socks5"}, {"server", "127.0.0.1"}} {
		model.SetKey(m, kv[0], model.Str(kv[1]))
	}
	model.SetKey(m, "port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(port)})
	model.SetKey(m, "udp", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	return model.NewNode(m, n.Pos)
}

// trojanGoClient is the part of trojan-go's client config nautilus writes.
type trojanGoClient struct {
	RunType    string   `json:"run_type"`
	LocalAddr  string   `json:"local_addr"`
	LocalPort  int      `json:"local_port"`
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	Password   []string `json:"password"`
	LogLevel   int      `json:"log_level"`
	SSL        struct {
		Verify         bool     `json:"verify"`
		VerifyHostname bool     `json:"verify_hostname"`
		SNI            string   `json:"sni,omitempty"`
		ALPN           []string `json:"alpn,omitempty"`
		Fingerprint    string   `json:"fingerprint,omitempty"`
	} `json:"ssl"`
	Mux struct {
		Enabled bool `json:"enabled"`
	} `json:"mux"`
	Websocket struct {
		Enabled bool   `json:"enabled"`
		Path    string `json:"path,omitempty"`
		Host    string `json:"host,omitempty"`
	} `json:"websocket"`
	Shadowsocks struct {
		Enabled  bool   `json:"enabled"`
		Method   string `json:"method,omitempty"`
		Password string `json:"password,omitempty"`
	} `json:"shadowsocks"`
	ForwardProxy struct {
		Enabled   bool   `json:"enabled"`
		ProxyAddr string `json:"proxy_addr,omitempty"`
		ProxyPort int    `json:"proxy_port,omitempty"`
	} `json:"forward_proxy"`
}

// TrojanGoConfig writes the client config for a trojan-go node, written
// the way Clash writes trojan nodes:
//
//	{ name, type: trojan-go, server, port, password, sni, alpn, skip-cert-verify,
//	  client-fingerprint, network: ws, ws-opts: { path, headers: { Host } },
//	  ss-opts: { enabled, method, password }, mux: true }
func TrojanGoConfig(n *model.Node, ports Ports) ([]byte, error) {
	m := n.Raw
	str := func(key string) string { return model.WeakString(model.Lookup(m, key)) }
	flag := func(key string) bool { b, _ := model.WeakBool(model.Lookup(m, key)); return b }
	c := trojanGoClient{RunType: "client", LocalAddr: "127.0.0.1", LocalPort: ports.Local, RemoteAddr: n.View.Server, RemotePort: n.View.Port, LogLevel: 2}
	if c.RemoteAddr == "" || c.RemotePort == 0 {
		return nil, fmt.Errorf("trojan-go 节点需要 server 和 port")
	}
	if pw := str("password"); pw != "" {
		c.Password = []string{pw}
	} else {
		return nil, fmt.Errorf("trojan-go 节点需要 password")
	}
	c.SSL.Verify = !flag("skip-cert-verify")
	c.SSL.VerifyHostname = c.SSL.Verify
	c.SSL.SNI = cmpOr(str("sni"), str("servername"))
	c.SSL.Fingerprint = cmpOr(str("client-fingerprint"), str("fingerprint"))
	if a := model.Lookup(m, "alpn"); a != nil && a.Kind == yaml.SequenceNode {
		for _, v := range a.Content {
			c.SSL.ALPN = append(c.SSL.ALPN, model.WeakString(v))
		}
	}
	c.Mux.Enabled = flag("mux")
	if strings.EqualFold(str("network"), "ws") {
		c.Websocket.Enabled = true
		if ws := model.Lookup(m, "ws-opts"); ws != nil {
			c.Websocket.Path = model.WeakString(model.Lookup(ws, "path"))
			if h := model.Lookup(ws, "headers"); h != nil {
				c.Websocket.Host = model.WeakString(model.Lookup(h, "Host"))
			}
		}
		c.Websocket.Path = cmpOr(c.Websocket.Path, "/")
	}
	if ss := model.Lookup(m, "ss-opts"); ss != nil {
		if on, ok := model.WeakBool(model.Lookup(ss, "enabled")); on || !ok {
			c.Shadowsocks.Enabled = true
			c.Shadowsocks.Method = strings.ToUpper(cmpOr(model.WeakString(model.Lookup(ss, "method")), "AES-128-GCM"))
			c.Shadowsocks.Password = model.WeakString(model.Lookup(ss, "password"))
		}
	}
	if ports.Forward != 0 {
		c.ForwardProxy.Enabled, c.ForwardProxy.ProxyAddr, c.ForwardProxy.ProxyPort = true, "127.0.0.1", ports.Forward
	}
	return json.MarshalIndent(c, "", "  ")
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Check reports what a profile's trojan-go nodes need that is missing.
func Check(res *compile.Result, installed bool) diag.List {
	var d diag.List
	for _, p := range res.Proxies {
		if Needs(p) && !installed {
			d.Errorf(p.Node.Pos, "节点 %q 是 trojan-go，需要 trojan-go 程序：运行 nautilus kernel install trojan-go", p.Node.Name)
			break
		}
	}
	return d
}
