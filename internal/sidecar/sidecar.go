// Package sidecar runs protocol helpers beside the kernel for nodes the
// kernel cannot speak; today that is trojan-go. Each sidecar is a local
// SOCKS5 proxy that the kernel uses in place of the node. A sidecar in the
// middle of a chain dials through the hop before via a loopback inbound
// of the kernel that sends everything to that hop.
package sidecar

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/backend"
	"github.com/xiongnemo/conch/internal/certpin"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/diag"
	"github.com/xiongnemo/conch/internal/model"
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
	// Cert is the PEM file the config names CertFile(Proxy), when it
	// pins a certificate: the roots trojan-go trusts.
	Cert []byte
}

// FileBase names a sidecar's files, in a directory of their own.
func FileBase(proxy string) string {
	sum := sha256.Sum256([]byte(proxy))
	return hex.EncodeToString(sum[:6])
}

// CertFile is the file a sidecar's pinned certificate is written to,
// relative to the directory trojan-go runs in.
func CertFile(proxy string) string { return FileBase(proxy) + ".pem" }

// Needs reports whether a proxy is served by a sidecar: trojan-go nodes,
// and Trojan nodes with an inner shadowsocks layer (ss-opts) for kernels
// without one (trojanSS false), which trojan-go speaks too.
func Needs(p *compile.Proxy, trojanSS bool) bool {
	switch strings.ToLower(p.Node.View.Type) {
	case "trojan-go":
		return true
	case "trojan":
		if trojanSS {
			return false
		}
		on, _ := model.WeakBool(model.Lookup(model.Lookup(p.Node.Raw, "ss-opts"), "enabled"))
		return on
	}
	return false
}

// Plan replaces every proxy that needs a sidecar with a SOCKS5 node at its
// local port, in a copy of res for the backend, and returns the sidecars
// and the loopback inbounds the kernel must provide. ports must have an
// entry for every such proxy; certs has the certificate pins learned.
func Plan(res *compile.Result, ports map[string]Ports, certs certpin.Lookup, trojanSS bool) (*compile.Result, []Sidecar, []backend.Forward, diag.List, error) {
	out := *res
	out.Proxies = make([]*compile.Proxy, len(res.Proxies))
	var cars []Sidecar
	var forwards []backend.Forward
	var d diag.List
	warned := map[*model.Node]bool{}
	for i, p := range res.Proxies {
		out.Proxies[i] = p
		if !Needs(p, trojanSS) {
			continue
		}
		pp, ok := ports[p.Name]
		if !ok || pp.Local == 0 || p.Upstream != "" && pp.Forward == 0 {
			return nil, nil, nil, nil, fmt.Errorf("没有给 %q 分配边车端口", p.Name)
		}
		if p.Upstream == "" {
			pp.Forward = 0
		} else {
			forwards = append(forwards, backend.Forward{Name: compile.HopSep + "sidecar" + compile.HopSep + p.Name, Port: pp.Forward, Via: p.Upstream})
		}
		cfg, cert, warns, err := TrojanGoConfig(p.Node, pp, CertFile(p.Name), certs)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("节点 %q：%w", p.Node.Name, err)
		}
		if !warned[p.Node] { // chain copies share their node's
			warned[p.Node] = true
			for _, w := range warns {
				d.Warnf(p.Node.Pos, "节点 %q：%s", p.Node.Name, w)
			}
		}
		cars = append(cars, Sidecar{Proxy: p.Name, Ports: pp, Config: cfg, Cert: cert})
		local := *p
		local.Upstream = "" // the sidecar dials through the previous hop itself
		local.Node = socksNode(p.Node, pp.Local)
		out.Proxies[i] = &local
	}
	return &out, cars, forwards, d, nil
}

func socksNode(n *model.Node, port int) *model.Node {
	m := &yaml.Node{Kind: yaml.MappingNode}
	for _, kv := range [][2]string{{"name", n.Name}, {"type", "socks5"}, {"server", "127.0.0.1"}} {
		model.SetKey(m, kv[0], model.Str(kv[1]))
	}
	model.SetKey(m, "port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(port)})
	// The sidecar relays UDP when the node does (trojan-go's own always do).
	udp, set := model.WeakBool(model.Lookup(n.Raw, "udp"))
	if !set || strings.EqualFold(n.View.Type, "trojan-go") {
		udp = true
	}
	model.SetKey(m, "udp", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(udp)})
	return model.NewNode(m, n.Pos)
}

// trojanGoClient is the part of trojan-go's client config conch writes.
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
		Fingerprint    string   `json:"fingerprint,omitempty"` // uTLS: firefox, chrome or ios
		Cert           string   `json:"cert,omitempty"`        // PEM file of the only roots trusted
	} `json:"ssl"`
	Mux struct {
		Enabled     bool `json:"enabled"`
		Concurrency int  `json:"concurrency,omitempty"`
		IdleTimeout int  `json:"idle_timeout,omitempty"`
	} `json:"mux"`
	TCP struct {
		PreferIPv4 bool `json:"prefer_ipv4"`
	} `json:"tcp"`
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
//	  fingerprint, client-fingerprint, network: ws, ws-opts: { path, headers: { Host } },
//	  ss-opts: { enabled, method, password }, mux: true }
//
// fingerprint pins a certificate, as in mihomo. trojan-go cannot pin, but
// trusts the roots in a file: with the pinned certificate learned (certpin),
// it trusts that one alone, under the name certFile, and the PEM to write
// there is returned. That says what a pinned CA does in mihomo; a pinned
// leaf must then match the server name too. Until the pin is learned the
// certificate is verified as usual.
func TrojanGoConfig(n *model.Node, ports Ports, certFile string, certs certpin.Lookup) ([]byte, []byte, []string, error) {
	m := n.Raw
	str := func(key string) string { return model.WeakString(model.Lookup(m, key)) }
	flag := func(key string) bool { b, _ := model.WeakBool(model.Lookup(m, key)); return b }
	var warns []string
	c := trojanGoClient{RunType: "client", LocalAddr: "127.0.0.1", LocalPort: ports.Local, RemoteAddr: n.View.Server, RemotePort: n.View.Port, LogLevel: 2}
	if c.RemoteAddr == "" || c.RemotePort == 0 {
		return nil, nil, nil, fmt.Errorf("trojan-go 节点需要 server 和 port")
	}
	if pw := str("password"); pw != "" {
		c.Password = []string{pw}
	} else {
		return nil, nil, nil, fmt.Errorf("trojan-go 节点需要 password")
	}
	if model.Lookup(m, "reality-opts") != nil {
		return nil, nil, nil, fmt.Errorf("trojan-go 没有 REALITY")
	}
	c.SSL.Verify = !flag("skip-cert-verify")
	c.SSL.SNI = cmpOr(str("sni"), str("servername"))
	fp, w := uTLS(str("client-fingerprint"))
	c.SSL.Fingerprint, warns = fp, append(warns, w...)
	var cert []byte
	if pin := str("fingerprint"); pin != "" {
		c.SSL.Verify = true // a pin is checked whatever skip-cert-verify says
		if certs != nil {
			if p, ok := certs(pin); ok {
				c.SSL.Cert, cert = certFile, []byte(cmp.Or(p.CA, p.Leaf))
			}
		}
	}
	c.SSL.VerifyHostname = c.SSL.Verify
	if a := model.Lookup(m, "alpn"); a != nil {
		warns = append(warns, "trojan-go 的客户端不发送 ALPN（alpn 只对它的服务器有用）")
	}
	// mux: true; trojan-go's own mux: {enabled, concurrency, idle_timeout};
	// or mihomo's smux: {enabled}.
	for _, key := range []string{"mux", "smux"} {
		v := model.Lookup(m, key)
		if v == nil {
			continue
		}
		if v.Kind == yaml.MappingNode {
			c.Mux.Enabled, _ = model.WeakBool(model.Lookup(v, "enabled"))
			c.Mux.Concurrency, _ = model.WeakInt(model.Lookup(v, "concurrency"))
			c.Mux.IdleTimeout, _ = model.WeakInt(model.Lookup(v, "idle_timeout"))
		} else {
			c.Mux.Enabled, _ = model.WeakBool(v)
		}
	}
	switch network := strings.ToLower(str("network")); network {
	case "", "tcp":
	case "ws":
		c.Websocket.Enabled = true
		if ws := model.Lookup(m, "ws-opts"); ws != nil {
			if on, _ := model.WeakBool(model.Lookup(ws, "v2ray-http-upgrade")); on {
				return nil, nil, nil, fmt.Errorf("trojan-go 没有 HTTPUpgrade（v2ray-http-upgrade）")
			}
			c.Websocket.Path = model.WeakString(model.Lookup(ws, "path"))
			if h := model.Lookup(ws, "headers"); h != nil && h.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(h.Content); i += 2 {
					if strings.EqualFold(h.Content[i].Value, "host") {
						c.Websocket.Host = model.WeakString(h.Content[i+1])
					} else {
						warns = append(warns, fmt.Sprintf("trojan-go 的 WebSocket 只能设置 Host，不能加 %s 头", h.Content[i].Value))
					}
				}
			}
			if ed, _ := model.WeakInt(model.Lookup(ws, "max-early-data")); ed > 0 {
				warns = append(warns, "trojan-go 的 WebSocket 没有 early data，这个节点不用")
			}
		}
		// trojan-go refuses to start with a path not from the root.
		if !strings.HasPrefix(c.Websocket.Path, "/") {
			c.Websocket.Path = "/" + c.Websocket.Path
		}
	default:
		return nil, nil, nil, fmt.Errorf("trojan-go 没有 %s 传输，只有 TCP 和 WebSocket", network)
	}
	// mihomo's trojan needs ss-opts enabled; conch's own trojan-go nodes
	// have always meant it on without the key.
	if ss := model.Lookup(m, "ss-opts"); ss != nil {
		on, set := model.WeakBool(model.Lookup(ss, "enabled"))
		if on || !set && strings.EqualFold(n.View.Type, "trojan-go") {
			c.Shadowsocks.Enabled = true
			c.Shadowsocks.Method = strings.ToUpper(cmpOr(model.WeakString(model.Lookup(ss, "method")), "AES-128-GCM"))
			c.Shadowsocks.Password = model.WeakString(model.Lookup(ss, "password"))
		}
	}
	switch v := strings.ToLower(str("ip-version")); v {
	case "", "dual":
	case "ipv4", "ipv4-prefer":
		c.TCP.PreferIPv4 = true
	default:
		warns = append(warns, fmt.Sprintf("trojan-go 不能只用或优先用 IPv6（ip-version: %s）", v))
	}
	for _, key := range []string{"tfo", "mptcp", "interface-name", "routing-mark"} {
		if v := model.Lookup(m, key); v != nil && model.WeakString(v) != "" && model.WeakString(v) != "false" && model.WeakString(v) != "0" {
			warns = append(warns, fmt.Sprintf("trojan-go 没有 %s", key))
		}
	}
	if ports.Forward != 0 {
		c.ForwardProxy.Enabled, c.ForwardProxy.ProxyAddr, c.ForwardProxy.ProxyPort = true, "127.0.0.1", ports.Forward
	}
	b, err := json.MarshalIndent(c, "", "  ")
	return b, cert, warns, err
}

// uTLS is mihomo's client-fingerprint in trojan-go's three: firefox,
// chrome and ios; others the nearest, said. none is no uTLS.
func uTLS(name string) (string, []string) {
	switch name = strings.ToLower(name); {
	case name == "" || name == "none":
		return "", nil
	case name == "chrome" || name == "firefox" || name == "ios":
		return name, nil
	case name == "safari" || name == "safari16":
		return "ios", []string{"trojan-go 没有 " + name + " 指纹，改用 ios（也是 Safari 的）"}
	case strings.HasPrefix(name, "firefox"):
		return "firefox", []string{"trojan-go 没有 " + name + " 指纹，改用 firefox"}
	}
	return "chrome", []string{"trojan-go 没有 " + name + " 指纹，改用 chrome"}
}

// PinTarget is where the certificate a trojan-go node pins is fetched.
func PinTarget(n *model.Node) (certpin.Target, bool) {
	str := func(key string) string { return model.WeakString(model.Lookup(n.Raw, key)) }
	pin := str("fingerprint")
	if pin == "" || n.View.Server == "" || n.View.Port == 0 {
		return certpin.Target{}, false
	}
	t := certpin.Target{Pin: pin, Address: net.JoinHostPort(n.View.Server, strconv.Itoa(n.View.Port)), ServerName: cmp.Or(str("sni"), str("servername"), n.View.Server)}
	if a := model.Lookup(n.Raw, "alpn"); a != nil && a.Kind == yaml.SequenceNode {
		for _, v := range a.Content {
			t.ALPN = append(t.ALPN, model.WeakString(v))
		}
	}
	return t, true
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
