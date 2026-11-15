package subscription

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/conch/internal/linkparse"
	"github.com/xiongnemo/conch/internal/model"
	"github.com/xiongnemo/conch/internal/proto"
)

// Subscriptions in sing-box's JSON (outbounds and endpoints) and in
// SIP008 (shadowsocks servers) are read into mihomo's format through a
// Spec: the reverse of conch's sing-box backend.

// obj reads a JSON object leniently.
type obj map[string]any

func (o obj) str(k string) string {
	switch v := o[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func (o obj) num(k string) int { n, _ := strconv.Atoi(o.str(k)); return n }

func (o obj) flag(k string) bool { b, _ := o[k].(bool); return b }

func (o obj) sub(k string) obj { m, _ := o[k].(map[string]any); return m }

// strs reads a string or a list of them, as sing-box's listable fields are.
func (o obj) strs(k string) []string {
	switch v := o[k].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (o obj) strMap(k string) map[string]string {
	m := o.sub(k)
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for key := range m {
		if v := m.strs(key); len(v) > 0 {
			out[key] = v[0]
		}
	}
	return out
}

// seconds reads a sing-box duration ("30s", "1m") as whole seconds.
func seconds(s string) int {
	if d, err := time.ParseDuration(s); err == nil {
		return int(d.Seconds())
	}
	n, _ := strconv.Atoi(s)
	return n
}

// parseSingBox reads a sing-box config's outbounds and endpoints: proxies
// become nodes, selector and urltest groups.
func parseSingBox(doc obj) (*Snapshot, error) {
	s := &Snapshot{Providers: map[string][]string{}}
	var items []obj
	for _, key := range []string{"outbounds", "endpoints"} {
		list, _ := doc[key].([]any)
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				items = append(items, m)
			}
		}
	}
	// shadow-tls is an outbound shadowsocks or snell dials through; in
	// mihomo's terms, a plugin of the node.
	shadowTLS := map[string]obj{}
	for _, o := range items {
		if o.str("type") == "shadowtls" {
			shadowTLS[o.str("tag")] = o
		}
	}
	for _, o := range items {
		tag, typ := o.str("tag"), o.str("type")
		if st, ok := shadowTLS[o.str("detour")]; ok && (typ == "shadowsocks" || typ == "snell") {
			o = maps.Clone(o)
			delete(o, "detour")
			o["server"], o["server_port"] = st["server"], st["server_port"]
			o["shadow-tls"] = map[string]any(st)
		}
		switch typ {
		case "shadowtls":
			continue
		case "selector", "urltest":
			g := &yaml.Node{Kind: yaml.MappingNode}
			model.SetKey(g, "name", model.Str(tag))
			model.SetKey(g, "type", model.Str(map[string]string{"selector": "select", "urltest": "url-test"}[typ]))
			members := &yaml.Node{Kind: yaml.SequenceNode}
			for _, m := range o.strs("outbounds") {
				members.Content = append(members.Content, model.Str(m))
			}
			model.SetKey(g, "proxies", members)
			if u := o.str("url"); u != "" {
				model.SetKey(g, "url", model.Str(u))
			}
			if i := seconds(o.str("interval")); i > 0 {
				model.SetKey(g, "interval", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(i)})
			}
			if t := o.num("tolerance"); t > 0 {
				model.SetKey(g, "tolerance", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(t)})
			}
			s.Groups = append(s.Groups, g)
		case "direct", "block", "dns":
		default:
			spec, warns, err := singBoxSpec(o)
			if err != nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("节点 %q：%v，已跳过", tag, err))
				continue
			}
			for _, w := range warns {
				s.Warnings = append(s.Warnings, fmt.Sprintf("节点 %q：%s", tag, w))
			}
			n := proto.ToClash(tag, spec)
			if d := o.str("detour"); d != "" {
				model.SetKey(n, "dialer-proxy", model.Str(d))
			}
			s.Nodes = append(s.Nodes, n)
		}
	}
	if rules, ok := doc.sub("route")["rules"].([]any); ok && len(rules) > 0 {
		s.Warnings = append(s.Warnings, "sing-box 订阅里的路由规则没有导入（conch 只读 Clash 写法的规则）")
	}
	if len(s.Nodes) == 0 {
		return nil, noNodes(s.Warnings)
	}
	return s, nil
}

// singBoxSpec reads one sing-box outbound or endpoint.
func singBoxSpec(o obj) (*proto.Spec, []string, error) {
	var warns []string
	s := &proto.Spec{Server: o.str("server"), Port: o.num("server_port"), UDP: true}
	switch o.str("network") {
	case "tcp":
		s.UDP = false
	}
	switch typ := o.str("type"); typ {
	case "shadowsocks":
		s.Type, s.Cipher, s.Password = "ss", o.str("method"), o.str("password")
		switch u := o["udp_over_tcp"].(type) {
		case bool:
			s.UDPOverTCP, s.UoTVersion = u, 2 // sing-box's default
		case map[string]any:
			uo := obj(u)
			s.UDPOverTCP, s.UoTVersion = uo.flag("enabled"), uo.num("version")
			if s.UoTVersion == 0 {
				s.UoTVersion = 2
			}
		}
		if p := o.str("plugin"); p != "" {
			if s.Plugin = linkparse.SSPlugin(p + ";" + o.str("plugin_opts")); s.Plugin == nil {
				return nil, nil, fmt.Errorf("conch 不认识 %s 插件", p)
			}
		}
	case "snell":
		s.Type, s.Password = "snell", o.str("psk")
		if v := o.num("version"); v != 4 {
			return nil, nil, fmt.Errorf("mihomo 只有 snell 第 1 到 4 版，没有第 %d 版", v)
		}
		if o.str("userkey") != "" {
			return nil, nil, fmt.Errorf("mihomo 的 snell 没有 userkey")
		}
		s.Snell = &proto.Snell{Version: 4, Reuse: o.flag("reuse")}
		switch mode := o.str("obfs_mode"); mode {
		case "http", "tls":
			// sing-box's default hosts, which mihomo's (bing.com) are not.
			s.Plugin = &proto.Plugin{Name: "obfs", Mode: mode, Host: cmpOr(o.str("obfs_host"), map[string]string{"http": "bing.com", "tls": "cloudfront.net"}[mode])}
		}
	case "vmess":
		s.Type, s.UUID, s.Cipher, s.AlterID = "vmess", o.str("uuid"), o.str("security"), o.num("alter_id")
		s.GlobalPadding, s.AuthenticatedLength, s.PacketEncoding = o.flag("global_padding"), o.flag("authenticated_length"), o.str("packet_encoding")
	case "vless":
		s.Type, s.UUID, s.Flow, s.PacketEncoding = "vless", o.str("uuid"), o.str("flow"), o.str("packet_encoding")
	case "trojan":
		s.Type, s.Password = "trojan", o.str("password")
	case "socks":
		s.Type, s.Username, s.Password = "socks5", o.str("username"), o.str("password")
		if v := o.str("version"); v != "" && v != "5" {
			return nil, nil, fmt.Errorf("conch 只有 SOCKS5，没有 SOCKS%s", v)
		}
	case "http":
		s.Type, s.Username, s.Password, s.Headers = "http", o.str("username"), o.str("password"), o.strMap("headers")
	case "hysteria2", "hysteria":
		s.Type, s.Hysteria = typ, &proto.Hysteria{}
		h := s.Hysteria
		s.Password = o.str("password")
		if typ == "hysteria" {
			s.Password, h.Auth = o.str("auth_str"), o.str("auth")
			h.ObfsPassword = o.str("obfs")
			h.HopMin = 10
		} else if ob := o.sub("obfs"); ob != nil {
			h.Obfs, h.ObfsPassword = ob.str("type"), ob.str("password")
			h.ObfsMinPacket, h.ObfsMaxPacket = ob.num("min_packet_size"), ob.num("max_packet_size")
		}
		h.Up, h.Down = uint64(o.num("up_mbps"))*1e6, uint64(o.num("down_mbps"))*1e6
		if ports := o.strs("server_ports"); len(ports) > 0 {
			h.Ports = strings.ReplaceAll(strings.Join(ports, ","), ":", "-")
			// Unset, it is 30 s in mihomo and sing-box alike (v1 is set above).
			if v := seconds(o.str("hop_interval")); v > 0 {
				h.HopMin = v
			}
			h.HopMax = max(seconds(o.str("hop_interval_max")), h.HopMin)
		}
		h.BBRProfile = o.str("bbr_profile")
		if rl := o.sub("realm"); rl != nil {
			h.Realm = &proto.Realm{ServerURL: rl.str("server_url"), Token: rl.str("token"), RealmID: rl.str("realm_id"), STUN: rl.strs("stun_servers")}
			if t := rl.sub("http_client").sub("tls"); t != nil && t.flag("enabled") {
				tls, w := singBoxTLS(t)
				h.Realm.TLS, warns = tls, append(warns, w...)
			}
			// mihomo wants a server and port, which the realm overrides.
			if s.Server == "" {
				if u, err := url.Parse(h.Realm.ServerURL); err == nil {
					s.Server, s.Port = u.Hostname(), 443
				}
			}
		}
		h.MaxStreamWindow, h.MaxConnWindow = uint64(o.num("stream_receive_window")), uint64(o.num("connection_receive_window"))
	case "tuic":
		s.Type, s.UUID, s.Password = "tuic", o.str("uuid"), o.str("password")
		s.TUIC = &proto.TUIC{Congestion: o.str("congestion_control"), UDPRelayMode: o.str("udp_relay_mode"),
			UDPOverStream: o.flag("udp_over_stream"), ReduceRTT: o.flag("zero_rtt_handshake")}
		if d, err := time.ParseDuration(o.str("heartbeat")); err == nil {
			s.TUIC.Heartbeat = int(d.Milliseconds())
		} else {
			s.TUIC.Heartbeat = 10000
		}
	case "anytls":
		s.Type, s.Password = "anytls", o.str("password")
		s.AnyTLS = &proto.AnyTLS{IdleCheck: seconds(o.str("idle_session_check_interval")), IdleTimeout: seconds(o.str("idle_session_timeout")), MinIdle: o.num("min_idle_session")}
	case "ssh":
		s.Type, s.Username, s.Password = "ssh", o.str("user"), o.str("password")
		s.SSH = &proto.SSH{PrivateKey: strings.Join(o.strs("private_key"), "\n"), Passphrase: o.str("private_key_passphrase"),
			HostKeys: o.strs("host_key"), HostKeyAlgorithms: o.strs("host_key_algorithms")}
		if s.SSH.PrivateKey == "" {
			s.SSH.PrivateKey = o.str("private_key_path")
		}
	case "wireguard":
		s.Type, s.UDP = "wireguard", true
		wg := &proto.WireGuard{PrivateKey: o.str("private_key"), Address: o.strs("address"), MTU: o.num("mtu"), Workers: o.num("workers")}
		peers, _ := o["peers"].([]any)
		for _, x := range peers {
			p, _ := x.(map[string]any)
			po := obj(p)
			peer := proto.WireGuardPeer{Server: po.str("address"), Port: po.num("port"), PublicKey: po.str("public_key"),
				PreSharedKey: po.str("pre_shared_key"), AllowedIPs: po.strs("allowed_ips")}
			if r, ok := po["reserved"].([]any); ok {
				for _, b := range r {
					if f, ok := b.(float64); ok {
						peer.Reserved = append(peer.Reserved, int(f))
					}
				}
			}
			wg.Keepalive = max(wg.Keepalive, po.num("persistent_keepalive_interval"))
			wg.Peers = append(wg.Peers, peer)
		}
		if len(wg.Peers) == 0 {
			return nil, nil, fmt.Errorf("WireGuard 没有对端")
		}
		s.Server, s.Port = wg.Peers[0].Server, wg.Peers[0].Port
		s.WireGuard = wg
	default:
		return nil, nil, fmt.Errorf("conch 不认识 sing-box 的 %s 出站", typ)
	}
	if st := o.sub("shadow-tls"); st != nil {
		tls, w := singBoxTLS(st.sub("tls"))
		warns = append(warns, w...)
		s.Plugin = &proto.Plugin{Name: "shadow-tls", Host: tls.SNI, Password: st.str("password"), Version: st.num("version"), TLS: tls}
		if s.Plugin.Version == 0 {
			s.Plugin.Version = 1 // sing-box's default
		}
	}
	if t := o.sub("tls"); t != nil && t.flag("enabled") {
		var w []string
		s.TLS, w = singBoxTLS(t)
		warns = append(warns, w...)
	} else if s.Type == "hysteria2" || s.Type == "hysteria" || s.Type == "tuic" || s.Type == "anytls" {
		s.TLS = &proto.TLS{} // always TLS
	}
	if tr := o.sub("transport"); tr != nil {
		t, err := singBoxTransport(tr, s.TLS != nil)
		if err != nil {
			return nil, nil, err
		}
		s.Transport = t
	}
	if m := o.sub("multiplex"); m != nil && m.flag("enabled") {
		s.Mux = &proto.Mux{Protocol: m.str("protocol"), MaxConnections: m.num("max_connections"), MinStreams: m.num("min_streams"),
			MaxStreams: m.num("max_streams"), Padding: m.flag("padding")}
		if b := m.sub("brutal"); b != nil && b.flag("enabled") {
			s.Mux.BrutalUp, s.Mux.BrutalDown = uint64(b.num("up_mbps"))*1e6, uint64(b.num("down_mbps"))*1e6
		}
	}
	s.Sockopt = proto.Sockopt{Interface: o.str("bind_interface"), Mark: o.num("routing_mark"), TFO: o.flag("tcp_fast_open"), MPTCP: o.flag("tcp_multi_path")}
	strategy := o.str("domain_strategy")
	if r := o.sub("domain_resolver"); r != nil {
		strategy = r.str("strategy")
	}
	s.Sockopt.IPVersion = map[string]string{"ipv4_only": "ipv4", "ipv6_only": "ipv6", "prefer_ipv4": "ipv4-prefer", "prefer_ipv6": "ipv6-prefer"}[strategy]
	return s, warns, nil
}

func singBoxTLS(t obj) (*proto.TLS, []string) {
	var warns []string
	tls := &proto.TLS{SNI: t.str("server_name"), Insecure: t.flag("insecure"), ALPN: t.strs("alpn"), DisableSNI: t.flag("disable_sni")}
	if u := t.sub("utls"); u != nil && u.flag("enabled") {
		tls.Fingerprint = u.str("fingerprint")
		if tls.Fingerprint == "" {
			tls.Fingerprint = "chrome"
		}
	}
	if r := t.sub("reality"); r != nil && r.flag("enabled") {
		tls.Reality = &proto.Reality{PublicKey: r.str("public_key"), ShortID: r.str("short_id")}
	}
	if e := t.sub("ech"); e != nil && e.flag("enabled") {
		tls.ECH = &proto.ECH{QueryServerName: e.str("query_server_name")}
		var body []string
		for _, line := range e.strs("config") {
			if !strings.HasPrefix(line, "-----") {
				body = append(body, strings.TrimSpace(line))
			}
		}
		tls.ECH.Config = strings.Join(body, "")
	}
	if c := t.strs("client_certificate"); len(c) > 0 {
		tls.Certificate, tls.PrivateKey = strings.Join(c, "\n"), strings.Join(t.strs("client_key"), "\n")
	} else if c := t.strs("client_certificate_path"); len(c) > 0 {
		tls.Certificate, tls.PrivateKey = c[0], t.str("client_key_path")
	}
	if len(t.strs("certificate_public_key_sha256")) > 0 || len(t.strs("certificate")) > 0 || t.str("certificate_path") != "" {
		warns = append(warns, "mihomo 的写法只能固定证书本身的 SHA256，不能写 sing-box 的公钥指纹或信任的证书，按常规校验证书")
	}
	return tls, warns
}

func singBoxTransport(t obj, tls bool) (proto.Transport, error) {
	tr := proto.Transport{Headers: t.strMap("headers")}
	switch typ := t.str("type"); typ {
	case "ws":
		tr.Network, tr.Path = "ws", t.str("path")
		tr.EarlyData, tr.EarlyDataHeader = t.num("max_early_data"), t.str("early_data_header_name")
	case "httpupgrade":
		tr.Network, tr.Path, tr.Host = "httpupgrade", t.str("path"), t.str("host")
	case "grpc":
		tr.Network, tr.ServiceName = "grpc", t.str("service_name")
		tr.PingInterval = seconds(t.str("idle_timeout"))
	case "http":
		// HTTP/2 over TLS; without, TCP with HTTP headers.
		tr.Hosts, tr.Path, tr.Method = t.strs("host"), t.str("path"), t.str("method")
		tr.Host = first(tr.Hosts)
		if tls {
			tr.Network = "h2"
		} else {
			tr.Network = "http"
			tr.Paths = []string{tr.Path}
			tr.Method = cmpOr(tr.Method, "PUT") // sing-box's default
		}
	default:
		return tr, fmt.Errorf("conch 不支持 sing-box 的 %s 传输", typ)
	}
	for k, v := range tr.Headers {
		if strings.EqualFold(k, "host") {
			tr.Host = v
			delete(tr.Headers, k)
		}
	}
	if len(tr.Headers) == 0 {
		tr.Headers = nil
	}
	return tr, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseSIP008 reads SIP008's shadowsocks servers.
func parseSIP008(doc obj) (*Snapshot, error) {
	s := &Snapshot{Providers: map[string][]string{}}
	servers, _ := doc["servers"].([]any)
	for i, x := range servers {
		m, _ := x.(map[string]any)
		o := obj(m)
		name := cmpOr(o.str("remarks"), fmt.Sprintf("%s:%s", o.str("server"), o.str("server_port")))
		spec := &proto.Spec{Type: "ss", Server: o.str("server"), Port: o.num("server_port"), UDP: true, Cipher: o.str("method"), Password: o.str("password")}
		if p := o.str("plugin"); p != "" {
			if spec.Plugin = linkparse.SSPlugin(p + ";" + o.str("plugin_opts")); spec.Plugin == nil {
				s.Warnings = append(s.Warnings, fmt.Sprintf("第 %d 个服务器 %q：conch 不认识 %s 插件，已跳过", i+1, name, p))
				continue
			}
		}
		if spec.Server == "" || spec.Port == 0 {
			s.Warnings = append(s.Warnings, fmt.Sprintf("第 %d 个服务器缺少地址或端口，已跳过", i+1))
			continue
		}
		s.Nodes = append(s.Nodes, proto.ToClash(name, spec))
	}
	if len(s.Nodes) == 0 {
		return nil, noNodes(s.Warnings)
	}
	return s, nil
}

// parseJSON reads the JSON subscriptions: sing-box's and SIP008.
func parseJSON(body []byte) (*Snapshot, bool, error) {
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return nil, false, nil
	}
	switch {
	case doc["outbounds"] != nil || doc["endpoints"] != nil:
		s, err := parseSingBox(doc)
		return s, true, err
	case doc["servers"] != nil:
		s, err := parseSIP008(doc)
		return s, true, err
	}
	return nil, false, nil
}
