// Package linkparse parses proxy share links (vmess://, vless://, ss:// …)
// into backend-neutral specs.
package linkparse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/xiongnemo/conch/internal/proto"
)

// Parse parses one share link and returns the node's name and spec.
func Parse(link string) (string, *proto.Spec, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return "", nil, fmt.Errorf("不是分享链接：%q", short(link))
	}
	var (
		name string
		s    *proto.Spec
		err  error
	)
	switch strings.ToLower(scheme) {
	case "vmess":
		name, s, err = vmess(link)
	case "vless", "trojan":
		name, s, err = vlessTrojan(link)
	case "ss":
		name, s, err = shadowsocks(link)
	case "hysteria2", "hy2":
		name, s, err = hysteria2(link)
	case "socks", "socks5":
		name, s, err = socks(link)
	case "wireguard", "wg":
		name, s, err = wireguard(link)
	case "trojan-go":
		name, s, err = trojanGo(link)
	case "tuic":
		name, s, err = tuic(link)
	case "hysteria":
		name, s, err = hysteriaV1(link)
	case "anytls":
		name, s, err = anytls(link)
	default:
		return "", nil, fmt.Errorf("暂不支持 %s:// 链接", scheme)
	}
	if err != nil {
		return "", nil, fmt.Errorf("%s 链接无效：%w", scheme, err)
	}
	if s.Server == "" || s.Port == 0 {
		return "", nil, fmt.Errorf("%s 链接缺少服务器地址或端口", scheme)
	}
	if name == "" {
		name = net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	}
	return name, s, nil
}

// trojan-go://password@host:port/?sni=…&type=ws&host=…&path=…&encryption=ss;aes-128-gcm:pass#name
// is trojan-go's own scheme; such nodes run in a trojan-go sidecar.
func trojanGo(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "trojan-go", UDP: true, Password: userinfo(u), TLS: &proto.TLS{}}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	q := u.Query()
	s.TLS.SNI = q.Get("sni")
	switch t := q.Get("type"); t {
	case "", "original":
	case "ws":
		s.Transport = proto.Transport{Network: "ws", Path: cmpOr(q.Get("path"), "/"), Host: q.Get("host")}
	default:
		return "", nil, fmt.Errorf("不支持 trojan-go 的 %s 传输", t)
	}
	// trojan-go writes ss;method:password (url/share_link.go); conch once
	// wrote ss;method;password, which is still read.
	if enc := q.Get("encryption"); enc != "" && enc != "none" {
		provider, params, _ := strings.Cut(enc, ";")
		method, password, ok := strings.Cut(params, ":")
		if !ok {
			method, password, ok = strings.Cut(params, ";")
		}
		if provider != "ss" || !ok || method == "" || password == "" {
			return "", nil, fmt.Errorf("不认识的 encryption=%s（应该是 ss;加密方式:密码）", enc)
		}
		s.TrojanGo = &proto.TrojanGo{SSMethod: method, SSPassword: password}
	}
	if q.Get("plugin") != "" {
		s.Unknown = append(s.Unknown, "plugin")
	}
	return fragment(u), s, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// vmess:// carries base64-encoded JSON in the v2rayN format.
func vmess(link string) (string, *proto.Spec, error) {
	raw, err := decodeBase64(strings.TrimPrefix(link[len("vmess://"):], "/"))
	if err != nil {
		return "", nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", nil, fmt.Errorf("内容不是 JSON：%w", err)
	}
	str := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return strings.TrimSpace(x)
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	s := &proto.Spec{Type: "vmess", Server: str("add"), UUID: str("id"), Cipher: str("scy"), UDP: true}
	s.Port, _ = strconv.Atoi(str("port"))
	s.AlterID, _ = strconv.Atoi(str("aid"))
	// The rest are the query parameters of other links, except that
	// v2rayN uses "net" for the transport and "type" for its header.
	q := url.Values{}
	for k := range v {
		switch k {
		case "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "tls":
		default:
			if val := str(k); val != "" {
				q.Set(k, val)
			}
		}
	}
	q.Set("type", str("net"))
	q.Set("headerType", str("type"))
	q.Set("security", str("tls"))
	if err := applyQuery(s, q, true); err != nil {
		return "", nil, err
	}
	if q.Get("type") == "grpc" && s.Transport.ServiceName == "" {
		s.Transport.ServiceName = str("path")
	}
	return str("ps"), s, nil
}

// vless://uuid@host:port?… and trojan://password@host:port?…
func vlessTrojan(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: u.Scheme, UDP: true}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	q := u.Query()
	if u.Scheme == "vless" {
		s.UUID = u.User.Username()
		s.Flow = q.Get("flow")
		s.Encryption = q.Get("encryption")
		q.Del("flow")
		q.Del("encryption")
	} else {
		s.Password = userinfo(u)
		if q.Get("security") == "" {
			q.Set("security", "tls") // trojan is always TLS
		}
	}
	if err := applyQuery(s, q, true); err != nil {
		return "", nil, err
	}
	return fragment(u), s, nil
}

// ss:// in SIP002 form (ss://base64(method:password)@host:port/?plugin=…#name)
// or the legacy form (ss://base64(method:password@host:port)#name).
func shadowsocks(link string) (string, *proto.Spec, error) {
	body, frag, _ := strings.Cut(link[len("ss://"):], "#")
	name, _ := url.PathUnescape(frag)
	if !strings.Contains(body, "@") {
		decoded, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil {
			return "", nil, err
		}
		body = string(decoded)
	}
	u, err := url.Parse("ss://" + body)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "ss", UDP: true}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	userinfo := u.User.String()
	if _, hasPassword := u.User.Password(); !hasPassword {
		// SIP002 base64-encodes method:password; 2022 methods may not.
		if decoded, err := decodeBase64(u.User.Username()); err == nil {
			userinfo = string(decoded)
		}
	} else {
		userinfo, _ = url.PathUnescape(userinfo)
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return "", nil, fmt.Errorf("缺少加密方式或密码")
	}
	s.Cipher, s.Password = method, password
	if q := u.Query(); q.Get("udp-over-tcp") == "true" || q.Get("uot") == "1" || q.Get("uot") == "2" {
		s.UDPOverTCP = true
	}
	if p := u.Query().Get("plugin"); p != "" {
		s.Plugin = ssPlugin(p)
		if s.Plugin == nil {
			s.Unknown = append(s.Unknown, "plugin: "+strings.SplitN(p, ";", 2)[0])
		}
	}
	return name, s, nil
}

// ssPlugin reads a SIP002 plugin ("name;key=value;flag", with \ escapes)
// in mihomo's terms: obfs-local (simple-obfs) and v2ray-plugin, whose mux
// is on unless mux=0. Others it does not know.
func ssPlugin(p string) *proto.Plugin {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(p); i++ {
		switch {
		case p[i] == '\\' && i+1 < len(p):
			i++
			cur.WriteByte(p[i])
		case p[i] == ';':
			parts, cur = append(parts, cur.String()), strings.Builder{}
		default:
			cur.WriteByte(p[i])
		}
	}
	parts = append(parts, cur.String())
	opts := map[string]string{}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		opts[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	_, tls := opts["tls"]
	switch parts[0] {
	case "obfs-local", "simple-obfs", "obfs":
		return &proto.Plugin{Name: "obfs", Mode: cmpOr(opts["obfs"], "http"), Host: cmpOr(opts["obfs-host"], "bing.com")}
	case "v2ray-plugin":
		pl := &proto.Plugin{Name: "v2ray-plugin", Mode: cmpOr(opts["mode"], "websocket"), Host: cmpOr(opts["host"], "bing.com"), Path: opts["path"], Mux: opts["mux"] != "0"}
		if tls {
			pl.TLS = &proto.TLS{SNI: pl.Host}
		}
		return pl
	}
	return nil
}

// hysteria2://auth@host:port/?sni=…&obfs=salamander&obfs-password=…&mport=…
// The port may list hopping ports, e.g. host:443,20000-30000.
func hysteria2(link string) (string, *proto.Spec, error) {
	link, hop := splitHopPorts(link)
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "hysteria2", UDP: true, Hysteria: &proto.Hysteria{Ports: hop}}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	s.Password = userinfo(u)
	q := u.Query()
	s.Hysteria.Obfs = q.Get("obfs")
	s.Hysteria.ObfsPassword = q.Get("obfs-password")
	if mport := q.Get("mport"); mport != "" {
		s.Hysteria.Ports = mport
	}
	for _, b := range []struct {
		key string
		to  *uint64
	}{{"up", &s.Hysteria.Up}, {"down", &s.Hysteria.Down}} {
		if v := q.Get(b.key); v != "" {
			bits, ok := proto.ParseBandwidth(v)
			if !ok {
				s.Unknown = append(s.Unknown, b.key+"="+v)
			}
			*b.to = bits
		}
	}
	for _, k := range []string{"obfs", "obfs-password", "mport", "up", "down"} {
		q.Del(k)
	}
	if q.Get("security") == "" {
		q.Set("security", "tls")
	}
	if pin := q.Get("pinSHA256"); pin != "" {
		q.Set("pcs", pin)
		q.Del("pinSHA256")
	}
	if err := applyQuery(s, q, true); err != nil {
		return "", nil, err
	}
	return fragment(u), s, nil
}

// socks://[base64(user:pass)|user:pass@]host:port#name
func socks(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "socks5", UDP: true}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	if u.User != nil {
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		if !hasPass {
			if decoded, err := decodeBase64(user); err == nil {
				user, pass, _ = strings.Cut(string(decoded), ":")
			}
		}
		s.Username, s.Password = user, pass
	}
	return fragment(u), s, nil
}

// wireguard://privatekey@host:port?publickey=…&address=…&mtu=…&reserved=…
func wireguard(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "wireguard", UDP: true}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	q := u.Query()
	key, _ := url.PathUnescape(u.User.Username())
	wg := &proto.WireGuard{PrivateKey: key}
	// mihomo's format holds one address of each family.
	families := map[bool]bool{}
	for _, a := range strings.Split(firstOf(q, "address", "ip"), ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		a = withPrefix(a)
		v6 := strings.Contains(a, ":")
		if families[v6] {
			s.Unknown = append(s.Unknown, "address="+a+"（每类地址只能有一个）")
			continue
		}
		families[v6] = true
		wg.Address = append(wg.Address, a)
	}
	wg.MTU, _ = strconv.Atoi(q.Get("mtu"))
	peer := proto.WireGuardPeer{Server: s.Server, Port: s.Port, PublicKey: firstOf(q, "publickey", "public-key", "peer"), PreSharedKey: firstOf(q, "presharedkey", "pre-shared-key")}
	for _, r := range strings.Split(q.Get("reserved"), ",") {
		if v, err := strconv.Atoi(strings.TrimSpace(r)); err == nil {
			peer.Reserved = append(peer.Reserved, v)
		}
	}
	wg.Peers = []proto.WireGuardPeer{peer}
	s.WireGuard = wg
	return fragment(u), s, nil
}

// applyQuery reads the TLS and transport parameters shared by v2rayN-style
// links. Parameters it does not know are recorded as unknown.
func applyQuery(s *proto.Spec, q url.Values, report bool) error {
	known := map[string]bool{}
	get := func(keys ...string) string {
		for _, k := range keys {
			known[k] = true
		}
		return firstOf(q, keys...)
	}
	switch security := get("security"); security {
	case "tls", "reality", "xtls":
		t := &proto.TLS{
			SNI:         get("sni", "peer"),
			Fingerprint: get("fp"),
			PinSHA256:   get("pcs"),
			Insecure:    isTrue(get("allowInsecure", "insecure")),
			VerifyName:  get("vcn"),
		}
		// ech is xray's echConfigList: the list in base64, or looked up
		// in DNS ("name+https://dns/..."), which conch does through the
		// profile's DNS, as mihomo does.
		if e := get("ech"); e != "" {
			if name, _, isQuery := strings.Cut(e, "+"); isQuery && strings.Contains(e, "://") {
				t.ECH = &proto.ECH{QueryServerName: name}
			} else if strings.Contains(e, "://") {
				t.ECH = &proto.ECH{}
			} else {
				t.ECH = &proto.ECH{Config: e}
			}
		}
		if alpn := get("alpn"); alpn != "" {
			t.ALPN = strings.Split(alpn, ",")
		}
		if security == "reality" {
			t.Reality = &proto.Reality{PublicKey: get("pbk"), ShortID: get("sid"), SpiderX: get("spx")}
		}
		s.TLS = t
	case "", "none":
	default:
		s.Unknown = append(s.Unknown, "security="+security)
	}
	tr := proto.Transport{Network: get("type")}
	host, path := get("host"), get("path")
	switch tr.Network {
	case "", "tcp", "raw":
		tr.Network = ""
		if get("headerType") == "http" {
			tr.Network, tr.Host, tr.Path = "http", host, path
		}
	case "ws":
		tr.Host, tr.Path = host, path
		if ed := get("ed"); ed != "" {
			tr.EarlyData, _ = strconv.Atoi(ed)
			tr.EarlyDataHeader = "Sec-WebSocket-Protocol"
		} else if p, ed, ok := cutQuery(path, "ed"); ok {
			tr.Path = p
			tr.EarlyData, _ = strconv.Atoi(ed)
			tr.EarlyDataHeader = "Sec-WebSocket-Protocol"
		}
		if eh := get("eh"); eh != "" && tr.EarlyData > 0 {
			tr.EarlyDataHeader = eh
		}
	case "httpupgrade":
		tr.Host, tr.Path = host, path
	case "grpc":
		tr.ServiceName = get("serviceName")
		// mihomo's gRPC is gun: no multi mode, no authority of its own.
		if m := get("mode"); m != "" && m != "gun" {
			s.Unknown = append(s.Unknown, "mode="+m)
		}
		if a := get("authority"); a != "" {
			s.Unknown = append(s.Unknown, "authority="+a)
		}
	case "xhttp", "splithttp":
		tr.Network = "xhttp"
		tr.Host, tr.Path, tr.Mode = host, path, get("mode")
		if extra := get("extra"); extra != "" {
			xhttpExtra(s, &tr, extra)
		}
	case "h2", "http":
		tr.Network, tr.Host, tr.Path = "h2", host, path
	default:
		// mKCP, QUIC…: the node would dial plain TCP in mihomo.
		return fmt.Errorf("conch 不支持 %s 传输", tr.Network)
	}
	s.Transport = tr
	s.PacketEncoding = get("packetEncoding")
	get("headerType", "encryption", "flow", "spx")
	if report {
		var unknown []string
		for k := range q {
			if !known[k] {
				unknown = append(unknown, k)
			}
		}
		slices.Sort(unknown)
		s.Unknown = append(s.Unknown, unknown...)
	}
	return nil
}

// splitHopPorts replaces a multi-port authority ("h:443,2000-3000") with
// its first port, which net/url accepts, and returns the full port list.
func splitHopPorts(link string) (string, string) {
	scheme, rest, _ := strings.Cut(link, "://")
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	at := strings.LastIndex(authority, "@") + 1 // start of host:port
	hostport := authority[at:]
	colon := strings.LastIndex(hostport, ":")
	if strings.HasPrefix(hostport, "[") { // [ipv6]:port
		colon = strings.Index(hostport, "]:") + 1
	}
	if colon <= 0 {
		return link, ""
	}
	ports := hostport[colon+1:]
	i := strings.IndexAny(ports, ",-")
	if i < 0 {
		return link, ""
	}
	return scheme + "://" + authority[:at] + hostport[:colon+1] + ports[:i] + rest[end:], ports
}

func hostPort(s *proto.Spec, u *url.URL) error {
	s.Server = u.Hostname()
	if u.Port() == "" && slices.Contains([]string{"trojan", "trojan-go", "hysteria2", "hy2", "anytls"}, strings.ToLower(u.Scheme)) {
		s.Port = 443 // what these clients dial without a port
		return nil
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return fmt.Errorf("端口无效：%q", u.Port())
	}
	s.Port = port
	return nil
}

// userinfo is a password as the link has it, with any ":" in it: URLs
// would read it as a username and a password.
func userinfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	s := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		s += ":" + pw
	}
	return s
}

func fragment(u *url.URL) string {
	return strings.TrimSpace(u.Fragment)
}

func firstOf(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func isTrue(v string) bool {
	return v == "1" || strings.EqualFold(v, "true")
}

// cutQuery removes ?key=value from a path, e.g. "/ray?ed=2048".
func cutQuery(path, key string) (string, string, bool) {
	p, rawQuery, ok := strings.Cut(path, "?")
	if !ok {
		return path, "", false
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get(key) == "" {
		return path, "", false
	}
	v := q.Get(key)
	q.Del(key)
	if rest := q.Encode(); rest != "" {
		p += "?" + rest
	}
	return p, v, true
}

func withPrefix(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	if a := net.ParseIP(ip); a != nil {
		if a.To4() != nil {
			return ip + "/32"
		}
		return ip + "/128"
	}
	return ip
}

// decodeBase64 accepts standard and URL-safe base64, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("不是有效的 base64")
}

// DecodeBase64 is decodeBase64 for subscription bodies.
func DecodeBase64(s string) ([]byte, error) { return decodeBase64(s) }

func short(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// xhttpExtra reads xray's extra: xhttpSettings beyond the link's own
// parameters, in xray's names, into mihomo's; downloadSettings is a
// stream of its own.
func xhttpExtra(s *proto.Spec, tr *proto.Transport, extra string) {
	var x map[string]any
	if err := json.Unmarshal([]byte(extra), &x); err != nil {
		s.Unknown = append(s.Unknown, "extra（不是 JSON）")
		return
	}
	mihomo := map[string]string{}
	for k, v := range proto.XHTTPKeys {
		mihomo[v] = k
	}
	var rename func(m map[string]any, at string) map[string]any
	rename = func(m map[string]any, at string) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			name, ok := mihomo[k]
			if !ok {
				s.Unknown = append(s.Unknown, "extra."+at+k)
				continue
			}
			if sub, ok := v.(map[string]any); ok {
				v = rename(sub, at+k+".")
			}
			out[name] = v
		}
		return out
	}
	for _, k := range []string{"host", "path", "mode"} {
		if v, ok := x[k].(string); ok && v != "" {
			*map[string]*string{"host": &tr.Host, "path": &tr.Path, "mode": &tr.Mode}[k] = v
		}
		delete(x, k)
	}
	if h, ok := x["headers"].(map[string]any); ok {
		for k, v := range h {
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers[k] = fmt.Sprint(v)
		}
	}
	delete(x, "headers")
	if d, ok := x["downloadSettings"].(map[string]any); ok {
		tr.Download = xrayDownload(s, d, rename)
	}
	delete(x, "downloadSettings")
	if len(x) > 0 {
		tr.XHTTPExtra = rename(x, "")
	}
}

// xrayDownload reads xray's downloadSettings, a stream with an address.
func xrayDownload(s *proto.Spec, d map[string]any, rename func(map[string]any, string) map[string]any) *proto.XHTTPDownload {
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	sub := func(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
	dl := &proto.XHTTPDownload{Server: cmpOr(str(d, "address"), s.Server), Port: s.Port}
	if p, ok := d["port"].(float64); ok {
		dl.Port = int(p)
	}
	if x := sub(d, "xhttpSettings"); x != nil {
		dl.Path, dl.Host = str(x, "path"), str(x, "host")
		if h := sub(x, "headers"); h != nil {
			dl.Headers = map[string]string{}
			for k, v := range h {
				dl.Headers[k] = fmt.Sprint(v)
			}
		}
		if m := sub(x, "xmux"); m != nil {
			dl.Extra = map[string]any{"reuse-settings": rename(m, "downloadSettings.xhttpSettings.xmux.")}
		}
	}
	switch str(d, "security") {
	case "tls":
		t := sub(d, "tlsSettings")
		dl.TLS = &proto.TLS{SNI: str(t, "serverName"), Fingerprint: str(t, "fingerprint"), PinSHA256: str(t, "pinnedPeerCertSha256")}
		if a, ok := t["alpn"].([]any); ok {
			for _, v := range a {
				dl.TLS.ALPN = append(dl.TLS.ALPN, fmt.Sprint(v))
			}
		}
	case "reality":
		r := sub(d, "realitySettings")
		dl.TLS = &proto.TLS{SNI: str(r, "serverName"), Fingerprint: str(r, "fingerprint"),
			Reality: &proto.Reality{PublicKey: cmpOr(str(r, "publicKey"), str(r, "password")), ShortID: str(r, "shortId"), SpiderX: str(r, "spiderX")}}
	}
	return dl
}

// rest reports the query parameters a link parser did not use.
func rest(s *proto.Spec, q url.Values, used ...string) {
	var unknown []string
	for k := range q {
		if !slices.Contains(used, k) {
			unknown = append(unknown, k)
		}
	}
	slices.Sort(unknown)
	s.Unknown = append(s.Unknown, unknown...)
}

// tuic://uuid:password@host:port?sni=…&alpn=h3&congestion_control=bbr&udp_relay_mode=native
// (v5), or tuic://token@host:port (v4), as mihomo reads them.
func tuic(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "tuic", UDP: true, TUIC: &proto.TUIC{}}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	if pw, ok := u.User.Password(); ok {
		s.UUID, s.Password = u.User.Username(), pw
	} else {
		s.TUIC.Token = u.User.Username()
	}
	q := u.Query()
	s.TUIC.Congestion, s.TUIC.UDPRelayMode = q.Get("congestion_control"), q.Get("udp_relay_mode")
	s.TUIC.Heartbeat = 10000 // mihomo's default
	s.TLS = &proto.TLS{SNI: q.Get("sni"), Insecure: isTrue(firstOf(q, "allow_insecure", "insecure")), DisableSNI: q.Get("disable_sni") == "1",
		ALPN: []string{"h3"}}
	if a := q.Get("alpn"); a != "" {
		s.TLS.ALPN = strings.Split(a, ",")
	}
	rest(s, q, "congestion_control", "udp_relay_mode", "sni", "allow_insecure", "insecure", "disable_sni", "alpn")
	return fragment(u), s, nil
}

// hysteria://host:port?auth=…&peer=sni&obfs=…&upmbps=…&downmbps=…&protocol=udp (v1)
func hysteriaV1(link string) (string, *proto.Spec, error) {
	link, hop := splitHopPorts(link)
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	q := u.Query()
	s := &proto.Spec{Type: "hysteria", UDP: true, Password: q.Get("auth"),
		Hysteria: &proto.Hysteria{ObfsPassword: q.Get("obfs"), Protocol: q.Get("protocol"), Ports: cmpOr(q.Get("mport"), hop), HopMin: 10, HopMax: 10}}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	for _, b := range []struct {
		to   *uint64
		keys []string
	}{{&s.Hysteria.Up, []string{"up", "upmbps"}}, {&s.Hysteria.Down, []string{"down", "downmbps"}}} {
		if v := firstOf(q, b.keys...); v != "" {
			bits, ok := proto.ParseBandwidth(v)
			if !ok {
				s.Unknown = append(s.Unknown, b.keys[0]+"="+v)
			}
			*b.to = bits
		}
	}
	s.TLS = &proto.TLS{SNI: q.Get("peer"), Insecure: isTrue(q.Get("insecure")), ALPN: []string{"hysteria"}}
	if a := q.Get("alpn"); a != "" {
		s.TLS.ALPN = strings.Split(a, ",")
	}
	rest(s, q, "auth", "obfs", "protocol", "mport", "up", "upmbps", "down", "downmbps", "peer", "insecure", "alpn")
	return fragment(u), s, nil
}

// anytls://password@host:port?sni=…&insecure=1&hpkp=<certificate sha256>
func anytls(link string) (string, *proto.Spec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, err
	}
	s := &proto.Spec{Type: "anytls", UDP: true, Password: userinfo(u), AnyTLS: &proto.AnyTLS{}}
	if err := hostPort(s, u); err != nil {
		return "", nil, err
	}
	q := u.Query()
	s.TLS = &proto.TLS{SNI: q.Get("sni"), Insecure: isTrue(q.Get("insecure")), PinSHA256: q.Get("hpkp"), Fingerprint: q.Get("fp")}
	rest(s, q, "sni", "insecure", "hpkp", "fp")
	return fragment(u), s, nil
}
