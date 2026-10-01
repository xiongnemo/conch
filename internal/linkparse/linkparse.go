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

	"nautilus/internal/proto"
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
	q := url.Values{}
	for _, k := range []string{"net", "type", "host", "path", "tls", "sni", "alpn", "fp", "pbk", "sid", "spx", "mode", "serviceName"} {
		if val := str(k); val != "" {
			q.Set(k, val)
		}
	}
	// v2rayN uses "net" for the transport and "type" for its header/mode.
	q.Set("type", str("net"))
	q.Set("headerType", str("type"))
	q.Set("security", str("tls"))
	applyQuery(s, q, false)
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
		s.Password = u.User.Username()
		if q.Get("security") == "" {
			q.Set("security", "tls") // trojan is always TLS
		}
	}
	applyQuery(s, q, true)
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
	if p := u.Query().Get("plugin"); p != "" {
		s.Unknown = append(s.Unknown, "plugin: "+strings.SplitN(p, ";", 2)[0])
	}
	return name, s, nil
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
	s.Password = u.User.Username()
	if pw, ok := u.User.Password(); ok {
		s.Password += ":" + pw
	}
	q := u.Query()
	s.Hysteria.Obfs = q.Get("obfs")
	s.Hysteria.ObfsPassword = q.Get("obfs-password")
	if mport := q.Get("mport"); mport != "" {
		s.Hysteria.Ports = mport
	}
	s.Hysteria.Up, s.Hysteria.Down = bandwidth(q.Get("up")), bandwidth(q.Get("down"))
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
	applyQuery(s, q, true)
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
	for _, a := range strings.Split(firstOf(q, "address", "ip"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			wg.Address = append(wg.Address, withPrefix(a))
		}
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
func applyQuery(s *proto.Spec, q url.Values, report bool) {
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
	case "httpupgrade":
		tr.Host, tr.Path = host, path
	case "grpc":
		tr.ServiceName = get("serviceName")
		get("mode", "authority")
	case "xhttp", "splithttp":
		tr.Network = "xhttp"
		tr.Host, tr.Path, tr.Mode = host, path, get("mode")
		if get("extra") != "" {
			s.Unknown = append(s.Unknown, "extra")
		}
	case "h2", "http":
		tr.Network, tr.Host, tr.Path = "h2", host, path
	}
	s.Transport = tr
	get("headerType", "encryption", "flow", "fragment", "spx")
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
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return fmt.Errorf("端口无效：%q", u.Port())
	}
	s.Port = port
	return nil
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

func bandwidth(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return v + " mbps"
	}
	return v
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
