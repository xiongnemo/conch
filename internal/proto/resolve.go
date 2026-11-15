package proto

import (
	"net/url"
	"strconv"
)

// Resolve spells out what mihomo does with a node whose keys are left
// out or say more than they seem to, so that kernels which need it
// written down do the same. The unified format is mihomo's; these are
// its implicit rules (adapter/outbound and transport/vmess in mihomo):
//
//   - a WebSocket path with ?ed=N means N bytes of early data in the
//     Sec-WebSocket-Protocol header;
//   - VMess and VLESS over WebSocket with TLS speak http/1.1 and, without
//     a servername, send the Host header as SNI; over h2 and gRPC, h2;
//   - Trojan offers h2 and http/1.1 unless told otherwise, http/1.1 over
//     WebSocket, h2 over gRPC, and its WebSocket Host is the SNI;
//   - TCP with HTTP headers asks for "/" with GET, Host being the server;
//   - WireGuard's MTU is 1408.
//
// Backends that encode from a Spec call it; ToClash does not need it.
func (s *Spec) Resolve() {
	t := &s.Transport
	if (t.Network == "ws" || t.Network == "httpupgrade") && t.Path != "" {
		if u, err := url.Parse(t.Path); err == nil {
			q := u.Query()
			if ed, err := strconv.Atoi(q.Get("ed")); err == nil && ed > 0 {
				t.EarlyData, t.EarlyDataHeader = ed, "Sec-WebSocket-Protocol"
				q.Del("ed")
				u.RawQuery = q.Encode()
				t.Path = u.String()
			}
		}
	}
	if tls := s.TLS; tls != nil && tls.Reality == nil {
		switch s.Type {
		case "vmess", "vless":
			switch t.Network {
			case "ws", "httpupgrade":
				tls.ALPN = []string{"http/1.1"}
				if tls.SNI == "" {
					tls.SNI = t.Host
				}
			case "h2", "grpc":
				tls.ALPN = []string{"h2"}
			}
		case "trojan":
			switch t.Network {
			case "ws", "httpupgrade":
				if tls.ALPN == nil {
					tls.ALPN = []string{"http/1.1"}
				}
				if t.Host == "" {
					t.Host = tls.SNI
				}
			case "grpc":
				tls.ALPN = []string{"h2"}
			case "":
				if tls.ALPN == nil {
					tls.ALPN = []string{"h2", "http/1.1"}
				}
			}
		}
	}
	if t.Network == "http" {
		if t.Method == "" {
			t.Method = "GET"
		}
		if len(t.Paths) == 0 {
			t.Paths = []string{cmpOr(t.Path, "/")}
		}
		t.Path = t.Paths[0]
		if len(t.Hosts) == 0 {
			t.Hosts = []string{cmpOr(t.Host, s.Server)}
		}
		t.Host = t.Hosts[0]
	}
	if s.WireGuard != nil && s.WireGuard.MTU == 0 {
		s.WireGuard.MTU = 1408
	}
	if s.Hysteria != nil && s.Hysteria.HopMax < s.Hysteria.HopMin {
		s.Hysteria.HopMax = s.Hysteria.HopMin
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
