package xray

import (
	"net/netip"
	"regexp"
	"strings"
)

// requiresEncryption reports whether xray refuses an unencrypted VLESS
// outbound to server: it does unless server is a private address
// or a private domain (common/geodata/consts.go in Xray-core v26.11.9).
func requiresEncryption(server string) bool {
	server = strings.TrimSuffix(strings.ToLower(strings.Trim(server, "[]")), ".")
	if ip, err := netip.ParseAddr(server); err == nil {
		ip = ip.Unmap()
		for _, p := range privatePrefixes {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	}
	if dotless.MatchString(server) {
		return false
	}
	for _, d := range privateDomains {
		if server == d || strings.HasSuffix(server, "."+d) {
			return false
		}
	}
	return true
}

var privateDomains = []string{"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal"}

var dotless = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
		"192.0.2.0/24", "192.52.193.0/24", "192.88.99.2/32", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32", "224.0.0.0/4",
		"::1/128", "::/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
		"2001::/32", "2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:2::/48", "2001:3::/32",
		"2001:20::/28", "2001:30::/28", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
		"fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()
