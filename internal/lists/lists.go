// Package lists downloads, caches and parses rule lists for kernels that
// cannot fetch Clash rule-providers themselves.
package lists

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Kind is what a list entry matches on.
type Kind int

const (
	Domain       Kind = iota // exact host
	DomainSuffix             // host and its subdomains
	DomainKeyword
	DomainRegex
	GeoSite
	IPCIDR
	GeoIP
	ProcessName
	ProcessPath
	DstPort
	Network
)

// Entry is one item of a rule list.
type Entry struct {
	Kind  Kind
	Value string
}

// Parse decodes a Clash rule-provider file. skipped lists entries no
// backend-neutral entry exists for, so callers can tell the user.
func Parse(data []byte, format, behavior string) (entries []Entry, skipped []string, err error) {
	var lines []string
	switch format {
	case "yaml":
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, nil, fmt.Errorf("规则列表不是有效的 YAML：%w", err)
		}
		lines = doc.Payload
	case "text":
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("无法解析 %s 格式的规则列表", format)
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		var e Entry
		var ok bool
		switch behavior {
		case "domain":
			e, ok = domainEntry(line)
		case "ipcidr":
			e, ok = ipEntry(line)
		case "classical":
			e, ok = classicalEntry(line)
		default:
			return nil, nil, fmt.Errorf("不认识的 behavior %q", behavior)
		}
		if ok {
			entries = append(entries, e)
		} else {
			skipped = append(skipped, line)
		}
	}
	if len(entries) == 0 {
		return nil, skipped, fmt.Errorf("规则列表是空的")
	}
	return entries, skipped, nil
}

// domainEntry parses mihomo's domain-behavior syntax: "+.x" is x and its
// subdomains, ".x" only subdomains, "*.x" exactly one more label, and a
// plain name is exact.
func domainEntry(s string) (Entry, bool) {
	switch {
	case strings.HasPrefix(s, "+."):
		return Entry{DomainSuffix, strings.ToLower(s[2:])}, true
	case strings.HasPrefix(s, "*."):
		return Entry{DomainRegex, `^[^.]+\.` + regexp.QuoteMeta(strings.ToLower(s[2:])) + `$`}, true
	case strings.HasPrefix(s, "."):
		return Entry{DomainRegex, `\.` + regexp.QuoteMeta(strings.ToLower(s[1:])) + `$`}, true
	case strings.ContainsAny(s, "*+ /,"):
		return Entry{}, false
	default:
		return Entry{Domain, strings.ToLower(s)}, true
	}
}

func ipEntry(s string) (Entry, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return Entry{IPCIDR, p.Masked().String()}, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return Entry{IPCIDR, netip.PrefixFrom(a, a.BitLen()).String()}, true
	}
	return Entry{}, false
}

// classicalEntry parses a Clash rule line without its target, such as
// "DOMAIN-SUFFIX,google.com" or "IP-CIDR,1.0.0.0/8,no-resolve".
func classicalEntry(s string) (Entry, bool) {
	typ, value, ok := strings.Cut(s, ",")
	if !ok {
		return Entry{}, false
	}
	value, _, _ = strings.Cut(value, ",") // drop options such as no-resolve
	value = strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "DOMAIN":
		return Entry{Domain, strings.ToLower(value)}, true
	case "DOMAIN-SUFFIX":
		return Entry{DomainSuffix, strings.ToLower(value)}, true
	case "DOMAIN-KEYWORD":
		return Entry{DomainKeyword, strings.ToLower(value)}, true
	case "DOMAIN-REGEX":
		if _, err := regexp.Compile(value); err != nil {
			return Entry{}, false
		}
		return Entry{DomainRegex, value}, true
	case "GEOSITE":
		return Entry{GeoSite, strings.ToLower(value)}, true
	case "IP-CIDR", "IP-CIDR6":
		return ipEntry(value)
	case "GEOIP":
		return Entry{GeoIP, strings.ToLower(value)}, true
	case "PROCESS-NAME":
		return Entry{ProcessName, value}, true
	case "PROCESS-PATH":
		return Entry{ProcessPath, value}, true
	case "DST-PORT":
		return Entry{DstPort, value}, true
	case "NETWORK":
		return Entry{Network, strings.ToLower(value)}, true
	}
	return Entry{}, false
}
