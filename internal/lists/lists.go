// Package lists downloads, caches and parses rule lists for kernels that
// cannot fetch Clash rule-providers themselves.
package lists

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
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
	// Exception marks AutoProxy "@@" rules: matching traffic is excluded
	// from the list and goes direct.
	Exception bool
}

// Select returns the entries whose Exception flag equals exceptions.
func Select(entries []Entry, exceptions bool) []Entry {
	var out []Entry
	for _, e := range entries {
		if e.Exception == exceptions {
			out = append(out, e)
		}
	}
	return out
}

// Parse decodes a Clash rule-provider file. skipped lists entries no
// backend-neutral entry exists for, so callers can tell the user.
func Parse(data []byte, format, behavior string) (entries []Entry, skipped []string, err error) {
	var lines []string
	switch format {
	case "autoproxy":
		return parseAutoProxy(data)
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

// parseAutoProxy parses an AutoProxy list such as gfwlist, which is often
// base64-encoded. Rules are reduced to host matches; URL-path and regex
// rules cannot be expressed that way and are skipped.
func parseAutoProxy(data []byte) ([]Entry, []string, error) {
	text := string(data)
	if !strings.Contains(text, "[AutoProxy") && !strings.Contains(text, "||") {
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return nil, nil, fmt.Errorf("不是 AutoProxy 格式的列表")
		}
		text = string(decoded)
	}
	var entries []Entry
	var skipped []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		rule, exception := strings.CutPrefix(line, "@@")
		var host string
		suffix := true
		switch {
		case strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/"):
			skipped = append(skipped, line) // URL regex
			continue
		case strings.HasPrefix(rule, "||"):
			host = rule[2:]
		case strings.HasPrefix(rule, "|"):
			u, err := url.Parse(rule[1:])
			if err != nil || u.Hostname() == "" {
				skipped = append(skipped, line)
				continue
			}
			host, suffix = u.Hostname(), false
		default:
			host = strings.TrimPrefix(rule, ".")
		}
		host = strings.ToLower(strings.TrimSuffix(strings.SplitN(host, "/", 2)[0], "^"))
		if host == "" || strings.ContainsAny(host, "*?:%") || !strings.Contains(host, ".") {
			skipped = append(skipped, line)
			continue
		}
		e := Entry{Kind: DomainSuffix, Value: host, Exception: exception}
		if ip, ok := ipEntry(host); ok {
			e = Entry{Kind: IPCIDR, Value: ip.Value, Exception: exception}
		} else if !suffix {
			e.Kind = Domain
		}
		entries = append(entries, e)
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
		return Entry{Kind: DomainSuffix, Value: strings.ToLower(s[2:])}, true
	case strings.HasPrefix(s, "*."):
		return Entry{Kind: DomainRegex, Value: `^[^.]+\.` + regexp.QuoteMeta(strings.ToLower(s[2:])) + `$`}, true
	case strings.HasPrefix(s, "."):
		return Entry{Kind: DomainRegex, Value: `\.` + regexp.QuoteMeta(strings.ToLower(s[1:])) + `$`}, true
	case strings.ContainsAny(s, "*+ /,"):
		return Entry{}, false
	default:
		return Entry{Kind: Domain, Value: strings.ToLower(s)}, true
	}
}

func ipEntry(s string) (Entry, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return Entry{Kind: IPCIDR, Value: p.Masked().String()}, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return Entry{Kind: IPCIDR, Value: netip.PrefixFrom(a, a.BitLen()).String()}, true
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
		return Entry{Kind: Domain, Value: strings.ToLower(value)}, true
	case "DOMAIN-SUFFIX":
		return Entry{Kind: DomainSuffix, Value: strings.ToLower(value)}, true
	case "DOMAIN-KEYWORD":
		return Entry{Kind: DomainKeyword, Value: strings.ToLower(value)}, true
	case "DOMAIN-REGEX":
		if _, err := regexp.Compile(value); err != nil {
			return Entry{}, false
		}
		return Entry{Kind: DomainRegex, Value: value}, true
	case "GEOSITE":
		return Entry{Kind: GeoSite, Value: strings.ToLower(value)}, true
	case "IP-CIDR", "IP-CIDR6":
		return ipEntry(value)
	case "GEOIP":
		return Entry{Kind: GeoIP, Value: strings.ToLower(value)}, true
	case "PROCESS-NAME":
		return Entry{Kind: ProcessName, Value: value}, true
	case "PROCESS-PATH":
		return Entry{Kind: ProcessPath, Value: value}, true
	case "DST-PORT":
		return Entry{Kind: DstPort, Value: value}, true
	case "NETWORK":
		return Entry{Kind: Network, Value: strings.ToLower(value)}, true
	}
	return Entry{}, false
}
