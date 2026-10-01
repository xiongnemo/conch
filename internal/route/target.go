// Package route turns the user's routing table into an ordered, backend
// neutral rule list. Manual entries are ranked purely by specificity, so the
// order they are written in never changes the result.
package route

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Kind is what a manual entry matches on.
type Kind int

const (
	KindAppPath Kind = iota
	KindApp
	KindDomain       // exact host, written "=example.com"
	KindDomainSuffix // host and all subdomains, written "example.com" or "*.example.com"
	KindKeyword      // substring of the host, written "~keyword"
	KindIP           // IP address or CIDR
)

// Target is a parsed entry key.
type Target struct {
	Kind   Kind
	Value  string       // normalized domain / keyword / process, or canonical CIDR
	Prefix netip.Prefix // KindIP only
}

// Key renders the target back in profile syntax; equal targets render equally.
func (t Target) Key() string {
	switch t.Kind {
	case KindApp, KindAppPath:
		return "app:" + t.Value
	case KindDomain:
		return "=" + t.Value
	case KindKeyword:
		return "~" + t.Value
	default:
		return t.Value
	}
}

// ParseTarget parses an entry key. note is non-empty when the key was
// accepted but normalized in a way the user may want to know about.
func ParseTarget(key string) (t Target, note string, err error) {
	k := strings.TrimSpace(key)
	if k == "" {
		return t, "", fmt.Errorf("目标不能为空")
	}
	if strings.Contains(k, ",") {
		return t, "", fmt.Errorf("目标 %q 不能包含逗号", key)
	}
	switch {
	case len(k) >= 4 && strings.EqualFold(k[:4], "app:"):
		v := strings.TrimSpace(k[4:])
		if v == "" {
			return t, "", fmt.Errorf("app: 后面需要写应用名，例如 app:Telegram")
		}
		if strings.ContainsAny(v, `/\`) {
			return Target{Kind: KindAppPath, Value: v}, "", nil
		}
		return Target{Kind: KindApp, Value: v}, "", nil
	case strings.HasPrefix(k, "="):
		d, err := normDomain(k[1:])
		if err != nil {
			return t, "", err
		}
		return Target{Kind: KindDomain, Value: d}, "", nil
	case strings.HasPrefix(k, "~"):
		kw := strings.ToLower(strings.TrimSpace(k[1:]))
		if kw == "" {
			return t, "", fmt.Errorf("~ 后面需要写关键词，例如 ~google")
		}
		return Target{Kind: KindKeyword, Value: kw}, "", nil
	}
	if p, err := netip.ParsePrefix(k); err == nil {
		m := p.Masked()
		if m != p {
			note = fmt.Sprintf("%s 不是网段起始地址，已按 %s 处理", k, m)
		}
		return Target{Kind: KindIP, Value: m.String(), Prefix: m}, note, nil
	}
	if a, err := netip.ParseAddr(k); err == nil {
		if a.Zone() != "" {
			return t, "", fmt.Errorf("IP 地址 %q 不能带网卡后缀", key)
		}
		a = a.Unmap()
		p := netip.PrefixFrom(a, a.BitLen())
		return Target{Kind: KindIP, Value: p.String(), Prefix: p}, "", nil
	}
	s := strings.TrimPrefix(k, "*.")
	s = strings.TrimPrefix(s, ".")
	d, err := normDomain(s)
	if err != nil {
		return t, "", err
	}
	return Target{Kind: KindDomainSuffix, Value: d}, "", nil
}

var domainProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

func normDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" || strings.ContainsAny(s, " /:*?#@") {
		return "", fmt.Errorf("%q 不是有效的域名", s)
	}
	d, err := domainProfile.ToASCII(s)
	if err != nil || d == "" {
		return "", fmt.Errorf("%q 不是有效的域名", s)
	}
	return d, nil
}

// labels counts domain labels; more labels means more specific.
func labels(domain string) int {
	return strings.Count(domain, ".") + 1
}
