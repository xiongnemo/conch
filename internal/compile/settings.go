package compile

import (
	"slices"
	"strings"

	"nautilus/internal/diag"
)

// Settings are the profile's global options with defaults applied.
type Settings struct {
	MixedPort   int
	AllowLAN    bool
	BindAddress string
	Mode        string // rule | global | direct
	LogLevel    string
	DNS         DNSSettings
	TUN         TUNSettings
}

type DNSSettings struct {
	Enable      bool
	Mode        string // fake-ip | redir-host
	Nameservers []string
	IPv6        bool
}

type TUNSettings struct {
	Enable      bool
	Stack       string // mixed | system | gvisor
	StrictRoute bool
}

const defaultMixedPort = 7890

// Encrypted resolvers reachable by IP, so they work before any proxy is up.
var defaultNameservers = []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"}

func (c *compiler) settings() Settings {
	p := c.p
	s := Settings{
		MixedPort:   p.Inbound.MixedPort,
		AllowLAN:    p.Inbound.AllowLAN,
		BindAddress: p.Inbound.BindAddress,
		Mode:        strings.ToLower(strings.TrimSpace(p.Mode)),
		LogLevel:    strings.ToLower(strings.TrimSpace(p.LogLevel)),
	}
	if s.MixedPort == 0 {
		s.MixedPort = defaultMixedPort
	}
	if s.MixedPort < 1 || s.MixedPort > 65535 {
		c.d.Errorf(diag.Pos{}, "inbound.mixed-port %d 不是有效端口", s.MixedPort)
	}
	if s.Mode == "" {
		s.Mode = "rule"
	}
	if !slices.Contains([]string{"rule", "global", "direct"}, s.Mode) {
		c.d.Errorf(diag.Pos{}, "mode 应该是 rule、global 或 direct，而不是 %q", p.Mode)
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if !slices.Contains([]string{"silent", "error", "warning", "info", "debug"}, s.LogLevel) {
		c.d.Errorf(diag.Pos{}, "log-level 应该是 silent、error、warning、info 或 debug，而不是 %q", p.LogLevel)
	}

	s.TUN = TUNSettings{Enable: p.TUN.Enable, Stack: strings.ToLower(p.TUN.Stack), StrictRoute: p.TUN.StrictRoute}
	if s.TUN.Stack == "" {
		// Always explicit: mihomo's own default changed between releases.
		s.TUN.Stack = "mixed"
	}
	if !slices.Contains([]string{"mixed", "system", "gvisor"}, s.TUN.Stack) {
		c.d.Errorf(diag.Pos{}, "tun.stack 应该是 mixed、system 或 gvisor，而不是 %q", p.TUN.Stack)
	}

	s.DNS = DNSSettings{Enable: s.TUN.Enable, Mode: strings.ToLower(p.DNS.Mode), Nameservers: p.DNS.Nameservers, IPv6: p.DNS.IPv6}
	if p.DNS.Enable != nil {
		if s.TUN.Enable && !*p.DNS.Enable {
			// With TUN, hijacked queries are answered by the kernel's resolver.
			c.d.Errorf(diag.Pos{}, "开启 TUN 时必须开启 DNS（dns.enable 不能为 false）")
		}
		s.DNS.Enable = *p.DNS.Enable || s.TUN.Enable
	}
	if s.DNS.Mode == "" {
		s.DNS.Mode = "redir-host"
		if s.TUN.Enable {
			s.DNS.Mode = "fake-ip"
		}
	}
	if s.DNS.Mode != "fake-ip" && s.DNS.Mode != "redir-host" {
		c.d.Errorf(diag.Pos{}, "dns.mode 应该是 fake-ip 或 redir-host，而不是 %q", p.DNS.Mode)
	}
	if len(s.DNS.Nameservers) == 0 {
		s.DNS.Nameservers = defaultNameservers
	}
	return s
}
