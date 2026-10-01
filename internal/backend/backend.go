// Package backend defines what a kernel backend must provide to turn a
// compiled profile into kernel configuration.
package backend

import (
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/route"
)

// Router is a primary kernel: it owns inbounds, routing, DNS and TUN.
type Router interface {
	Name() string
	Capabilities() Capabilities
	Encode(r *compile.Result, opts Options) (*Artifact, error)
}

// Options are runtime settings that are not part of the user's profile.
type Options struct {
	// ControllerUnix is a unix socket for the kernel API. Kernels do not
	// authenticate it, so it must live in a directory only nautilus can access.
	ControllerUnix string
	// ControllerPipe is the Windows named-pipe equivalent of ControllerUnix.
	ControllerPipe string
	// Controller is a TCP address for the kernel API, for debugging only.
	Controller string
}

// Artifact is an encoded kernel configuration.
type Artifact struct {
	Config   []byte
	Manifest *Manifest
}

// Capabilities describes which profile features a backend can express.
type Capabilities struct {
	ProcessMatch bool // app: entries
	KeywordMatch bool // ~keyword entries
	RawClash     bool // { clash: [...] } list items
	Chains       bool
}

// Check reports profile features the backend cannot express, so users get
// a clear error instead of a broken kernel configuration.
func Check(r *compile.Result, caps Capabilities, backendName string) diag.List {
	var d diag.List
	for _, rule := range r.Rules {
		switch {
		case (rule.Match == route.MatchProcessName || rule.Match == route.MatchProcessPath) && !caps.ProcessMatch:
			d.Errorf(rule.Origin.Pos, "%s 后端不支持按应用分流（%s）", backendName, rule.Origin.Key)
		case rule.Match == route.MatchDomainKeyword && !caps.KeywordMatch:
			d.Errorf(rule.Origin.Pos, "%s 后端不支持关键词条目（%s）", backendName, rule.Origin.Key)
		case rule.Match == route.MatchRaw && !caps.RawClash:
			d.Errorf(rule.Origin.Pos, "%s 后端不支持 clash 原始规则", backendName)
		}
	}
	if len(r.Chains) > 0 && !caps.Chains {
		d.Errorf(r.Chains[0].Pos, "%s 后端不支持链式代理", backendName)
	}
	return d
}

// Manifest maps emitted objects back to what the user wrote, so runtime
// data (connections, latencies) can be explained in the user's terms.
type Manifest struct {
	Backend string          `json:"backend"`
	Proxies []ManifestProxy `json:"proxies"`
	Rules   []ManifestRule  `json:"rules"`
}

type ManifestProxy struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // node | chain-hop | chain-exit
	Node     string `json:"node"` // source node
	Chain    string `json:"chain,omitempty"`
	Hop      int    `json:"hop,omitempty"`
	Upstream string `json:"upstream,omitempty"`
}

type ManifestRule struct {
	Index   int    `json:"index"`
	Rule    string `json:"rule"` // as emitted
	Tier    string `json:"tier"`
	Key     string `json:"key"`
	Source  string `json:"source,omitempty"` // file:line
	Builtin bool   `json:"builtin,omitempty"`
}

// ProxyManifest builds the backend-independent part of a manifest.
func ProxyManifest(r *compile.Result) []ManifestProxy {
	kinds := map[compile.ProxyKind]string{
		compile.ProxyNode:      "node",
		compile.ProxyChainHop:  "chain-hop",
		compile.ProxyChainExit: "chain-exit",
	}
	var out []ManifestProxy
	for _, p := range r.Proxies {
		out = append(out, ManifestProxy{
			Name:     p.Name,
			Kind:     kinds[p.Kind],
			Node:     p.Node.Name,
			Chain:    p.Chain,
			Hop:      p.Hop,
			Upstream: p.Upstream,
		})
	}
	return out
}
