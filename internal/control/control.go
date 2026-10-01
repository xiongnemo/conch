// Package control talks to running kernels: it knows how to start,
// validate and reload each kernel and how to switch groups at runtime.
package control

import (
	"context"
	"errors"
	"time"

	"nautilus/internal/kernel"
)

// ErrRestart means the kernel cannot apply a config in place.
var ErrRestart = errors.New("需要重启内核才能生效")

// ErrUnsupported means the kernel has no way to do something.
var ErrUnsupported = errors.New("当前内核不支持这个操作")

// Traffic is the throughput over the last second, in bytes.
type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Kernel controls one kind of kernel. Paths are absolute.
type Kernel interface {
	Name() string
	ConfigFile() string // file name inside the kernel's home
	Spec(bin, home, config string) kernel.Spec
	Validate(ctx context.Context, bin, home, config string) error
	// Ready reports whether the kernel's API answers.
	Ready(ctx context.Context) bool
	// Reload applies a new config in place, or returns ErrRestart.
	Reload(ctx context.Context, config []byte, forceListeners bool) error
	// Select chooses the member of a select group. tag is the member's
	// identifier in the kernel, which may differ from its name.
	Select(ctx context.Context, group, tag string) error
	// Delay measures latency through an outbound.
	Delay(ctx context.Context, tag, url string, timeout time.Duration) (time.Duration, error)
	// Traffic streams throughput until ctx is done.
	Traffic(ctx context.Context) (<-chan Traffic, error)
	// Connections lists open connections; ErrUnsupported if the kernel cannot.
	Connections(ctx context.Context) ([]Connection, error)
	CloseConnection(ctx context.Context, id string) error
}

// Connection is an open connection as the kernel reports it.
type Connection struct {
	ID          string    `json:"id"`
	Network     string    `json:"network"`
	Host        string    `json:"host"` // domain, or the IP when there is none
	Port        string    `json:"port"`
	Process     string    `json:"process,omitempty"`
	Chains      []string  `json:"chains"`      // outbound first, then the groups that chose it
	Rule        string    `json:"rule"`        // kernel rule type, e.g. DomainSuffix
	RulePayload string    `json:"rulePayload"` // e.g. google.com
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
}
