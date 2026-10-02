// Package control talks to running kernels: it knows how to start,
// validate and reload each kernel and how to switch groups at runtime.
package control

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/xiongnemo/conch/internal/kernel"
)

// ErrRestart means the kernel cannot apply a config in place.
var ErrRestart = errors.New("需要重启内核才能生效")

// ErrUnsupported means the kernel has no way to do something.
var ErrUnsupported = errors.New("当前内核不支持这个操作")

// ErrTimeout means a delay test got no response in time.
var ErrTimeout = errors.New("超时")

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
	// Connections lists open connections, or recently opened ones for
	// kernels without LiveConnections.
	Connections(ctx context.Context) ([]Connection, error)
	CloseConnection(ctx context.Context, id string) error
	// Picks returns the member each group currently uses, where the kernel
	// knows. groups maps kernel tags to group types (select, url-test, …);
	// the result maps group tags to member tags.
	Picks(ctx context.Context, groups map[string]string) (map[string]string, error)
	Caps() Caps
	// LogLevel is the least verbose log level ObserveLog needs.
	LogLevel() string
	// ObserveLog reads the kernel's output, one line at a time and in order.
	ObserveLog(line string) LogLine
}

// Resolver is a kernel that looks names up for others the way its rules
// do (mihomo and sing-box, through the Clash API).
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
}

// LogLine is what a line of kernel output says.
type LogLine struct {
	// Level is debug, info, warning or error, comparable across kernels;
	// empty for lines without one.
	Level string
	// Internal lines are about conch's own traffic: API calls and delay tests.
	Internal bool
	// Failure is a connection the kernel could not establish.
	Failure *DialFailure
}

// Caps says what a kernel's runtime API offers, so UIs can leave out the rest.
type Caps struct {
	// LiveConnections means Connections lists the open connections with
	// their traffic. Without it, Connections lists recently opened ones.
	LiveConnections bool `json:"liveConnections"`
	CloseConnection bool `json:"closeConnection"`
}

// DialFailure is a connection the kernel could not establish.
type DialFailure struct {
	Source string // who connected; repeats from one source are retries
	Via    string // the outbound that failed
	Host   string
	Port   string
	Error  string
}

// Connection is an open connection as the kernel reports it.
type Connection struct {
	ID          string    `json:"id"`
	Network     string    `json:"network"`
	Host        string    `json:"host"` // domain, or the IP when there is none
	Port        string    `json:"port"`
	Process     string    `json:"process,omitempty"`
	Chains      []string  `json:"chains"`            // outbound first, then the groups that chose it
	Rule        string    `json:"rule"`              // kernel rule type, e.g. DomainSuffix
	RulePayload string    `json:"rulePayload"`       // e.g. google.com
	RuleTag     string    `json:"ruleTag,omitempty"` // the rule's tag, for kernels that name rules
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
}
