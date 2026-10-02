package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xiongnemo/conch/internal/kernel"
)

// Xray controls xray through its gRPC API, using the xray binary's own
// "xray api" client so conch needs no gRPC stubs. The API is served on
// a unix socket in a private directory.
type Xray struct {
	Bin    string
	Socket string
	// Probes are the inbounds delay tests go through, if the config has them.
	Probes []Probe

	once     sync.Once
	free     chan int // indexes of probes not in use
	sessions sessions
}

// Probe is an HTTP proxy inbound whose balancer can be pointed at any
// outbound, which lets conch measure delays through that outbound.
type Probe struct {
	Tag    string // of the inbound, its routing rule and its balancer
	Socket string
}

// userInbounds are the inbounds clients connect to. Counting them gives the
// traffic users see; outbound counters would count chained traffic once
// per hop and loopback traffic once per group.
var userInbounds = map[string]bool{"›mixed": true, "›tun": true}

func (*Xray) Name() string       { return "xray" }
func (*Xray) ConfigFile() string { return "config.json" }

// Spec runs xray with its geodata (geoip.dat, geosite.dat) in home.
func (*Xray) Spec(bin, home, config string) kernel.Spec {
	return kernel.Spec{Path: bin, Args: []string{"run", "-c", config}, Env: []string{"XRAY_LOCATION_ASSET=" + home}, Dir: home}
}

func (*Xray) Validate(ctx context.Context, bin, home, config string) error {
	cmd := exec.CommandContext(ctx, bin, "run", "-test", "-c", config)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+home)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("Configuration OK")) {
		return fmt.Errorf("xray 不接受生成的配置：%s", lastLines(out, 3))
	}
	return nil
}

func (x *Xray) api(ctx context.Context, args ...string) ([]byte, error) {
	// "unix:" and the path, which gRPC reads as the path also on Windows
	// (unix://C:\… would make C: a host).
	full := append([]string{"api", args[0], "--server=unix:" + x.Socket}, args[1:]...)
	out, err := exec.CommandContext(ctx, x.Bin, full...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("xray api %s：%s", args[0], lastLines(out, 2))
	}
	return out, nil
}

func (x *Xray) Ready(ctx context.Context) bool {
	_, err := x.api(ctx, "lso")
	return err == nil
}

// Reload always needs a restart: xray cannot replace its config in place.
func (*Xray) Reload(context.Context, []byte, bool) error { return ErrRestart }

// Select overrides the balancer that implements a select group; it takes
// effect immediately, without a restart.
func (x *Xray) Select(ctx context.Context, group, tag string) error {
	_, err := x.api(ctx, "bo", "-b", group, tag)
	return err
}

// Delay points a free probe at the outbound and times a request through it.
func (x *Xray) Delay(ctx context.Context, tag, testURL string, timeout time.Duration) (time.Duration, error) {
	if len(x.Probes) == 0 {
		return 0, ErrUnsupported
	}
	x.once.Do(func() {
		x.free = make(chan int, len(x.Probes))
		for i := range x.Probes {
			x.free <- i
		}
	})
	var i int
	select {
	case i = <-x.free:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { x.free <- i }()
	p := x.Probes[i]
	if _, err := x.api(ctx, "bo", "-b", p.Tag, tag); err != nil {
		return 0, err
	}
	return timeRequest(ctx, p.Socket, testURL, timeout)
}

// timeRequest sends a HEAD request through the HTTP proxy on socket, on a
// fresh connection, and returns how long the response took.
func timeRequest(ctx context.Context, socket, testURL string, timeout time.Duration) (time.Duration, error) {
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: "probe"}, nil },
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, testURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := tr.RoundTrip(req)
	switch {
	case ctx.Err() != nil:
		return 0, ErrTimeout
	case err != nil:
		// The probe only sees xray hang up; why is in xray's log.
		return 0, errors.New("连接失败")
	}
	resp.Body.Close()
	// For plain HTTP, xray answers 503 itself when the outbound fails,
	// saying Proxy-Connection: close, which only a proxy says.
	if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Proxy-Connection") == "close" {
		return 0, errors.New("连接失败")
	}
	return time.Since(start), nil
}

// Traffic polls the inbound counters once a second.
func (x *Xray) Traffic(ctx context.Context) (<-chan Traffic, error) {
	ch := make(chan Traffic)
	go func() {
		defer close(ch)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			out, err := x.api(ctx, "statsquery", "-pattern", "inbound>>>", "-reset")
			if err != nil {
				continue
			}
			t, err := sumTraffic(out)
			if err != nil {
				continue
			}
			select {
			case ch <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

func sumTraffic(out []byte) (Traffic, error) {
	var v struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return Traffic{}, err
	}
	var t Traffic
	for _, s := range v.Stat {
		// inbound>>>TAG>>>traffic>>>uplink
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || !userInbounds[parts[1]] {
			continue
		}
		switch parts[3] {
		case "uplink":
			t.Up += s.Value
		case "downlink":
			t.Down += s.Value
		}
	}
	return t, nil
}

// Connections lists recently opened connections, read from xray's log:
// its API has no list of open connections.
func (x *Xray) Connections(context.Context) ([]Connection, error) {
	return x.sessions.recent(time.Now()), nil
}

func (*Xray) CloseConnection(context.Context, string) error { return ErrUnsupported }

func (*Xray) Caps() Caps { return Caps{} }

// Picks reports the members chosen by select groups (the balancer's
// override) and by url-test groups (leastPing's pick). Which member other
// groups use depends on health xray's API does not expose.
func (x *Xray) Picks(ctx context.Context, groups map[string]string) (map[string]string, error) {
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for tag, typ := range groups {
		if typ != "select" && typ != "url-test" {
			continue
		}
		wg.Go(func() {
			raw, err := x.api(ctx, "bi", "-json", tag)
			if err != nil {
				return
			}
			if pick := balancerPick(raw); pick != "" {
				mu.Lock()
				out[tag] = pick
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out, nil
}

func balancerPick(raw []byte) string {
	var v struct {
		Balancer struct {
			Override struct {
				Target string `json:"target"`
			} `json:"override"`
			PrincipleTarget struct {
				Tag []string `json:"tag"`
			} `json:"principleTarget"`
		} `json:"balancer"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	if t := v.Balancer.Override.Target; t != "" {
		return t
	}
	if tags := v.Balancer.PrincipleTarget.Tag; len(tags) == 1 {
		return tags[0]
	}
	return ""
}

// Connections and failures come from the info log.
func (*Xray) LogLevel() string { return "info" }

// ObserveLog follows connections through the log. xray's info level logs
// several lines per connection, about as much as mihomo's debug level, so
// they count as debug; the access log's one line per connection is info.
func (x *Xray) ObserveLog(line string) LogLine {
	m := xrayLine.FindStringSubmatch(line)
	if m == nil {
		if strings.Contains(line, " accepted ") || strings.Contains(line, " rejected ") {
			// Access log: from 127.0.0.1:5000 accepted tcp:example.com:443 [›mixed -> proxy]
			return LogLine{Level: "info", Internal: strings.Contains(line, "[›api") || strings.Contains(line, "[›probe")}
		}
		return LogLine{}
	}
	l := LogLine{Level: map[string]string{"Debug": "debug", "Info": "debug", "Warning": "warning", "Error": "error"}[m[1]]}
	if m[2] != "" {
		l.Failure, l.Internal = x.sessions.observe(m[2], m[3], time.Now())
	}
	return l
}

// sessions follows connections through xray's log. Every line about a
// connection carries its session id:
//
//	[Info] [7] app/dispatcher: Hit route rule: [#3 openai.com] so taking detour [AI] for [tcp:chatgpt.com:443]
//	[Info] [7] app/dispatcher: taking detour [HK 01] for [tcp:chatgpt.com:443]  (a group picks a member)
//	[Info] [8] app/dispatcher: default route for tcp:example.com:443
//	[Warning] [8] app/proxyman/outbound: failed to process outbound traffic > …
type sessions struct {
	mu    sync.Mutex
	byID  map[string]*session
	order []string // oldest first
}

type session struct {
	Connection
	detours  []string // outbounds in the order routing chose them
	internal bool     // conch's own: API calls and delay tests
	failed   bool
}

const (
	keepSessions  = 300
	recentWindow  = 10 * time.Minute
	xrayDefault   = "app/dispatcher: default route for "
	xrayFailedOut = "failed to process outbound traffic > "
)

var (
	xrayLine   = regexp.MustCompile(`\[(Debug|Info|Warning|Error)\] (?:\[(\d+)\] )?(.*)$`)
	xrayRule   = regexp.MustCompile(`^app/dispatcher: Hit route rule: \[([^\]]*)\] so taking detour \[(.*)\] for \[(.*)\]$`)
	xrayDetour = regexp.MustCompile(`^app/dispatcher: taking detour \[(.*)\] for \[(.*)\]$`)
	// Failures to connect, as opposed to connections that broke later.
	dialFailures = []string{"failed to find an available destination", "failed to open connection to",
		"failed to establish connection to server", "failed to create TCP connection", "failed to create UDP connection", "failed to lookup DNS"}
)

// observe reads one log message of session id. It returns the failure
// the message reports and whether the session is conch's own.
func (s *sessions) observe(id, msg string, now time.Time) (*DialFailure, bool) {
	var ruleTag, out, dest string
	routed := true
	if r := xrayRule.FindStringSubmatch(msg); r != nil {
		ruleTag, out, dest = r[1], r[2], r[3]
	} else if r := xrayDetour.FindStringSubmatch(msg); r != nil {
		out, dest = r[1], r[2]
	} else if rest, ok := strings.CutPrefix(msg, xrayDefault); ok {
		dest = rest
	} else {
		routed = false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]*session{}
	}
	ss := s.byID[id]
	if routed {
		if ss == nil {
			ss = &session{Connection: Connection{ID: id, Start: now, RuleTag: ruleTag}}
			ss.Network, ss.Host, ss.Port = splitDestination(dest)
			ss.internal = strings.HasPrefix(ruleTag, "›")
			if ruleTag == "" && out == "" {
				ss.Rule = "Match"
			}
			s.byID[id] = ss
			s.order = append(s.order, id)
			if len(s.order) > keepSessions {
				delete(s.byID, s.order[0])
				s.order = s.order[1:]
			}
		}
		if out != "" {
			ss.detours = append(ss.detours, out)
		}
		return nil, ss.internal
	}
	if ss == nil {
		return nil, false
	}
	// The message names its package twice: "app/proxyman/outbound: app/proxyman/outbound: failed to …".
	_, reason, ok := strings.Cut(msg, xrayFailedOut)
	if !ok || ss.internal || ss.failed || !slices.ContainsFunc(dialFailures, func(f string) bool { return strings.Contains(reason, f) }) {
		return nil, ss.internal
	}
	ss.failed = true
	via := ""
	if n := len(ss.detours); n > 0 {
		via = ss.detours[n-1]
	}
	return &DialFailure{Source: "session " + id, Via: via, Host: ss.Host, Port: ss.Port, Error: reason}, false
}

// recent returns the connections opened in the last few minutes, newest first.
func (s *sessions) recent(now time.Time) []Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Connection{}
	for i := len(s.order) - 1; i >= 0; i-- {
		ss := s.byID[s.order[i]]
		if ss.internal {
			continue
		}
		if now.Sub(ss.Start) > recentWindow {
			break
		}
		c := ss.Connection
		c.Chains = slices.Clone(ss.detours)
		slices.Reverse(c.Chains) // outbound first, like mihomo
		out = append(out, c)
	}
	return out
}

// splitDestination parses xray's "tcp:example.com:443" or "udp:[::1]:53".
func splitDestination(dest string) (network, host, port string) {
	network, addr, _ := strings.Cut(dest, ":")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return network, addr, ""
	}
	return network, host, port
}
