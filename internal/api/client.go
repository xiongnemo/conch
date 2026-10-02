package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xiongnemo/conch/internal/auth"
	"github.com/xiongnemo/conch/internal/daemon"
	"github.com/xiongnemo/conch/internal/view"
)

// Client talks to a running daemon.
type Client struct {
	Base     string
	Password string
	HTTP     *http.Client
}

// NewClient connects to the daemon described by the .env settings.
func NewClient(s auth.Settings) *Client {
	host, port, _ := net.SplitHostPort(s.Listen)
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	if s.TLSCert != "" {
		scheme = "https"
	}
	return &Client{Base: scheme + "://" + net.JoinHostPort(host, port), Password: s.Password, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// APIError is an error reported by the daemon.
type APIError struct {
	Status int
	Body   Error
}

func (e *APIError) Error() string {
	msg := e.Body.Error
	for _, d := range e.Body.Diagnostics {
		msg += "\n" + d
	}
	return msg
}

// ErrNotRunning means no daemon answered.
var ErrNotRunning = errors.New("conch daemon 没有在运行")

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Password != "" {
		req.Header.Set("Authorization", "Bearer "+c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		if json.NewDecoder(resp.Body).Decode(&e.Body) != nil {
			e.Body.Error = resp.Status
		}
		return e
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Status(ctx context.Context) (daemon.Status, error) {
	var s daemon.Status
	return s, c.do(ctx, http.MethodGet, "/api/v1/status", nil, &s)
}

func (c *Client) Routes(ctx context.Context) (view.Table, error) {
	var t view.Table
	return t, c.do(ctx, http.MethodGet, "/api/v1/routes", nil, &t)
}

func (c *Client) SetRoute(ctx context.Context, target, via string, ttl time.Duration) error {
	body := map[string]string{"target": target, "via": via}
	switch {
	case ttl == daemon.ForRun:
		body["ttl"] = "run"
	case ttl > 0:
		body["ttl"] = ttl.String()
	}
	return c.do(ctx, http.MethodPut, "/api/v1/routes", body, nil)
}

func (c *Client) DeleteRoute(ctx context.Context, target string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/routes?target="+url.QueryEscape(target), nil, nil)
}

func (c *Client) Explain(ctx context.Context, target, app string) (view.Explanation, error) {
	var v view.Explanation
	q := url.Values{"target": {target}}
	if app != "" {
		q.Set("app", app)
	}
	return v, c.do(ctx, http.MethodGet, "/api/v1/route/explain?"+q.Encode(), nil, &v)
}

func (c *Client) Outbounds(ctx context.Context) ([]daemon.Outbound, error) {
	var o []daemon.Outbound
	return o, c.do(ctx, http.MethodGet, "/api/v1/outbounds", nil, &o)
}

func (c *Client) Select(ctx context.Context, group, member string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/groups/"+url.PathEscape(group), map[string]string{"selected": member}, nil)
}

// Delay is the result of a delay test.
type Delay struct {
	Delay int64             `json:"delay"` // milliseconds; 0 when the test failed
	Error string            `json:"error,omitempty"`
	Hops  []daemon.HopDelay `json:"hops,omitempty"` // for chains: through each hop
}

// Delay measures latency through an outbound. For chains it also
// measures each hop, and a failed end-to-end test is reported in the
// result rather than as an error.
func (c *Client) SetChain(ctx context.Context, name string, hops []string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/chains/"+url.PathEscape(name), map[string][]string{"hops": hops}, nil)
}

func (c *Client) DeleteChain(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/chains/"+url.PathEscape(name), nil, nil)
}

// AddNode adds a node from a share link and returns its name.
func (c *Client) AddNode(ctx context.Context, link string) (string, error) {
	var v struct {
		Name string `json:"name"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/nodes", map[string]string{"link": link}, &v)
	return v.Name, err
}

func (c *Client) DeleteNode(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/nodes/"+url.PathEscape(name), nil, nil)
}

func (c *Client) Delay(ctx context.Context, name string) (Delay, error) {
	var v Delay
	err := c.do(ctx, http.MethodPost, "/api/v1/delay", map[string]string{"name": name}, &v)
	return v, err
}

func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/mode", map[string]string{"mode": mode}, nil)
}

func (c *Client) SetSysProxy(ctx context.Context, on bool) error {
	return c.do(ctx, http.MethodPut, "/api/v1/sysproxy", map[string]bool{"enabled": on}, nil)
}

func (c *Client) SetTUN(ctx context.Context, on bool) error {
	return c.do(ctx, http.MethodPut, "/api/v1/tun", map[string]bool{"enabled": on}, nil)
}

func (c *Client) UpdateSubscription(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/subscriptions/"+url.PathEscape(name)+"/update", nil, nil)
}

func (c *Client) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/kernel/restart", nil, nil)
}

func (c *Client) Logs(ctx context.Context) ([]string, error) {
	var l []string
	return l, c.do(ctx, http.MethodGet, "/api/v1/logs", nil, &l)
}

func (c *Client) Connections(ctx context.Context) ([]daemon.Connection, error) {
	var l []daemon.Connection
	return l, c.do(ctx, http.MethodGet, "/api/v1/connections", nil, &l)
}

func (c *Client) CloseConnection(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/connections/"+url.PathEscape(id), nil, nil)
}

func (c *Client) Failed(ctx context.Context) ([]daemon.Failed, error) {
	var l []daemon.Failed
	return l, c.do(ctx, http.MethodGet, "/api/v1/failed", nil, &l)
}

func (c *Client) ClearFailed(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/failed", nil, nil)
}

// Suggest proposes route targets for a host, the registrable domain first.
func (c *Client) Suggest(ctx context.Context, host string) ([]string, error) {
	var l []string
	return l, c.do(ctx, http.MethodGet, "/api/v1/suggest?host="+url.QueryEscape(host), nil, &l)
}

// PairCode issues a code a browser extension can pair with.
func (c *Client) PairCode(ctx context.Context) (string, time.Time, error) {
	var v struct {
		Code    string    `json:"code"`
		Expires time.Time `json:"expires"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/pair/code", nil, &v)
	return v.Code, v.Expires, err
}

func (c *Client) Pairings(ctx context.Context) ([]auth.Pairing, error) {
	var l []auth.Pairing
	return l, c.do(ctx, http.MethodGet, "/api/v1/pairings", nil, &l)
}

func (c *Client) RevokePairing(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/pairings/"+url.PathEscape(id), nil, nil)
}

// Event is one server-sent event: a state change, a traffic sample or a log line.
type Event struct {
	Type string
	Data json.RawMessage
}

// Events streams the daemon's events until ctx is done or the
// connection drops; the channel is closed then.
func (c *Client) Events(ctx context.Context) (<-chan Event, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/api/v1/events", nil)
	if err != nil {
		return nil, err
	}
	if c.Password != "" {
		req.Header.Set("Authorization", "Bearer "+c.Password)
	}
	stream := &http.Client{Transport: c.HTTP.Transport} // no timeout: the stream stays open
	resp, err := stream.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil, ErrNotRunning
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		e := &APIError{Status: resp.StatusCode}
		if json.NewDecoder(resp.Body).Decode(&e.Body) != nil {
			e.Body.Error = resp.Status
		}
		return nil, e
	}
	ch := make(chan Event, 16)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 4<<20)
		var ev Event
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.Type != "" {
					select {
					case ch <- ev:
					case <-ctx.Done():
						return
					}
				}
				ev = Event{}
			case strings.HasPrefix(line, "event: "):
				ev.Type = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.Data = append(ev.Data, strings.TrimPrefix(line, "data: ")...)
			}
		}
	}()
	return ch, nil
}

// String helps error messages mention where the daemon was expected.
func (c *Client) String() string { return fmt.Sprintf("conch daemon（%s）", c.Base) }
