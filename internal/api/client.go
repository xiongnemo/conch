package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"nautilus/internal/auth"
	"nautilus/internal/daemon"
	"nautilus/internal/view"
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
var ErrNotRunning = errors.New("nautilus daemon 没有在运行")

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
	if ttl > 0 {
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

func (c *Client) Delay(ctx context.Context, name string) (time.Duration, error) {
	var v struct {
		Delay int64 `json:"delay"`
	}
	err := c.do(ctx, http.MethodPost, "/api/v1/delay", map[string]string{"name": name}, &v)
	return time.Duration(v.Delay) * time.Millisecond, err
}

func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/mode", map[string]string{"mode": mode}, nil)
}

func (c *Client) SetSysProxy(ctx context.Context, on bool) error {
	return c.do(ctx, http.MethodPut, "/api/v1/sysproxy", map[string]bool{"enabled": on}, nil)
}

func (c *Client) UpdateSubscription(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/subscriptions/"+url.PathEscape(name)+"/update", nil, nil)
}

func (c *Client) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/kernel/restart", nil, nil)
}

// String helps error messages mention where the daemon was expected.
func (c *Client) String() string { return fmt.Sprintf("nautilus daemon（%s）", c.Base) }
