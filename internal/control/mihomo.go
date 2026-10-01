package control

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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nautilus/internal/kernel"
)

// Mihomo controls mihomo through its REST API on a unix socket. mihomo
// does not authenticate the socket, so it must live in a private directory.
type Mihomo struct {
	Socket string
	client *http.Client
}

func NewMihomo(socket string) *Mihomo {
	return &Mihomo{Socket: socket, client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

func (*Mihomo) Name() string       { return "mihomo" }
func (*Mihomo) ConfigFile() string { return "config.yaml" }

func (*Mihomo) Spec(bin, home, config string) kernel.Spec {
	return kernel.Spec{Path: bin, Args: []string{"-d", home, "-f", config}, Dir: home}
}

func (*Mihomo) Validate(ctx context.Context, bin, home, config string) error {
	out, err := exec.CommandContext(ctx, bin, "-t", "-d", home, "-f", config).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("test is successful")) {
		return fmt.Errorf("mihomo 不接受生成的配置：%s", lastLines(out, 3))
	}
	return nil
}

func (m *Mihomo) do(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://mihomo"+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &apiError{Status: resp.StatusCode, Text: fmt.Sprintf("mihomo %s %s：%s %s", method, path, resp.Status, bytes.TrimSpace(msg))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (m *Mihomo) Ready(ctx context.Context) bool {
	var v struct {
		Version string `json:"version"`
	}
	return m.do(ctx, http.MethodGet, "/version", nil, &v) == nil && v.Version != ""
}

// Reload hot-reloads the config. Listeners are only recreated when ports
// changed, so existing connections survive ordinary edits.
func (m *Mihomo) Reload(ctx context.Context, config []byte, forceListeners bool) error {
	path := "/configs"
	if forceListeners {
		path += "?force=true"
	}
	return m.do(ctx, http.MethodPut, path, map[string]string{"payload": string(config)}, nil)
}

func (m *Mihomo) Select(ctx context.Context, group, tag string) error {
	return m.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": tag}, nil)
}

func (m *Mihomo) Delay(ctx context.Context, tag, testURL string, timeout time.Duration) (time.Duration, error) {
	q := url.Values{"url": {testURL}, "timeout": {strconv.Itoa(min(int(timeout.Milliseconds()), 32767))}}
	var v struct {
		Delay int `json:"delay"`
	}
	err := m.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+q.Encode(), nil, &v)
	var e *apiError
	switch {
	case errors.As(err, &e) && e.Status == http.StatusGatewayTimeout:
		return 0, ErrTimeout
	case errors.As(err, &e) && e.Status == http.StatusServiceUnavailable:
		return 0, errors.New("连接失败")
	case err != nil:
		return 0, err
	}
	return time.Duration(v.Delay) * time.Millisecond, nil
}

type apiError struct {
	Status int
	Text   string
}

func (e *apiError) Error() string { return e.Text }

// Traffic reads mihomo's streaming /traffic endpoint (one JSON object per second).
func (m *Mihomo) Traffic(ctx context.Context) (<-chan Traffic, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://mihomo/traffic", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	ch := make(chan Traffic)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var t Traffic
			if json.Unmarshal(sc.Bytes(), &t) != nil {
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

func lastLines(out []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

func (m *Mihomo) Connections(ctx context.Context) ([]Connection, error) {
	var v struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				Network string `json:"network"`
				Host    string `json:"host"`
				DstIP   string `json:"destinationIP"`
				DstPort string `json:"destinationPort"`
				Process string `json:"process"`
			} `json:"metadata"`
			Upload      int64     `json:"upload"`
			Download    int64     `json:"download"`
			Start       time.Time `json:"start"`
			Chains      []string  `json:"chains"`
			Rule        string    `json:"rule"`
			RulePayload string    `json:"rulePayload"`
		} `json:"connections"`
	}
	if err := m.do(ctx, http.MethodGet, "/connections", nil, &v); err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(v.Connections))
	for _, c := range v.Connections {
		host := c.Metadata.Host
		if host == "" {
			host = c.Metadata.DstIP
		}
		out = append(out, Connection{
			ID: c.ID, Network: c.Metadata.Network, Host: host, Port: c.Metadata.DstPort, Process: c.Metadata.Process,
			Chains: c.Chains, Rule: c.Rule, RulePayload: c.RulePayload, Upload: c.Upload, Download: c.Download, Start: c.Start,
		})
	}
	return out, nil
}

func (m *Mihomo) CloseConnection(ctx context.Context, id string) error {
	return m.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

func (*Mihomo) Caps() Caps { return Caps{LiveConnections: true, CloseConnection: true} }

func (m *Mihomo) Picks(ctx context.Context, groups map[string]string) (map[string]string, error) {
	var v struct {
		Proxies map[string]struct {
			Now string `json:"now"`
		} `json:"proxies"`
	}
	if err := m.do(ctx, http.MethodGet, "/proxies", nil, &v); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for g := range groups {
		if now := v.Proxies[g].Now; now != "" {
			out[g] = now
		}
	}
	return out, nil
}

// mihomo logs failed dials as warnings.
func (*Mihomo) LogLevel() string { return "warning" }

// [TCP] dial 节点 (match DomainSuffix/x) 127.0.0.1:1(curl, uid=1000) --> host:443 error: …
// The source carries the process when mihomo could find it.
var mihomoDialError = regexp.MustCompile(`\[(?:TCP|UDP)\] dial (.+?) \(match [^)]*\) (.+?) --> (\S+):(\d+) error: (.*?)"?$`)

var mihomoLevel = regexp.MustCompile(`^time="[^"]*" level=(\w+)`)

func (*Mihomo) ObserveLog(line string) LogLine {
	var l LogLine
	if m := mihomoLevel.FindStringSubmatch(line); m != nil {
		l.Level = m[1]
	}
	if m := mihomoDialError.FindStringSubmatch(line); m != nil {
		l.Failure = &DialFailure{Via: m[1], Source: m[2], Host: m[3], Port: m[4], Error: m[5]}
	}
	return l
}
