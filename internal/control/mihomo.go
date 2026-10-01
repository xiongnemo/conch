package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
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
		return fmt.Errorf("mihomo %s %s：%s %s", method, path, resp.Status, bytes.TrimSpace(msg))
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
	if err := m.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+q.Encode(), nil, &v); err != nil {
		return 0, err
	}
	return time.Duration(v.Delay) * time.Millisecond, nil
}

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
