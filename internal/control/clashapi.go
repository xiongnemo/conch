package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// clashAPI talks to the REST API that mihomo and sing-box share with
// Clash: groups, delay tests, traffic and connections.
type clashAPI struct {
	name   string // for error messages
	base   string // e.g. http://127.0.0.1:9090
	secret string // sent as a bearer token when set
	client *http.Client
}

func (m *clashAPI) do(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.secret != "" {
		req.Header.Set("Authorization", "Bearer "+m.secret)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &apiError{Status: resp.StatusCode, Text: fmt.Sprintf("%s %s %s：%s %s", m.name, method, path, resp.Status, bytes.TrimSpace(msg))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (m *clashAPI) Ready(ctx context.Context) bool {
	var v struct {
		Version string `json:"version"`
	}
	return m.do(ctx, http.MethodGet, "/version", nil, &v) == nil && v.Version != ""
}

func (m *clashAPI) Select(ctx context.Context, group, tag string) error {
	return m.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": tag}, nil)
}

func (m *clashAPI) Delay(ctx context.Context, tag, testURL string, timeout time.Duration) (time.Duration, error) {
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

// Traffic reads the streaming /traffic endpoint (one JSON object per second).
func (m *clashAPI) Traffic(ctx context.Context) (<-chan Traffic, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/traffic", nil)
	if err != nil {
		return nil, err
	}
	if m.secret != "" {
		req.Header.Set("Authorization", "Bearer "+m.secret)
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

// clashConnection is a connection as the API reports it.
type clashConnection struct {
	ID       string `json:"id"`
	Metadata struct {
		Network     string `json:"network"`
		Host        string `json:"host"`
		DstIP       string `json:"destinationIP"`
		DstPort     string `json:"destinationPort"`
		Process     string `json:"process"`
		ProcessPath string `json:"processPath"`
	} `json:"metadata"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
}

func (c clashConnection) connection(process, rule, payload, ruleTag string) Connection {
	host := c.Metadata.Host
	if host == "" {
		host = c.Metadata.DstIP
	}
	return Connection{
		ID: c.ID, Network: c.Metadata.Network, Host: host, Port: c.Metadata.DstPort, Process: process,
		Chains: c.Chains, Rule: rule, RulePayload: payload, RuleTag: ruleTag, Upload: c.Upload, Download: c.Download, Start: c.Start,
	}
}

func (m *clashAPI) connections(ctx context.Context) ([]clashConnection, error) {
	var v struct {
		Connections []clashConnection `json:"connections"`
	}
	err := m.do(ctx, http.MethodGet, "/connections", nil, &v)
	return v.Connections, err
}

func (m *clashAPI) CloseConnection(ctx context.Context, id string) error {
	return m.do(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

func (*clashAPI) Caps() Caps { return Caps{LiveConnections: true, CloseConnection: true} }

func (m *clashAPI) Picks(ctx context.Context, groups map[string]string) (map[string]string, error) {
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
