package control

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"

	"nautilus/internal/kernel"
)

// Mihomo controls mihomo through its REST API on a unix socket. mihomo
// does not authenticate the socket, so it must live in a private directory.
type Mihomo struct {
	clashAPI
	Socket string
}

func NewMihomo(socket string) *Mihomo {
	return &Mihomo{Socket: socket, clashAPI: clashAPI{name: "mihomo", base: "http://mihomo", client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}}
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

// Reload hot-reloads the config. Listeners are only recreated when ports
// changed, so existing connections survive ordinary edits.
func (m *Mihomo) Reload(ctx context.Context, config []byte, forceListeners bool) error {
	path := "/configs"
	if forceListeners {
		path += "?force=true"
	}
	return m.do(ctx, http.MethodPut, path, map[string]string{"payload": string(config)}, nil)
}

func (m *Mihomo) Connections(ctx context.Context) ([]Connection, error) {
	raw, err := m.connections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(raw))
	for _, c := range raw {
		out = append(out, c.connection(c.Metadata.Process, c.Rule, c.RulePayload, ""))
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
