package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xiongnemo/conch/internal/kernel"
)

// SingBox controls sing-box through its Clash-compatible API. sing-box
// serves it on TCP only, so it listens on loopback with a random secret.
type SingBox struct {
	clashAPI
	Addr string
}

func NewSingBox(addr, secret string) *SingBox {
	return &SingBox{Addr: addr, clashAPI: clashAPI{name: "sing-box", base: "http://" + addr, secret: secret, client: &http.Client{Timeout: 30 * time.Second}}}
}

func (*SingBox) Name() string       { return "sing-box" }
func (*SingBox) ConfigFile() string { return "config.json" }

func (*SingBox) Spec(bin, home, config string) kernel.Spec {
	return kernel.Spec{Path: bin, Args: []string{"run", "--disable-color", "-c", config, "-D", home}, Dir: home}
}

func (*SingBox) Validate(ctx context.Context, bin, home, config string) error {
	if out, err := exec.CommandContext(ctx, bin, "check", "--disable-color", "-c", config, "-D", home).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box 不接受生成的配置：%s", lastLines(out, 3))
	}
	return nil
}

// Reload needs a restart: sing-box's PUT /configs changes nothing.
func (*SingBox) Reload(context.Context, []byte, bool) error { return ErrRestart }

// Connections names the rule each connection matched by its description,
// e.g. "domain_suffix=openai.com", which the encoder records per rule.
func (s *SingBox) Connections(ctx context.Context) ([]Connection, error) {
	raw, err := s.connections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(raw))
	for _, c := range raw {
		process := c.Metadata.ProcessPath
		if i := strings.Index(process, " ("); i > 0 {
			process = process[:i] // "… (user)"
		}
		if process != "" {
			process = filepath.Base(process)
		}
		rule, tag := "", ""
		if c.Rule == "final" {
			rule = "Match"
		} else {
			tag, _, _ = strings.Cut(c.Rule, " => ")
		}
		out = append(out, c.connection(process, rule, "", tag))
	}
	return out, nil
}

// sing-box logs failed dials as errors.
func (*SingBox) LogLevel() string { return "error" }

var (
	// -0700 2006-01-02 15:04:05 ERROR [3141592653 5ms] connection: open connection to …
	singBoxLine = regexp.MustCompile(`^[+-]\d{4} \S+ \S+ (TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC) (?:\[(\d+) [^\]]*\] )?(.*)$`)
	// connection: open connection to example.com:443 using outbound/socks[dead]: dial tcp …: connection refused
	singBoxDialError = regexp.MustCompile(`^connection: open (?:packet )?connection to (\S+) using outbound/[\w-]+\[(.*?)\]: (.*)$`)
	singBoxLevels    = map[string]string{"TRACE": "debug", "DEBUG": "debug", "INFO": "info", "WARN": "warning", "ERROR": "error", "FATAL": "error", "PANIC": "error"}
)

func (*SingBox) ObserveLog(line string) LogLine {
	m := singBoxLine.FindStringSubmatch(line)
	if m == nil {
		return LogLine{}
	}
	l := LogLine{Level: singBoxLevels[m[1]]}
	if f := singBoxDialError.FindStringSubmatch(m[3]); f != nil {
		host, port, err := net.SplitHostPort(f[1])
		if err != nil {
			host, port = f[1], "" // resolved addresses, [ip1,ip2]
		}
		l.Failure = &DialFailure{Source: "connection " + m[2], Via: f[2], Host: host, Port: port, Error: f[3]}
	}
	return l
}
