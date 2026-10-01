package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"nautilus/internal/kernel"
)

// Xray controls xray through its gRPC API, using the xray binary's own
// "xray api" client so nautilus needs no gRPC stubs. The API is served on
// a unix socket in a private directory.
type Xray struct {
	Bin    string
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
	full := append([]string{"api", args[0], "--server=unix://" + x.Socket}, args[1:]...)
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

func (*Xray) Delay(context.Context, string, string, time.Duration) (time.Duration, error) {
	return 0, ErrUnsupported
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

// xray's API has no list of open connections.
func (*Xray) Connections(context.Context) ([]Connection, error) { return nil, ErrUnsupported }

func (*Xray) CloseConnection(context.Context, string) error { return ErrUnsupported }
