package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// macOS keeps proxy settings per network service (Wi-Fi, Ethernet …);
// every enabled service is set so the proxy follows network changes.

type darwinService struct {
	Name    string            `json:"name"`
	Proxies map[string]string `json:"proxies"` // web | secureweb | socksfirewall → "on host port" or "off"
	Bypass  []string          `json:"bypass"`
}

var proxyKinds = []string{"web", "secureweb", "socksfirewall"}

func services() ([]string, error) {
	out, err := run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("列出网络服务：%w", err)
	}
	var names []string
	for i, l := range strings.Split(out, "\n") {
		// The first line is a notice; disabled services start with "*".
		if l = strings.TrimSpace(l); i > 0 && l != "" && !strings.HasPrefix(l, "*") {
			names = append(names, l)
		}
	}
	return names, nil
}

// readProxy parses "networksetup -getwebproxy" output.
func readProxy(service, kind string) string {
	out, err := run("networksetup", "-get"+kind+"proxy", service)
	if err != nil {
		return "off"
	}
	fields := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if fields["Enabled"] != "Yes" {
		return "off"
	}
	return "on " + fields["Server"] + " " + fields["Port"]
}

func enable(port int) (Snapshot, error) {
	names, err := services()
	if err != nil {
		return "", err
	}
	var snap []darwinService
	for _, n := range names {
		s := darwinService{Name: n, Proxies: map[string]string{}}
		for _, k := range proxyKinds {
			s.Proxies[k] = readProxy(n, k)
		}
		if out, err := run("networksetup", "-getproxybypassdomains", n); err == nil && !strings.Contains(out, "There aren't any") {
			s.Bypass = strings.Fields(out)
		}
		snap = append(snap, s)
	}
	p := strconv.Itoa(port)
	for _, n := range names {
		for _, k := range proxyKinds {
			if _, err := run("networksetup", "-set"+k+"proxy", n, "127.0.0.1", p); err != nil {
				return "", fmt.Errorf("设置 %s 的代理（需要管理员权限时请用 sudo 运行）：%w", n, err)
			}
		}
		run("networksetup", append([]string{"-setproxybypassdomains", n}, Bypass...)...)
	}
	data, err := json.Marshal(snap)
	return Snapshot(data), err
}

func restore(s Snapshot) error {
	var snap []darwinService
	if err := json.Unmarshal([]byte(s), &snap); err != nil {
		return fmt.Errorf("系统代理快照损坏：%w", err)
	}
	for _, svc := range snap {
		for _, k := range proxyKinds {
			prev := strings.Fields(svc.Proxies[k])
			if len(prev) == 3 && prev[0] == "on" {
				run("networksetup", "-set"+k+"proxy", svc.Name, prev[1], prev[2])
			} else if _, err := run("networksetup", "-set"+k+"proxystate", svc.Name, "off"); err != nil {
				return fmt.Errorf("恢复 %s 的代理：%w", svc.Name, err)
			}
		}
		bypass := svc.Bypass
		if len(bypass) == 0 {
			bypass = []string{"Empty"}
		}
		run("networksetup", append([]string{"-setproxybypassdomains", svc.Name}, bypass...)...)
	}
	return nil
}

func current() (Status, error) {
	names, err := services()
	if err != nil || len(names) == 0 {
		return Status{}, err
	}
	f := strings.Fields(readProxy(names[0], "web"))
	if len(f) == 3 {
		return Status{Enabled: true, Server: f[1] + ":" + f[2]}, nil
	}
	return Status{}, nil
}
