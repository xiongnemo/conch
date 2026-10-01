package sysdns

import (
	"encoding/json"
	"fmt"
	"strings"
)

// macOS keeps DNS servers per network service (Wi-Fi, Ethernet …). An
// empty list means the servers the network hands out (DHCP).
type macService struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers,omitempty"`
}

type macResolver struct{ run runner }

func (m macResolver) services() ([]string, error) {
	out, err := m.run("networksetup", "-listallnetworkservices")
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

func (m macResolver) enable(server string) (Snapshot, error) {
	names, err := m.services()
	if err != nil {
		return "", err
	}
	var snap []macService
	for _, n := range names {
		out, err := m.run("networksetup", "-getdnsservers", n)
		if err != nil {
			return "", fmt.Errorf("读取 %s 的 DNS：%w", n, err)
		}
		s := macService{Name: n}
		if !strings.Contains(out, "There aren't any DNS Servers") {
			s.Servers = strings.Fields(out)
		}
		snap = append(snap, s)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if _, err := m.run("networksetup", "-setdnsservers", n, server); err != nil {
			m.restore(Snapshot(data))
			return "", fmt.Errorf("设置 %s 的 DNS（需要 root 权限）：%w", n, err)
		}
	}
	return Snapshot(data), nil
}

func (m macResolver) restore(s Snapshot) error {
	var snap []macService
	if err := json.Unmarshal([]byte(s), &snap); err != nil {
		return fmt.Errorf("读取保存的 DNS 设置：%w", err)
	}
	var firstErr error
	for _, svc := range snap {
		args := append([]string{"-setdnsservers", svc.Name}, svc.Servers...)
		if len(svc.Servers) == 0 {
			args = append(args, "Empty")
		}
		if _, err := m.run("networksetup", args...); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("恢复 %s 的 DNS：%w", svc.Name, err)
		}
	}
	return firstErr
}
