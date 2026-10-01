package sysproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows keeps the WinINet proxy (used by browsers and most apps) per
// user in the registry; InternetSetOption tells running apps to reread it.

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type windowsSnapshot struct {
	ProxyEnable   uint32 `json:"proxyEnable"`
	ProxyServer   string `json:"proxyServer"`
	ProxyOverride string `json:"proxyOverride"`
	AutoConfigURL string `json:"autoConfigURL"`
}

func enable(port int) (Snapshot, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	var snap windowsSnapshot
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		snap.ProxyEnable = uint32(v)
	}
	snap.ProxyServer, _, _ = k.GetStringValue("ProxyServer")
	snap.ProxyOverride, _, _ = k.GetStringValue("ProxyOverride")
	snap.AutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")

	// WinINet takes host wildcards, not CIDR ranges.
	wildcards := map[string]string{
		"127.0.0.0/8": "127.*", "10.0.0.0/8": "10.*", "192.168.0.0/16": "192.168.*", "169.254.0.0/16": "169.254.*",
		"172.16.0.0/12": "172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*", "::1": "[::1]",
	}
	bypass := []string{"<local>"}
	for _, b := range Bypass {
		if w, ok := wildcards[b]; ok {
			b = w
		}
		bypass = append(bypass, b)
	}
	if err := k.SetStringValue("ProxyServer", "127.0.0.1:"+strconv.Itoa(port)); err != nil {
		return "", err
	}
	k.SetStringValue("ProxyOverride", strings.Join(bypass, ";"))
	k.DeleteValue("AutoConfigURL") // a PAC script would take precedence
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return "", err
	}
	notify()
	data, err := json.Marshal(snap)
	return Snapshot(data), err
}

func restore(s Snapshot) error {
	var snap windowsSnapshot
	if err := json.Unmarshal([]byte(s), &snap); err != nil {
		return fmt.Errorf("系统代理快照损坏：%w", err)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	k.SetDWordValue("ProxyEnable", snap.ProxyEnable)
	k.SetStringValue("ProxyServer", snap.ProxyServer)
	k.SetStringValue("ProxyOverride", snap.ProxyOverride)
	if snap.AutoConfigURL != "" {
		k.SetStringValue("AutoConfigURL", snap.AutoConfigURL)
	}
	notify()
	return nil
}

func current() (Status, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return Status{}, err
	}
	defer k.Close()
	on, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	return Status{Enabled: on == 1, Server: server}, nil
}

var (
	wininet           = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

// notify makes WinINet applications pick up the new settings.
func notify() {
	const settingsChanged, refresh = 39, 37
	if internetSetOption.Find() != nil {
		return
	}
	internetSetOption.Call(0, settingsChanged, 0, 0)
	internetSetOption.Call(0, refresh, 0, 0)
}
