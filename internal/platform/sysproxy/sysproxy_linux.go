package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Linux has no system-wide proxy setting; desktops keep their own. GNOME
// and the desktops built on it use GSettings, KDE uses kioslaverc.

type linuxSnapshot struct {
	Desktop string            `json:"desktop"` // gnome | kde
	Values  map[string]string `json:"values"`
}

const gnomeProxy = "org.gnome.system.proxy"

var gnomeKeys = [][2]string{
	{gnomeProxy, "mode"}, {gnomeProxy, "ignore-hosts"},
	{gnomeProxy + ".http", "host"}, {gnomeProxy + ".http", "port"},
	{gnomeProxy + ".https", "host"}, {gnomeProxy + ".https", "port"},
	{gnomeProxy + ".socks", "host"}, {gnomeProxy + ".socks", "port"},
}

var kdeKeys = []string{"ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"}

func desktop() string {
	d := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP") + ":" + os.Getenv("DESKTOP_SESSION"))
	switch {
	case strings.Contains(d, "KDE") || strings.Contains(d, "PLASMA"):
		if kdeTool("kwriteconfig") != "" {
			return "kde"
		}
	case lookPath("gsettings"):
		if _, err := run("gsettings", "get", gnomeProxy, "mode"); err == nil {
			return "gnome"
		}
	}
	return ""
}

var lookPath = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// kdeTool finds kwriteconfig6/5 or kreadconfig6/5.
func kdeTool(base string) string {
	for _, v := range []string{"6", "5"} {
		if lookPath(base + v) {
			return base + v
		}
	}
	return ""
}

func enable(port int) (Snapshot, error) {
	p := strconv.Itoa(port)
	switch desktop() {
	case "gnome":
		snap := linuxSnapshot{Desktop: "gnome", Values: map[string]string{}}
		for _, k := range gnomeKeys {
			v, err := run("gsettings", "get", k[0], k[1])
			if err != nil {
				return "", fmt.Errorf("读取 GNOME 代理设置：%w", err)
			}
			snap.Values[k[0]+" "+k[1]] = v
		}
		ignore := "['" + strings.Join(Bypass, "', '") + "']"
		for _, set := range [][3]string{
			{gnomeProxy + ".http", "host", "127.0.0.1"}, {gnomeProxy + ".http", "port", p},
			{gnomeProxy + ".https", "host", "127.0.0.1"}, {gnomeProxy + ".https", "port", p},
			{gnomeProxy + ".socks", "host", "127.0.0.1"}, {gnomeProxy + ".socks", "port", p},
			{gnomeProxy, "ignore-hosts", ignore}, {gnomeProxy, "mode", "manual"},
		} {
			if _, err := run("gsettings", "set", set[0], set[1], set[2]); err != nil {
				return "", fmt.Errorf("设置 GNOME 代理：%w", err)
			}
		}
		return marshal(snap)
	case "kde":
		snap := linuxSnapshot{Desktop: "kde", Values: map[string]string{}}
		read := kdeTool("kreadconfig")
		for _, k := range kdeKeys {
			v, _ := run(read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k)
			snap.Values[k] = v
		}
		for _, set := range [][2]string{
			{"httpProxy", "http://127.0.0.1 " + p}, {"httpsProxy", "http://127.0.0.1 " + p},
			{"socksProxy", "socks://127.0.0.1 " + p}, {"NoProxyFor", strings.Join(Bypass, ",")}, {"ProxyType", "1"},
		} {
			if err := kdeWrite(set[0], set[1]); err != nil {
				return "", err
			}
		}
		kdeNotify()
		return marshal(snap)
	}
	return "", ErrUnsupported
}

func restore(s Snapshot) error {
	var snap linuxSnapshot
	if err := json.Unmarshal([]byte(s), &snap); err != nil {
		return fmt.Errorf("系统代理快照损坏：%w", err)
	}
	switch snap.Desktop {
	case "gnome":
		// Mode last, so the proxy is off before its address changes.
		for i := len(gnomeKeys) - 1; i >= 0; i-- {
			k := gnomeKeys[i]
			if v, ok := snap.Values[k[0]+" "+k[1]]; ok {
				if _, err := run("gsettings", "set", k[0], k[1], v); err != nil {
					return fmt.Errorf("恢复 GNOME 代理设置：%w", err)
				}
			}
		}
		return nil
	case "kde":
		for _, k := range kdeKeys {
			if err := kdeWrite(k, snap.Values[k]); err != nil {
				return err
			}
		}
		kdeNotify()
		return nil
	}
	return fmt.Errorf("不认识的系统代理快照（%s）", snap.Desktop)
}

func kdeWrite(key, value string) error {
	if _, err := run(kdeTool("kwriteconfig"), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value); err != nil {
		return fmt.Errorf("设置 KDE 代理：%w", err)
	}
	return nil
}

// kdeNotify tells running KDE applications to reread the proxy settings.
func kdeNotify() {
	run("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
}

func current() (Status, error) {
	switch desktop() {
	case "gnome":
		mode, err := run("gsettings", "get", gnomeProxy, "mode")
		if err != nil {
			return Status{}, err
		}
		host, _ := run("gsettings", "get", gnomeProxy+".http", "host")
		port, _ := run("gsettings", "get", gnomeProxy+".http", "port")
		return Status{Enabled: strings.Trim(mode, "'") == "manual", Server: strings.Trim(host, "'") + ":" + port}, nil
	case "kde":
		read := kdeTool("kreadconfig")
		typ, _ := run(read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType")
		http, _ := run(read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy")
		host, port, _ := strings.Cut(strings.TrimPrefix(http, "http://"), " ")
		return Status{Enabled: typ == "1", Server: host + ":" + port}, nil
	}
	return Status{}, ErrUnsupported
}

func marshal(v any) (Snapshot, error) {
	data, err := json.Marshal(v)
	return Snapshot(data), err
}
