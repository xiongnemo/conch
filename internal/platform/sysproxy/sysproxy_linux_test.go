package sysproxy

import (
	"fmt"
	"maps"
	"strings"
	"testing"
)

// fakeDesktop stands in for gsettings and kreadconfig/kwriteconfig.
type fakeDesktop struct{ values map[string]string }

func (f *fakeDesktop) run(name string, args ...string) (string, error) {
	switch {
	case name == "gsettings" && args[0] == "get":
		v, ok := f.values[args[1]+" "+args[2]]
		if !ok {
			return "", fmt.Errorf("no such key")
		}
		return v, nil
	case name == "gsettings" && args[0] == "set":
		f.values[args[1]+" "+args[2]] = args[3]
		return "", nil
	case strings.HasPrefix(name, "kreadconfig"):
		return f.values[args[len(args)-1]], nil
	case strings.HasPrefix(name, "kwriteconfig"):
		f.values[args[len(args)-2]] = args[len(args)-1]
		return "", nil
	case name == "dbus-send":
		return "", nil
	}
	return "", fmt.Errorf("unexpected command %s %v", name, args)
}

func fake(t *testing.T, desktopName string, values map[string]string) *fakeDesktop {
	f := &fakeDesktop{values: values}
	oldRun, oldLook := run, lookPath
	run = f.run
	lookPath = func(string) bool { return true }
	t.Cleanup(func() { run, lookPath = oldRun, oldLook })
	t.Setenv("XDG_CURRENT_DESKTOP", desktopName)
	t.Setenv("DESKTOP_SESSION", "")
	return f
}

func TestGNOME(t *testing.T) {
	before := map[string]string{
		"org.gnome.system.proxy mode": "'none'", "org.gnome.system.proxy ignore-hosts": "['localhost']",
		"org.gnome.system.proxy.http host": "''", "org.gnome.system.proxy.http port": "0",
		"org.gnome.system.proxy.https host": "''", "org.gnome.system.proxy.https port": "0",
		"org.gnome.system.proxy.socks host": "'old'", "org.gnome.system.proxy.socks port": "1080",
	}
	f := fake(t, "ubuntu:GNOME", maps.Clone(before))
	snap, err := Enable(7890)
	if err != nil {
		t.Fatal(err)
	}
	if f.values["org.gnome.system.proxy mode"] != "manual" || f.values["org.gnome.system.proxy.http port"] != "7890" ||
		f.values["org.gnome.system.proxy.socks host"] != "127.0.0.1" {
		t.Errorf("after Enable: %v", f.values)
	}
	if st, _ := Current(); !st.Enabled || st.Server != "127.0.0.1:7890" {
		t.Errorf("Current = %+v", st)
	}
	if err := Restore(snap); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(f.values, before) {
		t.Errorf("Restore did not bring back the previous settings:\n got  %v\n want %v", f.values, before)
	}
}

func TestKDE(t *testing.T) {
	before := map[string]string{"ProxyType": "0", "httpProxy": "", "httpsProxy": "", "socksProxy": "", "NoProxyFor": ""}
	f := fake(t, "KDE", maps.Clone(before))
	snap, err := Enable(7891)
	if err != nil {
		t.Fatal(err)
	}
	if f.values["ProxyType"] != "1" || f.values["httpProxy"] != "http://127.0.0.1 7891" {
		t.Errorf("after Enable: %v", f.values)
	}
	if err := Restore(snap); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(f.values, before) {
		t.Errorf("Restore: got %v, want %v", f.values, before)
	}
}

func TestUnsupportedDesktop(t *testing.T) {
	fake(t, "", map[string]string{}) // gsettings exists but has no proxy schema
	if _, err := Enable(1); err != ErrUnsupported {
		t.Errorf("Enable = %v, want ErrUnsupported", err)
	}
}
