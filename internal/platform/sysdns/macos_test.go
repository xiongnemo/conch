package sysdns

import (
	"slices"
	"strings"
	"testing"
)

// fakeMac answers networksetup like macOS does.
type fakeMac struct {
	dns   map[string][]string
	calls []string
}

func (f *fakeMac) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch args[0] {
	case "-listallnetworkservices":
		return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nThunderbolt Bridge\n*VPN", nil
	case "-getdnsservers":
		if s := f.dns[args[1]]; len(s) > 0 {
			return strings.Join(s, "\n"), nil
		}
		return "There aren't any DNS Servers set on " + args[1] + ".", nil
	case "-setdnsservers":
		if args[2] == "Empty" {
			f.dns[args[1]] = nil
		} else {
			f.dns[args[1]] = args[2:]
		}
	}
	return "", nil
}

func TestMacTakeover(t *testing.T) {
	f := &fakeMac{dns: map[string][]string{"Wi-Fi": {"192.168.1.1", "8.8.8.8"}}}
	m := macResolver{f.run}
	snap, err := m.enable("223.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.dns["Wi-Fi"], []string{"223.5.5.5"}) || !slices.Equal(f.dns["Thunderbolt Bridge"], []string{"223.5.5.5"}) {
		t.Fatalf("after enable: %v", f.dns)
	}
	if slices.Contains(f.calls, "networksetup -setdnsservers *VPN 223.5.5.5") {
		t.Error("a disabled service was changed")
	}
	if err := m.restore(snap); err != nil {
		t.Fatal(err)
	}
	// Servers come back as they were; a service that had none goes back
	// to what the network hands out.
	if !slices.Equal(f.dns["Wi-Fi"], []string{"192.168.1.1", "8.8.8.8"}) || f.dns["Thunderbolt Bridge"] != nil {
		t.Errorf("after restore: %v", f.dns)
	}
	if !slices.Contains(f.calls, "networksetup -setdnsservers Thunderbolt Bridge Empty") {
		t.Errorf("calls: %q", f.calls)
	}
}
