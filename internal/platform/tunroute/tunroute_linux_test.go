package tunroute

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fake records ip commands; rule deletions fail once nothing is left, and
// IPv6 commands fail as on a system without IPv6.
func fake(t *testing.T, noIPv6 bool) *[]string {
	var calls []string
	oldRun, oldUp := run, deviceUp
	run = func(args ...string) error {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case strings.Contains(line, "rule del"):
			return errors.New("no such rule")
		case noIPv6 && args[0] == "-6":
			return errors.New("IPv6 is disabled")
		}
		return nil
	}
	deviceUp = func(string) error { return nil }
	t.Cleanup(func() { run, deviceUp = oldRun, oldUp })
	return &calls
}

func TestUp(t *testing.T) {
	calls := fake(t, false)
	if err := Up("conch0"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"link set dev conch0 up",
		"-4 route replace default dev conch0 table 17230",
		"-4 rule add priority 17230 fwmark 0x434e lookup main",
		"-4 rule add priority 17231 ipproto udp dport 53 lookup 17230",
		"-4 rule add priority 17232 ipproto tcp dport 53 lookup 17230",
		"-4 rule add priority 17233 lookup main suppress_prefixlength 0",
		"-4 rule add priority 17234 lookup 17230",
		"-6 rule add priority 17234 lookup 17230",
	} {
		if !slices.Contains(*calls, want) {
			t.Errorf("missing %q in\n%s", want, strings.Join(*calls, "\n"))
		}
	}
	// What an earlier Up left goes first.
	if i, j := slices.Index(*calls, "-4 rule del priority 17230"), slices.Index(*calls, "-4 rule add priority 17230 fwmark 0x434e lookup main"); i < 0 || i > j {
		t.Errorf("old rules are not removed first:\n%s", strings.Join(*calls, "\n"))
	}
}

// Without IPv6, IPv4 still works, and no half-made IPv6 rules stay.
func TestUpWithoutIPv6(t *testing.T) {
	calls := fake(t, true)
	if err := Up("conch0"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(*calls, "-4 rule add priority 17234 lookup 17230") || !slices.Contains(*calls, "-6 route flush table 17230") {
		t.Errorf("calls:\n%s", strings.Join(*calls, "\n"))
	}
}

func TestDown(t *testing.T) {
	calls := fake(t, false)
	Down()
	for _, want := range []string{"-4 rule del priority 17230", "-4 rule del priority 17234", "-4 route flush table 17230", "-6 route flush table 17230"} {
		if !slices.Contains(*calls, want) {
			t.Errorf("missing %q in\n%s", want, strings.Join(*calls, "\n"))
		}
	}
}
