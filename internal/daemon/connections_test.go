package daemon

import (
	"slices"
	"testing"
	"time"

	"nautilus/internal/control"
)

func TestFailures(t *testing.T) {
	var f failures
	now := time.Now()
	dial := control.DialFailure{Source: "127.0.0.1:46178", Via: "dead", Host: "www.example.com", Port: "80", Error: "connect: connection refused"}
	for range 5 { // the kernel retries one connection several times
		f.add(dial, now)
	}
	dial.Source, dial.Error = "127.0.0.1:46200", "timeout"
	f.add(dial, now.Add(time.Second))
	f.add(control.DialFailure{Source: "127.0.0.1:46812", Via: "AI-Exit", Host: "chat.openai.com", Port: "80", Error: "refused"}, now.Add(2*time.Second))
	got := f.list()
	if len(got) != 2 || got[0].Host != "chat.openai.com" || got[0].Via != "AI-Exit" || got[0].Error != "refused" {
		t.Fatalf("failures = %+v", got)
	}
	if w := got[1]; w.Host != "www.example.com" || w.Count != 2 || w.Via != "dead" || w.Error != "timeout" {
		t.Errorf("www.example.com = %+v", w)
	}
	f.clear()
	if len(f.list()) != 0 {
		t.Error("clear did not forget failures")
	}
}

// The log follows the profile's log-level even when the kernel runs
// more verbosely for nautilus's sake.
func TestShown(t *testing.T) {
	for _, c := range []struct {
		level, setting string
		want           bool
	}{
		{"debug", "info", false}, {"info", "info", true}, {"warning", "info", true},
		{"info", "warning", false}, {"error", "warning", true}, {"", "error", true}, {"debug", "", true},
	} {
		if got := shown(c.level, c.setting); got != c.want {
			t.Errorf("shown(%q, %q) = %v", c.level, c.setting, got)
		}
	}
}

func TestSuggest(t *testing.T) {
	for host, want := range map[string][]string{
		"api.openai.com":   {"openai.com", "api.openai.com"},
		"openai.com":       {"openai.com"},
		"www.bbc.co.uk":    {"bbc.co.uk", "www.bbc.co.uk"},
		"Chat.OpenAI.com.": {"openai.com", "chat.openai.com"},
	} {
		if got := Suggest(host); !slices.Equal(got, want) {
			t.Errorf("Suggest(%q) = %q, want %q", host, got, want)
		}
	}
}
