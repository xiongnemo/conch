package daemon

import (
	"slices"
	"testing"
	"time"
)

func TestFailures(t *testing.T) {
	var f failures
	now := time.Now()
	line := `time="2026-10-01T22:41:46+10:00" level=warning msg="[TCP] dial dead (match DomainSuffix/example.com) 127.0.0.1:46178 --> www.example.com:80 error: connect: connection refused"`
	for range 5 { // the kernel retries one connection several times
		f.observe(line, now)
	}
	f.observe(`msg="[TCP] dial dead (match DomainSuffix/example.com) 127.0.0.1:46200 --> www.example.com:80 error: timeout"`, now.Add(time.Second))
	f.observe(`msg="[TCP] 127.0.0.1:1 --> ok.example:443 match Match using DIRECT"`, now) // not a failure
	// With the process known, the source has spaces in it.
	f.observe(`level=warning msg="[TCP] dial AI-Exit (match DomainSuffix/openai.com) 127.0.0.1:46812(curl, uid=1000) --> chat.openai.com:80 error: refused"`, now.Add(2*time.Second))
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
