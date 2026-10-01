package control

import (
	"slices"
	"testing"
	"time"
)

func TestMihomoObserveLog(t *testing.T) {
	var m Mihomo
	l := m.ObserveLog(`time="2026-10-01T22:41:46+10:00" level=warning msg="[TCP] dial AI-Exit (match DomainSuffix/openai.com) 127.0.0.1:46812(curl, uid=1000) --> chat.openai.com:80 error: connect: connection refused"`)
	want := DialFailure{Source: "127.0.0.1:46812(curl, uid=1000)", Via: "AI-Exit", Host: "chat.openai.com", Port: "80", Error: "connect: connection refused"}
	if l.Level != "warning" || l.Failure == nil || *l.Failure != want {
		t.Errorf("dial error = %+v %+v", l, l.Failure)
	}
	l = m.ObserveLog(`time="2026-10-01T22:41:46+10:00" level=info msg="[TCP] 127.0.0.1:1 --> ok.example:443 match Match using DIRECT"`)
	if l.Level != "info" || l.Failure != nil {
		t.Errorf("connection line = %+v", l)
	}
}

func TestXrayObserveLog(t *testing.T) {
	var x Xray
	lines := []struct {
		line     string
		level    string
		internal bool
		failure  bool
	}{
		{"2026/10/01 22:41:46 [Warning] core: Xray 26.3.27 started", "warning", false, false},
		{"2026/10/01 22:41:46.1 [Info] [11] proxy/http: request to Method [CONNECT] Host [chatgpt.com:443] with URL [//chatgpt.com:443]", "debug", false, false},
		{"2026/10/01 22:41:46.2 [Info] [11] app/dispatcher: Hit route rule: [#3 openai.com] so taking detour [AI-Exit] for [tcp:chatgpt.com:443]", "debug", false, false},
		{"2026/10/01 22:41:46.3 from 127.0.0.1:50312 accepted tcp:chatgpt.com:443 [›mixed -> AI-Exit]", "info", false, false},
		// A rule that sends traffic to a group's balancer names the member.
		{"2026/10/01 22:41:47 [Info] [22] app/dispatcher: Hit route rule: [#5 google.com] so taking detour [HK 01] for [tcp:www.google.com:443]", "debug", false, false},
		// The default route goes to a group's loopback, which picks a member.
		{"2026/10/01 22:41:47 [Info] [33] app/dispatcher: default route for tcp:example.com:443", "debug", false, false},
		{"2026/10/01 22:41:47 [Info] [33] app/dispatcher: taking detour [HK 02] for [tcp:example.com:443]", "debug", false, false},
		{"2026/10/01 22:41:48 [Warning] [33] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: all retry attempts failed", "warning", false, true},
		{"2026/10/01 22:41:48 [Warning] [33] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination", "warning", false, false}, // counted once
		// A connection that broke after it was established is not a failure to connect.
		{"2026/10/01 22:41:49 [Info] [22] app/proxyman/outbound: failed to process outbound traffic > proxy/freedom: connection ends > read: connection reset by peer", "debug", false, false},
		// nautilus's own API calls and delay tests.
		{"2026/10/01 22:41:49 [Info] [44] app/dispatcher: Hit route rule: [›api] so taking detour [›api] for [tcp:127.0.0.1:1]", "debug", true, false},
		{"2026/10/01 22:41:49 from @ accepted tcp:127.0.0.1:1 [›api -> ›api]", "info", true, false},
		{"2026/10/01 22:41:50 [Info] [55] app/dispatcher: Hit route rule: [›probe›1] so taking detour [dead] for [tcp:www.gstatic.com:443]", "debug", true, false},
		{"2026/10/01 22:41:50 [Info] [55] app/proxyman/outbound: failed to process outbound traffic > proxy/freedom: failed to open connection to tcp:www.gstatic.com:443", "debug", true, false},
		{"2026/10/01 22:41:51 [Info] [66] app/dispatcher: Hit route rule: [#7 v6] so taking detour [香港 [IPLC]] for [tcp:[2001:db8::1]:443]", "debug", false, false},
	}
	var failures []DialFailure
	for _, c := range lines {
		l := x.ObserveLog(c.line)
		if l.Level != c.level || l.Internal != c.internal || (l.Failure != nil) != c.failure {
			t.Errorf("%s\n got level %q internal %v failure %+v", c.line, l.Level, l.Internal, l.Failure)
		}
		if l.Failure != nil {
			failures = append(failures, *l.Failure)
		}
	}
	if len(failures) != 1 || failures[0].Host != "example.com" || failures[0].Port != "443" || failures[0].Via != "HK 02" ||
		failures[0].Error != "proxy/vless/outbound: failed to find an available destination > common/retry: all retry attempts failed" {
		t.Errorf("failures = %+v", failures)
	}

	conns, _ := x.Connections(nil)
	var ids []string
	for _, c := range conns {
		ids = append(ids, c.ID)
	}
	if !slices.Equal(ids, []string{"66", "33", "22", "11"}) {
		t.Fatalf("connections = %q, want newest first without nautilus's own", ids)
	}
	if c := conns[3]; c.Host != "chatgpt.com" || c.Port != "443" || c.Network != "tcp" || c.RuleTag != "#3 openai.com" || !slices.Equal(c.Chains, []string{"AI-Exit"}) {
		t.Errorf("chatgpt.com = %+v", c)
	}
	if c := conns[1]; c.Rule != "Match" || c.RuleTag != "" || !slices.Equal(c.Chains, []string{"HK 02"}) {
		t.Errorf("default route = %+v", c)
	}
	if c := conns[0]; c.Host != "2001:db8::1" || !slices.Equal(c.Chains, []string{"香港 [IPLC]"}) {
		t.Errorf("IPv6 = %+v", c)
	}

	// Old sessions drop out of the list.
	if got := x.sessions.recent(time.Now().Add(recentWindow + time.Minute)); len(got) != 0 {
		t.Errorf("stale connections = %+v", got)
	}
}

func TestXrayBalancerPick(t *testing.T) {
	for raw, want := range map[string]string{
		`{"balancer":{"override":{"target":"HK 02"},"principleTarget":{"tag":["HK 01","HK 02"]}}}`: "HK 02",
		`{"balancer":{"override":{},"principleTarget":{"tag":["HK 03"]}}}`:                         "HK 03",
		`{"balancer":{"principleTarget":{"tag":["a","b"]}}}`:                                       "",
		`not json`: "",
	} {
		if got := balancerPick([]byte(raw)); got != want {
			t.Errorf("balancerPick(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestSingBoxObserveLog(t *testing.T) {
	var s SingBox
	l := s.ObserveLog("+1000 2026-10-02 01:30:00 ERROR [3141592653 5ms] connection: open connection to blocked.example:80 using outbound/socks[dead]: dial tcp 127.0.0.1:1: connect: connection refused")
	want := DialFailure{Source: "connection 3141592653", Via: "dead", Host: "blocked.example", Port: "80", Error: "dial tcp 127.0.0.1:1: connect: connection refused"}
	if l.Level != "error" || l.Failure == nil || *l.Failure != want {
		t.Errorf("dial error = %+v %+v", l, l.Failure)
	}
	if l := s.ObserveLog("+1000 2026-10-02 01:30:00 INFO [42 0ms] inbound/mixed[›mixed]: inbound connection to www.google.com:443"); l.Level != "info" || l.Failure != nil {
		t.Errorf("connection line = %+v", l)
	}
	if l := s.ObserveLog("+1000 2026-10-02 01:30:00 WARN router: something"); l.Level != "warning" {
		t.Errorf("warning = %+v", l)
	}
}
