package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"nautilus/internal/route"
)

func TestParse(t *testing.T) {
	tests := []struct {
		format, behavior, data string
		want                   []Entry
		skipped                []string
	}{
		{"text", "domain", "# comment\n+.hulu.com\n.disney.com\n*.max.com\nPrimeVideo.com\nbad domain\n",
			[]Entry{{DomainSuffix, "hulu.com"}, {DomainRegex, `\.disney\.com$`}, {DomainRegex, `^[^.]+\.max\.com$`}, {Domain, "primevideo.com"}},
			[]string{"bad domain"}},
		{"yaml", "ipcidr", "payload:\n  - 1.2.3.4\n  - 10.1.2.3/8\n  - 2001:db8::/32\n  - nope\n",
			[]Entry{{IPCIDR, "1.2.3.4/32"}, {IPCIDR, "10.0.0.0/8"}, {IPCIDR, "2001:db8::/32"}},
			[]string{"nope"}},
		{"text", "classical", "DOMAIN-SUFFIX,Google.com\nIP-CIDR6,2001:db8::/32,no-resolve\nGEOIP,CN\nDST-PORT,22\nNETWORK,UDP\nUSER-AGENT,x*\n",
			[]Entry{{DomainSuffix, "google.com"}, {IPCIDR, "2001:db8::/32"}, {GeoIP, "cn"}, {DstPort, "22"}, {Network, "udp"}},
			[]string{"USER-AGENT,x*"}},
	}
	for _, tt := range tests {
		got, skipped, err := Parse([]byte(tt.data), tt.format, tt.behavior)
		if err != nil {
			t.Errorf("%s/%s: %v", tt.format, tt.behavior, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) || !reflect.DeepEqual(skipped, tt.skipped) {
			t.Errorf("%s/%s:\n got  %v skipped %q\n want %v skipped %q", tt.format, tt.behavior, got, skipped, tt.want, tt.skipped)
		}
	}
	if _, _, err := Parse([]byte("payload: []"), "yaml", "domain"); err == nil {
		t.Error("an empty list must be an error, so it never replaces a good cache")
	}
	if _, _, err := Parse([]byte("x"), "mrs", "domain"); err == nil {
		t.Error("mrs cannot be parsed and must be an error")
	}
}

func TestStore(t *testing.T) {
	var body atomic.Value
	body.Store("+.example.com\n")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	p := route.Provider{Name: "x", Behavior: "domain", Format: "text", URL: srv.URL + "/list.txt"}
	ctx := context.Background()

	offline := &Store{Dir: t.TempDir(), Offline: true}
	if _, _, err := offline.Load(ctx, p); err == nil || hits.Load() != 0 {
		t.Fatalf("offline store must not download: err=%v hits=%d", err, hits.Load())
	}

	s := &Store{Dir: t.TempDir()}
	entries, _, err := s.Load(ctx, p)
	if err != nil || len(entries) != 1 {
		t.Fatalf("Load = %v, %v", entries, err)
	}
	if _, _, err := s.Load(ctx, p); err != nil || hits.Load() != 1 {
		t.Fatalf("second load should come from the cache: err=%v hits=%d", err, hits.Load())
	}

	// A broken download must not replace the cached copy.
	body.Store("")
	if err := s.Update(ctx, p); err == nil || !strings.Contains(err.Error(), "空") {
		t.Fatalf("Update with an empty list = %v, want error", err)
	}
	if entries, _, err := s.Load(ctx, p); err != nil || len(entries) != 1 {
		t.Fatalf("cache was damaged: %v, %v", entries, err)
	}
}
