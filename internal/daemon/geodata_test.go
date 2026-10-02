package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongnemo/conch/internal/backend/xray"
	"github.com/xiongnemo/conch/internal/kernels"
)

// xray's geodata is downloaded again when it is a week old, at most once
// a day, and only for xray.
func TestRefreshGeodata(t *testing.T) {
	const fresh = "new geodata"
	sum := sha256.Sum256([]byte(fresh))
	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256sum") {
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  file\n"))
			return
		}
		downloads.Add(1)
		w.Write([]byte(fresh))
	}))
	defer srv.Close()
	t.Setenv(kernels.MirrorEnv, srv.URL) // every GitHub URL goes to srv

	d := testDaemon(t, 7890)
	d.backend, d.home = xray.Backend{}, t.TempDir()
	now := time.Now()
	old := now.Add(-8 * 24 * time.Hour)
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		path := filepath.Join(d.home, f)
		os.WriteFile(path, []byte("old"), 0o644)
		os.Chtimes(path, old, old)
	}

	d.refreshGeodata(context.Background(), now)
	if got, _ := os.ReadFile(filepath.Join(d.home, "geosite.dat")); string(got) != fresh || downloads.Load() != 2 {
		t.Fatalf("after a week: geosite.dat = %q, %d downloads", got, downloads.Load())
	}
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		os.Chtimes(filepath.Join(d.home, f), old, old)
	}
	d.refreshGeodata(context.Background(), now.Add(time.Hour))
	if downloads.Load() != 2 {
		t.Errorf("downloaded again within a day: %d downloads", downloads.Load())
	}
}
