package kernels

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMirrorFromEnvironment(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv(MirrorEnv, srv.URL)
	err := FetchGeodata(t.Context(), srv.Client(), "xray", "", t.TempDir(), io.Discard)
	if err == nil || strings.Contains(err.Error(), MirrorEnv) {
		t.Fatalf("err = %v, want the mirror's 404 without the mirror hint", err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "/https://github.com/") {
		t.Errorf("requests = %q, want one through the mirror", got)
	}
}

func TestMirrorHint(t *testing.T) {
	t.Setenv(MirrorEnv, "")
	offline := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	err := FetchGeodata(t.Context(), offline, "xray", "", t.TempDir(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), MirrorEnv+"=") {
		t.Errorf("geodata: err = %v, want the mirror hint", err)
	}
	_, err = Install(t.Context(), InstallOptions{Kernel: "mihomo", Dir: t.TempDir(), Target: Host(), HTTP: offline})
	if err == nil || !strings.Contains(err.Error(), MirrorEnv+"=") {
		t.Errorf("kernel: err = %v, want the mirror hint", err)
	}
}
