// Package backendtest runs the shared golden profiles in
// internal/backend/testdata through a backend. Each backend's tests call
// Golden from their package directory and keep their outputs in their own
// testdata directory.
package backendtest

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nautilus/internal/backend"
	"nautilus/internal/compile"
	"nautilus/internal/diag"
	"nautilus/internal/lists"
	"nautilus/internal/model"
	"nautilus/internal/route"
	"nautilus/internal/subscription"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Cases maps case names to profile paths, relative to a backend package.
// The example profile is included so the documentation never goes stale.
func Cases(t *testing.T) map[string]string {
	t.Helper()
	cases := map[string]string{"example": "../../../examples/profile.yaml"}
	files, err := filepath.Glob("../testdata/*.profile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		// Slashes on every OS: the paths end up in the diagnostics goldens.
		cases[strings.TrimSuffix(filepath.Base(f), ".profile.yaml")] = filepath.ToSlash(f)
	}
	return cases
}

// Lists serves URL rule lists from ../testdata/lists/<file name>.
func Lists(p route.Provider) ([]lists.Entry, []string, error) {
	data, err := os.ReadFile(filepath.Join("../testdata/lists", filepath.Base(p.URL)))
	if err != nil {
		return nil, nil, err
	}
	return lists.Parse(data, p.Format, p.Behavior)
}

// Subscriptions loads ../testdata/subs/<name>.yaml for every subscription
// of a profile; proxy-providers are served from the same directory.
func Subscriptions(t *testing.T, p *model.Profile) map[string]*subscription.Snapshot {
	t.Helper()
	snaps := map[string]*subscription.Snapshot{}
	for _, sub := range p.Subscriptions {
		body, err := os.ReadFile(filepath.Join("../testdata/subs", sub.Name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		snap, err := subscription.Parse(body, func(url string) ([]byte, error) {
			return os.ReadFile(filepath.Join("../testdata/subs", filepath.Base(url)))
		})
		if err != nil {
			t.Fatal(err)
		}
		snaps[sub.Name] = snap
	}
	return snaps
}

// Build compiles a profile for a backend the way the CLI does.
func Build(t *testing.T, b backend.Router, path string, opts backend.Options) (*backend.Artifact, diag.List) {
	t.Helper()
	p, err := model.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var diags diag.List
	subscription.Apply(p, Subscriptions(t, p), &diags)
	res := compile.Compile(p)
	diags = append(diags, res.Diags...)
	diags = append(diags, backend.Check(res, b.Capabilities(), b.Name())...)
	if diags.HasErrors() {
		return nil, diags
	}
	art, d := b.Encode(res, opts)
	return art, append(diags, d...)
}

// Golden compiles every case and compares the config (with extension ext),
// the manifest and the diagnostics with golden files in ./testdata. A case
// the backend rejects only has a diagnostics golden.
func Golden(t *testing.T, b backend.Router, ext string) {
	for name, path := range Cases(t) {
		t.Run(name, func(t *testing.T) {
			art, diags := Build(t, b, path, backend.Options{Lists: Lists})
			var text strings.Builder
			for _, d := range diags {
				text.WriteString(d.String() + "\n")
			}
			Check(t, "testdata/"+name+".diags.golden", []byte(text.String()))
			config, manifest := "testdata/"+name+".golden"+ext, "testdata/"+name+".manifest.golden.json"
			if art == nil {
				for _, f := range []string{config, manifest} {
					if _, err := os.Stat(f); err == nil {
						if *update {
							os.Remove(f)
						} else {
							t.Errorf("%s exists but the profile no longer compiles", f)
						}
					}
				}
				return
			}
			data, err := json.MarshalIndent(art.Manifest, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			Check(t, config, art.Config)
			Check(t, manifest, append(data, '\n'))
		})
	}
}

// Check compares got with a golden file, or rewrites it with -update.
// Empty content means the golden file must not exist.
func Check(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if len(got) == 0 {
			os.Remove(path)
			return
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if os.IsNotExist(err) && len(got) == 0 {
		return
	}
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run go test -update and review the diff.\ngot:\n%s", path, got)
	}
}

// Configs lists the golden configs with extension ext, for tests that feed
// them to a real kernel.
func Configs(t *testing.T, ext string) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/*.golden" + ext)
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(files, func(f string) bool { return strings.Contains(f, ".manifest.") })
}
