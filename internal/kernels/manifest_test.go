package kernels

import "testing"

// Every machine conch supports finds its asset in the embedded
// manifest, so installs never fail on a checksum that was not recorded.
func TestAssetsInManifest(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	targets := []Target{
		{OS: "linux", Arch: "amd64", AMD64Level: 1}, {OS: "linux", Arch: "amd64", AMD64Level: 3},
		{OS: "linux", Arch: "arm64"}, {OS: "linux", Arch: "arm", ARM: 7}, {OS: "linux", Arch: "arm", ARM: 5},
		{OS: "linux", Arch: "386"}, {OS: "linux", Arch: "mipsle", Float: "softfloat"}, {OS: "linux", Arch: "mips", Float: "hardfloat"},
		{OS: "darwin", Arch: "amd64", AMD64Level: 2}, {OS: "darwin", Arch: "arm64"},
		{OS: "windows", Arch: "amd64", AMD64Level: 3}, {OS: "windows", Arch: "arm64"},
		{OS: "freebsd", Arch: "amd64", AMD64Level: 1},
	}
	for name, k := range m {
		rel := k.Releases[0]
		for _, tg := range targets {
			a, err := AssetFor(name, rel.Version, tg)
			if err != nil {
				// The primary kernels run everywhere conch does; sing-box
				// and trojan-go have no builds for some systems.
				if name == "mihomo" || name == "xray" {
					t.Errorf("%s %+v: %v", name, tg, err)
				}
				continue
			}
			if rel.Assets[a.Name] == "" {
				t.Errorf("%s %+v: asset %s is not in the manifest", name, tg, a.Name)
			}
		}
	}
}

// The recommended release is the one CI tests conch with, so it must be
// marked verified; a release added to the manifest is not until then.
func TestRecommendedReleasesAreVerified(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range m {
		if len(k.Releases) == 0 || !k.Releases[0].Verified {
			t.Errorf("%s: the recommended release %s is not marked verified", name, k.Releases[0].Version)
		}
		if got := Verified(name); len(got) == 0 || got[0] != k.Releases[0].Version {
			t.Errorf("Verified(%q) = %v", name, got)
		}
	}
	if IsVerified("xray", "v26.3.27") || !IsVerified("xray", "v26.11.9") {
		t.Error("xray v26.3.27 predates the configs conch writes; v26.11.9 is the one tested")
	}
}
