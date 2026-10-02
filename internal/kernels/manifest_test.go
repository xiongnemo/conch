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
