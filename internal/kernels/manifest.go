// Package kernels downloads and verifies kernel binaries. Every nautilus
// release embeds the sha256 of each tested kernel asset, so downloads can
// be verified even when they come through a mirror.
package kernels

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/sys/cpu"
)

//go:generate go run ./gen -kernel mihomo -repo MetaCubeX/mihomo -version v1.19.32 -file kernels.json
//go:generate go run ./gen -kernel xray -repo XTLS/Xray-core -version v26.3.27 -file kernels.json
//go:generate go run ./gen -kernel trojan-go -repo p4gefau1t/trojan-go -version v0.10.6 -file kernels.json
//go:generate go run ./gen -kernel sing-box -repo SagerNet/sing-box -version v1.14.2 -file kernels.json

//go:embed kernels.json
var manifestJSON []byte

// Manifest maps a kernel name to its tested releases.
type Manifest map[string]*Kernel

type Kernel struct {
	Repo     string     `json:"repo"`     // GitHub owner/name
	Releases []*Release `json:"releases"` // tested releases, recommended first
}

type Release struct {
	Version string            `json:"version"`
	Assets  map[string]string `json:"assets"` // asset file name → sha256 hex
}

// Embedded returns the manifest compiled into this binary.
func Embedded() (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("内置内核清单损坏：%w", err)
	}
	return m, nil
}

func (k *Kernel) Release(version string) *Release {
	for _, r := range k.Releases {
		if r.Version == version {
			return r
		}
	}
	return nil
}

// Target describes the machine a kernel will run on.
type Target struct {
	OS         string
	Arch       string
	AMD64Level int    // 1–3, amd64 only
	ARM        int    // 5–7, 32-bit arm only
	Float      string // softfloat | hardfloat, mips only
}

// Host describes the current machine.
func Host() Target {
	t := Target{OS: runtime.GOOS, Arch: runtime.GOARCH, ARM: 7, Float: "softfloat"}
	if t.Arch == "amd64" {
		t.AMD64Level = amd64Level()
	}
	return t
}

// amd64Level reports the x86-64 microarchitecture level. Plain "amd64"
// mihomo builds require v3 (AVX2), so older CPUs need an explicit level.
func amd64Level() int {
	x := cpu.X86
	if !(x.HasSSE3 && x.HasSSSE3 && x.HasSSE41 && x.HasSSE42 && x.HasPOPCNT && x.HasCX16) {
		return 1
	}
	if !(x.HasAVX && x.HasAVX2 && x.HasBMI1 && x.HasBMI2 && x.HasFMA && x.HasOSXSAVE) {
		return 2
	}
	return 3
}

// Asset is a release file and what to take out of it.
type Asset struct {
	Name string
	// Files maps archive members (path.Match patterns) to local file names.
	// A .gz asset holds a single file, so its only key is "".
	Files map[string]string
}

// AssetFor returns the release asset of a kernel for a target.
func AssetFor(kernel, version string, t Target) (Asset, error) {
	switch kernel {
	case "mihomo":
		return mihomoAsset(version, t)
	case "xray":
		return xrayAsset(t)
	case "trojan-go":
		return trojanGoAsset(t)
	case "sing-box":
		return singBoxAsset(version, t)
	}
	return Asset{}, fmt.Errorf("不认识的内核 %q", kernel)
}

func singBoxAsset(version string, t Target) (Asset, error) {
	var arch string
	switch t.Arch {
	case "amd64", "386", "arm64", "riscv64", "loong64", "s390x", "ppc64le":
		arch = t.Arch
	case "arm":
		arch = fmt.Sprintf("armv%d", t.ARM)
	case "mips", "mips64":
		arch = t.Arch + "-softfloat" // the only build; it runs on hardfloat CPUs too
	case "mipsle", "mips64le":
		arch = t.Arch
		if t.Float == "softfloat" {
			arch += "-softfloat"
		}
	}
	v := strings.TrimPrefix(version, "v")
	bin := BinaryName("sing-box", t.OS)
	switch {
	case arch == "":
	case t.OS == "windows" && (t.Arch == "amd64" || t.Arch == "386" || t.Arch == "arm64"):
		return Asset{Name: fmt.Sprintf("sing-box-%s-windows-%s.zip", v, arch), Files: map[string]string{"*/" + bin: bin}}, nil
	case t.OS == "linux" || t.OS == "darwin" && (t.Arch == "amd64" || t.Arch == "arm64"):
		return Asset{Name: fmt.Sprintf("sing-box-%s-%s-%s.tar.gz", v, t.OS, arch), Files: map[string]string{"*/" + bin: bin}}, nil
	}
	return Asset{}, fmt.Errorf("sing-box 没有 %s/%s 的安装包", t.OS, t.Arch)
}

// trojan-go only runs as a sidecar for trojan-go nodes; its last release
// is v0.10.6.
func trojanGoAsset(t Target) (Asset, error) {
	var arch string
	switch t.Arch {
	case "amd64", "386", "mips64", "mips64le":
		arch = t.Arch
	case "arm64":
		arch = "armv8"
		if t.OS == "darwin" || t.OS == "windows" {
			arch = "arm64"
		}
	case "arm":
		arch = fmt.Sprintf("armv%d", t.ARM)
	case "mips", "mipsle":
		arch = t.Arch + "-" + t.Float
	}
	if arch == "" || t.OS != "linux" && t.OS != "darwin" && t.OS != "windows" && t.OS != "freebsd" {
		return Asset{}, fmt.Errorf("trojan-go 没有 %s/%s 的安装包", t.OS, t.Arch)
	}
	bin := BinaryName("trojan-go", t.OS)
	return Asset{Name: fmt.Sprintf("trojan-go-%s-%s.zip", t.OS, arch), Files: map[string]string{bin: bin}}, nil
}

func mihomoAsset(version string, t Target) (Asset, error) {
	var arch string
	switch t.Arch {
	case "amd64":
		arch = fmt.Sprintf("amd64-v%d", t.AMD64Level)
	case "arm64", "386", "mips64", "mips64le", "riscv64", "ppc64le", "s390x":
		arch = t.Arch
	case "arm":
		arch = fmt.Sprintf("armv%d", t.ARM)
	case "mips", "mipsle":
		arch = t.Arch + "-" + t.Float
	case "loong64":
		arch = "loong64-abi2"
	default:
		return Asset{}, fmt.Errorf("不认识的 CPU 架构 %s，请用 --asset 指定安装包", t.Arch)
	}
	bin := BinaryName("mihomo", t.OS)
	if t.OS == "windows" {
		return Asset{Name: fmt.Sprintf("mihomo-windows-%s-%s.zip", arch, version), Files: map[string]string{"*.exe": bin}}, nil
	}
	return Asset{Name: fmt.Sprintf("mihomo-%s-%s-%s.gz", t.OS, arch, version), Files: map[string]string{"": bin}}, nil
}

func xrayAsset(t Target) (Asset, error) {
	osName := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows", "freebsd": "freebsd", "openbsd": "openbsd"}[t.OS]
	var arch string
	switch t.Arch {
	case "amd64":
		arch = "64"
	case "386":
		arch = "32"
	case "arm64":
		arch = "arm64-v8a"
	case "arm":
		arch = map[int]string{5: "arm32-v5", 6: "arm32-v6", 7: "arm32-v7a"}[t.ARM]
	case "mips":
		arch = "mips32"
	case "mipsle":
		arch = "mips32le"
	case "mips64", "mips64le", "riscv64", "loong64", "ppc64", "ppc64le", "s390x":
		arch = t.Arch
	}
	if osName == "" || arch == "" {
		return Asset{}, fmt.Errorf("xray 没有 %s/%s 的安装包，请用 --asset 指定", t.OS, t.Arch)
	}
	bin := BinaryName("xray", t.OS)
	files := map[string]string{bin: bin}
	switch {
	case t.OS == "windows":
		files["wintun.dll"] = "wintun.dll" // needed for TUN
	case (t.Arch == "mips" || t.Arch == "mipsle") && t.Float == "softfloat":
		files = map[string]string{"xray_softfloat": bin}
	}
	return Asset{Name: fmt.Sprintf("Xray-%s-%s.zip", osName, arch), Files: files}, nil
}

// BinaryName is the executable's file name on disk.
func BinaryName(kernel, goos string) string {
	if goos == "windows" {
		return kernel + ".exe"
	}
	return kernel
}
