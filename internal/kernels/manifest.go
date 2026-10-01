// Package kernels downloads and verifies kernel binaries. Every nautilus
// release embeds the sha256 of each tested kernel asset, so downloads can
// be verified even when they come through a mirror.
package kernels

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"runtime"

	"golang.org/x/sys/cpu"
)

//go:generate go run ./gen -kernel mihomo -repo MetaCubeX/mihomo -version v1.19.32 -file kernels.json

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

// AssetName returns the release asset of a kernel for a target.
func AssetName(kernel, version string, t Target) (string, error) {
	if kernel != "mihomo" {
		return "", fmt.Errorf("还不支持自动选择 %s 的安装包，请用 --asset 指定", kernel)
	}
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
		return "", fmt.Errorf("不认识的 CPU 架构 %s，请用 --asset 指定安装包", t.Arch)
	}
	ext := ".gz"
	if t.OS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("mihomo-%s-%s-%s%s", t.OS, arch, version, ext), nil
}

// BinaryName is the executable's file name on disk.
func BinaryName(kernel, goos string) string {
	if goos == "windows" {
		return kernel + ".exe"
	}
	return kernel
}
