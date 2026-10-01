package kernels

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type InstallOptions struct {
	Kernel  string
	Version string // empty = recommended release
	Asset   string // empty = chosen from Target
	Mirror  string // URL prefix put in front of github.com download links
	Dir     string // data directory
	Target  Target
	HTTP    *http.Client
	Log     io.Writer
}

type Installed struct {
	Kernel  string
	Version string
	Path    string
}

// Install downloads, verifies and unpacks a kernel into
// <Dir>/kernels/<kernel>/<version>/ and marks it as current.
func Install(ctx context.Context, o InstallOptions) (*Installed, error) {
	m, err := Embedded()
	if err != nil {
		return nil, err
	}
	k := m[o.Kernel]
	if k == nil {
		return nil, fmt.Errorf("不认识的内核 %q", o.Kernel)
	}
	if o.HTTP == nil {
		o.HTTP = http.DefaultClient
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	version := o.Version
	if version == "" {
		version = k.Releases[0].Version
	}
	asset := o.Asset
	if asset == "" {
		if asset, err = AssetName(o.Kernel, version, o.Target); err != nil {
			return nil, err
		}
	}

	var want string
	if rel := k.Release(version); rel != nil {
		want = rel.Assets[asset]
	} else {
		fmt.Fprintf(o.Log, "%s %s 不在内置清单里，改用 GitHub 提供的校验值\n", o.Kernel, version)
		digests, err := githubDigests(ctx, o.HTTP, k.Repo, version)
		if err != nil {
			return nil, err
		}
		want = digests[asset]
	}
	if want == "" {
		return nil, fmt.Errorf("%s %s 没有 %s 这个安装包（可以用 --asset 指定）", o.Kernel, version, asset)
	}

	dest := filepath.Join(o.Dir, "kernels", o.Kernel, version)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dest, asset+".*.part")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	url := Mirrored(o.Mirror, fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", k.Repo, version, asset))
	fmt.Fprintf(o.Log, "下载 %s\n", url)
	got, err := Fetch(ctx, o.HTTP, url, tmp)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("%s 校验失败（期望 sha256 %s，实际 %s），文件可能不完整或被篡改", asset, want, got)
	}

	bin := filepath.Join(dest, BinaryName(o.Kernel, o.Target.OS))
	if err := unpack(tmp.Name(), asset, bin); err != nil {
		return nil, fmt.Errorf("解压 %s：%w", asset, err)
	}
	if err := os.WriteFile(filepath.Join(o.Dir, "kernels", o.Kernel, "current"), []byte(version+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &Installed{Kernel: o.Kernel, Version: version, Path: bin}, nil
}

// Current returns the path of the kernel marked as current.
func Current(dir, kernel, goos string) (*Installed, error) {
	data, err := os.ReadFile(filepath.Join(dir, "kernels", kernel, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("还没有安装 %s，请先运行 nautilus kernel install", kernel)
	}
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(string(data))
	return &Installed{
		Kernel:  kernel,
		Version: version,
		Path:    filepath.Join(dir, "kernels", kernel, version, BinaryName(kernel, goos)),
	}, nil
}

// Mirrored prefixes a GitHub URL with a mirror such as https://ghfast.top.
func Mirrored(mirror, url string) string {
	if mirror == "" {
		return url
	}
	return strings.TrimSuffix(mirror, "/") + "/" + url
}

// Fetch streams url into w and returns the sha256 of what was written.
// It refuses HTML responses, which mirrors return for errors and captive
// portals return for everything.
func Fetch(ctx context.Context, client *http.Client, url string, w io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载 %s：%w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载 %s：服务器返回 %s", url, resp.Status)
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return "", fmt.Errorf("下载 %s：服务器返回的是网页而不是文件，请检查网络或镜像地址", url)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", fmt.Errorf("下载 %s：%w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func githubDigests(ctx context.Context, client *http.Client, repo, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 %s %s 的校验值：%w", repo, version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 %s %s 的校验值：GitHub 返回 %s", repo, version, resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, a := range rel.Assets {
		if hexsum, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
			out[a.Name] = hexsum
		}
	}
	return out, nil
}

// unpack extracts the kernel binary from a .gz or .zip asset into bin.
func unpack(archive, asset, bin string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader
	switch {
	case strings.HasSuffix(asset, ".gz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		src = zr
	case strings.HasSuffix(asset, ".zip"):
		st, err := f.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(f, st.Size())
		if err != nil {
			return err
		}
		var exe *zip.File
		for _, zf := range zr.File {
			if !zf.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(zf.Name), ".exe") {
				exe = zf
				break
			}
		}
		if exe == nil {
			return fmt.Errorf("压缩包里没有可执行文件")
		}
		rc, err := exe.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		src = rc
	default:
		return fmt.Errorf("不支持的安装包格式")
	}
	tmp := bin + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, bin)
}
