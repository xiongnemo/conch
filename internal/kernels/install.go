package kernels

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"nautilus/internal/fetch"
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
	asset, err := AssetFor(o.Kernel, version, o.Target)
	if o.Asset != "" {
		// An explicit asset is normally a variant for this machine (e.g. a
		// "compatible" build), so the extraction plan still applies.
		asset.Name = o.Asset
		if strings.HasSuffix(o.Asset, ".gz") {
			asset.Files = map[string]string{"": BinaryName(o.Kernel, o.Target.OS)}
		}
	} else if err != nil {
		return nil, err
	}

	var want string
	if rel := k.Release(version); rel != nil {
		want = rel.Assets[asset.Name]
	} else {
		fmt.Fprintf(o.Log, "%s %s 不在内置清单里，改用 GitHub 提供的校验值\n", o.Kernel, version)
		digests, err := githubDigests(ctx, o.HTTP, k.Repo, version)
		if err != nil {
			return nil, err
		}
		want = digests[asset.Name]
	}
	if want == "" {
		return nil, fmt.Errorf("%s %s 没有 %s 这个安装包（可以用 --asset 指定）", o.Kernel, version, asset.Name)
	}

	dest := filepath.Join(o.Dir, "kernels", o.Kernel, version)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dest, asset.Name+".*.part")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	url := fetch.Mirrored(o.Mirror, fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", k.Repo, version, asset.Name))
	fmt.Fprintf(o.Log, "下载 %s\n", url)
	got, err := fetch.To(ctx, o.HTTP, url, tmp)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("%s 校验失败（期望 sha256 %s，实际 %s），文件可能不完整或被篡改", asset.Name, want, got)
	}

	bin := BinaryName(o.Kernel, o.Target.OS)
	if err := unpack(tmp.Name(), asset, dest, bin); err != nil {
		return nil, fmt.Errorf("解压 %s：%w", asset.Name, err)
	}
	if err := os.WriteFile(filepath.Join(o.Dir, "kernels", o.Kernel, "current"), []byte(version+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &Installed{Kernel: o.Kernel, Version: version, Path: filepath.Join(dest, bin)}, nil
}

// NotInstalledError means a kernel has never been installed.
type NotInstalledError struct{ Kernel string }

func (e *NotInstalledError) Error() string {
	return fmt.Sprintf("还没有安装 %s，请先运行 nautilus kernel install %s", e.Kernel, e.Kernel)
}

// Current returns the path of the kernel marked as current.
func Current(dir, kernel, goos string) (*Installed, error) {
	data, err := os.ReadFile(filepath.Join(dir, "kernels", kernel, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, &NotInstalledError{Kernel: kernel}
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

// unpack extracts the files named by asset.Files into dir. The kernel
// binary must be present; other files (e.g. wintun.dll) are optional.
func unpack(archive string, asset Asset, dir, bin string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	if strings.HasSuffix(asset.Name, ".tar.gz") {
		return untar(f, asset, dir, bin)
	}
	if strings.HasSuffix(asset.Name, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		return writeFile(filepath.Join(dir, bin), zr)
	}
	if !strings.HasSuffix(asset.Name, ".zip") {
		return fmt.Errorf("不支持的安装包格式")
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return err
	}
	for pattern, local := range asset.Files {
		var member *zip.File
		for _, zf := range zr.File {
			if ok, _ := path.Match(pattern, zf.Name); ok && !zf.FileInfo().IsDir() {
				member = zf
				break
			}
		}
		if member == nil {
			if local == bin {
				return fmt.Errorf("压缩包里没有 %s", pattern)
			}
			continue
		}
		rc, err := member.Open()
		if err != nil {
			return err
		}
		err = writeFile(filepath.Join(dir, local), rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// untar extracts the files an asset names from a .tar.gz archive.
func untar(r io.Reader, asset Asset, dir, bin string) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	found := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		for pattern, local := range asset.Files {
			if ok, _ := path.Match(pattern, h.Name); ok && !found[local] {
				if err := writeFile(filepath.Join(dir, local), tr); err != nil {
					return err
				}
				found[local] = true
				break
			}
		}
	}
	if !found[bin] {
		return fmt.Errorf("压缩包里没有 %s", bin)
	}
	return nil
}

// writeFile atomically writes an executable file.
func writeFile(dst string, src io.Reader) error {
	tmp := dst + ".tmp"
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
	return os.Rename(tmp, dst)
}
