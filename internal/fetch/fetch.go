// Package fetch downloads files over HTTP with the checks every download
// in nautilus needs.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Mirrored prefixes a GitHub URL with a mirror such as https://ghfast.top.
func Mirrored(mirror, url string) string {
	if mirror == "" {
		return url
	}
	return strings.TrimSuffix(mirror, "/") + "/" + url
}

// To streams url into w and returns the sha256 of what was written. It
// refuses HTML responses, which mirrors return for errors and captive
// portals return for everything.
func To(ctx context.Context, client *http.Client, url string, w io.Writer) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
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
