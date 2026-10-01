package kernels

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const geodataBase = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"

// geodataFiles maps release file names to the names mihomo looks for.
// mihomo downloads missing geodata synchronously while parsing its config
// and fails to start if that download fails, so we fetch it beforehand.
var geodataFiles = []struct{ remote, local string }{
	{"geoip.metadb", "geoip.metadb"},
	{"geosite.dat", "geosite.dat"},
	{"GeoLite2-ASN.mmdb", "ASN.mmdb"},
}

// FetchGeodata downloads mihomo's geodata into dir, verifying each file
// against the .sha256sum published next to it.
func FetchGeodata(ctx context.Context, client *http.Client, mirror, dir string, log io.Writer) error {
	if client == nil {
		client = http.DefaultClient
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range geodataFiles {
		url := Mirrored(mirror, geodataBase+f.remote)
		var sumFile bytes.Buffer
		if _, err := Fetch(ctx, client, url+".sha256sum", &sumFile); err != nil {
			return err
		}
		want, _, _ := strings.Cut(strings.TrimSpace(sumFile.String()), " ")
		if len(want) != 64 {
			return fmt.Errorf("%s.sha256sum 的内容无法识别", f.remote)
		}

		fmt.Fprintf(log, "下载 %s\n", url)
		tmp, err := os.CreateTemp(dir, f.local+".*.part")
		if err != nil {
			return err
		}
		got, err := Fetch(ctx, client, url, tmp)
		tmp.Close()
		if err == nil && got != want {
			err = fmt.Errorf("%s 校验失败，文件可能不完整", f.remote)
		}
		if err == nil {
			err = os.Rename(tmp.Name(), filepath.Join(dir, f.local))
		}
		if err != nil {
			os.Remove(tmp.Name())
			return err
		}
	}
	return nil
}
