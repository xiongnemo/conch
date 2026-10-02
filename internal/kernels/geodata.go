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

	"github.com/xiongnemo/conch/internal/fetch"
)

const geodataBase = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"

type geoFile struct{ remote, local string }

// geodataFiles maps release file names to the names each kernel looks for.
// mihomo downloads missing geodata synchronously while parsing its config
// and fails to start if that download fails; xray refuses to start without
// the files its rules reference. So we fetch them beforehand, from the same
// source for both kernels so category names agree.
var geodataFiles = map[string][]geoFile{
	"mihomo": {{"geoip.metadb", "geoip.metadb"}, {"geosite.dat", "geosite.dat"}, {"GeoLite2-ASN.mmdb", "ASN.mmdb"}},
	"xray":   {{"geoip.dat", "geoip.dat"}, {"geosite.dat", "geosite.dat"}},
}

// HasGeodata reports whether dir holds every geodata file a kernel uses.
func HasGeodata(kernel, dir string) bool {
	for _, f := range geodataFiles[kernel] {
		if _, err := os.Stat(filepath.Join(dir, f.local)); err != nil {
			return false
		}
	}
	return true
}

// FetchGeodata downloads a kernel's geodata into dir, verifying each file
// against the .sha256sum published next to it.
func FetchGeodata(ctx context.Context, client *http.Client, kernel, mirror, dir string, log io.Writer) error {
	files, ok := geodataFiles[kernel]
	if !ok {
		return fmt.Errorf("不认识的内核 %q", kernel)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		url := fetch.Mirrored(mirror, geodataBase+f.remote)
		var sumFile bytes.Buffer
		if _, err := fetch.To(ctx, client, url+".sha256sum", &sumFile); err != nil {
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
		got, err := fetch.To(ctx, client, url, tmp)
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
