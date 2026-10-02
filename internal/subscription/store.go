package subscription

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

	"github.com/xiongnemo/conch/internal/model"
)

// DefaultUserAgent makes most providers answer with a Clash/mihomo config,
// which carries more than share links do (groups, rules).
const DefaultUserAgent = "clash.meta"

const maxBody = 32 << 20

// Info is what a provider reports about the subscription.
type Info struct {
	FetchedAt      time.Time `json:"fetchedAt"`
	Upload         int64     `json:"upload,omitempty"`
	Download       int64     `json:"download,omitempty"`
	Total          int64     `json:"total,omitempty"`
	Expire         int64     `json:"expire,omitempty"`         // unix seconds
	UpdateInterval int       `json:"updateInterval,omitempty"` // hours, from profile-update-interval
	Summary        string    `json:"summary,omitempty"`        // what it brings, e.g. "38 个节点，…"
}

// Store keeps downloaded subscriptions, and the proxy-providers they use,
// in a cache directory.
type Store struct {
	Dir     string
	HTTP    *http.Client
	Offline bool
	Log     io.Writer
}

// Load returns a subscription from the cache, downloading it if missing.
func (s *Store) Load(ctx context.Context, sub *model.Subscription) (*Snapshot, *Info, error) {
	body, err := os.ReadFile(s.path(sub, "body"))
	if errors.Is(err, os.ErrNotExist) {
		if s.Offline {
			return nil, nil, fmt.Errorf("订阅 %q 还没有下载（离线模式）", sub.Name)
		}
		return s.Update(ctx, sub)
	}
	if err != nil {
		return nil, nil, err
	}
	snap, err := Parse(body, func(url string) ([]byte, error) { return os.ReadFile(s.providerPath(sub, url)) })
	if err != nil {
		return nil, nil, fmt.Errorf("订阅 %q 的缓存无法解析：%w", sub.Name, err)
	}
	var info Info
	if data, err := os.ReadFile(s.path(sub, "json")); err == nil {
		json.Unmarshal(data, &info)
	}
	info.Summary = snap.Summary()
	return snap, &info, nil
}

// Update downloads a subscription. The cache is only replaced when the new
// content parses and has nodes, so a broken response never wipes it.
func (s *Store) Update(ctx context.Context, sub *model.Subscription) (*Snapshot, *Info, error) {
	ua := sub.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	if s.Log != nil {
		fmt.Fprintf(s.Log, "更新订阅 %s\n", sub.Name)
	}
	body, header, err := s.get(ctx, sub.URL, ua)
	if err != nil {
		return nil, nil, fmt.Errorf("订阅 %q：%w", sub.Name, err)
	}
	providers := map[string][]byte{}
	snap, err := Parse(body, func(url string) ([]byte, error) {
		b, _, err := s.get(ctx, url, ua)
		if err == nil {
			providers[url] = b
		}
		return b, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("订阅 %q：%w（已保留之前的缓存）", sub.Name, err)
	}
	info := parseInfo(header)
	info.FetchedAt = time.Now().UTC().Truncate(time.Second)
	info.Summary = snap.Summary()

	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, nil, err
	}
	for url, b := range providers {
		if err := writeAtomic(s.providerPath(sub, url), b); err != nil {
			return nil, nil, err
		}
	}
	meta, _ := json.MarshalIndent(info, "", "  ")
	if err := writeAtomic(s.path(sub, "json"), meta); err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(s.path(sub, "body"), body); err != nil {
		return nil, nil, err
	}
	return snap, &info, nil
}

func (s *Store) get(ctx context.Context, url, ua string) ([]byte, http.Header, error) {
	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("服务器返回 %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxBody {
		return nil, nil, fmt.Errorf("订阅内容超过 %d MB", maxBody>>20)
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("<")) {
		return nil, nil, fmt.Errorf("服务器返回的是网页而不是订阅内容，请检查订阅地址或网络")
	}
	return body, resp.Header, nil
}

// parseInfo reads "subscription-userinfo: upload=1; download=2; total=3; expire=4".
func parseInfo(h http.Header) Info {
	var info Info
	for part := range strings.SplitSeq(h.Get("Subscription-Userinfo"), ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.ToLower(k) {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			info.Expire = n
		}
	}
	info.UpdateInterval, _ = strconv.Atoi(strings.TrimSpace(h.Get("Profile-Update-Interval")))
	return info
}

// path names cache files by subscription name and URL, so changing the URL
// never serves the old provider's content.
func (s *Store) path(sub *model.Subscription, ext string) string {
	return filepath.Join(s.Dir, safeName(sub.Name)+"-"+hash(sub.URL)+"."+ext)
}

func (s *Store) providerPath(sub *model.Subscription, url string) string {
	return filepath.Join(s.Dir, safeName(sub.Name)+"-provider-"+hash(url)+".body")
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func safeName(name string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>| `, r) {
			return '_'
		}
		return r
	}, name)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
