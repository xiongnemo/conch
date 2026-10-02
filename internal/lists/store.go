package lists

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/xiongnemo/conch/internal/fetch"
	"github.com/xiongnemo/conch/internal/route"
)

// ErrNotCached means an offline store has not downloaded a list.
var ErrNotCached = errors.New("还没有下载")

// Store keeps downloaded rule lists in a cache directory.
type Store struct {
	Dir     string
	HTTP    *http.Client
	Offline bool      // never download; use the cache only
	Log     io.Writer // progress messages; may be nil
	// Proxy returns the running kernel's HTTP proxy, which a download that
	// failed directly tries next; nil, or a nil URL, means no second try.
	Proxy func() *url.URL
}

// Load returns a provider's entries, downloading it when it is not cached.
// A download that does not parse never replaces a cached copy.
func (s *Store) Load(ctx context.Context, p route.Provider) ([]Entry, []string, error) {
	path := s.path(p)
	if data, err := os.ReadFile(path); err == nil {
		return Parse(data, p.Format, p.Behavior)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if s.Offline {
		return nil, nil, fmt.Errorf("规则列表 %s %w（离线模式）", p.URL, ErrNotCached)
	}
	if err := s.Update(ctx, p); err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(data, p.Format, p.Behavior)
}

// Update downloads a provider and replaces the cached copy if it parses.
func (s *Store) Update(ctx context.Context, p route.Provider) error {
	if s.Log != nil {
		fmt.Fprintf(s.Log, "下载规则列表 %s\n", p.URL)
	}
	var buf bytes.Buffer
	if _, err := fetch.To(ctx, s.HTTP, p.URL, &buf); err != nil {
		var proxy *url.URL
		if s.Proxy != nil && ctx.Err() == nil {
			proxy = s.Proxy()
		}
		if proxy == nil {
			return err
		}
		buf.Reset()
		if _, err2 := fetch.To(ctx, fetch.Via(proxy), p.URL, &buf); err2 != nil {
			return fmt.Errorf("%w；经由内核下载也失败：%v", err, err2)
		}
	}
	if _, _, err := Parse(buf.Bytes(), p.Format, p.Behavior); err != nil {
		return fmt.Errorf("规则列表 %s：%w", p.URL, err)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	path := s.path(p)
	tmp := path + ".part"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Refresh downloads again the lists among ps that were downloaded more
// than maxAge ago, and reports whether any of them changed. Lists never
// downloaded stay that way; one that fails is tried again in an hour.
func (s *Store) Refresh(ctx context.Context, ps []route.Provider, maxAge time.Duration, now time.Time) bool {
	if s.Offline {
		return false
	}
	changed := false
	seen := map[string]bool{}
	for _, p := range ps {
		var copies []route.Provider // the list, and its text twin for explanations
		if p.URL != "" {
			copies = append(copies, p)
		}
		if p.TextURL != "" {
			q := p
			q.URL, q.Format = p.TextURL, "text"
			copies = append(copies, q)
		}
		for _, q := range copies {
			path := s.path(q)
			fi, err := os.Stat(path)
			if seen[path] || err != nil || now.Sub(fi.ModTime()) < maxAge {
				continue
			}
			seen[path] = true
			old, _ := os.ReadFile(path)
			if err := s.Update(ctx, q); err != nil {
				later := now.Add(time.Hour - maxAge)
				os.Chtimes(path, later, later)
				if s.Log != nil {
					fmt.Fprintf(s.Log, "更新规则列表失败，一小时后重试：%v\n", err)
				}
				continue
			}
			if fresh, _ := os.ReadFile(path); !bytes.Equal(old, fresh) {
				changed = true
			}
		}
	}
	return changed
}

func (s *Store) path(p route.Provider) string {
	sum := sha256.Sum256([]byte(p.URL))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:8])+"."+p.Format)
}
