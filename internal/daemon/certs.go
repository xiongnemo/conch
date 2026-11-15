package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/xiongnemo/conch/internal/certpin"
	"github.com/xiongnemo/conch/internal/compile"
	"github.com/xiongnemo/conch/internal/proto"
	"github.com/xiongnemo/conch/internal/sidecar"
)

// LearnedCerts finds the certificate pins a daemon with dataDir learned,
// for configs compiled outside it.
func LearnedCerts(dataDir string) certpin.Lookup {
	return certpin.Open(certsPath(dataDir)).Lookup
}

func certsPath(dataDir string) string { return filepath.Join(dataDir, "certs.json") }

// pinRetry is when a certificate pin that could not be learned is tried next.
type pinRetry struct {
	wait time.Duration
	next time.Time
}

// pinTargets are where the certificates behind the pins of res's nodes
// can be fetched, with a node name for each pin, for messages: the
// nodes of trojan-go sidecars, which cannot pin, and all nodes when the
// kernel cannot check a certificate's hash either.
func (d *Daemon) pinTargets(res *compile.Result) ([]certpin.Target, map[string]string) {
	all := !d.backend.Capabilities().CertSHA256
	var targets []certpin.Target
	names := map[string]string{}
	for _, p := range res.Proxies {
		if p.Kind != compile.ProxyNode {
			continue
		}
		var t certpin.Target
		ok := false
		switch {
		case sidecar.Needs(p, d.backend.Capabilities().TrojanSS):
			t, ok = sidecar.PinTarget(p.Node)
		case all:
			t, ok = certpin.TargetOf(proto.FromClash(p.Node.Raw))
		}
		if !ok {
			continue
		}
		key, ok := certpin.Normalize(t.Pin)
		if !ok {
			continue
		}
		targets = append(targets, t)
		if names[key] == "" {
			names[key] = p.Name
		}
	}
	return targets, names
}

// learnPins makes sure the pins of res's nodes are known before kernels
// or sidecars that cannot check a certificate's hash get configs. Pins never
// tried are fetched now, for a few seconds at most; ones that failed
// wait for their retry (retryPins), so a dead server does not hold
// every reconcile.
func (d *Daemon) learnPins(ctx context.Context, res *compile.Result) {
	targets, names := d.pinTargets(res)
	d.mu.Lock()
	var fresh []certpin.Target
	for _, t := range targets {
		key, _ := certpin.Normalize(t.Pin)
		if _, waiting := d.pinRetry[key]; !waiting {
			fresh = append(fresh, t)
		}
	}
	d.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d.notePins(d.certs.Learn(ctx, fresh), names, time.Now())
}

// retryPins tries again the pins whose retry is due. It reports whether
// it learned any, which calls for a reconcile.
func (d *Daemon) retryPins(ctx context.Context, now time.Time) bool {
	d.mu.Lock()
	res := d.res
	due := map[string]bool{}
	for key, r := range d.pinRetry {
		if !now.Before(r.next) {
			due[key] = true
		}
	}
	d.mu.Unlock()
	if res == nil || len(due) == 0 {
		return false
	}
	targets, names := d.pinTargets(res)
	var retry []certpin.Target
	for _, t := range targets {
		if key, _ := certpin.Normalize(t.Pin); due[key] {
			retry = append(retry, t)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	failed := d.certs.Learn(ctx, retry)
	d.notePins(failed, names, now)
	learned := false
	for _, t := range retry {
		if _, ok := d.certs.Lookup(t.Pin); ok {
			learned = true
		}
	}
	return learned
}

// notePins schedules the pins that failed for another try, a minute
// later doubling up to half an hour, and forgets the retries of the
// ones learned.
func (d *Daemon) notePins(failed map[string]error, names map[string]string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pinRetry {
		if _, ok := d.certs.Lookup(key); ok {
			delete(d.pinRetry, key)
			fmt.Fprintf(d.opts.Log, "取到了节点 %s 的证书，改为按证书指纹校验\n", names[key])
		}
	}
	for key, err := range failed {
		r := d.pinRetry[key]
		r.wait = min(max(2*r.wait, time.Minute), 30*time.Minute)
		r.next = now.Add(r.wait)
		d.pinRetry[key] = r
		why := err.Error()
		if errors.Is(err, certpin.ErrNotInChain) {
			why = "服务器的证书和指纹对不上：指纹写错了，或者连接被人截持了"
		}
		fmt.Fprintf(d.opts.Log, "取节点 %s 的证书失败，%s 后重试：%s\n", names[key], r.wait, why)
	}
}
