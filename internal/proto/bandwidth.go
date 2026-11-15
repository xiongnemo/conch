package proto

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Bandwidth hints (hysteria2's up and down) mean different things to each
// kernel: mihomo reads "100 Mbps" as bits and "100 MBps" as bytes but
// ignores "100 mbps", xray reads every unit as bits in steps of 1024, and
// sing-box takes whole Mbps. A Spec holds them as bits per second, and
// each backend writes its own form.

var rate = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)([bB])(?:ps|/s)?$`)

// ParseBandwidth reads a bandwidth as mihomo writes it ("100 Mbps", or
// bytes: "12 MBps"; a bare number is Mbps), also in lower case or with
// decimals, which hysteria's own configs use. Prefixes are powers of 1000.
func ParseBandwidth(s string) (bits uint64, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil && v > 0 {
		return uint64(math.Round(v * 1e6)), true
	}
	m := rate.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	mul := map[string]float64{"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}[strings.ToLower(m[2])]
	if m[3] == "B" {
		mul *= 8
	}
	return uint64(math.Round(v * mul)), true
}

// FormatBandwidth writes bits per second the way mihomo reads them, in the
// largest unit that keeps the value whole.
func FormatBandwidth(bits uint64) string {
	if bits == 0 {
		return ""
	}
	for _, u := range []struct {
		n    uint64
		name string
	}{{1e12, "Tbps"}, {1e9, "Gbps"}, {1e6, "Mbps"}, {1e3, "Kbps"}} {
		if bits%u.n == 0 {
			return fmt.Sprintf("%d %s", bits/u.n, u.name)
		}
	}
	return fmt.Sprintf("%d bps", bits)
}
