package route

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"nautilus/internal/model"
)

// Provider is a rule set the kernel downloads and keeps up to date.
type Provider struct {
	Name     string
	Behavior string // domain | ipcidr | classical
	Format   string // mrs | yaml | text
	URL      string
	TextURL  string // plain-text variant, used for local explanations

	// Geo and Category identify geosite:/geoip: categories, which some
	// kernels (xray) load from their own geodata files instead of a URL.
	Geo      string // geosite | geoip
	Category string

	// Payload holds the rules of an inline provider (no URL).
	Payload []string
	// Exceptions selects the "@@" entries of an AutoProxy list; the other
	// provider for the same list holds the remaining entries.
	Exceptions bool
}

const defaultListBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/"

// Presets are friendly names for commonly used categories.
var presets = map[string]string{
	"ads":     "geosite:category-ads-all",
	"ai":      "geosite:category-ai-!cn",
	"gfwlist": "geosite:gfw",
}

func listBase(mirror string) (string, error) {
	switch m := strings.TrimSpace(mirror); strings.ToLower(m) {
	case "", "github":
		return defaultListBase, nil
	case "jsdelivr":
		return "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/", nil
	default:
		if !strings.HasPrefix(m, "https://") && !strings.HasPrefix(m, "http://") {
			return "", fmt.Errorf("list-mirror 应该是 github、jsdelivr 或一个 http(s):// 开头的地址，而不是 %q", mirror)
		}
		return strings.TrimSuffix(m, "/") + "/", nil
	}
}

var categoryRe = regexp.MustCompile(`^[a-z0-9][a-z0-9!@._-]*$`)

// resolveList turns a list reference into a provider definition.
func resolveList(ref *model.ListRef, base string) (Provider, error) {
	name := strings.TrimSpace(ref.List)
	if p, ok := presets[strings.ToLower(name)]; ok {
		name = p
	}
	lower := strings.ToLower(name)
	for _, kind := range []struct{ prefix, behavior string }{
		{"geosite:", "domain"},
		{"geoip:", "ipcidr"},
	} {
		if !strings.HasPrefix(lower, kind.prefix) {
			continue
		}
		cat := lower[len(kind.prefix):]
		if !categoryRe.MatchString(cat) {
			return Provider{}, fmt.Errorf("%q 不是有效的分类名", cat)
		}
		if ref.Behavior != "" || ref.Format != "" {
			return Provider{}, fmt.Errorf("%s 列表的 behavior/format 是固定的，不需要填写", kind.prefix)
		}
		geo := strings.TrimSuffix(kind.prefix, ":")
		dir := "geo/" + geo + "/"
		return Provider{
			Name:     geo + "-" + cat,
			Behavior: kind.behavior,
			Format:   "mrs",
			URL:      base + dir + cat + ".mrs",
			TextURL:  base + dir + cat + ".list",
			Geo:      geo,
			Category: cat,
		}, nil
	}
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return urlProvider(name, ref)
	}
	return Provider{}, fmt.Errorf("不认识的规则列表 %q（可以用 ads、ai、gfwlist、geosite:<分类>、geoip:<分类>，或一个 http(s) 地址）", ref.List)
}

func urlProvider(raw string, ref *model.ListRef) (Provider, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Provider{}, fmt.Errorf("%q 不是有效的地址", raw)
	}
	base := path.Base(u.Path)
	ext := strings.ToLower(path.Ext(base))
	format := strings.ToLower(ref.Format)
	if format == "autoproxy" {
		return Provider{Name: "list-" + slug(base), Behavior: "domain", Format: format, URL: raw}, nil
	}
	if format == "" {
		switch ext {
		case ".mrs":
			format = "mrs"
		case ".yaml", ".yml":
			format = "yaml"
		default:
			format = "text"
		}
	}
	behavior := strings.ToLower(ref.Behavior)
	if behavior == "" {
		behavior = "classical"
	}
	switch {
	case format != "mrs" && format != "yaml" && format != "text":
		return Provider{}, fmt.Errorf("format 只能是 mrs、yaml、text 或 autoproxy，而不是 %q", ref.Format)
	case behavior != "domain" && behavior != "ipcidr" && behavior != "classical":
		return Provider{}, fmt.Errorf("behavior 只能是 domain、ipcidr 或 classical，而不是 %q", ref.Behavior)
	case format == "mrs" && behavior == "classical":
		return Provider{}, fmt.Errorf("mrs 格式的列表需要写明 behavior: domain 或 behavior: ipcidr")
	}
	return Provider{Name: "list-" + slug(base), Behavior: behavior, Format: format, URL: raw}, nil
}

func slug(file string) string {
	stem := strings.ToLower(strings.TrimSuffix(file, path.Ext(file)))
	stem = strings.Trim(nonSlug.ReplaceAllString(stem, "-"), "-")
	if stem == "" {
		return "custom"
	}
	return stem
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// TargetField finds which field of a Clash rule line names the outbound,
// e.g. to rename targets of imported rules. MATCH has its target second.
func TargetField(fields []string) (int, error) {
	if strings.EqualFold(fields[0], "MATCH") {
		if len(fields) < 2 {
			return 0, fmt.Errorf("MATCH 缺少出口")
		}
		return 1, nil
	}
	return rawTargetField(fields)
}

// rawTargetField finds which field of a raw Clash rule line names the
// outbound. Logical and regex rules may contain commas in their payload, so
// their target is the last field (ignoring trailing options).
func rawTargetField(fields []string) (int, error) {
	typ := strings.ToUpper(fields[0])
	switch {
	case typ == "MATCH":
		return 0, fmt.Errorf("规则列表里不能写 MATCH，默认出口请写在 routes.default")
	case typ == "SUB-RULE":
		return 0, fmt.Errorf("暂不支持 SUB-RULE")
	case typ == "AND" || typ == "OR" || typ == "NOT" || strings.HasSuffix(typ, "-REGEX"):
		i := len(fields) - 1
		for i > 1 && isRuleOption(fields[i]) {
			i--
		}
		if i < 2 {
			return 0, fmt.Errorf("规则缺少出口")
		}
		return i, nil
	default:
		if len(fields) < 3 {
			return 0, fmt.Errorf("规则应该写成「类型,内容,出口」")
		}
		return 2, nil
	}
}

func isRuleOption(s string) bool {
	return s == "no-resolve" || s == "src"
}
