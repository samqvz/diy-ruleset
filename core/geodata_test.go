package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// geo/asn 数据文件（geosite.dat / geoip.dat / asn.mmdb）读写与输出测试
// ---------------------------------------------------------------------------

func TestGeoSiteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	entries := map[string][]Rule{
		"google": {
			{Type: "DOMAIN", Value: "google.com"},
			{Type: "DOMAIN-SUFFIX", Value: "googleapis.com"},
			{Type: "DOMAIN-KEYWORD", Value: "gstatic"},
			{Type: "DOMAIN-REGEX", Value: `^goog\w+\.com$`},
		},
		"cn": {
			{Type: "DOMAIN-SUFFIX", Value: "baidu.com"},
		},
	}
	if err := WriteGeoSite(path, entries); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGeoSite(path)
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "google", got["google"], []Rule{
		{Type: "DOMAIN", Value: "google.com"},
		{Type: "DOMAIN-SUFFIX", Value: "googleapis.com"},
		{Type: "DOMAIN-KEYWORD", Value: "gstatic"},
		{Type: "DOMAIN-REGEX", Value: `^goog\w+\.com$`},
	})
	assertRuleSet(t, "cn", got["cn"], []Rule{{Type: "DOMAIN-SUFFIX", Value: "baidu.com"}})
}

func TestGeoIPRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.dat")
	entries := map[string][]Rule{
		"cn": {
			{Type: "IP-CIDR", Value: "1.1.1.0/24"},
			{Type: "IP-CIDR", Value: "8.8.8.0/24"},
			{Type: "IP-CIDR6", Value: "2400:3200::/32"},
		},
		"us": {
			{Type: "IP-CIDR", Value: "9.9.9.0/24"},
		},
	}
	if err := WriteGeoIP(path, entries); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGeoIP(path)
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "cn", got["cn"], []Rule{
		{Type: "IP-CIDR", Value: "1.1.1.0/24"},
		{Type: "IP-CIDR", Value: "8.8.8.0/24"},
		{Type: "IP-CIDR6", Value: "2400:3200::/32"},
	})
	assertRuleSet(t, "us", got["us"], []Rule{{Type: "IP-CIDR", Value: "9.9.9.0/24"}})
}

func TestASNRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	entries := map[string][]Rule{
		"AS13335": {
			{Type: "IP-CIDR", Value: "1.1.1.0/24"},
			{Type: "IP-CIDR", Value: "8.8.8.0/24"},
			{Type: "IP-CIDR6", Value: "2606:4700::/32"},
		},
		"AS15169": {
			{Type: "IP-CIDR", Value: "8.8.4.0/24"},
		},
	}
	if err := WriteMMDB(path, entries, true); err != nil {
		t.Fatal(err)
	}
	got, err := LoadMMDB(path)
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "AS13335", got["AS13335"], entries["AS13335"])
	assertRuleSet(t, "AS15169", got["AS15169"], entries["AS15169"])
}

func TestParseASNTag(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"AS13335", 13335, true},
		{"as13335", 13335, true},
		{"13335", 13335, true},
		{" AS15169 ", 15169, true},
		{"ASabc", 0, false},
		{"", 0, false},
	} {
		got, ok := parseASNTag(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("parseASNTag(%q) = %d,%v，期望 %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestPickMatches(t *testing.T) {
	pick := map[string]bool{"cn": true, "google": true, "13335": true}
	if !pickMatches("geosite", "cn", pick) {
		t.Fatal("cn 应命中 pick")
	}
	if !pickMatches("geosite", "google", pick) {
		t.Fatal("google 应命中 pick")
	}
	if pickMatches("geosite", "facebook", pick) {
		t.Fatal("facebook 不应命中 pick")
	}
	// asn 的 pick 支持 AS13335 与 13335 两种写法
	if !pickMatches("asn", "AS13335", pick) {
		t.Fatal("AS13335 应命中 pick 里的 13335")
	}
	// 空 pick = 全部
	if !pickMatches("geosite", "anything", nil) {
		t.Fatal("空 pick 应命中一切")
	}
}

// TestGeoOutputUnmarshal 验证 geosite/geoip/asn 的对象形式解析（含 upstreams + pick）。
func TestGeoOutputUnmarshal(t *testing.T) {
	var cfg struct {
		Geodata GeodataConfig `yaml:"geodata"`
	}
	data := `
geodata:
  geosite:
    enable: true
    upstreams: ["https://x/geosite-all.dat"]
    pick: [google]
  geoip:
    enable: false
  mmdb:
    enable: true
    upstreams: ["https://x/country.mmdb"]
    pick: [AS13335]
`
	if err := yaml.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Geodata.GeoSite.Enable {
		t.Fatal("geosite.enable 应解析为 true")
	}
	if len(cfg.Geodata.GeoSite.Upstreams) != 1 || len(cfg.Geodata.GeoSite.Pick) != 1 {
		t.Fatalf("geosite 应解析出 upstreams 与 pick，实际 %+v", cfg.Geodata.GeoSite)
	}
	if cfg.Geodata.GeoIP.Enable {
		t.Fatal("geoip.enable 应解析为 false")
	}
	if !cfg.Geodata.MMDB.Enable {
		t.Fatal("asn.enable 应解析为 true")
	}
	if len(cfg.Geodata.MMDB.Upstreams) != 1 || len(cfg.Geodata.MMDB.Pick) != 1 {
		t.Fatalf("asn 应解析出 upstreams 与 pick，实际 %+v", cfg.Geodata.MMDB)
	}
}

func TestToMihomoWildcardSubdomain(t *testing.T) {
	// DOMAIN-WILDCARD `*.google.com`（正则 ^.*\.google\.com$）应映射为 `.google.com`（任意层级子域），
	// 而非收窄为 `*.google.com`（仅一级）。
	if got := toMihomoWildcard(`^.*\.google\.com$`); got != `.google.com` {
		t.Fatalf("toMihomoWildcard(^.*\\.google\\.com$) = %q，期望 .google.com", got)
	}
	if got := toMihomoWildcard(`^[^.]+\.google\.com$`); got != `*.google.com` {
		t.Fatalf("toMihomoWildcard(^[^.]+...) = %q，期望 *.google.com", got)
	}
	if got := toMihomoWildcard(`^(.+\.)?google\.com$`); got != `+.google.com` {
		t.Fatalf("toMihomoWildcard(^(.+\\.)?...) = %q，期望 +.google.com", got)
	}
}

// serveGeoSiteFile 用本地 httptest 服务器提供一份 geosite.dat，避免测试依赖外网。
func serveGeoSiteFile(t *testing.T, entries map[string][]Rule) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := WriteGeoSite(path, entries); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
}

// TestBuildGeoDataWithUpstream 验证 upstreams 拉取 + pick 筛选。
func TestBuildGeoDataWithUpstream(t *testing.T) {
	srv := serveGeoSiteFile(t, map[string][]Rule{
		"google":   {{Type: "DOMAIN", Value: "google.com"}},
		"facebook": {{Type: "DOMAIN", Value: "facebook.com"}},
	})
	defer srv.Close()

	cfg := &Config{Global: GlobalConfig{Geodata: GeodataConfig{
		GeoSite: GeoOutput{Enable: true, Upstreams: []string{srv.URL + "/geosite.dat"}, Pick: []string{"google"}},
	}}}
	store := BuildGeoData(cfg)

	if len(store.geosite["google"]) != 1 {
		t.Fatalf("google 应被 pick，实际 %v", store.geosite["google"])
	}
	if len(store.geosite["facebook"]) != 0 {
		t.Fatalf("facebook 不应被 pick，实际 %v", store.geosite["facebook"])
	}
}

// TestExportGeoData 验证：不依赖任何上游，仅凭全局开关 + add/remove 目录，
// 就能把处理好的规则直接打包成 geosite.dat / geoip.dat / asn.mmdb（add/remove 自然生效）。
func TestExportGeoData(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"add", "remove"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(dir, "add", "testcat.list"),
		"DOMAIN,google.com\nDOMAIN,ads.google.com\nIP-CIDR,1.1.1.0/24\nIP-CIDR,8.8.8.0/24\n")
	mustWrite(t, filepath.Join(dir, "remove", "testcat.list"),
		"DOMAIN,ads.google.com\nIP-CIDR,8.8.8.0/24\n")

	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	cat := Category{Name: "testcat"}
	cfg := &Config{
		Global: GlobalConfig{Geodata: GeodataConfig{
			GeoSite: GeoOutput{Enable: true},
			GeoIP:   GeoOutput{Enable: true},
			MMDB:    GeoOutput{Enable: true},
		}},
		Categories: []Category{cat},
	}
	store := BuildGeoData(cfg)

	res := ProcessCategory(cat, cfg)
	results := map[string]*ProcessedResult{cat.Name: res}
	ExportGeoData(cfg, store, results)

	gs, err := LoadGeoSite("publish/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "geosite-testcat", gs["testcat"], []Rule{
		{Type: "DOMAIN", Value: "google.com"},
	})

	gip, err := LoadGeoIP("publish/geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "geoip-testcat", gip["testcat"], []Rule{
		{Type: "IP-CIDR", Value: "1.1.1.0/24"},
	})

	// category 的 IP 规则 → country.mmdb 的 category name 标签
	mmdb, err := LoadMMDB("publish/country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "mmdb-testcat", mmdb["testcat"], []Rule{
		{Type: "IP-CIDR", Value: "1.1.1.0/24"},
	})
}

// TestExportGeoDataCategoryOverride 验证 category 级开关覆盖全局。
func TestExportGeoDataCategoryOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "add"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "add", "google.list"), "DOMAIN,google.com\n")
	mustWrite(t, filepath.Join(dir, "add", "excluded.list"), "DOMAIN,ads.com\n")

	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	falsePtr := false
	cfg := &Config{
		Global: GlobalConfig{Geodata: GeodataConfig{GeoSite: GeoOutput{Enable: true}}},
		Categories: []Category{
			{Name: "google"},                       // 未覆盖 -> 参与（回退全局 enable）
			{Name: "excluded", GeoSite: &falsePtr}, // 显式 false -> 排除
		},
	}
	store := BuildGeoData(cfg)

	results := map[string]*ProcessedResult{}
	for _, c := range cfg.Categories {
		results[c.Name] = ProcessCategory(c, cfg)
	}
	ExportGeoData(cfg, store, results)

	gs, err := LoadGeoSite("publish/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	assertRuleSet(t, "google", gs["google"], []Rule{{Type: "DOMAIN", Value: "google.com"}})
	if _, ok := gs["excluded"]; ok {
		t.Fatalf("excluded 应被 category 级 geosite:false 排除，实际存在 %v", gs["excluded"])
	}
}

// TestExportGeoDataPreserveUpstream 验证：上游拉取的标签（pick 进来）原样保留，
// 被 category 覆盖的标签用去重结果替换。
func TestExportGeoDataPreserveUpstream(t *testing.T) {
	srv := serveGeoSiteFile(t, map[string][]Rule{
		"google":   {{Type: "DOMAIN", Value: "google.com"}, {Type: "DOMAIN", Value: "ads.google.com"}},
		"facebook": {{Type: "DOMAIN", Value: "facebook.com"}},
	})
	defer srv.Close()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "add"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "add", "google.list"), "DOMAIN,youtube.com\n")

	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	cfg := &Config{
		Global: GlobalConfig{Geodata: GeodataConfig{
			GeoSite: GeoOutput{Enable: true, Upstreams: []string{srv.URL + "/geosite.dat"}},
		}},
		Categories: []Category{
			{Name: "google"}, // 覆盖同名标签
		},
	}
	store := BuildGeoData(cfg)

	results := map[string]*ProcessedResult{}
	for _, c := range cfg.Categories {
		results[c.Name] = ProcessCategory(c, cfg)
	}
	ExportGeoData(cfg, store, results)

	gs, err := LoadGeoSite("publish/geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	// google 标签被 category 覆盖为 add 的结果
	assertRuleSet(t, "google", gs["google"], []Rule{
		{Type: "DOMAIN", Value: "youtube.com"},
	})
	// facebook 标签：上游拉取原样保留（未被子规则集覆盖）
	assertRuleSet(t, "facebook", gs["facebook"], []Rule{
		{Type: "DOMAIN", Value: "facebook.com"},
	})
}

// assertRuleSet 以"无序集合"语义比较两组规则。
func assertRuleSet(t *testing.T, name string, got, want []Rule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: 规则数期望 %d，实际 %d（got=%v）", name, len(want), len(got), got)
	}
	key := func(rs []Rule) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.Type + "," + r.Value
		}
		sort.Strings(out)
		return out
	}
	g, w := key(got), key(want)
	for i := range w {
		if g[i] != w[i] {
			t.Fatalf("%s: 规则集合不一致，期望 %v，实际 %v", name, want, got)
		}
	}
}
