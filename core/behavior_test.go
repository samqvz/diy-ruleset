package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// 基准测试（Behavior Baseline）
//
// 这些用例锁定重构前引擎的关键可观测行为：多语法解析、通配符归一化、
// 字典树去重、跨类型查杀与端到端 ProcessCategory 结果。
// 前后必须全部通过，用于保证"去重效果与功能完全不变"。
// ---------------------------------------------------------------------------

func eqRule(t *testing.T, got *Rule, wantType, wantVal string) {
	t.Helper()
	if got == nil {
		t.Fatalf("期望 %s,%s，实际得到 nil", wantType, wantVal)
	}
	if got.Type != wantType || got.Value != wantVal {
		t.Fatalf("期望 %s,%s，实际得到 %s,%s", wantType, wantVal, got.Type, got.Value)
	}
}

func TestParseClash(t *testing.T) {
	cases := []struct {
		in       string
		wantType string
		wantVal  string
	}{
		{"DOMAIN,Example.COM", "DOMAIN", "example.com"},
		{"- DOMAIN-SUFFIX,Google.com", "DOMAIN-SUFFIX", "google.com"},
		{"DOMAIN-KEYWORD,AdS", "DOMAIN-KEYWORD", "ads"},
		{"HOST,foo.com", "DOMAIN", "foo.com"},
		{"HOST-SUFFIX,foo.com", "DOMAIN-SUFFIX", "foo.com"},
		{"DEST-PORT,443", "DST-PORT", "443"},
		{"PORT,80", "DST-PORT", "80"},
		{"IP4-CIDR,1.2.3.4", "IP-CIDR", "1.2.3.4/32"},
		{"IP6-CIDR,::1", "IP-CIDR6", "::1/128"},
		{"IP-CIDR,1.1.1.1", "IP-CIDR", "1.1.1.1/32"},
		{"IP-CIDR6,::1", "IP-CIDR6", "::1/128"},
		{"IP-ASN,13335", "IP-ASN", "13335"},
		{"+.baidu.com", "DOMAIN-SUFFIX", "baidu.com"},
		{"*.baidu.com", "DOMAIN-REGEX", `^[^.]+\.baidu\.com$`},
		{"*", "DOMAIN-REGEX", `^[^.]+$`},
		{"naked.com", "DOMAIN", "naked.com"},
		{"DOMAIN-WILDCARD,*.google.com", "DOMAIN-WILDCARD", "*.google.com"},
		{"DOMAIN,foo.com # comment", "DOMAIN", "foo.com"},
		{"// comment only", "", ""},
		{"payload:", "", ""},
	}
	for _, c := range cases {
		got := Parse(c.in, "clash")
		if c.wantType == "" {
			if got != nil {
				t.Fatalf("输入 %q 期望 nil，实际得到 %s,%s", c.in, got.Type, got.Value)
			}
			continue
		}
		eqRule(t, got, c.wantType, c.wantVal)
	}
}

func TestParseClashDotPrefixExact(t *testing.T) {
	// `.baidu.com` 应转为"多级但不含裸域"的正则（与 mihomo 通配符 `.` 语义一致）
	got := Parse(".baidu.com", "clash")
	eqRule(t, got, "DOMAIN-REGEX", `^.+\.baidu\.com$`)
}

func TestParseV2Ray(t *testing.T) {
	eqRule(t, Parse("full:baidu.com", "v2ray"), "DOMAIN", "baidu.com")
	eqRule(t, Parse("domain:baidu.com", "v2ray"), "DOMAIN-SUFFIX", "baidu.com")
	eqRule(t, Parse("keyword:Ads", "v2ray"), "DOMAIN-KEYWORD", "ads")
	eqRule(t, Parse("regexp:^foo$", "v2ray"), "DOMAIN-REGEX", "^foo$")
	eqRule(t, Parse(".baidu.com", "v2ray"), "DOMAIN-SUFFIX", "baidu.com")
	eqRule(t, Parse("1.1.1.1", "v2ray"), "IP-CIDR", "1.1.1.1/32")
	eqRule(t, Parse("baidu.com", "v2ray"), "DOMAIN-KEYWORD", "baidu.com")
	if got := Parse("include:foo", "v2ray"); got != nil {
		t.Fatalf("include: 期望 nil，实际 %s,%s", got.Type, got.Value)
	}
}

func TestParseAdblock(t *testing.T) {
	eqRule(t, Parse("||ads.example.com^", "adblock"), "DOMAIN-SUFFIX", "ads.example.com")
	eqRule(t, Parse("||1.2.3.4^", "adblock"), "IP-CIDR", "1.2.3.4/32")
	// 注意：`:` 已被 ContainsAny("/?=:") 过滤，故 adblock 的 IPv6 分支实际不可达，
	// `||::1^` 返回 nil（此用例锁定现状，见审查报告"死分支"一节）。
	if got := Parse("||::1^", "adblock"); got != nil {
		t.Fatalf("adblock IPv6 期望 nil，实际 %s,%s", got.Type, got.Value)
	}
	eqRule(t, Parse("||ads*.example.com^", "adblock"), "DOMAIN-REGEX", `^(.+\.)?ads.*\.example\.com$`)
	if got := Parse("||ads.example.com^$third-party", "adblock"); got != nil {
		t.Fatalf("含 $ 选项期望 nil，实际 %s,%s", got.Type, got.Value)
	}
	if got := Parse("||ads.example.com/path^", "adblock"); got != nil {
		t.Fatalf("含路径期望 nil，实际 %s,%s", got.Type, got.Value)
	}
}

func TestParseHosts(t *testing.T) {
	eqRule(t, Parse("127.0.0.1 ads.example.com", "hosts"), "DOMAIN", "ads.example.com")
	eqRule(t, Parse("0.0.0.0 *.example.com", "hosts"), "DOMAIN-REGEX", `^[^.]+\.example\.com$`)
	if got := Parse("0.0.0.0 blocked.localdomain", "hosts"); got != nil {
		t.Fatalf("localdomain 期望 nil，实际 %s,%s", got.Type, got.Value)
	}
	if got := Parse("0.0.0.0 nodot", "hosts"); got != nil {
		t.Fatalf("无点域名期望 nil，实际 %s,%s", got.Type, got.Value)
	}
}

func TestParseDnsmasqAndSmartDNS(t *testing.T) {
	eqRule(t, Parse("address=/ads.example.com/0.0.0.0", "dnsmasq"), "DOMAIN-SUFFIX", "ads.example.com")
	eqRule(t, Parse("server=/ads.example.com/223.6.6.6", "dnsmasq"), "DOMAIN-SUFFIX", "ads.example.com")
	eqRule(t, Parse("address /ads.example.com/1.2.3.4", "smartdns"), "DOMAIN-SUFFIX", "ads.example.com")
}

func TestParseEgern(t *testing.T) {
	eqRule(t, ParseEgern("- google.com", "domain_set"), "DOMAIN", "google.com")
	eqRule(t, ParseEgern("- .google.com", "domain_suffix_set"), "DOMAIN-SUFFIX", "google.com")
	eqRule(t, ParseEgern("- ads", "domain_keyword_set"), "DOMAIN-KEYWORD", "ads")
	eqRule(t, ParseEgern("- 10.0.0.0", "ip_cidr_set"), "IP-CIDR", "10.0.0.0/32")
	eqRule(t, ParseEgern("- ::1", "ip_cidr6_set"), "IP-CIDR6", "::1/128")
	eqRule(t, ParseEgern("- 13335", "asn_set"), "IP-ASN", "13335")
}

func TestParseAppleClients(t *testing.T) {
	eqRule(t, Parse(".google.com", "surge"), "DOMAIN-SUFFIX", "google.com")
	eqRule(t, Parse("google.com", "surge"), "DOMAIN", "google.com")
	eqRule(t, Parse("DOMAIN-SUFFIX,google.com,no-resolve", "surge"), "DOMAIN-SUFFIX", "google.com")
	eqRule(t, Parse("USER-AGENT,apple*,PROXY", "surge"), "USER-AGENT", "apple*")
	eqRule(t, Parse("DEST-PORT,443,PROXY", "loon"), "DST-PORT", "443")
}

func TestParseWhite(t *testing.T) {
	eqRule(t, Parse("@@||whitelist.com^", "white"), "DOMAIN-SUFFIX", "whitelist.com")
	eqRule(t, Parse("@@|exact.com|", "white"), "DOMAIN", "exact.com")
	eqRule(t, Parse("@@||ads*.example.com^", "white"), "DOMAIN-REGEX", `^(.+\.)?ads.*\.example\.com$`)
	if got := Parse("@@||whitelist.com^$third-party", "white"); got != nil {
		t.Fatalf("含 $ 期望 nil，实际 %s,%s", got.Type, got.Value)
	}
	if got := Parse("||whitelist.com^", "white"); got != nil {
		t.Fatalf("缺少 @@ 前缀期望 nil，实际 %s,%s", got.Type, got.Value)
	}
}

func TestInferParser(t *testing.T) {
	write := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct{ name, body, want string }{
		{"clash.list", "payload:\n  - DOMAIN,foo.com\n  - DOMAIN-SUFFIX,bar.com\n", "clash"},
		{"v2ray.list", "domain:google.com\nfull:exact.com\n", "v2ray"},
		{"adblock.txt", "||ads.example.com^\n||tracker.net^\n", "adblock"},
		{"hosts.txt", "127.0.0.1 ads.example.com\n0.0.0.0 x.example.com\n", "hosts"},
		{"dnsmasq.conf", "address=/ads.example.com/0.0.0.0\n", "dnsmasq"},
		{"smartdns.conf", "address /ads.example.com/1.2.3.4\n", "smartdns"},
		{"egern.yaml", "domain_suffix_set:\n  - google.com\n", "egern"},
		{"qx.list", "host-suffix,google.com,PROXY\n", "quantumultx"},
		{"surge.list", "DEST-PORT,443,PROXY\n", "surge"},
	}
	for _, c := range cases {
		if got := InferParser(write(c.name, c.body)); got != c.want {
			t.Fatalf("%s 推断期望 %s，实际 %s", c.name, c.want, got)
		}
	}
}

func TestSuffixTrieSemantics(t *testing.T) {
	trie := NewSuffixTrie()
	trie.Insert("google.com")
	if !trie.MatchAnySuffix("www.google.com") || !trie.MatchAnySuffix("google.com") {
		t.Fatal("MatchAnySuffix 应命中自身与子域")
	}
	if trie.MatchAnySuffix("notgoogle.com") {
		t.Fatal("MatchAnySuffix 不应命中非后缀")
	}
	if !trie.MatchParentSuffix("www.google.com") {
		t.Fatal("MatchParentSuffix 应命中父后缀")
	}
	if trie.MatchParentSuffix("google.com") {
		t.Fatal("MatchParentSuffix 不应命中自身")
	}
}

func TestIPTrieSubsumption(t *testing.T) {
	t4, t6 := &IPv4Trie{}, &IPv6Trie{}
	insertIP("10.0.0.0/8", t4, t6)
	insertIP("10.1.0.0/16", t4, t6) // 被 /8 覆盖
	insertIP("192.168.0.0/24", t4, t6)
	insertIP("192.168.0.0/16", t4, t6) // 覆盖 /24
	out := map[string][]string{}
	t4.Walk(0, 0, &out)
	if len(out["IP-CIDR"]) != 2 {
		t.Fatalf("期望 2 条聚合网段，实际 %v", out["IP-CIDR"])
	}
}

func TestWildcardHelpers(t *testing.T) {
	if got := wildcardToRegex("*.google.com"); got != `^.*\.google\.com$` {
		t.Fatalf("wildcardToRegex 实际 %q", got)
	}
	if got := wildcardToRegex("a?c.com"); got != `^a.c\.com$` {
		t.Fatalf("wildcardToRegex ? 实际 %q", got)
	}
	if got := toMihomoWildcard(`^[^.]+\.google\.com$`); got != `*.google.com` {
		t.Fatalf("toMihomoWildcard 实际 %q", got)
	}
	if got := toMihomoWildcard(`^(.+\.)?google\.com$`); got != `+.google.com` {
		t.Fatalf("toMihomoWildcard +. 实际 %q", got)
	}
}

func TestCleanPatternForMatch(t *testing.T) {
	m := &RuleMatcher{}
	if got := m.cleanPatternForMatch(`^(.+\.)?ads\.com$`); got != `+.ads.com` {
		t.Fatalf("cleanPatternForMatch 实际 %q", got)
	}
	if got := m.cleanPatternForMatch(`^.+\.ads\.com$`); got != `.ads.com` {
		t.Fatalf("cleanPatternForMatch .+\\\\. 实际 %q", got)
	}
}

// TestProcessCategoryDedup 端到端锁定去重与跨类型查杀行为。
func TestProcessCategoryDedup(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"temp/raw", "add", "remove"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	upstream := "DOMAIN,keep.com\n" +
		"DOMAIN,sub.keep.com\n" +
		"DOMAIN-SUFFIX,keep.com\n" +
		"DOMAIN-KEYWORD,ads\n" +
		"DOMAIN,ads.example.com\n" +
		`DOMAIN-REGEX,^foo\.bar$` + "\n" +
		"IP-CIDR,10.0.0.0/8\n"
	mustWrite(t, filepath.Join(dir, "temp/raw/testcat_1.txt"), upstream)
	mustWrite(t, filepath.Join(dir, "add/testcat.list"), "DOMAIN,added.com\n")
	mustWrite(t, filepath.Join(dir, "remove/testcat.list"), "DOMAIN,sub.keep.com\n")

	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	cat := Category{Name: "testcat", Upstreams: []Upstream{{URL: "u1", Parser: "clash"}}}
	cfg := &Config{Categories: []Category{cat}}
	res := ProcessCategory(cat, cfg)

	// 上游 DOMAIN-KEYWORD 只做"同类型"去重，不跨类型查杀其它规则（见 README 注意事项 3），
	// 因此 DOMAIN,ads.example.com 不会被上游的 DOMAIN-KEYWORD,ads 命中。
	assertSlice(t, "DOMAIN", res.DomRules["DOMAIN"], []string{"added.com", "ads.example.com"})
	assertSlice(t, "DOMAIN-SUFFIX", res.DomRules["DOMAIN-SUFFIX"], []string{"keep.com"})
	assertSlice(t, "DOMAIN-KEYWORD", res.DomRules["DOMAIN-KEYWORD"], []string{"ads"})
	assertSlice(t, "DOMAIN-REGEX", res.DomRules["DOMAIN-REGEX"], []string{`^foo\.bar$`})
	assertSlice(t, "IP-CIDR", res.IPRules["IP-CIDR"], []string{"10.0.0.0/8"})

	if res.FinalCount != 6 {
		t.Fatalf("FinalCount 期望 6，实际 %d", res.FinalCount)
	}
}

// TestProcessCategoryConcurrent 验证多规则集并发处理不产生数据竞争（配合 -race 使用）。
func TestProcessCategoryConcurrent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "temp/raw"), 0o755); err != nil {
		t.Fatal(err)
	}

	const n = 8
	cats := make([]Category, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("cat%d", i)
		body := fmt.Sprintf("DOMAIN,host%d.example.com\nDOMAIN-SUFFIX,example.com\n", i)
		mustWrite(t, filepath.Join(dir, "temp/raw", name+"_1.txt"), body)
		cats = append(cats, Category{Name: name, Upstreams: []Upstream{{URL: "u", Parser: "clash"}}})
	}

	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	cfg := &Config{Categories: cats}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var problems []string

	for _, c := range cats {
		wg.Go(func() {
			res := ProcessCategory(c, cfg)
			mu.Lock()
			defer mu.Unlock()
			// DOMAIN,hostX.example.com 应被 DOMAIN-SUFFIX,example.com 覆盖，仅剩 1 条后缀规则
			if res.FinalCount != 1 {
				problems = append(problems, fmt.Sprintf("%s FinalCount=%d", c.Name, res.FinalCount))
			}
		})
	}
	wg.Wait()

	if len(problems) > 0 {
		t.Fatalf("并发处理结果异常: %v", problems)
	}
}

// TestExampleConfigParses 保证仓库根目录的 config-example.yaml 始终是合法可用的配置。
func TestExampleConfigParses(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "config-example.yaml"))
	if err != nil {
		t.Fatalf("config-example.yaml 解析失败: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config-example.yaml 校验失败: %v", err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertSlice(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s 期望 %v，实际 %v", name, want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s 期望 %v，实际 %v", name, want, got)
		}
	}
}
