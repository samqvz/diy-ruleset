package core

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Geo/ASN 数据编排：拉取上游、pick 筛选、按开关从处理结果打包输出
const (
	geoSiteOutputPath = "publish/geosite.dat"
	geoIPOutputPath   = "publish/geoip.dat"
	countryOutputPath = "publish/country.mmdb"

	// geopickPrefix 标记由 pick 标签物化出的"虚拟上游"（格式 geopick:<来源URL>|<标签>）：
	// FetchAll 据此跳过下载（规则已写入 temp/raw）；报表据此还原真实来源与标签名。
	geopickPrefix = "geopick:"
)

// GeoDataStore 缓存一次构建过程中的 geo/mmdb 上游数据（pick 选中的标签）。
// geosite / geoip / mmdb 三张表统一用 "标签 -> []Rule" 表达：
//
//	geosite: 标签 = 站点/分类名（如 "google"），规则为域名类
//	geoip  : 标签 = 国家码（如 "cn"），规则为 IP-CIDR
//	asn    : 标签 = "AS<number>"，规则为 IP-CIDR
type GeoDataStore struct {
	geosite map[string][]Rule
	geoip   map[string][]Rule
	asn     map[string][]Rule
	// source 记录每个标签的来源上游 URL（key 为 "kind:tag"），用于报告展示；自动识别的来源记为 "auto"。
	source map[string]string
}

// BuildGeoData 拉取各类型配置的上游数据文件，按 pick 筛选标签，构建本次构建共享的 geo/mmdb 数据。
// 拉取/解析失败不中断整体构建，仅告警。
func BuildGeoData(cfg *Config) *GeoDataStore {
	gd := cfg.Global.Geodata
	geosite, geoSrc := buildGeoOfType(gd.GeoSite, "geosite")
	geoip, geoIPSrc := buildGeoOfType(gd.GeoIP, "geoip")
	asn, asnSrc := buildGeoOfType(gd.MMDB, "asn")

	source := make(map[string]string, len(geoSrc)+len(geoIPSrc)+len(asnSrc))
	for k, v := range geoSrc {
		source["geosite:"+k] = v
	}
	for k, v := range geoIPSrc {
		source["geoip:"+k] = v
	}
	for k, v := range asnSrc {
		source["asn:"+k] = v
	}

	return &GeoDataStore{
		geosite: geosite,
		geoip:   geoip,
		asn:     asn,
		source:  source,
	}
}

// materializePickCategories 把 pick 选中的 geo/mmdb 标签物化为规则集（category）。
// 规则写入 temp/raw 作为对应 category 的上游文件：
//   - 存在同名 category → 作为其额外上游合并（与普通上游一起参与去重）
//   - 不存在同名 category → 新建一个同名 category（用于生成 mrs/srs/list 等文件）
//
// 这样 pick 的标签既进入 geosite.dat / geoip.dat / country.mmdb，也生成对应的 mrs/srs/list 文件。
func materializePickCategories(cfg *Config, store *GeoDataStore) {
	writePick := func(kind, tag string, rules []Rule) {
		// ASN 标签（如 AS13335）不是独立规则集，不物化为 category，避免污染统计报表。
		if _, isASN := parseASNTag(tag); isASN {
			return
		}
		if len(rules) == 0 {
			return
		}
		src := store.source[kind+":"+tag]
		if src == "" {
			src = "auto"
		}
		url := geopickPrefix + src + "|" + tag

		for i := range cfg.Categories {
			if cfg.Categories[i].Name == tag {
				idx := len(cfg.Categories[i].Upstreams) + 1
				writeRulesFile(fmt.Sprintf("temp/raw/%s_%d.txt", tag, idx), rules)
				cfg.Categories[i].Upstreams = append(cfg.Categories[i].Upstreams, Upstream{URL: url})
				return
			}
		}
		// 无同名 → 新建 category 用于分发 srs/mrs/list，不参与 geosite/geoip/mmdb 构建
		writeRulesFile(fmt.Sprintf("temp/raw/%s_1.txt", tag), rules)
		falsePtr := false
		cfg.Categories = append(cfg.Categories, Category{
			Name:      tag,
			Upstreams: []Upstream{{URL: url}},
			GeoSite:   &falsePtr,
			GeoIP:     &falsePtr,
			MMDB:      &falsePtr,
		})
	}

	for _, tag := range slices.Sorted(maps.Keys(store.geosite)) {
		writePick("geosite", tag, store.geosite[tag])
	}
	for _, tag := range slices.Sorted(maps.Keys(store.geoip)) {
		writePick("geoip", tag, store.geoip[tag])
	}
	for _, tag := range slices.Sorted(maps.Keys(store.asn)) {
		writePick("asn", tag, store.asn[tag])
	}
}

// writeRulesFile 把规则写为 Clash 文本行文件（供 ProcessCategory 解析）。
func writeRulesFile(path string, rules []Rule) {
	if err := os.WriteFile(path, []byte(strings.Join(rulesToLines(rules), "\n")), 0o644); err != nil {
		fmt.Printf("⚠️ 写入 pick 规则文件失败 [%s]: %v\n", path, err)
	}
}

// rulesToLines 把规则序列化为 Clash 文本行。
func rulesToLines(rules []Rule) []string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		lines = append(lines, r.Type+","+r.Value)
	}
	return lines
}

// normalizeTagSet 把 pick/exclude 列表归一化为集合（geosite/geoip 标签统一小写，asn 保持原样）。
func normalizeTagSet(list []string, kind string) map[string]bool {
	set := make(map[string]bool, len(list))
	for _, s := range list {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if kind != "asn" {
			t = strings.ToLower(t)
		}
		set[t] = true
	}
	return set
}

// buildGeoOfType 拉取某类（geosite/geoip/mmdb）的上游并 pick 筛选标签。
// 标签名大小写不敏感（上游标签常用大写，pick 可用小写），统一按小写归一化。
// geoip/mmdb 的 pick 中上游数据里没有的 AS 号，自动从公开数据源拉取网段。
// 返回 (标签->规则, 标签->来源上游 URL)；自动识别的来源记为 "auto"。
func buildGeoOfType(out GeoOutput, kind string) (map[string][]Rule, map[string]string) {
	m := map[string][]Rule{}
	source := map[string]string{}
	if !out.Enable {
		return m, source
	}

	pick := normalizeTagSet(out.Pick, kind)
	exclude := normalizeTagSet(out.Exclude, kind)

	for _, url := range out.Upstreams {
		if url == "" {
			continue
		}
		mm, err := loadGeoUpstream(url, kind)
		if err != nil {
			fmt.Printf("⚠️ 拉取/解析 geo 上游 [%s] 失败: %v\n", url, err)
			continue
		}
		for tag, rules := range mm {
			if !pickMatches(kind, tag, pick) {
				continue
			}
			if kind != "asn" {
				tag = strings.ToLower(tag)
			} else if _, isASN := parseASNTag(tag); !isASN {
				tag = strings.ToLower(tag)
			}
			if exclude[tag] {
				continue
			}
			m[tag] = append(m[tag], rules...)
			if _, ok := source[tag]; !ok {
				source[tag] = url
			}
		}
	}

	if kind != "geosite" {
		for _, p := range out.Pick {
			n, ok := parseASNTag(p)
			if !ok {
				continue
			}
			key := fmt.Sprintf("AS%d", n)
			if _, exists := m[key]; !exists {
				if rules := fetchASNToRules(n); rules != nil {
					m[key] = rules
					source[key] = "auto"
				}
			}
		}
	}
	return m, source
}

// loadGeoUpstream 下载并按类型解析一个上游 geo/mmdb 数据文件，返回 (标签->规则, 错误)。
// kind 由外层 geosite/geoip/mmdb 决定，无需在 upstreams 里再指定。
func loadGeoUpstream(url, kind string) (map[string][]Rule, error) {
	f, err := os.CreateTemp("", "geodata-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	_ = f.Close()
	defer os.Remove(tmp)

	client := &http.Client{Timeout: httpTimeout}
	if !downloadWithRetry(client, url, tmp, fetchRetries) {
		return nil, fmt.Errorf("下载失败")
	}

	var m map[string][]Rule
	switch kind {
	case "geosite":
		m, err = LoadGeoSite(tmp)
	case "geoip":
		m, err = LoadGeoIP(tmp)
	case "asn":
		m, err = LoadMMDB(tmp)
	default:
		return nil, fmt.Errorf("未知 geo 文件类型 %q", kind)
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// pickMatches 判断标签是否命中 pick 白名单（空 pick = 全部）。
// geosite/geoip 的标签名大小写不敏感；asn 的 pick 同时支持 "AS13335" 与 "13335"。
func pickMatches(kind, tag string, pick map[string]bool) bool {
	if len(pick) == 0 {
		return true
	}
	if pick[tag] || pick[strings.ToLower(tag)] || pick[strings.ToUpper(tag)] {
		return true
	}
	if kind == "asn" {
		if n, ok := parseASNTag(tag); ok {
			return pick[fmt.Sprintf("AS%d", n)] || pick[fmt.Sprintf("%d", n)]
		}
	}
	return false
}

// asnHTTPClient 复用统一的超时设置，避免为每个数据源重复创建。
var asnHTTPClient = &http.Client{Timeout: 30 * time.Second}

// FetchASNPrefixes 从 RIPEstat 拉取 ASN 的宣告网段，返回 IP-CIDR 列表。
func FetchASNPrefixes(asn uint32) ([]string, error) {
	return fetchRIPEstat(asn)
}

func fetchRIPEstat(asn uint32) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)
	resp, err := asnHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat 返回 %d", resp.StatusCode)
	}
	var data struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(data.Data.Prefixes))
	for _, p := range data.Data.Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

// fetchASNToRules 拉取 ASN 网段并归一化为 IP-CIDR 规则；失败返回 nil 并告警。
func fetchASNToRules(n uint32) []Rule {
	prefixes, err := FetchASNPrefixes(n)
	if err != nil {
		fmt.Printf("⚠️ 拉取 AS%d 网段失败: %v\n", n, err)
		return nil
	}
	rules := make([]Rule, 0, len(prefixes))
	for _, p := range prefixes {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		typ := "IP-CIDR"
		if pfx.Addr().Is6() {
			typ = "IP-CIDR6"
		}
		rules = append(rules, Rule{Type: typ, Value: pfx.String()})
	}
	return rules
}

// ExportGeoData 根据 geosite / geoip / mmdb 的 enable 开关，把"处理好的规则集结果"打包为数据文件。
func ExportGeoData(cfg *Config, store *GeoDataStore, results map[string]*ProcessedResult) int {
	geosite := cloneRuleMap(store.geosite)
	failed := 0

	needGeoIP := cfg.Global.Geodata.GeoIP.Enable
	needMMDB := cfg.Global.Geodata.MMDB.Enable

	// ASN 网段表（IP-ASN 规则识别），共享给 geoip.dat 与 country.mmdb。
	var asnTags map[string][]Rule
	if needGeoIP || needMMDB {
		asnTags = collectASNTags(results)
	}
	// ASN 网段规则数（IP-ASN 识别出的网段，未物化为 category，单独计入「规则总数」）。
	asnRuleCount := 0
	for _, rules := range asnTags {
		asnRuleCount += len(rules)
	}

	if cfg.Global.Geodata.GeoSite.Enable {
		for _, cat := range cfg.Categories {
			res := results[cat.Name]
			if res == nil || !resolveVal(cat.GeoSite, true) {
				continue
			}
			if rules := domRulesToSlice(res.DomRules); len(rules) > 0 {
				geosite[cat.Name] = rules
			} else {
				delete(geosite, cat.Name)
			}
		}
		if !writeOut("geosite.dat", geoSiteOutputPath, func() error { return WriteGeoSite(geoSiteOutputPath, geosite) }, len(geosite)) {
			failed++
		}
	}

	// geoip.dat = geoip 上游 pick + category geoip 标签 + IP-ASN 识别。
	if needGeoIP {
		geoip := cloneRuleMap(store.geoip)
		for _, cat := range cfg.Categories {
			res := results[cat.Name]
			if res == nil || !resolveVal(cat.GeoIP, true) {
				continue
			}
			if rules := ipRulesToSlice(res.IPRules); len(rules) > 0 {
				geoip[cat.Name] = rules
			} else {
				delete(geoip, cat.Name)
			}
		}
		for tag, rules := range asnTags {
			geoip[tag] = rules
		}
		if !writeOut("geoip.dat", geoIPOutputPath, func() error { return WriteGeoIP(geoIPOutputPath, geoip) }, len(geoip)) {
			failed++
		}
	}

	// country.mmdb = mmdb 上游 pick + category mmdb 标签 + IP-ASN 识别。
	if needMMDB {
		mmdb := cloneRuleMap(store.asn)
		for _, cat := range cfg.Categories {
			res := results[cat.Name]
			if res == nil || !resolveVal(cat.MMDB, true) {
				continue
			}
			if rules := ipRulesToSlice(res.IPRules); len(rules) > 0 {
				mmdb[cat.Name] = rules
			} else {
				delete(mmdb, cat.Name)
			}
		}
		for tag, rules := range asnTags {
			mmdb[tag] = rules
		}
		onlyASN := cfg.Global.Geodata.MMDB.OnlyASN
		if !writeOut("country.mmdb", countryOutputPath, func() error { return WriteMMDB(countryOutputPath, mmdb, onlyASN) }, len(mmdb)) {
			failed++
		}
	}

	if failed > 0 {
		fmt.Printf("⚠️ 有 %d 个 Geo/ASN 文件写入失败，请检查磁盘空间或权限。\n", failed)
	}
	return asnRuleCount
}

// collectASNTags 从所有规则集的 IP-ASN 规则提取 AS 号，自动拉取网段，返回 "AS<number>" -> IP-CIDR。
// 这样即使不配置 geo/mmdb 上游，也能从分散上游（如 Telegram.list）与 add/<name>.list 中的
// IP-ASN 规则自动识别网段，共享给 geoip.dat 与 country.mmdb。
func collectASNTags(results map[string]*ProcessedResult) map[string][]Rule {
	asnTags := map[string][]Rule{}
	for _, res := range results {
		if res == nil {
			continue
		}
		for _, asnVal := range res.IPRules["IP-ASN"] {
			n, ok := parseASNTag(asnVal)
			if !ok {
				continue
			}
			key := fmt.Sprintf("AS%d", n)
			if _, exists := asnTags[key]; exists {
				continue
			}
			if rules := fetchASNToRules(n); rules != nil {
				asnTags[key] = rules
			}
		}
	}
	return asnTags
}

// writeOut 统一输出与告警，返回是否写入成功。
func writeOut(label, path string, write func() error, count int) bool {
	ensureParentDir(path)
	if err := write(); err != nil {
		fmt.Printf("❌ 写出 %s [%s] 失败: %v\n", label, path, err)
		return false
	}
	fmt.Printf("✅ 已生成 %s: %s（%d 个标签）\n", label, path, count)
	return true
}

// domRulesToSlice 把去重结果中的域名规则（按类型分组）展开为规则切片（固定顺序，确定性输出）。
func domRulesToSlice(m map[string][]string) []Rule {
	var out []Rule
	for _, t := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"} {
		for _, v := range m[t] {
			out = append(out, Rule{Type: t, Value: v})
		}
	}
	return out
}

// ipRulesToSlice 把去重结果中的 IP 规则展开为规则切片。
func ipRulesToSlice(m map[string][]string) []Rule {
	var out []Rule
	for _, t := range []string{"IP-CIDR", "IP-CIDR6"} {
		for _, v := range m[t] {
			out = append(out, Rule{Type: t, Value: v})
		}
	}
	return out
}

// cloneRuleMap 浅拷贝（值切片共享，此处只读不再改），避免污染 store。
func cloneRuleMap(m map[string][]Rule) map[string][]Rule {
	out := make(map[string][]Rule, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ensureParentDir 确保文件所在的父目录存在（幂等，忽略错误由后续写操作兜底）。
func ensureParentDir(path string) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
}
