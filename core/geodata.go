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
	// asnOutputPath 与 countryOutputPath 同源（同一份 store.asn + category mmdb 标签 + IP-ASN 识别），
	// 只是记录形态不同：country.mmdb 写 tags 数组，asn.mmdb 写 autonomous_system_number（GeoLite2-ASN 兼容）。
	asnOutputPath = "publish/asn.mmdb"

	// geopickPrefix 标记由 pick 标签物化出的"虚拟上游"（格式 geopick:<来源URL>|<标签>）：
	// FetchAll 据此跳过下载（规则已写入 temp/raw）；报表据此还原真实来源与标签名。
	//
	// 这是「虚拟上游」的**唯一**判定：categories.upstreams 里的 geosite:/geoip:/asn:
	// 标签引用也会被 materializeGeoRefUpstreams 改写成同一形态，因此下载阶段无需
	// 再认识第二种前缀。
	geopickPrefix = "geopick:"
)

// geoKindNames 是 GeoDataStore 三张表与 kind 名的对应关系（顺序固定，用于稳定遍历与文案）。
// **这是 kind 清单的唯一来源**：geoRefPrefixes（引用语法前缀）由它派生，避免两处各自维护
// 一份 "geosite"/"geoip"/"asn" 字面量而悄悄漂移。
var geoKindNames = [...]string{"geosite", "geoip", "asn"}

// geoStoreKey 生成 GeoDataStore.source 的键（"<kind>:<tag>"）。
// store.source 的写入方（BuildGeoData）与读取方（materializePickCategories /
// materializeGeoRefUpstreams）必须用同一套拼接规则：任一处改名会让查表静默落空、
// 回退成 "auto"，表现为**报表来源错标且不报错**。
func geoStoreKey(kind, tag string) string { return kind + ":" + tag }

// geoTable 按 kind 取对应的标签表；未知 kind 返回 nil（读取方对 nil map 安全）。
func (s *GeoDataStore) geoTable(kind string) map[string][]Rule {
	switch kind {
	case "geosite":
		return s.geosite
	case "geoip":
		return s.geoip
	case "asn":
		return s.asn
	default:
		return nil
	}
}

// geoRules 按 kind 取标签规则；未配置该类型的上游（enable=false）时返回 nil。
func (s *GeoDataStore) geoRules(kind, tag string) []Rule {
	return s.geoTable(kind)[tag]
}

// geoTagKnown 判断某标签是否在本次构建的 store 中存在（即使规则为空也算"已知"）。
func (s *GeoDataStore) geoTagKnown(kind, tag string) bool {
	return hasMapKey(s.geoTable(kind), tag)
}

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

	// source 的键统一由 geoStoreKey 生成：读取方（materialize*）必须用同一函数，
	// 否则查表静默落空 → 来源回退 "auto" → 报表错标且不报错。
	source := make(map[string]string, len(geoSrc)+len(geoIPSrc)+len(asnSrc))
	for k, v := range geoSrc {
		source[geoStoreKey("geosite", k)] = v
	}
	for k, v := range geoIPSrc {
		source[geoStoreKey("geoip", k)] = v
	}
	for k, v := range asnSrc {
		source[geoStoreKey("asn", k)] = v
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
// 这样 pick 的标签既进入 geosite.dat / geoip.dat / country.mmdb（与 asn.mmdb），也生成对应的 mrs/srs/list 文件。
func materializePickCategories(cfg *Config, store *GeoDataStore) {
	writePick := func(kind, tag string, rules []Rule) {
		// ASN 标签（如 AS13335）不是独立规则集，不物化为 category，避免污染统计报表。
		if _, isASN := parseASNTag(tag); isASN {
			return
		}
		if len(rules) == 0 {
			return
		}
		src := store.source[geoStoreKey(kind, tag)]
		if src == "" {
			src = "auto"
		}
		// 注意：这里必须使用**原始标签**（不做归一化）。
		// 该 URL 只用于报表展示与来源追溯，category 名与 store.source 的键都用原始标签；
		// 若在此归一化（如 geosite 标签 "as123" 变成 "AS123"），会出现"URL 标签 ≠ category 名"的展示层不一致。
		// normalizeGeoRefTag 只服务于新增的 geosite:/geoip:/asn: 引用解析路径（parseGeoRef），
		// 且它是 kind 感知的：geosite/geoip 只小写，绝不做 ASN 归一。
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

// materializeGeoRefUpstreams 让 categories.upstreams 可以直接引用 geo/mmdb 标签：
func materializeGeoRefUpstreams(cfg *Config, store *GeoDataStore) {
	prefix := geopickPrefix
	for i := range cfg.Categories {
		cat := &cfg.Categories[i]
		for j := range cat.Upstreams {
			up := &cat.Upstreams[j]
			raw := strings.TrimSpace(up.URL)
			// 幂等守卫：已物化为 geopick: 形态的上游不再处理（未物化的 geo 引用必须继续往下走）。
			// 只跳过、不登记：规则文件由物化它的那一方写出。
			if raw == "" || strings.HasPrefix(raw, prefix) {
				continue
			}
			kind, tag, ok := parseGeoRef(raw)
			if !ok {
				continue
			}

			rules := store.geoRules(kind, tag)
			if len(rules) == 0 {
				if store.geoTagKnown(kind, tag) {
					// 标签存在但规则为空：数据异常（上游数据里该标签为空）。
					fmt.Printf("⚠️ [%s] 上游引用 %s 命中标签但规则为空（异常数据）：可能 "+
						"global.geodata.%s 的上游数据中该标签为空；已跳过该上游，其余上游不受影响。\n",
						cat.Name, raw, kind)
				} else {
					fmt.Printf("⚠️ [%s] 上游引用 %s 未命中本次构建的 Geo 数据：可能 "+
						"global.geodata.%s.enable=false，或上游未 pick 到该标签；已跳过该上游，其余上游不受影响。\n",
						cat.Name, raw, kind)
				}
				// 统一改写为"无规则"的虚拟上游形态：不写文件，但必须避免它被下载阶段
				// 当作真实 URL 请求（那样会把"标签不存在/为空"误报成"下载失败"）。
				up.URL = prefix + "auto|" + tag
				continue
			}

			src := store.source[geoStoreKey(kind, tag)]
			if src == "" {
				src = "auto"
			}
			// 下标 j+1 与 ProcessCategory 的 i+1 定位一致：引用与普通上游共用同一套槽位约定。
			// 同一标签被重复引用时，每个槽位各写一份内容相同的文件（保持槽位 1:1 关系），
			// 最终规则由 ProcessCategory 跨上游合并去重 —— 与"用户真的写了两条相同上游"同构。
			writeRulesFile(fmt.Sprintf("temp/raw/%s_%d.txt", cat.Name, j+1), rules)
			up.URL = prefix + src + "|" + tag
		}
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

// geoRefPrefixes 是 categories.upstreams 中「Geo 标签引用」的允许前缀。
// 由 geoKindNames 派生（kind + ":"），因此新增 kind 只需改 geoKindNames 一处；
// 归属判定只依赖这一张表，避免多处字符串比较漂移。
var geoRefPrefixes = func() []string {
	prefixes := make([]string, 0, len(geoKindNames))
	for _, kind := range geoKindNames {
		prefixes = append(prefixes, kind+":")
	}
	return prefixes
}()

// geoRefPrefixKind 判断一个「未归一化」的引用文本是否使用了 geo 前缀，并返回其 kind。
// 与 parseGeoRef 的区别：**不要求标签非空**，因此可用于区分
// "geosite:cn"（合法引用）与 "geosite:"（引用了合法前缀但标签为空，属配置错误）。
// 前缀识别同样只依赖 geoRefPrefixes，不在别处重复字符串比较。
func geoRefPrefixKind(rawURL string) (kind string, ok bool) {
	lower := strings.ToLower(strings.TrimSpace(rawURL))
	for _, prefix := range geoRefPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSuffix(prefix, ":"), true
		}
	}
	return "", false
}

// validateGeoRefUpstream 校验用户配置里的一个上游 url 是否为**合法**的 geo 标签引用。
// 返回 (kind, tag, true) 表示是引用且形态合法；ok=false 表示"该 url 不被视为合法引用"。
// 调用方据此 fail fast，把错误从运行期（下载失败/静默失效）提前到配置校验期。
//
// 被判定为非法（isGeoRef=true 但 ok=false）的情形：
//   - 前缀命中 geoRefPrefixes 但标签为空（"geosite:" / "geoip:   "）——
//     这类 url 既不是可下载的真实地址，也不是有效引用，运行期只能表现为"下载失败"，会误导排查；
//   - geopickPrefix（内部物化标记）——它不是公开配置语法，用户手写会让整条上游静默失效。
func validateGeoRefUpstream(rawURL string) (kind, tag string, isGeoRef bool, ok bool) {
	trimmed := strings.TrimSpace(rawURL)
	if strings.HasPrefix(trimmed, geopickPrefix) {
		return "", "", true, false
	}
	kind, ok2 := geoRefPrefixKind(trimmed)
	if !ok2 {
		return "", "", false, false
	}
	refKind, refTag, valid := parseGeoRef(trimmed)
	return kind, refTag, true, valid && refKind == kind
}

// isVirtualUpstream 判断一个上游 url 是否属于「虚拟上游」——即**不应被当作真实 URL 下载**的上游。
// 判定只有这一处，供 FetchAll 的下载跳过判定使用（并作为 TestGeoRef* 的分类口径）。
//
// 谓词为真有两种情形：
//  1. 已物化的 geopick:<来源URL>|<标签> 形态（materializePickCategories / materializeGeoRefUpstreams 产出）；
//  2. 由 parseGeoRef 可识别的 geo 标签引用（geosite:|geoip:|asn:），即使它尚未物化。
//
// 情形 2 是必要的防御纵深：未命中标签的引用会被 materializeGeoRefUpstreams 改写成
// "geopick:auto|<标签>"，但若有人把未经物化的 cfg 直接交给 FetchAll，下载阶段也不会
// 拿 "geosite:xxx" 去发请求——否则会把"引用了不存在的标签"误报成"下载失败"。
//
// 注意：形如 "geosite:"（空标签）不是有效引用，仍按普通 URL 处理
// （这类配置已由 validateGeoRefUpstream 在校验期拒绝）。
func isVirtualUpstream(url string) bool {
	if strings.HasPrefix(strings.TrimSpace(url), geopickPrefix) {
		return true
	}
	_, _, ok := parseGeoRef(url)
	return ok
}

// parseGeoRef 解析 "geosite:cn" / "geoip:cn" / "asn:AS13335" 形态的标签引用。
// 前缀大小写不敏感；kind 取 geoKindNames 中的规范名（与 GeoDataStore 的字段对应），
// tag 按 normalizeGeoRefTag 归一化（geosite/geoip 只小写、asn 规范为 AS<n>）。
//
// 不满足形态（含空标签）时 ok=false，调用方应把该上游当作普通 URL 处理。
// 注意 "geopick:" 由 geopickPrefix 单独判定，不在此处识别，因此已物化的虚拟上游不会被二次改写。
func parseGeoRef(rawURL string) (kind, tag string, ok bool) {
	ref := strings.TrimSpace(rawURL)
	lower := strings.ToLower(ref)
	for _, prefix := range geoRefPrefixes {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		kind = strings.TrimSuffix(prefix, ":")
		tag = normalizeGeoRefTag(kind, strings.TrimSpace(ref[len(prefix):]))
		if tag == "" {
			return "", "", false
		}
		return kind, tag, true
	}
	return "", "", false
}

// normalizeGeoRefTag 归一化**引用语法**里的标签，结果必须与 store 的键一致：
//   - asn 引用统一为 "AS<n>"（与 geoip/mmdb 的 pick 一致）；
//   - geosite/geoip 引用只做小写，**绝不做 ASN 归一**。
//
// 后者是关键：store 的键来自上游标签（geosite/geoip 统一小写），若把纯数字标签
// （如 geosite 里真实存在的 "123"）归一成 "AS123"，查表必然失配，已存在的标签会被
// 误判为"未命中"，导致告警、不写槽位文件、该上游规则**静默丢失**。
func normalizeGeoRefTag(kind, tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	if kind == "asn" {
		// 与 buildGeoOfType 对 kind==asn 的归一保持一致：能解析为 AS 号的写成 "AS<n>"，
		// 其余标签小写（不能用 ToUpper——那会与 store 的小写键失配，重演本轮修掉的 bug）。
		if n, ok := parseASNTag(tag); ok {
			return fmt.Sprintf("AS%d", n)
		}
		return strings.ToLower(tag)
	}
	return strings.ToLower(tag)
}

// hasMapKey 判断映射是否含该键（nil 映射安全）。
func hasMapKey[V any](m map[string]V, key string) bool {
	_, ok := m[key]
	return ok
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
	if err := downloadWithRetry(client, url, tmp, fetchRetries); err != nil {
		return nil, fmt.Errorf("下载 geo 上游失败: %w", err)
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
//
// 声明为函数变量（而非普通函数）是为了给离线测试留出替换点：
// 回归测试可临时替换该变量以 mock 网络，避免依赖真实外网。
// 生产路径不做任何替换，行为与普通函数一致。
var FetchASNPrefixes = func(asn uint32) ([]string, error) {
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

	// ASN 网段表（IP-ASN 规则识别），同时喂给 geoip.dat 与两份 mmdb（country.mmdb / asn.mmdb）。
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
		replaceCategoryTags(geosite, cfg, results, func(cat Category) *bool { return cat.GeoSite }, domainSide)
		if !writeOut("geosite.dat", geoSiteOutputPath, func() error { return WriteGeoSite(geoSiteOutputPath, geosite) }, len(geosite)) {
			failed++
		}
	}

	// geoip.dat = geoip 上游 pick + category geoip 标签 + IP-ASN 识别。
	if needGeoIP {
		geoip := cloneRuleMap(store.geoip)
		replaceCategoryTags(geoip, cfg, results, func(cat Category) *bool { return cat.GeoIP }, ipSide)
		for tag, rules := range asnTags {
			geoip[tag] = rules
		}
		if !writeOut("geoip.dat", geoIPOutputPath, func() error { return WriteGeoIP(geoIPOutputPath, geoip) }, len(geoip)) {
			failed++
		}
	}

	// mmdb.enable=true 时固定产出两份文件，且**共用同一份**已解析数据：
	//   country.mmdb = mmdb 上游 pick + category mmdb 标签 + IP-ASN 识别，记录写 tags 数组；
	//   asn.mmdb     = 同一份数据中的 ASN 标签，记录写 autonomous_system_number（GeoLite2-ASN 兼容）。
	// 两份文件都只由 geodata.mmdb 的开关控制；任一份写出失败只计数与告警，不阻断另一份。
	if needMMDB {
		mmdb := cloneRuleMap(store.asn)
		replaceCategoryTags(mmdb, cfg, results, func(cat Category) *bool { return cat.MMDB }, ipSide)
		for tag, rules := range asnTags {
			mmdb[tag] = rules
		}
		if !writeOut("country.mmdb", countryOutputPath, func() error { return WriteMMDB(countryOutputPath, mmdb) }, len(mmdb)) {
			failed++
		}
		if !writeOut("asn.mmdb", asnOutputPath, func() error { return WriteASNMMDB(asnOutputPath, mmdb) }, len(mmdb)) {
			failed++
		}
	}

	if failed > 0 {
		fmt.Printf("⚠️ 有 %d 个 Geo/ASN 文件写入失败，请检查磁盘空间或权限。\n", failed)
	}
	return asnRuleCount
}

// replaceCategoryTags 用各 category 的处理结果覆盖（或删除）同名标签。
//
// 语义：category 级开关为 false → **跳过**该 category（上游标签原样保留）；
// 未覆盖（nil）→ 视为 true；结果为空 → **删除**同名标签。
//
// 三个产物（geosite.dat / geoip.dat / country.mmdb）的覆盖逻辑只有两处差异——
// "取哪个开关"与"取域名还是 IP 规则"，因此把差异参数化，共用这一份实现。
func replaceCategoryTags(
	dst map[string][]Rule,
	cfg *Config,
	results map[string]*ProcessedResult,
	override func(Category) *bool,
	side ruleSide,
) {
	toRules := side.toRules
	for _, cat := range cfg.Categories {
		res := results[cat.Name]
		if res == nil || !resolveVal(override(cat), true) {
			continue
		}
		if rules := toRules(side.pick(res)); len(rules) > 0 {
			dst[cat.Name] = rules
		} else {
			delete(dst, cat.Name)
		}
	}
}

// ruleSide 描述"从 ProcessedResult 的哪一侧取规则、以及如何展开为 []Rule"。
type ruleSide struct {
	pick    func(*ProcessedResult) map[string][]string
	toRules func(map[string][]string) []Rule
}

var (
	domainSide = ruleSide{func(r *ProcessedResult) map[string][]string { return r.DomRules }, domRulesToSlice}
	ipSide     = ruleSide{func(r *ProcessedResult) map[string][]string { return r.IPRules }, ipRulesToSlice}
)

// collectASNTags 从所有规则集的 IP-ASN 规则提取 AS 号，自动拉取网段，返回 "AS<number>" -> IP-CIDR。
// 这样即使不配置 geo/mmdb 上游，也能从分散上游（如 Telegram.list）与 add/<name>.list 中的
// IP-ASN 规则自动识别网段，共享给 geoip.dat 与两份 mmdb（country.mmdb / asn.mmdb）。
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
