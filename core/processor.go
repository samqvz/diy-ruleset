package core

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
)

// globalRegexCache 缓存跨规则集复用的正则，避免同一模式在多个 goroutine 中重复编译。
var globalRegexCache sync.Map

// localParserNames 是 add/remove 本地文件中允许的 `parser=...` 前缀名。
// 提升为包级变量，避免每个规则集重复构造。
var localParserNames = map[string]bool{
	"clash": true, "v2ray": true, "adblock": true, "hosts": true,
	"dnsmasq": true, "smartdns": true, "surge": true, "shadowrocket": true,
	"quantumultx": true, "loon": true, "stash": true, "white": true,
}

// getCachedRegex 编译并缓存正则。第二个返回值为编译错误，调用方必须显式处置：
// 剔除用的正则编译失败会让"剔除意图"无声失效，因此这里不把错误吞掉。
// 编译失败的结果同样进入缓存（存 nil），避免同一非法模式被反复编译。
func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := globalRegexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		if re == nil {
			// 命中"已知编译失败"的缓存项：重放同一语义的错误。
			return nil, fmt.Errorf("正则 %q 此前编译失败（已缓存）", pattern)
		}
		return re, nil
	}
	c, err := regexp.Compile(pattern)
	if err != nil {
		globalRegexCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil, err
	}
	actual, _ := globalRegexCache.LoadOrStore(pattern, c)
	re, _ := actual.(*regexp.Regexp)
	if re == nil {
		return nil, fmt.Errorf("正则 %q 缓存项非法", pattern)
	}
	return re, nil
}

// ProcessedResult 汇总单个规则集的处理产物与统计信息。
type ProcessedResult struct {
	DomRules      map[string][]string // 域名类规则，按 Rule.Type 分组
	IPRules       map[string][]string // IP/端口/ASN 类规则，按 Rule.Type 分组
	WhiteDomRules map[string][]string // 提取出的白名单域名规则

	RawCount   int // 上游原始命中行数
	AddCount   int // add/ 补充行数
	RmCount    int // remove/ 剔除行数
	FinalCount int // 去重后最终规则数
	WhiteCount int // 去重后白名单规则数

	ExactCounts        map[string]int // 各客户端导出条数（供报表展示）
	UpstreamStats      map[string]int // 每个上游贡献的原始行数
	WhiteUpstreamStats map[string]int

	RawAdblockRules       []string // 保留的上游 adblock 原始行
	RawDnsmasqRules       []string
	RawSmartDNSRules      []string
	RawWhiteAdblockRules  []string
	RawWhiteDnsmasqRules  []string
	RawWhiteSmartDNSRules []string
}

// RuleMatcher 封装"跨类型查杀"所需的匹配器：关键词子串、正则、后缀字典树。
//
// 正则集合带**字面前缀索引**（regexEntry.prefix）：只有字面前缀确实是候选值子串的正则
// 才进入 regexp 引擎。这是纯剪枝——被剪掉的正则必然不匹配（字面前缀都不在值里，
// 整条正则更不可能匹配），因此结果与"逐条全扫"逐位相同。
//
// 索引分两层，避免"正则数多时逐条比对前缀"重新退化为 O(候选数 × 正则数)：
//   - 第一层 regexBuckets：按**字面前缀首字符**分桶，候选只进对应桶；
//   - 第二层 regexEntry.prefix：桶内再做完整前缀子串判定，通过才进 regexp 引擎。
//
// 前缀为空的正则（如 `.*`、`(.+\.)?x$`）无法剪枝，统一放在空键桶里对每个候选尝试。
type RuleMatcher struct {
	keywords     []string
	regexes      []regexEntry          // 全部正则（保留原顺序，供无索引路径/调试使用）
	regexBuckets map[byte][]regexEntry // 首字符 -> 候选正则
	anyRegex     []regexEntry          // 前缀为空、无法剪枝的正则
	trie         *SuffixTrie
	ac           *ahoCorasick // 关键词多模式自动机（无关键词时为 nil）
}

// regexEntry 是一条剔除正则及其可安全剪枝的字面前缀。
// prefix == "" 表示无法提取字面前缀，必须对每个候选都尝试（等价于原线性扫描）。
type regexEntry struct {
	prefix string
	re     *regexp.Regexp
}

// NewRuleMatcher 由 rm* 集合构建匹配器。
// 空关键词/空正则在语义上会匹配一切，属于非法输入，这里直接跳过以保证健壮性。
func NewRuleMatcher(rmKeywords map[string]bool, rmRegexes map[string]*regexp.Regexp, trie *SuffixTrie) *RuleMatcher {
	m := &RuleMatcher{
		trie:         trie,
		keywords:     make([]string, 0, len(rmKeywords)),
		regexes:      make([]regexEntry, 0, len(rmRegexes)),
		regexBuckets: make(map[byte][]regexEntry, len(rmRegexes)),
	}
	// 按字典序迭代，保证关键词顺序确定（匹配结果为布尔值，顺序本不影响结果，但确定性更利于调试与可复现）。
	for _, kw := range slices.Sorted(maps.Keys(rmKeywords)) {
		if kw == "" {
			continue
		}
		m.keywords = append(m.keywords, kw)
	}
	for _, pattern := range slices.Sorted(maps.Keys(rmRegexes)) {
		if pattern == "" {
			continue
		}
		re := rmRegexes[pattern]
		if re == nil {
			continue
		}
		entry := regexEntry{prefix: regexLiteralPrefix(pattern), re: re}
		m.regexes = append(m.regexes, entry)
		if entry.prefix == "" {
			m.anyRegex = append(m.anyRegex, entry)
			continue
		}
		// 桶键用**小写**首字符：候选值经 Parse 小写化，但正则的字面前缀可能是大写
		// （如 `^UPPER`）。小写化桶键只会让更多候选进入桶内做完整前缀判定，
		// 不会漏判（完整前缀判定仍用原始大小写，与正则引擎一致）。
		key := entry.prefix[0] | 0x20
		m.regexBuckets[key] = append(m.regexBuckets[key], entry)
	}
	if len(m.keywords) > 0 {
		m.ac = newAhoCorasick(m.keywords)
	}
	return m
}

// regexLiteralPrefix 提取正则开头的**必然字面前缀**，作为剪枝索引。
//
// 只在确定安全时返回非空串：
//   - 跳过开头的 `^` 锚点（它不是字面字符）；
//   - 遇到转义（`\.`、`\s` 等）立即停止——不做反转义，宁可少提取也不误剪；
//   - 遇到任何正则元字符（含 `*` `?` `+` `(` `[` 等）立即停止；
//   - 其余字符是字面字符，原样累积。
//
// 返回空串表示"无可用前缀"（如 `.*`、`(.+\.)?x$`、纯转义开头），此时该正则对每个
// 候选都会被尝试。
func regexLiteralPrefix(pattern string) string {
	body := pattern
	if strings.HasPrefix(body, "^") {
		body = body[1:]
	}
	const meta = `\\.+*?()|[]{}^$`
	end := 0
	for end < len(body) {
		c := body[end]
		if strings.IndexByte(meta, c) >= 0 {
			break
		}
		end++
	}
	return body[:end]
}

// regexPrefilter 判断一条带字面前缀的正则是否**可能**匹配 val。
// 前缀为空 → 无法剪枝，返回 true（必须真跑引擎）。
func regexPrefilter(prefix, val string) bool {
	if prefix == "" {
		return true
	}
	// val 包含字面前缀才可能命中该正则；否则必然不匹配，直接剪枝。
	return strings.Contains(val, prefix)
}

// matchAnyRegex 按"首字符桶 + 字面前缀"两层剪枝判断 val 是否命中任一正则。
func (m *RuleMatcher) matchAnyRegex(val string) bool {
	if len(m.regexes) == 0 {
		return false
	}
	for _, entry := range m.anyRegex {
		if entry.re.MatchString(val) {
			return true
		}
	}
	if val == "" {
		return false
	}
	for _, entry := range m.regexBuckets[val[0]|0x20] {
		if !regexPrefilter(entry.prefix, val) {
			continue
		}
		if entry.re.MatchString(val) {
			return true
		}
	}
	return false
}

// cleanPatternForMatch 把 DOMAIN-REGEX/WILDCARD 的表达式还原为"近似通配符"字符串，
// 以便用子串/后缀方式做跨类型查杀。
func (m *RuleMatcher) cleanPatternForMatch(orig string) string {
	if len(orig) > 1 && orig[0] == '^' {
		orig = orig[1:]
	}
	if len(orig) > 1 && orig[len(orig)-1] == '$' {
		orig = orig[:len(orig)-1]
	}
	if strings.HasPrefix(orig, `(.+\.)?`) {
		orig = "+." + orig[7:]
	} else if strings.HasPrefix(orig, `.+\.`) {
		orig = "." + orig[4:]
	}
	if orig == ".*" || orig == "[^.]+" {
		return "*"
	}

	orig = strings.ReplaceAll(orig, ".*", "*")
	orig = strings.ReplaceAll(orig, "[^.]+", "*")
	orig = strings.ReplaceAll(orig, `\.`, ".")
	orig = strings.ReplaceAll(orig, `\\`, `\`)

	return orig
}

// IsCrossKilled 判断一条规则是否应被"跨类型剔除集合"（关键词/正则/后缀）查杀。
func (m *RuleMatcher) IsCrossKilled(val string, ruleType string) bool {
	checkVal := val
	if ruleType == "DOMAIN-REGEX" || ruleType == "DOMAIN-WILDCARD" {
		checkVal = m.cleanPatternForMatch(val)
	}
	if m.keywordHit(checkVal, ruleType) {
		return true
	}
	if ruleType == "DOMAIN-KEYWORD" {
		return false
	}
	if ruleType == "DOMAIN" {
		if m.trie.MatchAnySuffix(checkVal) {
			return true
		}
	} else {
		if m.trie.MatchParentSuffix(checkVal) {
			return true
		}
	}
	if ruleType == "DOMAIN-SUFFIX" {
		return false
	}
	if ruleType == "DOMAIN" {
		return m.matchAnyRegex(checkVal)
	}
	return false
}

// keywordHit 判断 checkVal 是否命中任一剔除关键词（子串匹配）。
//
// 仅当存在长度更短的关键词作为子串命中时才查杀，因此走 containsAnyShorterThan。
func (m *RuleMatcher) keywordHit(checkVal, ruleType string) bool {
	if m.ac == nil {
		return false
	}
	if ruleType == "DOMAIN-KEYWORD" {
		return m.ac.containsAnyShorterThan(checkVal, len(checkVal))
	}
	return m.ac.containsAny(checkVal)
}

// ruleBuckets 是去重阶段用到的各类集合，集中传递以减少函数签名噪音。
type ruleBuckets struct {
	domains   map[string]bool
	suffixes  map[string]bool
	keywords  map[string]bool
	regexes   map[string]bool
	wildcards map[string]bool
	others    map[Rule]bool
	ipv4      *IPv4Trie
	ipv6      *IPv6Trie
}

// add 把一条已解析规则投入对应集合。
func (b *ruleBuckets) add(r *Rule) {
	switch r.Type {
	case "DOMAIN":
		b.domains[r.Value] = true
	case "DOMAIN-SUFFIX":
		b.suffixes[r.Value] = true
	case "DOMAIN-KEYWORD":
		b.keywords[r.Value] = true
	case "DOMAIN-REGEX":
		b.regexes[r.Value] = true
	case "DOMAIN-WILDCARD":
		b.wildcards[r.Value] = true
	case "IP-CIDR", "IP-CIDR6":
		insertIP(r.Value, b.ipv4, b.ipv6)
	default:
		b.others[*r] = true
	}
}

// killKind 标识一条规则在"跨类型查杀"登记阶段的处置方式。
type killKind int

const (
	killNone     killKind = iota // 不登记到跨类型集合（DOMAIN / IP-CIDR / IP-CIDR6）
	killSuffix                   // DOMAIN-SUFFIX
	killKeyword                  // DOMAIN-KEYWORD
	killRegex                    // DOMAIN-REGEX
	killWildcard                 // DOMAIN-WILDCARD
)

// killKindOf 是"规则类型 → 跨类型登记方式"的唯一映射表。
func killKindOf(t string) killKind {
	switch t {
	case "DOMAIN-SUFFIX":
		return killSuffix
	case "DOMAIN-KEYWORD":
		return killKeyword
	case "DOMAIN-REGEX":
		return killRegex
	case "DOMAIN-WILDCARD":
		return killWildcard
	default:
		return killNone
	}
}

// crossTypeKills 是参与跨类型查杀的四个集合，集中传递以减少签名噪音。
type crossTypeKills struct {
	suffixes  map[string]bool
	keywords  map[string]bool
	regexes   map[string]bool
	wildcards map[string]bool
}

// register 按 killKindOf 的映射登记一条规则。
func (c crossTypeKills) register(t, value string) {
	switch killKindOf(t) {
	case killSuffix:
		c.suffixes[value] = true
	case killKeyword:
		c.keywords[value] = true
	case killRegex:
		c.regexes[value] = true
	case killWildcard:
		c.wildcards[value] = true
	}
}

// rawLineBuckets 收集需要"原样透传"到 DNS/Adblock 产物的上游原始行。
type rawLineBuckets struct {
	adblock  *[]string
	dnsmasq  *[]string
	smartdns *[]string
	seen     map[string]bool
	prefix   string // 去重键前缀：普通行为 a_/d_/s_，白名单行为 wa_/wd_/ws_
}

// add 把一行原始规则按其 parser 归入对应桶（同一 parser 内去重，保持首次出现顺序）。
func (b rawLineBuckets) add(cleanLine, parserType string) {
	var dst *[]string
	var mark string
	switch parserType {
	case "adblock":
		dst, mark = b.adblock, "a_"
	case "dnsmasq":
		dst, mark = b.dnsmasq, "d_"
	case "smartdns":
		dst, mark = b.smartdns, "s_"
	default:
		return
	}
	key := b.prefix + mark + cleanLine
	if b.seen[key] {
		return
	}
	b.seen[key] = true
	*dst = append(*dst, cleanLine)
}

// killableTypes 是跨类型查杀处理的**固定类型清单与顺序**。
var killableTypes = [...]string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}

// bucketOf 按规则类型取对应的值集合（仅覆盖 killableTypes 中的类型）。
func (b *ruleBuckets) bucketOf(typ string) map[string]bool {
	switch typ {
	case "DOMAIN":
		return b.domains
	case "DOMAIN-SUFFIX":
		return b.suffixes
	case "DOMAIN-REGEX":
		return b.regexes
	case "DOMAIN-KEYWORD":
		return b.keywords
	case "DOMAIN-WILDCARD":
		return b.wildcards
	default:
		return nil
	}
}

// ProcessCategory 是引擎核心：加载上游/本地/远程剔除规则，归一化后做统一交叉查杀去重。
// 返回该规则集的分组结果与统计信息。
func ProcessCategory(cat Category, cfg *Config) *ProcessedResult {
	b := &ruleBuckets{
		domains:   make(map[string]bool),
		suffixes:  make(map[string]bool),
		keywords:  make(map[string]bool),
		regexes:   make(map[string]bool),
		wildcards: make(map[string]bool),
		others:    make(map[Rule]bool),
		ipv4:      &IPv4Trie{},
		ipv6:      &IPv6Trie{},
	}

	rmExact := make(map[Rule]bool)
	addExact := make(map[Rule]bool)
	kills := crossTypeKills{
		suffixes:  make(map[string]bool),
		keywords:  make(map[string]bool),
		regexes:   make(map[string]bool),
		wildcards: make(map[string]bool),
	}
	whiteDomains, whiteSuffixes, whiteRegexes := make(map[string]bool), make(map[string]bool), make(map[string]bool)

	seenRawRules := make(map[string]bool)

	res := &ProcessedResult{
		DomRules:              make(map[string][]string),
		IPRules:               make(map[string][]string),
		WhiteDomRules:         make(map[string][]string),
		UpstreamStats:         make(map[string]int),
		WhiteUpstreamStats:    make(map[string]int),
		RawAdblockRules:       make([]string, 0),
		RawDnsmasqRules:       make([]string, 0),
		RawSmartDNSRules:      make([]string, 0),
		RawWhiteAdblockRules:  make([]string, 0),
		RawWhiteDnsmasqRules:  make([]string, 0),
		RawWhiteSmartDNSRules: make([]string, 0),
		ExactCounts:           make(map[string]int),
	}

	// 原始行收集：普通行与白名单行共用 rawLineBuckets.add，仅去重键前缀不同。
	rawLines := rawLineBuckets{
		adblock:  &res.RawAdblockRules,
		dnsmasq:  &res.RawDnsmasqRules,
		smartdns: &res.RawSmartDNSRules,
		seen:     seenRawRules,
	}
	whiteRawLines := rawLineBuckets{
		adblock:  &res.RawWhiteAdblockRules,
		dnsmasq:  &res.RawWhiteDnsmasqRules,
		smartdns: &res.RawWhiteSmartDNSRules,
		seen:     seenRawRules,
		prefix:   "w",
	}

	processLine := func(line string, parserType string, isAdd bool, isRm bool, upURL string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || hasAnyPrefix(cleanLine, "#", "!", "//", "[") {
			return
		}

		if strings.HasPrefix(cleanLine, "@@") {
			if (cat.AutoExtractWhite && !isRm) || isAdd {
				whiteRawLines.add(cleanLine, parserType)

				if w := ParseWhite(cleanLine); w != nil {
					switch w.Type {
					case "DOMAIN":
						whiteDomains[w.Value] = true
					case "DOMAIN-SUFFIX":
						whiteSuffixes[w.Value] = true
					case "DOMAIN-REGEX":
						whiteRegexes[w.Value] = true
					}
					if upURL != "" {
						res.WhiteUpstreamStats[upURL]++
					}

					if !isAdd {
						behavior := cat.WhiteBehavior
						if behavior == "" {
							behavior = "remove"
						}
						if behavior == "remove" {
							res.RmCount++
							rmExact[*w] = true
							switch w.Type {
							case "DOMAIN":
								// 仅记录到 rmExact，避免跨类型误杀
							case "DOMAIN-SUFFIX":
								kills.suffixes[w.Value] = true
							case "DOMAIN-REGEX":
								kills.regexes[w.Value] = true
							}
						}
					}
				}
			}
			return
		}

		if !isAdd && !isRm {
			rawLines.add(cleanLine, parserType)
		}

		isExactRm, isExactAdd := false, false
		if isRm && strings.HasPrefix(cleanLine, "EXACT:") {
			isExactRm = true
			cleanLine = strings.TrimSpace(strings.TrimPrefix(cleanLine, "EXACT:"))
		} else if isAdd && strings.HasPrefix(cleanLine, "EXACT:") {
			isExactAdd = true
			cleanLine = strings.TrimSpace(strings.TrimPrefix(cleanLine, "EXACT:"))
		}

		r := Parse(cleanLine, parserType)
		if r == nil {
			return
		}

		if isRm {
			res.RmCount++
			rmExact[*r] = true
			if !isExactRm {
				if r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" {
					removeIP(r.Value, b.ipv4, b.ipv6)
				} else {
					kills.register(r.Type, r.Value)
				}
			}
			return
		}

		if isAdd {
			res.AddCount++
			if isExactAdd {
				addExact[*r] = true
			} else {
				// 非精准补充：登记到跨类型集合，使其对上游规则产生跨类型去重
				kills.register(r.Type, r.Value)
			}
		} else {
			res.RawCount++
		}

		b.add(r)
	}

	// loadEgernUpstream 需要按 YAML section 解析，因此单独实现；
	// 但规则入库复用 ruleBuckets.add，避免重复逻辑。
	loadEgernUpstream := func(f *os.File, upURL string) {
		sc := newLineScanner(f)
		linesBefore := res.RawCount
		currentSection := ""

		for sc.Scan() {
			trimmed := strings.TrimSpace(sc.Text())
			if strings.HasSuffix(trimmed, ":") {
				currentSection = strings.TrimSuffix(trimmed, ":")
				continue
			}
			if trimmed == "" || hasAnyPrefix(trimmed, "#", "!", "//") {
				continue
			}
			if r := ParseEgern(sc.Text(), currentSection); r != nil {
				res.RawCount++
				b.add(r)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Printf("⚠️ 读取 Egern 上游时出错: %v\n", err)
		}
		if upURL != "" {
			res.UpstreamStats[upURL] += res.RawCount - linesBefore
		}
	}

	loadUpstreams := func(target Category) {
		for i, up := range target.Upstreams {
			filePath := fmt.Sprintf("%s/%s_%d.txt", "temp/raw", target.Name, i+1)
			f, err := os.Open(filePath)
			if err != nil {
				// 显式策略：文件"不存在"是预期状态（虚拟上游不落文件、上游未下载），静默跳过；
				// 其它读取错误（权限、路径被目录占用等）会让该上游规则**无声消失**，必须告警。
				if !os.IsNotExist(err) {
					fmt.Printf("⚠️ [%s] 读取上游文件 [%s] 失败（该上游规则将被跳过）: %v\n", target.Name, filePath, err)
				}
				continue
			}

			parserType := up.Parser
			if parserType == "" {
				parserType = InferParser(filePath)
			}

			if parserType == "egern" {
				loadEgernUpstream(f, up.URL)
			} else {
				sc := newLineScanner(f)
				linesBefore := res.RawCount
				for sc.Scan() {
					processLine(sc.Text(), parserType, false, false, up.URL)
				}
				if err := sc.Err(); err != nil {
					fmt.Printf("⚠️ 读取上游文件 [%s] 时出错: %v\n", up.URL, err)
				}
				res.UpstreamStats[up.URL] += res.RawCount - linesBefore
			}
			f.Close()
		}
	}

	loadUpstreams(cat)
	for _, mergeCatName := range cat.MergeFrom {
		for _, c := range cfg.Categories {
			if c.Name == mergeCatName {
				loadUpstreams(c)
				break
			}
		}
	}

	processLocalLine := func(line string, isAdd bool, isRm bool, source string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || hasAnyPrefix(cleanLine, "#", "//") {
			return
		}

		parserType := "clash"
		if eqIdx := strings.Index(cleanLine, "="); eqIdx != -1 {
			if prefix := strings.ToLower(strings.TrimSpace(cleanLine[:eqIdx])); localParserNames[prefix] {
				parserType = prefix
				cleanLine = strings.TrimSpace(cleanLine[eqIdx+1:])
			}
		}
		processLine(cleanLine, parserType, isAdd, isRm, source)
	}

	// 本地补充规则 add/<cat>.list
	if f, err := os.Open(fmt.Sprintf("add/%s.list", cat.Name)); err == nil {
		sc := newLineScanner(f)
		for sc.Scan() {
			processLocalLine(sc.Text(), true, false, "Local Add")
		}
		if err := sc.Err(); err != nil {
			fmt.Printf("⚠️ 读取 add/%s.list 时出错: %v\n", cat.Name, err)
		}
		f.Close()
	}

	// 本地剔除规则 remove/<cat>.list
	if f, err := os.Open(fmt.Sprintf("remove/%s.list", cat.Name)); err == nil {
		sc := newLineScanner(f)
		for sc.Scan() {
			processLocalLine(sc.Text(), false, true, "Local Remove")
		}
		if err := sc.Err(); err != nil {
			fmt.Printf("⚠️ 读取 remove/%s.list 时出错: %v\n", cat.Name, err)
		}
		f.Close()
	}

	// 远程剔除列表 remove_urls
	for i, rmUp := range cat.RemoveURLs {
		filePath := fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cat.Name, i+1)
		f, err := os.Open(filePath)
		if err != nil {
			continue
		}
		parserType := rmUp.Parser
		if parserType == "" {
			parserType = InferParser(filePath)
		}
		sc := newLineScanner(f)
		for sc.Scan() {
			processLine(sc.Text(), parserType, false, true, "Remote Remove")
		}
		if err := sc.Err(); err != nil {
			fmt.Printf("⚠️ 读取远程剔除文件时出错: %v\n", err)
		}
		f.Close()
	}

	// 编译剔除用正则：DOMAIN-REGEX 直接编译；DOMAIN-WILDCARD 转为等价正则。
	// 编译失败必须告警：否则"用户写了剔除规则"会表现为"剔除无效"，且完全无声。
	compiledRmRegexesMap := make(map[string]*regexp.Regexp)
	for reg := range kills.regexes {
		if reg == "" {
			continue
		}
		c, err := getCachedRegex(reg)
		if err != nil {
			fmt.Printf("⚠️ [%s] 剔除正则编译失败，该条剔除规则被跳过: %q (%v)\n", cat.Name, reg, err)
			continue
		}
		compiledRmRegexesMap[reg] = c
	}
	for w := range kills.wildcards {
		if w == "" {
			continue
		}
		regStr := "^" + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(w, ".", `\.`), "*", `.*`), "?", `.`) + "$"
		c, err := getCachedRegex(regStr)
		if err != nil {
			fmt.Printf("⚠️ [%s] 剔除通配符 %q 转换出的正则编译失败，该条剔除规则被跳过: %v\n", cat.Name, w, err)
			continue
		}
		compiledRmRegexesMap[w] = c
	}

	// 后缀字典树：装入剔除后缀 + 普通后缀（用于跨类型去重）
	suffixTrie := NewSuffixTrie()
	for s := range kills.suffixes {
		suffixTrie.Insert(s)
	}
	for s := range b.suffixes {
		if !rmExact[Rule{Type: "DOMAIN-SUFFIX", Value: s}] && !addExact[Rule{Type: "DOMAIN-SUFFIX", Value: s}] {
			suffixTrie.Insert(s)
		}
	}

	matcher := NewRuleMatcher(kills.keywords, compiledRmRegexesMap, suffixTrie)

	// 逐类做跨类型查杀。遍历顺序与类型清单集中在 killableTypes，
	// 固定顺序只影响输出可复现性，不影响匹配结果。
	for _, kt := range killableTypes {
		for v := range b.bucketOf(kt) {
			if rmExact[Rule{Type: kt, Value: v}] {
				continue
			}
			if !matcher.IsCrossKilled(v, kt) {
				res.DomRules[kt] = append(res.DomRules[kt], v)
			}
		}
	}
	for o := range b.others {
		if rmExact[o] {
			continue
		}
		t, v := o.Type, o.Value
		if isDomainSideType(t) {
			res.DomRules[t] = append(res.DomRules[t], v)
		} else {
			res.IPRules[t] = append(res.IPRules[t], v)
		}
	}

	// 网段剔除会把父网段"裂开"成补集碎片（删除被父网段吸收的子网段）。
	// 这里刻意**不做收敛**：碎片分解方式是有意保持的现状，任何收敛方案都会改变分解结果
	// （详见 IPv4Trie.Remove 的说明）。
	b.ipv4.Walk(0, 0, &res.IPRules)
	b.ipv6.Walk([16]byte{}, 0, &res.IPRules)

	// 白名单去重（仅后缀维度）
	whiteSuffixTrie := NewSuffixTrie()
	for s := range whiteSuffixes {
		whiteSuffixTrie.Insert(s)
	}
	for d := range whiteDomains {
		if !whiteSuffixTrie.MatchAnySuffix(d) {
			res.WhiteDomRules["DOMAIN"] = append(res.WhiteDomRules["DOMAIN"], d)
		}
	}
	for s := range whiteSuffixes {
		if !whiteSuffixTrie.MatchParentSuffix(s) {
			res.WhiteDomRules["DOMAIN-SUFFIX"] = append(res.WhiteDomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range whiteRegexes {
		res.WhiteDomRules["DOMAIN-REGEX"] = append(res.WhiteDomRules["DOMAIN-REGEX"], r)
	}

	sortAndCount(res)

	fmt.Printf("⚙️ 已处理规则集: %-15s | 最终规则数: %d\n", cat.Name, res.FinalCount)
	return res
}

// domainSideTypes / ipSideTypes 是"其它类型"（不参与跨类型查杀、直接透传）的归属清单。
//
// 唯一来源：ProcessCategory 的分组、sortAndCount 的计数、以及 exporter.go 的导出遍历都读这两张表，
// 避免"报表数字"与"产物内容"因各写一份字面量列表而悄悄不一致。
var (
	domainSideTypes = [...]string{"URL-REGEX", "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT"}
	ipSideTypes     = [...]string{"DST-PORT", "IP-ASN"}
)

// isDomainSideType 判断"其它类型"中哪些归入域名侧输出。
func isDomainSideType(t string) bool {
	return slices.Contains(domainSideTypes[:], t)
}

// sortAndCount 对最终结果排序并统计 FinalCount / WhiteCount。
func sortAndCount(res *ProcessedResult) {
	// 域名侧 9 类：5 个跨类型查杀类 + 4 个透传类（字符串序排序）。
	for _, k := range domainRuleTypes {
		if v, ok := res.DomRules[k]; ok {
			sort.Strings(v)
			res.FinalCount += len(v)
		}
	}
	for _, k := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX"} {
		if v, ok := res.WhiteDomRules[k]; ok {
			sort.Strings(v)
			res.WhiteCount += len(v)
		}
	}
	// IP-CIDR6 归一化排序：普通地址在前，::ffff: 映射地址在后
	if v, ok := res.IPRules["IP-CIDR6"]; ok {
		var norm, ffff []string
		for _, ip := range v {
			if strings.HasPrefix(strings.ToLower(ip), "::ffff:") {
				ffff = append(ffff, ip)
			} else {
				norm = append(norm, ip)
			}
		}
		res.IPRules["IP-CIDR6"] = append(norm, ffff...)
	}
	for _, k := range []string{"IP-CIDR", "IP-CIDR6"} {
		if v, ok := res.IPRules[k]; ok {
			res.FinalCount += len(v)
		}
	}
	for _, k := range ipSideTypes {
		if v, ok := res.IPRules[k]; ok {
			sort.Strings(v)
			res.FinalCount += len(v)
		}
	}
}

// domainRuleTypes 是"域名侧 9 类"的固定清单与顺序（跨类型查杀 5 类 + 透传 4 类）。
// FinalCount 与导出遍历都依赖它，因此必须是唯一来源。
var domainRuleTypes = append(append([]string{}, killableTypes[:]...), domainSideTypes[:]...)

// IPv4Trie 以二进制前缀树聚合 IPv4 网段，实现"父网段覆盖子网段"去重。
type IPv4Trie struct {
	isLeaf bool
	child  [2]*IPv4Trie
}

func (t *IPv4Trie) Insert(ip uint32, length, depth int) {
	if t.isLeaf {
		return
	}
	if depth == length {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
		return
	}
	bit := (ip >> (31 - depth)) & 1
	if t.child[bit] == nil {
		t.child[bit] = &IPv4Trie{}
	}
	t.child[bit].Insert(ip, length, depth+1)
	if t.child[0] != nil && t.child[0].isLeaf && t.child[1] != nil && t.child[1].isLeaf {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
	}
}

// Remove 从树中剔除一个网段。
//
// 本函数刻意保留"删除即裂开"的分解方式，不做碎片收敛：删除会在被删网段处把父网段
// 裂成补集碎片（/8 删 /16 输出 8 条），这是"覆盖集合不变、仅分解方式变粗"的**规模**问题，
// 不是正确性问题。已评估过的三种收敛方案都会被否决：
//   - 单纯"双子皆叶 → 折叠"：对 Remove 产生的树不生效（碎片不收敛）；
//   - "nil 子节点也视为空 → 折叠"：会把稀疏路径误判为已覆盖（10.0.0.0/8 → 0.0.0.0/0，严重错误）；
//   - "死节点标记 + 折叠"：无法与"该半从未被覆盖"区分，同样会错误放大覆盖范围。
//
// 三种方案都会改变**去重结果**，因此维持现状。
func (t *IPv4Trie) Remove(ip uint32, length, depth int) {
	if t == nil {
		return
	}
	if depth == length {
		t.isLeaf = false
		t.child[0], t.child[1] = nil, nil
		return
	}
	if t.isLeaf {
		t.isLeaf = false
		t.child[0], t.child[1] = &IPv4Trie{isLeaf: true}, &IPv4Trie{isLeaf: true}
	}
	bit := (ip >> (31 - depth)) & 1
	if t.child[bit] != nil {
		t.child[bit].Remove(ip, length, depth+1)
	}
}

func (t *IPv4Trie) Walk(val uint32, depth int, out *map[string][]string) {
	if t == nil {
		return
	}
	if t.isLeaf {
		addr := netip.AddrFrom4([4]byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)})
		(*out)["IP-CIDR"] = append((*out)["IP-CIDR"], netip.PrefixFrom(addr, depth).String())
		return
	}
	if t.child[0] != nil {
		t.child[0].Walk(val, depth+1, out)
	}
	if t.child[1] != nil {
		t.child[1].Walk(val|(1<<(31-depth)), depth+1, out)
	}
}

// IPv6Trie 与 IPv4Trie 同理，针对 128 位地址。
type IPv6Trie struct {
	isLeaf bool
	child  [2]*IPv6Trie
}

func (t *IPv6Trie) Insert(ip [16]byte, length, depth int) {
	if t.isLeaf {
		return
	}
	if depth == length {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
		return
	}
	bit := (ip[depth/8] >> (7 - (depth % 8))) & 1
	if t.child[bit] == nil {
		t.child[bit] = &IPv6Trie{}
	}
	t.child[bit].Insert(ip, length, depth+1)
	if t.child[0] != nil && t.child[0].isLeaf && t.child[1] != nil && t.child[1].isLeaf {
		t.isLeaf = true
		t.child[0], t.child[1] = nil, nil
	}
}

// Remove 与 IPv4Trie.Remove 同构（同样不做碎片收敛，理由见 IPv4Trie.Remove 的说明）。
func (t *IPv6Trie) Remove(ip [16]byte, length, depth int) {
	if t == nil {
		return
	}
	if depth == length {
		t.isLeaf = false
		t.child[0], t.child[1] = nil, nil
		return
	}
	if t.isLeaf {
		t.isLeaf = false
		t.child[0], t.child[1] = &IPv6Trie{isLeaf: true}, &IPv6Trie{isLeaf: true}
	}
	bit := (ip[depth/8] >> (7 - (depth % 8))) & 1
	if t.child[bit] != nil {
		t.child[bit].Remove(ip, length, depth+1)
	}
}

func (t *IPv6Trie) Walk(val [16]byte, depth int, out *map[string][]string) {
	if t == nil {
		return
	}
	if t.isLeaf {
		(*out)["IP-CIDR6"] = append((*out)["IP-CIDR6"], netip.PrefixFrom(netip.AddrFrom16(val), depth).String())
		return
	}
	if t.child[0] != nil {
		t.child[0].Walk(val, depth+1, out)
	}
	if t.child[1] != nil {
		newVal := val
		newVal[depth/8] |= (1 << (7 - (depth % 8)))
		t.child[1].Walk(newVal, depth+1, out)
	}
}

// ipv4ToUint32 把 IPv4 地址转成 32 位整数。
//
// 注意：addr.As4() 在非 IPv4 地址上会 panic。调用方（insertIP/removeIP）都先判过
// Is4()，但该前置条件分散在调用点，因此这里再兜一层显式断言，避免未来新增调用点
// 时把 panic 带进主流程（非法输入只应"不产生规则"，不应崩溃整个构建）。
func ipv4ToUint32(addr netip.Addr) uint32 {
	if !addr.Is4() {
		return 0
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func insertIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	p, ok := parsePrefixLenient(val)
	if !ok {
		return
	}
	if p.Addr().Is4() {
		t4.Insert(ipv4ToUint32(p.Addr()), p.Bits(), 0)
	} else {
		t6.Insert(p.Addr().As16(), p.Bits(), 0)
	}
}

func removeIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	p, ok := parsePrefixLenient(val)
	if !ok {
		return
	}
	if p.Addr().Is4() {
		t4.Remove(ipv4ToUint32(p.Addr()), p.Bits(), 0)
	} else {
		t6.Remove(p.Addr().As16(), p.Bits(), 0)
	}
}

// parsePrefixLenient 解析 "值,附加参数" 形态的 CIDR（只取逗号前的主值）。
// 非法输入返回 ok=false —— 调用方据此"不产生规则"，而不是把空值喂给 trie。
func parsePrefixLenient(val string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(firstField(val))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// firstField 取 "值,附加参数" 中的主值部分。
func firstField(s string) string {
	if idx := strings.IndexByte(s, ','); idx != -1 {
		return s[:idx]
	}
	return s
}

// SuffixTrie 用于域名后缀的 O(标签数) 匹配与"父后缀覆盖子后缀"去重。
type SuffixTrie struct {
	isEnd    bool
	children map[string]*SuffixTrie
}

func NewSuffixTrie() *SuffixTrie { return &SuffixTrie{children: make(map[string]*SuffixTrie)} }

func (t *SuffixTrie) Insert(suffix string) {
	if suffix == "" {
		return
	}
	curr := t
	for {
		idx := strings.LastIndexByte(suffix, '.')
		var part string
		if idx == -1 {
			part = suffix
		} else {
			part = suffix[idx+1:]
		}
		if curr.children[part] == nil {
			curr.children[part] = NewSuffixTrie()
		}
		curr = curr.children[part]
		if idx == -1 {
			break
		}
		suffix = suffix[:idx]
	}
	curr.isEnd = true
}

// MatchAnySuffix 判断 domain 自身或任一父后缀是否已登记（用于 DOMAIN 被 SUFFIX 覆盖）。
func (t *SuffixTrie) MatchAnySuffix(domain string) bool {
	if domain == "" {
		return false
	}
	curr := t
	for {
		idx := strings.LastIndexByte(domain, '.')
		var part string
		if idx == -1 {
			part = domain
		} else {
			part = domain[idx+1:]
		}
		if curr = curr.children[part]; curr == nil {
			return false
		}
		if curr.isEnd {
			return true
		}
		if idx == -1 {
			break
		}
		domain = domain[:idx]
	}
	return false
}

// MatchParentSuffix 判断 suffix 是否存在"更短的父后缀"已登记（不含自身）。
func (t *SuffixTrie) MatchParentSuffix(suffix string) bool {
	if suffix == "" {
		return false
	}
	curr := t
	for {
		idx := strings.LastIndexByte(suffix, '.')
		var part string
		if idx == -1 {
			part = suffix
		} else {
			part = suffix[idx+1:]
		}
		if curr = curr.children[part]; curr == nil {
			return false
		}
		if curr.isEnd && idx != -1 {
			return true
		}
		if idx == -1 {
			break
		}
		suffix = suffix[:idx]
	}
	return false
}
