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

func getCachedRegex(pattern string) *regexp.Regexp {
	if v, ok := globalRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	c, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	actual, _ := globalRegexCache.LoadOrStore(pattern, c)
	return actual.(*regexp.Regexp)
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
type RuleMatcher struct {
	keywords []string
	regexes  []*regexp.Regexp
	trie     *SuffixTrie
	ac       *ahoCorasick // 关键词多模式自动机（无关键词时为 nil）
}

// NewRuleMatcher 由 rm* 集合构建匹配器。
// 空关键词/空正则在语义上会匹配一切，属于非法输入，这里直接跳过以保证健壮性。
func NewRuleMatcher(rmKeywords map[string]bool, rmRegexes map[string]*regexp.Regexp, trie *SuffixTrie) *RuleMatcher {
	m := &RuleMatcher{
		trie:     trie,
		keywords: make([]string, 0, len(rmKeywords)),
		regexes:  make([]*regexp.Regexp, 0, len(rmRegexes)),
	}
	// 按字典序迭代，保证关键词顺序确定（匹配结果为布尔值，顺序本不影响结果，但确定性更利于调试与可复现）。
	for _, kw := range slices.Sorted(maps.Keys(rmKeywords)) {
		if kw == "" {
			continue
		}
		m.keywords = append(m.keywords, kw)
	}
	for pattern, re := range rmRegexes {
		if pattern == "" || re == nil {
			continue
		}
		m.regexes = append(m.regexes, re)
	}
	if len(m.keywords) > 0 {
		m.ac = newAhoCorasick(m.keywords)
	}
	return m
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
		for _, re := range m.regexes {
			if re.MatchString(checkVal) {
				return true
			}
		}
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
// processLine 与 loadEgernUpstream 共用，消除原先重复的 switch 逻辑。
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
	rmSuffixes, rmKeywords, rmRegexes, rmWildcards := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
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

	// 收集原始 adblock/dnsmasq/smartdns 行（去重，用于最终原样输出）。
	collectRaw := func(cleanLine, parserType string) {
		switch parserType {
		case "adblock":
			if !seenRawRules["a_"+cleanLine] {
				seenRawRules["a_"+cleanLine] = true
				res.RawAdblockRules = append(res.RawAdblockRules, cleanLine)
			}
		case "dnsmasq":
			if !seenRawRules["d_"+cleanLine] {
				seenRawRules["d_"+cleanLine] = true
				res.RawDnsmasqRules = append(res.RawDnsmasqRules, cleanLine)
			}
		case "smartdns":
			if !seenRawRules["s_"+cleanLine] {
				seenRawRules["s_"+cleanLine] = true
				res.RawSmartDNSRules = append(res.RawSmartDNSRules, cleanLine)
			}
		}
	}

	processLine := func(line string, parserType string, isAdd bool, isRm bool, upURL string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || hasAnyPrefix(cleanLine, "#", "!", "//", "[") {
			return
		}

		if strings.HasPrefix(cleanLine, "@@") {
			if (cat.AutoExtractWhite && !isRm) || isAdd {
				switch parserType {
				case "adblock":
					if !seenRawRules["wa_"+cleanLine] {
						seenRawRules["wa_"+cleanLine] = true
						res.RawWhiteAdblockRules = append(res.RawWhiteAdblockRules, cleanLine)
					}
				case "dnsmasq":
					if !seenRawRules["wd_"+cleanLine] {
						seenRawRules["wd_"+cleanLine] = true
						res.RawWhiteDnsmasqRules = append(res.RawWhiteDnsmasqRules, cleanLine)
					}
				case "smartdns":
					if !seenRawRules["ws_"+cleanLine] {
						seenRawRules["ws_"+cleanLine] = true
						res.RawWhiteSmartDNSRules = append(res.RawWhiteSmartDNSRules, cleanLine)
					}
				}

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
								rmSuffixes[w.Value] = true
							case "DOMAIN-REGEX":
								rmRegexes[w.Value] = true
							}
						}
					}
				}
			}
			return
		}

		if !isAdd && !isRm {
			collectRaw(cleanLine, parserType)
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
				switch r.Type {
				case "DOMAIN-SUFFIX":
					rmSuffixes[r.Value] = true
				case "DOMAIN-KEYWORD":
					rmKeywords[r.Value] = true
				case "DOMAIN-REGEX":
					rmRegexes[r.Value] = true
				case "DOMAIN-WILDCARD":
					rmWildcards[r.Value] = true
				case "IP-CIDR", "IP-CIDR6":
					removeIP(r.Value, b.ipv4, b.ipv6)
				}
			}
			return
		}

		if isAdd {
			res.AddCount++
			if isExactAdd {
				addExact[*r] = true
			} else {
				// 非精准补充：登记到 rm* 集合，使其对上游规则产生跨类型去重
				switch r.Type {
				case "DOMAIN-SUFFIX":
					rmSuffixes[r.Value] = true
				case "DOMAIN-KEYWORD":
					rmKeywords[r.Value] = true
				case "DOMAIN-REGEX":
					rmRegexes[r.Value] = true
				case "DOMAIN-WILDCARD":
					rmWildcards[r.Value] = true
				}
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
	compiledRmRegexesMap := make(map[string]*regexp.Regexp)
	for reg := range rmRegexes {
		if reg == "" {
			continue
		}
		if c := getCachedRegex(reg); c != nil {
			compiledRmRegexesMap[reg] = c
		}
	}
	for w := range rmWildcards {
		if w == "" {
			continue
		}
		regStr := "^" + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(w, ".", `\.`), "*", `.*`), "?", `.`) + "$"
		if c := getCachedRegex(regStr); c != nil {
			compiledRmRegexesMap[w] = c
		}
	}

	// 后缀字典树：装入剔除后缀 + 普通后缀（用于跨类型去重）
	suffixTrie := NewSuffixTrie()
	for s := range rmSuffixes {
		suffixTrie.Insert(s)
	}
	for s := range b.suffixes {
		if !rmExact[Rule{Type: "DOMAIN-SUFFIX", Value: s}] && !addExact[Rule{Type: "DOMAIN-SUFFIX", Value: s}] {
			suffixTrie.Insert(s)
		}
	}

	matcher := NewRuleMatcher(rmKeywords, compiledRmRegexesMap, suffixTrie)

	for d := range b.domains {
		if rmExact[Rule{Type: "DOMAIN", Value: d}] {
			continue
		}
		if !matcher.IsCrossKilled(d, "DOMAIN") {
			res.DomRules["DOMAIN"] = append(res.DomRules["DOMAIN"], d)
		}
	}
	for s := range b.suffixes {
		if rmExact[Rule{Type: "DOMAIN-SUFFIX", Value: s}] {
			continue
		}
		if !matcher.IsCrossKilled(s, "DOMAIN-SUFFIX") {
			res.DomRules["DOMAIN-SUFFIX"] = append(res.DomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range b.regexes {
		if rmExact[Rule{Type: "DOMAIN-REGEX", Value: r}] {
			continue
		}
		if !matcher.IsCrossKilled(r, "DOMAIN-REGEX") {
			res.DomRules["DOMAIN-REGEX"] = append(res.DomRules["DOMAIN-REGEX"], r)
		}
	}
	for k := range b.keywords {
		if rmExact[Rule{Type: "DOMAIN-KEYWORD", Value: k}] {
			continue
		}
		if !matcher.IsCrossKilled(k, "DOMAIN-KEYWORD") {
			res.DomRules["DOMAIN-KEYWORD"] = append(res.DomRules["DOMAIN-KEYWORD"], k)
		}
	}
	for w := range b.wildcards {
		if rmExact[Rule{Type: "DOMAIN-WILDCARD", Value: w}] {
			continue
		}
		if !matcher.IsCrossKilled(w, "DOMAIN-WILDCARD") {
			res.DomRules["DOMAIN-WILDCARD"] = append(res.DomRules["DOMAIN-WILDCARD"], w)
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

// isDomainSideType 判断"其它类型"中哪些归入域名侧输出。
func isDomainSideType(t string) bool {
	switch t {
	case "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT", "URL-REGEX":
		return true
	default:
		return false
	}
}

// sortAndCount 对最终结果排序并统计 FinalCount / WhiteCount。
func sortAndCount(res *ProcessedResult) {
	for _, k := range []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "DOMAIN-WILDCARD", "URL-REGEX", "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT"} {
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
	for _, k := range []string{"DST-PORT", "IP-ASN"} {
		if v, ok := res.IPRules[k]; ok {
			sort.Strings(v)
			res.FinalCount += len(v)
		}
	}
}

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

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func insertIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(firstField(val)); err == nil {
		if p.Addr().Is4() {
			t4.Insert(ipv4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Insert(p.Addr().As16(), p.Bits(), 0)
		}
	}
}

func removeIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(firstField(val)); err == nil {
		if p.Addr().Is4() {
			t4.Remove(ipv4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Remove(p.Addr().As16(), p.Bits(), 0)
		}
	}
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
