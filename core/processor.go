package core

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	globalRegexCache sync.Map
)

func getCachedRegex(pattern string) *regexp.Regexp {
	if v, ok := globalRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	if c, err := regexp.Compile(pattern); err == nil {
		actual, _ := globalRegexCache.LoadOrStore(pattern, c)
		return actual.(*regexp.Regexp)
	}
	return nil
}

type ProcessedResult struct {
	DomRules              map[string][]string
	IPRules               map[string][]string
	WhiteDomRules         map[string][]string
	RawCount              int
	AddCount              int
	RmCount               int
	FinalCount            int
	WhiteCount            int
	ExactCounts           map[string]int
	UpstreamStats         map[string]int
	WhiteUpstreamStats    map[string]int
	RawAdblockRules       []string
	RawDnsmasqRules       []string
	RawSmartDNSRules      []string
	RawWhiteAdblockRules  []string
	RawWhiteDnsmasqRules  []string
	RawWhiteSmartDNSRules []string
}

type RuleMatcher struct {
	keywords []string
	regexes  []*regexp.Regexp
	trie     *SuffixTrie
}

func NewRuleMatcher(rmKeywords map[string]bool, rmRegexes map[string]*regexp.Regexp, trie *SuffixTrie) *RuleMatcher {
	matcher := &RuleMatcher{
		trie:     trie,
		keywords: make([]string, 0, len(rmKeywords)),
		regexes:  make([]*regexp.Regexp, 0, len(rmRegexes)),
	}
	for kw := range rmKeywords {
		matcher.keywords = append(matcher.keywords, kw)
	}
	for _, re := range rmRegexes {
		matcher.regexes = append(matcher.regexes, re)
	}
	return matcher
}

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

func (m *RuleMatcher) IsCrossKilled(val string, ruleType string) bool {
	checkVal := val
	if ruleType == "DOMAIN-REGEX" || ruleType == "DOMAIN-WILDCARD" {
		checkVal = m.cleanPatternForMatch(val)
	}
	for _, kw := range m.keywords {
		if ruleType == "DOMAIN-KEYWORD" && val == kw {
			continue
		}
		if strings.Contains(checkVal, kw) {
			return true
		}
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

func ProcessCategory(cat Category, cfg *Config) *ProcessedResult {
	domains, suffixes, keywords, regexes, wildcards := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	others := make(map[Rule]bool)

	rmExact := make(map[Rule]bool)
	addExact := make(map[Rule]bool)
	rmDomains, rmSuffixes, rmKeywords, rmRegexes, rmWildcards := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	whiteDomains, whiteSuffixes, whiteRegexes := make(map[string]bool), make(map[string]bool), make(map[string]bool)

	ipv4Trie, ipv6Trie := &IPv4Trie{}, &IPv6Trie{}
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

	processLine := func(line string, parserType string, isAdd bool, isRm bool, upURL string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || strings.HasPrefix(cleanLine, "#") || strings.HasPrefix(cleanLine, "!") || strings.HasPrefix(cleanLine, "//") || strings.HasPrefix(cleanLine, "[") {
			return
		}

		if strings.HasPrefix(cleanLine, "@@") {
			if (cat.AutoExtractWhite && !isRm) || isAdd {
				if parserType == "adblock" && !seenRawRules["wa_"+cleanLine] {
					seenRawRules["wa_"+cleanLine] = true
					res.RawWhiteAdblockRules = append(res.RawWhiteAdblockRules, cleanLine)
				} else if parserType == "dnsmasq" && !seenRawRules["wd_"+cleanLine] {
					seenRawRules["wd_"+cleanLine] = true
					res.RawWhiteDnsmasqRules = append(res.RawWhiteDnsmasqRules, cleanLine)
				} else if parserType == "smartdns" && !seenRawRules["ws_"+cleanLine] {
					seenRawRules["ws_"+cleanLine] = true
					res.RawWhiteSmartDNSRules = append(res.RawWhiteSmartDNSRules, cleanLine)
				}

				if w := ParseWhite(cleanLine); w != nil {
					if w.Type == "DOMAIN" {
						whiteDomains[w.Value] = true
					}
					if w.Type == "DOMAIN-SUFFIX" {
						whiteSuffixes[w.Value] = true
					}
					if w.Type == "DOMAIN-REGEX" {
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
							if w.Type == "DOMAIN" {
								rmDomains[w.Value] = true
							}
							if w.Type == "DOMAIN-SUFFIX" {
								rmSuffixes[w.Value] = true
							}
							if w.Type == "DOMAIN-REGEX" {
								rmRegexes[w.Value] = true
							}
						}
					}
				}
			}
			return
		}

		if !isAdd && !isRm {
			if parserType == "adblock" && !seenRawRules["a_"+cleanLine] {
				seenRawRules["a_"+cleanLine] = true
				res.RawAdblockRules = append(res.RawAdblockRules, cleanLine)
			} else if parserType == "dnsmasq" && !seenRawRules["d_"+cleanLine] {
				seenRawRules["d_"+cleanLine] = true
				res.RawDnsmasqRules = append(res.RawDnsmasqRules, cleanLine)
			} else if parserType == "smartdns" && !seenRawRules["s_"+cleanLine] {
				seenRawRules["s_"+cleanLine] = true
				res.RawSmartDNSRules = append(res.RawSmartDNSRules, cleanLine)
			}
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
				if r.Type == "DOMAIN" {
					rmDomains[r.Value] = true
				}
				if r.Type == "DOMAIN-SUFFIX" {
					rmSuffixes[r.Value] = true
				}
				if r.Type == "DOMAIN-KEYWORD" {
					rmKeywords[r.Value] = true
				}
				if r.Type == "DOMAIN-REGEX" {
					rmRegexes[r.Value] = true
				}
				if r.Type == "DOMAIN-WILDCARD" {
					rmWildcards[r.Value] = true
				}
				if r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" {
					removeIP(r.Value, ipv4Trie, ipv6Trie)
				}
			}
			return
		}

		if isAdd {
			res.AddCount++
			if !isExactAdd {
				if r.Type == "DOMAIN" {
					rmDomains[r.Value] = true
				}
				if r.Type == "DOMAIN-SUFFIX" {
					rmSuffixes[r.Value] = true
				}
				if r.Type == "DOMAIN-KEYWORD" {
					rmKeywords[r.Value] = true
				}
				if r.Type == "DOMAIN-REGEX" {
					rmRegexes[r.Value] = true
				}
				if r.Type == "DOMAIN-WILDCARD" {
					rmWildcards[r.Value] = true
				}
			} else {
				addExact[*r] = true
			}
		} else {
			res.RawCount++
		}

		switch r.Type {
		case "DOMAIN":
			domains[r.Value] = true
		case "DOMAIN-SUFFIX":
			suffixes[r.Value] = true
		case "DOMAIN-KEYWORD":
			keywords[r.Value] = true
		case "DOMAIN-REGEX":
			regexes[r.Value] = true
		case "DOMAIN-WILDCARD":
			wildcards[r.Value] = true
		case "IP-CIDR", "IP-CIDR6":
			insertIP(r.Value, ipv4Trie, ipv6Trie)
		default:
			others[*r] = true
		}
	}

	loadEgernUpstream := func(f *os.File, upURL string) {
		scanner := bufio.NewScanner(f)
		linesBefore := res.RawCount
		currentEgernSection := ""

		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ":") {
				currentEgernSection = strings.TrimSuffix(trimmed, ":")
				continue
			}

			cleanLine := strings.TrimSpace(line)
			if cleanLine == "" || strings.HasPrefix(cleanLine, "#") || strings.HasPrefix(cleanLine, "!") || strings.HasPrefix(cleanLine, "//") {
				continue
			}

			if r := ParseEgern(line, currentEgernSection); r != nil {
				res.RawCount++
				switch r.Type {
				case "DOMAIN":
					domains[r.Value] = true
				case "DOMAIN-SUFFIX":
					suffixes[r.Value] = true
				case "DOMAIN-KEYWORD":
					keywords[r.Value] = true
				case "DOMAIN-REGEX":
					regexes[r.Value] = true
				case "IP-CIDR", "IP-CIDR6":
					insertIP(r.Value, ipv4Trie, ipv6Trie)
				default:
					others[*r] = true
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("⚠️ 读取 Egern 上游时出错: %v\n", err)
		}
		if upURL != "" {
			res.UpstreamStats[upURL] += res.RawCount - linesBefore
		}
	}

	loadUpstreams := func(targetCat Category) {
		for i, up := range targetCat.Upstreams {
			filePath := fmt.Sprintf("%s/%s_%d.txt", "temp/raw", targetCat.Name, i+1)
			if f, err := os.Open(filePath); err == nil {
				parserType := up.Parser
				if parserType == "" {
					parserType = InferParser(filePath)
				}

				if parserType == "egern" {
					loadEgernUpstream(f, up.URL)
				} else {
					scanner := bufio.NewScanner(f)
					linesBefore := res.RawCount
					for scanner.Scan() {
						processLine(scanner.Text(), parserType, false, false, up.URL)
					}
					if err := scanner.Err(); err != nil {
						fmt.Printf("⚠️ 读取上游文件 [%s] 时出错: %v\n", up.URL, err)
					}
					res.UpstreamStats[up.URL] += res.RawCount - linesBefore
				}
				f.Close()
			}
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

	validLocalParsers := map[string]bool{
		"clash": true, "v2ray": true, "adblock": true, "hosts": true,
		"dnsmasq": true, "smartdns": true, "surge": true, "shadowrocket": true,
		"quantumultx": true, "loon": true, "stash": true, "white": true,
	}

	processLocalLine := func(line string, isAdd bool, isRm bool, source string) {
		cleanLine := strings.TrimSpace(line)
		if cleanLine == "" || strings.HasPrefix(cleanLine, "#") || strings.HasPrefix(cleanLine, "//") {
			return
		}

		parserType := "clash"
		if eqIdx := strings.Index(cleanLine, "="); eqIdx != -1 {
			prefix := strings.ToLower(strings.TrimSpace(cleanLine[:eqIdx]))
			if validLocalParsers[prefix] {
				parserType = prefix
				cleanLine = strings.TrimSpace(cleanLine[eqIdx+1:])
			}
		}
		processLine(cleanLine, parserType, isAdd, isRm, source)
	}

	if f, err := os.Open(fmt.Sprintf("add/%s.list", cat.Name)); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processLocalLine(scanner.Text(), true, false, "Local Add")
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("⚠️ 读取 add/%s.list 时出错: %v\n", cat.Name, err)
		}
		f.Close()
	}

	if f, err := os.Open(fmt.Sprintf("remove/%s.list", cat.Name)); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processLocalLine(scanner.Text(), false, true, "Local Remove")
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("⚠️ 读取 remove/%s.list 时出错: %v\n", cat.Name, err)
		}
		f.Close()
	}

	for i, rmUp := range cat.RemoveURLs {
		filePath := fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cat.Name, i+1)
		if f, err := os.Open(filePath); err == nil {
			scanner := bufio.NewScanner(f)
			parserType := rmUp.Parser
			if parserType == "" {
				parserType = InferParser(filePath)
			}
			for scanner.Scan() {
				processLine(scanner.Text(), parserType, false, true, "Remote Remove")
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("⚠️ 读取远程剔除文件时出错: %v\n", err)
			}
			f.Close()
		}
	}

	compiledRmRegexesMap := make(map[string]*regexp.Regexp)
	for reg := range rmRegexes {
		if c := getCachedRegex(reg); c != nil {
			compiledRmRegexesMap[reg] = c
		}
	}
	for w := range rmWildcards {
		regStr := "^" + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(w, ".", `\.`), "*", `.*`), "?", `.`) + "$"
		if c := getCachedRegex(regStr); c != nil {
			compiledRmRegexesMap[w] = c
		}
	}

	suffixTrie := NewSuffixTrie()
	for s := range rmSuffixes {
		suffixTrie.Insert(s)
	}
	for s := range suffixes {
		if !rmExact[Rule{"DOMAIN-SUFFIX", s}] && !addExact[Rule{"DOMAIN-SUFFIX", s}] {
			suffixTrie.Insert(s)
		}
	}

	matcher := NewRuleMatcher(rmKeywords, compiledRmRegexesMap, suffixTrie)

	for d := range domains {
		if rmExact[Rule{"DOMAIN", d}] {
			continue
		}
		if !matcher.IsCrossKilled(d, "DOMAIN") {
			res.DomRules["DOMAIN"] = append(res.DomRules["DOMAIN"], d)
		}
	}
	for s := range suffixes {
		if rmExact[Rule{"DOMAIN-SUFFIX", s}] {
			continue
		}
		if !matcher.IsCrossKilled(s, "DOMAIN-SUFFIX") {
			res.DomRules["DOMAIN-SUFFIX"] = append(res.DomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range regexes {
		if rmExact[Rule{"DOMAIN-REGEX", r}] {
			continue
		}
		if !matcher.IsCrossKilled(r, "DOMAIN-REGEX") {
			res.DomRules["DOMAIN-REGEX"] = append(res.DomRules["DOMAIN-REGEX"], r)
		}
	}
	for k := range keywords {
		if rmExact[Rule{"DOMAIN-KEYWORD", k}] {
			continue
		}
		if !matcher.IsCrossKilled(k, "DOMAIN-KEYWORD") {
			res.DomRules["DOMAIN-KEYWORD"] = append(res.DomRules["DOMAIN-KEYWORD"], k)
		}
	}
	for w := range wildcards {
		if rmExact[Rule{"DOMAIN-WILDCARD", w}] {
			continue
		}
		if !matcher.IsCrossKilled(w, "DOMAIN-WILDCARD") {
			res.DomRules["DOMAIN-WILDCARD"] = append(res.DomRules["DOMAIN-WILDCARD"], w)
		}
	}
	for o := range others {
		if rmExact[o] {
			continue
		}
		t, v := o.Type, o.Value
		if t == "PROCESS-NAME" || t == "PROCESS-PATH" || t == "USER-AGENT" || t == "URL-REGEX" {
			res.DomRules[t] = append(res.DomRules[t], v)
		} else {
			res.IPRules[t] = append(res.IPRules[t], v)
		}
	}

	ipv4Trie.Walk(0, 0, &res.IPRules)
	ipv6Trie.Walk([16]byte{}, 0, &res.IPRules)

	whiteSuffixTrie := NewSuffixTrie()
	for s := range whiteSuffixes {
		whiteSuffixTrie.Insert(s)
	}

	isWhiteDomKilled := func(d string) bool { return whiteSuffixTrie.MatchAnySuffix(d) }
	isWhiteSufKilled := func(s string) bool { return whiteSuffixTrie.MatchParentSuffix(s) }

	for d := range whiteDomains {
		if !isWhiteDomKilled(d) {
			res.WhiteDomRules["DOMAIN"] = append(res.WhiteDomRules["DOMAIN"], d)
		}
	}
	for s := range whiteSuffixes {
		if !isWhiteSufKilled(s) {
			res.WhiteDomRules["DOMAIN-SUFFIX"] = append(res.WhiteDomRules["DOMAIN-SUFFIX"], s)
		}
	}
	for r := range whiteRegexes {
		res.WhiteDomRules["DOMAIN-REGEX"] = append(res.WhiteDomRules["DOMAIN-REGEX"], r)
	}
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

	fmt.Printf("⚙️ 已处理规则集: %-15s | 最终规则数: %d\n", cat.Name, res.FinalCount)
	return res
}

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

func IP4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func insertIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(strings.Split(val, ",")[0]); err == nil {
		if p.Addr().Is4() {
			t4.Insert(IP4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Insert(p.Addr().As16(), p.Bits(), 0)
		}
	}
}
func removeIP(val string, t4 *IPv4Trie, t6 *IPv6Trie) {
	if p, err := netip.ParsePrefix(strings.Split(val, ",")[0]); err == nil {
		if p.Addr().Is4() {
			t4.Remove(IP4ToUint32(p.Addr()), p.Bits(), 0)
		} else {
			t6.Remove(p.Addr().As16(), p.Bits(), 0)
		}
	}
}

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
