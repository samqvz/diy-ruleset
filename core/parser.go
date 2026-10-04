package core

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Rule struct {
	Type  string
	Value string
}

// scannerBufferSize 是行扫描器的最大单行容量。
// 上游 adblock 规则常常单行很长，默认 64KB 会触发 "token too long" 并静默截断，
// 因此统一放大到 1MB。
const scannerBufferSize = 1 << 20

// newLineScanner 返回一个带足够缓冲的行扫描器，供所有上游/本地文件读取复用。
func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), scannerBufferSize)
	return sc
}

var (
	hostsRegex         = regexp.MustCompile(`^[0-9a-fA-F:\.]+\s+([a-zA-Z0-9_*-]+(?:\.[a-zA-Z0-9_*-]+)*)$`)
	dnsmasqRegex       = regexp.MustCompile(`^(?:server|local|address)=/([^/]+)/`)
	smartdnsRegex      = regexp.MustCompile(`^address\s+/(.+?)/`)
	nakedDomainRegex   = regexp.MustCompile(`^[a-zA-Z0-9_*-]+(?:\.[a-zA-Z0-9_*-]+)*$`)
	adblockDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+$`)
	inferAdblockRe     = regexp.MustCompile(`^(?:@@)?\|\|[^\^]+\^?`)
	inferHostsRe       = regexp.MustCompile(`^(?:127\.0\.0\.1|0\.0\.0\.0|::1)\s+[a-zA-Z0-9.-]+`)
	inferDnsmasqRe     = regexp.MustCompile(`^(?:server|address|local)=/[^/]+/[^/]+`)
	inferSmartdnsRe    = regexp.MustCompile(`^(?:address|nameserver)\s+/[^/]+/`)
	inferQxStrictRe    = regexp.MustCompile(`(?i)^(?:host(?:-suffix|-keyword|-wildcard)?|ip6-cidr)\s*,`)
	inferSurgeStrictRe = regexp.MustCompile(`^(?:DEST-PORT|USER-AGENT|URL-REGEX|DOMAIN-SET)\s*,`)
	inferClashStrictRe = regexp.MustCompile(`^(?:payload:|DST-PORT|PROCESS-NAME|PROCESS-PATH|DOMAIN-REGEX)\s*,?`)
	inferGenericRe     = regexp.MustCompile(`^(?:DOMAIN(?:-SUFFIX|-KEYWORD|-WILDCARD)?|IP-CIDR6?|IP-ASN)\s*,`)
	inferV2rayRe       = regexp.MustCompile(`^(?:domain|full|keyword|regexp|regex|ext|include):`)
	inferEgernRe       = regexp.MustCompile(`^(?:domain_set|domain_suffix_set|domain_keyword_set|domain_regex_set|domain_wildcard_set|ip_cidr_set|ip_cidr6_set|asn_set|user_agent_set|url_regex_set|dest_port_set):`)
	inferIPRe          = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$|^(?:[0-9a-fA-F:]+:+)+[0-9a-fA-F]+(?:/\d{1,3})?$`)

	// clashTypeSuffixRe 用于剥离 DOMAIN-REGEX 末尾的规则集策略后缀（如 ",no-resolve"）。
	clashTypeSuffixRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// validClashTypes 是 parseTypedRule 允许的 "TYPE,VALUE" 类型白名单。
var validClashTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"DOMAIN-WILDCARD": true, "URL-REGEX": true, "IP-CIDR": true, "IP-CIDR6": true,
	"DST-PORT": true, "PROCESS-NAME": true, "PROCESS-PATH": true, "USER-AGENT": true, "IP-ASN": true,
}

// parseRegistry 把 "解析器名 -> 解析函数" 做成注册表。
var parseRegistry = map[string]func(string) *Rule{
	"clash":        ParseClash,
	"v2ray":        ParseV2Ray,
	"adblock":      ParseAdblock,
	"hosts":        ParseHosts,
	"dnsmasq":      ParseDnsmasq,
	"smartdns":     ParseSmartDNS,
	"white":        ParseWhite,
	"egern":        func(line string) *Rule { return ParseEgern(line, "") },
	"surge":        ParseAppleClients,
	"shadowrocket": ParseAppleClients,
	"loon":         ParseAppleClients,
	"quantumultx":  ParseAppleClients,
	"stash":        ParseAppleClients,
}

// Parse 将一行文本按指定 format 解析为统一 Rule。
// 返回 nil 表示该行应被忽略（空行/注释/不支持的语法）。
func Parse(line, format string) *Rule {
	line = strings.TrimSpace(line)
	if line == "" || hasAnyPrefix(line, "#", "//", "!", ";", "[") {
		return nil
	}

	// 剥离行尾注释：依次尝试四种注释标记。
	for _, commentMark := range []string{" #", "\t#", " //", "\t//"} {
		if idx := strings.Index(line, commentMark); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
	}
	if line == "" {
		return nil
	}

	parseFn, ok := parseRegistry[format]
	if !ok {
		parseFn = ParseClash // 未知格式回退为 Clash
	}
	r := parseFn(line)

	// 域名类规则统一小写，保证跨上游去重时大小写不敏感。
	if r != nil && isDomainRuleType(r.Type) {
		r.Value = strings.ToLower(r.Value)
	}
	return r
}

// isDomainRuleType 判断类型是否需要小写归一化。
func isDomainRuleType(t string) bool {
	return t == "DOMAIN" || t == "DOMAIN-SUFFIX" || t == "DOMAIN-KEYWORD"
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// InferParser 通过前 500 行 + 后 500 行的特征打分，嗅探上游文件最可能的解析器。
func InferParser(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return "clash"
	}
	defer f.Close()

	scores := make(map[string]int)
	scoreLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || hasAnyPrefix(line, "#", "//", "!") {
			return
		}

		switch {
		case inferAdblockRe.MatchString(line):
			scores["adblock"] += 10
		case inferHostsRe.MatchString(line):
			scores["hosts"] += 10
		case inferDnsmasqRe.MatchString(line):
			scores["dnsmasq"] += 10
		case inferSmartdnsRe.MatchString(line):
			scores["smartdns"] += 10
		case inferEgernRe.MatchString(line):
			scores["egern"] += 100
		case inferV2rayRe.MatchString(line):
			scores["v2ray"] += 10
		case inferQxStrictRe.MatchString(line):
			scores["quantumultx"] += 100
		case inferSurgeStrictRe.MatchString(line):
			scores["surge"] += 100
		case inferClashStrictRe.MatchString(line) || line == "payload:" || strings.HasPrefix(line, "- "):
			scores["clash"] += 100
		case inferGenericRe.MatchString(line):
			scores["clash"]++
			scores["surge"]++
			scores["shadowrocket"]++
		case inferIPRe.MatchString(line):
			scores["clash"]++
		}
	}

	const checkLimit = 500
	sc := newLineScanner(f)

	rollingTail := make([]string, checkLimit)
	tailIdx := 0
	totalLines := 0

	for sc.Scan() {
		line := sc.Text()
		if totalLines < checkLimit {
			scoreLine(line)
		}
		rollingTail[tailIdx] = line
		tailIdx = (tailIdx + 1) % checkLimit
		totalLines++
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("⚠️ 推断文件格式时发生读取错误: %v\n", err)
	}

	tailStart := totalLines - checkLimit
	if tailStart < checkLimit {
		tailStart = checkLimit
	}
	linesToCheck := totalLines - tailStart
	for i := 0; i < linesToCheck; i++ {
		idx := (tailIdx - linesToCheck + i + checkLimit) % checkLimit
		scoreLine(rollingTail[idx])
	}

	// 固定优先级顺序遍历，保证同分时结果稳定：
	// egern 的 `*_set:` 标记最具特异性，优先于通用 `- ` 行带来的 clash 分数。
	priority := []string{"egern", "clash", "quantumultx", "surge", "shadowrocket", "loon", "stash", "v2ray", "adblock", "hosts", "dnsmasq", "smartdns"}
	bestParser := "clash"
	maxScore := 0
	for _, parser := range priority {
		if scores[parser] > maxScore {
			maxScore = scores[parser]
			bestParser = parser
		}
	}
	return bestParser
}

// ParseClash 解析 Clash classical 规则行（含 `- DOMAIN,x` 列表项与裸域名快捷写法）。
func ParseClash(line string) *Rule {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
	}
	line = strings.Trim(line, "'\"\t ")

	if line == "payload:" || line == "" {
		return nil
	}
	if r := parseTypedRule(line); r != nil {
		return r
	}
	if r := parseIPOrCIDR(line); r != nil {
		return r
	}
	return parseFallback(line)
}

// ParseEgern 解析 Egern 规则集的 YAML 片段；section 为当前所在的集合名。
func ParseEgern(line string, section string) *Rule {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
	} else if strings.HasPrefix(line, "-") {
		line = strings.TrimSpace(line[1:])
	}
	line = strings.Trim(line, "'\"\t ")
	if line == "" || hasAnyPrefix(line, "#", "//") {
		return nil
	}
	switch section {
	case "domain_set":
		return &Rule{Type: "DOMAIN", Value: line}
	case "domain_suffix_set":
		return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.TrimPrefix(line, ".")}
	case "domain_keyword_set":
		return &Rule{Type: "DOMAIN-KEYWORD", Value: line}
	case "domain_wildcard_set":
		return &Rule{Type: "DOMAIN-WILDCARD", Value: line}
	case "url_regex_set":
		return &Rule{Type: "URL-REGEX", Value: line}
	case "domain_regex_set":
		return &Rule{Type: "DOMAIN-REGEX", Value: line}
	case "ip_cidr_set":
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		return &Rule{Type: "IP-CIDR", Value: line}
	case "ip_cidr6_set":
		if !strings.Contains(line, "/") {
			line += "/128"
		}
		return &Rule{Type: "IP-CIDR6", Value: line}
	case "asn_set":
		return &Rule{Type: "IP-ASN", Value: line}
	case "user_agent_set":
		return &Rule{Type: "USER-AGENT", Value: strings.TrimSuffix(line, "*")}
	case "dest_port_set":
		return &Rule{Type: "DST-PORT", Value: line}
	default:
		if strings.HasPrefix(line, ".") {
			return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.TrimPrefix(line, ".")}
		}
		return parseFallback(line)
	}
}

// ParseV2Ray 解析 V2Ray geosite/geoip 语法。
// 注意：裸字符串在 V2Ray 中语义为 KEYWORD（子串匹配）。
func ParseV2Ray(line string) *Rule {
	if idx := strings.Index(line, " @"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	if strings.HasPrefix(line, "include:") || strings.HasPrefix(line, "ext:") {
		return nil
	}
	if r := parseIPOrCIDR(line); r != nil {
		return r
	}

	switch {
	case strings.HasPrefix(line, "full:"):
		return &Rule{Type: "DOMAIN", Value: strings.TrimPrefix(line, "full:")}
	case strings.HasPrefix(line, "domain:"):
		return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.TrimPrefix(line, "domain:")}
	case strings.HasPrefix(line, "keyword:"):
		return &Rule{Type: "DOMAIN-KEYWORD", Value: strings.TrimPrefix(line, "keyword:")}
	case strings.HasPrefix(line, "regexp:"):
		return &Rule{Type: "DOMAIN-REGEX", Value: strings.TrimPrefix(line, "regexp:")}
	case strings.HasPrefix(line, "regex:"):
		return &Rule{Type: "DOMAIN-REGEX", Value: strings.TrimPrefix(line, "regex:")}
	case strings.HasPrefix(line, "."):
		return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.TrimPrefix(line, ".")}
	}

	if nakedDomainRegex.MatchString(line) {
		return &Rule{Type: "DOMAIN-KEYWORD", Value: line}
	}
	return nil
}

// ParseAdblock 解析 Adblock 拦截语法（仅处理 `||domain^` 形式）。
func ParseAdblock(line string) *Rule {
	if strings.Contains(line, "$") {
		return nil
	}
	if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		val := line[2 : len(line)-1]
		if strings.ContainsAny(val, "/?=:") {
			return nil
		}
		if _, err := netip.ParseAddr(val); err == nil {
			// 注意：val 已在上面被 "/?=:" 过滤，不可能包含 ":"，故不存在 IPv6 分支。
			return &Rule{Type: "IP-CIDR", Value: val + "/32"}
		}
		if strings.Contains(val, "*") {
			return &Rule{Type: "DOMAIN-REGEX", Value: "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", ".*") + "$"}
		}
		if adblockDomainRegex.MatchString(val) {
			return &Rule{Type: "DOMAIN-SUFFIX", Value: val}
		}
	}
	return nil
}

// normalizeWildcardDomain 将 Clash 域名通配符写法归一化为 Rule。
//
// 与 mihomo 文档 handbook/syntax#domain-wildcards 保持一致：
//   - `*`   仅匹配一级（`*.baidu.com` 不匹配 `a.b.baidu.com`，也不匹配 `baidu.com`）
//   - `+.`  等价 DOMAIN-SUFFIX（匹配自身及任意层级子域）
//   - `.`   匹配多级子域但不含裸域（`.baidu.com` 不匹配 `baidu.com`）
//
// 注意：这里的 `*` 与路由规则 DOMAIN-WILDCARD 的 `*`（零或多个任意字符）语义不同。
func normalizeWildcardDomain(domain string, expectedType string) *Rule {
	if domain == "*" {
		return &Rule{Type: "DOMAIN-REGEX", Value: "^[^.]+$"}
	}
	if strings.HasPrefix(domain, "+.") {
		val := strings.TrimPrefix(domain, "+.")
		if strings.Contains(val, "*") {
			return &Rule{Type: "DOMAIN-REGEX", Value: "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", "[^.]+") + "$"}
		}
		return &Rule{Type: "DOMAIN-SUFFIX", Value: val}
	}
	if strings.HasPrefix(domain, ".") {
		val := strings.TrimPrefix(domain, ".")
		return &Rule{Type: "DOMAIN-REGEX", Value: "^.+\\." + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", "[^.]+") + "$"}
	}
	if strings.Contains(domain, "*") {
		newVal := strings.ReplaceAll(domain, ".", `\.`)
		newVal = strings.ReplaceAll(newVal, "*", `[^.]+`)
		if expectedType == "DOMAIN-SUFFIX" {
			return &Rule{Type: "DOMAIN-REGEX", Value: "^(.+\\.)?" + newVal + "$"}
		}
		return &Rule{Type: "DOMAIN-REGEX", Value: "^" + newVal + "$"}
	}
	return nil
}

// parseTypedRule 解析标准 "TYPE,VALUE" 语法（Clash / Apple 系列共用）。
// 返回 nil 表示类型不在白名单内。
func parseTypedRule(line string) *Rule {
	idx := strings.Index(line, ",")
	if idx == -1 {
		return nil
	}
	t := strings.ToUpper(strings.TrimSpace(line[:idx]))
	v := strings.TrimSpace(line[idx+1:])
	v = strings.Trim(v, "'\"\t ")

	cleanV := strings.TrimSpace(strings.Split(v, ",")[0])

	switch t {
	case "HOST":
		t = "DOMAIN"
	case "HOST-SUFFIX":
		t = "DOMAIN-SUFFIX"
	case "HOST-KEYWORD":
		t = "DOMAIN-KEYWORD"
	case "HOST-WILDCARD":
		t = "DOMAIN-WILDCARD"
	case "DEST-PORT", "PORT":
		t = "DST-PORT"
	case "IP4-CIDR":
		t = "IP-CIDR"
	case "IP6-CIDR":
		t = "IP-CIDR6"
	}

	if !validClashTypes[t] {
		return nil
	}

	if t == "DOMAIN-REGEX" {
		cleanV = v
		if lastComma := strings.LastIndex(cleanV, ","); lastComma > 0 {
			if tail := strings.TrimSpace(cleanV[lastComma+1:]); clashTypeSuffixRe.MatchString(tail) {
				cleanV = cleanV[:lastComma]
			}
		}
		return &Rule{Type: t, Value: cleanV}
	}
	if t == "DOMAIN" || t == "DOMAIN-SUFFIX" {
		if r := normalizeWildcardDomain(cleanV, t); r != nil {
			return r
		}
	}
	if t == "IP-CIDR" && !strings.Contains(cleanV, "/") {
		cleanV += "/32"
	}
	if t == "IP-CIDR6" && !strings.Contains(cleanV, "/") {
		cleanV += "/128"
	}
	return &Rule{Type: t, Value: cleanV}
}

// parseFallback 处理无类型前缀的兜底写法（裸域名、通配符、hosts 行、dnsmasq 行）。
func parseFallback(line string) *Rule {
	if line == "Mijia Cloud" {
		return &Rule{Type: "DOMAIN-REGEX", Value: `^Mijia\sCloud$`}
	}
	if r := normalizeWildcardDomain(line, "DOMAIN-REGEX"); r != nil {
		return r
	}
	if nakedDomainRegex.MatchString(line) {
		return &Rule{Type: "DOMAIN", Value: line}
	}

	if matches := hostsRegex.FindStringSubmatch(line); len(matches) > 1 {
		domain := matches[1]
		if isValidHostsDomain(domain) {
			if strings.Contains(domain, "*") {
				return &Rule{Type: "DOMAIN-REGEX", Value: "^" + strings.ReplaceAll(strings.ReplaceAll(domain, ".", "\\."), "*", "[^.]+") + "$"}
			}
			return &Rule{Type: "DOMAIN", Value: domain}
		}
	}
	if matches := dnsmasqRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{Type: "DOMAIN-SUFFIX", Value: matches[1]}
	}
	return nil
}

// ParseHosts 解析 /etc/hosts 风格行。
func ParseHosts(line string) *Rule {
	if matches := hostsRegex.FindStringSubmatch(line); len(matches) > 1 {
		domain := matches[1]
		if isValidHostsDomain(domain) {
			if strings.Contains(domain, "*") {
				return &Rule{Type: "DOMAIN-REGEX", Value: "^" + strings.ReplaceAll(strings.ReplaceAll(domain, ".", "\\."), "*", "[^.]+") + "$"}
			}
			return &Rule{Type: "DOMAIN", Value: domain}
		}
	}
	return nil
}

// ParseDnsmasq 解析 dnsmasq 的 `server=/domain/...`、`address=/domain/...` 行。
func ParseDnsmasq(line string) *Rule {
	if matches := dnsmasqRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{Type: "DOMAIN-SUFFIX", Value: matches[1]}
	}
	return nil
}

// ParseSmartDNS 解析 smartdns 的 `address /domain/...` 行。
func ParseSmartDNS(line string) *Rule {
	if matches := smartdnsRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{Type: "DOMAIN-SUFFIX", Value: matches[1]}
	}
	return nil
}

// ParseWhite 解析 Adblock 白名单（`@@` 前缀）语法。
func ParseWhite(line string) *Rule {
	line = strings.TrimSpace(line)
	if strings.ContainsAny(line, "$~") {
		return nil
	}
	if !strings.HasPrefix(line, "@@") {
		return nil
	}

	val := line[2:]
	if strings.HasPrefix(val, "||") && strings.HasSuffix(val, "^") {
		clean := val[2 : len(val)-1]
		if !strings.ContainsAny(clean, "/?=:,|") {
			if strings.Contains(clean, "*") {
				return &Rule{Type: "DOMAIN-REGEX", Value: "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(clean, ".", "\\."), "*", ".*") + "$"}
			} else if adblockDomainRegex.MatchString(clean) {
				return &Rule{Type: "DOMAIN-SUFFIX", Value: clean}
			}
		}
	}
	if strings.HasPrefix(val, "|") && strings.HasSuffix(val, "|") && !strings.HasPrefix(val, "||") {
		clean := val[1 : len(val)-1]
		if !strings.ContainsAny(clean, "/?=:,^") {
			if strings.Contains(clean, "*") {
				return &Rule{Type: "DOMAIN-REGEX", Value: "^" + strings.ReplaceAll(strings.ReplaceAll(clean, ".", "\\."), "*", ".*") + "$"}
			} else if adblockDomainRegex.MatchString(clean) {
				return &Rule{Type: "DOMAIN", Value: clean}
			}
		}
	}
	return nil
}

// isValidHostsDomain 过滤 hosts 中的无效/本机域名。
func isValidHostsDomain(domain string) bool {
	if !strings.Contains(domain, ".") {
		return false
	}
	lower := strings.ToLower(domain)
	if lower == "0.0.0.0" || strings.HasSuffix(lower, ".localdomain") || strings.HasPrefix(lower, "ip6-") {
		return false
	}
	return true
}

// parseIPOrCIDR 解析裸 IP 或 CIDR，统一补齐 /32、/128。
func parseIPOrCIDR(line string) *Rule {
	if _, err := netip.ParsePrefix(line); err == nil {
		if strings.Contains(line, ":") {
			return &Rule{Type: "IP-CIDR6", Value: line}
		}
		return &Rule{Type: "IP-CIDR", Value: line}
	}
	if _, err := netip.ParseAddr(line); err == nil {
		if strings.Contains(line, ":") {
			return &Rule{Type: "IP-CIDR6", Value: line + "/128"}
		}
		return &Rule{Type: "IP-CIDR", Value: line + "/32"}
	}
	return nil
}

// ParseAppleClients 解析 Surge / Loon / QuantumultX / Shadowrocket / Stash 规则行。
// 这些客户端语法高度相似：`TYPE,VALUE[,策略]`，且支持 `.domain` 后缀快捷写法。
func ParseAppleClients(line string) *Rule {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, ",") {
		if strings.HasPrefix(line, ".") {
			return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.TrimPrefix(line, ".")}
		}
		if nakedDomainRegex.MatchString(line) {
			return &Rule{Type: "DOMAIN", Value: line}
		}
		return nil
	}

	parts := strings.SplitN(line, ",", 3)
	if len(parts) >= 2 {
		line = strings.TrimSpace(parts[0]) + "," + strings.TrimSpace(parts[1])
	}
	return parseTypedRule(line)
}
