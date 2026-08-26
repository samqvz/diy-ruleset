package core

import (
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Rule struct{ Type, Value string }

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
)

func Parse(line, format string) *Rule {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
		return nil
	}
	if idx := strings.Index(line, " #"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	} else if idx := strings.Index(line, "\t#"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, " //"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	} else if idx := strings.Index(line, "\t//"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return nil
	}

	var r *Rule

	switch format {
	case "clash":
		r = ParseClash(line)
	case "v2ray":
		r = ParseV2Ray(line)
	case "adblock":
		r = ParseAdblock(line)
	case "hosts":
		r = ParseHosts(line)
	case "dnsmasq":
		r = ParseDnsmasq(line)
	case "smartdns":
		r = ParseSmartDNS(line)
	case "white":
		r = ParseWhite(line)
	case "egern":
		r = ParseEgern(line, "")
	case "surge", "shadowrocket", "loon", "quantumultx", "stash":
		r = ParseAppleClients(line)
	default:
		r = ParseClash(line)
	}
	if r != nil && (r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX" || r.Type == "DOMAIN-KEYWORD") {
		r.Value = strings.ToLower(r.Value)
	}
	return r
}

func ParseClash(line string) *Rule {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
	}
	line = strings.Trim(line, "'\"\t ")
	if line == "payload:" || line == "" {
		return nil
	}
	if r := parseStandardClash(line); r != nil {
		return r
	}
	if r := parseIPOrCIDR(line); r != nil {
		return r
	}
	return parseFallback(line)
}

func ParseEgern(line string, section string) *Rule {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
	} else if strings.HasPrefix(line, "-") {
		line = strings.TrimSpace(line[1:])
	}
	line = strings.Trim(line, "'\"\t ")
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
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
		if !strings.Contains(line, "/") { line += "/32" }
		return &Rule{Type: "IP-CIDR", Value: line}
	case "ip_cidr6_set":
		if !strings.Contains(line, "/") { line += "/128" }
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
	if strings.HasPrefix(line, "full:") {
		return &Rule{"DOMAIN", strings.TrimPrefix(line, "full:")}
	}
	if strings.HasPrefix(line, "domain:") {
		return &Rule{"DOMAIN-SUFFIX", strings.TrimPrefix(line, "domain:")}
	}
	if strings.HasPrefix(line, "keyword:") {
		return &Rule{"DOMAIN-KEYWORD", strings.TrimPrefix(line, "keyword:")}
	}
	if strings.HasPrefix(line, "regexp:") {
		return &Rule{"DOMAIN-REGEX", strings.TrimPrefix(line, "regexp:")}
	}
	if strings.HasPrefix(line, "regex:") {
		return &Rule{"DOMAIN-REGEX", strings.TrimPrefix(line, "regex:")}
	}
	if strings.HasPrefix(line, ".") {
		return &Rule{"DOMAIN-SUFFIX", strings.TrimPrefix(line, ".")}
	}
	if nakedDomainRegex.MatchString(line) {
		return &Rule{"DOMAIN-KEYWORD", line}
	}
	return nil
}

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
			if strings.Contains(val, ":") {
				return &Rule{"IP-CIDR6", val + "/128"}
			}
			return &Rule{"IP-CIDR", val + "/32"}
		}
		if strings.Contains(val, "*") {
			return &Rule{"DOMAIN-REGEX", "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", ".*") + "$"}
		}
		if adblockDomainRegex.MatchString(val) {
			return &Rule{"DOMAIN-SUFFIX", val}
		}
		return nil
	}
	return nil
}

func normalizeClashWildcard(domain string, expectedType string) *Rule {
	if domain == "*" {
		return &Rule{"DOMAIN-REGEX", "^[^.]+$"}
	}
	if strings.HasPrefix(domain, "+.") {
		val := strings.TrimPrefix(domain, "+.")
		if strings.Contains(val, "*") {
			return &Rule{"DOMAIN-REGEX", "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", "[^.]+") + "$"}
		}
		return &Rule{"DOMAIN-SUFFIX", val}
	}
	if strings.HasPrefix(domain, ".") {
		val := strings.TrimPrefix(domain, ".")
		return &Rule{"DOMAIN-REGEX", "^.+\\." + strings.ReplaceAll(strings.ReplaceAll(val, ".", "\\."), "*", "[^.]+") + "$"}
	}
	if strings.Contains(domain, "*") {
		newVal := strings.ReplaceAll(domain, ".", `\.`)
		newVal = strings.ReplaceAll(newVal, "*", `[^.]+`)
		if expectedType == "DOMAIN-SUFFIX" {
			return &Rule{"DOMAIN-REGEX", "^(.+\\.)?" + newVal + "$"}
		} else {
			return &Rule{"DOMAIN-REGEX", "^" + newVal + "$"}
		}
	}
	return nil
}

func parseStandardClash(line string) *Rule {
	if !strings.Contains(line, ",") {
		return nil
	}
	idx := strings.Index(line, ",")
	t := strings.ToUpper(strings.TrimSpace(line[:idx]))
	v := strings.TrimSpace(line[idx+1:])
	v = strings.Trim(v, "'\"\t ")
	parts := strings.Split(v, ",")
	cleanV := strings.TrimSpace(parts[0])
	if t == "HOST" {
		t = "DOMAIN"
	} else if t == "HOST-SUFFIX" {
		t = "DOMAIN-SUFFIX"
	} else if t == "HOST-KEYWORD" {
		t = "DOMAIN-KEYWORD"
	} else if t == "HOST-WILDCARD" {
		t = "DOMAIN-WILDCARD"
	} else if t == "DEST-PORT" || t == "PORT" {
		t = "DST-PORT"
	} else if t == "IP4-CIDR" {
		t = "IP-CIDR"
	} else if t == "IP6-CIDR" {
		t = "IP-CIDR6"
	}
	valid := map[string]bool{
		"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true, 
		"DOMAIN-WILDCARD": true, "URL-REGEX": true, 
		"IP-CIDR": true, "IP-CIDR6": true, 
		"DST-PORT": true, "PROCESS-NAME": true, "PROCESS-PATH": true, "USER-AGENT": true, "IP-ASN": true,
	}
	if valid[t] {
		if t == "DOMAIN-REGEX" {
			cleanV = v
			if lastComma := strings.LastIndex(cleanV, ","); lastComma != -1 && lastComma > 0 {
				tail := strings.TrimSpace(cleanV[lastComma+1:])
				if matched, _ := regexp.MatchString(`^[A-Za-z0-9_-]+$`, tail); matched {
					cleanV = cleanV[:lastComma]
				}
			}
			return &Rule{Type: t, Value: cleanV}
		}
		if (t == "DOMAIN" || t == "DOMAIN-SUFFIX") {
			if r := normalizeClashWildcard(cleanV, t); r != nil {
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
	return nil
}

func parseFallback(line string) *Rule {
	if line == "Mijia Cloud" {
		return &Rule{"DOMAIN-REGEX", `^Mijia\sCloud$`}
	}
	if r := normalizeClashWildcard(line, "DOMAIN-REGEX"); r != nil {
		return r
	}
	if nakedDomainRegex.MatchString(line) {
		return &Rule{"DOMAIN", line}
	}
	if matches := hostsRegex.FindStringSubmatch(line); len(matches) > 1 {
		domain := matches[1]
		if isValidHostsDomain(domain) {
			if strings.Contains(domain, "*") {
				return &Rule{"DOMAIN-REGEX", "^" + strings.ReplaceAll(strings.ReplaceAll(domain, ".", "\\."), "*", "[^.]+") + "$"}
			}
			return &Rule{"DOMAIN", domain}
		}
	}
	if matches := dnsmasqRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{"DOMAIN-SUFFIX", matches[1]}
	}
	return nil
}

func ParseHosts(line string) *Rule {
	if matches := hostsRegex.FindStringSubmatch(line); len(matches) > 1 {
		domain := matches[1]
		if isValidHostsDomain(domain) {
			if strings.Contains(domain, "*") {
				return &Rule{"DOMAIN-REGEX", "^" + strings.ReplaceAll(strings.ReplaceAll(domain, ".", "\\."), "*", "[^.]+") + "$"}
			}
			return &Rule{"DOMAIN", domain}
		}
	}
	return nil
}

func ParseDnsmasq(line string) *Rule {
	if matches := dnsmasqRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{"DOMAIN-SUFFIX", matches[1]}
	}
	return nil
}

func ParseSmartDNS(line string) *Rule {
	if matches := smartdnsRegex.FindStringSubmatch(line); len(matches) > 1 {
		return &Rule{"DOMAIN-SUFFIX", matches[1]}
	}
	return nil
}

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
				regexPattern := "^(.+\\.)?" + strings.ReplaceAll(strings.ReplaceAll(clean, ".", "\\."), "*", ".*") + "$"
				return &Rule{"DOMAIN-REGEX", regexPattern}
			} else if adblockDomainRegex.MatchString(clean) {
				return &Rule{"DOMAIN-SUFFIX", clean}
			}
		}
	}
	if strings.HasPrefix(val, "|") && strings.HasSuffix(val, "|") && !strings.HasPrefix(val, "||") {
		clean := val[1 : len(val)-1]
		if !strings.ContainsAny(clean, "/?=:,^") {
			if strings.Contains(clean, "*") {
				regexPattern := "^" + strings.ReplaceAll(strings.ReplaceAll(clean, ".", "\\."), "*", ".*") + "$"
				return &Rule{"DOMAIN-REGEX", regexPattern}
			} else if adblockDomainRegex.MatchString(clean) {
				return &Rule{"DOMAIN", clean}
			}
		}
	}
	return nil
}

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

func parseIPOrCIDR(line string) *Rule {
	if _, err := netip.ParsePrefix(line); err == nil {
		if strings.Contains(line, ":") {
			return &Rule{"IP-CIDR6", line}
		}
		return &Rule{"IP-CIDR", line}
	}
	if _, err := netip.ParseAddr(line); err == nil {
		if strings.Contains(line, ":") {
			return &Rule{"IP-CIDR6", line + "/128"}
		}
		return &Rule{"IP-CIDR", line + "/32"}
	}
	return nil
}

func ParseAppleClients(line string) *Rule {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, ",") {
		if strings.HasPrefix(line, ".") {
			return &Rule{"DOMAIN-SUFFIX", strings.TrimPrefix(line, ".")}
		}
		if nakedDomainRegex.MatchString(line) {
			return &Rule{"DOMAIN", line}
		}
		return nil
	}
	parts := strings.Split(line, ",")
	if len(parts) >= 2 {
		line = strings.TrimSpace(parts[0]) + "," + strings.TrimSpace(parts[1])
	}
	return parseStandardClash(line)
}

func InferParser(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "clash"
	}
	lines := strings.Split(string(data), "\n")
	scores := make(map[string]int)
	scoreLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "!") {
			return
		}
		if inferAdblockRe.MatchString(line) { scores["adblock"] += 10 } else 
		if inferHostsRe.MatchString(line) { scores["hosts"] += 10 } else 
		if inferDnsmasqRe.MatchString(line) { scores["dnsmasq"] += 10 } else 
		if inferSmartdnsRe.MatchString(line) { scores["smartdns"] += 10 } else 
		if inferEgernRe.MatchString(line) { scores["egern"] += 100 } else 
		if inferV2rayRe.MatchString(line) { scores["v2ray"] += 10 } else 
		if inferQxStrictRe.MatchString(line) { scores["quantumultx"] += 100 } else 
		if inferSurgeStrictRe.MatchString(line) { scores["surge"] += 100 } else 
		if inferClashStrictRe.MatchString(line) || line == "payload:" || strings.HasPrefix(line, "- ") { scores["clash"] += 100 } else 
		if inferGenericRe.MatchString(line) {
			scores["clash"] += 1; scores["surge"] += 1; scores["shadowrocket"] += 1
		} else if inferIPRe.MatchString(line) {
			scores["clash"] += 1
		}
	}
	headLimit := 500
	if len(lines) < headLimit {
		headLimit = len(lines)
	}
	for i := 0; i < headLimit; i++ {
		scoreLine(lines[i])
	}
	tailStart := len(lines) - 500
	if tailStart < headLimit {
		tailStart = headLimit
	}
	for i := tailStart; i < len(lines); i++ {
		scoreLine(lines[i])
	}
	bestParser := "clash"
	maxScore := 0
	for parser, score := range scores {
		if score > maxScore {
			maxScore = score
			bestParser = parser
		}
	}
	return bestParser
}