package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type SingboxRuleSet struct {
	Version int              `json:"version"`
	Rules   []map[string]any `json:"rules"`
}

func toPortArray(vals []string) []any {
	var res []any
	for _, v := range vals {
		if n, err := strconv.Atoi(v); err == nil {
			res = append(res, n)
		} else {
			res = append(res, v)
		}
	}
	return res
}

func ensureDir(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatalf("❌ 无法创建目录 [%s]: %v\n", path, err)
	}
}

func writeToFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("❌ 无法写入文件 [%s]: %v\n", path, err)
	}
}

var (
	sbKeys = map[string]string{
		"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-REGEX": "domain_regex",
		"PROCESS-NAME": "process_name", "PROCESS-PATH": "process_path",
		"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "DST-PORT": "port",
	}
	domKeys = []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX", "URL-REGEX", "PROCESS-NAME", "PROCESS-PATH", "USER-AGENT"}
	ipKeys  = []string{"DST-PORT", "IP-ASN"}
)

func countRules(dom map[string][]string, ip map[string][]string) int {
	c := 0
	for _, v := range dom {
		c += len(v)
	}
	for _, v := range ip {
		c += len(v)
	}
	return c
}

type RuleExporter struct {
	cat     Category
	res     *ProcessedResult
	cfg     *Config
	catOut  ResolvedClientConfig
	catName string
	isWhite bool
}

func ExportFiles(cat Category, res *ProcessedResult, cfg *Config, isWhite bool) {
	ensureDir("process")
	ensureDir("publish/singbox")
	ensureDir("publish/mihomo")
	ensureDir("publish/v2ray")
	ensureDir("publish/surge")
	ensureDir("publish/shadowrocket")
	ensureDir("publish/quantumultx")
	ensureDir("publish/loon")
	ensureDir("publish/stash")
	ensureDir("publish/egern")

	exporter := &RuleExporter{
		cat:     cat,
		res:     res,
		cfg:     cfg,
		catOut:  ResolveClients(cfg.Global, cat),
		catName: cat.Name,
		isWhite: isWhite,
	}

	exporter.exportCNIP()
	exporter.exportSingbox()
	exporter.exportMihomo()
	exporter.exportDNS()
	exporter.exportV2ray()
	exporter.exportApple()
	exporter.exportEgern()
	exporter.exportWhite()
}

func (e *RuleExporter) exportCNIP() {
	if !(e.cfg.Global.SplitCNIP && e.catName == "cn") {
		return
	}
	ensureDir("publish/cnip")
	var ipv4, ipv6 []string

	for _, ip := range e.res.IPRules["IP-CIDR"] {
		ipv4 = append(ipv4, strings.Split(ip, ",")[0])
	}
	for _, ip := range e.res.IPRules["IP-CIDR6"] {
		ipv6 = append(ipv6, strings.Split(ip, ",")[0])
	}

	writeCnipFiles := func(name string, ips []string) {
		if len(ips) == 0 {
			return
		}
		writeToFile(fmt.Sprintf("publish/cnip/%s.txt", name), []byte(strings.Join(ips, "\n")))
		if e.catOut.Singbox.SRS {
			rs := SingboxRuleSet{Version: 5, Rules: []map[string]any{{"ip_cidr": ips}}}
			if d, err := json.MarshalIndent(rs, "", "  "); err == nil {
				writeToFile(fmt.Sprintf("process/srs_cnip_%s.json", name), d)
			}
		}
		if e.catOut.Mihomo.MRS {
			writeToFile(fmt.Sprintf("process/cnip_%s_mihomo_ip.txt", name), []byte(strings.Join(ips, "\n")))
		}
	}

	writeCnipFiles("cnipv4", ipv4)
	writeCnipFiles("cnipv6", ipv6)

	e.res.ExactCounts["cnipv4"] = len(ipv4)
	e.res.ExactCounts["cnipv6"] = len(ipv6)
}

func (e *RuleExporter) exportSingbox() {
	if !e.catOut.Singbox.Enable {
		return
	}

	sbDomRules, sbIPRules := e.res.DomRules, e.res.IPRules

	e.res.ExactCounts["singbox_dom"] = countRules(sbDomRules, nil)
	e.res.ExactCounts["singbox_ip"] = countRules(nil, sbIPRules)
	e.res.ExactCounts["singbox_total"] = e.res.ExactCounts["singbox_dom"] + e.res.ExactCounts["singbox_ip"]

	hasDom := false
	srDom := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}
	mergedDomRules := make(map[string][]string)
	for _, t := range domKeys {
		vals, ok := sbDomRules[t]
		if !ok || len(vals) == 0 {
			continue
		}
		if t == "URL-REGEX" || t == "USER-AGENT" {
			continue
		}
		if t == "DOMAIN-WILDCARD" {
			for _, v := range vals {
				mergedDomRules["DOMAIN-REGEX"] = append(mergedDomRules["DOMAIN-REGEX"], wildcardToRegex(v))
			}
		} else {
			mergedDomRules[t] = append(mergedDomRules[t], vals...)
		}
	}

	orderedOutputKeys := []string{"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH"}
	for _, t := range orderedOutputKeys {
		if vals, ok := mergedDomRules[t]; ok && len(vals) > 0 {
			if sbKey := sbKeys[t]; sbKey != "" {
				srDom.Rules = append(srDom.Rules, map[string]any{sbKey: vals})
				hasDom = true
			}
		}
	}

	hasIP := false
	srIP := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}
	srIP_SRS := SingboxRuleSet{Version: 5, Rules: []map[string]any{}}

	var combinedIPs []string
	combinedIPs = append(combinedIPs, sbIPRules["IP-CIDR"]...)
	combinedIPs = append(combinedIPs, sbIPRules["IP-CIDR6"]...)
	if len(combinedIPs) > 0 {
		srIP.Rules = append(srIP.Rules, map[string]any{"ip_cidr": combinedIPs})
		srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{"ip_cidr": combinedIPs})
		hasIP = true
	}

	for _, t := range ipKeys {
		if vals, ok := sbIPRules[t]; ok && len(vals) > 0 {
			sbKey := sbKeys[t]
			if sbKey == "" {
				continue
			}
			if t == "DST-PORT" {
				srIP.Rules = append(srIP.Rules, map[string]any{sbKey: toPortArray(vals)})
				srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKey: toPortArray(vals)})
			} else {
				srIP.Rules = append(srIP.Rules, map[string]any{sbKey: vals})
				srIP_SRS.Rules = append(srIP_SRS.Rules, map[string]any{sbKey: vals})
			}
			hasIP = true
		}
	}

	writeSb := func(name string, rs SingboxRuleSet, isIP bool, rsSRS SingboxRuleSet) {
		if e.catOut.Singbox.JSON {
			if d, err := json.MarshalIndent(rs, "", "  "); err == nil {
				writeToFile(fmt.Sprintf("%s/%s.json", "publish/singbox", name), d)
			}
		}
		if e.catOut.Singbox.SRS {
			targetRS := rs
			if isIP {
				targetRS = rsSRS
			}
			if d, err := json.MarshalIndent(targetRS, "", "  "); err == nil {
				writeToFile(fmt.Sprintf("%s/srs_%s.json", "process", name), d)
			}
		}
	}

	if e.catOut.Singbox.SingleFile {
		srCombined := SingboxRuleSet{Version: 5, Rules: append(srDom.Rules, srIP.Rules...)}
		if len(srCombined.Rules) > 0 {
			writeSb(e.catName, srCombined, false, SingboxRuleSet{})
		}
	} else {
		if hasDom {
			writeSb(e.catName, srDom, false, SingboxRuleSet{})
		}
		if hasIP {
			writeSb(e.catName+"_ip", srIP, true, srIP_SRS)
		}
	}
}

func (e *RuleExporter) exportMihomo() {
	if !e.catOut.Mihomo.Enable {
		return
	}

	miDomRules, miIPRules := e.res.DomRules, e.res.IPRules

	e.res.ExactCounts["mihomo_dom"] = countRules(miDomRules, nil)
	e.res.ExactCounts["mihomo_ip"] = countRules(nil, miIPRules)
	e.res.ExactCounts["mihomo_total"] = e.res.ExactCounts["mihomo_dom"] + e.res.ExactCounts["mihomo_ip"]

	var yamlDomLines, yamlIPLines, txtDomLines, txtIPLines []string
	hasDom, hasIP := false, false

	for _, t := range domKeys {
		if vals, ok := miDomRules[t]; ok && len(vals) > 0 {
			if t == "URL-REGEX" || t == "USER-AGENT" {
				continue
			}
			for _, v := range vals {
				yamlDomLines = append(yamlDomLines, fmt.Sprintf("%s,%s", t, v))
			}
			hasDom = true
		}
	}
	if hasDom {
		for _, s := range miDomRules["DOMAIN-SUFFIX"] {
			txtDomLines = append(txtDomLines, "+."+s)
		}
		for _, d := range miDomRules["DOMAIN"] {
			txtDomLines = append(txtDomLines, d)
		}
		for _, w := range miDomRules["DOMAIN-WILDCARD"] {
			txtDomLines = append(txtDomLines, w)
		}
		for _, r := range miDomRules["DOMAIN-REGEX"] {
			w := toMihomoWildcard(r)
			if w != "" && !strings.ContainsAny(w, "()[]|?^$") {
				txtDomLines = append(txtDomLines, w)
			}
		}
	}

	for _, k := range []string{"IP-CIDR", "IP-CIDR6", "DST-PORT", "IP-ASN"} {
		if vals, ok := miIPRules[k]; ok && len(vals) > 0 {
			for _, v := range vals {
				yamlIPLines = append(yamlIPLines, fmt.Sprintf("%s,%s", k, v))
				if k == "IP-CIDR" || k == "IP-CIDR6" {
					txtIPLines = append(txtIPLines, strings.Split(v, ",")[0])
				}
			}
			hasIP = true
		}
	}

	writeMihomoUserFiles := func(name string, classicalLines []string) {
		if e.catOut.Mihomo.YAML && len(classicalLines) > 0 {
			var yaml strings.Builder
			yaml.WriteString("payload:\n")
			for _, l := range classicalLines {
				yaml.WriteString(fmt.Sprintf("  - '%s'\n", l))
			}
			writeToFile(fmt.Sprintf("%s/%s.yaml", "publish/mihomo", name), []byte(yaml.String()))
		}

		if e.catOut.Mihomo.TXT && len(classicalLines) > 0 {
			writeToFile(fmt.Sprintf("%s/%s.txt", "publish/mihomo", name), []byte(strings.Join(classicalLines, "\n")))
		}
	}

	if e.catOut.Mihomo.SingleFile {
		combinedLines := append(yamlDomLines, yamlIPLines...)
		writeMihomoUserFiles(e.catName, combinedLines)
	} else {
		if hasDom {
			writeMihomoUserFiles(e.catName, yamlDomLines)
		}
		if hasIP {
			writeMihomoUserFiles(e.catName+"_ip", yamlIPLines)
		}
	}

	if e.catOut.Mihomo.MRS {
		if len(txtDomLines) > 0 {
			writeToFile(fmt.Sprintf("%s/%s_mihomo_domain.txt", "process", e.catName), []byte(strings.Join(txtDomLines, "\n")))
		}
		if len(txtIPLines) > 0 {
			writeToFile(fmt.Sprintf("%s/%s_mihomo_ip.txt", "process", e.catName), []byte(strings.Join(txtIPLines, "\n")))
		}
	}
}

func (e *RuleExporter) exportDNS() {
	if !(e.cat.PublishAdblock || e.cat.PublishDnsmasq || e.cat.PublishSmartDNS) {
		return
	}

	var adblockLines, dnsmasqLines, smartdnsLines []string
	adblockDedupe := make(map[string]bool)
	dnsmasqDedupe := make(map[string]bool)
	smartdnsDedupe := make(map[string]bool)

	addRule := func(lines *[]string, dedupe map[string]bool, rule string) {
		if !dedupe[rule] {
			dedupe[rule] = true
			*lines = append(*lines, rule)
		}
	}

	for _, s := range e.res.DomRules["DOMAIN-SUFFIX"] {
		if e.cat.PublishAdblock {
			if e.isWhite {
				addRule(&adblockLines, adblockDedupe, "@@||"+s+"^")
			} else {
				addRule(&adblockLines, adblockDedupe, "||"+s+"^")
			}
		}
	}
	for _, d := range e.res.DomRules["DOMAIN"] {
		if e.cat.PublishAdblock {
			if e.isWhite {
				addRule(&adblockLines, adblockDedupe, "@@|"+d+"|")
			} else {
				addRule(&adblockLines, adblockDedupe, "||"+d+"^")
			}
		}
	}

	if e.cat.PublishAdblock && !e.isWhite {
		for _, s := range e.res.WhiteDomRules["DOMAIN-SUFFIX"] {
			addRule(&adblockLines, adblockDedupe, "@@||"+s+"^")
		}
		for _, d := range e.res.WhiteDomRules["DOMAIN"] {
			addRule(&adblockLines, adblockDedupe, "@@|"+d+"|")
		}
		for _, l := range e.res.RawWhiteAdblockRules {
			addRule(&adblockLines, adblockDedupe, l)
		}
	}

	if !e.isWhite {
		dnsmasqTpl := "address=/%s/0.0.0.0"
		smartdnsTpl := "address /%s/#"
		if e.cat.DnsmasqServer != "" {
			dnsmasqTpl = fmt.Sprintf("server=/%%s/%s", e.cat.DnsmasqServer)
		}
		if e.cat.SmartdnsServer != "" {
			smartdnsTpl = fmt.Sprintf("nameserver /%%s/%s", e.cat.SmartdnsServer)
		}

		for _, s := range e.res.DomRules["DOMAIN-SUFFIX"] {
			if e.cat.PublishSmartDNS {
				addRule(&smartdnsLines, smartdnsDedupe, fmt.Sprintf(smartdnsTpl, s))
			}
			if e.cat.PublishDnsmasq {
				addRule(&dnsmasqLines, dnsmasqDedupe, fmt.Sprintf(dnsmasqTpl, s))
			}
		}
		for _, d := range e.res.DomRules["DOMAIN"] {
			if e.cat.PublishSmartDNS {
				addRule(&smartdnsLines, smartdnsDedupe, fmt.Sprintf(smartdnsTpl, d))
			}
			if e.cat.PublishDnsmasq {
				addRule(&dnsmasqLines, dnsmasqDedupe, fmt.Sprintf(dnsmasqTpl, d))
			}
		}
	}

	if e.cat.PublishAdblock {
		for _, l := range e.res.RawAdblockRules {
			addRule(&adblockLines, adblockDedupe, l)
		}
	}

	if !e.isWhite {
		if e.cat.PublishDnsmasq {
			for _, l := range e.res.RawDnsmasqRules {
				addRule(&dnsmasqLines, dnsmasqDedupe, l)
			}
		}
		if e.cat.PublishSmartDNS {
			for _, l := range e.res.RawSmartDNSRules {
				addRule(&smartdnsLines, smartdnsDedupe, l)
			}
		}
	}

	if e.cat.PublishAdblock && len(adblockLines) > 0 {
		ensureDir("publish/adblock")
		writeToFile(fmt.Sprintf("publish/adblock/%s.txt", e.catName), []byte(strings.Join(adblockLines, "\n")))
	}
	if e.cat.PublishDnsmasq && len(dnsmasqLines) > 0 {
		ensureDir("publish/dnsmasq")
		writeToFile(fmt.Sprintf("publish/dnsmasq/%s.conf", e.catName), []byte(strings.Join(dnsmasqLines, "\n")))
	}
	if e.cat.PublishSmartDNS && len(smartdnsLines) > 0 {
		ensureDir("publish/smartdns")
		writeToFile(fmt.Sprintf("publish/smartdns/%s.conf", e.catName), []byte(strings.Join(smartdnsLines, "\n")))
	}
}

func (e *RuleExporter) exportV2ray() {
	if !e.catOut.V2ray.Enable {
		return
	}

	v2DomRules, v2IPRules := e.res.DomRules, e.res.IPRules
	var v2Lines []string

	for _, t := range domKeys {
		for _, v := range v2DomRules[t] {
			if t == "URL-REGEX" || t == "USER-AGENT" || t == "PROCESS-NAME" || t == "PROCESS-PATH" {
				continue
			}

			prefix := ""
			switch t {
			case "DOMAIN":
				prefix = "full:"
			case "DOMAIN-SUFFIX":
				prefix = "domain:"
			case "DOMAIN-REGEX":
				prefix = "regexp:"
			case "DOMAIN-WILDCARD":
				prefix = "regexp:"
				v = wildcardToRegex(v)
			}
			v2Lines = append(v2Lines, prefix+v)
		}
	}

	var combinedIP []string
	for _, ip := range v2IPRules["IP-CIDR"] {
		combinedIP = append(combinedIP, strings.Split(ip, ",")[0])
	}
	for _, ip := range v2IPRules["IP-CIDR6"] {
		combinedIP = append(combinedIP, strings.Split(ip, ",")[0])
	}

	e.res.ExactCounts["v2ray_dom"] = len(v2Lines)
	e.res.ExactCounts["v2ray_ip"] = len(combinedIP)
	e.res.ExactCounts["v2ray_total"] = len(v2Lines) + len(combinedIP)

	if e.catOut.V2ray.SingleFile {
		combined := append(v2Lines, combinedIP...)
		if len(combined) > 0 {
			writeToFile(fmt.Sprintf("publish/v2ray/%s.txt", e.catName), []byte(strings.Join(combined, "\n")))
		}
	} else {
		if len(v2Lines) > 0 {
			writeToFile(fmt.Sprintf("publish/v2ray/%s.txt", e.catName), []byte(strings.Join(v2Lines, "\n")))
		}
		if len(combinedIP) > 0 {
			writeToFile(fmt.Sprintf("publish/v2ray/%s_ip.txt", e.catName), []byte(strings.Join(combinedIP, "\n")))
		}
	}
}

func (e *RuleExporter) exportApple() {
	buildAppleLines := func(clientName string, ruleName string) ([]string, []string) {
		appleDomRules, appleIPRules := e.res.DomRules, e.res.IPRules
		var domLines, ipLines []string

		for _, t := range domKeys {
			for _, v := range appleDomRules[t] {
				writeType, writeVal := t, v

				switch clientName {
				case "loon":
					if t == "DOMAIN-REGEX" || t == "DOMAIN-WILDCARD" || t == "PROCESS-NAME" || t == "PROCESS-PATH" {
						continue
					}
				case "surge":
					if t == "DOMAIN-REGEX" || t == "PROCESS-PATH" {
						continue
					}
				case "quantumultx":
					if t == "DOMAIN-REGEX" || t == "URL-REGEX" || t == "PROCESS-NAME" || t == "PROCESS-PATH" {
						continue
					}
					writeType = strings.ToLower(strings.ReplaceAll(t, "DOMAIN", "host"))
				case "shadowrocket":
					if t == "DOMAIN-REGEX" || t == "PROCESS-NAME" || t == "PROCESS-PATH" {
						continue
					}
				}

				suffix := ""
				if clientName == "quantumultx" {
					suffix = "," + ruleName
				}
				domLines = append(domLines, fmt.Sprintf("%s,%s%s", writeType, writeVal, suffix))
			}
		}

		for _, k := range []string{"IP-CIDR", "IP-CIDR6", "DST-PORT", "IP-ASN"} {
			for _, v := range appleIPRules[k] {
				writeType := k

				switch clientName {
				case "surge", "loon":
					if writeType == "DST-PORT" {
						writeType = "DEST-PORT"
					}
				case "quantumultx":
					if writeType == "DST-PORT" {
						writeType = "dest-port"
					}
					if writeType == "IP-CIDR" {
						writeType = "ip-cidr"
					}
					if writeType == "IP-CIDR6" {
						writeType = "ip6-cidr"
					}
					if writeType == "IP-ASN" {
						writeType = "ip-asn"
					}
				}

				suffix := ""
				if clientName == "quantumultx" {
					suffix = "," + ruleName
				} else if k == "IP-CIDR" || k == "IP-CIDR6" {
					suffix = ",no-resolve"
				}
				ipLines = append(ipLines, fmt.Sprintf("%s,%s%s", writeType, v, suffix))
			}
		}
		return domLines, ipLines
	}

	writeAppleFiles := func(clientName string, enable bool, singleFile bool, domLines, ipLines []string) {
		if !enable {
			return
		}

		e.res.ExactCounts[clientName+"_dom"] = len(domLines)
		e.res.ExactCounts[clientName+"_ip"] = len(ipLines)
		e.res.ExactCounts[clientName+"_total"] = len(domLines) + len(ipLines)

		if singleFile {
			combined := append(domLines, ipLines...)
			if len(combined) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s.list", clientName, e.catName), []byte(strings.Join(combined, "\n")))
			}
		} else {
			if len(domLines) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s.list", clientName, e.catName), []byte(strings.Join(domLines, "\n")))
			}
			if len(ipLines) > 0 {
				writeToFile(fmt.Sprintf("publish/%s/%s_ip.list", clientName, e.catName), []byte(strings.Join(ipLines, "\n")))
			}
		}
	}

	clients := []struct {
		name       string
		enable     bool
		singleFile bool
	}{
		{"surge", e.catOut.Surge.Enable, e.catOut.Surge.SingleFile},
		{"shadowrocket", e.catOut.Shadowrocket.Enable, e.catOut.Shadowrocket.SingleFile},
		{"loon", e.catOut.Loon.Enable, e.catOut.Loon.SingleFile},
		{"quantumultx", e.catOut.QuantumultX.Enable, e.catOut.QuantumultX.SingleFile},
		{"stash", e.catOut.Stash.Enable, e.catOut.Stash.SingleFile},
	}

	for _, client := range clients {
		if client.enable {
			d, i := buildAppleLines(client.name, e.catName)
			writeAppleFiles(client.name, true, client.singleFile, d, i)
		}
	}
}

func (e *RuleExporter) exportEgern() {
	if !e.catOut.Egern.Enable {
		return
	}

	egDomRules, egIPRules := e.res.DomRules, e.res.IPRules

	buildEgernYaml := func(doms, ips map[string][]string) string {
		var sb strings.Builder
		sb.WriteString("no_resolve: true\n")

		writeSet := func(key, setName, format string) {
			if vals, ok := doms[key]; ok && len(vals) > 0 {
				sb.WriteString(setName)
				sb.WriteString(":\n")
				for _, v := range vals {
					sb.WriteString(fmt.Sprintf(format, v))
				}
			}
			if vals, ok := ips[key]; ok && len(vals) > 0 {
				sb.WriteString(setName)
				sb.WriteString(":\n")
				for _, v := range vals {
					if key == "IP-ASN" && !strings.HasPrefix(strings.ToUpper(v), "AS") {
						v = "AS" + v
					}
					sb.WriteString(fmt.Sprintf(format, v))
				}
			}
		}

		writeSet("DOMAIN", "domain_set", "  - %s\n")
		writeSet("DOMAIN-KEYWORD", "domain_keyword_set", "  - %s\n")
		writeSet("DOMAIN-SUFFIX", "domain_suffix_set", "  - %s\n")
		writeSet("DOMAIN-WILDCARD", "domain_wildcard_set", "  - \"%s\"\n")
		writeSet("DOMAIN-REGEX", "domain_regex_set", "  - \"%s\"\n")
		writeSet("URL-REGEX", "url_regex_set", "  - \"%s\"\n")
		writeSet("USER-AGENT", "user_agent_set", "  - \"%s\"\n")

		writeSet("IP-CIDR", "ip_cidr_set", "  - %s\n")
		writeSet("IP-CIDR6", "ip_cidr6_set", "  - \"%s\"\n")
		writeSet("IP-ASN", "asn_set", "  - \"%s\"\n")
		writeSet("DST-PORT", "dest_port_set", "  - \"%s\"\n")

		return sb.String()
	}

	domCount, ipCount := countRules(egDomRules, nil), countRules(nil, egIPRules)
	e.res.ExactCounts["egern_dom"], e.res.ExactCounts["egern_ip"] = domCount, ipCount
	e.res.ExactCounts["egern_total"] = domCount + ipCount

	if e.catOut.Egern.SingleFile {
		if domCount+ipCount > 0 {
			writeToFile(fmt.Sprintf("publish/egern/%s.yaml", e.catName), []byte(buildEgernYaml(egDomRules, egIPRules)))
		}
	} else {
		if domCount > 0 {
			writeToFile(fmt.Sprintf("publish/egern/%s.yaml", e.catName), []byte(buildEgernYaml(egDomRules, nil)))
		}
		if ipCount > 0 {
			writeToFile(fmt.Sprintf("publish/egern/%s_ip.yaml", e.catName), []byte(buildEgernYaml(nil, egIPRules)))
		}
	}
}

func (e *RuleExporter) exportWhite() {
	if e.cat.PublishWhite && len(e.res.WhiteDomRules) > 0 {
		whiteCat := e.cat
		whiteCat.Name = e.catName + "_white"
		whiteCat.PublishWhite = false
		whiteCat.PublishAdblock = false
		whiteCat.PublishDnsmasq = false
		whiteCat.PublishSmartDNS = false
		whiteRes := &ProcessedResult{
			DomRules:    e.res.WhiteDomRules,
			IPRules:     make(map[string][]string),
			ExactCounts: make(map[string]int),
		}

		ExportFiles(whiteCat, whiteRes, e.cfg, true)

		for k, v := range whiteRes.ExactCounts {
			e.res.ExactCounts[k+"_white"] = v
		}
	}
}

func toMihomoWildcard(r string) string {
	clean := r
	clean = strings.TrimPrefix(clean, "^")
	clean = strings.TrimSuffix(clean, "$")
	if clean == "[^.]+" || clean == ".*" {
		return "*"
	}
	if strings.HasPrefix(clean, "(.+\\.)?") {
		clean = "+." + strings.TrimPrefix(clean, "(.+\\.)?")
	} else if strings.HasPrefix(clean, ".+\\.") {
		clean = "." + strings.TrimPrefix(clean, ".+\\.")
	}
	clean = strings.ReplaceAll(clean, ".*", "*")
	clean = strings.ReplaceAll(clean, "[^.]+", "*")
	clean = strings.ReplaceAll(clean, "\\.", ".")
	clean = strings.ReplaceAll(clean, "\\s", " ")
	return clean
}

func wildcardToRegex(w string) string {
	r := strings.ReplaceAll(w, ".", `\.`)
	r = strings.ReplaceAll(r, "*", `.*`)
	r = strings.ReplaceAll(r, "?", `.`)
	return "^" + r + "$"
}
