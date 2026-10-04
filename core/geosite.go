package core

import (
	"maps"
	"os"
	"slices"
	"strings"
)

// ---- geosite.dat（v2ray GeoSiteList）读写 ----
//
// proto 结构（app/router/routercommon/common.proto，稳定格式）：
//
//	message GeoSiteList { repeated GeoSite entry = 1; }
//	message GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//	message Domain      { enum Type { Plain=0; Regex=1; Domain=2; Full=3; }
//	                      Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//
// Domain.Type 到内部 Rule.Type 的映射（业界通用约定）：
//
//	Full(3)   -> DOMAIN        精确匹配
//	Domain(2) -> DOMAIN-SUFFIX 子域匹配
//	Plain(0)  -> DOMAIN-KEYWORD 关键词匹配
//	Regex(1)  -> DOMAIN-REGEX  正则匹配
//
// 读取时忽略未知字段（如 attribute）；写出仅写 type 与 value。

const (
	domainTypePlain  = 0
	domainTypeRegex  = 1
	domainTypeDomain = 2
	domainTypeFull   = 3
)

// LoadGeoSite 读取 geosite.dat，返回 "标签 -> 域名规则" 映射。
func LoadGeoSite(path string) (map[string][]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Rule)
	p := &pbuf{b: data}
	for p.more() {
		field, wire, err := p.readField()
		if err != nil {
			return nil, err
		}
		if field == -1 {
			break
		}
		if field != 1 || wire != 2 {
			if err := p.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		msg, err := p.readBytes()
		if err != nil {
			return nil, err
		}
		code, rules, err := parseGeoSiteEntry(msg)
		if err != nil {
			return nil, err
		}
		if code != "" {
			out[code] = append(out[code], rules...)
		}
	}
	return out, nil
}

func parseGeoSiteEntry(msg []byte) (string, []Rule, error) {
	p := &pbuf{b: msg}
	code := ""
	var rules []Rule
	for p.more() {
		field, wire, err := p.readField()
		if err != nil {
			return "", nil, err
		}
		if field == -1 {
			break
		}
		switch {
		case field == 1 && wire == 2: // country_code
			b, err := p.readBytes()
			if err != nil {
				return "", nil, err
			}
			code = string(b)
		case field == 2 && wire == 2: // domain
			b, err := p.readBytes()
			if err != nil {
				return "", nil, err
			}
			if r := parseDomain(b); r != nil {
				rules = append(rules, *r)
			}
		default:
			if err := p.skip(wire); err != nil {
				return "", nil, err
			}
		}
	}
	return code, rules, nil
}

func parseDomain(msg []byte) *Rule {
	p := &pbuf{b: msg}
	typ := domainTypePlain
	value := ""
	for p.more() {
		field, wire, err := p.readField()
		if err != nil {
			return nil
		}
		if field == -1 {
			break
		}
		switch {
		case field == 1 && wire == 0:
			if n, err := p.readVarint(); err == nil {
				typ = int(n)
			}
		case field == 2 && wire == 2:
			if b, err := p.readBytes(); err == nil {
				value = string(b)
			}
		default:
			_ = p.skip(wire)
		}
	}
	switch typ {
	case domainTypeFull:
		return &Rule{Type: "DOMAIN", Value: strings.ToLower(value)}
	case domainTypeDomain:
		return &Rule{Type: "DOMAIN-SUFFIX", Value: strings.ToLower(value)}
	case domainTypeRegex:
		return &Rule{Type: "DOMAIN-REGEX", Value: value}
	case domainTypePlain:
		return &Rule{Type: "DOMAIN-KEYWORD", Value: strings.ToLower(value)}
	}
	return nil
}

// WriteGeoSite 把 "标签 -> 域名规则" 写为 geosite.dat（标签按字典序稳定输出）。
func WriteGeoSite(path string, entries map[string][]Rule) error {
	var buf []byte
	for _, code := range slices.Sorted(maps.Keys(entries)) {
		var msg []byte
		msg = appendStringField(msg, 1, code)
		for _, r := range entries[code] {
			var d []byte
			switch r.Type {
			case "DOMAIN":
				d = appendVarintField(d, 1, domainTypeFull)
				d = appendStringField(d, 2, r.Value)
			case "DOMAIN-SUFFIX":
				d = appendVarintField(d, 1, domainTypeDomain)
				d = appendStringField(d, 2, r.Value)
			case "DOMAIN-KEYWORD":
				d = appendVarintField(d, 1, domainTypePlain)
				d = appendStringField(d, 2, r.Value)
			case "DOMAIN-REGEX":
				d = appendVarintField(d, 1, domainTypeRegex)
				d = appendStringField(d, 2, r.Value)
			default:
				continue
			}
			msg = appendBytesField(msg, 2, d)
		}
		buf = appendBytesField(buf, 1, msg)
	}
	return os.WriteFile(path, buf, 0o644)
}
