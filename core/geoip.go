package core

import (
	"maps"
	"net/netip"
	"os"
	"slices"
)

// ---- geoip.dat（v2ray GeoIPList）读写 ----
//
// proto 结构（app/router/routercommon/common.proto，稳定格式）：
//
//	message GeoIPList { repeated GeoIP entry = 1; }
//	message GeoIP    { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//	message CIDR     { bytes ip = 1; uint32 prefix = 2; }
//
// 读取时忽略未知字段；写出仅写 country_code 与 cidr（ip 为 4 或 16 字节 + 前缀长度）。

type geoIPCidr struct {
	ip     []byte
	prefix int
}

// LoadGeoIP 读取 geoip.dat，返回 "国家码 -> IP-CIDR 规则" 映射。
func LoadGeoIP(path string) (map[string][]Rule, error) {
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
		code, cidrs, err := parseGeoIPEntry(msg)
		if err != nil {
			return nil, err
		}
		if code == "" {
			continue
		}
		for _, c := range cidrs {
			addr, ok := netip.AddrFromSlice(c.ip)
			if !ok {
				continue
			}
			pfx := netip.PrefixFrom(addr, c.prefix)
			typ := "IP-CIDR"
			if addr.Is6() {
				typ = "IP-CIDR6"
			}
			out[code] = append(out[code], Rule{Type: typ, Value: pfx.String()})
		}
	}
	return out, nil
}

func parseGeoIPEntry(msg []byte) (string, []geoIPCidr, error) {
	p := &pbuf{b: msg}
	code := ""
	var cidrs []geoIPCidr
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
		case field == 2 && wire == 2: // cidr
			b, err := p.readBytes()
			if err != nil {
				return "", nil, err
			}
			c, err := parseCIDR(b)
			if err != nil {
				return "", nil, err
			}
			cidrs = append(cidrs, c)
		default:
			if err := p.skip(wire); err != nil {
				return "", nil, err
			}
		}
	}
	return code, cidrs, nil
}

func parseCIDR(msg []byte) (geoIPCidr, error) {
	p := &pbuf{b: msg}
	var c geoIPCidr
	for p.more() {
		field, wire, err := p.readField()
		if err != nil {
			return c, err
		}
		if field == -1 {
			break
		}
		switch {
		case field == 1 && wire == 2: // ip
			b, err := p.readBytes()
			if err != nil {
				return c, err
			}
			c.ip = append([]byte(nil), b...)
		case field == 2 && wire == 0: // prefix
			n, err := p.readVarint()
			if err != nil {
				return c, err
			}
			c.prefix = int(n)
		default:
			if err := p.skip(wire); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// WriteGeoIP 把 "国家码 -> IP-CIDR 规则" 写为 geoip.dat（标签按字典序稳定输出）。
func WriteGeoIP(path string, entries map[string][]Rule) error {
	var buf []byte
	for _, code := range slices.Sorted(maps.Keys(entries)) {
		var msg []byte
		msg = appendStringField(msg, 1, code)
		for _, r := range entries[code] {
			if r.Type != "IP-CIDR" && r.Type != "IP-CIDR6" {
				continue
			}
			pfx, err := netip.ParsePrefix(r.Value)
			if err != nil {
				continue
			}
			var c []byte
			c = appendBytesField(c, 1, pfx.Addr().AsSlice())
			c = appendVarintField(c, 2, uint64(pfx.Bits()))
			msg = appendBytesField(msg, 2, c)
		}
		buf = appendBytesField(buf, 1, msg)
	}
	return os.WriteFile(path, buf, 0o644)
}
