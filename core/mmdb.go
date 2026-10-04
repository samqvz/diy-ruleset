package core

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// ---- MMDB 数据（country.mmdb）：mmdb 读写 ----

// LoadMMDB 读取 mmdb 文件，返回 "标签 -> IP-CIDR 规则" 映射。
// 兼容三种记录：tags 数组（自定义）、GeoLite2-ASN（autonomous_system_number）、
// GeoLite2-Country（country.iso_code，如 CN / PRIVATE / CLOUDFLARE）。
func LoadMMDB(path string) (map[string][]Rule, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	out := make(map[string][]Rule)
	for result := range reader.Networks() {
		if result.Err() != nil {
			return nil, result.Err()
		}
		var rec struct {
			Tags    []string `maxminddb:"tags"`
			Number  uint32   `maxminddb:"autonomous_system_number"`
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := result.Decode(&rec); err != nil {
			return nil, err
		}
		tags := rec.Tags
		if len(tags) == 0 && rec.Number != 0 {
			tags = []string{fmt.Sprintf("AS%d", rec.Number)}
		}
		if len(tags) == 0 && rec.Country.ISOCode != "" {
			tags = []string{rec.Country.ISOCode}
		}
		if len(tags) == 0 {
			continue
		}
		rule := mmdbPrefixToRule(result.Prefix())
		for _, tag := range tags {
			out[tag] = append(out[tag], rule)
		}
	}
	return out, nil
}

// mmdbPrefixToRule 把 maxminddb 的 netip.Prefix 归一化为内部 IP-CIDR 规则，
// 兼容 v4 网络被存入 IPv6 树时产生的 IPv4-mapped 形式。
func mmdbPrefixToRule(pfx netip.Prefix) Rule {
	addr := pfx.Addr()
	bits := pfx.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Is4() {
		return Rule{Type: "IP-CIDR", Value: netip.PrefixFrom(addr, bits).String()}
	}
	return Rule{Type: "IP-CIDR6", Value: netip.PrefixFrom(addr, bits).String()}
}

// WriteMMDB 把 "标签 -> IP-CIDR 规则" 写为 mmdb 文件（MaxMind mmdb 格式）。
//
// onlyASN=true 时仅写 ASN 标签（记录用 GeoLite2-ASN 兼容的 autonomous_system_number）；
// 否则写所有标签（记录用 tags 数组，含国家码 / ASN / category 组，与 geoip.dat 一致）。
//
// 注意：一个 IP 可能同时属于多个标签（如既在国家 "cn" 又在 AS "13335"），
// 因此非 onlyASN 模式会把 "标签->IP" 反转为 "IP->标签集合"，用 tags 数组表达。
func WriteMMDB(path string, entries map[string][]Rule, onlyASN bool) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "DIY-Ruleset-MMDB",
		RecordSize:              24,
		IPVersion:               6,
		IncludeReservedNetworks: true, // 允许写入 0.0.0.0/8 等保留网段（private/lan 规则集需要）
	})
	if err != nil {
		return err
	}

	if onlyASN {
		for _, tag := range slices.Sorted(maps.Keys(entries)) {
			asnNum, ok := parseASNTag(tag)
			if !ok {
				continue
			}
			rec := mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(asnNum)}
			for _, r := range entries[tag] {
				ipNet, ok := parseIPNet(r.Value)
				if !ok {
					continue
				}
				if err := tree.Insert(ipNet, rec); err != nil {
					return fmt.Errorf("插入网段 %s 失败: %w", r.Value, err)
				}
			}
		}
	} else {
		ipTags := invertIPTags(entries)
		for _, ip := range slices.Sorted(maps.Keys(ipTags)) {
			tags := ipTags[ip]
			sort.Strings(tags)
			ipNet, ok := parseIPNet(ip)
			if !ok {
				continue
			}
			rec := mmdbtype.Map{"tags": toMmdbSlice(tags)}
			if err := tree.Insert(ipNet, rec); err != nil {
				return fmt.Errorf("插入网段 %s 失败: %w", ip, err)
			}
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		return fmt.Errorf("写入 mmdb 失败: %w", err)
	}
	return nil
}

// parseIPNet 解析 CIDR 为 net.IPNet，并把 IPv4-mapped IPv6 前缀解映射为 IPv4。
// mmdbwriter 会拒绝 aliased 网络（::ffff:x.x.x.x），故需先解映射。
func parseIPNet(cidr string) (*net.IPNet, bool) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, false
	}
	addr := pfx.Addr()
	bits := pfx.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	if !addr.IsValid() || bits < 0 {
		return nil, false
	}
	return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, addr.BitLen())}, true
}

// invertIPTags 把 "标签 -> IP 规则" 反转为 "IP 前缀 -> 标签集合"。
func invertIPTags(entries map[string][]Rule) map[string][]string {
	ipTags := make(map[string][]string)
	for tag, rules := range entries {
		for _, r := range rules {
			if r.Type != "IP-CIDR" && r.Type != "IP-CIDR6" {
				continue
			}
			if _, err := netip.ParsePrefix(r.Value); err != nil {
				continue
			}
			ipTags[r.Value] = append(ipTags[r.Value], tag)
		}
	}
	return ipTags
}

// toMmdbSlice 把字符串切片转为 mmdb 的 Slice 类型。
func toMmdbSlice(tags []string) mmdbtype.Slice {
	s := make(mmdbtype.Slice, 0, len(tags))
	for _, t := range tags {
		s = append(s, mmdbtype.String(t))
	}
	return s
}

// parseASNTag 解析 "AS12345" 或 "12345"，返回 ASN 数字。
func parseASNTag(tag string) (uint32, bool) {
	s := strings.TrimSpace(tag)
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}
