package core

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Global     GlobalConfig `yaml:"global"`
	Categories []Category   `yaml:"categories"`
}

type GlobalConfig struct {
	EnableGhProxy GhProxyConfig `yaml:"enable_gh_proxy"`
	SplitCNIP     bool          `yaml:"split_cnip"`

	Geodata GeodataConfig `yaml:"geodata"`

	Singbox      SingboxOutput `yaml:"singbox"`
	Mihomo       MihomoOutput  `yaml:"mihomo"`
	V2ray        V2rayOutput   `yaml:"v2ray"`
	Surge        AppleOutput   `yaml:"surge"`
	Shadowrocket AppleOutput   `yaml:"shadowrocket"`
	QuantumultX  AppleOutput   `yaml:"quantumultx"`
	Loon         AppleOutput   `yaml:"loon"`
	Stash        AppleOutput   `yaml:"stash"`
	Egern        AppleOutput   `yaml:"egern"`
}

type GhProxyConfig struct {
	Enable bool   `yaml:"enable"`
	URL    string `yaml:"gh_proxy"`
}

type GeodataConfig struct {
	GeoSite GeoOutput `yaml:"geosite"`
	GeoIP   GeoOutput `yaml:"geoip"`
	MMDB    GeoOutput `yaml:"mmdb"`
}

type GeoOutput struct {
	Enable    bool     `yaml:"enable"`
	Upstreams []string `yaml:"upstreams"`
	Pick      []string `yaml:"pick"`
	Exclude   []string `yaml:"exclude"`
}

type SingboxOutput struct {
	Enable     bool `yaml:"enable"`
	SingleFile bool `yaml:"single_file"`
	JSON       bool `yaml:"json"`
	SRS        bool `yaml:"srs"`
}

type CatSingboxOutput struct {
	Enable     *bool `yaml:"enable"`
	SingleFile *bool `yaml:"single_file"`
	JSON       *bool `yaml:"json"`
	SRS        *bool `yaml:"srs"`
}

type MihomoOutput struct {
	Enable     bool `yaml:"enable"`
	SingleFile bool `yaml:"single_file"`
	YAML       bool `yaml:"yaml"`
	MRS        bool `yaml:"mrs"`
	TXT        bool `yaml:"txt"`
}

type CatMihomoOutput struct {
	Enable     *bool `yaml:"enable"`
	SingleFile *bool `yaml:"single_file"`
	YAML       *bool `yaml:"yaml"`
	MRS        *bool `yaml:"mrs"`
	TXT        *bool `yaml:"txt"`
}

type V2rayOutput struct {
	Enable     bool `yaml:"enable"`
	SingleFile bool `yaml:"single_file"`
}

type CatV2rayOutput struct {
	Enable     *bool `yaml:"enable"`
	SingleFile *bool `yaml:"single_file"`
}

type AppleOutput struct {
	Enable     bool `yaml:"enable"`
	SingleFile bool `yaml:"single_file"`
}

type CatAppleOutput struct {
	Enable     *bool `yaml:"enable"`
	SingleFile *bool `yaml:"single_file"`
}

type Category struct {
	Name             string `yaml:"name"`
	AutoExtractWhite bool   `yaml:"auto_extract_white"`
	PublishWhite     bool   `yaml:"publish_white"`
	WhiteBehavior    string `yaml:"white_behavior"`

	Singbox      *CatSingboxOutput `yaml:"singbox"`
	Mihomo       *CatMihomoOutput  `yaml:"mihomo"`
	V2ray        *CatV2rayOutput   `yaml:"v2ray"`
	Surge        *CatAppleOutput   `yaml:"surge"`
	Shadowrocket *CatAppleOutput   `yaml:"shadowrocket"`
	QuantumultX  *CatAppleOutput   `yaml:"quantumultx"`
	Loon         *CatAppleOutput   `yaml:"loon"`
	Stash        *CatAppleOutput   `yaml:"stash"`
	Egern        *CatAppleOutput   `yaml:"egern"`

	PublishAdblock  bool `yaml:"publish_adblock"`
	PublishDnsmasq  bool `yaml:"publish_dnsmasq"`
	PublishSmartDNS bool `yaml:"publish_smartdns"`

	GeoSite *bool `yaml:"geosite"`
	GeoIP   *bool `yaml:"geoip"`
	MMDB    *bool `yaml:"mmdb"`

	DnsmasqServer  string `yaml:"dnsmasq_server"`
	SmartdnsServer string `yaml:"smartdns_server"`

	MergeFrom  []string   `yaml:"merge_from"`
	RemoveURLs []Upstream `yaml:"remove_urls"`
	Upstreams  []Upstream `yaml:"upstreams"`
}

type Upstream struct {
	URL    string `yaml:"url"`
	Parser string `yaml:"parser"`
}

var knownParsers = map[string]bool{
	"clash": true, "v2ray": true, "adblock": true,
	"hosts": true, "dnsmasq": true, "smartdns": true, "white": true,
	"surge": true, "shadowrocket": true, "quantumultx": true, "loon": true,
	"stash": true, "egern": true,
}

// LoadConfig 读取并反序列化配置文件。
// 使用 KnownFields 严格模式：未知字段（如拼写错误、多嵌套的键）会立即报错，
// 避免配置错误被静默忽略导致功能不生效。
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败：%w", err)
	}
	return &cfg, nil
}

// resolveVal 实现"分组值优先，否则回退全局值"。
func resolveVal[T any](catVal *T, globalVal T) T {
	if catVal != nil {
		return *catVal
	}
	return globalVal
}

// ResolvedClientConfig 是全局 + 分组覆盖后的最终输出配置。
type ResolvedClientConfig struct {
	Singbox      SingboxOutput
	Mihomo       MihomoOutput
	V2ray        V2rayOutput
	Surge        AppleOutput
	Shadowrocket AppleOutput
	QuantumultX  AppleOutput
	Loon         AppleOutput
	Stash        AppleOutput
	Egern        AppleOutput
}

// ResolveClients 把分组配置叠加到全局默认上，得到最终生效的输出开关。
func ResolveClients(global GlobalConfig, cat Category) ResolvedClientConfig {
	res := ResolvedClientConfig{
		Singbox: global.Singbox, Mihomo: global.Mihomo, V2ray: global.V2ray,
		Surge: global.Surge, Shadowrocket: global.Shadowrocket, QuantumultX: global.QuantumultX,
		Loon: global.Loon, Stash: global.Stash, Egern: global.Egern,
	}

	if c := cat.Singbox; c != nil {
		res.Singbox.Enable = resolveVal(c.Enable, global.Singbox.Enable)
		res.Singbox.SingleFile = resolveVal(c.SingleFile, global.Singbox.SingleFile)
		res.Singbox.JSON = resolveVal(c.JSON, global.Singbox.JSON)
		res.Singbox.SRS = resolveVal(c.SRS, global.Singbox.SRS)
	}
	if c := cat.Mihomo; c != nil {
		res.Mihomo.Enable = resolveVal(c.Enable, global.Mihomo.Enable)
		res.Mihomo.SingleFile = resolveVal(c.SingleFile, global.Mihomo.SingleFile)
		res.Mihomo.YAML = resolveVal(c.YAML, global.Mihomo.YAML)
		res.Mihomo.MRS = resolveVal(c.MRS, global.Mihomo.MRS)
		res.Mihomo.TXT = resolveVal(c.TXT, global.Mihomo.TXT)
	}
	if c := cat.V2ray; c != nil {
		res.V2ray.Enable = resolveVal(c.Enable, global.V2ray.Enable)
		res.V2ray.SingleFile = resolveVal(c.SingleFile, global.V2ray.SingleFile)
	}
	if c := cat.Surge; c != nil {
		res.Surge.Enable = resolveVal(c.Enable, global.Surge.Enable)
		res.Surge.SingleFile = resolveVal(c.SingleFile, global.Surge.SingleFile)
	}
	if c := cat.Shadowrocket; c != nil {
		res.Shadowrocket.Enable = resolveVal(c.Enable, global.Shadowrocket.Enable)
		res.Shadowrocket.SingleFile = resolveVal(c.SingleFile, global.Shadowrocket.SingleFile)
	}
	if c := cat.QuantumultX; c != nil {
		res.QuantumultX.Enable = resolveVal(c.Enable, global.QuantumultX.Enable)
		res.QuantumultX.SingleFile = resolveVal(c.SingleFile, global.QuantumultX.SingleFile)
	}
	if c := cat.Loon; c != nil {
		res.Loon.Enable = resolveVal(c.Enable, global.Loon.Enable)
		res.Loon.SingleFile = resolveVal(c.SingleFile, global.Loon.SingleFile)
	}
	if c := cat.Stash; c != nil {
		res.Stash.Enable = resolveVal(c.Enable, global.Stash.Enable)
		res.Stash.SingleFile = resolveVal(c.SingleFile, global.Stash.SingleFile)
	}
	if c := cat.Egern; c != nil {
		res.Egern.Enable = resolveVal(c.Enable, global.Egern.Enable)
		res.Egern.SingleFile = resolveVal(c.SingleFile, global.Egern.SingleFile)
	}
	return res
}

// Validate 校验配置的完整性，尽早暴露错误而非运行到一半才失败。
func (cfg *Config) Validate() error {
	if len(cfg.Categories) == 0 {
		return fmt.Errorf("❌ 规则集 (categories) 列表不能为空")
	}

	catNames := make(map[string]bool, len(cfg.Categories))
	for i, cat := range cfg.Categories {
		name := strings.TrimSpace(cat.Name)
		if name == "" {
			return fmt.Errorf("❌ 索引为 %d 的规则集缺少 name 属性", i+1)
		}
		// name 会参与文件路径拼接（add/<name>.list、publish/...），需防目录穿越。
		if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return fmt.Errorf("❌ 规则集名称 [%s] 含非法字符（不允许路径分隔符或 ..）", name)
		}
		if catNames[name] {
			return fmt.Errorf("❌ 检测到重复的规则集名称: [%s]", name)
		}
		catNames[name] = true

		if cat.WhiteBehavior != "" && cat.WhiteBehavior != "remove" && cat.WhiteBehavior != "extract_only" {
			return fmt.Errorf("❌ [%s] white_behavior 必须是 'remove' 或 'extract_only'", name)
		}

		for j, up := range cat.Upstreams {
			if strings.TrimSpace(up.URL) == "" {
				return fmt.Errorf("❌ [%s] 索引为 %d 的上游缺失 url", name, j+1)
			}
			// Geo 标签引用（geosite:/geoip:/asn:）与内部物化标记（geopick:）必须在校验期判定，
			// 否则错误只能推迟到运行期，表现为"上游文件下载失败"或整条上游静默失效。
			if kind, _, isGeoRef, ok := validateGeoRefUpstream(up.URL); isGeoRef {
				if strings.HasPrefix(strings.TrimSpace(up.URL), geopickPrefix) {
					return fmt.Errorf("❌ [%s] 索引为 %d 的上游 url [%s] 使用了内部物化标记 geopick:，"+
						"它不是公开配置语法；如需引用 Geo 标签请写 geosite:<标签> / geoip:<标签> / asn:<AS号>",
						name, j+1, up.URL)
				}
				if !ok {
					return fmt.Errorf("❌ [%s] 索引为 %d 的上游 url [%s] 的 %s 引用缺少标签；"+
						"正确写法形如 %s:<标签>（如 %s:cn、asn:AS13335）", name, j+1, up.URL, kind, kind, kind)
				}
				if strings.TrimSpace(up.Parser) != "" {
					return fmt.Errorf("❌ [%s] 索引为 %d 的上游 url [%s] 是 %s 标签引用，不能同时指定 parser: %s；"+
						"引用形态的规则由引擎按 Clash 语法写出，parser 在此无意义，请删除该字段",
						name, j+1, up.URL, kind, up.Parser)
				}
			}
			if up.Parser != "" && !knownParsers[up.Parser] {
				return fmt.Errorf("❌ [%s] 索引为 %d 的上游 parser 无效: %s", name, j+1, up.Parser)
			}
		}
	}

	for _, cat := range cfg.Categories {
		for _, mergeTarget := range cat.MergeFrom {
			if !catNames[mergeTarget] {
				return fmt.Errorf("❌ [%s] 试图合并一个不存在的规则集 (merge_from: %s)", cat.Name, mergeTarget)
			}
		}
	}

	return nil
}
