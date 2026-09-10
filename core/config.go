package core

import (
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
	EnableGhProxy bool    `yaml:"enable_gh_proxy"`
	GhProxy       string  `yaml:"gh_proxy"`
	SplitCNIP     bool    `yaml:"split_cnip"`

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

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func resolveVal[T any](catVal *T, globalVal T) T {
	if catVal != nil {
		return *catVal
	}
	return globalVal
}

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

func ResolveClients(global GlobalConfig, cat Category) ResolvedClientConfig {
	res := ResolvedClientConfig{
		Singbox: global.Singbox, Mihomo: global.Mihomo, V2ray: global.V2ray,
		Surge: global.Surge, Shadowrocket: global.Shadowrocket, QuantumultX: global.QuantumultX,
		Loon: global.Loon, Stash: global.Stash, Egern: global.Egern,
	}

	if cat.Singbox != nil {
		res.Singbox.Enable = resolveVal(cat.Singbox.Enable, global.Singbox.Enable)
		res.Singbox.SingleFile = resolveVal(cat.Singbox.SingleFile, global.Singbox.SingleFile)
		res.Singbox.JSON = resolveVal(cat.Singbox.JSON, global.Singbox.JSON)
		res.Singbox.SRS = resolveVal(cat.Singbox.SRS, global.Singbox.SRS)
	}
	if cat.Mihomo != nil {
		res.Mihomo.Enable = resolveVal(cat.Mihomo.Enable, global.Mihomo.Enable)
		res.Mihomo.SingleFile = resolveVal(cat.Mihomo.SingleFile, global.Mihomo.SingleFile)
		res.Mihomo.YAML = resolveVal(cat.Mihomo.YAML, global.Mihomo.YAML)
		res.Mihomo.MRS = resolveVal(cat.Mihomo.MRS, global.Mihomo.MRS)
		res.Mihomo.TXT = resolveVal(cat.Mihomo.TXT, global.Mihomo.TXT)
	}
	if cat.V2ray != nil {
		res.V2ray.Enable = resolveVal(cat.V2ray.Enable, global.V2ray.Enable)
		res.V2ray.SingleFile = resolveVal(cat.V2ray.SingleFile, global.V2ray.SingleFile)
	}
	if cat.Surge != nil {
		res.Surge.Enable = resolveVal(cat.Surge.Enable, global.Surge.Enable)
		res.Surge.SingleFile = resolveVal(cat.Surge.SingleFile, global.Surge.SingleFile)
	}
	if cat.Shadowrocket != nil {
		res.Shadowrocket.Enable = resolveVal(cat.Shadowrocket.Enable, global.Shadowrocket.Enable)
		res.Shadowrocket.SingleFile = resolveVal(cat.Shadowrocket.SingleFile, global.Shadowrocket.SingleFile)
	}
	if cat.QuantumultX != nil {
		res.QuantumultX.Enable = resolveVal(cat.QuantumultX.Enable, global.QuantumultX.Enable)
		res.QuantumultX.SingleFile = resolveVal(cat.QuantumultX.SingleFile, global.QuantumultX.SingleFile)
	}
	if cat.Loon != nil {
		res.Loon.Enable = resolveVal(cat.Loon.Enable, global.Loon.Enable)
		res.Loon.SingleFile = resolveVal(cat.Loon.SingleFile, global.Loon.SingleFile)
	}
	if cat.Stash != nil {
		res.Stash.Enable = resolveVal(cat.Stash.Enable, global.Stash.Enable)
		res.Stash.SingleFile = resolveVal(cat.Stash.SingleFile, global.Stash.SingleFile)
	}
	if cat.Egern != nil {
		res.Egern.Enable = resolveVal(cat.Egern.Enable, global.Egern.Enable)
		res.Egern.SingleFile = resolveVal(cat.Egern.SingleFile, global.Egern.SingleFile)
	}
	return res
}

func (cfg *Config) Validate() error {
	if len(cfg.Categories) == 0 {
		return fmt.Errorf("❌ 规则集 (categories) 列表不能为空")
	}

	validParsers := map[string]bool{
		"clash": true, "v2ray": true, "adblock": true,
		"hosts": true, "dnsmasq": true, "smartdns": true, "white": true,
		"surge": true, "shadowrocket": true, "quantumultx": true, "loon": true,
		"stash": true, "egern": true,
	}

	catNames := make(map[string]bool)

	for i, cat := range cfg.Categories {
		name := strings.TrimSpace(cat.Name)
		if name == "" {
			return fmt.Errorf("❌ 索引为 %d 的规则集缺少 name 属性", i+1)
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
			if up.Parser != "" && !validParsers[up.Parser] {
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