package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	httpTimeout    = 30 * time.Second
	fetchRetries   = 3
	fetchRetryGap  = 2 * time.Second
	maxFetchWorker = 30
)

// fetchTarget 是一次待下载的"上游 → 本地槽位文件"映射。
type fetchTarget struct {
	label string // 失败清单中的来源标签（普通上游为 category 名，剔除为 Remove-<category>）
	url   string
	dest  string
}

// FetchAll 并发拉取所有上游规则文件到 temp/raw，并做二进制格式（.srs/.mrs/.json）预处理。
// 单个上游失败不会中断整体流程，仅汇总告警。
// store 用于把 pick 选中的 geo/mmdb 标签物化为规则集（合并进同名 category 或新建 category）。
func FetchAll(cfg *Config, store *GeoDataStore) {
	_ = os.RemoveAll("temp/raw")
	if err := os.MkdirAll("temp/raw", 0o755); err != nil {
		fmt.Printf("❌ 无法创建临时目录 temp/raw: %v\n", err)
		return
	}

	// 物化 pick 标签：写规则到 temp/raw，合并/新建 category。
	materializePickCategories(cfg, store)

	// 物化 categories.upstreams 里的 Geo 标签引用（geosite:/geoip:/asn:）：同样把规则写进
	// temp/raw 并把 url 改写为 geopick: 虚拟上游形态（下载阶段据此跳过）。
	// 必须在这里完成——紧随其后就是并发下载与并发 ProcessCategory，对 cfg 的写入不能与并发读重叠。
	materializeGeoRefUpstreams(cfg, store)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxFetchWorker)
	client := &http.Client{Timeout: httpTimeout}

	var failedURLs []string
	var failMu sync.Mutex

	download := func(t fetchTarget) {
		if err := downloadWithRetry(client, t.url, t.dest, fetchRetries); err != nil {
			failMu.Lock()
			failedURLs = append(failedURLs, fmt.Sprintf("[%s] %s", t.label, t.url))
			failMu.Unlock()
		}
	}

	// 上游与剔除列表走**同一条**下载路径：两处若各写一份 goroutine + 信号量 + 计数
	// 闭包，任一处改动（如跳过判定）都会产生不对称行为。
	for _, cat := range cfg.Categories {
		var targets []fetchTarget
		for i, up := range cat.Upstreams {
			// 虚拟上游（已物化的 geopick: 形态，或未命中标签的 geo 标签引用）规则已在
			// temp/raw 就位，不能当真实 URL 下载——否则会把"引用了不存在的标签"
			// 误报成"下载失败"。判定收敛在 isVirtualUpstream 一处。
			if up.URL == "" || isVirtualUpstream(up.URL) {
				continue
			}
			targets = append(targets, fetchTarget{
				label: cat.Name,
				url:   up.URL,
				dest:  fmt.Sprintf("%s/%s_%d.txt", "temp/raw", cat.Name, i+1),
			})
		}
		for i, rmUp := range cat.RemoveURLs {
			// 与上游同一契约：虚拟上游（geopick: 形态或 geo 标签引用）不是可下载地址。
			// remove 侧目前无物化路径，但用户若把引用写进 remove_urls，这里必须同样跳过，
			// 否则会出现"上游跳过、剔除却当真实 URL 下载"的不对称行为与误导性失败清单。
			if rmUp.URL == "" || isVirtualUpstream(rmUp.URL) {
				continue
			}
			targets = append(targets, fetchTarget{
				label: "Remove-" + cat.Name,
				url:   rmUp.URL,
				dest:  fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cat.Name, i+1),
			})
		}
		for _, t := range targets {
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				download(t)
			})
		}
	}
	wg.Wait()

	if len(failedURLs) > 0 {
		fmt.Println("\n================ ⚠️ 警告 ================")
		fmt.Printf("有 %d 个上游文件下载失败：\n", len(failedURLs))
		for _, u := range failedURLs {
			fmt.Println(" -", u)
		}
		fmt.Println("=========================================")
	} else {
		fmt.Println("✅ 所有上游规则文件已成功下载并完成预处理。")
	}
}

// downloadWithRetry 带重试地下载单个 URL；重试耗尽后返回最后一次的错误。
// 成功时不返回错误，失败时清理残留文件由 downloadOnce 负责。
func downloadWithRetry(client *http.Client, url, dest string, retries int) error {
	var lastErr error
	for attempt := range retries {
		if attempt > 0 {
			time.Sleep(fetchRetryGap)
		}
		if err := downloadOnce(client, url, dest); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("重试 %d 次后仍失败: %w", retries, lastErr)
}

// downloadOnce 执行一次下载 + 二进制预处理。任何环节失败都会清理目标文件。
// 返回的 error 只用于诊断（调用方按"重试 N 次后计入失败清单"处置），
// 因此这里为每个失败分支补上上下文（URL / 目标路径 / HTTP 状态）。
func downloadOnce(client *http.Client, url, dest string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("无效的上游 URL: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("无法创建目标文件 [%s]: %w", dest, err)
	}
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("下载不完整（已移除损坏文件 [%s]）: %w", dest, errors.Join(copyErr, closeErr))
	}

	if err := postProcessBinary(url, dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("二进制预处理失败: %w", err)
	}
	return nil
}

// postProcessBinary 根据扩展名把二进制规则集转换为可解析的文本。
func postProcessBinary(url string, dest string) error {
	lowerURL := strings.ToLower(url)
	switch {
	case strings.HasSuffix(lowerURL, ".srs"):
		return decodeSRS(dest)
	case strings.HasSuffix(lowerURL, ".mrs"):
		return decodeMRS(dest)
	case strings.HasSuffix(lowerURL, ".json"):
		return convertSingboxJSONToText(dest, dest)
	default:
		return nil
	}
}

// decodeSRS 用 sing-box 反编译 .srs 为 JSON，再转为文本规则。
func decodeSRS(dest string) error {
	srsPath := dest + ".srs"
	jsonPath := dest + ".json"

	_ = os.Rename(dest, srsPath)
	defer os.Remove(srsPath)
	defer os.Remove(jsonPath)

	if err := runCore("sing-box", coreCmdTimeout, "rule-set", "decompile", srsPath, "-o", jsonPath); err != nil {
		return fmt.Errorf("sing-box 反编译失败: %w", err)
	}
	return convertSingboxJSONToText(jsonPath, dest)
}

// convertSingboxJSONToText 把 sing-box rule-set JSON 转为 Clash 风格文本行。
//
// 已知键按固定顺序遍历，保证输出稳定（下游解析为集合，顺序不影响最终结果）。
func convertSingboxJSONToText(srcPath string, destPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	var rs SingboxRuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("解析 JSON 失败: %w", err)
	}

	// sing-box 键 -> Clash 类型前缀
	keyToType := []struct {
		key    string
		prefix string
	}{
		{"domain", "DOMAIN"},
		{"domain_suffix", "DOMAIN-SUFFIX"},
		{"domain_keyword", "DOMAIN-KEYWORD"},
		{"domain_regex", "DOMAIN-REGEX"},
		{"process_name", "PROCESS-NAME"},
		{"process_path", "PROCESS-PATH"},
		{"port", "DST-PORT"},
		{"ip_cidr", ""}, // 前缀按地址族动态判定
	}

	var lines []string
	for _, rule := range rs.Rules {
		for _, kt := range keyToType {
			val, ok := rule[kt.key]
			if !ok {
				continue
			}
			emit := func(item string) {
				prefix := kt.prefix
				if kt.key == "ip_cidr" {
					if strings.Contains(item, ":") {
						prefix = "IP-CIDR6"
					} else {
						prefix = "IP-CIDR"
					}
				}
				lines = append(lines, fmt.Sprintf("%s,%s", prefix, item))
			}
			switch v := val.(type) {
			case []any:
				for _, item := range v {
					emit(fmt.Sprintf("%v", item))
				}
			case string:
				emit(v)
			default:
				emit(fmt.Sprintf("%v", v))
			}
		}
	}

	return os.WriteFile(destPath, []byte(strings.Join(lines, "\n")), 0o644)
}

// decodeMRS 用 mihomo 反编译 .mrs；先按 domain 尝试，再回退 ipcidr。
func decodeMRS(dest string) error {
	mrsPath := dest + ".mrs"

	_ = os.Rename(dest, mrsPath)
	defer os.Remove(mrsPath)

	if err := runCore("mihomo", coreCmdTimeout, "convert-ruleset", "domain", "mrs", mrsPath, dest); err == nil {
		if info, statErr := os.Stat(dest); statErr == nil && info.Size() > 0 {
			return nil
		}
	}

	if err := runCore("mihomo", coreCmdTimeout, "convert-ruleset", "ipcidr", "mrs", mrsPath, dest); err != nil {
		return fmt.Errorf("mihomo 反编译失败: %w", err)
	}
	return nil
}
