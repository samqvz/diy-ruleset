package core

import (
	"encoding/json"
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

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxFetchWorker)
	client := &http.Client{Timeout: httpTimeout}

	var failedURLs []string
	var failMu sync.Mutex

	download := func(label, url, dest string) {
		if !downloadWithRetry(client, url, dest, fetchRetries) {
			failMu.Lock()
			failedURLs = append(failedURLs, fmt.Sprintf("[%s] %s", label, url))
			failMu.Unlock()
		}
	}

	for _, cat := range cfg.Categories {
		for i, up := range cat.Upstreams {
			if up.URL == "" || strings.HasPrefix(up.URL, geopickPrefix) {
				continue
			}
			dest := fmt.Sprintf("%s/%s_%d.txt", "temp/raw", cat.Name, i+1)
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				download(cat.Name, up.URL, dest)
			})
		}

		for i, rmUp := range cat.RemoveURLs {
			if rmUp.URL == "" {
				continue
			}
			dest := fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cat.Name, i+1)
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				download("Remove-"+cat.Name, rmUp.URL, dest)
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

// downloadWithRetry 带重试地下载单个 URL；失败时清理残留文件并返回 false。
func downloadWithRetry(client *http.Client, url, dest string, retries int) bool {
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			time.Sleep(fetchRetryGap)
		}
		if downloadOnce(client, url, dest) {
			return true
		}
	}
	return false
}

// downloadOnce 执行一次下载 + 二进制预处理。任何环节失败都会清理目标文件。
func downloadOnce(client *http.Client, url, dest string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("⚠️ 无效的上游 URL [%s]: %v\n", url, err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}

	out, err := os.Create(dest)
	if err != nil {
		return false
	}
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dest)
		fmt.Printf("⚠️ 警告：%s 下载不完整，已移除损坏的文件。\n", url)
		return false
	}

	if err := postProcessBinary(url, dest); err != nil {
		fmt.Printf("⚠️ 警告：处理二进制文件失败 [%s]: %v\n", url, err)
		_ = os.Remove(dest)
		return false
	}
	return true
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
