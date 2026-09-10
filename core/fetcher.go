package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func FetchAll(cfg *Config) {
	os.RemoveAll("temp/raw")
	os.MkdirAll("temp/raw", 0755)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	client := &http.Client{Timeout: 30 * time.Second}

	var failedURLs []string
	var failMu sync.Mutex

	for _, cat := range cfg.Categories {
		for i, up := range cat.Upstreams {
			if up.URL == "" {
				continue
			}
			wg.Add(1)
			go func(cName string, idx int, u Upstream) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				dest := fmt.Sprintf("%s/%s_%d.txt", "temp/raw", cName, idx+1)
				if !downloadWithRetry(client, u.URL, dest, 3) {
					failMu.Lock()
					failedURLs = append(failedURLs, fmt.Sprintf("[%s] %s", cName, u.URL))
					failMu.Unlock()
				}
			}(cat.Name, i, up)
		}

		for i, rmUp := range cat.RemoveURLs {
			if rmUp.URL == "" {
				continue
			}
			wg.Add(1)
			go func(cName string, idx int, url string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				dest := fmt.Sprintf("%s/rm_%s_%d.txt", "temp/raw", cName, idx+1)
				if !downloadWithRetry(client, url, dest, 3) {
					failMu.Lock()
					failedURLs = append(failedURLs, fmt.Sprintf("[Remove-%s] %s", cName, url))
					failMu.Unlock()
				}
			}(cat.Name, i, rmUp.URL)
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

func downloadWithRetry(client *http.Client, url, dest string, retries int) bool {
	for i := 0; i < retries; i++ {
		success := func() bool {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				req.Header.Set("Authorization", "token "+token)
			}

			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				out, err := os.Create(dest)
				if err != nil {
					return false
				}

				_, err = io.Copy(out, resp.Body)
				out.Close()

				if err == nil {
					if err := postProcessBinary(url, dest); err != nil {
						fmt.Printf("⚠️ 警告：处理二进制文件失败 [%s]: %v\n", url, err)
						os.Remove(dest)
						return false
					}
					return true
				}

				os.Remove(dest)
				fmt.Printf("⚠️ 警告：%s 下载不完整，已移除损坏的文件。\n", url)
			}
			return false
		}()
		if success {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func postProcessBinary(url string, dest string) error {
	lowerURL := strings.ToLower(url)

	if strings.HasSuffix(lowerURL, ".srs") {
		return decodeSRS(dest)
	}
	if strings.HasSuffix(lowerURL, ".mrs") {
		return decodeMRS(dest)
	}
	if strings.HasSuffix(lowerURL, ".json") {
		return convertSingboxJSONToText(dest, dest)
	}

	return nil
}

func decodeSRS(dest string) error {
	srsPath := dest + ".srs"
	jsonPath := dest + ".json"

	_ = os.Rename(dest, srsPath)
	defer os.Remove(srsPath)
	defer os.Remove(jsonPath)

	if err := exec.Command(GetExecPath("sing-box"), "rule-set", "decompile", srsPath, "-o", jsonPath).Run(); err != nil {
		return fmt.Errorf("sing-box 反编译失败: %v", err)
	}

	return convertSingboxJSONToText(jsonPath, dest)
}

func convertSingboxJSONToText(srcPath string, destPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	var rs SingboxRuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return fmt.Errorf("解析 JSON 失败: %v", err)
	}

	var lines []string
	for _, rule := range rs.Rules {
		for key, val := range rule {
			clashPrefix := ""
			switch key {
			case "domain":
				clashPrefix = "DOMAIN"
			case "domain_suffix":
				clashPrefix = "DOMAIN-SUFFIX"
			case "domain_keyword":
				clashPrefix = "DOMAIN-KEYWORD"
			case "domain_regex":
				clashPrefix = "DOMAIN-REGEX"
			case "process_name":
				clashPrefix = "PROCESS-NAME"
			case "process_path":
				clashPrefix = "PROCESS-PATH"
			case "port":
				clashPrefix = "DST-PORT"
			}

			if clashPrefix != "" || key == "ip_cidr" {
				switch v := val.(type) {
				case []any:
					for _, item := range v {
						itemStr := fmt.Sprintf("%v", item)
						finalPrefix := clashPrefix

						if key == "ip_cidr" {
							if strings.Contains(itemStr, ":") {
								finalPrefix = "IP-CIDR6"
							} else {
								finalPrefix = "IP-CIDR"
							}
						}
						lines = append(lines, fmt.Sprintf("%s,%s", finalPrefix, itemStr))
					}
				case string:
					finalPrefix := clashPrefix
					if key == "ip_cidr" {
						if strings.Contains(v, ":") {
							finalPrefix = "IP-CIDR6"
						} else {
							finalPrefix = "IP-CIDR"
						}
					}
					lines = append(lines, fmt.Sprintf("%s,%s", finalPrefix, v))
				default:
					lines = append(lines, fmt.Sprintf("%s,%v", clashPrefix, v))
				}
			}
		}
	}

	return os.WriteFile(destPath, []byte(strings.Join(lines, "\n")), 0644)
}

func decodeMRS(dest string) error {
	mrsPath := dest + ".mrs"

	_ = os.Rename(dest, mrsPath)
	defer os.Remove(mrsPath)

	err := exec.Command(GetExecPath("mihomo"), "convert-ruleset", "domain", "mrs", mrsPath, dest).Run()
	if err == nil {
		if info, e := os.Stat(dest); e == nil && info.Size() > 0 {
			return nil
		}
	}

	err = exec.Command(GetExecPath("mihomo"), "convert-ruleset", "ipcidr", "mrs", mrsPath, dest).Run()
	if err != nil {
		return fmt.Errorf("mihomo 反编译失败: %v", err)
	}

	return nil
}
