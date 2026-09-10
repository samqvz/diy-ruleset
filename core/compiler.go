package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

func CompileAll(cfg *Config) {
	fmt.Println("📦 正在编译二进制规则集 (SRS/MRS)...")

	needSRS, needMRS := false, false
	for _, cat := range cfg.Categories {
		out := ResolveClients(cfg.Global, cat)
		if out.Singbox.SRS {
			needSRS = true
		}
		if out.Mihomo.MRS {
			needMRS = true
		}
	}

	hasSingbox := checkCommand("sing-box") && needSRS
	hasMihomo := checkCommand("mihomo") && needMRS

	if !hasSingbox && needSRS {
		fmt.Println("⚠️ 未检测到 sing-box 内核或 SRS 输出已关闭，跳过 .srs 编译。")
	}
	if !hasMihomo && needMRS {
		fmt.Println("⚠️ 未检测到 mihomo 内核或 MRS 输出已关闭，跳过 .mrs 编译。")
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	if hasSingbox {
		files, _ := filepath.Glob("process" + "/srs_*.json")

		for _, file := range files {
			wg.Add(1)

			go func(f string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				baseName := strings.TrimPrefix(filepath.Base(f), "srs_")
				outName := strings.TrimSuffix(baseName, ".json") + ".srs"
				outDir := "publish/singbox"

				if strings.HasPrefix(baseName, "cnip_") {
					outDir = "publish/cnip"
					outName = strings.TrimPrefix(outName, "cnip_")
				}

				outPath := filepath.Join(outDir, outName)

				if err := exec.Command(GetExecPath("sing-box"), "rule-set", "compile", f, "-o", outPath).Run(); err != nil {
					fmt.Printf("❌ 编译失败 (sing-box)：%s\n", f)
				}
			}(file)
		}
	}

	if hasMihomo {
		domFiles, _ := filepath.Glob("process" + "/*_mihomo_domain.txt")
		for _, file := range domFiles {
			wg.Add(1)

			go func(f string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				catName := strings.TrimSuffix(filepath.Base(f), "_mihomo_domain.txt")
				outFile := fmt.Sprintf("%s/%s.mrs", "publish/mihomo", catName)
				if err := exec.Command(GetExecPath("mihomo"), "convert-ruleset", "domain", "text", f, outFile).Run(); err != nil {
					fmt.Printf("❌ 编译失败 (mihomo domain)：%s\n", f)
				}
			}(file)
		}

		ipFiles, _ := filepath.Glob("process" + "/*_mihomo_ip.txt")
		for _, file := range ipFiles {
			wg.Add(1)

			go func(f string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				catName := strings.TrimSuffix(filepath.Base(f), "_mihomo_ip.txt")
				outDir := "publish/mihomo"
				outFile := ""
				if strings.HasPrefix(catName, "cnip_") {
					outDir = "publish/cnip"
					outFile = fmt.Sprintf("%s/%s.mrs", outDir, strings.TrimPrefix(catName, "cnip_"))
				} else {
					outFile = fmt.Sprintf("%s/%s_ip.mrs", outDir, catName)
				}
				if err := exec.Command(GetExecPath("mihomo"), "convert-ruleset", "ipcidr", "text", f, outFile).Run(); err != nil {
					fmt.Printf("❌ 编译失败 (mihomo ipcidr)：%s\n", f)
				}
			}(file)
		}
	}
	wg.Wait()
}

func GetExecPath(name string) string {
	exeName := name
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	if _, err := os.Stat(exeName); err == nil {
		if absPath, err := filepath.Abs(exeName); err == nil {
			return absPath
		}
		return "./" + exeName
	}
	if path, err := exec.LookPath(exeName); err == nil {
		return path
	}
	return name
}

func checkCommand(name string) bool {
	exeName := name
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	if _, err := os.Stat(exeName); err == nil {
		return true
	}
	_, err := exec.LookPath(exeName)
	return err == nil
}
