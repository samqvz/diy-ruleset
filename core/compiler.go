package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// coreCmdTimeout 是调用外部内核（sing-box / mihomo）的超时上限
const coreCmdTimeout = 5 * time.Minute

// CompileAll 调用 sing-box / mihomo 内核把 JSON/TXT 编译为 .srs / .mrs 二进制。
func CompileAll(cfg *Config) {
	needSRS, needMRS := false, false
	for _, cat := range cfg.Categories {
		out := ResolveClients(cfg.Global, cat)
		needSRS = needSRS || out.Singbox.SRS
		needMRS = needMRS || out.Mihomo.MRS
	}

	hasSingbox := needSRS && commandAvailable("sing-box")
	hasMihomo := needMRS && commandAvailable("mihomo")

	if needSRS && !hasSingbox {
		fmt.Println("⚠️ 未检测到 sing-box 内核或 SRS 输出已关闭，跳过 .srs 编译。")
	}
	if needMRS && !hasMihomo {
		fmt.Println("⚠️ 未检测到 mihomo 内核或 MRS 输出已关闭，跳过 .mrs 编译。")
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	// 收集编译的规则集名（去重），用于统计规则集数。
	ruleSets := make(map[string]bool)
	record := func(name string) {
		name = strings.TrimSuffix(name, "_ip")
		name = strings.TrimPrefix(name, "cnip_")
		ruleSets[name] = true
	}

	compile := func(bin string, args []string, label, srcFile string) {
		sem <- struct{}{}
		defer func() { <-sem }()
		if err := runCore(bin, coreCmdTimeout, args...); err != nil {
			fmt.Printf("❌ 编译失败 (%s)：%s (%v)\n", label, srcFile, err)
		}
	}

	if hasSingbox {
		for _, file := range globOrEmpty("process", "srs_*.json") {
			baseName := strings.TrimPrefix(filepath.Base(file), "srs_")
			outName := strings.TrimSuffix(baseName, ".json") + ".srs"
			outDir := "publish/singbox"

			if strings.HasPrefix(baseName, "cnip_") {
				outDir = "publish/cnip"
				outName = strings.TrimPrefix(outName, "cnip_")
			}
			outPath := filepath.Join(outDir, outName)
			record(strings.TrimSuffix(baseName, ".json"))

			wg.Go(func() { compile("sing-box", []string{"rule-set", "compile", file, "-o", outPath}, "sing-box", file) })
		}
	}

	if hasMihomo {
		for _, file := range globOrEmpty("process", "*_mihomo_domain.txt") {
			catName := strings.TrimSuffix(filepath.Base(file), "_mihomo_domain.txt")
			outFile := fmt.Sprintf("%s/%s.mrs", "publish/mihomo", catName)
			record(catName)

			wg.Go(func() {
				compile("mihomo", []string{"convert-ruleset", "domain", "text", file, outFile}, "mihomo domain", file)
			})
		}

		for _, file := range globOrEmpty("process", "*_mihomo_ip.txt") {
			catName := strings.TrimSuffix(filepath.Base(file), "_mihomo_ip.txt")
			outDir := "publish/mihomo"
			outFile := fmt.Sprintf("%s/%s_ip.mrs", outDir, catName)
			if strings.HasPrefix(catName, "cnip_") {
				outFile = fmt.Sprintf("%s/%s.mrs", "publish/cnip", strings.TrimPrefix(catName, "cnip_"))
			}
			record(catName)

			wg.Go(func() {
				compile("mihomo", []string{"convert-ruleset", "ipcidr", "text", file, outFile}, "mihomo ipcidr", file)
			})
		}
	}
	wg.Wait()

	if len(ruleSets) > 0 {
		fmt.Printf("✅ 已完成编译 SRS/MRS 二进制文件（%d 个规则集）\n", len(ruleSets))
	}
}

// globOrEmpty 是 filepath.Glob 的安全封装：忽略错误，返回空切片。
func globOrEmpty(dir, pattern string) []string {
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil
	}
	return files
}

// runCore 以超时方式执行外部内核命令。
func runCore(name string, timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, GetExecPath(name), args...).Run()
}

// execName 根据运行平台补全可执行文件后缀。
func execName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// GetExecPath 优先返回工作目录下的内核，其次返回 PATH 中的可执行文件路径。
func GetExecPath(name string) string {
	exeName := execName(name)
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

// commandAvailable 判断内核是否可在当前环境调用。
func commandAvailable(name string) bool {
	if _, err := os.Stat(execName(name)); err == nil {
		return true
	}
	_, err := exec.LookPath(execName(name))
	return err == nil
}
