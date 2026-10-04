package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"diy-ruleset/core"
)

const (
	publishDir = "publish"
	processDir = "process"
	tempDir    = "temp"
)

func main() {
	fmt.Println("🚀 启动 DIY-Ruleset 构建引擎...")
	if err := run(); err != nil {
		// log.Fatal 会跳过 defer，这里显式清理中间目录，避免残留临时文件。
		_ = os.RemoveAll(processDir)
		_ = os.RemoveAll(tempDir)
		log.Fatalf("❌ %v", err)
	}
	fmt.Println("🎉 规则集构建成功，所有任务已完成！")
}

// run 承载主流程，统一以 error 返回失败原因，保证清理逻辑只写一处。
func run() error {
	if err := ensureConfig(); err != nil {
		return err
	}

	cfg, err := core.LoadConfig("config.yaml")
	if err != nil {
		return fmt.Errorf("加载配置失败：%w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置验证失败：%w", err)
	}

	// 每次构建前清空工作目录，避免陈旧产物污染结果。
	for _, dir := range []string{publishDir, processDir, tempDir} {
		_ = os.RemoveAll(dir)
	}
	defer func() {
		_ = os.RemoveAll(processDir)
		_ = os.RemoveAll(tempDir)
	}()

	// 构建 geo/asn 数据（读取输入、应用定制、必要时拉取 ASN 网段）。
	geoData := core.BuildGeoData(cfg)

	core.FetchAll(cfg, geoData)

	fmt.Println("-----------------------------------")
	allResults := make(map[string]*core.ProcessedResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 每个规则集独立处理与导出；ProcessCategory 只操作各自的局部状态，
	// 共享的只有线程安全的正则缓存，因此并发安全。
	for _, cat := range cfg.Categories {
		wg.Go(func() {
			res := core.ProcessCategory(cat, cfg)

			mu.Lock()
			allResults[cat.Name] = res
			mu.Unlock()

			core.ExportFiles(cat, res, cfg, false)
		})
	}
	wg.Wait()

	fmt.Println("-----------------------------------")

	core.CompileAll(cfg)
	asnRuleCount := core.ExportGeoData(cfg, geoData, allResults)
	core.GenerateReport(allResults, cfg, asnRuleCount)
	return nil
}

// ensureConfig 在缺少 config.yaml 时用示例配置初始化一份。
func ensureConfig() error {
	if _, err := os.Stat("config.yaml"); !os.IsNotExist(err) {
		return nil
	}
	fmt.Println("⚠️ 未检测到 config.yaml；正在使用 config-example.yaml 初始化默认配置...")
	exampleData, err := os.ReadFile("config-example.yaml")
	if err != nil {
		return fmt.Errorf("未找到配置文件，且 config-example.yaml 也丢失：%w", err)
	}
	if err := os.WriteFile("config.yaml", exampleData, 0o644); err != nil {
		return fmt.Errorf("无法生成默认配置文件：%w", err)
	}
	fmt.Println("✅ 默认配置文件已生成！请编辑 config.yaml 进行自定义设置。")
	return nil
}
