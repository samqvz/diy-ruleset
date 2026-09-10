package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"diy-ruleset/core"
)

func main() {
	fmt.Println("🚀 启动 DIY-Ruleset 构建引擎...")

	_ = os.RemoveAll("publish")
	_ = os.RemoveAll("process")
	_ = os.RemoveAll("temp")

	defer os.RemoveAll("process")
	defer os.RemoveAll("temp")

	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		fmt.Println("⚠️ 未检测到 config.yaml；正在使用 config-example.yaml 初始化默认配置...")
		exampleData, err := os.ReadFile("config-example.yaml")
		if err != nil {
			log.Fatalf("❌ 未找到配置文件，且 config-example.yaml 也丢失：%v", err)
		}
		if err := os.WriteFile("config.yaml", exampleData, 0644); err != nil {
			log.Fatalf("❌ 无法生成默认配置文件：%v", err)
		}
		fmt.Println("✅ 默认配置文件已生成！请编辑 config.yaml 进行自定义设置。")
	}

	cfg, err := core.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("❌ 加载配置失败：%v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("❌ 配置验证失败：%v", err)
	}

	core.FetchAll(cfg)

	fmt.Println("-----------------------------------")
	allResults := make(map[string]*core.ProcessedResult)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, cat := range cfg.Categories {
		wg.Add(1)

		go func(c core.Category) {
			defer wg.Done()

			res := core.ProcessCategory(c, cfg)

			mu.Lock()
			allResults[c.Name] = res
			mu.Unlock()

			core.ExportFiles(c, res, cfg, false)
		}(cat)
	}

	wg.Wait()

	fmt.Println("-----------------------------------")

	core.CompileAll(cfg)

	core.GenerateReport(allResults, cfg)

	_ = os.RemoveAll("process")
	_ = os.RemoveAll("temp")

	fmt.Println("🎉 规则集构建成功，所有任务已完成！")
}
