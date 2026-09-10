package core

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

func getFileSize(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "-"
	}
	bytes := info.Size()
	if bytes >= 1048576 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/1048576.0)
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024.0)
	}
	return fmt.Sprintf("%dB", bytes)
}

func getLineCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := strings.Count(string(data), "\n")
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		count++
	}
	return count
}

func extractUpstreamName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Host
	if colonIdx := strings.IndexByte(host, ':'); colonIdx != -1 {
		host = host[:colonIdx]
	}
	host = strings.TrimPrefix(host, "www.")
	fileName := path.Base(u.Path)
	if extIdx := strings.LastIndexByte(fileName, '.'); extIdx != -1 {
		fileName = fileName[:extIdx]
	}
	if host == "raw.githubusercontent.com" || host == "github.com" {
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) >= 1 {
			return parts[0] + "/" + fileName
		}
	}
	return host + "/" + fileName
}

type LinkDef struct {
	Label string
	URL   string
	Size  string
	Show  bool
	Space string
}

func buildLinksCell(proxy string, enableProxy bool, links ...LinkDef) (string, string) {
	var directLinks, proxyLinks []string

	for _, l := range links {
		if l.Show {
			directLinks = append(directLinks, fmt.Sprintf("[%s](%s)%s`%s`", l.Label, l.URL, l.Space, l.Size))
			if enableProxy {
				proxyLinks = append(proxyLinks, fmt.Sprintf("[%s](%s%s)%s`%s`", l.Label, proxy, l.URL, l.Space, l.Size))
			}
		}
	}

	if len(directLinks) == 0 {
		return "-", "-"
	}

	return strings.Join(directLinks, "<br>"), strings.Join(proxyLinks, "<br>")
}

func anyFileExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

type ReportRow struct {
	DisplayName string
	Count       int
	CellDirect  string
	CellProxy   string
}

func renderTableSection(sb *strings.Builder, title string, enableProxy bool, rows []ReportRow) {
	if len(rows) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("### %s\n", title))
	if enableProxy {
		sb.WriteString("| 规&#8288;则&#8288;名&#8288;称 | 规&#8288;则&#8288;数 | 默&#8288;认&#8288;链&#8288;接 | 加&#8288;速&#8288;链&#8288;接 |\n| :--- | :--- | :--- | :--- |\n")
	} else {
		sb.WriteString("| 规&#8288;则&#8288;名&#8288;称 | 规&#8288;则&#8288;数 | 默&#8288;认&#8288;链&#8288;接 |\n| :--- | :--- | :--- |\n")
	}

	for _, row := range rows {
		if enableProxy {
			sb.WriteString(fmt.Sprintf("| **%s** | %d | %s | %s |\n", row.DisplayName, row.Count, row.CellDirect, row.CellProxy))
		} else {
			sb.WriteString(fmt.Sprintf("| **%s** | %d | %s |\n", row.DisplayName, row.Count, row.CellDirect))
		}
	}
	sb.WriteString("\n")
}

func GenerateReport(results map[string]*ProcessedResult, cfg *Config) {
	ghProxy := cfg.Global.GhProxy
	enableProxy := cfg.Global.EnableGhProxy
	const startTag = `<!-- REPORT_START -->`
	const endTag = `<!-- REPORT_END -->`
	var sb strings.Builder

	total := 0
	for _, cat := range cfg.Categories {
		if r, ok := results[cat.Name]; ok {
			total += r.FinalCount
			if cat.PublishWhite {
				total += r.WhiteCount
			}
		}
	}

	sb.WriteString(startTag + "\n")
	sb.WriteString(fmt.Sprintf("**最后更新时间** : %s ( UTC+8 )\n", time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**当前规则总数** : **%d** \n\n", total))
	sb.WriteString("### 自动统计\n")
	sb.WriteString("| 规&#8288;则&#8288;名&#8288;称 | 最&#8288;终&#8288;数&#8288;量 | 原&#8288;始&#8288;总&#8288;数 | 增&#8288;加 | 去&#8288;除 | 去&#8288;重&#8288;率 | 上&#8288;游&#8288;明&#8288;细&nbsp;(&#8288;来&#8288;源/数&#8288;量&#8288;) |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, cat := range cfg.Categories {
		r, ok := results[cat.Name]
		if !ok {
			continue
		}

		baseTotal := r.RawCount + r.AddCount - r.RmCount
		rate := 0.0
		if baseTotal > 0 {
			rate = (1.0 - float64(r.FinalCount)/float64(baseTotal)) * 100
			if rate < 0 {
				rate = 0
			}
		}

		displayName := strings.ReplaceAll(cat.Name, "-", "&#8209;")
		var upDetails []string
		for _, up := range cat.Upstreams {
			if count, exists := r.UpstreamStats[up.URL]; exists && count > 0 {
				extractedName := extractUpstreamName(up.URL)
				upDetails = append(upDetails, fmt.Sprintf("[%s](%s)(%d)", extractedName, up.URL, count))
			}
		}
		for _, mergeCatName := range cat.MergeFrom {
			for _, c := range cfg.Categories {
				if c.Name == mergeCatName {
					for _, up := range c.Upstreams {
						if count, exists := r.UpstreamStats[up.URL]; exists && count > 0 {
							extractedName := extractUpstreamName(up.URL)
							upDetails = append(upDetails, fmt.Sprintf("[%s](%s)(%d)", extractedName, up.URL, count))
						}
					}
				}
			}
		}
		upStr := strings.Join(upDetails, "<br>")
		if upStr == "" {
			upStr = "-"
		}

		sb.WriteString(fmt.Sprintf("| **%s** | %d | %d | %d | %d | %.1f%% | **%s** |\n", displayName, r.FinalCount, r.RawCount, r.AddCount, r.RmCount, rate, upStr))

		if cat.PublishWhite {
			whiteName := cat.Name + "_white"
			displayNameWhite := strings.ReplaceAll(whiteName, "-", "&#8209;")

			if r.WhiteCount > 0 {
				var whiteUpDetails []string
				for _, up := range cat.Upstreams {
					if wCount, exists := r.WhiteUpstreamStats[up.URL]; exists && wCount > 0 {
						extractedName := extractUpstreamName(up.URL)
						whiteUpDetails = append(whiteUpDetails, fmt.Sprintf("[%s](%s)(%d)", extractedName, up.URL, wCount))
					}
				}
				whiteUpStr := strings.Join(whiteUpDetails, "<br>")
				if whiteUpStr == "" {
					whiteUpStr = "-"
				}
				sb.WriteString(fmt.Sprintf("| **%s** | %d | %d | 0 | 0 | 0.0%% | **%s** |\n", displayNameWhite, r.WhiteCount, r.WhiteCount, whiteUpStr))
			}
		}
	}
	sb.WriteString("\n")

	var coreRows []ReportRow

	for _, cat := range cfg.Categories {
		r, ok := results[cat.Name]
		if !ok {
			continue
		}
		catOut := ResolveClients(cfg.Global, cat)

		if !catOut.Singbox.Enable && !catOut.Mihomo.Enable {
			continue
		}

		catName := cat.Name

		renderCoreRow := func(suffix string, rowType string) {
			targetName := catName + suffix
			if rowType == "white" {
				targetName = catName + "_white"
			}
			displayName := strings.ReplaceAll(targetName, "-", "&#8209;")
			sbJson := fmt.Sprintf("publish/singbox/%s.json", targetName)
			sbSrs := fmt.Sprintf("publish/singbox/%s.srs", targetName)
			miTxt := fmt.Sprintf("publish/mihomo/%s.txt", targetName)
			miYaml := fmt.Sprintf("publish/mihomo/%s.yaml", targetName)
			miMrs := fmt.Sprintf("publish/mihomo/%s.mrs", targetName)

			var miMrsIp string
			if rowType == "main" && catOut.Mihomo.SingleFile {
				miMrsIp = fmt.Sprintf("publish/mihomo/%s_ip.mrs", catName)
			}

			hasSb := anyFileExists(sbJson, sbSrs)
			hasMi := anyFileExists(miTxt, miYaml, miMrs) || (miMrsIp != "" && anyFileExists(miMrsIp))

			if !hasSb && !hasMi {
				return
			}

			var count int
			switch rowType {
			case "main":
				if hasSb {
					count = r.ExactCounts["singbox_dom"]
					if catOut.Singbox.SingleFile {
						count = r.ExactCounts["singbox_total"]
					}
				} else {
					count = r.ExactCounts["mihomo_dom"]
					if catOut.Mihomo.SingleFile {
						count = r.ExactCounts["mihomo_total"]
					}
				}
			case "ip":
				if hasSb {
					count = r.ExactCounts["singbox_ip"]
				} else {
					count = r.ExactCounts["mihomo_ip"]
				}
			case "white":
				count = r.WhiteCount
			}

			var links []LinkDef

			if hasSb {
				urlJson := fmt.Sprintf("https://github.com/%s/raw/publish/singbox/%s.json", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlSrs := fmt.Sprintf("https://github.com/%s/raw/publish/singbox/%s.srs", os.Getenv("GITHUB_REPOSITORY"), targetName)
				links = append(links,
					LinkDef{"singbox&#8288;-&#8288;json", urlJson, getFileSize(sbJson), catOut.Singbox.JSON && anyFileExists(sbJson), "&nbsp;&nbsp;"},
					LinkDef{"singbox&#8288;-&#8288;srs", urlSrs, getFileSize(sbSrs), catOut.Singbox.SRS && anyFileExists(sbSrs), "&nbsp;&nbsp;&nbsp;&nbsp;"},
				)
			}

			if hasMi {
				urlTxt := fmt.Sprintf("https://github.com/%s/raw/publish/mihomo/%s.txt", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlYaml := fmt.Sprintf("https://github.com/%s/raw/publish/mihomo/%s.yaml", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlMrs := fmt.Sprintf("https://github.com/%s/raw/publish/mihomo/%s.mrs", os.Getenv("GITHUB_REPOSITORY"), targetName)

				mrsLabel := "mihomo&#8288;-&#8288;mrs"
				if miMrsIp != "" && anyFileExists(miMrsIp) && anyFileExists(miMrs) {
					mrsLabel = "mihomo&#8288;-&#8288;mrs&#8288;(&#8288;domain&#8288;)"
				}

				links = append(links,
					LinkDef{"mihomo&#8288;-&#8288;txt", urlTxt, getFileSize(miTxt), catOut.Mihomo.TXT && anyFileExists(miTxt), "&nbsp;&nbsp;&nbsp;&nbsp;"},
					LinkDef{"mihomo&#8288;-&#8288;yaml", urlYaml, getFileSize(miYaml), catOut.Mihomo.YAML && anyFileExists(miYaml), "&nbsp;"},
					LinkDef{mrsLabel, urlMrs, getFileSize(miMrs), catOut.Mihomo.MRS && anyFileExists(miMrs), "&nbsp;&nbsp;"},
				)

				if miMrsIp != "" && anyFileExists(miMrsIp) {
					urlMrsIp := fmt.Sprintf("https://github.com/%s/raw/publish/mihomo/%s_ip.mrs", os.Getenv("GITHUB_REPOSITORY"), catName)
					links = append(links, LinkDef{"mihomo&#8288;-&#8288;mrs&#8288;(&#8288;ipcidr&#8288;)", urlMrsIp, getFileSize(miMrsIp), catOut.Mihomo.MRS, "&nbsp;&nbsp;"})
				}
			}

			cellDirect, cellProxy := buildLinksCell(ghProxy, enableProxy, links...)
			coreRows = append(coreRows, ReportRow{displayName, count, cellDirect, cellProxy})
		}

		renderCoreRow("", "main")

		if !catOut.Singbox.SingleFile || !catOut.Mihomo.SingleFile {
			renderCoreRow("_ip", "ip")
		}

		if cat.PublishWhite {
			renderCoreRow("_white", "white")
		}
	}
	renderTableSection(&sb, "Sing-Box & Mihomo (Clash Meta)", enableProxy, coreRows)

	var appleRows []ReportRow

	for _, cat := range cfg.Categories {
		r, ok := results[cat.Name]
		if !ok {
			continue
		}
		catOut := ResolveClients(cfg.Global, cat)
		if !(catOut.Surge.Enable || catOut.Shadowrocket.Enable || catOut.QuantumultX.Enable || catOut.Loon.Enable || catOut.Stash.Enable || catOut.Egern.Enable) {
			continue
		}
		catName := cat.Name

		renderAppleRow := func(suffix string, rowType string) {
			targetName := catName + suffix
			if rowType == "white" {
				targetName = catName + "_white"
			}
			displayName := strings.ReplaceAll(targetName, "-", "&#8209;")
			surgeFile := fmt.Sprintf("publish/surge/%s.list", targetName)
			srFile := fmt.Sprintf("publish/shadowrocket/%s.list", targetName)
			qxFile := fmt.Sprintf("publish/quantumultx/%s.list", targetName)
			loonFile := fmt.Sprintf("publish/loon/%s.list", targetName)
			stashFile := fmt.Sprintf("publish/stash/%s.list", targetName)
			egernFile := fmt.Sprintf("publish/egern/%s.yaml", targetName)

			if anyFileExists(surgeFile, srFile, qxFile, loonFile, stashFile, egernFile) {
				var linesCount int
				if rowType == "white" {
					if anyFileExists(surgeFile) {
						linesCount = r.ExactCounts["surge_total_white"]
					} else if anyFileExists(srFile) {
						linesCount = r.ExactCounts["shadowrocket_total_white"]
					} else if anyFileExists(qxFile) {
						linesCount = r.ExactCounts["quantumultx_total_white"]
					} else if anyFileExists(loonFile) {
						linesCount = r.ExactCounts["loon_total_white"]
					} else if anyFileExists(stashFile) {
						linesCount = r.ExactCounts["stash_total_white"]
					} else if anyFileExists(egernFile) {
						linesCount = r.ExactCounts["egern_total_white"]
					}
				} else if suffix == "_ip" {
					if anyFileExists(surgeFile) {
						linesCount = r.ExactCounts["surge_ip"]
					} else if anyFileExists(srFile) {
						linesCount = r.ExactCounts["shadowrocket_ip"]
					} else if anyFileExists(qxFile) {
						linesCount = r.ExactCounts["quantumultx_ip"]
					} else if anyFileExists(loonFile) {
						linesCount = r.ExactCounts["loon_ip"]
					} else if anyFileExists(stashFile) {
						linesCount = r.ExactCounts["stash_ip"]
					} else if anyFileExists(egernFile) {
						linesCount = r.ExactCounts["egern_ip"]
					}
				} else {
					if anyFileExists(surgeFile) {
						linesCount = r.ExactCounts["surge_total"]
					} else if anyFileExists(srFile) {
						linesCount = r.ExactCounts["shadowrocket_total"]
					} else if anyFileExists(qxFile) {
						linesCount = r.ExactCounts["quantumultx_total"]
					} else if anyFileExists(loonFile) {
						linesCount = r.ExactCounts["loon_total"]
					} else if anyFileExists(stashFile) {
						linesCount = r.ExactCounts["stash_total"]
					} else if anyFileExists(egernFile) {
						linesCount = r.ExactCounts["egern_total"]
					}
				}

				urlSurge := fmt.Sprintf("https://github.com/%s/raw/publish/surge/%s.list", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlSr := fmt.Sprintf("https://github.com/%s/raw/publish/shadowrocket/%s.list", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlQx := fmt.Sprintf("https://github.com/%s/raw/publish/quantumultx/%s.list", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlLoon := fmt.Sprintf("https://github.com/%s/raw/publish/loon/%s.list", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlStash := fmt.Sprintf("https://github.com/%s/raw/publish/stash/%s.list", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlEgern := fmt.Sprintf("https://github.com/%s/raw/publish/egern/%s.yaml", os.Getenv("GITHUB_REPOSITORY"), targetName)

				cellDirect, cellProxy := buildLinksCell(ghProxy, enableProxy,
					LinkDef{"loon", urlLoon, getFileSize(loonFile), catOut.Loon.Enable && anyFileExists(loonFile), "&nbsp;&nbsp;&nbsp;"},
					LinkDef{"surge", urlSurge, getFileSize(surgeFile), catOut.Surge.Enable && anyFileExists(surgeFile), "&nbsp;"},
					LinkDef{"egern", urlEgern, getFileSize(egernFile), catOut.Egern.Enable && anyFileExists(egernFile), "&nbsp;"},
					LinkDef{"stash", urlStash, getFileSize(stashFile), catOut.Stash.Enable && anyFileExists(stashFile), "&nbsp;&nbsp;"},
					LinkDef{"shadowrocket", urlSr, getFileSize(srFile), catOut.Shadowrocket.Enable && anyFileExists(srFile), "&nbsp;"},
					LinkDef{"quantumultx", urlQx, getFileSize(qxFile), catOut.QuantumultX.Enable && anyFileExists(qxFile), "&nbsp;&nbsp;&nbsp;"},
				)
				appleRows = append(appleRows, ReportRow{displayName, linesCount, cellDirect, cellProxy})
			}
		}
		renderAppleRow("", "main")
		renderAppleRow("_ip", "ip")
		if cat.PublishWhite {
			renderAppleRow("_white", "white")
		}
	}
	renderTableSection(&sb, "Loon / Surge / Quantumultx / Shadowrocket / Egern / Stash", enableProxy, appleRows)

	var v2rayRows []ReportRow

	for _, cat := range cfg.Categories {
		r, ok := results[cat.Name]
		if !ok {
			continue
		}
		catOut := ResolveClients(cfg.Global, cat)
		if !catOut.V2ray.Enable {
			continue
		}

		catName := cat.Name

		renderV2rayRow := func(suffix, rowType string) {
			targetName := catName + suffix
			if rowType == "white" {
				targetName = catName + "_white"
			}
			displayName := strings.ReplaceAll(targetName, "-", "&#8209;")
			v2File := fmt.Sprintf("publish/v2ray/%s.txt", targetName)
			if anyFileExists(v2File) {
				var linesCount int
				switch rowType {
				case "white":
					if catOut.V2ray.SingleFile {
						linesCount = r.ExactCounts["v2ray_total_white"]
					} else {
						linesCount = r.ExactCounts["v2ray_dom_white"]
					}
				case "ip":
					linesCount = r.ExactCounts["v2ray_ip"]
				default:
					if catOut.V2ray.SingleFile {
						linesCount = r.ExactCounts["v2ray_total"]
					} else {
						linesCount = r.ExactCounts["v2ray_dom"]
					}
				}

				label := "v2ray"
				switch rowType {
				case "main":
					if !catOut.V2ray.SingleFile {
						label = "v2ray&#8288;-&#8288;domain"
					}
				case "ip":
					label = "v2ray&#8288;-&#8288;ipcidr"
				case "white":
					label = "v2ray&#8288;-&#8288;white"
				}

				urlV2 := fmt.Sprintf("https://github.com/%s/raw/publish/v2ray/%s.txt", os.Getenv("GITHUB_REPOSITORY"), targetName)
				cellDirect, cellProxy := buildLinksCell(ghProxy, enableProxy, LinkDef{label, urlV2, getFileSize(v2File), true, "&nbsp;"})
				v2rayRows = append(v2rayRows, ReportRow{displayName, linesCount, cellDirect, cellProxy})
			}
		}
		if catOut.V2ray.SingleFile {
			renderV2rayRow("", "main")
		} else {
			renderV2rayRow("", "main")
			renderV2rayRow("_ip", "ip")
		}
		if cat.PublishWhite {
			renderV2rayRow("_white", "white")
		}
	}
	renderTableSection(&sb, "V2Ray (TXT)", enableProxy, v2rayRows)

	var dnsRows []ReportRow

	for _, cat := range cfg.Categories {
		if !(cat.PublishAdblock || cat.PublishDnsmasq || cat.PublishSmartDNS) {
			continue
		}

		catName := cat.Name

		renderDnsRow := func(suffix, rowType string) {
			targetName := catName + suffix
			if rowType == "white" {
				targetName = catName + "_white"
			}
			displayName := strings.ReplaceAll(targetName, "-", "&#8209;")
			adgFile := fmt.Sprintf("publish/adblock/%s.txt", targetName)
			dnsmasqFile := fmt.Sprintf("publish/dnsmasq/%s.conf", targetName)
			smartdnsFile := fmt.Sprintf("publish/smartdns/%s.conf", targetName)
			if anyFileExists(adgFile, dnsmasqFile, smartdnsFile) {
				var linesCount int
				if anyFileExists(adgFile) {
					linesCount = getLineCount(adgFile)
				} else if anyFileExists(dnsmasqFile) {
					linesCount = getLineCount(dnsmasqFile)
				} else if anyFileExists(smartdnsFile) {
					linesCount = getLineCount(smartdnsFile)
				}

				urlAdg := fmt.Sprintf("https://github.com/%s/raw/publish/adblock/%s.txt", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlDnsmasq := fmt.Sprintf("https://github.com/%s/raw/publish/dnsmasq/%s.conf", os.Getenv("GITHUB_REPOSITORY"), targetName)
				urlSmartdns := fmt.Sprintf("https://github.com/%s/raw/publish/smartdns/%s.conf", os.Getenv("GITHUB_REPOSITORY"), targetName)

				cellDirect, cellProxy := buildLinksCell(ghProxy, enableProxy,
					LinkDef{"adblock", urlAdg, getFileSize(adgFile), cat.PublishAdblock && anyFileExists(adgFile), "&nbsp;&nbsp;&nbsp;"},
					LinkDef{"dnsmasq", urlDnsmasq, getFileSize(dnsmasqFile), cat.PublishDnsmasq && anyFileExists(dnsmasqFile), "&nbsp;"},
					LinkDef{"smartdns", urlSmartdns, getFileSize(smartdnsFile), cat.PublishSmartDNS && anyFileExists(smartdnsFile), "&nbsp;"},
				)
				dnsRows = append(dnsRows, ReportRow{displayName, linesCount, cellDirect, cellProxy})
			}
		}
		renderDnsRow("", "main")
		if cat.PublishWhite {
			renderDnsRow("_white", "white")
		}
	}
	renderTableSection(&sb, "其它服务端 (DNS & Adblock)", enableProxy, dnsRows)

	if cfg.Global.SplitCNIP {
		var cnipRows []ReportRow
		for _, cat := range cfg.Categories {
			if cat.Name != "cn" {
				continue
			}
			r, ok := results[cat.Name]
			if !ok {
				continue
			}

			catOut := ResolveClients(cfg.Global, cat)

			buildCnipRow := func(name string, count int) {
				txtFile := fmt.Sprintf("publish/cnip/%s.txt", name)
				srsFile := fmt.Sprintf("publish/cnip/%s.srs", name)
				mrsFile := fmt.Sprintf("publish/cnip/%s.mrs", name)

				if anyFileExists(txtFile) {
					var links []LinkDef
					urlTxt := fmt.Sprintf("https://github.com/%s/raw/publish/cnip/%s.txt", os.Getenv("GITHUB_REPOSITORY"), name)
					links = append(links, LinkDef{"TXT", urlTxt, getFileSize(txtFile), true, "&nbsp;"})

					if catOut.Singbox.SRS && anyFileExists(srsFile) {
						urlSrs := fmt.Sprintf("https://github.com/%s/raw/publish/cnip/%s.srs", os.Getenv("GITHUB_REPOSITORY"), name)
						links = append(links, LinkDef{"SRS", urlSrs, getFileSize(srsFile), true, "&nbsp;"})
					}
					if catOut.Mihomo.MRS && anyFileExists(mrsFile) {
						urlMrs := fmt.Sprintf("https://github.com/%s/raw/publish/cnip/%s.mrs", os.Getenv("GITHUB_REPOSITORY"), name)
						links = append(links, LinkDef{"MRS", urlMrs, getFileSize(mrsFile), true, "&nbsp;"})
					}

					cellDirect, cellProxy := buildLinksCell(ghProxy, enableProxy, links...)
					cnipRows = append(cnipRows, ReportRow{name, count, cellDirect, cellProxy})
				}
			}

			buildCnipRow("cnipv4", r.ExactCounts["cnipv4"])
			buildCnipRow("cnipv6", r.ExactCounts["cnipv6"])
		}
		renderTableSection(&sb, "CNIP", enableProxy, cnipRows)
	}

	sb.WriteString("\n" + endTag + "\n")
	reportTitle := "# 📦 DIY-Ruleset 自动编译报告\n\n**该页面由 GitHub Actions 每日自动生成**\n\n"

	os.MkdirAll("publish", 0755)
	_ = os.WriteFile("publish/README.md", []byte(reportTitle+sb.String()), 0644)
}
