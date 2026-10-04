# DIY-Ruleset - 构建适合自己的规则集

DIY-Ruleset 是一个网络代理规则集处理引擎，通过 GitHub Actions 工作流每天自动拉取各个上游的优质规则，进行深度去重、清洗和精准剔除，按需生成 **Sing-box、Mihomo (Clash Meta)、Surge、Shadowrocket、Quantumultx、Loon、Egern、Stash** 以及 **DNS 服务端** 等多格式规则集。最终生成的文件将推送到 `publish` 分支，并生成一份包含计数统计和下载链接的 Markdown 报表。

<details>

<summary><strong>查看项目文件结构</strong></summary>

```text
DIY-Ruleset/
├── .github/workflows/     # GitHub Actions
│   └── run.yml            # 核心执行脚本
├── add/                   # 规则补充目录
├── remove/                # 规则剔除目录
├── core/                  # 核心代码
│   ├── aho.go             # Aho-Corasick 多模式关键词匹配
│   ├── mmdb.go             # country.mmdb 读写与 ASN 网段自动识别
│   ├── compiler.go        # 调用内核编译 .srs / .mrs
│   ├── config.go          # 配置解析与校验
│   ├── exporter.go        # 规则集导出模块
│   ├── fetcher.go         # 并发网络拉取与二进制预处理
│   ├── geodata.go         # Geo/ASN 数据编排（拉取/筛选/打包）
│   ├── geoip.go           # geoip.dat 读写
│   ├── geosite.go         # geosite.dat 读写
│   ├── parser.go          # 多语法解析器/格式嗅探
│   ├── processor.go       # 归一化与统一交叉查杀去重
│   ├── protobuf.go        # 最小 protobuf 编解码（geo 数据文件）
│   ├── report.go          # 生成 Markdown 报表
│   ├── behavior_test.go   # 多语法解析/去重/通配符/端到端处理测试
│   ├── aho_test.go        # Aho-Corasick 关键词匹配等价性测试
│   └── geodata_test.go    # geosite/geoip/mmdb 读写往返与输出测试
├── config-example.yaml    # 配置示例文件
├── config.yaml            # 主配置文件
├── main.go                # 主程序入口
├── go.mod                 # Go 模块依赖
└── README.md              # 项目说明文档

```

</details>

---

## 处理流程

```text
① 拉取上游
   ├─ 普通规则上游：.list / .txt / .yaml / .json / .srs / .mrs
   └─ Geo/ASN 上游：geosite.dat / geoip.dat / country.mmdb（按 geodata.*.upstreams 拉取）
        │
        ▼
② Geo/ASN 标签处理
   · 按 geodata.*.pick 筛选标签
   · 标签物化为规则集（与同名 category 合并；无同名则新建 category）
   · mmdb.pick 中缺失的 AS 号自动拉取网段（RIPEstat）
        │
        ▼
③ 多语法解析 → 统一 Rule 结构体（DOMAIN / IP-CIDR / …）
        │
        ▼
④ 统一交叉查杀去重
   · 关键词子串匹配 / 正则匹配
   · 域名后缀字典树（父后缀覆盖子后缀）
   · IP 前缀字典树（父网段覆盖子网段）
        │
        ▼
⑤ 按需导出各客户端格式（singbox / mihomo / v2ray / Apple / DNS）
   └─ 调用内核编译 .srs / .mrs
        │
        ▼
⑥ 打包 Geo/ASN 文件（geosite.dat / geoip.dat / country.mmdb）
        │
        ▼
⑦ 生成 Markdown 统计报表（含 Geo/ASN 文件表格）
```

---

## 规则类型映射列表

| 规则类型 | Clash | Loon | Surge | QuantumultX | Shadowrocket | Stash | Egern | SingBox | V2ray |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **匹配完整域名** | DOMAIN | DOMAIN | DOMAIN | host | DOMAIN | DOMAIN | domain_set: | domain | full: |
| **匹配域名后缀** | DOMAIN-SUFFIX | DOMAIN-SUFFIX | DOMAIN-SUFFIX | host-suffix | DOMAIN-SUFFIX | DOMAIN-SUFFIX | domain_suffix_set: | domain_suffix | domain: |
| **匹配域名关键词** | DOMAIN-KEYWORD | DOMAIN&#8288;-&#8288;KEYWORD | DOMAIN-KEYWORD | host&#8288;-&#8288;keyword | DOMAIN-KEYWORD | DOMAIN-KEYWORD | domain_keyword_set: | domain_keyword | 纯&#8288;字&#8288;符&#8288;串 |
| **匹&#8288;配&#8288;正&#8288;则&#8288;表&#8288;达&#8288;式** | DOMAIN-REGEX | - | - | - | - | DOMAIN-REGEX | domain_regex_set: | domain_regex | regexp: |
| **匹配通配符** | DOMAIN&#8288;-&#8288;WILDCARD | - | DOMAIN&#8288;-&#8288;WILDCARD | host&#8288;-&#8288;wildcard | DOMAIN&#8288;-&#8288;WILDCARD | DOMAIN&#8288;-&#8288;WILDCARD | domain_wildcard_set: | - | - |
| **匹配IPv4** | IP-CIDR | IP-CIDR | IP-CIDR | ip-cidr | IP-CIDR | IP-CIDR | ip_cidr_set: | ip_cidr | 纯IP |
| **匹配IPv6** | IP-CIDR6 | IP-CIDR6 | IP-CIDR6 | ip6-cidr | IP-CIDR6 | IP-CIDR6 | ip_cidr6_set: | ip_cidr | 纯IP |
| **匹配ASN** | IP-ASN | IP-ASN | IP-ASN | ip-asn | IP-ASN | IP-ASN | asn_set: | - | - |
| **匹配端口** | DST-PORT | DEST-PORT | DEST-PORT | dest-port | DST-PORT | DST-PORT | dest_port_set: | port | - |
| **匹配UA** | - | USER-AGENT | USER-AGENT | user-agent | USER-AGENT | USER-AGENT | user_agent_set: | - | - |
| **匹配URL正则** | - | URL-REGEX | URL-REGEX | - | URL-REGEX | URL-REGEX | url_regex_set: | - | - |
| **匹配进程名称** | PROCESS-NAME | - | PROCESS-NAME | - | - | PROCESS-NAME | - | process_name | - |
| **匹配进程路径** | PROCESS-PATH | - | - | - | - | PROCESS-PATH | - | process_path | - |

---

## ⚠️ 注意事项

1. **.mrs 的类型限制**：Mihomo (Clash Meta) 官方内核对 `.mrs` 二进制格式的类型要求极其严苛，仅支持完整域名、Clash 的域名通配符和 IP 规则。若 `.mrs` 内条目数与 `.yaml` 文本列表有出入，属上游内核编译机制限制。此外 `.mrs` 强制隔离域名与 IP，即使设置 `single_file: true`，引擎仍会拆分为独立文件（Stash 使用的 `.mrs` 同理）。

2. **两套通配符语义必须区分**（详见 [mihomo 语法手册](https://wiki.metacubex.one/handbook/syntax/#_7)）：

   | 使用场景 | `*` 的含义 | `+.` / `.` |
   | :--- | :--- | :--- |
   | **`.mrs` 规则集** | **仅匹配一级**：`*.baidu.com` 命中 `tieba.baidu.com`，**不命中** `a.b.baidu.com` 或 `baidu.com` | `+.baidu.com` 含裸域；`.baidu.com` 不含裸域 |
   | **DOMAIN-WILDCARD** | **零或多个任意字符**（可跨级）：`*.google.com` 命中 `a.b.google.com` | 不支持 |

   Mihomo (Clash Meta) .mrs 二进制格式使用的域名通配符规则与 DOMAIN-WILDCARD 通配符规则并不相同，详细文档请查看 Mihomo (Clash Meta) 官网。

3. **KEYWORD / REGEX / WILDCARD 只做"同类型"去重**：由于 `.mrs` 不支持这三类，且部分客户端不支持 REGEX / WILDCARD，引擎默认对这三类**只进行同类型匹配**去重，避免上游规则因跨类型去重被误删（例如上游含 `DOMAIN-KEYWORD,google`，若允许跨类型去重会命中大量含 google 的规则，但该 KEYWORD 因 `.mrs` 限制并未写入最终文件，从而造成规则丢失）。

4. **add/ 与 remove/ 采用"跨类型"匹配**：按直觉，补充/剔除名单通常希望影响所有相关规则。若只想精确增删单条，使用前缀 **`EXACT:`**（详见下文）。

---

## 规则集自定义 (add & remove)

如果发现上游规则有遗漏或误杀，无需等待上游作者更新，可直接通过本地文件夹增删。引擎处理对应规则集时，会自动读取 `add/<name>.list` 与 `remove/<name>.list`。

> 注：默认采用 **跨规则类型匹配去重**。

### 补充规则 (add/ 目录)
如需给名为 proxy 的规则集补充规则：
* 在 `add/` 下新建 `proxy.list`，写入规则，引擎会自动合并到最终输出。
* 默认示例：`DOMAIN-KEYWORD,google`，带有 google 字样的规则都会被去重，仅保留这一条。
* 仅添加、不参与跨类型去重：`EXACT:DOMAIN-KEYWORD,google`。
* 效果：只在最终文件新增 `DOMAIN-KEYWORD,google` 一行，并进行 KEYWORD 同类型去重，其它类型不受影响。

### 剔除规则 (remove/ 目录)
如发现上游误杀了正常网站（如 baidu.cn），想将其剔除：
* 在 `remove/` 下新建对应的 `.list`（如 `reject.list`）。
* 写入规则，引擎会在去重阶段精准剔除。
* 默认示例：`DOMAIN-SUFFIX,cn`，会剔除所有 `.cn` 后缀域名（含 `.cn` 本体）。DOMAIN-KEYWORD / DOMAIN-REGEX 同理。
* 仅剔除完全相等的一条：`EXACT:DOMAIN-SUFFIX,cn`。
* 效果：只剔除上游中完全等于 `DOMAIN-SUFFIX,cn` 的一行，`baidu.cn` 等规则不受影响。

### 语法
两个文件夹均建议使用 Clash 标准或快捷语法：

* 只写域名 `google.com`，引擎默认当作 `DOMAIN,google.com`。
* 写 `+.google.com`，等价 `DOMAIN-SUFFIX,google.com`（匹配其及所有子域名）。
* 带 `*` 或 `.` 前缀（如 `*.google.com`、`.google.com`），识别为 **Clash 通配符**并转为严谨正则；如需写入 `DOMAIN-WILDCARD` 请显式写类型前缀。
* 支持映射列表中全部语法：`DOMAIN-KEYWORD,google`、`IP-CIDR,1.1.1.1/32`、`PROCESS-NAME,v2ray.exe` 等。

### 其它写法 (指定解析器)
* V2Ray 引擎剔除完整域名：`v2ray=baidu.com`
* Adblock 语法剔除：`adblock=||ads.example.com^`
* Surge 引擎配合 EXACT 精准剔除：`surge=EXACT:.apple.com`
* 默认使用 Clash 常规语法，引擎会自动转换成适合各客户端的语法。

* **注意**：
  1. V2Ray 的 KEYWORD 为纯字符串（裸域），若上游为 v2ray 带有此类规则，**请强制指定 `parser: "v2ray"`**，否则会被嗅探为 Clash 的 DOMAIN。
  2. Apple 系客户端（Surge 等）存在以 `.` 为前缀的 SUFFIX 规则，若上游为 Apple 系客户端且含此类规则，**请强制指定 `parser: "surge"` 等**，否则会被嗅探为 Clash 通配符。
* `add/`、`remove/` 目录自定义此类规则时，也建议使用 **指定解析器** 写法以避免产生歧义。

---

## Geo 与 ASN 规则 (geodata)

引擎支持读取、自定义并输出 **geosite.dat / geoip.dat / country.mmdb** 三种规则数据文件。

### 支持的文件格式

| 文件 | 格式 | 内容 | 标签含义 |
| :--- | :--- | :--- | :--- |
| geosite.dat | v2ray GeoSite（protobuf） | 域名规则集合 | 站点/分类名，如 `google` |
| geoip.dat | v2ray GeoIP（protobuf） | IP 网段集合 | 国家码 / ASN 号 / 分类名 |
| country.mmdb | MaxMind mmdb | IP 网段集合 | 国家码 / ASN 号 / 分类名（`only_asn` 时仅 ASN） |

### 输出 GeoSite / GeoIP / ASN 文件

在 `global.geodata` 用 `geosite` / `geoip` / `mmdb` 控制是否生成（统一对象形式），路径固定为 `publish/geosite.dat`、`publish/geoip.dat`、`publish/country.mmdb`：

```yaml
global:
  geodata:
    geosite:
      enable: true   # true=生成；false=不生成
    geoip:
      enable: true
    mmdb:
      enable: true
      only_asn: false # false（默认）=与 geoip.dat 一致（国家/ASN/category）；true=仅写 ASN
```

- 开启后默认把**所有 category** 的去重结果打包进对应文件（标签 = 规则集名）：`geosite` 打包域名规则，`geoip` / `mmdb` 打包 IP 规则。
- `geoip.dat` 与 `country.mmdb` **各自独立**（各自的 pick 互不影响），均可包含**国家码标签**（如 `cn`）、**ASN 标签**（如 `AS13335`）与 **category 标签**；`only_asn: true` 时 `country.mmdb` 仅写 ASN 记录（GeoLite2-ASN 兼容）。
- category 可用**同名字段覆盖**（类似 single_file 继承逻辑）：`geosite: false` 排除该规则集；`mmdb: true` 时该规则集的 IP 规则写入 country.mmdb 的 `<name>` 标签。**ASN 分组**通过在 `add/<name>.list` 写一行 `IP-ASN,13335` 实现（自动识别网段），无需额外字段。
- 打包的是「该规则集去重后的最终结果」，**add/remove 目录、merge_from、远程剔除等全部自然生效**，无需逐条配置。
- 若一个 category 参与打包但其去重结果为空，则不会在输出中生成该标签（避免出现空标签）。要**剔除上游拉取来的标签**，请在 `pick`/`exclude` 中配置（见下节），不要依赖此机制。

### 拉取上游 Geo / ASN 文件（可选）

每个类型可独立配置 `upstreams`（上游数据文件 URL 列表）与 `pick`（从中选取标签）；文件类型由外层 `geosite` / `geoip` / `mmdb` 决定，无需额外指定：

```yaml
global:
  geodata:
    geosite:
      enable: true
      upstreams:
        - "https://github.com/.../geosite.dat"
      pick: []                    # 只选取这些标签；留空=全部
      exclude: [ads, gfw]         # 可选：从 pick 结果中剔除这些标签（大小写不敏感）
    geoip:
      enable: true
      upstreams: [".../geoip.dat"]
      pick: [cn]
    mmdb:
      enable: true
      only_asn: false             # false（默认）=与 geoip.dat 一致；true=仅写 ASN
      upstreams: [".../Country.mmdb"]
      pick: [AS13335]
```

- `pick` 选中的标签会**物化为规则集**：与同名 category 合并（一同去重、增删），无同名 category 时自动新建一个同名规则集——因此这些标签既会进入 `geosite.dat` / `geoip.dat` / `country.mmdb`，也会生成对应的 mrs / srs / list 文件。
- `exclude` 是**黑名单**：从 pick 结果中剔除指定标签，优先级高于 pick。当 `pick` 留空（选取全部）时，用 `exclude` 剔除不想要的标签即可。
- 未被任何 category 覆盖的标签原样保留到输出。

### ASN 自动识别

`mmdb.pick` 中上游数据里没有的 AS 号，以及规则集中出现的 `IP-ASN` 规则，会自动从 RIPEstat 拉取网段（内置、无需配置；AS 号由代码按需动态传入）：

| 数据源 | 官网 / 接口 |
| :--- | :--- |
| RIPEstat | <https://stat.ripe.net/>（`/data/announced-prefixes/data.json?resource=AS<号>`） |

---

## 配置参数说明 (config.yaml)

`config.yaml` 包含 `global`（全局参数）与 `categories`（规则集分组）两部分。分组参数可继承或覆盖全局参数。

### 1. 输出文件控制
所有支持的客户端均支持独立输出控制：
* `enable: true/false`：是否生成该客户端的规则文件。
* `single_file: true/false`：**true** 时域名与 IP 规则混合打包为一个文件；**false** 时拆分为两个独立文件。

### 2. 智能解析器
`parser` 强制指定上游解析器，留空时引擎自动嗅探（建议显式指定）。
* 可用值：`clash`、`v2ray`、`adblock`、`hosts`、`dnsmasq`、`smartdns`、`surge`、`shadowrocket`、`quantumultx`、`loon`、`stash`、`egern`、`white`。

### 3. DNS 防护与智能分流
Dnsmasq / SmartDNS 既可去广告，也可做路由分流：
* **拦截模式**：默认输出 `address=/domain/0.0.0.0`。
* **分流模式**：配置 Server（如 `dnsmasq_server: "223.5.5.5"`）后自动转为 `server=/domain/223.5.5.5`。

### 4. 白名单行为控制
对于 **reject** 去广告规则，若上游为 adblock 且含 **@@** 白名单，可开启 `auto_extract_white: true`，并控制其行为：
* `white_behavior: "remove"`（默认）：提取白名单并从原拦截规则中剔除。
* `white_behavior: "extract_only"`：仅提取，不干预原拦截规则。

---

## 本地开发与测试

```bash
go vet ./...        # 静态检查
go test ./...       # 运行全部测试（解析 / 去重 / 字典树 / 并发 / Aho-Corasick / geo-asn 读写）
go test -race ./... # 竞态检测（需 gcc 环境）
go run main.go      # 本地构建（需 sing-box/ mihomo 内核放置在 diy-ruleset 根目录）
```

测试文件说明：

- `core/behavior_test.go` — 多语法解析、通配符归一化、后缀/IP 字典树去重、跨类型查杀与端到端处理，是修改引擎时的回归保护网。
- `core/aho_test.go` — Aho-Corasick 关键词匹配的等价性测试（用 `strings.Contains` 交叉验证）。
- `core/geodata_test.go` — geosite.dat / geoip.dat / country.mmdb 的读写往返、定制与分发集成测试。

---

## 使用说明 (Fork)

1. 点击页面右上角的 **Fork** 按钮，将本仓库克隆到你的 GitHub 账号下。
2. 进入仓库的 Settings -> Actions -> General，确保 **Workflow permissions** 设置为 Read and write permissions。
3. 打开根目录的 `config.yaml`，按需调整上游规则源链接与客户端输出开关。仓库中的 `config.yaml` 是**维护者的默认配置**，仅作参考；请根据自身需求修改适合的配置，建议修改 `add/`（补充）、`remove/`（剔除）目录中的内容，可按需清空/替换。
4. 进入 Actions 页面，选择 Build Custom Rules，点击 Run workflow 手动运行一次。
5. 构建完成后，切换至 publish 分支查看生成的规则文件及报表。
