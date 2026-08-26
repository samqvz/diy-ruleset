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
│   ├── compiler.go        # 负责编译文件
│   ├── config.go          # 配置解析模块
│   ├── exporter.go        # 规则集导出模块
│   ├── fetcher.go         # 并发网络模块
│   ├── parser.go          # 多语法解析器
│   ├── processor.go       # 规则处理模块
│   └── report.go          # 负责生成报表
├── config-example.yaml    # 配置示例文件
├── config.yaml            # 主配置文件
├── main.go                # 主程序入口
├── go.mod                 # Go模块依赖包
└── README.md              # 项目说明文档

```

</details>

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

### ⚠️ 注意事项 ：

1. Mihomo (Clash Meta) 官方内核对 .mrs 二进制格式的类型要求极其严苛。仅支持完整域名、Clash 的域名通配符和 IP 规则。如果你发现 .mrs 文件内的条目数量与 .yaml 文本列表有出入，这属于上游内核的编译机制限制。此外， .mrs 二进制文件格式强制隔离域名与 IP，即便设定 single_file: true，引擎仍会强制对其拆分为独立文件。( Stash 使用的 .mrs 同理)

2. Mihomo (Clash Meta) .mrs 二进制格式使用的域名通配符规则与 DOMAIN-WILDCARD 通配符规则并不相同，详细文档请查看 Mihomo (Clash Meta) 官网。

3. 同时，出于 .mrs 二进制文件限制 (不支持 KEYWORD 写入)， 以及部分客户端规则集不支持 REGEX 或 WILDCARD 写入，引擎默认对这三个类型的规则强制只进行 **同类型匹配** 去重，避免上游规则含有三个类型中的其中一种而导致丢失规则。（比如含有：DOMAIN-KEYWORD,google，如果是不强制同类型去重的情况下，带有google字样的规则都会因这条 KEYWORD 去重，然而因为 .mrs 限制，剩下的这条 KEYWORD 并没有写入最终文件。）
   
4. 但是，对于 add/ 和 remove/ 文件夹，引擎采用的是 **跨类型匹配** （因为按惯性思维，需要填入补充或剔除名单的规则，应是要把与之相关的规则都进行合并或剔除）。不过，引擎添加了前缀 **精准匹配 (EXACT:)** 写法，可以强制指定 **仅添加或仅剔除** 该规则而不影响其它与之相关的规则，具体使用方式请参考下方。

---

## 规则集自定义 (add & remove)

如果你发现上游规则有遗漏或者误杀，无需等待上游作者更新，你可以直接通过本地文件夹实现增删。引擎会在处理对应规则集时，自动去这两个文件夹寻找同名的 `.list` 文件进行合并与剔除。

注意：默认采用 **跨规则类型匹配进行去重** 。

### 补充规则 (add/ 目录)
如果你想给名为 proxy 的规则集补充规则：
* 在 add/ 文件夹下新建文件 proxy.list。
* 在里面写入规则，引擎会自动将它们合并到最终输出文件。
* 默认示例：**DOMAIN-KEYWORD,google**，带有 google 字样的规则都会被去重，仅保留这一条。
* 仅添加规则不参与跨类型去重示例：**EXACT:DOMAIN-KEYWORD,google**。
* 效果：引擎只会在最终文件中新增 DOMAIN-KEYWORD,google 的这一行，并进行 KEYWORD 同类型去重，其它规则类型不受影响。

### 剔除规则 (remove/ 目录)
如果你发现上游把某个正常的网站（比如 baidu.cn）拦截了，你想把它剔除掉：
* 在 remove/ 文件夹下新建对应的 **.list** 文件（如 reject.list）。
* 写入规则，引擎会在去重阶段精准将其剔除。
* 默认示例：**DOMAIN-SUFFIX,cn**，会将所有包含 .cn 后缀的域名（如 baidu.cn, qq.cn 以及 .cn 本体）全部剔除。DOMAIN-KEYWORD 和 DOMAIN-REGEX 规则同理。
* 仅添加规则不参与跨类型去重示例：**EXACT:DOMAIN-SUFFIX,cn**
* 效果：引擎只会将上游中完全等于 DOMAIN-SUFFIX,cn 的这一行剔除，而 baidu.cn 等规则将不受影响。

### 语法
在这两个文件夹里，建议使用 Clash 标准语法或快捷语法：

* 只写域名 `google.com`，引擎会默认当做 `DOMAIN,google.com` 处理。
* 写 `+.google.com`，引擎会自动等同于 `DOMAIN-SUFFIX,google.com` (匹配其及所有子域名)。
* 带有 `*` 号或 `.` 号前缀（如 `*.google.com`、`.google.com`），引擎会将其识别为 **Clash 通配符** 并自动转换为严谨的正则表达式匹配。如需写入 DOMAIN-WILDCARD 请写上语法前缀头。
* 支持 `DOMAIN-KEYWORD,google`、`IP-CIDR,1.1.1.1/32`、`PROCESS-NAME,v2ray.exe` 等映射列表中含有的语法。

### 其它写法 (指定解析器)
* 使用 V2Ray 引擎剔除完整域名：v2ray=full:baidu.com
* 使用 Adblock 语法剔除：adblock=||ads.example.com^
* 使用 Surge 引擎并配合 EXACT 精准剔除：surge=EXACT:USER-AGENT,apple*
* 默认使用 Clash 常规语法就行，引擎会自动转换成适合各客户端的语法。

---

## 配置参数说明 (config.yaml)

config.yaml 包含 global (全局参数) 与 categories (规则集分组) 两部分。分组中的参数可继承或覆盖全局参数。

### 1. 输出文件控制
所有支持的客户端均支持独立的输出控制：
* `enable: true/false`：控制是否生成该客户端的规则文件。
* `single_file: true/false`：设置为 **true** 时，引擎会将域名规则和 IP 规则混合打包输出为一个文件。设置为 **false** 时，引擎会将域名规则和 IP 规则分为两个独立文件。

### 2. 智能解析器
**parser** 强制指定上游解析器，留空时引擎将自动嗅探。但更建议显式指定一种格式。
* 可用值为：`clash`, `v2ray`, `adblock`, `hosts`, `dnsmasq`, `smartdns`, `surge`, `shadowrocket`, `quantumultx`, `loon`, `stash`, `white`。
* **注意**：
1. 由于 **v2ray** 的 KEYWOED 规则为纯字符串，如果上游为 v2ray 规则，**请强制指定 parser 值为v2ray**。否则将自动嗅探为 Clash 的 DOMAIN 规则！
2. 由于 **Apple客户端 (如 Surge 等)** 中会带有以“.”符号作为前缀的规则，它的规则类型为 SUFFIX ，如果上游带有这类规则，**请强制指定  parser 为 surge 等值**。否则将自动嗅探为 Clash 的域名通配符规则！
* add/ 和 remove/ 目录自定义添加或剔除规则时，也请使用 **其它写法 (指定解析器)** 以避免这些规则类型的混淆。

### 3. DNS 防护与智能分流
Dnsmasq 和 SmartDNS 格式既可以用来去广告，也可以用来做路由分流：
* **拦截模式**：默认情况下，输出为 `address=/domain/0.0.0.0`。
* **分流模式**：如果你在配置中指定了 Server（例如 `dnsmasq_server: "223.5.5.5"`），引擎会自动将其转换为分流转发语法 `server=/domain/223.5.5.5`。

### 4. 白名单行为控制
对于 **reject** 去广告规则，若上游为 adblock 类型规则并带有 **@@** 的白名单规则时，可开启 `auto_extract_white: true` ，会提取上游带有 **@@** 的白名单规则，并且可以控制它的行为：
* `white_behavior: "remove"`（默认）：提取出白名单，并将它们从原拦截规则中抵消/剔除。
* `white_behavior: "extract_only"`：仅提取出白名单规则，不干预原拦截规则。

---

## 使用说明 (Fork)

只需简单几步，即可拥有属于你自己的每日更新规则库：

1. 点击页面右上角的 **Fork** 按钮，将本仓库克隆到你的 GitHub 账号下。
2. 进入你仓库的 Settings -> Actions -> General，确保 **Workflow permissions** 设置为 Read and write permissions。
3. 打开根目录的 `config.yaml`，按需调整上游规则源链接与客户端输出开关。
4. 进入 Actions 页面，在左侧选择 Build Custom Rules，然后点击右侧的 Run workflow 手动运行一次。
5. 等待构建完成后，切换至 publish 分支查看生成的规则文件及报表。