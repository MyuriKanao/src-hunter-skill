---
name: src-hunter
description: 实战 SRC / 众测 / Bug bounty 漏洞挖掘工作流 skill。包含：5 阶段方法论（intake → recon → enum → hunt → report）、19 个攻击类 playbook（SQLi/XSS/RCE/SSRF/IDOR/CSRF/Path Traversal/File Upload/SSTI/XXE/Race/HTTP Smuggling/OAuth/JWT/SAML/GraphQL/Mobile/LLM/DoS）、305 个结构化 payload、263 个 WAF/EDR 绕过变体、2887 份 HackerOne 真实 High/Critical 已披露案例、88,636 份 WooYun 案例统计、国产 OA / 中间件指纹库、银行 / 电信行业垂直 playbook。当用户提到 "src 挖洞 / src 漏洞挖掘 / bug bounty / 众测 / hackerone / 漏洞赏金 / SRC / 任意 X 漏洞 / 渗透测试" 或问"如何挖某个目标 / 怎么测某个 API / 如何绕过 WAF" 时触发。
argument-hint: "<target-or-program-or-phase>"
level: 2
---

# SRC Hunter — 实战漏洞挖掘工作流

这是一个**带强制 checkpoint 的工作流**,不是参考手册。每个阶段有 MUST 输出,未通过不进下一阶段。详细 payload / playbook / H1 案例**按需 Read**,不准凭记忆生成。

数据规模、目录树、工具索引见 `README.md`,本文件只管"做什么 / 何时做 / 何时去读哪个文件"。

---

## 触发条件

命中任一即进入:
- "src 挖洞 / 漏洞赏金 / bug bounty / 众测 / hackerone / Security Response Center"
- "如何挖 / 怎么测 / 怎么打 + 某目标 / 某接口 / 某参数"
- "WAF 绕过 / 任意账号 / 任意修改 / 密码重置 / 未授权访问 / 默认凭据"
- 用户给一个 URL / API endpoint / APK 让你测

**不应触发**:纯白盒源码审计 → `code-audit` skill;漏洞修复问答 → 通用对话;CTF → 通用对话。

---

## 反幻觉硬约束(全程适用)

1. **不准凭记忆出 payload**。要给 SQLi/RCE/SSRF/XSS 任何 payload 前,先 Read 对应 `references/playbooks/<type>.md`(或 `<type>/00-index.md` + 具体子文件,见下表)。Phase 4 的 payload 必须能在文件里查到出处。
2. **不准编造案例编号**。引用 H1/WooYun 案例前必须 Read `references/h1-reports/by-weakness/` 下的实际文件。说不出文件路径就别引。
3. **无证据不下结论**。无 HTTP 包/截图/视频时只能写"待验证 / 假设",不写"已确认 / 发现漏洞"。
4. **出 scope 立即停**。任何时候发现要测的资产不在 Phase 1 已确认的 in-scope 列表 → 立即停手,回到 Phase 1 重核。

---

## Phase 1 · Intake(接单)

**进入条件**:用户首次给出目标 / 程序名 / URL。

**MUST 输出 checkpoint**(四项缺一不进 Phase 2,缺什么向用户问什么,不要假设):

- [ ] **In-scope**:可测域名 / IP 段 / app / endpoint(逐条列)
- [ ] **Out-of-scope**:禁测项(逐条列)
- [ ] **规则**:payout tier / disclosure window / safe-harbor / 测试 header(如 `X-Bug-Bounty:<handle>`)
- [ ] **时间盒**:6h / 单日 / HVV / 月度

**仅当用户问"哪个最值得先测"** → Read `references/methodology/05-srctimebox-priority.md`。

---

## Phase 2 · Recon(被动侦察)

**进入条件**:Phase 1 checkpoint 四项全过。

**禁止**:任何主动发包(端口扫描 / 路径爆破 / payload 测试)。

**MUST 输出**:不发包给目标得到的资产清单 + 历史信息,来源 ≥3 种:
- CT 日志(crt.sh / Censys)
- Wayback / CommonCrawl 历史快照
- GitHub dorks(`org:target` + `password|api_key|SECRET|.env`)
- FOFA / Shodan favicon hash
- SecurityTrails / DNS 历史
- ASN / IP 段(bgp.he.net)

---

## Phase 3 · Enum(主动探测)

**进入条件**:Phase 2 资产清单非空。

**MUST 输出**:活资产矩阵——`域 → 端口 → 服务 → 指纹 → JS endpoint`。

**条件触发 Read**(命中就必读,不命中不读):

| 命中信号 | MUST Read |
|---|---|
| 指纹含 `weaver/seeyon/tongda/landray/yongyou/kingdee/hikvision/dahua` | `references/dictionaries/chinese-srcfingerprints.md` + `references/dictionaries/default-credentials-cn.md` |
| 资产含 银行 / 支付 / 网银 / 第三方支付聚合 | `references/industry/banking-finance.md` |
| 资产含 运营商 / BOSS / 网管 / 物联网卡 | `references/industry/telecom-isp.md` |

---

## Phase 4 · Hunt(漏洞探测)

**进入条件**:Phase 3 矩阵 ≥1 个候选目标。

**强制流程(每个候选目标走一遍)**:
1. 看目标信号,从下表选 1 个 playbook
2. **Read 该 playbook 文件**(不准跳过、不准凭记忆替代)
3. 按 playbook 的"参数频率表"挑入口
4. 按 playbook 的"payload 库"探测——payload 来自文件,不来自训练记忆
5. 被 WAF 拦 → Read `references/methodology/02-bypass-toolkit.md` 决策树
6. 命中后立即保存 HTTP 包 / 截图 → 进 Phase 5 候选

| 入口信号 | MUST Read |
|---|---|
| Actuator / Swagger / 默认端口 / 弱密码 | `references/playbooks/unauth-access.md` |
| .git / .svn / .env / heapdump / 路径列举 | `references/playbooks/info-disclosure.md` |
| 用户态 ID 可遍历 / 任意 X 越权 | `references/playbooks/arbitrary-x-authz.md` |
| 密码重置 / 支付 / 验证码 / 订单 / 提现 | `references/playbooks/logic-flaws/00-index.md` |
| OAuth / SAML / JWT / redirect_uri | `references/playbooks/oauth-saml-jwt/00-index.md` |
| REST API / BOLA / Mass Assignment / 速率 | `references/playbooks/api-rest/00-index.md` |
| 任何用户输入进 DB | `references/playbooks/sqli.md` |
| 反序列化 / SSTI / XXE / 原型链 / 框架 RCE | `references/playbooks/rce/00-index.md` |
| URL 入参 / 缓存 / Host 注入 | `references/playbooks/ssrf-cache-host/00-index.md` |
| 文件路径入参 / LFI / RFI | `references/playbooks/path-traversal/00-index.md` |
| 上传点 + 解析漏洞 | `references/playbooks/file-upload/00-index.md` |
| 用户输入回显到 HTML / JS | `references/playbooks/xss/00-index.md` |
| 反代 + Content-Length / TE | `references/playbooks/http-smuggling.md` |
| GraphQL endpoint / introspection | `references/playbooks/graphql.md` |
| 并发 / TOCTOU | `references/playbooks/race-conditions.md` |
| ReDoS / 资源不限速 / 算法爆炸 | `references/playbooks/dos.md` |
| APK / IPA / 移动端 | `references/playbooks/mobile.md` |
| LLM agent / prompt 入口 / 工具调用 | `references/playbooks/llm-prompt-injection/00-index.md` |
| 已拿到 shell / 凭据 / 内网 | `references/playbooks/intranet-postexp/00-index.md` |

**两步 Read 模式(已拆分的 playbook)**:目录形式的 playbook(`rce/` / `oauth-saml-jwt/` / `ssrf-cache-host/` / `api-rest/` / `logic-flaws/` / `file-upload/` / `path-traversal/` / `xss/` / `llm-prompt-injection/` / `intranet-postexp/`)第一步只 Read `00-index.md`——它含**子文件路由表**和通用方法论。**不要把 00-index 当 payload 库用**,据子文件路由定位到具体场景后**再 Read 对应子文件**(如 `rce/14-ssti.md` / `oauth-saml-jwt/12-jwt.md`)。单文件形式的 playbook(`sqli.md` / `xxx.md`)直接 Read 即可。

**通用方法论**(仅在卡壳时 Read,不要预加载):
- 不知道下一步打什么 → `references/methodology/01-attack-priority.md`
- 被 WAF / EDR 拦 → `references/methodology/02-bypass-toolkit.md`
- 怀疑自己幻觉 / 想检查证据链 → `references/methodology/03-evidence-discipline.md`
- 找不到漏洞点 → `references/methodology/04-control-gap-hunting.md`

---

## Phase 5 · Report(提交)

**进入条件**:Phase 4 至少一个 finding 已具备可重现 HTTP 包 / 截图 / 视频。

**MUST 流程**(顺序执行):
1. Read `references/compliance.md` 核对合规红线(不准跳)
2. Read `references/templates/report-submission.md` 取模板
3. 三段式输出:
   - **标题**:≤80 字,精确到 endpoint + 漏洞类型
   - **重现步骤**:每步可执行,带 HTTP 包 / curl / 截图
   - **影响 + 修复建议**:CVSS 4.0 vector + 业务影响段

---

## MCP 工具集成

默认 `mcp__jshook__search_tools` + `mcp__jshook__activate_tools` 按需激活(~3K token)。完整索引仅在用户问"用什么工具 / Burp / Frida / adb"时 Read:`references/tools/mcp-jshook.md`。
