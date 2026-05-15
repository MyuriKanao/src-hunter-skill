# 内网渗透 / 后渗透 — 决策索引

> ⚠️ **SRC 红线警告**:绝大多数 bug bounty / 众测程序**不允许**内网横向 / 后渗透。在 RCE / 凭据拿到后,**仅证明可达 + 价值**,不实际横向、不读 NTDS、不打 DC。本目录的内容默认用于**红队 / 授权内测 / 已明确允许后渗透的 HVV**。提交 SRC 前必读 [`../compliance.md`](../compliance.md)。

---

## 子文件路由(Phase 4 / 内网后渗透阶段读哪一份?)

| 当前阶段 | 任务 | MUST Read |
|---|---|---|
| 已拿 shell,身份是 user | 找系统凭据 / 浏览器密码 / Kerberos 票据 | `10-credentials.md` |
| 已有一组凭据,需要打第二台机器 | SMB / WMI / PsExec / RDP / WinRM / Pass-the-Hash / Ticket | `11-lateral.md` |
| 拿到 user,需要 root/SYSTEM | UAC bypass / sudo 提权 / 内核 / SUID / Token | `12-privesc.md` |
| 防护强,被 AV/EDR 拦 | AMSI bypass / ETW patch / DLL sideload / unhook | `13-evasion.md` |
| 已进域,要打 DC | Kerberoasting / AS-REP / Golden / Silver / DCSync / Constrained | `14-domain.md` |
| 内网不出网 | reGeorg / frp / Chisel / ICMP / DNS tunnel / SOCKS / ssh -D | `15-tunneling.md` |
| 进了陌生网,先摸地形 | 主机发现 / 端口扫描 / Bloodhound 收集 / hostname / hostfile | `16-recon.md` |
| 拿到 admin,要维持长期访问 | 服务 / 计划任务 / 注册表 / WMI 订阅 / Logon / SSP / Skeleton Key | `17-persistence.md` |
| 目标含 Exchange | NTLM Relay / EWS / OAB / CVE-2021-26855 / Mailbox Export | `18-exchange.md` |
| 目标含 ADCS / 证书服务 | ESC1–ESC8 模板滥用 | `19-adcs.md` |
| 目标含 SharePoint | 信息收集 / SOAP / API / OneDrive 同步 | `20-sharepoint.md` |

---

## 数据规模(原文档)

| 类别 | 数量 |
|---|--:|
| 凭证窃取 | 20 |
| 横向移动 | 16 |
| 权限提升 | 15 |
| 免杀与规避 | 14 |
| 域渗透攻击 | 14 |
| 隧道代理 | 13 |
| 信息收集 | 12 |
| 权限维持 | 12 |
| Exchange攻击 | 5 |
| ADCS攻击 | 5 |
| SharePoint攻击 | 2 |
| **合计** | **128** |

---

## SRC 场景下的"价值升级链停车点"

| 你拿到了 | SRC 允许做的"价值证明" | 不允许做的事 |
|---|---|---|
| Webshell / RCE | `whoami` / `hostname` / `ip route` / `/etc/issue` 截图 | 反弹 shell / 写持久化 / 提权 |
| 一组 SSH key | 截图 key 文件 mode + comment(脱敏) | 用 key 登录他人机器 |
| 一组数据库凭据 | 截图凭据存在 + 标记访问权限范围 | 实际连库 / dump 数据 |
| 进入内网(SSRF 触达) | 探测 1-2 个明确受影响端口的 banner | 端口扫描全网段 / 横向 |
| AWS / GCP credentials | `aws sts get-caller-identity`(只读 identity)| `aws s3 ls` 等枚举操作 |

任何超出"价值证明"的动作 → 立即停 + 回去看 [`../compliance.md`](../compliance.md)。

---

## 与红线规则的关系

- 本文件子目录所有 payload **只在已获授权时使用**(红队、合同测试、HVV)
- SRC 场景下大多数 payload 仅用作"我能做什么"的认知,不准实操
- 一旦提交 finding,价值评级写"假设具备内网持续访问,可进一步..." 而非"已演示横向"
