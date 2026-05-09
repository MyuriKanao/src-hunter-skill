# External Control of Critical State Data

_2 reports — High/Critical, disclosed_

### [match](https://hackerone.com/reports/1555440)

- **Report ID:** `1555440`
- **Severity:** High
- **Weakness:** External Control of Critical State Data
- **Program:** curl
- **Reporter:** @maslahhunter
- **Bounty:** - usd
- **Disclosed:** 2022-06-09T07:09:50.376Z
- **CVE(s):** -

**Vulnerability Information:**

## Steps To Reproduce:
lib/telnet.c suboption function incorrecly checks for the sscanf return value. Instead of checking that 2 elements are parsed, the code also continues if just one element matches:
if(sscanf(v->data, "%127[^,],%127s", varname, varval)) {
As such it is possible to construct environment values that don't update the varval buffer and instead use the previous value. In combination of advancing in the temp buffer by strlen(v->data) + 1, this means that there will be uninitialized gaps in the generated output temp buffer. These gaps will contain whatever stack contents from previous operation of the application.
Fortunately the environment is controlled by the client and not the server. As such this vulnerability can't be exploited by the server. Practical exploitation is limited by the following requirements:
attacker is able to control the environment passed to libcurl via CURLOPT_TELNETOPTIONS ("NEW_ENV=xxx,yyy") and control xxx and yyy in the curl_slist entries)
attacker is able to either inspect the network traffic of the telnet connection or to select the server/port the connection is established to
When both are true the attacker is able to some content of the stack. Note however that for this leak to be meaningful, some confidential or sensitive information would need to be leaked. This could happen if some key or other sensitive material (that is otherwise out of the reach of the attacker, due to for example setuid + dropping of privileges, or for example only being able to execute the command remotely in a limited fashion, for example php curl, or similar) would thus become visible fully, or partially. The leak is limited to maximum about half of the 2048 byte temp buffer.
Steps To Reproduce:
Run telnet service
tcpdump -i lo -X -s 65535 port 23
Execute

## Impact

lib/telnet.c suboption function incorrecly checks for the sscanf return value. Instead of checking that 2 elements are parsed, the code also continues if just one element matches:
if(sscanf(v->data, "%127[^,],%127s", varname, varval)) {
As such it is possible to construct environment values that don't update the varval buffer and instead use the previous value. In combination of advancing in the temp buffer by strlen(v->data) + 1, this means that there will be uninitialized gaps in the generated output temp buffer. These gaps will contain whatever stack contents from previous operation of the application.
Fortunately the environment is controlled by the client and not the server. As such this vulnerability can't be exploited by the server. Practical exploitation is limited by the following requirements:
attacker is able to control the environment passed to libcurl via CURLOPT_TELNETOPTIONS ("NEW_ENV=xxx,yyy") and control xxx and yyy in the curl_slist entries)
attacker is able to either inspect the network traffic of the telnet connection or to select the server/port the connection is established to
When both are true the attacker is able to some content of the stack. Note however that for this leak to be meaningful, some confidential or sensitive information would need to be leaked. This could happen if some key or other sensitive material (that is otherwise out of the reach of the attacker, due to for example setuid + dropping of privileges, or for example only being able to execute the command remotely in a limited fashion, for example php curl, or similar) would thus become visible fully, or partially. The leak is limited to maximum about half of the 2048 byte temp buffer.
Steps To Reproduce:
Run telnet service
tcpdump -i lo -X -s 65535 port 23
Execute

---

### [Disclosure of internal information using hidden NTLM authentication leading to an exploit server](https://hackerone.com/reports/853284)

- **Report ID:** `853284`
- **Severity:** High
- **Weakness:** External Control of Critical State Data
- **Program:** MTN Group
- **Reporter:** @z3lox
- **Bounty:** - usd
- **Disclosed:** 2021-08-04T14:49:10.236Z
- **CVE(s):** -

**Vulnerability Information:**

By using a request get on the url [██████████](███████) of the blog.
we collect sensitive information from blogs
## step 
Typically, when visiting a website  █████████ or directory  ██████ requiring privileged access, the server will initiate a login prompt. This allows the client to send blank username and password values to check for NTLM authentication and receive the encoded response. However, if the target server is configured to allow windowsAuthentication, it may be possible to invoke this response without a login prompt. This can be done by adding “Authorization: ███” to the request headers.
Once an NTLM challenge is returned in the “WWW-Authenticate” value of the response headers, it can be decoded to capture internal information. I personally use Burp’s NTLM Challenge Decoder, but multiple other scripts have been written that can perform these actions.

```
GET /fr/Pages/ HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/██████████ Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: ███
Upgrade-Insecure-Requests: 1
Authorization: ████████
```

```
Target MTNICT
MsvAvNbComputerName ZACNVSPRWSBS01
MsvAvDnsDomainName mtnict.local
Windows Server 2012 R2 / Windows 8.1 version
MsvAvNbDomainName MTNICT
MsvAvDnsComputerName ZACNVSPRWSBS01.mtnict.local
MsvAvDnsTreeName mtnict.local
MsvAvTimestamp ████ ████████
```
This same vulnerability is present on the blog ███████

```
Target	MTNGROUPSA
MsvAvNbComputerName	PSWSPEMVA21
MsvAvDnsDomainName	mtn.co.za
Version	Windows Server 2012 R2 / Windows 8.1
MsvAvNbDomainName	MTNGROUPSA
MsvAvDnsComputerName	PSWSPEMVA21.mtn.co.za
MsvAvDnsTreeName	mtn.co.za
MsvAvTimestamp	███████ █████████

```
Obviously we have a Target name, computer name, and the essential version:
version of Windows Server 2012 R2 / Windows 8.1 vulnerable to a remote attack, MS17-010: CVE: 2017-0144
Let run metasploite with the exploit Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)   
Exploiting this vulnerability would be going against the rules of politics
I would like to point out that this vulnerability is clearly dangerous and its exploitation would just be a game for an intentional bad attacker.

```
 -------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                  |  Path
                                                                                                                                | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)       | exploits/windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                                   | exploits/windows/dos/41891.rb
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                      | exploits/windows_x86-64/remote/42030.py
-------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
```

## Impact

>-Malicious attackers can add bitcoin mining source code to the site architecture
>-Modified changes to the database
>-Collect person information on blog staff

---
