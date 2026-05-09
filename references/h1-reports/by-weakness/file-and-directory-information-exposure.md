# File and Directory Information Exposure

_2 reports — High/Critical, disclosed_

### [Arbitrary File Reading leads to RCE in the Pulse Secure SSL VPN on the https://████](https://hackerone.com/reports/695005)

- **Report ID:** `695005`
- **Severity:** Critical
- **Weakness:** File and Directory Information Exposure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:49:31.429Z
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

I discovered that `https://██████████` instance is vulnerable to described vulnerabilities.

##POC

Reading `/etc/passwd` via CVE-2019-11510:
```
curl -i -k --path-as-is https://██████████/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/
```
```
███████
█████████
██████████
████
█████
██████
███████
████████
███████
```

The RCE can be achieved with this chain:
1) Pulse Secure stores credentials in the cleartext.
2) Attacker reads credentials  and authorizes on VPN
3) Attacker exploits CVE-2019-11539 - Post-auth Command Injection achieving RCE as root.

##Suggested fix
Update the Pulse Secure SSL VPN software.

## Impact

Remote code execution as root (by reading plaintext credentials and then exploiting CVE-2019-11539 - Post-auth Command Injection) and accessing intranet behind VPN.
You can see here example report to Twitter by Orange Tsai: https://hackerone.com/reports/591295

---

### [Open FTP server on a DoD system](https://hackerone.com/reports/192321)

- **Report ID:** `192321`
- **Severity:** High
- **Weakness:** File and Directory Information Exposure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:39:28.302Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I don't know if this qualifies but during my search I discovered an open FTP panel that I was able to successfully log into.   
Using any FTP program,  I used File zilla and then entered ████  as my host then connected. Then I was able to look through any of the files. I noticed the last modified file was  quite recent leading me to believe it's still in us

**Summary (researcher):**

An open FTP panel was discovered which allowed any attackers to connect and upload their files. Initial probing discovered it was still being used by multiple people confirming this was still in use.

---
