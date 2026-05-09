# Using Components with Known Vulnerabilities

_1 reports — High/Critical, disclosed_

### [CVE-2020-5902 ](https://hackerone.com/reports/2794126)

- **Report ID:** `2794126`
- **Severity:** Critical
- **Weakness:** Using Components with Known Vulnerabilities
- **Program:** AWS VDP
- **Reporter:** @perigou
- **Bounty:** - usd
- **Disclosed:** 2024-12-24T18:07:49.908Z
- **CVE(s):** CVE-2020-5902

**Vulnerability Information:**

**CVE ID: ** CVE-2020-5902

**Description:** 
Affected Product: F5 BIG-IP Traffic Management User Interface (TMUI)
Severity: Critical
CVSS Score: 9.8
Description: Remote Code Execution (RCE) vulnerability in undisclosed pages of the TMUI
CVE-2020-5902 is a critical vulnerability affecting the BIG-IP Traffic Management User Interface (TMUI), also known as the Configuration utility. This vulnerability allows for Remote Code Execution (RCE) in undisclosed pages of the TMUI.
Affected Versions
BIG-IP versions ████
BIG-IP versions █████
BIG-IP versions ███
BIG-IP versions ███
BIG-IP versions ███


## Steps To Reproduce:
## URL :
███
 payload used :/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
Full URL:
█████████?fileName=/etc/passwd

## Impact

## Summary:
The vulnerability can be exploited by an attacker to execute arbitrary code on the affected system, leading to unauthorized access, data breaches, and system compromise.

---
