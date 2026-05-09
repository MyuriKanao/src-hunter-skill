# Inclusion of Functionality from Untrusted Control Sphere

_1 reports — High/Critical, disclosed_

### [important: Apache HTTP Server may use exploitable/malicious backend application output to run local handlers via internal redirect (CVE-2024-38476)](https://hackerone.com/reports/2585376)

- **Report ID:** `2585376`
- **Severity:** High
- **Weakness:** Inclusion of Functionality from Untrusted Control Sphere
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-13T14:36:20.815Z
- **CVE(s):** CVE-2024-38476

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there:
> https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications whose response headers are malicious or exploitable.

Note: Some legacy uses of the 'AddType' directive to connect a request to a handler must be ported to 'SetHandler' after this fix.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

**Summary (team):**

###important: Apache HTTP Server may use exploitable/malicious backend application output to run local handlers via internal redirect (CVE-2024-38476)

Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications whose response headers are malicious or exploitable.

Note: Some legacy uses of the 'AddType' directive to connect a request to a handler must be ported to 'SetHandler' after this fix.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

Acknowledgements: finder: Orange Tsai (@orange_8361) from DEVCORE

Reported to security team: 2024-04-01
fixed by r1918560 in 2.4.x: 2024-07-01
Update 2.4.60 released: 2024-07-01
Affects: 2.4.0 through 2.4.59

---
