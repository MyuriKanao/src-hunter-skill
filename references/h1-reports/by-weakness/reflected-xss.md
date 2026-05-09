# Reflected XSS

_1 reports — High/Critical, disclosed_

### [Reflected XSS on Amazon EC2 Instance](https://hackerone.com/reports/2787650)

- **Report ID:** `2787650`
- **Severity:** High
- **Weakness:** Reflected XSS
- **Program:** AWS VDP
- **Reporter:** @perigou
- **Bounty:** - usd
- **Disclosed:** 2024-12-24T18:09:23.612Z
- **CVE(s):** CVE-2022-29548

**Vulnerability Information:**

Product: Amazon Elastic Compute Cloud (Amazon EC2)

Vulnerability Type:  Reflected Cross-Site Scripting (XSS)

CVE: CVE-2022-29548
Severity:  Medium

Description:
 A reflected XSS vulnerability was discovered on the Amazon EC2 instance, allowing an attacker to inject malicious JavaScript code, potentially leading to unauthorized access to sensitive data or system compromise.
Proof of Concept:

URL: ███████);alert(document.domain)//

## Impact

## The payload is injected into the errorCode parameter, which is reflected back to the user without proper validation or sanitization. This allows an attacker to execute arbitrary JavaScript code in the context of the vulnerable page

---
