# File Content Injection

_1 reports — High/Critical, disclosed_

### [DNN - Unrestricted Arbitrary File Upload #████████](https://hackerone.com/reports/3414079)

- **Report ID:** `3414079`
- **Severity:** Critical
- **Weakness:** File Content Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xr2r
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:03:57.998Z
- **CVE(s):** CVE-2025-64095

**Vulnerability Information:**

**Description:**
DNN (formerly DotNetNuke) \u003C 10.1.1 contains an unrestricted file upload vulnerability caused by the default HTML editor provider allowing unauthenticated file uploads and overwriting existing files, letting unauthenticated attackers deface websites and inject XSS payloads, exploit requires no authentication.

## References
https://nvd.nist.gov/vuln/detail/CVE-2025-64095

## Impact

Unauthenticated attackers can upload and overwrite files, leading to website defacement and cross-site scripting attacks.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
#Vulnerable subdomain

https://██████████/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx

#Testing the Vulnerability
raw POST request

██████████

## Suggested Mitigation/Remediation Actions
Update to version 10.1.1 or later.

---
