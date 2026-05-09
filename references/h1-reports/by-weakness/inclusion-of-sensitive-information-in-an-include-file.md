# Inclusion of Sensitive Information in an Include File

_1 reports — High/Critical, disclosed_

### [Critical Information Disclosure via /talos/api/v1/files/upload](https://hackerone.com/reports/3228011)

- **Report ID:** `3228011`
- **Severity:** Critical
- **Weakness:** Inclusion of Sensitive Information in an Include File
- **Program:** Bykea
- **Reporter:** @sameer_ali
- **Bounty:** - usd
- **Disclosed:** 2025-09-17T19:09:12.115Z
- **CVE(s):** -

**Summary (team):**

@sameer_ali discovered a vulnerability in the file upload functionality where uploaded files were first stored on the server before being sent to S3. Due to a configuration  flaw, memory chunks from the server were included in some uploaded files. This issue was classified as Critical and was addressed as a priority.

---
