# Execution with Unnecessary Privileges

_1 reports — High/Critical, disclosed_

### [One Click Code Execution via File](https://hackerone.com/reports/822609)

- **Report ID:** `822609`
- **Severity:** High
- **Weakness:** Execution with Unnecessary Privileges
- **Program:** Evernote
- **Reporter:** @ajdumanhug
- **Bounty:** - usd
- **Disclosed:** 2020-03-24T22:36:11.218Z
- **CVE(s):** CVE-2019-17051

**Summary (team):**

This issue was reported to Evernote by @ajdumanhug and fixed in November 2019. This disclosure is a copy of the original, and is for historical purposes only.

## Overview
The Open with Terminal functional is vulnerable to One Click Code Execution. Tested the vulnerability using the Mac Desktop App version Mac 7.13 and below.

It happens because they don't add com.apple.quarantine meta-attribute for downloaded files to avoid the execution of terminal files.

I already reported this to Evernote, and I just wanted to report it here to ask for disclosure.

## Proof of Concept
https://www.youtube.com/watch?v=OG2tKlZX5bg&feature=youtu.be

## Supporting Material/References:
https://discussion.evernote.com/topic/121459-evernote-for-mac-713/
https://evernote.com/security/updates#MACOSNOTE-28956
https://www.cvedetails.com/cve/CVE-2019-17051/

---
