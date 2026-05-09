# User Interface (UI) Misrepresentation of Critical Information

_2 reports — High/Critical, disclosed_

### [ Incorrect security UI of files' download source on brave MacOS](https://hackerone.com/reports/2888770)

- **Report ID:** `2888770`
- **Severity:** High
- **Weakness:** User Interface (UI) Misrepresentation of Critical Information
- **Program:** Brave Software
- **Reporter:** @syarif07
- **Bounty:** - usd
- **Disclosed:** 2025-01-16T22:17:26.441Z
- **CVE(s):** CVE-2025-23086

**Vulnerability Information:**

## Summary:
This vulnerability involves the incorrect display of the download source in the Brave download alert. Instead of displaying the actual source of the downloaded file, the browser displays the referrer header value, which may mislead the user into believing that the file is from a trusted source. This behavior creates a potential security risk as it could allow attackers to trick users into downloading malicious files.

## Products affected: 
Brave is up to date
Version 1.73.97 Chromium: 131.0.6778.108 (Official Build) (arm64)

## Steps To Reproduce:
1. Victim visit: https://ybt01.github.io/upload/google.html#
2. Victim click `click me to download google apk` and will pop up download location with wrong files origin

{F3826618}

## POC 
{F3826622}

## Expected result

The origin source on the download pop up should accurately reflect the actual source of the downloaded file, indicating the URL from which the file was downloaded directly (e.g., https://ybt01.github.io).

## Actual Result

The origin source on the pop up displays the URL of the referring page (e.g., https://google.com), thus misleading the user about the actual source of the downloaded file.

## Supporting Material/References:
This issue is similar to the one in the report: https://issues.chromium.org/issues/352681108 
but this is a different case because in chrome it is not affected. and in brave it is affected in the download pop up while in the chromium report it is affected in chrome: //downloads. However, in terms of impact and scenario this case is similar.

## Impact

This vulnerability can significantly impact user security by providing misleading information about file downloads. Users may unknowingly trust files downloaded from malicious sources, believing they originated from reputable domains. This can facilitate the distribution of malware and other harmful software, especially in targeted attacks by Advanced Persistent Threat (APT) groups or malicious websites that employ social engineering tactics. As a result, the risk of unintentional malware installation on user systems increases, undermining the overall security posture of users.

---

### [Mailsploit: a sender spoofing bug in over 30 email clients](https://hackerone.com/reports/295339)

- **Report ID:** `295339`
- **Severity:** High
- **Weakness:** User Interface (UI) Misrepresentation of Critical Information
- **Program:** Internet Bug Bounty
- **Reporter:** @pwnsdx
- **Bounty:** - usd
- **Disclosed:** 2019-09-19T20:34:46.811Z
- **CVE(s):** -

**Vulnerability Information:**

Mailsploit is a collection of bugs in email clients that allow effective sender spoofing and code injection attacks. The spoofing is not detected by Mail Transfer Agents (MTA) aka email servers, therefore circumventing spoofing protection mechanisms such as DMARC (DKIM/SPF) or spam filters.

Bugs were found in over 30 applications, including prominent ones like Apple Mail (macOS, iOS and watchOS), Mozilla Thunderbird, various Microsoft email clients, Yahoo! Mail, ProtonMail and others.

In addition to the spoofing vulnerability, some of the tested applications also proved to be vulnerable to XSS and code injection attacks.

More informations are available on mailsploit.com

## Impact

It allows the attacker to display an arbitrary sender email address to the email recipient while bypassing spoofing protection mechanisms such as DMARC (DKIM/SPF) or spam filters.

---
