# Information Exposure Through Debug Information

_5 reports — High/Critical, disclosed_

### [ASP.NET Application Trace Enabled](https://hackerone.com/reports/2928785)

- **Report ID:** `2928785`
- **Severity:** High
- **Weakness:** Information Exposure Through Debug Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:36:41.215Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The ASP.NET application trace feature is enabled on the public-facing URL: ██████████. This exposes sensitive internal information, including Session ID values and the physical file paths of server-side resources. An attacker could leverage this data to gain unauthorized insights into the server environment or session management mechanisms, increasing the risk of further exploitation.

PoC: ██████

## References

███████
███

## Impact

Information Disclosure: Reveals internal application structure and configuration.
Session Hijacking Risk: Exposed Session ID values could potentially allow unauthorized access to active user sessions.
Attack Surface Expansion: Exposed file paths and server-side request details can aid in reconnaissance for further exploitation attempts.

## System Host(s)
██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Open the link.

## Suggested Mitigation/Remediation Actions
Remove this file from your website or change its permissions to remove access.

More information: https://www.acunetix.com/vulnerabilities/web/trace-axd-detected/

---

### [Information Disclosure through DEBUG at Subscription [https://app.dropcontact.io/app/subscription?connector=salesforce](CRITICAL)](https://hackerone.com/reports/963921)

- **Report ID:** `963921`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Debug Information
- **Program:** Dropcontact
- **Reporter:** @xploiterr
- **Bounty:** - usd
- **Disclosed:** 2020-08-21T07:53:17.706Z
- **CVE(s):** -

**Summary (team):**

We were displaying some sytem information in case of app crashing.

---

### [Information Disclosure through Sentry Instance ███████](https://hackerone.com/reports/697512)

- **Report ID:** `697512`
- **Severity:** High
- **Weakness:** Information Exposure Through Debug Information
- **Program:** Eternal
- **Reporter:** @chajer
- **Bounty:** 750 usd
- **Disclosed:** 2019-09-19T09:27:08.719Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team 


I found a bug (sensitive information ) can be used from attackers to perfom attack in youre server 
I don't know if this in scope so i'm sorry if i'm wrrong 

withou spending youre time 
 here the steps how i found this bug :

1-Please use burp suite to reproduce the same result 
2-i notice you have as tool for track errors (sentry) 
3- i send the request to ███ via /api/20/store█████████

4-change request from get to post 
Request:
==
POST /api/20/store██████ HTTP/1.1
Host: ███
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
██████
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Sec-Fetch-Site: none
Accept-Encoding: gzip, deflate
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
5-go to response and click in the [Render ] to view disclosure UI 
6- i get alot of information disclosure ███(see my screenns) i think the server behind this is [███] with ███

## Impact

Please see the screens for more information 
best regards 
let me know if you need more information.

---

### [Trace.axd page leaks sensitive information](https://hackerone.com/reports/519418)

- **Report ID:** `519418`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Debug Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @arinerron2
- **Bounty:** - usd
- **Disclosed:** 2019-08-19T12:21:03.090Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

`Trace.axd` leaks sensitive information on `██████████` by allowing signed in users to view previous requests sent to the webserver.

## Impact

Information leaked includes (but is not limited to):
- full names
- email addresses
- social security numbers
- dates of birth
- plaintext passwords
- cookies, session tokens, and CSRF tokens
- IP addresses and headers
- application specific information (endpoints, files and directories on the filesystem, software versions, )

## Step-by-step Reproduction Instructions

1. Visit https://████████/Gateway/sso.aspx and sign in. Note that any user can create a user (and any privilege level works for this vulnerability as long as a user is signed in), so this should be considered an unauthenticated vulnerability.
2. Visit https://██████████/████/Trace.axd
3. Click on `View Details` for any request that seems interesting. You can find social security numbers by visiting any of the `/candidate_app/dspstatus.aspx` pages and then Ctrl+F'ing for `app_ssn`.

## Suggested Mitigation/Remediation Actions

Disable `Trace.axd`. https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/ms972204(v=msdn.10)

## Impact

Any attacker can potentially access the following information of current or future Navy personnel:
- full names
- email addresses
- social security numbers
- dates of birth
- plaintext passwords
- cookies, session tokens, and CSRF tokens
- IP addresses and headers
- application specific information (endpoints, files and directories on the filesystem, software versions, )

**Summary (researcher):**

See the writeup at https://aaronesau.com/blog/posts/5

---

### [Real Time Error Logs Through Debug Information](https://hackerone.com/reports/503283)

- **Report ID:** `503283`
- **Severity:** High
- **Weakness:** Information Exposure Through Debug Information
- **Program:** Slack
- **Reporter:** @rubaljain
- **Bounty:** - usd
- **Disclosed:** 2019-04-11T09:15:29.815Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary**: During the assessment, I have found the debug URL on slackb.com which is disclosing the World Wide real time error logs of Slack users.

The information leaked includes the following:
1. User Device Information
2. Redacted Token
3. Client IP Address
4. Description
5. Session ID
6. Team ID
7. User ID
8. User Agent
9. Server Response
10. Timestamp
11. api_call
12. x-amz-cf-id
13. x-amz-id-2

And other user sensitive information.

**Steps to Reproduce**

Open below URL in browser and refresh it to see real time logs.

https://slackb.com/debug

The vulnerable domain here is slackb.com. I have confirmed this with Slack to report this on Hackerone and mention the vulnerable domain.

## Impact

By exploiting this vulnerabiliti​y, an attacker can dump the real-time logs and information gained through this is critical which includes the team ID, user ID and redacted token which allows attackers to gather information which can be used later in the attack lifecycle, in order to achieve more than they could if they didn’t get access to such information.

---
