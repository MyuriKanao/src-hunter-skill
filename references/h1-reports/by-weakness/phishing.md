# Phishing

_5 reports — High/Critical, disclosed_

### [Address Bar Spoofing on TOR Browser](https://hackerone.com/reports/275960)

- **Report ID:** `275960`
- **Severity:** High
- **Weakness:** Phishing
- **Program:** Tor
- **Reporter:** @soulhunter
- **Bounty:** - usd
- **Disclosed:** 2023-01-02T08:43:51.692Z
- **CVE(s):** -

**Vulnerability Information:**

Hi TOR team,

I would like to report a security bug in your browser:

Step 1: Goto http://www.ոokia.com/(http://jsbin.com/wuyikedaxi/1/edit?html,output)
Step 2: Observe that address bar points to http://www.ոokia.com/ which actually to be pointing to http://xn--okia-zgf.com, however browser displays www.ոokia.com/

Actual results:

Address bar points to a spoofed domain http://www.ոokia.com/. Address bar fails to parse character "ո"(U+0578 Armenian Small Letter). Several other characters from Armenian family lead to the same effect. 

Expected results:

TORbrowser should have resolved the domain to real http://xn--okia-zgf.com.  On chrome, internet explorer and firefox it resolves to xn--okia-zgf.com.

---

### [ Github Account hijack through broken link in developer.twitter.com](https://hackerone.com/reports/1031321)

- **Report ID:** `1031321`
- **Severity:** High
- **Weakness:** Phishing
- **Program:** X / xAI
- **Reporter:** @milankatwal99
- **Bounty:** - usd
- **Disclosed:** 2021-02-04T06:25:16.411Z
- **CVE(s):** -

**Vulnerability Information:**

Description
A link in    https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries   was broken and anyone could create that account which leads to account impersonate

Steps To Reproduce
1) Visit https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries
2) Scroll down to Javascript/Node.js and click on by @HunterLarco (v2)
3)  Create github username HunterLarcol
4) When someone visits and scroll down to  javascript/Node.js and click on @HunterLarco (v2). They are redirected to my account

similar report
https://hackerone.com/reports/265696



To solve this issue 
put this link https://github.com/HunterLarco

Please let me know if you have any questions. I am happy to help

## Impact

Impact
The users are coming from developer.twitter.com So, the attacker can put malicious content on the github  and many users will be the victim for example https://github.com/HunterLarcol/twitter-v2. Moreover it leads to the loss in the reputation of the company

---

### [Domian Takeover in [███████]](https://hackerone.com/reports/804080)

- **Report ID:** `804080`
- **Severity:** High
- **Weakness:** Phishing
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xsnowmn
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T18:00:37.928Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
* subscription of ████ is expired so any attacker can takeover it

## Impact

* phishing attacks if any attacker takeovr the domain

---

### [Subdomain Takeover on demo.greenhouse.io pointing to unbouncepages](https://hackerone.com/reports/407355)

- **Report ID:** `407355`
- **Severity:** High
- **Weakness:** Phishing
- **Program:** Greenhouse.io
- **Reporter:** @ninadmathpati
- **Bounty:** - usd
- **Disclosed:** 2020-03-05T11:26:29.424Z
- **CVE(s):** -

**Vulnerability Information:**

Actuall this report is same as of this one:- https://hackerone.com/reports/38007  


Subdomain takeover vulnerabilities occur when a subdomain (subdomain.example.com) is pointing to a service (e.g. GitHub pages, Heroku, etc.) that has been removed or deleted. This allows an attacker to set up a page on the service that was being used and point their page to that subdomain. For example, if subdomain.example.com was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a CNAME file containing subdomain.example.com, and claim subdomain.example.com.

Here there is a greenhouse domain  (demo.greenhouse.io) which is pointing towards unbounce pages so  this domain can be taken over can can be used to do any type of attacks mostly i can make a fake login page on your behalf and spoof your users, this is a critical vulnerability and needs to be fixed .

Vulnerable url : demo.greenhouse.io

PoC
Snapshot of the vulnerable page(actually for taking over from unbounce i need to take a paid subscription hich is of higher cost neraly 150-200$ i cannot afford that so as a poc i m showing you a vulnerable page hoping this should work )

cname: unbouncepages.com
Name: demo.greenhouse.io
Type: CNAME
Class: IN

## Impact

Impact
Risk
fake website
malicious code injection
users tricking
company impersonation
This issue can have really huge impact on the companies reputation someone could post malicious content on the compromised site and then your users will think it's official but it's not.

Remediation
Remove the cname entry or claim the subdomain demo.greenhouse.io on unbounce.com

See also
https://github.com/EdOverflow/can-i-take-over-xyz#unbounce
https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/
https://0xpatrik.com/subdomain-takeover/
https://medium.com/@ajdumanhug/subdomain-takeover-through-external-services-f0f7ee2b93bd
http://yassineaboukir.com/blog/neglected-dns-records-exploited-to-takeover-subdomains/



Best regards,
Hacker2202

---

### [npm packages that overlap with core node packages](https://hackerone.com/reports/333459)

- **Report ID:** `333459`
- **Severity:** High
- **Weakness:** Phishing
- **Program:** Node.js third-party modules
- **Reporter:** @mlucool
- **Bounty:** - usd
- **Disclosed:** 2018-06-16T12:32:41.121Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
  

I have [posted here](https://github.com/npm/registry/issues/306), but I wanted to make you aware of this easy social engineering trick. I do not want to claim any of these are currently malicious, but it they easily could be.

  

Thanks,

Marc

## Impact

The attacker could do anything...use the postinstall as the user, work the same as steal data, etc.

---
