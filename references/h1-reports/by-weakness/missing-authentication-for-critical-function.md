# Missing Authentication for Critical Function

_2 reports — High/Critical, disclosed_

### [Authentication bypass  for  ███  leads to  take over any users account.](https://hackerone.com/reports/1608151)

- **Report ID:** `1608151`
- **Severity:** Critical
- **Weakness:** Missing Authentication for Critical Function
- **Program:** Krisp
- **Reporter:** @20_root
- **Bounty:** - usd
- **Disclosed:** 2022-10-31T17:56:04.359Z
- **CVE(s):** -

**Summary (team):**

@n0_m3rcy has identified and reported an account takeover issue which required no user interaction.
We would like to thank @n0_m3rcy for reporting it responsibly to our bug bounty program !

---

### [Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password](https://hackerone.com/reports/739737)

- **Report ID:** `739737`
- **Severity:** High
- **Weakness:** Missing Authentication for Critical Function
- **Program:** PayPal
- **Reporter:** @alexbirsan
- **Bounty:** 15300 usd
- **Disclosed:** 2020-01-08T16:31:37.333Z
- **CVE(s):** -

**Summary (team):**

A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA.

The researcher identified a method by which a user, starting from a malicious site, could expose the security challenge token to a third party via a cross-site script inclusion (XSSI) attack. If the user then followed a login link from the malicious site and entered their credentials, the malicious third party could complete the security challenge, triggering the authentication request replay and exposing the user's password. This exposure only occurred if a user followed a login link from a malicious site, similar to a phishing page. 

PayPal implemented additional controls on the security challenge request to prevent token reuse, which resolved the issue, and no evidence of abuse was found.

**Summary (researcher):**

Full write-up available here: 

https://medium.com/@alex.birsan/the-bug-that-exposed-your-paypal-password-539fc2896da9?sk=aeba33c3c331c3f06d230296a21a41e7

---
