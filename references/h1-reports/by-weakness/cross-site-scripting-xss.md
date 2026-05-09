# Cross-Site Scripting (XSS)

_1 reports — High/Critical, disclosed_

### [[Meetup][World ID][OIDC] Insufficient Filtering of "state" Parameter in Response Mode form_post leads to XSS and ATO](https://hackerone.com/reports/2515808)

- **Report ID:** `2515808`
- **Severity:** Critical
- **Weakness:** Cross-Site Scripting (XSS)
- **Program:** Tools for Humanity
- **Reporter:** @lauritz
- **Bounty:** - usd
- **Disclosed:** 2024-06-19T13:31:09.122Z
- **CVE(s):** -

**Summary (team):**

A lack of proper validation in the state parameter of the World ID OIDC authentication logic allowed the injection of HTML characters into the response body when using form_post as the OIDC response mode. This vulnerability could enable attackers to obtain access tokens from targeted users with minimal user interaction. Additionally, an XSS vulnerability was identified in the same parameter but was mitigated by our Content Security Policy (CSP).

The researcher was able to demonstrate this vulnerability by injecting a button that, when clicked, would direct users to an attacker-controlled site. Since the access token is included in the form HTML, clicking the button would include it in the request, exposing the user's access token.

A bounty of $7,000 was awarded as part of a HackerOne event.

**Summary (researcher):**

A blog post about this report including technical details can be found here: https://security.lauritz-holtmann.de/advisories/tfh-form_post-xss-ato/

I would like to especially thank Ian and Juan of Tools for Humanity for their continuous support throughout and after the [meetup](https://h1.community/events/details/hackerone-germany-hackerone-club-presents-hackerone-hacking-meetup-tools-for-humanity-x-hackerone-club-germany/). 😊

Join your local [H1 Community](https://h1.community/chapters/)!

---
