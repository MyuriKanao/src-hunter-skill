# Missing Critical Step in Authentication

_1 reports — High/Critical, disclosed_

### [JWT audience claim is not verified](https://hackerone.com/reports/1889161)

- **Report ID:** `1889161`
- **Severity:** Critical
- **Weakness:** Missing Critical Step in Authentication
- **Program:** Internet Bug Bounty
- **Reporter:** @farcaller
- **Bounty:** - usd
- **Disclosed:** 2023-04-16T18:43:01.524Z
- **CVE(s):** CVE-2023-22482

**Vulnerability Information:**

All versions of Argo CD starting with v1.8.2 are vulnerable to an improper authorization bug causing the API to accept certain invalid tokens.

OIDC providers include an aud (audience) claim in signed tokens. The value of that claim specifies the intended audience(s) of the token (i.e. the service or services which are meant to accept the token). Argo CD does validate that the token was signed by Argo CD's configured OIDC provider. But Argo CD does not validate the audience claim, so it will accept tokens that are not intended for Argo CD.

## Impact

If Argo CD's configured OIDC provider also serves other audiences (for example, a file storage service), then Argo CD will accept a token intended for one of those other audiences. Argo CD will grant the user privileges based on the token's groups claim, even though those groups were not intended to be used by Argo CD.

This bug also increases the blast radius of a stolen token. If an attacker steals a valid token for a different audience, they can use it to access Argo CD.

**Summary (team):**

JWT audience claim is not verified 
Severity: Critical

Description
Impact
All versions of Argo CD starting with v1.8.2 are vulnerable to an improper authorization bug causing the API to accept certain invalid tokens.

OIDC providers include an aud (audience) claim in signed tokens. The value of that claim specifies the intended audience(s) of the token (i.e. the service or services which are meant to accept the token). Argo CD does validate that the token was signed by Argo CD's configured OIDC provider. But Argo CD does not validate the audience claim, so it will accept tokens that are not intended for Argo CD.

If Argo CD's configured OIDC provider also serves other audiences (for example, a file storage service), then Argo CD will accept a token intended for one of those other audiences. Argo CD will grant the user privileges based on the token's groups claim, even though those groups were not intended to be used by Argo CD.

This bug also increases the blast radius of a stolen token. If an attacker steals a valid token for a different audience, they can use it to access Argo CD.

Patches
A patch for this vulnerability has been released in the following Argo CD versions:

v2.6.0-rc5
v2.5.8
v2.4.20
v2.3.14

Credits
The Argo CD team would like to express their gratitude to Vladimir Pouzanov [@farcaller](https://github.com/farcaller) from Indeed, who discovered the issue, reported it confidentially according to our guidelines, and actively worked with the project to provide a remedy. Many thanks to Vladimir!

Full GHSA: https://github.com/argoproj/argo-cd/security/advisories/GHSA-q9hr-j4rf-8fjc

---
