# Plaintext Storage of a Password

_2 reports — High/Critical, disclosed_

### [Arbitrary File Reading on Uber SSL VPN](https://hackerone.com/reports/617543)

- **Report ID:** `617543`
- **Severity:** High
- **Weakness:** Plaintext Storage of a Password
- **Program:** Uber
- **Reporter:** @orange
- **Bounty:** 6500 usd
- **Disclosed:** 2021-02-25T21:25:15.447Z
- **CVE(s):** CVE-2019-11510, CVE-2019-11542, CVE-2019-11539, CVE-2019-11538, CVE-2019-11508, CVE-2019-11540

**Summary (team):**

The hacker has found a series of 0 day related to Pulse Secure SSL VPN.

---

### [Password of failed (2FA) login attempt is stored in log](https://hackerone.com/reports/244092)

- **Report ID:** `244092`
- **Severity:** High
- **Weakness:** Plaintext Storage of a Password
- **Program:** Nextcloud
- **Reporter:** @maprambo
- **Bounty:** - usd
- **Disclosed:** 2020-03-01T14:10:53.113Z
- **CVE(s):** -

**Vulnerability Information:**

If I try to log in on Webdav with my usual Nextcloud password, it doesn't work due to 2FA. I need an application password.

The password of a failed login attempt by any user is stored plain text in the log:
`[...]OCA\\\\DAV\\\\Connector\\\\Sabre\\\\Auth->validateUserPass('matthes', '***THE_PASSWORD***')[...]`

Even though the login attempt failed, the password is the right password. I am using two factor, but still, the password may not be leaked to anyone. It may also be used for other websites or services, like LDAP. And you can disable 2FA and still use the same password. The log is in some cases visible to multiple people, may it be admins (but who shouldn't have access to the user data) or if the file is just sent to someone else for debugging.

---
