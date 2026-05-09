# Externally Controlled Reference to a Resource in Another Sphere

_2 reports — High/Critical, disclosed_

### [Subdomain takeover of v.zego.com](https://hackerone.com/reports/1180697)

- **Report ID:** `1180697`
- **Severity:** High
- **Weakness:** Externally Controlled Reference to a Resource in Another Sphere
- **Program:** Zego
- **Reporter:** @ian
- **Bounty:** - usd
- **Disclosed:** 2021-06-26T04:22:26.339Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
v.zego.com points to an AWS EC2 instance at 52.214.138.192 that no longer exists. I was able to take control of this IP address and run my own EC2 instance. I can now serve content on this domain, obtain a TLS certificate for this domain, etc.

If any customers or servers are pointing to anything within this domain, I could serve them arbitrary/malicious content. I could also use this in case your domain whitelists your own domain for OAuth, or if there are cookies scoped to the entire domain. Usually this can have a high impact.

### PoC
```
% dig +short v.zego.com
52.214.138.192

% curl v.zego.com
<!-- hackerone.com/ian -->
```

## Impact

Subdomain takeover

---

### [Subdomain takeover of mydailydev.starbucks.com](https://hackerone.com/reports/570651)

- **Report ID:** `570651`
- **Severity:** High
- **Weakness:** Externally Controlled Reference to a Resource in Another Sphere
- **Program:** Starbucks
- **Reporter:** @0xpatrik
- **Bounty:** - usd
- **Disclosed:** 2019-05-22T16:25:42.948Z
- **CVE(s):** -

**Summary (team):**

A subdomain of `starbucks.com` had a CNAME record pointing to an Azure Traffic Manager profile that @0xpatrik was able to claim.

---
