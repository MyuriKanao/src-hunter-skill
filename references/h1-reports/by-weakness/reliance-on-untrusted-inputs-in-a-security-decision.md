# Reliance on Untrusted Inputs in a Security Decision

_2 reports — High/Critical, disclosed_

### [[High] MITM via Insecure CA Path Handling in cURL (--capath, CURLOPT_CAPATH) (CWE-494: Download of Code Without Integrity Check)](https://hackerone.com/reports/3120969)

- **Report ID:** `3120969`
- **Severity:** High
- **Weakness:** Reliance on Untrusted Inputs in a Security Decision
- **Program:** curl
- **Reporter:** @oicus
- **Bounty:** - usd
- **Disclosed:** 2025-06-30T18:55:20.079Z
- **CVE(s):** CVE-2022-32221

**Vulnerability Information:**

## Summary:
The --capath option in cURL and CURLOPT_CAPATH in libcurl accept any directory path without validation. If an attacker provides a custom CA path containing a fake root certificate, cURL will trust malicious HTTPS endpoints signed with that fake root. This allows for full Man-in-the-Middle (MITM) attacks and silent decryption of HTTPS traffic without user warnings.

## Affected version
Affected Asset:

Component: cURL CLI and libcurl
Versions: 7.82.0 to 8.4.0
Platform: All OS (Linux, macOS, Windows)


## Steps To Reproduce:
Works across OS, no user interaction required, and reproducible without root.
1.Create Fake Root CA:
 openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout fake.key -out fake.crt \
  -subj "/CN=FakeMITMRoot" -days 365

2.Prepare a directory:
mkdir -p /tmp/fake-ca
cp fake.crt /tmp/fake-ca

3.Run vulnerable cURL command:
curl --capath /tmp/fake-ca https://example.com

4.If the server’s TLS certificate was signed by this fake CA, cURL connects successfully and exposes decrypted HTTPS data.
Environment Tested:

curl 7.85.0 (x86_64-pc-linux-gnu) libcurl/7.85.0 OpenSSL/3.0.2

## Supporting Material/References:
References:

CWE-494: https://cwe.mitre.org/data/definitions/494.html
Similar CVE: CVE-2022-32221
cURL Docs: https://curl.se/docs/manpage.html

Recommendation:

Add a whitelist or allowlist of trusted CA directories (e.g., /etc/ssl/certs/, /usr/share/ca-certificates/).
Warn users if non-standard --capath is used.
Consider validating contents with signed manifests or checksum hashes.

Disclosure Policy:

PoC and full exploit details available upon request.
I adhere to a 90-day responsible disclosure timeline.

## Impact

| Vector               | Risk Description                                                                 |

| MITM & Decryption    | Attacker silently decrypts HTTPS (credentials, tokens, sessions).                |
| Silent Exploitation  | No TLS warning shown, making the attack stealthy.                                |
| Cross-Platform Abuse | Affects Linux, Windows, macOS, containers, and CI/CD tools using `libcurl`.      |
| Supply Chain Attack  | Tools and apps that dynamically set `CURLOPT_CAPATH` can be abused automatically.|

---

### [Helpdesk Takeover at dmc.datastax.com](https://hackerone.com/reports/759454)

- **Report ID:** `759454`
- **Severity:** High
- **Weakness:** Reliance on Untrusted Inputs in a Security Decision
- **Program:** DataStax
- **Reporter:** @matrixsoftsec
- **Bounty:** - usd
- **Disclosed:** 2020-01-15T17:49:43.120Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
DNS record [dmc.datastax.com](dmc.datastax.com) is pointing to stale [dmc-support.zendesk.com](dmc-support.zendesk.com) domain on Zendesk which is available for takeover.

DNS Stale Records: {F661014}


## Proof of Concept:
There was no helpdesk configured at this address, which means that the address was available and anyone could claim it. I was able to claim dmc-support.zendesk.com.

On this page, https://dmc.datastax.com/hc/en-us I haven't made the page public, I'm attaching a screenshot of the webpage:
{F661004} 

## Supporting Material/References:
Login page:
{F661021}

## Impact

Subdomain takeover

---
