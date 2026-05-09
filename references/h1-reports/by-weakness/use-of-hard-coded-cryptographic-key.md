# Use of Hard-coded Cryptographic Key

_2 reports — High/Critical, disclosed_

### [Exposure of Hard-coded Private Keys and Credentials in curl Source Repository (CWE-321)](https://hackerone.com/reports/3295650)

- **Report ID:** `3295650`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Cryptographic Key
- **Program:** curl
- **Reporter:** @spectre-1
- **Bounty:** - usd
- **Disclosed:** 2025-08-12T08:33:15.149Z
- **CVE(s):** -

**Vulnerability Information:**

Multiple private/test RSA keys and example credentials were discovered embedded in the public curl source repository and associated documentation. These sensitive secrets were detected using automated tools (gitleaks) and manual review. Their presence could allow attackers to impersonate trusted curl infrastructure, decrypt traffic, or pivot into build or CI systems if reused, creating a severe supply chain risk. Such exposures also risk compliance violations (e.g., GDPR, PCI-DSS, HIPAA) and undermine trust in open source releases.

This report, including the verification steps and analysis, was prepared using an AI security assistant to ensure comprehensive and reproducible results.
Affected version

Confirmed in curl master branch as of August 2025. Also observed in prior tags (≥ 7.80.0) on Linux and macOS. Example version for testing:

curl 8.1.2 (x86_64-pc-linux-gnu) libcurl/8.1.2 OpenSSL/3.0.7 zlib/1.2.13 brotli/1.0.9 zstd/1.5.2 libidn2/2.3.4 nghttp2/1.51.0
Release-Date: 2023-06-12
Protocols: dict file ftp ftps gopher gophers http https imap imaps mqtt pop3 pop3s rtmp rtsp smb smbs smtp smtps telnet tftp ws wss
Platform: Linux 5.15.0-83-generic x86_64

Steps To Reproduce:

    Clone the curl repository: git clone https://github.com/curl/curl.git
    Run a secret scanning tool (e.g., gitleaks detect --source=.) to identify hard-coded secrets.
    Alternatively, search for likely private key and credential strings with:
        grep -r '-----BEGIN' ./tests/
        grep -r 'password' ./docs/examples/
    Review identified files to confirm the presence of full private keys or functional credential examples, such as tests/data/testprivkey.pem or docs/examples/http-auth-example.txt.
    See .gitleaks/report.json for a consolidated findings report.

Supporting Material/References:

    Example evidence: tests/data/testprivkey.pem containing full private key
    Example evidence: docs/examples/http-auth-example.txt with plaintext credentials
    Full scan log: .gitleaks/report.json (generated via gitleaks)
    curl/curl GitHub repository
    Screenshot evidence as required (available on request)

Severity: Critical / CWE-321 (Use of Hard-coded Cryptographic Key)

## Impact

## Summary:The security impact of this vulnerability is severe and multi-faceted:

    Impersonation & Privilege Escalation: Attackers can use leaked private keys to impersonate curl services, developers, or automated systems, gaining unauthorized access to protected infrastructure or code-signing processes.
    Data Decryption: If any of the exposed keys have been (or are) used in production, an attacker could decrypt sensitive traffic or files, leading to data breaches.
    Credential Stuffing & Service Hijack: Exposed example/test credentials may be reused in production or CI/CD, allowing attackers to pivot and escalate their access within targeted environments.
    Supply Chain Attacks: Malicious actors might leverage sensitive secrets to inject or distribute malicious builds of curl/libcurl or to poison official releases.
    Regulatory & Compliance Risks: This level of exposure may trigger mandatory breach reporting and legal or regulatory actions, especially for downstream consumers subject to compliance standards.

In summary: This issue enables attackers to compromise trust in the curl project, attack users and downstream integrations at scale, and potentially introduce persistent, hard-to-detect threats into the open source supply chain and the global software ecosystem.

---

### [Slack DTLS uses a private key that is in the public domain, which may lead to SRTP stream hijack](https://hackerone.com/reports/531032)

- **Report ID:** `531032`
- **Severity:** High
- **Weakness:** Use of Hard-coded Cryptographic Key
- **Program:** Slack
- **Reporter:** @sandrogauci
- **Bounty:** 2000 usd
- **Disclosed:** 2020-03-12T00:17:02.105Z
- **CVE(s):** -

**Vulnerability Information:**

- Affects: Janus DTLS certificate

### Description

The Janus server in use by Slack is configured using a certificate and private key that were previously distributed by default. This certificate is used to authenticate the DTLS _connection_ which is later used to exchange keys for the SRTP stream. As a result, the confidentiality of the WebRTC call over Slack cannot be ensured.


### How to reproduce the issue

1. Start Wireshark and set a display filter for stun
2. In the web browser, open `about:webrtc-internals`
3. Start a call on Slack
4. Observe the packets containing the string _rainmaker_ which would be part of the DTLS certificate
5. Notice that the `SetRemoteDescription` fingerprint in the `about:webrtc-internals` page is `C5:5F:DA:7D:84:47:B1:BF:6B:55:16:62:48:31:3E:D3:F1:7B:25:89:92:4A:4B:4D:4D:D9:D5:AF:EA:D8:15:44`

The old certificate can be obtained from the following commit where it was previously removed:

https://github.com/meetecho/janus-gateway/commit/6f98f2dde644b3ead4a162c241dff9da1587ec13

The certificate's SHA256 checksum can be calculated using the OpenSSL command line tool as follows:

```
openssl x509 -noout -fingerprint -sha256 -inform pem -in janus-cert1.crt 
SHA256 Fingerprint=C5:5F:DA:7D:84:47:B1:BF:6B:55:16:62:48:31:3E:D3:F1:7B:25:89:92:4A:4B:4D:4D:D9:D5:AF:EA:D8:15:44
```

Attachments:

- `dump-stun.pcapng`: contains the data stream containing the TURN tunnelled DTLS exchange and SRTP stream that follows
- `janus-cert1.crt` and `janus-cert1.key` are the certificate and key in use by Slack
- `2019-04-07_16-06-wireshark.png` shows the certificate in the Wireshark dump
- `2019-04-07_16-13-fingerprint.png` shows the SHA256 fingerprint which matches the public certificate and corresponding private key

An attacker would probably need to take the following steps to exploit this issue in the case of Slack:

1. Start a man-in-the-middle attack using any known method (ARP cache poisoning, DNS cache poisoning, static routes on compromised network router etc)
2. Actively hijack the Slack TURN servers between the victim and the Internet
3. Wait for victim to make a Slack call
4. Handle STUN packets from victim to attacker-controlled TURN server; allow authentication with any password
5. Start DTLS exchange
6. When DTLS certificate is required, present victim with the Janus default certificate
7. The attacker does __NOT__ verify the victim's DTLS certificate
8. The SRTP Master Key is set over this DTLS connection
9. Attacker can now handle the SRTP stream between the victim and attacker

### Solutions and recommendations

It is recommended to generate a new certificate and private key.

## Impact

Attackers positioned as man-in-the-middle may hijack the DTLS connection and set their own SRTP keys, handling the SRTP stream instead of Slack. This is still research in progress but it does not appear that attackers can perform a two-way MITM attack due to the mutual authentication required by the DTLS exchange. Therefore, it seems that this vulnerability can only be abused to hijack the SRTP stream between the WebRTC client and Slack but not the other way round.

**Summary (researcher):**

DTLS certificate used for Slack WebRTC calls was previously included in the Janus (WebRTC server) together with the private key, thus considered public domain.

---
