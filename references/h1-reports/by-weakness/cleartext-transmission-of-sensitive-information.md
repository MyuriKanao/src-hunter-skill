# Cleartext Transmission of Sensitive Information

_5 reports — High/Critical, disclosed_

### [Insecure WebSocket Usage in curl Documentation and Examples (CWE-319: Cleartext Transmission of Sensitive Information)](https://hackerone.com/reports/3295652)

- **Report ID:** `3295652`
- **Severity:** High
- **Weakness:** Cleartext Transmission of Sensitive Information
- **Program:** curl
- **Reporter:** @spectre-1
- **Bounty:** - usd
- **Disclosed:** 2025-08-12T08:47:43.093Z
- **CVE(s):** -

**Vulnerability Information:**

The curl source repository contains official documentation and example code that demonstrate WebSocket connections using the insecure ws:// protocol instead of the secure wss://. This misleading guidance may encourage developers to implement cleartext WebSocket endpoints, exposing users and infrastructure to eavesdropping, MITM (Man-in-the-Middle) attacks, and session hijacking. Failing to promote secure defaults in a popular open-source project creates systemic risks for downstream adopters.

This report and its analysis were enhanced and generated using an AI assistant to ensure a comprehensive security review and reproducibility.
Affected version

Verified on the curl master branch as of August 2025. Insecure usage appears in historical releases as well. Example tested version:

curl 8.1.2 (x86_64-pc-linux-gnu) libcurl/8.1.2 OpenSSL/3.0.7 zlib/1.2.13 brotli/1.0.9 zstd/1.5.2 libidn2/2.3.4 nghttp2/1.51.0
Release-Date: 2023-06-12
Protocols: dict file ftp ftps gopher gophers http https imap imaps mqtt pop3 pop3s rtmp rtsp smb smbs smtp smtps telnet tftp ws wss
Platform: Linux 5.15.0-83-generic x86_64

Steps To Reproduce:

    Clone or download the curl GitHub repository.
    Search for insecure WebSocket URIs by running:
        grep -rn 'ws://' ./docs/ ./examples/
    Review the documentation (docs/WEBSOCKETS.md, etc.) and example code (e.g., examples/websocket-client.c) to confirm insecure ws:// references are present and no explicit security warning is provided.
    Validate that instructions or sample code do not require, prefer, or warn about secure WebSocket (wss://) usage.

Supporting Material/References:

    File: docs/WEBSOCKETS.md (e.g., line 15: curl "ws://echo.websocket.org")
    File: examples/websocket-client.c (e.g., line 42: #define WS_URL "ws://test.websocket.org")
    Manual and Semgrep findings for insecure protocol patterns
    curl/curl GitHub repository

## Impact

## Summary:
By demonstrating and failing to warn against insecure WebSocket usage (ws://), curl's documentation may lead developers to implement applications that transmit data over unencrypted channels. This enables attackers to:

    Eavesdrop on user data in transit
    Hijack sessions or inject malicious payloads
    Perform MiTM attacks against production services and infrastructure

For a widely adopted open source tool, propagating insecure defaults has downstream and supply chain impact, potentially affecting thousands of projects. Severity is High, and the most relevant CWE is CWE-319: Cleartext Transmission of Sensitive Information.

---

### [Plaintext leakage of DNS requests in Windows 1.1.1.1 WARP client](https://hackerone.com/reports/1941390)

- **Report ID:** `1941390`
- **Severity:** High
- **Weakness:** Cleartext Transmission of Sensitive Information
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @vanhoefm
- **Bounty:** - usd
- **Disclosed:** 2023-08-03T13:54:06.376Z
- **CVE(s):** CVE-2023-2754

**Summary (team):**

The Cloudflare WARP client for Windows assigns loopback IPv4 addresses for the DNS Servers, since WARP acts as local DNS server that performs DNS queries in a secure manner, however, if a user is connected to WARP over an IPv6-capable network, te WARP client did not assign loopback IPv6 addresses but Unique Local Addresses, which under certain conditions could point towards unknown devices in the same local network which enables an Attacker to view DNS queries made by the device.

---

### [Leak of Google Sheets API credentials](https://hackerone.com/reports/965314)

- **Report ID:** `965314`
- **Severity:** High
- **Weakness:** Cleartext Transmission of Sensitive Information
- **Program:** Azbuka Vkusa
- **Reporter:** @adsec2s
- **Bounty:** - usd
- **Disclosed:** 2021-11-15T20:14:43.457Z
- **CVE(s):** -

**Summary (team):**

Closed.

---

### [Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg](https://hackerone.com/reports/340431)

- **Report ID:** `340431`
- **Severity:** High
- **Weakness:** Cleartext Transmission of Sensitive Information
- **Program:** Uber
- **Reporter:** @healdb
- **Bounty:** 4000 usd
- **Disclosed:** 2020-04-30T21:12:45.704Z
- **CVE(s):** -

**Summary (team):**

lioncityrentals.com.sg employed a Wordpress installation that possessed a vulnerable plugin, Formidable Forms, which was vulnerable to reflected XSS, and exposed sensitive form data. 

Thanks again for the report, @healdb!

**Summary (researcher):**

This was the first bug I ever found that exposed a large amount of PII, thanks for disclosing @uber! 

This bug reinforces to me that hackers should always examine microsites as well as core domains, sometimes bugs on microsites can lead to significant data exposure. In this case, lioncityrentals.com.sg  was collecting data on thousands of Uber Singapore users, which was then exposed by the outdated Wordpress plugin. 

You can read more about the formidable forms vulnerability here - https://klikki.fi/adv/formidable.html

And be sure to check out my blog https://healdb.tech/blog/ or my twitter https://twitter.com/heald_ben
for Bug Bounty tips and guides!

---

### [Login form on non-HTTPS page](https://hackerone.com/reports/214571)

- **Report ID:** `214571`
- **Severity:** High
- **Weakness:** Cleartext Transmission of Sensitive Information
- **Program:** Rockstar Games
- **Reporter:** @scraps
- **Bounty:** 350 usd
- **Disclosed:** 2017-04-26T20:16:58.273Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
=======
A page on a microsite is not fully protected by an SSL certificate. This could allow an attacker in a Man-in-the-Middle position to obtain usernames and passwords of users visiting the site. 

Description:
=======
On the Red Dead Redemption subpage, the comments section on news articles allows registered social club users to post comments. When posting a comment, the user first has to login, which appears as if it is done over a non-secure page:

http://www.rockstargames.com/reddeadredemption/news/article/52645/rockstar-fan-art-gallery-gta-in-a-bottle-8-bit-bully-red.html/#comments

Note the warning in screenshot 1, firefox has identified that this page is not protected with an SSL certificate, therefore the username and password will be sent over a plaintext connection. In itself, this may be enough to put some users off using your page. 

Interestingly, if you manually change the address bar to be https, it does redirect to a https version of the same page, albeit with a mixed content error (screenshot 2). This indicates that an SSL certificate is in place for this page, however not all requests are sent through HTTPS by default. 

Once submit is pressed on the comment, it appears as though the request is sent over a HTTPS connection (when seen through Burp Suite or Wireshark), which suggests that the page does protect the username and password with SSL/TLS, see packets 167501-167519 in screenshot 3. Although this will work in most cases, there are techniques that can defeat this, such as using the [sslstrip][1] tool. There are several in-depth descriptions of how this works, such as this [one][2]

An example of using this is shown in screenshots 4 and  5 below, which was carried out solely on my own computer and against my own user account (scrapsH1).

[1]: https://moxie.org/software/sslstrip/ "sslstrip"
[2]: https://avicoder.me/2016/02/22/SSLstrip-for-newbies/ "one"

Steps to reproduce:
=============
1. On a Kali Linux machine, set up sslstrip as per screenshot 3
2. Set the browser settings to use the Kali machine as a proxy server. NB, this was done in this example for convenience. In a real-world attack, an attacker could force everyone on the network to use his machine as a proxy using a technique such as [ARP Spoofing][3], thereby requiring no interaction from the user
3. When the user submits a comment, rather than their POST request being protected by HTTPS, the attacking machine will negotiate the HTTPS connection with the rockstargames server, but trick the user machine into believing that the request should be sent as a HTTP request rather than HTTPS
4. As the request has been sent via HTTP, the POST request is now visible to sslstrip, which collects the credentials entered by the user, as per screenshot 5.

[3]: https://en.wikipedia.org/wiki/ARP_spoofing "ARP Spoofing"

Impact:
=====
If a user were to visit this page from a public or shared network (eg, starbucks, airport, library, etc) and submit a comment, a malicious user on the same network would be able to obtain that users username and password by conducting a Man-in-the-Middle attack using sslstrip and wireshark.

This would allow the malicious user complete access to the user's account. 

Remediation:
=========
1. If any part of a site is required to be protected by SSL, the entire site should be protected by SSL. Ts this would stop the attack outlined above from working, as a certificate error would be displayed to the user. 
2. HTTP Strict Transport [security][4] could be used to mitigate this attack, which would tell all browsers not to allow a HTTP connection to the rockstargames website

[4]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security "security"

---
