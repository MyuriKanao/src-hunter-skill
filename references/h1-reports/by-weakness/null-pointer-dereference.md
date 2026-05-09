# NULL Pointer Dereference

_8 reports — High/Critical, disclosed_

### [important: Apache HTTP Server: Crash resulting in Denial of Service in mod_proxy via a malicious request (CVE-2024-38477)](https://hackerone.com/reports/2585375)

- **Report ID:** `2585375`
- **Severity:** High
- **Weakness:** NULL Pointer Dereference
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-13T14:36:11.635Z
- **CVE(s):** CVE-2024-38477

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there:
> https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash the server via a malicious request.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

**Summary (team):**

###important: Apache HTTP Server: Crash resulting in Denial of Service in mod_proxy via a malicious request (CVE-2024-38477)

null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash the server via a malicious request.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

Acknowledgements: finder: Orange Tsai (@orange_8361) from DEVCORE

Reported: 2024-04-01
fixed by r1918607 in 2.4.x: 2024-07-01
Update 2.4.60 released: 2024-07-01
Affects: 2.4.0 through 2.4.59

---

### [NULL Pointer dereference in idn.c](https://hackerone.com/reports/2171309)

- **Report ID:** `2171309`
- **Severity:** Critical
- **Weakness:** NULL Pointer Dereference
- **Program:** curl
- **Reporter:** @s0urc3_
- **Bounty:** - usd
- **Disclosed:** 2023-09-20T12:07:26.974Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A NULL Pointer dereference vulnerability is present in idn.c source code.
This module is responsible of handling international domain name.
This issue was found performing manual source code review of Curl which took >20 hours.

## Steps To Reproduce:
Find below a detailed and commented execution flow / code snippet explanation.

## Impact 
In some circumstances writing or reading memory is possible, which may lead to code execution. 

###  Code Snippet
```c
static CURLcode idn_decode(const char *input, char **output)
{

char *decoded = NULL;
/* 4. 'decoded' initialized to a null pointer value	*/

CURLcode result = CURLE_OK;
#ifdef USE_LIBIDN2
if(idn2_check_version(IDN2_VERSION)) {
	
/* 5. Assuming the condition is false	*/
/* 6. Taking false branch	*/

int flags = IDN2_NFC_INPUT
#if IDN2_VERSION_NUMBER >= 0x00140000 | IDN2_NONTRANSITIONAL
#endif;
int rc = IDN2_LOOKUP(input, &decoded, flags);
if(rc != IDN2_OK)
rc = IDN2_LOOKUP(input, &decoded, IDN2_TRANSITIONAL);
if(rc != IDN2_OK)
result = CURLE_URL_MALFORMAT;
}
#elif defined(USE_WIN32_IDN)
result = win32_idn_to_ascii(input, &decoded);
#endif

if(!result)
/* 7. Taking true branch */
*output = decoded;
/* 8. Null pointer value stored to 'decoded'	*/
return result;
/* 9. Returning zero (loaded from 'result'), which participates in a condition later */

...

#ifdef USE_IDN

if(!Curl_is_ASCII_name(host->name)) {
/* 1. Assuming condition is True */
char *decoded;

/* 2  Calling idn_decode */
CURLcode result = idn_decode(host->name, &decoded); 

/* 10. Returning from idn_decode*/
if(!result) 
/* 11. Taking True branch */
{
    if(!*decoded) 
    {
	/* 12.  Dereference of null pointer (loaded from variable 'decoded') */
    Curl_idn_free(decoded);
    return CURLE_URL_MALFORMAT;
	}

host->encalloc = decoded;
host->name = host->encalloc;
}
else
    return result;
}
#endif
return CURLE_OK;
 }
```
## Remediation
Implement sanity checks to never dereference null pointer.

## References
- https://cwe.mitre.org/data/definitions/476.html
- https://0x00sec.org/t/kernel-exploitation-dereferencing-a-null-pointer/3850
- https://www.abatchy.com/2018/01/kernel-exploitation-6
- https://access.redhat.com/articles/20484

## Impact

- Crash or Segmentation Fault: If the decoded pointer is dereferenced when it is still NULL, it will lead to a crash or segmentation fault. This can disrupt the normal operation of the program.
    - Exploitation Scenario: An attacker can send specially crafted input data to trigger the vulnerable code path, causing the program to crash. While this doesn't directly lead to a security breach, it can be used as part of a larger attack to disrupt a service or application.

- Denial of Service (DoS): A null pointer dereference can be exploited to cause a DoS attack by repeatedly triggering the vulnerable code path, causing the application to crash and become unavailable.
    - Exploitation Scenario: An attacker could send a high volume of malicious requests that exploit the vulnerability, causing the service to crash repeatedly. This results in a DoS condition, making the service unavailable to legitimate users.

-   Remote Code Execution (Rare): In some cases, null pointer dereferences can potentially be leveraged for remote code execution if the attacker can control the data that leads to the dereference and can influence the program's control flow.
    *  Exploitation Scenario: An attacker would need to have a deep understanding of the program's memory layout and control flow to craft input that not only triggers the null pointer dereference but also redirects program execution to attacker-controlled code. This scenario is less likely but more severe.

---

### [[WiiU/Switch] nullptr dereference in the ENL framework](https://hackerone.com/reports/1540907)

- **Report ID:** `1540907`
- **Severity:** High
- **Weakness:** NULL Pointer Dereference
- **Program:** Nintendo
- **Reporter:** @crazy_man123
- **Bounty:** - usd
- **Disclosed:** 2023-08-22T10:41:15.377Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

#Introduction

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

- ENL only sends packet through the Unreliable Protocol (PIA can also do reliable UDP transmission)
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

ENL is a C++ library, content transporters are implemented using abstract classes, each content transporter must implement some virtual methods to initialize state, handle received data, etc..

All of the data received and sent is handled by the **TransportManager**, when data is received it will eventually go through this function: ``enl::TransportManager::updateReceiveBuffer_`` 

(pseudo-code obtained through reverse engineering)
```c++
class enl::TransportManager {
    enl::IContentTransporter* getContentTransporter(uint8_t contentTransporterId) {
        for (int i = 0; i < this->transporterList.size(); i++) {
            if (this->transporterList[i]->getContentID() == contentTransporterId) {
                return this->transporterList[i];
            }
        }
        return nullptr;
    }

    void updateReceiveBuffer_(uint8_t bufferId, uint8_t* data, size_t size) {
        /* ... */
        while (1) {
            ReceiveHeaderInfo hdrInfo;
            sead::Serialization::read<ReceiveHeaderInfo>(userHeaderStream, &hdrInfo);
            if(hdrInfo.contentID == 255 && hdrInfo.contentLength == 0)
                break;
            
            enl::IContentTransporter* transporter = this->getContentTransporter(receiveHdrInfo.type);
            /* ... */

            // Virtual method, but transporter may be "nullptr" ...
            transporter->readyReceiveStream(userDataStream, this->recordStateBuffer, hdrInfo.size); 

            /* ... */
        }
    }
}
```

So as we can see ``transporter`` will be a ``nullptr`` if a packet is received with an unregistered content transporter ID, **trigerring a nullptr dereference** on the virtual call.

 
---
&nbsp;

# Impact

- A malicious user with a fake or modified client could abuse this vulnerability and crash the console/game of anyone
- Large scale denial of service for the players on multiple online games

---

### [[MK8DX] Improper metadata parsing](https://hackerone.com/reports/1688309)

- **Report ID:** `1688309`
- **Severity:** Critical
- **Weakness:** NULL Pointer Dereference
- **Program:** Nintendo
- **Reporter:** @crazy_man123
- **Bounty:** - usd
- **Disclosed:** 2023-08-17T00:16:05.217Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

# Introduction

This vulnerability impacts:

- Mario Kart 8 Deluxe on the Switch
- Mario Kart 8 on the WiiU

**The vulnerability was fixed for Mario Kart 8 Deluxe the 7 December, 2022 with the release of v2.2 (or v851968 for the internal version)**
**The vulnerability was fixed for Mario Kart 8 the 3 August, 2023 with the release of v4.2 (or v81 for the internal version)**

---
&nbsp;

The competition/tournaments ([SimpleSearchObject](https://github.com/kinnay/NintendoClients/wiki/Matchmake-Extension-Protocol-(MK8D)#simplesearchobject-structure)) contains a 'metadata' field, it is used by the game to store tournament data such as:

- Competition name (**ID 2**)
- Description (unused but still exists, **ID 4**)
- Red/Blue team names (if applicable, **ID 7/8** respectively)
- Icon type (**ID 3**)
- etc ...

It's stored with the ``ChunkData`` format: (stored in little endian for MK8DX)

**ChunkData**

| Type     | Description |
| ------------| ----------- |
| uint16_t      | Magic (0x5a5a, 'ZZ' in ASCII)       |
| ChunkDataList[]  | List of chunk data 'list', goes until end marker       |
| uint8_t      | End marker ( 0xff)     |

**ChunkDataList**

| Type     | Description |
| ------------| ----------- |
| uint8_t      | ID       |
| uint16_t  | Length       |
| T    | Any data of size 'length' (previous field)     |

Then the game would try to extract competition data like this: 

```c++
void ChunkDataAccessor::reset(uchar* pData, uint dataSize);
bool ChunkDataAccessor::parse();
ChunkDataAccessor::ChunkDataList* ChunkDataAccessor::getDataList(uint id);
void* ChunkDataAccessor::ChunkDataList::getData(uint offset?);

bool CompetitionInfo::extractUniqueAppData_() {
    g_ChunkDataAccessor->reset(this->simpleSearchObject.mMetadata.data(), 0x200);
    g_ChunkDataAccessor->parse();
    // The parsing function verifies the header magic then loops on the structure to extract all ChunkDataList entries, used to not validate the chunk length
   // The chunk length is now limited to 0x400 bytes (even if the maximum size the server/client allows is 0x200 bytes)

    /* ... */
    
    // 2 == Competition name index in the tournament metadata (ChunkData)
    char16_t* compName = (char16_t*)g_ChunkDataAccessor->getDataList(2)->getData(0);
    sead::BufferedSafeStringBase<char16_t> compNameStr(compName);
    this->mCompetitionName = compNameStr; // operator= override, calls sead::BufferedSafeStringBase<T>::copy()

    /* ... */
}

bool ChunkDataAccessor::parse() {
    sead::RamReadStream readStream(this->mBuffer, this->mBufferSize, sead::Stream::Modes::Binary);
    
    // must be a custom type probably
    uint16_t magic;
    readStream.readMemBlock(&magic, sizeof(uint16_t));
    if(magic != 0x5a5a /* gear::ChunkDataAccessor::cStart */) {
        return false;
    }

    uint8_t id;
    uint16_t length;
    readStream.readU8(&id);
    while(id != 0xff) {
        readStream.readU16(&length);
        // Issue, it can overrun the temporary buffer, which is of size 0x400
        // But only with uncontrolled data considering the server enforces a 0x200 bytes limit on the metadata
        // The updated code now checks the length is <= 0x400
        readStream.readMemBlock(this->tmpBuffer, length);
        this->addReadInfo_(id, this->mBuffer + readStream.mOffset, length);
        readStream.readU8(&id);
    }

    return true;
}
```

The parsing function wasn't validating the chunk size, so a big enough size would overflow some class members (with uncontrolled data) and crash the process

---
&nbsp;

## Impact

Combined with the bug that allowed to create official competitions, you could crash any players opening the "Tournament" menu

---

### [Denial of Service: nghttp2 use of uninitialized pointer](https://hackerone.com/reports/335608)

- **Report ID:** `335608`
- **Severity:** Critical
- **Weakness:** NULL Pointer Dereference
- **Program:** Node.js
- **Reporter:** @jasnell
- **Bounty:** - usd
- **Disclosed:** 2020-02-13T23:47:23.557Z
- **CVE(s):** -

**Vulnerability Information:**

While investigating https://hackerone.com/reports/335533 and while following the same reproduction steps, I uncovered a bug in nghttp2 that causes use of an uninitialized pointer for an altsvc frameresulting in crash. The error can be easily triggered by a remote attacker by sending malformed ALTSVC and GOAWAY frames to the server, or by a malicious server sending same to the client. For Node.js, the result is a crashed process. The report has been submitted to the nghttp2 author who is working on a fix and is working on a fixed release.

## Impact

Crashing the Node.js process causing a Denial of Service

---

### [CVE-2017-10965: Null pointer dereference in Irssi <1.0.4 ](https://hackerone.com/reports/247027)

- **Report ID:** `247027`
- **Severity:** High
- **Weakness:** NULL Pointer Dereference
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T17:40:30.146Z
- **CVE(s):** CVE-2017-10965

**Vulnerability Information:**

34 days after reading https://irssi.org/2017/05/12/fuzzing-irssi/, I was finally able to trigger a null pointer dereference in irssi 1.0.2. 

Timeline:
Report to vendor: 15 June 2017
Acknowledge by vendor: 15 June 2017
Fixed by vendor: 7 July 2017

Advisory: 
http://seclists.org/oss-sec/2017/q3/80

Patch:
https://github.com/irssi/irssi/commit/5e26325317c72a04c1610ad952974e206

```
./irssi < test000
CAP LS
NICK root
USER root root /dev/stdin :root
ASAN:DEADLYSIGNAL
=================================================================
==23308==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f4505521e56 bp 0x7fff0bf30d90 sp 0x7fff0bf30518 T0)
==23308==The signal is caused by a READ memory access.
==23308==Hint: address points to the zero page.
    #0 0x7f4505521e55 in strlen /build/glibc-cxyGtm/glibc-2.24/string/../sysdeps/x86_64/strlen.S:76
    #1 0x4536dc in __interceptor_strlen.part.31 (/root/irssi-1.0.2/src/fe-text/irssi+0x4536dc)
    #2 0x6bf3c9 in my_asctime /root/irssi-1.0.2/src/core/misc.c:565:8
    #3 0x594d51 in event_topic_info /root/irssi-1.0.2/src/fe-common/irc/fe-events-numeric.c:275:19
    #4 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #5 0x6f4207 in signal_emit /root/irssi-1.0.2/src/core/signals.c:286:3
    #6 0x62cd3d in irc_server_event /root/irssi-1.0.2/src/irc/core/irc.c:308:7
    #7 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #8 0x6f59b6 in signal_emit_id /root/irssi-1.0.2/src/core/signals.c:304:3
    #9 0x62d33a in irc_parse_incoming_line /root/irssi-1.0.2/src/irc/core/irc.c:362:3
    #10 0x6f499b in signal_emit_real /root/irssi-1.0.2/src/core/signals.c:242:3
    #11 0x6f59b6 in signal_emit_id /root/irssi-1.0.2/src/core/signals.c:304:3
    #12 0x62d6ba in irc_parse_incoming /root/irssi-1.0.2/src/irc/core/irc.c:383:3
    #13 0x6bb9b2 in irssi_io_invoke /root/irssi-1.0.2/src/core/misc.c:55:3
    #14 0x7f4506cc6229 in g_main_context_dispatch (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a229)
    #15 0x7f4506cc65df  (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a5df)
    #16 0x7f4506cc668b in g_main_context_iteration (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4a68b)
    #17 0x57e4a7 in main /root/irssi-1.0.2/src/fe-text/irssi.c:326:3
    #18 0x7f45054b53f0 in __libc_start_main /build/glibc-cxyGtm/glibc-2.24/csu/../csu/libc-start.c:291
    #19 0x42e979 in _start (/root/irssi-1.0.2/src/fe-text/irssi+0x42e979)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /build/glibc-cxyGtm/glibc-2.24/string/../sysdeps/x86_64/strlen.S:76 in strlen
==23308==ABORTING
```

---

### [null pointer dereference and segfault in tile-count-merge](https://hackerone.com/reports/245221)

- **Report ID:** `245221`
- **Severity:** High
- **Weakness:** NULL Pointer Dereference
- **Program:** Mapbox
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2017-07-11T15:36:07.317Z
- **CVE(s):** -

**Vulnerability Information:**

This crash was triggered with `642f773 ` while fuzzing `tile-count-merge` with AFL on Debian 8 x64.

`./tile-count-merge -o /dev/null test000`

```
ASAN:SIGSEGV
=================================================================
==10201==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x00000048d0af bp 0x7ffd8644b6a0 sp 0x7ffd8644ae30 T0)
    #0 0x48d0ae in __interceptor_memcmp (/root/tile-count/tile-count-merge+0x48d0ae)
    #1 0x4dc6c9 in finder::operator<(finder const&) const /root/tile-count/merge.cpp:115:10
    #2 0x4dc6c9 in bool __gnu_cxx::__ops::_Iter_less_val::operator()<finder*, finder const>(finder*, finder const&) const /usr/bin/../lib/gcc/x86_64-linux-gnu/4.9/../../../../include/c++/4.9/bits/predefined_ops.h:54
    #3 0x4dc6c9 in finder* std::__lower_bound<finder*, finder, __gnu_cxx::__ops::_Iter_less_val>(finder*, finder*, finder const&, __gnu_cxx::__ops::_Iter_less_val) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.9/../../../../include/c++/4.9/bits/stl_algobase.h:965
    #4 0x4ca6e0 in finder* std::lower_bound<finder*, finder>(finder*, finder*, finder const&) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.9/../../../../include/c++/4.9/bits/stl_algobase.h:999:14
    #5 0x4ca6e0 in do_merge(merge*, unsigned long, int, int, long long, int, bool, unsigned long) /root/tile-count/merge.cpp:213
    #6 0x4c38e4 in main /root/tile-count/mergetool.cpp:105:2
    #7 0x7fba250bcb44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #8 0x4c248c in _start (/root/tile-count/tile-count-merge+0x4c248c)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ??:0 __interceptor_memcmp
==10201==ABORTING
```

---

### [null pointer dereference in Sass::Eval::operator()(Sass::Map*)](https://hackerone.com/reports/221287)

- **Report ID:** `221287`
- **Severity:** High
- **Weakness:** NULL Pointer Dereference
- **Program:** LibSass
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2017-06-08T19:09:04.418Z
- **CVE(s):** -

**Vulnerability Information:**

Feeding `@P#{(200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0:0)}` to `./sassc -s` triggers this null pointer dereference.

```
==9885==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x000000952f5b bp 0x7fff7748a970 sp 0x7fff7748a720 T0)
    #0 0x952f5a in Sass::Eval::operator()(Sass::Map*) /home/geeknik/libsass/src/eval.cpp:525:31
    #1 0x951dff in Sass::Eval::operator()(Sass::List*) /home/geeknik/libsass/src/eval.cpp:490:14
    #2 0x951b36 in Sass::Eval::operator()(Sass::List*) /home/geeknik/libsass/src/eval.cpp:502:18
    #3 0x9a0042 in Sass::Eval::operator()(Sass::String_Schema*) /home/geeknik/libsass/src/eval.cpp:1236:27
    #4 0x9a0042 in Sass::Eval::operator()(Sass::String_Schema*) /home/geeknik/libsass/src/eval.cpp:1236:27
    #5 0x9cc301 in Sass::Expand::operator()(Sass::Directive*) /home/geeknik/libsass/src/expand.cpp:226:18
    #6 0x9f964c in Sass::Expand::append_block(Sass::Block*) /home/geeknik/libsass/src/expand.cpp:788:27
    #7 0x9c2379 in Sass::Expand::operator()(Sass::Block*) /home/geeknik/libsass/src/expand.cpp:81:5
    #8 0x656973 in Sass::Context::compile() /home/geeknik/libsass/src/context.cpp:658:12
    #9 0x64c56b in Sass::File_Context::parse() /home/geeknik/libsass/src/context.cpp:587:12
    #10 0x5d0650 in Sass::sass_parse_block(Sass_Compiler*) /home/geeknik/libsass/src/sass_context.cpp:227:22
    #11 0x5d0650 in sass_compiler_parse /home/geeknik/libsass/src/sass_context.cpp:476
    #12 0x5cf1d1 in sass_compile_context(Sass_Context*, Sass::Context*) /home/geeknik/libsass/src/sass_context.cpp:364:7
    #13 0x5cf6be in sass_compile_file_context /home/geeknik/libsass/src/sass_context.cpp:463:12
    #14 0x5b9d2e in compile_file /home/geeknik/sassc/sassc.c:145:5
    #15 0x5bab9b in main /home/geeknik/sassc/sassc.c:335:18
    #16 0x7f4edf974b44 in __libc_start_main /build/glibc-qK83Be/glibc-2.19/csu/libc-start.c:287
    #17 0x5b92fc in _start (/home/geeknik/sassc/bin/sassc+0x5b92fc)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/geeknik/libsass/src/eval.cpp:525 Sass::Eval::operator()(Sass::Map*)
==9885==ABORTING
```

---
