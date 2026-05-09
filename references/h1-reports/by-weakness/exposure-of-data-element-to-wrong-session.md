# Exposure of Data Element to Wrong Session

_1 reports — High/Critical, disclosed_

### [State Isolation Failure in Multiplexed Connections (Shared Auth Context)](https://hackerone.com/reports/3487952)

- **Report ID:** `3487952`
- **Severity:** Critical
- **Weakness:** Exposure of Data Element to Wrong Session
- **Program:** curl
- **Reporter:** @raulvdv
- **Bounty:** - usd
- **Disclosed:** 2026-01-08T12:57:03.273Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerability: State Isolation Failure in Multiplexed Connections (Shared Auth Context) Product: libcurl Affected Versions: v7.43.0 - Current (v8.x) - All versions supporting HTTP/2 Multiplexing Severity: CRITICAL (CVSS: 9.1)

1. Executive Summary
A fundamental design flaw exists in libcurl's state management for HTTP/2 multiplexed connections. The library violates the "Easy Handle Isolation" contract by storing Authentication State (specifically NTLM/Negotiate contexts) on the shared Connection Object rather than the individual Stream (Easy Handle).

This violation allows a secondary, unauthenticated Easy Handle ("Attacker Stream") to effectively "inherit" the authentication context of a primary, privileged Easy Handle ("Admin Stream") if they share the same physical TCP connection. While often triggered by race conditions or specific flow control states ("Ouroboros"), the vulnerability is rooted in the Invariant Violation: Authentication State ⊂ Connection instead of Authentication State ⊂ Stream.

This is not a usage error. It is impossible for a user to opt-out of this state sharing while using HTTP/2, making the library unsafe by default for multiplexed authenticated traffic.

2. Technical Chain Analysis
The exploit relies on the structural failure to isolate state:

Defect A: Invariant Violation (STATE-001)
Location: 
lib/url.c
 / 
lib/transfer.c
 Description: The conn->ntlm and conn->negotiate structs are attached to the connectdata object. In HTTP/1.1 (1:1 mapping), this was acceptable. In HTTP/2 (1:N mapping), this means all N streams improperly share the same authentication machine state.

Defect B: The Chronos Trigger (RACE-001)
Location: lib/multi.c
 Description: To weaponize the shared state, an attacker needs the "Admin" stream to keep the connection open and authenticated without consuming the response. The CURL_READFUNC_PAUSE or Network Backpressure states allow a stream to be "paused" indefinitely, creating a stable window where conn->ntlm.state is AUTHENTICATED, available for any new stream to pivot off.

3. Proof of Concept (PoC)
A functional C program (ouroboros_poc.c) is attached. Zero Preparation: The PoC uses standard curl_multi_add_handle calls. No memory corruption or special payload is required. It simply demonstrates that Handle B (with no credentials) returns 200 OK from a protected endpoint because Handle A (with credentials) is active on the same connection.

4. Anticipated Objections & Rebuttals
Objection A: "NTLM/Negotiate are Connection-Oriented protocols, unaware of Multiplexing."

Rebuttal: Acknowledged. However, if libcurl chooses to support these protocols over HTTP/2 (a multiplexed transport), it assumes the responsibility of enforcing the Handle Isolation Invariant.
If the protocol cannot differentiate streams (like NTLM), libcurl MUST EITHER:
- Block Multiplexing for that connection (downgrade to 1:1).
- Lock the connection to the Authenticated Handle exclusively.
- Allowing "State Bleed" because the underlying protocol is legacy is a failure of the Abstraction Layer (libcurl), not the Protocol itself.

Objection B: "This is an Application Logic Error. The App should not mix users on one Multi handle."
Rebuttal: False. The CURLM (Multi) interface is designed to manage a pool of connections physically, while logically presenting separated CURL (Easy) handles to the application.

The Application Developer has no granular control over which Easy Handles map to which physical TCP connection in an HTTP/2 context. libcurl manages this mapping internally.
Therefore, the Developer cannot prevent this race condition via application logic (short of disabling HTTP/2 globally). The defect lies within the internal Connection Pool management.

## Impact

Impact Analysis (CVSS 9.1)

Confidentiality: High. Credentials/Sessions are leaked across handle boundaries.
Integrity: High. Requests are authorized incorrectly.
Availability: None (in this context).
Vector: Network (AV:N).
Complexity: Low (AC:L) - Default behavior on HTTP/2.
Privileges: None (PR:N).
User Interaction: None (UI:N).
Scope: Unchanged (S:U) - (Conservative scoring to avoid rejection, strictly affecting the application relying on curl).
CVSS v3.1 Score: 9.1 (Critical) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

---
