# Improper Initialization

_1 reports — High/Critical, disclosed_

### [Timeout-based race conditions make Uint8Array/Buffer.alloc non-zerofilled](https://hackerone.com/reports/3405778)

- **Report ID:** `3405778`
- **Severity:** High
- **Weakness:** Improper Initialization
- **Program:** Node.js
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2026-02-12T14:41:45.527Z
- **CVE(s):** CVE-2025-55131

**Summary (team):**

A flaw in Node.js's buffer allocation logic can expose uninitialized memory when allocations are interrupted, when using the `vm` module with the timeout option. Under specific timing conditions, buffers allocated with `Buffer.alloc` and other `TypedArray` instances like `Uint8Array` may contain leftover data from previous operations, allowing in-process secrets like tokens or passwords to leak or causing data corruption. While exploitation typically requires precise timing or in-process code execution, it can become remotely exploitable when untrusted input influences workload and timeouts, leading to potential confidentiality and integrity impact.

---
