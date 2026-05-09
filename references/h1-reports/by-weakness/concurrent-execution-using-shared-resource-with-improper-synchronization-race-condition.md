# Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')

_1 reports — High/Critical, disclosed_

### [Race Condition Enables Bypassing Verification Check](https://hackerone.com/reports/2110030)

- **Report ID:** `2110030`
- **Severity:** High
- **Weakness:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Program:** Tools for Humanity
- **Reporter:** @toormund
- **Bounty:** 3000 usd
- **Disclosed:** 2024-04-04T21:55:53.952Z
- **CVE(s):** -

**Summary (team):**

A race condition was discovered in the WorldID platform that could enable bypassing the verification check limits under certain conditions. The issue resided in the enforcement of maximum allowed verifications, which was not properly synchronized across parallel requests to the cloud backend service.

The fix implemented enforcement of the maximum verifications in the database, making it the source of truth for state. This ensures that only one successful request per nullifier use can occur, even if parallel requests are attempted simultaneously. The vulnerability only affected certain cloud-backed verification flows, not on-chain WorldID applications.

---
