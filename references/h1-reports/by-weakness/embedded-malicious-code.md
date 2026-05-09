# Embedded Malicious Code

_1 reports — High/Critical, disclosed_

### [flatmap-stream malicious package (distributed via the popular events-stream)](https://hackerone.com/reports/450006)

- **Report ID:** `450006`
- **Severity:** Critical
- **Weakness:** Embedded Malicious Code
- **Program:** Node.js third-party modules
- **Reporter:** @danny_grander
- **Bounty:** - usd
- **Disclosed:** 2018-11-26T22:26:43.896Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a case of malicious package (flat-stream) that made it's way into many other npm packages. One such popular package is `event-stream` (user dominictarr transferred the ownership of an npm module to another user because he wasn't actively maintaining it. That user then added malicious dependency to the package)

See discussion here: 
https://github.com/dominictarr/event-stream/issues/116

# Module

**module name:**  flatmap-stream
**version:** [MODULE VERSION]
**npm page:** `https://www.npmjs.com/package/flatmap-stream` (removed from npm by now)

## Module Description

It is not yet clear what the malicious code was doing. 
See discussion here: https://github.com/dominictarr/event-stream/issues/116#issuecomment-441737695

## Module Stats

> Replace stats below with numbers from npm’s module page:

flatmap-stream is not popular, but event-stream is very popular (1,996,440 downloads per week)

## Impact

RCE

---
