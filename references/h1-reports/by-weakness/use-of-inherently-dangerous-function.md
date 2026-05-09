# Use of Inherently Dangerous Function

_2 reports — High/Critical, disclosed_

### [Unexpected input validation of octal literals in nodejs v15.12.0 and below returns defined values for all undefined octal literals.](https://hackerone.com/reports/1141623)

- **Report ID:** `1141623`
- **Severity:** Critical
- **Weakness:** Use of Inherently Dangerous Function
- **Program:** Node.js
- **Reporter:** @sickcodes
- **Bounty:** - usd
- **Disclosed:** 2021-06-14T12:46:17.325Z
- **CVE(s):** CVE-2021-28918, CVE-2020-28360

**Vulnerability Information:**

**Summary:**
 Unexpected input validation of octal literals in the nodejs implementation of V8 JavaScript engine V8 9.0.257.13 and below returns defined values for all undefined octal literals where otherwise should return undefined. Input data 08, 09... 078, 079 should return undefined, as evinced by 0o8, 0o9 etc. This affects ALL downstream nodejs software. An attacker could abuse a myriad of downstream software that relies on nodejs, for example any of the 1,570,041 npm packages that expect an undefined response for `eval(08)`;. One such example is netmask npm package: the package is unable to evaluate any octal literal containing an 8 or a 9 leading to SSRF, LFI, RFI.

**Description:**
Downstream direct references:
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Bad_octal
https://sick.codes/universal-netmask-npm-package-used-by-270000-projects-vulnerable-to-octal-input-data-server-side-request-forgery-remote-file-inclusion-local-file-inclusion-and-more-cve-2021-28918/

CVSS Pending
https://sick.codes/sick-2021-011

CVSS 9.8 Critical
https://nvd.nist.gov/vuln/detail/CVE-2020-28360

## Steps To Reproduce:

nodejs, as well as Chrome Console:
```js
console.log(04);
console.log(05);
console.log(06);
console.log(07);
console.log(08);
console.log(09);
console.log(010);
console.log(0o4);
console.log(0o5);
console.log(0o6);
console.log(0o7);
console.log(0o8);
console.log(0o9);
```

```bash

STATEMENT='
console.log(04);
console.log(05);
console.log(06);
console.log(07);
console.log(08);
console.log(09);
console.log(010);
'

node <<EOF
${STATEMENT}
EOF

coffee <<EOF
${STATEMENT}
EOF

ts-node <<EOF
${STATEMENT}
EOF
```

node (V8) returns:
```
4
5
6
7
8
9
8
```
However, it should absolutely be:
```
4
5
6
7
undef
undef
8
```

## expected results

```bash
STATEMENT='
console.log(0o4);
console.log(0o5);
console.log(0o6);
console.log(0o7);
console.log(0o8);
console.log(0o9);
console.log(0o10);
'

node <<EOF
${STATEMENT}
EOF

coffee <<EOF
${STATEMENT}
EOF

ts-node <<EOF
${STATEMENT}
EOF
```

Every other JS runtime evaluates defined as undefined.

CWE-20: Improper Input Validation

VERSION
Google Chrome   90.0.4430.40 (Official Build) unknown (64-bit)
Revision 13a486ce2d7548247f6314bbccf47e47773938f6-refs/branch-heads/4430@{#715}
OS  Linux
JavaScript  V8 9.0.257.13
User Agent  Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.40 Safari/537.36
Command Line    ./chrome --flag-switches-begin --flag-switches-end

REPRODUCTION CASE

```bash
STATEMENT='
console.log(04);
console.log(05);
console.log(06);
console.log(07);
console.log(08);
console.log(09);
console.log(010);
'

node <<EOF
${STATEMENT}
EOF

coffee <<EOF
${STATEMENT}
EOF

ts-node <<EOF
${STATEMENT}
EOF
```
FOR CRASHES, PLEASE INCLUDE THE FOLLOWING ADDITIONAL INFORMATION
```
console.log(04);
console.log(05);
console.log(06);
console.log(07);
console.log(08);
console.log(09);
console.log(010);
console.log(0o4);
console.log(0o5);
console.log(0o6);
console.log(0o7);
console.log(0o8);
console.log(0o9);
console.log(0o10);
VM78:12 Uncaught SyntaxError: Invalid or unexpected token

console.log(04);
console.log(05);
console.log(06);
console.log(07);
console.log(08);
console.log(09);
console.log(010);
console.log(0o4);
console.log(0o5);
console.log(0o6);
console.log(0o7);
VM111:1 4
VM111:2 5
VM111:3 6
VM111:4 7
VM111:5 8
VM111:6 9
VM111:7 8
VM111:8 4
VM111:9 5
VM111:10 6
VM111:11 7
```

## Impact: [add why this issue matters]
SSRF, RFI, LFI in absolutely any downstream package that relies on octal literal IP address translation.

https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Bad_octal

## Supporting Material/References:

This bug I previously submitted to Chromium V8 (yesterday) which was rejected as "per spec"

However, this does not account for the fact that this is extremely dangerous for nodejs webapps, if not all nodejs web applications.

Mozilla interprets ECMA-262 octal literals containing 8 or 9 as not legal.
```
08 is not a legal ECMA-262 octal constant.
09 is not a legal ECMA-262 octal constant.
```

The spec:

https://tc39.es/ecma262/#sec-additional-syntax-numeric-literals

## Impact

As per Chromium's response as well as our own research, random deviations in octal literal is catastrophic.

The issue highly affects parseInt. It should return undefined for truly undefined results.

```console
> parseInt(08);
8
> parseInt(0177);
127
> parseInt(012);
10
> parseInt(0000127);
87
> 
```

---

### [URL Spoof / Brave Shield Bypass](https://hackerone.com/reports/255991)

- **Report ID:** `255991`
- **Severity:** High
- **Weakness:** Use of Inherently Dangerous Function
- **Program:** Brave Software
- **Reporter:** @mattaustin
- **Bounty:** 200 usd
- **Disclosed:** 2017-08-31T21:48:19.844Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Improper URL parsing in Brave allows an attacker to spoof the hostname shield settings are applied to.

## POC:
https://youtu.be/yz99T_Trfuc

## Products affected: 

 * Brave (browser-laptop) 0.18.14 rev ad92d02

## Steps To Reproduce:

 1. Browse to http://brave.com
 2. Click on the Shield icon and toggle the shield from "up" to "down"
 3. Browse to http://brave.com%60x.code-fu.org/ and notice the shield is down for this domain as well. 

I believe this could be used enable flash by spoofing one of the "whitelisted" domains. 

The renderer will load the code-fu.org domain, however I believe when the  URL is later parsed in node it uses (non standards compliant?) url.parse. This leads to some confusion: 

``` javascript
> url.parse('http://brave.com%60x.code-fu.org/')
Url {
  href: 'http://brave.com/%60x.code-fu.org/'
  protocol: 'http:',
  host: 'brave.com',
  hostname: 'brave.com',
  pathname: '%60x.code-fu.org/',
  path: '%60x.code-fu.org/',
}
```

vs

``` javascript
> new url.URL('http://brave.com%60x.code-fu.org/')
URL {
  href: 'http://brave.com`x.code-fu.org/',
  protocol: 'http:',
  host: 'brave.com`x.code-fu.org',
  hostname: 'brave.com`x.code-fu.org',
  pathname: '/',
}
```

Node now (7+) supports the the WHATWG through the [url.URL](https://nodejs.org/api/url.html#url_the_whatwg_url_api) . This seems to be the same / compatible with the way the render / chrome parses the URL.

---
