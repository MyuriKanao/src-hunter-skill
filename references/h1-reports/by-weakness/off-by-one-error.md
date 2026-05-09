# Off-by-one Error

_2 reports — High/Critical, disclosed_

### [urlapi: off-by-one in custom scheme validation skips last character](https://hackerone.com/reports/3598358)

- **Report ID:** `3598358`
- **Severity:** High
- **Weakness:** Off-by-one Error
- **Program:** curl
- **Reporter:** @otiscui
- **Bounty:** - usd
- **Disclosed:** 2026-03-12T15:51:30.100Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

In `lib/urlapi.c`, the `set_url_scheme()` function has an off-by-one error when validating custom scheme names. The validation loop checks `scheme[0]` twice (once by `ISALPHA`, once in the loop) and never checks the last character. This allows schemes ending with any arbitrary byte (e.g., `foo!`, `bar{`, `bad/`) to pass validation when set via `curl_url_set(url, CURLUPART_SCHEME, ..., CURLU_NON_SUPPORT_SCHEME)`, violating RFC 3986 Section 3.1.

## Affected version

curl 8.19.1-DEV (Darwin) libcurl/8.19.1-DEV OpenSSL/3.6.1 zlib/1.2.12 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns mqtt mqtts pop3 pop3s rtsp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli HSTS HTTPS-proxy IDN IPv6 Largefile libz NTLM SSL threadsafe TLS-SRP UnixSockets zstd

Tested on macOS (Darwin 25.2.0, arm64). The bug is platform-independent, in `lib/urlapi.c` lines 1648-1657.

## Steps To Reproduce

Build and run this PoC:

```c
#include <stdio.h>
#include <curl/curl.h>

int main(void) {
  CURLU *url;
  CURLUcode rc;
  const char *schemes[] = {"bad!", "bad{", "bad/", "bad\\", "a!", NULL};

  for(int i = 0; schemes[i]; i++) {
    url = curl_url();
    rc = curl_url_set(url, CURLUPART_SCHEME, schemes[i],
                      CURLU_NON_SUPPORT_SCHEME);
    char *out = NULL;
    if(rc == CURLUE_OK)
      curl_url_get(url, CURLUPART_SCHEME, &out, 0);
    printf("%-10s  %s", schemes[i],
           rc == CURLUE_OK ? "ACCEPTED (BUG!)" : "REJECTED (correct)");
    if(out) { printf("  stored='%s'", out); curl_free(out); }
    printf("\n");
    curl_url_cleanup(url);
  }
  return 0;
}
```

Output:


bad!        ACCEPTED (BUG!)  stored='bad!'
bad{        ACCEPTED (BUG!)  stored='bad{'
bad/        ACCEPTED (BUG!)  stored='bad/'
bad\        ACCEPTED (BUG!)  stored='bad\'
a!          ACCEPTED (BUG!)  stored='a!'
All should be REJECTED per RFC 3986 Section 3.1.

Root cause in set_url_scheme() (urlapi.c:1648-1657): after the ISALPHA(*s) check, s is not incremented before entering the while(--plen) loop, so the first character is validated twice and the last character is never validated.

Suggested fix: add s++ after the ISALPHA(*s) check, before the loop.

## Impact

## Summary

- **Input validation bypass:** Applications using `CURLU_NON_SUPPORT_SCHEME` that rely on libcurl's URL API for scheme validation will accept malformed schemes containing illegal characters in the final position.
- **Potential SSRF filter bypass:** Security filters that use libcurl's URL parser to validate/normalize URLs before making requests may accept URLs with invalid scheme characters, which downstream components may interpret differently.
- **RFC non-compliance:** Violates RFC 3986 Section 3.1 scheme syntax: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`

Note: The bug is only triggerable via the direct `CURLUPART_SCHEME` API, not when parsing a full URL via `CURLUPART_URL` (because the URL parser's scheme extraction filters special characters before reaching `set_url_scheme()`).

---

### [Exim off-by-one RCE vulnerability](https://hackerone.com/reports/322935)

- **Report ID:** `322935`
- **Severity:** Critical
- **Weakness:** Off-by-one Error
- **Program:** Internet Bug Bounty
- **Reporter:** @mehqq
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T20:23:16.785Z
- **CVE(s):** CVE-2018-6789

**Vulnerability Information:**

Hi, 

I found an off-by-one in Exim MTA utility function. It was reported to exim and official patch has been released, assigned CVE-2018-6789. This bug affects all versions of exim.

This bug is simple, but can be leverage to gain remote code execution, using skillful heap exploitation. Details are here: https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/

I believe exim is widespread enough and it seems to fit all criteria. I wonder if this finding worths a bounty, or the reason why it is not included. Thanks!

## Impact

Pre-auth remote code execution on all versions of exim mail server

---
