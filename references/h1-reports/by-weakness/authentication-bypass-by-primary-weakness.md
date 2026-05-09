# Authentication Bypass by Primary Weakness

_2 reports — High/Critical, disclosed_

### [Missing server identity policy enforcement in SSH connection reuse allows host key verification bypass via pool poisoning](https://hackerone.com/reports/3640932)

- **Report ID:** `3640932`
- **Severity:** High
- **Weakness:** Authentication Bypass by Primary Weakness
- **Program:** curl
- **Reporter:** @intrax71
- **Bounty:** - usd
- **Disclosed:** 2026-04-03T14:54:16.359Z
- **CVE(s):** CVE-2022-27782, CVE-2023-27538

**Vulnerability Information:**

# Missing server identity policy enforcement in SSH connection reuse allows host key verification bypass via pool poisoning

---

## Summary

`ssh_config_matches()` in `lib/url.c` decides whether an existing SSH connection can be reused by a new transfer handle. It checks client key paths (`rsa`, `rsa_pub`) but never inspects the three options that control server identity verification: `STRING_SSH_KNOWNHOSTS`, `STRING_SSH_HOST_PUBLIC_KEY_MD5`, and `STRING_SSH_HOST_PUBLIC_KEY_SHA256`. A handle configured with strict host key pinning reuses a pooled connection that was established with zero server verification — the pinning check never fires because the SSH handshake is skipped entirely.

This is the same bug class as CVE-2022-27782 and CVE-2023-27538. Both fixed client-side key options. The server-side identity options were never added.

---

## Vulnerability Details

- **Vulnerability Type:** Authentication Bypass (Connection Pool Poisoning)
- **CVSS 3.1 Score:** 7.5 (High) — `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N`
- **Affected Component:** `lib/url.c` → `ssh_config_matches()`
- **Affected Protocols:** SFTP, SCP

---

## Root Cause

The full function body at `lib/url.c`:

```c
static bool ssh_config_matches(struct connectdata *one,
                               struct connectdata *two)
{
  struct ssh_conn *sshc1, *sshc2;

  sshc1 = Curl_conn_meta_get(one, CURL_META_SSH_CONN);
  sshc2 = Curl_conn_meta_get(two, CURL_META_SSH_CONN);
  return sshc1 && sshc2 && Curl_safecmp(sshc1->rsa, sshc2->rsa) &&
          Curl_safecmp(sshc1->rsa_pub, sshc2->rsa_pub);
}
```

Three `data->set.str[]` entries are absent from this comparison:

| Option | String Key | Purpose |
|--------|------------|---------|
| `CURLOPT_SSH_KNOWNHOSTS` | `STRING_SSH_KNOWNHOSTS` | Path to known_hosts file for server fingerprint validation |
| `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5` | `STRING_SSH_HOST_PUBLIC_KEY_MD5` | Expected MD5 hash of server's public key |
| `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256` | `STRING_SSH_HOST_PUBLIC_KEY_SHA256` | Expected SHA-256 hash of server's public key |

For contrast, the TLS backend enforces full parity on security-relevant fields during connection reuse — `verifypeer`, `verifyhost`, pinned certificates are all compared. The SSH backend has no equivalent enforcement.

---

## Steps to Reproduce

**Environment:**
- libcurl built with libssh2 (default SSH backend)
- Two easy handles sharing one connection pool via `CURLSH`
- Target: any SFTP server (e.g. `test.rebex.net`, public demo)

```
./poc
```

**Source (`poc.c`):**

```c
#include <curl/curl.h>
#include <stdio.h>

int main(void) {
    CURL *relaxed, *strict;
    CURLSH *pool;
    long new_connections = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    pool = curl_share_init();
    curl_share_setopt(pool, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);

    relaxed = curl_easy_init();
    strict  = curl_easy_init();

    if(relaxed && strict && pool) {
        /* --- Transfer 1: no host verification --- */
        curl_easy_setopt(relaxed, CURLOPT_URL, "sftp://demo:password@test.rebex.net/readme.txt");
        curl_easy_setopt(relaxed, CURLOPT_SHARE, pool);
        // Silencing stderr for clean output
        curl_easy_setopt(relaxed, CURLOPT_NOBODY, 1L); 

        fprintf(stderr, "[*] Transfer 1 — no host key checks\n");
        curl_easy_perform(relaxed);

        /* --- Transfer 2: strict host key pinning requested --- */
        curl_easy_setopt(strict, CURLOPT_URL, "sftp://demo:password@test.rebex.net/readme.txt");
        curl_easy_setopt(strict, CURLOPT_SHARE, pool);
        curl_easy_setopt(strict, CURLOPT_SSH_KNOWNHOSTS, "/non/existent/file");
        curl_easy_setopt(strict, CURLOPT_NOBODY, 1L);

        fprintf(stderr, "[*] Transfer 2 — CURLOPT_SSH_KNOWNHOSTS set to non-existent file\n");
        curl_easy_perform(strict);

        curl_easy_getinfo(strict, CURLINFO_NUM_CONNECTS, &new_connections);

        if(new_connections == 0) {
            fprintf(stderr, "\n[!] VULNERABLE — Transfer 2 reused the unverified connection.\n"
                            "    CURLOPT_SSH_KNOWNHOSTS was silently ignored.\n"
                            "    No new TCP or SSH handshake occurred.\n");
        } else {
            fprintf(stderr, "\n[+] NOT VULNERABLE — new connection was established.\n");
        }
    }

    curl_easy_cleanup(relaxed);
    curl_easy_cleanup(strict);
    curl_share_cleanup(pool);
    curl_global_cleanup();

    return 0;
}
```

**Output on vulnerable build:**

```
[*] Transfer 1 — no host key checks
[*] Transfer 2 — CURLOPT_SSH_KNOWNHOSTS set to non-existent file

[!] VULNERABLE — Transfer 2 reused the unverified connection.
    CURLOPT_SSH_KNOWNHOSTS was silently ignored.
    No new TCP or SSH handshake occurred.
```

{F5648299}

**Expected behavior:** Transfer 2 opens a new connection, attempts to read `/tmp/does_not_exist_known_hosts`, fails, and returns `CURLE_SSH` error.

**Actual behavior:** Transfer 2 reuses the pooled connection from Transfer 1. `CURLINFO_NUM_CONNECTS` returns `0` — no handshake, no host key check, no error.

---

## Impact

In any environment where multiple transfer handles share a connection pool — `CURLM` multi-handle applications, `CURLSH` shared caches, PHP-FPM worker pools, proxy daemons — a connection established without server identity verification is reusable by handles that explicitly require it.

An attacker who performs a MITM on the initial unverified connection inherits access to every subsequent transfer on that pool, including those configured with host key pinning or `known_hosts` validation. Sensitive SFTP/SCP data (credentials, files, configuration) flows over the attacker-controlled channel. The developer's explicit security policy is discarded without error or warning.

This is not theoretical — `CURLSH` shared pools exist precisely for multi-tenant connection reuse. The TLS backend already prevents this exact pattern. The SSH backend does not.

**Prior art:**
- **CVE-2022-27782** — fixed TLS + partial SSH reuse checks ($2,400)
- **CVE-2023-27538** — fixed remaining client key options ($480)
- **This report** — server identity options remain unchecked

---

## Recommended Fix

Add three comparisons to `ssh_config_matches()`:

```c
static bool ssh_config_matches(struct connectdata *one,
                               struct connectdata *two)
{
  struct ssh_conn *sshc1, *sshc2;

  sshc1 = Curl_conn_meta_get(one, CURL_META_SSH_CONN);
  sshc2 = Curl_conn_meta_get(two, CURL_META_SSH_CONN);
  return sshc1 && sshc2 &&
         Curl_safecmp(sshc1->rsa, sshc2->rsa) &&
         Curl_safecmp(sshc1->rsa_pub, sshc2->rsa_pub) &&
         Curl_safecmp(one->data->set.str[STRING_SSH_KNOWNHOSTS],
                      two->data->set.str[STRING_SSH_KNOWNHOSTS]) &&
         Curl_safecmp(one->data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5],
                      two->data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]) &&
         Curl_safecmp(one->data->set.str[STRING_SSH_HOST_PUBLIC_KEY_SHA256],
                      two->data->set.str[STRING_SSH_HOST_PUBLIC_KEY_SHA256]);
}
```

## Impact

## Summary:
An attacker who can perform a MITM against an initial unverified SFTP/SCP connection gains persistent access to all subsequent transfers on the same shared connection pool — including those from handles that explicitly require host key pinning via CURLOPT_SSH_KNOWNHOSTS or CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256. The strict handle's SSH handshake never occurs; it inherits the compromised connection silently, with no error returned to the application. Sensitive file contents, credentials, and configuration transferred over SFTP/SCP are exposed to the attacker despite the developer having configured server identity verification.

---

### [Incorrect Parsing of IPv6 Zone ID in curl](https://hackerone.com/reports/3319767)

- **Report ID:** `3319767`
- **Severity:** High
- **Weakness:** Authentication Bypass by Primary Weakness
- **Program:** curl
- **Reporter:** @9vvert
- **Bounty:** - usd
- **Disclosed:** 2025-09-01T17:00:53.424Z
- **CVE(s):** -

**Vulnerability Information:**

I'm Zehui Miao from NISL@THU. During recent research, our team identified a parsing inconsistency in the curl.

### **0x01 Affected components**

#### **1.1 Affected components**

•     **C Curl**

•     **Versions:** tested in 8.4.0

•     **CLAIMS TO FOLLOW: RFC-3986**
#### **1.2 Attack scenario**

The threat model illustrated in Figure 1 explains the security risks in web systems caused by inconsistent URL parsing. Attackers initiate requests to web systems by constructing ambiguous URLs. These requests first go through a preprocessor for security checks. Preprocessors typically handle tasks such as permission verification, URL whitelist and blacklist checks, and URL normalization to ensure that the requested access is to authorized resources. However, due to the possibility of preprocessors and executors (such as browsers, API routers, requesters, etc.) using different programming languages or following different specification standards for URL parsing, the same URL string may be parsed into different target resource locations. Specifically, as shown in the figure, the preprocessor may parse the URL into a legitimate resource location A and pass security verification, while the executor parses the same URL into another sensitive resource location B and ultimately executes the actual request targeting sensitive resource B. This parsing discrepancy allows attackers to cleverly bypass the preprocessor's security mechanisms, gaining access to sensitive or unauthorized resources, thus posing potential security threats.

```

---------
|attacker|
---------
    |
    |  Ambiguous URL
    V
------------------ ================>  Resource Location A  ----|
|  Preprocesser  |_____________ Allow/Deny List                |
------------------       |_____ Access Control Inspector       V 
    |                   |_____ URL Normalizer            Not Equal
    |  Ambiguous URL                                                          ^
    V                                                          |
------------------ ================>  Resource Location B  ----|
|  Executor      |_____________ Browser
------------------       |_____ API Router
    |                    |_____ Requester
    |
    |_________________________________
    |                                 |
    X                                 |
    |                                 |
    V                                 |
-------------------------             |
| Accessible Resource A |             |
-------------------------             |
                                      |
-------------------------             |
| Sensitive Resource B  | <------------
-------------------------

```

**Figure 1: Principle of URL semantic gap attack caused by inconsistent URL parsing.**

 

Through our research, we have found that for this attack scenario, URL semantic gap attack may lead to three main types of security vulnerabilities:

1. Server-side request forgery: The attacker bypasses the domain name check of the preprocessor, causing the executor to make requests to the internal network or unauthorized external servers.
2. Open redirection: The attacker bypasses the domain name whitelist check of the redirection URL, redirecting the browser request to a malicious website.
3. Access control bypass: The attacker bypasses access control policies based on HTTP request paths to gain unauthorized access to protected resources.

### **0x02 Incorrect Parsing of IPv6 Zone ID**

#### **2.1 Overview of the Issue**

The IPv6 Zone ID follows after character `%`, which will be encoded to %25 in URL. When parsing a url like `http://[fe80::1%251]`, the correct parsing result is to decode `%25` and get Zone ID `1` rather than `251`.

In the following table, parsing results of url(perl) and urllib3(python) are correct. The curl seems to discard the Zone ID.

| payload              | curl(c)   | url (perl) | urllib3 (python) |
| -------------------- | --------- | ---------- | ---------------- |
| http://[fe80::1%251] | [fe80::1] | fe80::1%1  | [fe80::1%1]      |



#### **2.2 Definition of this parsing behavior in international standards**

**RFC parsing standard**

According to **RFC 3986** , IPv6 addresses are represented in URI (Uniform Resource Identifier) between square brackets `[]` , for example:

```
http://[2001:db8::1]:80/
```

However, RFC 3986 ** does not explicitly support IPv6 Zone IDs ** (i.e. suffixes like `%eth0` ). Instead, it only defines the basic syntax of `IPv6 address` :

```
IPv6address =                            6( h16 ":" ) ls32
             /                       "::" 5( h16 ":" ) ls32
             / [               h16 ] "::" 4( h16 ":" ) ls32
             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
             / [ *4( h16 ":" ) h16 ] "::"              ls32
             / [ *5( h16 ":" ) h16 ] "::"              h16
             / [ *6( h16 ":" ) h16 ] "::"

```

In addition, RFC 3986 further clarifies:

> “This syntax does not support IPv6 scoped addressing zone identifiers”

**RFC 6874** later extended support for IPv6 Zone IDs and proposed the following format:

```
http://[fe80::1%25eth0]:80/
```

Among them, `%25` is the URL encoding of `%` (percent sign). However, many resolvers do not fully implement this standard, so some resolvers may not correctly parse IPv6 Zone IDs, resulting in parsing failure or direct error.

The corresponding ABNF normal form is

```
IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture ) "]"

ZoneID = 1*( unreserved / pct-encoded )

IPv6addrz = IPv6address "%25" ZoneID

```

**RFC 6874** also mentions the ambiguity of ZoneID-Parsing. It's recommended to decode `%25` as `%` to avoid URL Ambiguity Attack.

```
Due to the lack of defined syntax, web browsers have been
inconsistent in providing for ZoneIDs.  Many have no support, but
there are examples of ad hoc support.  For example, some versions of
Firefox allowed the use of a ZoneID preceded by a bare "%" character,
but this feature was removed for consistency with established syntax
[RFC3986].  As another example, some versions of Internet Explorer
allow use of a ZoneID preceded by a "%" character encoded as "%25",
still beyond the syntax allowed by the established rules [RFC3986].
This syntax extension is in fact used internally in the Windows
operating system and some of its APIs.

It is desirable for all browsers to recognise a ZoneID preceded by a
percent-encoded "%".  In the spirit of "be liberal with what you
accept", we also suggest that URI parsers accept bare "%" signs when
possible (i.e., a "%" not followed by two valid and meaningful
hexadecimal characters).  This would make it possible for a user to
copy and paste a string such as "fe80::a%en1" from the output of a
"ping" command and have it work.  On the other hand, "%ee1" would
need to be manually rewritten to "fe80::a%25ee1" to avoid any risk of
misinterpretation.

Such bare "%" signs are for user interface convenience, and need to
be turned into properly encoded characters (where "%25" encodes "%")
before the URI is used in any protocol or HTML document.  However,
URIs including a ZoneID have no meaning outside the originating node.
It would therefore be highly desirable for a browser to remove the
ZoneID from a URI before including that URI in an HTTP request.

```

**WHATWG URL Parsing Standard**

WHATWG URL Living Standard intentionally omits support for zone_id

```
Support for <zone_id> is intentionally omitted.
```



#### **2.3 Security Threat Scenarios - SSRF Attacks Based on Zone ID**

**Attack scenario**

1. **Authentication phase resolvers** (e.g. for security checks) **do not support IPv6 Zone IDs** , resolve `http://[fe80::1%25eth0]/`
2. **The resolver in the actual request phase** (e.g. HTTP Client) **supports Zone ID** , successfully resolves the `fe80::1` and sends the request, leading to an SSRF attack, accessing internal resources.

#### **2.4 Mitigation measures**

•     If you need to resolve IPv6 Zone IDs, it is recommended to use an RFC 6874-compatible parser and ensure that the percent encoding is correct.

•     **The WHATWG URL standard does not support IPv6 Zone IDs** , so in web applications, resolvers may refuse to resolve such URLs.

•     **Security risk** : Inconsistent implementation of parsers can lead to SSRF attacks and additional security checks should be performed on the server side.


This vulnerability was jointly discovered by multiple researchers:
1. Enze Wang(IPASSLAB & Tsinghua University)
2. Jingcheng Yang (Tsinghua University)
3. Zehui Miao (Tsinghua University)

## Impact

## Summary:
Bypass the blacklist/whitelist and access the sensitive resources

---
