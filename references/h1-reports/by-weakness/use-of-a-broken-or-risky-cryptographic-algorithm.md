# Use of a Broken or Risky Cryptographic Algorithm

_2 reports — High/Critical, disclosed_

### [0 Click account takeover via timed requests to ███████forgot-password (single-packet attack)](https://hackerone.com/reports/2142109)

- **Report ID:** `2142109`
- **Severity:** High
- **Weakness:** Use of a Broken or Risky Cryptographic Algorithm
- **Program:** Mars
- **Reporter:** @0x999
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T17:05:42.992Z
- **CVE(s):** -

**Summary (team):**

An account takeover vulnerability was present in the forgot password functionality of ██████████. By sending carefully timed requests using a single-packet attack to the ████forgot-password path, an attacker is able to obtain the password reset token for any account on the platform. This attack requires only knowledge of the victim's email address registered on █████████████████████████████████.

---

### [Inadequate Cryptographic Key Size and Insecure Cryptographic Mode.  File Name :- curl_ntlm_core.c](https://hackerone.com/reports/1113663)

- **Report ID:** `1113663`
- **Severity:** High
- **Weakness:** Use of a Broken or Risky Cryptographic Algorithm
- **Program:** curl
- **Reporter:** @sanchitcfc
- **Bounty:** - usd
- **Disclosed:** 2021-03-08T08:24:10.065Z
- **CVE(s):** -

**Vulnerability Information:**

The application is generating cryptographic keys or key pairs using a short and inadequate length.
This application is using the ECB (Electronic Codebook) mode of operation to perform encryption, which is considered semantically insecure.

Vulnerable File name :- curl_ntlm_core.c
Vulnerable line no. 274 :- err = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, key,

## Impact

If a message with identical blocks is encrypted, an attacker get a certain advantage to have information on plaintext, by only observing CipherText.

---
