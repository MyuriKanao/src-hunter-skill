# Missing Required Cryptographic Step

_2 reports — High/Critical, disclosed_

### [Missing AES-GCM Authentication Tag Validation and Improper Deprecation Handling](https://hackerone.com/reports/3463949)

- **Report ID:** `3463949`
- **Severity:** High
- **Weakness:** Missing Required Cryptographic Step
- **Program:** Node.js
- **Reporter:** @sideni
- **Bounty:** - usd
- **Disclosed:** 2025-12-19T21:03:44.897Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
In Node.js' crypto module, the `createDecipheriv` states that "the `authTagLength` option defaults to 16 bytes and must be set to a different value if a different length is used." ([here](https://nodejs.org/api/crypto.html#class-decipheriv:~:text=the%20authTagLength%20option%20defaults%20to%2016%20bytes%20and%20must%20be%20set%20to%20a%20different%20value%20if%20a%20different%20length%20is%20used.))
The authentication tag's length is however not validated against that default value and can be truncated down to either 4, 8, 12, 13, 14, or 15 bytes. ([here](https://github.com/nodejs/node/blob/4f24aff94ad9160bceaf9dcc9cf5235a65f01029/deps/ncrypto/ncrypto.h#L407-L409))
This allows an attacker to brute force an authentication tag after modifying a ciphertext and recover the key material to compute more authentication tags offline afterwards.

**Description:**
These authenticated encryption schemes are frequently used to protect some session or some token. An attacker could exploit this flaw by changing a valid ciphertext and by bruteforcing the new authentication tag on the server (with at most 12,884,902,656 requests : `(2**32) * 3 + 2 * 256`) to gain a valid session/token.
This also results in a nonce reuse with AES-GCM which leaks the key needed to compute any further authentication tags (see [this blogpost](https://frereit.de/aes_gcm/)). Note that 12 billion requests are not necessarily needed as one could use the truncated tag to recover the needed key (see [this cryptopals challenge](https://cryptopals.com/sets/8/challenges/64.txt)).

With the key needed to compute arbitrary authentication tags, an attacker can manipulate a ciphertext to decrypt it and to forge a new one.

I understand implicit shorter tag lengths have been deprecated with this [PR](https://github.com/nodejs/node/pull/52345), the deprecation warning however is [only emitted when the tag is actually shorter than 16 bytes](https://github.com/nodejs/node/blob/ebf38d825d20f14a80405be182cfaa568c1eb99f/src/crypto/crypto_cipher.cc#L568C7-L568C25).
For people using the function as documented (i.e. expecting the `authTagLength` option to default to 16 bytes), the warning is never shown unless an attack is on the way.

## Steps To Reproduce:
The following script shows how the default `authTagLength` of 16 bytes is not enforced and allows for implicit shorter tags.
It also shows that the deprecation warning is only shown when an attacker truncates the authentication tag (or when it's explicitly truncated, but that's not the scenario where people are in unknown danger).

```js
const {
    createCipheriv,
    createDecipheriv
} = require('crypto');

const key = 'key0123456789key';
const nonce = '123456789012';

var algo = 'aes-128-gcm';
const cipher = createCipheriv(algo, key, nonce);
const plaintext = 'This is some plaintext';

const ciphertext = cipher.update(plaintext, 'utf8');
cipher.final();
const tag = cipher.getAuthTag();


var decipher = createDecipheriv(algo, key, nonce);
decipher.setAuthTag(tag);
var decryptedPlaintext = decipher.update(ciphertext, null, 'utf8') + decipher.final();

console.log('Decrypted with full tag: ' + decryptedPlaintext);

console.log('---------------------------------');

decipher = createDecipheriv(algo, key, nonce);
// Truncating the authentication tag
decipher.setAuthTag(tag.subarray(0, 4));
decryptedPlaintext = decipher.update(ciphertext, null, 'utf8') + decipher.final();
console.log('Decrypted with truncated tag: ' + decryptedPlaintext);
```

Observe how the deprecation warning message is only shown for the latter and how a truncated authentication tag successfully allowed decryption (even if "the `authTagLength` option defaults to 16 bytes and must be set to a different value if a different length is used.)
{F5115107}

###For code references:
The deprecation warning message is emitted [here](https://github.com/nodejs/node/blob/ebf38d825d20f14a80405be182cfaa568c1eb99f/src/crypto/crypto_cipher.cc#L567-L577).
The auth tag is set with `setAuthTag` in which the tag length taken [here](https://github.com/nodejs/node/blob/ebf38d825d20f14a80405be182cfaa568c1eb99f/src/crypto/crypto_cipher.cc#L542-L546) is set implicitly [here](https://github.com/nodejs/node/blob/ebf38d825d20f14a80405be182cfaa568c1eb99f/src/crypto/crypto_cipher.cc#L579-L582).

## Impact

- Ciphertexts can be modified to decrypt to an arbitrary value
- Ciphertexts can be decrypted by observing parsing differences
    - For example, if the decrypted data is expected to be JSON, it's possible to observe valid/invalid JSON parsing to decrypt the ciphertext just like with padding oracles
- The GCM internal GHASH key can be recovered (to compute more arbitrary authentication tags without need for bruteforce)
    - Requires rotation of the encryption keys

Considering how the `createDecipheriv` function is documented, this completely breaks the integrity and confidentiality of the encryption scheme that people expect from this API.

---

### [Constant-time comparison is not always implemented; critical areas are vulnerable to key-timing attacks](https://hackerone.com/reports/363680)

- **Report ID:** `363680`
- **Severity:** Critical
- **Weakness:** Missing Required Cryptographic Step
- **Program:** Monero
- **Reporter:** @anonimal
- **Bounty:** - usd
- **Disclosed:** 2018-08-06T15:13:53.417Z
- **CVE(s):** -

**Vulnerability Information:**

In my most superficial of reviews, constant-time comparison appears to not be globally implemented (at a glance, only implemented within the ref10 implementation).

With that said, the following areas either appear to be vulnerable, or are potentially vulnerable, to key-timing attacks:

1. Containers used for RingCT (in particular, the key struct) as deployed throughout RingCT
2. The definition and implementations of `CRYPTO_MAKE_COMPARABLE`
3. `equalKeys` in rctOps.cpp, whose comparison speed appears to be relative to its available hardware

For points 1 and 2, as a steadfast rule; do **NOT** use `memcmp` when comparing cryptographic secrets (or any cryptographic material for that matter). For point 3, be careful with conditional branches which can be optimized or subject to speculative execution. One possible fix for point 3 is to perform an XOR of all the bytes in both buffers, and then compare the result (see kovri below).

As the literature states, key timing vulnerabilities can range from somewhat-trivial to extremely-difficult to exploit. For this report, I cannot assess a difficulty. For an active attack, monero has a very simple yet friendly network layer which I *imagine* could make remote execution *somewhat* easier (depending on the context and application) but, I don't have PoC. Now, at the local level for, let's say, a malicious node that wants to forge X before sending to the next peer, the results could be easier to attain (again, no PoC).

This was only the most superficial of reviews - so please forgive any assumptions or inaccuracies on my part. If I had more time with this issue, I would love to look deeper in order to provide a more details and to assert a monero PoC. Unfortunately, I am too busy with kovri - but I hope that this report will at least raises awareness.

Mitigation:

- Use a function which provides constant-time comparison. For example, [kovri has a crypto++ solution](https://github.com/monero-project/kovri/issues/895) at its disposal.

## Impact

At first glance, a forged RingCT signature - but the extent of the problem could be possibly extended to other areas (to be determined).

---
