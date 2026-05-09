# Storing Passwords in a Recoverable Format

_2 reports — High/Critical, disclosed_

### [External storage app saves password for all users in the database](https://hackerone.com/reports/867164)

- **Report ID:** `867164`
- **Severity:** High
- **Weakness:** Storing Passwords in a Recoverable Format
- **Program:** Nextcloud
- **Reporter:** @alacn1
- **Bounty:** - usd
- **Disclosed:** 2021-03-01T11:01:47.786Z
- **CVE(s):** CVE-2020-8296

**Vulnerability Information:**

External storage (files_external) app save passwords of all users to database table "oc_credentials" even when "Log-in credentials, save in database" option is not used.

It's a security risk that allow password extraction of all users.

A local system admin that has access to database and nextcloud config file could decrypt any user password.

### Steps to reproduce
1. Enable app "External storage support" (files_external).
2. Login to nextcloud.
3. User recoverable password will be saved to table "oc_credentials" at "password::logincredentials/credentials".

### Expected behaviour
Don't save user password to table "oc_credentials" unless user has a mount with "Log-in credentials, save in database" option.

### Actual behaviour
Passwords of all users is saved to table "oc_credentials" when files_external app is enabled.

### Tested with
Nextcloud 18.0.4 + External storage 1.9.0
Nextcloud 17.0.5 + External storage 1.8.0

## Impact

A local system admin could recover any user password.

---

### [Password Cracking - Weak Password Used to Secure ████ Containing a Plaintext Password](https://hackerone.com/reports/985133)

- **Report ID:** `985133`
- **Severity:** High
- **Weakness:** Storing Passwords in a Recoverable Format
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:14:14.454Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I was able to crack the password to the ████████ located at ██████, as the pdf was protected with a weak password contained in a common word list. This guide contains steps to set-up the ███████ secure communication application with the unprotected configuration file located at██████████. This guide also contains a plaintext password for the configuration file.

## Step-by-step Reproduction Instructions

1. Browse to ███
2. Click `████████`. You will be prompted for a password.
3. Using wget, download the pdf: `wget ████████`.
4. Once downloaded, you can use `pdf2john` to convert the pdf password into a format that is parse-able by `john`: 
`perl /path/to/john/pdf2john.pl █████████.pdf`
5. This will produce a hash. Cracking this hash with `john` and the `rockyou` wordlist will produce the password: 

```
root@kali:/home/kali# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 6 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
█████████           (████████.pdf)
1g 0:00:00:00 DONE (2020-09-18 01:08) 1.785g/s 2285p/s 2285c/s 2285C/s 753951..poohbear1
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed
```

7. You can now browse to █████████, click `███`, and type in the password `█████████` to view the pdf (or view it on your local system).
8. Reading the setup instructions, and attacker can download the `Messaging Config`to download the ████ configuration file. This mobile guide contains the plaintext password for the configuration file (`███████`). They can then attempt to use the configuration file and a compromised `.mil`/`.gov`/etc. account to gain access to ████ secure communications.

## References
https://github.com/openwall/john/blob/bleeding-jumbo/run/pdf2john.pl

## Suggested Mitigation/Remediation Actions
Use a strong password for this .pdf file in order to prevent successful password cracking attempts.

## Impact

This guide contains steps to set-up the ███████ secure communication application with the unprotected configuration file located at█████. This guide also contains a plaintext password for the configuration file. An attacker could potentially join the secure communication channel if they were able to obtain access to the DoD ID number of an ███ member.

---
