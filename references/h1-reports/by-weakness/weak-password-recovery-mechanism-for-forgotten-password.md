# Weak Password Recovery Mechanism for Forgotten Password

_4 reports — High/Critical, disclosed_

### [Cookie steal through content Uri](https://hackerone.com/reports/876192)

- **Report ID:** `876192`
- **Severity:** Critical
- **Weakness:** Weak Password Recovery Mechanism for Forgotten Password
- **Program:** Brave Software
- **Reporter:** @kanytu
- **Bounty:** 500 usd
- **Disclosed:** 2021-04-22T18:05:12.454Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

A misconfiguration in a content provider is allowing Brave for Android to download internal files to Downloads folder, making them accessible to other apps. A malicious app could order Brave to download the cookies database and retrieve it afterwards.

## Environment

- **Device:** HTC M8
- **OS version:** Android 9
- **Package name:** com.brave.browser
- **App version:** 1.8.93 (`versionCode` 410809320)



## Proof of concept

### Pre-conditions:

- Poc installed with `STORAGE` permissions
- Brave installed with some cookies saved
- Brave should have `STORAGE` permission as well

### Steps:

1. Tap "Start Exploit" in PoC app
2. Brave will start to download the cookies file
3. Open back PoC app

### Result

Cookies are shown in PoC app

### Expected result

Private files shouldn't be exported



## Detailed explanation

When `Start Exploit` is tapped, the app is sending an intent to Brave Browser to view a content URI:

```
content://com.brave.browser.FileProvider/root/data/data/com.brave.browser/app_chrome/Default/Cookies
```

This content URI will be resolved to `ChromeFileProvider`. This File Content Provider has the following path configuration:

```
<paths>
    <root-path name="root" path="." />
    <files-path name="images" path="images/" />
    <cache-path name="cache" path="net-export/" />
    <cache-path name="passwords" path="passwords/" />
    <cache-path name="traces" path="traces/" />
    <cache-path name="webapk" path="webapks/" />
    <cache-path name="offline-cache" path="Offline Pages/archives/" />
    <external-path name="downloads" path="Download/" />
    <external-path name="downloads" path="Android/data/com.brave.browser/files/Download/" />
</paths>
```

Because of the usage of `root-path` with path `.`, it is possible to use this provider to point to all files in the Android system.

By using the path segment `/root/` followed by the absolute path to the internal file, Brave will easily process this URI because it belongs to itself, hence, no need to grant permissions to this URI.

Brave will then proceed to download this file because of it's mime type (`application/octet-stream`). The file is saved in `/sdcard/Download/`. This is a public directory and all files with `STORAGE` permission can access them.

The PoC listens for changes in Downloads directory and when the Cookies file is created there, it will access this database and print all cookies in it.



## Remediation

Brave should not use `root-path` point to the root of the file system (`./`). If this needed for some edge case, Brave should implement path checks to make sure that no internal file is used in this URI.

## Attachments

- PoC.zip - source code of the PoC used in this exploit
- poc.apk - compiled binary to use in this exploit
- video.mp4 - a video showing the exploit in action

## Impact

This allows a malicious app with `STORAGE` permission to access all cookies in Brave which has a high confidentiality impact. This requires no user interaction other than a malicious app installed.

This works for all internal files but cookies allow the malicious app to potentially access private information from the user, impacting the availability and integrity of their logged in accounts.

**Summary (researcher):**

Write-up available [here](https://infosecwriteups.com/brave-stealing-your-cookies-remotely-1e09d1184675).

---

### [Reset any password](https://hackerone.com/reports/703972)

- **Report ID:** `703972`
- **Severity:** High
- **Weakness:** Weak Password Recovery Mechanism for Forgotten Password
- **Program:** pixiv
- **Reporter:** @noxxxx
- **Bounty:** - usd
- **Disclosed:** 2021-03-31T01:58:17.733Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

When I try to reset the password, the verification code of the mailbox is 6 digits, and there is no limit on the number of submissions, so I can reset the password of any user.

## Steps To Reproduce:
1.input the email  [reset password url](https://www.pixiv.net/reminder.php).
{F595146}
click  the "submit" button
{F595147}
input the email verification code and try to guess the verification code, but I won’t be able to continue using it after I try it a few times.

{F595148}

2.After trying, I found that there was no such submission restriction when the password was reset in the third step.

Repeat the above steps, the only difference is that you need to enter the correct verification code.

{F595160}
It can be seen that when we reset the password in the last step, the verification code will still be sent, that is, the verification code will be sent to the server for validity verification in the last step, and the verification code of the last step is not limited by the number of submissions. In other words, we can guess the verification code.

I wrote a python script to verify the vulnerability, you only need to enter the following parameters to verify the vulnerability.

parameter：tt code_id code phpsession

python: {F595166}
video: {F595172}

## Supporting Material/References:
none

  * [attachment / reference]

## Impact

Reset any user's password

---

### [(Possible) staff account takeover via reset token bruteforce at helpdesk.bistudio.com](https://hackerone.com/reports/332632)

- **Report ID:** `332632`
- **Severity:** Critical
- **Weakness:** Weak Password Recovery Mechanism for Forgotten Password
- **Program:** BOHEMIA INTERACTIVE a.s.
- **Reporter:** @europa
- **Bounty:** - usd
- **Disclosed:** 2018-09-19T14:42:15.945Z
- **CVE(s):** -

**Vulnerability Information:**

As stated in a brief exchange with @rvn in my other report ##312433, I might have found a logic flaw in the way https://helpdesk.bistudio.com handles the reset flow and tokens.
I've asked if it was possible to obtain a test account, but I fully understand that it's something that cannot be done; as such I'll submit a "blind" report based on my black-box analysis and wait for your team to verify it. Also note that this flaw seems to also be present in the "Set out of office email response" flow, albeit less critical.

### Flow
The **SYSTEM PASSWORD RESET** flow is a 3-steps process:

1. the staff member requests a SMS TOKEN using the first form
2. the 6-digits SMS TOKEN is used in the second form
3. the staff member can now set a new SYSTEM PASSWORD in the third form

### Analysis and logic
I was able to go through the process even after providing non-existing usernames and tokens by intercepting the **response** in BurpSuite and changing the status code from **400 Bad Request** to **200 OK** and the body from `"status":"error"` to `"status":"ok"`, allowing the AngularJS applet to follow through.
I then noticed that the API endpoint for verifying the SMS TOKEN and changing the password where open and free of rate-limiting measures, allowing for a quick bruteforce of the 000000-999999 space. 
It should be therefore possible to perform an account takeover on any staff member, provided the SMS TOKEN really is a 6-digits code

### Theoretical POC
1. adversary starts the SYSTEM PASSWORD RESET process for the target victim using a POST request to `/api/system/verification-codes` (ie: `{"username":"admin"}`). The backend generates a SMS TOKEN and sends it to the victim's phone. Meanwhile,
2. adversary obtains the **securityCode** value for the victim by bruteforcing `/api/system/verification-codes/[0-9]{6}` before the victim can cancel the flow (threat scenario places the attack durin night time)
3. adversary can now reset the SYSTEM PASSWORD by sending the complete POST request to `/api/system/email-account/password` (ie: `{"password":"<NEW PASSWORD>","code":"<BRUTEFORCED SMS TOKEN>","securityCode":"<RETRIEVED SECURITY CODE>"}`)

Step #1 offers a ReCAPTCHA anti-CSRF token but it's not used anywhere in the flow, making the attack possible

Step #2 is really a matter of resources. Being free of rate-limiting, the API endpoint will be quickly queried for all the possible token combinations in a matter of minutes using a multithreaded approach (ie: using BurpSuite's Intruder).

Albeit theoretical, the logic behind the threat scenario seems plausible. It might be worth investigating.

### Recommended actions
Properly implement the ReCAPTCHA and a strict ratelimiting on the API endpoints

## Impact

An adversary might be able to takeover staff accounts, or set their "out of office" email replies.

---

### [Password Reset Token Not Expired ](https://hackerone.com/reports/283550)

- **Report ID:** `283550`
- **Severity:** High
- **Weakness:** Weak Password Recovery Mechanism for Forgotten Password
- **Program:** Infogram
- **Reporter:** @geekninja
- **Bounty:** - usd
- **Disclosed:** 2017-10-30T09:20:44.066Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,

Here in this scenario, I've found that the there's a kind of server side invalidation of Password Reset tokens. Like if I've requested for password reset token (token1) and I don't use it, after I will make another request for password reset token (token2). This time I'll use the token2 means the link that I requested for the second time, so the first token (token1) should explicitly expire by the server. But here I can use the token1 also after password change by token2, this is unusual behavior of web application.

Exploit Scenario:
If victim's email account is still logged into his/her Office Computers or any public Internet Cafe. Then any external attacker can use the unused token to reset victims token.

Proof of Concept:

1)Go to https://infogram.com/forgot and ask for password reset link.
2)Don't use the link keep it in Email inbox.
3)After some time repeat the step 1.
4)This time use the password reset link which was asked in step 3. means the 2nd link.
5)After changing the password, use the password reset link that was captured in step 1.
6)You'll see the password reset link is not expired even after password change.
7)I've also explained you the Exploit Scenario, now its all upto you.

Regards,
Ali Razzaq

---
