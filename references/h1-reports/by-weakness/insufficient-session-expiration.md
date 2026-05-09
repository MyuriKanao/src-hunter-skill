# Insufficient Session Expiration

_4 reports — High/Critical, disclosed_

### [Can use the Reddit android app as usual even though revoking the access of it from reddit.com](https://hackerone.com/reports/1632186)

- **Report ID:** `1632186`
- **Severity:** Critical
- **Weakness:** Insufficient Session Expiration
- **Program:** Reddit
- **Reporter:** @sateeshn
- **Bounty:** - usd
- **Disclosed:** 2022-07-16T11:10:55.959Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi Team,

For the last 4 days, I kept testing reddit web. That time, I revoked app access from the old.reddit.com and i checked my app and as expected i was not able to use the account in my app. 

After 2 days I was checking the chat invites feature on the web and after some time I turned on the internet on my mobile and got a Reddit "invitation accept"  notification. I clicked on that and I was surprised that I was able to use the previously revoked user account again in the Reddit app.

After I tried to reproduce the scenario again. I  thought the revoked account get access again after clicking on the app "chat invite" notification. 
- I again revoked the app access from the old.reddit.com
- I sent a chat invitation link to another test account and replied with the test account so that I get a "chat accept" notification in the mobile
- After several tries from several test accounts, Finally, I received the "chat accept" invitation, only one time on the mobile (Note: this is also an issue)
- I clicked on the notification and I was not able to access anything in the app (it was showing some error)
- I tried to reproduce the issue again, I don't know the reason But this time I was not able to view the chat invite links from any accounts. (it was showing some error)
- It took my whole day and I stopped testing.

The next day again I got a post notification on my mobile. I clicked on that and again I see that the app was working as usual with a previous logged-in user!!!

Finally, I came to the conclusion that whenever we revoke the app access, it works fine. But if you check the app approximately after 20+ hours you can reuse the previously logged-in account again.

## Steps To Reproduce:
  1. log in to your account from both the android mobile app and from the web(reddit.com or old.reddit.com)
  2. On the Reddit web go to https://www.reddit.com/account-activity 
  3. Navigate to the "Apps you have authorized" section
  4. Find "Reddit on Android" click the revoke access and confirm
  5. Now open the Reddit app where you have logged in step 1
  6. You are no more able to access any info about the user and it will show errors like "Let's try that again" or "uh oh something went wrong but we're not     sure what"
  7. Open the app approximately after 20+ hours and see that you can reuse the previously logged-in account without any issue.

## Supporting Material/References:
I see that I got the latest app update and trying to reproduce the issue again on the latest version i.e 2022.25.1 I will update you on it again. I assume previously my Reddit app version was 2022.25.0 or 2022.24.1
Device and version info{F1814768}
The account/username used for testing is: sateeshn_1

## Impact

Unauthorized access to account even though revoking the access.

---

### [Web Server Predictable Session ID on EdgeSwitch ](https://hackerone.com/reports/774393)

- **Report ID:** `774393`
- **Severity:** High
- **Weakness:** Insufficient Session Expiration
- **Program:** Ubiquiti Inc.
- **Reporter:** @fr33rh
- **Bounty:** - usd
- **Disclosed:** 2021-05-23T01:22:00.144Z
- **CVE(s):** CVE-2020-8234

**Summary (team):**

In EdgeSwitch legacy web interface the SIDSSL cookie for admin can be guessed, enabling the attacker to obtain high privileges and get a root shell by a Command injection.
These vulnerabilities were found on EdgeSwitch 1G switch (ESWH) and EdgeSwitch 10G switch (ESGH) firmware v1.9.0.

The fix for these vulnerabilities were included in the new version of EdgeMax EdgeSwitch firmware v1.9.1
For more details please visit:

https://community.ui.com/releases/EdgeMAX-EdgeSwitch-Firmware-v1-9-1-v1-9-1/8a87dfc5-70f5-4055-8d67-570db1f5695c

https://www.ui.com/download/edgemax

---

### [Узнаем несколько цифр номера телефона юзера (можно флудить смс), всего раз узнав его remixsid и его ид юзера, и установка оффлайна юзерам.](https://hackerone.com/reports/390126)

- **Report ID:** `390126`
- **Severity:** High
- **Weakness:** Insufficient Session Expiration
- **Program:** VK.com
- **Reporter:** @povargek
- **Bounty:** 300 usd
- **Disclosed:** 2019-05-10T23:16:24.694Z
- **CVE(s):** -

**Summary (team):**

Недостаточные проверки сессии.

**Summary (researcher):**

Было можно узнать часть номера телефона юзера и отправлять ему смс с ссылкой на приложение (https://vk.com/mobile) всего раз узнав его `remixsid`, вне зависимости сколько раз были ресетнуты сессии. Самый давний валидный для этой темы `remixsid`  был давности ~ май 2016 года.

Была возможность имея только ид юзера установить ему статус "оффлайн" (т.е. был в сети 1 сек назад и тд) и сбросить ему queue-ключи, что принудительно вызывало `/notifier.php?act=a_get_key` где был рейт лимит на получение ключей, таким образом можно было отключить юзеру queue серв (нотифиер, не тот что `imv4`, а `queuev4` - те реалтайм события не приходили, кроме тех что в личку идут)

---

### [Session replay vulnerability in www.urbandictionary.com](https://hackerone.com/reports/216294)

- **Report ID:** `216294`
- **Severity:** High
- **Weakness:** Insufficient Session Expiration
- **Program:** Urban Dictionary
- **Reporter:** @tcpiplab
- **Bounty:** - usd
- **Disclosed:** 2017-06-20T08:20:00.441Z
- **CVE(s):** -

**Vulnerability Information:**

# Session replay vulnerability in www.urbandictionary.com

I considered titling this bug "*Session tokens not expiring*", which is what you need to tell your development team. But I titled it as I did to emphasize at least one attack made possible by the bug. There may be others.

## Description
Privileged functions, e.g., `/handle.save.php` can still be used after the user has clicked the "sign out" link. The cause of the vulnerability seems to be that the server is not invalidating session cookies when the user "signs out". I observed session tokens remaining valid even 72 hours after being issued.

Exploitation requires the anti-CSRF `authenticity_token` from the privileged page from before the victim "logged out", and any one of the victim's `_rails_session` cookies from before the victim "logged out". Note that because the server issues a new cookie with each Response, the attacker may choose from among many cookies.

## Impact
1. Cookies that never expire can impact the security of the user:
   1. The user's session is susceptible to hijacking or replay.
   1. The user has no way of causing the application to invalidate their session. This is important in shared computing environments.
2. Cookies that never expire can impact the security of the server:
   1. The time window to brute-force a valid session token is increased.
   1. If many session tokens remain valid, brute-forcing has that many more chances to guess correctly.

## Step-by-step Reproduction Instructions
1. Set up an HTTP intercept proxy like Burp Suite or ZAP.

1. Authenticate to `http://www.urbandictionary.com/users.php` via the Gmail OAuth function, receiving a valid session cookie from `www.urbandictionary.com`, and then "sign out" by clicking `http://www.urbandictionary.com/auth/logout`.

1. Send a `POST` request to `https://www.urbandictionary.com/handle.save.php` containing:
   1. The `authenticity_token` from the privileged page from before the user "logged out".
   1. Any one of the user's `_rails_session` cookies from before the user "logged out".
   1. In the body of the POST set `user[handle]` to a new value. I've used `H.H. Vong`.
   1. In the body of the POST set `commit` to `Save`.

   {F171456}

   The screen-shot above shows how to use Burp Repeater to replay a session and modify the user handle.

   Here is that request as a curl command:

   ```
   $ curl -L -i -s -k  -X $'POST'     -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H $'Referer: https://www.urbandictionary.com/handle.php' -H $'Content-Type: application/x-www-form-urlencoded'     -b $'_rails_session=bnBaYnJjSjNJcmxGN1JrWjFkbmUwa0NFY05GdThtcmtHQU0zTHhsem1iQngyQmhvYUdKQTRCVmNHNlBGRTEvRm9aczFwRXc5ekVUV2FEVDM4RSswQU9rejBReGc1M3dxVGhRV0REQmFCUWFkYWcwQ1RhV2NIN1VUalQyM09tNHAwS3lkc0JaRlJqNkxKd2xNZVdKQzhYOFpBdlhqRHhoYVplWmczTFZBL3hlb3E2YUxkVmp4NEkzZUxtZXBQa1ozME9MUFdXRHRDQStOWXdUT2xkcTRSdz09LS1LNXVZWmFBL0F5STRIUjkwTmdnczR3PT0%3D--4ea5f8f5d73379881a6db43b9b8cdcc9d7c89773'     --data-binary $'authenticity_token=C4EmquHAIijNq8UrFfbdfm%2B3Bp5RxvL1BpzMdf3%2FJgtw%2FSn%2FgTt4AlFlIDWFivaesfXJFgNqrWS8DD85obbnpA%3D%3D&user%5Bhandle%5D=H.H.+Vong&commit=Save'     $'https://www.urbandictionary.com/handle.save.php'
   ```

1. The response will be a `302/Found` with the `Location` field set to `https://www.urbandictionary.com/users.php`. Your browser will follow the `302` redirect, issuing a `GET` request for the URL in the `Location` field. The server will respond with a `200/OK` status code.

   {F171455}

   The screen-shot above shows the Burp Repeater response with the rendered HTML displaying the successfully modified user handle.

   If you're verifying this with `curl`, you could just `grep` for the modified value. Append this to the `curl` command previously specified: ` | grep -i vong`. Two lines of the HTML in the returned page will contain the newly modified handle:

   ```
   <title>Urban Dictionary: Hello H.H. Vong</title>
   <span>Hello H.H. Vong</span>
   ```

## Suggested Mitigation/Remediation Actions
1. Configure the server side application to invalidate a user's submitted session token:
   1. When a new token is issued by the server side application, so that only one token is valid at any given time.
   1. When the user submits a valid session token to `/auth/logout`.
   1. When a valid session token has not been submitted to the server side application for greater than *n* seconds where *n* is some value consistent with your own internal policy.
   1. When a valid session token, stored on the server, is older than *m* seconds, where *m* is the maximum age allowed for a session cookie, based on your own internal policy.

## Product, Version, and Configuration
* Kali Linux 2016.2
* Mozilla Firefox 45.7.0
* Burp Suite 1.7.17
* `curl` 7.52.1

Please let me know if you need more information about this issue. Thanks.

---
