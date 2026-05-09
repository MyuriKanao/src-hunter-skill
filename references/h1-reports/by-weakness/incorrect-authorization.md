# Incorrect Authorization

_4 reports — High/Critical, disclosed_

### [IDOR Leads To  User Profile Modification https://mtnmobad.mtnbusiness.com.ng/app/updateUser](https://hackerone.com/reports/1714638)

- **Report ID:** `1714638`
- **Severity:** Critical
- **Weakness:** Incorrect Authorization
- **Program:** MTN Group
- **Reporter:** @reachaxis
- **Bounty:** - usd
- **Disclosed:** 2024-09-18T23:21:51.728Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hello Team,
https://mtnmobad.mtnbusiness.com.ng/app/updateUser allows authenticated users to alter their account profile. But, however, there is no authorization check when updating another user's profile thus, allowing attacker to modify  anyone's profile info such as `Username, Address,  Mobile Number,  Company Name and Company Size`

## Steps To Reproduce:

## Requirements:
Create two Test Accounts (Attacker & Victim)
Login into attacker's account In Mozilla Firefox at https://mtnmobad.mtnbusiness.com.ng/#/login1.   

1. Visit https://mtnmobad.mtnbusiness.com.ng/#/userProfile 
2. Goto to Burp and turn Intercept is on to capture request.
3. Locate this endpoint `POST /app/updateUser HTTP/1.1` while still proxying traffic through Burp. Notice, json blob data being presented.
3. Record `"id":"/###", "email":"redacted+attacker@wearehackerone.com"` for attacker's account and Logout.
4. Now, Login into victim's account and repeat step [1, 2 & 3] and Logout.

## Attack Steps
Login into attacker's account in Mozilla Firefox and Victim's Account in Google Chrome.

1. Using attacker's account in Firefox, visit https://mtnmobad.mtnbusiness.com.ng/#/userProfile and capture request with Burp. 
2. Switch attacker's "id":"/redacted", "email":"redacted+attacker@wearehackerone.com" to victim "id":"/redacted" "email":"redacted+victim@wearehackerone.com" and forward request.
3. Go to victim's account in google chrome and refresh the page.
4. Visit victim's profile and notice, attacker has successfully updated the user's Profile without their knowledge.

## Recommendation/Remediation:
Implement stringent authorization controls to make sure a user has the necessary rights before allowing them to make such a harmful request on another account.
Generate random `userIds`  to prevent attacker from predicting such `userIds`.

## Supporting Material/References:

Video: 
{F1957836}

## Screenshots:
Before:
{F1957817}

## After:
{F1957834}


  * [attachment / reference]

## Tools
BurpSuite Community Edition: [v2022.8.4]
Morzila Firefox: 105.0.1 (64-bit)
Google Chrome: Version 105.0.5195.127 (Official Build) (64-bit)
OS:  Microsoft Windows [Version 10.0.22000.856]

## Impact

An attacker will be able to use this technique to change any user's (advertiser's) profile, for example, a company name and  phone number under the attacker's control to commit a crime entirely in the victim's name.

Regards!
@v3rvain0001

**Summary (researcher):**

It was possible for a remote authenticated attacker to update the profile details of all users due to insufficient authorization check. The profile details include `Mobile Number`,`Residential Address`,`Username`

---

### [Any meeting chat history can be read and modified by an arbitrary user](https://hackerone.com/reports/1038658)

- **Report ID:** `1038658`
- **Severity:** Critical
- **Weakness:** Incorrect Authorization
- **Program:** 8x8
- **Reporter:** @pmnh
- **Bounty:** 1337 usd
- **Disclosed:** 2021-04-29T22:18:44.323Z
- **CVE(s):** -

**Summary (team):**

A vulnerability existed where a `JaaS` user could read & modify the chat history of an `8x8 Meet` conference. It was limited by the fact that the meeting UUID was required to be known. The fix was promptly deployed to production.

**Summary (researcher):**

A vulnerability in an API accessible through the `jaas.8x8.vc` white-label frontend of the Jitsi platform allowed a user to view, edit, and overwrite / delete the conversation (chat) history or transcript of any `8x8.vc` conference due to a lack of authorization checks to validate that the meeting being edited belonged to the white-label customer.

---

### [Email verification bypasa](https://hackerone.com/reports/763458)

- **Report ID:** `763458`
- **Severity:** High
- **Weakness:** Incorrect Authorization
- **Program:** Stripo Inc
- **Reporter:** @veejeey_
- **Bounty:** - usd
- **Disclosed:** 2020-03-24T08:44:02.643Z
- **CVE(s):** -

**Summary (team):**

Email verification bypass:

after finishing the registration user need to verify the email address, this can be bypased while loggin in to the account.

---

### [Full access to internal Gitlab instances at redash.gitlab.com, dashboards.gitlab.com, prometheus.gitlab.com](https://hackerone.com/reports/498964)

- **Report ID:** `498964`
- **Severity:** Critical
- **Weakness:** Incorrect Authorization
- **Program:** GitLab
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2019-04-19T09:46:26.556Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Lack of proper ticket trick security leads to internal access on Gitlab instances. **I did not use support.gitlab.com instead just using support@gitlab.com email was suffice. 

**Description:**

*Getting a support@gitlab.com Google Account*

After the Ticket Trick attack that Inti reported and disclosed, many companies including Gitlab added proper security measures to prevent this kind of attack. What companies did not realize is that Zendesk has a feature that can be exploited by attackers other than the CC feature. 

In this case, Gitlab has blocked sending emails to support+*@gitlab.com which prevents Ticket Trick that Inti came up with. However, the CC feature along with the Zendesk's feature can lead to further exploitation. 

To begin with, I sent an email to support@gitlab.com. After this, an automated reply was sent by Gitlab with confirmation that my ticket went through. Next, I went to accounts.google.com and registered support@gitlab.com. For the firstname and last name I copied a special hash for the ticket. Zendesk as a feature has a special hash for each ticket that is generated in the system This hash is like the key in a dictionary and can be used to add more content to the ticket. So by getting that hash and sending the request, Google allegedly sends an email to verify.

What happened here was due to Zendesk's own security measures, the first email from Google will be set as private because they are not CCed to my ticket. So then, I replied to the support ticket from Gitlab and in CC put noreply@google.com. Once this was done, I replayed the request in Google and again tried to verify `support@gitlab.com` this time the ticket had the verification code public. 

{F427388}

If you check the image on the top right corner you can see the hash repeated twice because I put that as a first and last name. 

Once this was done, I had a verified support@gitlab.com email. 

{F427390}

Next, I went to crt.sh to search for gitlab.com domains and found 3 domains that stood out: 

* prometheus.gitlab.com
{F427391}

* redash.gitlab.com 
{F427393}

* dashboards.gitlab.com
{F427395}

## Impact

Getting access to internal applications.

**Summary (researcher):**

Read about the test here: https://sites.google.com/securifyinc.com/secblogs/scary-tickets

---
