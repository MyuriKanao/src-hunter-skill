# Reliance on Cookies without Validation and Integrity Checking in a Security Decision

_3 reports — High/Critical, disclosed_

### [Ruby CVE-2021-41819: Cookie Prefix Spoofing in CGI::Cookie.parse](https://hackerone.com/reports/1464396)

- **Report ID:** `1464396`
- **Severity:** High
- **Weakness:** Reliance on Cookies without Validation and Integrity Checking in a Security Decision
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 2000 usd
- **Disclosed:** 2022-02-03T03:43:03.517Z
- **CVE(s):** CVE-2021-41819, CVE-2020-8184

**Vulnerability Information:**

Release note: https://www.ruby-lang.org/en/news/2021/11/24/cookie-prefix-spoofing-in-cgi-cookie-parse-cve-2021-41819/

> The old versions of CGI::Cookie.parse applied URL decoding to cookie names. An attacker could exploit this vulnerability to spoof security prefixes in cookie names, which may be able to trick a vulnerable application.

> By this fix, CGI::Cookie.parse no longer decodes cookie names. Note that this is an incompatibility if cookie names that you are using include non-alphanumeric characters that are URL-encoded.

> This is the same issue of CVE-2020-8184.

---

The following is copied from hackerone's report. https://hackerone.com/reports/910552

I found the same problem with https://hackerone.com/reports/895727 exists at `CGI::Cookie.parse`.

https://github.com/ruby/ruby/blob/v2_7_1/lib/cgi/cookie.rb#L162

```ruby
def self.parse(raw_cookie)
  cookies = Hash.new([])
  return cookies unless raw_cookie

  raw_cookie.split(/;\s?/).each do |pairs|
    name, values = pairs.split('=',2)
    next unless name and values
    name = CGI.unescape(name)
    values ||= ""
    values = values.split('&').collect{|v| CGI.unescape(v,@@accept_charset) }
    if cookies.has_key?(name)
      values = cookies[name].value + values
    end
    cookies[name] = Cookie.new(name, *values)
  end

  cookies
end
```

The value of `name` is decoded.


#### PoC

```ruby
❯ ruby -v
ruby 2.7.1p83 (2020-03-31 revision a0c7c23c9c) [x86_64-darwin19]

❯ irb
irb(main):001:0> require 'cgi'
=> true

irb(main):002:0> cookie_a = CGI::Cookie.parse("__%48ost-evil=evil;__Host-evil=abc")
irb(main):003:0> cookie_a["__Host-evil"]
=> #<CGI::Cookie: "__Host-evil=evil&abc; path=">
irb(main):004:0> cookie_a["__Host-evil"].to_a
=> ["evil", "abc"]

irb(main):005:0> cookie_b = CGI::Cookie.parse("%48oge=evil;Hoge=abc;Foo=xxx")
irb(main):006:0> cookie_b["Hoge"].to_a
=> ["evil", "abc"]
irb(main):007:0> cookie_b["Foo"].to_a
=> ["xxx"]
```

## Impact

It has the same impact as #895727, and it is possible to insert a value into the name of a cookie that should be protected by Cookie prefixes.

**Summary (team):**

A cookie prefix spoofing vulnerability was discovered in CGI::Cookie.parse. This vulnerability has been assigned the CVE identifier CVE-2021-41819. We strongly recommend upgrading Ruby.

Details
The old versions of CGI::Cookie.parse applied URL decoding to cookie names. An attacker could exploit this vulnerability to spoof security prefixes in cookie names, which may be able to trick a vulnerable application.

By this fix, CGI::Cookie.parse no longer decodes cookie names. Note that this is an incompatibility if cookie names that you are using include non-alphanumeric characters that are URL-encoded.

This is the same issue of CVE-2020-8184.

If you are using Ruby 2.7 or 3.0:
* Please update the cgi gem to version 0.3.1, 0.2,1, and 0.1,1 or later. You can use gem update cgi to update it. If you are using bundler, please add gem "cgi", ">= 0.3.1" to your Gemfile.
* Alternatively, please update Ruby to 2.7.5 or 3.0.3.

If you are using Ruby 2.6:
* Please update Ruby to 2.6.9. You cannot use gem update cgi for Ruby 2.6 or prior.

Affected versions
* ruby 2.6.8 or prior (You can not use gem update cgi for this version.)
* cgi gem 0.1.0 or prior (which are bundled versions with Ruby 2.7 series prior to Ruby 2.7.5)
* cgi gem 0.2.0 or prior (which are bundled versions with Ruby 3.0 series prior to Ruby 3.0.3)
* cgi gem 0.3.0 or prior

Credits
Thanks to ooooooo_q for discovering this issue.

https://www.ruby-lang.org/en/news/2021/11/24/cookie-prefix-spoofing-in-cgi-cookie-parse-cve-2021-41819/

---

### [Отправка писем с произвольным текстом/кликабельными ссылками любому зарегистрированному пользователю с указанной почтой, зная только steamid](https://hackerone.com/reports/993711)

- **Report ID:** `993711`
- **Severity:** Critical
- **Weakness:** Reliance on Cookies without Validation and Integrity Checking in a Security Decision
- **Program:** CS Money
- **Reporter:** @libneko
- **Bounty:** - usd
- **Disclosed:** 2020-12-20T11:11:57.040Z
- **CVE(s):** -

**Summary (team):**

Using a third-party service `GetResponse` used on the project and the 2FA deactivation functionality combined, a hacker found a way to send **arbitrary text** to **any** user, knowing only the victim's SteamID.

*The vulnerability relied on:*
1. Invalid cookie management in request;
1. No additional validation for email ownership.

---

### [[REMOTE] Full Account Takeover At https://██████████████/CAS/](https://hackerone.com/reports/215859)

- **Report ID:** `215859`
- **Severity:** High
- **Weakness:** Reliance on Cookies without Validation and Integrity Checking in a Security Decision
- **Program:** U.S. Dept Of Defense
- **Reporter:** @karimrahal
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:23:30.728Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A session cookie **PROD_CAS_SESSION** takes a User ID as an input, hence an attacker is able to insert his victim's User ID and takeover his victim's account. (P.S The User ID is only 6 numbers long). 
## Impact
An attacker is able to insert his victim's User ID into the cookie **PROD_CAS_SESSION** and takeover his victim's account.
## Step-by-step Reproduction Instructions

1. Go to https://██████/MOS/ (This is one of many websites you can do this from)
2. Add a cookie with the domain **███**, the name **PROD_CAS_SESSION*, and the value should be ur victim's User ID (example: **195141**).
3. Refresh the page
4. Done, you will be logged into your victim's account.

**To Get User's Info**
4. At https://████/MOS/, you will notice a dropdown on the right top corner with **Welcome (Your Victim's Name)**, click the dropdown and click **My Profile**
5. Done, you will be able to see your victim's user info.

## Suggested Mitigation/Remediation Actions
Add a more secure session value.

---
