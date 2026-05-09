# Unverified Password Change

_2 reports — High/Critical, disclosed_

### [Password authentication when changing information bypass. Bypass of report #721341](https://hackerone.com/reports/1040373)

- **Report ID:** `1040373`
- **Severity:** High
- **Weakness:** Unverified Password Change
- **Program:** Khan Academy
- **Reporter:** @tomorrowisnew_
- **Bounty:** - usd
- **Disclosed:** 2021-02-11T23:08:27.883Z
- **CVE(s):** -

**Vulnerability Information:**

#SUMMARY
When reading the disclosed reports of your program, i see this one report #721341 . The reporter reported a lack of password confirmation when linking accounts. A fix was applied, adding password confirmation when linking account to other services. But i found a way to bypass this, The password confirmation is only done in the client side. This is bad because such methods are vulnerable to response manipulation. I will add a video poc 

#STEPS TO REPRODUCE
1. Open a browser in which a user has previously logged into an account, but hasn't logged out.
2. Open another browser and login using your account
3. Try to link gmail using your account, it will prompt for a password confirmation, enter your password
4. Intercept the response and copy it
5. Go to the victims account and link to gmail again
6. This time enter any password and intercept response
7. Paste the copied response from the attacker account

#POC
██████████

## Impact

An attacker can take over an account and lock a user out by resetting the password.

---

### [Information can be changed without a password](https://hackerone.com/reports/721341)

- **Report ID:** `721341`
- **Severity:** High
- **Weakness:** Unverified Password Change
- **Program:** Khan Academy
- **Reporter:** @jamesconnor
- **Bounty:** - usd
- **Disclosed:** 2020-03-14T01:41:03.427Z
- **CVE(s):** -

**Vulnerability Information:**

If a user has access to a logged in session on Khan Academy, they are able to conduct a full account takeover. This is due to the fact that a new email address can be added to an account without a method of re-authentication. Once this email address has been added, the attacker can simply logout and follow the "Forgot Password" dialogue on the login page to send a password reset email to the email address they added. This allows them to change the password and completely take over the account. While this could arguably be the user's fault for not logging out, Khan Academy specifically targets an audience of students and educators, many of whom may use their accounts on shared computers in school. As a result, it's necessary to require re-authentication before allowing modifications to certain user settings, such as the account's email addresses.

**Steps to reproduce**

1. Open a browser in which a user has previously logged into an account, but hasn't logged out.
2. Go to https://www.khanacademy.com/settings (the user settings)
3. Scroll down to "Connect an email", click the button, and type in any email address that you control. This simulates the attacker's email address. Finally, click "Send a Confirmation Email". 
4. Open the attacker's inbox and follow the instructions to reset the password. Change the password to whatever you want.
5. Click "Reset and Log In". The account has now been successfully taken over.

## Impact

An attacker can take over an account and lock a user out by resetting the password.

---
