# Use of Hard-coded Credentials

_6 reports — High/Critical, disclosed_

### [Exposed valid AWS, Mysql, Sendgrid and other secrets](https://hackerone.com/reports/1580567)

- **Report ID:** `1580567`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Credentials
- **Program:** Glovo
- **Reporter:** @mehdisadir
- **Bounty:** - usd
- **Disclosed:** 2022-07-08T15:48:55.275Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,

I just discovered some hardcoded credentials allowing access to AWS, Mysql database, ...

To make this report short, here is the POC: 
see ███ & █████
## Steps To Reproduce:

where there are the info : 

<p>
APP_NAME=Glovo
APP_ENV=local
APP_KEY=█████
APP_DEBUG=false
APP_URL=http://localhost
LOG_CHANNEL=stack
LOG_LEVEL=debug
DB_CONNECTION=mysql
DB_HOST=██████████
DB_PORT=3306
DB_DATABASE=████████
DB_USERNAME=█████
DB_PASSWORD=█████████
BROADCAST_DRIVER=log
CACHE_DRIVER=file
QUEUE_CONNECTION=sync
SESSION_DRIVER=file
SESSION_LIFETIME=120
MEMCACHED_HOST=127.0.0.1
REDIS_HOST=█████
REDIS_PASSWORD=██████████
REDIS_PORT=11773
MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS=null
MAIL_FROM_NAME="${APP_NAME}"
AWS_ACCESS_KEY_ID=███
AWS_SECRET_ACCESS_KEY=███████
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET=glovos3
PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1
MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
SENDGRID_API_KEY=████
MAIL_FROM=glovo@appsmart.ro
MAIL_REPLY_TO=glovo@appsmart.ro
REDIS_URL=█████
LINK_RECEIPT=https://glovo.onlineservice.io/g/c/
SENDGRID_TEMPLATE=d-6ae3f2fe536c41fda21ad60a18c10cce
SENDGRID_PUBLIC_KEY=███████
</p>




  1. The leak was found using Leakix : https://leakix.net/host/16.170.179.191

#Mitigation :

Remove the exposed credentials and revoke them.

Regards,

NB: After checking some files which i deleted immediatly, I found the company name is GLOVOAPPRO SRL and im not sure if it is related to Glovo company, but I can confirm a little bit from the database where I could see delivery fees ... which is about Glovo's principal service (delivery).

## Impact

Anyone could access

---

### [Hardcoded AWS credentials in ███████.msi](https://hackerone.com/reports/1368690)

- **Report ID:** `1368690`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Credentials
- **Program:** 8x8
- **Reporter:** @chip_sec
- **Bounty:** - usd
- **Disclosed:** 2022-04-29T17:01:08.879Z
- **CVE(s):** -

**Summary (team):**

A hardcoded AWS access token was discovered within an MSI file available for download on the 8x8 site. The researcher was able to demonstrate access to 8x8 AWS infrastructure. The token was promptly restricted.

---

### [[com.smule.autorap.*] Cloud Messaging/Push Notification service takeover due to clear-text usage of Legacy FCM Server keys in the client app ](https://hackerone.com/reports/789370)

- **Report ID:** `789370`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Credentials
- **Program:** Smule
- **Reporter:** @absshax
- **Bounty:** - usd
- **Disclosed:** 2020-08-24T19:27:09.595Z
- **CVE(s):** -

**Summary (team):**

Potential FCM issues across several apps investigated and remediated.

**Summary (researcher):**

Reference to Research:

https://twitter.com/absshax/status/1295383047295008768?s=19

---

### [JumpCloud API Key leaked via Open Github Repository.](https://hackerone.com/reports/716292)

- **Report ID:** `716292`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Credentials
- **Program:** Starbucks
- **Reporter:** @vinothkumar
- **Bounty:** - usd
- **Disclosed:** 2019-12-30T15:40:29.038Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Open Github Repo Leaking Starbucks JumbCloud API Key

**Description:** 
Team,

While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks. 

Repo:  [https://github.com/██████████/Project](https://github.com/██████████/Project).
File: [https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go](https://github.com/████/Project/blob/0d56bb910923da2fbee95971778923f734a25f68/getSystemUsers.go)

```
req.Header.Add("x-api-key", "████████")
```

**POC**
* List systems ```
curl -H "x-api-key: ████████" "https://console.jumpcloud.com/api/systems"
``` There are multiple AWS instances present

* ```
curl -H "x-api-key: █████" "https://console.jumpcloud.com/api/systemusers"
```
* SSO Applications ```curl -H "x-api-key: ██████" "https://console.jumpcloud.com/api/applications"
``` AWS login SAM config is presents. This would leads to AWS account takeover

## Impact

This issue impact is critical as through this API anyone could 
* Execute commands on systems [https://docs.jumpcloud.com/1.0/commands/create-a-command](https://docs.jumpcloud.com/1.0/commands/create-a-command)
* Add/Remove users which has access to internal systems
* AWS Account Takeover

**Summary (team):**

vinothkumar discovered a publicly available Github repository containing a Starbucks JumpCloud API Key which provided access to internal system information.

@vinothkumar — thank you for reporting this vulnerability and confirming the resolution.

---

### [Important information leaked on Github](https://hackerone.com/reports/649322)

- **Report ID:** `649322`
- **Severity:** High
- **Weakness:** Use of Hard-coded Credentials
- **Program:** Equifax-vdp
- **Reporter:** @mohanaddobal
- **Bounty:** - usd
- **Disclosed:** 2019-08-22T12:52:28.011Z
- **CVE(s):** -

**Vulnerability Information:**

While searchin on Github about Equifax i found some juicy information like a username and password of this subdomain (https://transport5.ec.equifax.com/), internal ip of the database and its username & password 
 In the following link (https://github.com/ajiththorali/Testing/blob/49025b364451fb2076f85ad009a0dc50a941c5ce/target/classes/API_Equifax/propertiesHandle.properties) you could find this info 
*******
XML_URL = https://transport5.ec.equifax.com/ists/stspost?require_security= HTTP/1.1
Username = 50404
Password = ny5b2MuswjrFq3J2P9
service_name = acroxmltest
Content_Type = application/xml
*******
jdbc_driver = com.mysql.jdbc.Driver
db_url = jdbc:mysql://192.168.84.225:3700/EquiFax
db_username = root
db_password = redhat
*********

You should change passwords of the leaked account and remove this info from github

## Impact

any attacker can login to this sub domain and do unauthorized actions
If any one was able to be inside the network he would connect to the leaked database ip and steal important information

---

### [[█████████] Hardcoded credentials in Android App](https://hackerone.com/reports/246995)

- **Report ID:** `246995`
- **Severity:** Critical
- **Weakness:** Use of Hard-coded Credentials
- **Program:** Eternal
- **Reporter:** @gerben_javado
- **Bounty:** 500 usd
- **Disclosed:** 2017-07-19T08:39:45.270Z
- **CVE(s):** -

**Summary (team):**

Authorization credentials for one of our development environments were hard coded in our Android App. We changed it as soon as this was reported. 

Thanks @gerben_javado for reporting this.

**Summary (researcher):**

After decompiling the Zomato app I found basic HTTP credentials in the app. This sort of happend on accident since I was looking for new endpoints to the API instead of looking for credentials. After finding the credentials I didn't know what do with them since the domain they belonged to returned a 503 error. Doing a subdomain bruteforce however discovered a subdomain where the credentials would expose a clone of the main admin panel.

Zomato shutdown this domain 5 minutes after I logged in.

---
