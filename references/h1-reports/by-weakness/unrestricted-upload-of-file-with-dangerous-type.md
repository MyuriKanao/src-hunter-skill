# Unrestricted Upload of File with Dangerous Type

_5 reports — High/Critical, disclosed_

### [Unrestricted File Upload at ██████████](https://hackerone.com/reports/2357778)

- **Report ID:** `2357778`
- **Severity:** Critical
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Program:** Mars
- **Reporter:** @xplo1t
- **Bounty:** - usd
- **Disclosed:** 2024-02-19T14:34:21.049Z
- **CVE(s):** -

**Summary (team):**

The endpoint "████████" enables unrestricted file uploads, meaning anyone on the internet, without registration, can upload any type of file. This poses a security risk as unauthorized users could upload potentially harmful or malicious files without restriction.

---

### [[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia](https://hackerone.com/reports/1547877)

- **Report ID:** `1547877`
- **Severity:** Critical
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Program:** Aiven Ltd
- **Reporter:** @jarij
- **Bounty:** 5000 usd
- **Disclosed:** 2022-11-08T06:29:22.109Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on `localhost:6725`.  JMX exports the `com.sun.management:type=DiagnosticCommand` MBean, which contains the `jvmtiAgentLoad` operation. This operation can be used to execute the SQLite database as JVM Agent by embedding the JVM Agent JAR file inside the SQLite database as an BLOB field in a table.

## Steps To Reproduce:

{F1703051}

  1. Login into my VPS: `ssh ████`, password: `█████████@`
  1. Execute `nc -nlvp 4446`
  1. cd to `jdbc-sqlite-jolokia-rce` and run `python3 poc.py` (if running locally, install kafka-python using pip first).
  1. Reverse shell connection should now be established to my test instance

## Impact

RCE on the Kafka Connect server

---

### [Stored XSS on ████████helpdesk](https://hackerone.com/reports/901799)

- **Report ID:** `901799`
- **Severity:** High
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Program:** U.S. Dept Of Defense
- **Reporter:** @atbabers
- **Bounty:** - usd
- **Disclosed:** 2020-07-30T17:45:27.668Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense(DoD) asset was vulnerable to Stored XSS due to a file upload feature. This may have led to Local File Inclusion. The DoD Representatives were responsive and thorough when handling my report.

**Summary (researcher):**

A Department of Defense(DoD) asset was vulnerable to Stored XSS due to a file upload feature. This may have led to Local File Inclusion. The DoD Representatives were responsive and thorough when handling my report.

---

### [Unrestricted File Upload Leads to XSS & Potential RCE](https://hackerone.com/reports/900179)

- **Report ID:** `900179`
- **Severity:** High
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Program:** U.S. Dept Of Defense
- **Reporter:** @5050thepiguy
- **Bounty:** - usd
- **Disclosed:** 2020-07-08T17:47:54.279Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Unrestricted file upload at████████/request?openform. When the user wants to upload a file the app allows the user to upload a HTML file leading to stored XSS and creation of a simple php script. A user can upload the HTML file and trigger XSS and trigger potential RCE with php shell. Please go to the ██████ Request that I created at -- ██████████AllOpenOrders/4F4D0C69EA2B33A58525858A001E2B8C?opendocument and select the file at the bottom "unsure1.html" to trigger payload to show XSS and php shell. You can also go directly to the uploaded file at ████0/4f4d0c69ea2b33a58525858a001e2b8c/$FILE/unsure1.html. Please see the attached PoC video as well. Thanks.

## Impact
The unrestricted file upload vulnerability leads to stored XSS and creation of php shell leading to potential RCE, which opens the door to numerous malicious attacks by the attacker. 

## Step-by-step Reproduction Instructions

1. Go to███/request?openform
2. Enter in the details for this page and you will automatically be redirected to the next page. Do the same thing here and enter in all the necessary information
3. Then, towards the bottom you are given the option to upload files so click "browse" and upload your payload
4. Click "submit request" then go back to █████████ModifyRequest.xsp and enter in the 14 digit Document Number. 
5. Scroll down to the bottom of your request and click the HTML payload.
6. Observe that XSS triggers and php shell is seen as well. 

## Product, Version, and Configuration (If applicable)
███
███request?openform

## Suggested Mitigation/Remediation Actions
Restrict file uploads to only necessary business requirements. If possible restrict uploads to JPG, DOC, DOCX, and PDF. Don't allowed upload of executable files.

##References
Please see attached PoC video
Please see attached PoC HTML page as well used for the payload

## Impact

The unrestricted file upload vulnerability leads to stored XSS and creation of php shell leading to potential RCE, which opens the door to numerous malicious attacks by the attacker.

---

### [Tricking the "Create snippet" feature into displaying the wrong filetype can lead to RCE on Slack users](https://hackerone.com/reports/833080)

- **Report ID:** `833080`
- **Severity:** High
- **Weakness:** Unrestricted Upload of File with Dangerous Type
- **Program:** Slack
- **Reporter:** @padillac
- **Bounty:** 1500 usd
- **Disclosed:** 2020-06-30T22:56:24.360Z
- **CVE(s):** -

**Summary (team):**

An issue in Slack's Create snippet feature results in filetypes being displayed incorrectly. This can lead to RCE if a Slack user downloads an executable file thinking that it is a CSV or other benign file type.

**Summary (researcher):**

https://www.youtube.com/watch?v=cIlGfnn4iG8

---
