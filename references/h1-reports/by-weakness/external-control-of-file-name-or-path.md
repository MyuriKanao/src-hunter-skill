# External Control of File Name or Path

_1 reports — High/Critical, disclosed_

### [Arbitrary Configuration File Inclusion: via External Control of File Name or Path](https://hackerone.com/reports/3418646)

- **Report ID:** `3418646`
- **Severity:** Critical
- **Weakness:** External Control of File Name or Path
- **Program:** curl
- **Reporter:** @rootsecret3
- **Bounty:** - usd
- **Disclosed:** 2025-11-10T16:21:14.255Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The Arbitrary Configuration File Inclusion (ACFI) vulnerability was identified in the curl utility via the --config <file> option. This flaw is a form of External Control of File Name or Path (CWE-73), occurring due to the lack of adequate validation on the user-supplied configuration file path.

An attacker can leverage this weakness to:
Trick a user into executing curl with a malicious configuration file located at an arbitrary path (e.g., /tmp/malicious.curlrc).

Significantly control curl's behavior, including setting dangerous options such as url = "file:///" and output = "...".

The impact is Critical, potentially allowing the attacker to perform a Local File Read of sensitive files like /etc/passwd and an Arbitrary File Write to arbitrary locations on the victim's system.

"I confirm that I performed the vulnerability discovery and core technical analysis manually. However, AI tools (such as Gemini/ChatGPT) were utilized solely for summarizing the findings, calculating the CVSS score, and drafting the formal report structure based on my raw technical data. AI was not used to generate the exploit code or perform the scan/discovery."

## Affected version
curl/libcurl version :  8.15.0
platform : x86_64-pc-linux-gnu

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1.  create a malicious configuration file :
Open the terminal and run the following command to create a file named /tmp/malicious.curlrc. This file will instruct curl to read the /etc/passwd file and save it to /tmp/stolen_passwd.txt.

echo 'url = "file:///etc/passwd"' > /tmp/malicious.curlrc
echo 'output = "/tmp/stolen_passwd.txt"' >> /tmp/malicious.curlrc

  2. and then Run curl and direct it to use the configuration file you just created using the --config

curl --config /tmp/malicious.curlrc

  3. Then we check whether the file /tmp/stolen_passwd.txt has been successfully created and contains the contents of /etc/passwd.

cat /tmp/stolen_passwd.txt

The results are in.

curl executes instructions from configuration files without warning, reads sensitive local files (/etc/passwd), and writes them to a location specified by the attacker (/tmp/stolen_passwd.txt).

This proves that attackers can read arbitrary local files and write to locations accessible to users running curl

## Supporting Material/References:
This vulnerability stems from the way curl parses configuration files without adequate path validation.

source file: /curl/src/

The curlx_fopen function is called with a filename that is directly controlled by the user via the --config argument.
vulnerable lines of code : 
file = curlx_fopen(filename, FOPEN_READTEXT);

Execution point (sink): Each line of the configuration file is then processed by the `getparameter` function, which executes malicious instructions such as `url` and `output`.
code :
res = getparameter(option, param, &usedarg, config, max_recursive);

  * [attachment / reference]
 CWE-73: External Control of File Name or Path

## Impact

## Summary: The impact of this vulnerability is Critical, as it gives attackers the ability to perform several dangerous actions on the target system, depending on the access rights of the user running curl.

 1. Sensitive Information Disclosure:
An attacker can read any file accessible to the user. This
includes, but is not limited to:
* User Credentials: Private SSH keys (~/.ssh/id_rsa), shell
history files (~/.bash_history), API tokens, or cloud credentials stored in ~/.aws/credentials.
* Application Secrets: Configuration files containing database passwords, API keys, or other sensitive data.
* System Data: Files such as /etc/passwd or system logs that can be used for user enumeration and system mapping.

 2. File Modification and Potential Code Execution (Arbitrary File Write & Code Execution):
  By using output parameters in configuration files, attackers can write or overwrite files in permitted locations. Attack scenarios
  include:
* Achieving Persistent Code Execution: Overwriting startup shell files such as ~/.bashrc or ~/.profile to insert malicious commands that will be executed every time a user logs in.
* Planting a Web Shell: If curl is run by the web server, attackers can write PHP files or other scripts to the web directory
(/var/www/html/shell.php), which gives them remote shell access.
* Compromising System Integrity: Overwriting important files that can cause Denial of Service (DoS).

3. SSRF (Server-Side Request Forgery) Attack:
  An attacker can force the server to make network requests to internal resources that are not accessible from the outside. By setting url = “http://169.254.169.254/latest/meta-data/” (in an AWS environment) or url = “http://localhost:8080/admin”, attackers can scan the internal network and steal data from internal services.

Overall, this vulnerability compromises the three pillars of security: Confidentiality, Integrity, and potentially Availability of the system.

---
